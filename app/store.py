from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from typing import Sequence

from .atomic_execution import (
    _commit_digest_payload,
    _commit_payload,
    _permit_digest_payload,
    _permit_payload,
    atomic_execution_policy_sha256,
    atomic_initial_state_sha256,
    atomic_next_state_sha256,
)
from .distributed_execution import (
    _claim_digest_payload,
    _claim_payload,
    distributed_execution_policy_sha256,
)
from .integrity import sha256_object, sha256_text
from .privacy_minimization import decrypt_replay_text
from .provider_execution import (
    _record_digest_payload,
    _record_payload,
    _reconciliation_digest_payload,
    _reconciliation_payload,
    provider_call_id,
)
from .schemas import (
    RecoveryAtomicActionCommit,
    RecoveryAtomicActionPermit,
    RecoveryDistributedWorkerClaim,
    RecoveryProviderCallRecord,
    RecoveryProviderCallReconciliation,
)

_MIN_KEY_BYTES = 32
_ZERO = "0" * 64
_POLICY = {
    "domain": "ILLUSIONTION_RECOVERY_STATE_INTEGRITY_V0_40",
    "resume_rule": "AUDIT_SHARED_DURABLE_STATE_BEFORE_ANY_INTERRUPTED_RESUME",
    "atomic_rule": "RECOMPUTE_CONTIGUOUS_SIGNED_ACTION_STATE_CHAIN",
    "provider_rule": "REQUIRE_PROVIDER_ROWS_TO_MATCH_AUTHORIZED_ATOMIC_ACTIONS",
    "distributed_rule": "RECOMPUTE_MONOTONIC_WORKER_CLAIM_CHAIN_WHEN_PRESENT",
    "corruption_rule": "ANY_CROSS_STORE_INCONSISTENCY_FAILS_CLOSED_BEFORE_NETWORK",
    "authority_scope": "STATE_INTEGRITY_ONLY_NEVER_UPGRADES_VERDICT",
}


def state_integrity_policy_sha256() -> str:
    return sha256_object(_POLICY)


def _hmac(payload: dict, key: bytes) -> str:
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError("State integrity runtime key must be at least 32 bytes.")
    return hmac.new(key, sha256_object(payload).encode("ascii"), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class RecoveryStateIntegrityAudit:
    attempt_id: str
    status: str
    safe_to_resume: bool
    errors: tuple[str, ...]
    atomic_next_step: int
    atomic_action_count: int
    provider_call_count: int
    worker_claim_count: int
    state_integrity_policy_sha256: str

    def as_dict(self) -> dict:
        return {
            "attempt_id": self.attempt_id,
            "status": self.status,
            "safe_to_resume": self.safe_to_resume,
            "errors": list(self.errors),
            "atomic_next_step": self.atomic_next_step,
            "atomic_action_count": self.atomic_action_count,
            "provider_call_count": self.provider_call_count,
            "worker_claim_count": self.worker_claim_count,
            "state_integrity_policy_sha256": self.state_integrity_policy_sha256,
        }


class RecoveryStateIntegrityError(RuntimeError):
    pass


def _parse_json_model(raw: str | None, model, label: str, errors: list[str]):
    if raw is None:
        errors.append(f"{label}-missing")
        return None
    try:
        return model.model_validate(json.loads(raw))
    except Exception:
        errors.append(f"{label}-invalid-json-or-schema")
        return None


def audit_recovery_state_universe(
    *,
    db_path: str,
    attempt_id: str,
    reviewer_order: Sequence[str],
    runtime_key: bytes,
    require_distributed_claim: bool,
) -> RecoveryStateIntegrityAudit:
    """Recompute cross-table authority state before an interrupted v0.40 resume.

    The audit is read-only. It does not attempt to repair corrupted state and it
    never turns a failure into a resumable condition. A successful audit only says
    that the durable atomic/provider/distributed state is internally coherent; the
    normal v0.38 interruption classifier still decides whether the current crash
    point is resumable or terminally uncertain.
    """
    errors: list[str] = []
    if len(runtime_key) < _MIN_KEY_BYTES:
        raise ValueError("State integrity runtime key must be at least 32 bytes.")

    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.row_factory = sqlite3.Row
    except Exception:
        return RecoveryStateIntegrityAudit(
            attempt_id=attempt_id, status="FAIL_CLOSED", safe_to_resume=False,
            errors=("state-db-open-failed",), atomic_next_step=-1, atomic_action_count=0,
            provider_call_count=0, worker_claim_count=0,
            state_integrity_policy_sha256=state_integrity_policy_sha256(),
        )

    try:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        required = {"attempts", "actions", "provider_calls"}
        missing = sorted(required - tables)
        errors.extend(f"state-table-missing:{name}" for name in missing)
        if missing:
            return RecoveryStateIntegrityAudit(
                attempt_id=attempt_id, status="FAIL_CLOSED", safe_to_resume=False,
                errors=tuple(sorted(set(errors))), atomic_next_step=-1, atomic_action_count=0,
                provider_call_count=0, worker_claim_count=0,
                state_integrity_policy_sha256=state_integrity_policy_sha256(),
            )

        attempt = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        actions = conn.execute(
            "SELECT * FROM actions WHERE attempt_id=? ORDER BY step_index ASC", (attempt_id,)
        ).fetchall()
        calls = conn.execute(
            "SELECT * FROM provider_calls WHERE attempt_id=? ORDER BY step_index ASC", (attempt_id,)
        ).fetchall()
        reconciliations = []
        if "provider_reconciliations" in tables:
            reconciliations = conn.execute(
                "SELECT * FROM provider_reconciliations WHERE attempt_id=? ORDER BY step_index ASC",
                (attempt_id,),
            ).fetchall()

        if attempt is None:
            errors.append("atomic-attempt-missing")
            return RecoveryStateIntegrityAudit(
                attempt_id=attempt_id, status="FAIL_CLOSED", safe_to_resume=False,
                errors=tuple(sorted(set(errors))), atomic_next_step=-1,
                atomic_action_count=len(actions), provider_call_count=len(calls), worker_claim_count=0,
                state_integrity_policy_sha256=state_integrity_policy_sha256(),
            )

        expected_steps = len(reviewer_order)
        next_step = int(attempt["next_step"])
        if not 0 <= next_step <= expected_steps:
            errors.append("atomic-next-step-out-of-range")
        if attempt["policy_sha256"] != atomic_execution_policy_sha256():
            errors.append("atomic-policy-digest-mismatch")
        expected_initial = atomic_initial_state_sha256(
            attempt_id=attempt_id, attempt_lease_set_sha256=str(attempt["lease_set_sha256"])
        )
        state = expected_initial

        # Worker claim chain, if v0.39+ distributed state is present/required.
        claims: list[RecoveryDistributedWorkerClaim] = []
        claim_by_hash: dict[str, RecoveryDistributedWorkerClaim] = {}
        current_claim_hash = ""
        current_epoch = 0
        if "distributed_attempts" in tables and "distributed_worker_claims" in tables:
            drow = conn.execute(
                "SELECT * FROM distributed_attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            crows = conn.execute(
                "SELECT * FROM distributed_worker_claims WHERE attempt_id=? ORDER BY epoch ASC",
                (attempt_id,),
            ).fetchall()
            if drow is None:
                if require_distributed_claim:
                    errors.append("distributed-attempt-missing")
            else:
                current_claim_hash = str(drow["current_claim_sha256"])
                current_epoch = int(drow["current_epoch"])
                if drow["published_core_sha256"] and not drow["publication_json"]:
                    errors.append("distributed-published-core-without-publication")
                if drow["publication_json"] and not drow["published_core_sha256"]:
                    errors.append("distributed-publication-without-published-core")
            for pos, crow in enumerate(crows, start=1):
                claim = _parse_json_model(crow["claim_json"], RecoveryDistributedWorkerClaim,
                                          f"distributed-claim:{pos}", errors)
                if claim is None:
                    continue
                claims.append(claim)
                if int(crow["epoch"]) != pos or claim.epoch != pos:
                    errors.append(f"distributed-claim-epoch-gap:{pos}")
                expected_prior = _ZERO if pos == 1 else claims[-2].claim_sha256 if len(claims) >= 2 else _ZERO
                if claim.prior_claim_sha256 != expected_prior:
                    errors.append(f"distributed-claim-prior-mismatch:{pos}")
                if claim.claim_sha256 != sha256_object(_claim_digest_payload(claim)):
                    errors.append(f"distributed-claim-digest-mismatch:{pos}")
                if claim.runtime_signature != _hmac(_claim_payload(claim), runtime_key):
                    errors.append(f"distributed-claim-signature-invalid:{pos}")
                if claim.attempt_id != attempt_id:
                    errors.append(f"distributed-claim-attempt-mismatch:{pos}")
                if pos == 1 and claim.takeover:
                    errors.append("distributed-first-claim-takeover-invalid")
                if pos > 1 and not claim.takeover:
                    errors.append(f"distributed-successor-claim-without-takeover:{pos}")
                if claim.claim_sha256 in claim_by_hash:
                    errors.append(f"distributed-claim-duplicate:{pos}")
                claim_by_hash[claim.claim_sha256] = claim
            if drow is not None:
                if len(claims) != current_epoch:
                    errors.append("distributed-current-epoch-count-mismatch")
                if claims and claims[-1].claim_sha256 != current_claim_hash:
                    errors.append("distributed-current-claim-mismatch")
        elif require_distributed_claim:
            errors.append("distributed-state-tables-missing")

        def claim_epoch(value: str, label: str) -> int:
            if not value:
                if require_distributed_claim:
                    errors.append(f"{label}-worker-claim-missing")
                return 0
            claim = claim_by_hash.get(value)
            if claim is None:
                errors.append(f"{label}-worker-claim-unknown")
                return 0
            return claim.epoch

        # Atomic actions must be contiguous, signed, and reproduce the attempt state.
        committed_count = 0
        has_uncommitted = False
        prior_commit_epoch = 0
        permit_by_step: dict[int, RecoveryAtomicActionPermit] = {}
        commit_by_step: dict[int, RecoveryAtomicActionCommit] = {}
        for idx, row in enumerate(actions):
            step_index = int(row["step_index"])
            if step_index != idx:
                errors.append(f"atomic-action-step-gap:{idx}")
            permit = _parse_json_model(row["permit_json"], RecoveryAtomicActionPermit,
                                       f"atomic-permit:{idx}", errors)
            if permit is None:
                continue
            permit_by_step[step_index] = permit
            if permit.attempt_id != attempt_id or permit.step_index != step_index:
                errors.append(f"atomic-permit-identity-mismatch:{idx}")
            if step_index < expected_steps and permit.reviewer != reviewer_order[step_index]:
                errors.append(f"atomic-permit-reviewer-mismatch:{idx}")
            if permit.attempt_lease_set_sha256 != attempt["lease_set_sha256"]:
                errors.append(f"atomic-permit-lease-mismatch:{idx}")
            if permit.prior_state_sha256 != state:
                errors.append(f"atomic-permit-prior-state-mismatch:{idx}")
            if permit.permit_sha256 != sha256_object(_permit_digest_payload(permit)):
                errors.append(f"atomic-permit-digest-mismatch:{idx}")
            if permit.runtime_signature != _hmac(_permit_payload(permit), runtime_key):
                errors.append(f"atomic-permit-signature-invalid:{idx}")
            pe = claim_epoch(permit.distributed_worker_claim_sha256, f"atomic-permit:{idx}")
            if pe and pe < prior_commit_epoch:
                errors.append(f"atomic-permit-worker-epoch-regression:{idx}")

            if row["commit_json"] is None:
                has_uncommitted = True
                if step_index != next_step:
                    errors.append(f"atomic-uncommitted-permit-not-current-step:{idx}")
                continue
            commit = _parse_json_model(row["commit_json"], RecoveryAtomicActionCommit,
                                       f"atomic-commit:{idx}", errors)
            if commit is None:
                continue
            commit_by_step[step_index] = commit
            committed_count += 1
            if commit.attempt_id != attempt_id or commit.step_index != step_index or commit.reviewer != permit.reviewer:
                errors.append(f"atomic-commit-identity-mismatch:{idx}")
            if commit.permit_sha256 != permit.permit_sha256:
                errors.append(f"atomic-commit-permit-mismatch:{idx}")
            if commit.prior_state_sha256 != state:
                errors.append(f"atomic-commit-prior-state-mismatch:{idx}")
            expected_next = atomic_next_state_sha256(
                prior_state_sha256=state,
                permit_sha256=permit.permit_sha256,
                action_class=commit.action_class,
                receipt_signature=commit.receipt_signature,
            )
            if commit.next_state_sha256 != expected_next:
                errors.append(f"atomic-commit-next-state-mismatch:{idx}")
            if commit.commit_sha256 != sha256_object(_commit_digest_payload(commit)):
                errors.append(f"atomic-commit-digest-mismatch:{idx}")
            if commit.runtime_signature != _hmac(_commit_payload(commit), runtime_key):
                errors.append(f"atomic-commit-signature-invalid:{idx}")
            ce = claim_epoch(commit.distributed_worker_claim_sha256, f"atomic-commit:{idx}")
            if pe and ce and ce < pe:
                errors.append(f"atomic-commit-worker-before-permit:{idx}")
            if ce:
                prior_commit_epoch = ce
            state = expected_next

        if committed_count != next_step:
            errors.append("atomic-next-step-does-not-equal-committed-count")
        if attempt["state_sha256"] != state:
            errors.append("atomic-attempt-state-digest-mismatch")
        inflight = str(attempt["in_flight_permit_sha256"] or "")
        if has_uncommitted:
            current = permit_by_step.get(next_step)
            if current is None or inflight != current.permit_sha256:
                errors.append("atomic-in-flight-permit-pointer-mismatch")
            if len(actions) != committed_count + 1:
                errors.append("atomic-multiple-uncommitted-actions")
        else:
            if inflight:
                errors.append("atomic-in-flight-pointer-without-uncommitted-action")
            if len(actions) != committed_count:
                errors.append("atomic-action-count-inconsistent")
        if bool(attempt["completed"]):
            if next_step != expected_steps or has_uncommitted:
                errors.append("atomic-completed-flag-on-incomplete-attempt")

        # Provider calls must be a prefix contained by the authorized action rows.
        call_by_step: dict[int, RecoveryProviderCallRecord] = {}
        seen_responses: set[tuple[str, str]] = set()
        for idx, row in enumerate(calls):
            step_index = int(row["step_index"])
            if step_index != idx:
                errors.append(f"provider-call-step-gap:{idx}")
            permit = permit_by_step.get(step_index)
            if permit is None:
                errors.append(f"provider-call-without-atomic-permit:{idx}")
                continue
            expected_id = provider_call_id(
                attempt_id=attempt_id,
                step_index=step_index,
                reviewer=permit.reviewer,
                atomic_permit_sha256=permit.permit_sha256,
            )
            if row["provider_call_id"] != expected_id:
                errors.append(f"provider-call-id-mismatch:{idx}")
            if row["reviewer"] != permit.reviewer or row["atomic_permit_sha256"] != permit.permit_sha256:
                errors.append(f"provider-call-permit-identity-mismatch:{idx}")
            ve = claim_epoch(str(row["distributed_worker_claim_sha256"] or ""), f"provider-call:{idx}")
            pe = claim_epoch(permit.distributed_worker_claim_sha256, f"provider-permit:{idx}")
            if pe and ve and ve < pe:
                errors.append(f"provider-call-worker-before-permit:{idx}")
            state_name = str(row["state"])
            if state_name not in {"IN_FLIGHT", "UNCERTAIN", "COMPLETED"}:
                errors.append(f"provider-call-unknown-state:{idx}")
            if state_name == "COMPLETED":
                record = _parse_json_model(row["record_json"], RecoveryProviderCallRecord,
                                           f"provider-record:{idx}", errors)
                if record is None:
                    continue
                call_by_step[step_index] = record
                if record.provider_call_id != expected_id or record.attempt_id != attempt_id or record.step_index != step_index:
                    errors.append(f"provider-record-identity-mismatch:{idx}")
                if record.call_sha256 != sha256_object(_record_digest_payload(record)):
                    errors.append(f"provider-record-digest-mismatch:{idx}")
                if record.runtime_signature != _hmac(_record_payload(record), runtime_key):
                    errors.append(f"provider-record-signature-invalid:{idx}")
                replay_state = str(row["replay_material_state"] or "LEGACY_OR_AVAILABLE") if "replay_material_state" in row.keys() else "LEGACY_OR_AVAILABLE"
                invocation_blob = row["invocation_json"]
                raw_blob = row["raw_output"]
                try:
                    if not invocation_blob and "invocation_ciphertext" in row.keys() and row["invocation_ciphertext"]:
                        invocation_blob = decrypt_replay_text(
                            runtime_key=runtime_key, provider_call_id=str(row["provider_call_id"]),
                            label="invocation", ciphertext_hex=str(row["invocation_ciphertext"]),
                        )
                    if raw_blob is None and "raw_output_ciphertext" in row.keys() and row["raw_output_ciphertext"]:
                        raw_blob = decrypt_replay_text(
                            runtime_key=runtime_key, provider_call_id=str(row["provider_call_id"]),
                            label="raw_output", ciphertext_hex=str(row["raw_output_ciphertext"]),
                        )
                except Exception:
                    errors.append(f"provider-replay-vault-decryption-failed:{idx}")
                allow_purged = replay_state == "PURGED" and next_step == expected_steps
                if not invocation_blob and not allow_purged:
                    errors.append(f"provider-completed-missing-invocation-envelope:{idx}")
                if raw_blob is None and not allow_purged:
                    errors.append(f"provider-completed-missing-raw-output:{idx}")
                elif raw_blob is not None and sha256_text(str(raw_blob)) != record.raw_output_sha256:
                    errors.append(f"provider-completed-output-hash-mismatch:{idx}")
                if row["invocation_sha256"] != record.invocation_sha256:
                    errors.append(f"provider-completed-invocation-digest-mismatch:{idx}")
                response_key = (record.provider, record.model_response_id)
                if response_key in seen_responses:
                    errors.append(f"provider-response-id-duplicate:{idx}")
                seen_responses.add(response_key)
            else:
                if row["record_json"]:
                    errors.append(f"provider-noncompleted-has-completion-record:{idx}")
                if row["raw_output"] is not None or ("raw_output_ciphertext" in row.keys() and row["raw_output_ciphertext"]):
                    errors.append(f"provider-noncompleted-has-raw-output:{idx}")
            commit = commit_by_step.get(step_index)
            if commit is not None and state_name != "COMPLETED":
                errors.append(f"atomic-commit-without-completed-provider-call:{idx}")

        if len(calls) > len(actions):
            errors.append("provider-call-count-exceeds-atomic-actions")
        # A committed atomic action in v0.37+ must always have a durable completion.
        for step_index in commit_by_step:
            if step_index >= len(calls):
                errors.append(f"atomic-commit-missing-provider-row:{step_index}")
            elif str(calls[step_index]["state"]) != "COMPLETED":
                errors.append(f"atomic-commit-provider-not-completed:{step_index}")

        for idx, row in enumerate(reconciliations):
            rec = _parse_json_model(row["reconciliation_json"], RecoveryProviderCallReconciliation,
                                    f"provider-reconciliation:{idx}", errors)
            if rec is None:
                continue
            call = call_by_step.get(rec.step_index)
            if call is None:
                errors.append(f"provider-reconciliation-without-completed-call:{idx}")
                continue
            if rec.provider_call_id != call.provider_call_id or rec.call_sha256 != call.call_sha256:
                errors.append(f"provider-reconciliation-call-mismatch:{idx}")
            if rec.reconciliation_sha256 != sha256_object(_reconciliation_digest_payload(rec)):
                errors.append(f"provider-reconciliation-digest-mismatch:{idx}")
            if rec.runtime_signature != _hmac(_reconciliation_payload(rec), runtime_key):
                errors.append(f"provider-reconciliation-signature-invalid:{idx}")
            re = claim_epoch(rec.distributed_worker_claim_sha256, f"provider-reconciliation:{idx}")
            ve = claim_epoch(call.distributed_worker_claim_sha256, f"provider-reconciliation-call:{idx}")
            if ve and re and re < ve:
                errors.append(f"provider-reconciliation-worker-epoch-regression:{idx}")

        # Current worker pointer must refer to the last known epoch on distributed campaigns.
        if require_distributed_claim and claims:
            if current_epoch != len(claims) or current_claim_hash != claims[-1].claim_sha256:
                errors.append("distributed-current-worker-pointer-incoherent")

        unique = tuple(sorted(set(errors)))
        return RecoveryStateIntegrityAudit(
            attempt_id=attempt_id,
            status="PASS" if not unique else "FAIL_CLOSED",
            safe_to_resume=not unique,
            errors=unique,
            atomic_next_step=next_step,
            atomic_action_count=len(actions),
            provider_call_count=len(calls),
            worker_claim_count=len(claims),
            state_integrity_policy_sha256=state_integrity_policy_sha256(),
        )
    except sqlite3.DatabaseError:
        return RecoveryStateIntegrityAudit(
            attempt_id=attempt_id, status="FAIL_CLOSED", safe_to_resume=False,
            errors=("state-database-integrity-error",), atomic_next_step=-1,
            atomic_action_count=0, provider_call_count=0, worker_claim_count=0,
            state_integrity_policy_sha256=state_integrity_policy_sha256(),
        )
    finally:
        conn.close()


def require_recovery_state_integrity(**kwargs) -> RecoveryStateIntegrityAudit:
    audit = audit_recovery_state_universe(**kwargs)
    if not audit.safe_to_resume:
        raise RecoveryStateIntegrityError(
            "recovery-state-integrity-audit-failed:" + ";".join(audit.errors)
        )
    return audit
