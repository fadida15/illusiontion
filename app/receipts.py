from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .integrity import canonical_json, sha256_object, sha256_text
from .privacy_minimization import encrypt_replay_text, decrypt_replay_text
from .distributed_execution import assert_current_worker_conn
from .sqlite_utils import managed_sqlite_connection
from .runtime import IndependentReviewRuntime, ReviewInvocation, ModelReviewCompletion
from .schemas import (
    ClaimCandidate,
    EvidenceBundle,
    RecoveryAtomicActionPermit,
    RecoveryProviderCallChain,
    RecoveryProviderCallRecord,
    RecoveryProviderCallReconciliation,
    RecoveryDistributedWorkerClaim,
    ReviewExecutionMode,
)

_MIN_KEY_BYTES = 32
_POLICY = {
    "domain": "ILLUSIONTION_PROVIDER_CALL_EXECUTION_V0_37",
    "assignment": "ONE_GOVERNED_PROVIDER_CREATE_PER_ATOMIC_ACTION",
    "network_retry": "OFFICIAL_ADAPTER_SINGLE_CREATE_ATTEMPT",
    "crash_rule": "IN_FLIGHT_OR_UNCERTAIN_CALL_IS_NOT_RETRIED",
    "authority_scope": "CALL_PROVENANCE_ONLY_NEVER_UPGRADES_VERDICT",
}
_INTERRUPTION_POLICY = {
    "domain": "ILLUSIONTION_PROVIDER_INTERRUPTION_RECOVERY_V0_38",
    "pre_network": "PERMIT_WITHOUT_PROVIDER_ROW_MAY_RESUME",
    "ambiguous_network": "IN_FLIGHT_OR_UNCERTAIN_PROVIDER_CALL_FAILS_CLOSED",
    "durable_completion": "COMPLETED_PROVIDER_CALL_MAY_REPLAY_STORED_OUTPUT_WITHOUT_NETWORK",
    "post_commit": "COMMITTED_ACTION_MAY_BE_RECONSTRUCTED_FROM_DURABLE_CALL",
    "authority_scope": "RECOVERY_ONLY_NEVER_UPGRADES_VERDICT",
}


def provider_call_policy_sha256() -> str:
    return sha256_object(_POLICY)


def provider_interruption_policy_sha256() -> str:
    return sha256_object(_INTERRUPTION_POLICY)


def provider_call_id(*, attempt_id: str, step_index: int, reviewer: str, atomic_permit_sha256: str) -> str:
    return sha256_object({
        "domain": "ILLUSIONTION_PROVIDER_CALL_ID_V0_37",
        "attempt_id": attempt_id,
        "step_index": step_index,
        "reviewer": reviewer,
        "atomic_permit_sha256": atomic_permit_sha256,
    })


def _hmac(payload: dict, key: bytes) -> str:
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError("Provider call runtime key must be at least 32 bytes.")
    return hmac.new(key, sha256_object(payload).encode("ascii"), hashlib.sha256).hexdigest()


def _record_payload(value: RecoveryProviderCallRecord | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("runtime_signature", None)
    if not row.get("distributed_worker_claim_sha256"):
        row.pop("distributed_worker_claim_sha256", None)
    return row


def _record_digest_payload(value: RecoveryProviderCallRecord | dict) -> dict:
    row = _record_payload(value)
    row.pop("call_sha256", None)
    return row


def _reconciliation_payload(value: RecoveryProviderCallReconciliation | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("runtime_signature", None)
    if not row.get("distributed_worker_claim_sha256"):
        row.pop("distributed_worker_claim_sha256", None)
    return row


def _reconciliation_digest_payload(value: RecoveryProviderCallReconciliation | dict) -> dict:
    row = _reconciliation_payload(value)
    row.pop("reconciliation_sha256", None)
    return row


def _chain_payload(value: RecoveryProviderCallChain | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("chain_sha256", None)
    # Preserve v0.37 chain bytes exactly when no v0.38 reconciliation exists.
    if not row.get("reconciliations"):
        row.pop("reconciliations", None)
    return row


def _invocation_json(invocation: ReviewInvocation) -> str:
    return canonical_json({
        "reviewer": invocation.reviewer,
        "invocation_id": invocation.invocation_id,
        "run_token": invocation.run_token,
        "prompt": invocation.prompt,
        "payload_json": invocation.payload_json,
        "evidence": invocation.evidence.model_dump(mode="json"),
        "claim_sha256": invocation.claim_sha256,
        "evidence_digests": invocation.evidence_digests,
        "invocation_sha256": invocation.invocation_sha256,
        "attempt_context_sha256": invocation.attempt_context_sha256,
    })


def _invocation_from_json(raw: str) -> ReviewInvocation:
    row = json.loads(raw)
    return ReviewInvocation(
        reviewer=row["reviewer"],
        invocation_id=row["invocation_id"],
        run_token=row["run_token"],
        prompt=row["prompt"],
        payload_json=row["payload_json"],
        evidence=EvidenceBundle.model_validate(row["evidence"]),
        claim_sha256=row["claim_sha256"],
        evidence_digests=dict(row["evidence_digests"]),
        invocation_sha256=row["invocation_sha256"],
        attempt_context_sha256=row.get("attempt_context_sha256", ""),
    )


class ProviderCallUncertainError(RuntimeError):
    """The provider may have received a call, so automatic reissue is forbidden."""


class ProviderCallLedgerStore:
    """Durable call state sharing the trusted atomic recovery database.

    v0.37 commits IN_FLIGHT before network I/O and never automatically retries an
    ambiguous call. v0.38 additionally stores the exact invocation envelope and
    raw provider output for new governed calls. This permits recovery only when
    the provider completion was already durably recorded before the process died.
    An IN_FLIGHT/UNCERTAIN call remains terminally ambiguous and is never reissued.
    """

    def __init__(
        self,
        *,
        path: str | Path,
        runtime_key: bytes,
        durable_reconciliation: bool = False,
        privacy_minimized: bool = False,
        distributed_worker_claim: RecoveryDistributedWorkerClaim | None = None,
        require_distributed_claim: bool = False,
    ) -> None:
        if len(runtime_key) < _MIN_KEY_BYTES:
            raise ValueError("Provider call runtime key must be at least 32 bytes.")
        self.path = str(path)
        self.key = runtime_key
        self.durable_reconciliation = durable_reconciliation
        self.privacy_minimized = privacy_minimized
        self.distributed_worker_claim = distributed_worker_claim
        self.require_distributed_claim = require_distributed_claim
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS provider_calls (
                    attempt_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    reviewer TEXT NOT NULL,
                    distributed_worker_claim_sha256 TEXT,
                    atomic_permit_sha256 TEXT NOT NULL,
                    provider_call_id TEXT NOT NULL UNIQUE,
                    invocation_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    provider TEXT,
                    model_id TEXT,
                    model_response_id TEXT,
                    raw_output_sha256 TEXT,
                    record_json TEXT,
                    uncertainty_detail TEXT,
                    invocation_json TEXT,
                    raw_output TEXT,
                    invocation_ciphertext TEXT,
                    raw_output_ciphertext TEXT,
                    replay_material_state TEXT NOT NULL DEFAULT 'LEGACY_OR_AVAILABLE',
                    PRIMARY KEY(attempt_id, step_index)
                )"""
            )
            # Migration for a v0.37 state file opened by v0.38 code.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(provider_calls)").fetchall()}
            if "invocation_json" not in cols:
                conn.execute("ALTER TABLE provider_calls ADD COLUMN invocation_json TEXT")
            if "raw_output" not in cols:
                conn.execute("ALTER TABLE provider_calls ADD COLUMN raw_output TEXT")
            if "distributed_worker_claim_sha256" not in cols:
                conn.execute("ALTER TABLE provider_calls ADD COLUMN distributed_worker_claim_sha256 TEXT")
            if "invocation_ciphertext" not in cols:
                conn.execute("ALTER TABLE provider_calls ADD COLUMN invocation_ciphertext TEXT")
            if "raw_output_ciphertext" not in cols:
                conn.execute("ALTER TABLE provider_calls ADD COLUMN raw_output_ciphertext TEXT")
            if "replay_material_state" not in cols:
                conn.execute("ALTER TABLE provider_calls ADD COLUMN replay_material_state TEXT NOT NULL DEFAULT 'LEGACY_OR_AVAILABLE'")
            conn.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS provider_response_once
                ON provider_calls(provider, model_response_id)
                WHERE state='COMPLETED'"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS provider_reconciliations (
                    provider_call_id TEXT PRIMARY KEY,
                    attempt_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    reconciliation_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _assert_worker(self, conn: sqlite3.Connection, *, allow_published: bool = False) -> None:
        assert_current_worker_conn(
            conn,
            claim=self.distributed_worker_claim,
            runtime_key=self.key,
            required=self.require_distributed_claim,
            allow_published=allow_published,
        )

    def state_for_step(self, *, attempt_id: str, step_index: int) -> str | None:
        with managed_sqlite_connection(self._connect()) as conn:
            row = conn.execute(
                "SELECT state FROM provider_calls WHERE attempt_id=? AND step_index=?",
                (attempt_id, step_index),
            ).fetchone()
        return None if row is None else str(row["state"])

    def record_for_step(self, *, attempt_id: str, step_index: int) -> RecoveryProviderCallRecord | None:
        with managed_sqlite_connection(self._connect()) as conn:
            row = conn.execute(
                "SELECT record_json FROM provider_calls WHERE attempt_id=? AND step_index=?",
                (attempt_id, step_index),
            ).fetchone()
        if row is None or not row["record_json"]:
            return None
        return RecoveryProviderCallRecord.model_validate(json.loads(row["record_json"]))

    def mark_restart_in_flight_uncertain(self, *, attempt_id: str) -> list[int]:
        """Fail closed after a process restart with an ambiguous network call.

        Only explicit recovery code should call this. A call left IN_FLIGHT may
        already have reached the provider, therefore it cannot be safely retried.
        """
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            rows = conn.execute(
                "SELECT step_index,provider_call_id FROM provider_calls WHERE attempt_id=? AND state='IN_FLIGHT'",
                (attempt_id,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE provider_calls SET state='UNCERTAIN', uncertainty_detail=? WHERE provider_call_id=?",
                    ("PROCESS_RESTART_WITH_IN_FLIGHT_PROVIDER_CALL", row["provider_call_id"]),
                )
            conn.execute("COMMIT")
        return [int(row["step_index"]) for row in rows]

    def begin_call(
        self,
        *,
        permit: RecoveryAtomicActionPermit,
        invocation_sha256: str,
        expected_call_id: str,
        invocation: ReviewInvocation | None = None,
    ) -> str:
        actual = provider_call_id(
            attempt_id=permit.attempt_id,
            step_index=permit.step_index,
            reviewer=permit.reviewer,
            atomic_permit_sha256=permit.permit_sha256,
        )
        if actual != expected_call_id:
            raise ValueError("provider-call-id-mismatch-before-network")
        if invocation is not None and invocation.invocation_sha256 != invocation_sha256:
            raise ValueError("provider-call-invocation-envelope-digest-mismatch")
        if self.durable_reconciliation and invocation is None:
            raise ValueError("v0.38-provider-call-requires-durable-invocation-envelope")
        now = datetime.now(timezone.utc).isoformat()
        invocation_blob = _invocation_json(invocation) if invocation is not None else None
        invocation_ciphertext = None
        if self.privacy_minimized and invocation_blob is not None:
            invocation_ciphertext = encrypt_replay_text(
                runtime_key=self.key, provider_call_id=actual, label="invocation", plaintext=invocation_blob
            )
            invocation_blob = None
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            try:
                conn.execute(
                    """INSERT INTO provider_calls(
                        attempt_id,step_index,reviewer,distributed_worker_claim_sha256,atomic_permit_sha256,provider_call_id,
                        invocation_sha256,state,started_at,invocation_json,invocation_ciphertext,replay_material_state
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (permit.attempt_id, permit.step_index, permit.reviewer,
                     self.distributed_worker_claim.claim_sha256 if self.distributed_worker_claim is not None else None,
                     permit.permit_sha256, actual, invocation_sha256, "IN_FLIGHT", now, invocation_blob, invocation_ciphertext,
                     "ENCRYPTED_AVAILABLE" if self.privacy_minimized else "LEGACY_OR_AVAILABLE"),
                )
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                raise ValueError("provider-call-already-started-for-atomic-action") from exc
            conn.execute("COMMIT")
        return actual

    def complete_call(
        self,
        *,
        provider_call_id_value: str,
        provider: str,
        model_id: str,
        model_response_id: str,
        raw_output: str,
    ) -> RecoveryProviderCallRecord:
        if not provider.strip() or not model_id.strip() or not model_response_id.strip():
            raise ValueError("provider-call-completion-metadata-empty")
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            row = conn.execute("SELECT * FROM provider_calls WHERE provider_call_id=?", (provider_call_id_value,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise ValueError("provider-call-not-started")
            if row["state"] != "IN_FLIGHT":
                conn.execute("ROLLBACK")
                raise ValueError("provider-call-not-in-flight")
            if self.durable_reconciliation and not row["invocation_json"] and not row["invocation_ciphertext"]:
                conn.execute("ROLLBACK")
                raise ValueError("v0.38-provider-call-missing-durable-invocation-envelope")
            duplicate = conn.execute(
                "SELECT provider_call_id FROM provider_calls WHERE state='COMPLETED' AND provider=? AND model_response_id=?",
                (provider, model_response_id),
            ).fetchone()
            if duplicate is not None:
                conn.execute("ROLLBACK")
                raise ValueError("provider-response-id-reused-across-actions")
            completed_at = datetime.now(timezone.utc).isoformat()
            unsigned = RecoveryProviderCallRecord(
                attempt_id=row["attempt_id"], step_index=int(row["step_index"]), reviewer=row["reviewer"],
                distributed_worker_claim_sha256=(row["distributed_worker_claim_sha256"] or ""),
                atomic_permit_sha256=row["atomic_permit_sha256"], provider_call_id=row["provider_call_id"],
                invocation_sha256=row["invocation_sha256"], provider=provider, model_id=model_id,
                model_response_id=model_response_id, raw_output_sha256=sha256_text(raw_output),
                started_at=row["started_at"], completed_at=completed_at,
                call_sha256="0"*64, runtime_signature="0"*64,
            )
            digest = sha256_object(_record_digest_payload(unsigned))
            tmp = unsigned.model_copy(update={"call_sha256": digest})
            record = tmp.model_copy(update={"runtime_signature": _hmac(_record_payload(tmp), self.key)})
            try:
                raw_plain = raw_output if (self.durable_reconciliation and not self.privacy_minimized) else None
                raw_cipher = (
                    encrypt_replay_text(runtime_key=self.key, provider_call_id=provider_call_id_value,
                                        label="raw_output", plaintext=raw_output)
                    if self.durable_reconciliation and self.privacy_minimized else None
                )
                conn.execute(
                    """UPDATE provider_calls SET state='COMPLETED',completed_at=?,provider=?,model_id=?,
                    model_response_id=?,raw_output_sha256=?,record_json=?,raw_output=?,raw_output_ciphertext=?,replay_material_state=?
                    WHERE provider_call_id=?""",
                    (completed_at, provider, model_id, model_response_id, record.raw_output_sha256,
                     canonical_json(record.model_dump(mode="json")), raw_plain, raw_cipher,
                     "ENCRYPTED_AVAILABLE" if self.privacy_minimized else "LEGACY_OR_AVAILABLE",
                     provider_call_id_value),
                )
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                raise ValueError("provider-response-id-reused-across-actions") from exc
            conn.execute("COMMIT")
        return record

    def mark_uncertain(self, *, provider_call_id_value: str, detail: str) -> None:
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            row = conn.execute("SELECT state FROM provider_calls WHERE provider_call_id=?", (provider_call_id_value,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise ValueError("provider-call-not-started")
            if row["state"] != "IN_FLIGHT":
                conn.execute("ROLLBACK")
                raise ValueError("provider-call-not-in-flight")
            conn.execute(
                "UPDATE provider_calls SET state='UNCERTAIN', uncertainty_detail=? WHERE provider_call_id=?",
                (detail[:4096], provider_call_id_value),
            )
            conn.execute("COMMIT")

    def replay_completed_call(
        self,
        *,
        attempt_id: str,
        step_index: int,
        claim: ClaimCandidate,
        runtime: IndependentReviewRuntime,
        execution_mode: ReviewExecutionMode,
        record_reconciliation: bool,
    ) -> tuple[ModelReviewCompletion, ReviewInvocation, str, RecoveryProviderCallRecord]:
        """Recreate a reviewer completion from a durable provider response only.

        No provider adapter is called. This is the sole v0.38 recovery path for a
        crash after provider completion but before the atomic action commit.
        """
        with managed_sqlite_connection(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM provider_calls WHERE attempt_id=? AND step_index=?",
                (attempt_id, step_index),
            ).fetchone()
        if row is None or row["state"] != "COMPLETED" or not row["record_json"]:
            raise ValueError("provider-completion-not-durable-for-reconciliation")
        if row["replay_material_state"] == "PURGED":
            raise ValueError("provider-completion-replay-material-purged-after-publication")
        invocation_blob = row["invocation_json"]
        raw_blob = row["raw_output"]
        if not invocation_blob and row["invocation_ciphertext"]:
            invocation_blob = decrypt_replay_text(
                runtime_key=self.key, provider_call_id=str(row["provider_call_id"]),
                label="invocation", ciphertext_hex=str(row["invocation_ciphertext"]),
            )
        if raw_blob is None and row["raw_output_ciphertext"]:
            raw_blob = decrypt_replay_text(
                runtime_key=self.key, provider_call_id=str(row["provider_call_id"]),
                label="raw_output", ciphertext_hex=str(row["raw_output_ciphertext"]),
            )
        if not invocation_blob or raw_blob is None:
            raise ValueError("provider-completion-lacks-v0.38-recovery-envelope")
        record = RecoveryProviderCallRecord.model_validate(json.loads(row["record_json"]))
        if record.call_sha256 != sha256_object(_record_digest_payload(record)):
            raise ValueError("provider-completion-record-digest-invalid-before-reconciliation")
        if record.runtime_signature != _hmac(_record_payload(record), self.key):
            raise ValueError("provider-completion-record-signature-invalid-before-reconciliation")
        invocation = _invocation_from_json(str(invocation_blob))
        if invocation.invocation_sha256 != record.invocation_sha256:
            raise ValueError("provider-completion-invocation-mismatch-before-reconciliation")
        raw_output = str(raw_blob)
        if sha256_text(raw_output) != record.raw_output_sha256:
            raise ValueError("provider-completion-output-hash-mismatch-before-reconciliation")
        completion = runtime.complete_model_output(
            invocation=invocation,
            claim=claim,
            raw_output=raw_output,
            model_provider=record.provider,
            model_id=record.model_id,
            model_response_id=record.model_response_id,
            execution_mode=execution_mode,
        )
        if record_reconciliation:
            self._record_reconciliation(record)
        return completion, invocation, raw_output, record

    def _record_reconciliation(self, record: RecoveryProviderCallRecord) -> RecoveryProviderCallReconciliation:
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            existing = conn.execute(
                "SELECT reconciliation_json FROM provider_reconciliations WHERE provider_call_id=?",
                (record.provider_call_id,),
            ).fetchone()
            if existing is not None:
                conn.execute("ROLLBACK")
                return RecoveryProviderCallReconciliation.model_validate(json.loads(existing["reconciliation_json"]))
            now = datetime.now(timezone.utc).isoformat()
            unsigned = RecoveryProviderCallReconciliation(
                attempt_id=record.attempt_id,
                step_index=record.step_index,
                reviewer=record.reviewer,
                distributed_worker_claim_sha256=(
                    self.distributed_worker_claim.claim_sha256 if self.distributed_worker_claim is not None else ""
                ),
                provider_call_id=record.provider_call_id,
                call_sha256=record.call_sha256,
                invocation_sha256=record.invocation_sha256,
                raw_output_sha256=record.raw_output_sha256,
                reconciled_at=now,
                reconciliation_sha256="0"*64,
                runtime_signature="0"*64,
            )
            digest = sha256_object(_reconciliation_digest_payload(unsigned))
            tmp = unsigned.model_copy(update={"reconciliation_sha256": digest})
            rec = tmp.model_copy(update={"runtime_signature": _hmac(_reconciliation_payload(tmp), self.key)})
            conn.execute(
                "INSERT INTO provider_reconciliations(provider_call_id,attempt_id,step_index,reconciliation_json,created_at) VALUES(?,?,?,?,?)",
                (record.provider_call_id, record.attempt_id, record.step_index,
                 canonical_json(rec.model_dump(mode="json")), now),
            )
            conn.execute("COMMIT")
            return rec

    def purge_private_replay_material(self, *, attempt_id: str) -> int:
        """Delete exact replay bytes after authoritative rerun publication.

        v0.45 keeps invocation/output bytes encrypted only while crash reconciliation
        may still be required. Signed hashes and structured authority records remain.
        """
        if not self.privacy_minimized:
            return 0
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn, allow_published=True)
            rows = conn.execute(
                "SELECT provider_call_id,state FROM provider_calls WHERE attempt_id=?", (attempt_id,)
            ).fetchall()
            if not rows or any(str(row["state"]) != "COMPLETED" for row in rows):
                conn.execute("ROLLBACK")
                raise ValueError("privacy-purge-requires-complete-provider-call-population")
            conn.execute(
                """UPDATE provider_calls SET invocation_json=NULL,raw_output=NULL,
                invocation_ciphertext=NULL,raw_output_ciphertext=NULL,replay_material_state='PURGED'
                WHERE attempt_id=?""",
                (attempt_id,),
            )
            conn.execute("COMMIT")
        return len(rows)

    def finalize(self, *, attempt_id: str, expected_steps: int) -> RecoveryProviderCallChain:
        with managed_sqlite_connection(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM provider_calls WHERE attempt_id=? ORDER BY step_index ASC", (attempt_id,)
            ).fetchall()
            rec_rows = conn.execute(
                "SELECT reconciliation_json FROM provider_reconciliations WHERE attempt_id=? ORDER BY step_index ASC",
                (attempt_id,),
            ).fetchall()
        if len(rows) != expected_steps:
            raise ValueError("provider-call-chain-incomplete")
        calls: list[RecoveryProviderCallRecord] = []
        for idx, row in enumerate(rows):
            if int(row["step_index"]) != idx or row["state"] != "COMPLETED" or not row["record_json"]:
                raise ValueError("provider-call-chain-incomplete-or-uncertain")
            calls.append(RecoveryProviderCallRecord.model_validate(json.loads(row["record_json"])))
        reconciliations = [
            RecoveryProviderCallReconciliation.model_validate(json.loads(row["reconciliation_json"]))
            for row in rec_rows
        ]
        unsigned = RecoveryProviderCallChain(
            attempt_id=attempt_id,
            provider_call_policy_sha256=provider_call_policy_sha256(),
            calls=calls,
            reconciliations=reconciliations,
            chain_sha256="0"*64,
        )
        return unsigned.model_copy(update={"chain_sha256": sha256_object(_chain_payload(unsigned))})


def verify_provider_call_chain(
    chain: RecoveryProviderCallChain,
    *,
    attempt_id: str,
    atomic_chain,
    traces: list,
    runtime_key: bytes,
) -> list[str]:
    errors: list[str] = []
    if chain.attempt_id != attempt_id:
        errors.append("provider-call-chain-attempt-id-mismatch")
    if chain.provider_call_policy_sha256 != provider_call_policy_sha256():
        errors.append("provider-call-chain-policy-mismatch")
    if chain.chain_sha256 != sha256_object(_chain_payload(chain)):
        errors.append("provider-call-chain-digest-mismatch")
    if len(chain.calls) != len(atomic_chain.steps) or len(chain.calls) != len(traces):
        errors.append("provider-call-chain-cardinality-mismatch")
        return sorted(set(errors))
    seen_responses: set[tuple[str,str]] = set()
    call_by_id: dict[str, RecoveryProviderCallRecord] = {}
    for idx, (call, atomic_step, trace) in enumerate(zip(chain.calls, atomic_chain.steps, traces)):
        permit = atomic_step.permit
        call_by_id[call.provider_call_id] = call
        if call.step_index != idx or call.reviewer != permit.reviewer or trace.reviewer != permit.reviewer:
            errors.append(f"provider-call-step-identity-mismatch:{idx}")
        expected_id = provider_call_id(
            attempt_id=attempt_id, step_index=idx, reviewer=permit.reviewer,
            atomic_permit_sha256=permit.permit_sha256,
        )
        if call.provider_call_id != expected_id:
            errors.append(f"provider-call-id-mismatch:{idx}")
        if call.atomic_permit_sha256 != permit.permit_sha256:
            errors.append(f"provider-call-permit-mismatch:{idx}")
        if call.invocation_sha256 != trace.invocation_sha256:
            errors.append(f"provider-call-invocation-mismatch:{idx}")
        if call.provider != trace.model_provider or call.model_id != trace.model_id:
            errors.append(f"provider-call-model-identity-mismatch:{idx}")
        if call.model_response_id != trace.model_response_id:
            errors.append(f"provider-call-response-id-mismatch:{idx}")
        if call.raw_output_sha256 != trace.raw_output_sha256:
            errors.append(f"provider-call-output-hash-mismatch:{idx}")
        if call.call_sha256 != sha256_object(_record_digest_payload(call)):
            errors.append(f"provider-call-record-digest-mismatch:{idx}")
        if call.runtime_signature != _hmac(_record_payload(call), runtime_key):
            errors.append(f"provider-call-record-signature-invalid:{idx}")
        key = (call.provider, call.model_response_id)
        if key in seen_responses:
            errors.append(f"provider-call-response-id-duplicate:{idx}")
        seen_responses.add(key)
    seen_reconciled: set[str] = set()
    for rec in chain.reconciliations:
        call = call_by_id.get(rec.provider_call_id)
        if call is None:
            errors.append(f"provider-reconciliation-call-missing:{rec.step_index}")
            continue
        if rec.provider_call_id in seen_reconciled:
            errors.append(f"provider-reconciliation-duplicate:{rec.step_index}")
        seen_reconciled.add(rec.provider_call_id)
        if rec.attempt_id != attempt_id or rec.step_index != call.step_index or rec.reviewer != call.reviewer:
            errors.append(f"provider-reconciliation-identity-mismatch:{rec.step_index}")
        if rec.call_sha256 != call.call_sha256:
            errors.append(f"provider-reconciliation-call-digest-mismatch:{rec.step_index}")
        if rec.invocation_sha256 != call.invocation_sha256:
            errors.append(f"provider-reconciliation-invocation-mismatch:{rec.step_index}")
        if rec.raw_output_sha256 != call.raw_output_sha256:
            errors.append(f"provider-reconciliation-output-mismatch:{rec.step_index}")
        if rec.reconciliation_sha256 != sha256_object(_reconciliation_digest_payload(rec)):
            errors.append(f"provider-reconciliation-digest-mismatch:{rec.step_index}")
        if rec.runtime_signature != _hmac(_reconciliation_payload(rec), runtime_key):
            errors.append(f"provider-reconciliation-signature-invalid:{rec.step_index}")
    return sorted(set(errors))
