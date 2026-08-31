from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .integrity import canonical_json, sha256_object
from .distributed_execution import assert_current_worker_conn
from .sqlite_utils import managed_sqlite_connection
from .schemas import (
    RecoveryAtomicActionCommit,
    RecoveryAtomicActionPermit,
    RecoveryAtomicActionStep,
    RecoveryAtomicExecutionChain,
    RecoveryDistributedWorkerClaim,
)

_MIN_KEY_BYTES = 32
_POLICY = {
    "domain": "ILLUSIONTION_ATOMIC_ACTION_EXECUTION_V0_35",
    "ordering": "ONE_IN_FLIGHT_REVIEWER_ACTION_PER_ATTEMPT",
    "permit_rule": "ATOMIC_COMPARE_AND_SWAP_BEFORE_PROVIDER_CALL",
    "commit_rule": "CLASSIFY_AND_COMMIT_BEFORE_NEXT_ACTION",
    "learning_authority": "NEGATIVE_ONLY_NEVER_UPGRADES_VERDICT",
}


def atomic_execution_policy_sha256() -> str:
    return sha256_object(_POLICY)


def atomic_initial_state_sha256(*, attempt_id: str, attempt_lease_set_sha256: str) -> str:
    return sha256_object({
        "domain": "ILLUSIONTION_ATOMIC_ATTEMPT_INITIAL_STATE_V0_35",
        "attempt_id": attempt_id,
        "attempt_lease_set_sha256": attempt_lease_set_sha256,
        "atomic_policy_sha256": atomic_execution_policy_sha256(),
    })


def atomic_next_state_sha256(*, prior_state_sha256: str, permit_sha256: str, action_class: str, receipt_signature: str) -> str:
    return sha256_object({
        "domain": "ILLUSIONTION_ATOMIC_ATTEMPT_ACTION_COMMIT_V0_35",
        "prior_state_sha256": prior_state_sha256,
        "permit_sha256": permit_sha256,
        "action_class": action_class,
        "receipt_signature": receipt_signature,
    })


def action_attempt_context_sha256(*, attempt_lease_set_sha256: str, permit_sha256: str, provider_call_id: str = "") -> str:
    payload = {
        "domain": "ILLUSIONTION_RECOVERY_ACTION_INVOCATION_CONTEXT_V0_35",
        "attempt_lease_set_sha256": attempt_lease_set_sha256,
        "permit_sha256": permit_sha256,
    }
    # Preserve v0.35/v0.36 bytes exactly. v0.37 binds the deterministic provider
    # call identity into the invocation before network I/O.
    if provider_call_id:
        payload["provider_call_id"] = provider_call_id
        payload["provider_binding_domain"] = "ILLUSIONTION_PROVIDER_CALL_CONTEXT_V0_37"
    return sha256_object(payload)


def _hmac(payload: dict, key: bytes) -> str:
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError("Atomic execution runtime key must be at least 32 bytes.")
    return hmac.new(key, sha256_object(payload).encode("ascii"), hashlib.sha256).hexdigest()


def _permit_payload(value: RecoveryAtomicActionPermit | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("runtime_signature", None)
    if not row.get("distributed_worker_claim_sha256"):
        row.pop("distributed_worker_claim_sha256", None)
    return row


def _permit_digest_payload(value: RecoveryAtomicActionPermit | dict) -> dict:
    row = _permit_payload(value)
    row.pop("permit_sha256", None)
    return row


def _commit_payload(value: RecoveryAtomicActionCommit | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("runtime_signature", None)
    if not row.get("distributed_worker_claim_sha256"):
        row.pop("distributed_worker_claim_sha256", None)
    return row


def _commit_digest_payload(value: RecoveryAtomicActionCommit | dict) -> dict:
    row = _commit_payload(value)
    row.pop("commit_sha256", None)
    return row


def _chain_payload(value: RecoveryAtomicExecutionChain | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("chain_sha256", None)
    return row


class AtomicRecoveryActionStore:
    """SQLite-backed compare-and-swap state for one authoritative recovery attempt.

    The store intentionally fails closed after a crash or duplicate attempt. SQLite
    transactions serialize concurrent processes that share the same state file.
    Protection against disk rollback/cloning remains an explicit trust boundary.
    """

    def __init__(
        self,
        *,
        path: str | Path,
        runtime_key: bytes,
        distributed_worker_claim: RecoveryDistributedWorkerClaim | None = None,
        require_distributed_claim: bool = False,
    ) -> None:
        if len(runtime_key) < _MIN_KEY_BYTES:
            raise ValueError("Atomic execution runtime key must be at least 32 bytes.")
        self.path = str(path)
        self.key = runtime_key
        self.distributed_worker_claim = distributed_worker_claim
        self.require_distributed_claim = require_distributed_claim
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY,
                    lease_set_sha256 TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    next_step INTEGER NOT NULL,
                    state_sha256 TEXT NOT NULL,
                    in_flight_permit_sha256 TEXT,
                    completed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS actions (
                    attempt_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    permit_json TEXT NOT NULL,
                    commit_json TEXT,
                    PRIMARY KEY(attempt_id, step_index)
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _assert_worker(self, conn: sqlite3.Connection) -> None:
        assert_current_worker_conn(
            conn,
            claim=self.distributed_worker_claim,
            runtime_key=self.key,
            required=self.require_distributed_claim,
        )

    def begin_attempt(self, *, attempt_id: str, attempt_lease_set_sha256: str) -> None:
        initial = atomic_initial_state_sha256(attempt_id=attempt_id, attempt_lease_set_sha256=attempt_lease_set_sha256)
        now = datetime.now(timezone.utc).isoformat()
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            try:
                conn.execute(
                    "INSERT INTO attempts(attempt_id, lease_set_sha256, policy_sha256, next_step, state_sha256, created_at) VALUES(?,?,?,?,?,?)",
                    (attempt_id, attempt_lease_set_sha256, atomic_execution_policy_sha256(), 0, initial, now),
                )
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-attempt-slot-already-consumed-or-in-progress") from exc
            conn.execute("COMMIT")

    def attempt_progress(self, *, attempt_id: str) -> dict:
        """Return durable execution progress without mutating authority state."""
        with managed_sqlite_connection(self._connect()) as conn:
            row = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is None:
                return {"exists": False}
            actions = conn.execute(
                "SELECT step_index,permit_json,commit_json FROM actions WHERE attempt_id=? ORDER BY step_index ASC",
                (attempt_id,),
            ).fetchall()
        return {
            "exists": True,
            "attempt_id": attempt_id,
            "lease_set_sha256": row["lease_set_sha256"],
            "policy_sha256": row["policy_sha256"],
            "next_step": int(row["next_step"]),
            "state_sha256": row["state_sha256"],
            "in_flight_permit_sha256": row["in_flight_permit_sha256"] or "",
            "completed": bool(row["completed"]),
            "actions": [
                {
                    "step_index": int(action["step_index"]),
                    "committed": action["commit_json"] is not None,
                }
                for action in actions
            ],
        }

    def load_permit(self, *, attempt_id: str, step_index: int) -> RecoveryAtomicActionPermit | None:
        with managed_sqlite_connection(self._connect()) as conn:
            row = conn.execute(
                "SELECT permit_json FROM actions WHERE attempt_id=? AND step_index=?",
                (attempt_id, step_index),
            ).fetchone()
        if row is None:
            return None
        return RecoveryAtomicActionPermit.model_validate(json.loads(row["permit_json"]))

    def load_commit(self, *, attempt_id: str, step_index: int) -> RecoveryAtomicActionCommit | None:
        with managed_sqlite_connection(self._connect()) as conn:
            row = conn.execute(
                "SELECT commit_json FROM actions WHERE attempt_id=? AND step_index=?",
                (attempt_id, step_index),
            ).fetchone()
        if row is None or row["commit_json"] is None:
            return None
        return RecoveryAtomicActionCommit.model_validate(json.loads(row["commit_json"]))

    def authorize(self, *, attempt_id: str, step_index: int, reviewer: str) -> RecoveryAtomicActionPermit:
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            row = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-attempt-not-initialized")
            if row["completed"]:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-attempt-already-completed")
            if row["in_flight_permit_sha256"]:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-action-already-in-flight")
            if int(row["next_step"]) != step_index:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-action-step-out-of-order")
            now = datetime.now(timezone.utc).isoformat()
            unsigned = RecoveryAtomicActionPermit(
                attempt_id=attempt_id,
                attempt_lease_set_sha256=row["lease_set_sha256"],
                step_index=step_index,
                reviewer=reviewer,
                distributed_worker_claim_sha256=(
                    self.distributed_worker_claim.claim_sha256 if self.distributed_worker_claim is not None else ""
                ),
                prior_state_sha256=row["state_sha256"],
                permit_nonce=secrets.token_hex(24),
                issued_at=now,
                permit_sha256="0" * 64,
                runtime_signature="0" * 64,
            )
            digest = sha256_object(_permit_digest_payload(unsigned))
            tmp = unsigned.model_copy(update={"permit_sha256": digest})
            permit = tmp.model_copy(update={"runtime_signature": _hmac(_permit_payload(tmp), self.key)})
            conn.execute(
                "INSERT INTO actions(attempt_id, step_index, permit_json, commit_json) VALUES(?,?,?,NULL)",
                (attempt_id, step_index, canonical_json(permit.model_dump(mode="json"))),
            )
            conn.execute(
                "UPDATE attempts SET in_flight_permit_sha256=? WHERE attempt_id=?",
                (permit.permit_sha256, attempt_id),
            )
            conn.execute("COMMIT")
            return permit

    def commit(
        self,
        *,
        permit: RecoveryAtomicActionPermit,
        action_class: str,
        receipt_signature: str,
    ) -> RecoveryAtomicActionCommit:
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            row = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (permit.attempt_id,)).fetchone()
            action = conn.execute(
                "SELECT * FROM actions WHERE attempt_id=? AND step_index=?",
                (permit.attempt_id, permit.step_index),
            ).fetchone()
            if row is None or action is None:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-action-permit-not-authorized")
            if action["commit_json"] is not None:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-action-already-committed")
            if row["in_flight_permit_sha256"] != permit.permit_sha256:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-action-in-flight-permit-mismatch")
            stored = RecoveryAtomicActionPermit.model_validate(json.loads(action["permit_json"]))
            if stored != permit:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-action-permit-mutation")
            next_state = atomic_next_state_sha256(
                prior_state_sha256=permit.prior_state_sha256,
                permit_sha256=permit.permit_sha256,
                action_class=action_class,
                receipt_signature=receipt_signature,
            )
            now = datetime.now(timezone.utc).isoformat()
            unsigned = RecoveryAtomicActionCommit(
                attempt_id=permit.attempt_id,
                step_index=permit.step_index,
                reviewer=permit.reviewer,
                distributed_worker_claim_sha256=(
                    self.distributed_worker_claim.claim_sha256 if self.distributed_worker_claim is not None else ""
                ),
                permit_sha256=permit.permit_sha256,
                action_class=action_class,
                receipt_signature=receipt_signature,
                prior_state_sha256=permit.prior_state_sha256,
                next_state_sha256=next_state,
                committed_at=now,
                commit_sha256="0" * 64,
                runtime_signature="0" * 64,
            )
            digest = sha256_object(_commit_digest_payload(unsigned))
            tmp = unsigned.model_copy(update={"commit_sha256": digest})
            commit = tmp.model_copy(update={"runtime_signature": _hmac(_commit_payload(tmp), self.key)})
            conn.execute(
                "UPDATE actions SET commit_json=? WHERE attempt_id=? AND step_index=?",
                (canonical_json(commit.model_dump(mode="json")), permit.attempt_id, permit.step_index),
            )
            conn.execute(
                "UPDATE attempts SET next_step=?, state_sha256=?, in_flight_permit_sha256=NULL WHERE attempt_id=?",
                (permit.step_index + 1, next_state, permit.attempt_id),
            )
            conn.execute("COMMIT")
            return commit

    def finalize(self, *, attempt_id: str, expected_steps: int) -> RecoveryAtomicExecutionChain:
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._assert_worker(conn)
            row = conn.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            actions = conn.execute(
                "SELECT * FROM actions WHERE attempt_id=? ORDER BY step_index ASC", (attempt_id,)
            ).fetchall()
            if row is None:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-attempt-not-initialized")
            if row["in_flight_permit_sha256"]:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-attempt-has-uncommitted-action")
            if int(row["next_step"]) != expected_steps or len(actions) != expected_steps:
                conn.execute("ROLLBACK")
                raise ValueError("atomic-attempt-incomplete")
            steps: list[RecoveryAtomicActionStep] = []
            for action in actions:
                if action["commit_json"] is None:
                    conn.execute("ROLLBACK")
                    raise ValueError("atomic-attempt-incomplete")
                steps.append(RecoveryAtomicActionStep(
                    permit=RecoveryAtomicActionPermit.model_validate(json.loads(action["permit_json"])),
                    commit=RecoveryAtomicActionCommit.model_validate(json.loads(action["commit_json"])),
                ))
            initial = atomic_initial_state_sha256(attempt_id=attempt_id, attempt_lease_set_sha256=row["lease_set_sha256"])
            unsigned = RecoveryAtomicExecutionChain(
                attempt_id=attempt_id,
                attempt_lease_set_sha256=row["lease_set_sha256"],
                atomic_policy_sha256=row["policy_sha256"],
                initial_state_sha256=initial,
                steps=steps,
                final_state_sha256=row["state_sha256"],
                chain_sha256="0" * 64,
            )
            chain = unsigned.model_copy(update={"chain_sha256": sha256_object(_chain_payload(unsigned))})
            conn.execute("UPDATE attempts SET completed=1 WHERE attempt_id=?", (attempt_id,))
            conn.execute("COMMIT")
            return chain


def verify_atomic_execution_chain(
    chain: RecoveryAtomicExecutionChain,
    *,
    attempt_id: str,
    attempt_lease_set_sha256: str,
    reviewer_order: list[str] | tuple[str, ...],
    traces: list,
    runtime_key: bytes,
    provider_call_chain=None,
) -> list[str]:
    errors: list[str] = []
    if chain.attempt_id != attempt_id:
        errors.append("atomic-chain-attempt-id-mismatch")
    if chain.attempt_lease_set_sha256 != attempt_lease_set_sha256:
        errors.append("atomic-chain-lease-set-mismatch")
    if chain.atomic_policy_sha256 != atomic_execution_policy_sha256():
        errors.append("atomic-chain-policy-mismatch")
    expected_initial = atomic_initial_state_sha256(attempt_id=attempt_id, attempt_lease_set_sha256=attempt_lease_set_sha256)
    if chain.initial_state_sha256 != expected_initial:
        errors.append("atomic-chain-initial-state-mismatch")
    if chain.chain_sha256 != sha256_object(_chain_payload(chain)):
        errors.append("atomic-chain-digest-mismatch")
    if len(chain.steps) != len(reviewer_order) or len(traces) != len(reviewer_order):
        errors.append("atomic-chain-reviewer-cardinality-mismatch")
        return sorted(set(errors))
    state = expected_initial
    for idx, (reviewer, step, trace) in enumerate(zip(reviewer_order, chain.steps, traces)):
        permit, commit = step.permit, step.commit
        if permit.step_index != idx or commit.step_index != idx:
            errors.append(f"atomic-step-index-mismatch:{idx}")
        if permit.reviewer != reviewer or commit.reviewer != reviewer or trace.reviewer != reviewer:
            errors.append(f"atomic-step-reviewer-mismatch:{idx}")
        if permit.attempt_id != attempt_id or commit.attempt_id != attempt_id:
            errors.append(f"atomic-step-attempt-mismatch:{idx}")
        if permit.attempt_lease_set_sha256 != attempt_lease_set_sha256:
            errors.append(f"atomic-step-lease-set-mismatch:{idx}")
        if permit.prior_state_sha256 != state or commit.prior_state_sha256 != state:
            errors.append(f"atomic-step-prior-state-mismatch:{idx}")
        if permit.permit_sha256 != sha256_object(_permit_digest_payload(permit)):
            errors.append(f"atomic-permit-digest-mismatch:{idx}")
        if permit.runtime_signature != _hmac(_permit_payload(permit), runtime_key):
            errors.append(f"atomic-permit-signature-invalid:{idx}")
        provider_id = ""
        if provider_call_chain is not None and idx < len(provider_call_chain.calls):
            provider_id = provider_call_chain.calls[idx].provider_call_id
        expected_context = action_attempt_context_sha256(
            attempt_lease_set_sha256=attempt_lease_set_sha256, permit_sha256=permit.permit_sha256,
            provider_call_id=provider_id,
        )
        if trace.attempt_context_sha256 != expected_context:
            errors.append(f"atomic-review-invocation-context-mismatch:{idx}")
        if commit.permit_sha256 != permit.permit_sha256:
            errors.append(f"atomic-commit-permit-mismatch:{idx}")
        if commit.action_class != trace.action_class:
            errors.append(f"atomic-commit-classification-mismatch:{idx}")
        if commit.receipt_signature != trace.receipt_signature:
            errors.append(f"atomic-commit-receipt-mismatch:{idx}")
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
        state = expected_next
    if chain.final_state_sha256 != state:
        errors.append("atomic-chain-final-state-mismatch")
    return sorted(set(errors))
