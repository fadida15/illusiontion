from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .integrity import canonical_json, sha256_object
from .sqlite_utils import managed_sqlite_connection
from .schemas import (
    RecoveryAtomicExecutionChain,
    RecoveryDistributedExecutionSeal,
    RecoveryDistributedWorkerClaim,
    RecoveryProviderCallChain,
)

_MIN_KEY_BYTES = 32
_ZERO = "0" * 64
_POLICY = {
    "domain": "ILLUSIONTION_DISTRIBUTED_RECOVERY_EXECUTION_V0_39",
    "worker_rule": "ONE_CURRENT_FENCING_EPOCH_PER_DETERMINISTIC_ATTEMPT",
    "takeover_rule": "EXPLICIT_TAKEOVER_ADVANCES_EPOCH_AND_FENCES_PRIOR_WORKER",
    "mutation_rule": "EVERY_SHARED_STATE_MUTATION_REQUIRES_CURRENT_WORKER_CLAIM",
    "publication_rule": "ONE_RERUN_CORE_PER_DETERMINISTIC_ATTEMPT",
    "authority_scope": "CONCURRENCY_ONLY_NEVER_UPGRADES_VERDICT",
    "storage_assumption": "SHARED_TRANSACTIONAL_NON_ROLLBACK_STATE",
}


def distributed_execution_policy_sha256() -> str:
    return sha256_object(_POLICY)


def _hmac(payload: dict, key: bytes) -> str:
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError("Distributed execution runtime key must be at least 32 bytes.")
    return hmac.new(key, sha256_object(payload).encode("ascii"), hashlib.sha256).hexdigest()


def _claim_payload(value: RecoveryDistributedWorkerClaim | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("runtime_signature", None)
    return row


def _claim_digest_payload(value: RecoveryDistributedWorkerClaim | dict) -> dict:
    row = _claim_payload(value)
    row.pop("claim_sha256", None)
    return row


def _seal_payload(value: RecoveryDistributedExecutionSeal | dict) -> dict:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop("runtime_signature", None)
    return row


def _seal_digest_payload(value: RecoveryDistributedExecutionSeal | dict) -> dict:
    row = _seal_payload(value)
    row.pop("publication_sha256", None)
    return row


def verify_worker_claim_signature(claim: RecoveryDistributedWorkerClaim, runtime_key: bytes) -> list[str]:
    errors: list[str] = []
    if claim.claim_sha256 != sha256_object(_claim_digest_payload(claim)):
        errors.append("distributed-worker-claim-digest-mismatch")
    if claim.runtime_signature != _hmac(_claim_payload(claim), runtime_key):
        errors.append("distributed-worker-claim-signature-invalid")
    return errors


def assert_current_worker_conn(
    conn: sqlite3.Connection,
    *,
    claim: RecoveryDistributedWorkerClaim | None,
    runtime_key: bytes,
    required: bool,
    allow_published: bool = False,
) -> None:
    if claim is None:
        if required:
            raise ValueError("distributed-worker-claim-required")
        return
    errors = verify_worker_claim_signature(claim, runtime_key)
    if errors:
        raise ValueError(errors[0])
    row = conn.execute(
        "SELECT current_epoch,current_claim_sha256,published_core_sha256 FROM distributed_attempts WHERE attempt_id=?",
        (claim.attempt_id,),
    ).fetchone()
    if row is None:
        raise ValueError("distributed-worker-attempt-not-claimed")
    if int(row["current_epoch"]) != claim.epoch or row["current_claim_sha256"] != claim.claim_sha256:
        raise ValueError("distributed-worker-fenced-by-newer-epoch")
    if row["published_core_sha256"] and not allow_published:
        raise ValueError("distributed-attempt-already-published")


class DistributedRecoveryCoordinator:
    """Shared-state worker fencing and single-assignment rerun publication.

    Every process invocation receives one unique worker epoch. A later explicit
    takeover advances the epoch. Mutating atomic/provider stores verify the current
    epoch inside their own SQLite write transaction, preventing a stale worker from
    committing after takeover. The same shared state finally single-assigns one
    rerun core for the deterministic attempt.

    Cloning or rolling back this database remains an explicit deployment boundary.
    """

    def __init__(self, *, path: str | Path, runtime_key: bytes) -> None:
        if len(runtime_key) < _MIN_KEY_BYTES:
            raise ValueError("Distributed execution runtime key must be at least 32 bytes.")
        self.path = str(path)
        self.key = runtime_key
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS distributed_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    current_epoch INTEGER NOT NULL,
                    current_claim_sha256 TEXT NOT NULL,
                    reserved_publication_at TEXT,
                    reserved_publication_claim_sha256 TEXT,
                    published_core_sha256 TEXT,
                    publication_json TEXT,
                    created_at TEXT NOT NULL
                )"""
            )
            cols = {row[1] for row in conn.execute("PRAGMA table_info(distributed_attempts)").fetchall()}
            if "reserved_publication_at" not in cols:
                conn.execute("ALTER TABLE distributed_attempts ADD COLUMN reserved_publication_at TEXT")
            if "reserved_publication_claim_sha256" not in cols:
                conn.execute("ALTER TABLE distributed_attempts ADD COLUMN reserved_publication_claim_sha256 TEXT")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS distributed_worker_claims (
                    attempt_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    claim_sha256 TEXT NOT NULL UNIQUE,
                    claim_json TEXT NOT NULL,
                    PRIMARY KEY(attempt_id, epoch)
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def claim_worker(self, *, attempt_id: str, worker_id: str, takeover: bool = False) -> RecoveryDistributedWorkerClaim:
        if not worker_id.strip():
            raise ValueError("distributed-worker-id-empty")
        now = datetime.now(timezone.utc).isoformat()
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM distributed_attempts WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if row is None:
                if takeover:
                    conn.execute("ROLLBACK")
                    raise ValueError("distributed-worker-takeover-without-existing-claim")
                epoch = 1
                prior = _ZERO
            else:
                if row["published_core_sha256"]:
                    conn.execute("ROLLBACK")
                    raise ValueError("distributed-attempt-already-published")
                if not takeover:
                    conn.execute("ROLLBACK")
                    raise ValueError("distributed-attempt-already-owned-requires-explicit-takeover")
                epoch = int(row["current_epoch"]) + 1
                prior = str(row["current_claim_sha256"])
            unsigned = RecoveryDistributedWorkerClaim(
                attempt_id=attempt_id,
                worker_id=worker_id,
                epoch=epoch,
                prior_claim_sha256=prior,
                takeover=bool(takeover),
                claim_nonce=secrets.token_hex(24),
                claimed_at=now,
                claim_sha256=_ZERO,
                runtime_signature=_ZERO,
            )
            digest = sha256_object(_claim_digest_payload(unsigned))
            tmp = unsigned.model_copy(update={"claim_sha256": digest})
            claim = tmp.model_copy(update={"runtime_signature": _hmac(_claim_payload(tmp), self.key)})
            if row is None:
                conn.execute(
                    "INSERT INTO distributed_attempts(attempt_id,current_epoch,current_claim_sha256,created_at) VALUES(?,?,?,?)",
                    (attempt_id, epoch, claim.claim_sha256, now),
                )
            else:
                conn.execute(
                    "UPDATE distributed_attempts SET current_epoch=?,current_claim_sha256=?,reserved_publication_at=NULL,reserved_publication_claim_sha256=NULL WHERE attempt_id=?",
                    (epoch, claim.claim_sha256, attempt_id),
                )
            conn.execute(
                "INSERT INTO distributed_worker_claims(attempt_id,epoch,claim_sha256,claim_json) VALUES(?,?,?,?)",
                (attempt_id, epoch, claim.claim_sha256, canonical_json(claim.model_dump(mode="json"))),
            )
            conn.execute("COMMIT")
        return claim

    def reserve_publication_time(self, *, claim: RecoveryDistributedWorkerClaim) -> str:
        """Single-assign the rerun publication clock to the current worker epoch.

        Publisher head/transparency checks are evaluated against this shared time.
        A takeover clears any unconsumed reservation so the new worker cannot be
        forced to use a timestamp reserved by a fenced process.
        """
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM distributed_attempts WHERE attempt_id=?", (claim.attempt_id,)
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise ValueError("distributed-worker-attempt-not-claimed")
            if row["published_core_sha256"]:
                if row["reserved_publication_claim_sha256"] == claim.claim_sha256 and row["reserved_publication_at"]:
                    value = str(row["reserved_publication_at"])
                    conn.execute("ROLLBACK")
                    return value
                conn.execute("ROLLBACK")
                raise ValueError("distributed-attempt-already-published")
            assert_current_worker_conn(conn, claim=claim, runtime_key=self.key, required=True)
            if row["reserved_publication_at"]:
                if row["reserved_publication_claim_sha256"] != claim.claim_sha256:
                    conn.execute("ROLLBACK")
                    raise ValueError("distributed-publication-time-reserved-by-different-worker")
                value = str(row["reserved_publication_at"])
                conn.execute("COMMIT")
                return value
            value = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE distributed_attempts SET reserved_publication_at=?,reserved_publication_claim_sha256=? WHERE attempt_id=?",
                (value, claim.claim_sha256, claim.attempt_id),
            )
            conn.execute("COMMIT")
            return value


    def publish(
        self,
        *,
        claim: RecoveryDistributedWorkerClaim,
        rerun_core_sha256: str,
        atomic_chain_sha256: str,
        provider_call_chain_sha256: str,
        atomic_finalization_seal_sha256: str,
        execution_trajectory_sha256: str,
    ) -> RecoveryDistributedExecutionSeal:
        with managed_sqlite_connection(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM distributed_attempts WHERE attempt_id=?", (claim.attempt_id,)
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise ValueError("distributed-worker-attempt-not-claimed")
            if row["published_core_sha256"]:
                if row["published_core_sha256"] != rerun_core_sha256:
                    conn.execute("ROLLBACK")
                    raise ValueError("distributed-rerun-core-already-published-different-value")
                seal = RecoveryDistributedExecutionSeal.model_validate(json.loads(row["publication_json"]))
                conn.execute("ROLLBACK")
                return seal
            assert_current_worker_conn(conn, claim=claim, runtime_key=self.key, required=True)
            if row["reserved_publication_at"]:
                if row["reserved_publication_claim_sha256"] != claim.claim_sha256:
                    conn.execute("ROLLBACK")
                    raise ValueError("distributed-publication-time-reserved-by-different-worker")
                now = str(row["reserved_publication_at"])
            else:
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "UPDATE distributed_attempts SET reserved_publication_at=?,reserved_publication_claim_sha256=? WHERE attempt_id=?",
                    (now, claim.claim_sha256, claim.attempt_id),
                )
            claim_rows = conn.execute(
                "SELECT claim_json FROM distributed_worker_claims WHERE attempt_id=? ORDER BY epoch ASC",
                (claim.attempt_id,),
            ).fetchall()
            claims = [RecoveryDistributedWorkerClaim.model_validate(json.loads(x["claim_json"])) for x in claim_rows]
            unsigned = RecoveryDistributedExecutionSeal(
                attempt_id=claim.attempt_id,
                distributed_policy_sha256=distributed_execution_policy_sha256(),
                worker_claims=claims,
                final_worker_claim_sha256=claim.claim_sha256,
                atomic_chain_sha256=atomic_chain_sha256,
                provider_call_chain_sha256=provider_call_chain_sha256,
                atomic_finalization_seal_sha256=atomic_finalization_seal_sha256,
                execution_trajectory_sha256=execution_trajectory_sha256,
                rerun_core_sha256=rerun_core_sha256,
                published_at=now,
                publication_sha256=_ZERO,
                runtime_signature=_ZERO,
            )
            digest = sha256_object(_seal_digest_payload(unsigned))
            tmp = unsigned.model_copy(update={"publication_sha256": digest})
            seal = tmp.model_copy(update={"runtime_signature": _hmac(_seal_payload(tmp), self.key)})
            conn.execute(
                "UPDATE distributed_attempts SET published_core_sha256=?,publication_json=? WHERE attempt_id=?",
                (rerun_core_sha256, canonical_json(seal.model_dump(mode="json")), claim.attempt_id),
            )
            conn.execute("COMMIT")
        return seal


def verify_distributed_execution_seal(
    seal: RecoveryDistributedExecutionSeal,
    *,
    attempt_id: str,
    rerun_core_sha256: str,
    atomic_chain: RecoveryAtomicExecutionChain,
    provider_chain: RecoveryProviderCallChain,
    atomic_finalization_seal_sha256: str,
    execution_trajectory_sha256: str,
    runtime_key: bytes,
) -> list[str]:
    errors: list[str] = []
    if seal.attempt_id != attempt_id:
        errors.append("distributed-publication-attempt-id-mismatch")
    if seal.distributed_policy_sha256 != distributed_execution_policy_sha256():
        errors.append("distributed-publication-policy-mismatch")
    if seal.rerun_core_sha256 != rerun_core_sha256:
        errors.append("distributed-publication-rerun-core-mismatch")
    if seal.atomic_chain_sha256 != atomic_chain.chain_sha256:
        errors.append("distributed-publication-atomic-chain-mismatch")
    if seal.provider_call_chain_sha256 != provider_chain.chain_sha256:
        errors.append("distributed-publication-provider-chain-mismatch")
    if seal.atomic_finalization_seal_sha256 != atomic_finalization_seal_sha256:
        errors.append("distributed-publication-anchor-seal-mismatch")
    if seal.execution_trajectory_sha256 != execution_trajectory_sha256:
        errors.append("distributed-publication-trajectory-mismatch")
    if seal.publication_sha256 != sha256_object(_seal_digest_payload(seal)):
        errors.append("distributed-publication-digest-mismatch")
    if seal.runtime_signature != _hmac(_seal_payload(seal), runtime_key):
        errors.append("distributed-publication-signature-invalid")

    claims = seal.worker_claims
    if not claims:
        errors.append("distributed-worker-claim-chain-empty")
        return sorted(set(errors))
    by_hash: dict[str, RecoveryDistributedWorkerClaim] = {}
    for idx, claim in enumerate(claims, start=1):
        for e in verify_worker_claim_signature(claim, runtime_key):
            errors.append(f"{e}:{idx}")
        if claim.attempt_id != attempt_id:
            errors.append(f"distributed-worker-claim-attempt-mismatch:{idx}")
        if claim.epoch != idx:
            errors.append(f"distributed-worker-claim-epoch-gap:{idx}")
        expected_prior = _ZERO if idx == 1 else claims[idx - 2].claim_sha256
        if claim.prior_claim_sha256 != expected_prior:
            errors.append(f"distributed-worker-claim-prior-mismatch:{idx}")
        if idx == 1 and claim.takeover:
            errors.append("distributed-worker-first-claim-cannot-be-takeover")
        if idx > 1 and not claim.takeover:
            errors.append(f"distributed-worker-successor-must-be-explicit-takeover:{idx}")
        if claim.claim_sha256 in by_hash:
            errors.append(f"distributed-worker-claim-duplicate:{idx}")
        by_hash[claim.claim_sha256] = claim
    if seal.final_worker_claim_sha256 != claims[-1].claim_sha256:
        errors.append("distributed-publication-final-worker-claim-mismatch")

    def epoch_for(value: str, label: str) -> int | None:
        if not value:
            errors.append(f"{label}-missing-worker-claim")
            return None
        claim = by_hash.get(value)
        if claim is None:
            errors.append(f"{label}-unknown-worker-claim")
            return None
        return claim.epoch

    prior_commit_epoch = 1
    reconciliations = {r.step_index: r for r in provider_chain.reconciliations}
    for idx, (step, call) in enumerate(zip(atomic_chain.steps, provider_chain.calls)):
        pe = epoch_for(step.permit.distributed_worker_claim_sha256, f"distributed-step-{idx}-permit")
        ce = epoch_for(step.commit.distributed_worker_claim_sha256, f"distributed-step-{idx}-commit")
        ve = epoch_for(call.distributed_worker_claim_sha256, f"distributed-step-{idx}-provider")
        if pe is not None and pe < prior_commit_epoch:
            errors.append(f"distributed-step-worker-epoch-regression:{idx}")
        if pe is not None and ve is not None and ve < pe:
            errors.append(f"distributed-provider-before-permit-worker-epoch:{idx}")
        if ve is not None and ce is not None and ce < ve:
            errors.append(f"distributed-commit-before-provider-worker-epoch:{idx}")
        rec = reconciliations.get(idx)
        if rec is not None:
            re = epoch_for(rec.distributed_worker_claim_sha256, f"distributed-step-{idx}-reconciliation")
            if ve is not None and re is not None and re < ve:
                errors.append(f"distributed-reconciliation-worker-epoch-regression:{idx}")
            if re is not None and ce is not None and ce < re:
                errors.append(f"distributed-commit-before-reconciliation-worker-epoch:{idx}")
        if ce is not None:
            prior_commit_epoch = ce
    final_epoch = by_hash.get(seal.final_worker_claim_sha256).epoch if seal.final_worker_claim_sha256 in by_hash else None
    if final_epoch is not None and final_epoch < prior_commit_epoch:
        errors.append("distributed-publication-final-worker-precedes-last-commit")
    return sorted(set(errors))
