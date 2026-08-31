from __future__ import annotations

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .integrity import canonical_json, sha256_object
from .schemas import (
    RecoveryAttemptLease,
    RecoveryAttemptLeaseSet,
    RecoveryAttemptStateCheckpoint,
    RecoveryAttemptWitnessSpec,
    RecoveryExecutionTrajectory,
    RecoveryTrajectoryStep,
    ReviewBundle,
    ReviewStatus,
)


_POLICY = {
    "domain": "ILLUSIONTION_OBSERVABLE_TRAJECTORY_CLASSIFIER_V0_34",
    "inputs": [
        "reviewer_role",
        "runtime_status",
        "finding_severity",
        "finding_evidence_ids",
        "semantic_obligation_results",
        "semantic_obligation_evidence_ids",
        "model_id",
        "model_response_id",
        "runtime_receipt_signature",
    ],
    "classes": [
        "EXECUTION_FAILURE",
        "CRITICAL_FINDING",
        "SEMANTIC_CONFLICT",
        "CAUTION",
        "SEMANTIC_SUPPORT",
        "CLEAN",
        "OBSERVATION",
    ],
    "authority": "NEGATIVE_ONLY_MEMORY_NEVER_UPGRADES_VERDICT",
}

_NEGATIVE_RESULTS = {
    "CONTRADICTS",
    "VIOLATED",
    "UNRESOLVED",
    "SCOPE_GAP",
    "COUNTEREXAMPLE_FOUND",
}
_POSITIVE_RESULTS = {
    "SUPPORTS",
    "SATISFIED",
    "WITHIN_SCOPE",
    "NO_COUNTEREXAMPLE_FOUND",
}


def _pub(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _unsigned_payload(value, signature_field: str) -> bytes:
    row = value.model_dump(mode="json") if hasattr(value, "model_dump") else dict(value)
    row.pop(signature_field, None)
    return canonical_json(row).encode("utf-8")


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def behavior_classification_policy_sha256() -> str:
    return sha256_object(_POLICY)


def recovery_attempt_id(*, campaign_id: str, case_id: str, original_run_sha256: str, rerun_id: str) -> str:
    return sha256_object(
        {
            "domain": "ILLUSIONTION_RECOVERY_ATTEMPT_ID_V0_34",
            "campaign_id": campaign_id,
            "case_id": case_id,
            "original_run_sha256": original_run_sha256,
            "rerun_id": rerun_id,
        }
    )


def attempt_checkpoint_sha256(checkpoint: RecoveryAttemptStateCheckpoint) -> str:
    return sha256_object(checkpoint)


def issue_recovery_attempt_state_checkpoint(
    *, witness_id: str, sequence: int, state_sha256: str, issued_at: str, private_key: Ed25519PrivateKey
) -> RecoveryAttemptStateCheckpoint:
    unsigned = RecoveryAttemptStateCheckpoint(
        witness_id=witness_id,
        witness_public_key=_pub(private_key),
        sequence=sequence,
        state_sha256=state_sha256,
        issued_at=issued_at,
        witness_signature="0" * 128,
    )
    return unsigned.model_copy(
        update={"witness_signature": private_key.sign(_unsigned_payload(unsigned, "witness_signature")).hex()}
    )


def verify_recovery_attempt_state_checkpoint(checkpoint: RecoveryAttemptStateCheckpoint) -> list[str]:
    errors: list[str] = []
    try:
        if len(checkpoint.state_sha256) != 64:
            raise ValueError
        int(checkpoint.state_sha256, 16)
    except Exception:
        errors.append("attempt-state-checkpoint-root-invalid")
    if _parse_time(checkpoint.issued_at) is None:
        errors.append("attempt-state-checkpoint-time-invalid")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(checkpoint.witness_public_key))
        key.verify(bytes.fromhex(checkpoint.witness_signature), _unsigned_payload(checkpoint, "witness_signature"))
    except Exception:
        errors.append("attempt-state-checkpoint-signature-invalid")
    return sorted(set(errors))


def advance_attempt_state(
    *, prior_state_sha256: str, leased_sequence: int, campaign_id: str, case_id: str,
    original_run_sha256: str, rerun_id: str, attempt_id: str, classification_policy_sha256: str
) -> str:
    return sha256_object(
        {
            "domain": "ILLUSIONTION_STATEFUL_RECOVERY_SLOT_CONSUMPTION_V0_34",
            "prior_state_sha256": prior_state_sha256,
            "leased_sequence": leased_sequence,
            "campaign_id": campaign_id,
            "case_id": case_id,
            "original_run_sha256": original_run_sha256,
            "rerun_id": rerun_id,
            "attempt_id": attempt_id,
            "classification_policy_sha256": classification_policy_sha256,
        }
    )


def issue_recovery_attempt_lease(
    *, spec: RecoveryAttemptWitnessSpec, campaign_id: str, case_id: str, original_run_sha256: str,
    rerun_id: str, leased_at: str, private_key: Ed25519PrivateKey
) -> RecoveryAttemptLease:
    if _pub(private_key) != spec.witness_public_key:
        raise ValueError("Recovery attempt lease signing key does not match committed witness.")
    anchor = spec.anchor_checkpoint
    attempt_id = recovery_attempt_id(
        campaign_id=campaign_id, case_id=case_id, original_run_sha256=original_run_sha256, rerun_id=rerun_id
    )
    policy_sha = behavior_classification_policy_sha256()
    leased_sequence = anchor.sequence + 1
    leased_state = advance_attempt_state(
        prior_state_sha256=anchor.state_sha256,
        leased_sequence=leased_sequence,
        campaign_id=campaign_id,
        case_id=case_id,
        original_run_sha256=original_run_sha256,
        rerun_id=rerun_id,
        attempt_id=attempt_id,
        classification_policy_sha256=policy_sha,
    )
    successor_checkpoint = issue_recovery_attempt_state_checkpoint(
        witness_id=spec.witness_id,
        sequence=leased_sequence,
        state_sha256=leased_state,
        issued_at=leased_at,
        private_key=private_key,
    )
    unsigned = RecoveryAttemptLease(
        witness_id=spec.witness_id,
        witness_public_key=spec.witness_public_key,
        anchor_checkpoint_sha256=attempt_checkpoint_sha256(anchor),
        campaign_id=campaign_id,
        case_id=case_id,
        original_run_sha256=original_run_sha256,
        rerun_id=rerun_id,
        attempt_id=attempt_id,
        classification_policy_sha256=policy_sha,
        prior_sequence=anchor.sequence,
        prior_state_sha256=anchor.state_sha256,
        leased_sequence=leased_sequence,
        leased_state_sha256=leased_state,
        leased_at=leased_at,
        successor_checkpoint=successor_checkpoint,
        witness_signature="0" * 128,
    )
    return unsigned.model_copy(
        update={"witness_signature": private_key.sign(_unsigned_payload(unsigned, "witness_signature")).hex()}
    )


def verify_recovery_attempt_lease(
    lease: RecoveryAttemptLease,
    *, spec: RecoveryAttemptWitnessSpec, campaign_id: str, case_id: str, original_run_sha256: str,
    rerun_id: str, runtime_issued_at: str, max_age_seconds: int
) -> list[str]:
    errors: list[str] = []
    anchor = spec.anchor_checkpoint
    errors.extend(verify_recovery_attempt_state_checkpoint(anchor))
    checks = {
        "attempt-witness-id-mismatch": lease.witness_id == spec.witness_id,
        "attempt-witness-key-mismatch": lease.witness_public_key == spec.witness_public_key,
        "attempt-anchor-mismatch": lease.anchor_checkpoint_sha256 == attempt_checkpoint_sha256(anchor),
        "attempt-campaign-mismatch": lease.campaign_id == campaign_id,
        "attempt-case-mismatch": lease.case_id == case_id,
        "attempt-original-run-mismatch": lease.original_run_sha256 == original_run_sha256,
        "attempt-rerun-slot-mismatch": lease.rerun_id == rerun_id,
        "attempt-prior-sequence-mismatch": lease.prior_sequence == anchor.sequence,
        "attempt-prior-state-mismatch": lease.prior_state_sha256 == anchor.state_sha256,
        "attempt-leased-sequence-mismatch": lease.leased_sequence == anchor.sequence + 1,
        "attempt-classification-policy-mismatch": lease.classification_policy_sha256 == behavior_classification_policy_sha256(),
    }
    errors.extend(name for name, ok in checks.items() if not ok)
    expected_attempt_id = recovery_attempt_id(
        campaign_id=campaign_id, case_id=case_id, original_run_sha256=original_run_sha256, rerun_id=rerun_id
    )
    if lease.attempt_id != expected_attempt_id:
        errors.append("attempt-id-mismatch")
    expected_state = advance_attempt_state(
        prior_state_sha256=anchor.state_sha256,
        leased_sequence=anchor.sequence + 1,
        campaign_id=campaign_id,
        case_id=case_id,
        original_run_sha256=original_run_sha256,
        rerun_id=rerun_id,
        attempt_id=expected_attempt_id,
        classification_policy_sha256=behavior_classification_policy_sha256(),
    )
    if lease.leased_state_sha256 != expected_state:
        errors.append("attempt-leased-state-mismatch")
    successor = lease.successor_checkpoint
    successor_errors = verify_recovery_attempt_state_checkpoint(successor)
    errors.extend(f"attempt-successor:{x}" for x in successor_errors)
    if successor.witness_id != spec.witness_id or successor.witness_public_key != spec.witness_public_key:
        errors.append("attempt-successor-witness-mismatch")
    if successor.sequence != lease.leased_sequence:
        errors.append("attempt-successor-sequence-mismatch")
    if successor.state_sha256 != lease.leased_state_sha256:
        errors.append("attempt-successor-state-mismatch")
    if successor.issued_at != lease.leased_at:
        errors.append("attempt-successor-time-mismatch")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(lease.witness_public_key))
        key.verify(bytes.fromhex(lease.witness_signature), _unsigned_payload(lease, "witness_signature"))
    except Exception:
        errors.append("attempt-lease-signature-invalid")
    lease_time = _parse_time(lease.leased_at)
    runtime_time = _parse_time(runtime_issued_at)
    if lease_time is None or runtime_time is None:
        errors.append("attempt-lease-time-unverifiable")
    else:
        if lease_time > runtime_time:
            errors.append("attempt-lease-after-rerun-seal")
        elif (runtime_time - lease_time).total_seconds() > max_age_seconds:
            errors.append("attempt-lease-stale")
    return sorted(set(errors))


def issue_recovery_attempt_lease_set(
    *, specs: list[RecoveryAttemptWitnessSpec], campaign_id: str, case_id: str, original_run_sha256: str,
    rerun_id: str, leased_at: str, private_keys: list[Ed25519PrivateKey]
) -> RecoveryAttemptLeaseSet:
    if len(specs) != len(private_keys):
        raise ValueError("Recovery attempt witness/key cardinality mismatch.")
    attempt_id = recovery_attempt_id(
        campaign_id=campaign_id, case_id=case_id, original_run_sha256=original_run_sha256, rerun_id=rerun_id
    )
    policy_sha = behavior_classification_policy_sha256()
    leases = [
        issue_recovery_attempt_lease(
            spec=spec, campaign_id=campaign_id, case_id=case_id, original_run_sha256=original_run_sha256,
            rerun_id=rerun_id, leased_at=leased_at, private_key=key,
        )
        for spec, key in zip(specs, private_keys)
    ]
    return RecoveryAttemptLeaseSet(
        campaign_id=campaign_id,
        case_id=case_id,
        original_run_sha256=original_run_sha256,
        rerun_id=rerun_id,
        attempt_id=attempt_id,
        classification_policy_sha256=policy_sha,
        leases=leases,
    )


def verify_recovery_attempt_lease_set(
    lease_set: RecoveryAttemptLeaseSet,
    *, specs: list[RecoveryAttemptWitnessSpec], quorum: int, campaign_id: str, case_id: str,
    original_run_sha256: str, rerun_id: str, runtime_issued_at: str, max_age_seconds: int
) -> list[str]:
    errors: list[str] = []
    expected_attempt_id = recovery_attempt_id(
        campaign_id=campaign_id, case_id=case_id, original_run_sha256=original_run_sha256, rerun_id=rerun_id
    )
    expected_policy = behavior_classification_policy_sha256()
    if lease_set.campaign_id != campaign_id or lease_set.case_id != case_id:
        errors.append("attempt-lease-set-campaign-case-mismatch")
    if lease_set.original_run_sha256 != original_run_sha256:
        errors.append("attempt-lease-set-original-run-mismatch")
    if lease_set.rerun_id != rerun_id:
        errors.append("attempt-lease-set-rerun-mismatch")
    if lease_set.attempt_id != expected_attempt_id:
        errors.append("attempt-lease-set-attempt-id-mismatch")
    if lease_set.classification_policy_sha256 != expected_policy:
        errors.append("attempt-lease-set-classification-policy-mismatch")
    spec_by_id = {x.witness_id: x for x in specs}
    valid: set[str] = set()
    for lease in lease_set.leases:
        spec = spec_by_id.get(lease.witness_id)
        if spec is None:
            errors.append(f"attempt-lease-uncommitted-witness:{lease.witness_id}")
            continue
        lease_errors = verify_recovery_attempt_lease(
            lease,
            spec=spec,
            campaign_id=campaign_id,
            case_id=case_id,
            original_run_sha256=original_run_sha256,
            rerun_id=rerun_id,
            runtime_issued_at=runtime_issued_at,
            max_age_seconds=max_age_seconds,
        )
        if lease_errors:
            errors.extend(f"{lease.witness_id}:{x}" for x in lease_errors)
        else:
            valid.add(lease.witness_id)
    if len(valid) < quorum:
        errors.append(f"attempt-lease-quorum-not-met:required={quorum}:valid={len(valid)}")
    return sorted(set(errors))


def _step_payload(step: RecoveryTrajectoryStep | dict) -> dict:
    row = step.model_dump(mode="json") if hasattr(step, "model_dump") else dict(step)
    row.pop("step_sha256", None)
    return row


def classify_observable_completion(*, receipt, findings, obligations) -> str:
    if receipt.status != ReviewStatus.SUCCESS:
        return "EXECUTION_FAILURE"
    severities = {x.severity.value for x in findings}
    results = {x.result.value for x in obligations}
    if "CRITICAL" in severities:
        return "CRITICAL_FINDING"
    if results & _NEGATIVE_RESULTS:
        return "SEMANTIC_CONFLICT"
    if "WARNING" in severities:
        return "CAUTION"
    if results and results <= _POSITIVE_RESULTS:
        return "SEMANTIC_SUPPORT"
    if not findings and not obligations:
        return "CLEAN"
    return "OBSERVATION"


def build_recovery_execution_trajectory(
    *, attempt_id: str, attempt_lease_set_sha256: str, review: ReviewBundle, traces: list
) -> RecoveryExecutionTrajectory:
    receipts = review.receipts_by_reviewer()
    findings_by = {name: [] for name in receipts}
    obligations_by = {name: [] for name in receipts}
    for item in review.findings:
        findings_by.setdefault(item.reviewer, []).append(item)
    for item in review.semantic_obligations:
        obligations_by.setdefault(item.reviewer, []).append(item)
    previous = "0" * 64
    steps: list[RecoveryTrajectoryStep] = []
    for idx, trace in enumerate(traces):
        receipt = receipts[trace.reviewer]
        findings = findings_by.get(trace.reviewer, [])
        obligations = obligations_by.get(trace.reviewer, [])
        evidence_ids: set[str] = set()
        for item in findings:
            evidence_ids.update(item.evidence_ids)
        for item in obligations:
            if item.evidence_id:
                evidence_ids.add(item.evidence_id)
            evidence_ids.update(item.witness_evidence_ids)
        unsigned = RecoveryTrajectoryStep(
            step_index=idx,
            reviewer=trace.reviewer,
            action_class=classify_observable_completion(receipt=receipt, findings=findings, obligations=obligations),
            evidence_ids=sorted(evidence_ids),
            finding_severities=sorted(x.severity.value for x in findings),
            semantic_results=sorted(x.result.value for x in obligations),
            model_id=receipt.model_id,
            model_response_id=receipt.model_response_id,
            receipt_signature=receipt.runtime_signature,
            previous_step_sha256=previous,
            step_sha256="0" * 64,
        )
        digest = sha256_object(_step_payload(unsigned))
        step = unsigned.model_copy(update={"step_sha256": digest})
        steps.append(step)
        previous = digest
    classes = {x.action_class for x in steps}
    if "EXECUTION_FAILURE" in classes:
        overall = "FAILED_TRAJECTORY"
    elif classes & {"CRITICAL_FINDING", "SEMANTIC_CONFLICT"}:
        overall = "CONFLICT_TRAJECTORY"
    elif "CAUTION" in classes:
        overall = "CAUTION_TRAJECTORY"
    elif classes <= {"SEMANTIC_SUPPORT", "CLEAN", "OBSERVATION"} and "SEMANTIC_SUPPORT" in classes:
        overall = "SUPPORT_TRAJECTORY"
    else:
        overall = "MIXED_TRAJECTORY"
    unsigned_trajectory = RecoveryExecutionTrajectory(
        attempt_id=attempt_id,
        attempt_lease_set_sha256=attempt_lease_set_sha256,
        classification_policy_sha256=behavior_classification_policy_sha256(),
        steps=steps,
        overall_class=overall,
        trajectory_sha256="0" * 64,
    )
    payload = unsigned_trajectory.model_dump(mode="json")
    payload.pop("trajectory_sha256", None)
    digest = sha256_object(payload)
    return unsigned_trajectory.model_copy(update={"trajectory_sha256": digest})


def verify_recovery_execution_trajectory(
    trajectory: RecoveryExecutionTrajectory,
    *, attempt_id: str, attempt_lease_set_sha256: str, review: ReviewBundle, traces: list
) -> list[str]:
    errors: list[str] = []
    receipts = review.receipts_by_reviewer()
    findings_by = {name: [] for name in receipts}
    obligations_by = {name: [] for name in receipts}
    for item in review.findings:
        findings_by.setdefault(item.reviewer, []).append(item)
    for item in review.semantic_obligations:
        obligations_by.setdefault(item.reviewer, []).append(item)
    for trace in traces:
        expected_class = classify_observable_completion(
            receipt=receipts[trace.reviewer],
            findings=findings_by.get(trace.reviewer, []),
            obligations=obligations_by.get(trace.reviewer, []),
        )
        if getattr(trace, "action_class", "UNCLASSIFIED") != expected_class:
            errors.append(f"recovery-mid-completion-classification-mismatch:{trace.reviewer}")
    expected = build_recovery_execution_trajectory(
        attempt_id=attempt_id,
        attempt_lease_set_sha256=attempt_lease_set_sha256,
        review=review,
        traces=traces,
    )
    if trajectory.model_dump(mode="json") != expected.model_dump(mode="json"):
        errors.append("recovery-execution-trajectory-mismatch")
    if trajectory.classification_policy_sha256 != behavior_classification_policy_sha256():
        errors.append("recovery-execution-classification-policy-mismatch")
    return sorted(set(errors))
