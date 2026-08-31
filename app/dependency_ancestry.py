from __future__ import annotations

from collections import Counter

from .schemas import (
    DecisionCalibrationAssurance,
    DecisionUsefulnessAssurance,
    FindingType,
    ReviewFinding,
    Verdict,
)

# v0.20 separates *why* a HOLD occurred from whether the HOLD is authoritative.
# These buckets are calibration/measurement metadata only. They never override
# PASS/HOLD/REJECT and are intentionally not confidence scores.
_EVIDENCE_DEBT = {
    FindingType.INSUFFICIENT_EVIDENCE,
    FindingType.STALE_EVIDENCE,
    FindingType.ATOMIC_COVERAGE_GAP,
    FindingType.SOURCE_DIVERSITY_GAP,
    FindingType.SOURCE_PROVENANCE_MISSING,
    FindingType.EVIDENCE_ORIGIN_DIVERSITY_GAP,
}

_SEMANTIC_DEBT = {
    FindingType.DECOMPOSITION_GAP,
    FindingType.ENTAILMENT_GAP,
    FindingType.SEMANTIC_REVIEW_COVERAGE_GAP,
    FindingType.REPRESENTATION_DISAGREEMENT,
    FindingType.SEMANTIC_OBLIGATION_GAP,
}

_CLAIM_CONFLICT = {
    FindingType.CONTRADICTION,
    FindingType.SCOPE_INFLATION,
    FindingType.COUNTEREXAMPLE_FOUND,
    FindingType.SEMANTIC_OBLIGATION_FAILED,
    FindingType.EXTERNAL_WITNESS_COUNTEREXAMPLE,
}

# Process/security/provenance faults are not candidates for policy relaxation.
_HARD_RISK_FINDINGS = {
    FindingType.PROMPT_INJECTION,
    FindingType.MALFORMED_EVIDENCE,
    FindingType.REVIEWER_ROLE_VIOLATION,
    FindingType.EVIDENCE_TAMPER,
    FindingType.INVALID_RUNTIME_RECEIPT,
    FindingType.REVIEW_OUTPUT_TAMPER,
    FindingType.REVIEW_CONTEXT_CONTAMINATION,
    FindingType.DUPLICATE_REVIEW_INVOCATION,
    FindingType.DUPLICATE_ATOMIC_CLAIM,
    FindingType.EVIDENCE_ADMISSION_MISSING,
    FindingType.INVALID_EVIDENCE_ADMISSION,
    FindingType.EVIDENCE_ACQUISITION_FAILED,
    FindingType.DUPLICATE_EVIDENCE_CAPTURE,
    FindingType.MODEL_EXECUTION_UNBOUND,
    FindingType.MODEL_OUTPUT_MALFORMED,
    FindingType.MODEL_SCHEMA_MISMATCH,
    FindingType.DUPLICATE_MODEL_RESPONSE,
    FindingType.INVOCATION_CONTINUITY_FAILURE,
    FindingType.EVIDENCE_SPACE_VIOLATION,
    FindingType.MATERIAL_TRANSITION_LEAKAGE,
    FindingType.EXTERNAL_WITNESS_GAP,
    FindingType.EXTERNAL_WITNESS_INVALID,
    FindingType.EXTERNAL_WITNESS_NOT_INDEPENDENT,
    FindingType.EXTERNAL_WITNESS_UNRESOLVED,
    FindingType.WITNESS_SELECTION_INVALID,
    FindingType.WITNESS_AUTHORITY_QUORUM_GAP,
    FindingType.WITNESS_AUTHORITY_DISAGREEMENT,
    FindingType.WITNESS_CHALLENGE_SUBSTITUTION,
    FindingType.WITNESS_MEASUREMENT_PROVENANCE_INVALID,
    FindingType.WITNESS_DEPENDENCY_DIVERSITY_GAP,
    FindingType.WITNESS_MEASUREMENT_AUTHORITY_GAP,
    FindingType.WITNESS_ANCESTRY_INVALID,
    FindingType.WITNESS_ANCESTRY_OVERLAP,
    FindingType.WITNESS_REGISTRY_INVALID,
    FindingType.WITNESS_REGISTRY_DISCLOSURE_GAP,
    FindingType.WITNESS_REGISTRY_ANCESTRY_INVALID,
    FindingType.WITNESS_REGISTRY_ANCESTRY_OVERLAP,
    FindingType.WITNESS_REGISTRY_OBSERVATION_INVALID,
    FindingType.WITNESS_REGISTRY_OBSERVATION_DISCLOSURE_GAP,
}

_HARD_USEFULNESS_BLOCKERS = {
    "EVIDENCE_ADMISSION_INTEGRITY",
    "RUNTIME_KEY_UNAVAILABLE",
    "CLAIM_EVIDENCE_SET_EMPTY",
    "MISSING_EVIDENCE_OBJECT",
    "MISSING_REQUIRED_REVIEWER",
    "INVALID_RUNTIME_RECEIPT",
    "REVIEWER_EXECUTION_FAILURE",
    "REVIEW_CONTEXT_CONTAMINATION",
    "REVIEW_PROMPT_MISMATCH",
    "INVOCATION_CONTINUITY_FAILURE",
    "MODEL_EXECUTION_UNBOUND",
    "DUPLICATE_MODEL_RESPONSE",
    "DUPLICATE_REVIEW_INVOCATION",
    "REVIEW_BINDING_MISMATCH",
    "REVIEW_OUTPUT_TAMPER",
    "SEMANTIC_ARTIFACT_TAMPER",
    "REVIEWER_ROLE_VIOLATION",
    "BAD_EVIDENCE_REFERENCE",
    "EVIDENCE_SPACE_ADDITION",
    "EVIDENCE_SPACE_MUTATION",
    "MATERIAL_TRANSITION_LEAKAGE",
    "SEMANTIC_REVIEW_COVERAGE_GAP",
    "EXTERNAL_WITNESS_LAYER_HOLD",
    "WITNESS_QUORUM_LAYER_HOLD",
    "WITNESS_PROVENANCE_LAYER_HOLD",
    "WITNESS_ANCESTRY_LAYER_HOLD",
    "WITNESS_REGISTRY_LAYER_HOLD",
    "WITNESS_REGISTRY_ANCESTRY_LAYER_HOLD",
    "WITNESS_REGISTRY_OBSERVATION_LAYER_HOLD",
    "DUPLICATE_ATOMIC_CLAIM",
}


def assess_decision_calibration(
    *,
    verdict: Verdict,
    findings: list[ReviewFinding],
    usefulness_assurance: DecisionUsefulnessAssurance | None,
) -> DecisionCalibrationAssurance:
    """Classify decision friction without changing decision authority.

    A RECOVERABLE-like bucket means only that the observed blocker is the kind
    of debt a future policy experiment may study. It is *not* permission to
    promote, and automatic_relaxation_allowed is always False in v0.20.
    """

    if verdict == Verdict.PASS:
        return DecisionCalibrationAssurance(
            status="CLEAR_PASS",
            evidence_debt=[] , semantic_debt=[], claim_conflicts=[], hard_risks=[],
            blocker_counts={}, recovery_actions=[], automatic_relaxation_allowed=False,
        )
    if verdict == Verdict.REJECT:
        return DecisionCalibrationAssurance(
            status="REJECTED",
            evidence_debt=[], semantic_debt=[], claim_conflicts=["FABRICATION_OR_REJECT_BOUNDARY"],
            hard_risks=[], blocker_counts={"REJECT": 1},
            recovery_actions=["Correct the rejected claim/evidence and rerun the full assurance path."],
            automatic_relaxation_allowed=False,
        )

    evidence_debt: list[str] = []
    semantic_debt: list[str] = []
    claim_conflicts: list[str] = []
    hard_risks: list[str] = []

    for finding in findings:
        token = finding.finding_type.value
        if finding.finding_type in _HARD_RISK_FINDINGS:
            hard_risks.append(token)
        elif finding.finding_type in _CLAIM_CONFLICT:
            claim_conflicts.append(token)
        elif finding.finding_type in _SEMANTIC_DEBT:
            semantic_debt.append(token)
        elif finding.finding_type in _EVIDENCE_DEBT:
            evidence_debt.append(token)
        elif finding.finding_type == FindingType.FABRICATION:
            claim_conflicts.append(token)
        else:
            # Unknown/new blocking finding types default to hard rather than
            # accidentally entering a future relaxation bucket.
            hard_risks.append(token)

    if usefulness_assurance is not None:
        for blocker in usefulness_assurance.global_blockers:
            if blocker in _HARD_USEFULNESS_BLOCKERS:
                hard_risks.append(blocker)

    evidence_debt = list(dict.fromkeys(evidence_debt))
    semantic_debt = list(dict.fromkeys(semantic_debt))
    claim_conflicts = list(dict.fromkeys(claim_conflicts))
    hard_risks = list(dict.fromkeys(hard_risks))

    active_classes = sum(bool(group) for group in (evidence_debt, semantic_debt, claim_conflicts, hard_risks))
    if hard_risks:
        status = "HARD_INTEGRITY_HOLD" if active_classes == 1 else "MIXED_HOLD"
    elif claim_conflicts:
        status = "CLAIM_CONFLICT_HOLD" if active_classes == 1 else "MIXED_HOLD"
    elif evidence_debt and semantic_debt:
        status = "MIXED_HOLD"
    elif evidence_debt:
        status = "EVIDENCE_DEBT_HOLD"
    elif semantic_debt:
        status = "SEMANTIC_DEBT_HOLD"
    else:
        status = "HARD_INTEGRITY_HOLD"
        hard_risks = ["UNCLASSIFIED_HOLD"]

    counts = Counter(evidence_debt + semantic_debt + claim_conflicts + hard_risks)
    recovery_actions = []
    if evidence_debt:
        recovery_actions.append("Repair or refresh the identified evidence debt, then rerun; do not auto-promote.")
    if semantic_debt:
        recovery_actions.append("Resolve the semantic/entailment debt with new independent work products, then rerun.")
    if claim_conflicts:
        recovery_actions.append("Reconcile or narrow the claim conflict before any promotion attempt.")
    if hard_risks:
        recovery_actions.append("Repair the integrity/security/provenance boundary and rerun the complete path.")

    return DecisionCalibrationAssurance(
        status=status,
        evidence_debt=evidence_debt,
        semantic_debt=semantic_debt,
        claim_conflicts=claim_conflicts,
        hard_risks=hard_risks,
        blocker_counts=dict(sorted(counts.items())),
        recovery_actions=recovery_actions,
        automatic_relaxation_allowed=False,
    )


def shadow_policy_would_promote(status: str, policy: str) -> bool:
    """Benchmark-only policy simulation; never used by the decision gate."""
    if status == "CLEAR_PASS":
        return True
    if policy == "BASELINE_NO_RELAXATION":
        return False
    if policy == "NAIVE_EVIDENCE_DEBT_RELEASE":
        return status == "EVIDENCE_DEBT_HOLD"
    if policy == "NAIVE_SEMANTIC_DEBT_RELEASE":
        return status == "SEMANTIC_DEBT_HOLD"
    if policy == "NAIVE_ALL_DEBT_RELEASE":
        return status in {"EVIDENCE_DEBT_HOLD", "SEMANTIC_DEBT_HOLD"}
    raise ValueError(f"unknown shadow calibration policy: {policy}")
