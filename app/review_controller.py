from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .integrity import canonical_json, sha256_object


class ExecutionResourceBudget(BaseModel):
    """v0.46 plan-committed aggregate execution/resource envelope.

    These limits are deliberately finite and fail closed. They are not performance
    targets and they never create positive verdict authority.
    """

    model_config = ConfigDict(extra="forbid")

    max_manifest_cases: int = Field(default=128, ge=1, le=4096)
    max_json_file_utf8_bytes: int = Field(default=8 * 1024 * 1024, ge=64 * 1024, le=64 * 1024 * 1024)
    max_case_utf8_bytes: int = Field(default=2 * 1024 * 1024, ge=64 * 1024, le=16 * 1024 * 1024)
    max_evidence_items_per_case: int = Field(default=128, ge=1, le=512)
    max_evidence_bundle_utf8_bytes: int = Field(default=1024 * 1024, ge=32 * 1024, le=16 * 1024 * 1024)
    max_single_evidence_excerpt_utf8_bytes: int = Field(default=128 * 1024, ge=1024, le=1024 * 1024)
    max_candidate_output_utf8_bytes: int = Field(default=256 * 1024, ge=4096, le=4 * 1024 * 1024)
    max_reviewer_input_utf8_bytes: int = Field(default=2 * 1024 * 1024, ge=64 * 1024, le=16 * 1024 * 1024)
    max_reviewer_output_utf8_bytes: int = Field(default=256 * 1024, ge=4096, le=4 * 1024 * 1024)
    max_review_artifacts_total: int = Field(default=2048, ge=16, le=16384)
    max_recovery_submissions: int = Field(default=128, ge=1, le=4096)
    max_recovery_outcome_records: int = Field(default=4096, ge=1, le=100000)
    max_challenge_observations: int = Field(default=2048, ge=1, le=4096)
    max_audit_records: int = Field(default=4096, ge=1, le=100000)
    max_observation_provenances: int = Field(default=4096, ge=1, le=100000)
    max_transparency_extension_entries: int = Field(default=2048, ge=1, le=100000)
    candidate_wall_clock_seconds: float = Field(default=45.0, gt=0.0, le=120.0)
    reviewer_wall_clock_seconds: float = Field(default=30.0, gt=0.0, le=120.0)


def default_v046_resource_budget() -> ExecutionResourceBudget:
    return ExecutionResourceBudget()


def resource_budget_sha256(budget: ExecutionResourceBudget) -> str:
    return sha256_object({
        "domain": "ILLUSIONTION_RESOURCE_BUDGET_V0_46",
        "budget": budget.model_dump(mode="json"),
    })


def utf8_len(value: str) -> int:
    return len(value.encode("utf-8"))


def canonical_utf8_len(value: Any) -> int:
    return utf8_len(canonical_json(value))


def enforce_json_file_size(path: str, budget: ExecutionResourceBudget) -> None:
    from pathlib import Path

    size = Path(path).stat().st_size
    if size > budget.max_json_file_utf8_bytes:
        raise ValueError(
            f"resource-budget-json-file-exceeded:{size}>{budget.max_json_file_utf8_bytes}"
        )


def enforce_manifest_budget(manifest: Any, budget: ExecutionResourceBudget) -> None:
    cases = list(manifest.cases)
    if len(cases) > budget.max_manifest_cases:
        raise ValueError(
            f"resource-budget-manifest-cases-exceeded:{len(cases)}>{budget.max_manifest_cases}"
        )
    for case in cases:
        case_bytes = canonical_utf8_len(case.model_dump(mode="json"))
        if case_bytes > budget.max_case_utf8_bytes:
            raise ValueError(
                f"resource-budget-case-bytes-exceeded:{case.case_id}:{case_bytes}>{budget.max_case_utf8_bytes}"
            )
        enforce_evidence_bundle_budget(case.evidence, budget, label=f"case:{case.case_id}")


def enforce_evidence_bundle_budget(evidence: Any, budget: ExecutionResourceBudget, *, label: str = "evidence") -> None:
    items = list(evidence.items)
    if len(items) > budget.max_evidence_items_per_case:
        raise ValueError(
            f"resource-budget-evidence-items-exceeded:{label}:{len(items)}>{budget.max_evidence_items_per_case}"
        )
    total = canonical_utf8_len(evidence.model_dump(mode="json"))
    if total > budget.max_evidence_bundle_utf8_bytes:
        raise ValueError(
            f"resource-budget-evidence-bytes-exceeded:{label}:{total}>{budget.max_evidence_bundle_utf8_bytes}"
        )
    for item in items:
        excerpt_bytes = utf8_len(item.excerpt)
        if excerpt_bytes > budget.max_single_evidence_excerpt_utf8_bytes:
            raise ValueError(
                f"resource-budget-evidence-excerpt-exceeded:{label}:{item.evidence_id}:{excerpt_bytes}>{budget.max_single_evidence_excerpt_utf8_bytes}"
            )


def enforce_candidate_output_budget(raw_output: str, budget: ExecutionResourceBudget) -> None:
    size = utf8_len(raw_output)
    if size > budget.max_candidate_output_utf8_bytes:
        raise ValueError(
            f"resource-budget-candidate-output-exceeded:{size}>{budget.max_candidate_output_utf8_bytes}"
        )


def enforce_reviewer_input_budget(payload_json: str, budget: ExecutionResourceBudget, *, reviewer: str) -> None:
    size = utf8_len(payload_json)
    if size > budget.max_reviewer_input_utf8_bytes:
        raise ValueError(
            f"resource-budget-reviewer-input-exceeded:{reviewer}:{size}>{budget.max_reviewer_input_utf8_bytes}"
        )


def enforce_reviewer_output_budget(raw_output: str, budget: ExecutionResourceBudget, *, reviewer: str) -> None:
    size = utf8_len(raw_output)
    if size > budget.max_reviewer_output_utf8_bytes:
        raise ValueError(
            f"resource-budget-reviewer-output-exceeded:{reviewer}:{size}>{budget.max_reviewer_output_utf8_bytes}"
        )


def enforce_review_bundle_budget(review: Any, budget: ExecutionResourceBudget) -> None:
    total = len(review.findings) + len(review.semantic_frames) + len(review.semantic_obligations)
    if total > budget.max_review_artifacts_total:
        raise ValueError(
            f"resource-budget-review-artifacts-exceeded:{total}>{budget.max_review_artifacts_total}"
        )


def enforce_recovery_submission_budget(submissions: Any, budget: ExecutionResourceBudget) -> None:
    count = len(submissions.submissions)
    if count > budget.max_recovery_submissions:
        raise ValueError(
            f"resource-budget-recovery-submissions-exceeded:{count}>{budget.max_recovery_submissions}"
        )
    for case_id, submission in submissions.submissions.items():
        if len(submission.recovery_outcome_records) > budget.max_recovery_outcome_records:
            raise ValueError(f"resource-budget-recovery-outcomes-exceeded:{case_id}")
        if len(submission.challenge_observations) > budget.max_challenge_observations:
            raise ValueError(f"resource-budget-challenge-observations-exceeded:{case_id}")
        if len(submission.audit_records) > budget.max_audit_records:
            raise ValueError(f"resource-budget-audit-records-exceeded:{case_id}")
        if len(submission.observation_provenances) > budget.max_observation_provenances:
            raise ValueError(f"resource-budget-observation-provenances-exceeded:{case_id}")
        proof_entries = sum(
            len(proof.extension_entries)
            for proof in submission.rerun.publisher_transparency_proofs
        )
        if proof_entries > budget.max_transparency_extension_entries:
            raise ValueError(
                f"resource-budget-transparency-extension-exceeded:{case_id}:{proof_entries}>{budget.max_transparency_extension_entries}"
            )


def enforce_recovery_rerun_budget(record_or_evidence: Any, budget: ExecutionResourceBudget) -> None:
    evidence = getattr(record_or_evidence, "recovery_evidence", record_or_evidence)
    enforce_evidence_bundle_budget(evidence, budget, label="recovery")
