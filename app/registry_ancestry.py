from __future__ import annotations

import hashlib
import hmac
import os

from .integrity import canonical_json, evidence_digest_map, findings_digest, semantic_artifacts_digest, sha256_object, sha256_text
from .schemas import (
    ClaimCandidate,
    EvidenceBundle,
    ModelReviewOutput,
    ReviewContextMode,
    ReviewExecutionMode,
    ReviewFinding,
    SemanticFrame,
    SemanticObligationCheck,
    ReviewerName,
    ReviewerReceipt,
    ReviewStatus,
)

_MIN_KEY_BYTES = 32


def load_runtime_key() -> bytes:
    raw = os.environ.get("ILLUSIONTION_RECEIPT_KEY", "")
    key = raw.encode("utf-8")
    if len(key) < _MIN_KEY_BYTES:
        raise RuntimeError(
            "ILLUSIONTION_RECEIPT_KEY must be at least 32 bytes; "
            "runtime receipt signing is unavailable."
        )
    return key


def model_review_schema_sha256() -> str:
    return sha256_object(ModelReviewOutput.model_json_schema())


def review_invocation_digest(
    *,
    reviewer: ReviewerName,
    claim: ClaimCandidate,
    evidence: EvidenceBundle,
    prompt_text: str,
    context_mode: ReviewContextMode,
    upstream_review_digests: list[str] | None,
    invocation_id: str,
    run_token: str,
    attempt_context_sha256: str = "",
) -> str:
    """Digest the semantic reviewer invocation before any model output exists."""
    payload = {
        "reviewer": reviewer,
        "claim_sha256": sha256_object(claim),
        "evidence_digests": evidence_digest_map(evidence),
        "prompt_sha256": sha256_text(prompt_text),
        "context_mode": context_mode.value,
        "upstream_review_digests": sorted(upstream_review_digests or []),
        "invocation_id": invocation_id,
        "run_token": run_token,
    }
    # Preserve pre-v0.34 invocation digests byte-for-byte when no attempt context
    # exists. Recovery calls bind the externally leased attempt here before any
    # provider request is made.
    if attempt_context_sha256:
        payload["attempt_context_sha256"] = attempt_context_sha256
    return sha256_object(payload)


def _receipt_payload(
    *,
    reviewer: ReviewerName,
    status: ReviewStatus,
    claim_sha256: str,
    evidence_digests: dict[str, str],
    findings_sha256: str,
    semantic_artifacts_sha256: str,
    prompt_sha256: str,
    context_mode: ReviewContextMode,
    upstream_review_digests: list[str],
    invocation_id: str,
    run_token: str,
    invocation_sha256: str,
    attempt_context_sha256: str,
    execution_mode: ReviewExecutionMode,
    model_provider: str,
    model_id: str,
    model_response_id: str,
    raw_output_sha256: str,
    raw_output_utf8_bytes: int = 0,
    response_schema_sha256: str,
    detail: str,
) -> dict:
    payload = {
        "reviewer": reviewer,
        "status": status.value,
        "claim_sha256": claim_sha256,
        "evidence_digests": evidence_digests,
        "findings_sha256": findings_sha256,
        "semantic_artifacts_sha256": semantic_artifacts_sha256,
        "prompt_sha256": prompt_sha256,
        "context_mode": context_mode.value,
        "upstream_review_digests": sorted(upstream_review_digests),
        "invocation_id": invocation_id,
        "run_token": run_token,
        "invocation_sha256": invocation_sha256,
        "execution_mode": execution_mode.value,
        "model_provider": model_provider,
        "model_id": model_id,
        "model_response_id": model_response_id,
        "raw_output_sha256": raw_output_sha256,
        "response_schema_sha256": response_schema_sha256,
        "detail": detail,
    }
    if raw_output_utf8_bytes:
        payload["raw_output_utf8_bytes"] = raw_output_utf8_bytes
    if attempt_context_sha256:
        payload["attempt_context_sha256"] = attempt_context_sha256
    return payload


def _sign_payload(payload: dict, key: bytes) -> str:
    message = sha256_object(payload).encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def issue_runtime_receipt(
    *,
    reviewer: ReviewerName,
    status: ReviewStatus,
    claim: ClaimCandidate,
    evidence: EvidenceBundle,
    findings: list[ReviewFinding] | None = None,
    semantic_frames: list[SemanticFrame] | None = None,
    semantic_obligations: list[SemanticObligationCheck] | None = None,
    prompt_text: str = "",
    context_mode: ReviewContextMode = ReviewContextMode.ISOLATED,
    upstream_review_digests: list[str] | None = None,
    invocation_id: str,
    run_token: str,
    attempt_context_sha256: str = "",
    execution_mode: ReviewExecutionMode = ReviewExecutionMode.HOST_FIXTURE,
    model_provider: str = "trusted-host",
    model_id: str = "none",
    model_response_id: str = "",
    raw_output: str | None = None,
    response_schema_sha256: str | None = None,
    detail: str = "",
    key: bytes | None = None,
) -> ReviewerReceipt:
    """Trusted-runtime function. Never expose this function as an LLM tool.

    The signature binds the exact input invocation, normalized findings, and—
    for model executions—the exact raw model response digest and schema digest.
    """
    signing_key = key if key is not None else load_runtime_key()
    if len(signing_key) < _MIN_KEY_BYTES:
        raise ValueError("Runtime receipt key must be at least 32 bytes.")

    reviewer_findings = list(findings or [])
    reviewer_frames = list(semantic_frames or [])
    reviewer_obligations = list(semantic_obligations or [])
    if any(finding.reviewer != reviewer for finding in reviewer_findings):
        raise ValueError("Runtime receipt may bind only findings emitted by its reviewer role.")
    if any(frame.reviewer != reviewer for frame in reviewer_frames):
        raise ValueError("Runtime receipt may bind only semantic frames emitted by its reviewer role.")
    if any(item.reviewer != reviewer for item in reviewer_obligations):
        raise ValueError("Runtime receipt may bind only semantic obligations emitted by its reviewer role.")

    upstream = list(upstream_review_digests or [])
    claim_digest = sha256_object(claim)
    digests = evidence_digest_map(evidence)
    output_digest = findings_digest(reviewer_findings)
    semantic_digest = semantic_artifacts_digest(reviewer_frames, reviewer_obligations)
    prompt_digest = sha256_text(prompt_text)
    invocation_digest = review_invocation_digest(
        reviewer=reviewer,
        claim=claim,
        evidence=evidence,
        prompt_text=prompt_text,
        context_mode=context_mode,
        upstream_review_digests=upstream,
        invocation_id=invocation_id,
        run_token=run_token,
        attempt_context_sha256=attempt_context_sha256,
    )
    # Host-fixture receipts still bind a deterministic representation of the
    # normalized findings. Model-bound receipts pass the literal raw response.
    raw = raw_output if raw_output is not None else canonical_json(
        [finding.model_dump(mode="json") for finding in reviewer_findings]
    )
    raw_digest = sha256_text(raw)
    raw_size = len(raw.encode("utf-8")) if raw_output is not None else 0
    schema_digest = response_schema_sha256 or model_review_schema_sha256()

    payload = _receipt_payload(
        reviewer=reviewer,
        status=status,
        claim_sha256=claim_digest,
        evidence_digests=digests,
        findings_sha256=output_digest,
        semantic_artifacts_sha256=semantic_digest,
        prompt_sha256=prompt_digest,
        context_mode=context_mode,
        upstream_review_digests=upstream,
        invocation_id=invocation_id,
        run_token=run_token,
        invocation_sha256=invocation_digest,
        attempt_context_sha256=attempt_context_sha256,
        execution_mode=execution_mode,
        model_provider=model_provider,
        model_id=model_id,
        model_response_id=model_response_id,
        raw_output_sha256=raw_digest,
        raw_output_utf8_bytes=raw_size,
        response_schema_sha256=schema_digest,
        detail=detail,
    )
    return ReviewerReceipt(
        reviewer=reviewer,
        status=status,
        claim_sha256=claim_digest,
        evidence_digests=digests,
        findings_sha256=output_digest,
        semantic_artifacts_sha256=semantic_digest,
        prompt_sha256=prompt_digest,
        context_mode=context_mode,
        upstream_review_digests=upstream,
        invocation_id=invocation_id,
        run_token=run_token,
        invocation_sha256=invocation_digest,
        attempt_context_sha256=attempt_context_sha256,
        execution_mode=execution_mode,
        model_provider=model_provider,
        model_id=model_id,
        model_response_id=model_response_id,
        raw_output_sha256=raw_digest,
        raw_output_utf8_bytes=raw_size,
        response_schema_sha256=schema_digest,
        detail=detail,
        runtime_signature=_sign_payload(payload, signing_key),
    )


def verify_runtime_receipt(receipt: ReviewerReceipt, key: bytes) -> bool:
    if len(key) < _MIN_KEY_BYTES:
        return False
    payload = _receipt_payload(
        reviewer=receipt.reviewer,
        status=receipt.status,
        claim_sha256=receipt.claim_sha256,
        evidence_digests=receipt.evidence_digests,
        findings_sha256=receipt.findings_sha256,
        semantic_artifacts_sha256=receipt.semantic_artifacts_sha256,
        prompt_sha256=receipt.prompt_sha256,
        context_mode=receipt.context_mode,
        upstream_review_digests=receipt.upstream_review_digests,
        invocation_id=receipt.invocation_id,
        run_token=receipt.run_token,
        invocation_sha256=receipt.invocation_sha256,
        attempt_context_sha256=receipt.attempt_context_sha256,
        execution_mode=receipt.execution_mode,
        model_provider=receipt.model_provider,
        model_id=receipt.model_id,
        model_response_id=receipt.model_response_id,
        raw_output_sha256=receipt.raw_output_sha256,
        raw_output_utf8_bytes=receipt.raw_output_utf8_bytes,
        response_schema_sha256=receipt.response_schema_sha256,
        detail=receipt.detail,
    )
    expected = _sign_payload(payload, key)
    return hmac.compare_digest(expected, receipt.runtime_signature)
