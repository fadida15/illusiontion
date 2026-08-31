from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Callable

from pydantic import ValidationError

from .integrity import evidence_digest_map, sha256_object
from .prompts import REVIEWER_PROMPTS
from .receipts import issue_runtime_receipt, model_review_schema_sha256, review_invocation_digest
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


@dataclass(frozen=True)
class ReviewInvocation:
    reviewer: ReviewerName
    invocation_id: str
    run_token: str
    prompt: str
    payload_json: str
    evidence: EvidenceBundle
    claim_sha256: str
    evidence_digests: dict[str, str]
    invocation_sha256: str
    attempt_context_sha256: str = ""


@dataclass(frozen=True)
class ModelReviewCompletion:
    receipt: ReviewerReceipt
    findings: list[ReviewFinding]
    semantic_frames: list[SemanticFrame]
    semantic_obligations: list[SemanticObligationCheck]
    parse_error: str = ""


class IndependentReviewRuntime:
    """Trusted host boundary for pre-gate specialist reviews.

    Each invocation is frozen to a claim/evidence/prompt digest before a model is
    called. Completion will not sign a result if those invocation inputs changed.
    The model-output path strictly parses a schema with no verdict field and then
    stamps the reviewer identity from the trusted invocation role.
    """

    def __init__(
        self,
        *,
        key: bytes,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if len(key) < 32:
            raise ValueError("Runtime key must be at least 32 bytes.")
        self._key = key
        self._id_factory = id_factory or (lambda: secrets.token_hex(16))

    def begin(
        self,
        *,
        reviewer: ReviewerName,
        claim: ClaimCandidate,
        evidence: EvidenceBundle,
        attempt_context_sha256: str = "",
    ) -> ReviewInvocation:
        # E2 reviewer authority is derived from the complete frozen evidence
        # universe E0, never from the candidate-selected transition projection
        # E1 (claim.evidence_ids). Admissions stay outside semantic prompts and
        # are verified separately by the deterministic gate.
        isolated_evidence = EvidenceBundle(items=list(evidence.items))
        invocation_id = f"inv-{self._id_factory()}"
        run_token = f"run-{self._id_factory()}"
        payload = {
            "claim": claim.model_dump(mode="json"),
            "evidence": isolated_evidence.model_dump(mode="json"),
            "reviewer_role": reviewer,
        }
        prompt = REVIEWER_PROMPTS[reviewer]
        invocation_digest = review_invocation_digest(
            reviewer=reviewer,
            claim=claim,
            evidence=isolated_evidence,
            prompt_text=prompt,
            context_mode=ReviewContextMode.ISOLATED,
            upstream_review_digests=[],
            invocation_id=invocation_id,
            run_token=run_token,
            attempt_context_sha256=attempt_context_sha256,
        )
        return ReviewInvocation(
            reviewer=reviewer,
            invocation_id=invocation_id,
            run_token=run_token,
            prompt=prompt,
            payload_json=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            evidence=isolated_evidence,
            claim_sha256=sha256_object(claim),
            evidence_digests=evidence_digest_map(isolated_evidence),
            invocation_sha256=invocation_digest,
            attempt_context_sha256=attempt_context_sha256,
        )

    def _assert_continuity(self, *, invocation: ReviewInvocation, claim: ClaimCandidate) -> None:
        if sha256_object(claim) != invocation.claim_sha256:
            raise ValueError("Invocation continuity failure: claim changed after reviewer begin().")
        if evidence_digest_map(invocation.evidence) != invocation.evidence_digests:
            raise ValueError("Invocation continuity failure: evidence changed after reviewer begin().")
        current_invocation_digest = review_invocation_digest(
            reviewer=invocation.reviewer,
            claim=claim,
            evidence=invocation.evidence,
            prompt_text=invocation.prompt,
            context_mode=ReviewContextMode.ISOLATED,
            upstream_review_digests=[],
            invocation_id=invocation.invocation_id,
            run_token=invocation.run_token,
            attempt_context_sha256=invocation.attempt_context_sha256,
        )
        if current_invocation_digest != invocation.invocation_sha256:
            raise ValueError("Invocation continuity failure: invocation metadata changed.")

    def complete(
        self,
        *,
        invocation: ReviewInvocation,
        claim: ClaimCandidate,
        findings: list[ReviewFinding],
        status: ReviewStatus,
        semantic_frames: list[SemanticFrame] | None = None,
        semantic_obligations: list[SemanticObligationCheck] | None = None,
        detail: str = "",
    ) -> ReviewerReceipt:
        self._assert_continuity(invocation=invocation, claim=claim)
        if any(finding.reviewer != invocation.reviewer for finding in findings):
            raise ValueError("Reviewer output contains a foreign reviewer identity.")
        return issue_runtime_receipt(
            reviewer=invocation.reviewer,
            status=status,
            claim=claim,
            evidence=invocation.evidence,
            findings=findings,
            semantic_frames=semantic_frames or [],
            semantic_obligations=semantic_obligations or [],
            prompt_text=invocation.prompt,
            context_mode=ReviewContextMode.ISOLATED,
            upstream_review_digests=[],
            invocation_id=invocation.invocation_id,
            run_token=invocation.run_token,
            attempt_context_sha256=invocation.attempt_context_sha256,
            execution_mode=ReviewExecutionMode.HOST_FIXTURE,
            detail=detail,
            key=self._key,
        )

    def complete_model_output(
        self,
        *,
        invocation: ReviewInvocation,
        claim: ClaimCandidate,
        raw_output: str,
        model_provider: str,
        model_id: str,
        model_response_id: str,
        execution_mode: ReviewExecutionMode,
    ) -> ModelReviewCompletion:
        """Parse and attest one raw reviewer-model output.

        MODEL_LIVE and MODEL_REPLAY are the only accepted modes here. Malformed
        output is signed as FAILED rather than repaired, guessed, or retried into
        a clean-looking SUCCESS receipt.
        """
        self._assert_continuity(invocation=invocation, claim=claim)
        if execution_mode not in {ReviewExecutionMode.MODEL_LIVE, ReviewExecutionMode.MODEL_REPLAY}:
            raise ValueError("complete_model_output requires MODEL_LIVE or MODEL_REPLAY mode.")
        if not model_provider.strip() or not model_id.strip() or not model_response_id.strip():
            raise ValueError("Model provider, model ID, and response ID must be non-empty.")

        parsed_findings: list[ReviewFinding] = []
        parsed_frames: list[SemanticFrame] = []
        parsed_obligations: list[SemanticObligationCheck] = []
        parse_error = ""
        status = ReviewStatus.SUCCESS
        try:
            parsed = ModelReviewOutput.model_validate_json(raw_output)
            declared_ids = set(invocation.evidence.by_id())
            for item in parsed.findings:
                unknown = sorted(set(item.evidence_ids) - declared_ids)
                if unknown:
                    raise ValueError(
                        "Model finding references evidence outside the reviewer universe: " + ", ".join(unknown)
                    )
                parsed_findings.append(
                    ReviewFinding(
                        reviewer=invocation.reviewer,
                        finding_type=item.finding_type,
                        severity=item.severity,
                        message=item.message,
                        evidence_ids=item.evidence_ids,
                    )
                )
            atom_ids = {atom.atom_id for atom in claim.atoms}
            for frame in parsed.semantic_frames:
                if frame.atom_id not in atom_ids:
                    raise ValueError(f"Semantic frame references unknown atom: {frame.atom_id}")
                parsed_frames.append(SemanticFrame(reviewer=invocation.reviewer, **frame.model_dump(mode="json")))
            for item in parsed.semantic_obligations:
                if item.atom_id not in atom_ids:
                    raise ValueError(f"Semantic obligation references unknown atom: {item.atom_id}")
                refs = set(item.witness_evidence_ids)
                if item.evidence_id:
                    refs.add(item.evidence_id)
                unknown = sorted(refs - declared_ids)
                if unknown:
                    raise ValueError("Semantic obligation references evidence outside reviewer universe: " + ", ".join(unknown))
                parsed_obligations.append(SemanticObligationCheck(reviewer=invocation.reviewer, **item.model_dump(mode="json")))
        except (ValidationError, ValueError) as exc:
            status = ReviewStatus.FAILED
            parsed_findings = []
            parsed_frames = []
            parsed_obligations = []
            parse_error = f"MODEL_OUTPUT_PARSE_FAILURE: {exc}"

        receipt = issue_runtime_receipt(
            reviewer=invocation.reviewer,
            status=status,
            claim=claim,
            evidence=invocation.evidence,
            findings=parsed_findings,
            semantic_frames=parsed_frames,
            semantic_obligations=parsed_obligations,
            prompt_text=invocation.prompt,
            context_mode=ReviewContextMode.ISOLATED,
            upstream_review_digests=[],
            invocation_id=invocation.invocation_id,
            run_token=invocation.run_token,
            attempt_context_sha256=invocation.attempt_context_sha256,
            execution_mode=execution_mode,
            model_provider=model_provider,
            model_id=model_id,
            model_response_id=model_response_id,
            raw_output=raw_output,
            response_schema_sha256=model_review_schema_sha256(),
            detail=parse_error,
            key=self._key,
        )
        return ModelReviewCompletion(receipt=receipt, findings=parsed_findings, semantic_frames=parsed_frames, semantic_obligations=parsed_obligations, parse_error=parse_error)

    def complete_model_failure(
        self,
        *,
        invocation: ReviewInvocation,
        claim: ClaimCandidate,
        status: ReviewStatus,
        model_provider: str,
        model_id: str,
        model_response_id: str,
        detail: str,
        raw_output: str = "",
        execution_mode: ReviewExecutionMode = ReviewExecutionMode.MODEL_LIVE,
    ) -> ModelReviewCompletion:
        """Authenticate a transport/runtime model failure without inventing findings."""
        self._assert_continuity(invocation=invocation, claim=claim)
        if status not in {ReviewStatus.FAILED, ReviewStatus.TIMEOUT, ReviewStatus.LOOP_DETECTED}:
            raise ValueError("Model failure completion requires a non-success terminal status.")
        if execution_mode not in {ReviewExecutionMode.MODEL_LIVE, ReviewExecutionMode.MODEL_REPLAY}:
            raise ValueError("Model failure must be MODEL_LIVE or MODEL_REPLAY.")
        response_id = model_response_id.strip() or f"failure-{invocation.invocation_id}"
        receipt = issue_runtime_receipt(
            reviewer=invocation.reviewer,
            status=status,
            claim=claim,
            evidence=invocation.evidence,
            findings=[],
            prompt_text=invocation.prompt,
            context_mode=ReviewContextMode.ISOLATED,
            upstream_review_digests=[],
            invocation_id=invocation.invocation_id,
            run_token=invocation.run_token,
            attempt_context_sha256=invocation.attempt_context_sha256,
            execution_mode=execution_mode,
            model_provider=model_provider or "unknown-provider",
            model_id=model_id or "unknown-model",
            model_response_id=response_id,
            raw_output=raw_output,
            response_schema_sha256=model_review_schema_sha256(),
            detail=detail,
            key=self._key,
        )
        return ModelReviewCompletion(receipt=receipt, findings=[], semantic_frames=[], semantic_obligations=[], parse_error=detail)
