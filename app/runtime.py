from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
import os

from .attempt_continuity import classify_observable_completion
from .atomic_execution import action_attempt_context_sha256
from .provider_execution import ProviderCallUncertainError, provider_call_id
from .interruption import RecoveryInterruptionError
from .state_integrity import require_recovery_state_integrity
from .gate import REQUIRED_REVIEWERS, SEMANTIC_REVIEWERS, required_reviewers_for_claim
from .integrity import sha256_text
from .model_adapter import GeminiInteractionsReviewer
from .runtime import IndependentReviewRuntime
from .timeouts import call_with_wall_clock_timeout
from .resource_governance import ExecutionResourceBudget, enforce_reviewer_input_budget, enforce_reviewer_output_budget, enforce_review_bundle_budget
from .schemas import (
    AssuranceProfile,
    ClaimCandidate,
    EvidenceBundle,
    ReviewBundle,
    ReviewExecutionMode,
    ReviewStatus,
)

REVIEW_ORDER = ("decomposer", "evidence", "challenger", "scope", "security")
SEMANTIC_REVIEW_ORDER = ("entailment", "counterexample")
assert set(REVIEW_ORDER) == REQUIRED_REVIEWERS
assert set(SEMANTIC_REVIEW_ORDER) == SEMANTIC_REVIEWERS


def review_order_for_profile(profile: AssuranceProfile) -> tuple[str, ...]:
    ordered = REVIEW_ORDER + SEMANTIC_REVIEW_ORDER
    if profile in {AssuranceProfile.SEMANTIC_FORTIFIED, AssuranceProfile.REPRESENTATION_FORTIFIED, AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED, AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        return ordered
    return REVIEW_ORDER


def review_order_for_claim(claim: ClaimCandidate) -> tuple[str, ...]:
    return review_order_for_profile(claim.assurance_profile)


@dataclass(frozen=True)
class ModelReviewTrace:
    reviewer: str
    invocation_id: str
    run_token: str
    invocation_sha256: str
    attempt_context_sha256: str
    action_class: str
    status: str
    execution_mode: str
    model_provider: str
    model_id: str
    model_response_id: str
    raw_output: str
    raw_output_sha256: str
    raw_output_utf8_bytes: int
    detail: str
    receipt_signature: str


def execute_model_reviews_traced(
    *,
    claim: ClaimCandidate,
    evidence: EvidenceBundle,
    runtime: IndependentReviewRuntime,
    adapter: GeminiInteractionsReviewer | Mapping[str, GeminiInteractionsReviewer],
    execution_mode: ReviewExecutionMode = ReviewExecutionMode.MODEL_LIVE,
    timeout_seconds: float | None = None,
    attempt_context_sha256: str = "",
    atomic_action_store=None,
    atomic_attempt_id: str = "",
    atomic_lease_set_sha256: str = "",
    provider_call_store=None,
    resume_interrupted: bool = False,
    resource_budget: ExecutionResourceBudget | None = None,
) -> tuple[ReviewBundle, list[ModelReviewTrace]]:
    """Execute isolated reviews and preserve raw traces.

    v0.38 adds deterministic restart semantics for governed recovery attempts.
    Previously committed actions are reconstructed from durable provider records.
    A provider completion durably recorded before the crash may be replayed through
    the trusted parser and committed without another network call. Any provider
    call left IN_FLIGHT/UNCERTAIN after restart fails closed and is never reissued.
    """
    if timeout_seconds is None:
        timeout_seconds = float(os.getenv("ILLUSIONTION_REVIEW_TIMEOUT_SECONDS", "30"))
    receipts = []
    findings = []
    semantic_frames = []
    semantic_obligations = []
    traces: list[ModelReviewTrace] = []

    def append_completion(*, reviewer, invocation, completion, raw_output: str) -> None:
        if resource_budget is not None and raw_output:
            enforce_reviewer_output_budget(raw_output, resource_budget, reviewer=reviewer)
        action_class = classify_observable_completion(
            receipt=completion.receipt,
            findings=completion.findings,
            obligations=completion.semantic_obligations,
        )
        receipts.append(completion.receipt)
        findings.extend(completion.findings)
        semantic_frames.extend(completion.semantic_frames)
        semantic_obligations.extend(completion.semantic_obligations)
        traces.append(
            ModelReviewTrace(
                reviewer=reviewer,
                invocation_id=invocation.invocation_id,
                run_token=invocation.run_token,
                invocation_sha256=invocation.invocation_sha256,
                attempt_context_sha256=invocation.attempt_context_sha256,
                action_class=action_class,
                status=completion.receipt.status.value,
                execution_mode=completion.receipt.execution_mode.value,
                model_provider=completion.receipt.model_provider,
                model_id=completion.receipt.model_id,
                model_response_id=completion.receipt.model_response_id,
                raw_output=raw_output,
                raw_output_sha256=sha256_text(raw_output),
                raw_output_utf8_bytes=completion.receipt.raw_output_utf8_bytes,
                detail=completion.receipt.detail,
                receipt_signature=completion.receipt.runtime_signature,
            )
        )

    reviewer_order = review_order_for_claim(claim)
    if resume_interrupted and atomic_action_store is not None and provider_call_store is not None:
        if getattr(atomic_action_store, "require_distributed_claim", False):
            require_recovery_state_integrity(
                db_path=atomic_action_store.path, attempt_id=atomic_attempt_id, reviewer_order=reviewer_order,
                runtime_key=atomic_action_store.key, require_distributed_claim=True,
            )
    for step_index, reviewer in enumerate(reviewer_order):
        selected_adapter = adapter.get(reviewer) if isinstance(adapter, Mapping) else adapter
        if selected_adapter is None:
            raise ValueError(f"No model adapter configured for required reviewer {reviewer}.")
        if provider_call_store is not None and getattr(selected_adapter, "no_automatic_retry", False) is not True:
            raise ValueError("v0.37+ provider-call authority requires an adapter with automatic retries disabled.")

        permit = None
        governed_provider_call_id = ""
        action_context = attempt_context_sha256
        existing_commit = None
        provider_state = None

        if atomic_action_store is not None:
            if not atomic_attempt_id or not atomic_lease_set_sha256:
                raise ValueError("Atomic recovery execution requires attempt ID and lease-set digest.")
            if resume_interrupted:
                permit = atomic_action_store.load_permit(attempt_id=atomic_attempt_id, step_index=step_index)
                existing_commit = atomic_action_store.load_commit(attempt_id=atomic_attempt_id, step_index=step_index)
                if provider_call_store is not None:
                    provider_state = provider_call_store.state_for_step(
                        attempt_id=atomic_attempt_id, step_index=step_index
                    )

                # A prior committed action is reconstructed from the exact durable
                # provider response so the restarted process can rebuild the whole
                # review bundle without another model call.
                if existing_commit is not None:
                    if provider_call_store is None or provider_state != "COMPLETED":
                        raise RecoveryInterruptionError("committed-action-missing-durable-provider-completion")
                    completion, invocation, raw_output, _ = provider_call_store.replay_completed_call(
                        attempt_id=atomic_attempt_id,
                        step_index=step_index,
                        claim=claim,
                        runtime=runtime,
                        execution_mode=execution_mode,
                        record_reconciliation=False,
                    )
                    action_class = classify_observable_completion(
                        receipt=completion.receipt,
                        findings=completion.findings,
                        obligations=completion.semantic_obligations,
                    )
                    if existing_commit.action_class != action_class:
                        raise RecoveryInterruptionError("committed-action-classification-replay-mismatch")
                    if existing_commit.receipt_signature != completion.receipt.runtime_signature:
                        raise RecoveryInterruptionError("committed-action-receipt-replay-mismatch")
                    append_completion(
                        reviewer=reviewer, invocation=invocation, completion=completion, raw_output=raw_output
                    )
                    continue

                if permit is not None and provider_call_store is not None:
                    governed_provider_call_id = provider_call_id(
                        attempt_id=atomic_attempt_id,
                        step_index=step_index,
                        reviewer=reviewer,
                        atomic_permit_sha256=permit.permit_sha256,
                    )
                    if provider_state == "COMPLETED":
                        completion, invocation, raw_output, _ = provider_call_store.replay_completed_call(
                            attempt_id=atomic_attempt_id,
                            step_index=step_index,
                            claim=claim,
                            runtime=runtime,
                            execution_mode=execution_mode,
                            record_reconciliation=True,
                        )
                        action_class = classify_observable_completion(
                            receipt=completion.receipt,
                            findings=completion.findings,
                            obligations=completion.semantic_obligations,
                        )
                        atomic_action_store.commit(
                            permit=permit,
                            action_class=action_class,
                            receipt_signature=completion.receipt.runtime_signature,
                        )
                        append_completion(
                            reviewer=reviewer, invocation=invocation, completion=completion, raw_output=raw_output
                        )
                        continue
                    if provider_state == "IN_FLIGHT":
                        provider_call_store.mark_uncertain(
                            provider_call_id_value=governed_provider_call_id,
                            detail="PROCESS_RESTART_WITH_IN_FLIGHT_PROVIDER_CALL",
                        )
                        raise ProviderCallUncertainError(
                            "provider-call-in-flight-after-restart-no-retry-permitted"
                        )
                    if provider_state == "UNCERTAIN":
                        raise ProviderCallUncertainError(
                            "provider-call-uncertain-after-restart-no-retry-permitted"
                        )
                    if provider_state is not None:
                        raise RecoveryInterruptionError(
                            f"unknown-provider-state-after-restart:{provider_state}"
                        )
                elif permit is not None and provider_call_store is None:
                    raise RecoveryInterruptionError("in-flight-atomic-permit-without-provider-ledger")

            if permit is None:
                permit = atomic_action_store.authorize(
                    attempt_id=atomic_attempt_id, step_index=step_index, reviewer=reviewer
                )
            if provider_call_store is not None and not governed_provider_call_id:
                governed_provider_call_id = provider_call_id(
                    attempt_id=atomic_attempt_id,
                    step_index=step_index,
                    reviewer=reviewer,
                    atomic_permit_sha256=permit.permit_sha256,
                )
            action_context = action_attempt_context_sha256(
                attempt_lease_set_sha256=atomic_lease_set_sha256,
                permit_sha256=permit.permit_sha256,
                provider_call_id=governed_provider_call_id,
            )

        invocation = runtime.begin(
            reviewer=reviewer, claim=claim, evidence=evidence, attempt_context_sha256=action_context
        )
        if resource_budget is not None:
            enforce_reviewer_input_budget(invocation.payload_json, resource_budget, reviewer=reviewer)
        if provider_call_store is not None:
            provider_call_store.begin_call(
                permit=permit,
                invocation_sha256=invocation.invocation_sha256,
                expected_call_id=governed_provider_call_id,
                invocation=invocation,
            )
        raw_output = ""
        provider = "google-gemini-interactions"
        model_id = getattr(selected_adapter, "model", "unknown-model")
        response_id = f"failure-{invocation.invocation_id}"
        try:
            response = call_with_wall_clock_timeout(lambda: selected_adapter.run(invocation), timeout_seconds)
        except TimeoutError as exc:
            if provider_call_store is not None:
                provider_call_store.mark_uncertain(
                    provider_call_id_value=governed_provider_call_id,
                    detail=f"MODEL_TRANSPORT_TIMEOUT: {exc}",
                )
                raise ProviderCallUncertainError(
                    "provider-call-timeout-uncertain-no-retry-permitted"
                ) from exc
            response_id = f"timeout-{invocation.invocation_id}"
            completion = runtime.complete_model_failure(
                invocation=invocation,
                claim=claim,
                status=ReviewStatus.TIMEOUT,
                model_provider=provider,
                model_id=model_id,
                model_response_id=response_id,
                detail=f"MODEL_TRANSPORT_TIMEOUT: {exc}",
                execution_mode=execution_mode,
            )
        except Exception as exc:
            if provider_call_store is not None:
                provider_call_store.mark_uncertain(
                    provider_call_id_value=governed_provider_call_id,
                    detail=f"MODEL_TRANSPORT_FAILURE: {type(exc).__name__}: {exc}",
                )
                raise ProviderCallUncertainError(
                    "provider-call-transport-uncertain-no-retry-permitted"
                ) from exc
            completion = runtime.complete_model_failure(
                invocation=invocation,
                claim=claim,
                status=ReviewStatus.FAILED,
                model_provider=provider,
                model_id=model_id,
                model_response_id=response_id,
                detail=f"MODEL_TRANSPORT_FAILURE: {type(exc).__name__}: {exc}",
                execution_mode=execution_mode,
            )
        else:
            provider = response.provider
            model_id = response.model_id
            response_id = response.response_id
            try:
                if resource_budget is not None:
                    enforce_reviewer_output_budget(response.output_text, resource_budget, reviewer=reviewer)
            except ValueError as exc:
                if provider_call_store is not None:
                    provider_call_store.mark_uncertain(
                        provider_call_id_value=governed_provider_call_id,
                        detail=f"MODEL_RESOURCE_LIMIT_EXCEEDED: {exc}",
                    )
                    raise ProviderCallUncertainError("provider-output-resource-limit-exceeded-no-retry-permitted") from exc
                completion = runtime.complete_model_failure(
                    invocation=invocation, claim=claim, status=ReviewStatus.FAILED,
                    model_provider=provider, model_id=model_id, model_response_id=response_id,
                    detail=f"MODEL_RESOURCE_LIMIT_EXCEEDED: {exc}", raw_output="", execution_mode=execution_mode,
                )
            else:
                raw_output = response.output_text
            if provider_call_store is not None and raw_output:
                provider_call_store.complete_call(
                    provider_call_id_value=governed_provider_call_id,
                    provider=provider,
                    model_id=model_id,
                    model_response_id=response_id,
                    raw_output=raw_output,
                )
            if raw_output:
                completion = runtime.complete_model_output(
                    invocation=invocation,
                    claim=claim,
                    raw_output=raw_output,
                    model_provider=provider,
                    model_id=model_id,
                    model_response_id=response_id,
                    execution_mode=execution_mode,
                )
        action_class = classify_observable_completion(
            receipt=completion.receipt,
            findings=completion.findings,
            obligations=completion.semantic_obligations,
        )
        if atomic_action_store is not None:
            atomic_action_store.commit(
                permit=permit,
                action_class=action_class,
                receipt_signature=completion.receipt.runtime_signature,
            )
        append_completion(reviewer=reviewer, invocation=invocation, completion=completion, raw_output=raw_output)

    bundle = ReviewBundle(
        receipts=receipts,
        findings=findings,
        semantic_frames=semantic_frames,
        semantic_obligations=semantic_obligations,
    )
    if resource_budget is not None:
        enforce_review_bundle_budget(bundle, resource_budget)
    return bundle, traces


def execute_model_reviews(
    *,
    claim: ClaimCandidate,
    evidence: EvidenceBundle,
    runtime: IndependentReviewRuntime,
    adapter: GeminiInteractionsReviewer | Mapping[str, GeminiInteractionsReviewer],
    execution_mode: ReviewExecutionMode = ReviewExecutionMode.MODEL_LIVE,
    timeout_seconds: float | None = None,
    attempt_context_sha256: str = "",
    resource_budget: ExecutionResourceBudget | None = None,
) -> ReviewBundle:
    review, _ = execute_model_reviews_traced(
        claim=claim,
        evidence=evidence,
        runtime=runtime,
        adapter=adapter,
        execution_mode=execution_mode,
        timeout_seconds=timeout_seconds,
        attempt_context_sha256=attempt_context_sha256,
        resource_budget=resource_budget,
    )
    return review
