from __future__ import annotations

from .integrity import sha256_object

_POLICY = {
    "domain": "ILLUSIONTION_RECOVERY_INTERRUPTION_SEMANTICS_V0_38",
    "permit_without_provider_row": "SAFE_PRE_NETWORK_RESUME",
    "provider_in_flight_or_uncertain": "FAIL_CLOSED_NO_RETRY",
    "provider_completed_without_atomic_commit": "REPLAY_DURABLE_COMPLETION_NO_PROVIDER_CALL",
    "atomic_commit_complete": "RESUME_NEXT_STEP",
    "completed_chain": "IDEMPOTENT_FINALIZATION_ALLOWED",
    "authority_scope": "INTERRUPTION_RECOVERY_ONLY_NEVER_UPGRADES_VERDICT",
}


def interruption_policy_sha256() -> str:
    return sha256_object(_POLICY)


class RecoveryInterruptionError(RuntimeError):
    pass


def inspect_interrupted_attempt(*, atomic_store, provider_store, attempt_id: str, reviewer_order) -> dict:
    """Classify the durable state of a v0.38 recovery attempt without mutation."""
    progress = atomic_store.attempt_progress(attempt_id=attempt_id)
    if not progress.get("exists"):
        return {
            "attempt_id": attempt_id,
            "status": "NOT_STARTED",
            "safe_to_resume": False,
            "next_step": 0,
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    expected_steps = len(reviewer_order)
    next_step = int(progress["next_step"])
    if next_step > expected_steps:
        return {
            "attempt_id": attempt_id,
            "status": "INVALID_STATE",
            "reason": "next-step-exceeds-reviewer-count",
            "safe_to_resume": False,
            "next_step": next_step,
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    if progress["completed"] or next_step == expected_steps:
        return {
            "attempt_id": attempt_id,
            "status": "READY_FOR_IDEMPOTENT_FINALIZATION",
            "safe_to_resume": True,
            "next_step": next_step,
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    permit = atomic_store.load_permit(attempt_id=attempt_id, step_index=next_step)
    commit = atomic_store.load_commit(attempt_id=attempt_id, step_index=next_step)
    provider_state = provider_store.state_for_step(attempt_id=attempt_id, step_index=next_step)
    if commit is not None:
        return {
            "attempt_id": attempt_id,
            "status": "INVALID_STATE",
            "reason": "commit-exists-at-current-next-step",
            "safe_to_resume": False,
            "next_step": next_step,
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    if permit is None:
        if provider_state is not None:
            return {
                "attempt_id": attempt_id,
                "status": "INVALID_STATE",
                "reason": "provider-row-without-atomic-permit",
                "safe_to_resume": False,
                "next_step": next_step,
                "interruption_policy_sha256": interruption_policy_sha256(),
            }
        return {
            "attempt_id": attempt_id,
            "status": "RESUME_NEXT_FRESH_ACTION",
            "safe_to_resume": True,
            "next_step": next_step,
            "reviewer": reviewer_order[next_step],
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    if provider_state is None:
        return {
            "attempt_id": attempt_id,
            "status": "SAFE_PRE_NETWORK_RESUME",
            "safe_to_resume": True,
            "next_step": next_step,
            "reviewer": reviewer_order[next_step],
            "permit_sha256": permit.permit_sha256,
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    if provider_state == "COMPLETED":
        return {
            "attempt_id": attempt_id,
            "status": "SAFE_DURABLE_COMPLETION_RECONCILIATION",
            "safe_to_resume": True,
            "next_step": next_step,
            "reviewer": reviewer_order[next_step],
            "permit_sha256": permit.permit_sha256,
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    if provider_state in {"IN_FLIGHT", "UNCERTAIN"}:
        return {
            "attempt_id": attempt_id,
            "status": "FAIL_CLOSED_UNCERTAIN_PROVIDER_CALL",
            "safe_to_resume": False,
            "next_step": next_step,
            "reviewer": reviewer_order[next_step],
            "permit_sha256": permit.permit_sha256,
            "provider_state": provider_state,
            "interruption_policy_sha256": interruption_policy_sha256(),
        }
    return {
        "attempt_id": attempt_id,
        "status": "INVALID_STATE",
        "reason": f"unknown-provider-state:{provider_state}",
        "safe_to_resume": False,
        "next_step": next_step,
        "interruption_policy_sha256": interruption_policy_sha256(),
    }
