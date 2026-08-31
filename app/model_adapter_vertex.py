from __future__ import annotations

from dataclasses import dataclass

from .schemas import ModelReviewOutput
from .runtime import ReviewInvocation


@dataclass(frozen=True)
class RawModelResponse:
    output_text: str
    response_id: str
    provider: str
    model_id: str


class GeminiInteractionsReviewer:
    """Thin live Gemini adapter for isolated reviewer execution.

    This adapter is intentionally not an authority boundary. It returns the raw
    response and provider metadata. `IndependentReviewRuntime` must strictly
    parse and sign that response before the deterministic gate will consider it.

    Each call is stateless (`store=False`) and does not use
    `previous_interaction_id`, preventing accidental cross-review conversation
    inheritance at the API layer.
    """

    no_automatic_retry = True

    def __init__(self, *, model: str = "gemini-3.7-flash", client=None) -> None:
        self.model = model
        if client is None:
            from google import genai
            from google.genai import types

            # The SDK retries transient create failures by default. Illusiontion's
            # signed plan forbids retry selection, so the official adapter forces
            # exactly one HTTP create attempt.
            client = genai.Client(http_options=types.HttpOptions(
                retry_options=types.HttpRetryOptions(attempts=1)
            ))
        self.client = client

    def run(self, invocation: ReviewInvocation) -> RawModelResponse:
        interaction = self.client.interactions.create(
            model=self.model,
            system_instruction=invocation.prompt,
            input=invocation.payload_json,
            store=False,
            response_format={
                "type": "text",
                "mime_type": "application/json",
                "schema": ModelReviewOutput.model_json_schema(),
            },
        )
        return RawModelResponse(
            output_text=interaction.output_text,
            response_id=str(interaction.id),
            provider="google-gemini-interactions",
            model_id=self.model,
        )
