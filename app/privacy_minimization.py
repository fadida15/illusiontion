from __future__ import annotations

import hashlib
import os

from .model_adapter import RawModelResponse
from .runtime import ReviewInvocation
from .schemas import (
    SemanticObligationResult,
    SemanticObligationType,
    SemanticQuantifier,
    SemanticRelation,
    Severity,
)


VERTEX_TRANSPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_type": {"type": "string"},
                    "severity": {"type": "string", "enum": [x.value for x in Severity]},
                    "message": {"type": "string"},
                    "evidence_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "finding_type",
                    "severity",
                    "message",
                    "evidence_ids",
                ],
            },
        },
        "semantic_frames": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "atom_id": {"type": "string"},
                    "quantifier": {"type": "string", "enum": [x.value for x in SemanticQuantifier]},
                    "relation": {"type": "string", "enum": [x.value for x in SemanticRelation]},
                    "normalized_statement": {"type": "string"},
                    "conditions": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "atom_id",
                    "quantifier",
                    "relation",
                    "normalized_statement",
                    "conditions",
                ],
            },
        },
        "semantic_obligations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "atom_id": {"type": "string"},
                    "obligation_type": {"type": "string", "enum": [x.value for x in SemanticObligationType]},
                    "result": {"type": "string", "enum": [x.value for x in SemanticObligationResult]},
                    "witness_evidence_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "rationale": {"type": "string"},
                },
                "required": [
                    "atom_id",
                    "obligation_type",
                    "result",
                    "witness_evidence_ids",
                    "rationale",
                ],
            },
        },
        "notes": {"type": "string"},
    },
    "required": [
        "findings",
        "semantic_frames",
        "semantic_obligations",
        "notes",
    ],
}


class GeminiVertexReviewer:
    """Vertex transport adapter for the hackathon deployment."""

    no_automatic_retry = True

    def __init__(self, *, model: str = "gemini-3.7-flash", client=None) -> None:
        self.model = model

        if client is None:
            from google import genai
            from google.genai import types

            client = genai.Client(
                vertexai=True,
                project=os.environ["GOOGLE_CLOUD_PROJECT"],
                location=os.getenv("GOOGLE_CLOUD_LOCATION", "global"),
                http_options=types.HttpOptions(
                    retry_options=types.HttpRetryOptions(attempts=1)
                ),
            )

        self.client = client

    def run(self, invocation: ReviewInvocation) -> RawModelResponse:
        from google.genai import types

        response = self.client.models.generate_content(
            model=self.model,
            contents=invocation.payload_json,
            config=types.GenerateContentConfig(
                system_instruction=invocation.prompt,
                response_mime_type="application/json",
                response_json_schema=VERTEX_TRANSPORT_SCHEMA,
            ),
        )

        text = response.text or ""

        response_id = (
            getattr(response, "response_id", None)
            or getattr(response, "id", None)
        )

        if not response_id:
            response_id = "local-vertex-" + hashlib.sha256(
                (invocation.invocation_id + "\n" + text).encode("utf-8")
            ).hexdigest()[:32]

        return RawModelResponse(
            output_text=text,
            response_id=str(response_id),
            provider="google-vertex-generate-content",
            model_id=self.model,
        )
