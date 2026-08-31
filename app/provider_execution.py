from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from google.cloud import kms


PROOF_SCHEMA = "illusiontion.external-proof.v1"
PROOF_TYPE = "governed_decision"
VALID_VERDICTS = {"PASS", "HOLD", "REJECT"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decision_dict(decision: Any) -> dict[str, Any]:
    if hasattr(decision, "model_dump"):
        value = decision.model_dump(mode="json")
    elif isinstance(decision, Mapping):
        value = dict(decision)
    else:
        raise TypeError("decision must be a Pydantic model or mapping")

    return value


def _verify_internal_decision_hash(decision: dict[str, Any]) -> None:
    stored = decision.get("decision_sha256")

    if not isinstance(stored, str) or not stored:
        raise ValueError("decision_sha256 is missing")

    payload = dict(decision)
    payload.pop("decision_sha256", None)

    calculated = hashlib.sha256(
        canonical_json(payload)
    ).hexdigest()

    if calculated != stored:
        raise ValueError(
            "decision_sha256 does not match canonical decision payload"
        )


@dataclass(frozen=True)
class SignedProofArtifact:
    bundle: dict[str, Any]
    canonical_bytes: bytes
    signature: bytes
    public_key_pem: bytes
    proof_sha256: str
    signature_sha256: str

    def response_payload(self) -> dict[str, Any]:
        return {
            "proof_schema": self.bundle["proof_schema"],
            "claim_id": self.bundle["claim_id"],
            "proof_sha256": self.proof_sha256,
            "signature_sha256": self.signature_sha256,
            "signature_base64": base64.b64encode(
                self.signature
            ).decode("ascii"),
            "canonical_proof_base64": base64.b64encode(
                self.canonical_bytes
            ).decode("ascii"),
            "public_key_sha256": self.bundle[
                "issuer"
            ]["public_key_sha256"],
            "kms_key_version": self.bundle[
                "issuer"
            ]["kms_key_version"],
        }


class KmsDecisionProofSigner:
    def __init__(
        self,
        *,
        key_version: str | None = None,
        expected_public_key_sha256: str | None = None,
        client=None,
    ) -> None:
        self.key_version = (
            key_version
            or os.environ.get(
                "ILLUSIONTION_PROOF_KMS_KEY_VERSION",
                "",
            ).strip()
        )

        self.expected_public_key_sha256 = (
            expected_public_key_sha256
            or os.environ.get(
                "ILLUSIONTION_PROOF_PUBLIC_KEY_SHA256",
                "",
            ).strip().lower()
        )

        if not self.key_version:
            raise RuntimeError(
                "ILLUSIONTION_PROOF_KMS_KEY_VERSION is required"
            )

        if not self.expected_public_key_sha256:
            raise RuntimeError(
                "ILLUSIONTION_PROOF_PUBLIC_KEY_SHA256 is required"
            )

        self.client = client or kms.KeyManagementServiceClient()

    def sign_decision(self, decision: Any) -> SignedProofArtifact:
        decision_data = _decision_dict(decision)

        claim_id = decision_data.get("claim_id")
        verdict = decision_data.get("verdict")

        if not isinstance(claim_id, str) or not claim_id:
            raise ValueError("decision claim_id is missing")

        if verdict not in VALID_VERDICTS:
            raise ValueError(
                f"invalid governed verdict: {verdict!r}"
            )

        # Never ask KMS to authenticate an internally inconsistent decision.
        _verify_internal_decision_hash(decision_data)

        public_key_response = self.client.get_public_key(
            request={"name": self.key_version}
        )

        public_key_pem = public_key_response.pem.encode("ascii")
        public_key_sha256 = hashlib.sha256(
            public_key_pem
        ).hexdigest()

        # Fail closed if the configured KMS key has drifted or was substituted.
        if public_key_sha256 != self.expected_public_key_sha256:
            raise RuntimeError(
                "KMS public key does not match pinned Illusiontion trust anchor"
            )

        bundle = {
            "proof_schema": PROOF_SCHEMA,
            "proof_type": PROOF_TYPE,
            "claim_id": claim_id,
            "issued_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "issuer": {
                "system": "Illusiontion",
                "cloud_service": "Google Cloud Run",
                "region": os.environ.get(
                    "ILLUSIONTION_CLOUD_REGION",
                    "me-west1",
                ),
                "model": os.environ.get(
                    "ILLUSIONTION_MODEL",
                    "gemini-3.7-flash",
                ),
                "decision_store": os.environ.get(
                    "ILLUSIONTION_DECISION_STORE",
                    "firestore",
                ),
                "kms_key_version": self.key_version,
                "public_key_sha256": public_key_sha256,
            },
            "decision": decision_data,
        }

        canonical = canonical_json(bundle)
        digest = hashlib.sha256(canonical).digest()

        response = self.client.asymmetric_sign(
            request={
                "name": self.key_version,
                "digest": kms.Digest(sha256=digest),
            }
        )

        signature = bytes(response.signature)

        return SignedProofArtifact(
            bundle=bundle,
            canonical_bytes=canonical,
            signature=signature,
            public_key_pem=public_key_pem,
            proof_sha256=hashlib.sha256(canonical).hexdigest(),
            signature_sha256=hashlib.sha256(signature).hexdigest(),
        )
