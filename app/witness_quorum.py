from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .integrity import canonical_json
from .schemas import ExternalWitnessCheck, ExternalWitnessSet


def _payload(*, case_id: str, claim_sha256: str, verifier_id: str, public_key_hex: str, checks: list[ExternalWitnessCheck]) -> bytes:
    body = {
        "case_id": case_id,
        "claim_sha256": claim_sha256,
        "verifier_id": verifier_id,
        "verifier_public_key": public_key_hex,
        "checks": [check.model_dump(mode="json") for check in checks],
    }
    return canonical_json(body).encode("utf-8")


def sign_external_witness_set(
    *,
    case_id: str,
    claim_sha256: str,
    verifier_id: str,
    checks: list[ExternalWitnessCheck],
    private_key: Ed25519PrivateKey,
) -> ExternalWitnessSet:
    if not verifier_id.strip():
        raise ValueError("verifier_id must be non-empty")
    public_key_hex = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    signature = private_key.sign(
        _payload(
            case_id=case_id,
            claim_sha256=claim_sha256,
            verifier_id=verifier_id,
            public_key_hex=public_key_hex,
            checks=checks,
        )
    ).hex()
    return ExternalWitnessSet(
        case_id=case_id,
        claim_sha256=claim_sha256,
        verifier_id=verifier_id,
        verifier_public_key=public_key_hex,
        checks=checks,
        verifier_signature=signature,
    )


def verify_external_witness_set(witness: ExternalWitnessSet) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(witness.verifier_public_key))
        public.verify(
            bytes.fromhex(witness.verifier_signature),
            _payload(
                case_id=witness.case_id,
                claim_sha256=witness.claim_sha256,
                verifier_id=witness.verifier_id,
                public_key_hex=witness.verifier_public_key,
                checks=witness.checks,
            ),
        )
    except Exception:
        return False
    return True
