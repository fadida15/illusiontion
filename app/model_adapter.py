from __future__ import annotations

from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .integrity import canonical_json, sha256_object
from .witness_quorum import WitnessChallengeSpec, WitnessQuorumPolicy


class WitnessMeasurementReceipt(BaseModel):
    """Independent provenance for one held-out witness challenge.

    This authority attests where the measurement artifact came from. It is
    intentionally separate from the witness authority that later judges whether
    the frozen claim survived the challenge.
    """

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=256)
    atom_id: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=4096)
    source_group: str = Field(min_length=1, max_length=512)
    method: str = Field(min_length=1, max_length=512)
    dependency_group: str = Field(min_length=1, max_length=512)
    measurement_id: str = Field(min_length=1, max_length=512)
    measurement_artifact_sha256: str = Field(min_length=64, max_length=64)
    measurement_authority_id: str = Field(min_length=1, max_length=512)
    measurement_authority_public_key: str = Field(min_length=64, max_length=64)
    measured_at: str | None = Field(default=None, max_length=128)
    ancestry_manifest_sha256: str = Field(default="", max_length=64)
    authority_signature: str = Field(min_length=128, max_length=128)


def _payload(receipt: WitnessMeasurementReceipt | None = None, **kwargs) -> bytes:
    if receipt is not None:
        body = receipt.model_dump(mode="json", exclude={"authority_signature"})
    else:
        body = dict(kwargs)
    return canonical_json(body).encode("utf-8")


def sign_measurement_receipt(
    *,
    spec: WitnessChallengeSpec,
    dependency_group: str,
    measurement_id: str,
    measurement_artifact_sha256: str,
    measurement_authority_id: str,
    private_key: Ed25519PrivateKey,
    measured_at: str | None = None,
    ancestry_manifest_sha256: str = "",
) -> WitnessMeasurementReceipt:
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    body = {
        "challenge_id": spec.challenge_id,
        "atom_id": spec.atom_id,
        "source": spec.source,
        "source_group": spec.source_group,
        "method": spec.method,
        "dependency_group": dependency_group,
        "measurement_id": measurement_id,
        "measurement_artifact_sha256": measurement_artifact_sha256,
        "measurement_authority_id": measurement_authority_id,
        "measurement_authority_public_key": public_key,
        "measured_at": measured_at,
        "ancestry_manifest_sha256": ancestry_manifest_sha256,
    }
    signature = private_key.sign(_payload(**body)).hex()
    return WitnessMeasurementReceipt(**body, authority_signature=signature)


def verify_measurement_receipt(receipt: WitnessMeasurementReceipt) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt.measurement_authority_public_key))
        public.verify(bytes.fromhex(receipt.authority_signature), _payload(receipt))
    except Exception:
        return False
    return True


def measurement_receipt_sha256(receipt: WitnessMeasurementReceipt) -> str:
    return sha256_object(receipt.model_dump(mode="json"))


class WitnessProvenancePolicy(BaseModel):
    """Strongest v0.14 witness policy.

    The witness quorum decides claim survival. Separate measurement authorities
    establish provenance for the challenge artifacts themselves.
    """

    model_config = ConfigDict(extra="forbid")

    quorum: WitnessQuorumPolicy
    measurement_authority_public_keys: list[str] = Field(min_length=2, max_length=32)
    minimum_universe_dependency_groups_per_atom: int = Field(default=3, ge=2, le=256)
    minimum_universe_measurement_authorities_per_atom: int = Field(default=2, ge=2, le=32)
    minimum_selected_dependency_groups_per_atom: int = Field(default=2, ge=2, le=64)
    minimum_selected_measurement_authorities_per_atom: int = Field(default=2, ge=2, le=32)
    require_measurement_witness_key_separation: bool = True

    @model_validator(mode="after")
    def validate_policy(self) -> "WitnessProvenancePolicy":
        keys = self.measurement_authority_public_keys
        if len(keys) != len(set(keys)):
            raise ValueError("Measurement authority public keys must be unique.")
        for key in keys:
            try:
                raw = bytes.fromhex(key)
            except ValueError as exc:
                raise ValueError("Measurement authority public keys must be raw Ed25519 hex.") from exc
            if len(raw) != 32:
                raise ValueError("Measurement authority public keys must be 32 bytes.")
        if self.require_measurement_witness_key_separation:
            overlap = set(keys) & set(self.quorum.verifier_public_keys)
            if overlap:
                raise ValueError("Measurement and witness authority keys must be disjoint.")
        if self.quorum.selection.selection_algorithm != "SHA256_DIVERSITY_RANK_V1":
            raise ValueError("Witness provenance fortification requires SHA256_DIVERSITY_RANK_V1 selection.")
        return self


def verify_measurement_universe(
    *,
    policy: WitnessProvenancePolicy,
    challenge_universe: list[WitnessChallengeSpec],
    selected: list[WitnessChallengeSpec],
    receipts: list[WitnessMeasurementReceipt],
    required_atom_ids: set[str],
) -> tuple[bool, list[str], dict[str, object]]:
    errors: list[str] = []
    receipt_by_id = {r.challenge_id: r for r in receipts}
    if len(receipt_by_id) != len(receipts):
        errors.append("duplicate-measurement-receipt")
    universe_ids = {spec.challenge_id for spec in challenge_universe}
    if set(receipt_by_id) != universe_ids:
        errors.append("measurement-receipt-coverage")

    committed_keys = set(policy.measurement_authority_public_keys)
    witness_keys = set(policy.quorum.verifier_public_keys)
    valid_ids: set[str] = set()
    artifact_groups: dict[str, set[str]] = defaultdict(set)
    by_atom_groups: dict[str, set[str]] = defaultdict(set)
    by_atom_authorities: dict[str, set[str]] = defaultdict(set)

    for spec in challenge_universe:
        receipt = receipt_by_id.get(spec.challenge_id)
        if receipt is None:
            continue
        valid = (
            verify_measurement_receipt(receipt)
            and receipt.measurement_authority_public_key in committed_keys
            and receipt.challenge_id == spec.challenge_id
            and receipt.atom_id == spec.atom_id
            and receipt.source == spec.source
            and receipt.source_group == spec.source_group
            and receipt.method == spec.method
            and receipt.dependency_group == spec.dependency_group
            and receipt.measurement_artifact_sha256 == spec.measurement_artifact_sha256
            and (not spec.measurement_receipt_sha256 or measurement_receipt_sha256(receipt) == spec.measurement_receipt_sha256)
        )
        if policy.require_measurement_witness_key_separation and receipt.measurement_authority_public_key in witness_keys:
            valid = False
        if not valid:
            errors.append(f"invalid-measurement:{spec.challenge_id}")
            continue
        valid_ids.add(spec.challenge_id)
        by_atom_groups[spec.atom_id].add(receipt.dependency_group)
        by_atom_authorities[spec.atom_id].add(receipt.measurement_authority_public_key)
        artifact_groups[receipt.measurement_artifact_sha256].add(receipt.dependency_group)

    for artifact_sha, groups in artifact_groups.items():
        if len(groups) > 1:
            errors.append(f"artifact-cross-dependency:{artifact_sha}")

    for atom_id in sorted(required_atom_ids):
        if len(by_atom_groups[atom_id]) < policy.minimum_universe_dependency_groups_per_atom:
            errors.append(f"universe-dependency-diversity:{atom_id}")
        if len(by_atom_authorities[atom_id]) < policy.minimum_universe_measurement_authorities_per_atom:
            errors.append(f"universe-measurement-authority-diversity:{atom_id}")

    selected_by_atom_groups: dict[str, set[str]] = defaultdict(set)
    selected_by_atom_authorities: dict[str, set[str]] = defaultdict(set)
    for spec in selected:
        receipt = receipt_by_id.get(spec.challenge_id)
        if receipt and spec.challenge_id in valid_ids:
            selected_by_atom_groups[spec.atom_id].add(receipt.dependency_group)
            selected_by_atom_authorities[spec.atom_id].add(receipt.measurement_authority_public_key)
    for atom_id in sorted(required_atom_ids):
        if len(selected_by_atom_groups[atom_id]) < policy.minimum_selected_dependency_groups_per_atom:
            errors.append(f"selected-dependency-diversity:{atom_id}")
        if len(selected_by_atom_authorities[atom_id]) < policy.minimum_selected_measurement_authorities_per_atom:
            errors.append(f"selected-measurement-authority-diversity:{atom_id}")

    details = {
        "valid_measurement_receipt_count": len(valid_ids),
        "universe_dependency_groups": {k: sorted(v) for k, v in by_atom_groups.items()},
        "universe_measurement_authorities": {k: sorted(v) for k, v in by_atom_authorities.items()},
        "selected_dependency_groups": {k: sorted(v) for k, v in selected_by_atom_groups.items()},
        "selected_measurement_authorities": {k: sorted(v) for k, v in selected_by_atom_authorities.items()},
    }
    return not errors, sorted(set(errors)), details
