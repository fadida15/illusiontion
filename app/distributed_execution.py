from __future__ import annotations

from collections import defaultdict
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .dependency_ancestry import (
    MeasurementAncestryManifest,
    WitnessAncestryPolicy,
    ancestry_manifest_sha256,
    verify_dependency_ancestry,
)
from .integrity import canonical_json, sha256_object
from .measurement_provenance import WitnessMeasurementReceipt
from .witness_quorum import WitnessChallengeSpec


class RegistryAttestationResult(str, Enum):
    MATCH = "MATCH"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    UNRESOLVED = "UNRESOLVED"


class DependencyRegistryAttestation(BaseModel):
    """Independent cross-check of a measurement authority's declared ancestry.

    Registry authorities are not measurement authorities and are not witness
    adjudicators. They report the upstream fingerprints they can independently
    observe for the already-frozen held-out measurement.
    """

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=256)
    atom_id: str = Field(min_length=1, max_length=256)
    measurement_id: str = Field(min_length=1, max_length=512)
    measurement_artifact_sha256: str = Field(min_length=64, max_length=64)
    ancestry_manifest_sha256: str = Field(min_length=64, max_length=64)
    registry_authority_id: str = Field(min_length=1, max_length=512)
    registry_authority_public_key: str = Field(min_length=64, max_length=64)
    registry_source_group: str = Field(min_length=1, max_length=512)
    registry_ancestry_manifest_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    source_records: list[str] = Field(min_length=1, max_length=64)
    observed_fingerprints: list[str] = Field(min_length=1, max_length=256)
    observed_root_fingerprints: list[str] = Field(min_length=1, max_length=64)
    result: RegistryAttestationResult
    checked_at: str | None = Field(default=None, max_length=128)
    authority_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def validate_sets(self) -> "DependencyRegistryAttestation":
        for field_name, values in (
            ("source_records", self.source_records),
            ("observed_fingerprints", self.observed_fingerprints),
            ("observed_root_fingerprints", self.observed_root_fingerprints),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} values must be unique.")
        for fingerprint in self.observed_fingerprints + self.observed_root_fingerprints:
            try:
                raw = bytes.fromhex(fingerprint)
            except ValueError as exc:
                raise ValueError("Registry fingerprints must be SHA-256 hex.") from exc
            if len(raw) != 32:
                raise ValueError("Registry fingerprints must be 32-byte SHA-256 hex.")
        if not set(self.observed_root_fingerprints).issubset(set(self.observed_fingerprints)):
            raise ValueError("Observed root fingerprints must be included in observed_fingerprints.")
        return self


def _payload(attestation: DependencyRegistryAttestation | None = None, **kwargs) -> bytes:
    body = (
        attestation.model_dump(mode="json", exclude={"authority_signature"})
        if attestation is not None
        else dict(kwargs)
    )
    return canonical_json(body).encode("utf-8")


def sign_registry_attestation(
    *,
    spec: WitnessChallengeSpec,
    manifest: MeasurementAncestryManifest,
    registry_authority_id: str,
    registry_source_group: str,
    source_records: list[str],
    observed_fingerprints: list[str],
    observed_root_fingerprints: list[str],
    result: RegistryAttestationResult,
    private_key: Ed25519PrivateKey,
    registry_ancestry_manifest_sha256: str | None = None,
    checked_at: str | None = None,
) -> DependencyRegistryAttestation:
    if manifest.challenge_id != spec.challenge_id or manifest.atom_id != spec.atom_id:
        raise ValueError("Registry attestation manifest/spec mismatch.")
    if manifest.measurement_artifact_sha256 != spec.measurement_artifact_sha256:
        raise ValueError("Registry attestation artifact/spec mismatch.")
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    body = {
        "challenge_id": spec.challenge_id,
        "atom_id": spec.atom_id,
        "measurement_id": manifest.measurement_id,
        "measurement_artifact_sha256": manifest.measurement_artifact_sha256,
        "ancestry_manifest_sha256": ancestry_manifest_sha256(manifest),
        "registry_authority_id": registry_authority_id,
        "registry_authority_public_key": public_key,
        "registry_source_group": registry_source_group,
        "registry_ancestry_manifest_sha256": registry_ancestry_manifest_sha256,
        "source_records": source_records,
        "observed_fingerprints": observed_fingerprints,
        "observed_root_fingerprints": observed_root_fingerprints,
        "result": result,
        "checked_at": checked_at,
    }
    candidate = DependencyRegistryAttestation(**body, authority_signature="0" * 128)
    signature = private_key.sign(_payload(**candidate.model_dump(mode="json", exclude={"authority_signature"}))).hex()
    return candidate.model_copy(update={"authority_signature": signature})


def verify_registry_attestation(attestation: DependencyRegistryAttestation) -> bool:
    try:
        raw_key = bytes.fromhex(attestation.registry_authority_public_key)
        if len(raw_key) != 32:
            return False
        public = Ed25519PublicKey.from_public_bytes(raw_key)
        public.verify(bytes.fromhex(attestation.authority_signature), _payload(attestation))
    except Exception:
        return False
    return True


def registry_attestation_sha256(attestation: DependencyRegistryAttestation) -> str:
    return sha256_object(attestation.model_dump(mode="json"))


class WitnessRegistryPolicy(BaseModel):
    """v0.16 policy: independently cross-check declared ancestry against registries."""

    model_config = ConfigDict(extra="forbid")

    ancestry: WitnessAncestryPolicy
    registry_authority_public_keys: list[str] = Field(min_length=2, max_length=32)
    registry_authority_quorum_per_challenge: int = Field(default=2, ge=2, le=32)
    minimum_registry_source_groups_per_challenge: int = Field(default=2, ge=2, le=32)
    require_registry_measurement_key_separation: bool = True
    require_registry_witness_key_separation: bool = True

    @model_validator(mode="after")
    def validate_policy(self) -> "WitnessRegistryPolicy":
        keys = self.registry_authority_public_keys
        if len(keys) != len(set(keys)):
            raise ValueError("Registry authority public keys must be unique.")
        if self.registry_authority_quorum_per_challenge > len(keys):
            raise ValueError("Registry authority quorum cannot exceed committed registry authority count.")
        for key in keys:
            try:
                raw = bytes.fromhex(key)
            except ValueError as exc:
                raise ValueError("Registry authority public keys must be raw Ed25519 hex.") from exc
            if len(raw) != 32:
                raise ValueError("Registry authority public keys must be 32 bytes.")
        registry = set(keys)
        measurement = set(self.ancestry.provenance.measurement_authority_public_keys)
        witness = set(self.ancestry.provenance.quorum.verifier_public_keys)
        if self.require_registry_measurement_key_separation and registry & measurement:
            raise ValueError("Registry and measurement authority keys must be disjoint.")
        if self.require_registry_witness_key_separation and registry & witness:
            raise ValueError("Registry and witness authority keys must be disjoint.")
        return self


def _manifest_fingerprints(manifest: MeasurementAncestryManifest) -> set[str]:
    return {node.fingerprint_sha256 for node in manifest.nodes}


def _manifest_root_fingerprints(manifest: MeasurementAncestryManifest) -> set[str]:
    return {node.fingerprint_sha256 for node in manifest.nodes if not node.upstream_node_ids}


def verify_dependency_registry(
    *,
    policy: WitnessRegistryPolicy,
    challenge_universe: list[WitnessChallengeSpec],
    selected: list[WitnessChallengeSpec],
    measurement_receipts: list[WitnessMeasurementReceipt],
    ancestry_manifests: list[MeasurementAncestryManifest],
    registry_attestations: list[DependencyRegistryAttestation],
    required_atom_ids: set[str],
) -> tuple[bool, list[str], dict[str, object]]:
    """Verify ancestry first, then cross-check it against independent registries.

    A registry attestation can only add doubt, never erase it: any authenticated
    MISSING_DEPENDENCY/UNRESOLVED attestation or any observed fingerprint absent
    from the measurement-authored ancestry causes HOLD, even if quorum otherwise
    agrees. Quorum is therefore a minimum evidence floor, not a majority vote.
    """

    errors: list[str] = []
    ancestry_ok, ancestry_errors, ancestry_details = verify_dependency_ancestry(
        policy=policy.ancestry,
        challenge_universe=challenge_universe,
        selected=selected,
        measurement_receipts=measurement_receipts,
        ancestry_manifests=ancestry_manifests,
        required_atom_ids=required_atom_ids,
    )
    if not ancestry_ok:
        errors.extend("ancestry:" + item for item in ancestry_errors)

    spec_by_id = {item.challenge_id: item for item in challenge_universe}
    manifest_by_id = {item.challenge_id: item for item in ancestry_manifests}
    committed = set(policy.registry_authority_public_keys)
    measurement_keys = set(policy.ancestry.provenance.measurement_authority_public_keys)
    witness_keys = set(policy.ancestry.provenance.quorum.verifier_public_keys)

    by_challenge: dict[str, list[DependencyRegistryAttestation]] = defaultdict(list)
    duplicate_pairs: set[tuple[str, str]] = set()
    seen_pairs: set[tuple[str, str]] = set()
    for attestation in registry_attestations:
        pair = (attestation.challenge_id, attestation.registry_authority_public_key)
        if pair in seen_pairs:
            duplicate_pairs.add(pair)
        seen_pairs.add(pair)
        by_challenge[attestation.challenge_id].append(attestation)
    for challenge_id, key in sorted(duplicate_pairs):
        errors.append(f"duplicate-registry-attestation:{challenge_id}:{key[:16]}")

    valid_authorities_by_challenge: dict[str, set[str]] = defaultdict(set)
    source_groups_by_challenge: dict[str, set[str]] = defaultdict(set)
    missing_fingerprints: dict[str, set[str]] = defaultdict(set)
    negative_attestations: list[str] = []
    invalid_attestations: list[str] = []

    for challenge_id, spec in spec_by_id.items():
        manifest = manifest_by_id.get(challenge_id)
        if manifest is None:
            continue
        manifest_sha = ancestry_manifest_sha256(manifest)
        manifest_fps = _manifest_fingerprints(manifest)
        manifest_roots = _manifest_root_fingerprints(manifest)
        for attestation in by_challenge.get(challenge_id, []):
            valid = (
                verify_registry_attestation(attestation)
                and attestation.registry_authority_public_key in committed
                and attestation.challenge_id == spec.challenge_id
                and attestation.atom_id == spec.atom_id
                and attestation.measurement_id == manifest.measurement_id
                and attestation.measurement_artifact_sha256 == manifest.measurement_artifact_sha256
                and attestation.ancestry_manifest_sha256 == manifest_sha
            )
            if policy.require_registry_measurement_key_separation and attestation.registry_authority_public_key in measurement_keys:
                valid = False
            if policy.require_registry_witness_key_separation and attestation.registry_authority_public_key in witness_keys:
                valid = False
            if not valid:
                invalid_attestations.append(f"invalid-registry-attestation:{challenge_id}:{attestation.registry_authority_id}")
                continue
            valid_authorities_by_challenge[challenge_id].add(attestation.registry_authority_public_key)
            source_groups_by_challenge[challenge_id].add(attestation.registry_source_group)
            extra = set(attestation.observed_fingerprints) - manifest_fps
            root_extra = set(attestation.observed_root_fingerprints) - manifest_roots
            if extra or root_extra:
                missing_fingerprints[challenge_id].update(extra | root_extra)
            if attestation.result != RegistryAttestationResult.MATCH:
                negative_attestations.append(
                    f"registry-{attestation.result.value.lower()}:{challenge_id}:{attestation.registry_authority_id}"
                )

    errors.extend(invalid_attestations)
    errors.extend(negative_attestations)
    for challenge_id, fingerprints in sorted(missing_fingerprints.items()):
        if fingerprints:
            errors.append(f"registry-ancestry-disclosure-mismatch:{challenge_id}")

    for challenge_id in sorted(spec_by_id):
        if len(valid_authorities_by_challenge[challenge_id]) < policy.registry_authority_quorum_per_challenge:
            errors.append(f"registry-authority-quorum:{challenge_id}")
        if len(source_groups_by_challenge[challenge_id]) < policy.minimum_registry_source_groups_per_challenge:
            errors.append(f"registry-source-diversity:{challenge_id}")

    selected_ids = {item.challenge_id for item in selected}
    if any(challenge_id not in valid_authorities_by_challenge for challenge_id in selected_ids):
        errors.append("selected-registry-coverage")

    details = {
        "valid_registry_authority_counts": {
            challenge_id: len(keys) for challenge_id, keys in sorted(valid_authorities_by_challenge.items())
        },
        "registry_source_groups": {
            challenge_id: sorted(groups) for challenge_id, groups in sorted(source_groups_by_challenge.items())
        },
        "registry_disclosure_mismatches": {
            challenge_id: sorted(values) for challenge_id, values in sorted(missing_fingerprints.items()) if values
        },
        "negative_attestations": sorted(negative_attestations),
        "invalid_attestations": sorted(invalid_attestations),
        "ancestry_status": "PASS" if ancestry_ok else "HOLD",
        "ancestry_details": ancestry_details,
    }
    return not errors, sorted(set(errors)), details
