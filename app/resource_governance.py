from __future__ import annotations

from collections import defaultdict
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .integrity import canonical_json, sha256_object
from .registry_ancestry import (
    RegistryAncestryManifest,
    WitnessRegistryAncestryPolicy,
    registry_ancestry_manifest_sha256,
    verify_registry_ancestry,
)
from .dependency_ancestry import MeasurementAncestryManifest
from .dependency_registry import DependencyRegistryAttestation
from .measurement_provenance import WitnessMeasurementReceipt
from .witness_quorum import WitnessChallengeSpec


class RegistryObservationResult(str, Enum):
    MATCH = "MATCH"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    UNRESOLVED = "UNRESOLVED"


class RegistryDependencyObservation(BaseModel):
    """Externally observable challenge to one signed registry-ancestry declaration.

    The observer does not author or rewrite registry ancestry.  It reports
    concrete upstream fingerprints observed through a precommitted probe path.
    The signature authenticates the observation; it is not itself a truth
    guarantee.
    """

    model_config = ConfigDict(extra="forbid")

    registry_authority_public_key: str = Field(min_length=64, max_length=64)
    registry_source_group: str = Field(min_length=1, max_length=512)
    registry_ancestry_manifest_sha256: str = Field(min_length=64, max_length=64)
    observer_authority_id: str = Field(min_length=1, max_length=512)
    observer_authority_public_key: str = Field(min_length=64, max_length=64)
    observer_source_group: str = Field(min_length=1, max_length=512)
    probe_id: str = Field(min_length=1, max_length=512)
    probe_method: str = Field(min_length=1, max_length=256)
    source_records: list[str] = Field(min_length=1, max_length=64)
    observed_fingerprints: list[str] = Field(min_length=1, max_length=256)
    result: RegistryObservationResult
    observed_at: str | None = Field(default=None, max_length=128)
    authority_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def validate_sets(self) -> "RegistryDependencyObservation":
        if len(self.source_records) != len(set(self.source_records)):
            raise ValueError("Observation source_records must be unique.")
        if len(self.observed_fingerprints) != len(set(self.observed_fingerprints)):
            raise ValueError("Observation fingerprints must be unique.")
        for value in self.observed_fingerprints:
            try:
                raw = bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError("Observation fingerprints must be SHA-256 hex.") from exc
            if len(raw) != 32:
                raise ValueError("Observation fingerprints must be 32-byte SHA-256 hex.")
        return self


def _payload(observation: RegistryDependencyObservation | None = None, **kwargs) -> bytes:
    body = observation.model_dump(mode="json", exclude={"authority_signature"}) if observation is not None else dict(kwargs)
    return canonical_json(body).encode("utf-8")


def sign_registry_dependency_observation(
    *,
    registry_manifest: RegistryAncestryManifest,
    observer_authority_id: str,
    observer_source_group: str,
    private_key: Ed25519PrivateKey,
    probe_id: str,
    probe_method: str,
    source_records: list[str],
    observed_fingerprints: list[str],
    result: RegistryObservationResult,
    observed_at: str | None = None,
) -> RegistryDependencyObservation:
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    body = {
        "registry_authority_public_key": registry_manifest.registry_authority_public_key,
        "registry_source_group": registry_manifest.registry_source_group,
        "registry_ancestry_manifest_sha256": registry_ancestry_manifest_sha256(registry_manifest),
        "observer_authority_id": observer_authority_id,
        "observer_authority_public_key": public_key,
        "observer_source_group": observer_source_group,
        "probe_id": probe_id,
        "probe_method": probe_method,
        "source_records": source_records,
        "observed_fingerprints": observed_fingerprints,
        "result": result,
        "observed_at": observed_at,
    }
    candidate = RegistryDependencyObservation(**body, authority_signature="0" * 128)
    sig = private_key.sign(_payload(**candidate.model_dump(mode="json", exclude={"authority_signature"}))).hex()
    return candidate.model_copy(update={"authority_signature": sig})


def verify_registry_dependency_observation(observation: RegistryDependencyObservation) -> bool:
    try:
        raw = bytes.fromhex(observation.observer_authority_public_key)
        if len(raw) != 32:
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(bytes.fromhex(observation.authority_signature), _payload(observation))
    except Exception:
        return False
    return True


def registry_dependency_observation_sha256(observation: RegistryDependencyObservation) -> str:
    return sha256_object(observation.model_dump(mode="json"))


class WitnessRegistryObservationPolicy(BaseModel):
    """v0.18 policy: challenge registry ancestry with external observable probes."""

    model_config = ConfigDict(extra="forbid")

    registry_ancestry: WitnessRegistryAncestryPolicy
    observer_authority_public_keys: list[str] = Field(min_length=2, max_length=32)
    observer_source_group_by_public_key: dict[str, str] = Field(min_length=2, max_length=32)
    observer_quorum_per_registry_source: int = Field(default=2, ge=2, le=32)
    minimum_observer_source_groups_per_registry_source: int = Field(default=2, ge=2, le=32)
    allowed_probe_methods: list[str] = Field(min_length=1, max_length=32)
    require_observer_key_separation: bool = True

    @model_validator(mode="after")
    def validate_policy(self) -> "WitnessRegistryObservationPolicy":
        keys = self.observer_authority_public_keys
        if len(keys) != len(set(keys)):
            raise ValueError("Observer authority public keys must be unique.")
        if self.observer_quorum_per_registry_source > len(keys):
            raise ValueError("Observer quorum cannot exceed committed observer authority count.")
        if set(self.observer_source_group_by_public_key) != set(keys):
            raise ValueError("Observer source-group map must exactly cover committed observer keys.")
        groups = list(self.observer_source_group_by_public_key.values())
        if len(groups) != len(set(groups)):
            raise ValueError("Observer source groups must be unique across committed observer authorities.")
        if len(self.allowed_probe_methods) != len(set(self.allowed_probe_methods)):
            raise ValueError("Allowed probe methods must be unique.")
        for key in keys:
            try:
                raw = bytes.fromhex(key)
            except ValueError as exc:
                raise ValueError("Observer authority public keys must be raw Ed25519 hex.") from exc
            if len(raw) != 32:
                raise ValueError("Observer authority public keys must be 32 bytes.")
        if self.require_observer_key_separation:
            registry_keys = set(self.registry_ancestry.registry.registry_authority_public_keys)
            measurement_keys = set(self.registry_ancestry.registry.ancestry.provenance.measurement_authority_public_keys)
            witness_keys = set(self.registry_ancestry.registry.ancestry.provenance.quorum.verifier_public_keys)
            observers = set(keys)
            if observers & (registry_keys | measurement_keys | witness_keys):
                raise ValueError("Observer keys must be disjoint from registry, measurement, and witness keys.")
        return self


def _manifest_fingerprints(manifest: RegistryAncestryManifest) -> set[str]:
    return {node.fingerprint_sha256 for node in manifest.nodes}


def verify_registry_observations(
    *,
    policy: WitnessRegistryObservationPolicy,
    challenge_universe: list[WitnessChallengeSpec],
    selected: list[WitnessChallengeSpec],
    measurement_receipts: list[WitnessMeasurementReceipt],
    ancestry_manifests: list[MeasurementAncestryManifest],
    registry_attestations: list[DependencyRegistryAttestation],
    registry_ancestry_manifests: list[RegistryAncestryManifest],
    registry_observations: list[RegistryDependencyObservation],
    required_atom_ids: set[str],
) -> tuple[bool, list[str], dict[str, object]]:
    """Verify v0.17, then externally challenge each committed registry ancestry.

    Any authenticated observer that reports MISSING_DEPENDENCY/UNRESOLVED, or
    any observed upstream fingerprint absent from the bound registry ancestry,
    causes HOLD. Observer quorum is a minimum coverage floor, not majority vote.
    """

    errors: list[str] = []
    ancestry_ok, ancestry_errors, ancestry_details = verify_registry_ancestry(
        policy=policy.registry_ancestry,
        challenge_universe=challenge_universe,
        selected=selected,
        measurement_receipts=measurement_receipts,
        ancestry_manifests=ancestry_manifests,
        registry_attestations=registry_attestations,
        registry_ancestry_manifests=registry_ancestry_manifests,
        required_atom_ids=required_atom_ids,
    )
    if not ancestry_ok:
        errors.extend("registry-ancestry:" + item for item in ancestry_errors)

    committed_observers = set(policy.observer_authority_public_keys)
    manifest_by_pair = {
        (m.registry_authority_public_key, m.registry_source_group): m
        for m in registry_ancestry_manifests
    }
    required_pairs = set()
    for att in registry_attestations:
        pair = (att.registry_authority_public_key, att.registry_source_group)
        if pair in manifest_by_pair:
            required_pairs.add(pair)

    by_pair: dict[tuple[str, str], list[RegistryDependencyObservation]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    duplicates: list[str] = []
    for obs in registry_observations:
        key = (obs.registry_authority_public_key, obs.registry_source_group, obs.observer_authority_public_key)
        if key in seen:
            duplicates.append(f"duplicate-registry-observer:{obs.registry_source_group}:{obs.observer_authority_public_key[:16]}")
        seen.add(key)
        by_pair[(obs.registry_authority_public_key, obs.registry_source_group)].append(obs)
    errors.extend(sorted(set(duplicates)))

    valid_counts: dict[str, int] = {}
    source_groups: dict[str, list[str]] = {}
    disclosure_mismatches: dict[str, list[str]] = {}
    negative_observations: list[str] = []
    invalid_observations: list[str] = []

    for pair in sorted(required_pairs):
        manifest = manifest_by_pair[pair]
        manifest_sha = registry_ancestry_manifest_sha256(manifest)
        manifest_fps = _manifest_fingerprints(manifest)
        valid_keys: set[str] = set()
        groups: set[str] = set()
        missing: set[str] = set()
        for obs in by_pair.get(pair, []):
            expected_group = policy.observer_source_group_by_public_key.get(obs.observer_authority_public_key)
            valid = (
                verify_registry_dependency_observation(obs)
                and obs.observer_authority_public_key in committed_observers
                and expected_group == obs.observer_source_group
                and obs.registry_ancestry_manifest_sha256 == manifest_sha
                and obs.registry_authority_public_key == manifest.registry_authority_public_key
                and obs.registry_source_group == manifest.registry_source_group
                and obs.probe_method in set(policy.allowed_probe_methods)
            )
            if not valid:
                invalid_observations.append(f"invalid-registry-observation:{manifest.registry_source_group}:{obs.observer_authority_id}")
                continue
            valid_keys.add(obs.observer_authority_public_key)
            groups.add(obs.observer_source_group)
            extra = set(obs.observed_fingerprints) - manifest_fps
            if extra:
                missing.update(extra)
            if obs.result != RegistryObservationResult.MATCH:
                negative_observations.append(
                    f"registry-observer-{obs.result.value.lower()}:{manifest.registry_source_group}:{obs.observer_authority_id}"
                )
        label = manifest.registry_source_group
        valid_counts[label] = len(valid_keys)
        source_groups[label] = sorted(groups)
        if missing:
            disclosure_mismatches[label] = sorted(missing)
            errors.append(f"registry-observation-disclosure-mismatch:{label}")
        if len(valid_keys) < policy.observer_quorum_per_registry_source:
            errors.append(f"registry-observer-quorum:{label}")
        if len(groups) < policy.minimum_observer_source_groups_per_registry_source:
            errors.append(f"registry-observer-source-diversity:{label}")

    errors.extend(sorted(set(invalid_observations)))
    errors.extend(sorted(set(negative_observations)))
    if required_pairs and any(pair not in by_pair for pair in required_pairs):
        errors.append("registry-observer-coverage")

    details = {
        "valid_observer_counts": valid_counts,
        "observer_source_groups": source_groups,
        "registry_observation_disclosure_mismatches": disclosure_mismatches,
        "negative_observations": sorted(set(negative_observations)),
        "invalid_observations": sorted(set(invalid_observations)),
        "registry_ancestry_status": "PASS" if ancestry_ok else "HOLD",
        "registry_ancestry_details": ancestry_details,
    }
    return not errors, sorted(set(errors)), details
