from __future__ import annotations

from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .dependency_ancestry import DependencyNode, DependencyRole
from .dependency_registry import (
    DependencyRegistryAttestation,
    WitnessRegistryPolicy,
    verify_dependency_registry,
)
from .integrity import canonical_json, sha256_object
from .measurement_provenance import WitnessMeasurementReceipt
from .dependency_ancestry import MeasurementAncestryManifest
from .witness_quorum import WitnessChallengeSpec


class RegistryAncestryManifest(BaseModel):
    """Signed declared upstream ancestry of one dependency-registry source.

    This is intentionally separate from measurement ancestry.  It describes the
    catalogs, crawlers, APIs, models, mirrors, or other upstream dependencies
    used by a registry authority/source group to produce registry attestations.

    The signature authenticates the declaration; it does not prove that the
    declaration is complete.  v0.17 compares declarations across registry
    source groups and fails closed on declared shared upstream fingerprints.
    """

    model_config = ConfigDict(extra="forbid")

    registry_authority_id: str = Field(min_length=1, max_length=512)
    registry_authority_public_key: str = Field(min_length=64, max_length=64)
    registry_source_group: str = Field(min_length=1, max_length=512)
    output_node_id: str = Field(min_length=1, max_length=256)
    nodes: list[DependencyNode] = Field(min_length=2, max_length=256)
    declared_at: str | None = Field(default=None, max_length=128)
    authority_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_nodes(self) -> "RegistryAncestryManifest":
        ids = [node.node_id for node in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("Registry ancestry node IDs must be unique.")
        fingerprints = [node.fingerprint_sha256 for node in self.nodes]
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("Registry ancestry fingerprints must be unique within one manifest.")
        return self


def _payload(manifest: RegistryAncestryManifest | None = None, **kwargs) -> bytes:
    body = (
        manifest.model_dump(mode="json", exclude={"authority_signature"})
        if manifest is not None
        else dict(kwargs)
    )
    return canonical_json(body).encode("utf-8")


def _graph_errors(manifest: RegistryAncestryManifest) -> list[str]:
    errors: list[str] = []
    by_id = {node.node_id: node for node in manifest.nodes}
    if manifest.output_node_id not in by_id:
        return ["registry-ancestry-output-missing"]
    for node in manifest.nodes:
        unknown = sorted(set(node.upstream_node_ids) - set(by_id))
        if unknown:
            errors.append(f"registry-ancestry-unknown-upstream:{node.node_id}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            errors.append("registry-ancestry-cycle")
            return
        visiting.add(node_id)
        node = by_id.get(node_id)
        if node is not None:
            for upstream in node.upstream_node_ids:
                if upstream in by_id:
                    visit(upstream)
        visiting.remove(node_id)
        visited.add(node_id)

    visit(manifest.output_node_id)
    if len(visited) != len(by_id):
        errors.append("registry-ancestry-disconnected-node")
    roles = {node.role for node in manifest.nodes}
    if DependencyRole.ORIGIN not in roles:
        errors.append("registry-ancestry-origin-missing")
    if not roles.intersection({
        DependencyRole.TRANSFORM,
        DependencyRole.EXECUTION,
        DependencyRole.INSTRUMENT,
        DependencyRole.MODEL,
        DependencyRole.OTHER,
    }):
        errors.append("registry-ancestry-process-missing")
    return sorted(set(errors))


def sign_registry_ancestry_manifest(
    *,
    registry_authority_id: str,
    registry_source_group: str,
    private_key: Ed25519PrivateKey,
    output_node_id: str,
    nodes: list[DependencyNode],
    declared_at: str | None = None,
) -> RegistryAncestryManifest:
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    body = {
        "registry_authority_id": registry_authority_id,
        "registry_authority_public_key": public_key,
        "registry_source_group": registry_source_group,
        "output_node_id": output_node_id,
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "declared_at": declared_at,
    }
    candidate = RegistryAncestryManifest(**body, authority_signature="0" * 128)
    errors = _graph_errors(candidate)
    if errors:
        raise ValueError("Invalid registry ancestry graph: " + ", ".join(errors))
    signature = private_key.sign(_payload(**body)).hex()
    return RegistryAncestryManifest(**body, authority_signature=signature)


def verify_registry_ancestry_manifest(manifest: RegistryAncestryManifest) -> tuple[bool, list[str]]:
    errors = _graph_errors(manifest)
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest.registry_authority_public_key))
        public.verify(bytes.fromhex(manifest.authority_signature), _payload(manifest))
    except Exception:
        errors.append("registry-ancestry-signature")
    return not errors, sorted(set(errors))


def registry_ancestry_manifest_sha256(manifest: RegistryAncestryManifest) -> str:
    return sha256_object(manifest.model_dump(mode="json"))


def _all_fingerprints(manifest: RegistryAncestryManifest) -> set[str]:
    return {node.fingerprint_sha256 for node in manifest.nodes}


def _root_fingerprints(manifest: RegistryAncestryManifest) -> set[str]:
    return {node.fingerprint_sha256 for node in manifest.nodes if not node.upstream_node_ids}


class WitnessRegistryAncestryPolicy(BaseModel):
    """v0.17 policy: recurse ancestry checks into dependency registries."""

    model_config = ConfigDict(extra="forbid")

    registry: WitnessRegistryPolicy
    registry_source_group_by_public_key: dict[str, str] = Field(min_length=2, max_length=32)
    require_cross_registry_fingerprint_disjointness: bool = True
    minimum_declared_nodes_per_manifest: int = Field(default=2, ge=2, le=256)
    minimum_root_nodes_per_manifest: int = Field(default=1, ge=1, le=64)

    @model_validator(mode="after")
    def validate_registry_sources(self) -> "WitnessRegistryAncestryPolicy":
        committed = set(self.registry.registry_authority_public_keys)
        mapped = set(self.registry_source_group_by_public_key)
        if mapped != committed:
            raise ValueError("Registry ancestry source-group map must exactly cover committed registry authority keys.")
        groups = list(self.registry_source_group_by_public_key.values())
        if any(not group.strip() or len(group) > 512 for group in groups):
            raise ValueError("Registry ancestry source groups must be non-empty and at most 512 characters.")
        if len(groups) != len(set(groups)):
            raise ValueError("Registry ancestry source groups must be unique across committed registry authorities.")
        return self


def verify_registry_ancestry(
    *,
    policy: WitnessRegistryAncestryPolicy,
    challenge_universe: list[WitnessChallengeSpec],
    selected: list[WitnessChallengeSpec],
    measurement_receipts: list[WitnessMeasurementReceipt],
    ancestry_manifests: list[MeasurementAncestryManifest],
    registry_attestations: list[DependencyRegistryAttestation],
    registry_ancestry_manifests: list[RegistryAncestryManifest],
    required_atom_ids: set[str],
) -> tuple[bool, list[str], dict[str, object]]:
    """Verify the full v0.16 registry path, then recurse into registry ancestry.

    Every registry attestation under this profile must bind a preregistered
    registry-ancestry manifest for the exact authority/source-group pair.  If
    two source groups used for the same challenge share any declared upstream
    fingerprint, they do not count as independent registry channels.
    """

    errors: list[str] = []
    registry_ok, registry_errors, registry_details = verify_dependency_registry(
        policy=policy.registry,
        challenge_universe=challenge_universe,
        selected=selected,
        measurement_receipts=measurement_receipts,
        ancestry_manifests=ancestry_manifests,
        registry_attestations=registry_attestations,
        required_atom_ids=required_atom_ids,
    )
    if not registry_ok:
        errors.extend("registry:" + item for item in registry_errors)

    committed_keys = set(policy.registry.registry_authority_public_keys)
    manifest_by_pair: dict[tuple[str, str], RegistryAncestryManifest] = {}
    duplicate_pairs: set[tuple[str, str]] = set()
    invalid_manifests: list[str] = []

    for manifest in registry_ancestry_manifests:
        pair = (manifest.registry_authority_public_key, manifest.registry_source_group)
        if pair in manifest_by_pair:
            duplicate_pairs.add(pair)
            continue
        valid, manifest_errors = verify_registry_ancestry_manifest(manifest)
        bound = (
            valid
            and manifest.registry_authority_public_key in committed_keys
            and policy.registry_source_group_by_public_key.get(manifest.registry_authority_public_key) == manifest.registry_source_group
            and len(manifest.nodes) >= policy.minimum_declared_nodes_per_manifest
            and len(_root_fingerprints(manifest)) >= policy.minimum_root_nodes_per_manifest
        )
        if not bound:
            invalid_manifests.append(
                f"invalid-registry-ancestry:{manifest.registry_authority_id}:{manifest.registry_source_group}"
            )
            invalid_manifests.extend(
                f"{item}:{manifest.registry_authority_id}:{manifest.registry_source_group}"
                for item in manifest_errors
            )
            continue
        manifest_by_pair[pair] = manifest

    for key, group in sorted(duplicate_pairs):
        errors.append(f"duplicate-registry-ancestry:{key[:16]}:{group}")
    errors.extend(invalid_manifests)

    bound_pairs_by_challenge: dict[str, set[tuple[str, str]]] = defaultdict(set)
    missing_bindings: list[str] = []
    for attestation in registry_attestations:
        pair = (attestation.registry_authority_public_key, attestation.registry_source_group)
        manifest = manifest_by_pair.get(pair)
        expected_sha = registry_ancestry_manifest_sha256(manifest) if manifest is not None else None
        if (
            manifest is None
            or not attestation.registry_ancestry_manifest_sha256
            or attestation.registry_ancestry_manifest_sha256 != expected_sha
        ):
            missing_bindings.append(
                f"registry-ancestry-binding:{attestation.challenge_id}:{attestation.registry_authority_id}"
            )
            continue
        bound_pairs_by_challenge[attestation.challenge_id].add(pair)
    errors.extend(missing_bindings)

    overlap_details: dict[str, list[str]] = {}
    root_details: dict[str, dict[str, list[str]]] = {}
    if policy.require_cross_registry_fingerprint_disjointness:
        for spec in challenge_universe:
            pairs = bound_pairs_by_challenge.get(spec.challenge_id, set())
            fingerprint_to_groups: dict[str, set[str]] = defaultdict(set)
            group_roots: dict[str, set[str]] = defaultdict(set)
            for pair in pairs:
                manifest = manifest_by_pair[pair]
                group = manifest.registry_source_group
                group_roots[group].update(_root_fingerprints(manifest))
                for fingerprint in _all_fingerprints(manifest):
                    fingerprint_to_groups[fingerprint].add(group)
            overlaps = {
                fp: groups for fp, groups in fingerprint_to_groups.items() if len(groups) > 1
            }
            if overlaps:
                errors.append(f"registry-ancestry-cross-source-overlap:{spec.challenge_id}")
                overlap_details[spec.challenge_id] = sorted(overlaps)
            root_details[spec.challenge_id] = {
                group: sorted(values) for group, values in sorted(group_roots.items())
            }

    selected_ids = {item.challenge_id for item in selected}
    for challenge_id in sorted(selected_ids):
        source_groups = {
            group for _, group in bound_pairs_by_challenge.get(challenge_id, set())
        }
        if len(source_groups) < policy.registry.minimum_registry_source_groups_per_challenge:
            errors.append(f"selected-registry-ancestry-diversity:{challenge_id}")

    details = {
        "valid_registry_ancestry_manifest_count": len(manifest_by_pair),
        "registry_ancestry_root_fingerprints": root_details,
        "registry_ancestry_overlap_fingerprints": overlap_details,
        "missing_registry_ancestry_bindings": sorted(missing_bindings),
        "invalid_registry_ancestry_manifests": sorted(invalid_manifests),
        "registry_status": "PASS" if registry_ok else "HOLD",
        "registry_details": registry_details,
    }
    return not errors, sorted(set(errors)), details
