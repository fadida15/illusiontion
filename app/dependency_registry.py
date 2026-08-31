from __future__ import annotations

from collections import defaultdict
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .integrity import canonical_json, sha256_object
from .measurement_provenance import (
    WitnessMeasurementReceipt,
    WitnessProvenancePolicy,
    measurement_receipt_sha256,
    verify_measurement_receipt,
)
from .witness_quorum import WitnessChallengeSpec


class DependencyRole(str, Enum):
    ORIGIN = "ORIGIN"
    TRANSFORM = "TRANSFORM"
    CALIBRATION = "CALIBRATION"
    MODEL = "MODEL"
    INSTRUMENT = "INSTRUMENT"
    EXECUTION = "EXECUTION"
    OTHER = "OTHER"


class DependencyNode(BaseModel):
    """One declared dependency in a measurement ancestry graph.

    fingerprint_sha256 is the stable identity used to detect aliasing across
    separately named dependency groups. It should identify the upstream object
    itself (dataset/calibration/model/instrument/pipeline input), not the local
    label used by this manifest.
    """

    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(min_length=1, max_length=256)
    role: DependencyRole
    fingerprint_sha256: str = Field(min_length=64, max_length=64)
    description: str = Field(min_length=1, max_length=4096)
    upstream_node_ids: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def unique_upstream_ids(self) -> "DependencyNode":
        if len(self.upstream_node_ids) != len(set(self.upstream_node_ids)):
            raise ValueError("Dependency upstream node IDs must be unique.")
        if self.node_id in self.upstream_node_ids:
            raise ValueError("Dependency node cannot depend directly on itself.")
        return self


class MeasurementAncestryManifest(BaseModel):
    """Signed declared ancestry for one held-out measurement artifact."""

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=256)
    atom_id: str = Field(min_length=1, max_length=256)
    measurement_id: str = Field(min_length=1, max_length=512)
    measurement_artifact_sha256: str = Field(min_length=64, max_length=64)
    measurement_authority_id: str = Field(min_length=1, max_length=512)
    measurement_authority_public_key: str = Field(min_length=64, max_length=64)
    output_node_id: str = Field(min_length=1, max_length=256)
    nodes: list[DependencyNode] = Field(min_length=2, max_length=256)
    declared_at: str | None = Field(default=None, max_length=128)
    authority_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_nodes(self) -> "MeasurementAncestryManifest":
        ids = [node.node_id for node in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("Dependency node IDs must be unique within an ancestry manifest.")
        fingerprints = [node.fingerprint_sha256 for node in self.nodes]
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("Dependency fingerprints must be unique within an ancestry manifest.")
        return self


def _payload(manifest: MeasurementAncestryManifest | None = None, **kwargs) -> bytes:
    if manifest is not None:
        body = manifest.model_dump(mode="json", exclude={"authority_signature"})
    else:
        body = dict(kwargs)
    return canonical_json(body).encode("utf-8")


def _graph_errors(manifest: MeasurementAncestryManifest) -> list[str]:
    errors: list[str] = []
    by_id = {node.node_id: node for node in manifest.nodes}
    if manifest.output_node_id not in by_id:
        return ["ancestry-output-missing"]
    for node in manifest.nodes:
        unknown = sorted(set(node.upstream_node_ids) - set(by_id))
        if unknown:
            errors.append(f"ancestry-unknown-upstream:{node.node_id}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            errors.append("ancestry-cycle")
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
        errors.append("ancestry-disconnected-node")
    roles = {node.role for node in manifest.nodes}
    if DependencyRole.ORIGIN not in roles:
        errors.append("ancestry-origin-missing")
    if not roles.intersection({DependencyRole.TRANSFORM, DependencyRole.EXECUTION, DependencyRole.INSTRUMENT, DependencyRole.MODEL}):
        errors.append("ancestry-process-missing")
    return sorted(set(errors))


def sign_ancestry_manifest(
    *,
    spec: WitnessChallengeSpec,
    measurement_id: str,
    measurement_authority_id: str,
    private_key: Ed25519PrivateKey,
    output_node_id: str,
    nodes: list[DependencyNode],
    declared_at: str | None = None,
) -> MeasurementAncestryManifest:
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    body = {
        "challenge_id": spec.challenge_id,
        "atom_id": spec.atom_id,
        "measurement_id": measurement_id,
        "measurement_artifact_sha256": spec.measurement_artifact_sha256,
        "measurement_authority_id": measurement_authority_id,
        "measurement_authority_public_key": public_key,
        "output_node_id": output_node_id,
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "declared_at": declared_at,
    }
    candidate = MeasurementAncestryManifest(**body, authority_signature="0" * 128)
    graph_errors = _graph_errors(candidate)
    if graph_errors:
        raise ValueError("Invalid ancestry graph: " + ", ".join(graph_errors))
    signature = private_key.sign(_payload(**body)).hex()
    return MeasurementAncestryManifest(**body, authority_signature=signature)


def verify_ancestry_manifest(manifest: MeasurementAncestryManifest) -> tuple[bool, list[str]]:
    errors = _graph_errors(manifest)
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(manifest.measurement_authority_public_key))
        public.verify(bytes.fromhex(manifest.authority_signature), _payload(manifest))
    except Exception:
        errors.append("ancestry-signature")
    return not errors, sorted(set(errors))


def ancestry_manifest_sha256(manifest: MeasurementAncestryManifest) -> str:
    return sha256_object(manifest.model_dump(mode="json"))


class WitnessAncestryPolicy(BaseModel):
    """v0.15 policy: authenticate dependency ancestry, then require declared groups to be root-disjoint."""

    model_config = ConfigDict(extra="forbid")

    provenance: WitnessProvenancePolicy
    require_cross_group_fingerprint_disjointness: bool = True
    minimum_declared_nodes_per_manifest: int = Field(default=2, ge=2, le=256)
    minimum_root_nodes_per_manifest: int = Field(default=1, ge=1, le=64)


def _root_fingerprints(manifest: MeasurementAncestryManifest) -> set[str]:
    return {node.fingerprint_sha256 for node in manifest.nodes if not node.upstream_node_ids}


def _all_fingerprints(manifest: MeasurementAncestryManifest) -> set[str]:
    return {node.fingerprint_sha256 for node in manifest.nodes}


def verify_dependency_ancestry(
    *,
    policy: WitnessAncestryPolicy,
    challenge_universe: list[WitnessChallengeSpec],
    selected: list[WitnessChallengeSpec],
    measurement_receipts: list[WitnessMeasurementReceipt],
    ancestry_manifests: list[MeasurementAncestryManifest],
    required_atom_ids: set[str],
) -> tuple[bool, list[str], dict[str, object]]:
    errors: list[str] = []
    receipt_by_id = {item.challenge_id: item for item in measurement_receipts}
    manifest_by_id = {item.challenge_id: item for item in ancestry_manifests}
    universe_by_id = {item.challenge_id: item for item in challenge_universe}
    if len(manifest_by_id) != len(ancestry_manifests):
        errors.append("duplicate-ancestry-manifest")
    if set(manifest_by_id) != set(universe_by_id):
        errors.append("ancestry-manifest-coverage")

    valid_manifests: dict[str, MeasurementAncestryManifest] = {}
    by_atom_group_fingerprints: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    by_atom_group_roots: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    committed_measurement_keys = set(policy.provenance.measurement_authority_public_keys)
    for challenge_id, spec in universe_by_id.items():
        manifest = manifest_by_id.get(challenge_id)
        receipt = receipt_by_id.get(challenge_id)
        if manifest is None or receipt is None:
            continue
        valid, manifest_errors = verify_ancestry_manifest(manifest)
        if manifest_errors:
            errors.extend(f"{item}:{challenge_id}" for item in manifest_errors)
        manifest_sha = ancestry_manifest_sha256(manifest)
        receipt_valid = verify_measurement_receipt(receipt)
        bound = (
            valid
            and receipt_valid
            and manifest.challenge_id == spec.challenge_id
            and manifest.atom_id == spec.atom_id
            and manifest.measurement_id == receipt.measurement_id
            and manifest.measurement_artifact_sha256 == spec.measurement_artifact_sha256
            and manifest.measurement_artifact_sha256 == receipt.measurement_artifact_sha256
            and manifest.measurement_authority_public_key == receipt.measurement_authority_public_key
            and manifest.measurement_authority_public_key in committed_measurement_keys
            and receipt.ancestry_manifest_sha256 == manifest_sha
            and len(manifest.nodes) >= policy.minimum_declared_nodes_per_manifest
            and len(_root_fingerprints(manifest)) >= policy.minimum_root_nodes_per_manifest
        )
        if not bound:
            errors.append(f"ancestry-binding:{challenge_id}")
            continue
        valid_manifests[challenge_id] = manifest
        by_atom_group_fingerprints[spec.atom_id][spec.dependency_group].update(_all_fingerprints(manifest))
        by_atom_group_roots[spec.atom_id][spec.dependency_group].update(_root_fingerprints(manifest))

    overlap_details: dict[str, list[str]] = {}
    if policy.require_cross_group_fingerprint_disjointness:
        for atom_id in sorted(required_atom_ids):
            groups = by_atom_group_fingerprints.get(atom_id, {})
            fingerprint_to_groups: dict[str, set[str]] = defaultdict(set)
            for group, fingerprints in groups.items():
                for fingerprint in fingerprints:
                    fingerprint_to_groups[fingerprint].add(group)
            overlaps = {
                fingerprint: sorted(group_names)
                for fingerprint, group_names in fingerprint_to_groups.items()
                if len(group_names) > 1
            }
            if overlaps:
                errors.append(f"ancestry-cross-group-overlap:{atom_id}")
                overlap_details[atom_id] = sorted(overlaps)

    selected_ids = {item.challenge_id for item in selected}
    selected_valid = sorted(selected_ids & set(valid_manifests))
    if selected_ids != set(selected_valid):
        errors.append("selected-ancestry-coverage")

    details = {
        "valid_ancestry_manifest_count": len(valid_manifests),
        "selected_valid_ancestry_count": len(selected_valid),
        "universe_group_root_fingerprints": {
            atom: {group: sorted(values) for group, values in groups.items()}
            for atom, groups in by_atom_group_roots.items()
        },
        "overlap_fingerprints": overlap_details,
    }
    return not errors, sorted(set(errors)), details
