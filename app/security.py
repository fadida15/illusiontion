from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ReviewerName = Literal["decomposer", "evidence", "challenger", "scope", "security", "entailment", "counterexample"]


class Verdict(str, Enum):
    PASS = "PASS"
    HOLD = "HOLD"
    REJECT = "REJECT"


class FindingType(str, Enum):
    FABRICATION = "FABRICATION"
    CONTRADICTION = "CONTRADICTION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    SCOPE_INFLATION = "SCOPE_INFLATION"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    MALFORMED_EVIDENCE = "MALFORMED_EVIDENCE"
    REVIEWER_ROLE_VIOLATION = "REVIEWER_ROLE_VIOLATION"
    EVIDENCE_TAMPER = "EVIDENCE_TAMPER"
    INVALID_RUNTIME_RECEIPT = "INVALID_RUNTIME_RECEIPT"
    REVIEW_OUTPUT_TAMPER = "REVIEW_OUTPUT_TAMPER"
    REVIEW_CONTEXT_CONTAMINATION = "REVIEW_CONTEXT_CONTAMINATION"
    DUPLICATE_REVIEW_INVOCATION = "DUPLICATE_REVIEW_INVOCATION"
    DECOMPOSITION_GAP = "DECOMPOSITION_GAP"
    ATOMIC_COVERAGE_GAP = "ATOMIC_COVERAGE_GAP"
    SOURCE_DIVERSITY_GAP = "SOURCE_DIVERSITY_GAP"
    SOURCE_PROVENANCE_MISSING = "SOURCE_PROVENANCE_MISSING"
    DUPLICATE_ATOMIC_CLAIM = "DUPLICATE_ATOMIC_CLAIM"
    EVIDENCE_ADMISSION_MISSING = "EVIDENCE_ADMISSION_MISSING"
    INVALID_EVIDENCE_ADMISSION = "INVALID_EVIDENCE_ADMISSION"
    EVIDENCE_ACQUISITION_FAILED = "EVIDENCE_ACQUISITION_FAILED"
    EVIDENCE_ORIGIN_DIVERSITY_GAP = "EVIDENCE_ORIGIN_DIVERSITY_GAP"
    DUPLICATE_EVIDENCE_CAPTURE = "DUPLICATE_EVIDENCE_CAPTURE"
    MODEL_EXECUTION_UNBOUND = "MODEL_EXECUTION_UNBOUND"
    MODEL_OUTPUT_MALFORMED = "MODEL_OUTPUT_MALFORMED"
    MODEL_SCHEMA_MISMATCH = "MODEL_SCHEMA_MISMATCH"
    DUPLICATE_MODEL_RESPONSE = "DUPLICATE_MODEL_RESPONSE"
    INVOCATION_CONTINUITY_FAILURE = "INVOCATION_CONTINUITY_FAILURE"
    EVIDENCE_SPACE_VIOLATION = "EVIDENCE_SPACE_VIOLATION"
    MATERIAL_TRANSITION_LEAKAGE = "MATERIAL_TRANSITION_LEAKAGE"
    ENTAILMENT_GAP = "ENTAILMENT_GAP"
    COUNTEREXAMPLE_FOUND = "COUNTEREXAMPLE_FOUND"
    SEMANTIC_REVIEW_COVERAGE_GAP = "SEMANTIC_REVIEW_COVERAGE_GAP"
    REPRESENTATION_DISAGREEMENT = "REPRESENTATION_DISAGREEMENT"
    SEMANTIC_OBLIGATION_GAP = "SEMANTIC_OBLIGATION_GAP"
    SEMANTIC_OBLIGATION_FAILED = "SEMANTIC_OBLIGATION_FAILED"
    EXTERNAL_WITNESS_GAP = "EXTERNAL_WITNESS_GAP"
    EXTERNAL_WITNESS_INVALID = "EXTERNAL_WITNESS_INVALID"
    EXTERNAL_WITNESS_NOT_INDEPENDENT = "EXTERNAL_WITNESS_NOT_INDEPENDENT"
    EXTERNAL_WITNESS_COUNTEREXAMPLE = "EXTERNAL_WITNESS_COUNTEREXAMPLE"
    EXTERNAL_WITNESS_UNRESOLVED = "EXTERNAL_WITNESS_UNRESOLVED"
    WITNESS_SELECTION_INVALID = "WITNESS_SELECTION_INVALID"
    WITNESS_AUTHORITY_QUORUM_GAP = "WITNESS_AUTHORITY_QUORUM_GAP"
    WITNESS_AUTHORITY_DISAGREEMENT = "WITNESS_AUTHORITY_DISAGREEMENT"
    WITNESS_CHALLENGE_SUBSTITUTION = "WITNESS_CHALLENGE_SUBSTITUTION"
    WITNESS_MEASUREMENT_PROVENANCE_INVALID = "WITNESS_MEASUREMENT_PROVENANCE_INVALID"
    WITNESS_DEPENDENCY_DIVERSITY_GAP = "WITNESS_DEPENDENCY_DIVERSITY_GAP"
    WITNESS_MEASUREMENT_AUTHORITY_GAP = "WITNESS_MEASUREMENT_AUTHORITY_GAP"
    WITNESS_ANCESTRY_INVALID = "WITNESS_ANCESTRY_INVALID"
    WITNESS_ANCESTRY_OVERLAP = "WITNESS_ANCESTRY_OVERLAP"
    WITNESS_REGISTRY_INVALID = "WITNESS_REGISTRY_INVALID"
    WITNESS_REGISTRY_DISCLOSURE_GAP = "WITNESS_REGISTRY_DISCLOSURE_GAP"
    WITNESS_REGISTRY_ANCESTRY_INVALID = "WITNESS_REGISTRY_ANCESTRY_INVALID"
    WITNESS_REGISTRY_ANCESTRY_OVERLAP = "WITNESS_REGISTRY_ANCESTRY_OVERLAP"
    WITNESS_REGISTRY_OBSERVATION_INVALID = "WITNESS_REGISTRY_OBSERVATION_INVALID"
    WITNESS_REGISTRY_OBSERVATION_DISCLOSURE_GAP = "WITNESS_REGISTRY_OBSERVATION_DISCLOSURE_GAP"


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class ReviewStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    LOOP_DETECTED = "LOOP_DETECTED"


class ReviewContextMode(str, Enum):
    ISOLATED = "ISOLATED"
    SHARED = "SHARED"
    UNKNOWN = "UNKNOWN"


class AssuranceProfile(str, Enum):
    """Evidence/review assurance policy, not a truth guarantee."""

    STANDARD = "STANDARD"
    CORROBORATED = "CORROBORATED"
    FORTIFIED = "FORTIFIED"
    MODEL_BOUND = "MODEL_BOUND"
    SEMANTIC_FORTIFIED = "SEMANTIC_FORTIFIED"
    REPRESENTATION_FORTIFIED = "REPRESENTATION_FORTIFIED"
    EXTERNAL_WITNESS_FORTIFIED = "EXTERNAL_WITNESS_FORTIFIED"
    WITNESS_QUORUM_FORTIFIED = "WITNESS_QUORUM_FORTIFIED"
    WITNESS_PROVENANCE_FORTIFIED = "WITNESS_PROVENANCE_FORTIFIED"
    WITNESS_ANCESTRY_FORTIFIED = "WITNESS_ANCESTRY_FORTIFIED"
    WITNESS_REGISTRY_FORTIFIED = "WITNESS_REGISTRY_FORTIFIED"
    WITNESS_REGISTRY_ANCESTRY_FORTIFIED = "WITNESS_REGISTRY_ANCESTRY_FORTIFIED"
    WITNESS_REGISTRY_OBSERVATION_FORTIFIED = "WITNESS_REGISTRY_OBSERVATION_FORTIFIED"


class SemanticQuantifier(str, Enum):
    POINT = "POINT"
    CONDITIONAL = "CONDITIONAL"
    UNIVERSAL = "UNIVERSAL"
    EXISTENTIAL = "EXISTENTIAL"
    COMPARATIVE = "COMPARATIVE"
    UNKNOWN = "UNKNOWN"


class SemanticRelation(str, Enum):
    DESCRIPTIVE = "DESCRIPTIVE"
    CAUSAL = "CAUSAL"
    ASSOCIATIONAL = "ASSOCIATIONAL"
    COMPARATIVE = "COMPARATIVE"
    UNKNOWN = "UNKNOWN"


class SemanticObligationType(str, Enum):
    SOURCE_CLASSIFICATION = "SOURCE_CLASSIFICATION"
    JOINT_ENTAILMENT = "JOINT_ENTAILMENT"
    SCOPE_BOUNDARY = "SCOPE_BOUNDARY"
    COUNTEREXAMPLE_SEARCH = "COUNTEREXAMPLE_SEARCH"


class SemanticObligationResult(str, Enum):
    SUPPORTS = "SUPPORTS"
    NEUTRAL = "NEUTRAL"
    CONTRADICTS = "CONTRADICTS"
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNRESOLVED = "UNRESOLVED"
    WITHIN_SCOPE = "WITHIN_SCOPE"
    SCOPE_GAP = "SCOPE_GAP"
    NO_COUNTEREXAMPLE_FOUND = "NO_COUNTEREXAMPLE_FOUND"
    COUNTEREXAMPLE_FOUND = "COUNTEREXAMPLE_FOUND"




class ExternalWitnessResult(str, Enum):
    SURVIVED_CHALLENGE = "SURVIVED_CHALLENGE"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    UNRESOLVED = "UNRESOLVED"
    EXECUTION_FAILED = "EXECUTION_FAILED"


class ExternalWitnessCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str = Field(min_length=1, max_length=256)
    atom_id: str = Field(min_length=1, max_length=256)
    challenge: str = Field(min_length=1, max_length=20_000)
    result: ExternalWitnessResult
    source: str = Field(min_length=1, max_length=4096)
    source_group: str = Field(min_length=1, max_length=512)
    observation: str = Field(min_length=1, max_length=100_000)
    method: str = Field(min_length=1, max_length=512)
    observed_at: str | None = None


class ExternalWitnessSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(default="", max_length=256)
    claim_sha256: str = Field(min_length=64, max_length=64)
    verifier_id: str = Field(min_length=1, max_length=512)
    verifier_public_key: str = Field(min_length=64, max_length=64)
    checks: list[ExternalWitnessCheck] = Field(min_length=1, max_length=2048)
    verifier_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_check_ids(self) -> "ExternalWitnessSet":
        ids = [check.check_id for check in self.checks]
        if len(ids) != len(set(ids)):
            raise ValueError("External witness check IDs must be unique.")
        return self


class ReviewExecutionMode(str, Enum):
    HOST_FIXTURE = "HOST_FIXTURE"
    MODEL_REPLAY = "MODEL_REPLAY"
    MODEL_LIVE = "MODEL_LIVE"


class EvidenceAdmissionStatus(str, Enum):
    CAPTURED = "CAPTURED"
    FAILED = "FAILED"


class EvidenceItem(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=4096)
    # Declared common-control / common-origin family. Two URLs mirroring the
    # same paper, API, organization, or upstream dataset should share a group.
    source_group: str = Field(min_length=1, max_length=512)
    excerpt: str = Field(default="", max_length=250_000)
    retrieved_at: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict, max_length=64)


class EvidenceAdmissionReceipt(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=256)
    evidence_sha256: str = Field(min_length=64, max_length=64)
    source_origin: str = Field(min_length=1)
    status: EvidenceAdmissionStatus
    capture_method: str = Field(min_length=1)
    capture_id: str = Field(min_length=1)
    captured_at: str | None = None
    detail: str = ""
    runtime_signature: str = Field(min_length=64, max_length=64)


class EvidenceBundle(BaseModel):
    items: list[EvidenceItem] = Field(default_factory=list, max_length=512)
    admissions: list[EvidenceAdmissionReceipt] = Field(default_factory=list, max_length=512)

    @model_validator(mode="after")
    def unique_ids(self) -> "EvidenceBundle":
        ids = [item.evidence_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("Evidence IDs must be unique.")
        admission_ids = [item.evidence_id for item in self.admissions]
        if len(admission_ids) != len(set(admission_ids)):
            raise ValueError("At most one evidence admission is allowed per evidence ID.")
        return self

    def by_id(self) -> dict[str, EvidenceItem]:
        return {item.evidence_id: item for item in self.items}

    def admissions_by_evidence_id(self) -> dict[str, EvidenceAdmissionReceipt]:
        return {item.evidence_id: item for item in self.admissions}


class ClaimAtom(BaseModel):
    atom_id: str = Field(min_length=1, max_length=256)
    statement: str = Field(min_length=1, max_length=50_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=512)

    @model_validator(mode="after")
    def unique_evidence_ids(self) -> "ClaimAtom":
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("Atomic claim evidence IDs must be unique.")
        return self


class ClaimCandidate(BaseModel):
    claim_id: str = Field(min_length=1, max_length=256)
    claim: str = Field(min_length=1, max_length=100_000)
    declared_scope: str = Field(min_length=1, max_length=20_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=512)
    atoms: list[ClaimAtom] = Field(default_factory=list, max_length=512)
    assurance_profile: AssuranceProfile = AssuranceProfile.CORROBORATED

    @model_validator(mode="after")
    def unique_ids(self) -> "ClaimCandidate":
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("Claim evidence IDs must be unique.")
        atom_ids = [atom.atom_id for atom in self.atoms]
        if len(atom_ids) != len(set(atom_ids)):
            raise ValueError("Atomic claim IDs must be unique.")
        return self


class ReviewFinding(BaseModel):
    reviewer: ReviewerName
    finding_type: FindingType
    severity: Severity
    message: str = Field(min_length=1, max_length=20_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=512)


class ModelFinding(BaseModel):
    """Strict reviewer finding schema returned by a model.

    The reviewer identity is intentionally absent: trusted runtime stamps it
    from the invocation role, so a model cannot impersonate another reviewer.
    """

    model_config = ConfigDict(extra="forbid")

    finding_type: FindingType
    severity: Severity
    message: str = Field(min_length=1, max_length=20_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=512)


class ModelSemanticFrame(BaseModel):
    """Independent structured reading of one claim atom."""

    model_config = ConfigDict(extra="forbid")

    atom_id: str = Field(min_length=1, max_length=256)
    quantifier: SemanticQuantifier
    relation: SemanticRelation
    normalized_statement: str = Field(min_length=1, max_length=20_000)
    conditions: list[str] = Field(default_factory=list, max_length=64)


class ModelSemanticObligation(BaseModel):
    """One falsifiable semantic work product emitted by a strategy reviewer."""

    model_config = ConfigDict(extra="forbid")

    atom_id: str = Field(min_length=1, max_length=256)
    obligation_type: SemanticObligationType
    result: SemanticObligationResult
    evidence_id: str | None = Field(default=None, max_length=256)
    witness_evidence_ids: list[str] = Field(default_factory=list, max_length=512)
    rationale: str = Field(min_length=1, max_length=20_000)


class SemanticFrame(ModelSemanticFrame):
    reviewer: ReviewerName


class SemanticObligationCheck(ModelSemanticObligation):
    reviewer: ReviewerName


class ModelReviewOutput(BaseModel):
    """Only accepted semantic output from a reviewer model.

    There is deliberately no PASS/HOLD/REJECT field. Verdict authority remains
    outside the model. Extra keys are rejected rather than silently ignored.
    """

    model_config = ConfigDict(extra="forbid")

    findings: list[ModelFinding] = Field(default_factory=list, max_length=512)
    semantic_frames: list[ModelSemanticFrame] = Field(default_factory=list, max_length=512)
    semantic_obligations: list[ModelSemanticObligation] = Field(default_factory=list, max_length=2048)
    notes: str = Field(default="", max_length=20_000)


class ReviewerReceipt(BaseModel):
    reviewer: ReviewerName
    status: ReviewStatus
    claim_sha256: str = Field(min_length=64, max_length=64)
    evidence_digests: dict[str, str] = Field(default_factory=dict)
    findings_sha256: str = Field(min_length=64, max_length=64)
    semantic_artifacts_sha256: str = Field(min_length=64, max_length=64)
    prompt_sha256: str = Field(min_length=64, max_length=64)
    context_mode: ReviewContextMode = ReviewContextMode.UNKNOWN
    upstream_review_digests: list[str] = Field(default_factory=list)
    invocation_id: str = Field(min_length=1)
    run_token: str = Field(min_length=1)
    invocation_sha256: str = Field(min_length=64, max_length=64)
    attempt_context_sha256: str = Field(default="", max_length=64)
    execution_mode: ReviewExecutionMode = ReviewExecutionMode.HOST_FIXTURE
    model_provider: str = "trusted-host"
    model_id: str = "none"
    model_response_id: str = ""
    raw_output_sha256: str = Field(min_length=64, max_length=64)
    raw_output_utf8_bytes: int = Field(default=0, ge=0, le=16 * 1024 * 1024)
    response_schema_sha256: str = Field(min_length=64, max_length=64)
    detail: str = ""
    runtime_signature: str = Field(min_length=64, max_length=64)


class ReviewBundle(BaseModel):
    receipts: list[ReviewerReceipt] = Field(default_factory=list, max_length=16)
    findings: list[ReviewFinding] = Field(default_factory=list, max_length=2048)
    semantic_frames: list[SemanticFrame] = Field(default_factory=list, max_length=2048)
    semantic_obligations: list[SemanticObligationCheck] = Field(default_factory=list, max_length=4096)

    @model_validator(mode="after")
    def unique_receipts(self) -> "ReviewBundle":
        names = [receipt.reviewer for receipt in self.receipts]
        if len(names) != len(set(names)):
            raise ValueError("At most one reviewer receipt is allowed per reviewer.")
        return self

    def receipts_by_reviewer(self) -> dict[str, ReviewerReceipt]:
        return {receipt.reviewer: receipt for receipt in self.receipts}


class AtomAssurance(BaseModel):
    atom_id: str
    required_source_groups: int
    observed_source_groups: int
    source_groups: list[str]
    observed_sources: int
    sources: list[str]
    required_captured_origins: int = 0
    observed_captured_origins: int = 0
    captured_origins: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD"]


class EvidenceTransitionAssurance(BaseModel):
    """Three-space evidence accounting.

    E0/universe is the complete frozen case evidence. E1/transition is the
    candidate-selected projection. E2/reviewer is the evidence set actually
    bound into reviewer receipts. Omission is observable but only material
    omission is blocking by itself.
    """

    universe_ids: list[str] = Field(default_factory=list)
    transition_ids: list[str] = Field(default_factory=list)
    reviewer_ids: list[str] = Field(default_factory=list)
    omitted_ids: list[str] = Field(default_factory=list)
    added_ids: list[str] = Field(default_factory=list)
    mutated_ids: list[str] = Field(default_factory=list)
    material_omission_ids: list[str] = Field(default_factory=list)
    status: Literal["PASS", "OBSERVED", "HOLD"] = "PASS"




class SemanticAssurance(BaseModel):
    """Status of the heterogeneous semantic challenge layer.

    This is a process assurance record, not a truth certificate. It records
    whether the additional entailment/counterexample strategies actually ran
    and how much model diversity was observed across them.
    """

    required_reviewers: list[str] = Field(default_factory=list)
    completed_reviewers: list[str] = Field(default_factory=list)
    model_ids: list[str] = Field(default_factory=list)
    distinct_model_ids: int = 0
    strategy_count: int = 0
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"


class SemanticObligationAssurance(BaseModel):
    required_frame_reviewers: list[str] = Field(default_factory=list)
    atom_ids: list[str] = Field(default_factory=list)
    frame_count: int = 0
    obligation_count: int = 0
    representation_mismatch_atoms: list[str] = Field(default_factory=list)
    missing_obligations: list[str] = Field(default_factory=list)
    failed_obligations: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"




class ExternalWitnessAssurance(BaseModel):
    required_atom_ids: list[str] = Field(default_factory=list)
    covered_atom_ids: list[str] = Field(default_factory=list)
    counterexample_atom_ids: list[str] = Field(default_factory=list)
    unresolved_atom_ids: list[str] = Field(default_factory=list)
    nonindependent_check_ids: list[str] = Field(default_factory=list)
    verifier_id: str = ""
    verifier_public_key: str = ""
    check_count: int = 0
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"


class WitnessQuorumAssurance(BaseModel):
    selection_verified: bool = False
    selected_check_ids: list[str] = Field(default_factory=list)
    authority_ids: list[str] = Field(default_factory=list)
    authority_public_keys: list[str] = Field(default_factory=list)
    valid_authority_count: int = 0
    required_authority_quorum: int = 0
    covered_check_ids: list[str] = Field(default_factory=list)
    counterexample_check_ids: list[str] = Field(default_factory=list)
    unresolved_check_ids: list[str] = Field(default_factory=list)
    disagreement_check_ids: list[str] = Field(default_factory=list)
    invalid_authority_ids: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"




class WitnessProvenanceAssurance(BaseModel):
    measurement_receipt_count: int = 0
    valid_measurement_receipt_count: int = 0
    universe_dependency_groups: dict[str, list[str]] = Field(default_factory=dict)
    selected_dependency_groups: dict[str, list[str]] = Field(default_factory=dict)
    universe_measurement_authorities: dict[str, list[str]] = Field(default_factory=dict)
    selected_measurement_authorities: dict[str, list[str]] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"




class WitnessAncestryAssurance(BaseModel):
    ancestry_manifest_count: int = 0
    valid_ancestry_manifest_count: int = 0
    selected_valid_ancestry_count: int = 0
    universe_group_root_fingerprints: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    overlap_fingerprints: dict[str, list[str]] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"


class WitnessRegistryAssurance(BaseModel):
    registry_attestation_count: int = 0
    valid_registry_authority_counts: dict[str, int] = Field(default_factory=dict)
    registry_source_groups: dict[str, list[str]] = Field(default_factory=dict)
    registry_disclosure_mismatches: dict[str, list[str]] = Field(default_factory=dict)
    negative_attestations: list[str] = Field(default_factory=list)
    invalid_attestations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"



class WitnessRegistryAncestryAssurance(BaseModel):
    registry_ancestry_manifest_count: int = 0
    valid_registry_ancestry_manifest_count: int = 0
    registry_ancestry_root_fingerprints: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    registry_ancestry_overlap_fingerprints: dict[str, list[str]] = Field(default_factory=dict)
    missing_registry_ancestry_bindings: list[str] = Field(default_factory=list)
    invalid_registry_ancestry_manifests: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"

class WitnessRegistryObservationAssurance(BaseModel):
    observation_count: int = 0
    valid_observer_counts: dict[str, int] = Field(default_factory=dict)
    observer_source_groups: dict[str, list[str]] = Field(default_factory=dict)
    registry_observation_disclosure_mismatches: dict[str, list[str]] = Field(default_factory=dict)
    negative_observations: list[str] = Field(default_factory=list)
    invalid_observations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    status: Literal["PASS", "HOLD", "NOT_REQUIRED"] = "NOT_REQUIRED"




class DecisionCalibrationAssurance(BaseModel):
    """v0.20 calibration metadata; never overrides PASS/HOLD/REJECT."""

    status: Literal[
        "CLEAR_PASS",
        "EVIDENCE_DEBT_HOLD",
        "SEMANTIC_DEBT_HOLD",
        "CLAIM_CONFLICT_HOLD",
        "HARD_INTEGRITY_HOLD",
        "MIXED_HOLD",
        "REJECTED",
    ]
    evidence_debt: list[str] = Field(default_factory=list)
    semantic_debt: list[str] = Field(default_factory=list)
    claim_conflicts: list[str] = Field(default_factory=list)
    hard_risks: list[str] = Field(default_factory=list)
    blocker_counts: dict[str, int] = Field(default_factory=dict)
    recovery_actions: list[str] = Field(default_factory=list)
    automatic_relaxation_allowed: bool = False


class RecoveryProbeResult(str, Enum):
    RESOLVED = "RESOLVED"
    COUNTERSIGNAL = "COUNTERSIGNAL"
    UNRESOLVED = "UNRESOLVED"
    EXECUTION_FAILED = "EXECUTION_FAILED"


class RecoveryProbe(BaseModel):
    """Signed post-decision probe. Never changes the original verdict."""

    model_config = ConfigDict(extra="forbid")

    probe_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    calibration_status: Literal["EVIDENCE_DEBT_HOLD", "SEMANTIC_DEBT_HOLD"]
    target_blockers: list[str] = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=512)
    observation: str = Field(min_length=1, max_length=100_000)
    result: RecoveryProbeResult
    authority_id: str = Field(min_length=1, max_length=512)
    authority_public_key: str = Field(min_length=64, max_length=64)
    authority_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_blockers(self) -> "RecoveryProbe":
        if len(self.target_blockers) != len(set(self.target_blockers)):
            raise ValueError("Recovery probe blocker tokens must be unique.")
        return self


class RecoveryAssessment(BaseModel):
    """v0.21 recovery metadata. Authority can only come from a fresh rerun PASS."""

    status: Literal[
        "NOT_APPLICABLE",
        "INVALID_PROBE",
        "RESOLUTION_SIGNAL",
        "COUNTERSIGNAL",
        "UNRESOLVED",
        "RECOVERED_BY_FULL_RERUN",
        "PROBE_NOT_CONFIRMED",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    probe_result: RecoveryProbeResult | None = None
    blockers: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    original_verdict: Verdict
    rerun_verdict: Verdict | None = None
    authoritative_promotion: bool = False
    authority_rule: Literal["RERUN_PASS_ONLY"] = "RERUN_PASS_ONLY"




class RecoveryAuthoritySpec(BaseModel):
    """Precommitted identity and independence metadata for a recovery authority."""

    model_config = ConfigDict(extra="forbid")

    authority_id: str = Field(min_length=1, max_length=512)
    authority_public_key: str = Field(min_length=64, max_length=64)
    source_group: str = Field(min_length=1, max_length=512)
    method_families: dict[str, str] = Field(min_length=1, max_length=64)


class RecoveryPolicy(BaseModel):
    """Signed v0.22 recovery policy. Still grants no promotion authority."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    authorities: list[RecoveryAuthoritySpec] = Field(min_length=2, max_length=32)
    resolved_quorum: int = Field(default=2, ge=2, le=32)
    min_source_groups: int = Field(default=2, ge=2, le=32)
    min_method_families: int = Field(default=2, ge=2, le=32)
    audit_min_resolved_samples: int = Field(default=3, ge=1, le=10_000)
    max_unconfirmed_resolution_rate: float = Field(default=0.25, ge=0.0, le=1.0)
    policy_authority_id: str = Field(min_length=1, max_length=512)
    policy_public_key: str = Field(min_length=64, max_length=64)
    policy_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_authorities(self) -> "RecoveryPolicy":
        ids = [x.authority_id for x in self.authorities]
        keys = [x.authority_public_key for x in self.authorities]
        if len(ids) != len(set(ids)):
            raise ValueError("Recovery policy authority IDs must be unique.")
        if len(keys) != len(set(keys)):
            raise ValueError("Recovery policy authority keys must be unique.")
        return self


class RecoveryProbeEnvelope(BaseModel):
    """Binds a v0.21 RecoveryProbe to its v0.22 independence metadata."""

    model_config = ConfigDict(extra="forbid")

    probe: RecoveryProbe
    source_group: str = Field(min_length=1, max_length=512)
    method_family: str = Field(min_length=1, max_length=512)
    envelope_signature: str = Field(min_length=128, max_length=128)


class RecoveryOutcomeStatus(str, Enum):
    RESOLUTION_CONFIRMED = "RESOLUTION_CONFIRMED"
    RESOLUTION_NOT_CONFIRMED = "RESOLUTION_NOT_CONFIRMED"
    COUNTERSIGNAL_CONFIRMED = "COUNTERSIGNAL_CONFIRMED"
    COUNTERSIGNAL_NOT_CONFIRMED = "COUNTERSIGNAL_NOT_CONFIRMED"
    UNRESOLVED = "UNRESOLVED"
    NO_RERUN = "NO_RERUN"


class RecoveryOutcomeRecord(BaseModel):
    """Audit-signed observation of whether a recovery signal matched the mandatory rerun."""

    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    probe_id: str = Field(min_length=1, max_length=256)
    authority_id: str = Field(min_length=1, max_length=512)
    probe_result: RecoveryProbeResult
    rerun_decision_sha256: str | None = None
    rerun_verdict: Verdict | None = None
    status: RecoveryOutcomeStatus
    audit_authority_id: str = Field(min_length=1, max_length=512)
    audit_public_key: str = Field(min_length=64, max_length=64)
    audit_signature: str = Field(min_length=128, max_length=128)


class RecoveryAuthorityAccountability(BaseModel):
    authority_id: str
    resolved_samples: int = 0
    confirmed_resolutions: int = 0
    unconfirmed_resolutions: int = 0
    unconfirmed_resolution_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    status: Literal["ACTIVE", "PROBATION", "QUARANTINED"] = "PROBATION"
    errors: list[str] = Field(default_factory=list)


class RecoveryQuorumAssessment(BaseModel):
    """v0.22 recovery assessment. Quorum can request a rerun, never promote directly."""

    status: Literal[
        "NOT_APPLICABLE",
        "INVALID_POLICY",
        "INVALID_PROBE_SET",
        "COUNTERSIGNAL",
        "UNRESOLVED",
        "RESOLUTION_QUORUM",
        "RECOVERED_BY_FULL_RERUN",
        "PROBE_NOT_CONFIRMED",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    blockers: list[str] = Field(default_factory=list)
    valid_authorities: list[str] = Field(default_factory=list)
    quarantined_authorities: list[str] = Field(default_factory=list)
    resolved_authorities: list[str] = Field(default_factory=list)
    counter_signal_authorities: list[str] = Field(default_factory=list)
    unresolved_authorities: list[str] = Field(default_factory=list)
    source_groups: list[str] = Field(default_factory=list)
    method_families: list[str] = Field(default_factory=list)
    accountability: dict[str, RecoveryAuthorityAccountability] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    original_verdict: Verdict
    rerun_verdict: Verdict | None = None
    authoritative_promotion: bool = False
    authority_rule: Literal["RERUN_PASS_ONLY"] = "RERUN_PASS_ONLY"

class RecoveryEvidenceLineage(BaseModel):
    """Frozen evidence lineage used only to prove a recovery rerun changed information ancestry."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=256)
    evidence_sha256: str = Field(min_length=64, max_length=64)
    source_group: str = Field(min_length=1, max_length=512)
    source_locator: str = Field(min_length=1, max_length=4096)


class RecoveryReasoningLineage(BaseModel):
    """Committed reasoning lineage for one reviewer role in a recovery rerun."""

    model_config = ConfigDict(extra="forbid")

    reviewer_role: ReviewerName
    model_id: str = Field(min_length=1, max_length=512)
    provider_family: str = Field(min_length=1, max_length=512)
    strategy_family: str = Field(min_length=1, max_length=512)
    prompt_sha256: str = Field(min_length=64, max_length=64)


class RecoveryPathPolicy(BaseModel):
    """Signed v0.23 policy defining what counts as a materially different recovery path."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    evidence_debt_min_new_source_groups: int = Field(default=1, ge=1, le=32)
    evidence_debt_min_new_evidence_items: int = Field(default=1, ge=1, le=512)
    semantic_debt_min_changed_roles: int = Field(default=2, ge=1, le=7)
    semantic_debt_min_new_reasoning_families: int = Field(default=1, ge=1, le=7)
    path_authority_id: str = Field(min_length=1, max_length=512)
    path_authority_public_key: str = Field(min_length=64, max_length=64)
    policy_signature: str = Field(min_length=128, max_length=128)


class RecoveryPathAttestation(BaseModel):
    """Runtime-signed comparison of the original and rerun information/reasoning paths."""

    model_config = ConfigDict(extra="forbid")

    path_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str = Field(min_length=64, max_length=64)
    calibration_status: Literal["EVIDENCE_DEBT_HOLD", "SEMANTIC_DEBT_HOLD"]
    original_evidence: list[RecoveryEvidenceLineage] = Field(default_factory=list, max_length=512)
    rerun_evidence: list[RecoveryEvidenceLineage] = Field(default_factory=list, max_length=512)
    original_reasoning: list[RecoveryReasoningLineage] = Field(default_factory=list, max_length=7)
    rerun_reasoning: list[RecoveryReasoningLineage] = Field(default_factory=list, max_length=7)
    path_authority_id: str = Field(min_length=1, max_length=512)
    path_authority_public_key: str = Field(min_length=64, max_length=64)
    path_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_lineages(self) -> "RecoveryPathAttestation":
        for rows, label in ((self.original_evidence, "original"), (self.rerun_evidence, "rerun")):
            ids = [x.evidence_id for x in rows]
            if len(ids) != len(set(ids)):
                raise ValueError(f"{label} recovery evidence IDs must be unique.")
        for rows, label in ((self.original_reasoning, "original"), (self.rerun_reasoning, "rerun")):
            roles = [x.reviewer_role for x in rows]
            if len(roles) != len(set(roles)):
                raise ValueError(f"{label} recovery reasoning roles must be unique.")
        return self


class RecoveryPathAssessment(BaseModel):
    """v0.23 recovery result. Only a path-independent full rerun PASS may promote."""

    status: Literal[
        "NOT_APPLICABLE",
        "INVALID_RECOVERY_QUORUM",
        "INVALID_PATH_POLICY",
        "INVALID_PATH_ATTESTATION",
        "RERUN_REQUIRED",
        "RERUN_PATH_NOT_INDEPENDENT",
        "PROBE_NOT_CONFIRMED",
        "RECOVERED_BY_INDEPENDENT_FULL_RERUN",
        "COUNTERSIGNAL",
        "UNRESOLVED",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    original_verdict: Verdict
    rerun_verdict: Verdict | None = None
    new_evidence_items: list[str] = Field(default_factory=list)
    new_source_groups: list[str] = Field(default_factory=list)
    changed_reasoning_roles: list[str] = Field(default_factory=list)
    new_reasoning_families: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    authoritative_promotion: bool = False
    authority_rule: Literal["INDEPENDENT_RERUN_PASS_ONLY"] = "INDEPENDENT_RERUN_PASS_ONLY"


class RecoveryLineageAncestry(BaseModel):
    """Declared upstream roots for one recovery evidence/reasoning lineage."""

    model_config = ConfigDict(extra="forbid")

    lineage_key: str = Field(min_length=1, max_length=1536)
    root_fingerprints: list[str] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def unique_roots(self) -> "RecoveryLineageAncestry":
        if len(self.root_fingerprints) != len(set(self.root_fingerprints)):
            raise ValueError("Recovery ancestry roots must be unique.")
        for value in self.root_fingerprints:
            if len(value) != 64:
                raise ValueError("Recovery ancestry root fingerprints must be SHA-256 hex strings.")
            int(value, 16)
        return self


class RecoveryPathAncestryPolicy(BaseModel):
    """v0.24 policy for upstream recovery-lineage independence."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    min_independent_evidence_roots: int = Field(default=1, ge=1, le=64)
    min_independent_reasoning_roots: int = Field(default=1, ge=1, le=64)
    forbid_shared_roots_in_qualifying_lineage: bool = True
    ancestry_authority_id: str = Field(min_length=1, max_length=512)
    ancestry_authority_public_key: str = Field(min_length=64, max_length=64)
    policy_signature: str = Field(min_length=128, max_length=128)


class RecoveryPathAncestryAttestation(BaseModel):
    """Signed ancestry map bound to the exact v0.23 recovery path attestation."""

    model_config = ConfigDict(extra="forbid")

    ancestry_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str = Field(min_length=64, max_length=64)
    path_attestation_sha256: str = Field(min_length=64, max_length=64)
    original_evidence_ancestry: list[RecoveryLineageAncestry] = Field(default_factory=list, max_length=512)
    rerun_evidence_ancestry: list[RecoveryLineageAncestry] = Field(default_factory=list, max_length=512)
    original_reasoning_ancestry: list[RecoveryLineageAncestry] = Field(default_factory=list, max_length=64)
    rerun_reasoning_ancestry: list[RecoveryLineageAncestry] = Field(default_factory=list, max_length=64)
    ancestry_authority_id: str = Field(min_length=1, max_length=512)
    ancestry_authority_public_key: str = Field(min_length=64, max_length=64)
    ancestry_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_lineage_keys(self) -> "RecoveryPathAncestryAttestation":
        for rows, label in (
            (self.original_evidence_ancestry, "original evidence"),
            (self.rerun_evidence_ancestry, "rerun evidence"),
            (self.original_reasoning_ancestry, "original reasoning"),
            (self.rerun_reasoning_ancestry, "rerun reasoning"),
        ):
            keys = [x.lineage_key for x in rows]
            if len(keys) != len(set(keys)):
                raise ValueError(f"{label} recovery ancestry keys must be unique.")
        return self


class RecoveryPathAncestryAssessment(BaseModel):
    """v0.24 result. A v0.23 recovery PASS is authoritative only if upstream ancestry is material."""

    status: Literal[
        "NOT_APPLICABLE",
        "BASE_RECOVERY_NOT_AUTHORIZED",
        "INVALID_ANCESTRY_POLICY",
        "INVALID_ANCESTRY_ATTESTATION",
        "RECOVERY_ANCESTRY_NOT_INDEPENDENT",
        "RECOVERED_BY_ANCESTRY_INDEPENDENT_FULL_RERUN",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    independent_evidence_groups: list[str] = Field(default_factory=list)
    common_mode_evidence_groups: list[str] = Field(default_factory=list)
    independent_reasoning_families: list[str] = Field(default_factory=list)
    common_mode_reasoning_families: list[str] = Field(default_factory=list)
    new_evidence_ancestry_roots: list[str] = Field(default_factory=list)
    new_reasoning_ancestry_roots: list[str] = Field(default_factory=list)
    shared_evidence_ancestry_roots: list[str] = Field(default_factory=list)
    shared_reasoning_ancestry_roots: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    authoritative_promotion: bool = False
    authority_rule: Literal["ANCESTRY_INDEPENDENT_RERUN_PASS_ONLY"] = "ANCESTRY_INDEPENDENT_RERUN_PASS_ONLY"


class RecoveryLineageChallengeResult(str, Enum):
    """External v0.25 observation about one purportedly independent recovery lineage."""

    CLEAR = "CLEAR"
    HIDDEN_OVERLAP = "HIDDEN_OVERLAP"
    DISCLOSURE_GAP = "DISCLOSURE_GAP"
    UNRESOLVED = "UNRESOLVED"


class RecoveryLineageChallengeAuthority(BaseModel):
    """Precommitted external challenger identity and probe families."""

    model_config = ConfigDict(extra="forbid")

    authority_id: str = Field(min_length=1, max_length=512)
    authority_public_key: str = Field(min_length=64, max_length=64)
    source_group: str = Field(min_length=1, max_length=512)
    method_families: dict[str, str] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def valid_methods(self) -> "RecoveryLineageChallengeAuthority":
        if len(set(self.method_families.values())) < 1:
            raise ValueError("Challenge authority must declare at least one method family.")
        return self


class RecoveryPathChallengePolicy(BaseModel):
    """v0.25 policy for externally challenging a signed recovery-ancestry claim."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    recovery_ancestry_attestation_sha256: str = Field(min_length=64, max_length=64)
    authorities: list[RecoveryLineageChallengeAuthority] = Field(min_length=2, max_length=32)
    clear_quorum_per_lineage: int = Field(default=2, ge=2, le=32)
    min_source_groups_per_lineage: int = Field(default=2, ge=2, le=32)
    min_method_families_per_lineage: int = Field(default=2, ge=2, le=32)
    forbid_ancestry_authority_key_overlap: bool = True
    policy_authority_id: str = Field(min_length=1, max_length=512)
    policy_public_key: str = Field(min_length=64, max_length=64)
    policy_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_authorities(self) -> "RecoveryPathChallengePolicy":
        ids = [x.authority_id for x in self.authorities]
        keys = [x.authority_public_key for x in self.authorities]
        if len(ids) != len(set(ids)):
            raise ValueError("Recovery lineage challenger IDs must be unique.")
        if len(keys) != len(set(keys)):
            raise ValueError("Recovery lineage challenger keys must be unique.")
        if self.clear_quorum_per_lineage > len(self.authorities):
            raise ValueError("Challenge quorum cannot exceed committed authority count.")
        if self.min_source_groups_per_lineage > len(self.authorities):
            raise ValueError("Challenge source diversity cannot exceed committed authority count.")
        if self.min_method_families_per_lineage > len(self.authorities):
            raise ValueError("Challenge method diversity cannot exceed committed authority count.")
        return self


class RecoveryLineageChallengeObservation(BaseModel):
    """Signed external observation of one v0.24 qualifying recovery lineage.

    The observation can falsify or leave unresolved a declared ancestry claim. A
    CLEAR observation has no direct promotion authority.
    """

    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str = Field(min_length=64, max_length=64)
    recovery_ancestry_attestation_sha256: str = Field(min_length=64, max_length=64)
    target_kind: Literal["EVIDENCE", "REASONING"]
    lineage_key: str = Field(min_length=1, max_length=1536)
    probe_method: str = Field(min_length=1, max_length=256)
    source_records: list[str] = Field(min_length=1, max_length=64)
    observed_root_fingerprints: list[str] = Field(min_length=1, max_length=256)
    result: RecoveryLineageChallengeResult
    authority_id: str = Field(min_length=1, max_length=512)
    authority_public_key: str = Field(min_length=64, max_length=64)
    source_group: str = Field(min_length=1, max_length=512)
    method_family: str = Field(min_length=1, max_length=512)
    observed_at: str | None = Field(default=None, max_length=128)
    challenge_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_observations(self) -> "RecoveryLineageChallengeObservation":
        if len(self.source_records) != len(set(self.source_records)):
            raise ValueError("Challenge source records must be unique.")
        if len(self.observed_root_fingerprints) != len(set(self.observed_root_fingerprints)):
            raise ValueError("Challenge observed roots must be unique.")
        for value in self.observed_root_fingerprints:
            if len(value) != 64:
                raise ValueError("Challenge roots must be SHA-256 hex strings.")
            int(value, 16)
        return self


class RecoveryPathChallengeAssessment(BaseModel):
    """v0.25 result. External challenges may veto ancestry recovery, never create it."""

    status: Literal[
        "BASE_ANCESTRY_RECOVERY_NOT_AUTHORIZED",
        "INVALID_CHALLENGE_POLICY",
        "INVALID_CHALLENGE_SET",
        "COUNTERSIGNAL",
        "UNRESOLVED",
        "RECOVERED_BY_EXTERNALLY_CHALLENGED_ANCESTRY_RERUN",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    challenged_lineages: list[str] = Field(default_factory=list)
    valid_authorities: list[str] = Field(default_factory=list)
    source_groups: list[str] = Field(default_factory=list)
    method_families: list[str] = Field(default_factory=list)
    observed_overlap_roots: list[str] = Field(default_factory=list)
    disclosure_gap_roots: list[str] = Field(default_factory=list)
    unresolved_lineages: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    authoritative_promotion: bool = False
    authority_rule: Literal["EXTERNAL_CHALLENGE_PLUS_ANCESTRY_RERUN_PASS_ONLY"] = "EXTERNAL_CHALLENGE_PLUS_ANCESTRY_RERUN_PASS_ONLY"


class RecoveryChallengeOutcomeStatus(str, Enum):
    """Later audit outcome for a challenger's previously issued CLEAR."""

    CLEAR_CONFIRMED = "CLEAR_CONFIRMED"
    FALSE_CLEAR = "FALSE_CLEAR"


class RecoveryChallengeAccountabilityPolicy(BaseModel):
    """v0.26 preregistered accountability thresholds for lineage challengers."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    challenge_policy_sha256: str = Field(min_length=64, max_length=64)
    audit_min_clear_samples: int = Field(default=3, ge=1, le=10000)
    max_false_clear_rate: float = Field(default=0.25, ge=0.0, le=1.0)
    audit_authority_id: str = Field(min_length=1, max_length=512)
    audit_public_key: str = Field(min_length=64, max_length=64)
    policy_authority_id: str = Field(min_length=1, max_length=512)
    policy_public_key: str = Field(min_length=64, max_length=64)
    policy_signature: str = Field(min_length=128, max_length=128)


class RecoveryChallengeOutcomeRecord(BaseModel):
    """Audit-signed later outcome for one exact challenger observation."""

    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(min_length=1, max_length=256)
    challenge_observation_sha256: str = Field(min_length=64, max_length=64)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    authority_id: str = Field(min_length=1, max_length=512)
    lineage_key: str = Field(min_length=1, max_length=1536)
    original_result: Literal["CLEAR"] = "CLEAR"
    outcome_status: RecoveryChallengeOutcomeStatus
    downstream_reference: str = Field(min_length=1, max_length=2048)
    audit_authority_id: str = Field(min_length=1, max_length=512)
    audit_public_key: str = Field(min_length=64, max_length=64)
    audit_signature: str = Field(min_length=128, max_length=128)


class RecoveryChallengeAuthorityAccountability(BaseModel):
    authority_id: str = Field(min_length=1, max_length=512)
    clear_samples: int = Field(ge=0)
    confirmed_clear: int = Field(ge=0)
    false_clear: int = Field(ge=0)
    false_clear_rate: float = Field(ge=0.0, le=1.0)
    status: Literal["ACTIVE", "QUARANTINED"]
    errors: list[str] = Field(default_factory=list)


class RecoveryPathChallengeAccountabilityAssessment(BaseModel):
    """v0.26 result. Quarantined CLEARs cannot satisfy challenge quorum."""

    status: Literal[
        "INVALID_ACCOUNTABILITY_POLICY",
        "INVALID_ACCOUNTABILITY_RECORDS",
        "COUNTERSIGNAL",
        "UNRESOLVED",
        "RECOVERED_BY_ACCOUNTABLE_EXTERNAL_CHALLENGE",
        "BASE_ANCESTRY_RECOVERY_NOT_AUTHORIZED",
        "INVALID_CHALLENGE_POLICY",
        "INVALID_CHALLENGE_SET",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    quarantined_authorities: list[str] = Field(default_factory=list)
    eligible_clear_authorities: list[str] = Field(default_factory=list)
    accountability: dict[str, RecoveryChallengeAuthorityAccountability] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    authoritative_promotion: bool = False
    authority_rule: Literal["ACCOUNTABLE_EXTERNAL_CHALLENGE_PLUS_ANCESTRY_RERUN_ONLY"] = "ACCOUNTABLE_EXTERNAL_CHALLENGE_PLUS_ANCESTRY_RERUN_ONLY"


class RecoveryChallengeAuditAuthority(BaseModel):
    """Precommitted downstream auditor identity and independence metadata."""

    model_config = ConfigDict(extra="forbid")

    audit_authority_id: str = Field(min_length=1, max_length=512)
    audit_public_key: str = Field(min_length=64, max_length=64)
    source_group: str = Field(min_length=1, max_length=512)
    method_family: str = Field(min_length=1, max_length=512)


class RecoveryChallengeAuditIndependencePolicy(BaseModel):
    """v0.27 policy: positive audit confirmation needs independent audit quorum."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    challenge_policy_sha256: str = Field(min_length=64, max_length=64)
    audit_min_clear_samples: int = Field(default=3, ge=1, le=10000)
    max_false_clear_rate: float = Field(default=0.25, ge=0.0, le=1.0)
    audit_authorities: list[RecoveryChallengeAuditAuthority] = Field(min_length=2, max_length=32)
    confirming_quorum: int = Field(default=2, ge=2, le=32)
    min_confirming_source_groups: int = Field(default=2, ge=2, le=32)
    min_confirming_method_families: int = Field(default=2, ge=2, le=32)
    policy_authority_id: str = Field(min_length=1, max_length=512)
    policy_public_key: str = Field(min_length=64, max_length=64)
    policy_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_auditors(self) -> "RecoveryChallengeAuditIndependencePolicy":
        ids=[x.audit_authority_id for x in self.audit_authorities]
        keys=[x.audit_public_key for x in self.audit_authorities]
        if len(ids)!=len(set(ids)):
            raise ValueError("Audit authority IDs must be unique.")
        if len(keys)!=len(set(keys)):
            raise ValueError("Audit authority keys must be unique.")
        return self


class RecoveryChallengeAuditConsensus(BaseModel):
    challenge_observation_sha256: str = Field(min_length=64, max_length=64)
    authority_id: str = Field(min_length=1, max_length=512)
    outcome: Literal["FALSE_CLEAR", "CLEAR_CONFIRMED", "UNRESOLVED"]
    audit_authorities: list[str] = Field(default_factory=list)
    source_groups: list[str] = Field(default_factory=list)
    method_families: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class RecoveryPathChallengeAuditIndependenceAssessment(BaseModel):
    """v0.27 result: challenger CLEAR weight depends on independently audited history."""

    status: Literal[
        "INVALID_AUDIT_INDEPENDENCE_POLICY",
        "INVALID_AUDIT_RECORDS",
        "COUNTERSIGNAL",
        "UNRESOLVED",
        "RECOVERED_BY_AUDIT_INDEPENDENT_EXTERNAL_CHALLENGE",
        "BASE_ANCESTRY_RECOVERY_NOT_AUTHORIZED",
        "INVALID_CHALLENGE_POLICY",
        "INVALID_CHALLENGE_SET",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    quarantined_authorities: list[str] = Field(default_factory=list)
    eligible_clear_authorities: list[str] = Field(default_factory=list)
    accountability: dict[str, RecoveryChallengeAuthorityAccountability] = Field(default_factory=dict)
    audit_consensus: list[RecoveryChallengeAuditConsensus] = Field(default_factory=list)
    unresolved_audit_samples: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list)
    authoritative_promotion: bool = False
    authority_rule: Literal["AUDIT_INDEPENDENT_ACCOUNTABLE_EXTERNAL_CHALLENGE_ONLY"] = "AUDIT_INDEPENDENT_ACCOUNTABLE_EXTERNAL_CHALLENGE_ONLY"


class RecoveryChallengeAuditObservationPolicy(BaseModel):
    """v0.28 policy: positive challenger history must rest on diverse audit observation lineage."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=256)
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    audit_independence_policy_sha256: str = Field(min_length=64, max_length=64)
    min_confirmed_samples_for_clear_authority: int = Field(default=1, ge=1, le=10000)
    min_primary_observation_roots_per_sample: int = Field(default=2, ge=2, le=32)
    forbid_shared_observation_roots: bool = True
    policy_authority_id: str = Field(min_length=1, max_length=512)
    policy_public_key: str = Field(min_length=64, max_length=64)
    policy_signature: str = Field(min_length=128, max_length=128)


class RecoveryChallengeAuditObservationProvenance(BaseModel):
    """Auditor-signed provenance for the downstream observation behind one audit record."""

    model_config = ConfigDict(extra="forbid")

    provenance_id: str = Field(min_length=1, max_length=256)
    audit_record_sha256: str = Field(min_length=64, max_length=64)
    challenge_observation_sha256: str = Field(min_length=64, max_length=64)
    audit_authority_id: str = Field(min_length=1, max_length=512)
    audit_public_key: str = Field(min_length=64, max_length=64)
    source_records: list[str] = Field(min_length=1, max_length=64)
    primary_observation_root_fingerprint: str = Field(min_length=64, max_length=64)
    observation_root_fingerprints: list[str] = Field(min_length=1, max_length=256)
    observed_at: str | None = Field(default=None, max_length=128)
    provenance_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def valid_observation_roots(self) -> "RecoveryChallengeAuditObservationProvenance":
        if len(self.source_records) != len(set(self.source_records)):
            raise ValueError("Audit observation source records must be unique.")
        if len(self.observation_root_fingerprints) != len(set(self.observation_root_fingerprints)):
            raise ValueError("Audit observation root fingerprints must be unique.")
        if self.primary_observation_root_fingerprint not in self.observation_root_fingerprints:
            raise ValueError("Primary audit observation root must be present in the root set.")
        for value in self.observation_root_fingerprints:
            if len(value) != 64:
                raise ValueError("Audit observation roots must be SHA-256 hex strings.")
            int(value, 16)
        return self


class RecoveryPathChallengeAuditObservationAssessment(BaseModel):
    """v0.28 result: positive CLEAR weight requires observation-lineage-diverse audit history."""

    status: Literal[
        "INVALID_AUDIT_OBSERVATION_POLICY",
        "INVALID_AUDIT_OBSERVATION_PROVENANCE",
        "COUNTERSIGNAL",
        "UNRESOLVED",
        "RECOVERED_BY_AUDIT_OBSERVATION_DIVERSE_EXTERNAL_CHALLENGE",
        "BASE_ANCESTRY_RECOVERY_NOT_AUTHORIZED",
        "INVALID_CHALLENGE_POLICY",
        "INVALID_CHALLENGE_SET",
    ]
    original_decision_sha256: str = Field(min_length=64, max_length=64)
    rerun_decision_sha256: str | None = None
    quarantined_authorities: list[str] = Field(default_factory=list)
    eligible_clear_authorities: list[str] = Field(default_factory=list)
    unproven_clear_authorities: list[str] = Field(default_factory=list)
    accountability: dict[str, RecoveryChallengeAuthorityAccountability] = Field(default_factory=dict)
    provenance_confirmed_samples: dict[str, int] = Field(default_factory=dict)
    unresolved_provenance_samples: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list)
    authoritative_promotion: bool = False
    authority_rule: Literal["AUDIT_OBSERVATION_DIVERSE_ACCOUNTABLE_EXTERNAL_CHALLENGE_ONLY"] = "AUDIT_OBSERVATION_DIVERSE_ACCOUNTABLE_EXTERNAL_CHALLENGE_ONLY"


class RecoveryAuthorityIdentity(BaseModel):
    """Manifest-committed identity for one recovery-governance authority."""

    model_config = ConfigDict(extra="forbid")

    authority_id: str = Field(min_length=1, max_length=512)
    authority_public_key: str = Field(min_length=64, max_length=64)




class PublisherVersionStatement(BaseModel):
    """Publisher-signed immutable version identity for one recovery artifact.

    The signature authenticates the statement to a manifest-pinned publisher key.
    It does not, by itself, prove that the version is still current; v0.32 introduced
    it with a transaction-bound publisher head attestation after the HOLD.
    """

    model_config = ConfigDict(extra="forbid")

    publisher_id: str = Field(min_length=1, max_length=512)
    publisher_public_key: str = Field(min_length=64, max_length=64)
    document_id: str = Field(min_length=1, max_length=1024)
    canonical_source: str = Field(min_length=1, max_length=4096)
    version_id: str = Field(min_length=1, max_length=512)
    version_sequence: int = Field(ge=0, le=2**63 - 1)
    content_sha256: str = Field(min_length=64, max_length=64)
    previous_version_statement_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    publisher_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def valid_hashes_and_key(self) -> "PublisherVersionStatement":
        for label, value in (("publisher public key", self.publisher_public_key), ("content hash", self.content_sha256)):
            try:
                bytes.fromhex(value)
            except ValueError as exc:
                raise ValueError(f"Publisher version {label} must be hex.") from exc
        if self.previous_version_statement_sha256 is not None:
            try:
                int(self.previous_version_statement_sha256, 16)
            except ValueError as exc:
                raise ValueError("Publisher previous-version digest must be SHA-256 hex.") from exc
        try:
            bytes.fromhex(self.publisher_signature)
        except ValueError as exc:
            raise ValueError("Publisher version signature must be hex.") from exc
        return self


class PublisherKeyIdentityAttestation(BaseModel):
    """External identity-authority binding of a publisher key to a DNS subject.

    v0.33 deliberately treats the identity-authority key as an external trust
    anchor. The signature proves continuity to that anchor; it does not prove
    that the operator selected an honest authority.
    """

    model_config = ConfigDict(extra="forbid")

    publisher_id: str = Field(min_length=1, max_length=512)
    publisher_public_key: str = Field(min_length=64, max_length=64)
    subject_dns_name: str = Field(min_length=1, max_length=253)
    identity_authority_id: str = Field(min_length=1, max_length=512)
    identity_authority_public_key: str = Field(min_length=64, max_length=64)
    valid_from: str = Field(min_length=1, max_length=128)
    valid_until: str = Field(min_length=1, max_length=128)
    identity_signature: str = Field(min_length=128, max_length=128)


class PublisherTransparencyCheckpoint(BaseModel):
    """Signed checkpoint of an external append-only hash-chain transparency log."""

    model_config = ConfigDict(extra="forbid")

    log_id: str = Field(min_length=1, max_length=512)
    log_public_key: str = Field(min_length=64, max_length=64)
    entry_count: int = Field(ge=0, le=2**63 - 1)
    chain_root_sha256: str = Field(min_length=64, max_length=64)
    issued_at: str = Field(min_length=1, max_length=128)
    log_signature: str = Field(min_length=128, max_length=128)


class PublisherTransparencyWitnessIdentity(BaseModel):
    """Manifest-pinned external witness allowed to cosign transparency checkpoints."""

    model_config = ConfigDict(extra="forbid")

    witness_id: str = Field(min_length=1, max_length=512)
    witness_public_key: str = Field(min_length=64, max_length=64)


class RecoveryPublisherSourceSpec(BaseModel):
    """Manifest-pinned publisher, identity, and transparency authority for one refreshed slot."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=256)
    publisher_id: str = Field(min_length=1, max_length=512)
    publisher_public_key: str = Field(min_length=64, max_length=64)
    document_id: str = Field(min_length=1, max_length=1024)
    expected_version: PublisherVersionStatement
    identity_attestation: PublisherKeyIdentityAttestation
    transparency_log_id: str = Field(min_length=1, max_length=512)
    transparency_log_public_key: str = Field(min_length=64, max_length=64)
    transparency_anchor_checkpoint: PublisherTransparencyCheckpoint
    transparency_witnesses: list[PublisherTransparencyWitnessIdentity] = Field(min_length=2, max_length=32)
    transparency_witness_quorum: int = Field(default=2, ge=2, le=32)

    @model_validator(mode="after")
    def version_identity_matches_spec(self) -> "RecoveryPublisherSourceSpec":
        if self.expected_version.publisher_id != self.publisher_id:
            raise ValueError("Recovery publisher expected-version publisher ID mismatch.")
        if self.expected_version.publisher_public_key != self.publisher_public_key:
            raise ValueError("Recovery publisher expected-version public key mismatch.")
        if self.expected_version.document_id != self.document_id:
            raise ValueError("Recovery publisher expected-version document ID mismatch.")
        if self.identity_attestation.publisher_id != self.publisher_id:
            raise ValueError("Recovery publisher identity-attestation publisher ID mismatch.")
        if self.identity_attestation.publisher_public_key != self.publisher_public_key:
            raise ValueError("Recovery publisher identity-attestation public key mismatch.")
        if self.transparency_anchor_checkpoint.log_id != self.transparency_log_id:
            raise ValueError("Recovery publisher transparency anchor log ID mismatch.")
        if self.transparency_anchor_checkpoint.log_public_key != self.transparency_log_public_key:
            raise ValueError("Recovery publisher transparency anchor log public key mismatch.")
        ids = [x.witness_id for x in self.transparency_witnesses]
        keys = [x.witness_public_key for x in self.transparency_witnesses]
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise ValueError("Recovery publisher transparency witnesses must have unique IDs and keys.")
        if self.transparency_witness_quorum > len(self.transparency_witnesses):
            raise ValueError("Recovery publisher transparency witness quorum exceeds witness count.")
        return self


class PublisherHeadAttestation(BaseModel):
    """Publisher-signed current-head answer bound to one live recovery transaction."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=256)
    publisher_id: str = Field(min_length=1, max_length=512)
    publisher_public_key: str = Field(min_length=64, max_length=64)
    document_id: str = Field(min_length=1, max_length=1024)
    campaign_id: str = Field(min_length=1, max_length=512)
    case_id: str = Field(min_length=1, max_length=512)
    original_run_sha256: str = Field(min_length=64, max_length=64)
    rerun_id: str = Field(min_length=1, max_length=2048)
    recovery_evidence_sha256: str = Field(min_length=64, max_length=64)
    head_version_statement_sha256: str = Field(min_length=64, max_length=64)
    attested_at: str = Field(min_length=1, max_length=128)
    publisher_signature: str = Field(min_length=128, max_length=128)


class PublisherTransparencyWitnessCosignature(BaseModel):
    """External witness signature over one log checkpoint and its campaign anchor."""

    model_config = ConfigDict(extra="forbid")

    witness_id: str = Field(min_length=1, max_length=512)
    witness_public_key: str = Field(min_length=64, max_length=64)
    anchor_checkpoint_sha256: str = Field(min_length=64, max_length=64)
    checkpoint_sha256: str = Field(min_length=64, max_length=64)
    witnessed_at: str = Field(min_length=1, max_length=128)
    witness_signature: str = Field(min_length=128, max_length=128)


class PublisherTransparencyProof(BaseModel):
    """Verifiable append-only extension containing the exact transaction head event."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=256)
    publisher_head_sha256: str = Field(min_length=64, max_length=64)
    appended_entry_sha256: list[str] = Field(min_length=1, max_length=4096)
    checkpoint: PublisherTransparencyCheckpoint
    witness_cosignatures: list[PublisherTransparencyWitnessCosignature] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def valid_proof_shape(self) -> "PublisherTransparencyProof":
        for value in self.appended_entry_sha256:
            if len(value) != 64:
                raise ValueError("Transparency appended entries must be SHA-256 hex.")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ValueError("Transparency appended entries must be SHA-256 hex.") from exc
        ids = [x.witness_id for x in self.witness_cosignatures]
        if len(ids) != len(set(ids)):
            raise ValueError("Transparency proof witness IDs must be unique.")
        return self


class RecoveryAttemptStateCheckpoint(BaseModel):
    """External stateful-witness checkpoint for recovery-attempt continuity.

    The witness is expected to persist this state outside Illusiontion and to
    advance it atomically. Local verification proves a signed transition from
    the manifest-pinned anchor; it cannot force a malicious witness to remember.
    """

    model_config = ConfigDict(extra="forbid")

    witness_id: str = Field(min_length=1, max_length=512)
    witness_public_key: str = Field(min_length=64, max_length=64)
    sequence: int = Field(ge=0, le=2**63 - 1)
    state_sha256: str = Field(min_length=64, max_length=64)
    issued_at: str = Field(min_length=1, max_length=128)
    witness_signature: str = Field(min_length=128, max_length=128)


class RecoveryAttemptWitnessSpec(BaseModel):
    """Manifest-pinned external witness and its prior persistent state."""

    model_config = ConfigDict(extra="forbid")

    witness_id: str = Field(min_length=1, max_length=512)
    witness_public_key: str = Field(min_length=64, max_length=64)
    anchor_checkpoint: RecoveryAttemptStateCheckpoint

    @model_validator(mode="after")
    def anchor_matches_identity(self) -> "RecoveryAttemptWitnessSpec":
        if self.anchor_checkpoint.witness_id != self.witness_id:
            raise ValueError("Recovery attempt witness anchor ID mismatch.")
        if self.anchor_checkpoint.witness_public_key != self.witness_public_key:
            raise ValueError("Recovery attempt witness anchor key mismatch.")
        return self


class RecoveryAttemptLease(BaseModel):
    """One externally signed, state-consuming authorization for a recovery slot."""

    model_config = ConfigDict(extra="forbid")

    witness_id: str = Field(min_length=1, max_length=512)
    witness_public_key: str = Field(min_length=64, max_length=64)
    anchor_checkpoint_sha256: str = Field(min_length=64, max_length=64)
    campaign_id: str = Field(min_length=1, max_length=512)
    case_id: str = Field(min_length=1, max_length=512)
    original_run_sha256: str = Field(min_length=64, max_length=64)
    rerun_id: str = Field(min_length=1, max_length=2048)
    attempt_id: str = Field(min_length=64, max_length=64)
    classification_policy_sha256: str = Field(min_length=64, max_length=64)
    prior_sequence: int = Field(ge=0, le=2**63 - 1)
    prior_state_sha256: str = Field(min_length=64, max_length=64)
    leased_sequence: int = Field(ge=1, le=2**63 - 1)
    leased_state_sha256: str = Field(min_length=64, max_length=64)
    leased_at: str = Field(min_length=1, max_length=128)
    successor_checkpoint: RecoveryAttemptStateCheckpoint
    witness_signature: str = Field(min_length=128, max_length=128)


class RecoveryAttemptLeaseSet(BaseModel):
    """Quorum of stateful external witnesses consuming the same deterministic slot."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1, max_length=512)
    case_id: str = Field(min_length=1, max_length=512)
    original_run_sha256: str = Field(min_length=64, max_length=64)
    rerun_id: str = Field(min_length=1, max_length=2048)
    attempt_id: str = Field(min_length=64, max_length=64)
    classification_policy_sha256: str = Field(min_length=64, max_length=64)
    leases: list[RecoveryAttemptLease] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def unique_witnesses(self) -> "RecoveryAttemptLeaseSet":
        ids = [x.witness_id for x in self.leases]
        if len(ids) != len(set(ids)):
            raise ValueError("Recovery attempt lease witness IDs must be unique.")
        return self




class RecoveryKeyLifecycleEntry(BaseModel):
    """v0.43 current key epoch for one authority/secret subject."""

    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=1024)
    epoch: int = Field(ge=1, le=2**31-1)
    key_fingerprint_sha256: str = Field(min_length=64, max_length=64)
    predecessor_key_fingerprint_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    valid_from: str = Field(min_length=1, max_length=128)
    valid_until: str = Field(min_length=1, max_length=128)
    revoked_at: str | None = Field(default=None, min_length=1, max_length=128)
    status: Literal["ACTIVE", "REVOKED", "EXPIRED_OR_NOT_YET_VALID", "KEY_MISMATCH"]


class RecoveryKeyLifecycleAdmission(BaseModel):
    """v0.43 lifecycle-authority-signed snapshot of all keys required by one execution boundary."""

    model_config = ConfigDict(extra="forbid")
    authority_id: str = Field(min_length=1, max_length=512)
    authority_public_key: str = Field(min_length=64, max_length=64)
    registry_generation: int = Field(ge=0, le=2**63-1)
    entries: list[RecoveryKeyLifecycleEntry] = Field(min_length=1, max_length=4096)
    issued_at: str = Field(min_length=1, max_length=128)
    admission_sha256: str = Field(min_length=64, max_length=64)
    authority_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def unique_subjects(self) -> "RecoveryKeyLifecycleAdmission":
        subjects=[x.subject for x in self.entries]
        if len(subjects) != len(set(subjects)):
            raise ValueError("Key lifecycle admission subjects must be unique.")
        return self


class RecoveryLearningModelState(BaseModel):
    """Monotonic negative-only cross-attempt behavior memory for one model identity."""

    model_config = ConfigDict(extra="forbid")

    model_id: str = Field(min_length=1, max_length=512)
    negative_debt: int = Field(default=0, ge=0, le=2**31 - 1)
    negative_case_sha256: list[str] = Field(default_factory=list, max_length=100000)
    quarantined: bool = False




class RecoveryLearningMigrationCertificate(BaseModel):
    """v0.42 signed reviewer-model migration decision."""

    model_config = ConfigDict(extra="forbid")

    migration_id: str = Field(min_length=1, max_length=512)
    reviewer: ReviewerName
    predecessor_model_id: str = Field(min_length=1, max_length=512)
    successor_model_id: str = Field(min_length=1, max_length=512)
    relation: Literal["SAME_LINEAGE_OR_ALIAS", "INDEPENDENT_REPLACEMENT", "POLICY_REVISION_CONTINUITY"]
    from_policy_sha256: str = Field(min_length=64, max_length=64)
    to_policy_sha256: str = Field(min_length=64, max_length=64)
    independence_basis_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    authority_id: str = Field(min_length=1, max_length=512)
    authority_public_key: str = Field(min_length=64, max_length=64)
    certificate_sha256: str = Field(min_length=64, max_length=64)
    authority_signature: str = Field(min_length=128, max_length=128)

    @model_validator(mode="after")
    def independent_requires_basis(self) -> "RecoveryLearningMigrationCertificate":
        if self.relation == "INDEPENDENT_REPLACEMENT" and not self.independence_basis_sha256:
            raise ValueError("Independent replacement migration requires a committed independence basis hash.")
        if self.relation != "INDEPENDENT_REPLACEMENT" and self.independence_basis_sha256 is not None:
            raise ValueError("Only independent replacement migration may carry an independence basis.")
        return self


class RecoveryLearningAdmission(BaseModel):
    """Pre-provider v0.41 admission snapshot. Learning may only deny future execution."""

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    policy_sha256: str = Field(min_length=64, max_length=64)
    prior_state_sha256: str = Field(min_length=64, max_length=64)
    model_states: list[RecoveryLearningModelState] = Field(min_length=1, max_length=32)
    admitted: bool
    blocked_model_ids: list[str] = Field(default_factory=list, max_length=32)
    reviewer_model_bindings: dict[str, str] = Field(default_factory=dict)
    migration_certificates: list[RecoveryLearningMigrationCertificate] = Field(default_factory=list, max_length=32)
    issued_at: str = Field(min_length=1, max_length=128)
    admission_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryLearningUpdate(BaseModel):
    """Post-trajectory monotonic update under the fixed v0.41 negative-only policy."""

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    admission_sha256: str = Field(min_length=64, max_length=64)
    trajectory_sha256: str = Field(min_length=64, max_length=64)
    policy_sha256: str = Field(min_length=64, max_length=64)
    case_identity_sha256: str = Field(min_length=64, max_length=64)
    debt_delta_by_model: dict[str, int] = Field(default_factory=dict)
    model_states_after: list[RecoveryLearningModelState] = Field(min_length=1, max_length=32)
    next_state_sha256: str = Field(min_length=64, max_length=64)
    update_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryTrajectoryStep(BaseModel):
    """Deterministic observable classification of one completed reviewer action."""

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(ge=0, le=31)
    reviewer: ReviewerName
    action_class: Literal[
        "EXECUTION_FAILURE", "CRITICAL_FINDING", "SEMANTIC_CONFLICT",
        "CAUTION", "SEMANTIC_SUPPORT", "CLEAN", "OBSERVATION"
    ]
    evidence_ids: list[str] = Field(default_factory=list, max_length=512)
    finding_severities: list[str] = Field(default_factory=list, max_length=512)
    semantic_results: list[str] = Field(default_factory=list, max_length=2048)
    model_id: str = Field(min_length=1, max_length=512)
    model_response_id: str = Field(min_length=1, max_length=1024)
    receipt_signature: str = Field(min_length=64, max_length=64)
    previous_step_sha256: str = Field(min_length=64, max_length=64)
    step_sha256: str = Field(min_length=64, max_length=64)


class RecoveryExecutionTrajectory(BaseModel):
    """Runtime-observable attempt representation used as a conservative learning curve.

    This representation never upgrades a verdict. It records the action classes
    and their transition history so future stateful policy can only remove
    authority or request more review under precommitted rules.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    attempt_lease_set_sha256: str = Field(min_length=64, max_length=64)
    classification_policy_sha256: str = Field(min_length=64, max_length=64)
    steps: list[RecoveryTrajectoryStep] = Field(min_length=1, max_length=16)
    overall_class: Literal[
        "FAILED_TRAJECTORY", "CONFLICT_TRAJECTORY", "CAUTION_TRAJECTORY",
        "SUPPORT_TRAJECTORY", "MIXED_TRAJECTORY"
    ]
    trajectory_sha256: str = Field(min_length=64, max_length=64)


class RecoveryDistributedWorkerClaim(BaseModel):
    """Runtime-signed fencing claim for one recovery worker epoch.

    v0.39 treats every process invocation as a distinct worker epoch. A newer
    takeover claim fences every older epoch in the shared authoritative state.
    The worker label is descriptive only; authority comes from the stateful
    runtime transition and HMAC signature.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    worker_id: str = Field(min_length=1, max_length=512)
    epoch: int = Field(ge=1, le=2**31 - 1)
    prior_claim_sha256: str = Field(min_length=64, max_length=64)
    takeover: bool = False
    claim_nonce: str = Field(min_length=32, max_length=128)
    claimed_at: str = Field(min_length=1, max_length=128)
    claim_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryDistributedExecutionSeal(BaseModel):
    """Single-assignment publication seal for one multi-worker recovery history.

    The seal contains the complete worker-epoch chain observed by the shared
    state coordinator and binds exactly one rerun core to the deterministic
    recovery attempt. It is concurrency authority only and never upgrades a
    verdict.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    distributed_policy_sha256: str = Field(min_length=64, max_length=64)
    worker_claims: list[RecoveryDistributedWorkerClaim] = Field(min_length=1, max_length=1024)
    final_worker_claim_sha256: str = Field(min_length=64, max_length=64)
    atomic_chain_sha256: str = Field(min_length=64, max_length=64)
    provider_call_chain_sha256: str = Field(min_length=64, max_length=64)
    atomic_finalization_seal_sha256: str = Field(min_length=64, max_length=64)
    execution_trajectory_sha256: str = Field(min_length=64, max_length=64)
    rerun_core_sha256: str = Field(min_length=64, max_length=64)
    published_at: str = Field(min_length=1, max_length=128)
    publication_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryAtomicActionPermit(BaseModel):
    """Runtime-signed one-use permission for one reviewer action.

    The permit is issued by an atomic state store before the provider call. Its
    digest is bound into the reviewer invocation, so a later output cannot be
    attached to an unrelated permission token.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    attempt_lease_set_sha256: str = Field(min_length=64, max_length=64)
    step_index: int = Field(ge=0, le=31)
    reviewer: ReviewerName
    distributed_worker_claim_sha256: str = Field(default="", max_length=64)
    prior_state_sha256: str = Field(min_length=64, max_length=64)
    permit_nonce: str = Field(min_length=32, max_length=128)
    issued_at: str = Field(min_length=1, max_length=128)
    permit_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryAtomicActionCommit(BaseModel):
    """Atomic post-completion state transition for one observable action class."""

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    step_index: int = Field(ge=0, le=31)
    reviewer: ReviewerName
    distributed_worker_claim_sha256: str = Field(default="", max_length=64)
    permit_sha256: str = Field(min_length=64, max_length=64)
    action_class: Literal[
        "EXECUTION_FAILURE", "CRITICAL_FINDING", "SEMANTIC_CONFLICT",
        "CAUTION", "SEMANTIC_SUPPORT", "CLEAN", "OBSERVATION"
    ]
    receipt_signature: str = Field(min_length=64, max_length=64)
    prior_state_sha256: str = Field(min_length=64, max_length=64)
    next_state_sha256: str = Field(min_length=64, max_length=64)
    committed_at: str = Field(min_length=1, max_length=128)
    commit_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryAtomicActionStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permit: RecoveryAtomicActionPermit
    commit: RecoveryAtomicActionCommit


class RecoveryAtomicExecutionChain(BaseModel):
    """Authoritative per-action state chain for one recovery attempt.

    v0.35 turns v0.34's observable learning curve into an online state machine:
    every reviewer action receives an atomic permit before invocation and commits
    its deterministic class before the next permit may be issued. The chain is
    negative-only memory; it never grants PASS authority.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    attempt_lease_set_sha256: str = Field(min_length=64, max_length=64)
    atomic_policy_sha256: str = Field(min_length=64, max_length=64)
    initial_state_sha256: str = Field(min_length=64, max_length=64)
    steps: list[RecoveryAtomicActionStep] = Field(min_length=1, max_length=16)
    final_state_sha256: str = Field(min_length=64, max_length=64)
    chain_sha256: str = Field(min_length=64, max_length=64)


class RecoveryAtomicFinalizationSeal(BaseModel):
    """Externally signed single-assignment seal for one completed atomic attempt.

    v0.36 uses an independently keyed stateful anchor to ensure that only one
    completed atomic execution chain for a deterministic attempt ID can acquire
    authority. The seal does not prove that no extra provider calls occurred; it
    prevents two cloned local action stores from producing two independently
    authoritative recovery histories while they share the same honest anchor.
    """

    model_config = ConfigDict(extra="forbid")

    anchor_authority_id: str = Field(min_length=1, max_length=512)
    anchor_public_key: str = Field(min_length=64, max_length=64)
    attempt_id: str = Field(min_length=64, max_length=64)
    atomic_chain_sha256: str = Field(min_length=64, max_length=64)
    seal_nonce: str = Field(min_length=32, max_length=128)
    sealed_at: str = Field(min_length=1, max_length=128)
    seal_sha256: str = Field(min_length=64, max_length=64)
    anchor_signature: str = Field(min_length=128, max_length=128)


class RecoveryProviderCallRecord(BaseModel):
    """Runtime-authenticated record of the one governed provider create for an action.

    The call is durably marked in-flight before network I/O. A completed record
    binds the atomic permit, frozen reviewer invocation, provider/model identity,
    provider interaction ID, and raw output hash.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    step_index: int = Field(ge=0, le=31)
    reviewer: ReviewerName
    distributed_worker_claim_sha256: str = Field(default="", max_length=64)
    atomic_permit_sha256: str = Field(min_length=64, max_length=64)
    provider_call_id: str = Field(min_length=64, max_length=64)
    invocation_sha256: str = Field(min_length=64, max_length=64)
    provider: str = Field(min_length=1, max_length=512)
    model_id: str = Field(min_length=1, max_length=512)
    model_response_id: str = Field(min_length=1, max_length=1024)
    raw_output_sha256: str = Field(min_length=64, max_length=64)
    started_at: str = Field(min_length=1, max_length=128)
    completed_at: str = Field(min_length=1, max_length=128)
    call_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryProviderCallReconciliation(BaseModel):
    """Runtime-signed v0.38 replay of one already-durable provider completion.

    This record is created only after a process interruption when the provider
    call had already reached durable COMPLETED state but the corresponding
    atomic action had not yet committed. Reconciliation replays the stored raw
    output through the trusted parser/runtime; it never issues another provider
    request and never upgrades a verdict.
    """

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    step_index: int = Field(ge=0, le=31)
    reviewer: ReviewerName
    distributed_worker_claim_sha256: str = Field(default="", max_length=64)
    provider_call_id: str = Field(min_length=64, max_length=64)
    call_sha256: str = Field(min_length=64, max_length=64)
    invocation_sha256: str = Field(min_length=64, max_length=64)
    raw_output_sha256: str = Field(min_length=64, max_length=64)
    mode: Literal["DURABLE_COMPLETION_REPLAY_NO_PROVIDER_CALL"] = "DURABLE_COMPLETION_REPLAY_NO_PROVIDER_CALL"
    reconciled_at: str = Field(min_length=1, max_length=128)
    reconciliation_sha256: str = Field(min_length=64, max_length=64)
    runtime_signature: str = Field(min_length=64, max_length=64)


class RecoveryProviderCallChain(BaseModel):
    """Complete provider-call population for one atomic recovery attempt."""

    model_config = ConfigDict(extra="forbid")

    attempt_id: str = Field(min_length=64, max_length=64)
    provider_call_policy_sha256: str = Field(min_length=64, max_length=64)
    calls: list[RecoveryProviderCallRecord] = Field(min_length=1, max_length=16)
    reconciliations: list[RecoveryProviderCallReconciliation] = Field(default_factory=list, max_length=16)
    chain_sha256: str = Field(min_length=64, max_length=64)


class RecoveryRefreshSourceSpec(BaseModel):
    """Manifest-committed held-out recovery snapshot and declared dependency roots.

    v0.31 commits not only the recovery locator/source group before the HOLD, but
    also the exact raw snapshot hash expected at recovery time and the declared
    upstream dependency roots for both the original and recovery source lineages.
    The hash commitment makes mutable-source drift fail closed. The ancestry roots
    remain declared provenance facts, not proof of real-world organizational
    independence; later recovery ancestry attestations must match them exactly.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=4096)
    source_group: str = Field(min_length=1, max_length=512)
    expected_raw_content_sha256: str = Field(min_length=64, max_length=64)
    original_dependency_root_fingerprints: list[str] = Field(min_length=1, max_length=64)
    recovery_dependency_root_fingerprints: list[str] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def valid_quality_commitments(self) -> "RecoveryRefreshSourceSpec":
        for label, values in (
            ("original", self.original_dependency_root_fingerprints),
            ("recovery", self.recovery_dependency_root_fingerprints),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"Recovery refresh {label} dependency roots must be unique.")
            for value in values:
                if len(value) != 64:
                    raise ValueError(f"Recovery refresh {label} dependency roots must be SHA-256 hex.")
                try:
                    int(value, 16)
                except ValueError as exc:
                    raise ValueError(f"Recovery refresh {label} dependency roots must be SHA-256 hex.") from exc
        try:
            int(self.expected_raw_content_sha256, 16)
        except ValueError as exc:
            raise ValueError("Recovery refresh expected raw content hash must be SHA-256 hex.") from exc
        return self

class RecoveryConstitution(BaseModel):
    """v0.35 pre-decision constitution for the complete live recovery path.

    Every authority identity, participant set and promotion-relevant threshold is
    committed in the campaign manifest before candidate generation. Per-decision
    signed policies may bind the eventual HOLD hash, but may not choose a friendlier
    quorum, authority set or diversity rule after seeing that decision.
    """

    model_config = ConfigDict(extra="forbid")

    recovery_coverage_rule: Literal["ALL_ELIGIBLE_EVIDENCE_DEBT_HOLDS"] = "ALL_ELIGIBLE_EVIDENCE_DEBT_HOLDS"
    recovery_attempt_rule: Literal["ONE_SEALED_AUTHORITATIVE_RERUN_PER_ELIGIBLE_HOLD"] = "ONE_SEALED_AUTHORITATIVE_RERUN_PER_ELIGIBLE_HOLD"
    recovery_refresh_rule: Literal["MANIFEST_EXACT_SOURCE_MAP"] = "MANIFEST_EXACT_SOURCE_MAP"
    recovery_refresh_quality_rule: Literal["PINNED_HELD_OUT_SNAPSHOT_DECLARED_ANCESTRY_REVIEW_RELEVANCE"] = "PINNED_HELD_OUT_SNAPSHOT_DECLARED_ANCESTRY_REVIEW_RELEVANCE"
    recovery_capture_order_rule: Literal["STRICTLY_AFTER_ORIGINAL_CAPTURE"] = "STRICTLY_AFTER_ORIGINAL_CAPTURE"
    recovery_publisher_authority_rule: Literal["EXTERNAL_IDENTITY_ANCHORED_PUBLISHER_VERSION_WITNESSED_APPEND_ONLY_HEAD"] = "EXTERNAL_IDENTITY_ANCHORED_PUBLISHER_VERSION_WITNESSED_APPEND_ONLY_HEAD"
    recovery_attempt_continuity_rule: Literal["STATEFUL_EXTERNAL_WITNESS_ONE_SLOT_LEASE"] = "STATEFUL_EXTERNAL_WITNESS_ONE_SLOT_LEASE"
    recovery_behavior_classification_rule: Literal["DETERMINISTIC_OBSERVABLE_TRAJECTORY_NEGATIVE_ONLY_MEMORY"] = "DETERMINISTIC_OBSERVABLE_TRAJECTORY_NEGATIVE_ONLY_MEMORY"
    recovery_atomic_execution_rule: Literal["OFFLINE_LEASE_COMPATIBILITY", "ATOMIC_PER_ACTION_RUNTIME_STATE"] = "ATOMIC_PER_ACTION_RUNTIME_STATE"
    recovery_atomic_learning_rule: Literal["MID_COMPLETION_CLASSIFICATION_STATE_TRANSITION_NEGATIVE_ONLY"] = "MID_COMPLETION_CLASSIFICATION_STATE_TRANSITION_NEGATIVE_ONLY"
    recovery_atomic_finalization_rule: Literal[
        "LOCAL_ATOMIC_COMPATIBILITY",
        "INDEPENDENT_SINGLE_ASSIGNMENT_FINALIZATION_ANCHOR",
    ] = "LOCAL_ATOMIC_COMPATIBILITY"
    recovery_atomic_anchor_authority: RecoveryAuthorityIdentity | None = None
    recovery_provider_call_rule: Literal[
        "LEGACY_PROVIDER_CALL_COMPATIBILITY",
        "ATOMIC_SINGLE_CREATE_NO_AUTOMATIC_RETRY",
    ] = "LEGACY_PROVIDER_CALL_COMPATIBILITY"
    recovery_interruption_rule: Literal[
        "LEGACY_INTERRUPTION_COMPATIBILITY",
        "DURABLE_CRASH_RECONCILIATION_FAIL_CLOSED_ON_UNCERTAIN_PROVIDER",
    ] = "LEGACY_INTERRUPTION_COMPATIBILITY"
    recovery_distributed_execution_rule: Literal[
        "LOCAL_WORKER_COMPATIBILITY",
        "SHARED_STATE_FENCED_WORKERS_SINGLE_ASSIGNMENT_PUBLICATION",
    ] = "LOCAL_WORKER_COMPATIBILITY"
    recovery_state_integrity_rule: Literal[
        "LEGACY_STATE_INTEGRITY_COMPATIBILITY",
        "PRE_RESUME_CROSS_STORE_INTEGRITY_AUDIT",
    ] = "LEGACY_STATE_INTEGRITY_COMPATIBILITY"
    recovery_learning_curve_rule: Literal[
        "LEGACY_TRAJECTORY_ONLY",
        "MONOTONIC_NEGATIVE_ONLY_CROSS_ATTEMPT_MEMORY",
    ] = "LEGACY_TRAJECTORY_ONLY"
    recovery_learning_migration_rule: Literal[
        "LEGACY_MODEL_IDENTITY_MEMORY",
        "POLICY_SIGNED_MODEL_SUCCESSION_NEGATIVE_ONLY",
    ] = "LEGACY_MODEL_IDENTITY_MEMORY"
    recovery_key_lifecycle_rule: Literal[
        "LEGACY_STATIC_KEYS",
        "MONOTONIC_EPOCH_ROTATION_EXPIRY_REVOCATION",
    ] = "LEGACY_STATIC_KEYS"
    recovery_key_lifecycle_authority: RecoveryAuthorityIdentity | None = None
    recovery_key_lifecycle_max_age_seconds: int = Field(default=60, ge=1, le=900)
    recovery_dependency_environment_rule: Literal[
        "LEGACY_LOCKFILE_ONLY",
        "PLAN_COMMITTED_TRANSITIVE_RUNTIME_ENVIRONMENT",
    ] = "LEGACY_LOCKFILE_ONLY"
    recovery_privacy_rule: Literal[
        "LEGACY_FULL_REPLAY_RETENTION",
        "ENCRYPTED_EPHEMERAL_REPLAY_HASH_ONLY_AUTHORITY",
    ] = "LEGACY_FULL_REPLAY_RETENTION"
    recovery_resource_governance_rule: Literal[
        "LEGACY_RESOURCE_LIMITS",
        "PLAN_COMMITTED_FAIL_CLOSED_RESOURCE_ENVELOPE",
    ] = "LEGACY_RESOURCE_LIMITS"
    recovery_independent_verifier_rule: Literal[
        "LEGACY_RUNTIME_VERIFIER",
        "SEPARATE_STDLIB_AUTHORITY_ENVELOPE_VERIFIER",
    ] = "LEGACY_RUNTIME_VERIFIER"
    recovery_reproducibility_rule: Literal[
        "LEGACY_NO_EXTERNAL_REPRODUCIBILITY_HARNESS",
        "PLAN_COMMITTED_EXTERNAL_REPRODUCIBILITY_HARNESS",
    ] = "LEGACY_NO_EXTERNAL_REPRODUCIBILITY_HARNESS"
    publisher_head_max_age_seconds: int = Field(default=900, ge=1, le=3600)
    recovery_attempt_lease_max_age_seconds: int = Field(default=900, ge=1, le=3600)
    recovery_attempt_witnesses: list[RecoveryAttemptWitnessSpec] = Field(min_length=2, max_length=32)
    recovery_attempt_witness_quorum: int = Field(default=2, ge=2, le=32)
    recovery_refresh_sources: list[RecoveryRefreshSourceSpec] = Field(min_length=1, max_length=512)
    recovery_publisher_sources: list[RecoveryPublisherSourceSpec] = Field(min_length=1, max_length=512)

    recovery_policy_authority: RecoveryAuthorityIdentity
    recovery_authorities: list[RecoveryAuthoritySpec] = Field(min_length=2, max_length=32)
    resolved_quorum: int = Field(default=2, ge=2, le=32)
    min_source_groups: int = Field(default=2, ge=2, le=32)
    min_method_families: int = Field(default=2, ge=2, le=32)
    audit_min_resolved_samples: int = Field(default=3, ge=1, le=10000)
    max_unconfirmed_resolution_rate: float = Field(default=0.25, ge=0.0, le=1.0)
    recovery_outcome_audit_authority: RecoveryAuthorityIdentity

    path_authority: RecoveryAuthorityIdentity
    evidence_debt_min_new_source_groups: int = Field(default=1, ge=1, le=32)
    evidence_debt_min_new_evidence_items: int = Field(default=1, ge=1, le=512)
    semantic_debt_min_changed_roles: int = Field(default=2, ge=1, le=7)
    semantic_debt_min_new_reasoning_families: int = Field(default=1, ge=1, le=7)

    ancestry_authority: RecoveryAuthorityIdentity
    min_independent_evidence_roots: int = Field(default=1, ge=1, le=64)
    min_independent_reasoning_roots: int = Field(default=1, ge=1, le=64)
    forbid_shared_roots_in_qualifying_lineage: bool = True

    challenge_policy_authority: RecoveryAuthorityIdentity
    challenge_authorities: list[RecoveryLineageChallengeAuthority] = Field(min_length=2, max_length=32)
    clear_quorum_per_lineage: int = Field(default=2, ge=2, le=32)
    min_source_groups_per_lineage: int = Field(default=2, ge=2, le=32)
    min_method_families_per_lineage: int = Field(default=2, ge=2, le=32)
    forbid_ancestry_authority_key_overlap: bool = True

    audit_policy_authority: RecoveryAuthorityIdentity
    audit_authorities: list[RecoveryChallengeAuditAuthority] = Field(min_length=2, max_length=32)
    audit_min_clear_samples: int = Field(default=3, ge=1, le=10000)
    max_false_clear_rate: float = Field(default=0.25, ge=0.0, le=1.0)
    confirming_quorum: int = Field(default=2, ge=2, le=32)
    min_confirming_source_groups: int = Field(default=2, ge=2, le=32)
    min_confirming_method_families: int = Field(default=2, ge=2, le=32)

    observation_policy_authority: RecoveryAuthorityIdentity
    min_confirmed_samples_for_clear_authority: int = Field(default=1, ge=1, le=10000)
    min_primary_observation_roots_per_sample: int = Field(default=2, ge=2, le=32)
    forbid_shared_observation_roots: bool = True

    @model_validator(mode="after")
    def feasible_and_unique(self) -> "RecoveryConstitution":
        if self.recovery_privacy_rule == "ENCRYPTED_EPHEMERAL_REPLAY_HASH_ONLY_AUTHORITY":
            if self.recovery_interruption_rule != "DURABLE_CRASH_RECONCILIATION_FAIL_CLOSED_ON_UNCERTAIN_PROVIDER":
                raise ValueError("v0.45 privacy minimization requires durable crash reconciliation before replay bytes can be minimized safely.")
            if self.recovery_dependency_environment_rule != "PLAN_COMMITTED_TRANSITIVE_RUNTIME_ENVIRONMENT":
                raise ValueError("v0.45 privacy minimization requires the v0.44 dependency environment contract.")
        if self.recovery_resource_governance_rule == "PLAN_COMMITTED_FAIL_CLOSED_RESOURCE_ENVELOPE":
            if self.recovery_privacy_rule != "ENCRYPTED_EPHEMERAL_REPLAY_HASH_ONLY_AUTHORITY":
                raise ValueError("v0.46 resource governance requires v0.45 privacy minimization.")
        if self.recovery_independent_verifier_rule == "SEPARATE_STDLIB_AUTHORITY_ENVELOPE_VERIFIER":
            if self.recovery_resource_governance_rule != "PLAN_COMMITTED_FAIL_CLOSED_RESOURCE_ENVELOPE":
                raise ValueError("v0.47 independent verifier separation requires v0.46 resource governance.")
        if self.recovery_reproducibility_rule == "PLAN_COMMITTED_EXTERNAL_REPRODUCIBILITY_HARNESS":
            if self.recovery_independent_verifier_rule != "SEPARATE_STDLIB_AUTHORITY_ENVELOPE_VERIFIER":
                raise ValueError("v0.48 external reproducibility requires v0.47 independent verifier separation.")
        if self.resolved_quorum > len(self.recovery_authorities):
            raise ValueError("Recovery constitution quorum exceeds recovery authority count.")
        if self.min_source_groups > len(self.recovery_authorities):
            raise ValueError("Recovery constitution source diversity exceeds recovery authority count.")
        if self.min_method_families > len(self.recovery_authorities):
            raise ValueError("Recovery constitution method diversity exceeds recovery authority count.")
        if self.clear_quorum_per_lineage > len(self.challenge_authorities):
            raise ValueError("Recovery constitution challenge quorum exceeds challenger count.")
        if self.min_source_groups_per_lineage > len(self.challenge_authorities):
            raise ValueError("Recovery constitution challenge source diversity exceeds challenger count.")
        if self.min_method_families_per_lineage > len(self.challenge_authorities):
            raise ValueError("Recovery constitution challenge method diversity exceeds challenger count.")
        if self.confirming_quorum > len(self.audit_authorities):
            raise ValueError("Recovery constitution audit quorum exceeds auditor count.")
        if self.min_confirming_source_groups > len(self.audit_authorities):
            raise ValueError("Recovery constitution audit source diversity exceeds auditor count.")
        if self.min_confirming_method_families > len(self.audit_authorities):
            raise ValueError("Recovery constitution audit method diversity exceeds auditor count.")

        refresh_ids = [x.evidence_id for x in self.recovery_refresh_sources]
        if len(refresh_ids) != len(set(refresh_ids)):
            raise ValueError("Recovery constitution refresh evidence IDs must be unique.")
        publisher_ids = [x.evidence_id for x in self.recovery_publisher_sources]
        if len(publisher_ids) != len(set(publisher_ids)):
            raise ValueError("Recovery constitution publisher evidence IDs must be unique.")

        recovery_ids=[x.authority_id for x in self.recovery_authorities]
        recovery_keys=[x.authority_public_key for x in self.recovery_authorities]
        challenge_ids=[x.authority_id for x in self.challenge_authorities]
        challenge_keys=[x.authority_public_key for x in self.challenge_authorities]
        audit_ids=[x.audit_authority_id for x in self.audit_authorities]
        audit_keys=[x.audit_public_key for x in self.audit_authorities]
        for values,label in ((recovery_ids,"recovery authority IDs"),(recovery_keys,"recovery authority keys"),(challenge_ids,"challenger IDs"),(challenge_keys,"challenger keys"),(audit_ids,"auditor IDs"),(audit_keys,"auditor keys")):
            if len(values) != len(set(values)):
                raise ValueError(f"Recovery constitution requires unique {label}.")

        singleton_identities = [
            self.recovery_policy_authority, self.recovery_outcome_audit_authority,
            self.path_authority, self.ancestry_authority, self.challenge_policy_authority,
            self.audit_policy_authority, self.observation_policy_authority,
        ]
        if self.recovery_atomic_finalization_rule == "INDEPENDENT_SINGLE_ASSIGNMENT_FINALIZATION_ANCHOR":
            if self.recovery_atomic_execution_rule != "ATOMIC_PER_ACTION_RUNTIME_STATE":
                raise ValueError("Recovery v0.36 finalization anchor requires atomic per-action runtime state.")
            if self.recovery_atomic_anchor_authority is None:
                raise ValueError("Recovery v0.36 finalization anchor rule requires a manifest-pinned anchor authority.")
        if self.recovery_atomic_anchor_authority is not None:
            singleton_identities.append(self.recovery_atomic_anchor_authority)
        if self.recovery_provider_call_rule == "ATOMIC_SINGLE_CREATE_NO_AUTOMATIC_RETRY":
            if self.recovery_atomic_execution_rule != "ATOMIC_PER_ACTION_RUNTIME_STATE":
                raise ValueError("Recovery v0.37+ provider-call rule requires atomic per-action runtime state.")
            if self.recovery_atomic_finalization_rule != "INDEPENDENT_SINGLE_ASSIGNMENT_FINALIZATION_ANCHOR":
                raise ValueError("Recovery v0.37+ provider-call rule requires independent finalization anchor.")
        if self.recovery_interruption_rule == "DURABLE_CRASH_RECONCILIATION_FAIL_CLOSED_ON_UNCERTAIN_PROVIDER":
            if self.recovery_provider_call_rule != "ATOMIC_SINGLE_CREATE_NO_AUTOMATIC_RETRY":
                raise ValueError("Recovery v0.38 interruption rule requires governed single-create provider calls.")
            if self.recovery_atomic_execution_rule != "ATOMIC_PER_ACTION_RUNTIME_STATE":
                raise ValueError("Recovery v0.38 interruption rule requires atomic per-action runtime state.")
            if self.recovery_atomic_finalization_rule != "INDEPENDENT_SINGLE_ASSIGNMENT_FINALIZATION_ANCHOR":
                raise ValueError("Recovery v0.38 interruption rule requires independent finalization anchor.")
        if self.recovery_distributed_execution_rule == "SHARED_STATE_FENCED_WORKERS_SINGLE_ASSIGNMENT_PUBLICATION":
            if self.recovery_interruption_rule != "DURABLE_CRASH_RECONCILIATION_FAIL_CLOSED_ON_UNCERTAIN_PROVIDER":
                raise ValueError("Recovery v0.39 distributed execution requires v0.38 interruption semantics.")
            if self.recovery_provider_call_rule != "ATOMIC_SINGLE_CREATE_NO_AUTOMATIC_RETRY":
                raise ValueError("Recovery v0.39 distributed execution requires governed single-create provider calls.")
            if self.recovery_atomic_execution_rule != "ATOMIC_PER_ACTION_RUNTIME_STATE":
                raise ValueError("Recovery v0.39 distributed execution requires atomic per-action runtime state.")
            if self.recovery_atomic_finalization_rule != "INDEPENDENT_SINGLE_ASSIGNMENT_FINALIZATION_ANCHOR":
                raise ValueError("Recovery v0.39 distributed execution requires independent finalization anchor.")
        if self.recovery_state_integrity_rule == "PRE_RESUME_CROSS_STORE_INTEGRITY_AUDIT":
            if self.recovery_distributed_execution_rule != "SHARED_STATE_FENCED_WORKERS_SINGLE_ASSIGNMENT_PUBLICATION":
                raise ValueError("Recovery v0.40 state integrity requires v0.39 shared-state worker fencing.")
            if self.recovery_interruption_rule != "DURABLE_CRASH_RECONCILIATION_FAIL_CLOSED_ON_UNCERTAIN_PROVIDER":
                raise ValueError("Recovery v0.40 state integrity requires v0.38 interruption semantics.")
        if self.recovery_learning_curve_rule == "MONOTONIC_NEGATIVE_ONLY_CROSS_ATTEMPT_MEMORY":
            if self.recovery_state_integrity_rule != "PRE_RESUME_CROSS_STORE_INTEGRITY_AUDIT":
                raise ValueError("Recovery v0.41 learning memory requires v0.40 pre-resume state integrity.")
            if self.recovery_atomic_learning_rule != "MID_COMPLETION_CLASSIFICATION_STATE_TRANSITION_NEGATIVE_ONLY":
                raise ValueError("Recovery v0.41 learning memory requires negative-only mid-completion classification.")
        if self.recovery_learning_migration_rule == "POLICY_SIGNED_MODEL_SUCCESSION_NEGATIVE_ONLY":
            if self.recovery_learning_curve_rule != "MONOTONIC_NEGATIVE_ONLY_CROSS_ATTEMPT_MEMORY":
                raise ValueError("Recovery v0.42 model migration requires v0.41 monotonic negative-only learning memory.")
        if self.recovery_key_lifecycle_rule == "MONOTONIC_EPOCH_ROTATION_EXPIRY_REVOCATION":
            if self.recovery_learning_migration_rule != "POLICY_SIGNED_MODEL_SUCCESSION_NEGATIVE_ONLY":
                raise ValueError("Recovery v0.43 key lifecycle requires v0.42 model/policy migration government.")
            if self.recovery_key_lifecycle_authority is None:
                raise ValueError("Recovery v0.43 key lifecycle requires a manifest-pinned lifecycle authority.")
        if self.recovery_dependency_environment_rule == "PLAN_COMMITTED_TRANSITIVE_RUNTIME_ENVIRONMENT":
            if self.recovery_key_lifecycle_rule != "MONOTONIC_EPOCH_ROTATION_EXPIRY_REVOCATION":
                raise ValueError("Recovery v0.44 dependency environment governance requires v0.43 key lifecycle.")
        if self.recovery_key_lifecycle_authority is not None:
            singleton_identities.append(self.recovery_key_lifecycle_authority)
        all_ids = [x.authority_id for x in singleton_identities] + recovery_ids + challenge_ids + audit_ids
        all_keys = [x.authority_public_key for x in singleton_identities] + recovery_keys + challenge_keys + audit_keys
        if len(all_ids) != len(set(all_ids)):
            raise ValueError("Recovery constitution requires globally distinct typed authority IDs.")
        if len(all_keys) != len(set(all_keys)):
            raise ValueError("Recovery constitution requires globally distinct typed authority keys.")
        publisher_keys = {x.publisher_public_key for x in self.recovery_publisher_sources}
        if publisher_keys & set(all_keys):
            raise ValueError("Recovery constitution publisher keys must be external to all internal recovery-governance keys.")
        attempt_ids = [x.witness_id for x in self.recovery_attempt_witnesses]
        attempt_keys = [x.witness_public_key for x in self.recovery_attempt_witnesses]
        if len(attempt_ids) != len(set(attempt_ids)) or len(attempt_keys) != len(set(attempt_keys)):
            raise ValueError("Recovery attempt state witnesses must have unique IDs and keys.")
        if self.recovery_attempt_witness_quorum > len(self.recovery_attempt_witnesses):
            raise ValueError("Recovery attempt witness quorum exceeds witness count.")
        if set(attempt_keys) & (set(all_keys) | publisher_keys):
            raise ValueError("Recovery attempt witness keys must be external to internal recovery and publisher keys.")

        log_key_by_id: dict[str, str] = {}
        transparency_external_keys: set[str] = set()
        for spec in self.recovery_publisher_sources:
            prior_log_key = log_key_by_id.get(spec.transparency_log_id)
            if prior_log_key is not None and prior_log_key != spec.transparency_log_public_key:
                raise ValueError("Recovery transparency log ID cannot map to multiple public keys.")
            log_key_by_id[spec.transparency_log_id] = spec.transparency_log_public_key
            identity_key = spec.identity_attestation.identity_authority_public_key
            log_key = spec.transparency_log_public_key
            witness_keys = {x.witness_public_key for x in spec.transparency_witnesses}
            external_roles = {spec.publisher_public_key, identity_key, log_key} | witness_keys
            if len(external_roles) != 3 + len(witness_keys):
                raise ValueError(
                    "Recovery publisher identity, publisher, transparency log, and witness keys must be role-distinct."
                )
            if (external_roles - {spec.publisher_public_key}) & set(all_keys):
                raise ValueError(
                    "Recovery publisher identity/log/witness keys must be external to all internal recovery-governance keys."
                )
            transparency_external_keys |= external_roles
        if set(attempt_keys) & transparency_external_keys:
            raise ValueError("Recovery attempt state witnesses must be role-distinct from publisher transparency authorities.")
        return self


class DecisionUsefulnessAssurance(BaseModel):
    """Utility record that never overrides PASS/HOLD/REJECT.

    SCOPED_SALVAGE means the full composite claim remains HOLD, but exact
    atom statements listed here passed independently localizable checks and may
    be reused only as those exact scoped atoms. Global integrity failures always
    disable salvage.
    """

    status: Literal["FULL_PASS", "SCOPED_SALVAGE", "HARD_HOLD", "REJECTED"]
    promotable_atom_ids: list[str] = Field(default_factory=list)
    promotable_statements: dict[str, str] = Field(default_factory=dict)
    held_atom_ids: list[str] = Field(default_factory=list)
    atom_blockers: dict[str, list[str]] = Field(default_factory=dict)
    global_blockers: list[str] = Field(default_factory=list)
    recovery_requirements: list[str] = Field(default_factory=list)
    preserved_atom_count: int = 0
    total_atom_count: int = 0
    preservation_rate: float = Field(default=0.0, ge=0.0, le=1.0)


class DecisionRecord(BaseModel):
    claim_id: str
    verdict: Verdict
    declared_scope: str
    reasons: list[str]
    findings: list[ReviewFinding]
    reviewer_status: dict[str, str]
    reviewer_execution: dict[str, str] = Field(default_factory=dict)
    evidence_digests: dict[str, str]
    evidence_admission_status: dict[str, str] = Field(default_factory=dict)
    evidence_transition: EvidenceTransitionAssurance | None = None
    semantic_assurance: SemanticAssurance | None = None
    semantic_obligation_assurance: SemanticObligationAssurance | None = None
    external_witness_assurance: ExternalWitnessAssurance | None = None
    witness_quorum_assurance: WitnessQuorumAssurance | None = None
    witness_provenance_assurance: WitnessProvenanceAssurance | None = None
    witness_ancestry_assurance: WitnessAncestryAssurance | None = None
    witness_registry_assurance: WitnessRegistryAssurance | None = None
    witness_registry_ancestry_assurance: WitnessRegistryAncestryAssurance | None = None
    witness_registry_observation_assurance: WitnessRegistryObservationAssurance | None = None
    usefulness_assurance: DecisionUsefulnessAssurance | None = None
    calibration_assurance: DecisionCalibrationAssurance | None = None
    atom_assurance: list[AtomAssurance] = Field(default_factory=list)
    allowed_output: str
    input_sha256: str
    decision_sha256: str
