from __future__ import annotations

from collections import Counter, defaultdict

from .integrity import evidence_digest_map, findings_digest, semantic_artifacts_digest, sha256_object, sha256_text
from .evidence_admission import canonical_origin, load_evidence_key, verify_evidence_admission
from .prompts import REVIEWER_PROMPTS
from .receipts import (
    load_runtime_key,
    model_review_schema_sha256,
    review_invocation_digest,
    verify_runtime_receipt,
)
from .schemas import (
    AssuranceProfile,
    AtomAssurance,
    ClaimCandidate,
    DecisionRecord,
    EvidenceAdmissionStatus,
    EvidenceBundle,
    EvidenceTransitionAssurance,
    ExternalWitnessAssurance,
    ExternalWitnessResult,
    ExternalWitnessSet,
    WitnessQuorumAssurance,
    WitnessProvenanceAssurance,
    WitnessAncestryAssurance,
    WitnessRegistryAssurance,
    WitnessRegistryAncestryAssurance,
    WitnessRegistryObservationAssurance,
    FindingType,
    ReviewBundle,
    ReviewContextMode,
    ReviewExecutionMode,
    ReviewFinding,
    ReviewStatus,
    Severity,
    SemanticAssurance,
    SemanticFrame,
    SemanticObligationAssurance,
    SemanticObligationCheck,
    SemanticObligationResult,
    SemanticObligationType,
    SemanticQuantifier,
    SemanticRelation,
    Verdict,
)
from .security import scan_bundle
from .witness_auth import verify_external_witness_set
from .witness_quorum import WitnessQuorumPolicy, WitnessSelectionReveal, check_matches_spec, verify_selection_reveal
from .measurement_provenance import WitnessMeasurementReceipt, WitnessProvenancePolicy, verify_measurement_universe
from .dependency_ancestry import MeasurementAncestryManifest, WitnessAncestryPolicy, verify_dependency_ancestry
from .dependency_registry import DependencyRegistryAttestation, WitnessRegistryPolicy, verify_dependency_registry
from .registry_ancestry import RegistryAncestryManifest, WitnessRegistryAncestryPolicy, verify_registry_ancestry
from .registry_observation import RegistryDependencyObservation, WitnessRegistryObservationPolicy, verify_registry_observations
from .usefulness import assess_decision_usefulness
from .calibration import assess_decision_calibration

REQUIRED_REVIEWERS = {"decomposer", "evidence", "challenger", "scope", "security"}
SEMANTIC_REVIEWERS = {"entailment", "counterexample"}


def required_reviewers_for_claim(claim: ClaimCandidate) -> set[str]:
    required = set(REQUIRED_REVIEWERS)
    if claim.assurance_profile in {AssuranceProfile.SEMANTIC_FORTIFIED, AssuranceProfile.REPRESENTATION_FORTIFIED, AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED, AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        required.update(SEMANTIC_REVIEWERS)
    return required

_FINDING_OWNER = {
    FindingType.DECOMPOSITION_GAP: "decomposer",
    FindingType.FABRICATION: "evidence",
    FindingType.INSUFFICIENT_EVIDENCE: "evidence",
    FindingType.STALE_EVIDENCE: "evidence",
    FindingType.CONTRADICTION: "challenger",
    FindingType.SCOPE_INFLATION: "scope",
    FindingType.PROMPT_INJECTION: "security",
    FindingType.ENTAILMENT_GAP: "entailment",
    FindingType.COUNTEREXAMPLE_FOUND: "counterexample",
    FindingType.REPRESENTATION_DISAGREEMENT: "decomposer",
    FindingType.SEMANTIC_OBLIGATION_GAP: "decomposer",
    FindingType.SEMANTIC_OBLIGATION_FAILED: "entailment",
}

_HOLD_TYPES = {
    FindingType.CONTRADICTION,
    FindingType.INSUFFICIENT_EVIDENCE,
    FindingType.SCOPE_INFLATION,
    FindingType.PROMPT_INJECTION,
    FindingType.STALE_EVIDENCE,
    FindingType.MALFORMED_EVIDENCE,
    FindingType.REVIEWER_ROLE_VIOLATION,
    FindingType.EVIDENCE_TAMPER,
    FindingType.INVALID_RUNTIME_RECEIPT,
    FindingType.REVIEW_OUTPUT_TAMPER,
    FindingType.REVIEW_CONTEXT_CONTAMINATION,
    FindingType.DUPLICATE_REVIEW_INVOCATION,
    FindingType.DECOMPOSITION_GAP,
    FindingType.ATOMIC_COVERAGE_GAP,
    FindingType.SOURCE_DIVERSITY_GAP,
    FindingType.SOURCE_PROVENANCE_MISSING,
    FindingType.DUPLICATE_ATOMIC_CLAIM,
    FindingType.EVIDENCE_ADMISSION_MISSING,
    FindingType.INVALID_EVIDENCE_ADMISSION,
    FindingType.EVIDENCE_ACQUISITION_FAILED,
    FindingType.EVIDENCE_ORIGIN_DIVERSITY_GAP,
    FindingType.DUPLICATE_EVIDENCE_CAPTURE,
    FindingType.MODEL_EXECUTION_UNBOUND,
    FindingType.MODEL_OUTPUT_MALFORMED,
    FindingType.MODEL_SCHEMA_MISMATCH,
    FindingType.DUPLICATE_MODEL_RESPONSE,
    FindingType.INVOCATION_CONTINUITY_FAILURE,
    FindingType.EVIDENCE_SPACE_VIOLATION,
    FindingType.MATERIAL_TRANSITION_LEAKAGE,
    FindingType.ENTAILMENT_GAP,
    FindingType.COUNTEREXAMPLE_FOUND,
    FindingType.SEMANTIC_REVIEW_COVERAGE_GAP,
    FindingType.REPRESENTATION_DISAGREEMENT,
    FindingType.SEMANTIC_OBLIGATION_GAP,
    FindingType.SEMANTIC_OBLIGATION_FAILED,
    FindingType.EXTERNAL_WITNESS_GAP,
    FindingType.EXTERNAL_WITNESS_INVALID,
    FindingType.EXTERNAL_WITNESS_NOT_INDEPENDENT,
    FindingType.EXTERNAL_WITNESS_COUNTEREXAMPLE,
    FindingType.EXTERNAL_WITNESS_UNRESOLVED,
    FindingType.WITNESS_SELECTION_INVALID,
    FindingType.WITNESS_AUTHORITY_QUORUM_GAP,
    FindingType.WITNESS_AUTHORITY_DISAGREEMENT,
    FindingType.WITNESS_CHALLENGE_SUBSTITUTION,
    FindingType.WITNESS_MEASUREMENT_PROVENANCE_INVALID,
    FindingType.WITNESS_DEPENDENCY_DIVERSITY_GAP,
    FindingType.WITNESS_MEASUREMENT_AUTHORITY_GAP,
    FindingType.WITNESS_ANCESTRY_INVALID,
    FindingType.WITNESS_ANCESTRY_OVERLAP,
    FindingType.WITNESS_REGISTRY_INVALID,
    FindingType.WITNESS_REGISTRY_DISCLOSURE_GAP,
    FindingType.WITNESS_REGISTRY_ANCESTRY_INVALID,
    FindingType.WITNESS_REGISTRY_ANCESTRY_OVERLAP,
    FindingType.WITNESS_REGISTRY_OBSERVATION_INVALID,
    FindingType.WITNESS_REGISTRY_OBSERVATION_DISCLOSURE_GAP,
}


def _role_violation(finding: ReviewFinding) -> bool:
    owner = _FINDING_OWNER.get(finding.finding_type)
    return owner is not None and finding.reviewer != owner


def _seal_decision(record: DecisionRecord) -> DecisionRecord:
    digest = sha256_object(record.model_dump(mode="json", exclude={"decision_sha256"}))
    return record.model_copy(update={"decision_sha256": digest})


def _required_source_groups(claim: ClaimCandidate) -> int:
    return 2 if claim.assurance_profile in {AssuranceProfile.CORROBORATED, AssuranceProfile.FORTIFIED, AssuranceProfile.MODEL_BOUND, AssuranceProfile.SEMANTIC_FORTIFIED, AssuranceProfile.REPRESENTATION_FORTIFIED, AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED, AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED} else 1


def _requires_admission(claim: ClaimCandidate) -> bool:
    return claim.assurance_profile in {AssuranceProfile.FORTIFIED, AssuranceProfile.MODEL_BOUND, AssuranceProfile.SEMANTIC_FORTIFIED, AssuranceProfile.REPRESENTATION_FORTIFIED, AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED, AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}


def _requires_model_binding(claim: ClaimCandidate) -> bool:
    return claim.assurance_profile in {AssuranceProfile.MODEL_BOUND, AssuranceProfile.SEMANTIC_FORTIFIED, AssuranceProfile.REPRESENTATION_FORTIFIED, AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED, AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}


def _atomic_preflight(
    claim: ClaimCandidate,
    evidence: EvidenceBundle,
    trusted_admission_origins: dict[str, str] | None = None,
) -> tuple[list[ReviewFinding], list[str], list[AtomAssurance], bool]:
    """Deterministic structural anti-consensus checks.

    This does not decide semantic truth. It prevents PASS when the claim was not
    atomized, when an atom has no declared evidence, or when a corroborated atom
    depends on fewer than two declared source families.
    """
    findings: list[ReviewFinding] = []
    reasons: list[str] = []
    atom_reports: list[AtomAssurance] = []
    hold = False
    evidence_by_id = evidence.by_id()
    claim_evidence_ids = set(claim.evidence_ids)
    required_groups = _required_source_groups(claim)
    admission_origins = trusted_admission_origins or {}
    required_origins = 2 if _requires_admission(claim) else 0

    if not claim.atoms:
        hold = True
        reasons.append("CLAIM_NOT_DECOMPOSED: no atomic propositions were supplied.")
        findings.append(
            ReviewFinding(
                reviewer="decomposer",
                finding_type=FindingType.ATOMIC_COVERAGE_GAP,
                severity=Severity.CRITICAL,
                message="Candidate claim has no atomic proposition map.",
                evidence_ids=[],
            )
        )
        return findings, reasons, atom_reports, hold

    normalized_statements: dict[str, list[str]] = defaultdict(list)
    for atom in claim.atoms:
        normalized = " ".join(atom.statement.casefold().split())
        normalized_statements[normalized].append(atom.atom_id)
    duplicates = [ids for ids in normalized_statements.values() if len(ids) > 1]
    if duplicates:
        hold = True
        flat = sorted(atom_id for group in duplicates for atom_id in group)
        reasons.append("DUPLICATE_ATOMIC_CLAIM: " + ", ".join(flat))
        findings.append(
            ReviewFinding(
                reviewer="decomposer",
                finding_type=FindingType.DUPLICATE_ATOMIC_CLAIM,
                severity=Severity.WARNING,
                message="Atomic map contains duplicate proposition text.",
                evidence_ids=[],
            )
        )

    for atom in claim.atoms:
        atom_hold = False
        if not atom.evidence_ids:
            atom_hold = hold = True
            reasons.append(f"ATOM_NO_EVIDENCE: {atom.atom_id}")
            findings.append(
                ReviewFinding(
                    reviewer="evidence",
                    finding_type=FindingType.ATOMIC_COVERAGE_GAP,
                    severity=Severity.CRITICAL,
                    message=f"Atomic claim {atom.atom_id} has no declared evidence.",
                    evidence_ids=[],
                )
            )

        undeclared = sorted(set(atom.evidence_ids) - claim_evidence_ids)
        if undeclared:
            atom_hold = hold = True
            reasons.append(
                f"ATOM_EVIDENCE_OUTSIDE_CLAIM: {atom.atom_id} -> {', '.join(undeclared)}"
            )

        missing = sorted(set(atom.evidence_ids) - set(evidence_by_id))
        if missing:
            atom_hold = hold = True
            reasons.append(
                f"ATOM_MISSING_EVIDENCE_OBJECTS: {atom.atom_id} -> {', '.join(missing)}"
            )

        available = [
            evidence_by_id[eid]
            for eid in atom.evidence_ids
            if eid in evidence_by_id and eid in claim_evidence_ids
        ]
        source_groups = sorted({item.source_group.strip() for item in available if item.source_group.strip()})
        sources = sorted({item.source.strip() for item in available if item.source.strip()})
        missing_provenance = sorted(
            item.evidence_id for item in available if not item.source_group.strip()
        )
        if missing_provenance:
            atom_hold = hold = True
            reasons.append(
                f"SOURCE_PROVENANCE_MISSING: {atom.atom_id} -> {', '.join(missing_provenance)}"
            )
            findings.append(
                ReviewFinding(
                    reviewer="evidence",
                    finding_type=FindingType.SOURCE_PROVENANCE_MISSING,
                    severity=Severity.CRITICAL,
                    message=f"Atomic claim {atom.atom_id} contains evidence without a declared source group.",
                    evidence_ids=missing_provenance,
                )
            )

        diversity_gap = len(source_groups) < required_groups or len(sources) < required_groups
        if diversity_gap:
            atom_hold = hold = True
            reasons.append(
                f"SOURCE_DIVERSITY_GAP: {atom.atom_id} requires {required_groups} "
                f"declared source group(s) and {required_groups} distinct source locator(s); "
                f"observed groups={len(source_groups)}, locators={len(sources)}."
            )
            findings.append(
                ReviewFinding(
                    reviewer="evidence",
                    finding_type=FindingType.SOURCE_DIVERSITY_GAP,
                    severity=Severity.WARNING,
                    message=(
                        f"Atomic claim {atom.atom_id} does not meet the {claim.assurance_profile.value} "
                        "declared source-diversity policy."
                    ),
                    evidence_ids=[item.evidence_id for item in available],
                )
            )

        captured_origins = sorted({
            admission_origins[eid]
            for eid in atom.evidence_ids
            if eid in admission_origins
        })
        if required_origins and len(captured_origins) < required_origins:
            atom_hold = hold = True
            reasons.append(
                f"EVIDENCE_ORIGIN_DIVERSITY_GAP: {atom.atom_id} requires {required_origins} "
                f"runtime-attested source origin(s); observed={len(captured_origins)}."
            )
            findings.append(
                ReviewFinding(
                    reviewer="evidence",
                    finding_type=FindingType.EVIDENCE_ORIGIN_DIVERSITY_GAP,
                    severity=Severity.WARNING,
                    message=(
                        f"Atomic claim {atom.atom_id} lacks enough distinct runtime-attested "
                        "source origins for fortified assurance."
                    ),
                    evidence_ids=[item.evidence_id for item in available],
                )
            )

        atom_reports.append(
            AtomAssurance(
                atom_id=atom.atom_id,
                required_source_groups=required_groups,
                observed_source_groups=len(source_groups),
                source_groups=source_groups,
                observed_sources=len(sources),
                sources=sources,
                required_captured_origins=required_origins,
                observed_captured_origins=len(captured_origins),
                captured_origins=captured_origins,
                status="HOLD" if atom_hold else "PASS",
            )
        )

    return findings, reasons, atom_reports, hold


def decide(
    claim: ClaimCandidate,
    evidence: EvidenceBundle,
    review: ReviewBundle,
    *,
    runtime_key: bytes | None = None,
    evidence_key: bytes | None = None,
    external_witness: ExternalWitnessSet | None = None,
    expected_witness_public_key: str | None = None,
    external_witness_sets: list[ExternalWitnessSet] | None = None,
    witness_quorum_policy: WitnessQuorumPolicy | None = None,
    witness_selection_reveal: WitnessSelectionReveal | None = None,
    witness_provenance_policy: WitnessProvenancePolicy | None = None,
    witness_measurement_receipts: list[WitnessMeasurementReceipt] | None = None,
    witness_ancestry_policy: WitnessAncestryPolicy | None = None,
    witness_ancestry_manifests: list[MeasurementAncestryManifest] | None = None,
    witness_registry_policy: WitnessRegistryPolicy | None = None,
    witness_registry_attestations: list[DependencyRegistryAttestation] | None = None,
    witness_registry_ancestry_policy: WitnessRegistryAncestryPolicy | None = None,
    witness_registry_ancestry_manifests: list[RegistryAncestryManifest] | None = None,
    witness_registry_observation_policy: WitnessRegistryObservationPolicy | None = None,
    witness_registry_observations: list[RegistryDependencyObservation] | None = None,
    expected_witness_case_id: str | None = None,
) -> DecisionRecord:
    try:
        receipt_key = runtime_key if runtime_key is not None else load_runtime_key()
    except RuntimeError:
        receipt_key = b""

    evidence_by_id = evidence.by_id()
    current_digests = evidence_digest_map(evidence)
    current_claim_digest = sha256_object(claim)
    required_reviewers = required_reviewers_for_claim(claim)
    claim_ids = set(claim.evidence_ids)  # E1: candidate transition/support projection
    universe_ids = set(evidence_by_id)   # E0: complete frozen evidence universe
    receipts = review.receipts_by_reviewer()
    model_findings = list(review.findings)
    findings = list(model_findings)
    reasons: list[str] = []

    # FORTIFIED assurance requires trusted-runtime evidence acquisition receipts.
    trusted_admission_origins: dict[str, str] = {}
    admission_target_ids = universe_ids if _requires_admission(claim) else claim_ids
    admission_status: dict[str, str] = {eid: "NOT_REQUIRED" for eid in sorted(admission_target_ids)}
    admission_reasons: list[str] = []
    admission_hold = False
    if _requires_admission(claim):
        try:
            admission_key = evidence_key if evidence_key is not None else load_evidence_key()
        except RuntimeError:
            admission_key = b""
        if not admission_key:
            admission_hold = True
            admission_reasons.append(
                "EVIDENCE_ADMISSION_KEY_UNAVAILABLE: cannot authenticate evidence acquisition."
            )

        admissions = evidence.admissions_by_evidence_id()
        unknown_admissions = sorted(set(admissions) - set(evidence_by_id))
        if unknown_admissions:
            admission_hold = True
            admission_reasons.append(
                "EVIDENCE_ADMISSION_UNKNOWN_OBJECT: " + ", ".join(unknown_admissions)
            )

        capture_ids = [
            admissions[eid].capture_id
            for eid in sorted(admission_target_ids & set(admissions))
        ]
        duplicate_capture_ids = sorted(
            value for value, count in Counter(capture_ids).items() if count > 1
        )
        if duplicate_capture_ids:
            admission_hold = True
            admission_reasons.append(
                "DUPLICATE_EVIDENCE_CAPTURE: " + ", ".join(duplicate_capture_ids)
            )
            findings.append(
                ReviewFinding(
                    reviewer="evidence",
                    finding_type=FindingType.DUPLICATE_EVIDENCE_CAPTURE,
                    severity=Severity.CRITICAL,
                    message="Multiple evidence objects reuse the same acquisition identity.",
                    evidence_ids=sorted(admission_target_ids & set(admissions)),
                )
            )

        for evidence_id in sorted(admission_target_ids):
            item = evidence_by_id.get(evidence_id)
            receipt = admissions.get(evidence_id)
            if item is None:
                continue
            if receipt is None:
                admission_status[evidence_id] = "MISSING"
                admission_hold = True
                admission_reasons.append(f"EVIDENCE_ADMISSION_MISSING: {evidence_id}")
                findings.append(
                    ReviewFinding(
                        reviewer="evidence",
                        finding_type=FindingType.EVIDENCE_ADMISSION_MISSING,
                        severity=Severity.CRITICAL,
                        message=f"Evidence {evidence_id} has no trusted acquisition receipt.",
                        evidence_ids=[evidence_id],
                    )
                )
                continue
            signature_ok = bool(admission_key) and verify_evidence_admission(receipt, admission_key)
            digest_ok = receipt.evidence_sha256 == current_digests.get(evidence_id)
            origin_ok = receipt.source_origin == canonical_origin(item.source)
            if not signature_ok or not digest_ok or not origin_ok:
                admission_status[evidence_id] = "INVALID"
                admission_hold = True
                admission_reasons.append(f"INVALID_EVIDENCE_ADMISSION: {evidence_id}")
                findings.append(
                    ReviewFinding(
                        reviewer="evidence",
                        finding_type=FindingType.INVALID_EVIDENCE_ADMISSION,
                        severity=Severity.CRITICAL,
                        message=f"Evidence {evidence_id} acquisition receipt is invalid or unbound.",
                        evidence_ids=[evidence_id],
                    )
                )
                continue
            if receipt.status != EvidenceAdmissionStatus.CAPTURED:
                admission_status[evidence_id] = receipt.status.value
                admission_hold = True
                admission_reasons.append(f"EVIDENCE_ACQUISITION_FAILED: {evidence_id}")
                findings.append(
                    ReviewFinding(
                        reviewer="evidence",
                        finding_type=FindingType.EVIDENCE_ACQUISITION_FAILED,
                        severity=Severity.CRITICAL,
                        message=f"Evidence {evidence_id} was not successfully captured.",
                        evidence_ids=[evidence_id],
                    )
                )
                continue
            trusted_admission_origins[evidence_id] = receipt.source_origin
            admission_status[evidence_id] = "CAPTURED"

    # Local deterministic policy output remains separate from model findings.
    findings.extend(scan_bundle(evidence))
    atomic_findings, atomic_reasons, atom_assurance, atomic_hold = _atomic_preflight(
        claim, evidence, trusted_admission_origins
    )
    findings.extend(atomic_findings)
    reasons.extend(admission_reasons)
    reasons.extend(atomic_reasons)

    if not receipt_key:
        reasons.append("RUNTIME_RECEIPT_KEY_UNAVAILABLE: cannot authenticate reviewer completion.")

    if not claim.evidence_ids:
        reasons.append("NO_EVIDENCE: candidate claim has no declared evidence.")

    missing_evidence = sorted(claim_ids - set(evidence_by_id))
    if missing_evidence:
        reasons.append("MISSING_EVIDENCE_OBJECTS: " + ", ".join(missing_evidence))

    missing_reviewers = sorted(required_reviewers - set(receipts))
    if missing_reviewers:
        reasons.append("MISSING_REVIEWER_RECEIPT: " + ", ".join(missing_reviewers))

    invalid_receipts = sorted(
        name for name, receipt in receipts.items()
        if not receipt_key or not verify_runtime_receipt(receipt, receipt_key)
    )
    if invalid_receipts:
        reasons.append("INVALID_RUNTIME_RECEIPT: " + ", ".join(invalid_receipts))

    failed_reviewers = sorted(
        name for name, receipt in receipts.items() if receipt.status != ReviewStatus.SUCCESS
    )
    if failed_reviewers:
        details = [f"{name}={receipts[name].status.value}" for name in failed_reviewers]
        reasons.append("REVIEWER_NOT_SUCCESSFUL: " + ", ".join(details))

    contaminated_context = sorted(
        name for name, receipt in receipts.items()
        if receipt.context_mode != ReviewContextMode.ISOLATED or receipt.upstream_review_digests
    )
    if contaminated_context:
        reasons.append("REVIEW_CONTEXT_CONTAMINATION: " + ", ".join(contaminated_context))

    prompt_mismatch = sorted(
        name for name, receipt in receipts.items()
        if name in REVIEWER_PROMPTS and receipt.prompt_sha256 != sha256_text(REVIEWER_PROMPTS[name])
    )
    if prompt_mismatch:
        reasons.append("REVIEWER_PROMPT_MISMATCH: " + ", ".join(prompt_mismatch))

    invocation_continuity_mismatch = []
    for name, receipt in receipts.items():
        if name not in REVIEWER_PROMPTS:
            continue
        expected_invocation = review_invocation_digest(
            reviewer=name,
            claim=claim,
            evidence=EvidenceBundle(items=list(evidence.items)),
            prompt_text=REVIEWER_PROMPTS[name],
            context_mode=receipt.context_mode,
            upstream_review_digests=receipt.upstream_review_digests,
            invocation_id=receipt.invocation_id,
            run_token=receipt.run_token,
            attempt_context_sha256=receipt.attempt_context_sha256,
        )
        if receipt.invocation_sha256 != expected_invocation:
            invocation_continuity_mismatch.append(name)
    if invocation_continuity_mismatch:
        reasons.append(
            "INVOCATION_CONTINUITY_FAILURE: " + ", ".join(sorted(invocation_continuity_mismatch))
        )

    model_binding_failures: list[str] = []
    duplicate_model_responses: list[str] = []
    correlated_model_output_sha256 = ""
    if _requires_model_binding(claim):
        expected_schema = model_review_schema_sha256()
        for name in sorted(required_reviewers & set(receipts)):
            receipt = receipts[name]
            if receipt.execution_mode not in {
                ReviewExecutionMode.MODEL_LIVE,
                ReviewExecutionMode.MODEL_REPLAY,
            }:
                model_binding_failures.append(f"{name}=execution_mode")
            if not receipt.model_provider.strip() or not receipt.model_id.strip():
                model_binding_failures.append(f"{name}=model_identity")
            if not receipt.model_response_id.strip():
                model_binding_failures.append(f"{name}=response_id")
            if receipt.response_schema_sha256 != expected_schema:
                model_binding_failures.append(f"{name}=schema")
        response_ids = [
            receipt.model_response_id
            for receipt in receipts.values()
            if receipt.model_response_id.strip()
        ]
        duplicate_model_responses = sorted(
            value for value, count in Counter(response_ids).items() if count > 1
        )
        successful_output_hashes = [
            receipts[name].raw_output_sha256
            for name in sorted(required_reviewers & set(receipts))
            if receipts[name].status == ReviewStatus.SUCCESS
            and receipts[name].raw_output_utf8_bytes > 0
        ]
        if (
            len(successful_output_hashes) == len(required_reviewers)
            and len(set(successful_output_hashes)) == 1
        ):
            correlated_model_output_sha256 = successful_output_hashes[0]
        if model_binding_failures:
            reasons.append("MODEL_EXECUTION_UNBOUND: " + ", ".join(model_binding_failures))
        if duplicate_model_responses:
            reasons.append(
                "DUPLICATE_MODEL_RESPONSE: " + ", ".join(duplicate_model_responses)
            )
        if correlated_model_output_sha256:
            reasons.append(
                "CORRELATED_MODEL_OUTPUT: every required reviewer returned the exact same raw output "
                f"({correlated_model_output_sha256})."
            )

    invocation_ids = [receipt.invocation_id for receipt in receipts.values()]
    duplicate_invocations = sorted(
        value for value, count in Counter(invocation_ids).items() if count > 1
    )
    run_tokens = [receipt.run_token for receipt in receipts.values()]
    duplicate_tokens = sorted(value for value, count in Counter(run_tokens).items() if count > 1)
    if duplicate_invocations or duplicate_tokens:
        detail = []
        if duplicate_invocations:
            detail.append("invocation_id=" + ",".join(duplicate_invocations))
        if duplicate_tokens:
            detail.append("run_token=" + ",".join(duplicate_tokens))
        reasons.append("DUPLICATE_REVIEW_INVOCATION: " + "; ".join(detail))

    binding_mismatch = False
    for reviewer in sorted(required_reviewers & set(receipts)):
        receipt = receipts[reviewer]
        if receipt.claim_sha256 != current_claim_digest:
            binding_mismatch = True
            reasons.append(f"CLAIM_BINDING_MISMATCH: {reviewer} reviewed a different claim snapshot.")
        if receipt.status != ReviewStatus.SUCCESS:
            continue
        reviewed_ids = set(receipt.evidence_digests)
        if reviewed_ids != universe_ids:
            binding_mismatch = True
            extra = sorted(reviewed_ids - universe_ids)
            omitted = sorted(universe_ids - reviewed_ids)
            detail = []
            if omitted:
                detail.append("omitted=" + ",".join(omitted))
            if extra:
                detail.append("extra=" + ",".join(extra))
            reasons.append(
                f"REVIEW_EVIDENCE_SET_MISMATCH: {reviewer} " + "; ".join(detail)
            )
        for evidence_id in sorted(universe_ids):
            actual = current_digests.get(evidence_id)
            reviewed = receipt.evidence_digests.get(evidence_id)
            if actual is None:
                continue
            if reviewed != actual:
                binding_mismatch = True
                reasons.append(
                    f"EVIDENCE_BINDING_MISMATCH: {reviewer} did not bind current {evidence_id}."
                )

    findings_by_reviewer: dict[str, list[ReviewFinding]] = defaultdict(list)
    for finding in model_findings:
        findings_by_reviewer[finding.reviewer].append(finding)

    output_mismatch = sorted(
        name for name, receipt in receipts.items()
        if receipt.findings_sha256 != findings_digest(findings_by_reviewer.get(name, []))
    )
    if output_mismatch:
        reasons.append("REVIEW_OUTPUT_BINDING_MISMATCH: " + ", ".join(output_mismatch))

    semantic_frames_by_reviewer: dict[str, list[SemanticFrame]] = defaultdict(list)
    semantic_obligations_by_reviewer: dict[str, list[SemanticObligationCheck]] = defaultdict(list)
    for frame in review.semantic_frames:
        semantic_frames_by_reviewer[frame.reviewer].append(frame)
    for item in review.semantic_obligations:
        semantic_obligations_by_reviewer[item.reviewer].append(item)
    semantic_artifact_mismatch = sorted(
        name for name, receipt in receipts.items()
        if receipt.semantic_artifacts_sha256 != semantic_artifacts_digest(
            semantic_frames_by_reviewer.get(name, []),
            semantic_obligations_by_reviewer.get(name, []),
        )
    )
    if semantic_artifact_mismatch:
        reasons.append("SEMANTIC_ARTIFACT_BINDING_MISMATCH: " + ", ".join(semantic_artifact_mismatch))

    role_violations = [finding for finding in model_findings if _role_violation(finding)]
    if role_violations:
        reasons.append(f"REVIEWER_ROLE_VIOLATION: {len(role_violations)} finding(s).")
        findings.extend(
            ReviewFinding(
                reviewer="security",
                finding_type=FindingType.REVIEWER_ROLE_VIOLATION,
                severity=Severity.CRITICAL,
                message=(
                    f"Reviewer {finding.reviewer} attempted finding type "
                    f"{finding.finding_type.value}, owned by {_FINDING_OWNER[finding.finding_type]}."
                ),
                evidence_ids=finding.evidence_ids,
            )
            for finding in role_violations
        )

    bad_refs = sorted(
        {
            evidence_id
            for finding in model_findings
            for evidence_id in finding.evidence_ids
            if evidence_id not in evidence_by_id
        }
    )
    if bad_refs:
        reasons.append("FINDING_REFERENCES_UNKNOWN_EVIDENCE: " + ", ".join(bad_refs))

    # Three-space accounting: E0 is the complete frozen universe, E1 is the
    # candidate-selected projection, and E2 is the authenticated reviewer set.
    # E1 omission is observable but not automatically blocking. It becomes
    # material leakage when a blocking reviewer finding relies on omitted E0 data.
    reviewer_space_ids = set()
    if receipts:
        reviewer_sets = [set(r.evidence_digests) for r in receipts.values()]
        if reviewer_sets:
            reviewer_space_ids = set.intersection(*reviewer_sets)
    omitted_ids = sorted(universe_ids - claim_ids)
    added_ids = sorted(claim_ids - universe_ids)
    mutated_ids: list[str] = []  # E1 contains references, not mutable evidence copies.
    material_types = {
        FindingType.CONTRADICTION,
        FindingType.INSUFFICIENT_EVIDENCE,
        FindingType.SCOPE_INFLATION,
        FindingType.STALE_EVIDENCE,
        FindingType.FABRICATION,
    }
    material_omission_ids = sorted({
        eid
        for finding in model_findings
        if finding.finding_type in material_types
        for eid in finding.evidence_ids
        if eid in set(omitted_ids)
    })
    if added_ids:
        reasons.append("EVIDENCE_SPACE_VIOLATION: E1 contains IDs outside frozen E0: " + ", ".join(added_ids))
    if material_omission_ids:
        reasons.append("MATERIAL_TRANSITION_LEAKAGE: omitted E0 evidence affected independent review: " + ", ".join(material_omission_ids))
    transition_status = "HOLD" if added_ids or mutated_ids or material_omission_ids else ("OBSERVED" if omitted_ids else "PASS")
    transition_assurance = EvidenceTransitionAssurance(
        universe_ids=sorted(universe_ids),
        transition_ids=sorted(claim_ids),
        reviewer_ids=sorted(reviewer_space_ids),
        omitted_ids=omitted_ids,
        added_ids=added_ids,
        mutated_ids=mutated_ids,
        material_omission_ids=material_omission_ids,
        status=transition_status,
    )

    semantic_assurance = SemanticAssurance(status="NOT_REQUIRED")
    semantic_hold = False
    if claim.assurance_profile in {AssuranceProfile.SEMANTIC_FORTIFIED, AssuranceProfile.REPRESENTATION_FORTIFIED, AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED, AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        completed_semantic = sorted(
            name for name in SEMANTIC_REVIEWERS
            if name in receipts and receipts[name].status == ReviewStatus.SUCCESS
        )
        semantic_model_ids = sorted({
            receipts[name].model_id
            for name in completed_semantic
            if receipts[name].model_id.strip()
        })
        semantic_hold = len(completed_semantic) != len(SEMANTIC_REVIEWERS)
        if semantic_hold:
            reasons.append(
                "SEMANTIC_REVIEW_COVERAGE_GAP: required heterogeneous semantic strategies did not all complete."
            )
            findings.append(
                ReviewFinding(
                    reviewer="decomposer",
                    finding_type=FindingType.SEMANTIC_REVIEW_COVERAGE_GAP,
                    severity=Severity.CRITICAL,
                    message="Entailment and counterexample review strategies are both required.",
                    evidence_ids=[],
                )
            )
        semantic_assurance = SemanticAssurance(
            required_reviewers=sorted(SEMANTIC_REVIEWERS),
            completed_reviewers=completed_semantic,
            model_ids=semantic_model_ids,
            distinct_model_ids=len(semantic_model_ids),
            strategy_count=len(completed_semantic),
            status="HOLD" if semantic_hold else "PASS",
        )

    semantic_obligation_assurance = SemanticObligationAssurance(status="NOT_REQUIRED")
    obligation_hold = False
    if claim.assurance_profile in {AssuranceProfile.REPRESENTATION_FORTIFIED, AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED, AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        atom_ids = [atom.atom_id for atom in claim.atoms]
        atom_id_set = set(atom_ids)
        expected_frame_roles = {"decomposer", "entailment", "counterexample"}
        expected_obligation_owner = {
            SemanticObligationType.SOURCE_CLASSIFICATION: "entailment",
            SemanticObligationType.JOINT_ENTAILMENT: "entailment",
            SemanticObligationType.SCOPE_BOUNDARY: "counterexample",
            SemanticObligationType.COUNTEREXAMPLE_SEARCH: "counterexample",
        }
        invalid_artifacts = []
        for frame in review.semantic_frames:
            if frame.reviewer not in expected_frame_roles or frame.atom_id not in atom_id_set:
                invalid_artifacts.append(f"frame:{frame.reviewer}:{frame.atom_id}")
        for item in review.semantic_obligations:
            owner = expected_obligation_owner.get(item.obligation_type)
            if owner != item.reviewer or item.atom_id not in atom_id_set:
                invalid_artifacts.append(
                    f"obligation:{item.reviewer}:{item.atom_id}:{item.obligation_type.value}"
                )
            refs = set(item.witness_evidence_ids)
            if item.evidence_id:
                refs.add(item.evidence_id)
            if refs - universe_ids:
                invalid_artifacts.append(
                    f"evidence-ref:{item.reviewer}:{item.atom_id}:{','.join(sorted(refs - universe_ids))}"
                )
        if invalid_artifacts:
            obligation_hold = True
            reasons.append("SEMANTIC_OBLIGATION_GAP: invalid semantic artifacts: " + ", ".join(sorted(invalid_artifacts)))

        required_frame_reviewers = {"decomposer", "entailment", "counterexample"}
        frame_index: dict[tuple[str, str], list[SemanticFrame]] = defaultdict(list)
        for frame in review.semantic_frames:
            frame_index[(frame.reviewer, frame.atom_id)].append(frame)
        obligation_index: dict[tuple[str, str, str, str], list[SemanticObligationCheck]] = defaultdict(list)
        for item in review.semantic_obligations:
            key = (item.reviewer, item.atom_id, item.obligation_type.value, item.evidence_id or "")
            obligation_index[key].append(item)

        missing_obligations: list[str] = []
        failed_obligations: list[str] = []
        representation_mismatch_atoms: list[str] = []
        claim_atoms = {atom.atom_id: atom for atom in claim.atoms}

        for atom_id in atom_ids:
            frames: list[SemanticFrame] = []
            for reviewer in sorted(required_frame_reviewers):
                rows = frame_index.get((reviewer, atom_id), [])
                if len(rows) != 1:
                    missing_obligations.append(f"frame:{reviewer}:{atom_id}")
                else:
                    frames.append(rows[0])
            if len(frames) == len(required_frame_reviewers):
                quantifiers = {frame.quantifier for frame in frames}
                relations = {frame.relation for frame in frames}
                if (
                    len(quantifiers) != 1
                    or len(relations) != 1
                    or SemanticQuantifier.UNKNOWN in quantifiers
                    or SemanticRelation.UNKNOWN in relations
                ):
                    representation_mismatch_atoms.append(atom_id)

            atom = claim_atoms[atom_id]
            for evidence_id in atom.evidence_ids:
                key = ("entailment", atom_id, SemanticObligationType.SOURCE_CLASSIFICATION.value, evidence_id)
                rows = obligation_index.get(key, [])
                if len(rows) != 1:
                    missing_obligations.append(f"source:{atom_id}:{evidence_id}")
                elif rows[0].result not in {SemanticObligationResult.SUPPORTS, SemanticObligationResult.NEUTRAL}:
                    failed_obligations.append(f"source:{atom_id}:{evidence_id}:{rows[0].result.value}")

            key = ("entailment", atom_id, SemanticObligationType.JOINT_ENTAILMENT.value, "")
            rows = obligation_index.get(key, [])
            if len(rows) != 1:
                missing_obligations.append(f"joint:{atom_id}")
            elif rows[0].result != SemanticObligationResult.SATISFIED:
                failed_obligations.append(f"joint:{atom_id}:{rows[0].result.value}")

            key = ("counterexample", atom_id, SemanticObligationType.SCOPE_BOUNDARY.value, "")
            rows = obligation_index.get(key, [])
            if len(rows) != 1:
                missing_obligations.append(f"scope:{atom_id}")
            elif rows[0].result != SemanticObligationResult.WITHIN_SCOPE:
                failed_obligations.append(f"scope:{atom_id}:{rows[0].result.value}")

            key = ("counterexample", atom_id, SemanticObligationType.COUNTEREXAMPLE_SEARCH.value, "")
            rows = obligation_index.get(key, [])
            if len(rows) != 1:
                missing_obligations.append(f"counterexample:{atom_id}")
            elif rows[0].result != SemanticObligationResult.NO_COUNTEREXAMPLE_FOUND:
                failed_obligations.append(f"counterexample:{atom_id}:{rows[0].result.value}")

        if representation_mismatch_atoms:
            obligation_hold = True
            reasons.append("REPRESENTATION_DISAGREEMENT: " + ", ".join(sorted(representation_mismatch_atoms)))
            findings.append(ReviewFinding(
                reviewer="decomposer", finding_type=FindingType.REPRESENTATION_DISAGREEMENT,
                severity=Severity.CRITICAL,
                message="Independent semantic frames disagree or remain UNKNOWN.",
                evidence_ids=[],
            ))
        if missing_obligations:
            obligation_hold = True
            reasons.append("SEMANTIC_OBLIGATION_GAP: " + ", ".join(sorted(missing_obligations)))
            findings.append(ReviewFinding(
                reviewer="decomposer", finding_type=FindingType.SEMANTIC_OBLIGATION_GAP,
                severity=Severity.CRITICAL,
                message="Representation-fortified semantic work products are incomplete.",
                evidence_ids=[],
            ))
        if failed_obligations:
            obligation_hold = True
            reasons.append("SEMANTIC_OBLIGATION_FAILED: " + ", ".join(sorted(failed_obligations)))
            findings.append(ReviewFinding(
                reviewer="entailment", finding_type=FindingType.SEMANTIC_OBLIGATION_FAILED,
                severity=Severity.CRITICAL,
                message="One or more falsifiable semantic obligations failed or remained unresolved.",
                evidence_ids=[],
            ))
        semantic_obligation_assurance = SemanticObligationAssurance(
            required_frame_reviewers=sorted(required_frame_reviewers),
            atom_ids=atom_ids,
            frame_count=len(review.semantic_frames),
            obligation_count=len(review.semantic_obligations),
            representation_mismatch_atoms=sorted(representation_mismatch_atoms),
            missing_obligations=sorted(missing_obligations),
            failed_obligations=sorted(failed_obligations),
            status="HOLD" if obligation_hold else "PASS",
        )

    external_witness_assurance = ExternalWitnessAssurance(status="NOT_REQUIRED")
    witness_hold = False
    if claim.assurance_profile == AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED:
        required_atom_ids = [atom.atom_id for atom in claim.atoms]
        required_atom_set = set(required_atom_ids)
        covered_atom_ids: set[str] = set()
        counterexample_atom_ids: set[str] = set()
        unresolved_atom_ids: set[str] = set()
        nonindependent_check_ids: list[str] = []
        verifier_id = ""
        verifier_public_key = ""
        check_count = 0

        if external_witness is None:
            witness_hold = True
            reasons.append("EXTERNAL_WITNESS_GAP: no independently signed witness set supplied.")
            findings.append(ReviewFinding(
                reviewer="counterexample",
                finding_type=FindingType.EXTERNAL_WITNESS_GAP,
                severity=Severity.CRITICAL,
                message="External-witness fortified assurance requires a signed witness set for every atom.",
                evidence_ids=[],
            ))
        else:
            verifier_id = external_witness.verifier_id
            verifier_public_key = external_witness.verifier_public_key
            check_count = len(external_witness.checks)
            witness_valid = verify_external_witness_set(external_witness)
            key_matches = bool(expected_witness_public_key) and external_witness.verifier_public_key == expected_witness_public_key
            claim_matches = external_witness.claim_sha256 == current_claim_digest
            case_matches = expected_witness_case_id is None or external_witness.case_id == expected_witness_case_id
            if not witness_valid or not key_matches or not claim_matches or not case_matches:
                witness_hold = True
                detail = []
                if not witness_valid:
                    detail.append("signature")
                if not key_matches:
                    detail.append("verifier-key")
                if not claim_matches:
                    detail.append("claim-binding")
                if not case_matches:
                    detail.append("case-binding")
                reasons.append("EXTERNAL_WITNESS_INVALID: " + ",".join(detail))
                findings.append(ReviewFinding(
                    reviewer="counterexample",
                    finding_type=FindingType.EXTERNAL_WITNESS_INVALID,
                    severity=Severity.CRITICAL,
                    message="External witness set failed authentication, verifier-key commitment, or claim binding.",
                    evidence_ids=[],
                ))
            else:
                e0_origins = {canonical_origin(item.source) for item in evidence.items}
                e0_groups = {item.source_group.strip() for item in evidence.items if item.source_group.strip()}
                checks_by_atom: dict[str, list] = defaultdict(list)
                invalid_atoms: list[str] = []
                for check in external_witness.checks:
                    if check.atom_id not in required_atom_set:
                        invalid_atoms.append(check.atom_id)
                        continue
                    checks_by_atom[check.atom_id].append(check)
                    origin = canonical_origin(check.source)
                    if origin in e0_origins or check.source_group.strip() in e0_groups:
                        nonindependent_check_ids.append(check.check_id)
                    if check.result == ExternalWitnessResult.COUNTEREXAMPLE:
                        counterexample_atom_ids.add(check.atom_id)
                    elif check.result in {ExternalWitnessResult.UNRESOLVED, ExternalWitnessResult.EXECUTION_FAILED}:
                        unresolved_atom_ids.add(check.atom_id)
                    elif check.result == ExternalWitnessResult.SURVIVED_CHALLENGE:
                        covered_atom_ids.add(check.atom_id)

                missing_atoms = sorted(atom_id for atom_id in required_atom_ids if not checks_by_atom.get(atom_id))
                if invalid_atoms or missing_atoms:
                    witness_hold = True
                    reasons.append(
                        "EXTERNAL_WITNESS_GAP: "
                        + ("unknown-atoms=" + ",".join(sorted(set(invalid_atoms))) + "; " if invalid_atoms else "")
                        + ("missing-atoms=" + ",".join(missing_atoms) if missing_atoms else "")
                    )
                    findings.append(ReviewFinding(
                        reviewer="counterexample",
                        finding_type=FindingType.EXTERNAL_WITNESS_GAP,
                        severity=Severity.CRITICAL,
                        message="External witness coverage is incomplete or references unknown atoms.",
                        evidence_ids=[],
                    ))
                if nonindependent_check_ids:
                    witness_hold = True
                    reasons.append("EXTERNAL_WITNESS_NOT_INDEPENDENT: " + ", ".join(sorted(nonindependent_check_ids)))
                    findings.append(ReviewFinding(
                        reviewer="counterexample",
                        finding_type=FindingType.EXTERNAL_WITNESS_NOT_INDEPENDENT,
                        severity=Severity.CRITICAL,
                        message="External witness reused a source origin or source group already present in E0.",
                        evidence_ids=[],
                    ))
                if counterexample_atom_ids:
                    witness_hold = True
                    reasons.append("EXTERNAL_WITNESS_COUNTEREXAMPLE: " + ", ".join(sorted(counterexample_atom_ids)))
                    findings.append(ReviewFinding(
                        reviewer="counterexample",
                        finding_type=FindingType.EXTERNAL_WITNESS_COUNTEREXAMPLE,
                        severity=Severity.CRITICAL,
                        message="An independently authenticated witness produced a counterexample to one or more atoms.",
                        evidence_ids=[],
                    ))
                if unresolved_atom_ids:
                    witness_hold = True
                    reasons.append("EXTERNAL_WITNESS_UNRESOLVED: " + ", ".join(sorted(unresolved_atom_ids)))
                    findings.append(ReviewFinding(
                        reviewer="counterexample",
                        finding_type=FindingType.EXTERNAL_WITNESS_UNRESOLVED,
                        severity=Severity.WARNING,
                        message="An external falsification challenge failed to resolve cleanly.",
                        evidence_ids=[],
                    ))
                # A survived challenge counts only when at least one independent
                # check exists for every atom and no stronger witness failure exists.
                covered_atom_ids = {
                    atom_id for atom_id in covered_atom_ids
                    if any(
                        canonical_origin(check.source) not in e0_origins
                        and check.source_group.strip() not in e0_groups
                        and check.result == ExternalWitnessResult.SURVIVED_CHALLENGE
                        for check in checks_by_atom.get(atom_id, [])
                    )
                }
                uncovered_survivals = sorted(required_atom_set - covered_atom_ids - counterexample_atom_ids - unresolved_atom_ids)
                if uncovered_survivals:
                    witness_hold = True
                    reasons.append("EXTERNAL_WITNESS_GAP: no independent survived challenge for " + ", ".join(uncovered_survivals))

        external_witness_assurance = ExternalWitnessAssurance(
            required_atom_ids=required_atom_ids,
            covered_atom_ids=sorted(covered_atom_ids),
            counterexample_atom_ids=sorted(counterexample_atom_ids),
            unresolved_atom_ids=sorted(unresolved_atom_ids),
            nonindependent_check_ids=sorted(nonindependent_check_ids),
            verifier_id=verifier_id,
            verifier_public_key=verifier_public_key,
            check_count=check_count,
            status="HOLD" if witness_hold else "PASS",
        )

    witness_quorum_assurance = WitnessQuorumAssurance(status="NOT_REQUIRED")
    quorum_hold = False
    if claim.assurance_profile in {AssuranceProfile.WITNESS_QUORUM_FORTIFIED, AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        required_atom_set = {atom.atom_id for atom in claim.atoms}
        invalid_authority_ids: set[str] = set()
        selected_check_ids: list[str] = []
        covered_check_ids: set[str] = set()
        counterexample_check_ids: set[str] = set()
        unresolved_check_ids: set[str] = set()
        disagreement_check_ids: set[str] = set()
        authority_ids: list[str] = []
        authority_public_keys: list[str] = []
        selection_verified = False
        valid_authorities: list[ExternalWitnessSet] = []

        effective_quorum_policy = (
            witness_registry_policy.ancestry.provenance.quorum if witness_registry_policy is not None
            else witness_ancestry_policy.provenance.quorum if witness_ancestry_policy is not None
            else witness_provenance_policy.quorum if witness_provenance_policy is not None
            else witness_quorum_policy
        )
        if effective_quorum_policy is None or witness_selection_reveal is None:
            quorum_hold = True
            reasons.append("WITNESS_SELECTION_INVALID: quorum policy or selection reveal missing.")
            findings.append(ReviewFinding(
                reviewer="counterexample", finding_type=FindingType.WITNESS_SELECTION_INVALID, severity=Severity.CRITICAL,
                message="Witness-quorum assurance requires a preregistered policy and a valid selection reveal.", evidence_ids=[]
            ))
        else:
            selection_verified, selected_specs, selection_errors = verify_selection_reveal(
                effective_quorum_policy.selection, witness_selection_reveal, required_atom_ids=required_atom_set
            )
            if expected_witness_case_id is not None and witness_selection_reveal.case_id != expected_witness_case_id:
                selection_verified = False
                selection_errors.append("case-binding")
            selected_check_ids = sorted(spec.challenge_id for spec in selected_specs)
            if not selection_verified:
                quorum_hold = True
                reasons.append("WITNESS_SELECTION_INVALID: " + ",".join(selection_errors))
                findings.append(ReviewFinding(
                    reviewer="counterexample", finding_type=FindingType.WITNESS_SELECTION_INVALID, severity=Severity.CRITICAL,
                    message="Held-out challenge universe or deterministic selection seed failed preregistration verification.", evidence_ids=[]
                ))
            else:
                spec_by_id = {spec.challenge_id: spec for spec in selected_specs}
                committed_keys = set(effective_quorum_policy.verifier_public_keys)
                seen_keys: set[str] = set()
                seen_ids: set[str] = set()
                e0_origins = {canonical_origin(item.source) for item in evidence.items}
                e0_groups = {item.source_group.strip() for item in evidence.items if item.source_group.strip()}
                for witness in external_witness_sets or []:
                    authority_ids.append(witness.verifier_id)
                    authority_public_keys.append(witness.verifier_public_key)
                    authority_valid = (
                        verify_external_witness_set(witness)
                        and witness.verifier_public_key in committed_keys
                        and witness.verifier_public_key not in seen_keys
                        and witness.verifier_id not in seen_ids
                        and witness.claim_sha256 == current_claim_digest
                        and (expected_witness_case_id is None or witness.case_id == expected_witness_case_id)
                    )
                    check_map = {check.check_id: check for check in witness.checks}
                    if set(check_map) != set(spec_by_id):
                        authority_valid = False
                    if authority_valid:
                        for check_id, spec in spec_by_id.items():
                            check = check_map[check_id]
                            if not check_matches_spec(check, spec):
                                authority_valid = False
                                break
                            if canonical_origin(check.source) in e0_origins or check.source_group.strip() in e0_groups:
                                authority_valid = False
                                break
                    if authority_valid:
                        valid_authorities.append(witness)
                        seen_keys.add(witness.verifier_public_key)
                        seen_ids.add(witness.verifier_id)
                    else:
                        invalid_authority_ids.add(witness.verifier_id or witness.verifier_public_key)

                if invalid_authority_ids:
                    quorum_hold = True
                    reasons.append("WITNESS_CHALLENGE_SUBSTITUTION: invalid authority/check binding: " + ", ".join(sorted(invalid_authority_ids)))
                    findings.append(ReviewFinding(
                        reviewer="counterexample", finding_type=FindingType.WITNESS_CHALLENGE_SUBSTITUTION, severity=Severity.CRITICAL,
                        message="A witness authority was uncommitted, duplicated, invalid, or substituted a preregistered challenge.", evidence_ids=[]
                    ))

                if len(valid_authorities) < effective_quorum_policy.authority_quorum:
                    quorum_hold = True
                    reasons.append(
                        f"WITNESS_AUTHORITY_QUORUM_GAP: valid={len(valid_authorities)} required={effective_quorum_policy.authority_quorum}"
                    )
                    findings.append(ReviewFinding(
                        reviewer="counterexample", finding_type=FindingType.WITNESS_AUTHORITY_QUORUM_GAP, severity=Severity.CRITICAL,
                        message="Too few distinct preregistered witness authorities authenticated successfully.", evidence_ids=[]
                    ))

                for check_id in selected_check_ids:
                    results = [
                        next(check.result for check in witness.checks if check.check_id == check_id)
                        for witness in valid_authorities
                    ]
                    result_values = {result.value for result in results}
                    if len(result_values) > 1:
                        disagreement_check_ids.add(check_id)
                    if ExternalWitnessResult.COUNTEREXAMPLE in results:
                        counterexample_check_ids.add(check_id)
                    if any(result in {ExternalWitnessResult.UNRESOLVED, ExternalWitnessResult.EXECUTION_FAILED} for result in results):
                        unresolved_check_ids.add(check_id)
                    survived = sum(result == ExternalWitnessResult.SURVIVED_CHALLENGE for result in results)
                    if survived >= effective_quorum_policy.authority_quorum:
                        covered_check_ids.add(check_id)

                if disagreement_check_ids:
                    quorum_hold = True
                    reasons.append("WITNESS_AUTHORITY_DISAGREEMENT: " + ", ".join(sorted(disagreement_check_ids)))
                    findings.append(ReviewFinding(
                        reviewer="counterexample", finding_type=FindingType.WITNESS_AUTHORITY_DISAGREEMENT, severity=Severity.CRITICAL,
                        message="Independent witness authorities disagreed on one or more preregistered challenges.", evidence_ids=[]
                    ))
                if counterexample_check_ids:
                    quorum_hold = True
                    reasons.append("EXTERNAL_WITNESS_COUNTEREXAMPLE: " + ", ".join(sorted(counterexample_check_ids)))
                if unresolved_check_ids:
                    quorum_hold = True
                    reasons.append("EXTERNAL_WITNESS_UNRESOLVED: " + ", ".join(sorted(unresolved_check_ids)))
                uncovered = set(selected_check_ids) - covered_check_ids
                if uncovered:
                    quorum_hold = True
                    reasons.append("WITNESS_AUTHORITY_QUORUM_GAP: uncovered checks " + ", ".join(sorted(uncovered)))

        witness_quorum_assurance = WitnessQuorumAssurance(
            selection_verified=selection_verified,
            selected_check_ids=selected_check_ids,
            authority_ids=sorted(set(authority_ids)),
            authority_public_keys=sorted(set(authority_public_keys)),
            valid_authority_count=len(valid_authorities),
            required_authority_quorum=effective_quorum_policy.authority_quorum if effective_quorum_policy else 0,
            covered_check_ids=sorted(covered_check_ids),
            counterexample_check_ids=sorted(counterexample_check_ids),
            unresolved_check_ids=sorted(unresolved_check_ids),
            disagreement_check_ids=sorted(disagreement_check_ids),
            invalid_authority_ids=sorted(invalid_authority_ids),
            status="HOLD" if quorum_hold else "PASS",
        )

    witness_provenance_assurance = WitnessProvenanceAssurance(status="NOT_REQUIRED")
    provenance_hold = False
    if claim.assurance_profile in {AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED, AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        effective_provenance_policy = (
            witness_provenance_policy
            or (witness_ancestry_policy.provenance if witness_ancestry_policy is not None else None)
            or (witness_registry_policy.ancestry.provenance if witness_registry_policy is not None else None)
        )
        if effective_provenance_policy is None or witness_selection_reveal is None:
            provenance_hold = True
            prov_errors = ["provenance-policy-or-reveal-missing"]
            prov_details = {}
        else:
            selection_ok, selected_specs, selection_errors = verify_selection_reveal(
                effective_provenance_policy.quorum.selection,
                witness_selection_reveal,
                required_atom_ids={atom.atom_id for atom in claim.atoms},
            )
            if not selection_ok:
                provenance_hold = True
                prov_errors = ["selection:" + item for item in selection_errors]
                prov_details = {}
            else:
                provenance_ok, prov_errors, prov_details = verify_measurement_universe(
                    policy=effective_provenance_policy,
                    challenge_universe=witness_selection_reveal.challenge_universe,
                    selected=selected_specs,
                    receipts=witness_measurement_receipts or [],
                    required_atom_ids={atom.atom_id for atom in claim.atoms},
                )
                provenance_hold = not provenance_ok
        if provenance_hold:
            reasons.append("WITNESS_MEASUREMENT_PROVENANCE_INVALID: " + ",".join(prov_errors))
            ftype = FindingType.WITNESS_MEASUREMENT_PROVENANCE_INVALID
            direct_provenance_error = any(
                item.startswith(("invalid-measurement:", "measurement-receipt-coverage", "duplicate-measurement-receipt", "artifact-cross-dependency:"))
                for item in prov_errors
            )
            if not direct_provenance_error and any("dependency-diversity" in item for item in prov_errors):
                ftype = FindingType.WITNESS_DEPENDENCY_DIVERSITY_GAP
            elif not direct_provenance_error and any("authority-diversity" in item for item in prov_errors):
                ftype = FindingType.WITNESS_MEASUREMENT_AUTHORITY_GAP
            findings.append(ReviewFinding(
                reviewer="counterexample", finding_type=ftype, severity=Severity.CRITICAL,
                message="Witness challenge universe lacks authenticated independent measurement provenance.", evidence_ids=[]
            ))
        witness_provenance_assurance = WitnessProvenanceAssurance(
            measurement_receipt_count=len(witness_measurement_receipts or []),
            valid_measurement_receipt_count=int(prov_details.get("valid_measurement_receipt_count", 0)) if 'prov_details' in locals() else 0,
            universe_dependency_groups=dict(prov_details.get("universe_dependency_groups", {})) if 'prov_details' in locals() else {},
            selected_dependency_groups=dict(prov_details.get("selected_dependency_groups", {})) if 'prov_details' in locals() else {},
            universe_measurement_authorities=dict(prov_details.get("universe_measurement_authorities", {})) if 'prov_details' in locals() else {},
            selected_measurement_authorities=dict(prov_details.get("selected_measurement_authorities", {})) if 'prov_details' in locals() else {},
            errors=list(prov_errors) if 'prov_errors' in locals() else [],
            status="HOLD" if provenance_hold else "PASS",
        )

    witness_ancestry_assurance = WitnessAncestryAssurance(status="NOT_REQUIRED")
    ancestry_hold = False
    if claim.assurance_profile in {AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        ancestry_errors: list[str] = []
        ancestry_details: dict[str, object] = {}
        effective_ancestry_policy = witness_ancestry_policy or (witness_registry_policy.ancestry if witness_registry_policy is not None else None)
        if effective_ancestry_policy is None or witness_selection_reveal is None:
            ancestry_hold = True
            ancestry_errors = ["ancestry-policy-or-reveal-missing"]
        else:
            selection_ok, selected_specs, selection_errors = verify_selection_reveal(
                effective_ancestry_policy.provenance.quorum.selection,
                witness_selection_reveal,
                required_atom_ids={atom.atom_id for atom in claim.atoms},
            )
            if not selection_ok:
                ancestry_hold = True
                ancestry_errors = ["selection:" + item for item in selection_errors]
            else:
                ancestry_ok, ancestry_errors, ancestry_details = verify_dependency_ancestry(
                    policy=effective_ancestry_policy,
                    challenge_universe=witness_selection_reveal.challenge_universe,
                    selected=selected_specs,
                    measurement_receipts=witness_measurement_receipts or [],
                    ancestry_manifests=witness_ancestry_manifests or [],
                    required_atom_ids={atom.atom_id for atom in claim.atoms},
                )
                ancestry_hold = not ancestry_ok
        if ancestry_hold:
            reasons.append("WITNESS_ANCESTRY_INVALID: " + ",".join(ancestry_errors))
            ftype = (
                FindingType.WITNESS_ANCESTRY_OVERLAP
                if any("ancestry-cross-group-overlap" in item for item in ancestry_errors)
                else FindingType.WITNESS_ANCESTRY_INVALID
            )
            findings.append(ReviewFinding(
                reviewer="counterexample", finding_type=ftype, severity=Severity.CRITICAL,
                message="Witness dependency ancestry is missing, invalid, disconnected, or shares an upstream dependency across purportedly independent groups.", evidence_ids=[]
            ))
        witness_ancestry_assurance = WitnessAncestryAssurance(
            ancestry_manifest_count=len(witness_ancestry_manifests or []),
            valid_ancestry_manifest_count=int(ancestry_details.get("valid_ancestry_manifest_count", 0)),
            selected_valid_ancestry_count=int(ancestry_details.get("selected_valid_ancestry_count", 0)),
            universe_group_root_fingerprints=dict(ancestry_details.get("universe_group_root_fingerprints", {})),
            overlap_fingerprints=dict(ancestry_details.get("overlap_fingerprints", {})),
            errors=list(ancestry_errors),
            status="HOLD" if ancestry_hold else "PASS",
        )

    witness_registry_assurance = WitnessRegistryAssurance(status="NOT_REQUIRED")
    registry_hold = False
    if claim.assurance_profile in {AssuranceProfile.WITNESS_REGISTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        registry_errors: list[str] = []
        registry_details: dict[str, object] = {}
        if witness_registry_policy is None or witness_selection_reveal is None:
            registry_hold = True
            registry_errors = ["registry-policy-or-reveal-missing"]
        else:
            selection_ok, selected_specs, selection_errors = verify_selection_reveal(
                witness_registry_policy.ancestry.provenance.quorum.selection,
                witness_selection_reveal,
                required_atom_ids={atom.atom_id for atom in claim.atoms},
            )
            if not selection_ok:
                registry_hold = True
                registry_errors = ["selection:" + item for item in selection_errors]
            else:
                registry_ok, registry_errors, registry_details = verify_dependency_registry(
                    policy=witness_registry_policy,
                    challenge_universe=witness_selection_reveal.challenge_universe,
                    selected=selected_specs,
                    measurement_receipts=witness_measurement_receipts or [],
                    ancestry_manifests=witness_ancestry_manifests or [],
                    registry_attestations=witness_registry_attestations or [],
                    required_atom_ids={atom.atom_id for atom in claim.atoms},
                )
                registry_hold = not registry_ok
        if registry_hold:
            reasons.append("WITNESS_REGISTRY_INVALID: " + ",".join(registry_errors))
            ftype = (
                FindingType.WITNESS_REGISTRY_DISCLOSURE_GAP
                if any("registry-ancestry-disclosure-mismatch" in item or "registry-missing_dependency" in item for item in registry_errors)
                else FindingType.WITNESS_REGISTRY_INVALID
            )
            findings.append(ReviewFinding(
                reviewer="counterexample", finding_type=ftype, severity=Severity.CRITICAL,
                message="Independent dependency-registry cross-check is missing, invalid, unresolved, or exposes an ancestry disclosure gap.", evidence_ids=[]
            ))
        witness_registry_assurance = WitnessRegistryAssurance(
            registry_attestation_count=len(witness_registry_attestations or []),
            valid_registry_authority_counts=dict(registry_details.get("valid_registry_authority_counts", {})),
            registry_source_groups=dict(registry_details.get("registry_source_groups", {})),
            registry_disclosure_mismatches=dict(registry_details.get("registry_disclosure_mismatches", {})),
            negative_attestations=list(registry_details.get("negative_attestations", [])),
            invalid_attestations=list(registry_details.get("invalid_attestations", [])),
            errors=list(registry_errors),
            status="HOLD" if registry_hold else "PASS",
        )

    witness_registry_ancestry_assurance = WitnessRegistryAncestryAssurance(status="NOT_REQUIRED")
    registry_ancestry_hold = False
    if claim.assurance_profile in {AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED, AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED}:
        registry_ancestry_errors: list[str] = []
        registry_ancestry_details: dict[str, object] = {}
        if witness_registry_ancestry_policy is None or witness_selection_reveal is None:
            registry_ancestry_hold = True
            registry_ancestry_errors = ["registry-ancestry-policy-or-reveal-missing"]
        elif witness_registry_policy is None or witness_registry_policy != witness_registry_ancestry_policy.registry:
            registry_ancestry_hold = True
            registry_ancestry_errors = ["registry-ancestry-policy-nesting-mismatch"]
        else:
            selection_ok, selected_specs, selection_errors = verify_selection_reveal(
                witness_registry_ancestry_policy.registry.ancestry.provenance.quorum.selection,
                witness_selection_reveal,
                required_atom_ids={atom.atom_id for atom in claim.atoms},
            )
            if not selection_ok:
                registry_ancestry_hold = True
                registry_ancestry_errors = ["selection:" + item for item in selection_errors]
            else:
                registry_ancestry_ok, registry_ancestry_errors, registry_ancestry_details = verify_registry_ancestry(
                    policy=witness_registry_ancestry_policy,
                    challenge_universe=witness_selection_reveal.challenge_universe,
                    selected=selected_specs,
                    measurement_receipts=witness_measurement_receipts or [],
                    ancestry_manifests=witness_ancestry_manifests or [],
                    registry_attestations=witness_registry_attestations or [],
                    registry_ancestry_manifests=witness_registry_ancestry_manifests or [],
                    required_atom_ids={atom.atom_id for atom in claim.atoms},
                )
                registry_ancestry_hold = not registry_ancestry_ok
        if registry_ancestry_hold:
            reasons.append("WITNESS_REGISTRY_ANCESTRY_INVALID: " + ",".join(registry_ancestry_errors))
            ftype = (
                FindingType.WITNESS_REGISTRY_ANCESTRY_OVERLAP
                if any("registry-ancestry-cross-source-overlap" in item for item in registry_ancestry_errors)
                else FindingType.WITNESS_REGISTRY_ANCESTRY_INVALID
            )
            findings.append(ReviewFinding(
                reviewer="counterexample", finding_type=ftype, severity=Severity.CRITICAL,
                message="Dependency registries are missing authenticated ancestry, fail binding, or share a declared upstream registry dependency.", evidence_ids=[]
            ))
        witness_registry_ancestry_assurance = WitnessRegistryAncestryAssurance(
            registry_ancestry_manifest_count=len(witness_registry_ancestry_manifests or []),
            valid_registry_ancestry_manifest_count=int(registry_ancestry_details.get("valid_registry_ancestry_manifest_count", 0)),
            registry_ancestry_root_fingerprints=dict(registry_ancestry_details.get("registry_ancestry_root_fingerprints", {})),
            registry_ancestry_overlap_fingerprints=dict(registry_ancestry_details.get("registry_ancestry_overlap_fingerprints", {})),
            missing_registry_ancestry_bindings=list(registry_ancestry_details.get("missing_registry_ancestry_bindings", [])),
            invalid_registry_ancestry_manifests=list(registry_ancestry_details.get("invalid_registry_ancestry_manifests", [])),
            errors=list(registry_ancestry_errors),
            status="HOLD" if registry_ancestry_hold else "PASS",
        )

    witness_registry_observation_assurance = WitnessRegistryObservationAssurance(status="NOT_REQUIRED")
    registry_observation_hold = False
    if claim.assurance_profile == AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED:
        observation_errors: list[str] = []
        observation_details: dict[str, object] = {}
        if witness_registry_observation_policy is None or witness_selection_reveal is None:
            registry_observation_hold = True
            observation_errors = ["registry-observation-policy-or-reveal-missing"]
        elif witness_registry_ancestry_policy is None or witness_registry_ancestry_policy != witness_registry_observation_policy.registry_ancestry:
            registry_observation_hold = True
            observation_errors = ["registry-observation-ancestry-policy-nesting-mismatch"]
        else:
            selection_ok, selected_specs, selection_errors = verify_selection_reveal(
                witness_registry_observation_policy.registry_ancestry.registry.ancestry.provenance.quorum.selection,
                witness_selection_reveal,
                required_atom_ids={atom.atom_id for atom in claim.atoms},
            )
            if not selection_ok:
                registry_observation_hold = True
                observation_errors = ["selection:" + item for item in selection_errors]
            else:
                observation_ok, observation_errors, observation_details = verify_registry_observations(
                    policy=witness_registry_observation_policy,
                    challenge_universe=witness_selection_reveal.challenge_universe,
                    selected=selected_specs,
                    measurement_receipts=witness_measurement_receipts or [],
                    ancestry_manifests=witness_ancestry_manifests or [],
                    registry_attestations=witness_registry_attestations or [],
                    registry_ancestry_manifests=witness_registry_ancestry_manifests or [],
                    registry_observations=witness_registry_observations or [],
                    required_atom_ids={atom.atom_id for atom in claim.atoms},
                )
                registry_observation_hold = not observation_ok
        if registry_observation_hold:
            reasons.append("WITNESS_REGISTRY_OBSERVATION_INVALID: " + ",".join(observation_errors))
            ftype = (
                FindingType.WITNESS_REGISTRY_OBSERVATION_DISCLOSURE_GAP
                if any("registry-observation-disclosure-mismatch" in item or "missing_dependency" in item for item in observation_errors)
                else FindingType.WITNESS_REGISTRY_OBSERVATION_INVALID
            )
            findings.append(ReviewFinding(
                reviewer="counterexample", finding_type=ftype, severity=Severity.CRITICAL,
                message="External registry observation is missing, invalid, unresolved, or exposes an upstream dependency absent from the signed registry ancestry.", evidence_ids=[]
            ))
        witness_registry_observation_assurance = WitnessRegistryObservationAssurance(
            observation_count=len(witness_registry_observations or []),
            valid_observer_counts=dict(observation_details.get("valid_observer_counts", {})),
            observer_source_groups=dict(observation_details.get("observer_source_groups", {})),
            registry_observation_disclosure_mismatches=dict(observation_details.get("registry_observation_disclosure_mismatches", {})),
            negative_observations=list(observation_details.get("negative_observations", [])),
            invalid_observations=list(observation_details.get("invalid_observations", [])),
            errors=list(observation_errors),
            status="HOLD" if registry_observation_hold else "PASS",
        )

    types = {finding.finding_type for finding in findings}
    evidence_receipt = receipts.get("evidence")
    evidence_review_trusted = bool(
        evidence_receipt is not None
        and evidence_receipt.status == ReviewStatus.SUCCESS
        and "evidence" not in invalid_receipts
        and "evidence" not in contaminated_context
        and "evidence" not in prompt_mismatch
        and "evidence" not in output_mismatch
        and evidence_receipt.claim_sha256 == current_claim_digest
    )
    critical_valid_fabrication = any(
        finding.finding_type == FindingType.FABRICATION
        and finding.severity == Severity.CRITICAL
        and finding.reviewer == "evidence"
        and evidence_review_trusted
        for finding in model_findings
    )

    structural_hold = bool(
        atomic_hold
        or admission_hold
        or not receipt_key
        or not claim.evidence_ids
        or missing_evidence
        or missing_reviewers
        or invalid_receipts
        or failed_reviewers
        or contaminated_context
        or prompt_mismatch
        or invocation_continuity_mismatch
        or model_binding_failures
        or duplicate_model_responses
        or correlated_model_output_sha256
        or duplicate_invocations
        or duplicate_tokens
        or binding_mismatch
        or output_mismatch
        or semantic_artifact_mismatch
        or role_violations
        or bad_refs
        or added_ids
        or mutated_ids
        or material_omission_ids
        or semantic_hold
        or obligation_hold
        or witness_hold
        or quorum_hold
        or provenance_hold
        or ancestry_hold
        or registry_hold
        or registry_ancestry_hold
        or registry_observation_hold
    )

    if critical_valid_fabrication and not structural_hold:
        verdict = Verdict.REJECT
        allowed = "Do not publish or act on this claim."
    elif structural_hold or (types & _HOLD_TYPES) or FindingType.FABRICATION in types:
        verdict = Verdict.HOLD
        allowed = "Preserve the claim as unresolved; request corrective evidence or review."
    else:
        verdict = Verdict.PASS
        allowed = f"Claim may be used only within declared scope: {claim.declared_scope}"

    usefulness_global_blockers: list[str] = []
    for name, active in (
        ("EVIDENCE_ADMISSION_INTEGRITY", admission_hold),
        ("RUNTIME_KEY_UNAVAILABLE", not receipt_key),
        ("CLAIM_EVIDENCE_SET_EMPTY", not claim.evidence_ids),
        ("MISSING_EVIDENCE_OBJECT", bool(missing_evidence)),
        ("MISSING_REQUIRED_REVIEWER", bool(missing_reviewers)),
        ("INVALID_RUNTIME_RECEIPT", bool(invalid_receipts)),
        ("REVIEWER_EXECUTION_FAILURE", bool(failed_reviewers)),
        ("REVIEW_CONTEXT_CONTAMINATION", bool(contaminated_context)),
        ("REVIEW_PROMPT_MISMATCH", bool(prompt_mismatch)),
        ("INVOCATION_CONTINUITY_FAILURE", bool(invocation_continuity_mismatch)),
        ("MODEL_EXECUTION_UNBOUND", bool(model_binding_failures)),
        ("DUPLICATE_MODEL_RESPONSE", bool(duplicate_model_responses)),
        ("CORRELATED_MODEL_OUTPUT", bool(correlated_model_output_sha256)),
        ("DUPLICATE_REVIEW_INVOCATION", bool(duplicate_invocations or duplicate_tokens)),
        ("REVIEW_BINDING_MISMATCH", bool(binding_mismatch)),
        ("REVIEW_OUTPUT_TAMPER", bool(output_mismatch)),
        ("SEMANTIC_ARTIFACT_TAMPER", bool(semantic_artifact_mismatch)),
        ("REVIEWER_ROLE_VIOLATION", bool(role_violations)),
        ("BAD_EVIDENCE_REFERENCE", bool(bad_refs)),
        ("EVIDENCE_SPACE_ADDITION", bool(added_ids)),
        ("EVIDENCE_SPACE_MUTATION", bool(mutated_ids)),
        ("MATERIAL_TRANSITION_LEAKAGE", bool(material_omission_ids)),
        ("SEMANTIC_REVIEW_COVERAGE_GAP", semantic_hold),
        ("EXTERNAL_WITNESS_LAYER_HOLD", witness_hold),
        ("WITNESS_QUORUM_LAYER_HOLD", quorum_hold),
        ("WITNESS_PROVENANCE_LAYER_HOLD", provenance_hold),
        ("WITNESS_ANCESTRY_LAYER_HOLD", ancestry_hold),
        ("WITNESS_REGISTRY_LAYER_HOLD", registry_hold),
        ("WITNESS_REGISTRY_ANCESTRY_LAYER_HOLD", registry_ancestry_hold),
        ("WITNESS_REGISTRY_OBSERVATION_LAYER_HOLD", registry_observation_hold),
        ("DUPLICATE_ATOMIC_CLAIM", any(reason.startswith("DUPLICATE_ATOMIC_CLAIM:") for reason in reasons)),
    ):
        if active:
            usefulness_global_blockers.append(name)

    usefulness_assurance = assess_decision_usefulness(
        claim=claim,
        verdict=verdict,
        findings=findings,
        atom_assurance=atom_assurance,
        semantic_obligation_assurance=semantic_obligation_assurance,
        global_blockers=usefulness_global_blockers,
    )
    if verdict == Verdict.HOLD and usefulness_assurance.status == "SCOPED_SALVAGE":
        allowed = (
            "Full composite claim remains HOLD. Only these exact independently cleared atomic statements may be reused "
            f"within declared scope: {', '.join(usefulness_assurance.promotable_atom_ids)}"
        )

    calibration_assurance = assess_decision_calibration(
        verdict=verdict,
        findings=findings,
        usefulness_assurance=usefulness_assurance,
    )

    counts = Counter(finding.finding_type.value for finding in findings)
    reasons.extend(f"{name}: {count}" for name, count in sorted(counts.items()))
    if not reasons:
        reasons = [
            "All required runtime-authenticated reviewers succeeded independently; "
            "the exact claim/evidence/findings/prompts remained bound; every atomic "
            "claim met the declared evidence-source policy; and no blocking finding was recorded."
        ]

    input_sha256 = sha256_object(
        {
            "claim": claim.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json"),
            "review": review.model_dump(mode="json"),
        }
    )

    record = DecisionRecord(
        claim_id=claim.claim_id,
        verdict=verdict,
        declared_scope=claim.declared_scope,
        reasons=reasons,
        findings=findings,
        reviewer_status={
            name: receipts[name].status.value if name in receipts else "MISSING"
            for name in sorted(required_reviewers)
        },
        reviewer_execution={
            name: receipts[name].execution_mode.value if name in receipts else "MISSING"
            for name in sorted(required_reviewers)
        },
        evidence_digests={key: current_digests[key] for key in sorted(universe_ids & set(current_digests))},
        evidence_admission_status=admission_status,
        evidence_transition=transition_assurance,
        semantic_assurance=semantic_assurance,
        semantic_obligation_assurance=semantic_obligation_assurance,
        external_witness_assurance=external_witness_assurance,
        witness_quorum_assurance=witness_quorum_assurance,
        witness_provenance_assurance=witness_provenance_assurance,
        witness_ancestry_assurance=witness_ancestry_assurance,
        witness_registry_assurance=witness_registry_assurance,
        witness_registry_ancestry_assurance=witness_registry_ancestry_assurance,
        witness_registry_observation_assurance=witness_registry_observation_assurance,
        usefulness_assurance=usefulness_assurance,
        calibration_assurance=calibration_assurance,
        atom_assurance=atom_assurance,
        allowed_output=allowed,
        input_sha256=input_sha256,
        decision_sha256="",
    )
    return _seal_decision(record)
