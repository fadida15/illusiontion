from __future__ import annotations

from collections import defaultdict

from .schemas import (
    AssuranceProfile,
    AtomAssurance,
    ClaimCandidate,
    DecisionUsefulnessAssurance,
    FindingType,
    ReviewFinding,
    SemanticObligationAssurance,
    Verdict,
)

# Scoped salvage requires per-atom semantic work products. Earlier profiles do
# not carry enough atom-specific reasoning to safely separate a composite HOLD.
_SALVAGE_PROFILES = {
    AssuranceProfile.REPRESENTATION_FORTIFIED,
    AssuranceProfile.EXTERNAL_WITNESS_FORTIFIED,
    AssuranceProfile.WITNESS_QUORUM_FORTIFIED,
    AssuranceProfile.WITNESS_PROVENANCE_FORTIFIED,
    AssuranceProfile.WITNESS_ANCESTRY_FORTIFIED,
    AssuranceProfile.WITNESS_REGISTRY_FORTIFIED,
    AssuranceProfile.WITNESS_REGISTRY_ANCESTRY_FORTIFIED,
    AssuranceProfile.WITNESS_REGISTRY_OBSERVATION_FORTIFIED,
}

# These content findings may be localized to atoms *only* when they cite
# evidence used by those atoms. Integrity/process failures are never localized.
_LOCALIZABLE_FINDINGS = {
    FindingType.FABRICATION,
    FindingType.CONTRADICTION,
    FindingType.INSUFFICIENT_EVIDENCE,
    FindingType.SCOPE_INFLATION,
    FindingType.STALE_EVIDENCE,
    FindingType.ATOMIC_COVERAGE_GAP,
    FindingType.SOURCE_DIVERSITY_GAP,
    FindingType.SOURCE_PROVENANCE_MISSING,
    FindingType.EVIDENCE_ORIGIN_DIVERSITY_GAP,
    FindingType.ENTAILMENT_GAP,
    FindingType.COUNTEREXAMPLE_FOUND,
}

# Gate-generated summary findings whose atom localization comes from the
# structured semantic assurance object instead of their (empty) evidence refs.
_SEMANTIC_SUMMARIES = {
    FindingType.REPRESENTATION_DISAGREEMENT,
    FindingType.SEMANTIC_OBLIGATION_GAP,
    FindingType.SEMANTIC_OBLIGATION_FAILED,
}


def _semantic_atom_from_token(token: str, atom_ids: set[str]) -> str | None:
    # Current obligation tokens are shapes such as joint:a2,
    # source:a2:e3, scope:a2, counterexample:a2:RESULT.
    parts = token.split(":")
    for part in parts[1:]:
        if part in atom_ids:
            return part
    return None


def assess_decision_usefulness(
    *,
    claim: ClaimCandidate,
    verdict: Verdict,
    findings: list[ReviewFinding],
    atom_assurance: list[AtomAssurance],
    semantic_obligation_assurance: SemanticObligationAssurance | None,
    global_blockers: list[str],
) -> DecisionUsefulnessAssurance:
    atom_ids = [atom.atom_id for atom in claim.atoms]
    atom_id_set = set(atom_ids)
    statements = {atom.atom_id: atom.statement for atom in claim.atoms}
    total = len(atom_ids)

    if verdict == Verdict.PASS:
        return DecisionUsefulnessAssurance(
            status="FULL_PASS",
            promotable_atom_ids=atom_ids,
            promotable_statements={atom_id: statements[atom_id] for atom_id in atom_ids},
            held_atom_ids=[],
            atom_blockers={},
            global_blockers=[],
            recovery_requirements=[],
            preserved_atom_count=total,
            total_atom_count=total,
            preservation_rate=1.0 if total else 0.0,
        )

    if verdict == Verdict.REJECT:
        return DecisionUsefulnessAssurance(
            status="REJECTED",
            promotable_atom_ids=[],
            promotable_statements={},
            held_atom_ids=atom_ids,
            atom_blockers={atom_id: ["FULL_CLAIM_REJECTED"] for atom_id in atom_ids},
            global_blockers=["FULL_CLAIM_REJECTED"],
            recovery_requirements=["Do not salvage from a rejected claim; correct the underlying fabrication and rerun."],
            preserved_atom_count=0,
            total_atom_count=total,
            preservation_rate=0.0,
        )

    blockers = list(dict.fromkeys(global_blockers))
    atom_blockers: dict[str, list[str]] = defaultdict(list)

    # Atom-level deterministic evidence assurance.
    for report in atom_assurance:
        if report.status == "HOLD" and report.atom_id in atom_id_set:
            atom_blockers[report.atom_id].append("ATOM_ASSURANCE_HOLD")

    # Atom-level representation / obligation failures.
    if semantic_obligation_assurance is not None:
        for atom_id in semantic_obligation_assurance.representation_mismatch_atoms:
            if atom_id in atom_id_set:
                atom_blockers[atom_id].append("REPRESENTATION_DISAGREEMENT")
        for token in semantic_obligation_assurance.missing_obligations:
            atom_id = _semantic_atom_from_token(token, atom_id_set)
            if atom_id:
                atom_blockers[atom_id].append("SEMANTIC_OBLIGATION_MISSING")
            else:
                blockers.append("UNLOCALIZED_SEMANTIC_OBLIGATION_GAP")
        for token in semantic_obligation_assurance.failed_obligations:
            atom_id = _semantic_atom_from_token(token, atom_id_set)
            if atom_id:
                atom_blockers[atom_id].append("SEMANTIC_OBLIGATION_FAILED")
            else:
                blockers.append("UNLOCALIZED_SEMANTIC_OBLIGATION_FAILURE")

    evidence_to_atoms: dict[str, set[str]] = defaultdict(set)
    for atom in claim.atoms:
        for evidence_id in atom.evidence_ids:
            evidence_to_atoms[evidence_id].add(atom.atom_id)

    # Localize only content findings whose evidence references identify the
    # affected atoms. Everything else remains a global HOLD blocker.
    for finding in findings:
        if finding.finding_type in _SEMANTIC_SUMMARIES:
            continue
        if finding.finding_type not in _LOCALIZABLE_FINDINGS:
            blockers.append(f"GLOBAL_{finding.finding_type.value}")
            continue
        if not finding.evidence_ids:
            blockers.append(f"UNLOCALIZED_{finding.finding_type.value}")
            continue
        touched: set[str] = set()
        unknown_ref = False
        for evidence_id in finding.evidence_ids:
            owners = evidence_to_atoms.get(evidence_id)
            if not owners:
                unknown_ref = True
                break
            touched.update(owners)
        if unknown_ref or not touched:
            blockers.append(f"UNLOCALIZED_{finding.finding_type.value}")
            continue
        for atom_id in touched:
            atom_blockers[atom_id].append(finding.finding_type.value)

    # Deduplicate while preserving readable ordering.
    blockers = list(dict.fromkeys(blockers))
    atom_blockers = {
        atom_id: list(dict.fromkeys(values))
        for atom_id, values in sorted(atom_blockers.items())
        if values
    }

    salvage_supported = claim.assurance_profile in _SALVAGE_PROFILES and total >= 2
    if blockers or not salvage_supported:
        if not salvage_supported:
            blockers.append("PROFILE_NOT_ATOM_SALVAGE_ELIGIBLE")
        recovery = [f"Resolve global blocker: {item}" for item in dict.fromkeys(blockers)]
        return DecisionUsefulnessAssurance(
            status="HARD_HOLD",
            promotable_atom_ids=[],
            promotable_statements={},
            held_atom_ids=atom_ids,
            atom_blockers=atom_blockers,
            global_blockers=list(dict.fromkeys(blockers)),
            recovery_requirements=recovery,
            preserved_atom_count=0,
            total_atom_count=total,
            preservation_rate=0.0,
        )

    held = [atom_id for atom_id in atom_ids if atom_blockers.get(atom_id)]
    promotable = [atom_id for atom_id in atom_ids if atom_id not in set(held)]
    if not promotable or not held:
        # A HOLD with no safely localized split is not salvageable.
        blockers.append("NO_SAFE_LOCALIZED_SPLIT")
        return DecisionUsefulnessAssurance(
            status="HARD_HOLD",
            promotable_atom_ids=[],
            promotable_statements={},
            held_atom_ids=atom_ids,
            atom_blockers=atom_blockers,
            global_blockers=list(dict.fromkeys(blockers)),
            recovery_requirements=["Resolve the unresolved claim as a whole before promotion."],
            preserved_atom_count=0,
            total_atom_count=total,
            preservation_rate=0.0,
        )

    recovery = [
        f"Repair atom {atom_id}: " + ", ".join(atom_blockers[atom_id])
        for atom_id in held
    ]
    return DecisionUsefulnessAssurance(
        status="SCOPED_SALVAGE",
        promotable_atom_ids=promotable,
        promotable_statements={atom_id: statements[atom_id] for atom_id in promotable},
        held_atom_ids=held,
        atom_blockers=atom_blockers,
        global_blockers=[],
        recovery_requirements=recovery,
        preserved_atom_count=len(promotable),
        total_atom_count=total,
        preservation_rate=(len(promotable) / total) if total else 0.0,
    )
