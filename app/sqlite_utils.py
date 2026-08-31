from __future__ import annotations

import re
import unicodedata

from .schemas import EvidenceBundle, FindingType, ReviewFinding, Severity

# Conservative deterministic pre-filter. Semantic security review remains a
# separate role, but known instruction-like payloads cannot depend on the LLM
# noticing them.
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all|any|the|your)\s+(previous|prior|earlier)", re.IGNORECASE),
    re.compile(r"(ignore|disregard|forget|discard)\s+.{0,80}(instruction|rule|policy|prompt|constraint)", re.IGNORECASE),
    re.compile(r"system\s+prompt", re.IGNORECASE),
    re.compile(r"(reveal|print|show|expose)\s+.{0,60}(system|developer)\s+(prompt|message|instruction)", re.IGNORECASE),
    re.compile(r"(mark|treat|consider|declare)\s+.{0,50}(verified|trusted|safe|approved)", re.IGNORECASE),
    re.compile(r"(bypass|skip|disable|evade)\s+.{0,60}(check|verification|review|guard|policy|filter)", re.IGNORECASE),
    re.compile(r"(override|replace|supersede)\s+.{0,60}(policy|instruction|rule|review|decision)", re.IGNORECASE),
    re.compile(r"do\s+not\s+(report|flag|mention|surface)\s+.{0,60}(error|issue|conflict|contradiction|risk)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+.{0,80}(system|reviewer|administrator|authority)", re.IGNORECASE),
    re.compile(r"(approve|accept|pass)\s+.{0,50}(claim|result|answer|evidence)", re.IGNORECASE),
    re.compile(
        r"(?:^|[.!?;:]\s+)"
        r"(?:(?:please|now|then)\s+)?"
        r"(?:you\s+(?:must|should|need\s+to)\s+)?"
        r"(?:"
        r"(?:call|invoke)\s+"
        r"(?:(?:the|this|that|a|an)\s+)?"
        r"(?:following\s+)?"
        r"(?:tool|function)"
        r"|"
        r"(?:run|execute)\s+"
        r"(?:(?:the|this|that|a|an)\s+)?"
        r"(?:following\s+)?"
        r"(?:tool|function|command|shell(?:\s+command)?)"
        r")\b",
        re.IGNORECASE,
    ),
]


def _normalize_untrusted_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[\t\r\n]+", " ", text)
    # Remove common zero-width characters used to split keywords.
    return text.translate({ord(ch): None for ch in "\u200b\u200c\u200d\ufeff"})


def scan_for_prompt_injection(text: str, evidence_id: str) -> list[ReviewFinding]:
    normalized = _normalize_untrusted_text(text)
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(normalized):
            return [
                ReviewFinding(
                    reviewer="security",
                    finding_type=FindingType.PROMPT_INJECTION,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Evidence {evidence_id} contains instruction-like content "
                        "and was quarantined from model authority."
                    ),
                    evidence_ids=[evidence_id],
                )
            ]
    return []


def scan_bundle(bundle: EvidenceBundle) -> list[ReviewFinding]:
    findings: list[ReviewFinding] = []
    for item in bundle.items:
        findings.extend(scan_for_prompt_injection(item.excerpt, item.evidence_id))
    return findings
