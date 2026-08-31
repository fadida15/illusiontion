from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel

from .schemas import EvidenceBundle, EvidenceItem, ReviewFinding, SemanticFrame, SemanticObligationCheck


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_object(value: Any) -> str:
    return sha256_text(canonical_json(value))


def evidence_digest(item: EvidenceItem) -> str:
    payload = {
        "source": item.source,
        "source_group": item.source_group,
        "excerpt": item.excerpt,
        "retrieved_at": item.retrieved_at,
        "metadata": item.metadata,
    }
    return sha256_object(payload)


def evidence_digest_map(bundle: EvidenceBundle) -> dict[str, str]:
    return {item.evidence_id: evidence_digest(item) for item in bundle.items}


def findings_digest(findings: list[ReviewFinding]) -> str:
    """Order-independent digest of a reviewer's normalized findings."""
    rows = [finding.model_dump(mode="json") for finding in findings]
    rows.sort(key=lambda row: canonical_json(row))
    return sha256_object(rows)


def semantic_artifacts_digest(
    frames: list[SemanticFrame],
    obligations: list[SemanticObligationCheck],
) -> str:
    """Order-independent digest of structured semantic work products."""
    rows = [
        {"kind": "frame", **item.model_dump(mode="json")} for item in frames
    ] + [
        {"kind": "obligation", **item.model_dump(mode="json")} for item in obligations
    ]
    rows.sort(key=lambda row: canonical_json(row))
    return sha256_object(rows)
