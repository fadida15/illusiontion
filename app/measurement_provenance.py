from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

from .acquisition import TrustedEvidenceAcquirer
from .evidence_admission import load_evidence_key
from .schemas import EvidenceBundle


def canonical_https_origin(source: str) -> str:
    parsed = urlsplit(source.strip())

    if parsed.scheme.lower() != "https":
        raise ValueError(
            "Live evidence acquisition requires HTTPS."
        )

    if not parsed.hostname:
        raise ValueError(
            "Live evidence source must contain a hostname."
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "Credentials embedded in evidence URLs are forbidden."
        )

    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port

    if port is None or port == 443:
        return f"https://{host}"

    return f"https://{host}:{port}"


def allowed_origins() -> set[str]:
    raw = os.environ.get(
        "ILLUSIONTION_EVIDENCE_ALLOWED_ORIGINS",
        "",
    )

    origins = {
        value.strip().rstrip("/")
        for value in raw.split(",")
        if value.strip()
    }

    if not origins:
        raise RuntimeError(
            "ILLUSIONTION_EVIDENCE_ALLOWED_ORIGINS is empty; "
            "live network acquisition is disabled."
        )

    return origins


def acquire_evidence_bundle(
    acquisition_plan_json: str,
) -> EvidenceBundle:
    """Trusted host-side HTTP acquisition.

    The LLM may request acquisition through the high-level tool, but it never
    receives the evidence-admission signing key and cannot mint admission
    receipts directly.

    Only explicitly allowlisted HTTPS origins may be fetched.
    """

    plan = json.loads(acquisition_plan_json)

    if not isinstance(plan, list) or not plan:
        raise ValueError(
            "acquisition_plan_json must be a non-empty JSON list."
        )

    allowed = allowed_origins()

    seen_ids: set[str] = set()
    items = []
    admissions = []

    acquirer = TrustedEvidenceAcquirer(
        key=load_evidence_key(),
    )

    for index, entry in enumerate(plan):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Acquisition entry {index} must be an object."
            )

        permitted_fields = {
            "evidence_id",
            "source",
            "source_group",
        }

        unknown = set(entry) - permitted_fields

        if unknown:
            raise ValueError(
                f"Acquisition entry {index} has unsupported fields: "
                + ", ".join(sorted(unknown))
            )

        evidence_id = str(
            entry.get("evidence_id", "")
        ).strip()

        source = str(
            entry.get("source", "")
        ).strip()

        source_group = str(
            entry.get("source_group", "")
        ).strip()

        if not evidence_id:
            raise ValueError(
                f"Acquisition entry {index} lacks evidence_id."
            )

        if evidence_id in seen_ids:
            raise ValueError(
                f"Duplicate evidence_id: {evidence_id}"
            )

        if not source:
            raise ValueError(
                f"Acquisition entry {index} lacks source."
            )

        if not source_group:
            raise ValueError(
                f"Acquisition entry {index} lacks source_group."
            )

        origin = canonical_https_origin(source)

        if origin not in allowed:
            raise ValueError(
                f"Evidence origin is not allowlisted: {origin}"
            )

        item, receipt = acquirer.capture_url(
            evidence_id=evidence_id,
            source=source,
            source_group=source_group,
        )

        seen_ids.add(evidence_id)
        items.append(item)
        admissions.append(receipt)

    return EvidenceBundle(
        items=items,
        admissions=admissions,
    )
