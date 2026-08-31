from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from .evidence_admission import _issue_evidence_admission
from .schemas import EvidenceAdmissionStatus, EvidenceItem

LIVE_HTTP_CAPTURE_METHOD = "HTTP_FETCH_V1"


MAX_EVIDENCE_EXCERPT_CHARS = 240_000


class TrustedEvidenceAcquirer:
    """Trusted host operation that actually fetches and freezes HTTP evidence.

    This is intentionally separate from generic fixture admission. A live
    campaign accepts LIVE_HTTP_CAPTURE_METHOD only, so a fixture attestation
    cannot masquerade as a network acquisition.
    """

    def __init__(self, *, key: bytes, timeout_seconds: float = 15.0, max_bytes: int = 1_000_000) -> None:
        if len(key) < 32:
            raise ValueError("Evidence acquisition key must be at least 32 bytes.")
        if timeout_seconds <= 0 or max_bytes <= 0:
            raise ValueError("timeout_seconds and max_bytes must be positive.")
        self._key = key
        self._timeout = timeout_seconds
        self._max_bytes = max_bytes

    def capture_url(self, *, evidence_id: str, source: str, source_group: str) -> tuple[EvidenceItem, object]:
        request = Request(source, headers={"User-Agent": "Illusiontion/0.10 evidence-acquirer"})
        observed_at = datetime.now(timezone.utc).isoformat()
        with urlopen(request, timeout=self._timeout) as response:
            status = int(getattr(response, "status", 200))

            # Fail closed when urllib followed a redirect. Live evidence
            # provenance must remain bound to the exact allowlisted locator
            # requested by the trusted runtime.
            final_url = response.geturl()
            if final_url != source:
                raise ValueError(
                    "Evidence acquisition redirect is forbidden: "
                    f"{source} -> {final_url}"
                )

            content_type = response.headers.get("Content-Type", "")
            body = response.read(self._max_bytes + 1)
            if len(body) > self._max_bytes:
                raise ValueError("Evidence response exceeds configured max_bytes.")
            if status < 200 or status >= 300:
                raise ValueError(f"Evidence fetch returned HTTP {status}.")
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"
        text = body.decode(charset, errors="replace")
        content_sha = hashlib.sha256(body).hexdigest()
        full_text_char_count = len(text)
        excerpt_truncated = (
            full_text_char_count > MAX_EVIDENCE_EXCERPT_CHARS
        )
        evidence_excerpt = text[:MAX_EVIDENCE_EXCERPT_CHARS]

        item = EvidenceItem(
            evidence_id=evidence_id,
            source=source,
            source_group=source_group,
            excerpt=evidence_excerpt,
            retrieved_at=observed_at,
            metadata={
                "transport": "http",
                "final_url": final_url,
                "http_status": str(status),
                "content_type": content_type,
                "raw_content_sha256": content_sha,
                "raw_byte_count": str(len(body)),
                "full_text_char_count": str(full_text_char_count),
                "evidence_excerpt_char_count": str(len(evidence_excerpt)),
                "evidence_excerpt_truncated": (
                    "true" if excerpt_truncated else "false"
                ),
                "evidence_excerpt_limit": str(
                    MAX_EVIDENCE_EXCERPT_CHARS
                ),
            },
        )
        receipt = _issue_evidence_admission(
            item=item,
            status=EvidenceAdmissionStatus.CAPTURED,
            capture_method=LIVE_HTTP_CAPTURE_METHOD,
            captured_at=observed_at,
            detail=f"http_status={status};raw_sha256={content_sha};bytes={len(body)}",
            key=self._key,
            allow_live_method=True,
        )
        return item, receipt
