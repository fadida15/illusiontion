from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from urllib.parse import urlsplit

from .integrity import evidence_digest, sha256_object
from .schemas import EvidenceAdmissionReceipt, EvidenceAdmissionStatus, EvidenceItem

_MIN_KEY_BYTES = 32


def load_evidence_key() -> bytes:
    raw = os.environ.get("ILLUSIONTION_EVIDENCE_KEY", "")
    key = raw.encode("utf-8")
    if len(key) < _MIN_KEY_BYTES:
        raise RuntimeError(
            "ILLUSIONTION_EVIDENCE_KEY must be at least 32 bytes; "
            "evidence admission verification is unavailable."
        )
    return key


def canonical_origin(source: str) -> str:
    """Return a deterministic coarse origin label for a source locator.

    This is a structural anti-duplication signal, not proof that two origins are
    legally or operationally independent.
    """
    source = source.strip()
    parsed = urlsplit(source)
    if parsed.scheme and parsed.netloc:
        host = (parsed.hostname or parsed.netloc).lower().rstrip(".")
        port = parsed.port
        default_port = (parsed.scheme.lower() == "https" and port == 443) or (
            parsed.scheme.lower() == "http" and port == 80
        )
        authority = host if port is None or default_port else f"{host}:{port}"
        return f"{parsed.scheme.lower()}://{authority}"
    # Non-URL fixture/local locators remain explicit and deterministic.
    return source.casefold()


def _payload(
    *,
    evidence_id: str,
    evidence_sha256: str,
    source_origin: str,
    status: EvidenceAdmissionStatus,
    capture_method: str,
    capture_id: str,
    captured_at: str | None,
    detail: str,
) -> dict:
    return {
        "evidence_id": evidence_id,
        "evidence_sha256": evidence_sha256,
        "source_origin": source_origin,
        "status": status.value,
        "capture_method": capture_method,
        "capture_id": capture_id,
        "captured_at": captured_at,
        "detail": detail,
    }


def _sign(payload: dict, key: bytes) -> str:
    message = sha256_object(payload).encode("ascii")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _issue_evidence_admission(
    *,
    item: EvidenceItem,
    status: EvidenceAdmissionStatus,
    capture_method: str,
    capture_id: str | None = None,
    captured_at: str | None = None,
    detail: str = "",
    key: bytes,
    allow_live_method: bool = False,
) -> EvidenceAdmissionReceipt:
    """Trusted-runtime operation; never expose signing as an LLM tool.

    CAPTURED means the trusted acquisition runtime states that this exact
    evidence snapshot was acquired through the declared method. It is not a
    truth certificate for the source's content.
    """
    if len(key) < _MIN_KEY_BYTES:
        raise ValueError("Evidence admission key must be at least 32 bytes.")
    if not capture_method.strip():
        raise ValueError("capture_method must be non-empty.")
    if capture_method == "HTTP_FETCH_V1" and not allow_live_method:
        raise ValueError("HTTP_FETCH_V1 receipts may only be issued by TrustedEvidenceAcquirer.")
    cid = capture_id or f"capture-{secrets.token_hex(16)}"
    digest = evidence_digest(item)
    origin = canonical_origin(item.source)
    payload = _payload(
        evidence_id=item.evidence_id,
        evidence_sha256=digest,
        source_origin=origin,
        status=status,
        capture_method=capture_method,
        capture_id=cid,
        captured_at=captured_at,
        detail=detail,
    )
    return EvidenceAdmissionReceipt(
        evidence_id=item.evidence_id,
        evidence_sha256=digest,
        source_origin=origin,
        status=status,
        capture_method=capture_method,
        capture_id=cid,
        captured_at=captured_at,
        detail=detail,
        runtime_signature=_sign(payload, key),
    )


def verify_evidence_admission(receipt: EvidenceAdmissionReceipt, key: bytes) -> bool:
    if len(key) < _MIN_KEY_BYTES:
        return False
    payload = _payload(
        evidence_id=receipt.evidence_id,
        evidence_sha256=receipt.evidence_sha256,
        source_origin=receipt.source_origin,
        status=receipt.status,
        capture_method=receipt.capture_method,
        capture_id=receipt.capture_id,
        captured_at=receipt.captured_at,
        detail=receipt.detail,
    )
    return hmac.compare_digest(_sign(payload, key), receipt.runtime_signature)


def issue_evidence_admission(
    *,
    item: EvidenceItem,
    status: EvidenceAdmissionStatus,
    capture_method: str,
    capture_id: str | None = None,
    captured_at: str | None = None,
    detail: str = "",
    key: bytes,
) -> EvidenceAdmissionReceipt:
    """Offline/fixture admission helper. Reserved live HTTP method is blocked.

    This remains for deterministic historical fixtures. Live campaign prepare
    requires receipts produced by TrustedEvidenceAcquirer with HTTP_FETCH_V1.
    """
    return _issue_evidence_admission(
        item=item, status=status, capture_method=capture_method, capture_id=capture_id,
        captured_at=captured_at, detail=detail, key=key, allow_live_method=False
    )


def verify_live_acquired_bundle(bundle, key: bytes) -> list[str]:
    """Return errors when a live campaign evidence universe lacks real fetch attestations."""
    errors: list[str] = []
    admissions = bundle.admissions_by_evidence_id()
    by_id = bundle.by_id()
    for evidence_id, item in by_id.items():
        receipt = admissions.get(evidence_id)
        if receipt is None:
            errors.append(f"{evidence_id}:missing admission")
            continue
        if receipt.capture_method != "HTTP_FETCH_V1":
            errors.append(f"{evidence_id}:not live-acquired")
        if receipt.status != EvidenceAdmissionStatus.CAPTURED:
            errors.append(f"{evidence_id}:capture failed")
        if not verify_evidence_admission(receipt, key):
            errors.append(f"{evidence_id}:invalid admission signature")
        if receipt.evidence_sha256 != evidence_digest(item):
            errors.append(f"{evidence_id}:snapshot digest mismatch")
        if receipt.source_origin != canonical_origin(item.source):
            errors.append(f"{evidence_id}:origin mismatch")
        if item.metadata.get("transport") != "http" or not item.metadata.get("raw_content_sha256"):
            errors.append(f"{evidence_id}:missing transport metadata")
    if set(admissions) - set(by_id):
        errors.append("admission references unknown evidence")
    return errors
