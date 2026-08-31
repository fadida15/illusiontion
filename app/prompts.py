from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .integrity import sha256_object

_POLICY = {
    "domain": "ILLUSIONTION_PRIVACY_MINIMIZATION_V0_45",
    "candidate_output": "HASH_ONLY_AFTER_TRUSTED_PARSE",
    "reviewer_output": "HASH_ONLY_AFTER_TRUSTED_PARSE",
    "provider_replay_material": "AES256_GCM_EPHEMERAL_UNTIL_AUTHORITATIVE_PUBLICATION",
    "provider_replay_purge": "PURGE_AFTER_RERUN_PUBLICATION",
    "authority_scope": "PRIVACY_ONLY_NEVER_UPGRADES_VERDICT",
}


def privacy_minimization_policy_sha256() -> str:
    return sha256_object(_POLICY)


def _vault_key(runtime_key: bytes, provider_call_id: str) -> bytes:
    if len(runtime_key) < 32:
        raise ValueError("Privacy replay-vault runtime key must be at least 32 bytes.")
    return hmac.new(
        runtime_key,
        ("ILLUSIONTION_V0_45_REPLAY_VAULT|" + provider_call_id).encode("utf-8"),
        hashlib.sha256,
    ).digest()


def encrypt_replay_text(*, runtime_key: bytes, provider_call_id: str, label: str, plaintext: str) -> str:
    nonce = os.urandom(12)
    aad = ("ILLUSIONTION_V0_45|" + provider_call_id + "|" + label).encode("utf-8")
    ciphertext = AESGCM(_vault_key(runtime_key, provider_call_id)).encrypt(
        nonce, plaintext.encode("utf-8"), aad
    )
    return (nonce + ciphertext).hex()


def decrypt_replay_text(*, runtime_key: bytes, provider_call_id: str, label: str, ciphertext_hex: str) -> str:
    raw = bytes.fromhex(ciphertext_hex)
    if len(raw) < 13:
        raise ValueError("Privacy replay-vault ciphertext is truncated.")
    nonce, ciphertext = raw[:12], raw[12:]
    aad = ("ILLUSIONTION_V0_45|" + provider_call_id + "|" + label).encode("utf-8")
    plaintext = AESGCM(_vault_key(runtime_key, provider_call_id)).decrypt(nonce, ciphertext, aad)
    return plaintext.decode("utf-8")


def hash_only_trace(trace: Any):
    """Return a ReviewTrace-like object with raw model text removed.

    The signed receipt already commits the raw output SHA-256. v0.45 retains the
    parsed structured review plus that digest, not the raw provider text.
    """
    return trace.model_copy(update={"raw_output": ""})
