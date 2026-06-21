"""EXTENSION-ENCRYPTION §3 — cipher-suite advertisement + selection policy.

Thin layer over the pure-crypto registries in ``entity_core.crypto`` (aead /
kdf / ecdh): re-exports the byte constants and adds the cross-cutting policy a
single primitive module shouldn't own — suite intersection (§3.4) and the
mode-vs-AEAD restriction (§5.3, short-nonce AEADs forbidden outside peer mode).
"""

from __future__ import annotations

from entity_core.crypto.aead import (
    AEAD_CHACHA20_POLY1305_IETF,
    AEAD_NAMES,
    AEAD_XCHACHA20_POLY1305,
    SHORT_NONCE_AEADS,
    is_supported_aead,
)
from entity_core.crypto.ecdh import ENC_KEY_X25519, is_supported_enc_key_type
from entity_core.crypto.kdf import KDF_HKDF_SHA256, KDF_NAMES, is_supported_kdf

# v1 cipher-suite floor (§1): every conformant peer MUST support this for every
# mode it implements.
FLOOR_ENC_KEY_TYPE = ENC_KEY_X25519
FLOOR_AEAD_ID = AEAD_XCHACHA20_POLY1305
FLOOR_KDF_ID = KDF_HKDF_SHA256

# What this build advertises on every encryption-pubkey it publishes. XChaCha is
# first (the floor + the only AEAD valid in all modes); the 12-byte-nonce IETF
# ChaCha is offered for peer-mode senders that prefer it.
DEFAULT_SUPPORTED_AEAD_IDS = [AEAD_XCHACHA20_POLY1305, AEAD_CHACHA20_POLY1305_IETF]
DEFAULT_SUPPORTED_KDF_IDS = [KDF_HKDF_SHA256]


def suite_name(enc_key_type: int, aead_id: int, kdf_id: int) -> str:
    return (
        f"enc_key={enc_key_type:#04x}/"
        f"aead={AEAD_NAMES.get(aead_id, hex(aead_id))}/"
        f"kdf={KDF_NAMES.get(kdf_id, hex(kdf_id))}"
    )


def select_suite(
    *,
    recipient_aead_ids: list[int],
    recipient_kdf_ids: list[int],
    sender_aead_ids: list[int] | None = None,
    sender_kdf_ids: list[int] | None = None,
) -> tuple[int, int] | None:
    """Pick ``(aead_id, kdf_id)`` per §3.4: first recipient-advertised entry the
    sender also supports. Returns ``None`` if either intersection is empty.
    """
    sender_aead = sender_aead_ids if sender_aead_ids is not None else DEFAULT_SUPPORTED_AEAD_IDS
    sender_kdf = sender_kdf_ids if sender_kdf_ids is not None else DEFAULT_SUPPORTED_KDF_IDS

    aead = next((a for a in recipient_aead_ids if a in sender_aead and is_supported_aead(a)), None)
    kdf = next((k for k in recipient_kdf_ids if k in sender_kdf and is_supported_kdf(k)), None)
    if aead is None or kdf is None:
        return None
    return aead, kdf


def aead_allowed_in_mode(aead_id: int, mode: str) -> bool:
    """§5.3: short-nonce AEADs are peer-mode-only (fresh key per message). In
    self / group modes a stable key + short random nonce risks reuse.
    """
    if aead_id in SHORT_NONCE_AEADS and mode != "peer":
        return False
    return True


def is_floor_suite(enc_key_type: int, aead_id: int, kdf_id: int) -> bool:
    return (
        enc_key_type == FLOOR_ENC_KEY_TYPE
        and aead_id == FLOOR_AEAD_ID
        and kdf_id == FLOOR_KDF_ID
    )


__all__ = [
    "FLOOR_ENC_KEY_TYPE",
    "FLOOR_AEAD_ID",
    "FLOOR_KDF_ID",
    "DEFAULT_SUPPORTED_AEAD_IDS",
    "DEFAULT_SUPPORTED_KDF_IDS",
    "suite_name",
    "select_suite",
    "aead_allowed_in_mode",
    "is_floor_suite",
    "is_supported_enc_key_type",
]
