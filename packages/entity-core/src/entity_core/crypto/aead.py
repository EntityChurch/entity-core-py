"""AEAD adapters for EXTENSION-ENCRYPTION §3.2.

Pure-crypto substrate: dispatch an ``aead_id`` byte to a concrete AEAD
construction. Lives in ``entity_core.crypto`` (not the handler package) so the
primitive is reusable and the handler logic composes it.

v1 floor is ``aead_id = 0x01`` XChaCha20-Poly1305 (24-byte nonce, safe under
random nonces). The 12-byte-nonce AEADs (AES-256-GCM, ChaCha20-Poly1305 IETF)
are ALLOWED in peer mode only — each peer-mode message uses a fresh ephemeral
key so nonce reuse is structurally avoided — and FORBIDDEN in self / group
modes for v1 (§3.2 / §5.3). Suite-vs-mode policy is enforced one layer up
(the mode flows); this module is mode-agnostic and only knows nonce lengths.

The XChaCha20-Poly1305 implementation comes from libsodium via PyNaCl — the
``cryptography`` wheel pinned for this project does not expose it. The IETF
XChaCha construction (HChaCha20 subkey + ChaCha20-Poly1305-IETF) is byte-equal
to Go's ``chacha20poly1305.NewX`` and Rust's ``XChaCha20Poly1305``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt as _xchacha_decrypt,
)
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as _xchacha_encrypt,
)

# -- Registry (§3.2) --------------------------------------------------------

AEAD_XCHACHA20_POLY1305 = 0x01  # v1 floor
AEAD_AES_256_GCM = 0x02  # peer-mode-only in v1
AEAD_CHACHA20_POLY1305_IETF = 0x03  # peer-mode-only in v1

AEAD_NAMES: dict[int, str] = {
    AEAD_XCHACHA20_POLY1305: "XChaCha20-Poly1305",
    AEAD_AES_256_GCM: "AES-256-GCM",
    AEAD_CHACHA20_POLY1305_IETF: "ChaCha20-Poly1305",
}

# Nonce length per AEAD (§5.3).
AEAD_NONCE_LEN: dict[int, int] = {
    AEAD_XCHACHA20_POLY1305: 24,
    AEAD_AES_256_GCM: 12,
    AEAD_CHACHA20_POLY1305_IETF: 12,
}

# Symmetric key length per AEAD (all v1 AEADs are 256-bit).
AEAD_KEY_LEN: dict[int, int] = {
    AEAD_XCHACHA20_POLY1305: 32,
    AEAD_AES_256_GCM: 32,
    AEAD_CHACHA20_POLY1305_IETF: 32,
}

# AEADs whose nonce is short enough that reuse under a stable key is a hazard;
# permitted only where a fresh key is guaranteed per message (peer mode).
SHORT_NONCE_AEADS = frozenset({AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305_IETF})


class UnsupportedAeadError(ValueError):
    """Raised for an ``aead_id`` this build does not implement."""


def is_supported_aead(aead_id: int) -> bool:
    return aead_id in AEAD_NAMES


def aead_key_len(aead_id: int) -> int:
    try:
        return AEAD_KEY_LEN[aead_id]
    except KeyError:
        raise UnsupportedAeadError(f"aead_id {aead_id:#04x}") from None


def aead_nonce_len(aead_id: int) -> int:
    try:
        return AEAD_NONCE_LEN[aead_id]
    except KeyError:
        raise UnsupportedAeadError(f"aead_id {aead_id:#04x}") from None


def aead_encrypt(
    aead_id: int, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> bytes:
    """AEAD-seal ``plaintext``. Returns ``ciphertext || tag``."""
    _check_nonce(aead_id, nonce)
    if aead_id == AEAD_XCHACHA20_POLY1305:
        return _xchacha_encrypt(plaintext, aad, nonce, key)
    if aead_id == AEAD_AES_256_GCM:
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    if aead_id == AEAD_CHACHA20_POLY1305_IETF:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    raise UnsupportedAeadError(f"aead_id {aead_id:#04x}")


def aead_decrypt(
    aead_id: int, key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes
) -> bytes:
    """AEAD-open ``ciphertext || tag``. Raises on tag failure.

    The caller maps the raised exception to ``400 encryption_aead_failed``.
    """
    _check_nonce(aead_id, nonce)
    if aead_id == AEAD_XCHACHA20_POLY1305:
        return _xchacha_decrypt(ciphertext, aad, nonce, key)
    if aead_id == AEAD_AES_256_GCM:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    if aead_id == AEAD_CHACHA20_POLY1305_IETF:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    raise UnsupportedAeadError(f"aead_id {aead_id:#04x}")


def _check_nonce(aead_id: int, nonce: bytes) -> None:
    expected = aead_nonce_len(aead_id)
    if len(nonce) != expected:
        raise ValueError(
            f"{AEAD_NAMES[aead_id]} needs a {expected}-byte nonce, "
            f"got {len(nonce)}"
        )
