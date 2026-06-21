"""Encryption-keypair adapters for EXTENSION-ENCRYPTION §3.1 + §7.3.

Pure-crypto substrate for the ``enc_key_type`` registry: the DH / KEM
primitive that peer + group modes use to establish a per-message shared
secret. Distinct from the signing keys in ``crypto.identity`` (§2: don't
reuse the identity key for encryption).

v1 floor is ``enc_key_type = 0x01`` X25519 (Curve25519 ECDH, RFC 7748,
32-byte keys). X448 (0x02) is wired because ``cryptography`` provides it and
it pairs with v7.67's Ed448 / SHA-384 validate slot; it is reserved, not
floor. ML-KEM (0x03–0x06) and the X25519+ML-KEM hybrid (0x04) are byte-
allocated only — no KEM in this build's ``cryptography`` wheel (§19.3).

A "seed" here is the raw private-key byte string (what the KATs pin): X25519
private keys ARE 32 raw bytes, consumed directly by ``from_private_bytes`` —
identical to Go's ``ecdh.X25519().NewPrivateKey(seed)``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x448 import (
    X448PrivateKey,
    X448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# -- enc_key_type registry (§3.1) -------------------------------------------

ENC_KEY_RESERVED = 0x00  # self mode carries this (no keypair)
ENC_KEY_X25519 = 0x01  # v1 floor
ENC_KEY_X448 = 0x02  # reserved (next validate slot)
ENC_KEY_MLKEM768 = 0x03  # reserved (PQ KEM) — not implemented
ENC_KEY_X25519_MLKEM768 = 0x04  # reserved (hybrid) — not implemented

ENC_KEY_NAMES: dict[int, str] = {
    ENC_KEY_RESERVED: "reserved",
    ENC_KEY_X25519: "X25519",
    ENC_KEY_X448: "X448",
    ENC_KEY_MLKEM768: "ML-KEM-768",
    ENC_KEY_X25519_MLKEM768: "X25519+ML-KEM-768",
}

# Public-key byte length per type (DH types only; KEM ciphertext sizes differ).
ENC_KEY_PUBLIC_LEN: dict[int, int] = {
    ENC_KEY_X25519: 32,
    ENC_KEY_X448: 56,
}

# enc_key_types this build can actually perform ECDH/KEM with.
_DH_TYPES = frozenset({ENC_KEY_X25519, ENC_KEY_X448})


class UnsupportedEncKeyTypeError(ValueError):
    """Raised for an ``enc_key_type`` this build does not implement."""


def is_supported_enc_key_type(enc_key_type: int) -> bool:
    return enc_key_type in _DH_TYPES


def public_key_len(enc_key_type: int) -> int:
    try:
        return ENC_KEY_PUBLIC_LEN[enc_key_type]
    except KeyError:
        raise UnsupportedEncKeyTypeError(f"enc_key_type {enc_key_type:#04x}") from None


def derive_public_key(enc_key_type: int, private_seed: bytes) -> bytes:
    """Return the raw public key for a raw private seed (KAT helper)."""
    priv = _load_private(enc_key_type, private_seed)
    return priv.public_key().public_bytes_raw()


def generate_keypair(enc_key_type: int) -> tuple[bytes, bytes]:
    """Generate an ephemeral keypair. Returns ``(private_bytes, public_bytes)``."""
    if enc_key_type == ENC_KEY_X25519:
        priv = X25519PrivateKey.generate()
    elif enc_key_type == ENC_KEY_X448:
        priv = X448PrivateKey.generate()
    else:
        raise UnsupportedEncKeyTypeError(f"enc_key_type {enc_key_type:#04x}")
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def ecdh(enc_key_type: int, private_seed: bytes, peer_public: bytes) -> bytes:
    """Raw ECDH shared secret between a private seed and a peer public key."""
    priv = _load_private(enc_key_type, private_seed)
    pub = _load_public(enc_key_type, peer_public)
    return priv.exchange(pub)


def _load_private(enc_key_type: int, seed: bytes):
    if enc_key_type == ENC_KEY_X25519:
        return X25519PrivateKey.from_private_bytes(seed)
    if enc_key_type == ENC_KEY_X448:
        return X448PrivateKey.from_private_bytes(seed)
    raise UnsupportedEncKeyTypeError(f"enc_key_type {enc_key_type:#04x}")


def _load_public(enc_key_type: int, raw: bytes):
    if enc_key_type == ENC_KEY_X25519:
        return X25519PublicKey.from_public_bytes(raw)
    if enc_key_type == ENC_KEY_X448:
        return X448PublicKey.from_public_bytes(raw)
    raise UnsupportedEncKeyTypeError(f"enc_key_type {enc_key_type:#04x}")
