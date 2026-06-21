"""Ed448 keypair (V7 v7.67 §3 Phase 1 allocation).

Ed448 lands at ``key_type = 0x02`` ("ed448" entity-data string). The
canonical wire form per v7.67 §3.2 is SHA-256-form ``(0x02, 0x01)`` —
Ed448's 57-byte raw pubkey exceeds the v7.65 §10 informative 46-Base58
floor, so identity-form would yield a 59-byte raw segment that bloats
peer-ID strings beyond the substrate guideline.

Per RFC 8032: Ed448 private keys derive from a 57-byte seed; public keys
are 57 bytes; signatures are 114 bytes.

This module intentionally mirrors :mod:`entity_core.crypto.identity` for
Ed25519 but stays surface-narrow at Phase 1 — only the primitives needed
to (a) construct an Ed448 peer_id from a seed and (b) sign / verify on a
fixed corpus seed for cross-impl byte-equal interop confirmation
(IMPL-TEAM-ALIGNMENT §3.4 lock gate). End-to-end wiring through
``protocol/auth.py`` + ``capability/grant_signing.py`` is Phase 2 work
when the cross-key matrix (M2/M6) actually exercises an Ed448 peer pair
over the wire.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)

from entity_core.crypto.identity import (
    KEY_TYPE_ED448,
    peer_id_from_public_key_bytes,
)

ED448_PUBKEY_LEN = 57
ED448_SEED_LEN = 57
ED448_SIGNATURE_LEN = 114


@dataclass
class Ed448Keypair:
    """Ed448 keypair with derived peer ID (canonical SHA-256-form ``(0x02, 0x01)``)."""

    private_key: Ed448PrivateKey
    public_key: Ed448PublicKey
    peer_id: str

    # Entity-data `key_type` string (v7.67 §3.3). Mirrors
    # :attr:`entity_core.crypto.identity.Keypair.key_type` so handshake and
    # signing code is keypair-type-agnostic.
    key_type: str = "ed448"

    @classmethod
    def generate(cls) -> Ed448Keypair:
        private_key = Ed448PrivateKey.generate()
        public_key = private_key.public_key()
        peer_id = peer_id_from_public_key_bytes(
            _public_key_bytes(public_key), key_type=KEY_TYPE_ED448,
        )
        return cls(private_key, public_key, peer_id)

    @classmethod
    def from_seed(cls, seed: bytes) -> Ed448Keypair:
        """Deterministic keypair from a 57-byte Ed448 seed (RFC 8032 §5.2)."""
        if len(seed) != ED448_SEED_LEN:
            raise ValueError(
                f"Ed448 seed must be {ED448_SEED_LEN} bytes, got {len(seed)}"
            )
        private_key = Ed448PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key()
        peer_id = peer_id_from_public_key_bytes(
            _public_key_bytes(public_key), key_type=KEY_TYPE_ED448,
        )
        return cls(private_key, public_key, peer_id)

    def public_key_bytes(self) -> bytes:
        return _public_key_bytes(self.public_key)

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


def _public_key_bytes(public_key: Ed448PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed448_public_key_from_bytes(key_bytes: bytes) -> Ed448PublicKey:
    """Load an Ed448 public key from raw 57 bytes."""
    return Ed448PublicKey.from_public_bytes(key_bytes)


def verify_ed448_signature(
    public_key: Ed448PublicKey, message: bytes, signature: bytes,
) -> bool:
    """Verify an Ed448 signature. Returns ``True`` on valid, ``False`` on
    ``InvalidSignature``."""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
