"""Ed25519 signature operations.

Provides signature verification and public key loading utilities.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_signature(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key: The signer's public key.
        message: The original message that was signed.
        signature: The 64-byte signature to verify.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def public_key_from_bytes(key_bytes: bytes) -> Ed25519PublicKey:
    """Load Ed25519 public key from raw bytes.

    Args:
        key_bytes: 32-byte raw public key.

    Returns:
        The Ed25519PublicKey object.

    Raises:
        ValueError: If key_bytes is not valid.
    """
    return Ed25519PublicKey.from_public_bytes(key_bytes)


def verify_for_key_type(
    key_type: int, public_key_bytes: bytes, message: bytes, signature: bytes,
) -> bool:
    """Verify a signature, dispatching the algorithm on the wire ``key_type`` byte.

    V7 v7.67 Phase 2 — the handshake decodes ``(key_type, hash_type)`` from
    the presented peer_id (see ``handlers/connect.py``); this routes the
    signature check to the matching primitive so an Ed448 peer
    (``key_type == 0x02``) is verified with Ed448, not Ed25519.

    Raises :class:`UnsupportedKeyTypeError` for unallocated key_types — the
    handshake boundary has already called ``validate_supported_key_type`` so
    this is defense-in-depth, mapping to ``400 unsupported_key_type``.
    """
    from entity_core.crypto.identity import (
        KEY_TYPE_ED25519,
        KEY_TYPE_ED448,
        UnsupportedKeyTypeError,
    )

    if key_type == KEY_TYPE_ED25519:
        return verify_signature(
            public_key_from_bytes(public_key_bytes), message, signature,
        )
    if key_type == KEY_TYPE_ED448:
        from entity_core.crypto.ed448 import (
            ed448_public_key_from_bytes,
            verify_ed448_signature,
        )

        return verify_ed448_signature(
            ed448_public_key_from_bytes(public_key_bytes), message, signature,
        )
    raise UnsupportedKeyTypeError(
        f"no signature verifier for key_type {key_type:#x}"
    )
