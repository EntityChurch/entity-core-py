"""EXTENSION-ENCRYPTION R6 — key-separation MUST (arch v2.5).

§2 / §9.4: the encryption key MUST be separate from the identity (signing) key
— separate keys limit compromise blast radius and avoid retroactive readability
of past ciphertext on signing-key compromise. R6 makes this a normative gate
(``ENC-KEY-SEPARATION-1``) enforced against *real* key generation, not the
pinned-seed KATs: an encryption-pubkey is rejected when it equals either

  1. the raw Ed25519 identity pubkey bytes, OR
  2. ``birational(identity_pubkey)`` — the well-known Ed25519→X25519 image
     (``u = (1+y)/(1-y) mod 2^255-19``), i.e. the libsodium / age
     ``crypto_sign_ed25519_pk_to_curve25519`` transform.

Every published / accepted encryption-pubkey whose owner has a known identity
key MUST pass ``validate_key_separation``. We use PyNaCl's binding directly as
the birational reference rather than re-deriving the field arithmetic.
"""

from __future__ import annotations

from hmac import compare_digest

from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519

from .errors import KEY_DERIVED_FROM_IDENTITY, EncryptionError


def birational_ed_to_x25519(identity_ed25519_pk: bytes) -> bytes:
    """Map a 32-byte Ed25519 pubkey to its Curve25519 (Montgomery-u) image.

    The libsodium ``crypto_sign_ed25519_pk_to_curve25519`` transform — the
    same birational map age and other tools use. Raises if the point is not
    convertible (the vanishing ``1 - y`` case).
    """
    if len(identity_ed25519_pk) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return crypto_sign_ed25519_pk_to_curve25519(identity_ed25519_pk)


def validate_key_separation(
    identity_ed25519_pk: bytes, encryption_x25519_pk: bytes
) -> None:
    """Enforce R6: raise ``EncryptionError`` if the encryption pubkey is derived
    from the identity key (equal to it, or to its birational X25519 image).

    Constant-time comparison. Call for every published / accepted
    encryption-pubkey whose owner's identity key is known.
    """
    if len(encryption_x25519_pk) != 32:
        raise ValueError("X25519 encryption public key must be 32 bytes")

    if compare_digest(bytes(identity_ed25519_pk), bytes(encryption_x25519_pk)):
        raise EncryptionError(
            KEY_DERIVED_FROM_IDENTITY, "encryption_pk == identity_pk bytes"
        )

    try:
        image = birational_ed_to_x25519(identity_ed25519_pk)
    except Exception:
        # An identity key that can't be mapped can't collide via the image.
        return
    if compare_digest(image, bytes(encryption_x25519_pk)):
        raise EncryptionError(
            KEY_DERIVED_FROM_IDENTITY,
            "encryption_pk == birational(identity_pk) image",
        )
