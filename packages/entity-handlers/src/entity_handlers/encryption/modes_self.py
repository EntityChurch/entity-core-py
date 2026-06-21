"""EXTENSION-ENCRYPTION §6 — mode ``self`` (storage encryption), v1 PRIMARY.

At-rest symmetric encryption for the encrypting peer's own later decryption.
No public-key crypto: a local secret (passphrase / keyfile / keychain entry,
selected by ``key_id``) is stretched through Argon2id → HKDF → per-entity AEAD
key. The mode functions operate on raw inner-entity ECF bytes so they are
KAT-testable standalone; the handler composes entity encode/decode around them.
"""

from __future__ import annotations

from entity_core.crypto.aead import aead_decrypt, aead_encrypt, aead_key_len
from entity_core.crypto.kdf import argon2id_kek, hkdf
from entity_core.protocol.entity import Entity

from .aad import self_aad
from .entities import encrypted_entity
from .errors import AEAD_FAILED, KEY_UNAVAILABLE, UNSUPPORTED_SUITE, EncryptionError
from .registries import FLOOR_AEAD_ID, FLOOR_KDF_ID, aead_allowed_in_mode

# §6.2 — HKDF info prefix (ASCII, no separator, no NUL).
SELF_INFO_PREFIX = b"entity-core/self/"

# §6.1 — self mode carries enc_key_type 0x00 (no keypair).
SELF_ENC_KEY_TYPE = 0x00


def self_encrypt(
    *,
    plaintext: bytes,
    secret: bytes,
    key_id: str,
    nonce: bytes,
    kdf_salt: bytes,
    kdf_params: dict[str, int],
    aead_id: int = FLOOR_AEAD_ID,
    kdf_id: int = FLOOR_KDF_ID,
) -> Entity:
    """Encrypt ``plaintext`` (inner-entity ECF) → ``system/encrypted`` entity.

    ``secret`` is the raw user secret bytes (utf8(passphrase) with no trailing
    NUL, or raw keyfile/keychain bytes). The caller supplies ``nonce`` +
    ``kdf_salt`` (random in production, pinned for KATs).
    """
    if not aead_allowed_in_mode(aead_id, "self"):
        raise EncryptionError(UNSUPPORTED_SUITE, "short-nonce AEAD forbidden in self mode")

    aead_key = _derive_self_key(
        secret=secret, key_id=key_id, nonce=nonce,
        kdf_salt=kdf_salt, kdf_params=kdf_params, kdf_id=kdf_id, aead_id=aead_id,
    )
    aad = self_aad(
        enc_key_type=SELF_ENC_KEY_TYPE, aead_id=aead_id, kdf_id=kdf_id,
        nonce=nonce, kdf_salt=kdf_salt, kdf_params=kdf_params,
    )
    ciphertext = aead_encrypt(aead_id, aead_key, nonce, aad, plaintext)
    return encrypted_entity(
        "self",
        {
            "enc_key_type": SELF_ENC_KEY_TYPE,
            "aead_id": aead_id,
            "kdf_id": kdf_id,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "key_id": key_id,
            "kdf_salt": kdf_salt,
            "kdf_params": dict(kdf_params),
        },
    )


def self_decrypt(*, entity: Entity, secret: bytes) -> bytes:
    """Recover inner-entity ECF bytes from a self-mode ``system/encrypted``."""
    d = entity.data
    try:
        aead_id = d["aead_id"]
        kdf_id = d["kdf_id"]
        nonce = d["nonce"]
        ciphertext = d["ciphertext"]
        key_id = d["key_id"]
        kdf_salt = d["kdf_salt"]
        kdf_params = d["kdf_params"]
    except KeyError as e:
        raise EncryptionError(KEY_UNAVAILABLE, f"missing self field {e}") from None

    if not aead_allowed_in_mode(aead_id, "self"):
        raise EncryptionError(UNSUPPORTED_SUITE, "short-nonce AEAD forbidden in self mode")

    aead_key = _derive_self_key(
        secret=secret, key_id=key_id, nonce=nonce,
        kdf_salt=kdf_salt, kdf_params=kdf_params, kdf_id=kdf_id, aead_id=aead_id,
    )
    aad = self_aad(
        enc_key_type=SELF_ENC_KEY_TYPE, aead_id=aead_id, kdf_id=kdf_id,
        nonce=nonce, kdf_salt=kdf_salt, kdf_params=kdf_params,
    )
    try:
        return aead_decrypt(aead_id, aead_key, nonce, aad, ciphertext)
    except Exception as e:  # AEAD tag failure / tampered AAD
        raise EncryptionError(AEAD_FAILED, str(e)) from None


def _derive_self_key(
    *,
    secret: bytes,
    key_id: str,
    nonce: bytes,
    kdf_salt: bytes,
    kdf_params: dict[str, int],
    kdf_id: int,
    aead_id: int,
) -> bytes:
    """Argon2id(secret) → HKDF → AEAD key (§6.2)."""
    kek = argon2id_kek(
        password=secret,
        salt=kdf_salt,
        memory_cost=kdf_params["memory_cost"],
        time_cost=kdf_params["time_cost"],
        parallelism=kdf_params["parallelism"],
        output_len=kdf_params["output_len"],
        version=kdf_params["argon2_version"],
    )
    return hkdf(
        kdf_id,
        ikm=kek,
        salt=nonce,
        info=SELF_INFO_PREFIX + key_id.encode("utf-8"),
        length=aead_key_len(aead_id),
    )


def baseline_kdf_params() -> dict[str, int]:
    """Default §6.2 Argon2id parameters as a kdf_params dict."""
    from entity_core.crypto.kdf import (
        ARGON2_BASELINE_MEMORY_KIB,
        ARGON2_BASELINE_OUTPUT_LEN,
        ARGON2_BASELINE_PARALLELISM,
        ARGON2_BASELINE_TIME,
        ARGON2_VERSION,
    )

    return {
        "argon2_version": ARGON2_VERSION,
        "memory_cost": ARGON2_BASELINE_MEMORY_KIB,
        "time_cost": ARGON2_BASELINE_TIME,
        "parallelism": ARGON2_BASELINE_PARALLELISM,
        "output_len": ARGON2_BASELINE_OUTPUT_LEN,
    }


# Re-export for callers needing the field-typed dict shape.
__all__ = ["self_encrypt", "self_decrypt", "baseline_kdf_params"]
