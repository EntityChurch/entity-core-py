"""EXTENSION-ENCRYPTION §9 — at-rest key storage (defense in depth).

The encryption private key is a high-value secret. v1 mandates a two-tier
model so a single fault (lost device, forgotten passphrase, corrupted
keychain) never permanently locks a user out of their own encrypted storage.

- **Tier 1 (hot)** — platform secure storage (Keychain / Credential Manager /
  libsecret / hardware token), or a passphrase prompt on headless deployments.
  Platform-specific; out of scope for this pure-protocol module (the impl wires
  it per ``key_id`` at the CLI layer).
- **Tier 2 (cold)** — a passphrase-wrapped copy of the private key, stored as a
  normal ``system/encryption/key-backup`` tree entity. This module owns its
  byte construction (§9.2) and round-trip.

**AAD asymmetry vs self mode (deliberate, §9.2 vs §5.2):** the backup AAD
*flattens* the Argon2id params into sibling keys (``argon2_version`` /
``memory_cost`` / …) alongside ``pubkey_ref``; self-mode AAD *nests* them under
a single ``kdf_params`` key. Both are honored exactly as written — do not unify.

FLAG F-PY-ENC-2 (same as the modes): the HKDF ``info`` binds the FULL 33-byte
``pubkey_ref`` content_hash, not the bare digest.
"""

from __future__ import annotations

from typing import Any

from entity_core.crypto.aead import (
    AEAD_XCHACHA20_POLY1305,
    aead_decrypt,
    aead_encrypt,
)
from entity_core.crypto.kdf import KDF_HKDF_SHA256, argon2id_kek, hkdf
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ecf_encode

from .entities import PUBKEY_TYPE  # noqa: F401  (documents the ref target)
from .errors import AEAD_FAILED, EncryptionError
from .modes_self import baseline_kdf_params

KEY_BACKUP_TYPE = "system/encryption/key-backup"

# §9.2 — HKDF info prefix for the wrap key.
BACKUP_INFO_PREFIX = b"entity-core/key-backup/"

# Backup wrapping is always XChaCha20-Poly1305 (24-byte nonce) per §9.2.
_BACKUP_AEAD = AEAD_XCHACHA20_POLY1305


def _backup_aad(pubkey_ref: bytes, kdf_params: dict[str, int]) -> bytes:
    """§9.2 backup AAD — params FLATTENED (NOT nested; contrast self-mode)."""
    obj: dict[str, Any] = {
        "pubkey_ref": pubkey_ref,
        "argon2_version": kdf_params["argon2_version"],
        "memory_cost": kdf_params["memory_cost"],
        "time_cost": kdf_params["time_cost"],
        "parallelism": kdf_params["parallelism"],
        "output_len": kdf_params["output_len"],
    }
    return ecf_encode(obj)


def _wrap_key(
    *, passphrase: bytes, kdf_salt: bytes, wrap_nonce: bytes,
    pubkey_ref: bytes, kdf_params: dict[str, int],
) -> bytes:
    kek = argon2id_kek(
        password=passphrase, salt=kdf_salt,
        memory_cost=kdf_params["memory_cost"], time_cost=kdf_params["time_cost"],
        parallelism=kdf_params["parallelism"], output_len=kdf_params["output_len"],
        version=kdf_params["argon2_version"],
    )
    return hkdf(
        KDF_HKDF_SHA256, ikm=kek, salt=wrap_nonce,
        info=BACKUP_INFO_PREFIX + pubkey_ref, length=32,
    )


def make_key_backup(
    *,
    private_key: bytes,
    pubkey_ref: bytes,
    passphrase: bytes,
    kdf_salt: bytes,
    wrap_nonce: bytes,
    kdf_params: dict[str, int] | None = None,
) -> Entity:
    """Wrap ``private_key`` → a ``system/encryption/key-backup`` entity (§9.2).

    ``pubkey_ref`` is the 33-byte content_hash of the encryption-pubkey this
    backs up; ``passphrase`` is utf8 with no trailing NUL. ``kdf_salt`` (≥16B)
    and ``wrap_nonce`` (24B) are random in production, pinned for tests.
    """
    params = kdf_params or baseline_kdf_params()
    wrap_key = _wrap_key(
        passphrase=passphrase, kdf_salt=kdf_salt, wrap_nonce=wrap_nonce,
        pubkey_ref=pubkey_ref, kdf_params=params,
    )
    aad = _backup_aad(pubkey_ref, params)
    wrapped_key = aead_encrypt(_BACKUP_AEAD, wrap_key, wrap_nonce, aad, private_key)
    return Entity(
        type=KEY_BACKUP_TYPE,
        data={
            "pubkey_ref": pubkey_ref,
            "kdf_salt": kdf_salt,
            "kdf_params": dict(params),
            "wrap_nonce": wrap_nonce,
            "wrapped_key": wrapped_key,
        },
    )


def restore_key_backup(*, entity: Entity, passphrase: bytes) -> bytes:
    """Recover the private key from a ``system/encryption/key-backup`` (§9.2)."""
    d = entity.data
    try:
        pubkey_ref = d["pubkey_ref"]
        kdf_salt = d["kdf_salt"]
        kdf_params = d["kdf_params"]
        wrap_nonce = d["wrap_nonce"]
        wrapped_key = d["wrapped_key"]
    except KeyError as e:
        raise EncryptionError(AEAD_FAILED, f"missing key-backup field {e}") from None

    wrap_key = _wrap_key(
        passphrase=passphrase, kdf_salt=kdf_salt, wrap_nonce=wrap_nonce,
        pubkey_ref=pubkey_ref, kdf_params=kdf_params,
    )
    aad = _backup_aad(pubkey_ref, kdf_params)
    try:
        return aead_decrypt(_BACKUP_AEAD, wrap_key, wrap_nonce, aad, wrapped_key)
    except Exception as e:  # wrong passphrase / tampered backup
        raise EncryptionError(AEAD_FAILED, str(e)) from None
