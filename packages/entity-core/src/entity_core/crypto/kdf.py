"""Key-derivation adapters for EXTENSION-ENCRYPTION §3.3 + §6.2.

Two derivation surfaces:

- **HKDF** (``kdf_id`` registry) — the post-keying-material expansion that
  turns a shared secret / KEK into a per-entity AEAD key. Floor is
  ``kdf_id = 0x01`` HKDF-SHA-256 (RFC 5869).
- **Argon2id** — the memory-hard passphrase→KEK step used by ``self`` mode
  (§6.2) and the Tier-2 key-backup path (§9.2). NOT selected by ``kdf_id``;
  it is a separate mandated stage. Parameters (version 0x13 / v19, memory in
  KiB, time, parallelism, output length) are carried in the entity's
  ``kdf_params`` so any peer with the same user secret re-derives identically.

Argon2id comes from ``argon2-cffi`` (the reference C implementation via
bindings) with explicit ``(memory_cost, time_cost, parallelism, version)`` —
byte-equal to Go's ``x/crypto/argon2.IDKey`` and Rust's ``argon2`` crate for
the same parameters. The libsodium ``pwhash`` interface is deliberately NOT
used: its opslimit/memlimit abstraction does not let us pin the raw RFC-9106
parameters the KAT requires.
"""

from __future__ import annotations

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512, HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# -- kdf_id registry (§3.3) -------------------------------------------------

KDF_HKDF_SHA256 = 0x01  # v1 floor
KDF_HKDF_SHA512 = 0x02
KDF_HKDF_SHA384 = 0x03

KDF_NAMES: dict[int, str] = {
    KDF_HKDF_SHA256: "HKDF-SHA-256",
    KDF_HKDF_SHA512: "HKDF-SHA-512",
    KDF_HKDF_SHA384: "HKDF-SHA-384",
}

_HKDF_HASHES: dict[int, type[HashAlgorithm]] = {
    KDF_HKDF_SHA256: SHA256,
    KDF_HKDF_SHA512: SHA512,
    KDF_HKDF_SHA384: SHA384,
}

# -- Argon2id baseline (§6.2, RFC 9106) -------------------------------------

ARGON2_VERSION = 0x13  # v1.3 / v19 — pinned for v1
ARGON2_BASELINE_MEMORY_KIB = 65536  # 64 MiB
ARGON2_BASELINE_TIME = 3
ARGON2_BASELINE_PARALLELISM = 1
ARGON2_BASELINE_OUTPUT_LEN = 32

# §12 resource bound: refuse Argon2id memory above this ceiling (DoS guard).
ARGON2_MEMORY_CEILING_KIB = 1024 * 1024  # 1 GiB


class UnsupportedKdfError(ValueError):
    """Raised for a ``kdf_id`` this build does not implement."""


class KdfParamsExcessiveError(ValueError):
    """Argon2id memory parameter exceeds the §12 ceiling."""


def is_supported_kdf(kdf_id: int) -> bool:
    return kdf_id in KDF_NAMES


def hkdf(kdf_id: int, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Extract-then-Expand per ``kdf_id``. RFC 5869."""
    try:
        hash_cls = _HKDF_HASHES[kdf_id]
    except KeyError:
        raise UnsupportedKdfError(f"kdf_id {kdf_id:#04x}") from None
    return HKDF(algorithm=hash_cls(), length=length, salt=salt, info=info).derive(ikm)


def argon2id_kek(
    *,
    password: bytes,
    salt: bytes,
    memory_cost: int = ARGON2_BASELINE_MEMORY_KIB,
    time_cost: int = ARGON2_BASELINE_TIME,
    parallelism: int = ARGON2_BASELINE_PARALLELISM,
    output_len: int = ARGON2_BASELINE_OUTPUT_LEN,
    version: int = ARGON2_VERSION,
) -> bytes:
    """Derive a key-encryption-key from a user secret via Argon2id.

    ``password`` is raw bytes — for a passphrase, UTF-8 with NO trailing NUL
    (§6.2 / F-GO-9); for keyfile / keychain material, the raw stored bytes.
    """
    if memory_cost > ARGON2_MEMORY_CEILING_KIB:
        raise KdfParamsExcessiveError(
            f"memory_cost {memory_cost} KiB exceeds ceiling "
            f"{ARGON2_MEMORY_CEILING_KIB} KiB"
        )
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=output_len,
        type=Type.ID,
        version=version,
    )
