"""EXTENSION-ENCRYPTION §5.2 — AEAD additional-data construction (normative).

AAD binds the encryption context (mode / suite / nonce / recipient / key
commitment) into the AEAD tag so an attacker cannot replay a ciphertext into a
different mode, recipient, or cipher suite. **AAD is ECF** per
``ENTITY-CBOR-ENCODING.md`` (RFC 8949 §4.2 length-first canonical ordering) —
the same form authoritative for every other byte-pinned surface in the cohort
(F-GO-2). ``ecf_encode`` performs the length-then-lexicographic key ordering;
this module only assembles each mode's FIXED key set.

**All-keys-present discipline.** Each mode has a fixed key set; a key not
applicable to a mode is emitted as **empty bytes**, never omitted. Omission-vs-
present-empty is the v7.67 Phase-2 byte-pin trap (F-GO-2); these builders close
it by always emitting the full set.

Key sets (post-v2.4):
- self        — 8 keys (adds ``kdf_salt`` + ``kdf_params`` per F2-4)
- peer        — 7 keys
- group-outer — 7 keys (adds ``commitment`` per F2-1)
- group-wrap  — 7 keys, ``mode:"group-wrap"`` domain-separated (F2-2)

FLAG F-PY-ENC-1 (cohort byte-pin): §5.2 self-mode binds ``kdf_params`` as
"the kdf_params sub-shape … ECF-encoded". We bind it as a **nested CBOR map**
(the natural reading: the outer AAD is ECF, so the nested map is canonically
encoded as part of it) — NOT as a pre-serialized byte string. The §9.2 backup
path, by contrast, *flattens* the params into sibling AAD keys. If Go bound
pre-encoded bytes the self-mode AAD hex will diverge here; this is the first
thing to diff in the §16.5 round.
"""

from __future__ import annotations

from typing import Any

from entity_core.utils.ecf import ecf_encode


def _kdf_params_map(kdf_params: dict[str, int]) -> dict[str, int]:
    """Normative kdf_params sub-shape (§6.1 field names; F-GO-9)."""
    return {
        "argon2_version": kdf_params["argon2_version"],
        "memory_cost": kdf_params["memory_cost"],
        "time_cost": kdf_params["time_cost"],
        "parallelism": kdf_params["parallelism"],
        "output_len": kdf_params["output_len"],
    }


def self_aad(
    *,
    enc_key_type: int,
    aead_id: int,
    kdf_id: int,
    nonce: bytes,
    kdf_salt: bytes,
    kdf_params: dict[str, int],
) -> bytes:
    """Self-mode 8-key AAD (§5.2). ``recipient_key`` empty (no recipient)."""
    obj: dict[str, Any] = {
        "mode": "self",
        "enc_key_type": enc_key_type,
        "aead_id": aead_id,
        "kdf_id": kdf_id,
        "nonce": nonce,
        "kdf_salt": kdf_salt,
        "kdf_params": _kdf_params_map(kdf_params),
        "recipient_key": b"",
    }
    return ecf_encode(obj)


def peer_aad(
    *,
    enc_key_type: int,
    aead_id: int,
    kdf_id: int,
    nonce: bytes,
    recipient_key: bytes,
    ephemeral_key: bytes,
) -> bytes:
    """Peer-mode 7-key AAD (§5.2).

    ``recipient_key`` = recipient inner pubkey-entity content_hash (uniform at
    every tier, F-GO-1); ``ephemeral_key`` = sender's ephemeral public key.
    """
    obj: dict[str, Any] = {
        "mode": "peer",
        "enc_key_type": enc_key_type,
        "aead_id": aead_id,
        "kdf_id": kdf_id,
        "nonce": nonce,
        "recipient_key": recipient_key,
        "ephemeral_key": ephemeral_key,
    }
    return ecf_encode(obj)


def group_outer_aad(
    *,
    aead_id: int,
    kdf_id: int,
    nonce: bytes,
    commitment: bytes,
) -> bytes:
    """Group outer-ciphertext 7-key AAD (§5.2).

    ``enc_key_type`` is 0 (the outer key is the random group_aead_key, not a
    keypair); ``commitment = SHA-256(group_aead_key)`` (F2-1) makes only the
    single committed key open the outer ciphertext; ``recipient_key`` empty
    (no single recipient at the outer level).
    """
    obj: dict[str, Any] = {
        "mode": "group",
        "enc_key_type": 0,
        "aead_id": aead_id,
        "kdf_id": kdf_id,
        "nonce": nonce,
        "commitment": commitment,
        "recipient_key": b"",
    }
    return ecf_encode(obj)


def group_wrap_aad(
    *,
    enc_key_type: int,
    aead_id: int,
    kdf_id: int,
    nonce: bytes,
    recipient_key: bytes,
    ephemeral_key: bytes,
) -> bytes:
    """Group per-wrap 7-key AAD (§5.2), ``mode:"group-wrap"`` (F2-2).

    Peer-mode-shaped but domain-separated by the distinct mode label, so a
    lifted wrap blob is not a replayable standalone peer ciphertext.
    """
    obj: dict[str, Any] = {
        "mode": "group-wrap",
        "enc_key_type": enc_key_type,
        "aead_id": aead_id,
        "kdf_id": kdf_id,
        "nonce": nonce,
        "recipient_key": recipient_key,
        "ephemeral_key": ephemeral_key,
    }
    return ecf_encode(obj)
