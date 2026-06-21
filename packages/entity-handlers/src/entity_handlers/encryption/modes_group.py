"""EXTENSION-ENCRYPTION §8 — mode ``group`` (static key-wrap), v1 BEST-EFFORT.

A random ``group_aead_key`` seals the inner entity once (outer ciphertext);
that key is then wrapped per-member via peer-mode-style hybrid encryption
(``mode:"group-wrap"`` AAD, F2-2). The outer AAD binds
``commitment = SHA-256(group_aead_key)`` (F2-1) so XChaCha20-Poly1305's lack of
key-commitment cannot be exploited to equivocate (invisible-salamanders): a
member who recovers a *different* key reconstructs a different outer AAD and
AEAD.Open fails. No group-PFS; static groups only (§8.1).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from entity_core.crypto.aead import aead_decrypt, aead_encrypt
from entity_core.protocol.entity import Entity

from .aad import group_outer_aad
from .entities import encrypted_entity
from .errors import (
    AEAD_FAILED,
    INVALID_WRAPPER,
    RECIPIENT_UNKNOWN,
    WRAPPED_KEYS_TOO_MANY,
    EncryptionError,
)
from .modes_peer import peer_seal, peer_unseal
from .registries import FLOOR_AEAD_ID, FLOOR_ENC_KEY_TYPE, FLOOR_KDF_ID

# §8.6 default ceiling on wrapped_keys per entity.
DEFAULT_WRAPPED_KEYS_CEILING = 256

# §8.3 group outer carries enc_key_type 0x00 (the outer key is the symmetric
# random group_aead_key, not a keypair).
GROUP_OUTER_ENC_KEY_TYPE = 0x00


@dataclass(frozen=True)
class GroupMember:
    """One recipient of a group entity."""

    pubkey: bytes  # raw public key
    pubkey_hash: bytes  # 33-byte content_hash of the member's inner pubkey entity
    enc_key_type: int = FLOOR_ENC_KEY_TYPE
    ephemeral_seed: bytes | None = None  # pin per-wrap ephemeral for KATs


def group_encrypt(
    *,
    plaintext: bytes,
    members: list[GroupMember],
    group_aead_key: bytes,
    outer_nonce: bytes,
    wrap_nonces: list[bytes],
    aead_id: int = FLOOR_AEAD_ID,
    kdf_id: int = FLOOR_KDF_ID,
    ceiling: int = DEFAULT_WRAPPED_KEYS_CEILING,
) -> Entity:
    """Encrypt ``plaintext`` for a fixed member set → group ``system/encrypted``.

    ``group_aead_key`` (32 bytes) + ``outer_nonce`` + per-member ``wrap_nonces``
    are caller-supplied (random in production, pinned for KATs). Outer entity is
    signed once at the handler layer (§8.3 step 7).
    """
    if len(members) > ceiling:
        raise EncryptionError(
            WRAPPED_KEYS_TOO_MANY, f"{len(members)} members exceeds ceiling {ceiling}"
        )
    if len(wrap_nonces) != len(members):
        raise EncryptionError(INVALID_WRAPPER, "wrap_nonces length must match members")

    # §8.3 steps 2–4: commit + seal the inner entity under the group key.
    commitment = hashlib.sha256(group_aead_key).digest()
    outer_aad = group_outer_aad(
        aead_id=aead_id, kdf_id=kdf_id, nonce=outer_nonce, commitment=commitment
    )
    outer_ct = aead_encrypt(aead_id, group_aead_key, outer_nonce, outer_aad, plaintext)

    # §8.3 step 5: wrap the group key to each member (peer flow steps 1–6 only;
    # no per-wrap signing — F-GO-6 — and the wrap AAD is "group-wrap" — F2-2).
    wrapped_keys = []
    for member, wrap_nonce in zip(members, wrap_nonces, strict=True):
        wrap = peer_seal(
            plaintext=group_aead_key,
            recipient_pubkey=member.pubkey,
            recipient_pubkey_hash=member.pubkey_hash,
            nonce=wrap_nonce,
            enc_key_type=member.enc_key_type,
            aead_id=aead_id,
            kdf_id=kdf_id,
            ephemeral_seed=member.ephemeral_seed,
            mode="group-wrap",
        )
        wrapped_keys.append(
            {
                "recipient_key": wrap["recipient_key"],
                "enc_key_type": wrap["enc_key_type"],
                "ephemeral_key": wrap["ephemeral_key"],
                "wrapped_aead_key": wrap["ciphertext"],
                "wrap_nonce": wrap_nonce,
            }
        )

    return encrypted_entity(
        "group",
        {
            "enc_key_type": GROUP_OUTER_ENC_KEY_TYPE,
            "aead_id": aead_id,
            "kdf_id": kdf_id,
            "nonce": outer_nonce,
            "ciphertext": outer_ct,
            "wrapped_keys": wrapped_keys,
        },
    )


def group_add_member(
    *,
    entity: Entity,
    group_aead_key: bytes,
    member: GroupMember,
    wrap_nonce: bytes,
    ceiling: int = DEFAULT_WRAPPED_KEYS_CEILING,
) -> Entity:
    """§8.5 add member — cheap: append one wrap, reuse the same key.

    The outer ciphertext + commitment are unchanged (same ``group_aead_key``),
    so existing members are unaffected; only a new ``wrapped_keys`` entry is
    added. The caller must hold ``group_aead_key`` (recovered from their own
    wrap, or retained as author). F2-1 holds across the add — the commitment
    still binds the one unchanged key.
    """
    existing = entity.data.get("wrapped_keys", [])
    if len(existing) + 1 > ceiling:
        raise EncryptionError(
            WRAPPED_KEYS_TOO_MANY,
            f"{len(existing) + 1} members exceeds ceiling {ceiling}",
        )
    aead_id = entity.data["aead_id"]
    kdf_id = entity.data["kdf_id"]
    wrap = peer_seal(
        plaintext=group_aead_key,
        recipient_pubkey=member.pubkey,
        recipient_pubkey_hash=member.pubkey_hash,
        nonce=wrap_nonce,
        enc_key_type=member.enc_key_type,
        aead_id=aead_id,
        kdf_id=kdf_id,
        ephemeral_seed=member.ephemeral_seed,
        mode="group-wrap",
    )
    new_wrap = {
        "recipient_key": wrap["recipient_key"],
        "enc_key_type": wrap["enc_key_type"],
        "ephemeral_key": wrap["ephemeral_key"],
        "wrapped_aead_key": wrap["ciphertext"],
        "wrap_nonce": wrap_nonce,
    }
    new_data = dict(entity.data)
    new_data["wrapped_keys"] = [*existing, new_wrap]
    return Entity(type=entity.type, data=new_data)


def group_rekey(
    *,
    plaintext: bytes,
    members: list[GroupMember],
    new_group_aead_key: bytes,
    outer_nonce: bytes,
    wrap_nonces: list[bytes],
    old_group_aead_key: bytes | None = None,
    aead_id: int = FLOOR_AEAD_ID,
    kdf_id: int = FLOOR_KDF_ID,
    ceiling: int = DEFAULT_WRAPPED_KEYS_CEILING,
) -> Entity:
    """§8.5 remove member / rotate — expensive: fresh key, full re-encrypt.

    A new ``group_aead_key`` is generated and the content re-encrypted + re-
    wrapped for the (post-removal) member set. A removed member retains the OLD
    key and can still read OLD entities — forward secrecy at the group-snapshot
    level only (§8.5 honest framing). ``old_group_aead_key`` is an optional
    guard asserting the key genuinely rotated.
    """
    if old_group_aead_key is not None and new_group_aead_key == old_group_aead_key:
        raise EncryptionError(
            INVALID_WRAPPER, "rekey must use a fresh group_aead_key"
        )
    return group_encrypt(
        plaintext=plaintext,
        members=members,
        group_aead_key=new_group_aead_key,
        outer_nonce=outer_nonce,
        wrap_nonces=wrap_nonces,
        aead_id=aead_id,
        kdf_id=kdf_id,
        ceiling=ceiling,
    )


def group_decrypt(*, entity: Entity, my_certs: dict[bytes, bytes]) -> bytes:
    """Recover inner-entity ECF from a group ``system/encrypted``.

    ``my_certs`` maps ``pubkey_hash -> encryption_private_key`` for the certs
    this peer holds. Outer-signature verification (§8.4 step 1) is the handler
    layer's job.
    """
    d = entity.data
    try:
        aead_id = d["aead_id"]
        kdf_id = d["kdf_id"]
        outer_nonce = d["nonce"]
        outer_ct = d["ciphertext"]
        wrapped_keys = d["wrapped_keys"]
    except KeyError as e:
        raise EncryptionError(INVALID_WRAPPER, f"missing group field {e}") from None

    # §8.4 step 2: find a wrap addressed to a cert we hold.
    group_aead_key = None
    for wrap in wrapped_keys:
        rk = wrap["recipient_key"]
        if rk in my_certs:
            group_aead_key = peer_unseal(
                ciphertext=wrap["wrapped_aead_key"],
                my_private=my_certs[rk],
                ephemeral_key=wrap["ephemeral_key"],
                recipient_key=rk,
                nonce=wrap["wrap_nonce"],
                enc_key_type=wrap["enc_key_type"],
                aead_id=aead_id,
                kdf_id=kdf_id,
                mode="group-wrap",
            )
            break
    if group_aead_key is None:
        raise EncryptionError(RECIPIENT_UNKNOWN, "no wrapped_key for a held cert")

    # §8.4 steps 3–4: recompute commitment, bind it, open the outer ciphertext.
    commitment = hashlib.sha256(group_aead_key).digest()
    outer_aad = group_outer_aad(
        aead_id=aead_id, kdf_id=kdf_id, nonce=outer_nonce, commitment=commitment
    )
    try:
        return aead_decrypt(aead_id, group_aead_key, outer_nonce, outer_aad, outer_ct)
    except Exception as e:
        # Equivocation attempt (F2-1): committed key differs from ours.
        raise EncryptionError(AEAD_FAILED, str(e)) from None
