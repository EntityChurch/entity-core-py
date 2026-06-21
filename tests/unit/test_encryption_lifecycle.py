"""EXTENSION-ENCRYPTION §8.5 / §10 / §11 — group lifecycle + Tier-A resolution.

Behavioral primitives mirroring Go's BLOCK-1 phases 5 + 7 (cert-lifecycle
refusal + group add/re-key), implemented from the spec:
- §10.1 handoff chain walk + §11.1 revocation refusal (sender-side).
- §8.5 group add member (same key, append wrap) + re-key (fresh key).
"""

from __future__ import annotations

import pytest

from entity_core.crypto.ecdh import ENC_KEY_X25519, derive_public_key
from entity_core.protocol.entity import Entity
from entity_handlers.encryption import (
    EncryptionError,
    GroupMember,
    encryption_pubkey_entity,
    group_add_member,
    group_decrypt,
    group_encrypt,
    group_rekey,
    is_pubkey_revoked,
    pubkey_content_hash,
    resolve_current_pubkey,
    resolve_current_recipient,
)


def _member(seed_byte: int, eph_byte: int) -> tuple[GroupMember, bytes, bytes]:
    seed = bytes([seed_byte]) * 32
    pub = derive_public_key(ENC_KEY_X25519, seed)
    h = pubkey_content_hash(
        encryption_pubkey_entity(
            enc_key_type=1, public_key=pub,
            supported_aead_ids=[1], supported_kdf_ids=[1], created=0,
        )
    )
    return GroupMember(pubkey=pub, pubkey_hash=h, ephemeral_seed=bytes([eph_byte]) * 32), h, seed


def _handoff(prev: bytes, nxt: bytes) -> Entity:
    return Entity(
        type="system/encryption/handoff",
        data={"previous_pubkey": prev, "next_pubkey": nxt, "created": 0},
    )


def _revocation(target: bytes) -> Entity:
    return Entity(
        type="system/encryption/revocation",
        data={"revokes": target, "created": 0},
    )


# -- §10.1 / §11.1 Tier-A resolution ----------------------------------------

def test_handoff_chain_resolves_to_terminal():
    a, b, c = bytes([1]) * 33, bytes([2]) * 33, bytes([3]) * 33
    handoffs = [_handoff(a, b), _handoff(b, c)]
    assert resolve_current_pubkey(a, handoffs) == c
    assert resolve_current_pubkey(b, handoffs) == c
    assert resolve_current_pubkey(c, handoffs) == c  # terminal


def test_resolve_current_recipient_refuses_revoked_terminal():
    a, b = bytes([1]) * 33, bytes([2]) * 33
    handoffs = [_handoff(a, b)]
    # b is live → resolves.
    assert resolve_current_recipient(start_hash=a, handoffs=handoffs, revocations=[]) == b
    # b revoked → hard stop.
    with pytest.raises(EncryptionError) as ei:
        resolve_current_recipient(
            start_hash=a, handoffs=handoffs, revocations=[_revocation(b)]
        )
    assert ei.value.code == "encryption_key_revoked"


def test_is_pubkey_revoked():
    a = bytes([1]) * 33
    assert is_pubkey_revoked(a, [_revocation(a)])
    assert not is_pubkey_revoked(a, [_revocation(bytes([9]) * 33)])


# -- §8.5 group lifecycle ----------------------------------------------------

def test_group_add_member_same_key_appends_wrap():
    m0, h0, s0 = _member(0x50, 0x70)
    m1, h1, s1 = _member(0x51, 0x71)
    gkey = bytes([0x54]) * 32
    ent = group_encrypt(
        plaintext=b"shared secret", members=[m0], group_aead_key=gkey,
        outer_nonce=bytes([0x53]) * 24, wrap_nonces=[bytes([0x60]) * 24],
    )
    assert len(ent.data["wrapped_keys"]) == 1

    # Add m1 with the same key; outer ciphertext unchanged.
    ent2 = group_add_member(
        entity=ent, group_aead_key=gkey, member=m1, wrap_nonce=bytes([0x61]) * 24,
    )
    assert len(ent2.data["wrapped_keys"]) == 2
    assert ent2.data["ciphertext"] == ent.data["ciphertext"]  # same key, same outer
    # Both the original and the new member decrypt the same plaintext.
    assert group_decrypt(entity=ent2, my_certs={h0: s0}) == b"shared secret"
    assert group_decrypt(entity=ent2, my_certs={h1: s1}) == b"shared secret"


def test_group_rekey_fresh_key_removed_member_cannot_read_new():
    m0, h0, s0 = _member(0x50, 0x70)
    m1, h1, s1 = _member(0x51, 0x71)
    old_key = bytes([0x54]) * 32
    new_key = bytes([0x55]) * 32
    ent = group_encrypt(
        plaintext=b"v1", members=[m0, m1], group_aead_key=old_key,
        outer_nonce=bytes([0x53]) * 24,
        wrap_nonces=[bytes([0x60]) * 24, bytes([0x61]) * 24],
    )
    # Re-key removing m1 (only m0 remains), fresh key, new content.
    ent2 = group_rekey(
        plaintext=b"v2", members=[m0], new_group_aead_key=new_key,
        old_group_aead_key=old_key, outer_nonce=bytes([0x53]) * 24,
        wrap_nonces=[bytes([0x60]) * 24],
    )
    assert group_decrypt(entity=ent2, my_certs={h0: s0}) == b"v2"
    # Removed member m1 has no wrap in the new entity → cannot read v2.
    with pytest.raises(EncryptionError) as ei:
        group_decrypt(entity=ent2, my_certs={h1: s1})
    assert ei.value.code == "encryption_recipient_unknown"
    # But m1 still holds old_key and reads the OLD entity (snapshot-level FS).
    assert group_decrypt(entity=ent, my_certs={h1: s1}) == b"v1"


def test_group_rekey_rejects_same_key():
    m0, _, _ = _member(0x50, 0x70)
    key = bytes([0x54]) * 32
    with pytest.raises(EncryptionError):
        group_rekey(
            plaintext=b"x", members=[m0], new_group_aead_key=key,
            old_group_aead_key=key, outer_nonce=bytes([0x53]) * 24,
            wrap_nonces=[bytes([0x60]) * 24],
        )
