"""EXTENSION-ENCRYPTION v1.0 §16 — cohort byte-pin conformance fixtures.

Python's **independent** reference bytes for the §16 floor vectors, produced
from the pinned inputs in §16.2–§16.4. These close the BLOCK-0 byte-pin lock
from the Python seat: the cohort diffs these against Go + Rust + arch's
independent re-derivation (§16.5). A disagreement is a real cross-impl
divergence to route to arch — NOT something to silently re-pin to match Go
(independent convergence, per the RELAY/REGISTRY discipline).

Two cohort byte-pin decisions are load-bearing here (both flagged for §16.5):

  * **F-PY-ENC-1** — self-mode AAD binds ``kdf_params`` as a NESTED CBOR map
    (``a5 …``), not a pre-serialized byte string. See ``aad.py``.
  * **F-PY-ENC-2** — peer/group HKDF ``info`` + AAD ``recipient_key`` bind the
    FULL 33-byte content_hash (format byte 0x00 + 32-byte digest), not the bare
    digest. See ``modes_peer.py``.

If Go's reference differs on either, that is the v2.4→v2.5 absorption signal.

All hashes are 33-byte wire form (0x00 = ECFv1-SHA256 + 32-byte digest).
"""

from __future__ import annotations

import copy
import hashlib

import pytest

from entity_core.crypto.ecdh import ENC_KEY_X25519, derive_public_key
from entity_core.protocol.entity import Entity
from entity_handlers.encryption import (
    EncryptionError,
    GroupMember,
    baseline_kdf_params,
    encryption_pubkey_entity,
    group_decrypt,
    group_encrypt,
    peer_decrypt,
    peer_encrypt,
    pubkey_content_hash,
    self_decrypt,
    self_encrypt,
)
from entity_handlers.encryption.aad import (
    group_outer_aad,
    peer_aad,
    self_aad,
)
from entity_handlers.encryption.conformance import enc_kat_inner_plaintext

# R3 (arch v2.5): the §16 KAT plaintext is the 79-byte ECF of
# ENC-KAT-INNER (system/note{body, created:0}), NOT a bare string. All three
# floor KATs share it; each ciphertext is 95 bytes (79 + 16-byte tag).
KAT_PLAINTEXT = enc_kat_inner_plaintext()

# ===========================================================================
# ENC-SELF-KAT-1 (§16.2)
# ===========================================================================

SELF_NONCE = bytes([0x42]) * 24
SELF_SALT = bytes([0x43]) * 16
SELF_SECRET = b"entity-core/test/self-kat-1"  # utf8, no trailing NUL
SELF_KEY_ID = "test-key-1"
SELF_PLAINTEXT = KAT_PLAINTEXT

SELF_AAD_HEX = (
    "a8646d6f64656473656c66656e6f6e63655818424242424242424242424242424242424242424242"
    "424242666b64665f69640167616561645f696401686b64665f73616c745043434343434343434343"
    "4343434343436a6b64665f706172616d73a56974696d655f636f7374036a6f75747075745f6c656e"
    "18206b6d656d6f72795f636f73741a000100006b706172616c6c656c69736d016e6172676f6e325f"
    "76657273696f6e136c656e635f6b65795f74797065006d726563697069656e745f6b657940"
)
SELF_CIPHERTEXT_HEX = (
    "1988938ebb6be64ce283683ed6278a0bcc105df639b6474dc807ee4210e65a0e354749aafa85f8"
    "d5502f3ebbe2697cb7aaa5922efe863a1b2bd6d4e44c3b8d0ae3fdd2d30ff02160055dc3687cac1"
    "48e0013eb25b361b70b949a7b17fa02e7"
)
SELF_HASH_HEX = "00c4ce6c850517de8a954595ea39e2e78f6d475e3d23b4d912827cd9b83b022cd9"


@pytest.mark.slow
def test_enc_self_kat_1():
    params = baseline_kdf_params()
    aad = self_aad(
        enc_key_type=0, aead_id=1, kdf_id=1,
        nonce=SELF_NONCE, kdf_salt=SELF_SALT, kdf_params=params,
    )
    assert aad.hex() == SELF_AAD_HEX

    ent = self_encrypt(
        plaintext=SELF_PLAINTEXT, secret=SELF_SECRET, key_id=SELF_KEY_ID,
        nonce=SELF_NONCE, kdf_salt=SELF_SALT, kdf_params=params,
    )
    assert ent.data["ciphertext"].hex() == SELF_CIPHERTEXT_HEX
    assert ent.compute_hash().hex() == SELF_HASH_HEX
    assert self_decrypt(entity=ent, secret=SELF_SECRET) == SELF_PLAINTEXT


# ===========================================================================
# ENC-PEER-KAT-1 (§16.3)
# ===========================================================================

PEER_RECIP_SEED = bytes([0x45]) * 32
PEER_EPH_SEED = bytes([0x46]) * 32
PEER_NONCE = bytes([0x44]) * 24
PEER_PLAINTEXT = KAT_PLAINTEXT

PEER_RECIP_HASH_HEX = "00c74157e335954311c86afb6852081d00c39b23b83377b588d092e3fc8e6c9d5c"
PEER_EPH_HEX = "a28a7c44ede257d664fbf156affa7da8abb3ae74b9fee8d7a2078543504e1a75"
PEER_AAD_HEX = (
    "a7646d6f64656470656572656e6f6e63655818444444444444444444444444444444444444444444"
    "444444666b64665f69640167616561645f6964016c656e635f6b65795f74797065016d657068656d"
    "6572616c5f6b65795820a28a7c44ede257d664fbf156affa7da8abb3ae74b9fee8d7a2078543504e"
    "1a756d726563697069656e745f6b6579582100c74157e335954311c86afb6852081d00c39b23b833"
    "77b588d092e3fc8e6c9d5c"
)
PEER_CIPHERTEXT_HEX = (
    "ec0a370301e686a6eb7055617b5af228dfa59a01c2c5ee54d6e0a0b14d304700b522396763d5e0"
    "cb60a90065c35ace3c4fa77707c835745dfb07987c7eb394aab2ab23f7e415f27d4067f5258d86"
    "27a9c6f8c045727d41d466b61f87352a1f"
)


def _recip_pubkey_and_hash(seed: bytes):
    pub = derive_public_key(ENC_KEY_X25519, seed)
    h = pubkey_content_hash(
        encryption_pubkey_entity(
            enc_key_type=1, public_key=pub,
            supported_aead_ids=[1], supported_kdf_ids=[1], created=0,
        )
    )
    return pub, h


def test_enc_peer_kat_1():
    recip_pub, recip_hash = _recip_pubkey_and_hash(PEER_RECIP_SEED)
    assert recip_hash.hex() == PEER_RECIP_HASH_HEX

    ent = peer_encrypt(
        plaintext=PEER_PLAINTEXT, recipient_pubkey=recip_pub,
        recipient_pubkey_hash=recip_hash, nonce=PEER_NONCE,
        ephemeral_seed=PEER_EPH_SEED,
    )
    assert ent.data["ephemeral_key"].hex() == PEER_EPH_HEX
    aad = peer_aad(
        enc_key_type=1, aead_id=1, kdf_id=1, nonce=PEER_NONCE,
        recipient_key=recip_hash, ephemeral_key=ent.data["ephemeral_key"],
    )
    assert aad.hex() == PEER_AAD_HEX
    assert ent.data["ciphertext"].hex() == PEER_CIPHERTEXT_HEX
    assert peer_decrypt(entity=ent, my_private=PEER_RECIP_SEED) == PEER_PLAINTEXT


# ===========================================================================
# ENC-GROUP-KAT-1 (§16.4)
# ===========================================================================

GROUP_SEEDS = [bytes([s]) * 32 for s in (0x50, 0x51, 0x52)]
# R1 (arch v2.5): per-wrap ephemeral seeds = 0x70+i; wrap NONCES stay 0x60+i.
GROUP_EPH_SEEDS = [bytes([0x70 + i]) * 32 for i in range(3)]
GROUP_KEY = bytes([0x54]) * 32
GROUP_OUTER_NONCE = bytes([0x53]) * 24
GROUP_WRAP_NONCES = [bytes([0x60 + i]) * 24 for i in range(3)]
GROUP_PLAINTEXT = KAT_PLAINTEXT

GROUP_COMMIT_HEX = "784ad05e9d7a6aeaca70c0acc22d65d14d9dbbc383ee442a3e15484bf7a594e6"
GROUP_OUTER_AAD_HEX = (
    "a7646d6f64656567726f7570656e6f6e63655818535353535353535353535353535353535353535353"
    "535353666b64665f69640167616561645f6964016a636f6d6d69746d656e745820784ad05e9d7a6aea"
    "ca70c0acc22d65d14d9dbbc383ee442a3e15484bf7a594e66c656e635f6b65795f74797065006d7265"
    "63697069656e745f6b657940"
)
GROUP_OUTER_CT_HEX = (
    "f048ed1f905803cb97f08ea4b6a7bc531016cbea5b9846c0495f6d805f3860985373f9ef5845c2"
    "1715ebab4d29ad4f1f49cb4d2f1a5398b9d2261e18520dd4270754642b769542d262648df1c542"
    "fd1ccc8d6f1bf1c1d29c103dc6d3c0d35e"
)


def _group_members_and_privs():
    members, privs = [], {}
    for seed, eph in zip(GROUP_SEEDS, GROUP_EPH_SEEDS, strict=True):
        pub, h = _recip_pubkey_and_hash(seed)
        members.append(GroupMember(pubkey=pub, pubkey_hash=h, ephemeral_seed=eph))
        privs[h] = seed
    return members, privs


def test_enc_group_kat_1():
    members, privs = _group_members_and_privs()
    assert hashlib.sha256(GROUP_KEY).digest().hex() == GROUP_COMMIT_HEX

    aad = group_outer_aad(
        aead_id=1, kdf_id=1, nonce=GROUP_OUTER_NONCE,
        commitment=hashlib.sha256(GROUP_KEY).digest(),
    )
    assert aad.hex() == GROUP_OUTER_AAD_HEX

    ent = group_encrypt(
        plaintext=GROUP_PLAINTEXT, members=members, group_aead_key=GROUP_KEY,
        outer_nonce=GROUP_OUTER_NONCE, wrap_nonces=GROUP_WRAP_NONCES,
    )
    assert ent.data["ciphertext"].hex() == GROUP_OUTER_CT_HEX
    assert len(ent.data["wrapped_keys"]) == 3
    # Every member recovers the same plaintext.
    for h, seed in privs.items():
        assert group_decrypt(entity=ent, my_certs={h: seed}) == GROUP_PLAINTEXT


# ===========================================================================
# ENC-GROUP-COMMIT-1 (§16, F2-1) — equivocation rejected
# ===========================================================================

def test_enc_group_commit_1_equivocation_rejected():
    members, privs = _group_members_and_privs()
    ent = group_encrypt(
        plaintext=GROUP_PLAINTEXT, members=members, group_aead_key=GROUP_KEY,
        outer_nonce=GROUP_OUTER_NONCE, wrap_nonces=GROUP_WRAP_NONCES,
    )
    # Forge an outer ciphertext committed to a DIFFERENT key while the wraps
    # still deliver GROUP_KEY. The decrypting member recomputes
    # commitment(GROUP_KEY), reconstructs an AAD that does not match the forged
    # outer, and AEAD.Open fails — equivocation structurally impossible.
    from entity_core.crypto.aead import aead_encrypt

    evil_key = bytes([0x99]) * 32
    evil_aad = group_outer_aad(
        aead_id=1, kdf_id=1, nonce=GROUP_OUTER_NONCE,
        commitment=hashlib.sha256(evil_key).digest(),
    )
    forged = Entity(type=ent.type, data=copy.deepcopy(ent.data))
    forged.data["ciphertext"] = aead_encrypt(
        1, evil_key, GROUP_OUTER_NONCE, evil_aad, b"DIVERGENT PLAINTEXT"
    )
    h0 = next(iter(privs))
    with pytest.raises(EncryptionError) as ei:
        group_decrypt(entity=forged, my_certs={h0: privs[h0]})
    assert ei.value.code == "encryption_aead_failed"


# ===========================================================================
# ENC-AAD-1 (§16) — tampering any AAD-bound field fails decryption
# ===========================================================================

@pytest.mark.slow
def test_enc_aad_1_self_tamper():
    params = baseline_kdf_params()
    ent = self_encrypt(
        plaintext=SELF_PLAINTEXT, secret=SELF_SECRET, key_id=SELF_KEY_ID,
        nonce=SELF_NONCE, kdf_salt=SELF_SALT, kdf_params=params,
    )
    # kdf_salt and kdf_params are AAD-bound (F2-4); flipping either must fail.
    for mutate in (
        lambda d: d.__setitem__("kdf_salt", bytes([0x44]) * 16),
        lambda d: d["kdf_params"].__setitem__("time_cost", 4),
    ):
        bad = Entity(type=ent.type, data=copy.deepcopy(ent.data))
        mutate(bad.data)
        with pytest.raises(EncryptionError) as ei:
            self_decrypt(entity=bad, secret=SELF_SECRET)
        assert ei.value.code == "encryption_aead_failed"


def test_enc_aad_1_peer_tamper():
    recip_pub, recip_hash = _recip_pubkey_and_hash(PEER_RECIP_SEED)
    ent = peer_encrypt(
        plaintext=PEER_PLAINTEXT, recipient_pubkey=recip_pub,
        recipient_pubkey_hash=recip_hash, nonce=PEER_NONCE,
        ephemeral_seed=PEER_EPH_SEED,
    )
    # Flip a byte of the nonce — AAD-bound and key-derivation salt both change.
    bad = Entity(type=ent.type, data=copy.deepcopy(ent.data))
    bad.data["nonce"] = bytes([0x45]) * 24
    with pytest.raises(EncryptionError) as ei:
        peer_decrypt(entity=bad, my_private=PEER_RECIP_SEED)
    assert ei.value.code == "encryption_aead_failed"


# ===========================================================================
# ENC-RESOURCE-BOUNDS-1 (§16 / §8.6) — wrapped_keys ceiling
# ===========================================================================

# ===========================================================================
# ENC-KEY-SEPARATION-1 (§16, R6) — encryption key MUST NOT derive from identity
# ===========================================================================

def test_enc_key_separation_1():
    from nacl.bindings import crypto_sign_keypair

    from entity_handlers.encryption import (
        birational_ed_to_x25519,
        validate_key_separation,
    )

    identity_pk, _ = crypto_sign_keypair()  # Ed25519 identity key
    # A genuinely separate X25519 encryption key passes.
    sep_pub = derive_public_key(ENC_KEY_X25519, bytes([0x11]) * 32)
    validate_key_separation(identity_pk, sep_pub)  # no raise

    # Encryption pubkey == raw identity bytes → reject.
    with pytest.raises(EncryptionError) as ei1:
        validate_key_separation(identity_pk, identity_pk)
    assert ei1.value.code == "encryption_key_derived_from_identity"

    # Encryption pubkey == birational(identity) → reject.
    image = birational_ed_to_x25519(identity_pk)
    with pytest.raises(EncryptionError) as ei2:
        validate_key_separation(identity_pk, image)
    assert ei2.value.code == "encryption_key_derived_from_identity"


def test_enc_resource_bounds_1_wrapped_keys_ceiling():
    pub, h = _recip_pubkey_and_hash(GROUP_SEEDS[0])
    members = [GroupMember(pubkey=pub, pubkey_hash=h) for _ in range(3)]
    nonces = [bytes([0x60 + i]) * 24 for i in range(3)]
    with pytest.raises(EncryptionError) as ei:
        group_encrypt(
            plaintext=GROUP_PLAINTEXT, members=members, group_aead_key=GROUP_KEY,
            outer_nonce=GROUP_OUTER_NONCE, wrap_nonces=nonces, ceiling=2,
        )
    assert ei.value.code == "encryption_wrapped_keys_too_many"
    assert ei.value.status == 413
