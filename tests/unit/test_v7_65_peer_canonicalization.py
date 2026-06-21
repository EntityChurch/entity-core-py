"""V7 v7.65 PEER-CANON / PEER-PATTERN / PEER-MUT / COMPOSITION conformance vectors.

Per `proposals/PROPOSAL-V7-PEER-ENTITY-CANONICALIZATION-AND-V1-CONTRACT.md` §13:

- PEER-CANON-1: content_hash(system/peer) invariance under wire-form choice (§2)
- PEER-CANON-2: dialer canonicalizes on wire receipt (§5)
- PEER-PATTERN-1: canonical pattern + canonical arrival matches (§6 rules 1+2)
- PEER-PATTERN-2: lazy canonicalization on later handshake (§6 rule 3)
- PEER-MUT-1: peer publishes one canonical form per operational window (§8 norm 1)
- PEER-MUT-2: new form arrival not auto-correlated to past forms (§8 norm 5 — T1 floor)
- COMPOSITION-1: cap chain interleaving v7.64-shape and v7.65-shape entities (§2.4)
"""

from __future__ import annotations

import hashlib

import pytest

from entity_core.crypto.identity import (
    HASH_TYPE_IDENTITY,
    HASH_TYPE_SHA256,
    KEY_TYPE_ED25519,
    Keypair,
    _peer_id_from_bytes,
    canonicalize_peer_id,
    derive_peer_from_peer_id,
    derive_peer_id,
    peer_id_from_identity_entity,
    peer_id_from_public_key_bytes,
)


def _legacy_form_for_corpus(pubkey_bytes: bytes) -> str:
    """V7 v7.66 §3.4 corpus-authoring helper — legacy SHA-256-form bytes."""
    return _peer_id_from_bytes(
        pubkey_bytes, key_type=KEY_TYPE_ED25519, hash_type=HASH_TYPE_SHA256,
    )
from entity_core.protocol.auth import (
    compute_peer_identity_hash,
    create_identity_entity,
    create_peer_entity,
)
from entity_core.protocol.entity import Entity


SEED_X = b"\xa0" * 32
SEED_Y = b"\xb0" * 32


# ---------- PEER-CANON-1: content_hash invariance ----------

def test_peer_canon_1_content_hash_invariant_under_wire_form_choice() -> None:
    """For any keypair K, content_hash(system/peer({pubkey, key_type})) is
    invariant — `peer_id` is no longer in the hashable basis (§2.1)."""
    kp = Keypair.from_seed(SEED_X)
    pubkey = kp.public_key_bytes()

    # Build the v7.65 entity directly.
    h_via_create = create_identity_entity(kp).compute_hash()
    h_via_func = compute_peer_identity_hash(public_key=pubkey)
    h_via_peer_entity = create_peer_entity(pubkey).compute_hash()
    h_via_canonical_pid = compute_peer_identity_hash(peer_id=kp.peer_id)

    # All four paths produce the same content_hash.
    assert h_via_create == h_via_func == h_via_peer_entity == h_via_canonical_pid

    # The hashable basis is (public_key, key_type) only — synthesizing the
    # SHA-256-form wire peer_id from the same pubkey must NOT change the hash.
    sha_pid = _legacy_form_for_corpus(pubkey)
    h_via_sha_pid_input = compute_peer_identity_hash(peer_id=sha_pid, public_key=pubkey)
    assert h_via_sha_pid_input == h_via_create


# ---------- PEER-CANON-2: storage-canonicalization on wire receipt ----------

def test_peer_canon_2_canonicalize_peer_id_returns_canonical_on_legacy_input() -> None:
    """§5 carve-out: a non-canonical SHA-256-form wire peer_id is mapped to
    canonical form when the impl has the pubkey at hand (post-handshake)."""
    kp = Keypair.from_seed(SEED_X)
    pubkey = kp.public_key_bytes()
    canonical_pid = kp.peer_id
    legacy_pid = _legacy_form_for_corpus(pubkey)

    # Canonicalize when pubkey is in hand (post-handshake case)
    out = canonicalize_peer_id(legacy_pid, public_key=pubkey)
    assert out == canonical_pid

    # Idempotent: canonical input passes through unchanged.
    assert canonicalize_peer_id(canonical_pid) == canonical_pid


def test_peer_canon_2_canonicalize_returns_none_when_pubkey_unknown() -> None:
    """§5/§6: SHA-256-form peer_id without pubkey cannot canonicalize
    (T1 floor) — caller MUST use lazy-canon path (§6 rule 3)."""
    kp = Keypair.from_seed(SEED_Y)
    legacy_pid = _legacy_form_for_corpus(kp.public_key_bytes())
    # No pubkey supplied + can't derive from SHA-form → None.
    assert canonicalize_peer_id(legacy_pid) is None


# ---------- PEER-MUT-1: peer mints exactly one canonical form ----------

def test_peer_mut_1_keypair_generate_yields_only_canonical_form() -> None:
    """§4 MUST + §8 norm 1: under v7.65 the Keypair construction API mints
    canonical (identity-multihash) form only — no kwarg, no opt-out."""
    kp = Keypair.generate()
    kt, ht, _digest = _decode(kp.peer_id)
    assert kt == KEY_TYPE_ED25519
    assert ht == HASH_TYPE_IDENTITY

    # The legacy construction kwarg is gone.
    with pytest.raises(TypeError):
        Keypair.generate(hash_type=HASH_TYPE_SHA256)  # type: ignore[call-arg]


# ---------- PEER-MUT-2: T1 floor — no cross-form auto-correlation ----------

def test_peer_mut_2_distinct_pubkeys_under_arbitrary_forms_stay_distinct() -> None:
    """§8 norm 5: arrivals under unrelated forms (decoded to distinct pubkeys)
    MUST NOT be auto-correlated to the same identity. Pre-handshake the impl
    has no basis for that correlation (hashes are one-way)."""
    kp_x = Keypair.from_seed(SEED_X)
    kp_y = Keypair.from_seed(SEED_Y)
    assert kp_x.public_key_bytes() != kp_y.public_key_bytes()

    # Their canonical content_hashes diverge (distinct pubkeys → distinct hashes).
    h_x = create_identity_entity(kp_x).compute_hash()
    h_y = create_identity_entity(kp_y).compute_hash()
    assert h_x != h_y

    # Their canonical AND legacy wire peer_ids never collide either
    # (cryptographic independence).
    legacy_x = _legacy_form_for_corpus(kp_x.public_key_bytes())
    legacy_y = _legacy_form_for_corpus(kp_y.public_key_bytes())
    assert kp_x.peer_id != kp_y.peer_id
    assert legacy_x != legacy_y
    assert kp_x.peer_id != legacy_y
    assert kp_y.peer_id != legacy_x


# ---------- COMPOSITION-1: v7.64-shape + v7.65-shape interleaving ----------

def test_composition_1_v7_64_shape_and_v7_65_shape_entities_coexist() -> None:
    """§2.4: pre-v7.65 entities (with peer_id in data) and v7.65 entities
    (without) coexist via distinct content_hashes — both verifiable, no
    hard fork. Cap chains MAY interleave shapes."""
    kp = Keypair.from_seed(SEED_X)

    v7_64_shape = Entity(
        type="system/peer",
        data={
            "peer_id": kp.peer_id,
            "public_key": kp.public_key_bytes(),
            "key_type": "ed25519",
        },
    )
    v7_65_shape = create_identity_entity(kp)

    # Distinct shapes → distinct content_hashes.
    assert v7_64_shape.compute_hash() != v7_65_shape.compute_hash()

    # Both are well-formed dicts and decodable.
    assert v7_64_shape.to_dict()["data"]["public_key"] == kp.public_key_bytes()
    assert v7_65_shape.to_dict()["data"]["public_key"] == kp.public_key_bytes()

    # Pubkey extraction from either shape (the helper looks at data.public_key,
    # which exists in both) yields the same canonical wire peer_id.
    assert peer_id_from_identity_entity(v7_64_shape.to_dict()) == kp.peer_id
    assert peer_id_from_identity_entity(v7_65_shape.to_dict()) == kp.peer_id


# ---------- PEER-PATTERN-1 / PEER-PATTERN-2: cap-pattern + lazy canon ----------
# (These depend on the lazy-canon module in entity_handlers.capability;
# implemented alongside §2.4/§2.5 landing.)

from entity_core.capability.peer_canon import (  # noqa: E402
    PolicyEntryCanonState,
    canonicalize_cap_pattern_peer_refs,
)


def test_peer_pattern_1_canonical_pattern_matches_canonical_arrival() -> None:
    """§6 rule 1 + rule 2: a cap pattern minted with canonical peer_id matches
    a peer arriving under canonical form."""
    kp = Keypair.from_seed(SEED_X)
    pattern = f"/{kp.peer_id}/system/files"
    pubkeys = {kp.peer_id: kp.public_key_bytes()}
    out_pattern, state = canonicalize_cap_pattern_peer_refs(
        pattern, known_pubkeys=pubkeys,
    )
    assert out_pattern == pattern
    assert state == PolicyEntryCanonState.CANONICAL


def test_peer_pattern_2_lazy_canonicalization_path() -> None:
    """§6 rule 3: cap pattern minted with SHA-256-form peer_id for unknown
    peer → state=pending-canonicalization. When peer connects (pubkey
    becomes known), pattern canonicalizes; subsequent matches succeed."""
    kp = Keypair.from_seed(SEED_X)
    legacy_pid = _legacy_form_for_corpus(kp.public_key_bytes())
    pattern = f"/{legacy_pid}/system/files"

    # Mint without pubkey → pending.
    out1, state1 = canonicalize_cap_pattern_peer_refs(pattern, known_pubkeys={})
    assert out1 == pattern
    assert state1 == PolicyEntryCanonState.PENDING

    # Later: pubkey becomes known via handshake → canonicalize in place.
    out2, state2 = canonicalize_cap_pattern_peer_refs(
        pattern,
        known_pubkeys={legacy_pid: kp.public_key_bytes()},
    )
    assert out2 == f"/{kp.peer_id}/system/files"
    assert state2 == PolicyEntryCanonState.CANONICAL


# ---------- Helpers ----------

def _decode(pid: str) -> tuple[int, int, bytes]:
    from entity_core.crypto.identity import decode_peer_id
    return decode_peer_id(pid)
