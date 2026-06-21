"""EXTENSION-DISCOVERY v1.0 — cohort byte-equality conformance fixtures.

Python's **independent** ECF byte reference for the three discovery entity
types, from a fixed seed (0x42×32, the cohort fixed-seed convention). These
are pinned so the D5 cross-impl diff round has a concrete Python artifact to
compare against Go + Rust byte dumps — independent convergence, not a Go
follow (per [[feedback_cohort_following_isnt_independent_convergence]]).

If Go's D5 reference disagrees with a pin here, that is a real cross-impl
divergence to route to arch — NOT something to silently re-pin to match Go.

All hashes are 33-byte wire form (format byte 0x00 = ECFv1-SHA256 + digest).
"""

from __future__ import annotations

from entity_core.crypto.identity import Keypair, decode_peer_id
from entity_core.utils.ecf import ecf_encode

from entity_handlers.discovery import (
    identity_claim_from_peer_id,
    identity_hint_for_peer_id,
    make_candidate,
    make_decision,
)

# Fixed-seed fixture peer (deterministic peer_id).
SEED = bytes([0x42]) * 32
PEER_ID = "2K62AiVLKtvD3RHVFXmyH6Fc81HPFbzEuKdxUNQd52Y1rH"

# Fixed observation parameters (ms-since-epoch; §2.1).
OBSERVED_AT_0 = 1750000000000
OBSERVED_AT_1 = 1750000001000
DECIDED_AT = 1750000002000
ENDPOINT = {"addresses": ["192.168.1.10"], "port": 9000, "profile_ref": "tcp"}
GRANT_HASH = bytes([0x00]) + bytes(range(32))

# --- Pinned ECF + content-hash references (Python, v1.0) -------------------

# NOTE: encodings are under the ruling-6 optional-field convention — None
# optionals are ABSENT, never CBOR-null. candidate_0 omits peer_id + supersedes;
# the decision below carries grant (non-None) so it is present.
IDENTITY_CLAIM_ECF = (
    "a26464617461a467706565725f6964782e324b36324169564c4b7476443352485646586d7948"
    "3646633831485046627a45754b6478554e5164353259317248686b65795f747970650169686173"
    "685f7479706500717075626c69635f6b65795f64696765737458202152f8d19b791d2445324"
    "2e15f2eab6cb7cffa7b6a5ed30097960e069881db126474797065781f73797374656d2f646973"
    "636f766572792f6964656e746974792d636c61696d"
)
IDENTITY_CLAIM_HASH = (
    "00125653431419dfe923c2074218f28d41f58788a48e1134fbf782b8b32ad98ddf"
)
CAND0_HASH = "00c0a6356363ec95a55168defb0c0a3dda28d45365eaba12a01d4e56f9dc4c592a"
CAND1_HASH = "001ab145efde31bfd5f2cf10068d77b33c5b6bfe8e15a20d092cf4664a2d241b75"
DECISION_HASH = "00625ee9447e35257b1c4fb63fda70f61881248c6a14ea44a0291bd281f48fa9fd"


def test_fixture_peer_id_stable():
    kp = Keypair.from_seed(SEED)
    assert kp.peer_id == PEER_ID
    # V7 §1.5 framing: Ed25519 (0x01), identity multihash (0x00).
    key_type, hash_type, digest = decode_peer_id(PEER_ID)
    assert (key_type, hash_type) == (0x01, 0x00)
    assert digest == kp.public_key_bytes()


def test_identity_claim_bytes():
    ic = identity_claim_from_peer_id(PEER_ID)
    assert ecf_encode(ic.to_dict(include_hash=False)).hex() == IDENTITY_CLAIM_ECF
    assert ic.compute_hash().hex() == IDENTITY_CLAIM_HASH


def test_candidate_pre_identify_bytes():
    # candidate_0: peer_id null (§2.2), identity_hint pinned from the peer-id.
    c0 = make_candidate(
        backend="mdns", observed_at=OBSERVED_AT_0, endpoint_hint=ENDPOINT,
        peer_id=None, identity_hint=identity_hint_for_peer_id(PEER_ID),
    )
    # Ruling 6: None optionals are ABSENT (not CBOR-null). peer_id + supersedes
    # are omitted; identity_hint (non-None) is present.
    assert "peer_id" not in c0.data
    assert "supersedes" not in c0.data
    assert "identity_hint" in c0.data
    assert c0.compute_hash().hex() == CAND0_HASH


def test_successor_candidate_bytes():
    # candidate_1: successor with peer_id populated + supersedes chain head.
    c1 = make_candidate(
        backend="mdns", observed_at=OBSERVED_AT_1, endpoint_hint=ENDPOINT,
        peer_id=PEER_ID, identity_hint=identity_hint_for_peer_id(PEER_ID),
        supersedes=bytes.fromhex(CAND0_HASH),
    )
    assert c1.compute_hash().hex() == CAND1_HASH


def test_decision_bytes():
    d = make_decision(
        candidate=bytes.fromhex(CAND1_HASH), outcome="grant-limited",
        grant=GRANT_HASH, decided_at=DECIDED_AT,
    )
    assert d.compute_hash().hex() == DECISION_HASH
