"""EXTENSION-RELAY v1.0 — cohort byte-equality conformance fixtures.

Python's **independent** ECF byte reference for the relay-envelope entity types
(§3.1 forward-request, §3.2 store-entry, §4.1 advertise), from the cohort fixed
seed (0x42×32). These are pinned so the cross-impl diff round has a concrete
Python artifact to compare against Go + Rust byte dumps — independent
convergence, not a Go follow (per [[feedback_cohort_following_isnt_independent_convergence]]).

If Go's reference disagrees with a pin here, that is a real cross-impl
divergence to route to arch — NOT something to silently re-pin to match Go.

*** LOAD-BEARING — F-PY-RELAY-1: ``envelope_inner`` (and any embedded
``system/hash``) is encoded as a **raw 33-byte byte string** in ``data`` (the
refless norm; same as DISCOVERY ``supersedes``). §3.0 also describes
``<system/hash>`` as the wrapped 2-key form ``ECF({type:"system/hash",
data:H})``. The store-entry hash is fetched cross-impl, so its ECF MUST be
byte-identical — these pins are the tripwire that catches a wrapped-vs-raw
divergence against Go/Rust. ***

All hashes are 33-byte wire form (format byte 0x00 = ECFv1-SHA256 + digest).
"""

from __future__ import annotations

from entity_core.crypto.identity import Keypair
from entity_core.utils.ecf import ecf_encode

from entity_handlers.relay import (
    make_advertise,
    make_forward_request,
    make_inbox_relay,
    make_store_entry,
)

# Fixed-seed fixture peer (deterministic peer_id — shared with DISCOVERY).
SEED = bytes([0x42]) * 32
PEER_ID = "2K62AiVLKtvD3RHVFXmyH6Fc81HPFbzEuKdxUNQd52Y1rH"

# A fixed bare system/hash (33-byte wire form) standing in for the carried
# inner envelope reference (refless raw bytes — F-PY-RELAY-1).
INNER_HASH = bytes([0x00]) + bytes(range(32))
ENDPOINT = {"addresses": ["192.168.1.10"], "port": 9000, "profile_ref": "tcp"}

# --- Pinned ECF + content-hash references (Python, v1.0) -------------------

FORWARD_REQUEST_ECF = (
    "a26464617461a36874746c5f686f7073086b64657374696e6174696f6e782e324b36324169564c"
    "4b7476443352485646586d79483646633831485046627a45754b6478554e51643532593172486e"
    "656e76656c6f70655f696e6e6572582100000102030405060708090a0b0c0d0e0f101112131415"
    "161718191a1b1c1d1e1f6474797065781c73797374656d2f72656c61792f666f72776172642d72"
    "657175657374"
)
FORWARD_REQUEST_HASH = (
    "005bdaaf40e769bfa30b88907c6a3c1647560adce607a415f6a83b0aeb39fa1c5e"
)
STORE_ENTRY_ECF = (
    "a26464617461a3667075745f6279782e324b36324169564c4b7476443352485646586d79483646"
    "633831485046627a45754b6478554e5164353259317248696e616d6573706163656a72656c6179"
    "2d746573746e656e76656c6f70655f696e6e6572582100000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f6474797065781873797374656d2f72656c61792f73746f"
    "72652d656e747279"
)
STORE_ENTRY_HASH = (
    "00d189d830294fb0e9ee896d7d949b24daf9ef3d2e0bf96793f831fa5cafc8769b"
)
ADVERTISE_ECF = (
    "a26464617461a4656d6f6465738261466153666c696d697473a069656e64706f696e747381a364"
    "706f727419232869616464726573736573816c3139322e3136382e312e31306b70726f66696c65"
    "5f726566637463706d636170735f726571756972656481781c73797374656d2f6361706162696c"
    "6974792f72656c61792d706f6c6c64747970657673797374656d2f72656c61792f616476657274"
    "697365"
)
ADVERTISE_HASH = (
    "0092f2117a013d9637e363772a141783d81efb30f84c0ac5b3fc9cd54bf5c7b58e"
)


def test_fixture_peer_id_stable():
    assert Keypair.from_seed(SEED).peer_id == PEER_ID


def test_forward_request_bytes():
    # §3.1: next_hop absent (optional-field-absent convention), ttl_hops + a
    # raw-bytes envelope_inner ref.
    fr = make_forward_request(destination=PEER_ID, envelope_inner=INNER_HASH, ttl_hops=8)
    assert "next_hop" not in fr.data
    assert isinstance(fr.data["envelope_inner"], bytes)
    assert ecf_encode(fr.to_dict(include_hash=False)).hex() == FORWARD_REQUEST_ECF
    assert fr.compute_hash().hex() == FORWARD_REQUEST_HASH


def test_store_entry_bytes():
    # §3.2: expires_at absent; put_by is the Base58 peer_id; envelope_inner raw.
    se = make_store_entry(namespace="relay-test", envelope_inner=INNER_HASH, put_by=PEER_ID)
    assert "expires_at" not in se.data
    assert ecf_encode(se.to_dict(include_hash=False)).hex() == STORE_ENTRY_ECF
    assert se.compute_hash().hex() == STORE_ENTRY_HASH


def test_advertise_bytes():
    # §4.1: modes F+S, one endpoint, one required cap, empty limits.
    ad = make_advertise(
        modes=["F", "S"],
        endpoints=[ENDPOINT],
        caps_required=["system/capability/relay-poll"],
    )
    assert "expires_at" not in ad.data
    assert ecf_encode(ad.to_dict(include_hash=False)).hex() == ADVERTISE_ECF
    assert ad.compute_hash().hex() == ADVERTISE_HASH


# ===========================================================================
# Cross-impl byte convergence — Go RELAY-R5 reference fixtures (4d089b0).
#
# These reproduce Go's `cmd/relay-fixtures` inputs and assert the EXACT Go
# content_hashes. "Rust + Py MUST reproduce byte-for-byte" (handoff §3). This
# is the live Python↔Go convergence lock — confirming F-PY-RELAY-1 resolved to
# raw-bytes-in-data (handoff §4.1: "envelope_inner lives IN the data field,
# NOT a refs block"). The Go hashes are `ecf-sha256:<digest>`; our 33-byte
# wire hash prepends the 0x00 algorithm byte, so we compare `.hex()[2:]`.
# ===========================================================================

GO_FIX_SENDER = "2KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
GO_FIX_RELAY = "2KBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
GO_FIX_DEST = "2KCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
GO_FIX_INNER = bytes([0x00]) + bytes([0xEE]) * 32  # fixHash(0xEE), 33-byte wire form


def _digest(entity) -> str:
    return entity.compute_hash().hex()[2:]  # strip 0x00 algorithm byte


def test_go_F1_forward_request_full():
    fr = make_forward_request(
        destination=GO_FIX_DEST, envelope_inner=GO_FIX_INNER, ttl_hops=5, next_hop=GO_FIX_RELAY
    )
    assert _digest(fr) == "a5f7048f6c5f44ba64c5a3373ded97d77c2600f62236e7e48be3d1cc42a24476"


def test_go_F2_forward_request_no_next_hop():
    fr = make_forward_request(destination=GO_FIX_DEST, envelope_inner=GO_FIX_INNER, ttl_hops=3)
    assert _digest(fr) == "73acd98db5781cbe28ad777628a72696cf9494e0135647888cfc98f918b1d42b"


def test_go_S1_store_entry_full():
    se = make_store_entry(
        namespace=GO_FIX_DEST, envelope_inner=GO_FIX_INNER, put_by=GO_FIX_SENDER,
        expires_at=1730000900000,
    )
    assert _digest(se) == "7170ad83b98218b6e976b1612573ad2f22bd3a6cc07be05aeb954a8cbeadb893"


def test_go_I1_inbox_relay_single_with_expiry():
    decl = make_inbox_relay(
        relays=[{"relay": GO_FIX_RELAY, "namespace": GO_FIX_DEST, "priority": 10}],
        expires_at=1730999999999,
    )
    assert _digest(decl) == "8d2039cbea7ab65ff59fa6ad5055e062c357d3314f8ccfd2ab31c03ef31629b0"


def test_go_I2_inbox_relay_primary_plus_backup_no_expiry():
    decl = make_inbox_relay(
        relays=[
            {"relay": GO_FIX_RELAY, "namespace": GO_FIX_DEST, "priority": 10},
            {"relay": GO_FIX_SENDER, "namespace": GO_FIX_DEST, "priority": 50},
        ],
    )
    assert "expires_at" not in decl.data
    assert _digest(decl) == "9e00962b4b7023e21431cd9d04e00e75fb7b785c602558494a15346e98a336cc"
