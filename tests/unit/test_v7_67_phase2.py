"""v7.67 Phase-2 matrix byte pins — Python cohort round-trip (deciding vote).

Parallel to Go's `cmd/v767-phase2-pins/main.go` and Rust's
`core/peer/tests/cohort_compare_v767_phase2.rs`. Derives MATRIX-M2/M3/M6 from
the SEEDS.md §2.1 seeds through Python's OWN serialization path and pins every
SEEDS §7 cross-impl gate.

THE DECISION THIS FILE RECORDS
------------------------------
Rust's round-trip (the V7.67 phase-2 Rust byte-pins §3) found that Go's
gate-5 pins encode the unconstrained `handlers`/`operations` `include` as CBOR
`null` (`0xf6`), while the spec-correct form is an empty array `[]` (`0x80`):
the locked v1 ECF corpus pins `[]→h'80'` (length.1) and `null→h'f6'`
(primitive.1) as DISTINCT canonical forms, and ENTITY-CBOR-ENCODING §232 forbids
dropping fields. Go's `f6` is a `[]string(nil)→CBOR null` artifact of its
`GrantEntry`, not a spec mandate.

Python's encoder (`CapabilityScope.to_dict` → `{"include": self.include}`,
`token.py:90`) emits the empty list as `[]` → `0x80`. This test asserts Python's
derivation is byte-equal to **Rust's spec-correct pins** on all 7 gates, making
it 2-of-3 (Rust + Python) for `0x80`. Go is the outlier and regenerates its
gate-5/6/7 pins; architecture rules on the empty-scope canonical before the
SEEDS §5 step-4 `.diag` fold.

Gates 1-4 (peer-identity layer) are byte-equal across ALL THREE impls; they are
pinned here against the shared Go==Rust values.
"""

from __future__ import annotations

import pytest

from entity_core.capability.token import CapabilityScope, CapabilityToken, Grant
from entity_core.crypto.ed448 import Ed448Keypair
from entity_core.crypto.identity import (
    KEY_TYPE_ED25519,
    KEY_TYPE_ED448,
    Keypair,
    peer_id_from_public_key_bytes,
)
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    compute_ecf_hash,
    ecf_encode,
)

H256, H384 = ALG_ECFV1_SHA256, ALG_ECFV1_SHA384


def _peer(kind: str, seed: bytes, home_fmt: int):
    """Build a peer from a raw RFC-8032 seed; return (keypair, pubkey, peer_id,
    home-format content_hash)."""
    if kind == "ed25519":
        kp = Keypair.from_seed(seed)
        kt_str, kt_int = "ed25519", KEY_TYPE_ED25519
    else:
        kp = Ed448Keypair.from_seed(seed)
        kt_str, kt_int = "ed448", KEY_TYPE_ED448
    pub = kp.public_key_bytes()
    data = {"key_type": kt_str, "public_key": pub}
    peer_id = peer_id_from_public_key_bytes(pub, key_type=kt_int)
    content_hash = compute_ecf_hash({"type": "system/peer", "data": data}, algorithm=home_fmt)
    return kp, pub, peer_id, content_hash


def _root_cap(a_home_hash: bytes, b_home_hash: bytes):
    """SEEDS §2.3 root cap A→B. `resources` constrained; `handlers`/`operations`
    unconstrained (empty include). Returns (cap_data_cbor, cap_content_hash)
    with the cap-token entity authored under the ACTIVE format (SHA-256)."""
    grant = Grant(
        handlers=CapabilityScope(include=[]),
        resources=CapabilityScope(include=["system/validate/matrix/*"]),
        operations=CapabilityScope(include=[]),
    )
    tok = CapabilityToken(
        grants=[grant],
        granter=a_home_hash,   # single-sig → CBOR bstr (major type 2)
        grantee=b_home_hash,
        created_at=0,
        expires_at=0,          # serialized as 0 (SEEDS §2.3), not omitted
        parent=None,           # root cap → omitted from the map
        not_before=None,
    )
    entity = tok.to_entity()                                   # {type, data}
    cap_data_cbor = ecf_encode(entity["data"])
    cap_content_hash = compute_ecf_hash(entity, algorithm=H256)  # active = SHA-256
    return cap_data_cbor, cap_content_hash


# SEEDS.md §2.1 keypair seeds + §2.4 per-peer home formats.
_MATRIX = {
    "M2": dict(a=("ed448",   bytes([0x42]) * 57, H256), b=("ed25519", bytes([0x43]) * 32, H256)),
    "M3": dict(a=("ed25519", bytes([0x44]) * 32, H384), b=("ed25519", bytes([0x45]) * 32, H256)),
    "M6": dict(a=("ed448",   bytes([0x46]) * 57, H384), b=("ed25519", bytes([0x47]) * 32, H256)),
}

# Gates 1-4 — byte-equal across ALL THREE impls (Go §§3/4/5 == Rust §2).
_IDENTITY_PINS = {
    "M2": dict(
        a_pub="2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00",
        a_pid="3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4",
        a_ch="002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748",
        b_pub="22fc297792f0b6ffc0bfcfdb7edb0c0aa14e025a365ec0e342e86e3829cb74b6",
        b_pid="2K68ekpdm3sTCUfTs39tpNxowivTsXpRsukodvtqwZmudX",
        b_ch="00f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b",
    ),
    "M3": dict(
        a_pub="d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48",
        a_pid="2KJGifeh6LynPNnmyQqHrugjm7iW8YPQ4VpWSGgYvHp2VM",
        a_ch="0166f421381111d3c861787a6e233c9cbc1a652093a472c177d6e4bdec0ed95e3873f9f482c282b781f7c44b4ff91b2c59",
        b_pub="6355691c178a8ff91007a7478afb955ef7352c63e7b25703984cf78b26e21a56",
        b_pid="2KATqnFJZboriNzCpVQ6nx7oCtc2qcTBToin4muxqo3ja5",
        b_ch="00bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040",
    ),
    "M6": dict(
        a_pub="ac3699dd5c3fb9461bf18ae2f943b129aa60d388ceb40be0b33cc1c37083faf2ed062cc7727376eae9afbdc66f433830abd5d93b64c0874780",
        a_pid="3dWKQXt2foyNFwZ7iyvXxiKLwnLHQZzdsdEpdzdYhP5aZD",
        a_ch="01ef28f9251ac8d26ee0a520b96b19cb93205a1923a238ef903b07b896738396faafc4be2d1d7d77dee0a53c992584f9cd",
        b_pub="e28a8970753332bd72fef413e6b0b2ef1b4aadda7aa2c141f233712a6876b351",
        b_pid="2KK2QYVGptXdChBXoNcXWhfaGRik85xSpefSeL4tPzkeye",
        b_ch="0056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335",
    ),
}

# Gates 5-7 — Rust's SPEC-CORRECT cap-layer pins (empty include = 0x80).
# The V7.67 phase-2 Rust byte-pins §3.1. Go's published values differ
# (null 0xf6 cascade) and are slated for regeneration.
_CAP_PINS_SPEC_CORRECT = {
    "M2": dict(
        cap_cbor="a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e746565582100f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b676772616e7465725821002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c707486a637265617465645f6174006a657870697265735f617400",
        cap_ch="0095852ce2ad1fa6ec97cf827413a328a1ca531a37984952a0f5f215c305b6e2ba",
        sig="6104711f3ba43ade204001ca3146c154b825b0db45a6be6811735bcbbc75da4e2cf5c6a69efb9d3bae3503b21164fd75e5b74f635c74f14f007381e23af338cb98afc299d45406956a029fb1bbfd418eff85ef2908467a56e549f4dbc74d50ca344ff0c1142770df68f956eccc3a5e023200",
    ),
    "M3": dict(
        cap_cbor="a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e746565582100bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040676772616e74657258310166f421381111d3c861787a6e233c9cbc1a652093a472c177d6e4bdec0ed95e3873f9f482c282b781f7c44b4ff91b2c596a637265617465645f6174006a657870697265735f617400",
        cap_ch="0053016041ab2f1b3826175cb8e6576d166969315beaed249e071abeb5e1808cbe",
        sig="05a6170bbf1eb188ee7423c7f989f5da668b043eb3d1d3a20c389979549931053d64fa56d3cbd0d35fbe0161c72b3044b485882bd1716e5d667b56a369b36100",
    ),
    "M6": dict(
        cap_cbor="a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e74656558210056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335676772616e746572583101ef28f9251ac8d26ee0a520b96b19cb93205a1923a238ef903b07b896738396faafc4be2d1d7d77dee0a53c992584f9cd6a637265617465645f6174006a657870697265735f617400",
        cap_ch="004ae3ec9d8999658ab164d454de81399bac3752fb3a7465120fe933621a41eab8",
        sig="547e8bf136b104228b1bb551e143e85a8585562b8b0a4a1791688cc3778ee41d7ebe305d5e5f387262dac8a7c722260affeb9bd42f1b707c8042b2aab14f73996f153e00c05b0243fad15121b0ec70f5d160f553979f332b5b6b392ef0617d2e345998b44c8503168d6cc584687759482d00",
    ),
}

# Go's published gate-6 cap content_hash (the outlier, null-cascade). Pinned so
# the test asserts Python is DISTINCT from Go — the negative half of the vote.
_GO_OUTLIER_CAP_CH = {
    "M2": "00298eb285d70b99d86bda819104535b3c2dcebbb4964ddf0987183ff758e0e2a2",
    "M3": "006572b77ccf6d6621b9a6c6f2745d362f8b763756efcf34c35fde14e32b464969",
    "M6": "00a4c408644595d96b1bc71e3ffce55491a0ca22e0c4980be0ca5b8a1505712739",
}


@pytest.mark.parametrize("name", ["M2", "M3", "M6"])
def test_phase2_gates_1_to_4_identity_layer_byte_equal(name: str):
    """Gates 1-4: public_key, peer_id, and home-format content_hash byte-equal
    across all three impls (the peer-identity layer; SHA-384 substrate parity
    for M3-A / M6-A)."""
    m = _MATRIX[name]
    exp = _IDENTITY_PINS[name]
    _, a_pub, a_pid, a_ch = _peer(*m["a"])
    _, b_pub, b_pid, b_ch = _peer(*m["b"])
    assert a_pub.hex() == exp["a_pub"], "gate 1 A.public_key"
    assert a_pid == exp["a_pid"], "gate 2 A.peer_id"
    assert a_ch.hex() == exp["a_ch"], "gate 4 A.home content_hash"
    assert b_pub.hex() == exp["b_pub"], "gate 1 B.public_key"
    assert b_pid == exp["b_pid"], "gate 2 B.peer_id"
    assert b_ch.hex() == exp["b_ch"], "gate 4 B.home content_hash"


@pytest.mark.parametrize("name", ["M2", "M3", "M6"])
def test_phase2_gate5_empty_include_is_0x80_not_null(name: str):
    """Gate 5 (DECISIVE): the unconstrained handlers/operations `include`
    encodes as CBOR empty array `0x80`, NOT Go's `0xf6` (null). Python's full
    cap-data CBOR is byte-equal to Rust's spec-correct pin."""
    m = _MATRIX[name]
    _, _, _, a_ch = _peer(*m["a"])
    _, _, _, b_ch = _peer(*m["b"])
    cap_cbor, _ = _root_cap(a_ch, b_ch)
    assert cap_cbor.hex() == _CAP_PINS_SPEC_CORRECT[name]["cap_cbor"], (
        "cap-data CBOR must be byte-equal to Rust's spec-correct pin"
    )
    # The literal CBOR byte following `handlers: {include:` MUST be 0x80.
    marker = "6868616e646c657273a167696e636c756465"  # "handlers" {"include"
    include_byte = cap_cbor.hex().split(marker, 1)[1][:2]
    assert include_byte == "80", (
        f"empty include MUST be 0x80 (empty array), got 0x{include_byte} "
        "(0xf6 would be Go's spec-incorrect null form)"
    )


@pytest.mark.parametrize("name", ["M2", "M3", "M6"])
def test_phase2_gates_6_7_cap_hash_and_sig_match_rust_not_go(name: str):
    """Gates 6-7: cap-token content_hash (active SHA-256) and A's signature are
    byte-equal to Rust's spec-correct pins and byte-DISTINCT from Go's outlier
    (which cascades from the 0xf6 cap-data delta)."""
    m = _MATRIX[name]
    a_kp, _, _, a_ch = _peer(*m["a"])
    _, _, _, b_ch = _peer(*m["b"])
    _, cap_ch = _root_cap(a_ch, b_ch)
    sig = a_kp.sign(bytes(cap_ch))
    spec = _CAP_PINS_SPEC_CORRECT[name]
    assert cap_ch.hex() == spec["cap_ch"], "gate 6 cap content_hash == Rust"
    assert sig.hex() == spec["sig"], "gate 7 signature == Rust"
    assert cap_ch.hex() != _GO_OUTLIER_CAP_CH[name], (
        "gate 6 MUST differ from Go's null-cascade outlier"
    )
