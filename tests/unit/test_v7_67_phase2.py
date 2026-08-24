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

THE M3/M6 RE-STAMP — SEEDS §5 step 3, py's arm  [2026-08-12]
------------------------------------------------------------
`ENTITY-CORE-PROTOCOL` §4.5a **item 1a** (v7.77) pins `system/peer` to the
ECFv1-SHA-256 floor unconditionally — every connection, whatever the active
format, whatever the peer's home format — and it landed *after* the M3/M6 rows
were stamped. So M3-A and M6-A's identity hashes moved from SHA-384-form
(`01…`, 49 B) to floor-form (`00…`, 33 B), and everything downstream of them
moved with them. `entity-core-go` found the corpus half by running their
verifier (`49 PASS, 6 FAIL`) and proposed six replacements; arch found the other
half by reading `SEEDS.md` §2.4 itself, which had gone stale in the same way.

**py's independent derivation is byte-equal to go's on all six**, run through
py's own serialization path at this commit. One cause, and the CBOR shows it:
the ONLY delta in the M3/M6 cap data is the `granter` bstr, `5831 01…` → `5821
00…`. Every `peer_b` value is untouched, because peer_b was already at the floor
and 1a did not move it.

Two things worth carrying back to the cohort:

1. **Go's re-stamp values are `0x80`-form.** py's spec-correct empty-array
   derivation matches go's proposed M3/M6 cap content hashes and signatures
   exactly — so whatever produced them had already left the `0xf6` null cascade
   behind, and M3/M6 are now 3-of-3 on the empty-include canonical. Only M2's
   last *published* go pin is still the null form; M2 has no SHA-384 row, so it
   was never in the six and was never re-derived.
2. **This file had go's own bypass.** `_peer` hand-assembled `{type, data}` and
   hashed under the row's home format, routing around the pinned constructor —
   the same shape as the `hash-format-sha-384.2.rehash` vector go flagged for
   staying green while asserting a construction 1a forbids. py *implemented* 1a
   at `7b89a5e` and this derivation kept producing pre-1a values anyway, because
   nothing connected the two. It now goes through `create_identity_entity`.
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
from entity_core.protocol.auth import create_identity_entity
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    compute_ecf_hash,
    ecf_encode,
)

H256, H384 = ALG_ECFV1_SHA256, ALG_ECFV1_SHA384


def _peer(kind: str, seed: bytes, home_fmt: int):
    """Build a peer from a raw RFC-8032 seed; return (keypair, pubkey, peer_id,
    content_hash).

    **The content hash is FLOOR-form regardless of `home_fmt`** — V7 v7.77
    §4.5a item 1a pins `system/peer` to ECFv1-SHA-256 unconditionally, and
    `home_fmt` survives here only as the row's declared home format (the thing
    the pin overrides), so the M3/M6 rows still say out loud what they are.

    And it is computed **through the pinned constructor**, not hand-built.
    That is not a style preference: go's re-stamp proposal names a vector of
    theirs that stayed green while asserting a construction 1a forbids, purely
    because its verifier hand-built the entity and routed around the code that
    would have refused it — *"a vector that exercises a forbidden construction,
    and passes because it routes around the code that would forbid it, is worse
    than a failing vector; it certifies the opposite of the rule."* This helper
    had the same bypass: it hand-assembled `{type, data}` and hashed under
    `home_fmt`, so it kept producing SHA-384-form M3/M6 identity hashes for a
    month after `7b89a5e` landed 1a in the implementation it was supposedly
    checking. The derivation and the peer had silently forked.
    """
    if kind == "ed25519":
        kp = Keypair.from_seed(seed)
        kt_int = KEY_TYPE_ED25519
    else:
        kp = Ed448Keypair.from_seed(seed)
        kt_int = KEY_TYPE_ED448
    pub = kp.public_key_bytes()
    peer_id = peer_id_from_public_key_bytes(pub, key_type=kt_int)
    content_hash = create_identity_entity(kp).compute_hash()
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
        a_ch="00af37ab940c4fd3f26d85d1e52343ca6a77b7698191553aee815650beaee92d41",
        b_pub="6355691c178a8ff91007a7478afb955ef7352c63e7b25703984cf78b26e21a56",
        b_pid="2KATqnFJZboriNzCpVQ6nx7oCtc2qcTBToin4muxqo3ja5",
        b_ch="00bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040",
    ),
    "M6": dict(
        a_pub="ac3699dd5c3fb9461bf18ae2f943b129aa60d388ceb40be0b33cc1c37083faf2ed062cc7727376eae9afbdc66f433830abd5d93b64c0874780",
        a_pid="3dWKQXt2foyNFwZ7iyvXxiKLwnLHQZzdsdEpdzdYhP5aZD",
        a_ch="00848e208deeb0b0523fe486f49da12b9e530c40d8d2795feb6ce663f5d517058e",
        b_pub="e28a8970753332bd72fef413e6b0b2ef1b4aadda7aa2c141f233712a6876b351",
        b_pid="2KK2QYVGptXdChBXoNcXWhfaGRik85xSpefSeL4tPzkeye",
        b_ch="0056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335",
    ),
}

# Gates 5-7 — the SPEC-CORRECT cap-layer pins (empty include = 0x80).
# M2 is Rust's, from the V7.67 phase-2 Rust byte-pins §3.1, unchanged: M2 has
# no SHA-384 row, so item 1a did not touch it, and go's last published M2 pin is
# still the 0xf6 null form (see _GO_OUTLIER_CAP_CH).
# M3/M6 are **re-derived under §4.5a item 1a** and byte-equal to go's re-stamp
# proposal (assertions 2/3/5/6 of the six) — so go's re-stamp is 0x80-form and
# the null cascade is gone from those two rows in both trees.
_CAP_PINS_SPEC_CORRECT = {
    "M2": dict(
        cap_cbor="a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e746565582100f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b676772616e7465725821002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c707486a637265617465645f6174006a657870697265735f617400",
        cap_ch="0095852ce2ad1fa6ec97cf827413a328a1ca531a37984952a0f5f215c305b6e2ba",
        sig="6104711f3ba43ade204001ca3146c154b825b0db45a6be6811735bcbbc75da4e2cf5c6a69efb9d3bae3503b21164fd75e5b74f635c74f14f007381e23af338cb98afc299d45406956a029fb1bbfd418eff85ef2908467a56e549f4dbc74d50ca344ff0c1142770df68f956eccc3a5e023200",
    ),
    "M3": dict(
        cap_cbor="a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e746565582100bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040676772616e746572582100af37ab940c4fd3f26d85d1e52343ca6a77b7698191553aee815650beaee92d416a637265617465645f6174006a657870697265735f617400",
        cap_ch="009b78514a0c74a757e622daca3f8f64093d32911970135954136b65d7cb39986a",
        sig="c31dcf78a26b40d83a19d4e15d90788e25193672e00a28ad68f26278afeac2b8c9e645dfb3ef0e83485360d703eb823b25c3f37da5430028c00b286aad123805",
    ),
    "M6": dict(
        cap_cbor="a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e74656558210056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335676772616e746572582100848e208deeb0b0523fe486f49da12b9e530c40d8d2795feb6ce663f5d517058e6a637265617465645f6174006a657870697265735f617400",
        cap_ch="0096d69daadcf8663c1a21efc39fae9c12472018804dc659c6f55bdeafadc04f50",
        sig="ea07a4a64dcb13078b75189034380ffcb94b88e25302cda22b62c07eb90a3632b20f5c9f4c13546bf23ffc14bf1ebe51d89cbc0818df65b980b511949b759f20e7e7f4d1750db840333a339b1bbffade9675e8fbe3935214173f33ecdd8c02e442c2970d33a2509db56e9d9ce42b7abd1200",
    ),
}

# Go's PUBLISHED gate-6 cap content_hash (the outlier, null-cascade). Pinned so
# the test asserts Python is DISTINCT from it — the negative half of the vote.
# For M3/M6 these are now doubly stale (null cascade AND pre-1a) and go's own
# re-stamp has left them; keeping them asserts the value did not drift back.
_GO_OUTLIER_CAP_CH = {
    "M2": "00298eb285d70b99d86bda819104535b3c2dcebbb4964ddf0987183ff758e0e2a2",
    "M3": "006572b77ccf6d6621b9a6c6f2745d362f8b763756efcf34c35fde14e32b464969",
    "M6": "00a4c408644595d96b1bc71e3ffce55491a0ca22e0c4980be0ca5b8a1505712739",
}


@pytest.mark.parametrize("name", ["M3", "M6"])
def test_item_1a_the_sha384_rows_are_floor_form(name: str):
    """§4.5a item 1a — the SHA-384-home rows' identity hash is FLOOR-form.

    The rule, asserted directly rather than only through a byte pin: M3-A and
    M6-A declare `content_hash_format = 0x01` as their home, and their
    `system/peer` hash is `00…`/33 B anyway, because 1a carves this one type
    out of the home format entirely (its data is wholly recoverable from the
    public peer-id, so every consumer derives it rather than fetching it).

    This is the check that was missing. The six stale expectations were found
    by a *verifier run*, and the stale `SEEDS.md` §2.4 sentence behind them by
    someone reading prose while ruling on that run — because a red fixture is
    visible and a stale sentence is not. A rule asserted as a rule is visible
    from either direction: re-stamping a pin cannot make this pass, and moving
    the pin back cannot make it fail quietly.

    It also names the field that can no longer exist: the corpus's
    `expected_peer_a_content_hash_sha384` is a misnomer under 1a — that value
    can never again be SHA-384, and SEEDS §2.6 always called it
    `peer_a_content_hash`.
    """
    m = _MATRIX[name]
    assert m["a"][2] == H384, "this row is supposed to declare a SHA-384 home"
    _, _, _, a_ch = _peer(*m["a"])
    assert a_ch[0] == 0x00, (
        f"{name}-A identity hash is {a_ch[:1].hex()}-form; item 1a pins "
        "system/peer to the ECFv1-SHA-256 floor whatever the home format"
    )
    assert len(a_ch) == 33
    # And the home format is genuinely live on this row — the pin is an
    # exception to §1.2, not a peer that simply has no SHA-384 anywhere.
    assert len(compute_ecf_hash({"type": "x", "data": {}}, algorithm=H384)) == 49


@pytest.mark.parametrize("name", ["M2", "M3", "M6"])
def test_phase2_gates_1_to_4_identity_layer_byte_equal(name: str):
    """Gates 1-4: public_key, peer_id, and content_hash byte-equal across all
    three impls (the peer-identity layer). M3-A / M6-A are the re-stamped
    floor-form values, byte-equal to go's independently-derived replacements."""
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
