"""§2.2 rendezvous-key derivation — the six §2.2.1 differential properties.

``PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH`` §2.2 / §2.2.1.

**No authored expected-key vectors exist, by design.** Correctness is settled by
implementations meeting or failing to meet, not by one author's oracle — so §2.2.1
publishes *differential* properties instead, and these are them. Ported from
Rust's ``extensions/signaling/src/tests.rs`` and
``tests/home_format_independence.rs``: the assertions, not the spelling.

Every property here guards a failure that is **invisible same-impl**: a
wrong-but-self-consistent derivation passes a same-impl suite exactly as a correct
one does, because the encoder and the decoder agree with themselves. The symptom
in production is "the peers never meet", with each individual step reporting
success.
"""

from __future__ import annotations

import hashlib
import unicodedata

import pytest

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    ecf_encode,
    get_default_hash_algorithm,
    set_default_hash_algorithm,
)
from entity_handlers.signaling import (
    LOBBY_DEFAULT,
    RENDEZVOUS_KEY_LEN,
    RENDEZVOUS_KEY_TYPE,
    SEP,
    SignalingDecodeError,
    derive,
    key_from_wire,
    lobby_key,
    pair_key,
    rendezvous_payload,
    secret_key,
    tag_key,
)

# ---------------------------------------------------------------------------
# The floor and the width — §2.2.1's "fixed format code" property
# ---------------------------------------------------------------------------


def test_every_key_is_33_bytes_at_the_sha256_floor():
    """A key is always ``0x00 ‖ SHA-256``, whatever the mode.

    Catches an otherwise-correct SHA-384 impl that passes every other
    differential property: it produces a 49-byte key and silently never meets a
    SHA-256-home peer.
    """
    for key in (
        pair_key("alice", "bob"),
        tag_key("chess"),
        secret_key("s3cr3t"),
        lobby_key(LOBBY_DEFAULT),
    ):
        assert len(key) == RENDEZVOUS_KEY_LEN == 33
        assert key[0] == 0x00, "the format code is pinned to the SHA-256 floor"


def test_the_derivation_is_the_pinned_construction():
    """The key equals the §2.2 formula computed independently, byte for byte.

    Recomputed here from primitives (``ecf_encode`` + ``hashlib``) rather than by
    calling the module's own helper, so this pins the *construction* — the
    ``{data, type}`` ECF map, the single CBOR bstr, the plain SHA-256 — and not
    merely that :func:`derive` is self-consistent.
    """
    payload = rendezvous_payload("tag", b"chess")
    expected_digest = hashlib.sha256(
        ecf_encode({"type": RENDEZVOUS_KEY_TYPE, "data": payload})
    ).digest()
    assert tag_key("chess") == bytes([ALG_ECFV1_SHA256]) + expected_digest


def test_the_payload_matches_the_published_stage_bisect_bytes():
    """§2.2.1's stage bisect, for use *after* two impls disagree.

    Published so two disagreeing impls can learn whether they differ on the
    concatenation or on the framing. The digest itself is **deliberately
    unpublished** — see the module docstring on why there are no authored key
    vectors — so this asserts the payload and the CBOR head only.
    """
    payload = rendezvous_payload("tag", b"chess")
    assert payload.hex() == "656e746974793a7264763a76311f7461671f6368657373"
    assert payload == b"entity:rdv:v1\x1ftag\x1fchess"
    assert len(payload) == 23

    # The payload rides as a single CBOR bstr with a minimal-length head:
    # 0x57 = major type 2 (bstr), length 23.
    as_bstr = ecf_encode(payload)
    assert as_bstr[0] == 0x57
    assert as_bstr == bytes([0x57]) + payload


# ---------------------------------------------------------------------------
# §2.2.1 property 1-2 — `pair`
# ---------------------------------------------------------------------------


def test_pair_is_order_independent():
    """The sort makes ``pair(A,B) == pair(B,A)``, so either peer may derive first."""
    assert pair_key("alice", "bob") == pair_key("bob", "alice")


def test_pair_separator_disambiguates_different_pairs():
    """The separator is load-bearing, not decoration.

    Bare concatenation makes ``sorted("ab","c")`` and ``sorted("a","bc")`` both
    yield ``abc``, so two *different* pairs would share one bucket — and each
    pair would think it had met the other.
    """
    assert pair_key("ab", "c") != pair_key("a", "bc")

    # And the reason, pinned at the payload layer so a regression is legible.
    assert rendezvous_payload("pair", b"ab" + bytes([SEP]) + b"c") != (
        rendezvous_payload("pair", b"a" + bytes([SEP]) + b"bc")
    )


# ---------------------------------------------------------------------------
# §2.2.1 property 3-4 — string inputs are byte-exact
# ---------------------------------------------------------------------------


def test_tags_are_case_sensitive():
    """No case-folding: the label is byte-exact UTF-8."""
    assert tag_key("chess") != tag_key("Chess")
    assert tag_key("chess") != tag_key("CHESS")


def test_no_unicode_normalization():
    """§2.2.1 names normalization "the likeliest accidental import".

    Many string libraries normalize by default. ``café`` composed (U+00E9) and
    decomposed (``e`` + U+0301) are *different byte sequences* and MUST derive
    different keys — an impl that normalizes agrees with itself and with nobody
    else.
    """
    composed = "café"
    decomposed = "café"
    # Re-normalized explicitly so the property still holds if an editor or a
    # formatter ever rewrote the literals above into a single form — NFC vs NFD
    # is the whole distinction under test, and it must not be able to go vacuous.
    composed = unicodedata.normalize("NFC", composed)
    decomposed = unicodedata.normalize("NFD", decomposed)
    assert composed != decomposed
    assert len(composed) == 4 and len(decomposed) == 5
    assert composed.encode("utf-8") != decomposed.encode("utf-8")

    assert tag_key(composed) != tag_key(decomposed)
    assert secret_key(composed) != secret_key(decomposed)


# ---------------------------------------------------------------------------
# §2.2.1 property 5 — the modes are separated
# ---------------------------------------------------------------------------


def test_modes_are_separated():
    """One input, four modes, four different keys.

    ``SEP`` after the domain *and* after the mode tag is what guarantees this: a
    ``tag`` named ``x`` and a ``secret`` of ``x`` must not collide, or knowing a
    public label would land you in the bucket gated by a secret.
    """
    same = "x"
    keys = {tag_key(same), secret_key(same), lobby_key(same)}
    assert len(keys) == 3

    # The mode tag cannot be absorbed into the input either: mode="tag",
    # input="x" must differ from any other (mode, input) pair that concatenates
    # to the same bytes.
    assert derive("tag", b"x") != derive("ta", b"gx")
    assert derive("tag", b"x") != derive("tag", b"\x1fx")


def test_the_separator_is_after_the_domain_and_after_the_mode():
    """``SEP`` appears twice, and both positions are pinned."""
    assert rendezvous_payload("tag", b"chess") == (
        b"entity:rdv:v1" + bytes([SEP]) + b"tag" + bytes([SEP]) + b"chess"
    )
    assert rendezvous_payload("tag", b"chess").count(bytes([SEP])) == 2


def test_the_lobby_default_is_a_named_constant():
    """§2.2 Finding B: "per deployment" without an actual named default is a
    silent-never-meet bug, because two peers on the same open node would each
    invent a different input."""
    assert LOBBY_DEFAULT == "lobby:default"
    assert lobby_key(LOBBY_DEFAULT) == lobby_key("lobby:default")
    # An override really does move the bucket — which is why a client calls
    # `advertise` before deriving a lobby key.
    assert lobby_key(LOBBY_DEFAULT) != lobby_key("lobby:chess-night")


# ---------------------------------------------------------------------------
# §2.2.1 property 6 — the load-bearing one, proved against what would break it
# ---------------------------------------------------------------------------


def test_derivation_ignores_the_peers_home_hash_format():
    """The SHA-256 floor holds **regardless of the deriving peer's home format**.

    A content hash is normally self-describing and format-carrying, and that is
    correct everywhere else *because* content is authored once and its hash
    travels with it. A rendezvous key inverts that: it is a lookup token two
    independent parties must reproduce. Let it follow the home format and a
    SHA-384-home peer and a SHA-256-home peer derive different keys for the same
    agreed input and **silently never meet**, with nothing failing loudly.

    What this actually catches is not an arithmetic slip but a *plausible
    refactor*: deriving the key by constructing an ``Entity`` — the
    obvious-looking way, and how every other value in this package is built —
    reads ``get_default_hash_algorithm()`` and is wrong in exactly this invisible
    manner.
    """
    original = get_default_hash_algorithm()
    try:
        set_default_hash_algorithm(ALG_ECFV1_SHA256)
        baseline = [
            pair_key("alice", "bob"),
            tag_key("chess"),
            secret_key("s3cr3t"),
            lobby_key(LOBBY_DEFAULT),
        ]

        # Become a SHA-384-home peer. Everything this process authors from here
        # carries a 49-byte content hash — except the rendezvous key, which MUST
        # NOT move a single byte.
        set_default_hash_algorithm(ALG_ECFV1_SHA384)

        # Sanity: the flip really is in effect, so the assertions below are
        # meaningful rather than vacuously true.
        probe = Entity(type="test/home-format-probe", data={"probe": True})
        probe_hash = probe.compute_hash()
        assert probe_hash[0] == ALG_ECFV1_SHA384, (
            "the home-format flip must actually be live, or this test proves "
            "nothing"
        )
        assert len(probe_hash) == 49

        under_sha384 = [
            pair_key("alice", "bob"),
            tag_key("chess"),
            secret_key("s3cr3t"),
            lobby_key(LOBBY_DEFAULT),
        ]

        for before, after in zip(baseline, under_sha384, strict=True):
            assert before == after, (
                "a SHA-384-home peer must derive byte-identical rendezvous "
                "keys, or it never meets a SHA-256-home peer"
            )
            assert len(after) == RENDEZVOUS_KEY_LEN
            assert after[0] == 0x00
    finally:
        # Leave the process as we found it — this global is shared with every
        # other test in the session.
        set_default_hash_algorithm(original)


# ---------------------------------------------------------------------------
# The edge check — refuse a foreign key of the wrong width, loudly
# ---------------------------------------------------------------------------


def test_key_from_wire_accepts_exactly_33_bytes():
    key = tag_key("chess")
    assert key_from_wire(key) == key


@pytest.mark.parametrize("width", [0, 32, 34, 49])
def test_key_from_wire_refuses_a_wrong_width(width: int):
    """Converts a silent never-meet into a visible error at the first request.

    49 bytes is the interesting one: that is what an otherwise-correct SHA-384
    implementation produces.
    """
    with pytest.raises(SignalingDecodeError):
        key_from_wire(b"\x00" * width)


# ---------------------------------------------------------------------------
# The cross-impl witness — keys go and py were observed to agree on
# ---------------------------------------------------------------------------

#: The full 33-byte keys the **Go** client derives for these inputs,
#: **re-derived live from ``entity-core-go`` @ ``94b6583`` on 2026-08-05** by
#: running its ``ext/signaling`` (``TagKey`` / ``SecretKey`` / ``LobbyKey`` /
#: ``PairKey``) over these exact inputs — not copied from a dated report.
#:
#: These SUPERSEDE the values recorded on 2026-07-30 (``entity-core-go`` @
#: ``989366c``), and the supersession is itself the finding: §13 open item #1
#: resolved the message namespace to ``system/signaling/*`` on 2026-08-02, the
#: derivation hashes the literal type string, so **every key changed**. Go and
#: Rust flipped; this client did not until 2026-08-05, and in between it agreed
#: with itself, reproduced the §2.2.1 stage-bisect payload byte-for-byte (the
#: payload carries no type string), and could not have met either of them.
#: That is the "silent never-meet" §3.1 exists to prevent, caught by exactly
#: the re-diff the stage-1 handoff's §7 promised.
#:
#: **Not an authored oracle** — the module docstring's point stands: no one is
#: entitled to publish "the right key" and have the others conform. These are a
#: *witness*, recorded after the fact, of what two independently written clients
#: were observed to produce. What they buy is direction: the differential
#: properties above catch a derivation that disagrees with itself, and these
#: catch a derivation that still agrees with itself but has drifted away from
#: the other impl — which is the failure that ends in "the peers never meet".
#:
#: If one of these ever fails, the answer is **not** to update the constant.
#: Either this client changed and go did not, or the committed spec landed and
#: says something else — both are findings. The 2026-08-05 update was the
#: second case, and it was resolved by re-diffing against the committed spec
#: (which Go and Rust already matched), not by trusting the newer number.
GO_AGREED_KEYS = {
    ("tag", "chess"): "00413829262cbc829de13f9230f4f6a2b3fe649f2d3e7df8b6a7f4934f189373c6",
    ("tag", "probe-tag"): "00a59d8da5a1813062a01e29b5fe474bd5814d77a0a6d4c44c104b5dd1a1362814",
    ("secret", "hunter2"): "000f130cd3967e3717e22b4622b023222d9f9b99862696e4119cb17bd13a43ccc2",
    ("lobby", LOBBY_DEFAULT): "00937b8835b427757b8a909a8d7229ee1f5d563af027400470e135064a0f3831d5",
    ("pair", "peerAAA|peerBBB"): "003bd617889d2bab865dd61142295df1289a2ec50570b90ace245475288c6f9cc6",
}


@pytest.mark.parametrize(
    ("mode", "spec"), sorted(GO_AGREED_KEYS), ids=lambda v: v.replace("|", "-")
)
def test_this_client_still_derives_the_key_go_derived(mode: str, spec: str):
    """Go's §1 table, re-derived here rather than taken on trust."""
    if mode == "tag":
        key = tag_key(spec)
    elif mode == "secret":
        key = secret_key(spec)
    elif mode == "lobby":
        key = lobby_key(spec)
    else:
        key = pair_key(*spec.split("|"))
    assert key.hex() == GO_AGREED_KEYS[(mode, spec)], (
        "this client and the Go client no longer derive the same rendezvous "
        "key — they will land in different buckets and never meet"
    )


def test_the_pair_key_go_agreed_on_is_the_same_from_either_side():
    """§2.2's sort-and-separate canonicalization, cross-checked: go recorded one
    key for ``pair(peerAAA, peerBBB)``, and an initiator naming the peers in the
    other order must produce it too — otherwise a pair meets only when both
    happen to sort the same way."""
    agreed = GO_AGREED_KEYS[("pair", "peerAAA|peerBBB")]
    assert pair_key("peerAAA", "peerBBB").hex() == agreed
    assert pair_key("peerBBB", "peerAAA").hex() == agreed
