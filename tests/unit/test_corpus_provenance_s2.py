"""`S-2` — what the corpus re-pin means at this seat, measured rather than assumed.

.. rubric:: The instruction, and why it does not apply here

`entity-core-go`'s ``ROUTING-2026-09-16-d`` tells both sibling seats::

    When the digest publishes, re-pin your corpus references to `16861cd0…`.
    The other 68 vectors are unchanged, so nothing else in your corpus
    handling moves.

Measured before replying: **this repo pins no corpus digest at all**, and the
reason is sharper than the instruction assumes. py's conformance harness does
not consume the published artifact. It reads a **local, pre-cross-bless
STARTER corpus** at ``test-vectors/v1/conformance-vectors-v1.diag``, whose own
header says so::

    Status: STARTER — pre-cross-bless. Inputs are authored; `canonical`
            fields for `encode_equal` vectors are left as h'' and get filled
            in by the cross-impl byte-equality round per Appendix E §E.4.

So `S-2` is a **no-op at this seat**, and the fact that it is a no-op is the
finding — not a clean bill.

.. rubric:: ⭐ py DOES execute Class B — and compares the result to nothing

⛔ **The first draft of this file asserted py's corpus had no ``signature``
category. Its own first run refuted that** (the standing *a gate's first act
should be able to correct its author* shape). py's starter carries the same
eleven categories as the published corpus, ``signature.1``–``.3`` included;
it is **69 vs 71** only because two ``nested`` vectors were added upstream.

What it does not carry is **answers**. Every ``encode_equal`` vector's
``canonical`` is ``h''`` — the header says so — so ``emit_canonical``
*computes* 64 canonicals, including the three Class-B signature
constructions, and **compares them to nothing**.

That is the sharper version of arch's ⚠ — *"reading a normative artifact and
running it are different acts, and only one of them is a measurement."* py
runs the Class-B construction on every suite invocation and has never
measured it, because an unfilled expected value cannot disagree. It is why
`SA`-adjacent defect ``_emit_signature`` signed the **losing** reading
undetected until `CQ-22` was read against the source
(``test_signature_message_is_the_content_hash_cq22.py``).

.. rubric:: Why this is pinned rather than fixed in the same commit

Adopting the published corpus **today** would import ``signature.1``–``.3``,
which arch's corpus ``CHANGELOG`` marks **KNOWN-DIVERGENT** in the same
revision, and go's relay carries an explicit ⛔ *"do NOT re-pin yet"* gate
pending the cross-bless and the protocol land. Syncing now would make this
seat the fourth implementation of a reading `0.8.2.26` withdrew.

**Retirement condition, in writing** (the standing rule — *a deferral without
a retirement condition is an omission with better prose*): when
`entity-core-protocol` lands the rebuilt ``.cbor`` at
``16861cd06be9d2dca71137f55551d693538d3b1885f581ab55eb3541f63b00b6``, this
seat adopts the **published** corpus and these rows retire together.
"""

from __future__ import annotations

from pathlib import Path

from entity_core.conformance import load_corpus

CORPUS_PATH = (
    Path(__file__).resolve().parents[2]
    / "test-vectors"
    / "v1"
    / "conformance-vectors-v1.diag"
)

#: The digest `S-1` will publish. py does NOT pin this yet — see the module
#: docstring. Named here so the day someone re-pins, the grep lands.
S1_PENDING_DIGEST = (
    "16861cd06be9d2dca71137f55551d693538d3b1885f581ab55eb3541f63b00b6"
)

#: The digest the published artifact carries today, and which arch's corpus
#: CHANGELOG marks known-divergent on the `signature` category.
S1_SUPERSEDED_DIGEST = (
    "9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc"
)


class TestTheCorpusThisSeatActuallyRuns:
    """Today's answer, with the retirement condition in the assertions."""

    def test_this_seat_runs_the_local_STARTER_corpus_not_the_published_one(self):
        corpus = load_corpus(str(CORPUS_PATH))
        assert len(corpus) == 69, (
            "py's conformance harness loads the local pre-cross-bless starter "
            f"corpus ({len(corpus)} vectors). The PUBLISHED corpus carries 71 "
            "— the same eleven categories plus two more `nested` vectors. If "
            "this number moved because the published corpus was adopted, "
            "retire this file — and "
            f"pin the digest ({S1_PENDING_DIGEST[:12]}…) while you are here."
        )

    def test_the_class_B_vectors_are_present_but_have_NO_expected_bytes(self):
        """⭐ The row that states why running Class B here measured nothing.

        py computes all three signature constructions on every suite run. The
        corpus carries ``h''`` for each, so the emission is never compared —
        which is exactly how ``_emit_signature`` shipped the losing reading.

        **Retirement condition:** when the published corpus is adopted (S-2),
        these canonicals arrive filled and this row flips to a byte-equality
        assertion. py is a legitimate second independent codec for `S-1`
        item 4 — independent decoder, independent ECF encoder, RFC 8032
        Ed25519 — and SHOULD be offered as one.
        """
        corpus = load_corpus(str(CORPUS_PATH))
        sigs = [v for v in corpus if v["id"].startswith("signature.")]
        assert len(sigs) == 3, "the Class-B signature category moved"
        for v in sigs:
            assert v.get("canonical", b"") == b"", (
                f"{v['id']} now carries expected bytes. The corpus was "
                "adopted or filled — retire this row and assert byte "
                "equality against the emitter instead."
            )

    def test_the_two_kinds_are_the_starter_corpus_shape(self):
        """The control: the starter corpus's two KINDS, so a later reader can
        tell a corpus swap from a `load_corpus` filtering change."""
        corpus = load_corpus(str(CORPUS_PATH))
        assert {v["kind"] for v in corpus} == {"encode_equal", "decode_reject"}

    def test_this_repo_pins_no_corpus_digest_yet(self):
        """`S-2` is a no-op here, asserted so it cannot quietly become one.

        Monotone in the useful direction: the day a digest literal lands in
        the tree, this row fails and whoever added it is told which digest is
        the blessed one and which is superseded.
        """
        tree = Path(__file__).resolve().parents[2]
        hits = []
        for path in list(tree.glob("packages/**/*.py")) + list(
            tree.glob("tests/**/*.py")
        ):
            if path.name == Path(__file__).name:
                continue
            text = path.read_text(errors="ignore")
            if S1_SUPERSEDED_DIGEST in text or S1_PENDING_DIGEST in text:
                hits.append(str(path.relative_to(tree)))
        assert not hits, (
            f"a corpus digest is now pinned in {hits}. If this is the S-1 "
            f"re-pin, the blessed digest is {S1_PENDING_DIGEST} and "
            f"{S1_SUPERSEDED_DIGEST} is SUPERSEDED (known-divergent on the "
            "`signature` category). Update this file's rows rather than "
            "deleting them — a later reader needs to know the re-pin happened."
        )
