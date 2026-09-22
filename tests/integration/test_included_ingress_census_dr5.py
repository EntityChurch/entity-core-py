"""§1.8 ``DR-5`` (0.8.2.26) — the ingress census mechanism (b) owes.

.. rubric:: Why this file exists, and why nobody routed it here

`.26` blesses **two** mechanisms for §1.8's mis-keyed ``included`` entry:

* **(a)** inspect every entry as the wire map is accepted — `entity-core-go`;
* **(b)** discard the wire keys, so there is no key to inspect and an
  *unreferenced* mis-keyed entry is **not represented at all** — `py`, whose
  ``Envelope.from_dict`` keeps a **list** (``envelope.py``).

`DR-4` rules **in favour of (b)** and forbids a conformance check from
asserting a refusal on that input. `DR-5` is the **cost** of the same choice,
in the same revision::

    (a) is one check at one site and cannot be partially adopted.
    (b) is a check at N ingresses, and N−1 of N is wire-indistinguishable
        from N of N. ... An implementation adopting (b) SHOULD enumerate its
        ingresses and assert the validation pass at each.

⛔ **`DR-5` lands on this seat and on no other, and both routing artifacts
score it "no".** arch's `.26` fold table marks `DR-5` *"does your tree move?
**no**"* — correct **for `entity-core-go`**, the packet's addressee, which is
mechanism (a) and for which `DR-5` is literally not applicable. go's relay
then forwarded §5 to py listing `DR-2`, `DR-8`, `DR-9` and `DR-4`, and
**does not mention `DR-5` at all** — reasonably, since its own column said
no.

So the one delta in `.26` written *about the mechanism py chose* reached py
marked as costing nothing. That is the standing hearsay law on its
**retraction-round** axis — *the seat that built the thing a delta concerns
is the seat the "—" is most expensive for* — with a **blessing** rather than
a withdrawal as the carrier.

.. rubric:: What the census found

Running it, before any edit, on the inventory a defect cannot edit (every
``ecf_decode`` call site in ``packages/``): **three** envelope ingresses, and
the two HTTP ones were hand-rolled copies of the TCP one that had **drifted
twice** — no 0.8.2.25 non-map arm, and no 0.8.2.26 tag policy — under a
docstring reading *"Validates hashes the same way ``recv_envelope`` does."*

⭐ And they are the boundary **no cohort probe reaches**: every conformance
prober in this ecosystem dials TCP. `DR-5`'s *"N−1 of N is
wire-indistinguishable from N of N"* is not a hypothetical here; it was the
measured state of this tree.

The remedy is the standing one — **one derivation, not N agreeing ones**
(`F68`): :func:`entity_core.protocol.framing.admit_decoded_frame`. This file
is the assertion that N stays enumerated.

.. rubric:: ⛔ N IS NOT COMPLETE, and the way this census is short is the
   census law firing on the census

This file enumerates from *"calls ``ecf_decode``"*. **That is a census of
DECODERS, not of §1.8 ingresses**, and the two differ by a whole class: a
wire-supplied ``included`` map nested **inside a params field** was already
decoded as part of its parent frame, so it calls ``ecf_decode`` never and is
structurally invisible here.

`entity-core-go` named that class in `ROUTING-2026-09-15-a`, one day before
`.26`, and it is still open at this seat:

    Check whether your merge ``source_envelope`` ingest runs §1.8 key-binding
    on the nested included map — **grep every ingest of a wire-supplied
    `included` map that does NOT pass through the receive boundary** — merge
    is one; inbox delivery / query / history / content result wrappers may be
    more.

Measured consequence: go's `tree_operations.merge_noncanonical_byte_fidelity`
FAILs against this peer (`400`, want `200`), and the connection dies
immediately after — **554 cascade-blocked checks and 351 transport errors
downstream of one request**. Identical at `11ad269` and at HEAD, so it is
pre-existing and not `.26`'s.

**This is `SA-PY-58`'s law about the sweep, arriving inside the sweep:** a
census keyed on the *syntax* of the thing you just fixed (`ecf_decode`)
shrinks to what you were already looking at; a census keyed on the *concept*
(*a wire-supplied entity map this peer is about to trust*) does not. The
concept-keyed census is owed and is tracked as the `§1.8 nested-ingest` item,
not silently absorbed into the count below.

:class:`TestTheNestedIngestClassIsOpen` pins that gap so the number in this
file cannot be read as coverage of §1.8.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import (
    FramingError,
    HashValidationError,
    NonCanonicalEcfError,
    admit_decoded_frame,
    ecf_encode,
)
from entity_core.utils.ecf import compute_ecf_hash

_PACKAGES = pathlib.Path(__file__).resolve().parents[2] / "packages"


#: Modules that call ``ecf_decode`` and are NOT envelope ingresses, each with
#: the argument for why. A ledger rather than a filter: an exemption that
#: stops matching anything is cover for nothing while reading as live, so
#: :func:`test_every_exemption_is_still_real` asserts each one still decodes.
#:
#: ⚠ These are **entity** ingresses, not §4.11 **frame** ingresses. They are
#: exempt from the frame obligation, NOT from §1.8 — each carries its own
#: verification, named here, and adding a tag refusal to them would be a wire
#: decision with no §4.11 row behind it (§1.8 requires storing and forwarding
#: the ORIGINAL bytes, so refusing content for its encoding is a separate
#: ruling nobody has made).
_NON_ENVELOPE_DECODERS: dict[str, str] = {
    "http_poll_client.py": (
        "polls single ENTITIES, not envelopes: `content()` rehashes the body "
        "against the requested hash before decoding (hostile-CDN guard), and "
        "`manifest()`/the root walk are signature-verified via "
        "`verify_published_root`. Neither is a frame and neither is admitted "
        "as a request."
    ),
    "coordination.py": (
        "decodes a stored signaling blob out of the content store — bytes "
        "this peer already admitted and hashed. Not an ingress."
    ),
}


def _decode_sites() -> dict[str, list[int]]:
    """Every ``ecf_decode(...)`` call site under ``packages/``.

    ⚠ Enumerated from the **call graph**, not from a grep for the fix. The
    standing law (`SA-PY-58`, AP-21) is that a census keyed on *"omits the
    check"* shrinks as you fix things and cannot see a site that never had
    it; a census keyed on *"decodes untrusted bytes"* does not.
    """
    sites: dict[str, list[int]] = {}
    for path in _PACKAGES.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:  # pragma: no cover - defensive
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ecf_decode"
            ):
                sites.setdefault(path.name, []).append(node.lineno)
    return sites


def _module_source(name: str) -> str:
    for path in _PACKAGES.rglob(name):
        return path.read_text()
    raise AssertionError(f"module {name} not found under packages/")


class TestTheIngressesAreEnumerated:
    """N is a number this repo states, so N−1 is a failing test."""

    def test_every_decode_site_is_an_admitted_ingress_or_a_ledgered_exemption(
        self,
    ):
        sites = _decode_sites()
        # `ecf.py` defines it; `framing.py` is the canonical ingress.
        unaccounted = []
        for module, lines in sorted(sites.items()):
            if module in ("ecf.py",):
                continue
            if module in _NON_ENVELOPE_DECODERS:
                continue
            src = _module_source(module)
            if "admit_decoded_frame" not in src:
                unaccounted.append(f"{module}:{lines}")

        assert not unaccounted, (
            "these modules decode untrusted CBOR and do NOT route it through "
            f"`admit_decoded_frame`: {unaccounted}. §1.8 DR-5 (0.8.2.26): py "
            "is mechanism (b), so the validation pass is owed at EVERY "
            "ingress and 'N−1 of N is wire-indistinguishable from N of N'. "
            "Either route it through the shared admission function, or add it "
            "to `_NON_ENVELOPE_DECODERS` with the argument for why it is not "
            "an envelope ingress."
        )

    def test_the_three_envelope_ingresses_are_all_present(self):
        """The count, stated — so an ingress silently disappearing fails too.

        A ratchet in both directions: an entry that *overstates* reality is a
        defect exactly as an omission is, because a census nobody can falsify
        is not a census.
        """
        expected = {"framing.py", "http_server.py", "http_client.py"}
        actual = {
            m for m in _decode_sites()
            if m not in _NON_ENVELOPE_DECODERS and m != "ecf.py"
        }
        assert actual == expected, (
            f"the envelope-ingress set moved: {actual} != {expected}. A new "
            "ingress owes the admission pass; a departed one owes an updated "
            "census."
        )

    def test_every_exemption_is_still_real(self):
        for module, why in _NON_ENVELOPE_DECODERS.items():
            src = _module_source(module)
            assert "ecf_decode" in src, (
                f"{module} is ledgered as a non-envelope decoder ({why}) but "
                "no longer decodes anything. Remove the exemption — a "
                "carve-out matching nothing reads as live cover and is not."
            )

    def test_no_ingress_keeps_a_PRIVATE_copy_of_the_admission_checks(self):
        """The structural row, and the one the behavioural rows cannot give.

        Both HTTP ingresses previously hand-rolled the hash loop. A private
        copy that happens to be *correct today* is behaviourally
        indistinguishable from the shared one — the whole defect is that it
        stops being correct when the shared rule grows an arm, which is what
        happened twice here.
        """
        for module in ("http_server.py", "http_client.py"):
            src = _module_source(module)
            assert "validate_entity_hash(" not in src, (
                f"{module} calls `validate_entity_hash` directly again. The "
                "admission checks have ONE derivation (`admit_decoded_frame`) "
                "because this module's own copy drifted from it twice: it "
                "missed 0.8.2.25's non-map arm and 0.8.2.26's tag policy "
                "while its docstring claimed to mirror `recv_envelope`."
            )


class TestTheSharedAdmissionActuallyRefuses:
    """Behaviour, at the function every ingress now shares."""

    def _entity(self, extra: dict | None = None) -> dict:
        ent = {"type": "system/test", "data": {"v": 1, **(extra or {})}}
        ent["content_hash"] = compute_ecf_hash(
            {"type": ent["type"], "data": ent["data"]}
        )
        return ent

    def test_a_non_map_frame_is_refused(self):
        """0.8.2.25's arm — *never becomes an Envelope* is wider than *does
        not decode*. This is the arm both HTTP copies were missing."""
        with pytest.raises(FramingError):
            admit_decoded_frame(None)
        with pytest.raises(FramingError):
            admit_decoded_frame(42)

    def test_a_tagged_frame_is_refused_non_canonical_ecf(self):
        from cbor2 import CBORTag

        with pytest.raises(NonCanonicalEcfError) as exc:
            admit_decoded_frame({"root": {"type": "t", "data": {
                "x": CBORTag(0, "2026-01-01"),
            }}})
        assert exc.value.status == 400
        assert exc.value.code == "non_canonical_ecf"
        # The frame was consumed whole, so §9 arm (f) binds it and the close
        # is a choice — the property 0.8.2.26 exempts only (a2) from.
        assert exc.value.stream_synchronized is True

    def test_a_mis_stamped_included_entry_is_refused(self):
        """A REFERENCED-or-not entry whose own bytes do not hash to its own
        claimed `content_hash`. This is the §1.8 check both mechanisms owe —
        distinct from the mis-KEYED case `DR-4` rules mechanism-shaped, which
        py cannot even represent (the wire key is discarded at decode)."""
        ent = self._entity()
        ent["content_hash"] = b"\x00" + b"\xaa" * 32
        with pytest.raises(HashValidationError):
            admit_decoded_frame({
                "root": {"type": "system/test", "data": {"request_id": "r"}},
                "included": {ent["content_hash"]: ent},
            })

    def test_a_well_formed_frame_is_admitted(self):
        """The control. Without it every row above passes on a function that
        refuses everything.

        ⚠ Uses the WIRE shape — ``included`` is a hash→entity **map**. The
        first draft passed a list, which `Envelope.from_dict` drops to `[]`
        (mechanism (b) reads `included_raw.values()`), so the control was
        asserting on an envelope whose entries had silently vanished. A
        fixture in the wrong shape is a claim about what production sends.
        """
        ent = self._entity()
        env = admit_decoded_frame({
            "root": {"type": "system/test", "data": {"request_id": "r"}},
            "included": {ent["content_hash"]: ent},
        })
        assert isinstance(env, Envelope)
        assert len(env.included) == 1

    def test_a_tag_55799_WRAPPING_the_envelope_is_the_tag_row_not_the_framing_row(
        self,
    ):
        """⛔ SA-PY-66's discriminator, and py answered it wrong until now.

        Tag 55799 is the CBOR self-describe marker — the one tag a real
        encoder emits by accident. Wrapped around the payload it decodes to a
        ``CBORTag``, which **is not a dict**, so with the non-map arm ordered
        first it took the FRAMING row and answered ``400 invalid_request``:
        *"your bytes are un-parseable"*, about bytes that parsed perfectly.

        That is `DR-3`'s own defect — *"the code selects the caller's remedy,
        so a code that is merely in the right family is still wrong"* —
        re-created by the row `DR-3` produced, because §4.11 scopes (5a) to
        *"a data-field position"* while ECF §6.3 forbids tags **at any
        depth**. Found by checking the SA filing's claim against the tree
        instead of shipping it.
        """
        from cbor2 import CBORTag

        wrapped = CBORTag(55799, {
            "root": {"type": "system/test", "data": {"request_id": "r"}},
        })
        with pytest.raises(NonCanonicalEcfError) as exc:
            admit_decoded_frame(wrapped)
        assert exc.value.code == "non_canonical_ecf"

    def test_the_non_map_arm_still_answers_the_FRAMING_code(self):
        """The control the ordering fix could break.

        Reordering the tag check ahead of the non-map check must not turn an
        ordinary non-map payload into a tag refusal — `\\xf6` carries no tag
        and is genuinely *"never becomes an Envelope"*.
        """
        with pytest.raises(FramingError) as exc:
            admit_decoded_frame(None)
        assert not isinstance(exc.value, NonCanonicalEcfError)
        assert exc.value.code == "invalid_request"

    def test_the_tag_check_precedes_the_hash_check(self):
        """⛔ The ORDER is the ruling, and it is not incidental.

        A tagged entity can carry a **correct** hash — the sender computed it
        over the same tagged bytes — so the two rules overlap on exactly one
        input, and a hash-first implementation admits it. The
        `EXTENSION-TREE` Appendix A row-ordering law with §5.4 and §1.8 as
        the two rows: the discriminating input belongs to both at once, so
        neither rule's author writes it.
        """
        from cbor2 import CBORTag

        data = {"v": CBORTag(0, "2026-01-01")}
        ent = {"type": "system/test", "data": data}
        ent["content_hash"] = compute_ecf_hash({"type": ent["type"], "data": data})
        # The hash really is correct — so a hash-first peer answers 200.
        assert ecf_encode(ent["data"]) is not None

        with pytest.raises(NonCanonicalEcfError):
            admit_decoded_frame({
                "root": {"type": "system/test", "data": {"request_id": "r"}},
                "included": {ent["content_hash"]: ent},
            })


class TestTheNestedIngestClassIsOpen:
    """⛔ The gap this file's own method cannot see — pinned, not absorbed.

    A wire-supplied ``included`` map nested inside a **params field** never
    calls ``ecf_decode``, so the census above is blind to it by construction.
    ``merge``'s ``source_envelope`` is the known member; `entity-core-go`
    routed it to this seat on 2026-09-15 and it is unabsorbed.

    These rows assert **today's answer with the retirement condition in the
    message**, so the day the §1.8 nested ingest lands they go red and point
    at the work rather than letting it disappear into a green suite.
    """

    def test_merge_still_ingests_source_envelope_without_the_shared_pass(self):
        """Structural: the merge handler does not route its nested included
        map through the admission function the frame ingresses share.

        A behavioural row cannot state this — the defect is a 400 that looks
        like an ordinary refusal, and the cascade that follows it looks like a
        network fault.
        """
        src = None
        for path in _PACKAGES.rglob("tree.py"):
            text = path.read_text()
            if "source_envelope" in text:
                src = text
                break
        assert src is not None, "merge's source_envelope ingest not found"

        assert "admit_decoded_frame" not in src, (
            "tree.py now references the shared admission pass. If the §1.8 "
            "nested-ingest item has landed, retire this class and add the "
            "merge ingest to the census above — and re-run go's "
            "`tree_operations.merge_noncanonical_byte_fidelity`, which is the "
            "oracle for it."
        )

    def test_the_census_method_is_recorded_as_decoder_keyed(self):
        """The honest statement of this file's scope, asserted so a later
        reader cannot mistake the count for §1.8 coverage.

        `AGENTS-STANDARD`: *a skip counts as a failure* — and an enumeration
        that silently excludes a class is the same failure with better prose.
        """
        this = pathlib.Path(__file__).read_text()
        assert "census of DECODERS, not of §1.8 ingresses" in this, (
            "the scope caveat was removed from this file's docstring. The "
            "count below enumerates `ecf_decode` call sites and does NOT "
            "cover nested included maps; say so or widen the census."
        )
