"""EXTENSION-TREE Appendix A (v4.5) — the four `put` error rows, walked whole.

.. rubric:: v4.5 — the two rows this file pinned as divergent were ruled, in go's shape

`ENTITY-CORE-PROTOCOL` **0.8.2.11** §6.3 states the admission ladder and
`EXTENSION-TREE` **v4.5** restates it on the rows. The predicate we filed as
SA-PY-41 did not need a new sentence: §3.9 types ``put-request.entity`` as
``core/entity`` and ``ENTITY-NATIVE-TYPE-SYSTEM`` §8.1 declares that type with
three required fields, so *"does not decode"* means *"is not a `core/entity`"*.
Both filed rows move, and a fourth row arrives:

===============================  ==========================  ==========================
Input                            Was (SA-PY-41, this file)   Now (0.8.2.11 / v4.5)
===============================  ==========================  ==========================
``content_hash`` absent          ``200`` — authored here     ``400 invalid_request``
``type`` is ``""``               ``200``                     ``400 invalid_request``
unallocated format code          ``400 invalid_request``     ``400 unsupported_…format``
``data`` is null                 ``200``                     ``200`` — ruled legal
===============================  ==========================  ==========================

**The absent-hash row is a two-sided fix and the sides are ordered.** ``put`` is
a **receipt** path: the peer validates the carried hash and MUST NOT author one.
The authoring step exists and is the SDK's — ``SDK-OPERATIONS`` §3.2's
``put(path, type, data) → hash`` cannot return a hash it did not compute. This
seat was wrong on **both** halves at once, which is exactly why six weeks of
green tests could not see it: the lenient peer and the stripping SDK were both
ours, so they compensated and the round-trip was perfect. It broke only across a
seat boundary, and it surfaced the day we drove a live go peer. So the SDK's
construction lands **first** and the peer's strictness second, or our own
round-trip breaks mid-change.

The third row is a correction of this file rather than of the peer: yesterday's
walk put an **unallocated** format code in row 1, and §4.7 row 5's own note says
that code is *"reachable on any frame carrying an unallocated format code"* —
row 4. `TestRow4UnsupportedContentHashFormat` holds it now.

.. rubric:: The original walk (v4.4), kept because the method is the point

`entity-core-go` built the driven wire check core-rust asked for
(`cmd/internal/validate/tree_put_error_codes.go`) and reported the cohort:
go 4/4, rust 4/4, **py 3/4** — a non-decoding submission answered
``500 internal_error`` where row 1 pins ``400 invalid_request``.

`entity-core-go` built the driven wire check core-rust asked for
(`cmd/internal/validate/tree_put_error_codes.go`) and reported the cohort:
go 4/4, rust 4/4, **py 3/4** — a non-decoding submission answered
``500 internal_error`` where row 1 pins ``400 invalid_request``.

The report is correct and reproducible. What it could not say — because a
probe's scope is the inputs it seeds — is how much of the row that one input
covers.

.. rubric:: The routed input is one of five

Row 1's subject is a **predicate** (*"the submitted entity does not decode"*),
not an example. go's probe drives one member of it, ``entity = 42``. Walking
the predicate instead of the example found **five** shapes reaching
``Entity.from_dict`` / ``validate_entity_hash`` intact, and py answered a
non-conformant pair on every one:

=================================  ==========================  ==========================
Input                              Was                         Row
=================================  ==========================  ==========================
``entity`` not a map (``42``)      ``500 internal_error``      1 — the routed one
``entity`` missing ``type``        ``500 internal_error``      1
``entity`` missing ``data``        ``500 internal_error``      1
``type`` not a text string         **``200``** — stored        1
``content_hash`` unparseable       ``400 hash_mismatch``       1, not 2
=================================  ==========================  ==========================

The fourth is the one a status-keyed census cannot see and the drive can: a
``type`` of ``42`` is not a decode *failure* in Python at all — ``cbor2`` hands
back a native mapping, ``compute_ecf_hash`` encodes the integer happily, and the
entity is **stored and bound** under a type no typed peer can decode. Both
siblings refuse it. That is the *"a routed report names the rows it seeded"*
law: the FAIL was one row, the defect was a class, and only one member of the
class was a 500.

.. rubric:: And the order between the two 400s is the row, not a detail

A malformed entity carrying a hash satisfies **both** row 1 and row 2's
descriptions. py validated the hash first, so it answered ``hash_mismatch``
where both siblings answer ``invalid_request`` — the caller is told *"your hash
is wrong"* when the fix is *"your entity is not an entity"*. This is go's own
cycle-4 finding about their tree, reached independently here: ``Validate()``
checks structure before hash, and *"flipping wholesale to hash_mismatch, as the
worklist prose read, would mis-code the structural case."* The fix is ordered
structure-first and :class:`TestTheOrderIsTheRow` pins the **source order**, not
just the behaviour — a reviewer reading two correct-looking branches cannot see
that one of them must precede the other.

.. rubric:: The second copy

``_handle_merge`` decodes a caller-supplied ``source_envelope``'s members and
root through the same ``Entity.from_dict``, with no guard. Same defect, same
file, in the copy no probe drives — the standing *two hand-rolled copies of one
traversal* shape with an entity **decode** as the subject. Guarded here too.

.. rubric:: What was NOT changed then, and was routed instead

**Two** shapes where the siblings measurably disagreed with *each other* — an
absent ``content_hash`` and an empty ``type``. Picking a side out of a gap is
the error this repo exists to find, so the guard was deliberately the
**intersection** of what go and rust refuse, both rows were filed as SA-PY-41,
and a pinning class held today's answer so a later reader could not "tidy" one
closed without a ruling. **The ruling came the next day and went go's way on
both**; the rows flipped rather than being deleted, and
:class:`TestTheRulingMovedTheTwoRowsWeFiled` says which ruling moved each.

That is the third recorded instance of a deferral's forward half executing — a
row held for a *written* retirement condition, the condition discharged, the row
armed in the same session. An ``xfail`` would have flipped to XPASS and read as
the divergence resolving itself.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest

from entity_core.capability.grant import Grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import compute_ecf_hash, get_default_hash_algorithm

BASE = "system/validate/tree-put-errcodes"


def _hash_of(entity_type: Any, data: Any) -> bytes:
    return compute_ecf_hash(
        {"type": entity_type, "data": data}, get_default_hash_algorithm()
    )


def _entity(entity_type: str, data: Any) -> dict[str, Any]:
    """A **well-formed** submission — all three keys.

    Every positive row below goes through this rather than through a literal,
    because a two-key ``{type, data}`` is no longer a well-formed put and a
    control that used one would fail for the reason it exists to rule out.
    """
    return {
        "type": entity_type,
        "data": data,
        "content_hash": _hash_of(entity_type, data),
    }


class _WirePeer:
    """A live peer plus a (status, code) driver for `system/tree:put`."""

    PORT = 19107

    @pytest.fixture
    async def server(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"], resources=["*"],
            )])
            .debug_mode(True)
            .build()
        )
        await peer.start("127.0.0.1", self.PORT)
        yield peer
        await peer.stop()

    async def _put(
        self, server, path: str, entity: Any, **extra: Any
    ) -> tuple[int, str]:
        """Drive a `put` with a caller-chosen `entity` payload.

        The payload rides in ``params.data`` verbatim — the point of every row
        below is a shape our own constructors cannot build.
        """
        from entity_core.peer.connection import Connection

        conn = await Connection.connect("127.0.0.1", self.PORT, Keypair.generate())
        try:
            data: dict[str, Any] = {"path": path, "entity": entity}
            data.update(extra)
            result = await conn.execute(
                f"entity://{server.peer_id}/system/tree",
                "put",
                {"type": "system/tree/put-request", "data": data},
                resource={"targets": [path]},
            )
            body = (result.result or {}).get("data") or {}
            return int(result.status), body.get("code", "")
        finally:
            conn.close()
            await conn.wait_closed()


class TestRow1TheSubmittedEntityDoesNotDecode(_WirePeer):
    """Row 1 — ``400 invalid_request``, walked as a predicate.

    The control comes first and gates the reading of everything under it: if a
    well-formed put does not land 200, a 400 on a hostile input is attributable
    to an unreachable handler or a denied grant rather than to the input. go's
    probe carries the same control for the same reason, and this file inherits
    the discipline rather than the vector.
    """

    @pytest.mark.asyncio
    async def test_control_a_well_formed_put_lands_200(self, server) -> None:
        status, code = await self._put(
            server, f"{BASE}/control", _entity("app/probe", {"v": "ok"})
        )
        assert (status, code) == (200, ""), (
            "the control put must land 200 or nothing below is attributable"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("label", "entity"),
        [
            # go's probe drives exactly this one — a bare CBOR integer.
            ("not_a_map_int", 42),
            ("not_a_map_str", "nope"),
            ("not_a_map_list", [1, 2, 3]),
            ("missing_type", {"data": {"v": 1}}),
            ("missing_data", {"type": "app/probe"}),
            # Not a decode FAILURE in Python — a decode failure in every typed
            # peer. This one was a 200 here: stored and bound under an integer
            # type. It is the member of the class a 500-keyed census misses.
            ("type_not_text_int", {"type": 42, "data": {"v": 1}}),
            ("type_not_text_bytes", {"type": b"app/probe", "data": {"v": 1}}),
            ("type_not_text_map", {"type": {"x": 1}, "data": {"v": 1}}),
            # v4.5 — the two SA-PY-41 rows, now ruled. Kept here as members of
            # the predicate rather than only in the ruling class below, because
            # row 1's subject is one predicate and these are two of its clauses.
            #
            # The empty-type vector carries a CORRECT content_hash, and that is
            # load-bearing: the first draft omitted it, and a mutation deleting
            # the empty-type clause outright left this row GREEN, because the
            # absent hash refused it at step 1b with the same code. A vector
            # carrying two faults cannot attribute a refusal to either — the
            # standing *"every rejection test must satisfy the rule it is not
            # about"* discipline, met by hashing the entity we expect refused.
            ("empty_type", _entity("", {"v": 1})),
            (
                "content_hash_absent",
                {"type": "app/probe", "data": {"v": 1}},
            ),
            (
                "content_hash_null",
                {"type": "app/probe", "data": {"v": 1}, "content_hash": None},
            ),
        ],
    )
    async def test_a_non_decoding_entity_is_400_invalid_request(
        self, server, label: str, entity: Any
    ) -> None:
        status, code = await self._put(server, f"{BASE}/row1/{label}", entity)
        assert (status, code) == (400, "invalid_request"), (
            f"{label}: EXTENSION-TREE Appendix A `put` row 1 (v4.5) — the "
            f"submitted entity is not a `core/entity`, which is §3.3's generic "
            f"400 default"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("label", "content_hash"),
        [
            ("not_bytes", "deadbeef"),
            ("empty_bytes_after_format_byte", b"\x00"),
            ("wrong_digest_length", b"\x00" + b"\xab" * 16),
            ("sha384_code_sha256_length", b"\x01" + b"\xab" * 32),
        ],
    )
    async def test_an_unparseable_content_hash_is_row_1_not_row_2(
        self, server, label: str, content_hash: Any
    ) -> None:
        """A hash that never parsed cannot be a hash that *does not match*.

        Row 2 reads *"the submitted entity's content hash does not match the
        entity it addresses"* — it presupposes a hash. These values are not one,
        so the failure is a decode failure, which is row 1: v4.5 spells the
        clause *"``content_hash`` absent or **mis-sized** for its format code
        (§1.2)"*. Both siblings put it there (go at ``Hash.UnmarshalCBOR``,
        rust at ``Hash::from_bytes``, both *before* any comparison); py
        answered ``hash_mismatch`` for all four before ``ca62657``.

        ``sha384_code_sha256_length`` replaces this row's original
        ``unallocated_format_byte`` vector, which v4.5 moves to row 4 — see
        :class:`TestRow4UnsupportedContentHashFormat`. It is the sharper vector
        anyway: the format code is one this peer **does** support, so the only
        thing wrong with the value is its length, and a peer that checked only
        the format code would pass it through to the comparison.
        """
        status, code = await self._put(
            server,
            f"{BASE}/row1hash/{label}",
            {"type": "app/probe", "data": {"v": 1}, "content_hash": content_hash},
        )
        assert (status, code) == (400, "invalid_request"), (
            f"unparseable content_hash ({label}) is row 1, not row 2"
        )


class TestRow2AndRow3DoNotCollapse(_WirePeer):
    """Rows 2 and 3 share the token ``hash_mismatch`` and are different rows.

    v4.4 tabulated them side by side precisely so a peer cannot collapse them:
    400 says *this entity is not what it claims to be* and is a defect in the
    submission; 409 says *someone else wrote first*, is nobody's defect, and is
    retryable. Both were already conformant here — asserted anyway, because the
    row-1 fix moves code directly above them and *a ruling you already satisfy
    produces no diff, and no diff produces no test.*
    """

    @pytest.mark.asyncio
    async def test_row_2_a_mismatched_content_hash_is_400_hash_mismatch(
        self, server
    ) -> None:
        # A well-formed hash of a *different* {type, data}: parses, does not match.
        wrong = _hash_of("app/probe", {"v": "other"})
        status, code = await self._put(
            server,
            f"{BASE}/row2",
            {"type": "app/probe", "data": {"v": "mine"}, "content_hash": wrong},
        )
        assert (status, code) == (400, "hash_mismatch"), (
            "Appendix A `put` row 2 — the same code EXTENSION-CONTENT §923 uses"
        )

    @pytest.mark.asyncio
    async def test_row_3_a_stale_expected_hash_is_409_hash_mismatch(
        self, server
    ) -> None:
        path = f"{BASE}/row3"
        seeded, _ = await self._put(server, path, _entity("app/probe", {"v": "seed"}))
        assert seeded == 200, "seed must land for the CAS race to be a race"
        stale = _hash_of("app/probe", {"v": "stale"})
        status, code = await self._put(
            server,
            path,
            _entity("app/probe", {"v": "update"}),
            expected_hash=stale,
        )
        assert (status, code) == (409, "hash_mismatch"), (
            "Appendix A `put` row 3 — a lost CAS race, retryable, nobody's defect"
        )

    @pytest.mark.asyncio
    async def test_the_two_400s_do_not_collapse(self, server) -> None:
        """The MUST is about the table, not about any one row.

        A peer that answered ``invalid_request`` to everything would pass row 1
        and fail here; a peer that answered ``hash_mismatch`` to everything
        (which is what a hash-first ordering approximates) would pass row 2 and
        fail row 1. Only the pair discriminates.
        """
        wrong = _hash_of("app/probe", {"v": "other"})
        structural = await self._put(server, f"{BASE}/nc/a", 42)
        mismatched = await self._put(
            server,
            f"{BASE}/nc/b",
            {"type": "app/probe", "data": {"v": "mine"}, "content_hash": wrong},
        )
        assert structural != mismatched, (
            "row 1 and row 2 are different failures and must answer differently"
        )


class TestRow4UnsupportedContentHashFormat(_WirePeer):
    """Row 4 (v4.5) — a well-formed hash in a format this peer cannot verify.

    Restated on Appendix A from ``ENTITY-CORE-PROTOCOL`` §4.7 row 5 *"because
    `put` is one of its ingest surfaces"*, and it is **not** row 1: the value is
    a structurally valid ``system/hash`` and the peer simply cannot verify it.
    The distinction is caller-actionable — row 1 says *fix your request*, row 4
    says *this peer does not speak your format* — and collapsing them tells a
    caller with a perfectly good SHA-512 entity that their request is malformed.

    This row is a **correction of this file**, not of the peer's behaviour:
    yesterday's row-1 walk classified an unallocated format code as
    ``invalid_request``. §4.7 row 5's own note says that code is *"reachable on
    any frame carrying an unallocated format code"*.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("label", "content_hash"),
        [
            # 0x02 is ALLOCATED (ECFv1-SHA-512, in DIGEST_SIZES) and NOT in
            # SUPPORTED_CONTENT_HASH_FORMATS — the cleanest read of row 4's
            # "well-formed but names a format code this peer does not support",
            # since the length is exactly right for the code it names.
            ("allocated_but_unsupported_sha512", b"\x02" + b"\xab" * 64),
            # Unallocated: also row 4, per §4.7 row 5's note.
            ("unallocated_format_byte", b"\x7f" + b"\xab" * 32),
        ],
    )
    async def test_an_unsupported_format_code_is_row_4(
        self, server, label: str, content_hash: bytes
    ) -> None:
        status, code = await self._put(
            server,
            f"{BASE}/row4/{label}",
            {"type": "app/probe", "data": {"v": 1}, "content_hash": content_hash},
        )
        assert (status, code) == (400, "unsupported_content_hash_format"), (
            f"{label}: Appendix A `put` row 4 (v4.5) / §4.7 row 5 — the value is "
            f"a hash, in a format we do not implement"
        )

    @pytest.mark.asyncio
    async def test_rows_1_and_4_do_not_collapse(self, server) -> None:
        """Teeth: both are 400s on the ``content_hash`` field, and they differ.

        A peer that answered ``invalid_request`` for every bad hash passes every
        row-1 vector above and is non-conformant on row 4 — which is what this
        peer did until v4.5, and what nothing could see while the two codes were
        one branch.
        """
        mis_sized = await self._put(
            server,
            f"{BASE}/r14/a",
            {"type": "app/probe", "data": {"v": 1}, "content_hash": b"\x00" + b"\xab" * 16},
        )
        unsupported = await self._put(
            server,
            f"{BASE}/r14/b",
            {"type": "app/probe", "data": {"v": 1}, "content_hash": b"\x02" + b"\xab" * 64},
        )
        assert mis_sized == (400, "invalid_request")
        assert unsupported == (400, "unsupported_content_hash_format")


class TestTheOrderIsTheRow(_WirePeer):
    """Structure is decided before the hash — behaviourally and structurally."""

    @pytest.mark.asyncio
    async def test_a_malformed_entity_carrying_a_hash_is_invalid_request(
        self, server
    ) -> None:
        """The input that satisfies BOTH row descriptions.

        This is the discriminator between the two orderings, and it is the row
        go's probe cannot express: its row-1 vector carries no ``content_hash``
        at all, so a hash-first peer reaches the structural branch anyway and
        passes. Ours did not — it answered ``hash_mismatch``.
        """
        # No `type` at all, plus a well-formed hash of something else. Under a
        # hash-first ordering this is `hash_mismatch`; under structure-first it
        # is `invalid_request`, which is what both siblings answer.
        status, code = await self._put(
            server,
            f"{BASE}/order",
            {"data": {"v": 1}, "content_hash": _hash_of("app/probe", {"v": 1})},
        )
        assert (status, code) == (400, "invalid_request"), (
            "structure is decided before the hash — a shape defect is row 1 "
            "even when a claimed hash is present to disagree with"
        )

    def test_the_source_orders_the_structural_check_before_the_hash(self) -> None:
        """Pinned over the AST, because behaviour alone does not pin an order.

        Two correct-looking branches read fine in either sequence; what a
        reviewer cannot see is that one of them must come first. A later seat
        hoisting the hash check for tidiness reintroduces the defect at every
        input that carries both faults, and only one row above would catch it.
        """
        from entity_handlers import tree as tree_module

        source = inspect.getsource(tree_module._handle_put)
        structure_at = source.index("validate_entity_structure(entity_data)")
        carried_at = source.index("validate_carried_content_hash(entity_data)")
        hash_at = source.index("validate_entity_hash(entity_data)")
        assert structure_at < carried_at < hash_at, (
            "0.8.2.11 §6.3's ladder is ordered: step 1a shape, step 1b the "
            "carried hash is well-formed, step 2 the carried hash is right. "
            "Step 2's inputs are exactly what step 1 establishes, so the order "
            "is a data dependency and not a convention"
        )

    def test_the_peer_has_no_authoring_arm(self) -> None:
        """The other half of the ruling, and it is a *negative* about the source.

        A behavioural row can only show that an absent hash is refused today; it
        cannot show that the refusal is the *only* path, and a later seat adding
        a convenience "author it if absent" branch would restore the compensating
        pair in one line. ``put`` reaches an ``Entity`` exactly one way — the
        wire form, carrying the validated hash (§1.8).
        """
        from entity_handlers import tree as tree_module

        source = inspect.getsource(tree_module._handle_put)
        assert "Entity.from_wire_dict(entity_data)" in source
        assert "Entity.from_dict(entity_data)" not in source, (
            "`put` is a receipt path (0.8.2.11 §6.3): a peer MUST NOT author a "
            "submitted entity's content_hash. `Entity.from_dict` is the "
            "authoring constructor and its presence here IS the defect"
        )


class TestTheSecondCopyIsGuardedToo(_WirePeer):
    """`merge`'s `source_envelope` decode is the copy no probe drives."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("label", "envelope"),
        [
            ("root_not_a_map", {"root": 42, "included": {}}),
            ("root_missing_type", {"root": {"data": {}}, "included": {}}),
            (
                "included_member_not_decoding",
                {
                    "root": {"type": "system/tree/snapshot", "data": {"root": None}},
                    "included": {"h": {"data": {"v": 1}}},
                },
            ),
        ],
    )
    async def test_an_undecodable_source_envelope_entity_is_400(
        self, server, label: str, envelope: dict[str, Any]
    ) -> None:
        from entity_core.peer.connection import Connection

        conn = await Connection.connect("127.0.0.1", self.PORT, Keypair.generate())
        try:
            result = await conn.execute(
                f"entity://{server.peer_id}/system/tree",
                "merge",
                {
                    "type": "system/tree/merge-request",
                    "data": {"source_envelope": envelope},
                },
            )
            body = (result.result or {}).get("data") or {}
            status, code = int(result.status), body.get("code", "")
        finally:
            conn.close()
            await conn.wait_closed()

        assert (status, code) == (400, "invalid_request"), (
            f"{label}: a caller-supplied entity that does not decode is §3.3's "
            f"generic 400 — not a 500, at either of the two decode sites"
        )

    def test_every_caller_supplied_entity_decode_in_tree_py_is_guarded(self) -> None:
        """A census over the AST, so the *next* decode site is caught here.

        Enumerated from the calls rather than from a hand-kept list: a list is
        the artifact that goes stale, and this defect was a second copy of a
        site that was already known.
        """
        path = Path(inspect.getfile(__import__(
            "entity_handlers.tree", fromlist=["tree"]
        )))
        tree_ast = ast.parse(path.read_text())

        decodes: list[int] = []
        guards: list[int] = []
        for node in ast.walk(tree_ast):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in (
                "from_dict",
                "from_wire_dict",
            ):
                if isinstance(func.value, ast.Name) and func.value.id == "Entity":
                    decodes.append(node.lineno)
            if isinstance(func, ast.Name) and func.id == "validate_entity_structure":
                guards.append(node.lineno)

        assert len(decodes) == 3, (
            f"tree.py decodes a caller-supplied entity at {decodes}; this census "
            f"expected the three known sites (put, merge root, merge members). A "
            f"new site needs a structural guard and a row here.\n"
            f"This was FOUR until 0.8.2.11: `put` had two, one per arm of an "
            f"`if content_hash is not None` — and the second arm was the "
            f"peer-side authoring the ruling forbids. The count dropping is the "
            f"fix, and a census enumerating from the calls is what reports it."
        )
        assert len(guards) == 3, (
            f"expected one guard per decode site (put, merge root, merge member) "
            f"— found {guards}"
        )


class TestTheRulingMovedTheTwoRowsWeFiled(_WirePeer):
    """The two SA-PY-41 divergences, and which ruling moved each.

    These rows were pinned at *today's answer* with their filing named, on the
    ground that picking a side out of a gap is the error this repo exists to
    find. Both were ruled the next day, both in go's shape, and both flipped
    here rather than being deleted — a reader who finds the class gone has no
    way to learn that the divergence was real and how it was settled.
    """

    @pytest.mark.asyncio
    async def test_an_absent_content_hash_is_now_400_invalid_request(
        self, server
    ) -> None:
        """SA-PY-41 row 6 → ruled at 0.8.2.11 §6.3 / EXTENSION-TREE v4.5 row 1.

        rust stated the lenient arm as a deliberate position (*"an entity being
        authored here, not one being carried"*) and py agreed by accident. The
        ruling refuses the dichotomy the filing posed: **both** layers exist —
        the peer's ``put`` is a receipt path and the SDK's
        ``put(path, type, data) → hash`` is the authoring one — so an absent
        ``content_hash`` is a required field's absence and nothing more.

        go's refusal was right and go's *code* was wrong: an absent hash decodes
        to the zero ``Hash``, so their ``hash.Validate`` answered
        ``400 hash_mismatch`` where the ladder puts it at step 1.
        """
        status, code = await self._put(
            server, f"{BASE}/nohash", {"type": "app/probe", "data": {"v": 1}}
        )
        assert (status, code) == (400, "invalid_request"), (
            "`put` is a receipt path — the peer authors nothing (0.8.2.11 §6.3)"
        )

    @pytest.mark.asyncio
    async def test_an_empty_type_is_now_400_invalid_request(self, server) -> None:
        """SA-PY-41 row 7 → ruled at 0.8.2.11 §6.3, go's answer.

        The filing was right that an empty string decodes into ``type: string``
        perfectly well and that no sentence *then* required a non-empty type.
        The derivation is §2.7's — *"the name is the interop contract"* — plus
        0.8.2.4's precedent that a present-but-empty ``protocols`` is *"a
        malformed request, not a version incompatibility."* A required field
        carrying no value has not been supplied.

        Hashed, so the empty ``type`` is the **only** thing wrong with it —
        see the note on the ``empty_type`` vector above for what the unhashed
        draft of this row could not discriminate.
        """
        status, code = await self._put(
            server, f"{BASE}/emptytype", _entity("", {"v": 1})
        )
        assert (status, code) == (400, "invalid_request"), (
            "an empty interop contract is not a contract (0.8.2.11 §6.3)"
        )

    @pytest.mark.asyncio
    async def test_a_null_data_is_still_accepted(self, server) -> None:
        """The control row, and the ruling kept it — which is the point of it.

        ``data: null`` is present-but-empty, and §6.3 step 1 says so outright:
        *"a present `data` (any CBOR value — `primitive/any` is unconstrained,
        so null is a legal payload)"*. This row is what keeps the guard honest
        while the two rows above tighten: a seat "tidying" the predicate to
        falsiness would pass both of them and partition the cohort here, in the
        direction nothing else measures.
        """
        status, code = await self._put(
            server, f"{BASE}/nulldata", _entity("app/probe", None)
        )
        assert (status, code) == (200, ""), (
            "`data: null` is present, not absent — §6.3 step 1 names it legal"
        )


class TestTheGuardIsWhatTheRuledPredicateSays(_WirePeer):
    """The predicate's contents, asserted directly rather than only on the wire.

    A unit-level row over the same functions the handler calls, so the *reason*
    each shape is in or out survives a refactor of the call site — and so the
    shapes we deliberately do NOT refuse are visible as decisions rather than as
    omissions.

    The guard was built as the **intersection of what go and rust refuse**, so
    that adopting it could not make this seat the outlier on any shape. 0.8.2.11
    then ruled the two shapes the siblings split on, both toward the stricter
    arm, so the intersection is now the ruled predicate — the two clauses below
    marked ``ruled 0.8.2.11`` are the ones that moved.
    """

    @pytest.mark.parametrize(
        ("value", "refused"),
        [
            (42, True),
            ("nope", True),
            ([1], True),
            (b"x", True),
            ({"data": {}}, True),
            ({"type": "app/x"}, True),
            ({"type": 42, "data": {}}, True),
            ({"type": None, "data": {}}, True),
            ({"type": "", "data": {}}, True),  # ruled 0.8.2.11 §6.3
            # Accepted — §6.3 step 1 names `data` "any CBOR value".
            ({"type": "app/x", "data": None}, False),
            ({"type": "app/x", "data": 42}, False),
            ({"type": "app/x", "data": {}}, False),
            ({"type": "app/x", "data": {"v": 1}, "unknown": "kept"}, False),
        ],
    )
    def test_the_predicate(self, value: Any, refused: bool) -> None:
        """The SHAPE half. ``content_hash`` is deliberately not read here."""
        from entity_core.protocol.framing import validate_entity_structure

        reason = validate_entity_structure(value)
        assert (reason is not None) is refused, f"{value!r} → {reason!r}"

    @pytest.mark.parametrize(
        ("label", "entity", "expected"),
        [
            ("absent", {"type": "app/x", "data": {}}, "invalid_request"),
            (
                "null",
                {"type": "app/x", "data": {}, "content_hash": None},
                "invalid_request",
            ),
            (
                "not_bytes",
                {"type": "app/x", "data": {}, "content_hash": "0011"},
                "invalid_request",
            ),
            (
                "empty_bytes",
                {"type": "app/x", "data": {}, "content_hash": b""},
                "invalid_request",
            ),
            (
                "mis_sized_for_its_code",
                {"type": "app/x", "data": {}, "content_hash": b"\x00" + b"\xab" * 31},
                "invalid_request",
            ),
            (
                "allocated_but_unsupported",
                {"type": "app/x", "data": {}, "content_hash": b"\x02" + b"\xab" * 64},
                "unsupported_content_hash_format",
            ),
            (
                "unallocated",
                {"type": "app/x", "data": {}, "content_hash": b"\x7f" + b"\xab" * 32},
                "unsupported_content_hash_format",
            ),
            # Accepted: right shape, right length, supported code. Whether it is
            # the RIGHT hash is step 2's question, not this one's.
            (
                "well_formed_but_wrong_value",
                {"type": "app/x", "data": {}, "content_hash": b"\x00" + b"\xab" * 32},
                None,
            ),
            (
                "well_formed_sha384",
                {"type": "app/x", "data": {}, "content_hash": b"\x01" + b"\xab" * 48},
                None,
            ),
        ],
    )
    def test_the_carried_hash_clause(
        self, label: str, entity: dict[str, Any], expected: str | None
    ) -> None:
        """Step 1b, and the two codes it can answer with.

        Separated from :meth:`test_the_predicate` because the shape half also
        guards ``merge``'s ``source_envelope``, which the admission ladder does
        not govern — one function serving both would have extended a ruled
        ``put`` rule to an unruled surface by accident of code reuse.
        """
        from entity_core.protocol.framing import validate_carried_content_hash

        verdict = validate_carried_content_hash(entity)
        assert (verdict[0] if verdict else None) == expected, (
            f"{label}: {verdict!r}"
        )

    def test_an_accepted_shape_really_does_reach_an_entity(self) -> None:
        """Teeth: the predicate accepting is only meaningful if the decode works.

        Without this, a guard that accepted nothing would pass every refusal row
        above and the whole class would read green while `put` was broken.
        """
        from entity_core.protocol.framing import validate_entity_structure

        payload = {"type": "app/x", "data": {"v": 1}}
        assert validate_entity_structure(payload) is None
        entity = Entity.from_dict(payload)
        assert entity.type == "app/x"
        assert entity.compute_hash() == _hash_of("app/x", {"v": 1})
