"""`CORE-RESOURCE-TWO-EMPTIES-1` (0.8.2.25) — the two empties, ACROSS A SOCKET.

`EXTENSION-TREE` v4.11 §2.2a is the normative per-operation declaration §3.3
delegates to, and it closes the field three implementations were each
inferring:

    | Operation | `resource` | Absent-case answer | `targets:[P] exclude:[P]` |
    | `get`      | optional | BROAD — the root listing            | 400 `path_required` |
    | `snapshot` | optional | BROAD — prefix `""`, the whole tree  | 400 `path_required` |
    | `extract`  | optional | BROAD — every bound entity under it  | 400 `path_required` |

.. rubric:: ⛔ Why this file exists when `test_the_two_empties_n6.py` already
   drives all three

Because that file builds its `HandlerContext` by hand, and §9 says in terms
that such a drive cannot see the failure the vector exists for:

    *"⚠ **The drive MUST cross a socket.** An in-tree test that builds the
    handler context directly cannot see a dispatch-boundary narrowing that
    collapses the two empties before the handler runs — the failure this
    vector exists for is **dead code behind a green unit test**, and only the
    wire shows it."*

    §2.2a: *"And the refusal is only reachable if the dispatch boundary
    preserved the discriminator … An implementation that narrows
    `resource.targets` to the effective set before the handler runs has
    already turned `targets:[P] exclude:[P]` into the absent case, and **every
    row in this table becomes dead code behind a green unit test**."*

py's whole N6 suite is that shape — `_ctx(peer, resource_targets)`, thirteen
rows, every one of them passing a list straight into the context the guard
reads. It proves the **guard** and says nothing about whether any request can
reach it. This peer narrows at the gate (F68), so the question is live here
rather than hypothetical, and the answer happens to be yes for the
inbound-wire seam and **was no** for the continuation forwarder, which
returned ``effective or None`` and erased the discriminator on the way to a
sub-dispatch.

.. rubric:: The absent-case assertion is CONTAINS, not a status

§9 requirement: *"the assertion **MUST be that the result CONTAINS a seeded
binding** — a prefix with nothing under it returns `count: 0`, which a peer
that never reached the branch also produces."* So each absent row below reads
the payload for a seeded path. A `200` alone is satisfied by a peer that
answered the absent case with an empty result, which is the failure mode on
the other side of this rule.

.. rubric:: And every other dimension of the grant is wide

§9: *"**Widen every dimension of the caller's grant except the one under
test**, or arm (a) answers `403` at the handlers dimension and says nothing
about the empties."* The grant here is `*`/`*`/`*`. The refusals below are
therefore attributable to the resource arithmetic and to nothing else — which
is the standing *"a negative security test can pass for the wrong reason"*
law: `400` and `403` are both "not 200", and only one of them is this row's
subject.
"""

from __future__ import annotations

import pytest

from entity_core.capability.token import Grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

#: Seeded bindings. `SEEDED_A` is the one the absent-case rows look for, and
#: the one the emptied-case rows name and then exclude.
PREFIX = "data/"
SEEDED_A = "data/alpha"
SEEDED_B = "data/beta"
#: `get`'s listing keys its entries by LEAF name, not by full path, so the
#: §9 CONTAINS assertion has to look for what the payload actually carries.
#: The first draft searched for `"data/alpha"` and failed against a perfectly
#: good `count: 2` listing of `{alpha, beta}` — a probe asserting the wrong
#: shape of the right answer.
SEEDED_A_LEAF = "alpha"

PORT = 19101


async def _serve(port: int):
    """A peer with every handler and a grant wide on all four dimensions."""
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
    for path in (SEEDED_A, SEEDED_B):
        peer.emit_pathway.emit(
            path, Entity(type="t/d", data={"at": path}), EmitContext.bootstrap(),
        )
    await peer.start("127.0.0.1", port)
    return peer


async def _drive(peer, port: int, operation: str, params: dict, resource):
    """One EXECUTE over a real connection. ``resource=None`` sends no field."""
    from entity_core.peer.connection import Connection

    conn = await Connection.connect("127.0.0.1", port, Keypair.generate())
    try:
        kwargs = {} if resource is None else {"resource": resource}
        result = await conn.execute(
            f"entity://{peer.peer_id}/system/tree",
            operation,
            {"type": "system/tree/request", "data": params},
            **kwargs,
        )
        return result
    finally:
        conn.close()
        await conn.wait_closed()


def _code_of(result) -> str | None:
    data = result.result if isinstance(result.result, dict) else {}
    if "data" in data and isinstance(data["data"], dict):
        return data["data"].get("code")
    return data.get("code")


def _blob(result) -> str:
    """The whole response rendered as text, for a CONTAINS assertion.

    Deliberately shape-agnostic: `get`'s listing, `snapshot`'s root and
    `extract`'s envelope are three different payloads, and what §9 asks is
    whether a seeded path is *in* the answer. Asserting each payload's schema
    would be three assertions about our own serializers and none about the
    rule.
    """
    return repr(result.result)


@pytest.fixture
async def peer():
    p = await _serve(PORT)
    try:
        yield p
    finally:
        await p.stop()


class TestTheEmptiedResourceIsRefusedOverTheWire:
    """Arm (b) at all three BROAD operations — `400 path_required`.

    `snapshot` and `extract` are the rows §2.2a orders by blast radius and
    calls the widest: neither reads `ctx.resource_targets` at all (their
    prefix is `params`, default `""`), so a guard keyed on *"the handler reads
    the field"* never reaches them.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operation,params",
        [
            ("get", {"path": SEEDED_A}),
            ("snapshot", {"prefix": PREFIX}),
            ("extract", {"prefix": PREFIX}),
        ],
    )
    async def test_targets_P_exclude_P_is_path_required(
        self, peer, operation, params,
    ):
        result = await _drive(
            peer, PORT, operation, params,
            {"targets": [SEEDED_A], "exclude": [SEEDED_A]},
        )
        assert result.status == 400, (
            f"{operation} answered {result.status} to a request that named "
            f"one target and excluded it. §2.2a: all three BROAD rows MUST be "
            f"refused `400 path_required` and MUST NOT fall back to the "
            f"absent case or to the `params` prefix — whose default is `''`, "
            f"so the fallback silently succeeds and validates."
        )
        assert _code_of(result) == "path_required", (
            f"{operation} refused with {_code_of(result)!r}. The code selects "
            "the caller's remedy and `path_required` means *supply a "
            "resource*; `ambiguous_resource` would invert the pair (§3.3)."
        )


class TestTheAbsentResourceStillGetsItsBroadAnswer:
    """Arm (a) — and the assertion is CONTAINS, per §9.

    This is the half that stops the fix being *"refuse whenever the effective
    set is empty"*, which would break every ordinary broad read. A peer that
    over-refuses passes every row in the class above.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operation,params",
        [
            ("get", {"path": PREFIX}),
            ("extract", {"prefix": PREFIX}),
        ],
    )
    async def test_no_resource_field_reaches_the_absent_case(
        self, peer, operation, params,
    ):
        result = await _drive(peer, PORT, operation, params, None)
        assert result.status == 200, (
            f"{operation} answered {result.status} with NO `resource` field "
            f"at all: {result.result!r}. §3.3 — a genuinely absent `resource` "
            f"takes the operation's own absent-case behaviour, and §2.2a "
            f"declares all three of these BROAD. Refusing here is the mirror "
            f"error 0.8.2.25 names: 'This rule exists to stop a request being "
            f"answered with something wider — never to refuse something "
            f"honest.'"
        )
        assert SEEDED_A_LEAF in _blob(result), (
            f"{operation} returned 200 but the payload does not mention "
            f"{SEEDED_A_LEAF!r}. §9 requires the CONTAINS assertion precisely "
            f"because a peer that never reached the branch also answers 200 "
            f"with `count: 0`, and a status-only row cannot tell the two "
            f"apart."
        )


    @pytest.mark.asyncio
    async def test_snapshot_absent_case_is_a_NON_EMPTY_snapshot(self, peer):
        """`snapshot` cannot carry §9's CONTAINS assertion — SA-PY-64.

        §9 prescribes one assertion for all three BROAD rows: *"the assertion
        MUST be that the result CONTAINS a seeded binding."* That is
        expressible at `get` (a listing of names) and at `extract` (an
        envelope of the entities themselves). **`snapshot`'s result is a
        single content hash** — §3: *"A snapshot captures tree state as a
        content-addressable entity"* — so no seeded path appears in its
        payload at any conformance level, and a peer cannot satisfy the
        prescribed assertion however correct it is.

        The property §9 wants is *"the branch was actually reached"*, and the
        discriminator snapshot CAN carry is that its root differs from the
        root of a prefix with nothing under it. Same rule, expressed in the
        one representation this operation has.

        (Standing law: a prescribed vector is a claim that it discriminates,
        and this one was written from the shape of the other two rows.)
        """
        seeded = await _drive(peer, PORT, "snapshot", {"prefix": PREFIX}, None)
        empty = await _drive(
            peer, PORT, "snapshot", {"prefix": "nothing/here/"}, None,
        )
        assert seeded.status == 200 and empty.status == 200
        assert _blob(seeded) != _blob(empty), (
            "the absent-case snapshot of a seeded prefix is byte-identical to "
            "a snapshot of an empty one, so the branch returned an empty "
            "snapshot — which is exactly the `count: 0` failure §9's CONTAINS "
            "assertion exists to exclude, reached at the one operation that "
            "cannot express that assertion."
        )


class TestTheTwoEmptiesDoNotCollapseOnTheWire:
    """The actual `[MUST]` is that the two inputs get DIFFERENT answers.

    Every row above could pass on a peer with one answer for both — the
    emptied rows on a peer that refuses everything, the absent rows on a peer
    that serves everything. Only the pair, driven on one connection and one
    operation, discriminates.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operation,absent_params,emptied_params",
        [
            ("get", {"path": PREFIX}, {"path": SEEDED_A}),
            ("snapshot", {"prefix": PREFIX}, {"prefix": PREFIX}),
            ("extract", {"prefix": PREFIX}, {"prefix": PREFIX}),
        ],
    )
    async def test_one_operation_answers_the_two_empties_differently(
        self, peer, operation, absent_params, emptied_params,
    ):
        absent = await _drive(peer, PORT, operation, absent_params, None)
        emptied = await _drive(
            peer, PORT, operation, emptied_params,
            {"targets": [SEEDED_A], "exclude": [SEEDED_A]},
        )
        assert (absent.status, emptied.status) == (200, 400), (
            f"{operation}: absent={absent.status} emptied={emptied.status}. "
            "§3.3 (0.8.2.24): the two empties are DISTINCT for a "
            "resource-optional operation. A peer answering both the same way "
            "has collapsed them, whichever way it collapsed them."
        )


class TestTheDispatchBoundaryPreservedTheDiscriminator:
    """§3.3's non-lossy-projection `[MUST]` (0.8.2.25), read at the wire.

        *"Where an implementation projects `resource.targets` onto the
        effective set ahead of the handler (§5.4, §6.5), that projection MUST
        NOT be lossy about its own emptiness … **Every seam that narrows is
        exempted alike**, inbound-wire and in-process sub-dispatch."*

    This peer narrows at the gate, so *this* is the row that proves the guard
    above is reachable at all rather than dead code. It is the same request as
    the emptied rows; what it asserts is that the refusal came from the
    HANDLER seeing an empty list, not from the dispatcher having dropped the
    field — distinguished by driving a target the grant does NOT cover, which
    the dispatcher refuses at `403` before the handler is reached.
    """

    @pytest.mark.asyncio
    async def test_the_handler_is_reached_with_the_empty_list_not_with_nothing(
        self, peer,
    ):
        """A `400` here is only attributable if a dispatcher-level refusal
        would have looked different. It does: the control below is `403`.
        """
        emptied = await _drive(
            peer, PORT, "extract", {"prefix": PREFIX},
            {"targets": [SEEDED_A], "exclude": [SEEDED_A]},
        )
        assert (emptied.status, _code_of(emptied)) == (400, "path_required")

    @pytest.mark.asyncio
    async def test_control_a_dispatcher_refusal_is_a_DIFFERENT_answer(self):
        """Teeth: the same emptied shape against a NARROW grant.

        Without this, `400 path_required` above is indistinguishable from "any
        refusal at all", and the file would pass on a peer that refuses every
        resource-bearing request for an unrelated reason.
        """
        narrow = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"],
                resources=["somewhere/else/*"],
            )])
            .debug_mode(True)
            .build()
        )
        narrow.emit_pathway.emit(
            SEEDED_A, Entity(type="t/d", data={"at": SEEDED_A}),
            EmitContext.bootstrap(),
        )
        await narrow.start("127.0.0.1", 19102)
        try:
            result = await _drive(
                narrow, 19102, "extract", {"prefix": PREFIX},
                {"targets": [SEEDED_A]},
            )
        finally:
            await narrow.stop()

        assert result.status == 403, (
            f"a target outside the grant answered {result.status}, so this "
            "file cannot tell an authorization refusal from the resource "
            "arithmetic and none of its 400s are attributable."
        )


class TestTheOutboundSeamsPreserveItToo:
    """§3.3: *"**Every seam that narrows is exempted alike**, inbound-wire and
    in-process sub-dispatch, or one request receives two different answers
    according to which door it arrived through."*

    .. rubric:: ⚠ Why these rows are STRUCTURAL and what is therefore owed

    The rows above drive the **inbound** seam over a socket. Two more seams
    rebuild a wire `resource` on the way **out** — `Peer.execute` (the
    outbound client path) and `_remote_execute` (a handler's cross-peer
    sub-dispatch) — and both tested truthiness, so `[]` silently became an
    absent resource for the receiving peer.

    Reverting both to `if resource_targets:` **reddens nothing above**, and
    that is a finding about the fixture rather than about the fix (the
    standing law: a mutation that reddens nothing is a finding, and the
    discriminator is whether some *other* path answers the same input for the
    same reason — here nothing does; `Connection.execute` simply never reaches
    these two functions).

    The discriminating behavioural configuration is a **cross-peer**
    continuation advance whose stored `resource` is self-excluded, which needs
    a second live peer and a hand-minted B-rooted dispatch capability. It is
    **owed and routed, not claimed** — and it is the standing seam this repo
    cannot measure locally anyway, because every cross-peer continuation test
    here drives a stub dispatcher. The cohort validator is the measurement for
    it, not a final gate on it.

    So these rows read the source. A structural row is the right instrument
    for the specific reason the charter records: a reviewer reading
    `if resource_targets:` sees a correct-looking null check, and nothing at
    the call site reveals that one of the two values it conflates is a
    normative distinction.
    """

    @staticmethod
    def _truthiness_tests_on(fn) -> list[str]:
        """Names tested for TRUTHINESS in `fn`, read by AST.

        ⛔ The first draft of these rows grepped the source text and **both
        failed against the fix**, because the docstrings above quote the very
        forms they forbid (*"`return effective or None` is the shape"*). That
        is the standing law — a gate that cannot tell a sanctioned MENTION
        from a smuggled CALL is not a gate, and prose inflated the count
        exactly as `entity://` did in the presentation-purity gate.

        The remedy is the one this repo already uses for code censuses: walk
        the AST, so a comment explaining the rule can never satisfy or
        violate it.
        """
        import ast
        import inspect
        import textwrap

        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        found = []
        for node in ast.walk(tree):
            # `if x:` / `x or y` / `x and y` where x is a bare name.
            tests = []
            if isinstance(node, ast.If):
                tests.append(node.test)
            elif isinstance(node, ast.BoolOp):
                tests.extend(node.values[:-1])
            elif isinstance(node, ast.IfExp):
                tests.append(node.test)
            for t in tests:
                if isinstance(t, ast.Name):
                    found.append(t.id)
        return found

    def test_neither_outbound_seam_tests_TRUTHINESS_of_the_target_list(self):
        from entity_core.peer import peer as peer_mod

        # `execute` is `ReentryChannel`'s (the outbound-over-inbound client
        # path), `_remote_execute` is `Peer`'s. Two classes, one rule — and
        # naming them explicitly is what stops this row silently covering
        # only whichever one a later reader happens to look up.
        seams = [
            (peer_mod.ReentryChannel, "execute"),
            (peer_mod.Peer, "_remote_execute"),
        ]
        for owner, fn_name in seams:
            fn = getattr(owner, fn_name)
            truthy = self._truthiness_tests_on(fn)
            assert "resource_targets" not in truthy, (
                f"`{owner.__name__}.{fn_name}` decides whether to put a `resource` on the "
                "wire by truthiness, so an explicitly EMPTY target list is "
                "re-spelled as an absent resource for the receiving peer. "
                "§3.3 (0.8.2.25) forbids exactly this: the projection MUST "
                "NOT be lossy about its own emptiness, and every narrowing "
                "seam is bound alike. Use `is not None`."
            )

    def test_the_continuation_forwarder_does_not_collapse_an_empty_set(self):
        """The third seam, pinned beside its inverted behavioural row in
        `test_continuation_handler.py`.

        `return effective or None` is the shape: correct-looking, and it
        erases the discriminator for every continuation sub-dispatch.
        """
        from entity_handlers import continuation as cont_mod

        truthy = self._truthiness_tests_on(cont_mod._effective_dispatch_targets)
        assert "effective" not in truthy, (
            "`_effective_dispatch_targets` collapses an empty effective set "
            "to the ABSENT signal (`effective or None`), so a continuation "
            "whose stored `resource` is self-excluded is advanced as though "
            "it named no resource — the whole tree at `tree:snapshot`, every "
            "bound entity under it at `tree:extract`."
        )


class TestTheRequiredColumnIsFiledNotImplemented:
    """§2.2a's four `resource`-**required** rows — SA-PY-65.

    §2.2a closes a real gap and the three BROAD rows are implemented above.
    Its `required` column contradicts the operations' own sections on three of
    four rows, and §3.3 delegates authority to *"each operation's own
    specification"*, so the two normative statements disagree about which one
    that is:

    * **`diff`** — §4.2, in words: *"Diff operates on stored snapshots — no
      path-level authorization. **The `resource` field is optional**; when
      omitted, handler-scope authorization (§11) suffices."* Params are two
      `system/hash` values. §11's table agrees. §2.2a says `required`.
    * **`create` / `destroy`** — params are a `tree_id`, and §3.3's own test
      excludes them: *"an operation that **targets no entity binding** carries
      no requirement … a `resource` would have nothing to name."*
    * **`merge`** — §5.2's EXECUTE line does carry
      `resource: {targets: [...]}`, so `required` is coherent there. Not
      contested.

    Under the `required` column an **absent** `resource` on `diff` MUST be
    `400 path_required` — i.e. a peer implementing the table refuses
    `diff(base, target)`, the only call shape §4.2 documents.

    **So these rows pin today's answer rather than settling it.** Inventing
    the refusal would refuse a call shape `entity-core-go` accepts, which
    manufactures a cross-impl divergence out of a contradiction — the error
    this repo exists to find rather than commit. They FAIL if the ruling lands
    the other way, which is the point: the retirement condition is in the
    assertion message.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "operation,params",
        [
            ("diff", {"base": None, "target": None}),
            ("create", {"tree_id": "sa-py-65-tree"}),
        ],
    )
    async def test_an_absent_resource_is_NOT_refused_path_required(
        self, peer, operation, params,
    ):
        """Today's answer: whatever these operations do with an absent
        `resource`, it is not `400 path_required`.

        Deliberately NOT asserting success — `diff` with null hashes and
        `create` with a fresh id have their own domain outcomes, and this row
        is about one code only. Asserting the domain result would make it a
        test of two rules and attributable to neither.
        """
        result = await _drive(peer, PORT, operation, params, None)
        assert _code_of(result) != "path_required", (
            f"`{operation}` refused an absent `resource` with "
            f"`path_required`. That is EXTENSION-TREE §2.2a's `required` "
            f"column implemented — which this seat has NOT adopted, because "
            f"§4.2 (`diff`) says the field is optional in words and §3.3's "
            f"'targets no entity binding' carve-out excludes "
            f"`create`/`destroy`. Filed as SA-PY-65. If arch ruled for the "
            f"§2.2a column, this row is the retirement condition: delete it "
            f"and implement the refusal."
        )
