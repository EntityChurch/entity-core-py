"""F68 — a caller can neutralize the `resources` dimension by excluding the
target it names, and the fix is at the AUTHORIZER, not at the consumer.

Routed by ``entity-core-go`` relaying arch's
``ROUTING-2026-09-10-d`` §2/§5. Verified here at the line before implementing,
per the standing rule that a routed report's claims about our repo are hearsay.

.. rubric:: The composition

`ENTITY-CORE-PROTOCOL` §5.2's ``check_resource_scope`` **skips** a target that
the caller's own ``resource.exclude`` covers — *"redundant but valid"* — and
returns ALLOW when every target is skipped. Every consumer in this tree then
reads ``ctx.resource_targets`` **raw**: the shared
``_common.require_single_resource_target`` counts ``len(targets)``, and
``tree.py``/``inbox.py``/``subscription.py``/``identity.py``/``local_files``/
``substitute`` index ``[0]`` directly. So:

    put the path you want in ``targets``, put it in ``exclude`` as well —
    authorization passes vacuously and the handler acts on it anyway.

Ceiling is the executing handler's own grant: `F67`'s shape on the resources
dimension. The caller still needs Dimensions 1 and 2; what it no longer needs
is a grant covering the **resource**, which is the dimension the mechanism
exists for.

.. rubric:: Why the fix is one line at the gate and not a sweep of the consumers

Arch's relay prescribes *"add the caller-`exclude` reduction in the helper,
which is why the helper exists."* **The helper cannot do it**: it takes a
``HandlerContext``, and ``HandlerContext`` carries no ``resource_exclude``
field at all — ``handle_execute`` reads ``resource.exclude`` into a local,
hands it to ``check_resource_scope``, and drops it. Plumbing it through would
give the peer **two** derivations of one set (the two-representations bug, with
an authorization decision on one side), and would still leave every consumer
that does not use the helper — ``tree.py`` first among them, the most-dispatched
handler in the peer — reading the raw list.

So the reduction happens **once, at the authorizer**, and the effective set is
what the handler is given. Then:

* a consumer cannot act on a skipped target, because it never receives one;
* arch's §3.3 table falls out of the *existing* helper unchanged — effective 0
  is literally ``targets == []`` (``path_required``) and effective >1 is
  ``len(targets) != 1`` (``ambiguous_resource``);
* the next handler someone writes inherits the property without knowing it
  exists, which is the difference between a fix and a sweep.

.. rubric:: The rows, and the one arch's prescribed vector set cannot reach

===  ==========================  ==============  ====================================
row  ``targets`` / ``exclude``   effective       what it discriminates
===  ==========================  ==============  ====================================
C-1  ``[app/allowed]`` / --      ``[app/…]``     control: no exclude, unchanged
F-1  ``[secret/keys]`` /         ``[]``          the named bypass — vacuous ALLOW,
     ``[secret/keys]``                           handler acted anyway
F-2  ``[secret/keys,             ``[app/…]``     ⭐ **a count-only fix passes both of
     app/allowed]`` /                            arch's §4 vectors and still hands
     ``[secret/keys]``                           the handler ``targets[0]`` =
                                                 ``secret/keys``
F-3  ``[app/allowed, app/b]``    two             §3.3 more-than-one, unchanged by the
     / --                                        reduction
F-4  ``[app/a, app/b]`` /        ``[app/b]``     the reduction is not "drop the
     ``[app/a]``                                 request": one survivor proceeds
===  ==========================  ==============  ====================================

**F-2 is the entry.** Arch's §4 asks each seat for a two-target vector
(→ ``ambiguous_resource``) and a lone-self-excluded vector
(→ ``path_required``). A peer that fixes only the **count** — reduces to decide
the arity and then still indexes the raw list — answers both correctly and
**still acts on the target the authorizer skipped**. It is the standing law that
when a rule composes two authorities the discriminating vector is the one where
they disagree, with *arity* and *identity* as the two authorities: the two
vectors everyone writes agree on both.
"""

from __future__ import annotations

import pytest

from entity_core.capability.token import Grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity

PROBE_PATTERN = "probe/sink"
IN_SCOPE = "app/allowed"
IN_SCOPE_2 = "app/other"
OUT_OF_SCOPE = "secret/keys"

#: What the peer's default grant covers. `secret/keys` is outside it.
SCOPED_RESOURCES = ["app/*"]


class _Sink:
    """Records the resource targets each dispatch arrived with, and answers 200.

    Performs no ``check_caller_permission`` — deliberately, so what it records
    is the **dispatcher's** verdict and the set the dispatcher handed over,
    not a handler's own opinion.
    """

    def __init__(self) -> None:
        self.reached: list[list[str] | None] = []

    async def __call__(
        self, path: str, operation: str, params: dict, ctx: HandlerContext,
    ) -> dict:
        self.reached.append(list(ctx.resource_targets or []))
        return {
            "status": 200,
            "result": Entity(type="probe/sink-result", data={"ok": True}).to_dict(),
        }


@pytest.fixture
def sink() -> _Sink:
    return _Sink()


async def _serve(port: int, sink: _Sink):
    server = (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_default_handlers()
        .with_handler(PROBE_PATTERN, sink, priority=200, name="probe/sink")
        .with_default_grants([Grant.create(
            handlers=["*"], operations=["*"], resources=SCOPED_RESOURCES,
        )])
        .debug_mode(True)
        .build()
    )
    await server.start("127.0.0.1", port)
    return server


async def _drive(server, port: int, resource: dict) -> int:
    from entity_core.peer.connection import Connection

    conn = await Connection.connect("127.0.0.1", port, Keypair.generate())
    try:
        result = await conn.execute(
            f"entity://{server.peer_id}/{PROBE_PATTERN}",
            "poke",
            {"type": "probe/params", "data": {}},
            resource=resource,
        )
        return result.status
    finally:
        conn.close()
        await conn.wait_closed()


class TestTheHandlerNeverSeesASkippedTarget:
    """§5.2 — an authorizer and a consumer reading one field derive one set."""

    @pytest.mark.asyncio
    async def test_the_effective_set_is_what_reaches_the_handler(self, sink):
        server = await _serve(19091, sink)
        try:
            c1 = await _drive(server, 19091, {"targets": [IN_SCOPE]})
            f1 = await _drive(
                server, 19091,
                {"targets": [OUT_OF_SCOPE], "exclude": [OUT_OF_SCOPE]},
            )
            f2 = await _drive(
                server, 19091,
                {"targets": [OUT_OF_SCOPE, IN_SCOPE], "exclude": [OUT_OF_SCOPE]},
            )
            f4 = await _drive(
                server, 19091,
                {"targets": [IN_SCOPE, IN_SCOPE_2], "exclude": [IN_SCOPE]},
            )
        finally:
            await server.stop()

        assert c1 == 200 and sink.reached[0] == [IN_SCOPE], (
            f"C-1 control failed — an ordinary in-scope dispatch with no "
            f"exclude was refused ({c1}) or arrived with "
            f"{sink.reached[0] if sink.reached else 'nothing'}, so every row "
            f"below would be unattributable"
        )

        # F-1: the named bypass. The target is outside the grant; excluding it
        # makes `check_resource_scope` skip it and return ALLOW vacuously.
        assert sink.reached[1] == [], (
            f"F-1 — a dispatch naming {OUT_OF_SCOPE!r} in BOTH `targets` and "
            f"`exclude` reached the handler carrying {sink.reached[1]!r} under "
            f"a grant scoped to {SCOPED_RESOURCES}. The authorizer skipped "
            f"that target ('redundant but valid', §5.2) and returned ALLOW "
            f"without ever checking it against the grant; the handler then "
            f"acts on it. Effective set is empty — the handler must be handed "
            f"nothing, which is §3.3's ABSENT input"
        )

        # F-2: the row a count-only fix passes while still leaking.
        assert sink.reached[2] == [IN_SCOPE], (
            f"F-2 — with targets=[{OUT_OF_SCOPE!r}, {IN_SCOPE!r}] and "
            f"exclude=[{OUT_OF_SCOPE!r}] the handler was handed "
            f"{sink.reached[2]!r}. Effective is exactly one target and it is "
            f"{IN_SCOPE!r}; a consumer indexing [0] on the raw list acts on "
            f"{OUT_OF_SCOPE!r}, which the authorizer never checked. This row "
            f"is the discriminator: a peer that reduces only to COUNT the "
            f"arity and then indexes the raw list answers both of arch's §4 "
            f"vectors correctly and still ships the bypass"
        )
        assert f2 == 200, f"F-2's dispatch was refused ({f2}); it is a legitimate request"

        # F-4: the reduction narrows, it does not refuse.
        assert sink.reached[3] == [IN_SCOPE_2], (
            f"F-4 — excluding one of two in-scope targets must leave the other "
            f"as the effective target, not empty the request; handler got "
            f"{sink.reached[3]!r}"
        )
        assert f4 == 200

        assert f1 == 200, (
            f"F-1's dispatch status was {f1}. The DISPATCHER must not refuse "
            f"here — §5.2 calls a caller exclude over a concrete target "
            f"'redundant but valid', so a 403 would contradict the layer "
            f"below. The refusal, where the operation requires a resource, is "
            f"the handler's 400 `path_required` on an empty effective set. "
            f"This probe handler requires no resource, so 200 is correct"
        )


class TestArchsTwoVectorsCannotDiscriminateAlone:
    """The negative half of F-2, stated as its own row.

    Asserts the property that makes F-2 load-bearing: on the F-2 input the
    **arity** is right under either implementation, so a check written against
    arity alone is green on a peer that leaks. Kept as a labelled
    non-discriminator so a later reader does not count it as coverage.
    """

    @pytest.mark.asyncio
    async def test_the_arity_agrees_on_the_row_where_the_identity_does_not(
        self, sink,
    ):
        server = await _serve(19092, sink)
        try:
            await _drive(
                server, 19092,
                {"targets": [OUT_OF_SCOPE, IN_SCOPE], "exclude": [OUT_OF_SCOPE]},
            )
        finally:
            await server.stop()

        effective = sink.reached[0]
        assert len(effective) == 1, "the effective arity is 1 on this input"
        assert effective[0] == IN_SCOPE, (
            "…and the identity is what separates a reduced set from a counted "
            "one. If this line is the only one that can fail on this input, "
            "that is the finding, not a weakness in the row"
        )


class TestArchsSelfExcludedSecurityVector:
    """§4's second vector, at a real resource-requiring operation.

    Arch's check-set requirement: *"a SELF-EXCLUDED-TARGET vector →
    `400 path_required`. This one is a security vector: on a seat with the §2
    composition it currently returns `200`."*

    Driven at ``system/content:get``, which `CONTENT` §6.2 makes
    resource-requiring, over a real connection — the in-process seam accepts no
    ``exclude`` at all, so this row is **unconstructible** on the path the rest
    of the §3.3 census uses. That is the finding worth carrying about the
    vector, not just its answer: the existing 3.3 file drives
    ``_dispatch_local_execute`` for every one of its ~20 rows and could never
    have reached this input.

    Nothing in the handler changed to make this pass. The reduction at the gate
    hands the handler an empty set and the helper's **existing** absent arm
    answers — which is the argument for fixing it at the authorizer, stated as
    a measurement.
    """

    @pytest.mark.asyncio
    async def test_a_lone_self_excluded_target_is_the_absent_case(self):
        from entity_core.peer.connection import Connection

        server = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"], resources=["/*/*"],
            )])
            .debug_mode(True)
            .build()
        )
        await server.start("127.0.0.1", 19093)
        try:
            conn = await Connection.connect("127.0.0.1", 19093, Keypair.generate())
            try:
                probe = "system/probe/one"
                result = await conn.execute(
                    f"entity://{server.peer_id}/system/content",
                    "get",
                    {"type": "primitive/any",
                     "data": {"hash": b"\x00" + b"\x11" * 32}},
                    resource={"targets": [probe], "exclude": [probe]},
                )
            finally:
                conn.close()
                await conn.wait_closed()
        finally:
            await server.stop()

        code = (result.result or {}).get("data", {}).get("code", "")
        assert result.status == 400, (
            f"a `system/content:get` naming one target and excluding it "
            f"answered {result.status}. The authorizer skipped that target, "
            f"so the effective resource set is EMPTY — §3.3's ABSENT input. A "
            f"200 here is the F68 composition: the operation ran on a path "
            f"nothing authorized. Result: {result.result}"
        )
        assert code == "path_required", (
            f"answered {code!r}. Effective 0 IS the absent case — it covers "
            "'no targets' and 'a lone self-excluded target' alike, and there "
            "is no third code (§5.2 calls the exclusion 'redundant but "
            "valid', so a handler cannot call the request malformed one layer "
            "after the authorizer called it valid)"
        )


class TestArchsAntecedentControl:
    """§6 requirement 3, and arch says outright why it is a requirement:
    *"the antecedent control — same `P`, **no** `exclude` → `403
    capability_denied`. Without this arm a run cannot tell a working guard
    from a peer that denies everything."*

    It is the one requirement in the set that is **not** about F68 at all. F-1
    two classes up shows a peer refusing to act on a self-excluded
    out-of-grant target; this shows that the same target without the exclude
    is refused **by the resources dimension**, i.e. that the grant used in
    these rows genuinely does not cover `P`. Take this row away and every
    other row in the file is satisfied by a peer that 400s or 403s on
    everything.

    The pair is also the only thing that distinguishes the two refusals: F-1
    is `400 path_required` (*you asked for nothing*) and this is `403
    capability_denied` (*you asked for something you may not have*), and a
    seat that answered one code to both would have collapsed the distinction
    §5.2 turns on — that the exclusion is *"redundant but valid"* rather than
    a denial.
    """

    @pytest.mark.asyncio
    async def test_the_same_target_without_the_exclude_is_refused_by_the_grant(
        self,
    ):
        from entity_core.peer.connection import Connection

        server = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"], resources=SCOPED_RESOURCES,
            )])
            .debug_mode(True)
            .build()
        )
        await server.start("127.0.0.1", 19094)
        try:
            conn = await Connection.connect("127.0.0.1", 19094, Keypair.generate())
            try:
                payload = {"type": "primitive/any",
                           "data": {"hash": b"\x00" + b"\x11" * 32}}
                uri = f"entity://{server.peer_id}/system/content"
                denied = await conn.execute(
                    uri, "get", payload, resource={"targets": [OUT_OF_SCOPE]},
                )
                excluded = await conn.execute(
                    uri, "get", payload,
                    resource={"targets": [OUT_OF_SCOPE],
                              "exclude": [OUT_OF_SCOPE]},
                )
            finally:
                conn.close()
                await conn.wait_closed()
        finally:
            await server.stop()

        assert denied.status == 403, (
            f"{OUT_OF_SCOPE!r} is outside a grant scoped to "
            f"{SCOPED_RESOURCES} and was answered {denied.status}. Every "
            f"other row in this file assumes this target is out of grant; if "
            f"it is not, they are all measuring nothing: {denied.result}"
        )
        assert (denied.result or {}).get("data", {}).get(
            "code"
        ) == "capability_denied"

        assert excluded.status == 400, (
            "the same target, excluded, must be the ABSENT case rather than a "
            f"denial: {excluded.result}"
        )
        assert denied.status != excluded.status, (
            "a peer answering one status to both inputs has one gate. §5.2 "
            "calls the caller's own exclusion 'redundant but valid' — it is "
            "not a denial, and the caller is owed the difference"
        )


class TestTheReductionIsAtTheAuthorizerAndNotInEachConsumer:
    """Structural — the property, not a behaviour.

    ``HandlerContext`` carries no ``resource_exclude``, and it must stay that
    way: a second copy of the field downstream is an invitation for a consumer
    to re-derive the set, which is the defect. The gate narrows; consumers read.
    """

    def test_the_handler_context_carries_no_caller_exclude(self):
        import dataclasses

        fields = {f.name for f in dataclasses.fields(HandlerContext)}
        assert "resource_exclude" not in fields, (
            "HandlerContext gained a `resource_exclude` field. F68 is a "
            "two-representations defect: the authorizer narrowed the set and "
            "the consumer re-widened it. Handing consumers the caller's "
            "exclude re-creates the second derivation this fix removed — the "
            "effective set is computed once, at the gate, and installed as "
            "`resource_targets`"
        )

    def test_the_gate_reduces_before_it_builds_the_context(self):
        """Reads the source: the reduction must precede the handler context.

        A reviewer reading a correct-looking `HandlerContext(...)` call cannot
        see that one of its arguments has already been narrowed, so the order
        is pinned here rather than left to a behavioural row.
        """
        import inspect

        from entity_core.peer import Peer

        # Scoped to the wire dispatch method. `resource_targets=` appears at
        # five construction sites in this module and a whole-file `find` picks
        # up whichever comes first, which is not a statement about this one.
        src = inspect.getsource(Peer._handle_execute)
        # The ASSIGNMENT, not the import. A row that greps for the identifier
        # alone stays green when the reduction is deleted and the import is
        # left behind — measured: the precise F68 mutation (drop the rebind,
        # keep everything else) reddened the two behavioural rows and left
        # this one green until the assertion was written this way.
        assert "resource_targets = effective_resource_targets(" in src, (
            "the wire dispatch no longer REBINDS `resource_targets` to the "
            "effective set before building the handler context. Importing the "
            "reduction is not applying it — F68 is the authorizer narrowing a "
            "set and the consumer re-widening it, and this row is the only "
            "one that can see the rebind go missing without a behavioural "
            "vector for the exact handler that regressed"
        )
        assert src.find("resource_targets = effective_resource_targets(") < src.find(
            "resource_targets=resource_targets,"
        ), (
            "the HandlerContext is built from `resource_targets` BEFORE the "
            "reduction rebinds it. A reviewer reading a correct-looking "
            "`HandlerContext(...)` call cannot see that one of its arguments "
            "has not yet been narrowed, which is why the order is pinned here"
        )
