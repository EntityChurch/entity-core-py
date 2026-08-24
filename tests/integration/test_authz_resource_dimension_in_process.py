"""V7 §5.2 — the `resources` grant dimension on the **in-process** dispatch path.

`ENTITY-CORE-PROTOCOL` §5.2 makes the dispatch-level check the primary one and
the handler's own check secondary::

    When the EXECUTE includes a `resource` field, the same grant's `resources`
    scope must also cover the resource. This check happens at dispatch, before
    the handler runs.  … When `resource` is present, this is a secondary
    defense-in-depth check — the dispatch-level `check_permission` handles the
    primary resource check.

`handle_execute` (the wire path) runs it. `_dispatch_local_execute` does not:
`resource_targets` is accepted and forwarded into the child `HandlerContext`
and nothing on that path consults `grant.resources`. So on an internal
sub-dispatch the *primary* check is absent and the only enforcement left is the
secondary one — which exists in **7 of 76** handler modules.

This is the third instance of *two dispatch paths, and the in-process one is
the untested half*, and the second time in two sessions that a capability
dimension turned out to be parsed/forwarded but never read.

.. rubric:: The rows

===  ==========================================  ==========  =======================
row  grant.resources / dispatch resource target  required    seam
===  ==========================================  ==========  =======================
D-1  ``app/*`` / ``app/allowed``                 ALLOW       in-process (control)
D-2  ``app/*`` / ``secret/keys``                 **DENY**    in-process
W-1  ``app/*`` / ``app/allowed``                 ALLOW       wire (control)
W-2  ``app/*`` / ``secret/keys``                 **DENY**    wire
===  ==========================================  ==========  =======================

D-1 and W-1 are the controls. Without them a peer that denied everything — or a
handler that was never reachable in this fixture at all — would score two green
denials, which is the failure mode the CAP-6a probe hit for real when a
transport drop got counted as a refusal.

The probe handler is synthetic on purpose: it performs no
`ctx.check_caller_permission`, so what it records is the **dispatcher's**
verdict and not a handler's. `TestTheGapIsReachableFromAShippedHandler` then
shows the same hole under a real one — `system/handler:register`, which derives
the install pattern from `resource_targets[0]` and deliberately does no check of
its own, because §6.2 assigns that job to dispatch:

    The handler path is the caller's authorization target — the standard
    dispatch capability check on `resource` validates that the caller may
    install/remove a handler at that path.
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
OUT_OF_SCOPE = "secret/keys"

#: What the caller (a handler, dispatching internally under its own grant) holds.
SCOPED_RESOURCES = ["app/*"]


class _Sink:
    """Records every dispatch that reached it, and answers 200.

    No `check_caller_permission` — deliberately. A handler that checks would
    mask the dispatcher's verdict, and masking is the state 69 of this repo's
    76 handler modules are actually in.
    """

    def __init__(self) -> None:
        self.reached: list[list[str] | None] = []

    async def __call__(
        self, path: str, operation: str, params: dict, ctx: HandlerContext,
    ) -> dict:
        self.reached.append(ctx.resource_targets)
        return {
            "status": 200,
            "result": Entity(type="probe/sink-result", data={"ok": True}).to_dict(),
        }


def _cap(resources: list[str]) -> dict:
    """A grant that is wide open on every axis except `resources`."""
    return {
        "grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "peers": {"include": ["*"]},
            "resources": {"include": resources},
        }]
    }


@pytest.fixture
def sink() -> _Sink:
    return _Sink()


@pytest.fixture
def peer(sink):
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_default_handlers()
        .with_handler(PROBE_PATTERN, sink, priority=200, name="probe/sink")
        .build()
    )


async def _dispatch(peer, target: str):
    return await peer._dispatch_local_execute(
        PROBE_PATTERN,
        "poke",
        {"type": "probe/params", "data": {}},
        _cap(SCOPED_RESOURCES),
        None,
        None,
        resource_targets=[target],
    )


class TestInProcessDispatch:
    @pytest.mark.asyncio
    async def test_a_target_inside_the_grant_reaches_the_handler(self, peer, sink):
        """D-1, the control: without it the denial below is unattributable."""
        result = await _dispatch(peer, IN_SCOPE)
        assert result.status == 200, (
            f"the control failed — an in-scope in-process dispatch was refused "
            f"({result.status}: {result.error}), so a refusal of the out-of-scope "
            f"target would not be attributable to the resources dimension"
        )
        assert sink.reached == [[IN_SCOPE]]

    @pytest.mark.asyncio
    async def test_a_target_outside_the_grant_does_not(self, peer, sink):
        """D-2 — the escalation.

        §5.2: the same grant's `resources` scope must cover the resource, and
        the check happens *at dispatch, before the handler runs*.
        """
        result = await _dispatch(peer, OUT_OF_SCOPE)
        assert sink.reached == [], (
            f"an in-process dispatch carrying resource target {OUT_OF_SCOPE!r} "
            f"reached the handler under a grant scoped to {SCOPED_RESOURCES} — "
            f"§5.2's dispatch-level resource check is not run on "
            f"_dispatch_local_execute, so the primary check is absent and only "
            f"a handler's own (optional) secondary check stands between a "
            f"sub-dispatch and any path on the peer"
        )
        assert result.status == 403


class TestTheWirePathAgrees:
    """The same two rows over a real connection — the seam that *does* check.

    Present so the in-process rows are read as a divergence between two paths
    rather than as a claim about the resource dimension as a whole.
    """

    async def _serve(self, port: int, sink):
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

    async def _status(self, server, port: int, target: str) -> int:
        from entity_core.peer.connection import Connection

        conn = await Connection.connect("127.0.0.1", port, Keypair.generate())
        try:
            result = await conn.execute(
                f"entity://{server.peer_id}/{PROBE_PATTERN}",
                "poke",
                {"type": "probe/params", "data": {}},
                resource={"targets": [target]},
            )
            return result.status
        finally:
            conn.close()
            await conn.wait_closed()

    @pytest.mark.asyncio
    async def test_the_wire_path_allows_in_scope_and_refuses_out_of_scope(self, sink):
        server = await self._serve(19081, sink)
        try:
            allowed = await self._status(server, 19081, IN_SCOPE)
            refused = await self._status(server, 19081, OUT_OF_SCOPE)
        finally:
            await server.stop()

        assert allowed == 200, (
            f"W-1 control failed — an in-scope wire dispatch was refused "
            f"({allowed})"
        )
        assert refused == 403, (
            f"W-2 — the wire path admitted resource target {OUT_OF_SCOPE!r} "
            f"under a grant scoped to {SCOPED_RESOURCES} (status {refused})"
        )


class TestAForeignGrantedCapFramesAgainstItsGranter:
    """§PR-8 / §5.5a, and the reason core-go's join fixture is now refused here.

    `EXTENSION-CONTINUATION` §3.6 step 5 sets
    ``execute.capability = continuation.data.dispatch_capability``, and §3.5
    requires that capability be "checked at dispatch time … against the final
    EXECUTE". Running that check is what this commit added; what it exposed is
    a *second* thing, one layer down.

    core-go's `installJoinFromData` mints the dispatch capability with
    ``Granter = client identity`` and ``resources = join.Resource.Targets`` —
    peer-relative strings like ``system/inbox/validate-join-target``. §5.5a
    canonicalizes a grant's own resource patterns against the **granter's**
    peer_id, so on the servicing peer those name
    ``/{client}/system/inbox/…`` and authorize nothing in the server's
    namespace. `ENTITY-CORE-PROTOCOL` §5.5a is explicit that this is the
    intended reading and that helpers minting such caps are non-conformant:

        A bare peer-relative resource on a foreign-granted cap does NOT
        authorize the target peer's namespace … cross-peer cap minting helpers
        (test fixtures, integration test scaffolds, …) MUST use explicit
        cross-peer form for cap resources.

    The pair below is the evidence, driven against the engine rather than
    argued from the text: same target, same handler, same operation, two
    spellings of the grant's resources, opposite verdicts.
    """

    def _foreign_granted(self, peer, resources: list[str]) -> dict:
        """A cap whose granter resolves to a *different* peer's identity."""
        from entity_core.protocol.auth import create_identity_entity

        foreign_identity = create_identity_entity(Keypair.generate())
        peer.content_store.put(foreign_identity)
        cap = _cap(resources)
        cap["granter"] = foreign_identity.compute_hash()
        return cap

    def _admits(self, peer, cap: dict, target: str) -> bool:
        from entity_core.capability.checking import (
            check_resource_scope,
            granter_frame_peer_id,
        )

        return check_resource_scope(
            cap, "system/inbox", "receive", [target], None, peer.peer_id,
            granter_peer_id=granter_frame_peer_id(
                cap, peer.peer_id, peer._resolve_identity_entity,
            ),
            target_peer=peer.peer_id,
        )

    def test_peer_relative_resources_name_the_granters_namespace(self, peer):
        target = "system/inbox/validate-join-target"
        cap = self._foreign_granted(peer, [target])
        assert self._admits(peer, cap, target) is False, (
            "a foreign-granted cap with a peer-relative resource authorized the "
            "local namespace — §5.5a frames a grant's own patterns against the "
            "granter, and collapsing that to the verifier is the V2(a) "
            "under-enforcement the rule exists to prevent"
        )

    def test_explicit_cross_peer_form_is_what_authorizes_it(self, peer):
        """The control, and the shape a conformant helper mints."""
        target = "system/inbox/validate-join-target"
        cap = self._foreign_granted(peer, [f"/{peer.peer_id}/{target}"])
        assert self._admits(peer, cap, target) is True, (
            "explicit cross-peer form was refused — the frame rule is now "
            "denying what it should allow, which is the failure in the other "
            "direction"
        )

    def test_a_self_granted_cap_is_unaffected(self, peer):
        """Why nothing in this repo's own suite moved: when granter == verifier
        the two frames are byte-identical, which is exactly why §PR-8 stayed
        latent in every implementation until a foreign-granter case appeared."""
        target = "system/inbox/validate-join-target"
        assert self._admits(peer, _cap([target]), target) is True


class TestTheGapIsReachableFromAShippedHandler:
    """`system/handler:register` under a resource-scoped grant.

    §6.2 assigns the authorization of the install path to the dispatch-level
    resource check, and `_handle_register` accordingly does no check of its own
    — it reads `resource_targets[0]`, strips `system/handler/`, and installs.
    So on the in-process path the install pattern is unauthorized by anything.

    Asserted at the handler boundary rather than on the eventual registration:
    a 400 from the handler's *own* validation is already proof that dispatch
    admitted the request, which is the thing under test.
    """

    @pytest.mark.asyncio
    async def test_registering_outside_the_grants_resources_is_refused(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .with_handlers_handler()
            .build()
        )
        result = await peer._dispatch_local_execute(
            "system/handler",
            "register",
            {"type": "system/handler/register-request", "data": {}},
            _cap(SCOPED_RESOURCES),
            None,
            None,
            resource_targets=["system/handler/pwn"],
        )
        assert result.status == 403, (
            f"an in-process dispatch reached system/handler:register with "
            f"install pattern 'pwn' under a grant scoped to "
            f"{SCOPED_RESOURCES} (status {result.status}: {result.error}). "
            f"§6.2 makes the dispatch-level resource check the *only* "
            f"authorization of the install path — the handler performs none."
        )
