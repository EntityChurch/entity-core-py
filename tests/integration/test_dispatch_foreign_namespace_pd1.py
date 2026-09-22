"""PD-1h — an inbound EXECUTE whose handler uri names a peer that is not us.

§1.4 *"Inbound dispatch (wire listener)"*: the path MUST target the local
peer's namespace, and a peer ID that does not match MUST be refused with
**400 `invalid_request`** (0.8.2.2 names the code; the status was already
pinned). §6.5 step 3 makes it a **gate, not an ordering preference** — the
refusal runs at canonicalization, *before* handler resolution and before
`check_permission`, and MUST NOT be reached by stripping the peer id,
resolving the local handler, and letting §5.2 decide.

.. rubric:: What this peer did

Stripped the peer id, resolved the *local* handler, and answered **200** under
a uri naming a peer that is not us — whenever the grant's `peers` scope
covered the named peer. All three ground-up impls were in that minority;
`entity-core-go` measured it on our peer at `ebe7a92` and it reproduces here
(`test_the_escalation_this_gate_closes`). §9.1 now names go's
`dispatch_inbound_foreign_namespace_refused` as the driver.

.. rubric:: The three things that are NOT gated, each with a row

1. **A resource target in a foreign namespace.** `/{them}/…` in
   `resource.targets` is the §1.4 universal-address-space slot: the peer's
   store is one local address space keyed by peer id, so writing there is a
   *local* write. The gate reads the **handler** uri and nothing else. This is
   the row that would break every follow-mirror write if the gate were put on
   the wrong field, and 0.8.2.3 withdrew a proposed `resources` narrowing for
   the same reason.
2. **A peer-relative uri.** `canonicalize` resolves it to the local peer, so
   `extract_peer` answers local and it must pass.
3. **In-process sub-dispatch.** The gate is on the inbound wire path only;
   §1.4's internal-dispatch class is where §5.2 Dimension 4 still decides.

.. rubric:: What this gate costs, stated rather than discovered later

Post-gate, the §5.2 `peers` dimension is **no longer observable from an
external wire probe** — every foreign-handler-uri EXECUTE is refused before
authorization, so the dimension's remaining live case is sub-dispatch, which
needs handler code installed on the peer under test. That is the finding go
records as PD-1d #2 (*"unconstructible from an external wire probe"*), and it
is why `test_authz_peers_dimension.py`'s over-the-wire class was re-pointed at
this gate rather than deleted: the rows still run, they now assert a different
refusal, and the dimension keeps its teeth at the predicate.
"""

from __future__ import annotations

import pytest

from entity_core.capability.token import Grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder

#: Syntactic but unowned — 46 Base58 chars, the shape every implementation's
#: `is_peer_id` accepts. Shared with `test_authz_peers_dimension.py` so the two
#: files' rows stay comparable.
FOREIGN = "1FZfarForeignPeerRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"

PORT = 19084


class _Peer:
    """A started peer plus a connected client, with the grant under test."""

    def __init__(self, grants):
        self._grants = grants

    async def __aenter__(self):
        from entity_core.peer.connection import Connection

        self.server = (
            PeerBuilder().with_keypair(Keypair.generate())
            .with_default_handlers().with_default_grants(self._grants)
            .debug_mode(True).build()
        )
        await self.server.start("127.0.0.1", PORT)
        self.conn = await Connection.connect("127.0.0.1", PORT, Keypair.generate())
        return self

    async def __aexit__(self, *exc):
        self.conn.close()
        await self.conn.wait_closed()
        await self.server.stop()

    async def get(self, uri: str, **kwargs):
        return await self.conn.execute(
            uri, "get", {"data": {"path": "app/anything"}}, **kwargs,
        )


def _wildcard_peers() -> list[Grant]:
    """The only grant shape under which the escalation was ever reachable.

    A grant that does not cover the foreign peer answered 403, so it cannot
    tell a gate from an authorization denial. Driving the rows under
    `peers: ["*"]` is what makes the 400 attributable to the gate.
    """
    return [Grant.create(
        handlers=["*"], resources=["*", "/*/*"], operations=["*"], peers=["*"],
    )]


class TestTheGate:
    @pytest.mark.asyncio
    async def test_a_foreign_handler_uri_is_refused_400_invalid_request(self):
        async with _Peer(_wildcard_peers()) as p:
            foreign = await p.get(f"entity://{FOREIGN}/system/tree")
            local = await p.get(f"entity://{p.server.peer_id}/system/tree")

        assert int(local.status) != 400, (
            f"the control failed — a LOCAL handler uri was refused "
            f"({int(local.status)}), so a foreign refusal would not be "
            f"attributable to the peer segment rather than to a malformed "
            f"request"
        )
        assert int(foreign.status) == 400, (
            f"an inbound EXECUTE naming peer {FOREIGN}'s namespace answered "
            f"{int(foreign.status)}; §1.4 requires 400 at canonicalization"
        )
        assert foreign.result["data"]["code"] == "invalid_request", (
            f"code was {foreign.result['data']['code']!r}; §3.3 pins "
            f"`invalid_request` for an inbound EXECUTE naming a non-local "
            f"namespace"
        )

    @pytest.mark.asyncio
    async def test_the_escalation_this_gate_closes(self):
        """The pre-fix behaviour, asserted as *absent* rather than described.

        200 here is the escalation: the peer resolved its own `system/tree`
        handler and executed it under a uri naming someone else.
        """
        async with _Peer(_wildcard_peers()) as p:
            foreign = await p.get(f"entity://{FOREIGN}/system/tree")

        assert int(foreign.status) != 200, (
            "the peer EXECUTED a local handler under a foreign peer's uri — "
            "this is the PD-1 escalation measured across all three ground-up "
            "impls"
        )

    @pytest.mark.asyncio
    async def test_it_is_not_reported_as_handler_not_found(self):
        """§6.2 (0.8.2.2 scope clarification): a foreign-namespace path is
        **not** `404 handler_not_found`, and the distinction is load-bearing —
        404 asserts *"this peer has no such handler"*, which is false of a
        peer that has the handler and is refusing the **address**. It tells a
        caller to stop asking for a handler that exists."""
        async with _Peer(_wildcard_peers()) as p:
            foreign = await p.get(f"entity://{FOREIGN}/system/tree")
            unknown = await p.get(
                f"entity://{FOREIGN}/no/such/handler/anywhere",
            )

        assert int(foreign.status) == 400
        assert int(unknown.status) == 400, (
            f"a foreign uri at an unregistered path answered "
            f"{int(unknown.status)} — the gate runs BEFORE handler "
            f"resolution (§6.5 step 3), so the peer cannot have looked"
        )

    @pytest.mark.asyncio
    async def test_it_is_not_reached_by_letting_authorization_decide(self):
        """§6.5 step 3's *"gate, not an ordering preference"* clause.

        Under a grant whose `peers` scope does NOT cover the foreign peer,
        §5.2 would refuse with 403 all by itself. A conformant peer still
        answers 400, because the gate ran first — so this row discriminates
        an implementation that reached the refusal through authorization.
        """
        local_only = [Grant.create(
            handlers=["*"], resources=["*", "/*/*"], operations=["*"],
        )]
        async with _Peer(local_only) as p:
            foreign = await p.get(f"entity://{FOREIGN}/system/tree")
            local = await p.get(f"entity://{p.server.peer_id}/system/tree")

        assert int(local.status) != 403, (
            f"control: the local dispatch was denied ({int(local.status)})"
        )
        assert int(foreign.status) == 400, (
            f"answered {int(foreign.status)} — a 403 here means the peer "
            f"stripped the peer id, resolved the local handler and let §5.2 "
            f"decide, which §6.5 step 3 forbids"
        )


class TestWhatIsNotGated:
    @pytest.mark.asyncio
    async def test_a_foreign_resource_target_under_a_local_handler_uri(self):
        """§1.4 universal address space — the row that keeps follow-mirror
        writes working. The store is one local address space keyed by peer
        id; `/{them}/…` names a **local** region holding that peer's mirrored
        data, and writing there is a local write, not a remote reach. The
        gate reads the handler uri, which is local here."""
        async with _Peer(_wildcard_peers()) as p:
            put = await p.conn.execute(
                f"entity://{p.server.peer_id}/system/tree", "put",
                {"data": {
                    "path": f"/{FOREIGN}/app/mirrored",
                    "entity": {"type": "app/note", "data": {"v": 1}},
                }},
                resource={"targets": [f"/{FOREIGN}/app/mirrored"]},
            )

        assert int(put.status) != 400, (
            f"a write to the foreign-namespace REGION of the local store was "
            f"refused {int(put.status)} — the gate is reading the resource "
            f"target instead of the handler uri, which breaks every "
            f"follow-mirror write (the reason 0.8.2.3 withdrew the proposed "
            f"`resources` narrowing)"
        )

    @pytest.mark.asyncio
    async def test_a_peer_relative_uri_is_local(self):
        """`canonicalize` resolves a peer-relative path to the local peer, so
        `extract_peer` answers local and the gate must not fire. A gate
        written as *"does the uri start with someone else's id"* rather than
        on `extract_peer`'s answer fails this row."""
        async with _Peer(_wildcard_peers()) as p:
            relative = await p.get("system/tree")

        assert int(relative.status) != 400, (
            f"a peer-relative uri was refused {int(relative.status)}; it "
            f"canonicalizes to the local peer"
        )
