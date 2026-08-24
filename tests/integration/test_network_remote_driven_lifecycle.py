"""§4.1 lifecycle driven by a REMOTE caller over the wire.

Regression for the maintain-peer 403->500 that gated validate-peer's whole
network category (probe 1, 500 internal_error, ~21ms).

The handler's lifecycle subscribe is self-authored bookkeeping: it delivers to
this peer's OWN inbox under a self-granted deliver_token (granter == grantee ==
local identity). But a plain `ctx.execute` sub-dispatch inherits the *inbound
caller's* identity and capability — the V7 §6.8 propagation default seeded by
Peer._make_execute_dispatcher. So under a remote driver the subscribe presented
validate-peer's identity against a token chain containing only the local peer,
and EXTENSION-SUBSCRIPTION §3.1's SB1 creator-authority check refused it 403
`embedded_cap_unauthorized` — which _subscribe_lifecycle then masked as a 500.

That is why tests/integration/test_network_lifecycle.py stayed green while the
live probe died: those vectors drive maintain-peer via _dispatch_local_execute,
where the author already IS the local peer. Only the wire path regresses, so
only a wire-path test pins it.
"""

from __future__ import annotations

import asyncio

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.auth import create_identity_entity
from entity_handlers.network import _upstream_error


def _cli_peer(kp: Keypair) -> Peer:
    """The stack cmd_start builds: with_all_handlers + debug_mode — i.e. what
    peer-manager starts for a validate-peer run."""
    return (
        PeerBuilder()
        .with_keypair(kp)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )


def _admin_grant(peer: Peer) -> dict:
    return {
        "grants": [g.to_dict() for g in create_full_access_grant()],
        "granter": peer.peer_id,
        "grantee": peer.peer_id,
    }


def _bound_port(peer: Peer) -> int:
    return peer._server.sockets[0].getsockname()[1]


def _subscription_owners(peer: Peer) -> set[bytes]:
    owners: set[bytes] = set()
    for uri in peer.entity_tree.list_prefix("system/subscription/"):
        h = peer.entity_tree.get(uri)
        ent = peer.content_store.get(h) if h else None
        if ent and ent.type == "system/subscription":
            owners.add(bytes(ent.data["subscriber_identity"]))
    return owners


class TestRemoteDrivenMaintainPeer:
    """validate-peer's probe 1: a remote caller EXECUTEs system/network
    maintain-peer over a live connection."""

    def test_maintain_and_release_over_the_wire(self):
        async def run():
            target_kp, third_kp = Keypair.generate(), Keypair.generate()
            target = _cli_peer(target_kp)
            await target.start("127.0.0.1", 0)
            third = _cli_peer(third_kp)
            await third.start("127.0.0.1", 0)
            try:
                conn = await Connection.connect(
                    "127.0.0.1", _bound_port(target), Keypair.generate()
                )
                try:
                    resp = await conn.execute(
                        "system/network",
                        "maintain-peer",
                        params={
                            "type": "system/network/maintain-request",
                            "data": {
                                "peer_id": third.peer_id,
                                "address": f"127.0.0.1:{_bound_port(third)}",
                            },
                        },
                    )
                    assert resp.status == 200, f"{resp.status}: {resp.result}"
                    assert len(resp.result["data"]["subscriptions"]) == 2

                    # Self-owned: the subscriber is the local peer, NOT the
                    # remote that drove maintain-peer. Otherwise release-peer
                    # (and delivery-time token re-validation) bind to that
                    # caller.
                    local_hash = create_identity_entity(
                        target.keypair
                    ).compute_hash()
                    assert _subscription_owners(target) == {local_hash}

                    # The teardown half must mirror the same pinning.
                    rel = await conn.execute(
                        "system/network",
                        "release-peer",
                        params={
                            "type": "system/network/release-request",
                            "data": {
                                "peer_id": third.peer_id,
                                "reason": "shutdown",
                            },
                        },
                    )
                    assert rel.status == 200, f"{rel.status}: {rel.result}"
                    assert rel.result["data"]["cleaned_up"]
                finally:
                    conn.close()
            finally:
                await target.stop()
                await third.stop()

        asyncio.run(run())

    def test_maintain_peer_locally_still_passes(self):
        """The local path the existing vectors exercise — kept as the contrast
        that made the wire-only nature of the bug visible."""
        async def run():
            server_kp, client_kp = Keypair.generate(), Keypair.generate()
            server = _cli_peer(server_kp)
            await server.start("127.0.0.1", 0)
            client = _cli_peer(client_kp)
            try:
                result = await client._dispatch_local_execute(
                    "system/network",
                    "maintain-peer",
                    {
                        "type": "system/network/maintain-request",
                        "data": {
                            "peer_id": server.peer_id,
                            "address": f"127.0.0.1:{_bound_port(server)}",
                        },
                    },
                    _admin_grant(client),
                    None,
                    None,
                    resource_targets=["system/network"],
                )
                assert result.status == 200, f"{result.status}: {result.error}"
            finally:
                await server.stop()

        asyncio.run(run())


class TestUpstreamErrorNotMasked:
    """A refused sub-dispatch must surface its own status/code — collapsing
    everything into 500 internal_error is what hid the 403 for two rounds."""

    def test_extracts_upstream_code_and_message(self):
        class _R:
            status = 403
            error = None
            result = {
                "type": "system/protocol/error",
                "data": {
                    "code": "embedded_cap_unauthorized",
                    "message": (
                        "Subscriber identity not in deliver_token authority chain"
                    ),
                },
            }

        code, message = _upstream_error(_R())
        assert code == "embedded_cap_unauthorized"
        assert "authority chain" in message

    def test_falls_back_to_internal_error(self):
        class _R:
            status = 500
            error = "boom"
            result = None

        assert _upstream_error(_R()) == ("internal_error", "boom")
