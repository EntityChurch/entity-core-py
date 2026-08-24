"""EXTENSION-NETWORK §6.7 reachability facts (Amendment 13).

The two operations plus the three MUSTs that make them safe. Each MUST here
is a cross-peer seam where two conformant readings diverge into a security
hole, so each gets a vector that *would go green on the wrong reading* if it
only asserted status — the body-supplied-address vectors assert the returned
address is the observed one and **not** the value the request supplied.

Live TCP throughout, not in-process dispatch: the whole mechanism is that the
responder reads the transport source of an *accepted* connection, and an
in-process call has no such source to read (which is itself pinned below).
"""

from __future__ import annotations

import asyncio

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_handlers.reachability import (
    CANDIDATE_HOST,
    CANDIDATE_PRIORITY,
    CANDIDATE_RELAY,
    CANDIDATE_SRFLX,
    DIALBACK_MIN_INTERVAL_S,
    REFLECT_MIN_INTERVAL_S,
    RateLimiter,
    dial_back,
    split_host_port,
)

NETWORK_URI = "system/network"
BOGUS_ADDRESS = "203.0.113.99:1"


def _build_peer(kp: Keypair) -> Peer:
    return (
        PeerBuilder()
        .with_keypair(kp)
        .with_default_handlers()
        .with_network_handler()
        .debug_mode(True)
        .build()
    )


def _bound_port(peer: Peer) -> int:
    return peer._server.sockets[0].getsockname()[1]


async def _pair() -> tuple[Peer, Peer, Keypair]:
    """A started responder and a client that can dial it."""
    server_kp, client_kp = Keypair.generate(), Keypair.generate()
    server = _build_peer(server_kp)
    await server.start("127.0.0.1", 0)
    client = _build_peer(client_kp)
    client.register_remote(
        server.peer_id, f"127.0.0.1:{_bound_port(server)}",
        public_key=server_kp.public_key_bytes(),
    )
    return server, client, client_kp


async def _observe(client: Peer, server: Peer, params=None):
    return await client._remote_execute(
        f"entity://{server.peer_id}/{NETWORK_URI}",
        "observe-address",
        params,
        resource_targets=[NETWORK_URI],
    )


async def _check_reachability(client: Peer, server: Peer, params=None):
    return await client._remote_execute(
        f"entity://{server.peer_id}/{NETWORK_URI}",
        "check-reachability",
        params,
        resource_targets=[NETWORK_URI],
    )


def _client_source_port(client: Peer, server: Peer) -> int:
    """The local port the client's pooled connection to `server` dials from —
    the mapping the responder observes, in NAT terms."""
    conn = client._remote_pool._connections[server.peer_id]
    return conn.writer.get_extra_info("sockname")[1]


class TestObserveAddress:
    """§6.7.1 — reflect the transport source of THIS connection."""

    def test_reflects_the_real_transport_source(self):
        async def run():
            server, client, _ = await _pair()
            try:
                result = await _observe(client, server)
                assert result.status == 200, result.error
                assert result.result["type"] == "system/network/observe-address-result"
                observed = result.result["data"]["observed_address"]
                # The responder saw exactly the client's local endpoint: the
                # ephemeral source port is the whole point — a peer behind a
                # NAT cannot name this itself.
                assert observed == f"127.0.0.1:{_client_source_port(client, server)}"
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_body_supplied_address_is_ignored(self):
        """§6.7.1 MUST 1 — never a value echoed from the request body.

        A body-supplied address makes the responder a laundering service for
        an attacker's chosen address. Status alone cannot tell a conformant
        peer from one that echoes, so this asserts the *value*.
        """
        async def run():
            server, client, _ = await _pair()
            try:
                result = await _observe(client, server, {
                    "type": "system/network/observe-address-result",
                    "data": {"observed_address": BOGUS_ADDRESS},
                })
                assert result.status == 200, result.error
                observed = result.result["data"]["observed_address"]
                assert observed != BOGUS_ADDRESS
                assert observed == f"127.0.0.1:{_client_source_port(client, server)}"
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_observed_address_is_never_persisted(self):
        """§6.7.1 MUST 2 — not `system/connection.address`, not a
        `system/peer/transport/*` profile, not `system/peer/status`.

        Asserted as an absence across the responder's whole store rather than
        field-by-field: the spec's point is that the first cheap instinct
        (writing it to the record that already has an `address` field, keyed
        by peer, already reachable from the handler) corrupts dispatch for
        every other reader. A per-field assertion would pass against the next
        wrong field.
        """
        async def run():
            server, client, _ = await _pair()
            try:
                result = await _observe(client, server)
                assert result.status == 200, result.error
                observed = result.result["data"]["observed_address"]
                source_port = str(_client_source_port(client, server))

                for uri in server.entity_tree.list_prefix(""):
                    h = server.entity_tree.get(uri)
                    if h is None:
                        continue
                    entity = server.content_store.get(h)
                    if entity is None:
                        continue
                    blob = repr(entity.data)
                    assert observed not in blob, f"observed address persisted at {uri}"
                    assert source_port not in blob, f"source port persisted at {uri}"
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_in_process_dispatch_has_no_transport_source(self):
        """No accepted connection ⇒ 400, never a substituted address.

        The seam that makes MUST 1 structural: `observed_source_address` is
        populated only by the accept-side dispatch path, so a peer with no
        observation says so rather than inventing one.
        """
        async def run():
            peer = _build_peer(Keypair.generate())
            try:
                from entity_core.capability.grant import create_full_access_grant

                result = await peer._dispatch_local_execute(
                    NETWORK_URI, "observe-address", None,
                    {
                        "grants": [g.to_dict() for g in create_full_access_grant()],
                        "granter": peer.peer_id,
                        "grantee": peer.peer_id,
                    },
                    None, None, resource_targets=[NETWORK_URI],
                )
                assert result.status == 400
                assert result.result["type"] == "system/protocol/error"
                assert result.result["data"]["code"] == "no_transport_source"
            finally:
                await peer.stop()

        asyncio.run(run())


class TestCheckReachability:
    """§6.7.2 — dial back the requester's OWN observed source."""

    def test_dials_back_the_observed_source_and_reports_it(self):
        async def run():
            server, client, _ = await _pair()
            try:
                result = await _check_reachability(client, server)
                assert result.status == 200, result.error
                assert result.result["type"] == "system/network/check-reachability-result"
                data = result.result["data"]
                # `address_tested` is the responder's own observation, echoed
                # so the requester can confirm WHICH address was proved
                # rather than inferring it.
                assert data["address_tested"] == (
                    f"127.0.0.1:{_client_source_port(client, server)}"
                )
                # The client dialed out from an ephemeral port and is not
                # listening on it, so the honest answer is "not reachable".
                # A peer that reported True here would be reporting on a
                # connection it already had, not on a dial that arrived.
                assert data["reachable"] is False
                assert isinstance(data["reachable"], bool)
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_body_supplied_target_is_ignored(self):
        """The load-bearing MUST: a body-supplied target turns every
        dial-back peer into a DDoS reflector.

        The attacker's address here is a documentation-range address that is
        not listening; the assertion is that it was neither dialed nor
        reported — `address_tested` is the observed source.
        """
        async def run():
            server, client, _ = await _pair()
            try:
                result = await _check_reachability(client, server, {
                    "type": "system/network/check-reachability-result",
                    "data": {"address_tested": BOGUS_ADDRESS, "reachable": True},
                })
                assert result.status == 200, result.error
                data = result.result["data"]
                assert data["address_tested"] != BOGUS_ADDRESS
                assert data["address_tested"] == (
                    f"127.0.0.1:{_client_source_port(client, server)}"
                )
                assert data["reachable"] is False
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())

    def test_dial_back_true_when_the_address_accepts(self):
        """The positive half of the probe, exercised directly.

        `reachable` must be able to be True, or the cross-peer vector above
        proves only that the responder always says False.
        """
        async def run():
            server = await asyncio.start_server(
                lambda r, w: w.close(), "127.0.0.1", 0,
            )
            port = server.sockets[0].getsockname()[1]
            try:
                assert await dial_back(f"127.0.0.1:{port}") is True
            finally:
                server.close()
                await server.wait_closed()
            # Closed listener: the same address is now unreachable.
            assert await dial_back(f"127.0.0.1:{port}") is False

        asyncio.run(run())


class TestRateLimiting:
    """§6.7.4 — both operations are always rate-limited, dial-back tighter."""

    def test_per_requester_min_interval(self):
        limiter = RateLimiter(interval_s=60.0)
        assert limiter.allow("peer-a") is True
        assert limiter.allow("peer-a") is False
        # Limiting is per requester: one peer's burst cannot deny another.
        assert limiter.allow("peer-b") is True

    def test_in_process_requester_is_never_limited(self):
        limiter = RateLimiter(interval_s=60.0)
        assert limiter.allow(None) is True
        assert limiter.allow(None) is True

    def test_dialback_is_limited_more_tightly_than_reflection(self):
        # §6.7.4's asymmetry: reflection is a mirror; dial-back makes this
        # peer emit traffic at an address.
        assert DIALBACK_MIN_INTERVAL_S > REFLECT_MIN_INTERVAL_S

    def test_second_immediate_observe_is_rate_limited(self):
        async def run():
            server, client, _ = await _pair()
            try:
                first = await _observe(client, server)
                assert first.status == 200, first.error
                second = await _observe(client, server)
                assert second.status == 429
                assert second.result["data"]["code"] == "rate_limited"
            finally:
                await client.stop()
                await server.stop()

        asyncio.run(run())


class TestAddressParsing:
    """`address_tested` is dialed back, so its parse is a security surface."""

    def test_ipv4(self):
        assert split_host_port("203.0.113.7:51820") == ("203.0.113.7", 51820)

    def test_ipv6_is_bracketed(self):
        assert split_host_port("[2001:db8::1]:51820") == ("2001:db8::1", 51820)

    def test_rejects_unbracketed_ipv6(self):
        # Ambiguous at the colon — refused rather than guessed.
        assert split_host_port("2001:db8::1:51820") is None

    def test_rejects_malformed(self):
        for bad in ("", "no-port", "host:", "host:0", "host:65536", "host:abc",
                    "[2001:db8::1]", "[2001:db8::1]51820"):
            assert split_host_port(bad) is None, bad

    def test_dial_back_refuses_unparseable_rather_than_dialing(self):
        assert asyncio.run(dial_back("not-an-address")) is False


class TestCandidateTyping:
    """§6.7.3 — candidates are typed and ordered host → srflx → relay."""

    def test_priority_order(self):
        assert (
            CANDIDATE_PRIORITY[CANDIDATE_HOST]
            < CANDIDATE_PRIORITY[CANDIDATE_SRFLX]
            < CANDIDATE_PRIORITY[CANDIDATE_RELAY]
        )


class TestSurfaceIsAdvertised:
    """§12.3: support is discovered from the operation's response, and
    offering the section is what makes its types owed."""

    def test_manifest_advertises_both_operations(self):
        from entity_handlers.manifest import NETWORK_HANDLER_MANIFEST

        ops = NETWORK_HANDLER_MANIFEST.data["operations"]
        assert ops["observe-address"]["output_type"] == (
            "system/network/observe-address-result"
        )
        assert ops["check-reachability"]["output_type"] == (
            "system/network/check-reachability-result"
        )
        # Neither declares an input type: the facts come off the connection,
        # and a declared input invites the body-supplied address both MUSTs
        # forbid.
        assert "input_type" not in ops["observe-address"]
        assert "input_type" not in ops["check-reachability"]

    def test_all_three_section_types_are_registered(self):
        from entity_core.types.definitions import get_all_type_entities

        names = {e.data.get("name") for e in get_all_type_entities()}
        for owed in (
            "system/network/observe-address-result",
            "system/network/check-reachability-result",
            "system/network/candidate",
        ):
            assert owed in names, owed


class TestPeernameFormatting:
    """The observed address is formatted once, at accept."""

    def test_ipv6_source_is_bracketed(self):
        from entity_core.peer.peer import _peername_of

        class _W:
            def __init__(self, info):
                self._info = info

            def get_extra_info(self, _key):
                return self._info

        assert _peername_of(_W(("127.0.0.1", 51820))) == "127.0.0.1:51820"
        # v6 peernames carry (host, port, flowinfo, scopeid); bracketed so the
        # string round-trips through split_host_port and is dialable.
        assert _peername_of(_W(("2001:db8::1", 51820, 0, 0))) == "[2001:db8::1]:51820"
        assert split_host_port(_peername_of(_W(("2001:db8::1", 51820, 0, 0)))) == (
            "2001:db8::1", 51820,
        )

    def test_missing_peername_is_none(self):
        from entity_core.peer.peer import _peername_of

        class _W:
            def get_extra_info(self, _key):
                return None

        assert _peername_of(_W()) is None
