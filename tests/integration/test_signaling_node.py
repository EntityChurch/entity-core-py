"""EXTENSION-SIGNALING §4/§5 — the rendezvous node (server) role.

§5's six pins are the whole design, so each gets its own vector: they are the
questions "a lone server implementer answers by fiat and never re-asks", and
nothing downstream surfaces a wrong answer. Two of them (order, and
non-destructive collect) are cross-peer divergences wearing the costume of a
preference — a node that gets them wrong passes every same-impl smoke test and
then answers the *wrong peer* out of a shared `lobby` bucket.

The meet at the end is the one that matters: two peers derive a key, one
offers, the other collects and answers, and the first isolates the answer by
nonce echo — the same choreography Go's `signalingMeet` drives against this
node in `validate-complete.sh`.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.utils.ecf import ecf_encode
from entity_handlers.signaling.constants import (
    LOBBY_DEFAULT,
    PATTERN,
    RENDEZVOUS_KEY_LEN,
)
from entity_handlers.signaling.data import (
    TYPE_ADVERTISE_RESULT,
    TYPE_COLLECT_RESULT,
    TYPE_OFFER_RESULT,
    advertisement_from_result,
    collect_messages_from_result,
    collect_params,
    empty_params,
    offer_ok,
    offer_params,
)
from entity_handlers.signaling.key import lobby_key, pair_key, secret_key, tag_key
from entity_handlers.signaling.node import (
    CODE_BUCKET_FULL,
    CODE_MESSAGE_TOO_LARGE,
    DEFAULT_MAX_BLOB_BYTES,
    DEFAULT_MAX_BUCKET_BLOBS,
    DEFAULT_TTL_SECONDS,
    RateLimiter,
    SignalingNode,
)
from entity_handlers.signaling.reflection import ReflectionEndpointError

KEY_A = bytes([0x00]) + bytes(range(32))
KEY_B = bytes([0x00]) + bytes(range(1, 33))


# ---------------------------------------------------------------------------
# §5 — the six pins, against the core (no peer needed)
# ---------------------------------------------------------------------------


class TestBucketSemantics:
    def test_pin1_collect_is_non_destructive(self):
        """A handshake has both peers polling and a `pair` bucket is read by
        both sides; a draining read makes a retry lose the peer's offer — a
        silent failure indistinguishable from absence."""
        node = SignalingNode()
        assert node.offer(KEY_A, b"hello") == (True, None)
        assert node.collect(KEY_A) == [b"hello"]
        assert node.collect(KEY_A) == [b"hello"]
        assert node.collect(KEY_A) == [b"hello"]

    def test_pin1_absent_key_is_an_empty_list_not_an_error(self):
        # A peer polling ahead of its counterpart is the normal case.
        assert SignalingNode().collect(KEY_A) == []

    def test_pin2_offer_appends_rather_than_replacing(self):
        """`lobby` and `tag` are inherently multi-party — replace would make
        the last writer erase everyone."""
        node = SignalingNode()
        node.offer(KEY_A, b"from-a")
        node.offer(KEY_A, b"from-b")
        assert node.collect(KEY_A) == [b"from-a", b"from-b"]

    def test_pin2_duplicate_offer_is_idempotent_not_an_accumulation(self):
        node = SignalingNode()
        assert node.offer(KEY_A, b"same") == (True, None)
        assert node.offer(KEY_A, b"same") == (True, None)
        assert node.collect(KEY_A) == [b"same"]

    def test_pin3_ttl_reaps(self):
        node = SignalingNode(ttl_seconds=60)
        node.offer(KEY_A, b"stale")
        assert node.collect(KEY_A) == [b"stale"]
        # Advance past the TTL without sleeping: the reaper reads one clock.
        node._now = lambda: __import__("time").monotonic() + 61
        assert node.collect(KEY_A) == []

    def test_pin4_collect_returns_deposit_order_oldest_first(self):
        """Two nodes scanning in different orders answer DIFFERENT peers out
        of one shared `lobby` bucket."""
        node = SignalingNode()
        for i in range(5):
            node.offer(KEY_A, f"msg-{i}".encode())
        assert node.collect(KEY_A) == [f"msg-{i}".encode() for i in range(5)]

    def test_pin5_oversize_offer_is_refused_never_truncated(self):
        node = SignalingNode()
        ok, code = node.offer(KEY_A, b"x" * (DEFAULT_MAX_BLOB_BYTES + 1))
        assert (ok, code) == (False, CODE_MESSAGE_TOO_LARGE)
        # Nothing stored — a truncated blob would decode to garbage at the
        # far peer, which is worse than a refusal it can retry.
        assert node.collect(KEY_A) == []

    def test_pin5_at_the_limit_is_accepted(self):
        node = SignalingNode()
        assert node.offer(KEY_A, b"x" * DEFAULT_MAX_BLOB_BYTES) == (True, None)

    def test_pin5_full_bucket_refuses_rather_than_evicting(self):
        """Eviction reproduces exactly the silent-never-meet shape this
        surface exists to avoid, with the evicted peer believing it is at the
        key and waiting."""
        node = SignalingNode()
        for i in range(DEFAULT_MAX_BUCKET_BLOBS):
            assert node.offer(KEY_A, f"m{i}".encode()) == (True, None)
        ok, code = node.offer(KEY_A, b"one-too-many")
        assert (ok, code) == (False, CODE_BUCKET_FULL)
        # The FIRST blob is still there — nothing was evicted to make room.
        blobs = node.collect(KEY_A)
        assert len(blobs) == DEFAULT_MAX_BUCKET_BLOBS
        assert blobs[0] == b"m0"

    def test_pin6_default_ttl_is_60_seconds(self):
        assert DEFAULT_TTL_SECONDS == 60

    def test_keys_are_compared_byte_wise_and_buckets_are_independent(self):
        node = SignalingNode()
        node.offer(KEY_A, b"for-a")
        node.offer(KEY_B, b"for-b")
        assert node.collect(KEY_A) == [b"for-a"]
        assert node.collect(KEY_B) == [b"for-b"]


class TestAdvertisedLimits:
    """§4.5 — the committed shape. Clients read the limits rather than
    assuming them; a limit the client does not know is a cross-impl reject
    boundary that presents as a rendezvous miss."""

    def test_limits_carry_the_committed_field_names_and_units(self):
        limits = SignalingNode().limits()
        assert limits == {
            "max_blob_bytes": DEFAULT_MAX_BLOB_BYTES,
            "max_bucket_blobs": DEFAULT_MAX_BUCKET_BLOBS,
            "ttl_seconds": DEFAULT_TTL_SECONDS,
        }
        # SECONDS, not the drifted pre-v1.0 `bucket_ttl_ms` — the unit is a
        # 1000x reap race, and the field name decodes to zero under the
        # committed names (the drift Go's signaling_limits_shape catches).
        assert "bucket_ttl_ms" not in limits
        assert "max_message_bytes" not in limits
        assert "max_messages_per_key" not in limits

    def test_max_keys_is_internal_and_not_published(self):
        # A node-internal backstop, not one of §4.5's published limits.
        assert "max_keys" not in SignalingNode().limits()

    def test_lobby_override_is_absent_never_null(self):
        assert "lobby_constant" not in SignalingNode().limits()
        # A node that sets the DEFAULT is a node with no override.
        assert "lobby_constant" not in SignalingNode(
            lobby_constant=LOBBY_DEFAULT,
        ).limits()

    def test_lobby_override_is_bytes(self):
        # §4.5 types it `primitive/bytes`: it is a derivation input §3.1
        # hashes verbatim, not a label to display.
        limits = SignalingNode(lobby_constant="lobby:chess-night").limits()
        assert limits["lobby_constant"] == b"lobby:chess-night"


class TestRateLimiting:
    """§8.2 MUST — per source AND per key, refusing with `rate_limited`
    rather than dropping silently."""

    def test_limits_per_source_and_per_key(self):
        limiter = RateLimiter(max_ops=2, window_s=60.0)
        assert limiter.allow("peer-a", KEY_A) is True
        assert limiter.allow("peer-a", KEY_A) is True
        assert limiter.allow("peer-a", KEY_A) is False
        # Same source, different key: per source ALONE would deny this, and a
        # client would be locked out of every bucket by one hot one.
        assert limiter.allow("peer-a", KEY_B) is True
        # Different source, same key: per key ALONE would deny this, and one
        # client could monopolize a bucket others need.
        assert limiter.allow("peer-b", KEY_A) is True

    def test_window_reopens(self):
        limiter = RateLimiter(max_ops=1, window_s=0.01)
        assert limiter.allow("peer-a", KEY_A) is True
        assert limiter.allow("peer-a", KEY_A) is False
        import time as _t

        _t.sleep(0.02)
        assert limiter.allow("peer-a", KEY_A) is True

    def test_in_process_dispatch_is_not_limited(self):
        limiter = RateLimiter(max_ops=1, window_s=60.0)
        assert limiter.allow(None, KEY_A) is True
        assert limiter.allow(None, KEY_A) is True

    def test_sweep_drops_closed_windows(self):
        limiter = RateLimiter(max_ops=5, window_s=0.01)
        limiter.allow("peer-a", KEY_A)
        assert limiter._counters
        import time as _t

        _t.sleep(0.02)
        limiter.sweep()
        assert not limiter._counters


# ---------------------------------------------------------------------------
# The wrapped surface, over a live peer
# ---------------------------------------------------------------------------


def _build_node(kp: Keypair, **kwargs) -> Peer:
    return (
        PeerBuilder()
        .with_keypair(kp)
        .with_default_handlers()
        .with_signaling_node_handler(**kwargs)
        .debug_mode(True)
        .build()
    )


def _build_client(kp: Keypair, node: Peer, node_kp: Keypair, port: int) -> Peer:
    client = (
        PeerBuilder().with_keypair(kp).with_default_handlers().debug_mode(True).build()
    )
    client.register_remote(
        node.peer_id, f"127.0.0.1:{port}", public_key=node_kp.public_key_bytes(),
    )
    return client


def _bound_port(peer: Peer) -> int:
    return peer._server.sockets[0].getsockname()[1]


async def _sig(client: Peer, node: Peer, operation: str, params):
    return await client._remote_execute(
        f"entity://{node.peer_id}/{PATTERN}", operation, params,
        resource_targets=[PATTERN],
    )


class TestWrappedSurface:
    def test_advertise_returns_the_committed_shape(self):
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                result = await _sig(client, node, "advertise", empty_params())
                assert result.status == 200, result.error
                assert result.result["type"] == TYPE_ADVERTISE_RESULT
                # The client codec decodes it — the two halves agree, which is
                # what the pre-§4.5 shape could not do against Go or Rust.
                ad = advertisement_from_result(result.result)
                assert ad.endpoint == f"127.0.0.1:{_bound_port(node)}"
                assert ad.limits.ttl_seconds == DEFAULT_TTL_SECONDS
                assert ad.limits.max_blob_bytes == DEFAULT_MAX_BLOB_BYTES
                assert ad.limits.max_bucket_blobs == DEFAULT_MAX_BUCKET_BLOBS
                assert ad.lobby is None
                assert ad.lobby_constant == LOBBY_DEFAULT
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_offer_then_collect_round_trips(self):
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                key = tag_key("round-trip")
                offered = await _sig(
                    client, node, "offer", offer_params(key, b"blob-one"),
                )
                assert offered.status == 200, offered.error
                assert offered.result["type"] == TYPE_OFFER_RESULT
                assert offer_ok(offered.result) is True

                collected = await _sig(client, node, "collect", collect_params(key))
                assert collected.status == 200, collected.error
                assert collected.result["type"] == TYPE_COLLECT_RESULT
                assert collect_messages_from_result(collected.result) == [b"blob-one"]
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_collect_on_an_untouched_key_is_200_with_an_empty_list(self):
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                result = await _sig(
                    client, node, "collect", collect_params(secret_key("nobody-here")),
                )
                assert result.status == 200, result.error
                assert collect_messages_from_result(result.result) == []
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_wrong_width_key_is_invalid_request(self):
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                # §4.3: "The key is exactly 33 bytes"; any other length is
                # refused. Built by hand — the client codec refuses to send
                # one, which is the point of checking the node too.
                #
                # Asserted against the SPEC's literal rather than against our
                # own `CODE_INVALID_REQUEST`: this row read
                # `== CODE_BAD_REQUEST` for the life of the synonym, so both
                # sides of it spelled the wrong code our way and it could not
                # fail. That is the version-string shape, in a test.
                for bad in (b"", bytes(32), bytes(34)):
                    result = await _sig(
                        client, node, "collect",
                        {"type": "system/signaling/collect-request",
                         "data": {"rendezvous_key": bad}},
                    )
                    assert result.status == 400, bad
                    assert result.result["data"]["code"] == "invalid_request", bad
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_unknown_operation_is_501_unsupported_operation(self):
        """§3.3's 501 row reaches the signaling node like any other handler.

        **This row asserted `400 invalid_request` until 0.8.2.7, and it is the
        reason no census in the cohort could see the defect.** Arch censused
        the 501 *slot* — every code emitted at status 501 — across six trees.
        A slot is keyed by status, so a site that gets the **status** wrong is
        structurally invisible to it, and this one was doubly hidden: the code
        it carried (`invalid_request`) is the correct default for the status it
        carried, so the pair reads conformant at every glance short of asking
        what the input was.

        The argument the old row encoded was that `reflect` is the *unwrapped*
        listener's verb (§1.4), so a wrapped node answering "not implemented"
        would imply a surface where it could be. §3.3's 501 row does not turn
        on that: its input is *a handler is registered at the path and does not
        implement the named operation*, and §6.2 (0.8.2.6) says the sentence is
        general. Arch ruled the same intent-flavoured distinction out at
        `entity-core-keystone` (`pd`: "unauthored pattern" vs "op outside the
        ladder"), which is the corroboration, not the argument.
        """
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                result = await _sig(client, node, "reflect", empty_params())
                assert (result.status, result.result["data"]["code"]) == (
                    501, "unsupported_operation",
                )
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_oversize_offer_is_refused_over_the_wire(self):
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp, max_blob_bytes=64)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                key = tag_key("too-big")
                result = await _sig(
                    client, node, "offer", offer_params(key, b"x" * 65),
                )
                assert result.status == 400
                assert result.result["data"]["code"] == CODE_MESSAGE_TOO_LARGE
                # Refused means NOT stored: the offerer must be able to tell.
                collected = await _sig(client, node, "collect", collect_params(key))
                assert collect_messages_from_result(collected.result) == []
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_full_bucket_answers_429_bucket_full(self):
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp, max_bucket_blobs=2)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                key = tag_key("full")
                for i in range(2):
                    ok = await _sig(
                        client, node, "offer", offer_params(key, f"m{i}".encode()),
                    )
                    assert ok.status == 200, ok.error
                result = await _sig(
                    client, node, "offer", offer_params(key, b"overflow"),
                )
                assert result.status == 429
                assert result.result["data"]["code"] == CODE_BUCKET_FULL
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_lobby_override_reaches_the_client_and_changes_the_key(self):
        """The override is a derivation input: a node that publishes one moves
        every peer's `lobby` bucket with it."""
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp, lobby_constant="lobby:chess-night")
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                result = await _sig(client, node, "advertise", empty_params())
                ad = advertisement_from_result(result.result)
                assert ad.lobby == "lobby:chess-night"
                assert ad.lobby_constant == "lobby:chess-night"
                assert lobby_key(ad.lobby_constant) != lobby_key(LOBBY_DEFAULT)
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())


class TestReflectionEndpoints:
    """§4.5.1 (added v1.1) — a node publishing its OWN §9.3 STUN listener(s).

    Before v1.1 a node that ran reflection had no way to say so, which is the
    hole that left `entity-browser-rust` unable to provision ICE automatically.
    The two assertions here are the ones Go's node carries, because the emit
    contract is where the two impls have to agree: **verbatim bytes**, and
    **absent, never `[]`**.
    """

    def test_the_configured_uris_reach_the_client_byte_for_byte(self):
        """Emitted verbatim — no `stun:` re-prefixing, no port
        canonicalization, no reordering. A consumer hands these to
        `RTCIceServer.urls` unchanged, so any transform on the way out is a
        place two consumers guess differently."""
        configured = [
            "stun:reflect.example.org:3478",
            "stuns:[2001:db8::1]:5349",
        ]

        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp, reflection_endpoints=configured)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                result = await _sig(client, node, "advertise", empty_params())
                assert result.status == 200, result.error

                # TOP-LEVEL, sibling to endpoint and limits — NOT nested
                # inside limits, which is the shape a reader skimming §4.5
                # would reach for.
                data = result.result["data"]
                assert data["reflection_endpoints"] == configured
                assert "reflection_endpoints" not in data["limits"]

                # And the client codec agrees with the node — the two halves
                # of this repo, which is what makes the round-trip a contract
                # rather than one side's opinion.
                ad = advertisement_from_result(result.result)
                assert list(ad.reflection_endpoints) == configured
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_a_node_serving_no_reflection_omits_the_key_entirely(self):
        """**Absent, never null and never `[]`** (§4.5.1, the `lobby_constant`
        precedent). Absent decodes to the already-legal no-reflection state,
        which is what makes v1.1 additive with no flag day; an empty array is a
        different, non-conformant encoding of the same fact."""
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)  # no reflection configured
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                result = await _sig(client, node, "advertise", empty_params())
                assert result.status == 200, result.error
                data = result.result["data"]
                assert "reflection_endpoints" not in data

                # Wire-level: the field name does not appear in the encoded
                # bytes at all. Asserting on the dict alone would pass for a
                # node that emitted an explicit null.
                assert b"reflection_endpoints" not in ecf_encode(result.result)

                # Absent decodes to empty, not to an error.
                ad = advertisement_from_result(result.result)
                assert ad.reflection_endpoints == ()
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_an_empty_configuration_is_the_same_as_none(self):
        """§4.5.1: "absent and empty are the same thing, and both are valid."
        So an operator passing an empty list gets the absent field, not `[]`."""
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp, reflection_endpoints=[])
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                result = await _sig(client, node, "advertise", empty_params())
                assert "reflection_endpoints" not in result.result["data"]
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())

    def test_a_malformed_uri_fails_at_build_not_at_advertise(self):
        """The operator is the only one who can fix it, and they are gone by
        the time a browser's `RTCPeerConnection` throws on it."""
        with pytest.raises(ReflectionEndpointError):
            _build_node(Keypair.generate(), reflection_endpoints=["stun://x:1"])

    def test_the_type_declares_the_field_optional(self):
        """A REQUIRED `reflection_endpoints` would make every pre-v1.1 node's
        advertisement invalid against our own type — the flag day §4.5.1 exists
        to avoid."""
        from entity_core.types.definitions import (
            type_system_signaling_advertise_result,
        )

        fields = type_system_signaling_advertise_result().data["fields"]
        assert fields["reflection_endpoints"] == {
            "array_of": {"type_ref": "primitive/string"},
            "optional": True,
        }


class TestTwoPeersMeet:
    """The §4 step-2 rendezvous, which is what the node exists for — the same
    choreography Go's `signalingMeet` drives against this node."""

    def test_two_peers_meet_at_a_derived_key(self):
        async def run():
            node_kp = Keypair.generate()
            kp_a, kp_b = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)
            await node.start("127.0.0.1", 0)
            port = _bound_port(node)
            peer_a = _build_client(kp_a, node, node_kp, port)
            peer_b = _build_client(kp_b, node, node_kp, port)
            try:
                key = pair_key(peer_a.peer_id, peer_b.peer_id)
                assert len(key) == RENDEZVOUS_KEY_LEN

                # A offers its request.
                offered = await _sig(
                    peer_a, node, "offer", offer_params(key, b"A:connect-request"),
                )
                assert offered.status == 200, offered.error

                # B collects, finds A's request (skipping nothing of its own
                # yet), and answers into the same bucket.
                b_view = collect_messages_from_result(
                    (await _sig(peer_b, node, "collect", collect_params(key))).result,
                )
                assert b_view == [b"A:connect-request"]
                answered = await _sig(
                    peer_b, node, "offer", offer_params(key, b"B:connect-response"),
                )
                assert answered.status == 200, answered.error

                # A re-reads the bucket and finds BOTH its own request (collect
                # is non-destructive) and B's answer — which is exactly what
                # makes a peer's own skip-own/nonce-echo isolation load-bearing.
                a_view = collect_messages_from_result(
                    (await _sig(peer_a, node, "collect", collect_params(key))).result,
                )
                assert a_view == [b"A:connect-request", b"B:connect-response"]
            finally:
                await peer_a.stop()
                await peer_b.stop()
                await node.stop()

        asyncio.run(run())

    def test_all_four_key_modes_reach_the_same_node(self):
        async def run():
            node_kp, client_kp = Keypair.generate(), Keypair.generate()
            node = _build_node(node_kp)
            await node.start("127.0.0.1", 0)
            client = _build_client(client_kp, node, node_kp, _bound_port(node))
            try:
                keys = {
                    "tag": tag_key("conformance"),
                    "secret": secret_key("conformance-secret"),
                    "lobby": lobby_key(LOBBY_DEFAULT),
                    "pair": pair_key(client.peer_id, node.peer_id),
                }
                for mode, key in keys.items():
                    blob = f"{mode}-blob".encode()
                    offered = await _sig(
                        client, node, "offer", offer_params(key, blob),
                    )
                    assert offered.status == 200, (mode, offered.error)
                    got = collect_messages_from_result(
                        (await _sig(
                            client, node, "collect", collect_params(key),
                        )).result,
                    )
                    assert got == [blob], mode
                # Four distinct modes are four distinct buckets — the node
                # derives nothing, it just compares 33 opaque bytes.
                assert len({bytes(k) for k in keys.values()}) == 4
            finally:
                await client.stop()
                await node.stop()

        asyncio.run(run())


class TestSurfaceIsWired:
    """The three-part registration `AGENTS.md` warns about: miss any and the
    handler looks registered and 404s on operations."""

    def test_manifest_is_in_all_handler_manifests(self):
        from entity_handlers.manifest import (
            ALL_HANDLER_MANIFESTS,
            SIGNALING_HANDLER_MANIFEST,
        )

        assert SIGNALING_HANDLER_MANIFEST in ALL_HANDLER_MANIFESTS
        ops = SIGNALING_HANDLER_MANIFEST.data["operations"]
        assert set(ops) == {"offer", "collect", "advertise"}
        assert ops["advertise"]["output_type"] == "system/signaling/advertise-result"
        # §4.0 declares advertise's input_type null — it takes no arguments.
        assert "input_type" not in ops["advertise"]

    def test_the_node_is_off_by_default(self):
        """A peer is a signaling CLIENT by default; only a deployed introducer
        serves. Serving means accepting opaque blobs at arbitrary keys, so it
        is an operator's call — same posture as Go's `-signaling-node`."""
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .build()
        )
        assert not any(
            h.pattern == PATTERN for h in peer.handlers.list_handlers()
        ), "with_all_handlers() must not serve the rendezvous node"

    def test_the_builder_call_registers_it(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_signaling_node_handler()
            .build()
        )
        assert any(
            h.pattern == PATTERN for h in peer.handlers.list_handlers()
        ), "with_signaling_node_handler() did not register system/signaling"

    def test_the_six_operation_types_are_registered(self):
        from entity_core.types.definitions import get_all_type_entities

        names = {e.data.get("name") for e in get_all_type_entities()}
        for owed in (
            "system/signaling/offer-request",
            "system/signaling/offer-result",
            "system/signaling/collect-request",
            "system/signaling/collect-result",
            "system/signaling/limits",
            "system/signaling/advertise-result",
        ):
            assert owed in names, owed
