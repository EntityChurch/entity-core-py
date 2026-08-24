"""Live interop: the Python signaling client against Rust's connection node.

``PROPOSAL-CONNECTION-NODE`` §1–§2, ``PROPOSAL-CONNECTIVITY-SIGNALING-AND-PUNCH``
§3–§4, ``PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT`` §3.1.1.

This is the first cross-impl evidence about the Python client: everything in
``tests/unit/test_signaling_*.py`` is same-impl and, for the two obligations that
matter, a wrong-but-self-consistent implementation passes those exactly as a
correct one does.

**Two Rust nodes with different ``--endpoint`` strings** are required — §6 step 2's
pool gate is invisible below pool size 2, because ``argmax`` over one member
returns that member whatever the weight computes — and both must be started
``--open``, which is what admits a foreign peer at all (brief §7.1)::

    cargo build -p entity-signaling-node
    ./target/debug/entity-signaling-node --listen 127.0.0.1:4050 --endpoint node-a:4050 --open
    ./target/debug/entity-signaling-node --listen 127.0.0.1:4051 --endpoint node-b:4051 --open

Then::

    uv run pytest tests/interop/test_signaling_rust_node.py -v

**These peers are strangers.** Every connection here authenticates as a freshly
generated identity that the node has never seen, which is the deployment posture
and no longer a harness workaround: Rust ``9714f13`` seeds
``system/signaling:{offer,collect,advertise}`` under the ``default`` policy key
when ``--open`` is passed. An earlier revision of this file had to authenticate
**as the node's own identity** because the shipped binary seeded no policy at all;
that is gone, and with it the one thing it could not exercise — the admission
model — is now under test here (:func:`test_an_ordinary_peer_is_admitted_by_the_narrow_grant`).

**What this does and does not settle.** It settles the *wire*: the params/result
shapes, blob framing and byte fidelity through the carrier, the bucket-reading
rules, the refusal statuses, admission under the narrow grant, and that two
clients converge on one node of a two-instance pool. It does **not** settle §2.2
key agreement between two *implementations* — nothing on the Rust side derives a
key here, since the node is mode-blind by construction, so both peers below are
this same client and converge trivially.

That gap is now *statically* closed against go and not live: go ran its client
and this one over identical inputs and got byte-identical keys and identical pool
selections (``entity-core-go`` @ ``989366c``), and those values are pinned from
this side in ``tests/unit/test_signaling_{key,pool}.py``. What remains is a real
cross-process meet — a go peer and a py peer at one node — which is what
``validate-peer -category signaling`` is being extended to do.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.connection import Connection
from entity_core.sdk.dispatcher import ConnectionDispatcher
from entity_handlers.signaling import (
    LOBBY_DEFAULT,
    Candidate,
    ConnectRequest,
    PoolMember,
    Refused,
    SignalingClient,
    UnknownMessage,
    find_request,
    find_requests,
    find_response,
    generate_nonce,
    lobby_key,
    pair_key,
    secret_key,
    select,
    tag_key,
    to_blob,
)

NODE_A_PORT = int(os.environ.get("SIGNALING_NODE_A_PORT", "4050"))
NODE_B_PORT = int(os.environ.get("SIGNALING_NODE_B_PORT", "4051"))

# The advertised strings the two nodes were started with. §3.1.1 weights over
# these bytes exactly as published, so the test pool must carry the same
# spellings the nodes print at startup.
NODE_A_ENDPOINT = os.environ.get("SIGNALING_NODE_A_ENDPOINT", "node-a:4050")
NODE_B_ENDPOINT = os.environ.get("SIGNALING_NODE_B_ENDPOINT", "node-b:4051")

HOST = Candidate("host", "tcp", "192.168.1.10:9000", 0)
SRFLX = Candidate("srflx", "tcp", "203.0.113.7:41234", 0)


async def _reachable(port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=1.0
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (TimeoutError, OSError):
        return False


async def _authority_blocker(port: int) -> str | None:
    """Is the node at ``port`` reachable *and* admitting strangers? A reason, or None.

    Reachable is not enough, and the difference is an operator mistake rather
    than a flaky environment — so it is detected and named here rather than
    surfacing as fifteen opaque 403s.

    A node started with neither ``--open`` nor ``--grant`` is **closed**: a
    connecting peer receives only the §4.4 floor (``system/tree:get`` +
    ``system/capability:request``) and every signaling call is
    ``403 capability_denied``. There is no client-side route around that —
    ``system/capability:request`` is pure attenuation, so it can only narrow the
    caller's own authority, never widen it. Closed is the deliberate default
    (brief §7.1): on the wrapped surface the capability grant *is* the admission
    control (§2.1).

    See ``docs/status/HANDOFF-2026-07-30-signaling-client-stage1-python.md``.
    """
    if not await _reachable(port):
        return f"no Rust signaling node reachable at 127.0.0.1:{port}"

    conn = await Connection.connect(
        "127.0.0.1", port, Keypair.generate(), wait_for_capability=True
    )
    try:
        response = await conn.execute(
            uri=f"entity://{conn.session.remote_peer_id}/system/signaling",
            operation="advertise",
            params={"type": "system/signaling/empty", "data": {}},
        )
        status = int(response.status)
        if status == 403:
            return (
                f"the node at 127.0.0.1:{port} is reachable but admits no "
                f"stranger (403 capability_denied) — it was started CLOSED. "
                f"Restart it with --open (serve anyone) or --grant <peer-id>; "
                f"its startup banner prints which posture it took."
            )
        if status != 200:
            return f"node at 127.0.0.1:{port} answered advertise with {status}"
        return None
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.fixture
async def node_a_available():
    reason = await _authority_blocker(NODE_A_PORT)
    if reason:
        pytest.skip(reason)


@pytest.fixture
async def two_node_pool_available():
    for port in (NODE_A_PORT, NODE_B_PORT):
        reason = await _authority_blocker(port)
        if reason:
            pytest.skip(f"§6 step 2 needs a usable two-instance pool: {reason}")


class _Peer:
    """One connected Python peer holding a typed client for one node.

    ``peer_id`` is the peer-id this peer authors coordination messages under and
    is what the §3.2 filters key on. It is the connection's own identity — two
    peers here are two genuinely distinct strangers, so the filters run against
    real identities rather than labels.
    """

    def __init__(
        self, conn: Connection, client: SignalingClient, peer_id: str
    ) -> None:
        self.conn = conn
        self.client = client
        self.peer_id = peer_id
        self.node_peer_id: str = conn.session.remote_peer_id


async def _connect(port: int) -> _Peer:
    """Connect to a node as a **fresh, unknown identity** and wrap it in a client.

    No keypair is supplied or shared: admission comes entirely from the node's
    seed policy, which is the thing under test.
    """
    conn = await Connection.connect(
        "127.0.0.1", port, Keypair.generate(), wait_for_capability=True
    )
    client = SignalingClient(
        ConnectionDispatcher(conn), conn.session.remote_peer_id
    )
    return _Peer(conn, client, conn.session.local_peer_id)


# ---------------------------------------------------------------------------
# §5.1 — the wire, as the node answers it
# ---------------------------------------------------------------------------


async def test_advertise_returns_the_running_nodes_endpoint_and_limits(
    node_a_available,
):
    """The node's own advertisement, read over the real wire.

    ``limits`` is a **bare CBOR map**, and ``lobby`` is **absent unless
    overridden** — decoding it wrong here is how a client ends up deriving a lobby
    key into a bucket nobody else on the pool uses.
    """
    peer = await _connect(NODE_A_PORT)
    try:
        ad = await peer.client.advertise()
        assert ad.endpoint == NODE_A_ENDPOINT
        # TTL is 60 s: advisory to peers, binding on the node.
        assert ad.limits.bucket_ttl_ms == 60_000
        assert ad.limits.max_message_bytes == 8192
        assert ad.limits.max_messages_per_key == 32
        assert ad.limits.max_keys > 0
        # Started without --lobby, so no override is published.
        assert ad.lobby is None
        assert ad.lobby_constant == LOBBY_DEFAULT
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_offer_then_collect_returns_the_blob_byte_identically(
    node_a_available,
):
    """Byte fidelity through the carrier.

    The node stores these bytes verbatim and hands them back verbatim — which is
    what makes the §3.3 signature these blobs will eventually carry survivable, and
    what a decode-and-re-encode round trip would destroy.
    """
    peer = await _connect(NODE_A_PORT)
    try:
        key = secret_key(f"byte-fidelity-{generate_nonce().hex()}")
        blob = to_blob(
            ConnectRequest(peer.peer_id, (HOST, SRFLX), generate_nonce()).to_entity()
        )
        await peer.client.offer(key, blob)
        collected = await peer.client.collect(key)
        assert collected == [blob], "the carrier must not perturb a single byte"
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_an_unknown_key_is_an_empty_list_and_a_200_never_a_404(
    node_a_available,
):
    """A peer polling ahead of its counterpart is the normal case."""
    peer = await _connect(NODE_A_PORT)
    try:
        never_used = tag_key(f"nobody-here-{generate_nonce().hex()}")
        assert await peer.client.collect(never_used) == []
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_collect_is_non_destructive(node_a_available):
    """TTL is the only reaper (§1.1 pin 1), so both peers may collect and
    re-collect the same bucket."""
    peer = await _connect(NODE_A_PORT)
    try:
        key = secret_key(f"non-destructive-{generate_nonce().hex()}")
        await peer.client.offer(key, b"a blob")
        first = await peer.client.collect(key)
        second = await peer.client.collect(key)
        assert first == second == [b"a blob"]
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_a_repeated_offer_is_idempotent(node_a_available):
    """§1.1 pin 2 dedups by content hash, so a retry after a timeout is
    idempotent rather than an accumulation — and a duplicate is ``ok: true``,
    indistinguishable on the wire, with nothing to branch on."""
    peer = await _connect(NODE_A_PORT)
    try:
        key = secret_key(f"idempotent-{generate_nonce().hex()}")
        await peer.client.offer(key, b"same bytes")
        await peer.client.offer(key, b"same bytes")
        await peer.client.offer(key, b"same bytes")
        assert await peer.client.collect(key) == [b"same bytes"]
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


# ---------------------------------------------------------------------------
# §5.3 — refusals
# ---------------------------------------------------------------------------


async def test_a_message_over_the_bound_is_refused_with_400(node_a_available):
    """8 KiB per message. The node **refuses, never evicts** — eviction would
    reproduce exactly the silent-never-meet shape, with the evicted peer believing
    it is at the key and waiting."""
    peer = await _connect(NODE_A_PORT)
    try:
        key = secret_key(f"too-large-{generate_nonce().hex()}")
        with pytest.raises(Refused) as exc:
            await peer.client.offer(key, b"x" * (8192 + 1))
        assert exc.value.status == 400
        # Refused before any state change, so the bucket is untouched.
        assert await peer.client.collect(key) == []
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_reflect_is_refused_403_by_the_narrow_grant_and_is_never_a_501(
    node_a_available,
):
    """§1.4: ``reflect`` is the unwrapped listener's verb, not a core operation —
    so a wrapped node never serves it. **Which refusal you see depends on the
    grant, and against a real node it is 403, not 400.**

    Corrected 2026-07-30 from a 400 assertion (brief §7.2). The capability check
    runs *before* dispatch, and ``--open`` seeds an **enumerated** grant naming
    exactly ``offer``/``collect``/``advertise`` — so ``reflect`` is refused at the
    check and never reaches the handler that would have called it unknown. A
    wildcard-granted node (Rust's in-process harness, or a caller holding owner
    authority) is authorized through to the handler and sees 400
    ``unknown_operation`` instead. Both are correct; what a client must not do is
    treat 400 as the *only* signal that ``reflect`` is unavailable here.

    What holds either way — and is the assertion that matters for §1.4 — is that
    it is **never 501**: "not implemented here" would imply the wrapped surface
    is a place ``reflect`` could be implemented.

    Dispatched directly rather than through the client, because the client
    deliberately exposes no ``reflect`` method.
    """
    peer = await _connect(NODE_A_PORT)
    try:
        response = await peer.conn.execute(
            uri=peer.client.node_uri,
            operation="reflect",
            params={"type": "system/signaling/empty", "data": {}},
        )
        status = int(response.status)
        assert status != 501, "reflect is not a core operation, so never a 501"
        assert status == 403, (
            "against a node seeded with the narrow grant the capability check "
            "refuses reflect before dispatch; 400 would mean the caller holds a "
            "wildcard and this test is no longer running as a stranger"
        )
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


# ---------------------------------------------------------------------------
# §4 step 2 — two peers actually meet, through a node that decodes none of it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["pair", "tag", "secret", "lobby"])
async def test_two_peers_exchange_candidates_at_every_key_mode(
    node_a_available, mode: str
):
    """The full §4 step-2 exchange over the real carrier, at all four key modes.

    Both §3.2 filters are exercised for real here, not simulated: ``collect`` is
    non-destructive, so each peer re-reads its own offer every poll, and the
    initiator must reject its own request and its own response before finding the
    answer by nonce echo.
    """
    alice = await _connect(NODE_A_PORT)
    bob = await _connect(NODE_A_PORT)
    try:
        # A unique input per run, so repeated runs don't collide in a live
        # bucket that the TTL has not yet reaped.
        salt = generate_nonce().hex()
        if mode == "pair":
            key = pair_key(alice.peer_id, bob.peer_id)
        elif mode == "tag":
            key = tag_key(f"chess-{salt}")
        elif mode == "secret":
            key = secret_key(f"s3cr3t-{salt}")
        else:
            # A lobby override would come from `advertise`; this node publishes
            # none, so the default constant is the agreed input.
            ad = await alice.client.advertise()
            key = lobby_key(ad.lobby_constant)
            assert ad.lobby_constant == LOBBY_DEFAULT

        # Alice initiates.
        nonce = await alice.client.initiate(key, alice.peer_id, [HOST, SRFLX])

        # Bob polls. The §3.2 own-message filter is what is under test here:
        # nothing Bob authored may come back to him as a request to answer.
        bucket = await bob.client.collect_messages(key)
        assert not any(
            isinstance(m, ConnectRequest) and m.initiator == bob.peer_id
            for m in bucket
        ), "find_request must never hand a peer its own request"
        assert find_request(bucket, bob.peer_id) is not None, (
            f"bob found no answerable request at the {mode} key"
        )

        # `pair` and `lobby` keys are **stable by design** — a pair's key is its
        # two peer-ids and a lobby's is a pool constant — so their buckets
        # legitimately hold earlier exchanges until the TTL reaps them. Bob
        # therefore answers **every** answerable request, not the first
        # (`find_requests`, not `find_request`): a responder that answers the
        # oldest spends the run replying to a stranger who has given up, leaves
        # this exchange unanswered, and reports success at every step. That is
        # the rerun-safety policy go's validator category adopted, and it is what
        # makes this test survive a second run inside the 60 s TTL.
        #
        # Bob does *not* filter by Alice's nonce here: a real responder has never
        # seen it. He answers blind, and correlation is entirely the initiator's
        # job below.
        answerable = find_requests(bucket, bob.peer_id)
        assert answerable, f"bob found no answerable request at the {mode} key"
        for request in answerable:
            await bob.client.respond(key, bob.peer_id, request, [HOST])

        mine = [r for r in answerable if r.nonce == nonce]
        assert len(mine) == 1, "alice's request must be in the set bob answered"
        assert mine[0].initiator == alice.peer_id
        assert mine[0].candidates == (HOST, SRFLX)

        # Alice polls and picks her answer out by nonce echo.
        bucket = await alice.client.collect_messages(key)
        response = find_response(bucket, nonce, alice.peer_id)
        assert response is not None, f"alice found no response at the {mode} key"
        assert response.responder == bob.peer_id
        assert response.nonce == nonce
        assert response.candidates == (HOST,)

        # And the node decoded none of it: her own request is still in the
        # bucket she just read, which is exactly why the filters are MUSTs.
        assert any(
            isinstance(m, ConnectRequest) and m.initiator == alice.peer_id
            for m in bucket
        )
    finally:
        for peer in (alice, bob):
            peer.conn.close()
            await peer.conn.wait_closed()


async def test_a_stranger_in_a_shared_bucket_is_not_mistaken_for_my_answer(
    node_a_available,
):
    """The nonce is a **correlator**: in a shared ``tag``/``lobby`` bucket someone
    else's response is not mine, and a fresh answer is not one I processed two
    polls ago."""
    alice = await _connect(NODE_A_PORT)
    stranger = await _connect(NODE_A_PORT)
    try:
        key = tag_key(f"shared-{generate_nonce().hex()}")

        # A stranger's whole exchange lands in the same bucket first.
        stranger_nonce = await stranger.client.initiate(
            key, stranger.peer_id, [HOST]
        )
        stranger_request = ConnectRequest(
            stranger.peer_id, (HOST,), stranger_nonce
        )
        await stranger.client.respond(
            key, stranger.peer_id, stranger_request, [HOST]
        )

        # Alice's own exchange has no answer yet, and she must not adopt the
        # stranger's.
        my_nonce = await alice.client.initiate(key, alice.peer_id, [HOST])
        bucket = await alice.client.collect_messages(key)
        assert find_response(bucket, my_nonce, alice.peer_id) is None

        # The stranger's traffic really is in the bucket she just filtered.
        assert len(bucket) >= 3
    finally:
        for peer in (alice, stranger):
            peer.conn.close()
            await peer.conn.wait_closed()


async def test_an_unrecognized_blob_is_skipped_not_an_error(node_a_available):
    """Anyone may write to a shared bucket and a newer impl's message type is
    MUST-ignore, so an undecodable blob must not fail the poll."""
    peer = await _connect(NODE_A_PORT)
    try:
        key = secret_key(f"mixed-{generate_nonce().hex()}")
        await peer.client.offer(key, b"\xff\xff definitely not an entity")
        good = ConnectRequest(peer.peer_id, (HOST,), generate_nonce())
        await peer.client.offer(key, to_blob(good.to_entity()))

        messages = await peer.client.collect_messages(key)
        assert len(messages) == 2
        assert sum(isinstance(m, UnknownMessage) for m in messages) == 1
        assert sum(isinstance(m, ConnectRequest) for m in messages) == 1
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


# ---------------------------------------------------------------------------
# §6 step 2 — the two-instance pool gate
# ---------------------------------------------------------------------------


async def test_gate_step_2_pool_selection_converges_over_a_two_instance_pool(
    two_node_pool_available,
):
    """§3.1.1 over two live nodes: both peers pick the same one, and the
    **unselected node ends empty**.

    The empty-node half is the part a single-instance run cannot check and the
    part that catches a selection rule which "converges" by always taking the
    first advertised member — that rule would pass the converge-on-one assertion
    and still be wrong the moment the advertisement order differed between peers.
    """
    alice = await _connect(NODE_A_PORT)
    bob = await _connect(NODE_B_PORT)
    try:
        # Both peers hold the same advertisement, in different orders — a stale
        # or reordered pool is the realistic case, not a contrived one.
        node_by_endpoint = {
            NODE_A_ENDPOINT: alice,
            NODE_B_ENDPOINT: bob,
        }
        pool_as_alice_sees_it = [
            PoolMember(NODE_A_ENDPOINT, 0),
            PoolMember(NODE_B_ENDPOINT, 0),
        ]
        pool_as_bob_sees_it = list(reversed(pool_as_alice_sees_it))

        # Verify the advertised strings really are what we are weighting over.
        for endpoint, peer in node_by_endpoint.items():
            ad = await peer.client.advertise()
            assert ad.endpoint == endpoint

        # Find a key that selects node A and one that selects node B, so the
        # test proves the rule discriminates rather than always picking one.
        # Salted per run: the live half below asserts the *winner's* bucket holds
        # exactly this run's blob, which a bucket left over from an earlier run
        # inside the 60 s TTL would break.
        salt = generate_nonce().hex()
        selected: dict[str, str] = {}
        for i in range(60):
            label = f"gate-{salt}-{i}"
            key = tag_key(label)
            chosen = select(key, pool_as_alice_sees_it)
            assert chosen == select(key, pool_as_bob_sees_it), (
                "two peers holding the same pool in different orders must "
                "select the same member"
            )
            selected.setdefault(chosen.endpoint, label)
        assert set(selected) == {NODE_A_ENDPOINT, NODE_B_ENDPOINT}, (
            "selection must discriminate across keys, or the pool shards nothing"
        )

        # Now the live half: offer at the *selected* node only, and prove the
        # unselected one never saw the key.
        for endpoint, label in selected.items():
            key = tag_key(label)
            winner = node_by_endpoint[endpoint]
            loser = node_by_endpoint[
                NODE_B_ENDPOINT if endpoint == NODE_A_ENDPOINT else NODE_A_ENDPOINT
            ]

            blob = to_blob(
                ConnectRequest(
                    winner.peer_id, (HOST,), generate_nonce()
                ).to_entity()
            )
            await winner.client.offer(key, blob)

            assert await winner.client.collect(key) == [blob]
            assert await loser.client.collect(key) == [], (
                f"the unselected node ({loser.client.node_peer_id}) must end "
                f"empty for a key that weighs to {endpoint}"
            )
    finally:
        for peer in (alice, bob):
            peer.conn.close()
            await peer.conn.wait_closed()


# ---------------------------------------------------------------------------
# §2.1 admission — what the grant admits, and what it still refuses
# ---------------------------------------------------------------------------


async def test_an_ordinary_peer_is_admitted_by_the_narrow_grant(node_a_available):
    """Harness self-check: name what grants these tests authority at all.

    **This is the assertion that replaced the owner workaround.** Until Rust
    ``9714f13`` the shipped node seeded no policy, so this suite had to
    authenticate *as the node's own identity* to reach the surface — which
    validated the wire while leaving the admission model, the one thing the gap
    was about, untestable. Now the reverse is asserted: the client is a
    **stranger** — a freshly generated identity the node has never seen, not the
    node's own — and the wrapped surface answers it.

    If this ever fails with the peer-ids equal, someone reintroduced the
    workaround and every "a foreign peer can do this" claim below is void.
    """
    peer = await _connect(NODE_A_PORT)
    try:
        assert peer.conn.session.local_peer_id != peer.node_peer_id, (
            "these tests must run as a stranger, not as the node itself"
        )
        # All three verbs, under nothing but the seeded grant.
        await peer.client.advertise()
        key = secret_key(f"admission-{generate_nonce().hex()}")
        await peer.client.offer(key, b"a stranger's blob")
        assert await peer.client.collect(key) == [b"a stranger's blob"]
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_a_resource_target_is_refused_even_though_the_verb_is_granted(
    node_a_available,
):
    """**The resource-target trap** (brief §5.1; found by go, pinned by Rust in
    ``cmd/entity-signaling-node/tests/admission.rs``).

    A signaling EXECUTE must carry **no resource target**. The seeded grant's
    resource scope is empty — deliberately, since signaling addresses no tree
    resource: the rendezvous key rides in ``params``, and the handler reads and
    writes nothing. V7 dispatch authorization checks ``grant.resources`` before
    the handler runs, and an empty include list covers nothing, so a target that
    "looks harmless" is refused.

    Asserted here from the client side because the failure is *indistinguishable
    from not being granted at all* — the same 403 ``capability_denied``. This
    test is what keeps :class:`SignalingClient` honest: it never sets
    ``resource_targets``, and the same call differs only by that field.
    """
    peer = await _connect(NODE_A_PORT)
    try:
        params = {"type": "system/signaling/empty", "data": {}}
        without = await peer.conn.execute(
            uri=peer.client.node_uri, operation="advertise", params=params
        )
        with_target = await peer.conn.execute(
            uri=peer.client.node_uri,
            operation="advertise",
            params=params,
            # The same target shape Rust's admission.rs uses. It must be a
            # well-formed resource path (a bare "/" is rejected earlier, with
            # 400 invalid_resource_path, and would prove nothing about scope).
            resource={"targets": [f"/{peer.node_peer_id}/system/signaling"]},
        )
        assert int(without.status) == 200
        assert int(with_target.status) == 403, (
            "the identical call must be refused once it carries a resource "
            "target — if this is 200 the grant was widened to '*', which hands "
            "callers resource authority no signaling verb can use"
        )
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_the_grant_does_not_spill_onto_other_handlers(node_a_available):
    """``--open`` seeds ``system/signaling`` and nothing else.

    The posture is "public introducer", not "public peer": the node still holds
    an ordinary tree and an ordinary identity. A stranger admitted to the
    rendezvous surface must not thereby be able to write to the node's tree —
    which is the whole reason the grant is enumerated rather than a wildcard, and
    the property the in-process wildcard harness structurally cannot check.
    """
    peer = await _connect(NODE_A_PORT)
    try:
        response = await peer.conn.execute(
            uri=f"entity://{peer.node_peer_id}/system/tree",
            operation="put",
            params={
                "type": "system/tree/put-request",
                "data": {"path": "/intruder", "data": {"type": "test", "data": {}}},
            },
        )
        assert int(response.status) == 403, (
            "signaling authority must not spill onto another handler"
        )
    finally:
        peer.conn.close()
        await peer.conn.wait_closed()


async def test_the_two_nodes_are_distinct_peers_with_distinct_endpoints(
    two_node_pool_available,
):
    """The gate requirement itself: two ports behind one advertised name weigh
    identically and a two-member pool silently behaves as one."""
    alice = await _connect(NODE_A_PORT)
    bob = await _connect(NODE_B_PORT)
    try:
        assert alice.node_peer_id != bob.node_peer_id
        ad_a = await alice.client.advertise()
        ad_b = await bob.client.advertise()
        assert ad_a.endpoint != ad_b.endpoint
    finally:
        for peer in (alice, bob):
            peer.conn.close()
            await peer.conn.wait_closed()
