"""R6 — `system/peer/session/{peer_id}` tree entity gates (§9 shape).

PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY-AND-SESSION-LIFECYCLE §9
(arch ruling, commit ``523cdc5``). The session entity is the
durable per-peer AUTH record at ``system/peer/session/{remote_peer_id}``
— it answers exactly one question for §10 dispatch: *"do I already hold
a valid capability to talk to this peer, or must I re-handshake?"*

Schema (§9.3 minimal):

    system/peer/session/{remote_peer_id} := {
        remote_peer_id,
        remote_identity_hash,
        remote_public_key?,                    # optional denorm (R6-g)
        held_capability:    {hash, chain},     # cap remote granted me
        minted_capability?: {hash, chain},     # cap I issued remote — R3a
        granted_at,
        expires_at?,
    }

Gates pinned here:

- **TV-LT1** — TCP + HTTP dials to the same peer → one cap (lookup by
  ``peer_id``, not by connection or transport).
- **TV-LT2** — reconnect → reuse / idempotent (cap hash unchanged across
  reconnect; granter does not re-mint).
- **TV-LT3** — one session entity per ``peer_id``.
- **persistence** — disconnect MUST NOT delete or modify the session
  entity (§9.1 R6-c: lifecycle is `system/peer/status`'s job).
- **bidirectional** — A's ``minted_capability`` for B = B's
  ``held_capability`` from A (one cap, two viewpoints, one entity).
- **no self-session** (§9.1 R6-f).
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.peer.session_entity import (
    read_held_capability,
    read_minted_capability,
    read_session,
    session_path,
)
from entity_core.protocol.auth import create_identity_entity


def _identity_hash(kp: Keypair) -> bytes:
    """V7 v7.64 §1.4 — the path-key bytes for ``system/peer/session/``."""
    return create_identity_entity(kp).compute_hash()


@pytest.fixture
async def server_with_tcp_and_http():
    """A single peer listening on BOTH TCP and HTTP — feeds TV-LT1
    (mixed-transport dial → one cap)."""
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 19201)
    http = await peer.start_http("127.0.0.1", 0)
    bind = http.bound_socket()
    assert bind is not None
    yield peer, "127.0.0.1", 19201, f"http://{bind[0]}:{bind[1]}/entity"
    await http.stop()
    await peer.stop()


@pytest.fixture
async def tcp_server_peer():
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 19202)
    yield peer
    await peer.stop()


# -----------------------------------------------------------------------------
# TV-LT3 — one session entity per peer_id
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tv_lt3_one_session_entity_per_peer_id(tcp_server_peer):
    """The path ``system/peer/session/{remote_peer_id}`` holds the single
    session entity for that remote — repeated connects do not create
    siblings or duplicate entries."""
    client_kp = Keypair.generate()
    conn1 = await Connection.connect(
        "127.0.0.1", 19202, client_kp,
        expected_peer_id=tcp_server_peer.peer_id,
    )
    try:
        conn2 = await Connection.connect(
            "127.0.0.1", 19202, client_kp,
            expected_peer_id=tcp_server_peer.peer_id,
        )
        try:
            tree = tcp_server_peer.entity_tree
            client_hex = _identity_hash(client_kp).hex()
            expected = tree.normalize_uri(
                f"system/peer/session/{client_hex}",
            )
            uris = [u for u in tree.list_prefix("system/peer/session/")
                    if u.endswith(client_hex)]
            assert len(uris) == 1, (
                f"expected one session entity for client_kp; got {uris}"
            )
            assert uris[0] == expected
        finally:
            conn2.close()
            await conn2.wait_closed()
    finally:
        conn1.close()
        await conn1.wait_closed()


# -----------------------------------------------------------------------------
# TV-LT2 — reconnect reuses the minted cap (granter idempotency)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tv_lt2_reconnect_reuses_minted_cap(tcp_server_peer):
    """Disconnect, reconnect — the session entity at
    ``system/peer/session/{peer_id}.minted_capability`` still points at
    the same cap hash. The granter MUST NOT mint a fresh cap."""
    client_kp = Keypair.generate()

    conn1 = await Connection.connect(
        "127.0.0.1", 19202, client_kp,
        expected_peer_id=tcp_server_peer.peer_id,
    )
    cap1_hash = conn1.capability.get("content_hash")
    assert cap1_hash is not None

    client_hash = _identity_hash(client_kp)
    session1 = read_session(
        tcp_server_peer.content_store,
        tcp_server_peer.entity_tree,
        client_hash,
    )
    assert session1 is not None
    minted1 = session1.data["minted_capability"]["hash"]
    assert minted1 == cap1_hash

    conn1.close()
    await conn1.wait_closed()
    # Small gap so a fresh `created_at: now()` mint would be observable.
    await asyncio.sleep(0.05)

    conn2 = await Connection.connect(
        "127.0.0.1", 19202, client_kp,
        expected_peer_id=tcp_server_peer.peer_id,
    )
    try:
        cap2_hash = conn2.capability.get("content_hash")
        assert cap2_hash == cap1_hash, (
            "reconnect minted a NEW cap entity; R6/R3a requires reuse"
        )
        session2 = read_session(
            tcp_server_peer.content_store,
            tcp_server_peer.entity_tree,
            client_hash,
        )
        assert session2 is not None
        assert session2.data["minted_capability"]["hash"] == minted1
    finally:
        conn2.close()
        await conn2.wait_closed()


# -----------------------------------------------------------------------------
# TV-LT1 — TCP + HTTP dials to the same peer use ONE held cap
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tv_lt1_tcp_and_http_share_one_cap(server_with_tcp_and_http):
    """A client that dials the same peer over both TCP and HTTP gets the
    same cap entity. Cap is keyed by ``(grantee_peer_id, grants)`` —
    transport is not part of the key."""
    server, tcp_host, tcp_port, http_url = server_with_tcp_and_http

    client_kp = Keypair.generate()

    tcp_conn = await Connection.connect(
        tcp_host, tcp_port, client_kp,
        expected_peer_id=server.peer_id,
    )
    tcp_cap_hash = tcp_conn.capability.get("content_hash")
    tcp_conn.close()
    await tcp_conn.wait_closed()

    from entity_core.peer.http_client import HttpConnection
    http_conn = await HttpConnection.connect(
        http_url, client_kp, expected_peer_id=server.peer_id,
    )
    try:
        http_cap_hash = http_conn.capability.get("content_hash")
        assert http_cap_hash == tcp_cap_hash, (
            "TCP and HTTP dials should share one held cap (R6) — "
            f"got {tcp_cap_hash!r} vs {http_cap_hash!r}"
        )
        session = read_session(
            server.content_store, server.entity_tree, _identity_hash(client_kp),
        )
        assert session is not None
        assert session.data["minted_capability"]["hash"] == tcp_cap_hash
    finally:
        await http_conn.aclose()


# -----------------------------------------------------------------------------
# Persistence — disconnect MUST NOT delete the session entity (§9.1 R6-c)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_entity_unchanged_across_disconnect(tcp_server_peer):
    """After disconnect the session entity stays in the tree, byte-identical
    to its pre-disconnect state. Lifecycle is `system/peer/status`'s job;
    the session entity is the AUTH record and is not touched on close."""
    client_kp = Keypair.generate()

    conn = await Connection.connect(
        "127.0.0.1", 19202, client_kp,
        expected_peer_id=tcp_server_peer.peer_id,
    )
    cap_hash_at_handshake = conn.capability.get("content_hash")

    client_hash = _identity_hash(client_kp)
    pre = read_session(
        tcp_server_peer.content_store,
        tcp_server_peer.entity_tree,
        client_hash,
    )
    assert pre is not None
    assert pre.data["minted_capability"]["hash"] == cap_hash_at_handshake
    pre_hash = pre.compute_hash()

    conn.close()
    await conn.wait_closed()
    await asyncio.sleep(0.05)

    post = read_session(
        tcp_server_peer.content_store,
        tcp_server_peer.entity_tree,
        client_hash,
    )
    assert post is not None, "disconnect deleted the session entity; §9 says no"
    # §9.1 R6-c — no status/last_active churn on close.
    assert post.compute_hash() == pre_hash, (
        "session entity changed across disconnect; AUTH record must be "
        "untouched (lifecycle lives on system/peer/status)"
    )
    # Schema gate: dropped fields must not be present.
    assert "status" not in post.data
    assert "last_active" not in post.data


# -----------------------------------------------------------------------------
# Client-side persistence: pool.get_connection writes held_capability
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_pool_writes_held_capability(tcp_server_peer):
    """The client's RemoteConnectionPool writes a session entity with
    `held_capability` populated after a successful dial. No status flip
    on eviction (§9.1 R6-c)."""
    client_kp = Keypair.generate()
    client_peer = (
        PeerBuilder()
        .with_keypair(client_kp)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    client_peer.register_remote(
        tcp_server_peer.peer_id, "127.0.0.1:19202",
        public_key=tcp_server_peer.keypair.public_key_bytes(),
    )

    try:
        endpoint = await client_peer._remote_pool.get_connection(
            tcp_server_peer.peer_id,
        )
        assert endpoint is not None
        server_hash = _identity_hash(tcp_server_peer.keypair)

        post_dial = read_session(
            client_peer.content_store,
            client_peer.entity_tree,
            server_hash,
        )
        assert post_dial is not None
        assert "held_capability" in post_dial.data
        assert "minted_capability" not in post_dial.data, (
            "client is grantee only for this peer; minted_capability should "
            "be absent (no bidirectional handshake to record)"
        )
        held_hash = post_dial.data["held_capability"]["hash"]
        assert held_hash == endpoint.capability.get("content_hash")

        # Evict — entity must be unchanged (§9.1 R6-c).
        client_peer._remote_pool.remove_connection(tcp_server_peer.peer_id)
        await asyncio.sleep(0.05)
        post_evict = read_session(
            client_peer.content_store,
            client_peer.entity_tree,
            server_hash,
        )
        assert post_evict is not None
        assert post_evict.compute_hash() == post_dial.compute_hash(), (
            "eviction changed the client-side session entity"
        )
    finally:
        await client_peer._remote_pool.close_all()


# -----------------------------------------------------------------------------
# §9.1 R6-d — chain leaf→root, cap delegation chain only
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chain_leaf_to_root_cap_delegation_only(tcp_server_peer):
    """§9.1 R6-d: chain[0] MUST == minted_capability.hash; for a self-rooted
    cap (no Parent) chain length MUST == 1; chain entries MUST be cap
    entities only (no granter identity / signature padding).

    Pinned against the R6 python chain-order spec-issue cohort
    gate ``session_chain_leaf_to_root``.
    """
    client_kp = Keypair.generate()
    conn = await Connection.connect(
        "127.0.0.1", 19202, client_kp,
        expected_peer_id=tcp_server_peer.peer_id,
    )
    try:
        # Server side (granter) — minted_capability shape.
        server_session = read_session(
            tcp_server_peer.content_store,
            tcp_server_peer.entity_tree,
            _identity_hash(client_kp),
        )
        assert server_session is not None
        minted = server_session.data["minted_capability"]
        assert minted["chain"][0] == minted["hash"], (
            "chain[0] != minted_capability.hash — chain is not leaf-first"
        )
        # Connect cap is self-rooted ⇒ chain length must be exactly 1.
        cap_entity = tcp_server_peer.content_store.get(minted["hash"])
        assert cap_entity is not None
        assert cap_entity.data.get("parent") is None
        assert len(minted["chain"]) == 1, (
            f"connect cap is self-rooted; chain must be length 1, got "
            f"{len(minted['chain'])} (chain MUST NOT carry granter/sig)"
        )
        # Every chain entry MUST resolve to a system/capability/token entity
        # (no system/peer / system/signature padding).
        for h in minted["chain"]:
            e = tcp_server_peer.content_store.get(h)
            assert e is not None
            assert e.type == "system/capability/token", (
                f"chain entry resolves to {e.type!r}; chain is cap delegation only (R6-d)"
            )
    finally:
        conn.close()
        await conn.wait_closed()


# -----------------------------------------------------------------------------
# No self-session (§9.1 R6-f)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_self_session(tcp_server_peer):
    """A peer never writes ``system/peer/session/{local_peer_id}``."""
    # Server hasn't been dialed by anyone yet; ensure no entity at its own slot.
    server_hash = _identity_hash(tcp_server_peer.keypair)
    self_session = read_session(
        tcp_server_peer.content_store,
        tcp_server_peer.entity_tree,
        server_hash,
    )
    assert self_session is None, (
        f"self-session entity exists at {session_path(server_hash)}"
    )


# -----------------------------------------------------------------------------
# Bidirectional: A's minted = B's held (one cap, two viewpoints)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bidirectional_minted_equals_held(tcp_server_peer):
    """For a client → server handshake, the server's
    ``minted_capability`` and the client's ``held_capability`` MUST point
    at the same cap entity (§9.1 R6-a reconciliation)."""
    client_kp = Keypair.generate()
    client_peer = (
        PeerBuilder()
        .with_keypair(client_kp)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    client_peer.register_remote(
        tcp_server_peer.peer_id, "127.0.0.1:19202",
        public_key=tcp_server_peer.keypair.public_key_bytes(),
    )

    try:
        # Dial; this populates both sides' session entities.
        await client_peer._remote_pool.get_connection(tcp_server_peer.peer_id)

        # Client side: held_capability for server.
        client_held = read_held_capability(
            client_peer.content_store, client_peer.entity_tree,
            _identity_hash(tcp_server_peer.keypair),
        )
        assert client_held is not None
        client_cap_entity, _, _ = client_held

        # Server side: minted_capability for client.
        server_minted = read_minted_capability(
            tcp_server_peer.content_store, tcp_server_peer.entity_tree,
            _identity_hash(client_kp),
        )
        assert server_minted is not None
        server_cap_entity, _, _ = server_minted

        assert client_cap_entity.compute_hash() == server_cap_entity.compute_hash(), (
            "client.held_capability and server.minted_capability must "
            "reference the SAME cap entity (one cap, two viewpoints)"
        )
    finally:
        await client_peer._remote_pool.close_all()
