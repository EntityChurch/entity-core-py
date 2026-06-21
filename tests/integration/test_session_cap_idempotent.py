"""R3a — granter idempotency for the connect-handshake cap.

PROPOSAL-TRANSPORT-FAMILY-LIVE-REACHABILITY-AND-SESSION-LIFECYCLE §7.3
(Round-2 LOCKED). The connect handler MUST reuse a live
`(grantee_peer_id, grants)` cap rather than minting a fresh
`created_at: now()` triple per handshake.

R6: held cap lives in the entity tree at
`system/peer/session/{remote_peer_id}` per PROPOSAL §7.2.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection


@pytest.fixture
async def server_peer():
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_default_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 19101)
    yield peer
    await peer.stop()


@pytest.mark.asyncio
async def test_repeat_handshake_same_client_returns_same_cap(server_peer):
    """Two handshakes from the same client peer reuse the same minted cap
    (same content_hash, same created_at, same signature)."""
    client_keypair = Keypair.generate()

    conn1 = await Connection.connect(
        "127.0.0.1", 19101, client_keypair,
        expected_peer_id=server_peer.peer_id,
    )
    cap1 = conn1.capability
    assert cap1 is not None
    cap1_hash = cap1.get("content_hash")
    cap1_created = cap1.get("data", {}).get("created_at")

    conn1.close()
    await conn1.wait_closed()

    # Small gap to ensure now_ms would differ if a fresh mint occurred.
    await asyncio.sleep(0.05)

    conn2 = await Connection.connect(
        "127.0.0.1", 19101, client_keypair,
        expected_peer_id=server_peer.peer_id,
    )
    cap2 = conn2.capability
    assert cap2 is not None

    assert cap2.get("content_hash") == cap1_hash, (
        "second handshake minted a NEW cap entity; R3a requires reuse"
    )
    assert cap2.get("data", {}).get("created_at") == cap1_created, (
        "second handshake reset created_at; reused cap should preserve it"
    )

    conn2.close()
    await conn2.wait_closed()


@pytest.mark.asyncio
async def test_distinct_clients_get_distinct_caps(server_peer):
    """Idempotency is keyed by (grantee_peer_id, grants); two DIFFERENT
    client peers must each get their own minted cap."""
    client_a = Keypair.generate()
    client_b = Keypair.generate()

    conn_a = await Connection.connect("127.0.0.1", 19101, client_a)
    conn_b = await Connection.connect("127.0.0.1", 19101, client_b)

    assert conn_a.capability.get("content_hash") != conn_b.capability.get(
        "content_hash"
    ), "different grantees must produce distinct cap entities"

    conn_a.close(); await conn_a.wait_closed()
    conn_b.close(); await conn_b.wait_closed()


@pytest.mark.asyncio
async def test_session_entity_persists_in_tree_after_handshake(server_peer):
    """R6 §9: after handshake, the server holds the cap as the
    `minted_capability` field of a `system/peer/session/{remote_peer_id}`
    tree entity (granter-side anchor; §9.1 R6-a)."""
    from entity_core.peer.session_entity import (
        read_session,
        session_path,
    )

    from entity_core.protocol.auth import create_identity_entity

    client_keypair = Keypair.generate()
    client_hash = create_identity_entity(client_keypair).compute_hash()
    conn = await Connection.connect(
        "127.0.0.1", 19101, client_keypair,
        expected_peer_id=server_peer.peer_id,
    )
    try:
        session_entity = read_session(
            server_peer.content_store,
            server_peer.entity_tree,
            client_hash,
        )
        assert session_entity is not None, (
            f"expected session entity at {session_path(client_hash)}"
        )
        assert session_entity.type == "system/peer/session"
        data = session_entity.data
        assert data["remote_peer_id"] == client_keypair.peer_id
        # §9.1 R6-c — status field dropped.
        assert "status" not in data
        # §9.1 R6-b — last_active field dropped.
        assert "last_active" not in data
        # Server side is the granter ⇒ minted_capability is populated.
        cap_field = data["minted_capability"]
        assert "hash" in cap_field and "chain" in cap_field
        assert cap_field["hash"] == conn.capability.get("content_hash"), (
            "session entity must point at the same cap as the connection"
        )
        # Chain entities MUST be in the content store so reconnect can re-bundle them.
        for h in cap_field["chain"]:
            assert server_peer.content_store.get(h) is not None, (
                f"chain entity {h.hex()[:16]} missing from content store"
            )
    finally:
        conn.close()
        await conn.wait_closed()
