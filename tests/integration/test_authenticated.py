"""Tests for authenticated EXECUTE requests.

Auth is always required - there is no bypass. Debug mode grants permissive
capabilities, but those capabilities are still verified.
"""

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.messages import Execute, ExecuteResponse


@pytest.fixture
async def server_peer():
    """Create and start a server peer."""
    keypair = Keypair.generate()
    # debug_mode=True grants capabilities to all connecting peers (for testing)
    # Auth is always required and verified - no bypass
    peer = PeerBuilder().with_keypair(keypair).with_default_handlers().debug_mode(True).build()
    await peer.start("127.0.0.1", 19002)
    yield peer
    await peer.stop()


@pytest.mark.asyncio
async def test_capability_grant_received(server_peer: Peer):
    """Client receives capability grant after connection."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", 19002, client_keypair)

    try:
        # Should have received a capability (stored as dict to preserve content_hash)
        assert conn.capability is not None
        assert conn.capability["type"] == "system/capability/token"
        assert "content_hash" in conn.capability  # Preserved from wire

        # Capability should have grants
        grants = conn.capability["data"].get("grants", [])
        assert len(grants) > 0

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_connection_cap_has_no_finite_expiry(server_peer: Peer):
    """Connection cap MUST omit `expires_at` (matches Go's
    `core/protocol/connect.go`). A finite default forces clients minting
    chained dispatch caps with their own TTL to clamp below the parent's
    expiry — they don't (cf. cross-impl tv_rd_caller_expiry_inheritance,
    where validate-peer mints `now+1h`), so V7 §5.6 attenuation rejects."""
    client_keypair = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19002, client_keypair)
    try:
        assert conn.capability is not None
        assert "expires_at" not in conn.capability["data"], (
            "connection cap must omit expires_at; finite expiry blocks "
            "wire-clients from minting chained caps with reasonable TTLs"
        )
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_authenticated_execute(server_peer: Peer):
    """Authenticated EXECUTE succeeds."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", 19002, client_keypair)

    try:
        # Send authenticated request
        response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/system/status",
            operation="get",
            authenticated=True,
        )

        assert response.status == 200
        assert response.result["type"] == "status"

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_unauthenticated_request_fails(server_peer: Peer):
    """Unauthenticated request fails - auth is always required."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", 19002, client_keypair)

    try:
        # Send unauthenticated request - should fail
        execute = Execute.create(
            uri=f"entity://{server_peer.peer_id}/system/status",
            operation="get",
        )
        await conn.send(Envelope(root=execute.to_entity()))

        response_env = await conn.recv()
        response = ExecuteResponse.from_entity(response_env.root)

        # V7 v7.71 §3.3: a request with no author is an authentication-class
        # failure (the wire-side identity half of §5.2), so it surfaces 401
        # authentication_failed — NOT the 403 authorization-class DENY.
        assert response.status == 401
        assert response.result["data"]["code"] == "authentication_failed"

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_storage_write_read(server_peer: Peer):
    """Authenticated write and read work correctly."""
    client_keypair = Keypair.generate()

    conn = await Connection.connect("127.0.0.1", 19002, client_keypair)

    try:
        # Write entity
        write_response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/data/auth-test",
            operation="write",
            params={"entity": {"type": "test", "data": {"value": 42}}},
            authenticated=True,
        )

        assert write_response.status == 200

        # Read it back
        read_response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/data/auth-test",
            operation="get",
            authenticated=True,
        )

        assert read_response.status == 200
        assert read_response.result["data"]["value"] == 42

    finally:
        conn.close()
        await conn.wait_closed()
