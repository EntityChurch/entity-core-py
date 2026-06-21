"""Tests for EXECUTE round-trip between Python peers.

Auth is always required - all requests must be authenticated.
"""

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection


@pytest.fixture
async def server_peer():
    """Create and start a server peer."""
    keypair = Keypair.generate()
    # debug_mode=True grants capabilities to all connecting peers (for testing)
    peer = PeerBuilder().with_keypair(keypair).with_default_handlers().debug_mode(True).build()
    await peer.start("127.0.0.1", 19001)
    yield peer
    await peer.stop()


@pytest.mark.asyncio
async def test_execute_system_status(server_peer: Peer):
    """Client can request system/status from server."""
    client_keypair = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19001, client_keypair)

    try:
        response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/system/status",
            operation="get",
            authenticated=True,
        )

        assert response.status == 200
        assert response.result["type"] == "status"
        assert response.result["data"]["peer_id"] == server_peer.peer_id

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_execute_system_peer_info(server_peer: Peer):
    """Client can request system/peer/info from server."""
    client_keypair = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19001, client_keypair)

    try:
        response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/system/peer/info",
            operation="get",
            authenticated=True,
        )

        assert response.status == 200
        assert response.result["type"] == "peer-info"
        assert "entity-core/7.0" in response.result["data"]["protocols"]

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_execute_storage_write_read(server_peer: Peer):
    """Client can write and read entities via storage handler."""
    client_keypair = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19001, client_keypair)

    try:
        # Write an entity
        write_response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/data/test",
            operation="write",
            params={
                "entity": {
                    "type": "test-data",
                    "data": {"message": "Hello from Python!"},
                }
            },
            authenticated=True,
        )

        assert write_response.status == 200
        # Storage handler returns raw {hash, uri}; after §3.4 wire wrapping,
        # the payload lives in result.data (or .result_data).
        assert "hash" in write_response.result_data

        # Read it back
        read_response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/data/test",
            operation="get",
            authenticated=True,
        )

        assert read_response.status == 200
        assert read_response.result["type"] == "test-data"
        assert read_response.result["data"]["message"] == "Hello from Python!"

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_execute_not_found(server_peer: Peer):
    """Reading non-existent entity returns 404."""
    client_keypair = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19001, client_keypair)

    try:
        response = await conn.execute(
            uri=f"entity://{server_peer.peer_id}/does/not/exist",
            operation="get",
            authenticated=True,
        )

        assert response.status == 404

    finally:
        conn.close()
        await conn.wait_closed()
