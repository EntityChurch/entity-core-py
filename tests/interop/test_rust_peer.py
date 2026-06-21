"""Interoperability tests with Rust peer.

These tests require a Rust peer running at 127.0.0.1:9000.
Run with: uv run pytest tests/interop/ -v

To test against a different port (e.g., Go peer on 9002):
    PEER_PORT=9002 uv run pytest tests/interop/test_rust_peer.py -v
"""

import os
import pytest

from entity_core.crypto.identity_file import load_identity
from entity_core.peer.connection import Connection
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.messages import Execute, ExecuteResponse


# Port can be overridden via environment variable
PEER_PORT = int(os.environ.get("PEER_PORT", "9000"))

# Skip all tests if Rust peer isn't available
pytestmark = pytest.mark.asyncio


@pytest.fixture
def framework_admin_keypair():
    """Load the framework-admin identity."""
    identity = load_identity("framework-admin")
    return identity.keypair


async def check_rust_peer_available() -> bool:
    """Check if Rust peer is running."""
    import asyncio

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", PEER_PORT),
            timeout=1.0,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


@pytest.fixture
async def rust_peer_available():
    """Skip test if Rust peer not available."""
    if not await check_rust_peer_available():
        pytest.skip(f"Rust peer not available at 127.0.0.1:{PEER_PORT}")


@pytest.mark.asyncio
async def test_connect_to_rust_peer(rust_peer_available, framework_admin_keypair):
    """Python peer can connect to Rust peer and complete handshake."""
    conn = await Connection.connect(
        "127.0.0.1",
        PEER_PORT,
        framework_admin_keypair,
        wait_for_capability=True,
    )

    try:
        print(f"\nConnected to Rust peer: {conn.session.remote_peer_id}")
        print(f"Our peer ID: {conn.session.local_peer_id}")

        assert conn.session.remote_peer_id is not None
        assert conn.session.local_peer_id == framework_admin_keypair.peer_id

        # Check if we received a capability (stored as raw dict to preserve content_hash)
        if conn.capability:
            print(f"Received capability: {conn.capability.get('type')}")
            print(f"Grants: {conn.capability.get('data', {}).get('grants', [])}")
        else:
            print("No capability received (might not be required)")

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_execute_system_status(rust_peer_available, framework_admin_keypair):
    """Python can request system/status from Rust peer."""
    conn = await Connection.connect(
        "127.0.0.1",
        PEER_PORT,
        framework_admin_keypair,
        wait_for_capability=True,
    )

    try:
        # Send EXECUTE for system/status (unauthenticated first)
        execute = Execute.create(
            uri=f"entity://{conn.session.remote_peer_id}/system/status",
            operation="read",
        )
        await conn.send(Envelope(root=execute.to_entity()))

        response_env = await conn.recv()
        print(f"\nResponse type: {response_env.root.get('type')}")
        print(f"Response: {response_env.root}")

        if response_env.root.get("type") == ExecuteResponse.TYPE:
            response = ExecuteResponse.from_entity(response_env.root)
            print(f"Status: {response.status}")
            print(f"Result: {response.result}")

    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_authenticated_execute(rust_peer_available, framework_admin_keypair):
    """Python sends authenticated EXECUTE to Rust peer."""
    conn = await Connection.connect(
        "127.0.0.1",
        PEER_PORT,
        framework_admin_keypair,
        wait_for_capability=True,
    )

    try:
        if conn.capability is None:
            pytest.skip("No capability received from Rust peer")

        # Use high-level execute with authentication
        response = await conn.execute(
            uri=f"entity://{conn.session.remote_peer_id}/system/status",
            operation="read",
            authenticated=True,
        )

        print(f"\nAuthenticated response status: {response.status}")
        print(f"Result: {response.result}")

        # We expect either success or a specific error
        assert response.status in [200, 403, 404, 500]

    finally:
        conn.close()
        await conn.wait_closed()
