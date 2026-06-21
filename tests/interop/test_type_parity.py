"""Interop tests for type parity between Python and other implementations.

These tests connect to a running peer (Go, Rust, etc.) and compare type
definitions to ensure both implementations produce identical hashes.

Run with: uv run pytest tests/interop/test_type_parity.py -v

Requires: Peer running on 127.0.0.1:9000 (or set INTEROP_PEER_HOST/PORT)
"""

import asyncio
import os

import pytest

from entity_cli.main import (
    CORE_TYPE_PATHS,
    TypeComparisonResult,
    compare_type_data,
    compare_types_with_peer,
    fetch_remote_type,
)
from entity_core.crypto.identity import Keypair
from entity_core.peer.connection import Connection
from entity_core.types import get_all_type_entities
from entity_core.utils.ecf import hash_to_display

# Peer connection settings (works with Go, Rust, or any implementation)
PEER_HOST = os.environ.get("INTEROP_PEER_HOST", "127.0.0.1")
PEER_PORT = int(os.environ.get("INTEROP_PEER_PORT", "9000"))


async def check_peer_available() -> bool:
    """Check if remote peer is available."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(PEER_HOST, PEER_PORT),
            timeout=2.0,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


@pytest.fixture
async def peer_connection():
    """Connect to remote peer for testing."""
    if not await check_peer_available():
        pytest.skip(f"Peer not available at {PEER_HOST}:{PEER_PORT}")

    keypair = Keypair.generate()
    conn = await Connection.connect(PEER_HOST, PEER_PORT, keypair)
    yield conn
    conn.close()
    await conn.wait_closed()


class TestTypeParity:
    """Tests comparing Python and remote peer type definitions."""

    @pytest.mark.asyncio
    async def test_can_connect_to_peer(self, peer_connection):
        """Verify we can connect to the remote peer."""
        assert peer_connection.session.remote_peer_id is not None

    @pytest.mark.asyncio
    async def test_peer_has_core_types(self, peer_connection):
        """Verify remote peer has all core types registered."""
        missing = []
        for type_path in CORE_TYPE_PATHS:
            remote_data = await fetch_remote_type(peer_connection, type_path)
            if remote_data is None:
                missing.append(type_path)
            elif remote_data.get("name") != type_path:
                missing.append(f"{type_path} (name mismatch: {remote_data.get('name')})")

        if missing:
            pytest.fail(f"Remote peer missing types: {missing}")

    @pytest.mark.asyncio
    async def test_type_hash_parity(self, peer_connection):
        """Compare type hashes between Python and remote peer.

        Both implementations should produce identical content hashes for
        the same type definitions per TYPE-SYSTEM spec.
        """
        local_types = {e.data["name"]: e for e in get_all_type_entities()}

        results = await compare_types_with_peer(
            peer_connection, CORE_TYPE_PATHS, local_types
        )

        matches = [r for r in results if r.match]
        mismatches = [r for r in results if not r.match]

        # Report results
        print(f"\n\nType Parity Results: {len(matches)}/{len(results)} match")
        print(f"Matches: {[r.type_path for r in matches]}")
        if mismatches:
            print(f"\nMismatches ({len(mismatches)}):")
            for r in mismatches:
                print(f"  {r.type_path}:")
                if r.local_hash:
                    print(f"    Local:  {hash_to_display(r.local_hash)}")
                if r.remote_hash:
                    print(f"    Remote: {hash_to_display(r.remote_hash)}")
                for diff in r.differences or []:
                    print(f"    - {diff}")

        # Fail if there are mismatches
        if mismatches:
            pytest.fail(f"Type hash mismatches: {[r.type_path for r in mismatches]}")


class TestTypeFieldComparison:
    """Detailed field comparison tests."""

    @pytest.mark.asyncio
    async def test_compare_all_types(self, peer_connection):
        """Generate detailed comparison report for all types."""
        local_types = {e.data["name"]: e for e in get_all_type_entities()}

        results = await compare_types_with_peer(
            peer_connection, CORE_TYPE_PATHS, local_types
        )

        # Print report for debugging
        print("\n" + "=" * 80)
        print("TYPE DEFINITION COMPARISON REPORT")
        print("=" * 80)

        for r in results:
            status = "MATCH" if r.match else "DIFF"
            print(f"\n[{status}] {r.type_path}")

            if not r.match and r.differences:
                for diff in r.differences:
                    print(f"  - {diff}")

        print("\n" + "=" * 80)
        matches = [r for r in results if r.match]
        print(f"Summary: {len(matches)}/{len(results)} types match")
        print("=" * 80)
