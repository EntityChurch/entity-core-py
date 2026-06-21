#!/usr/bin/env python3
"""
Rust Interoperability Example

Demonstrates full Python-Rust communication:
1. TCP connection
2. HELLO/IDENTIFY handshake
3. Capability grant reception
4. Authenticated EXECUTE requests
5. File read/write operations

Usage:
    # Start Rust peer first:
    cargo run -p entity-cli -- peer start test-peer -l 127.0.0.1:9000

    # Run this script:
    uv run python examples/rust_interop.py
"""

import asyncio
import struct
import json
import base64
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

from entity_core.crypto.identity_file import load_identity
from entity_core.utils.ecf import ecf_encode, ecf_decode
from entity_core.protocol.messages import compute_content_hash


async def send_envelope(writer, envelope: dict):
    """Send a length-prefixed CBOR envelope."""
    payload = ecf_encode(envelope)
    length = struct.pack(">I", len(payload))
    writer.write(length + payload)
    await writer.drain()


async def recv_envelope(reader, timeout=5.0) -> dict | None:
    """Receive a length-prefixed CBOR envelope."""
    try:
        length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout)
        length = struct.unpack(">I", length_bytes)[0]
        payload = await reader.readexactly(length)
        return ecf_decode(payload)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None


@dataclass
class RustSession:
    """Authenticated session with a Rust peer."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    keypair: Any
    peer_id: str
    capability_hash: str

    async def execute(
        self, uri: str, operation: str, params: dict | None = None
    ) -> dict | None:
        """Execute an authenticated request."""
        params = params or {}

        # Create identity entity
        identity_data = {
            "peer_id": self.keypair.peer_id,
            "public_key": base64.b64encode(self.keypair.public_key_bytes()).decode(
                "ascii"
            ),
            "key_type": "ed25519",
        }
        identity_entity = {
            "type": "system/peer",
            "data": identity_data,
            "content_hash": compute_content_hash("system/peer", identity_data),
            "refs": {},
        }
        identity_hash = identity_entity["content_hash"]

        # Create execute data
        execute_data = {
            "request_id": str(uuid.uuid4()),
            "uri": uri,
            "operation": operation,
            "params": params,
        }
        execute_hash = compute_content_hash("system/protocol/execute", execute_data)

        # Create signature
        sig_data = {
            "target": execute_hash,
            "algorithm": "ed25519",
            "signature": base64.b64encode(
                self.keypair.sign(execute_hash.encode("utf-8"))
            ).decode("ascii"),
            "signer": self.keypair.peer_id,
        }
        sig_entity = {
            "type": "system/signature",
            "data": sig_data,
            "content_hash": compute_content_hash("system/signature", sig_data),
            "refs": {},
        }
        sig_hash = sig_entity["content_hash"]

        # Build execute entity with refs
        execute_entity = {
            "type": "system/protocol/execute",
            "data": execute_data,
            "content_hash": execute_hash,
            "refs": {
                "author": {"hash": identity_hash},
                "signature": {"hash": sig_hash},
                "capability": {"hash": self.capability_hash},
            },
        }

        # Build envelope with included entities
        envelope = {
            "root": execute_entity,
            "included": {
                identity_hash: identity_entity,
                sig_hash: sig_entity,
            },
        }

        await send_envelope(self.writer, envelope)
        return await recv_envelope(self.reader)

    async def close(self):
        """Close the connection."""
        self.writer.close()
        await self.writer.wait_closed()


async def connect(host: str, port: int, identity_name: str = "framework-admin") -> RustSession:
    """Connect to a Rust peer and complete handshake."""
    identity = load_identity(identity_name)
    keypair = identity.keypair

    reader, writer = await asyncio.open_connection(host, port)

    # Send HELLO
    nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    hello_data = {
        "peer_id": keypair.peer_id,
        "nonce": nonce,
        "protocols": ["entity-core/0.1"],
        "timestamp": int(time.time() * 1000),
    }
    hello_entity = {
        "type": "system/protocol/hello",
        "data": hello_data,
        "content_hash": compute_content_hash("system/protocol/hello", hello_data),
        "refs": {},
    }
    await send_envelope(writer, {"root": hello_entity, "included": {}})

    # Receive their HELLO
    rust_hello = await recv_envelope(reader)
    if not rust_hello:
        raise RuntimeError("No HELLO from Rust peer")

    rust_nonce = rust_hello["root"]["data"]["nonce"]
    rust_peer_id = rust_hello["root"]["data"]["peer_id"]

    # Send IDENTIFY (sign their nonce as base64 string)
    signature = keypair.sign(rust_nonce.encode("utf-8"))
    identify_data = {
        "peer_id": keypair.peer_id,
        "public_key": base64.b64encode(keypair.public_key_bytes()).decode("ascii"),
        "key_type": "ed25519",
        "nonce": rust_nonce,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    identify_entity = {
        "type": "system/protocol/identify",
        "data": identify_data,
        "content_hash": compute_content_hash("system/protocol/identify", identify_data),
        "refs": {},
    }
    await send_envelope(writer, {"root": identify_entity, "included": {}})

    # Receive their IDENTIFY
    rust_identify = await recv_envelope(reader)
    if not rust_identify:
        raise RuntimeError("No IDENTIFY from Rust peer")

    # Wait for CAPABILITY_GRANT
    capability_hash = None
    for _ in range(3):
        msg = await recv_envelope(reader, timeout=2.0)
        if msg and msg["root"]["type"] == "system/capability/grant":
            token_ref = msg["root"].get("refs", {}).get("token")
            capability_hash = (
                token_ref.get("hash") if isinstance(token_ref, dict) else token_ref
            )
            break

    if not capability_hash:
        raise RuntimeError("No capability grant received")

    return RustSession(
        reader=reader,
        writer=writer,
        keypair=keypair,
        peer_id=rust_peer_id,
        capability_hash=capability_hash,
    )


async def main():
    """Run interoperability tests."""
    print("Connecting to Rust peer...")
    session = await connect("127.0.0.1", 9000)
    print(f"Connected to: {session.peer_id}")
    print(f"Capability: {session.capability_hash[:40]}...")

    # Test 1: Read system status
    print("\n=== Test 1: Read system/status ===")
    response = await session.execute(
        f"entity://{session.peer_id}/system/status", "read"
    )
    if response:
        result = response["root"]["data"]
        print(f"Status: {result.get('status')}")
        if result.get("status") == 200:
            print(f"Result: {json.dumps(result.get('result', {}).get('data', {}), indent=2)}")

    # Test 2: List home directory
    print("\n=== Test 2: List files ===")
    import os
    home = os.path.expanduser("~")
    response = await session.execute(
        f"entity://{session.peer_id}/local/files{home}/", "list"
    )
    if response:
        result = response["root"]["data"]
        print(f"Status: {result.get('status')}")
        if result.get("status") == 200:
            entity = result.get("result", {})
            print(f"Type: {entity.get('type')}")
            # Note: Rust uses "children" not "entries"
            children = entity.get("data", {}).get("children", [])
            print(f"Found {len(children)} children")
            for child in children[:5]:
                print(f"  - {child.get('name')} ({child.get('type')})")

    # Test 3: Write a file
    print("\n=== Test 3: Write a file ===")
    test_path = f"/tmp/python-interop-test-{int(time.time())}.txt"
    test_content = f"Written by Python at {time.strftime('%Y-%m-%d %H:%M:%S')}"
    response = await session.execute(
        f"entity://{session.peer_id}/local/files{test_path}",
        "write",
        {"content": test_content},
    )
    if response:
        result = response["root"]["data"]
        print(f"Status: {result.get('status')}")
        if result.get("status") == 200:
            print(f"Written: {result.get('result', {}).get('data', {}).get('written')}")

    # Test 4: Read it back
    print("\n=== Test 4: Read the file back ===")
    response = await session.execute(
        f"entity://{session.peer_id}/local/files{test_path}", "read"
    )
    if response:
        result = response["root"]["data"]
        print(f"Status: {result.get('status')}")
        if result.get("status") == 200:
            content = result.get("result", {}).get("data", {}).get("content", "")
            print(f"Content: {content}")

    # Cleanup
    import os
    if os.path.exists(test_path):
        os.remove(test_path)
        print(f"\nCleaned up: {test_path}")

    await session.close()
    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(main())
