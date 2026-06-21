#!/usr/bin/env python3
"""
Simple Delegation Test - Use the SAME identity that Rust knows about.

Since Rust saw our identity during IDENTIFY, maybe it stored it.
Let's try using the original capability's grantee hash directly.
"""

import asyncio
import struct
import json
import base64
import secrets
import time
import uuid

from entity_core.crypto.identity_file import load_identity
from entity_core.utils.ecf import ecf_encode, ecf_decode
from entity_core.protocol.messages import compute_content_hash


async def send_envelope(writer, envelope: dict):
    payload = ecf_encode(envelope)
    length = struct.pack(">I", len(payload))
    writer.write(length + payload)
    await writer.drain()


async def recv_envelope(reader, timeout=5.0) -> dict | None:
    try:
        length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout)
        length = struct.unpack(">I", length_bytes)[0]
        payload = await reader.readexactly(length)
        return ecf_decode(payload)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        return None


def get_ref_hash(ref):
    if ref is None:
        return None
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        return ref.get("hash")
    return None


async def main():
    print("Simple Delegation Test")
    print("=" * 60)

    identity = load_identity("framework-admin")
    keypair = identity.keypair

    reader, writer = await asyncio.open_connection("127.0.0.1", 9000)

    # === Handshake ===
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

    rust_hello = await recv_envelope(reader)
    rust_nonce = rust_hello["root"]["data"]["nonce"]
    rust_peer_id = rust_hello["root"]["data"]["peer_id"]

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

    await recv_envelope(reader)  # Their IDENTIFY

    # Get capability grant
    capability_entity = None
    capability_hash = None
    included = {}

    for _ in range(3):
        msg = await recv_envelope(reader, timeout=2.0)
        if msg and msg["root"]["type"] == "system/capability/grant":
            included = msg.get("included", {})
            token_ref = msg["root"].get("refs", {}).get("token")
            capability_hash = get_ref_hash(token_ref)
            capability_entity = included.get(capability_hash)
            break

    print(f"Got capability: {capability_hash[:50]}...")

    # Check what identity Rust used for us as grantee
    rust_grantee_hash = get_ref_hash(capability_entity["refs"]["grantee"])
    print(f"Rust's grantee hash for us: {rust_grantee_hash}")

    # Find that identity in included
    rust_grantee_entity = None
    for h, e in included.items():
        if e["type"] == "system/peer" and e["data"].get("peer_id") == keypair.peer_id:
            rust_grantee_entity = e
            print(f"Found our identity in Rust's included: {h}")
            print(f"  Data: {json.dumps(e['data'], sort_keys=True)}")
            break

    # Test: Can we use the capability normally?
    print("\n--- Test 1: Normal request with Rust's capability ---")

    # Use the identity entity from Rust's included if available
    identity_entity = rust_grantee_entity
    if not identity_entity:
        # Create our own
        identity_data = {
            "peer_id": keypair.peer_id,
            "public_key": base64.b64encode(keypair.public_key_bytes()).decode("ascii"),
            "key_type": "ed25519",
        }
        identity_entity = {
            "type": "system/peer",
            "data": identity_data,
            "content_hash": compute_content_hash("system/peer", identity_data),
            "refs": {},
        }

    identity_hash = identity_entity["content_hash"]

    execute_data = {
        "request_id": str(uuid.uuid4()),
        "uri": f"entity://{rust_peer_id}/system/status",
        "operation": "read",
        "params": {},
    }
    execute_hash = compute_content_hash("system/protocol/execute", execute_data)

    sig_data = {
        "target": execute_hash,
        "algorithm": "ed25519",
        "signature": base64.b64encode(keypair.sign(execute_hash.encode("utf-8"))).decode("ascii"),
        "signer": keypair.peer_id,
    }
    sig_entity = {
        "type": "system/signature",
        "data": sig_data,
        "content_hash": compute_content_hash("system/signature", sig_data),
        "refs": {},
    }
    sig_hash = sig_entity["content_hash"]

    execute_entity = {
        "type": "system/protocol/execute",
        "data": execute_data,
        "content_hash": execute_hash,
        "refs": {
            "author": {"hash": identity_hash},
            "signature": {"hash": sig_hash},
            "capability": {"hash": capability_hash},
        },
    }

    envelope = {
        "root": execute_entity,
        "included": {
            identity_hash: identity_entity,
            sig_hash: sig_entity,
        },
    }

    await send_envelope(writer, envelope)
    response = await recv_envelope(reader)
    status = response["root"]["data"].get("status") if response else None
    print(f"Status: {status}")

    writer.close()
    await writer.wait_closed()
    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(main())
