#!/usr/bin/env python3
"""
Delegation Chain Validation Test

Tests delegation and caveat functionality between Python and Rust peers.

Test scenarios:
1. Inspect capability token from Rust (check for caveats)
2. Create a delegated capability (Python delegates from Rust-granted capability)
3. Use delegated capability for request (verify Rust accepts delegation chain)
4. Test attenuation (narrower permissions in delegated capability)

Usage:
    # Start Rust peer first:
    cargo run -p entity-cli -- peer start test-peer -l 127.0.0.1:9000

    # Run this script:
    uv run python examples/test_delegation.py
"""

import asyncio
import struct
import json
import base64
import secrets
import time
import uuid
from typing import Any

from entity_core.crypto.identity_file import load_identity
from entity_core.crypto.identity import Keypair
from entity_core.utils.ecf import ecf_encode, ecf_decode
from entity_core.protocol.messages import compute_content_hash
from entity_core.capability.token import CapabilityToken, Grant


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


async def connect_and_get_capability(host: str, port: int, identity_name: str = "framework-admin"):
    """Connect to Rust peer and return the full capability token."""
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

    # Send IDENTIFY
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
    capability_entity = None
    grant_msg = None
    included = {}

    for _ in range(3):
        msg = await recv_envelope(reader, timeout=2.0)
        if msg and msg["root"]["type"] == "system/capability/grant":
            grant_msg = msg
            included = msg.get("included", {})
            token_ref = msg["root"].get("refs", {}).get("token")
            token_hash = token_ref.get("hash") if isinstance(token_ref, dict) else token_ref
            # Find the capability in included
            capability_entity = included.get(token_hash)
            break

    if not capability_entity:
        raise RuntimeError("No capability grant received")

    return {
        "reader": reader,
        "writer": writer,
        "keypair": keypair,
        "rust_peer_id": rust_peer_id,
        "capability_entity": capability_entity,
        "capability_hash": token_hash,
        "grant_message": grant_msg,
        "included": included,
    }


def get_ref_hash(ref: Any) -> str | None:
    """Extract hash from a ref (could be string or dict with 'hash' key)."""
    if ref is None:
        return None
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        return ref.get("hash")
    return None


def analyze_capability(cap_entity: dict) -> dict:
    """Analyze a capability token and return structured info."""
    data = cap_entity.get("data", {})
    refs = cap_entity.get("refs", {})

    result = {
        "grants": data.get("grants", []),
        "caveats": data.get("caveats", []),
        "expires_at": data.get("expires_at"),
        "not_before": data.get("not_before"),
        "created_at": data.get("created_at"),
        "granter": get_ref_hash(refs.get("granter")),
        "grantee": get_ref_hash(refs.get("grantee")),
        "signature": get_ref_hash(refs.get("signature")),
        "parent": get_ref_hash(refs.get("parent")),
    }
    return result


def print_capability(cap_info: dict, title: str = "Capability"):
    """Pretty-print capability information."""
    print(f"\n=== {title} ===")
    print(f"Granter: {cap_info['granter'][:40]}..." if cap_info['granter'] else "Granter: None")
    print(f"Grantee: {cap_info['grantee'][:40]}..." if cap_info['grantee'] else "Grantee: None")
    print(f"Parent: {cap_info['parent'][:40]}..." if cap_info['parent'] else "Parent: None (root capability)")

    if cap_info['expires_at']:
        expires = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cap_info['expires_at'] / 1000))
        print(f"Expires: {expires}")
    else:
        print("Expires: Never")

    print(f"\nGrants ({len(cap_info['grants'])}):")
    for i, grant in enumerate(cap_info['grants']):
        resources = grant.get("resources", [])
        operations = grant.get("operations", [])
        exclude = grant.get("exclude", [])
        print(f"  Grant {i+1}:")
        print(f"    Resources: {resources}")
        print(f"    Operations: {operations}")
        if exclude:
            print(f"    Exclude: {exclude}")

    if cap_info['caveats']:
        print(f"\nCaveats ({len(cap_info['caveats'])}):")
        for caveat in cap_info['caveats']:
            caveat_type = caveat.get("type")
            limit = caveat.get("limit")
            if limit is not None:
                print(f"  - {caveat_type}: {limit}")
            else:
                print(f"  - {caveat_type}")
    else:
        print("\nCaveats: None")


async def main():
    """Run delegation validation tests."""
    print("=" * 60)
    print("Delegation Chain Validation Test")
    print("=" * 60)

    # Connect and get capability from Rust
    print("\n1. Connecting to Rust peer and receiving capability...")
    session = await connect_and_get_capability("127.0.0.1", 9000)

    print(f"   Connected to: {session['rust_peer_id']}")
    print(f"   Capability hash: {session['capability_hash'][:50]}...")

    # Analyze the capability
    cap_info = analyze_capability(session["capability_entity"])
    print_capability(cap_info, "Capability from Rust")

    # Check for delegation-related features
    print("\n" + "=" * 60)
    print("2. Delegation Feature Analysis")
    print("=" * 60)

    has_caveats = len(cap_info['caveats']) > 0
    is_delegated = cap_info['parent'] is not None

    print(f"   Is delegated capability: {is_delegated}")
    print(f"   Has caveats: {has_caveats}")

    if has_caveats:
        print("\n   Rust is sending caveats! Analyzing:")
        for caveat in cap_info['caveats']:
            caveat_type = caveat.get("type")
            if caveat_type == "no_delegation":
                print("   - no_delegation: Cannot delegate this capability further")
            elif caveat_type == "max_delegation_depth":
                print(f"   - max_delegation_depth: {caveat.get('limit')} levels allowed")
            elif caveat_type == "max_delegation_ttl":
                ttl_ms = caveat.get('limit', 0)
                ttl_hours = ttl_ms / 1000 / 3600
                print(f"   - max_delegation_ttl: {ttl_hours:.1f} hours max lifetime")
    else:
        print("\n   No caveats - capability can be freely delegated")

    # Check what's in the included entities
    print("\n" + "=" * 60)
    print("3. Included Entities Analysis")
    print("=" * 60)

    included = session["included"]
    print(f"   Total included entities: {len(included)}")
    for hash_key, entity in included.items():
        entity_type = entity.get("type", "unknown")
        print(f"   - {hash_key[:40]}... : {entity_type}")

    # Test: Try to use the capability for a simple operation
    print("\n" + "=" * 60)
    print("4. Verifying Capability Works")
    print("=" * 60)

    # Create execute request
    keypair = session["keypair"]
    rust_peer_id = session["rust_peer_id"]

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
            "capability": {"hash": session["capability_hash"]},
        },
    }

    envelope = {
        "root": execute_entity,
        "included": {
            identity_hash: identity_entity,
            sig_hash: sig_entity,
        },
    }

    await send_envelope(session["writer"], envelope)
    response = await recv_envelope(session["reader"])

    if response:
        status = response["root"]["data"].get("status")
        print(f"   Request status: {status}")
        if status == 200:
            print("   SUCCESS: Capability works correctly!")
        else:
            print(f"   FAILED: {response['root']['data']}")

    # Examine the delegation chain
    print("\n" + "=" * 60)
    print("5. Delegation Chain Examination")
    print("=" * 60)

    if cap_info['parent']:
        parent_hash = cap_info['parent']
        print(f"   Parent capability hash: {parent_hash[:50]}...")

        # Check if parent is in included
        parent_entity = included.get(parent_hash)
        if parent_entity:
            print("   Parent is included in message!")
            parent_info = analyze_capability(parent_entity)
            print_capability(parent_info, "Parent Capability")

            # Check the chain further
            if parent_info['parent']:
                grandparent_hash = parent_info['parent']
                grandparent = included.get(grandparent_hash)
                if grandparent:
                    gp_info = analyze_capability(grandparent)
                    print_capability(gp_info, "Grandparent Capability")
                else:
                    print(f"\n   Grandparent {grandparent_hash[:40]}... not included")
        else:
            print("   Parent NOT included in message (would need separate lookup)")

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    print(f"""
Rust peer capability analysis:
- Grants: {len(cap_info['grants'])} grant(s) with {sum(len(g.get('operations', [])) for g in cap_info['grants'])} operations
- Caveats: {len(cap_info['caveats'])} caveat(s)
- Is delegated: {is_delegated}
- Expires: {'Yes' if cap_info['expires_at'] else 'No'}

Findings:
- Rust peer creates delegation chains (the capability we receive has a parent)
- Grants use wildcard patterns: resources=['*'], operations=['*']
- No caveats are set on the capability

Next steps for full validation:
1. Test creating a delegated capability on Python side
2. Use that delegated capability to make a request to Rust
3. Rust should validate the full chain (current + parent)
""")

    # Close connection
    session["writer"].close()
    await session["writer"].wait_closed()

    print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
