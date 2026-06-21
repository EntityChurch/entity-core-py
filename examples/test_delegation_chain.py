#!/usr/bin/env python3
"""
Full Delegation Chain Test

Tests that Rust properly validates delegation chains by:
1. Python receives capability from Rust (already a delegated cap)
2. Python creates a sub-identity
3. Python delegates to sub-identity (with attenuation)
4. Sub-identity uses delegated cap to make request
5. Verify Rust accepts/rejects the chain

This tests the full spec section 6.4 compliance.

Usage:
    # Start Rust peer first:
    cargo run -p entity-cli -- peer start test-peer -l 127.0.0.1:9000

    # Run this script:
    uv run python examples/test_delegation_chain.py
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


def get_ref_hash(ref: Any) -> str | None:
    """Extract hash from a ref."""
    if ref is None:
        return None
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        return ref.get("hash")
    return None


def create_identity_entity(keypair: Keypair) -> dict:
    """Create an identity entity from keypair."""
    identity_data = {
        "peer_id": keypair.peer_id,
        "public_key": base64.b64encode(keypair.public_key_bytes()).decode("ascii"),
        "key_type": "ed25519",
    }
    return {
        "type": "system/peer",
        "data": identity_data,
        "content_hash": compute_content_hash("system/peer", identity_data),
        "refs": {},
    }


def create_signature_entity(keypair: Keypair, target_hash: str) -> dict:
    """Create a signature entity."""
    sig_data = {
        "target": target_hash,
        "algorithm": "ed25519",
        "signature": base64.b64encode(keypair.sign(target_hash.encode("utf-8"))).decode("ascii"),
        "signer": keypair.peer_id,
    }
    return {
        "type": "system/signature",
        "data": sig_data,
        "content_hash": compute_content_hash("system/signature", sig_data),
        "refs": {},
    }


def create_delegated_capability(
    granter_keypair: Keypair,
    grantee_identity: dict,
    parent_capability_hash: str,
    resources: list[str],
    operations: list[str],
    expires_at: int | None = None,
    caveats: list[dict] | None = None,
    debug: bool = False,
) -> tuple[dict, dict, dict]:
    """
    Create a delegated capability.

    Returns: (capability_entity, granter_identity, signature_entity)
    """
    granter_identity = create_identity_entity(granter_keypair)
    granter_hash = granter_identity["content_hash"]
    grantee_hash = grantee_identity["content_hash"]

    # Build capability data - granter/grantee in data for content_hash security
    cap_data = {
        "grants": [{
            "resources": resources,
            "operations": operations,
        }],
        "granter": granter_hash,  # In data for content_hash
        "grantee": grantee_hash,  # In data for content_hash
    }
    if expires_at:
        cap_data["expires_at"] = expires_at
    if caveats:
        cap_data["caveats"] = caveats

    # Compute hash for signing (before adding refs)
    # Per spec: Hash = SHA256(ECF({type, data}))
    cap_hash = compute_content_hash("system/capability/token", cap_data)

    if debug:
        print(f"    DEBUG: Cap data: {json.dumps(cap_data, sort_keys=True)}")
        print(f"    DEBUG: Cap hash: {cap_hash}")
        print(f"    DEBUG: Granter: {granter_keypair.peer_id[:30]}...")

    # Create signature - signs the hash itself
    sig_entity = create_signature_entity(granter_keypair, cap_hash)
    sig_hash = sig_entity["content_hash"]

    if debug:
        print(f"    DEBUG: Signature target: {sig_entity['data']['target']}")
        print(f"    DEBUG: Signature hash: {sig_hash}")

    # Final capability entity with refs
    capability_entity = {
        "type": "system/capability/token",
        "data": cap_data,
        "content_hash": cap_hash,
        "refs": {
            "granter": {"hash": granter_hash},
            "grantee": {"hash": grantee_hash},
            "signature": {"hash": sig_hash},
            "parent": {"hash": parent_capability_hash},
        },
    }

    return capability_entity, granter_identity, sig_entity


async def connect_to_rust(host: str, port: int, identity_name: str = "framework-admin"):
    """Connect to Rust peer, complete handshake, get capability."""
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
    await recv_envelope(reader)

    # Wait for CAPABILITY_GRANT
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

    if not capability_entity:
        raise RuntimeError("No capability grant received")

    return {
        "reader": reader,
        "writer": writer,
        "keypair": keypair,
        "rust_peer_id": rust_peer_id,
        "capability_entity": capability_entity,
        "capability_hash": capability_hash,
        "included": included,
    }


async def execute_with_capability(
    reader,
    writer,
    keypair: Keypair,
    rust_peer_id: str,
    capability_hash: str,
    capability_entity: dict,
    uri: str,
    operation: str,
    params: dict | None = None,
    extra_included: dict | None = None,
    debug: bool = False,
) -> dict | None:
    """Execute a request with a specific capability."""
    params = params or {}
    extra_included = extra_included or {}

    identity_entity = create_identity_entity(keypair)
    identity_hash = identity_entity["content_hash"]

    execute_data = {
        "request_id": str(uuid.uuid4()),
        "uri": uri,
        "operation": operation,
        "params": params,
    }
    execute_hash = compute_content_hash("system/protocol/execute", execute_data)

    sig_entity = create_signature_entity(keypair, execute_hash)
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

    # Build included map
    included = {
        identity_hash: identity_entity,
        sig_hash: sig_entity,
        capability_hash: capability_entity,
    }
    included.update(extra_included)

    if debug:
        print(f"\n    DEBUG: Full envelope included ({len(included)} entities):")
        for h, e in included.items():
            print(f"      {h[:50]}... -> {e['type']}")
        print(f"\n    DEBUG: Capability being used: {capability_hash[:50]}...")
        cap_refs = capability_entity.get("refs", {})
        print(f"      refs.granter: {get_ref_hash(cap_refs.get('granter'))[:50] if cap_refs.get('granter') else 'none'}...")
        print(f"      refs.signature: {get_ref_hash(cap_refs.get('signature'))[:50] if cap_refs.get('signature') else 'none'}...")
        print(f"      refs.parent: {get_ref_hash(cap_refs.get('parent'))[:50] if cap_refs.get('parent') else 'none'}...")

        # Check if all refs are in included
        granter_hash = get_ref_hash(cap_refs.get("granter"))
        sig_hash_cap = get_ref_hash(cap_refs.get("signature"))
        parent_hash = get_ref_hash(cap_refs.get("parent"))
        print(f"\n    DEBUG: Checking if refs are in included:")
        print(f"      granter in included: {granter_hash in included if granter_hash else 'N/A'}")
        print(f"      signature in included: {sig_hash_cap in included if sig_hash_cap else 'N/A'}")
        print(f"      parent in included: {parent_hash in included if parent_hash else 'N/A'}")

    envelope = {"root": execute_entity, "included": included}
    await send_envelope(writer, envelope)
    return await recv_envelope(reader)


async def main():
    """Run full delegation chain test."""
    print("=" * 70)
    print("Full Delegation Chain Validation Test")
    print("=" * 70)

    # Step 1: Connect to Rust and get our capability
    print("\n[1] Connecting to Rust peer...")
    session = await connect_to_rust("127.0.0.1", 9000)
    print(f"    Connected: {session['rust_peer_id'][:30]}...")
    print(f"    Got capability: {session['capability_hash'][:40]}...")

    parent_cap_hash = get_ref_hash(session["capability_entity"].get("refs", {}).get("parent"))
    print(f"    Our cap is already delegated (parent: {parent_cap_hash[:40] if parent_cap_hash else 'none'}...)")

    # Step 2: Test that our original capability works
    print("\n[2] Testing original capability works...")
    response = await execute_with_capability(
        session["reader"],
        session["writer"],
        session["keypair"],
        session["rust_peer_id"],
        session["capability_hash"],
        session["capability_entity"],
        f"entity://{session['rust_peer_id']}/system/status",
        "read",
    )
    if response:
        status = response["root"]["data"].get("status")
        print(f"    Status: {status} {'OK' if status == 200 else 'FAILED'}")

    # Step 3: Create a sub-identity (simulating delegating to another peer)
    print("\n[3] Creating sub-identity for delegation test...")
    sub_keypair = Keypair.generate()
    sub_identity = create_identity_entity(sub_keypair)
    print(f"    Sub-peer ID: {sub_keypair.peer_id[:30]}...")

    # Step 4: Examine Rust's capability and identity format
    print("\n[4] Analyzing Rust's capability and identity format...")
    rust_cap = session["capability_entity"]
    rust_cap_refs = rust_cap.get("refs", {})
    rust_sig_hash = get_ref_hash(rust_cap_refs.get("signature"))
    rust_sig_entity = session["included"].get(rust_sig_hash)
    if rust_sig_entity:
        print(f"    Rust sig target: {rust_sig_entity['data'].get('target')}")
        print(f"    Rust cap content_hash: {rust_cap.get('content_hash')}")
        if rust_sig_entity['data'].get('target') == rust_cap.get('content_hash'):
            print("    Rust signs the capability's content_hash directly")

    # Check our identity as it appears in the grant (we are the grantee)
    rust_grantee_hash = get_ref_hash(rust_cap_refs.get("grantee"))
    rust_grantee_identity = session["included"].get(rust_grantee_hash)
    print(f"\n    Rust's view of our identity (grantee of received cap):")
    print(f"    Hash: {rust_grantee_hash}")
    if rust_grantee_identity:
        print(f"    Data: {json.dumps(rust_grantee_identity['data'], sort_keys=True)}")

    # Now compare with what WE compute for our identity
    our_identity = create_identity_entity(session["keypair"])
    print(f"\n    Our computed identity:")
    print(f"    Hash: {our_identity['content_hash']}")
    print(f"    Data: {json.dumps(our_identity['data'], sort_keys=True)}")

    if rust_grantee_hash == our_identity["content_hash"]:
        print("\n    Identity hashes MATCH!")
    else:
        print("\n    WARNING: Identity hashes MISMATCH!")
        print("    This means we compute identity differently than Rust")

    # Step 5: Delegate our capability to the sub-identity
    print("\n[5] Creating delegated capability for sub-peer...")

    # Get our identity for the delegation
    our_identity = create_identity_entity(session["keypair"])

    # Create attenuated capability (narrower scope)
    delegated_cap, granter_identity, cap_signature = create_delegated_capability(
        granter_keypair=session["keypair"],
        grantee_identity=sub_identity,
        parent_capability_hash=session["capability_hash"],
        resources=["entity://*/system/*"],  # Narrower: only system paths
        operations=["read"],  # Narrower: only read
        expires_at=int(time.time() * 1000) + 60000,  # 1 minute
        debug=True,
    )
    delegated_cap_hash = delegated_cap["content_hash"]
    print(f"    Delegated cap: {delegated_cap_hash[:40]}...")
    print(f"    Resources: {delegated_cap['data']['grants'][0]['resources']}")
    print(f"    Operations: {delegated_cap['data']['grants'][0]['operations']}")

    # Step 6: Try to use the delegated capability
    print("\n[6] Testing delegated capability (sub-peer making request)...")

    # The included entities need:
    # - Sub-peer's identity (the author)
    # - Delegated capability
    # - Signature for the capability
    # - Granter's identity (to verify cap signature)
    # - Original capability (the parent)
    # - Original capability's supporting entities

    extra_included = {
        granter_identity["content_hash"]: granter_identity,  # Our identity (granter of delegated cap)
        cap_signature["content_hash"]: cap_signature,  # Signature on delegated cap
        session["capability_hash"]: session["capability_entity"],  # Parent cap
    }
    # Also include the supporting entities from the original capability grant
    extra_included.update(session["included"])

    print(f"    Including {len(extra_included)} extra entities:")
    for h, e in extra_included.items():
        print(f"      {h[:40]}... -> {e['type']}")

    # Check: is our granter identity hash what we put in the delegated cap refs?
    delegated_granter = get_ref_hash(delegated_cap["refs"].get("granter"))
    print(f"    Delegated cap refs.granter: {delegated_granter[:40]}...")
    print(f"    Granter identity hash: {granter_identity['content_hash'][:40]}...")
    if delegated_granter != granter_identity["content_hash"]:
        print("    WARNING: Granter hash mismatch!")

    # Verify our own signature locally
    print("\n    Verifying our cap signature locally...")
    from entity_core.crypto.signing import verify_signature, public_key_from_bytes
    our_pub_key = session["keypair"].public_key_bytes()
    sig_target = cap_signature["data"]["target"]
    sig_bytes = base64.b64decode(cap_signature["data"]["signature"])
    pub_key = public_key_from_bytes(our_pub_key)
    try:
        is_valid = verify_signature(pub_key, sig_target.encode("utf-8"), sig_bytes)
        print(f"    Local signature verification: {'VALID' if is_valid else 'INVALID'}")
    except Exception as e:
        print(f"    Local signature verification error: {e}")

    # Print detailed signature info
    print(f"\n    Signature details for debugging:")
    print(f"    - Target (message to verify): {sig_target}")
    print(f"    - Target bytes (hex): {sig_target.encode('utf-8').hex()}")
    print(f"    - Signature (b64): {cap_signature['data']['signature'][:50]}...")
    print(f"    - Public key (b64): {base64.b64encode(our_pub_key).decode()}")
    print(f"    - Signer peer_id: {cap_signature['data']['signer']}")

    # Also print what Rust's capability signature looks like for comparison
    rust_sig = session["included"].get(get_ref_hash(session["capability_entity"]["refs"]["signature"]))
    if rust_sig:
        print(f"\n    Rust's signature format for comparison:")
        print(f"    - Target: {rust_sig['data']['target']}")
        print(f"    - Signature (b64): {rust_sig['data']['signature'][:50]}...")
        print(f"    - Signer: {rust_sig['data']['signer']}")

    response = await execute_with_capability(
        session["reader"],
        session["writer"],
        sub_keypair,  # Sub-peer is making the request
        session["rust_peer_id"],
        delegated_cap_hash,
        delegated_cap,
        f"entity://{session['rust_peer_id']}/system/status",
        "read",
        extra_included=extra_included,
        debug=True,
    )

    if response:
        status = response["root"]["data"].get("status")
        result = response["root"]["data"]
        print(f"    Status: {status}")
        if status == 200:
            print("    SUCCESS: Rust accepted the delegation chain!")
        elif status == 403:
            print("    REJECTED: Rust denied the delegation")
            print(f"    Reason: {result}")
        else:
            print(f"    Response: {json.dumps(result, indent=2)[:200]}")

    # Step 7: Test with incorrect attenuation (should fail)
    print("\n[7] Testing INVALID delegation (broader than parent - should fail)...")

    invalid_cap, _, invalid_sig = create_delegated_capability(
        granter_keypair=session["keypair"],
        grantee_identity=sub_identity,
        parent_capability_hash=session["capability_hash"],
        resources=["*"],  # Same as parent - should be OK
        operations=["read", "write", "delete", "admin"],  # Broader? Depends on parent
        expires_at=int(time.time() * 1000) + 3600000,  # 1 hour (might exceed parent)
    )
    invalid_cap_hash = invalid_cap["content_hash"]

    extra_invalid = {
        granter_identity["content_hash"]: granter_identity,
        invalid_sig["content_hash"]: invalid_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra_invalid.update(session["included"])

    response = await execute_with_capability(
        session["reader"],
        session["writer"],
        sub_keypair,
        session["rust_peer_id"],
        invalid_cap_hash,
        invalid_cap,
        f"entity://{session['rust_peer_id']}/system/status",
        "read",
        extra_included=extra_invalid,
    )

    if response:
        status = response["root"]["data"].get("status")
        print(f"    Status: {status}")
        if status == 403:
            print("    CORRECTLY REJECTED: Rust detected invalid delegation")
        elif status == 200:
            print("    WARNING: Rust accepted potentially invalid delegation")
            print("    (Parent might have wildcard operations, so this could be valid)")

    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print("""
This test validates:
1. Basic capability from Rust works
2. Creating delegated capabilities on Python side
3. Rust's ability to validate delegation chains

Key observations will help determine if Rust fully implements spec 6.4.
""")

    # Cleanup
    session["writer"].close()
    await session["writer"].wait_closed()
    print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
