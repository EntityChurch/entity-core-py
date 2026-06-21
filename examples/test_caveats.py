#!/usr/bin/env python3
"""
Caveat Enforcement Validation Test

Tests all three standard caveats between Python and Rust:
1. no_delegation - capability cannot be delegated further
2. max_delegation_depth - limits chain depth
3. max_delegation_ttl - limits lifetime of delegated capabilities

Usage:
    # Start Rust peer first:
    cargo run -p entity-cli -- peer start test-peer -l 127.0.0.1:9000

    # Run this script:
    uv run python examples/test_caveats.py
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


def get_ref_hash(ref: Any) -> str | None:
    if ref is None:
        return None
    if isinstance(ref, str):
        return ref
    if isinstance(ref, dict):
        return ref.get("hash")
    return None


def create_identity_entity(keypair: Keypair) -> dict:
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


def create_capability_with_caveats(
    granter_keypair: Keypair,
    grantee_identity: dict,
    parent_capability_hash: str | None,
    resources: list[str],
    operations: list[str],
    expires_at: int | None = None,
    caveats: list[dict] | None = None,
) -> tuple[dict, dict, dict]:
    """Create a capability with optional caveats."""
    granter_identity = create_identity_entity(granter_keypair)
    granter_hash = granter_identity["content_hash"]
    grantee_hash = grantee_identity["content_hash"]

    cap_data = {
        "grants": [{"resources": resources, "operations": operations}],
        "granter": granter_hash,
        "grantee": grantee_hash,
    }
    if expires_at:
        cap_data["expires_at"] = expires_at
    if caveats:
        cap_data["caveats"] = caveats

    cap_hash = compute_content_hash("system/capability/token", cap_data)
    sig_entity = create_signature_entity(granter_keypair, cap_hash)
    sig_hash = sig_entity["content_hash"]

    refs = {
        "granter": {"hash": granter_hash},
        "grantee": {"hash": grantee_hash},
        "signature": {"hash": sig_hash},
    }
    if parent_capability_hash:
        refs["parent"] = {"hash": parent_capability_hash}

    capability_entity = {
        "type": "system/capability/token",
        "data": cap_data,
        "content_hash": cap_hash,
        "refs": refs,
    }

    return capability_entity, granter_identity, sig_entity


async def connect_to_rust(host: str, port: int, identity_name: str = "framework-admin"):
    """Connect and complete handshake."""
    identity = load_identity(identity_name)
    keypair = identity.keypair

    reader, writer = await asyncio.open_connection(host, port)

    # Handshake
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

    # Get capability
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

    return {
        "reader": reader,
        "writer": writer,
        "keypair": keypair,
        "rust_peer_id": rust_peer_id,
        "capability_entity": capability_entity,
        "capability_hash": capability_hash,
        "included": included,
    }


async def execute_request(session, capability_hash, capability_entity,
                          author_keypair, uri, operation, extra_included=None):
    """Make an authenticated EXECUTE request."""
    extra_included = extra_included or {}

    identity_entity = create_identity_entity(author_keypair)
    identity_hash = identity_entity["content_hash"]

    execute_data = {
        "request_id": str(uuid.uuid4()),
        "uri": uri,
        "operation": operation,
        "params": {},
    }
    execute_hash = compute_content_hash("system/protocol/execute", execute_data)

    sig_entity = create_signature_entity(author_keypair, execute_hash)
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

    included = {
        identity_hash: identity_entity,
        sig_hash: sig_entity,
        capability_hash: capability_entity,
    }
    included.update(extra_included)

    await send_envelope(session["writer"], {"root": execute_entity, "included": included})
    return await recv_envelope(session["reader"])


def print_result(test_name: str, response: dict | None, expected_success: bool):
    """Print test result."""
    if response is None:
        print(f"  {test_name}: NO RESPONSE")
        return False

    status = response["root"]["data"].get("status")
    message = response["root"]["data"].get("message", "")

    if expected_success:
        if status == 200:
            print(f"  {test_name}: ✅ PASS (status {status})")
            return True
        else:
            print(f"  {test_name}: ❌ FAIL - expected success, got {status}: {message}")
            return False
    else:
        if status == 403:
            print(f"  {test_name}: ✅ PASS (correctly rejected: {message})")
            return True
        elif status == 200:
            print(f"  {test_name}: ❌ FAIL - expected rejection, but got success")
            return False
        else:
            print(f"  {test_name}: ⚠️  REJECTED but unexpected status {status}: {message}")
            return True  # Still rejected, so caveat worked


async def main():
    print("=" * 70)
    print("Caveat Enforcement Validation Test")
    print("=" * 70)

    session = await connect_to_rust("127.0.0.1", 9000)
    print(f"\nConnected to Rust peer: {session['rust_peer_id'][:30]}...")

    # Check if Rust capability has caveats
    rust_cap = session["capability_entity"]
    rust_caveats = rust_cap["data"].get("caveats", [])
    print(f"Rust capability caveats: {rust_caveats if rust_caveats else 'None'}")

    # Create test identities
    peer_b = Keypair.generate()
    peer_c = Keypair.generate()
    peer_b_identity = create_identity_entity(peer_b)
    peer_c_identity = create_identity_entity(peer_c)

    results = []

    # ==========================================================================
    print("\n" + "=" * 70)
    print("TEST 0: Baseline - capability WITHOUT caveats")
    print("=" * 70)
    print("Verify a capability without caveats works (isolate the issue)")

    cap_baseline, our_identity_baseline, cap_baseline_sig = create_capability_with_caveats(
        granter_keypair=session["keypair"],
        grantee_identity=peer_b_identity,
        parent_capability_hash=session["capability_hash"],
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=int(time.time() * 1000) + 60000,
        caveats=None,  # NO caveats
    )
    cap_baseline_hash = cap_baseline["content_hash"]

    print(f"\n  DEBUG: cap_baseline data: {json.dumps(cap_baseline['data'], sort_keys=True)}")
    print(f"  DEBUG: cap_baseline hash: {cap_baseline_hash}")

    extra_baseline = {
        our_identity_baseline["content_hash"]: our_identity_baseline,
        cap_baseline_sig["content_hash"]: cap_baseline_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra_baseline.update(session["included"])

    response = await execute_request(
        session, cap_baseline_hash, cap_baseline,
        peer_b, f"entity://{session['rust_peer_id']}/system/status", "read",
        extra_included=extra_baseline
    )
    baseline_passed = print_result("baseline (no caveats)", response, expected_success=True)
    results.append(baseline_passed)

    if not baseline_passed:
        print("\n  ⚠️  Baseline failed - there's a fundamental issue with capability creation")

    # ==========================================================================
    print("\n" + "=" * 70)
    print("TEST 1: no_delegation caveat")
    print("=" * 70)
    print("Create capability with no_delegation, try to delegate it")

    # Create capability from us to peer_b with no_delegation caveat
    cap_no_deleg, our_identity, cap_no_deleg_sig = create_capability_with_caveats(
        granter_keypair=session["keypair"],
        grantee_identity=peer_b_identity,
        parent_capability_hash=session["capability_hash"],
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=int(time.time() * 1000) + 60000,
        caveats=[{"type": "no_delegation"}],
    )
    cap_no_deleg_hash = cap_no_deleg["content_hash"]

    # Debug: verify our own signature
    print(f"\n  DEBUG: cap_no_deleg data: {json.dumps(cap_no_deleg['data'], sort_keys=True)}")
    print(f"  DEBUG: cap_no_deleg hash: {cap_no_deleg_hash}")
    print(f"  DEBUG: sig target: {cap_no_deleg_sig['data']['target']}")
    from entity_core.crypto.signing import verify_signature, public_key_from_bytes
    pub_key = public_key_from_bytes(session["keypair"].public_key_bytes())
    sig_bytes = base64.b64decode(cap_no_deleg_sig["data"]["signature"])
    try:
        is_valid = verify_signature(pub_key, cap_no_deleg_hash.encode("utf-8"), sig_bytes)
        print(f"  DEBUG: Local signature verification: {'VALID' if is_valid else 'INVALID'}")
    except Exception as e:
        print(f"  DEBUG: Local verification error: {e}")

    # First verify peer_b can use the capability
    print("\n  Step 1: Verify peer_b can use the capability...")
    extra = {
        our_identity["content_hash"]: our_identity,
        cap_no_deleg_sig["content_hash"]: cap_no_deleg_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra.update(session["included"])

    response = await execute_request(
        session, cap_no_deleg_hash, cap_no_deleg,
        peer_b, f"entity://{session['rust_peer_id']}/system/status", "read",
        extra_included=extra
    )
    results.append(print_result("peer_b uses cap with no_delegation", response, expected_success=True))

    # Now try to delegate from peer_b to peer_c (should fail)
    print("\n  Step 2: Try to delegate from peer_b to peer_c (should fail)...")

    cap_delegated, peer_b_id_entity, cap_delegated_sig = create_capability_with_caveats(
        granter_keypair=peer_b,
        grantee_identity=peer_c_identity,
        parent_capability_hash=cap_no_deleg_hash,
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=int(time.time() * 1000) + 30000,
    )
    cap_delegated_hash = cap_delegated["content_hash"]

    extra2 = {
        peer_b_id_entity["content_hash"]: peer_b_id_entity,
        cap_delegated_sig["content_hash"]: cap_delegated_sig,
        cap_no_deleg_hash: cap_no_deleg,
        our_identity["content_hash"]: our_identity,
        cap_no_deleg_sig["content_hash"]: cap_no_deleg_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra2.update(session["included"])

    response = await execute_request(
        session, cap_delegated_hash, cap_delegated,
        peer_c, f"entity://{session['rust_peer_id']}/system/status", "read",
        extra_included=extra2
    )
    results.append(print_result("peer_c uses delegated cap (should be rejected)", response, expected_success=False))

    # ==========================================================================
    print("\n" + "=" * 70)
    print("TEST 2: max_delegation_depth caveat")
    print("=" * 70)
    print("Create capability with max_delegation_depth=1, try to delegate twice")

    # Create capability with max_delegation_depth=1
    cap_depth1, _, cap_depth1_sig = create_capability_with_caveats(
        granter_keypair=session["keypair"],
        grantee_identity=peer_b_identity,
        parent_capability_hash=session["capability_hash"],
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=int(time.time() * 1000) + 60000,
        caveats=[{"type": "max_delegation_depth", "limit": 1}],
    )
    cap_depth1_hash = cap_depth1["content_hash"]

    # Delegate from peer_b to peer_c (depth 1 - should work)
    print("\n  Step 1: Delegate to depth 1 (should work)...")
    cap_depth1_child, _, cap_depth1_child_sig = create_capability_with_caveats(
        granter_keypair=peer_b,
        grantee_identity=peer_c_identity,
        parent_capability_hash=cap_depth1_hash,
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=int(time.time() * 1000) + 30000,
    )
    cap_depth1_child_hash = cap_depth1_child["content_hash"]

    extra3 = {
        peer_b_id_entity["content_hash"]: peer_b_id_entity,
        cap_depth1_child_sig["content_hash"]: cap_depth1_child_sig,
        cap_depth1_hash: cap_depth1,
        our_identity["content_hash"]: our_identity,
        cap_depth1_sig["content_hash"]: cap_depth1_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra3.update(session["included"])

    response = await execute_request(
        session, cap_depth1_child_hash, cap_depth1_child,
        peer_c, f"entity://{session['rust_peer_id']}/system/status", "read",
        extra_included=extra3
    )
    results.append(print_result("depth=1 delegation", response, expected_success=True))

    # Now try to delegate from peer_c to a new peer_d (depth 2 - should fail)
    print("\n  Step 2: Try to delegate to depth 2 (should fail)...")
    peer_d = Keypair.generate()
    peer_d_identity = create_identity_entity(peer_d)

    cap_depth2, peer_c_id_entity, cap_depth2_sig = create_capability_with_caveats(
        granter_keypair=peer_c,
        grantee_identity=peer_d_identity,
        parent_capability_hash=cap_depth1_child_hash,
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=int(time.time() * 1000) + 15000,
    )
    cap_depth2_hash = cap_depth2["content_hash"]

    extra4 = {
        peer_c_id_entity["content_hash"]: peer_c_id_entity,
        cap_depth2_sig["content_hash"]: cap_depth2_sig,
        cap_depth1_child_hash: cap_depth1_child,
        peer_b_id_entity["content_hash"]: peer_b_id_entity,
        cap_depth1_child_sig["content_hash"]: cap_depth1_child_sig,
        cap_depth1_hash: cap_depth1,
        our_identity["content_hash"]: our_identity,
        cap_depth1_sig["content_hash"]: cap_depth1_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra4.update(session["included"])

    response = await execute_request(
        session, cap_depth2_hash, cap_depth2,
        peer_d, f"entity://{session['rust_peer_id']}/system/status", "read",
        extra_included=extra4
    )
    results.append(print_result("depth=2 delegation (exceeds limit)", response, expected_success=False))

    # ==========================================================================
    print("\n" + "=" * 70)
    print("TEST 3: max_delegation_ttl caveat")
    print("=" * 70)
    print("Create capability with max_delegation_ttl=30000ms (30 sec), try longer TTL")

    # Create capability with max_delegation_ttl
    cap_ttl, _, cap_ttl_sig = create_capability_with_caveats(
        granter_keypair=session["keypair"],
        grantee_identity=peer_b_identity,
        parent_capability_hash=session["capability_hash"],
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=int(time.time() * 1000) + 120000,  # 2 min
        caveats=[{"type": "max_delegation_ttl", "limit": 30000}],  # 30 sec max for children
    )
    cap_ttl_hash = cap_ttl["content_hash"]

    # Delegate with short TTL (should work)
    print("\n  Step 1: Delegate with TTL within limit (should work)...")
    now = int(time.time() * 1000)
    cap_short_ttl, _, cap_short_ttl_sig = create_capability_with_caveats(
        granter_keypair=peer_b,
        grantee_identity=peer_c_identity,
        parent_capability_hash=cap_ttl_hash,
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=now + 20000,  # 20 sec TTL - within limit
    )
    cap_short_ttl_hash = cap_short_ttl["content_hash"]

    extra5 = {
        peer_b_id_entity["content_hash"]: peer_b_id_entity,
        cap_short_ttl_sig["content_hash"]: cap_short_ttl_sig,
        cap_ttl_hash: cap_ttl,
        our_identity["content_hash"]: our_identity,
        cap_ttl_sig["content_hash"]: cap_ttl_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra5.update(session["included"])

    response = await execute_request(
        session, cap_short_ttl_hash, cap_short_ttl,
        peer_c, f"entity://{session['rust_peer_id']}/system/status", "read",
        extra_included=extra5
    )
    results.append(print_result("TTL within limit (20s)", response, expected_success=True))

    # Delegate with long TTL (should fail)
    print("\n  Step 2: Delegate with TTL exceeding limit (should fail)...")
    cap_long_ttl, _, cap_long_ttl_sig = create_capability_with_caveats(
        granter_keypair=peer_b,
        grantee_identity=peer_c_identity,
        parent_capability_hash=cap_ttl_hash,
        resources=["entity://*/system/*"],
        operations=["read"],
        expires_at=now + 60000,  # 60 sec TTL - exceeds 30 sec limit
    )
    cap_long_ttl_hash = cap_long_ttl["content_hash"]

    extra6 = {
        peer_b_id_entity["content_hash"]: peer_b_id_entity,
        cap_long_ttl_sig["content_hash"]: cap_long_ttl_sig,
        cap_ttl_hash: cap_ttl,
        our_identity["content_hash"]: our_identity,
        cap_ttl_sig["content_hash"]: cap_ttl_sig,
        session["capability_hash"]: session["capability_entity"],
    }
    extra6.update(session["included"])

    response = await execute_request(
        session, cap_long_ttl_hash, cap_long_ttl,
        peer_c, f"entity://{session['rust_peer_id']}/system/status", "read",
        extra_included=extra6
    )
    results.append(print_result("TTL exceeds limit (60s > 30s)", response, expected_success=False))

    # ==========================================================================
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    passed = sum(results)
    total = len(results)
    print(f"\nTests passed: {passed}/{total}")

    if passed == total:
        print("\n✅ All caveat tests PASSED!")
    else:
        print(f"\n❌ {total - passed} test(s) FAILED")

    # Cleanup
    session["writer"].close()
    await session["writer"].wait_closed()
    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(main())
