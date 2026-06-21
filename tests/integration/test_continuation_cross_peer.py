"""Cross-peer continuation dispatch consumer (EXTENSION-CONTINUATION
§4.2 case 3 / §4.3, v1.11 three-slot model).

These guard the Python consumer change behind the continuation v1.9
G2-dispatch-grantee conformance recipe:

  step 2 — the cross-peer dispatch is authorized by the scoped
           `dispatch_capability`, signed by the dispatching host peer
           (EXECUTE author = host peer), NOT a silent fallback to the
           broad connection/session cap (V7 §6.8);
  step 3 — the full authority chain (leaf → B-recognized root) travels
           in the dispatched envelope `included` (§4.3).

Real two-peer wire (no mocked dispatcher) so the dispatch *side effect*
is the oracle — the lesson from the v1.9 mocked-dispatcher tests. The
cross-impl verdict is the Go `convergence/c3_*` proof gate; this is the
deterministic in-repo regression guard for the same mechanics.
"""

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import normalize_hash


@pytest.fixture
async def peer_b():
    """Target peer B — confers a B-rooted connection cap at connect and
    enforces capability scope at dispatch."""
    kp = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(kp)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    await peer.start("127.0.0.1", 19077)
    yield peer
    await peer.stop()


def _scoped_dispatch_cap(kp_a, parent_hash, *, handler, operation, resource):
    """Mint the §4.2 case 3 dispatch_capability by hand: B-rooted
    (parent = the B-conferred connection cap), installer in-chain as the
    leaf granter, **granted to the dispatching host peer A** (grantee =
    A's identity = the EXECUTE author). The handle the Go validator's
    `CreateChainedCapGrantedTo` produces — built locally here since
    Python's C-3 mint helper is not yet exposed."""
    a_id = create_identity_entity(kp_a)
    a_id_hash = a_id.compute_hash()
    scoped = Entity(
        type="system/capability/token",
        data={
            "grants": [{
                "handlers": {"include": [handler]},
                "resources": {"include": [resource]},
                "operations": {"include": [operation]},
            }],
            "granter": a_id_hash,           # installer in-chain (leaf granter)
            "grantee": a_id_hash,           # host peer A == EXECUTE author
            "parent": normalize_hash(parent_hash),  # B-rooted
            "created_at": 0,
        },
    )
    scoped_sig = create_signature_entity(
        kp_a, scoped.compute_hash(), a_id_hash
    )
    return scoped, scoped_sig, a_id


@pytest.mark.asyncio
async def test_cross_peer_dispatch_uses_scoped_cap_and_bundles_chain(peer_b):
    """Positive control + wire shape: the dispatched EXECUTE is authored
    by host peer A, authorized by the scoped dispatch_capability (not the
    connection cap), and the full chain travels in `included`."""
    kp_a = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19077, kp_a)
    try:
        assert conn.capability is not None
        parent_hash = conn.capability["content_hash"]
        # V7 §PR-8: a host (A) minting a cross-peer dispatch cap for B's
        # namespace MUST name B explicitly — a peer-relative resource now
        # canonicalizes against the *granter* (A), not the verifier (B). The
        # entity-URI form (matching the request URI) is the correct cross-peer
        # expression; the bare peer-relative form previously worked only
        # because of the (now-fixed) verifier-frame canonicalization bug.
        in_scope = f"entity://{peer_b.peer_id}/system/validate/c3-inscope"
        scoped, scoped_sig, a_id = _scoped_dispatch_cap(
            kp_a, parent_hash,
            handler="system/inbox", operation="receive", resource=in_scope,
        )
        # §4.3 bundle: leaf cap + its signature + host identity + the
        # B-rooted parent cap and its chain (B's sig + B identity).
        bundle = [
            scoped.to_dict(), scoped_sig.to_dict(), a_id.to_dict(),
            conn.capability, *(conn.capability_chain or []),
        ]

        # Capture what B ingests off the wire.
        captured = []
        orig = peer_b._store_included_entities

        def _spy(env):
            captured.append(env)
            return orig(env)

        peer_b._store_included_entities = _spy

        resp = await conn.execute(
            uri=f"entity://{peer_b.peer_id}/system/inbox",
            operation="receive",
            params={
                "type": "system/protocol/inbox/delivery",
                "data": {"original_request_id": "c3", "status": 200,
                         "result": {"probe": "x"}},
            },
            resource={"targets": [in_scope]},
            capability_override=scoped.to_dict(),
            capability_chain_override=bundle,
        )

        # Step 2: authorized strictly by the scoped cap (in-scope lands).
        assert resp.status == 200, resp.result

        # Find the EXECUTE envelope B ingested (not the connect frames).
        exec_envs = [
            e for e in captured
            if e.root.get("type") == "system/protocol/execute"
        ]
        assert exec_envs, "no EXECUTE envelope captured at B"
        ex = exec_envs[-1].root["data"]
        # Authored by host peer A (so B's grantee==author check passes).
        assert normalize_hash(ex["author"]) == a_id.compute_hash()
        # Authorized by the SCOPED cap — NOT the broad connection cap.
        assert normalize_hash(ex["capability"]) == scoped.compute_hash()
        assert normalize_hash(ex["capability"]) != normalize_hash(parent_hash)
        # Step 3: the full chain is bundled in `included`.
        inc = {normalize_hash(d.get("content_hash"))
               for d in exec_envs[-1].included if d.get("content_hash")}
        assert scoped.compute_hash() in inc
        assert normalize_hash(parent_hash) in inc
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_out_of_scope_denied_no_silent_escalation(peer_b):
    """Negative control (V7 §6.8): an out-of-scope dispatch under the
    scoped cap is DENIED — it must NOT silently ride the broad connection
    cap. Sanity: the same op with no override (connection cap = `*` in
    debug) succeeds, proving the override genuinely bounds authority."""
    kp_a = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19077, kp_a)
    try:
        parent_hash = conn.capability["content_hash"]
        # V7 §PR-8: a host (A) minting a cross-peer dispatch cap for B's
        # namespace MUST name B explicitly — a peer-relative resource now
        # canonicalizes against the *granter* (A), not the verifier (B). The
        # entity-URI form (matching the request URI) is the correct cross-peer
        # expression; the bare peer-relative form previously worked only
        # because of the (now-fixed) verifier-frame canonicalization bug.
        in_scope = f"entity://{peer_b.peer_id}/system/validate/c3-inscope"
        out_scope = "system/validate/c3-escalate"
        scoped, scoped_sig, a_id = _scoped_dispatch_cap(
            kp_a, parent_hash,
            handler="system/inbox", operation="receive", resource=in_scope,
        )
        bundle = [
            scoped.to_dict(), scoped_sig.to_dict(), a_id.to_dict(),
            conn.capability, *(conn.capability_chain or []),
        ]
        params = {
            "type": "system/protocol/inbox/delivery",
            "data": {"original_request_id": "c3", "status": 200,
                     "result": {"probe": "x"}},
        }

        # Out-of-scope under the scoped override → denied.
        denied = await conn.execute(
            uri=f"entity://{peer_b.peer_id}/system/inbox",
            operation="receive",
            params=params,
            resource={"targets": [out_scope]},
            capability_override=scoped.to_dict(),
            capability_chain_override=bundle,
        )
        assert denied.status == 403, (
            f"out-of-scope dispatch was not denied (status {denied.status}) "
            "— silent escalation to ambient/connection authority"
        )

        # Sanity: same out-of-scope op with NO override rides the broad
        # connection cap and is allowed — so 403 above is the scoped cap
        # binding authority, not an unrelated failure.
        allowed = await conn.execute(
            uri=f"entity://{peer_b.peer_id}/system/inbox",
            operation="receive",
            params=params,
            resource={"targets": [out_scope]},
        )
        assert allowed.status == 200, allowed.result
    finally:
        conn.close()
        await conn.wait_closed()
