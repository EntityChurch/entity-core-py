"""EXTENSION-REGISTRY §6a.9 — live registration over the real wire.

The in-process `test_registry.py` vectors put the layer-1 signature straight
into the content store. This test drives the full path instead: a publisher
peer sends a `register-request` over a socket with the signature + identity in
the request envelope's `included`, exercising `_store_included_entities` →
the handler's signature lookup in the content store (the seam the in-process
tests skip). On approval the registry signs + publishes the binding, and a
`resolve` against the registry returns it.
"""

import os
import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext


def _emit(peer, path, entity):
    peer.emit_pathway.emit(path, entity, EmitContext.bootstrap())


@pytest.fixture
async def registry_peer():
    """A live registry: open issuer-policy + a peer-issued resolver-config
    pointing at itself, so it both issues and resolves its own names."""
    keypair = Keypair.generate()
    peer = PeerBuilder().with_keypair(keypair).with_all_handlers().debug_mode(True).build()

    _emit(peer, "system/registry/issuer-policy",
          Entity(type="system/registry/issuer-policy",
                 data={"mode": "open", "allowlist": None,
                       "name_constraints": None, "default_ttl": None}))
    _emit(peer, "system/registry/resolver-config",
          Entity(type="system/registry/resolver-config",
                 data={"resolver_chain": [
                     {"backend_kind": "peer-issued", "backend_id": keypair.peer_id,
                      "priority": 0, "accepted_trust_anchors": ["peer_issued"],
                      "hints": {"endpoint": "http://reef.invalid"}}],
                       "pinned_bindings": [], "name_format_dispatch": []}))
    await peer.start("127.0.0.1", 19050)
    yield peer
    await peer.stop()


def _register_request(publisher_kp, name):
    """Build the request + its layer-1 signature, as wire `included` dicts."""
    data = {
        "name": name,
        "target_peer_id": publisher_kp.peer_id,
        "transports": [],
        "requested_ttl": None,
        "nonce": os.urandom(16),
        "issued_at": int(time.time() * 1000),
    }
    rh = Entity(type="system/registry/register-request", data=data).compute_hash()
    identity = create_identity_entity(publisher_kp)
    sig = create_signature_entity(publisher_kp, rh, identity.compute_hash())
    return data, [identity.to_dict(), sig.to_dict()]


@pytest.mark.asyncio
async def test_live_register_over_wire_then_resolve(registry_peer: Peer):
    publisher_kp = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19050, publisher_kp)
    try:
        data, included = _register_request(publisher_kp, "billslab.com")
        resp = await conn.execute(
            uri=f"entity://{registry_peer.peer_id}/system/registry",
            operation="register-request",
            params={"type": "system/registry/register-request", "data": data},
            included=included,
        )
        assert resp.status == 200, resp.result
        body = resp.result["data"] if "data" in resp.result else resp.result
        assert body["status"] == "registered"

        # The issued name now resolves against the registry (warm-cache precede).
        rresp = await conn.execute(
            uri=f"entity://{registry_peer.peer_id}/system/registry",
            operation="resolve",
            params={"type": "system/registry/resolve-request", "data": {"name": "billslab.com"}},
        )
        assert rresp.status == 200, rresp.result
        rbody = rresp.result["data"] if "data" in rresp.result else rresp.result
        assert rbody["status"] == "resolved"
        assert rbody["peer_id"] == publisher_kp.peer_id
        assert rbody["trust_anchor"] == f"peer_issued:{registry_peer.peer_id}"
    finally:
        conn.close()
        await conn.wait_closed()


@pytest.mark.asyncio
async def test_live_register_wire_proof_failure(registry_peer: Peer):
    """A request whose signature is by a DIFFERENT key than target_peer_id is
    rejected at layer-1, even delivered over the wire."""
    publisher_kp = Keypair.generate()
    attacker_kp = Keypair.generate()
    conn = await Connection.connect("127.0.0.1", 19050, publisher_kp)
    try:
        # Claim publisher's peer-id but sign with the attacker's key.
        data = {
            "name": "spoof.com", "target_peer_id": publisher_kp.peer_id,
            "transports": [], "requested_ttl": None,
            "nonce": os.urandom(16), "issued_at": int(time.time() * 1000),
        }
        rh = Entity(type="system/registry/register-request", data=data).compute_hash()
        attacker_id = create_identity_entity(attacker_kp)
        bad_sig = create_signature_entity(attacker_kp, rh, attacker_id.compute_hash())
        resp = await conn.execute(
            uri=f"entity://{registry_peer.peer_id}/system/registry",
            operation="register-request",
            params={"type": "system/registry/register-request", "data": data},
            included=[attacker_id.to_dict(), bad_sig.to_dict()],
        )
        assert resp.status == 403
        body = resp.result["data"] if "data" in resp.result else resp.result
        assert body["code"] == "proof_failed"
    finally:
        conn.close()
        await conn.wait_closed()
