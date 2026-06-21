"""V7 v7.71 §3.3 authorization error-code contract — verdict-to-status pins.

The §5.2 verify_request DENY discriminator splits along a single line
(v7.71 §A4-AUTHZ):

  - step-1/step-2 (content hash + signature/author/identity resolution —
    the wire-side authentication half) → ``error_code="authentication_failed"``
    which the dispatcher maps to **401** (Class B-Common).
  - leaf-cap grantee that does not resolve → ``error_code="unresolvable_grantee"``
    → **401** (PR-3 single 401 carve-out; Class B-Python-1). This MUST win
    over the 403 grantee/author-mismatch verdict — an unresolvable grantee
    is not the same as a resolvable-but-wrong one.
  - revoked cap (the verifier KNOWS) → ``error_code="revoked"`` → the
    dispatcher emits **403 capability_revoked** (Class C / RULING-CLASS-C).
  - everything else (authorization domain) → 403 capability_denied default.

These pins assert at the ``verify_request_integrity`` layer (where the
error_code is decided); the dispatcher status mapping is covered by the
connection-level test in test_authenticated.py.
"""

from __future__ import annotations

import copy

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import (
    create_authenticated_request,
    create_identity_entity,
    verify_request_integrity,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.messages import Execute

from entity_handlers.capability import (
    CAPABILITY_HANDLER_PATTERN,
    capability_handler,
)


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _full_access_cap() -> dict[str, object]:
    return {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*", "/*/*"]},
            "operations": {"include": ["*"]},
            "peers": {"include": ["*"]},
        }]
    }


async def _mint_cap(peer, caller_kp):
    """Mint a peer-rooted cap for caller_kp and persist its chain.

    Returns (cap_dict, chain_entities)."""
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    caller_identity = create_identity_entity(caller_kp)
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=caller_kp.peer_id,
        handler_grant=_full_access_cap(),
        caller_capability=_full_access_cap(),
        emit_pathway=peer.emit_pathway,
        keypair=peer.keypair,
        included={},
        author_identity_hash=caller_identity.compute_hash(),
        remote_identity_hash=caller_identity.compute_hash(),
    )
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, ctx,
    )
    assert mint["status"] == 200, mint
    cap_hash = mint["result"]["data"]["token"]
    cap_dict = mint["envelope_included"][cap_hash]
    chain_entities: list[dict] = []
    for h, ent in mint["envelope_included"].items():
        if h == cap_hash:
            continue
        chain_entities.append(ent)
        peer.content_store.put(Entity.from_dict(ent))
    peer.content_store.put(Entity.from_dict(cap_dict))
    return cap_dict, chain_entities


async def _valid_envelope(peer, caller_kp):
    cap_dict, chain = await _mint_cap(peer, caller_kp)
    execute = Execute.create(
        uri=f"entity://{peer.keypair.peer_id}/app/anything",
        operation="get",
    )
    auth = create_authenticated_request(
        keypair=caller_kp, execute=execute,
        capability_dict=cap_dict, capability_chain=chain,
    )
    return auth.to_envelope()


def _sig_entity_index(envelope) -> int:
    for i, ent in enumerate(envelope.included):
        if ent.get("type") == "system/signature":
            # The execute signature targets the execute root.
            if ent.get("data", {}).get("target") == envelope.root.get("content_hash"):
                return i
    raise AssertionError("execute signature not found in included")


# --- Baseline: the new grantee-resolution check is a no-op for valid requests ---

@pytest.mark.asyncio
async def test_valid_request_still_passes(peer) -> None:
    envelope = await _valid_envelope(peer, peer.keypair)
    result = verify_request_integrity(envelope, local_peer_id=peer.peer_id)
    assert result.valid is True, result.error


# --- Class B-Common: auth-class failures carry authentication_failed (→ 401) ---

@pytest.mark.asyncio
async def test_author_not_in_included_is_authentication_failed(peer) -> None:
    envelope = await _valid_envelope(peer, peer.keypair)
    author_hash = envelope.root["data"]["author"]
    envelope.included = [
        e for e in envelope.included if e.get("content_hash") != author_hash
    ]
    result = verify_request_integrity(envelope, local_peer_id=peer.peer_id)
    assert result.valid is False
    assert result.error_code == "authentication_failed", result.error


@pytest.mark.asyncio
async def test_no_signature_is_authentication_failed(peer) -> None:
    envelope = await _valid_envelope(peer, peer.keypair)
    idx = _sig_entity_index(envelope)
    del envelope.included[idx]
    result = verify_request_integrity(envelope, local_peer_id=peer.peer_id)
    assert result.valid is False
    assert result.error_code == "authentication_failed", result.error


@pytest.mark.asyncio
async def test_tampered_signature_is_authentication_failed(peer) -> None:
    envelope = await _valid_envelope(peer, peer.keypair)
    idx = _sig_entity_index(envelope)
    sig = copy.deepcopy(envelope.included[idx])
    raw = bytearray(sig["data"]["signature"])
    raw[0] ^= 0xFF  # flip a byte → signature no longer verifies
    sig["data"]["signature"] = bytes(raw)
    envelope.included[idx] = sig
    result = verify_request_integrity(envelope, local_peer_id=peer.peer_id)
    assert result.valid is False
    assert result.error_code == "authentication_failed", result.error


# --- Class B-Python-1: unresolvable grantee wins over grantee-mismatch (→ 401) ---

@pytest.mark.asyncio
async def test_unresolvable_grantee_is_401_not_403(peer) -> None:
    """A leaf cap whose grantee resolves to nothing surfaces
    unresolvable_grantee, NOT the generic 403 grantee/author mismatch."""
    cap_dict, chain = await _mint_cap(peer, peer.keypair)

    # Rewrite the cap's grantee to a fresh hash that resolves to nothing
    # (33-byte ECFv1-SHA256 form: 0x00 format byte + non-zero digest).
    bogus_grantee = bytes([0x00]) + bytes((0xC0 ^ i) & 0xFF for i in range(32))
    cap_entity = Entity(type=cap_dict["type"], data=dict(cap_dict["data"]))
    cap_entity.data["grantee"] = bogus_grantee
    new_hash = cap_entity.compute_hash()
    cap_dict2 = cap_entity.to_dict()
    cap_dict2["content_hash"] = new_hash

    execute = Execute.create(
        uri=f"entity://{peer.keypair.peer_id}/app/anything",
        operation="get",
    )
    auth = create_authenticated_request(
        keypair=peer.keypair, execute=execute,
        capability_dict=cap_dict2, capability_chain=chain,
    )
    envelope = auth.to_envelope()
    result = verify_request_integrity(envelope, local_peer_id=peer.peer_id)
    assert result.valid is False
    assert result.error_code == "unresolvable_grantee", result.error
