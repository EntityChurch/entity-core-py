"""F2 (V7 §5.2 v7.63): ``verify_request_integrity`` MUST invoke
``is_revoked`` when ``revocation_ctx.supports_revocation`` is true.

The marker mechanism is the only path that catches wire-only cap
revocation; an impl that writes the marker on ``revoke`` but does not
read it in ``verify_request`` silently fails open on wire-only caps.
This file pins the wire-in.
"""

from __future__ import annotations

import pytest

from entity_core.capability.revocation import (
    DefaultRevocationContext,
    REVOCATIONS_ROOT,
)
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import (
    create_authenticated_request,
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


async def _mint_and_authenticate(peer, caller_kp):
    """Mint a peer-rooted cap for caller_kp, then build an authenticated
    EXECUTE envelope using that cap. Returns (envelope, cap_hash)."""
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    from entity_core.protocol.auth import create_identity_entity
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
    # Persist the cap chain so verify_capability_chain can walk it (root cap +
    # its signature + granter identity all need to be reachable).
    chain_entities: list[dict] = []
    for h, ent in mint["envelope_included"].items():
        if h == cap_hash:
            continue
        chain_entities.append(ent)
        peer.content_store.put(Entity.from_dict(ent))
    peer.content_store.put(Entity.from_dict(cap_dict))

    execute = Execute.create(
        uri=f"entity://{peer.keypair.peer_id}/app/anything",
        operation="get",
    )
    auth = create_authenticated_request(
        keypair=caller_kp,
        execute=execute,
        capability_dict=cap_dict,
        capability_chain=chain_entities,
    )
    envelope = auth.to_envelope()
    return envelope, cap_hash


@pytest.mark.asyncio
async def test_verify_request_passes_without_revocation_ctx(peer) -> None:
    """Sanity baseline: with no revocation_ctx, verify still passes."""
    envelope, _ = await _mint_and_authenticate(peer, peer.keypair)
    result = verify_request_integrity(
        envelope, local_peer_id=peer.peer_id, revocation_ctx=None,
    )
    assert result.valid is True, result.error


@pytest.mark.asyncio
async def test_verify_request_passes_when_supports_revocation_false(peer) -> None:
    """The MUST is gated on supports_revocation=true; false skips is_revoked."""
    envelope, cap_hash = await _mint_and_authenticate(peer, peer.keypair)
    # Pre-write the marker — but the gate is off, so verify still passes.
    marker = Entity(
        type="system/capability/revocation",
        data={"token": cap_hash, "revoked_at": 0},
    )
    peer.content_store.put(marker)
    peer.entity_tree.set(
        f"{REVOCATIONS_ROOT}/{cap_hash.hex()}", marker.compute_hash(),
    )
    rev_ctx = DefaultRevocationContext(
        entity_tree=peer.entity_tree,
        content_store=peer.content_store,
        included={ent.get("content_hash"): ent for ent in envelope.included
                  if isinstance(ent.get("content_hash"), bytes)},
        supports_revocation=False,
    )
    result = verify_request_integrity(
        envelope, local_peer_id=peer.peer_id, revocation_ctx=rev_ctx,
    )
    assert result.valid is True, result.error


@pytest.mark.asyncio
async def test_verify_request_rejects_revoked_cap(peer) -> None:
    """F2: supports_revocation=true + marker → verify rejects with error_code=revoked."""
    envelope, cap_hash = await _mint_and_authenticate(peer, peer.keypair)
    # Pre-write the revocation marker for the cap.
    marker = Entity(
        type="system/capability/revocation",
        data={"token": cap_hash, "revoked_at": 0},
    )
    peer.content_store.put(marker)
    peer.entity_tree.set(
        f"{REVOCATIONS_ROOT}/{cap_hash.hex()}", marker.compute_hash(),
    )
    rev_ctx = DefaultRevocationContext(
        entity_tree=peer.entity_tree,
        content_store=peer.content_store,
        included={ent.get("content_hash"): ent for ent in envelope.included
                  if isinstance(ent.get("content_hash"), bytes)},
        supports_revocation=True,
    )
    result = verify_request_integrity(
        envelope, local_peer_id=peer.peer_id, revocation_ctx=rev_ctx,
    )
    assert result.valid is False, "expected revoked cap to be rejected"
    assert result.error_code == "revoked", result.error_code
