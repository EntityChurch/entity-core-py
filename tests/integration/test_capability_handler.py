"""Integration tests for the V7 §6.2 (v7.62) ``system/capability`` handler.

Pinned behaviors:
- request validates against BOTH the caller's authenticated cap AND the
  matched policy entry (exact-match-or-``default``-fallback per §6.2 v7.63).
- delegate is same-peer-only in v1 (V7 §6.2 v7.63 F1): remote callers get
  ``501 unsupported_operation``. Same-peer self-attenuation uses
  ``params.data.parent`` (hash), grantee = caller's authenticated identity.
- revoke is the universal entry point: unbinds the tree path (when known
  via ``capability_path_for``) AND writes a marker. Authorization is the
  standard dispatch check — no granter-only carve-out.
- configure writes ``system/capability/policy/{peer_pattern}`` with
  ``peer_pattern`` exactly 66-hex OR the literal segment ``default`` (V7
  §6.2 v7.63 F8: renamed from prior ``*``).
- Token + signature + granter identity ride in ``envelope_included`` on
  ``request``; ``delegate`` additionally bundles the parent chain.
- Unknown operation → ``501 unsupported_operation``.
"""

from __future__ import annotations

import pytest

from entity_core.capability.token import CapabilityToken
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers.capability import (
    CAPABILITY_HANDLER_PATTERN,
    GRANTS_ROOT,
    POLICY_ROOT,
    REVOCATIONS_ROOT,
    capability_handler,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def peer():
    kp = Keypair.generate()
    return PeerBuilder().with_keypair(kp).with_all_handlers().build()


def _full_access_cap() -> dict[str, object]:
    return {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*", "/*/*"]},
            "operations": {"include": ["*"]},
            "peers": {"include": ["*"]},
        }]
    }


def _narrow_cap(handler: str, op: str, resource: str) -> dict[str, object]:
    return {
        "grants": [{
            "handlers": {"include": [handler]},
            "resources": {"include": [resource]},
            "operations": {"include": [op]},
        }]
    }


def _ctx(
    peer,
    *,
    caller_cap: dict[str, object] | None = None,
    caller_keypair: Keypair | None = None,
    resource_targets: list[str] | None = None,
    included: dict[bytes, dict[str, object]] | None = None,
) -> HandlerContext:
    caller_cap = caller_cap if caller_cap is not None else _full_access_cap()
    if caller_keypair is None:
        caller_keypair = peer.keypair
    caller_identity = create_identity_entity(caller_keypair)
    caller_identity_hash = caller_identity.compute_hash()
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=caller_keypair.peer_id,
        handler_grant=_full_access_cap(),
        caller_capability=caller_cap,
        emit_pathway=peer.emit_pathway,
        keypair=peer.keypair,
        resource_targets=resource_targets,
        included=included or {},
        author_identity_hash=caller_identity_hash,
        remote_identity_hash=caller_identity_hash,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_capability_handler_registered(peer) -> None:
    info = peer.handlers.find_handler_info(CAPABILITY_HANDLER_PATTERN)
    assert info is not None
    assert info.pattern == CAPABILITY_HANDLER_PATTERN
    assert info.name == "capability"


def test_capability_handler_interface_in_tree(peer) -> None:
    uri = peer.entity_tree.normalize_uri(f"system/handler/{CAPABILITY_HANDLER_PATTERN}")
    h = peer.entity_tree.get(uri)
    assert h is not None
    entity = peer.content_store.get(h)
    assert entity is not None
    assert entity.type == "system/handler/interface"
    ops = entity.data["operations"]
    for op in ("request", "delegate", "revoke", "configure"):
        assert op in ops, f"missing op {op!r} in manifest"


# ---------------------------------------------------------------------------
# request
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_request_returns_grant_and_envelope_included(peer) -> None:
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, ctx,
    )
    assert result["status"] == 200
    assert result["result"]["type"] == "system/capability/grant"
    token_hash = result["result"]["data"]["token"]
    assert isinstance(token_hash, bytes) and len(token_hash) > 1
    included = result["envelope_included"]
    assert token_hash in included
    token = CapabilityToken.from_entity(included[token_hash])
    assert isinstance(token.granter, bytes)
    assert token.parent is None  # peer-rooted
    assert len(token.grants) == 1


@pytest.mark.asyncio
async def test_request_token_signed_by_peer(peer) -> None:
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, ctx,
    )
    token_hash = result["result"]["data"]["token"]
    included = result["envelope_included"]
    matches = [
        Entity.from_dict(e) for e in included.values()
        if e["type"] == "system/signature" and e["data"].get("target") == token_hash
    ]
    assert len(matches) == 1
    assert matches[0].data["algorithm"] == "ed25519"
    assert any(e["type"] == "system/peer" for e in included.values())


@pytest.mark.asyncio
async def test_request_rejects_scope_widening(peer) -> None:
    narrow = _narrow_cap("system/tree", "get", "app/*")
    wider = [{
        "handlers": {"include": ["*"]},
        "resources": {"include": ["*"]},
        "operations": {"include": ["*"]},
    }]
    ctx = _ctx(peer, caller_cap=narrow, caller_keypair=Keypair.generate())
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": wider}}, ctx,
    )
    assert result["status"] == 403
    assert result["result"]["data"]["code"] == "scope_exceeds_authority"


@pytest.mark.asyncio
async def test_request_requires_grants(peer) -> None:
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request", {"data": {}}, ctx,
    )
    assert result["status"] == 400
    assert result["result"]["data"]["code"] == "invalid_request"


# ---------------------------------------------------------------------------
# request — policy table ceiling
# ---------------------------------------------------------------------------

def _write_policy_entry(
    peer, peer_pattern: str, grants: list[dict], ttl_ms: int | None = None,
) -> None:
    """Directly seed a policy entry under the capability handler's namespace."""
    data: dict[str, object] = {"peer_pattern": peer_pattern, "grants": grants}
    if ttl_ms is not None:
        data["ttl_ms"] = ttl_ms
    entity = Entity(type="system/capability/policy-entry", data=data)
    peer.emit_pathway.emit(
        f"{POLICY_ROOT}/{peer_pattern}", entity, EmitContext.bootstrap(),
    )


@pytest.mark.asyncio
async def test_request_subset_of_policy_entry_succeeds(peer) -> None:
    """Policy entry bounds the caller. A subset request is allowed."""
    caller_kp = Keypair.generate()
    caller_id = create_identity_entity(caller_kp).compute_hash()
    _write_policy_entry(peer, caller_id.hex(), [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }])

    # Caller's authenticated cap is broad (full access); the policy entry
    # narrows to tree:get. A request for tree:get must succeed.
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    ctx = _ctx(peer, caller_keypair=caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, ctx,
    )
    assert result["status"] == 200, result


@pytest.mark.asyncio
async def test_request_exceeding_policy_entry_rejected(peer) -> None:
    """Policy entry caps the caller below their authenticated cap."""
    caller_kp = Keypair.generate()
    caller_id = create_identity_entity(caller_kp).compute_hash()
    _write_policy_entry(peer, caller_id.hex(), [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }])

    # Authenticated cap covers tree:put, but the policy entry does not.
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["put"]},
    }]
    ctx = _ctx(peer, caller_keypair=caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, ctx,
    )
    assert result["status"] == 403
    assert result["result"]["data"]["code"] == "scope_exceeds_authority"


@pytest.mark.asyncio
async def test_request_falls_back_to_default_policy(peer) -> None:
    """No specific entry — the ``default`` entry applies as the ceiling
    (V7 §6.2 v7.63 F8: fallback segment renamed from ``*`` to ``default``)."""
    _write_policy_entry(peer, "default", [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }])
    caller_kp = Keypair.generate()
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["put"]},  # exceeds default policy
    }]
    ctx = _ctx(peer, caller_keypair=caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, ctx,
    )
    assert result["status"] == 403


# ---------------------------------------------------------------------------
# delegate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delegate_requires_parent_hash(peer) -> None:
    """parent comes from params.data.parent (v7.62), not the resource."""
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "delegate",
        {"data": {"grants": requested}}, ctx,
    )
    assert result["status"] == 400
    assert result["result"]["data"]["code"] == "invalid_request"


@pytest.mark.asyncio
async def test_delegate_happy_path(peer) -> None:
    # F1 (V7 §6.2 v7.63): delegate is same-peer-only. Caller = local peer;
    # mint the parent in the local peer's own SDK and self-attenuate.
    parent_grants = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get", "put"]},
    }]
    ctx1 = _ctx(peer)
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": parent_grants}}, ctx1,
    )
    parent_hash = mint["result"]["data"]["token"]
    parent_dict = mint["envelope_included"][parent_hash]

    child_grants = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    ctx2 = _ctx(peer, included={parent_hash: parent_dict})
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "delegate",
        {"data": {"parent": parent_hash, "grants": child_grants}}, ctx2,
    )
    assert result["status"] == 200, result
    child_hash = result["result"]["data"]["token"]
    child_dict = result["envelope_included"][child_hash]
    child_token = CapabilityToken.from_entity(child_dict)
    assert child_token.parent == parent_hash
    assert child_token.grantee == ctx2.author_identity_hash
    # Bundled parent chain — parent token rides in included for cross-peer use.
    assert parent_hash in result["envelope_included"]


@pytest.mark.asyncio
async def test_delegate_rejects_widening(peer) -> None:
    parent_grants = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    ctx1 = _ctx(peer)
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": parent_grants}}, ctx1,
    )
    parent_hash = mint["result"]["data"]["token"]
    parent_dict = mint["envelope_included"][parent_hash]

    wider = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get", "put"]},
    }]
    ctx2 = _ctx(peer, included={parent_hash: parent_dict})
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "delegate",
        {"data": {"parent": parent_hash, "grants": wider}}, ctx2,
    )
    assert result["status"] == 403
    assert result["result"]["data"]["code"] == "scope_exceeds_authority"


@pytest.mark.asyncio
async def test_delegate_rejects_non_grantee(peer) -> None:
    # Parent minted to a foreign holder; local peer (the same-peer caller)
    # is not that grantee → 403 scope_exceeds_authority. (We mint via
    # `request` under the foreign keypair; `request` has no same-peer
    # restriction, only `delegate` does.)
    holder_kp = Keypair.generate()
    parent_grants = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": parent_grants}}, _ctx(peer, caller_keypair=holder_kp),
    )
    parent_hash = mint["result"]["data"]["token"]
    parent_dict = mint["envelope_included"][parent_hash]

    # Local peer attempts to delegate from a cap held by holder_kp.
    ctx2 = _ctx(peer, included={parent_hash: parent_dict})
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "delegate",
        {"data": {"parent": parent_hash, "grants": parent_grants}}, ctx2,
    )
    assert result["status"] == 403
    assert result["result"]["data"]["code"] == "scope_exceeds_authority"


@pytest.mark.asyncio
async def test_delegate_rejects_cross_peer(peer) -> None:
    """F1 (V7 §6.2 v7.63): remote caller → 501 unsupported_operation.

    v1 has no wire shape that makes the cross-peer chain valid (V7 §3.6
    `grantee=caller` + §5.5 `granter signs` together force the caller to
    sign, but the handler runs on the issuer peer without the caller's
    keypair). The handler rejects before any other validation.
    """
    remote_kp = Keypair.generate()
    ctx = _ctx(peer, caller_keypair=remote_kp)
    # No parent hash, no grants — the same-peer gate fires first, so the
    # 400-class shape errors never even run.
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "delegate",
        {"data": {}}, ctx,
    )
    assert result["status"] == 501, result
    assert result["result"]["data"]["code"] == "unsupported_operation"


# ---------------------------------------------------------------------------
# revoke — universal entry point (v7.62)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoke_rejects_zero_token(peer) -> None:
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "revoke",
        {"data": {"token": bytes(33)}}, ctx,
    )
    assert result["status"] == 400


@pytest.mark.asyncio
async def test_revoke_writes_marker(peer) -> None:
    """Wire-only cap → marker only (no tree path to unbind)."""
    caller_kp = Keypair.generate()
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, _ctx(peer, caller_keypair=caller_kp),
    )
    token_hash = mint["result"]["data"]["token"]
    token_dict = mint["envelope_included"][token_hash]
    peer.content_store.put(Entity.from_dict(token_dict))

    ctx = _ctx(peer, caller_keypair=peer.keypair)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "revoke",
        {"data": {"token": token_hash, "reason": "test"}}, ctx,
    )
    assert result["status"] == 200, result

    marker_uri = peer.entity_tree.normalize_uri(
        f"{REVOCATIONS_ROOT}/{token_hash.hex()}",
    )
    h = peer.entity_tree.get(marker_uri)
    assert h is not None
    marker = peer.content_store.get(h)
    assert marker is not None
    assert marker.type == "system/capability/revocation"
    assert marker.data["token"] == token_hash
    assert marker.data["reason"] == "test"
    assert isinstance(marker.data["revoked_at"], int)


@pytest.mark.asyncio
async def test_revoke_universal_unbinds_path_bound_cap(peer) -> None:
    """Path-bound cap → unbind tree entry AND write marker (defense in depth)."""
    caller_kp = Keypair.generate()
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, _ctx(peer, caller_keypair=caller_kp),
    )
    token_hash = mint["result"]["data"]["token"]
    token_entity = Entity.from_dict(mint["envelope_included"][token_hash])
    peer.content_store.put(token_entity)
    # Pin the cap to a storage path so capability_path_for returns it.
    storage_path = f"{GRANTS_ROOT}/{token_hash.hex()}"
    peer.emit_pathway.emit(storage_path, token_entity, EmitContext.bootstrap())
    assert peer.entity_tree.get(peer.entity_tree.normalize_uri(storage_path)) is not None

    ctx = _ctx(peer, caller_keypair=peer.keypair)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "revoke",
        {"data": {"token": token_hash}}, ctx,
    )
    assert result["status"] == 200

    # Tree path is unbound...
    assert peer.entity_tree.get(peer.entity_tree.normalize_uri(storage_path)) is None
    # ...and the marker is present.
    marker_uri = peer.entity_tree.normalize_uri(
        f"{REVOCATIONS_ROOT}/{token_hash.hex()}",
    )
    assert peer.entity_tree.get(marker_uri) is not None


@pytest.mark.asyncio
async def test_revoke_no_granter_carveout(peer) -> None:
    """v7.62: authorization is the dispatch check; the handler itself does
    not require caller == granter. A non-granter who holds the right cap
    is permitted by the handler (the dispatch layer enforces the cap).
    """
    caller_kp = Keypair.generate()
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested}}, _ctx(peer, caller_keypair=caller_kp),
    )
    token_hash = mint["result"]["data"]["token"]
    token_dict = mint["envelope_included"][token_hash]
    peer.content_store.put(Entity.from_dict(token_dict))

    ctx = _ctx(peer, caller_keypair=caller_kp)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "revoke",
        {"data": {"token": token_hash}}, ctx,
    )
    assert result["status"] == 200, result


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_configure_writes_policy_entry(peer) -> None:
    caller_kp = Keypair.generate()
    caller_id = create_identity_entity(caller_kp).compute_hash()
    entry = {
        "peer_pattern": caller_id.hex(),
        "grants": [{
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["app/*"]},
            "operations": {"include": ["get"]},
        }],
        "notes": "test entry",
    }
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "configure", {"data": entry}, ctx,
    )
    assert result["status"] == 200, result

    path = peer.entity_tree.normalize_uri(f"{POLICY_ROOT}/{caller_id.hex()}")
    h = peer.entity_tree.get(path)
    assert h is not None
    stored = peer.content_store.get(h)
    assert stored is not None
    assert stored.type == "system/capability/policy-entry"
    assert stored.data["peer_pattern"] == caller_id.hex()


@pytest.mark.asyncio
async def test_configure_accepts_default_segment(peer) -> None:
    """V7 §6.2 v7.63 F8: fallback peer_pattern is the literal ``default``
    (renamed from ``*`` to drop the glob-glyph collision)."""
    entry = {
        "peer_pattern": "default",
        "grants": [{
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["app/*"]},
            "operations": {"include": ["get"]},
        }],
    }
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "configure", {"data": entry}, ctx,
    )
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_configure_rejects_legacy_wildcard(peer) -> None:
    """V7 §6.2 v7.63 F8 / v7.64 §2.4: the prior ``*`` literal is no longer
    accepted; ``*`` is also outside the Base58 alphabet so the dual-form
    affordance doesn't admit it either."""
    entry = {
        "peer_pattern": "*",
        "grants": [],
    }
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "configure", {"data": entry}, ctx,
    )
    assert result["status"] == 400
    assert result["result"]["data"]["code"] == "invalid_peer_pattern"


@pytest.mark.asyncio
async def test_configure_rejects_partial_prefix(peer) -> None:
    """Partial-prefix patterns are not valid (§6.2 baseline policy surface)."""
    entry = {
        "peer_pattern": "00abc*",
        "grants": [],
    }
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "configure", {"data": entry}, ctx,
    )
    assert result["status"] == 400
    assert result["result"]["data"]["code"] == "invalid_peer_pattern"


@pytest.mark.asyncio
async def test_configure_rejects_non_hex(peer) -> None:
    entry = {
        "peer_pattern": "g" * 66,  # right length, wrong charset
        "grants": [],
    }
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "configure", {"data": entry}, ctx,
    )
    assert result["status"] == 400


# ---------------------------------------------------------------------------
# CAP-6 — ttl_ms zero and overflow (§5.6 "overflow contributes no ceiling")
#
# Found by `entity-core-go`'s wire probe, report
# docs/validation/reports/2026-08-17-g-core-py-cap-fold-validation.md, against
# py a7deda6. We minted `expires_at = 18446745860712217718` — larger than
# uint64 max — where go and rust mint no expiry at all.
#
# Python's ints are arbitrary-precision, so the overflow every other
# implementation has to guard against simply does not happen here: the sum
# succeeds and cbor2 encodes it as a **bignum**, producing a token a uint64
# peer cannot decode at all. A numeric-encoding slip that becomes a cross-impl
# interop break on the capability wire — and one that is invisible locally,
# because nothing in this process ever fails to read it back.
#
# The no-ceiling condition is load-bearing: with a finite caller cap the
# `min()` picks the finite side and the bug is masked. That is why go had to
# strengthen its check (u) with a no-ceiling probe before py went RED.
# ---------------------------------------------------------------------------

UINT64_MAX = (1 << 64) - 1


def _no_ceiling_cap() -> dict[str, object]:
    """Full access with **no `expires_at`** — the §4.4 nil-expiry connection cap.

    `_full_access_cap()` already has this shape; naming it here is the point of
    the test, so a later edit that adds an expiry to the shared fixture does not
    silently disarm these three assertions.
    """
    cap = _full_access_cap()
    assert "expires_at" not in cap, "this probe requires a caller cap with no ceiling"
    return cap


async def _mint_with_ttl(peer, ttl_ms: int, *, caller_cap=None):
    """Mint via `request` with `ttl_ms`, returning the token entity dict."""
    requested = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    ctx = _ctx(peer, caller_cap=caller_cap or _no_ceiling_cap())
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": requested, "ttl_ms": ttl_ms}}, ctx,
    )
    assert result["status"] == 200, result
    token_hash = result["result"]["data"]["token"]
    return result["envelope_included"][token_hash]


@pytest.mark.asyncio
async def test_cap6_overflowing_ttl_with_no_ceiling_mints_no_expiry(peer) -> None:
    """§5.6: an unrepresentable `created_at + ttl_ms` term is **absent**.

    Not wrapped, not saturated to a representable maximum, and — the form we
    had — not carried at full arbitrary precision. Saturation and absence
    differ in the encoded token, so "close enough" is not available.
    """
    token = await _mint_with_ttl(peer, UINT64_MAX - 10)

    assert "expires_at" not in token["data"] or token["data"]["expires_at"] is None, (
        f"overflowing ttl must mint no expiry, got {token['data'].get('expires_at')}"
    )


@pytest.mark.asyncio
async def test_cap6_the_minted_expiry_is_always_uint64_decodable(peer) -> None:
    """The property the cross-impl break actually violated.

    A value above uint64 max is CBOR-encoded as a bignum, which go and rust
    cannot decode — so the token is unreadable by the peers it was minted for.
    Asserted over the encoded bytes rather than the Python int, because the
    Python int is exactly the thing that never complains.
    """
    import cbor2

    for ttl in (0, 1_000, UINT64_MAX - 10, UINT64_MAX, 1 << 70):
        token = await _mint_with_ttl(peer, ttl)
        expires = token["data"].get("expires_at")
        if expires is None:
            continue
        assert 0 <= expires <= UINT64_MAX, f"ttl_ms={ttl} minted {expires}"
        # A bignum-tagged encoding is the wire symptom. Major type 6 (tag)
        # 2/3 is what cbor2 emits for an int outside the 64-bit range.
        encoded = cbor2.dumps(expires, canonical=True)
        assert encoded[0] not in (0xC2, 0xC3), (
            f"ttl_ms={ttl} encoded expires_at as a CBOR bignum: {encoded[:3].hex()}"
        )


@pytest.mark.asyncio
async def test_cap6_ttl_zero_expires_immediately_rather_than_never(peer) -> None:
    """`ttl_ms: 0` is a real expiry at mint time, not an absent one.

    The distinction matters: absent means *never expires*, so collapsing zero
    into the overflow branch would hand back an immortal token for the request
    that asked for the shortest possible life.
    """
    token = await _mint_with_ttl(peer, 0)

    expires = token["data"].get("expires_at")
    assert isinstance(expires, int)
    assert 0 < expires <= UINT64_MAX


@pytest.mark.asyncio
async def test_cap6_an_overflowing_ttl_does_not_erase_a_finite_ceiling(peer) -> None:
    """"Contributes no ceiling" means *skip the term*, not *set it to None*.

    The masking case from go's report, asserted from the other side: with a
    finite caller cap the overflowing request must leave that ceiling intact.
    Treating unrepresentable as `expires_at = None` would let an overflowing
    ttl **widen** authority past the caller's own expiry — a worse bug than
    the one being fixed, and one this shape of fix invites.
    """
    ceiling = 1_700_000_000_000
    capped = {**_full_access_cap(), "expires_at": ceiling}

    token = await _mint_with_ttl(peer, UINT64_MAX - 10, caller_cap=capped)

    assert token["data"].get("expires_at") == ceiling


@pytest.mark.asyncio
async def test_cap6_a_hugely_negative_ttl_expires_now_rather_than_never(peer) -> None:
    """Underflow is deliberately **not** symmetric with overflow.

    A sum below zero is equally unrepresentable as a uint64, but "absent" here
    would mean *never expires* — turning a nonsense request into an immortal
    token. It clamps to an already-expired value instead: a `ttl_ms` may never
    widen authority, in either direction.
    """
    token = await _mint_with_ttl(peer, -(1 << 70))

    expires = token["data"].get("expires_at")
    assert expires is not None, "underflow must not mint an unexpiring token"
    assert 0 <= expires <= UINT64_MAX
    assert expires <= _now_ms_upper_bound()


def _now_ms_upper_bound() -> int:
    import time

    return int(time.time() * 1000) + 60_000


@pytest.mark.asyncio
async def test_cap6_delegate_is_the_second_mint_site_and_has_the_same_rule(peer) -> None:
    """`delegate` computes `now + ttl_ms` too, and go's probe never reached it.

    The report tested `request`. A second mint site carrying the same defect
    that no probe visits is exactly the shape this repo has been bitten by
    before — one concern, two code paths, coverage on one of them. Delegating
    with an overflowing ttl must inherit the parent's expiry unchanged rather
    than mint an undecodable one or widen past the parent.
    """
    parent_grants = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get", "put"]},
    }]
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": parent_grants, "ttl_ms": 3_600_000}}, _ctx(peer),
    )
    parent_hash = mint["result"]["data"]["token"]
    parent_dict = mint["envelope_included"][parent_hash]
    parent_expiry = parent_dict["data"]["expires_at"]
    assert isinstance(parent_expiry, int)

    child_grants = [{
        "handlers": {"include": ["system/tree"]},
        "resources": {"include": ["app/*"]},
        "operations": {"include": ["get"]},
    }]
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "delegate",
        {"data": {
            "parent": parent_hash,
            "grants": child_grants,
            "ttl_ms": UINT64_MAX - 10,
        }},
        _ctx(peer, included={parent_hash: parent_dict}),
    )
    assert result["status"] == 200, result

    child = result["envelope_included"][result["result"]["data"]["token"]]
    assert child["data"]["expires_at"] == parent_expiry, (
        "an overflowing delegate ttl must leave the parent's ceiling intact"
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_operation_returns_501(peer) -> None:
    ctx = _ctx(peer)
    result = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "bogus", {"data": {}}, ctx,
    )
    assert result["status"] == 501
