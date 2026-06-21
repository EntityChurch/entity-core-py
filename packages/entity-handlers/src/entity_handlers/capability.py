"""Capability handler — V7 §6.2 system/capability (v7.62).

Operations:
  - request    : mint a peer-rooted token, validated as subset of BOTH the
                 caller's authenticated cap AND the matched policy entry.
  - delegate   : self-attenuate from a parent the caller directly holds.
                 Parent is identified by ``params.data.parent`` (hash),
                 NOT by the resource target — delegate-request shape.
  - revoke     : universal entry point. Unbinds the cap's tree path (when
                 known via ``capability_path_for``) AND writes a revocation
                 marker at ``system/capability/revocations/{cap_hash_hex}``.
                 Caller authorization is the standard dispatch check
                 (cap covering ``system/capability:revoke`` on the target);
                 no granter-identity carve-out.
  - configure  : write a policy entry at ``system/capability/policy/{peer_pattern}``.
                 ``peer_pattern`` is the canonical peer identity hash hex
                 (format-relative width: 66 for SHA-256, 98 for SHA-384) OR
                 the literal segment ``default`` (default-for-unknown-peers,
                 V7 §6.2 v7.63 F8: renamed from the prior ``*`` literal so
                 it no longer collides with the glob-pattern role of ``*``
                 elsewhere in V7) — no partial-prefix patterns.

Cross-cutting timestamp convention (§6.2): ``expires_at``, ``revoked_at``,
``created_at`` and ttl_ms-derived expiries are wall-clock ms since Unix
epoch set by the handler. Caller-supplied ``revoked_at``/``created_at``
are ignored.

Result envelope shape (§6.2): the ``request`` and ``delegate`` ops carry the
issued token, its signature, and the granter identity entity in ``included``.
For ``delegate``, the full authority chain (parent token + its signature +
its granter identity, recursively to the root) SHOULD ride along to spare
cross-peer verifiers a round-trip GET.
"""

from __future__ import annotations

import time
from typing import Any

from entity_core.capability.delegation import is_attenuated
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.utils.ecf import validate_hash
from entity_handlers._common import error_response as _error
from entity_handlers._common import params_data as _params_data


CAPABILITY_HANDLER_PATTERN = "system/capability"

REVOCATIONS_ROOT = "system/capability/revocations"
GRANTS_ROOT = "system/capability/grants"
POLICY_ROOT = "system/capability/policy"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _cap_hash_hex(cap_hash: bytes) -> str:
    """V7 §3.5 invariant-pointer hex form (66 chars for ECFv1-SHA-256)."""
    return cap_hash.hex()


def _revocation_path_for(cap_hash: bytes) -> str:
    return f"{REVOCATIONS_ROOT}/{_cap_hash_hex(cap_hash)}"


def _policy_path_for(peer_pattern: str) -> str:
    return f"{POLICY_ROOT}/{peer_pattern}"


def _caller_cap_data(ctx: HandlerContext) -> dict[str, Any] | None:
    """Return caller's authenticated cap data dict, or None if absent."""
    cap = ctx.caller_capability
    if not isinstance(cap, dict):
        return None
    if "data" in cap and isinstance(cap["data"], dict):
        return cap["data"]
    return cap


def _grants_subset(child_grants: list[dict[str, Any]],
                   parent_grants: list[dict[str, Any]],
                   local_peer_id: str) -> tuple[bool, str | None]:
    """True iff every child grant is covered by some parent grant.

    Reuses is_attenuated() by wrapping grants in cap-shaped dicts so the
    per-grant exclude-inheritance + scope-subset logic is shared with chain
    validation. Returns (ok, error_message).
    """
    hypothetical_child = {"data": {"grants": child_grants}}
    hypothetical_parent = {"data": {"grants": parent_grants}}
    result = is_attenuated(hypothetical_child, hypothetical_parent, local_peer_id)
    return result.valid, result.error


def _local_identity_hash(ctx: HandlerContext) -> tuple[bytes | None, Entity | None]:
    """Derive (identity_hash, identity_entity) for the local peer."""
    if ctx.keypair is None:
        return None, None
    identity_entity = create_identity_entity(ctx.keypair)
    return identity_entity.compute_hash(), identity_entity


def _caller_identity_hash(ctx: HandlerContext) -> bytes | None:
    """The cryptographically-verified author of THIS EXECUTE, falling back
    to the connection identity. Matches the writer-resolution pattern in
    continuation.py / role.py."""
    h = getattr(ctx, "author_identity_hash", None)
    if h is not None:
        return h
    return ctx.remote_identity_hash


def _resolve_token_entity(
    ctx: HandlerContext, cap_hash: bytes,
) -> Entity | None:
    """Look up a capability token entity by hash in `included` then content store."""
    included = ctx.included or {}
    raw = included.get(cap_hash)
    if isinstance(raw, dict):
        try:
            return Entity.from_dict(raw)
        except Exception:
            pass
    return ctx.emit_pathway.content_store.get(cap_hash)


def _capability_path_for(
    ctx: HandlerContext, cap_hash: bytes,
) -> str | None:
    """Return the canonical storage path for `cap_hash`, or None for wire-only caps.

    Per V7 §5.1: handler grants are stored at ``system/capability/grants/{pattern}``.
    Other cap-storage conventions (role-derived grants, app-issued caps) live
    under deeper subtrees. We scan the binding map for any path bound to
    ``cap_hash`` whose suffix matches a known cap-storage prefix. The tree's
    bindings are stored normalized (peer-prefixed), so the suffix check
    catches both ``system/...`` and ``/{peer_id}/system/...`` shapes.
    """
    tree = ctx.emit_pathway.entity_tree
    needle = GRANTS_ROOT + "/"
    for path in tree.paths_for_hash(cap_hash):
        if needle in path:
            return path
    return None


def _parse_grants_payload(
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]] | None, int | None, str | None]:
    """Extract (grants, ttl_ms, error) from a request/delegate-request body."""
    data = _params_data(params)
    grants = data.get("grants")
    if not isinstance(grants, list):
        return None, None, "missing or non-array `grants`"
    ttl_ms = data.get("ttl_ms")
    if ttl_ms is not None and (not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool)):
        return None, None, "`ttl_ms` must be an integer when present"
    return grants, ttl_ms, None


def _mint_token(
    *,
    keypair: Any,
    granter_hash: bytes,
    grantee_hash: bytes,
    grants: list[dict[str, Any]],
    parent: bytes | None,
    expires_at: int | None,
    now: int,
) -> tuple[Entity, Entity]:
    """Build and sign a capability token. Returns (token_entity, signature_entity)."""
    cap_data: dict[str, Any] = {
        "grants": grants,
        "granter": granter_hash,
        "grantee": grantee_hash,
        "created_at": now,
    }
    if expires_at is not None:
        cap_data["expires_at"] = expires_at
    if parent is not None:
        cap_data["parent"] = parent

    token_entity = Entity(type="system/capability/token", data=cap_data)
    sig_entity = create_signature_entity(
        keypair,
        target_hash=token_entity.compute_hash(),
        signer_identity_hash=granter_hash,
    )
    return token_entity, sig_entity


def _bundle_chain(
    ctx: HandlerContext, token_entity: Entity,
) -> dict[bytes, dict[str, Any]]:
    """Walk parent links from `token_entity`, gathering each parent + its
    signature + granter identity into a single envelope-included bundle.

    Per §6.2 result envelope shape: cross-peer dispatch SHOULD include the
    full chain so the verifier doesn't have to GET ancestors. We follow the
    chain through ``included`` then content store; missing links stop the
    walk silently — the response envelope contract is "what is locally
    resolvable", not "guaranteed complete".
    """
    bundle: dict[bytes, dict[str, Any]] = {}
    current = token_entity
    visited: set[bytes] = set()
    while True:
        parent_hash = current.data.get("parent")
        if not isinstance(parent_hash, bytes) or not parent_hash:
            return bundle
        if parent_hash in visited:
            return bundle
        visited.add(parent_hash)
        parent_entity = _resolve_token_entity(ctx, parent_hash)
        if parent_entity is None:
            return bundle
        parent_hash_bytes = parent_entity.compute_hash()
        bundle[parent_hash_bytes] = parent_entity.to_dict()
        # Find signature targeting the parent
        parent_granter = parent_entity.data.get("granter")
        if isinstance(parent_granter, bytes):
            for h, raw in (ctx.included or {}).items():
                if not isinstance(raw, dict):
                    continue
                if raw.get("type") != "system/signature":
                    continue
                rdata = raw.get("data") or {}
                if rdata.get("target") == parent_hash_bytes and rdata.get("signer") == parent_granter:
                    bundle[h] = raw
                    break
            # Find granter identity entity
            granter_identity = (ctx.included or {}).get(parent_granter)
            if isinstance(granter_identity, dict):
                bundle[parent_granter] = granter_identity
            else:
                stored = ctx.emit_pathway.content_store.get(parent_granter)
                if stored is not None:
                    bundle[parent_granter] = stored.to_dict()
        current = parent_entity


def _build_grant_result(
    ctx: HandlerContext,
    token_entity: Entity,
    signature_entity: Entity,
    identity_entity: Entity,
    *,
    bundle_chain: bool = False,
) -> dict[str, Any]:
    """Wrap a freshly minted token as a system/capability/grant response.

    Token + signature + granter identity ride in envelope_included. When
    ``bundle_chain`` is true (delegate path), the full authority chain
    rides along too (§6.2 SHOULD for cross-peer dispatch).
    """
    token_hash = token_entity.compute_hash()
    included: dict[bytes, dict[str, Any]] = {
        token_hash: token_entity.to_dict(),
        signature_entity.compute_hash(): signature_entity.to_dict(),
        identity_entity.compute_hash(): identity_entity.to_dict(),
    }
    if bundle_chain:
        included.update(_bundle_chain(ctx, token_entity))
    return {
        "status": 200,
        "result": {
            "type": "system/capability/grant",
            "data": {"token": token_hash},
        },
        "envelope_included": included,
    }


# ---------------------------------------------------------------------------
# Policy table
# ---------------------------------------------------------------------------

def _peer_hex_for(identity_hash: bytes | None) -> str | None:
    if not isinstance(identity_hash, bytes) or not identity_hash:
        return None
    return identity_hash.hex()


def _read_policy_entry(
    ctx: HandlerContext, peer_hex: str,
) -> dict[str, Any] | None:
    """Read a policy entry's data dict from ``system/capability/policy/{peer_hex}``,
    or None if absent."""
    tree = ctx.emit_pathway.entity_tree
    h = tree.get(_policy_path_for(peer_hex))
    if h is None:
        return None
    entity = ctx.emit_pathway.content_store.get(h)
    if entity is None:
        return None
    data = entity.data
    return data if isinstance(data, dict) else None


def _resolve_policy_for_caller(
    ctx: HandlerContext,
    caller_id: bytes | None,
    caller_peer_id_base58: str | None = None,
) -> dict[str, Any] | None:
    """V7 §6.2 v7.64 dual-form policy resolution.

    Look up the policy entry in order:
      1. Hex form ``system/capability/policy/{caller_peer_hex}`` —
         canonical (V7 §3.5 / §3.6 grantee convention).
      2. Base58 form ``system/capability/policy/{caller_peer_id_base58}``
         — pre-configuration affordance per
         PROPOSAL-V7-POLICY-DUAL-FORM. The operator may have written the
         entry by Base58 PeerID before public_key handoff (typical for
         SHA-256-form peers, or any peer pasted by handle).
      3. Default ``system/capability/policy/default``.

    Hex precedence: if a hex-form entry exists, the Base58 entry is not
    consulted (§2.2). On Base58-form match, an optional SHOULD-tier
    canonicalization (§2.3) may upgrade the entry to hex; we do so when
    the public_key is locally derivable (identity-form PeerIDs) or
    cached in the local tree.
    """
    peer_hex = _peer_hex_for(caller_id)
    if peer_hex is not None:
        specific = _read_policy_entry(ctx, peer_hex)
        if specific is not None:
            return specific
    if caller_peer_id_base58:
        base58_entry = _read_policy_entry(ctx, caller_peer_id_base58)
        if base58_entry is not None:
            _canonicalize_policy_entry(
                ctx,
                base58_pattern=caller_peer_id_base58,
                hex_pattern=peer_hex,
                entry=base58_entry,
            )
            return base58_entry
    return _read_policy_entry(ctx, "default")


def _canonicalize_policy_entry(
    ctx: HandlerContext,
    *,
    base58_pattern: str,
    hex_pattern: str | None,
    entry: dict[str, Any],
) -> None:
    """V7 §6.2 v7.64 §2.3 — SHOULD-tier canonicalization on Base58 match.

    Two independent idempotent operations: write hex (no-op if equal
    already exists), delete base58 (no-op if absent). Self-healing
    under crash / concurrent races.

    No-op when the hex form is unknown (e.g., couldn't be derived) —
    the Base58 entry stays and continues to match on future connects.
    """
    if hex_pattern is None:
        return
    if hex_pattern == base58_pattern:
        return
    try:
        tree = ctx.emit_pathway.entity_tree
        cs = ctx.emit_pathway.content_store
        if tree.get(_policy_path_for(hex_pattern)) is None:
            entry_entity = Entity(
                type="system/capability/policy-entry",
                data={**entry, "peer_pattern": hex_pattern},
            )
            ctx.emit_pathway.emit(
                _policy_path_for(hex_pattern), entry_entity, EmitContext.bootstrap(),
            )
        tree.remove(_policy_path_for(base58_pattern))
        _ = cs  # storage retains content (deduplication); only tree binding removed
    except Exception:
        # Canonicalization is best-effort — match has already succeeded.
        pass


def _valid_peer_pattern(pattern: str) -> bool:
    """V7 §6.2 v7.64 §2.4: ``peer_pattern`` is one of —
      - the canonical content_hash hex (hex form), or
      - a Base58 PeerID per V7 §1.5 (pre-configuration affordance), or
      - the literal segment ``default``.

    The hex width is **format-relative** (V7 §3.5 invariant pointer,
    v7.70 §1.2): 66 hex for ECFv1-SHA-256 (33 bytes), 98 for ECFv1-SHA-384
    (49 bytes), etc. A SHA-384 home peer's canonical peer hash is 98 hex,
    so a hardcoded 66 would reject it. We accept any lowercase hex that
    decodes to a structurally valid content_hash (supported format byte +
    matching digest width).

    Forms are unambiguously distinguishable by length+charset (§2.4
    pattern disjointness)."""
    if pattern == "default":
        return True
    # Hex form: lowercase canonical content_hash hex, width format-relative.
    if pattern == pattern.lower() and len(pattern) % 2 == 0:
        try:
            validate_hash(bytes.fromhex(pattern))
            return True
        except ValueError:
            pass
    # Base58 PeerID: must decode to a valid V7 §1.5 framing
    # (varint(key_type) || varint(hash_type) || digest) with a recognized
    # key_type, recognized hash_type, and matching digest length.
    # Rejects arbitrary Base58 garbage per §2.4 MUST-validate.
    try:
        import base58
        raw = base58.b58decode(pattern)
    except Exception:
        return False
    if len(raw) < 3:
        return False
    key_type = raw[0]
    hash_type = raw[1]
    digest = raw[2:]
    # Recognized key types: Ed25519 (0x01) for production; 0xFE
    # test/synthetic for PIM-5 length-agnostic decoder vectors.
    if key_type not in (0x01, 0xFE):
        return False
    if hash_type == 0x00:
        # identity-multihash: digest length is key-type-dependent.
        if key_type == 0x01 and len(digest) != 32:
            return False
        # 0xFE test/synthetic: any digest length accepted (PIM-5).
    elif hash_type == 0x01:
        # SHA-256 fingerprint: always 32 bytes.
        if len(digest) != 32:
            return False
    else:
        return False
    return True


# ---------------------------------------------------------------------------
# request
# ---------------------------------------------------------------------------

async def _handle_request(
    params: dict[str, Any], ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 (v7.62): mint a peer-rooted token validated against BOTH
    ceilings — the caller's authenticated cap AND the matched policy entry.

    Pure-attenuation flow (no policy entry) works by skipping the policy
    ceiling. Failures from either bound surface as
    ``403 scope_exceeds_authority``.
    """
    grants, ttl_ms, err = _parse_grants_payload(params)
    if err is not None:
        return _error(400, "invalid_request", err)

    caller_cap = _caller_cap_data(ctx)
    if caller_cap is None:
        return _error(403, "scope_exceeds_authority",
                      "request requires an authenticated caller capability")
    caller_grants = caller_cap.get("grants")
    if not isinstance(caller_grants, list):
        return _error(403, "scope_exceeds_authority",
                      "caller capability has no grants")

    # Ceiling 1: caller's authenticated cap (attenuation floor).
    ok, sub_err = _grants_subset(grants, caller_grants, ctx.local_peer_id)
    if not ok:
        return _error(403, "scope_exceeds_authority",
                      f"request exceeds caller authority: {sub_err}")

    # Ceiling 2: policy entry (per-peer operator-set bound), if present.
    caller_id = _caller_identity_hash(ctx)
    policy_entry = _resolve_policy_for_caller(
        ctx, caller_id, caller_peer_id_base58=ctx.remote_peer_id,
    )
    if policy_entry is not None:
        policy_grants = policy_entry.get("grants")
        if not isinstance(policy_grants, list):
            return _error(500, "internal_error",
                          "policy entry malformed: `grants` not an array")
        ok, sub_err = _grants_subset(grants, policy_grants, ctx.local_peer_id)
        if not ok:
            return _error(403, "scope_exceeds_authority",
                          f"request exceeds policy entry: {sub_err}")

    granter_hash, identity_entity = _local_identity_hash(ctx)
    if granter_hash is None or identity_entity is None:
        return _error(500, "internal_error",
                      "capability:request requires peer keypair")
    if caller_id is None:
        return _error(403, "scope_exceeds_authority",
                      "caller identity unavailable; cannot mint a token")

    now = _now_ms()
    caller_expires = caller_cap.get("expires_at")
    expires_at: int | None = None
    if isinstance(caller_expires, int):
        expires_at = caller_expires
    # Policy entry ttl_ms further constrains lifetime (if present).
    if policy_entry is not None:
        policy_ttl = policy_entry.get("ttl_ms")
        if isinstance(policy_ttl, int):
            policy_expiry = now + policy_ttl
            expires_at = policy_expiry if expires_at is None else min(expires_at, policy_expiry)
    if ttl_ms is not None:
        req_expiry = now + ttl_ms
        expires_at = req_expiry if expires_at is None else min(expires_at, req_expiry)

    token, signature = _mint_token(
        keypair=ctx.keypair,
        granter_hash=granter_hash,
        grantee_hash=caller_id,
        grants=grants,
        parent=None,
        expires_at=expires_at,
        now=now,
    )
    return _build_grant_result(ctx, token, signature, identity_entity)


# ---------------------------------------------------------------------------
# delegate
# ---------------------------------------------------------------------------

async def _handle_delegate(
    params: dict[str, Any], ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 (v7.63): self-attenuation only, same-peer-only for v1.

    Parent is identified by ``params.data.parent`` (hash). Grantee = caller's
    authenticated identity. Granter = local peer (peer-issued, same as
    ``request``); because v1 enforces ``caller == local_peer``, the local
    keypair IS the caller's keypair, so §5.5 chain verification passes.

    Cross-peer ``delegate`` is rejected with ``501 unsupported_operation``:
    no v1 wire shape encodes how the remote caller signs the minted child
    (V7 §3.6 ``grantee=caller`` + §5.5 ``granter signs``). Cross-peer
    self-attenuation is performed client-side instead.

    The result envelope SHOULD carry the full authority chain bundle so
    cross-peer verifiers don't have to GET ancestors.
    """
    # F1 (V7 §6.2 v7.63): same-peer-only. The EXECUTE author must be the
    # local peer; otherwise the v1 mint shape cannot produce a valid child.
    if ctx.remote_peer_id != ctx.local_peer_id:
        return _error(
            501, "unsupported_operation",
            "delegate is same-peer-only in v1; cross-peer self-attenuation "
            "is performed client-side (construct + sign child cap locally)",
        )

    grants, ttl_ms, err = _parse_grants_payload(params)
    if err is not None:
        return _error(400, "invalid_request", err)

    data = _params_data(params)
    parent_hash = data.get("parent")
    if not isinstance(parent_hash, bytes) or not parent_hash:
        return _error(400, "invalid_request",
                      "delegate requires `parent` (hash bytes of the parent token)")

    parent_entity = _resolve_token_entity(ctx, parent_hash)
    if parent_entity is None:
        return _error(404, "parent_not_found",
                      "parent capability token entity not found in included or content store")
    if parent_entity.type != "system/capability/token":
        return _error(400, "parent_not_a_token",
                      f"resolved entity is not a capability token ({parent_entity.type})")

    parent_data = parent_entity.data
    parent_grants = parent_data.get("grants")
    if not isinstance(parent_grants, list):
        return _error(400, "parent_malformed", "parent token has no grants")

    caller_id = _caller_identity_hash(ctx)
    if caller_id is None:
        return _error(403, "scope_exceeds_authority",
                      "caller identity unavailable; cannot delegate")
    parent_grantee = parent_data.get("grantee")
    if parent_grantee != caller_id:
        return _error(403, "scope_exceeds_authority",
                      "caller is not the grantee of the parent capability")

    ok, sub_err = _grants_subset(grants, parent_grants, ctx.local_peer_id)
    if not ok:
        return _error(403, "scope_exceeds_authority",
                      f"requested grants exceed parent authority: {sub_err}")

    granter_hash, identity_entity = _local_identity_hash(ctx)
    if granter_hash is None or identity_entity is None:
        return _error(500, "internal_error",
                      "capability:delegate requires peer keypair")

    now = _now_ms()
    parent_expires = parent_data.get("expires_at")
    expires_at: int | None = parent_expires if isinstance(parent_expires, int) else None
    if ttl_ms is not None:
        req_expiry = now + ttl_ms
        expires_at = req_expiry if expires_at is None else min(expires_at, req_expiry)

    token, signature = _mint_token(
        keypair=ctx.keypair,
        granter_hash=granter_hash,
        grantee_hash=caller_id,
        grants=grants,
        parent=parent_hash,
        expires_at=expires_at,
        now=now,
    )
    return _build_grant_result(
        ctx, token, signature, identity_entity, bundle_chain=True,
    )


# ---------------------------------------------------------------------------
# revoke (universal entry point)
# ---------------------------------------------------------------------------

async def _handle_revoke(
    params: dict[str, Any], ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 (v7.62): universal revoke.

    If the token has a known storage path (``capability_path_for``), unbind
    the tree entry AND write the marker (defense in depth — both
    ``is_revoked`` checks fire). For wire-only caps (no storage path),
    write the marker only.

    Authorization is the standard dispatch check on
    ``system/capability:revoke`` — no granter-identity carve-out.
    """
    data = _params_data(params)
    token_hash = data.get("token")
    if not isinstance(token_hash, bytes) or len(token_hash) == 0:
        return _error(400, "invalid_request",
                      "revoke requires `token` (hash bytes of the target capability)")
    if all(b == 0 for b in token_hash):
        return _error(400, "invalid_request", "revoke target is the zero hash")

    # The target SHOULD resolve so we can produce a sensible marker, but a
    # wire-only target hash with no resolvable entity is still legitimate
    # if the caller knows the hash — the marker functions as a tombstone
    # regardless.
    target_entity = _resolve_token_entity(ctx, token_hash)
    if target_entity is not None and target_entity.type != "system/capability/token":
        return _error(400, "target_not_a_token",
                      f"resolved entity is not a capability token ({target_entity.type})")

    ep = ctx.emit_pathway
    emit_ctx = EmitContext.bootstrap()

    # Universal revoke: unbind the cap's path (when known) AND write marker.
    storage_path = _capability_path_for(ctx, token_hash)
    if storage_path is not None:
        ep.entity_tree.remove(storage_path)

    now = _now_ms()
    reason = data.get("reason")
    marker_data: dict[str, Any] = {"token": token_hash, "revoked_at": now}
    if isinstance(reason, str) and reason:
        marker_data["reason"] = reason
    marker_entity = Entity(type="system/capability/revocation", data=marker_data)
    ep.emit(_revocation_path_for(token_hash), marker_entity, emit_ctx)

    return {
        "status": 200,
        "result": {
            "type": "system/protocol/status",
            "data": {"status": "revoked", "token": token_hash},
        },
    }


# ---------------------------------------------------------------------------
# configure
# ---------------------------------------------------------------------------

async def _handle_configure(
    params: dict[str, Any], ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 (v7.64): write a policy entry at
    ``system/capability/policy/{peer_pattern}``. ``peer_pattern`` is one
    of — the canonical content_hash hex (format-relative width: 66 for
    SHA-256, 98 for SHA-384), Base58 PeerID (pre-configuration affordance
    per PROPOSAL-V7-POLICY-DUAL-FORM-PRE-CONFIGURATION), or the literal
    segment ``default``. MUST reject any other shape with
    ``400 invalid_peer_pattern``.
    """
    data = _params_data(params)
    peer_pattern = data.get("peer_pattern")
    if not isinstance(peer_pattern, str) or not peer_pattern:
        return _error(400, "invalid_peer_pattern",
                      "configure requires `peer_pattern` (canonical identity "
                      "hash hex, Base58 PeerID, or 'default')")
    if not _valid_peer_pattern(peer_pattern):
        return _error(400, "invalid_peer_pattern",
                      "peer_pattern must be a canonical identity hash hex "
                      "(format-relative width), a Base58 PeerID, or the "
                      "literal 'default'")

    grants = data.get("grants")
    if not isinstance(grants, list):
        return _error(400, "invalid_request",
                      "configure requires `grants` (array of grant entries)")

    entry_data: dict[str, Any] = {
        "peer_pattern": peer_pattern,
        "grants": grants,
    }
    ttl_ms = data.get("ttl_ms")
    if isinstance(ttl_ms, int) and not isinstance(ttl_ms, bool):
        entry_data["ttl_ms"] = ttl_ms
    notes = data.get("notes")
    if isinstance(notes, str):
        entry_data["notes"] = notes

    entry_entity = Entity(type="system/capability/policy-entry", data=entry_data)
    ep = ctx.emit_pathway
    emit_ctx = EmitContext.bootstrap()
    ep.emit(_policy_path_for(peer_pattern), entry_entity, emit_ctx)

    return {
        "status": 200,
        "result": {
            "type": "system/protocol/status",
            "data": {"status": "configured", "peer_pattern": peer_pattern},
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

async def capability_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 (v7.62) system/capability handler.

    Status code discipline:
      - ``501 unsupported_operation`` for unknown operations (handler IS
        registered, op does not exist on it).
      - ``403 scope_exceeds_authority`` for authority failures.
    """
    if operation == "request":
        return await _handle_request(params, ctx)
    if operation == "delegate":
        return await _handle_delegate(params, ctx)
    if operation == "revoke":
        return await _handle_revoke(params, ctx)
    if operation == "configure":
        return await _handle_configure(params, ctx)
    return _error(
        501, "unsupported_operation",
        f"system/capability does not support operation: {operation}",
    )
