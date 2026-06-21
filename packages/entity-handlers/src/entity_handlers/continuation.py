"""Continuation handler for execution chaining.

The continuation handler enables chaining of operations where results
from one operation flow into the next. Supports:
- Forward continuations: Single dispatch with result transform
- Join continuations: Fan-in from multiple sources before dispatch

Pattern: system/continuation
Operations: install, advance, resume, abandon

Per EXTENSION-CONTINUATION v1.11. Conformant on the local / forward /
G1 surface (v1.10 §3.4 + the v1.9 pins, below). The only v1.11 delta is
the cross-peer §4.2 case 3 (iii) grantee pin (Amendment 2) — a deferred,
correctly-sequenced cross-peer item, not a present-tense gap; see the G2
paragraph at the end. Deltas implemented here:
- N1 (§3.1a): install authorization is an *in-chain* check (writer is a
  granter anywhere in the dispatch_capability's authority chain) — not a
  chain-root check. Already satisfied via check_creator_authority.
- *_extract (§2.2/§3.6, v1.7/1.8 catch-up): target_extract /
  operation_extract / resource_extract resolved at dispatch.
- G1 (§2.2): transform_ops bounded field-op set, applied at advance
  (extract -> select -> transform_ops, before the *_extract fields);
  an unknown op is rejected at install fail-closed with the spec-pinned
  `400 unknown_transform_op` (§2.2/§8.1).
- §3.4 forward-dispatch outcome classification (v1.10, normative): a
  *delivered* dispatch (the dispatcher returned, did not raise) is a
  COMPLETED forward dispatch even if the downstream handler returned a
  non-2xx — forward dispatch is a fire-and-forget closure invocation, not
  an RPC; the dispatched response is NOT threaded back. So a delivered
  non-2xx decrements remaining_executions and returns
  {status: 200, advanced: true}; it MUST NOT be promoted to
  transient/permanent, retried, suspended, or routed to on_error on the
  basis of the downstream status. Only a dispatch delivery/processing
  failure (the dispatcher raising) is a dispatch_result.error.
- A.1 (§3.4): lost-error marker bound when an on_error dispatch itself
  fails. Cross-impl pinned by v1.9/v1.10: marker entity `type` is
  `system/runtime/chain-error-lost` and `{step_index}` is the original
  request ID (see LOST_ERROR_MARKER_TYPE and _bind_chain_error_marker).

G2 (§4.2 case 3 / §4.3) — cross-peer continuation dispatch — IS WIRED
here per the v1.11 three-slot model and the cross-impl conformance
recipe for v1.9 G2 dispatch-grantee handling. When `target`
resolves to a remote peer B the advance dispatches the EXECUTE:
  - authorized by the scoped `dispatch_capability` (NOT the broad
    connection/session cap — no silent escalation, V7 §6.8); the cap is
    **rooted** at B's conferred authority, the installer **in-chain** as
    the re-attenuation leaf granter, **granted to** this dispatching host
    peer — which is the EXECUTE author, since the continuation handler
    signs with this peer's keypair (v1.11 §4.2 case 3 (iii); Amendment 2
    closed the v1.9 grantee gap that made the earlier installer-self-
    wielded attempt fail B's `grantee != author` check);
  - with the **full** authority chain (leaf → B-recognized root: caps +
    granter identities + bound signatures) bundled into the dispatched
    envelope `included` via `collect_chain_bundle` (§4.3) — the general
    V7 §3.1/§3.2 rule carries only the leaf.
The full chain is available because install (§3.2 step 5) persists it +
envelope ingest binds the signatures at the V7 invariant pointer path.
The §3.1a install writer check uses the per-EXECUTE verified author
(`ctx.author_identity_hash`, V7 §5.2 / §8.1) and falls back to the
connect-time session identity — they diverge only for cross-peer
installs. Local/system continuations are unchanged: the remote branch is
purely additive (gated on a remote target), the local path resolves the
chain from the install-persisted store as before.

Regression proof is the deterministic two-peer test
`tests/integration/test_continuation_cross_peer.py` (real wire: dispatch
authored by host peer, scoped cap — not connection cap, full chain in
`included`, out-of-scope denied). The Go `convergence/c3_*` gate is NOT
yet a usable cross-impl oracle: the committed harness mints the scoped
cap with the *minting client* as granter (installer NOT in-chain) and
only "passed" by collapsing all principals onto one shared identity —
the masking defect the Go team documents in their cross-peer
continuation conformance-harness notes and is reworking
(three-identity operator/role-SDK flow). Against the
committed harness a conformant impl MUST 403 at install (the installer
is not an in-chain granter, §3.1a); Python does, correctly. Re-run the
gate once the corrected harness lands.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from entity_core.capability.delegation import (
    ChainCollectStatus,
    check_creator_authority,
    collect_chain_bundle,
)
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.protocol.delivery import DeliverySpec
from entity_core.storage.emit import EmitContext
from entity_core.utils.ecf import Hash, is_hash_ref
from entity_core.utils.path import invariant_signature_path
from entity_handlers.manifest import error_response as _error_response

logger = logging.getLogger(__name__)


# EXTENSION-CONTINUATION v1.20 §3.10.5 path-safety. V7 §1.4 path-segment
# rules: UTF-8; no null bytes; no empty; no embedded `/`. Conservative
# subset (matches cross-impl convergence on `[a-zA-Z0-9_.-]+`).
_PATH_SAFE_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")


def _sanitize_reason(code: str | None) -> str:
    """Per v1.20 §3.10.5 path-safety: sentinel-substitute non-conformant codes.

    A handler emitting a non-path-safe ``code`` SHOULD have it sentinel-
    substituted (``{reason}`` = ``unspecified_error``) by the dispatching
    engine; raw ``code`` is preserved in the marker body's ``code`` field
    per §3.10.6 body-fields registry.
    """
    if code and _PATH_SAFE_RE.match(code):
        return code
    return "unspecified_error"


def _extract_response_code(result_payload: Any) -> str | None:
    """Extract ``result.data.code`` from a dispatch result per V7 §3.3.

    Tolerant of partial shapes — falls back to top-level ``code`` if
    ``data.code`` absent (some handlers emit the flat shape historically).
    Returns None when neither is present (the §3.10.5 missing-code condition,
    handled by caller via the ``protocol_error`` fallback).
    """
    if not isinstance(result_payload, dict):
        return None
    data_field = result_payload.get("data")
    if isinstance(data_field, dict):
        code_val = data_field.get("code")
        if isinstance(code_val, str):
            return code_val
    code_val = result_payload.get("code")
    if isinstance(code_val, str):
        return code_val
    return None


# EXTENSION-CONTINUATION v1.20 §3.10 + Appendix A canonical codes.
# Per V7 §3.3 line 742's per-component scoping: engine codes belong to
# EXTENSION-CONTINUATION (this module); transport codes belong to V7 §6.12;
# handler codes belong to each handler's own appendix.
LOST_ERROR_MARKER_TYPE = "system/runtime/chain-error-lost"

# Appendix A engine codes (canonical home; v1.19 / v1.20).
ENGINE_CODE_ON_ERROR_DISPATCH_FAILED = "on_error_dispatch_failed"
ENGINE_CODE_MERGE_VALUE_NOT_MAP = "merge_value_not_map"
ENGINE_CODE_TRANSFORM_FAILED = "transform_failed"
ENGINE_CODE_CHAIN_CONSTRUCTION_INVALID = "chain_construction_invalid"

# V7 §6.12 per-request transport codes (status pinned in spec).
TRANSPORT_CODE_RECV_TIMEOUT = "recv_timeout"          # 503
TRANSPORT_CODE_CONNECTION_BROKEN = "connection_broken"  # 503
TRANSPORT_CODE_PROTOCOL_ERROR = "protocol_error"      # 502 (also §3.10.5 missing-code fallback)

# V7 §3.3 line 736 canonical 403 example. Used as both response body code
# (messages.py::ExecuteResponse.forbidden) and rejected-marker {reason}.
CODE_CAPABILITY_DENIED = "capability_denied"

CONTINUATION_HANDLER_PATTERN = "system/continuation"

# Type names
CONTINUATION_TYPE = "system/continuation"
CONTINUATION_JOIN_TYPE = "system/continuation/join"
CONTINUATION_SUSPENDED_TYPE = "system/continuation/suspended"


async def continuation_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle continuation operations (advance, resume, abandon).

    Per EXTENSION-CONTINUATION v1.9:
    - advance: Run advancement algorithm on a continuation
    - resume: Resume a suspended continuation
    - abandon: Delete suspended continuation without dispatch

    Args:
        path: The full path (should be "system/continuation").
        operation: The operation (advance, resume, abandon).
        params: Operation parameters.
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    # Extract params data (params is a full entity per spec)
    params_data = params.get("data", params) if isinstance(params, dict) else {}
    params_type = params.get("type") if isinstance(params, dict) else None

    if operation == "install":
        return await _handle_install(params_data, ctx, params_type=params_type)
    elif operation == "advance":
        return await _handle_advance(params_data, ctx)
    elif operation == "resume":
        return await _handle_resume(params_data, ctx)
    elif operation == "abandon":
        return await _handle_abandon(params_data, ctx)
    else:
        return _error_response(
            501,
            "unsupported_operation",
            f"Continuation handler does not support operation: {operation}",
        )


async def _handle_install(
    params: dict[str, Any],
    ctx: HandlerContext,
    *,
    params_type: str | None = None,
) -> dict[str, Any]:
    """Handle install operation - persist a continuation entity (CT1).

    Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-CONTINUATION-1):
    The install-request wrapper is eliminated. The caller passes the
    continuation entity itself as params — either system/continuation
    (forward) or system/continuation/join. params.type is the
    discriminator; one install op accepts both.

    Per EXTENSION-CONTINUATION v1.9 §3.2:
    1. Validate resource = single install path.
    2. Validate params is system/continuation or system/continuation/join.
    3. Validate required fields on the continuation entity.
    3b. v1.9 G1 (§2.2/§8.1): reject an unrecognized transform_ops op
        (fail-closed) — never silently skipped at advance.
    4. §3.1a in-chain authorization on params.data.dispatch_capability
       (CT2/N1): the writer's identity MUST appear as a granter anywhere
       in the collected authority chain (NOT a chain-root check — a root
       check is correct only for the local case and breaks cross-peer).
    5. Persist the continuation entity at the resource path under the
       handler grant; persist the embedded cap + full chain to the
       local content store.
    """
    # Step 1: install path comes from resource (P-CONTINUATION-1).
    targets = ctx.resource_targets or []
    if len(targets) != 1:
        return _error_response(
            400,
            "ambiguous_resource",
            "install requires exactly one resource target (the suspended continuation path)",
        )
    install_path = targets[0]

    # Step 2: validate the entity-shaped params and discriminate by type.
    if params_type not in (CONTINUATION_TYPE, CONTINUATION_JOIN_TYPE):
        return _error_response(
            400,
            "invalid_params",
            "install expects system/continuation or system/continuation/join in params",
        )

    # Step 3: validate required fields on the continuation entity.
    target = params.get("target")
    operation_name = params.get("operation")
    dispatch_capability = params.get("dispatch_capability")

    if not target or not operation_name:
        return _error_response(
            400,
            "invalid_params",
            "continuation entity must include target and operation",
        )
    if not dispatch_capability:
        return _error_response(
            400,
            "missing_dispatch_capability",
            "install requires dispatch_capability for the deferred dispatch",
        )

    # Step 3b (v1.9 G1, §2.2/§8.1): fail-closed on an invalid transform_ops
    # op. Two distinct rejection modes, both at install — never silently
    # skipped at advance (which would change dispatch behavior):
    #   * unknown op  → `400 unknown_transform_op` (v1.10 pin).
    #   * collect_keys with both `field` and `fields` set (v1.15 §2.2)
    #     → `400 invalid_transform_args`.
    transform_err = _validate_transform_ops(params.get("result_transform"))
    if transform_err is not None:
        code, detail = transform_err
        if code == "unknown_transform_op":
            return _error_response(
                400,
                code,
                f"unrecognized transform_ops op: {detail} "
                f"(closed set: {sorted(KNOWN_TRANSFORM_OPS)})",
            )
        return _error_response(400, code, detail)

    # Step 3c (v1.16 §3.2): result_merge and result_field are mutually
    # exclusive — both express "what to do with the transformed value"
    # (Merge mode vs Inject mode). Reject the ambiguous combination at
    # install with the pinned cross-impl code.
    if params.get("result_merge") is True and params.get("result_field") is not None:
        return _error_response(
            400,
            "invalid_continuation",
            "result_merge is mutually exclusive with result_field (§3.2)",
        )

    # Step 4: resolve dispatch_capability and run the §3.1a in-chain check.
    cap_entity = ctx.emit_pathway.content_store.get(dispatch_capability)
    if cap_entity is None:
        return _error_response(
            404,
            "dispatch_capability_not_found",
            "Referenced capability entity not in content store or envelope",
        )

    if (
        getattr(ctx, "author_identity_hash", None) is None
        and ctx.remote_identity_hash is None
    ):
        return _error_response(
            403,
            "no_identity",
            "Writer identity not available for chain check",
        )

    def _chain_lookup(h: Hash) -> dict[str, Any] | None:
        ent = ctx.emit_pathway.content_store.get(h)
        return ent.to_dict() if ent is not None else None

    # Unified R1 check (PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.2). One
    # walker handles reachability + identity match + chain return for
    # persistence. Persistence runs only on found=True per §3.2.
    # §3.1a / §8.1: the writer whose identity must appear in-chain is
    # `ctx.execute.data.author` — the cryptographically-verified author of
    # THIS EXECUTE (the legitimate cap holder), NOT the connect-time
    # session identity. They coincide for same-identity local flows but
    # diverge for cross-peer installs (the installer authenticates the
    # connection with one identity yet authors the install as the in-chain
    # cap-holder). Prefer the per-EXECUTE author; fall back to the session
    # identity when the dispatcher did not surface a distinct author
    # (preserves existing local/test behavior).
    writer_identity_hash = (
        ctx.author_identity_hash
        if getattr(ctx, "author_identity_hash", None) is not None
        else ctx.remote_identity_hash
    )
    auth = check_creator_authority(
        cap_entity.to_dict(), writer_identity_hash, _chain_lookup,
    )
    if auth.status != ChainCollectStatus.OK:
        return _error_response(
            404,
            "chain_unreachable",
            "dispatch_capability authority chain incomplete in envelope and content store",
        )
    if not auth.found:
        return _error_response(
            403,
            "embedded_cap_unauthorized",
            "Writer identity not in dispatch_capability authority chain",
        )

    # Persist the cap + full chain so future advance() can resolve by
    # hash without the chain travelling again.
    for chain_dict in auth.chain:
        chain_entity = Entity.from_dict(chain_dict)
        if not ctx.emit_pathway.content_store.has(chain_entity.compute_hash()):
            ctx.emit_pathway.put_content_only(chain_entity)

    # Step 5: persist the continuation entity (params is the entity data).
    continuation_entity = Entity(type=params_type, data=dict(params))

    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(install_path)
    emit_ctx = EmitContext.from_handler_grant(ctx, "install")
    ctx.emit_pathway.emit(full_uri, continuation_entity, emit_ctx)

    return {
        "status": 200,
        "result": {
            "type": "system/continuation/install-result",
            "data": {"path": install_path},
        },
    }


async def _handle_advance(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle advance operation - run advancement algorithm.

    Per EXTENSION-CONTINUATION v1.9 §3.3-§3.6:
    1. Read continuation entity at path (from resource.targets[0] per §3.1)
    2. If forward continuation: single dispatch with transform
    3. If join continuation: accumulate in slot, dispatch when complete
    4. Apply result_transform (extract/select navigation)
    5. Dispatch to target with assembled params
    6. Decrement remaining_executions via CAS
    7. Route errors to on_error if configured

    Args:
        params: Advance parameters (system/continuation/advance-request format).
        ctx: Handler context with resource_targets[0] specifying continuation path.

    Returns:
        Response dict with status and result.
    """
    # Per EXTENSION-CONTINUATION §3.1: path from resource.targets[0]
    # Fall back to params for backwards compatibility with internal dispatch
    continuation_path = None
    if ctx.resource_targets and len(ctx.resource_targets) > 0:
        continuation_path = ctx.resource_targets[0]
    if not continuation_path:
        continuation_path = params.get("continuation_path")

    # Per EXTENSION-CONTINUATION §2.5: result and status from params
    result = params.get("result")
    status = params.get("status")  # Optional, defaults to 200 in advancement

    if not continuation_path:
        return _error_response(400, "missing_path", "continuation_path is required (via resource.targets[0] or params)")

    # Read continuation from tree
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(continuation_path)
    content_hash = ctx.emit_pathway.entity_tree.get(full_uri)

    # For join continuations, the path may include a slot suffix
    # e.g., "system/inbox/my-cont/slot-a" where join is at "system/inbox/my-cont"
    slot_from_path = None
    parent_path = None
    if content_hash is None:
        # Try parent path for join slot advancement
        path_parts = continuation_path.rstrip("/").rsplit("/", 1)
        if len(path_parts) == 2:
            parent_path = path_parts[0]
            slot_from_path = path_parts[1]
            parent_uri = ctx.emit_pathway.entity_tree.normalize_uri(parent_path)
            content_hash = ctx.emit_pathway.entity_tree.get(parent_uri)
            if content_hash is not None:
                full_uri = parent_uri
                continuation_path = parent_path

    if content_hash is None:
        # No continuation at path or parent - no-op
        logger.debug(f"No continuation at {continuation_path}")
        return {
            "status": 200,
            "result": {
                "type": "system/continuation/advance-result",
                "data": {
                    "advanced": False,
                    "reason": "no_continuation",
                },
            },
        }

    continuation_entity = ctx.emit_pathway.content_store.get(content_hash)
    if continuation_entity is None:
        return _error_response(404, "continuation_not_found", f"Continuation entity not found: {continuation_path}")

    cont_type = continuation_entity.type
    cont_data = continuation_entity.data

    if cont_type == CONTINUATION_TYPE:
        # Forward continuation
        return await _advance_forward(cont_data, result, status, continuation_path, full_uri, content_hash, ctx)
    elif cont_type == CONTINUATION_JOIN_TYPE:
        # Join continuation - pass slot extracted from path
        join_params = dict(params)
        if slot_from_path and "slot" not in join_params:
            join_params["slot"] = slot_from_path
        return await _advance_join(join_params, cont_data, result, status, continuation_path, full_uri, content_hash, ctx)
    else:
        return _error_response(
            400,
            "invalid_continuation_type",
            f"Unknown continuation type: {cont_type}",
        )


async def _advance_forward(
    cont_data: dict[str, Any],
    result: Any,
    status: int | None,
    continuation_path: str,
    full_uri: str,
    content_hash: bytes,
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Advance a forward continuation (single dispatch with transform).

    Per EXTENSION-CONTINUATION v1.9 §3.4:
    - If status >= 400 and on_error is configured, route to on_error.
    - Otherwise, dispatch to target with assembled params.

    Args:
        cont_data: Continuation entity data.
        result: The result to transform and dispatch.
        status: The status code from the incoming result (None = 200).
        continuation_path: Path to the continuation.
        full_uri: Full URI of the continuation.
        content_hash: Current hash of the continuation.
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    effective_status = status or 200
    target = cont_data.get("target")
    operation = cont_data.get("operation")
    remaining = cont_data.get("remaining_executions")
    result_field = cont_data.get("result_field")
    result_transform = cont_data.get("result_transform")
    deliver_to_data = cont_data.get("deliver_to")
    on_error_data = cont_data.get("on_error")
    base_params = cont_data.get("params") or {}

    if not target or not operation:
        return _error_response(400, "invalid_continuation", "Continuation missing target or operation")

    # Check lifecycle - exhausted?
    if remaining is not None and remaining <= 0:
        return _error_response(410, "continuation_exhausted", "Continuation has no remaining executions")

    # Per EXTENSION-CONTINUATION §3.4: Error path - route to on_error if status >= 400
    if effective_status >= 400 and on_error_data:
        on_error = DeliverySpec.from_dict(on_error_data)
        try:
            await ctx.deliver_async(
                f"cont-error-{continuation_path}",
                effective_status,
                result,
                on_error,
            )
        except Exception as e:
            logger.warning(f"Error routing to on_error: {e}")
            # §3.10.2 + Appendix A: on_error dispatch itself failed — bind
            # the lost marker under the canonical engine code so the chain
            # has an observable surface. Observation only; no reactive
            # behavior. Proximate cause (the on_error result's own code)
            # carried in `cause_detail` body field, distinct from the
            # canonical `code`/`reason` which describes the chain-machinery
            # event being observed (this is the §1.2b "code = chain event,
            # cause = proximate" disambiguation Python flagged on sign-off).
            cause_detail = (
                result.get("code") if isinstance(result, dict) else None
            )
            _bind_lost_marker(
                ctx,
                code=ENGINE_CODE_ON_ERROR_DISPATCH_FAILED,
                status=effective_status,
                request_id=f"cont-error-{continuation_path}",
                continuation_path=continuation_path,
                on_error_uri=getattr(on_error, "uri", None),
                extra_body={"cause_detail": cause_detail} if cause_detail else None,
            )
        # Error delivery is best-effort, no further advancement
        return {
            "status": 200,
            "result": {
                "type": "system/continuation/advance-result",
                "data": {
                    "advanced": True,
                    "error_routed": True,
                    "original_status": effective_status,
                },
            },
        }

    # EXTENSION-CONTINUATION v1.9 §3.6 step 1: transform pipeline
    # (extract -> select -> transform_ops). The post-navigation value
    # feeds BOTH dispatch-mode assembly and the *_extract fields (§2.2).
    value = _apply_transform(result, result_transform, ctx.included)

    # §3.6 step 2: Assemble params based on dispatch mode
    # - result_merge → merge: shallow-union value into static params (v1.16)
    # - no params, no result_field → pass-through: params = value
    # - params + result_field → inject: params[result_field] = value
    # - params, no result_field → trigger: params = cont.params (ignore result)
    # - result_field without params → invalid: return 400
    result_merge = cont_data.get("result_merge") is True
    has_params = bool(base_params)
    has_result_field = result_field is not None

    if result_merge:
        # Merge mode (v1.16 §2.1 / §3.6): shallow-merge the post-transform
        # map into static params at top level; value keys win on collision.
        # result_merge + result_field is rejected at install (§3.2), so we
        # don't have to disambiguate here. A non-map value degrades to
        # static-only params and binds an observable merge_value_not_map
        # lost-error marker (§3.4) — the dispatch still proceeds.
        if isinstance(value, dict):
            params = dict(base_params)
            params.update(value)
        else:
            request_id_for_marker = (
                ctx.request_id
                if getattr(ctx, "request_id", None)
                else f"cont-merge-{continuation_path}"
            )
            # §3.10.2 + Appendix A: assembly-phase observation; the
            # `value_type` impl-specific extra carries the spec's
            # diagnostic capture (per §3.10.6 "impls MAY add additional
            # fields").
            _bind_lost_marker(
                ctx,
                code=ENGINE_CODE_MERGE_VALUE_NOT_MAP,
                status=effective_status,
                request_id=request_id_for_marker,
                continuation_path=continuation_path,
                target_uri=target,
                extra_body={"value_type": type(value).__name__},
            )
            params = dict(base_params)
    elif has_result_field and not has_params:
        # Invalid: result_field without params
        return _error_response(400, "invalid_dispatch_mode", "result_field requires params to be set")
    elif has_params and has_result_field:
        # Inject mode: insert result at field
        params = dict(base_params)
        params[result_field] = value
    elif has_params:
        # Trigger mode: use params, ignore result
        params = dict(base_params)
    else:
        # Pass-through mode: result becomes params
        if isinstance(value, dict):
            params = value
        else:
            params = {"result": value}

    # W9: Resolve dispatch_capability — required for dispatching continuations
    dispatch_cap_hash = cont_data.get("dispatch_capability")
    if dispatch_cap_hash is None:
        return _error_response(400, "missing_dispatch_capability",
            "Continuation must have dispatch_capability to dispatch")
    dispatch_cap_entity = ctx.emit_pathway.content_store.get(dispatch_cap_hash)
    if dispatch_cap_entity is None:
        return _error_response(400, "invalid_dispatch_capability",
            "dispatch_capability not found in content store")

    # §3.6 step 3: dynamic EXECUTE field extraction. target_extract /
    # operation_extract / resource_extract navigate the same post-navigation
    # value and override the static fields when present and resolving;
    # otherwise the static continuation fields are used.
    eff_target = _resolve_or_default(value, result_transform, "target_extract", target)
    eff_operation = _resolve_or_default(
        value, result_transform, "operation_extract", operation
    )
    eff_resource = _resolve_or_default_resource(
        value, result_transform, "resource_extract", cont_data.get("resource")
    )

    # Per EXTENSION-CONTINUATION §3: `target` is the handler URI;
    # `resource.targets` identifies the resource to operate on — distinct
    # fields, dispatched separately.
    dispatch_resource_targets = (
        eff_resource.get("targets")
        if isinstance(eff_resource, dict) and eff_resource.get("targets")
        else None
    )

    # §4.2 case 3: when the target is a remote peer, the dispatched EXECUTE
    # is authorized by the scoped dispatch_capability (NOT the connection
    # cap), authored by this host peer, with the full authority chain in
    # the dispatched envelope `included` (§4.3). Local/system targets are
    # unchanged (capability_data drives the local scope check; the chain
    # resolves from the install-persisted store).
    cross_peer_kwargs: dict[str, Any] = {}
    if _remote_peer_of(ctx, eff_target) is not None:
        cross_peer_kwargs = {
            "dispatch_capability_entity": dispatch_cap_entity.to_dict(),
            "dispatch_capability_chain": _dispatch_chain_bundle(
                ctx, dispatch_cap_entity
            ),
        }

    # Dispatch to target using stored capability. Transport-layer failures
    # discriminate per V7 §6.12 into recv_timeout / connection_broken /
    # protocol_error so the chain-error marker {reason} matches the
    # operationally-distinguishable failure shape (operators can match
    # specific paths without parsing bodies — §1.2b.3 granularity choice).
    try:
        dispatch_result = await ctx.execute_with_capability(
            eff_target, eff_operation, params,
            capability_data=dispatch_cap_entity.data,
            resource_targets=dispatch_resource_targets,
            **cross_peer_kwargs,
        )
    except (asyncio.TimeoutError, ConnectionError, Exception) as e:
        # V7 §6.12 code discrimination at the engine boundary (the engine
        # has the chain context; transport doesn't). The catch list is
        # listed widest-to-narrowest as written; the runtime isinstance
        # below picks the canonical code.
        if isinstance(e, asyncio.TimeoutError):
            transport_code = TRANSPORT_CODE_RECV_TIMEOUT
            transport_status = 503
        elif isinstance(e, ConnectionError):
            transport_code = TRANSPORT_CODE_CONNECTION_BROKEN
            transport_status = 503
        else:
            transport_code = TRANSPORT_CODE_PROTOCOL_ERROR
            transport_status = 502
        logger.error(
            "Error dispatching to %s (transport_code=%s): %s",
            target, transport_code, e,
        )
        # Capture origination timestamp HERE (failure observed at this site)
        # per §3.10.6 v1.20 timestamp-capture discipline.
        origination_ms = int(time.time() * 1000)
        # Route to on_error if configured.
        if on_error_data:
            on_error = DeliverySpec.from_dict(on_error_data)
            try:
                await ctx.deliver_async(
                    f"cont-error-{continuation_path}",
                    transport_status,
                    {"error": str(e), "continuation_path": continuation_path,
                     "code": transport_code},
                    on_error,
                )
            except Exception as e2:
                logger.error(f"Error routing to on_error: {e2}")
                _bind_lost_marker(
                    ctx,
                    code=ENGINE_CODE_ON_ERROR_DISPATCH_FAILED,
                    status=500,
                    request_id=f"cont-error-{continuation_path}",
                    continuation_path=continuation_path,
                    on_error_uri=getattr(on_error, "uri", None),
                    target_uri=target,
                    timestamp_ms=origination_ms,
                    extra_body={"cause_detail": transport_code},
                )
        else:
            # v1.19 §3.10.5 + V7 §6.12: bind the transport-layer lost marker
            # so a persistently-failing forward target with no on_error
            # configured is still observable (previously a silent gap in
            # Python — the dispatch raised, the 500 went back to the caller,
            # nothing was bound).
            request_id_for_marker = (
                ctx.request_id
                if getattr(ctx, "request_id", None)
                else f"cont-forward-{continuation_path}"
            )
            _bind_lost_marker(
                ctx,
                code=transport_code,
                status=transport_status,
                request_id=request_id_for_marker,
                continuation_path=continuation_path,
                target_uri=target,
                timestamp_ms=origination_ms,
                extra_body={"cause_detail": str(e)},
            )
        return _error_response(transport_status, transport_code, str(e))

    # Update lifecycle - decrement remaining_executions
    # Per spec §3.3 step 9: delete if exhausted, otherwise CAS update
    if remaining is not None:
        new_remaining = remaining - 1
        emit_ctx = EmitContext.from_handler_grant(ctx, "advance")
        if new_remaining <= 0:
            # Exhausted - delete continuation
            ctx.emit_pathway.delete(full_uri, emit_ctx)
        else:
            # Update with decremented count
            new_cont_data = dict(cont_data)
            new_cont_data["remaining_executions"] = new_remaining
            new_cont_entity = Entity(
                type=CONTINUATION_TYPE,
                data=new_cont_data,
            )
            ctx.emit_pathway.emit(full_uri, new_cont_entity, emit_ctx)

    # Chain to next step - deliver result to deliver_to
    if deliver_to_data and dispatch_result.ok:
        deliver_to = DeliverySpec.from_dict(deliver_to_data)
        try:
            await ctx.deliver_async(
                f"cont-chain-{continuation_path}",
                dispatch_result.status,
                dispatch_result.result,
                deliver_to,
            )
        except Exception as e:
            logger.error(f"Error chaining to deliver_to: {e}")

    # §3.4 forward-dispatch outcome classification (v1.10, normative).
    # The dispatch was DELIVERED — execute_with_capability returned; a
    # dispatch delivery/processing failure raises and is handled above
    # (the dispatch_result.error path). A *delivered* handler-level
    # non-2xx is a COMPLETED forward dispatch: forward dispatch is a
    # fire-and-forget closure invocation, not an RPC — the dispatched
    # response is NOT threaded back (success path either). It MUST NOT be
    # promoted to transient/permanent, retried, suspended, or routed to
    # on_error on the basis of the downstream status. remaining_executions
    # was decremented above (it counts completed dispatch attempts, not
    # successful downstream outcomes); return {status: 200, advanced: true}.
    #
    # v1.19 §3.10.5 (was v1.13 §3.4 I-8): when no `on_error` is configured
    # and the forward dispatch completed with status ≥ 400, bind a lost
    # marker so the chain has an observable surface. The `{reason}` IS
    # `result.data.code` per the single-rule code-as-reason convention —
    # this replaces v1.13's `forward_dispatch_non2xx` catch-all that
    # clobbered distinct codes (different non-2xx outcomes at the same
    # chain step landed at the same path; subscribers saw the wrong one).
    # Missing `code` fallback per §3.10.5 → `protocol_error` (V7 §6.12;
    # the missing-code condition IS a handler-side protocol violation).
    # v1.20: timestamp captured at observation-origination here (right
    # after dispatch returns) per §3.10.6 discipline.
    if on_error_data is None and dispatch_result.status >= 400:
        dispatch_code = _extract_response_code(dispatch_result.result)
        origination_ms = int(time.time() * 1000)
        # CONTINUATION v1.14 §3.4: {step_index} MUST be the original
        # request_id of the forward dispatch — pinned cross-impl. Fall
        # back to a continuation-keyed string only when the EXECUTE
        # wasn't carrying a request_id (synthesized internal dispatch).
        request_id_for_marker = (
            ctx.request_id
            if getattr(ctx, "request_id", None)
            else f"cont-forward-{continuation_path}"
        )
        _bind_lost_marker(
            ctx,
            code=dispatch_code or TRANSPORT_CODE_PROTOCOL_ERROR,
            status=int(dispatch_result.status),
            request_id=request_id_for_marker,
            continuation_path=continuation_path,
            target_uri=eff_target,
            timestamp_ms=origination_ms,
        )

    return {
        "status": 200,
        "result": {
            "type": "system/continuation/advance-result",
            "data": {
                "advanced": True,
                "target": target,
                "operation": operation,
                # Observational only — NOT an error signal (§3.4 v1.10).
                "dispatch_status": dispatch_result.status,
            },
        },
    }


async def _advance_join(
    params: dict[str, Any],
    cont_data: dict[str, Any],
    result: Any,
    status: int | None,
    continuation_path: str,
    full_uri: str,
    content_hash: bytes,
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Advance a join continuation (fan-in from multiple sources).

    Args:
        params: Advance parameters (may contain slot).
        cont_data: Continuation entity data.
        result: The result to accumulate.
        status: The status code from the incoming result (stored with result).
        continuation_path: Path to the continuation.
        full_uri: Full URI of the continuation.
        content_hash: Current hash of the continuation.
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    target = cont_data.get("target")
    operation = cont_data.get("operation")
    expected = cont_data.get("expected", [])
    received = dict(cont_data.get("received") or {})
    remaining = cont_data.get("remaining_executions")
    deliver_to_data = cont_data.get("deliver_to")
    on_error_data = cont_data.get("on_error")

    if not target or not operation:
        return _error_response(400, "invalid_continuation", "Continuation missing target or operation")

    # Check lifecycle - exhausted?
    if remaining is not None and remaining <= 0:
        return _error_response(410, "continuation_exhausted", "Continuation has no remaining executions")

    # Extract slot from params or path
    slot = params.get("slot")
    if slot is None:
        # Try to extract slot from path suffix
        # e.g., system/inbox/my-cont/slot-a -> slot-a
        path_parts = continuation_path.rstrip("/").split("/")
        if len(path_parts) > 0:
            slot = path_parts[-1]

    if not slot or slot not in expected:
        return _error_response(400, "invalid_slot", f"Invalid or missing slot: {slot}")

    # Exactly-once: reject if slot already filled
    if slot in received:
        return _error_response(409, "slot_already_filled", f"Slot {slot} already received")

    # Accumulate result in slot
    received[slot] = result

    # Check if all slots filled
    if set(received.keys()) == set(expected):
        # All slots filled - dispatch to target
        logger.debug(f"Join continuation complete: {continuation_path}")

        # W9: Resolve dispatch_capability — required for dispatching continuations
        dispatch_cap_hash = cont_data.get("dispatch_capability")
        if dispatch_cap_hash is None:
            return _error_response(400, "missing_dispatch_capability",
                "Continuation must have dispatch_capability to dispatch")
        dispatch_cap_entity = ctx.emit_pathway.content_store.get(dispatch_cap_hash)
        if dispatch_cap_entity is None:
            return _error_response(400, "invalid_dispatch_capability",
                "dispatch_capability not found in content store")

        # Per EXTENSION-CONTINUATION v1.9 §3: `resource.targets` carries
        # the dispatch resource path, not `target`.
        resource_data = cont_data.get("resource")
        dispatch_resource_targets = (
            resource_data.get("targets")
            if isinstance(resource_data, dict) and resource_data.get("targets")
            else None
        )

        # §4.2 case 3 cross-peer: scoped dispatch_capability + full chain on
        # the wire, authored by this host peer (see _advance_forward).
        cross_peer_kwargs: dict[str, Any] = {}
        if _remote_peer_of(ctx, target) is not None:
            cross_peer_kwargs = {
                "dispatch_capability_entity": dispatch_cap_entity.to_dict(),
                "dispatch_capability_chain": _dispatch_chain_bundle(
                    ctx, dispatch_cap_entity
                ),
            }

        # Dispatch with all accumulated results as params. Transport-layer
        # failure discrimination per V7 §6.12 — mirror of _advance_forward
        # so the join terminal dispatch produces the same observability
        # shape as the forward dispatch.
        try:
            dispatch_result = await ctx.execute_with_capability(
                target, operation, received,
                capability_data=dispatch_cap_entity.data,
                resource_targets=dispatch_resource_targets,
                **cross_peer_kwargs,
            )
        except (asyncio.TimeoutError, ConnectionError, Exception) as e:
            if isinstance(e, asyncio.TimeoutError):
                transport_code = TRANSPORT_CODE_RECV_TIMEOUT
                transport_status = 503
            elif isinstance(e, ConnectionError):
                transport_code = TRANSPORT_CODE_CONNECTION_BROKEN
                transport_status = 503
            else:
                transport_code = TRANSPORT_CODE_PROTOCOL_ERROR
                transport_status = 502
            logger.error(
                "Error dispatching join to %s (transport_code=%s): %s",
                target, transport_code, e,
            )
            origination_ms = int(time.time() * 1000)
            if on_error_data:
                on_error = DeliverySpec.from_dict(on_error_data)
                try:
                    await ctx.deliver_async(
                        f"cont-error-{continuation_path}",
                        transport_status,
                        {"error": str(e), "continuation_path": continuation_path,
                         "code": transport_code},
                        on_error,
                    )
                except Exception as e2:
                    logger.error(f"Error routing to on_error: {e2}")
                    _bind_lost_marker(
                        ctx,
                        code=ENGINE_CODE_ON_ERROR_DISPATCH_FAILED,
                        status=500,
                        request_id=f"cont-error-{continuation_path}",
                        continuation_path=continuation_path,
                        on_error_uri=getattr(on_error, "uri", None),
                        target_uri=target,
                        timestamp_ms=origination_ms,
                        extra_body={"cause_detail": transport_code},
                    )
            else:
                request_id_for_marker = (
                    ctx.request_id
                    if getattr(ctx, "request_id", None)
                    else f"cont-join-{continuation_path}"
                )
                _bind_lost_marker(
                    ctx,
                    code=transport_code,
                    status=transport_status,
                    request_id=request_id_for_marker,
                    continuation_path=continuation_path,
                    target_uri=target,
                    timestamp_ms=origination_ms,
                    extra_body={"cause_detail": str(e)},
                )
            return _error_response(transport_status, transport_code, str(e))

        # Update lifecycle
        if remaining is not None:
            new_cont_data = dict(cont_data)
            new_cont_data["remaining_executions"] = remaining - 1
            new_cont_data["received"] = {}  # Reset for next round
            new_cont_entity = Entity(
                type=CONTINUATION_JOIN_TYPE,
                data=new_cont_data,
            )
            emit_ctx = EmitContext.from_handler_grant(ctx, "advance")
            ctx.emit_pathway.emit(full_uri, new_cont_entity, emit_ctx)

        # Chain to deliver_to
        if deliver_to_data and dispatch_result.ok:
            deliver_to = DeliverySpec.from_dict(deliver_to_data)
            try:
                await ctx.deliver_async(
                    f"cont-chain-{continuation_path}",
                    dispatch_result.status,
                    dispatch_result.result,
                    deliver_to,
                )
            except Exception as e:
                logger.error(f"Error chaining to deliver_to: {e}")

        # §3.4 forward-dispatch outcome classification (v1.10, normative):
        # the join's terminal dispatch was DELIVERED (a delivery/processing
        # failure raises and is handled above). A delivered handler-level
        # non-2xx is a COMPLETED forward dispatch — not threaded back, not
        # promoted to transient/permanent, not routed to on_error on the
        # basis of the downstream status. Return {status: 200, advanced}.
        return {
            "status": 200,
            "result": {
                "type": "system/continuation/advance-result",
                "data": {
                    "advanced": True,
                    "join_complete": True,
                    "target": target,
                    "operation": operation,
                    # Observational only — NOT an error signal (§3.4 v1.10).
                    "dispatch_status": dispatch_result.status,
                },
            },
        }
    else:
        # Not all slots filled - update and wait
        new_cont_data = dict(cont_data)
        new_cont_data["received"] = received
        new_cont_entity = Entity(
            type=CONTINUATION_JOIN_TYPE,
            data=new_cont_data,
        )
        emit_ctx = EmitContext.from_handler_grant(ctx, "advance")
        ctx.emit_pathway.emit(full_uri, new_cont_entity, emit_ctx)

        return {
            "status": 200,
            "result": {
                "type": "system/continuation/advance-result",
                "data": {
                    "advanced": False,
                    "accumulated": True,
                    "slot": slot,
                    "received_slots": list(received.keys()),
                    "expected_slots": expected,
                },
            },
        }


# EXTENSION-CONTINUATION v1.9 §2.2 (G1): the closed, total, pure, bounded
# transform-op set. An unrecognized `op` MUST be rejected at install
# (fail-closed) — never silently skipped.
#
# v1.15: `collect_keys` added (PROPOSAL-CONTINUATION-COLLECT-KEYS).
# Projects a map's keys (singular `field`) or several maps' keys
# (plural `fields:[...]`, concatenated in list order) into an array at
# `into`. Used to thread `tree:diff` results (`added`, `changed`) into
# `tree:extract.paths` without an opaque handler step. Field navigation
# follows the dotted-path rules from `extract`.
KNOWN_TRANSFORM_OPS = frozenset(
    {
        "strip_prefix",
        "prepend",
        "append",
        "join",
        "replace_literal",
        "split",
        "slice",
        "collect_keys",
        # v1.17 (§2.2): reads `field` as a system/hash and replaces it with
        # the entity bound to that hash in the *envelope's* `included` map —
        # in-flight envelope navigation (pure: a function of the input value +
        # the request's `included`), not a tree/store read. Lets a chain
        # consume an `include_payload`-delivered entity (EXTENSION-SUBSCRIPTION
        # §2.2) into a tree:put without an opaque handler step.
        "deref_included",
    }
)

# Navigation sentinel — distinguishes "path missed" from a legitimate null.
_MISSING = object()


def _navigate(obj: Any, path: str) -> Any:
    """Navigate a dotted path. Returns _MISSING when any segment is absent."""
    if not path:
        return obj
    current = obj
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _navigate_path(obj: Any, path: str) -> Any:
    """Navigate a dotted path, returning None when not found (legacy shape)."""
    value = _navigate(obj, path)
    return None if value is _MISSING else value


def _slice_by_range(seq: Any, range_spec: str) -> Any:
    """Bounded `start:end` slice (either side optional). Total — clamps."""
    if not isinstance(seq, (str, list)):
        return seq
    start_s, _, end_s = range_spec.partition(":")
    try:
        start = int(start_s) if start_s.strip() else None
        end = int(end_s) if end_s.strip() else None
    except ValueError:
        return seq
    return seq[start:end]


def _apply_transform_ops(
    value: Any,
    ops: list[dict[str, Any]],
    included: dict[bytes, dict[str, Any]] | None = None,
) -> Any:
    """Apply the v1.9 bounded field-op list (§2.2 G1).

    Total/pure/bounded. Ops read/write named fields of the post-navigation
    map; a missing field is a documented no-op. A non-map `value` has no
    named fields, so every op is a no-op (returns it unchanged). An
    unrecognized op raises — install validates fail-closed before advance,
    so this is defense-in-depth.

    `included` is the request envelope's included map (V7 §3.3 v7.51) — the
    `deref_included` op (v1.17) resolves a hash field against it. It is a pure
    input (part of the request, not the tree); empty/None when no entities
    were bundled.
    """
    if not ops:
        return value
    if not isinstance(value, dict):
        return value
    included = included or {}
    out = dict(value)
    for op in ops:
        name = op.get("op")
        if name not in KNOWN_TRANSFORM_OPS:
            raise ValueError(f"unrecognized transform op: {name!r}")
        field = op.get("field")
        if name == "strip_prefix":
            s = out.get(field)
            prefix = op.get("prefix", "")
            if isinstance(s, str) and prefix and s.startswith(prefix):
                out[field] = s[len(prefix):]
        elif name == "prepend":
            s = out.get(field)
            if isinstance(s, str):
                out[field] = op.get("literal", "") + s
        elif name == "append":
            s = out.get(field)
            if isinstance(s, str):
                out[field] = s + op.get("literal", "")
        elif name == "join":
            parts = [str(out.get(f, "")) for f in (op.get("fields") or [])]
            out[op.get("into", field)] = op.get("sep", "").join(parts)
        elif name == "replace_literal":
            s = out.get(field)
            if isinstance(s, str):
                out[field] = s.replace(op.get("from", ""), op.get("to", ""))
        elif name == "split":
            s = out.get(field)
            if isinstance(s, str):
                out[op.get("into", field)] = s.split(op.get("sep", ""))
        elif name == "slice":
            s = out.get(field)
            if isinstance(s, (str, list)):
                out[op.get("into", field)] = _slice_by_range(s, op.get("range", ""))
        elif name == "collect_keys":
            # v1.15 (§2.2): project map key(s) into an array at `into`.
            # Mutual exclusivity (`field` vs `fields`) was enforced at install
            # by `_validate_transform_ops`; here we just dispatch on shape.
            # Field navigation follows the dotted-path rules from `extract`.
            into = op.get("into")
            if not into:
                # Empty/missing `into` is a silent no-op per the best-effort rule.
                continue
            fields_list = op.get("fields")
            if isinstance(fields_list, list):
                # Plural: navigate each, project keys, concatenate in list order.
                # Missing/non-map entries are individually skipped; surviving
                # maps' keys are concatenated. All-missing → empty array.
                keys: list[Any] = []
                for f in fields_list:
                    sub = _navigate(out, f) if isinstance(f, str) else _MISSING
                    if sub is not _MISSING and isinstance(sub, dict):
                        keys.extend(sub.keys())
                out[into] = keys
            elif isinstance(field, str):
                # Singular: navigate one map's keys. Missing/non-map → no-op
                # (don't write `into`); empty map → empty array (write).
                sub = _navigate(out, field)
                if sub is not _MISSING and isinstance(sub, dict):
                    out[into] = list(sub.keys())
            # else: neither `field` nor `fields` present → silent no-op.
        elif name == "deref_included":
            # v1.17 (§2.2): read `field` as a system/hash, replace it with the
            # entity bound to that hash in the envelope's `included` map.
            # Best-effort no-op on a missing field, a non-hash value, or a hash
            # absent from `included` (does not assume a fixed hash length —
            # system/hash is variable-length, V7 §1.2). Pure: reads the
            # request's included map, never the tree/store.
            ref = out.get(field)
            if is_hash_ref(ref):
                entity = included.get(ref)
                if entity is not None:
                    out[op.get("into", field)] = entity
    return out


def _validate_transform_ops(transform: Any) -> tuple[str, str] | None:
    """Return (error_code, detail) for the first invalid op, or None.

    Install-time fail-closed gate. Detects two distinct rejection modes,
    each with its own pinned error-code string (cross-impl conformance):

    - `unknown_transform_op` (§2.2 / §8.1, v1.10): an unrecognized `op`
      MUST be rejected at install, never silently skipped at advance.
    - `invalid_transform_args` (§2.2, v1.15): `collect_keys` MUST NOT
      carry both `field` and `fields`. Reject at install if both present.
    """
    if not isinstance(transform, dict):
        return None
    ops = transform.get("transform_ops")
    if not isinstance(ops, list):
        return None
    for op in ops:
        if not isinstance(op, dict):
            return ("unknown_transform_op", repr(op))
        name = op.get("op")
        if name not in KNOWN_TRANSFORM_OPS:
            return ("unknown_transform_op", repr(name))
        if name == "collect_keys" and "field" in op and "fields" in op:
            return (
                "invalid_transform_args",
                "collect_keys: field and fields are mutually exclusive",
            )
    return None


def _apply_transform(
    result: Any,
    transform: Any,
    included: dict[bytes, dict[str, Any]] | None = None,
) -> Any:
    """Run the transform pipeline: extract -> select -> transform_ops.

    Per EXTENSION-CONTINUATION v1.9 §2.2 / §3.6 step 1. Best-effort
    structural navigation — transforms never produce errors:
    - transform is None: result as-is
    - transform is str: navigate (legacy shorthand for `extract`); on miss,
      pass the original result through
    - transform is dict: `extract` (miss -> original passes through), then
      `select` (each missed source -> null in the produced map), then
      `transform_ops`

    The returned value is what both dispatch-mode assembly AND the
    `*_extract` fields operate on (§2.2: they share the post-navigation
    value).
    """
    if transform is None:
        return result

    if isinstance(transform, str):
        navigated = _navigate(result, transform)
        return result if navigated is _MISSING else navigated

    if not isinstance(transform, dict):
        return result

    value = result
    if transform.get("extract") is not None:
        navigated = _navigate(value, transform["extract"])
        if navigated is not _MISSING:
            value = navigated
        # else: best-effort — original value passes through (§2.2)

    if transform.get("select") is not None:
        value = {
            dest: _navigate_path(value, src)
            for dest, src in transform["select"].items()
        }

    transform_ops = transform.get("transform_ops")
    if transform_ops:
        value = _apply_transform_ops(value, transform_ops, included)

    return value


def _resolve_or_default(
    value: Any, transform: Any, field_name: str, default: Any
) -> Any:
    """Resolve a `*_extract` dotted path, falling back to a static default.

    Per EXTENSION-CONTINUATION v1.9 §3.6. `*_extract` only applies when
    the transform is a dict carrying the field; absent path, navigation
    miss, or a null result all fall back to `default`.
    """
    if not isinstance(transform, dict):
        return default
    extract_path = transform.get(field_name)
    if not extract_path:
        return default
    extracted = _navigate(value, extract_path)
    if extracted is _MISSING or extracted is None:
        return default
    return extracted


def _resolve_or_default_resource(
    value: Any, transform: Any, field_name: str, default: Any
) -> Any:
    """Resolve `resource_extract`, wrapping the value into a resource-target.

    Per EXTENSION-CONTINUATION v1.9 §3.6: string -> {targets: [v]};
    array -> {targets: v}; an object already carrying `targets` is used
    as-is; anything else falls back to the static `default`.
    """
    if not isinstance(transform, dict):
        return default
    extract_path = transform.get(field_name)
    if not extract_path:
        return default
    extracted = _navigate(value, extract_path)
    if extracted is _MISSING or extracted is None:
        return default
    if isinstance(extracted, str):
        return {"targets": [extracted]}
    if isinstance(extracted, list):
        return {"targets": extracted}
    if isinstance(extracted, dict) and extracted.get("targets") is not None:
        return extracted
    return default


def _remote_peer_of(ctx: HandlerContext, target: Any) -> str | None:
    """Return the remote peer_id if `target` addresses a different peer.

    EXTENSION-CONTINUATION §4.2 case 3: a cross-peer dispatch must put the
    scoped `dispatch_capability` + full chain on the wire (and is authored
    by this host peer). A local/same-peer target resolves the chain from
    the install-persisted store and is unchanged — return None for it.
    """
    if not isinstance(target, str):
        return None
    if target.startswith("entity://"):
        peer = target[len("entity://"):].split("/", 1)[0]
    elif target.startswith("/"):
        peer = target[1:].split("/", 1)[0]
    else:
        return None
    if peer and peer != ctx.local_peer_id:
        return peer
    return None


def _dispatch_chain_bundle(
    ctx: HandlerContext, leaf_cap: Entity
) -> list[dict[str, Any]]:
    """Collect the full authority-chain bundle for a cross-peer dispatch
    (§4.3): leaf cap → B-recognized root, plus each link's granter
    identity and the signature bound at the V7 invariant pointer path
    `{signer_peer_id}/system/signature/{target_hex}` (what envelope ingest
    bound at install). Python analog of Go `CollectChainBundle`.
    """
    cs = ctx.emit_pathway.content_store
    tree = ctx.emit_pathway.entity_tree

    def _entity_lookup(h: Any) -> dict[str, Any] | None:
        ent = cs.get(h)
        return ent.to_dict() if ent is not None else None

    def _bound_sig_lookup(signer_peer_id: str, target: bytes) -> dict[str, Any] | None:
        path = invariant_signature_path(signer_peer_id, target)
        sig_hash = tree.get(tree.normalize_uri(path))
        if sig_hash is None:
            return None
        ent = cs.get(sig_hash)
        return ent.to_dict() if ent is not None else None

    return collect_chain_bundle(
        leaf_cap.to_dict(),
        entity_lookup=_entity_lookup,
        bound_signature_lookup=_bound_sig_lookup,
    )


def _bind_chain_error_marker(
    ctx: HandlerContext,
    *,
    kind: str,
    code: str,
    status: int,
    request_id: str,
    timestamp_ms: int | None = None,
    extra_body: dict[str, Any] | None = None,
) -> bytes | None:
    """Bind a chain-error marker per EXTENSION-CONTINUATION v1.20 §3.10.

    Path (v1.20 §3.10.1):
        ``system/runtime/chain-errors/{kind}/{chain_id}/{step_index}/{reason}/{marker_hash}``

    Where ``{marker_hash}`` is the marker entity's own ``content_hash`` in
    V7 §3.5 invariant-pointer hex form (`bytes.hex()` — lowercase, format-
    code byte included; reuses the same encoding `invariant_signature_path`
    already produces). Terminal hex segment means each distinct occurrence
    lands at its own path; the tree IS the event log; identical-bytes
    redelivery dedupes by content_hash → same path → genuine `tree:put`
    no-op (§3.10.6 timestamp-capture discipline).

    Per §3.10.5 single rule: ``{reason}`` is the ``code`` value verbatim
    (sanitized for path-safety via :func:`_sanitize_reason`; sentinel-
    substituted to ``unspecified_error`` if non-conformant, with raw value
    preserved in body's ``code`` field).

    Per §3.10.6 body-fields registry (cross-impl content-hash convergence):
    reserved fields are ``reason``, ``code``, ``timestamp``, ``chain_id``,
    ``step_index``, ``status``; impls MAY add additional fields via
    ``extra_body`` for impl-specific context.

    Per §3.10.6 timestamp-capture discipline (v1.20 normative): callers
    SHOULD pass ``timestamp_ms`` captured at failure-origination time so
    subscription redelivery of the same logical event produces bytes-
    identical bodies (dedup by content_hash). When omitted, defaults to
    ``time.time() * 1000`` at bind site — safe for Python today because
    observation and bind are co-located (no internal redelivery layer
    between them), but future redelivery layers MUST pass origination time.

    Per §3.10.7 component-owned authority (behavioral, not mechanism):
    uses ``EmitContext.from_handler_grant`` which routes the bind under
    the dispatching component's own authority — caller's propagated cap
    does NOT participate, so a cap-rejected variant can record itself.

    Per §3.10.8 + F11 / Class B bind-failure visibility (already landed
    cross-impl): both the exception path and the non-200 ``EmitResult.status``
    path log ``F11: ... FAILED ...`` so operators chasing a stalled chain
    have an observable surface. Best-effort: never raises, never affects
    advancement.

    Returns the bound marker's ``content_hash`` (so callers building a
    mirror-pointer per §3.10.4 can stash it on the wire response), or
    ``None`` if the bind failed.
    """
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    chain_id = getattr(ctx, "chain_id", None) or "unknown"
    sanitized_reason = _sanitize_reason(code)
    marker_path = "<unknown>"
    try:
        marker_data: dict[str, Any] = {
            # §3.10.6 reserved across both kinds (denormalized for in-body
            # inspection without path parsing).
            "reason": sanitized_reason,
            "code": code,  # raw code; equals reason when path-safe
            "status": status,
            "timestamp": timestamp_ms,
            "chain_id": chain_id,
            "step_index": request_id,
        }
        if extra_body:
            marker_data.update(extra_body)
        marker = Entity(type=LOST_ERROR_MARKER_TYPE, data=marker_data)
        marker_hash = marker.compute_hash()
        marker_path = (
            f"system/runtime/chain-errors/{kind}/{chain_id}/{request_id}/"
            f"{sanitized_reason}/{marker_hash.hex()}"
        )
        uri = ctx.emit_pathway.entity_tree.normalize_uri(marker_path)
        emit_ctx = EmitContext.from_handler_grant(ctx, "advance")
        result = ctx.emit_pathway.emit(uri, marker, emit_ctx)
        if result.status != 200:
            logger.warning(
                "F11: chain-error marker bind FAILED at %s "
                "(kind=%s, reason=%s, status=%d) — observability surface lost",
                marker_path, kind, sanitized_reason, result.status,
            )
            return None
        return marker_hash
    except Exception as exc:  # never let observability affect advancement
        logger.warning(
            "F11: chain-error marker bind FAILED at %s "
            "(kind=%s, reason=%s) — observability surface lost: %s",
            marker_path, kind, sanitized_reason, exc,
        )
        return None


def bind_dispatcher_rejected_marker(
    emit_pathway: Any,
    peer_id: str,
    *,
    chain_id: str | None,
    request_id: str,
    code: str,
    status: int,
    requesting_peer_id: str | None,
    attempted_uri: str | None,
    timestamp_ms: int | None = None,
    extra_body: dict[str, Any] | None = None,
) -> bytes | None:
    """Dispatcher-side ``rejected`` marker bind for the WB-27 cap-rejection path.

    Per EXTENSION-CONTINUATION v1.20 §3.10.3 (rejected variant scope):
    only fires when the inbound EXECUTE carries ``Bounds.chain_id`` —
    caller MUST gate. Per §3.10.7 component-owned authority + Q-C:
    "core protocol owns its own ``core/chain-errors`` internal_scope
    grant"; mechanism is impl-private. Python uses
    ``EmitContext.protocol(author=peer_id, source='handler')`` —
    binding under the local peer's own identity at the dispatcher
    layer, never the caller's propagated cap (the cap was just
    rejected, so by definition it cannot write the marker).

    Returns the bound marker's ``content_hash`` so the dispatcher can
    include it in the response's ``ErrorData.rejected_marker`` per
    §3.10.4 mirror-pointer SHOULD, or ``None`` if the bind failed (per
    §3.10.8 best-effort; logged via F11 surface but never raised).

    Parameter shape mirrors :func:`_bind_lost_marker` but takes raw
    ``emit_pathway`` + ``peer_id`` instead of a :class:`HandlerContext`
    because the dispatcher-level call site doesn't construct one (the
    cap-rejection happens before any handler is invoked).
    """
    from entity_core.storage.emit import EmitContext as _EmitContext

    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    chain_id_value = chain_id or "unknown"
    sanitized_reason = _sanitize_reason(code)
    marker_path = "<unknown>"
    try:
        marker_data: dict[str, Any] = {
            "reason": sanitized_reason,
            "code": code,
            "status": status,
            "timestamp": timestamp_ms,
            "chain_id": chain_id_value,
            "step_index": request_id,
        }
        # §3.10.6 rejected-kind reserved fields.
        if requesting_peer_id is not None:
            marker_data["requesting_peer_id"] = requesting_peer_id
        if attempted_uri is not None:
            marker_data["attempted_uri"] = attempted_uri
        if extra_body:
            marker_data.update(extra_body)
        marker = Entity(type=LOST_ERROR_MARKER_TYPE, data=marker_data)
        marker_hash = marker.compute_hash()
        marker_path = (
            f"system/runtime/chain-errors/rejected/{chain_id_value}/"
            f"{request_id}/{sanitized_reason}/{marker_hash.hex()}"
        )
        uri = emit_pathway.entity_tree.normalize_uri(marker_path)
        # Dispatcher-level binding authority — protocol context, NOT
        # handler context (cap-rejection is pre-handler).
        emit_ctx = _EmitContext.protocol(
            author=peer_id, handler_pattern=None, operation="reject",
        )
        result = emit_pathway.emit(uri, marker, emit_ctx)
        if result.status != 200:
            logger.warning(
                "F11: rejected marker bind FAILED at %s "
                "(reason=%s, status=%d) — observability surface lost",
                marker_path, sanitized_reason, result.status,
            )
            return None
        return marker_hash
    except Exception as exc:  # never let observability affect dispatch
        logger.warning(
            "F11: rejected marker bind FAILED at %s "
            "(reason=%s) — observability surface lost: %s",
            marker_path, sanitized_reason, exc,
        )
        return None


def _bind_lost_marker(
    ctx: HandlerContext,
    *,
    code: str,
    status: int,
    request_id: str,
    continuation_path: str | None = None,
    on_error_uri: str | None = None,
    target_uri: str | None = None,
    target_peer_id: str | None = None,
    rejected_marker_hash: bytes | None = None,
    timestamp_ms: int | None = None,
    extra_body: dict[str, Any] | None = None,
) -> bytes | None:
    """Convenience wrapper around :func:`_bind_chain_error_marker` for the
    ``lost`` kind (sender-side / originator-side).

    Populates the §3.10.6 lost-kind reserved fields when provided
    (``target_uri``, ``target_peer_id``) plus the v1.20 mirror-pointer
    field ``rejected_marker_hash`` when the lost marker mirrors a peer's
    rejected marker (§3.10.4 cross-peer audit pair).

    ``continuation_path`` + ``on_error_uri`` are Python-impl-specific
    extras (per §3.10.6 "impls MAY add additional fields for impl-specific
    context; consumers treat unknown fields as informational").
    """
    body_extras: dict[str, Any] = {}
    if continuation_path is not None:
        body_extras["continuation_path"] = continuation_path
    if on_error_uri is not None:
        body_extras["on_error_uri"] = on_error_uri
    if target_uri is not None:
        body_extras["target_uri"] = target_uri
    if target_peer_id is not None:
        body_extras["target_peer_id"] = target_peer_id
    if rejected_marker_hash is not None:
        body_extras["rejected_marker_hash"] = rejected_marker_hash
    if extra_body:
        body_extras.update(extra_body)
    return _bind_chain_error_marker(
        ctx,
        kind="lost",
        code=code,
        status=status,
        request_id=request_id,
        timestamp_ms=timestamp_ms,
        extra_body=body_extras,
    )


async def _handle_resume(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle resume operation - resume a suspended continuation.

    Per EXTENSION-CONTINUATION v1.9 §3.7:
    - Path comes from resource.targets[0] (the suspended entity path)
    - Read suspended state entity
    - Re-dispatch the original request
    - Delete suspended entity on success

    Args:
        params: Resume parameters (may contain result).
        ctx: Handler context with resource_targets[0] specifying suspended entity path.

    Returns:
        Response dict with status and result.
    """
    # Per spec §3.6: path from resource.targets[0], fallback to params
    suspended_path = None
    if ctx.resource_targets and len(ctx.resource_targets) > 0:
        suspended_path = ctx.resource_targets[0]
    if not suspended_path:
        suspended_path = params.get("suspended_path")
    if not suspended_path:
        # Legacy: try suspension_id
        suspension_id = params.get("suspension_id")
        if suspension_id:
            suspended_path = f"system/continuation/suspended/{suspension_id}"

    if not suspended_path:
        return _error_response(400, "missing_path", "suspended entity path is required (via resource.targets[0])")

    # Read suspended state
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(suspended_path)
    content_hash = ctx.emit_pathway.entity_tree.get(full_uri)

    if content_hash is None:
        return _error_response(404, "not_found", f"Suspended continuation not found: {suspended_path}")

    suspended_entity = ctx.emit_pathway.content_store.get(content_hash)
    if suspended_entity is None:
        return _error_response(404, "not_found", f"Suspended continuation entity missing: {suspended_path}")

    if suspended_entity.type != CONTINUATION_SUSPENDED_TYPE:
        return _error_response(400, "invalid_type", f"Entity is not a suspended continuation: {suspended_entity.type}")

    suspended_data = suspended_entity.data

    # Per spec §3.6: re-dispatch original request stored in suspended entity
    target = suspended_data.get("target")
    operation = suspended_data.get("operation")
    resource = suspended_data.get("resource")
    stored_params = suspended_data.get("params")

    if not target or not operation:
        return _error_response(400, "invalid_suspended", "Suspended continuation missing target or operation")

    # Delete suspended entity first
    emit_ctx = EmitContext.from_handler_grant(ctx, "resume")
    ctx.emit_pathway.delete(full_uri, emit_ctx)

    # Re-dispatch the original request
    try:
        dispatch_result = await ctx.execute(target, operation, stored_params)
    except Exception as e:
        logger.error(f"Error re-dispatching suspended request to {target}: {e}")
        return _error_response(500, "dispatch_error", str(e))

    return {
        "status": dispatch_result.status,
        "result": {
            "type": "system/continuation/resume-result",
            "data": {
                "resumed": True,
                "target": target,
                "operation": operation,
                "dispatch_status": dispatch_result.status,
                "dispatch_result": dispatch_result.result,
            },
        },
    }


async def _handle_abandon(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle abandon operation - delete suspended continuation without dispatch.

    Per EXTENSION-CONTINUATION v1.9 §3.8:
    - Path comes from resource.targets[0] (the suspended entity path)
    - Verify entity is a suspended continuation
    - Delete entity from tree
    - Return 200

    Args:
        params: Abandon parameters (unused).
        ctx: Handler context with resource_targets[0] specifying suspended entity path.

    Returns:
        Response dict with status and result.
    """
    # Per spec §3.7: path from resource.targets[0], fallback to params
    suspended_path = None
    if ctx.resource_targets and len(ctx.resource_targets) > 0:
        suspended_path = ctx.resource_targets[0]
    if not suspended_path:
        suspended_path = params.get("suspended_path")
    if not suspended_path:
        # Legacy: try suspension_id
        suspension_id = params.get("suspension_id")
        if suspension_id:
            suspended_path = f"system/continuation/suspended/{suspension_id}"

    if not suspended_path:
        return _error_response(400, "missing_path", "suspended entity path is required (via resource.targets[0])")

    # Read suspended state to verify it exists and is correct type
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(suspended_path)
    content_hash = ctx.emit_pathway.entity_tree.get(full_uri)

    if content_hash is None:
        return _error_response(404, "not_found", f"Suspended continuation not found: {suspended_path}")

    suspended_entity = ctx.emit_pathway.content_store.get(content_hash)
    if suspended_entity is None:
        return _error_response(404, "not_found", f"Suspended continuation entity missing: {suspended_path}")

    # Per spec §3.7: verify type is suspended - reject with 400 if not
    if suspended_entity.type != CONTINUATION_SUSPENDED_TYPE:
        return _error_response(400, "invalid_type", f"Entity is not a suspended continuation: {suspended_entity.type}")

    # Delete suspended entity
    emit_ctx = EmitContext.from_handler_grant(ctx, "abandon")
    ctx.emit_pathway.delete(full_uri, emit_ctx)

    return {
        "status": 200,
        "result": {
            "type": "system/continuation/abandon-result",
            "data": {
                "abandoned": True,
                "path": suspended_path,
            },
        },
    }
