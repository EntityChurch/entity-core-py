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
import hashlib
import secrets
import time
import weakref
from typing import Any

from entity_core.protocol.bounds import (
    Bounds,
    BUDGET_EXHAUSTED_CODE,
    BUDGET_EXHAUSTED_MESSAGE,
    TTL_EXHAUSTED_CODE,
    TTL_EXHAUSTED_MESSAGE,
)
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
from entity_core.utils.path import invariant_signature_path, sanitize_path_segment
from entity_handlers.manifest import error_response as _error_response

logger = logging.getLogger(__name__)


# EXTENSION-CONTINUATION v1.20 §3.10.5 path-safety. V7 §1.4 path-segment
# rules: UTF-8; no null bytes; no empty; no embedded `/`. Conservative
# subset (matches cross-impl convergence on `[a-zA-Z0-9_.-]+`).
_PATH_SAFE_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")


def _synthesized_step_key(kind: str, continuation_path: str) -> str:
    """The §3.4 / F1 synthesized ``{step_index}`` for a step carrying no request id.

    Arch ruling 14: **single-segment synthesized key, natural key in the body.**
    Our LOCAL notification delivery is an internal dispatch with no wire
    ``request_id``, so the marker sites fall back to a synthesized key. The F1
    pin sanctioned the *shape* ``cont-{kind}-{continuation_path}`` — but did so
    BEFORE §3.11 ruled the coordinate single-segment, and a continuation path is
    a tree path, so the sanctioned shape interpolated 3+ segments into a
    one-segment slot and forked the marker tree. Hashing the path fixes that:

        cont-error-system/inbox/v19-a1  ->  cont-error-<sha256(path)[:16]>

    The natural key survives in the marker body as ``continuation_path``
    (see :func:`_bind_lost_marker`), so this loses nothing — it is an index.

    This hash is NOT the ruling-13 case and does not re-open node-minting: the
    input is a path the LOCAL peer authored and a writer needs a capability to
    install a continuation, so the node count is bounded by authorization, not
    by an attacker's imagination. Ruling 13 forbids hashing precisely where the
    input is unbounded, remote, and unauthorized — the opposite of this.
    """
    digest = hashlib.sha256(continuation_path.encode("utf-8")).hexdigest()[:16]
    return f"cont-{kind}-{digest}"


def _sanitize_reason(code: str | None) -> str:
    """Per v1.20 §3.10.5 path-safety: sentinel-substitute non-conformant codes.

    A handler emitting a non-path-safe ``code`` SHOULD have it sentinel-
    substituted (``{reason}`` = ``unspecified_error``) by the dispatching
    engine; raw ``code`` is preserved in the marker body's ``code`` field
    per §3.10.6 body-fields registry.
    """
    if code and _PATH_SAFE_RE.match(code):
        return code
    return REASON_UNSPECIFIED


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

# Quarantine sentinels for a coordinate that fails path-safety (arch ruling 13
# as amended, ROUTING-2026-07-17 §1/§3: collapse to a fixed sentinel, never a
# hash; the original is recovered from the marker body, never the path).
#
# One sentinel PER COORDINATE, not one shared, so a quarantined marker still
# says which coordinate was hostile without the hostile value on the path.
# `unspecified_error` is landed spec (§3.10.5) and was never ours to choose;
# the other two follow its pattern and are entity-core-go's reported spelling
# (ROUTING-2026-07-17-go-round2-response.md §2) — adopted for convergence
# rather than independently invented, and pending arch pinning.
REASON_UNSPECIFIED = "unspecified_error"
CHAIN_ID_UNSPECIFIED = "unspecified_chain_id"
STEP_INDEX_UNSPECIFIED = "unspecified_step_index"

# Appendix A engine codes (canonical home; v1.19 / v1.20).
ENGINE_CODE_ON_ERROR_DISPATCH_FAILED = "on_error_dispatch_failed"
ENGINE_CODE_MERGE_VALUE_NOT_MAP = "merge_value_not_map"
ENGINE_CODE_TRANSFORM_FAILED = "transform_failed"
ENGINE_CODE_CHAIN_CONSTRUCTION_INVALID = "chain_construction_invalid"

# PROPOSAL-CONTINUATION-STANDING-MODEL §4 (join completion policy) codes.
# ENGINE_CODE_JOIN_LATE is the §4.1 R3 pin (Go's oracle spelling
# "join_late" — a stale-round slot dropped by the round_id guard).
ENGINE_CODE_JOIN_ABANDONED = "join_abandoned"
ENGINE_CODE_JOIN_LATE = "join_late"
ENGINE_CODE_JOIN_ERROR_SLOT = "join_error_slot"

# §4 mechanism 2 on_incomplete policy values + the fire-partial dispatch
# payload's incomplete-marker field name. Go: JoinOnIncompleteAbandon /
# JoinOnIncompleteFirePartial / JoinIncompleteField (core/types/continuation.go);
# rust mirrors the same three strings (extensions/continuation/src/lib.rs).
JOIN_ON_INCOMPLETE_ABANDON = "abandon"
JOIN_ON_INCOMPLETE_FIRE_PARTIAL = "fire-partial"
JOIN_INCOMPLETE_FIELD = "incomplete"

# O5 (STANDING-MODEL §4, RULED 2026-07-28): throttle floor for the sweep-all
# pass over tracked deadline-carrying joins. Matches Go's joinSweepThrottle —
# a 1-minute floor so a busy peer doesn't pay a full sweep per advance.
JOIN_SWEEP_THROTTLE_MS = 60_000

# ---------------------------------------------------------------------------
# v1.23 §3.4 A.1 — chain-error marker retention and self-collection
# ---------------------------------------------------------------------------
#
# v1.23 elevated the marker bind SHOULD → MUST and, in the same move, elevated
# collection to MUST: *"A MUST-write paired with a MAY-collect is a leak by
# construction."* A permanently-failing chain mints ~1,440 markers/day, so
# binding without a reaper is unbounded growth by construction — which is the
# state this peer was in until this landed.
#
# **The collector is the binder.** That is not a choice; it falls out of
# §3.10.7's invariant that markers are bound in the observing peer's own tree
# under its own authority. Nobody else can collect them, so nobody else should
# be asked to. There is no operator step and no external reaper.

#: The v1.23 canonical operator knob: a config ENTITY at this path whose
#: ``retention_ms`` field carries the window. Named by the spec, not by us —
#: Go had to retire an invented `system/runtime/chain-errors/retention-ms` for
#: this one, and Python never had a key at all to retire.
MARKER_RETENTION_CONFIG_PATH = "system/config/chain-errors"
MARKER_RETENTION_FIELD = "retention_ms"

#: §3.4 A.1's suggested default, now with a home: 24 hours.
DEFAULT_MARKER_RETENTION_MS = 24 * 60 * 60 * 1000

#: An explicit ``retention_ms: 0`` disables collection.
#:
#: Not a contradiction of the MUST. The obligation closes an ASYMMETRY — a
#: MUST-write that nothing was obliged to collect — so it lands on *having a
#: reaper with a bounded default*, which is what an impl gets wrong by
#: omission, rather than on any particular marker dying. An operator who wants
#: the full history is legitimate (the tree IS the event log) and sets this;
#: what they cannot do is get unbounded growth by accident. Same reading and
#: same sentinel value as Go's `RetainMarkersForever`, and Go has flagged the
#: same question to arch: if the elevation meant "no opt-out", this knob is
#: non-conformant in both impls and the ruling should say so.
RETAIN_MARKERS_FOREVER = 0

#: Both marker kinds live under this root — `lost` (sender-side, this module)
#: and `rejected` (receiver-side, the dispatcher). Collection is indifferent to
#: which: it reads the timestamp every marker body carries.
CHAIN_ERROR_MARKER_ROOT = "system/runtime/chain-errors/"

#: Throttle floor for the collection sweep, mirroring JOIN_SWEEP_THROTTLE_MS
#: above and Go's `collectThrottle`. Keeps the amortized cost off the bind path.
MARKER_COLLECT_THROTTLE_MS = 60_000

# V7 §6.12 per-request transport codes (status pinned in spec).
TRANSPORT_CODE_RECV_TIMEOUT = "recv_timeout"          # 503
TRANSPORT_CODE_CONNECTION_BROKEN = "connection_broken"  # 503
TRANSPORT_CODE_PROTOCOL_ERROR = "protocol_error"      # 502 (also §3.10.5 missing-code fallback)

# V7 §3.3 line 736 canonical 403 example. Used as both response body code
# (messages.py::ExecuteResponse.forbidden) and rejected-marker {reason}.
CODE_CAPABILITY_DENIED = "capability_denied"

CONTINUATION_HANDLER_PATTERN = "system/continuation"

# PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §4 / EXTENSION-CONTINUATION §3.9:
# the causal-chain ceiling. Peer-local and implementation-defined (§8.4 O3 — no
# pinned interop floor: the tested value is *global* by inheritance, so peers
# with different maxima still terminate, the lower one governs). 64 mirrors
# entity-core-go's DefaultMaxChainDepth for cohort parity.
DEFAULT_MAX_CHAIN_DEPTH = 64
# Internal suspension reason (spec §3.9 line: `suspend(reason="chain_depth_exceeded")`)
# — recorded on the suspended entity so the *cause* stays attributable (depth vs. a
# local ttl/budget bound; the §4a O1 discipline). This is NOT the outward wire code.
CHAIN_DEPTH_EXCEEDED_REASON = "chain_depth_exceeded"
# Outward/observable code for the continuation depth brake. EXTENSION-CONTINUATION
# §3.9 pins the 429 result as `{code: "bounds_exceeded", suspended_at: …}` for ALL
# three suspension causes; §3.10.5 makes the lost-marker `{reason}` == that `code`.
# So the depth brake's caller-observed 429 and its cross-impl lost-marker carry
# `bounds_exceeded` (matching Go — PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION Ruling 3),
# while the suspended entity retains `chain_depth_exceeded` internally (line above).
# This supersedes the earlier in-flight "proposal §8 anchor" spelling; the landed
# spec text (§3.9 / §3.10.5) governs. O1 attributability is preserved because the
# local-bound brakes still surface their own distinct codes (ttl_exhausted /
# budget_exhausted), never bounds_exceeded — those paths are unchanged here.
# NOTE: the *capability*-delegation depth ceiling is a SEPARATE mechanism that stays
# `chain_depth_exceeded` at 400 (capability/delegation.py → peer.py) — do not conflate.
CHAIN_DEPTH_BRAKE_CODE = "bounds_exceeded"

# §4a de-confound (PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION Ruling 2): a continuation
# chain seeds its TTL well ABOVE the chain_depth ceiling so DEPTH — deterministic,
# inherited globally — is the PRIMARY brake, and TTL is only a fan-out resource
# backstop. Without the headroom, TTL (default 64 == the ceiling) exhausts first on a
# same-peer self-loop (~2 dispatches/advance) and MASKS the depth brake, so cb2's
# depth-brake marker never surfaces single-peer. 8× the ceiling matches Go's shipped
# `DefaultChainTTL` and tolerates several decrements/hop while depth still binds first.
#
# PROVISIONAL magnitude: the seed value and the decrement rate are BOTH arch-unpinned
# (entity-core-go spec-issues 2026-07-19 chain-ttl-seed-magnitude-unpinned /
# 2026-07-21 ttl-decrement-rate-per-hop-vs-per-dispatch — "arch cannot pin the
# magnitude without first pinning the rate"). We track Go's 512 for cohort convergence;
# retune this one constant when arch pins it. The de-confound INVARIANT (seed > ceiling)
# is what Ruling 2 fixes; only the exact number is provisional.
DEFAULT_CHAIN_TTL = 8 * DEFAULT_MAX_CHAIN_DEPTH  # 512

# PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §4a (arch ruling 2026-07-18): the
# chain_depth brake is GLOBAL and independent; TTL/budget exhaustion is an
# ADDITIONAL LOCAL bound that terminates a continuation causal chain, never a
# substitute for the depth brake. When a local bound is what actually
# terminated the chain, attribute it honestly (not the misleading
# `protocol_error` a delivered non-2xx would carry) so the terminal is
# observable AND correctly named — the O1 discipline arch asked for: the
# suspension's cause must be attributable, depth vs. a local bound must not
# collapse. Same-peer, TTL (a local bound, default 64) reaches exhaustion
# before depth (64) in a synchronous self-loop (~2 dispatches/advance), so it
# legitimately fires first — arch blessed that as "locally safe"; the depth
# brake governs where TTL cannot (the cross-peer chain, once rung-4 refills
# per hop — deferred, a shared cohort hold).
# The chain-error `{reason}` is the same identifier the peer's ingress emits as
# the wire code (bounds.py) — one spelling for the sender-side lost marker and
# the caller-observed terminal.
TTL_EXHAUSTED_REASON = TTL_EXHAUSTED_CODE
BUDGET_EXHAUSTED_REASON = BUDGET_EXHAUSTED_CODE


def _resource_bound_reason(dispatch_result: Any) -> str | None:
    """If ``dispatch_result`` is a dispatch REFUSED because a local resource
    bound (ttl/budget) is exhausted, return the honest ``{reason}`` for the
    chain-error marker; otherwise None.

    A ttl/budget-exhausted dispatch is refused *pre-handler* (peer dispatch
    returns 400 with the canonical message, the handler never runs) — so it is
    NOT a delivered non-2xx (§3.4 v1.10) and MUST NOT be attributed
    `protocol_error`. It is the local resource brake terminating the causal
    chain; naming it as such is what makes the terminal attributable (§4a O1).
    """
    if getattr(dispatch_result, "status", None) != 400:
        return None
    err = getattr(dispatch_result, "error", None)
    if err == TTL_EXHAUSTED_MESSAGE:
        return TTL_EXHAUSTED_REASON
    if err == BUDGET_EXHAUSTED_MESSAGE:
        return BUDGET_EXHAUSTED_REASON
    return None

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
    # §3.3's 400 row (0.8.2.18): an operation that requires a resource answers
    # ABSENT with `path_required` and MORE THAN ONE with `ambiguous_resource`.
    # The two are different inputs with different remedies — *supply a
    # resource* is a different instruction from *name only one* — and the row
    # exists because the code selects the remedy. Collapsing them into
    # `len(targets) != 1` is *"non-conformant on the absent case"*, which is
    # what this site did.
    if not targets:
        return _error_response(
            400,
            "path_required",
            "install requires a resource target (the suspended continuation path)",
        )
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

    # Step 3d (PROPOSAL-CONTINUATION-STANDING-MODEL §4): a join's optional
    # completion_deadline_ms/on_incomplete govern its round lifecycle.
    # "abandon" (default/absent) and "fire-partial" (opt-in, §4 mechanism 2)
    # are the only two legal values — fail-closed on anything else, same
    # discipline as unknown_transform_op: an unrecognized value is rejected
    # at install rather than silently defaulting to abandon at the deadline.
    # Both gates below share Go/rust's `invalid_continuation` code (mirrors
    # validOnIncomplete / core/types/continuation.go and rust's install match
    # arm — cross-impl convergence, not independently invented).
    completion_deadline_ms = params.get("completion_deadline_ms")
    on_incomplete = params.get("on_incomplete")
    if params_type == CONTINUATION_JOIN_TYPE:
        if on_incomplete is not None and on_incomplete not in (
            JOIN_ON_INCOMPLETE_ABANDON, JOIN_ON_INCOMPLETE_FIRE_PARTIAL,
        ):
            return _error_response(
                400,
                "invalid_continuation",
                f"unrecognized on_incomplete {on_incomplete!r}: expected "
                f"{JOIN_ON_INCOMPLETE_ABANDON!r} or {JOIN_ON_INCOMPLETE_FIRE_PARTIAL!r}",
            )
        # A policy with no deadline can never fire — the round never ends.
        if on_incomplete is not None and completion_deadline_ms is None:
            return _error_response(
                400,
                "invalid_continuation",
                "on_incomplete requires completion_deadline_ms — without a "
                "deadline no round is ever incomplete",
            )
        if completion_deadline_ms is not None and (
            isinstance(completion_deadline_ms, bool)
            or not isinstance(completion_deadline_ms, int)
            or completion_deadline_ms <= 0
        ):
            return _error_response(
                400,
                "invalid_completion_deadline_ms",
                "completion_deadline_ms must be a positive integer (milliseconds)",
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
    # §4.1: round_id/round_started_at_ms are synthesized bookkeeping, added
    # only for a deadline-carrying join — a join without
    # completion_deadline_ms stays byte-identical to a pre-§4 join.
    entity_data = dict(params)
    if params_type == CONTINUATION_JOIN_TYPE and completion_deadline_ms is not None:
        entity_data["round_id"] = 0
        entity_data["round_started_at_ms"] = int(time.time() * 1000)
    continuation_entity = Entity(type=params_type, data=entity_data)

    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(install_path)
    emit_ctx = EmitContext.from_handler_grant(ctx, "install")
    ctx.emit_pathway.emit(full_uri, continuation_entity, emit_ctx)

    # O5: register a deadline-carrying join as sweepable from install too —
    # not only from its own advance traffic — so an installed-but-untouched
    # join is still in the sweep set (mirrors Go's noteJoinPath call site).
    if params_type == CONTINUATION_JOIN_TYPE and completion_deadline_ms is not None:
        _note_join_path(ctx, install_path, completion_deadline_ms)

    return {
        "status": 200,
        "result": {
            "type": "system/continuation/install-result",
            "data": {"path": install_path},
        },
    }


def _advancement_not_found() -> dict[str, Any]:
    """The shared 200/no-op response for 'nothing here to advance' — either
    no continuation ever existed at the path, or a fire-partial reap just
    exhausted and deleted the join this advance was about to touch (Go's
    ``advancementNotFound``)."""
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
    # O5 (STANDING-MODEL §4, RULED 2026-07-28): throttled sweep over ALL
    # tracked deadline-carrying joins, before touching THIS advance's own
    # path — reaping a foreign join is this peer's own housekeeping on its
    # own tree, not something the caller is authorized for (mirrors Go's
    # placement of maybeSweepJoins at the very top of handleAdvance, before
    # the resource-path read and the cap check).
    await _maybe_sweep_joins(ctx)

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
        return _advancement_not_found()

    continuation_entity = ctx.emit_pathway.content_store.get(content_hash)
    if continuation_entity is None:
        return _error_response(404, "continuation_not_found", f"Continuation entity not found: {continuation_path}")

    cont_type = continuation_entity.type
    cont_data = continuation_entity.data

    # PROPOSAL-CONTINUATION-STANDING-MODEL §3 (arch ruling 2026-07-18, MUST) —
    # the advance-authority split. A standing continuation is subscription-
    # shaped: a trigger reaches it, but does not own it. Two authorities:
    #
    #  * REACTIVE (ctx.reactive_trigger) — a delivery mechanism (inbox route,
    #    subscription/timer poke) advancing the continuation as a consequence of
    #    a delivered event. Gated by delivery-REACHABILITY: the inbound delivery
    #    already passed its own Level-2 path check to land here. The advance then
    #    runs under the continuation's OWN dispatch_capability (below), and MUST
    #    NOT additionally require the delivering caller to hold advance-cap on
    #    the continuation's path. Cross-peer, ctx.caller_capability is the
    #    triggering peer's narrowly-scoped cap (V7 §6.8 propagation) — precisely
    #    the cap that does NOT cover B's own continuation state, the Q2 defect.
    #
    #  * ADMINISTRATIVE (marker absent) — a bare `advance` EXECUTE, an operator
    #    or handler directly managing continuations. Stays capability-gated on
    #    the path: the caller MUST hold `advance` on the continuation path. (The
    #    wire dispatcher's §5.2 resource-scope check already enforces this for a
    #    wire advance; this is the same gate expressed at the handler, so an
    #    internal administrative advance under a propagated caller cap is held to
    #    the same rule — defense-in-depth, one explicit site keyed on the
    #    marker, not an inference from dispatch surface.)
    #
    # The escalation mitigation remains the §3.1a INSTALL-time in-chain check on
    # dispatch_capability (a continuation can only have been installed by an
    # in-chain granter); the residual on the reactive path is timing/frequency
    # (DoS, bounded by the continuation's own `bounds`), not escalation.
    # Defense-in-depth, scoped like every other `check_caller_permission` use:
    # it corrects a *present but insufficient* caller capability, it does not
    # invent a gate where the dispatcher already authorized. An internal /
    # synthesized advance carries no caller capability ({} / falsy) — the
    # peer's §5.2 dispatcher already ran the primary authorization for a wire
    # advance, and the handler trusts that — so an absent caller cap is trusted
    # here (not treated as "grants nothing"). The gate therefore fires only for
    # an ADMINISTRATIVE advance that arrived with a real caller capability which
    # does not cover `advance` on the continuation's path.
    #
    # O1 (2026-07-28, RESOLVED — fail-closed): confirmed end-to-end, not
    # assumed. `check_handler_scope` (peer.py `_handle_execute`, unconditional
    # Steps 1-2, before any resource-target check and before this handler
    # runs) denies a caller presenting an EMPTY/absent capability regardless
    # of whether `resource.targets` is set — so a genuine external caller
    # with zero capability never reaches this branch with `caller_capability`
    # falsy; that state is reserved for a truly internal/synthesized advance.
    # AT-4 (administrative, zero capability -> 403) and its companion
    # (administrative, present-but-insufficient capability, no
    # `resource.targets` -> still 403 via THIS gate) are proven live over a
    # real connection in `tests/integration/test_continuation_advance_authority_wire.py`.
    if not ctx.reactive_trigger and ctx.caller_capability:
        if not ctx.check_caller_permission("advance", continuation_path):
            return _error_response(
                403,
                CODE_CAPABILITY_DENIED,
                f"insufficient capability for path: {continuation_path}",
            )

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


def _step6_chain_context(ctx: HandlerContext) -> HandlerContext:
    """§3.6 step 6: seed the dispatch's ``chain_id`` and ``chain_depth``.

    ``chain_id: context.chain_id or generate_id()`` — a continuation whose
    trigger carried no chain (a timer advance, an inbox delivery that is not
    itself a chain dispatch) MUST still dispatch under *some* chain id. Without
    this the dispatch goes out with ``chain_id`` absent and every downstream
    marker binder falls down its own fallback ladder onto a meaningless key
    (here: ``"unknown"``) — the cross-impl marker-coordinate divergence, whose
    root cause is this step, not the fallbacks. The sentinels stay: they are
    the correct behavior for the genuinely-absent case, they just stop firing.

    ``chain_depth: (context.chain_depth or 0) + 1`` — the causal-chain length
    (PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §4/§5), the continuation-axis
    mirror of ``cascade_depth``. This is the **sole incrementing site**. The
    O1 signal the cohort converges on is inherited-bounds *presence*, NOT the
    trigger type:

    - **Causal advancement** — the triggering advancement's ``bounds.chain_depth``
      is present in ``ctx.bounds`` (seeded at ingress from the wire, or carried
      same-peer through the synchronous dispatch), so this dispatch inherits and
      ``+1``s it. A synchronous self-redispatch accumulates and eventually trips
      the ceiling brake (``_advance_forward``).
    - **Standing continuation on a fresh external trigger** — a timer tick, a
      ``system/peer/status`` write, or an inbox delivery (async, fresh bounds)
      arrives with **no** ``chain_depth``, so ``(None or 0) + 1`` roots this
      firing at 1 and it never accumulates across firings. NETWORK retry-forever
      stays unbounded on the depth axis while ``chain_id`` stays stable for
      correlation — depth and identity are independent axes.

    TTL/budget refill (step 6 proper — deferred, rung 4) does NOT reset
    ``chain_depth`` (§6.2); the two live on different axes.

    Generated ids are a single path segment (§3.11) — ``chain_id`` is a segment
    of the §3.10.6 marker path, so a multi-segment value forks the marker tree.

    Seeds the advance's own context in place: the dispatch and every marker
    bound around it MUST key on one chain, and ``ctx`` is built per-dispatch by
    the caller for exactly this operation. ``bounds`` is copied before seeding
    so the caller's Bounds object (potentially the inbound request's) is not
    touched. Both carriers are seeded — ``chain_id`` feeds the child's context,
    ``bounds.chain_id``/``bounds.chain_depth`` feed the emit pathway's cascade
    tracking, the §3.10.3 rejected-marker gate, and the cross-peer wire
    (Delta 1) — because they are read from different sources downstream and
    MUST agree.
    """
    chain_id = ctx.chain_id or f"chain-{secrets.token_hex(8)}"
    ctx.chain_id = chain_id

    # §5 increment: read the inherited depth BEFORE mutating. Absence roots at
    # 0 (a fresh external trigger); presence means a causal advancement.
    inherited_depth = (
        ctx.bounds.chain_depth
        if ctx.bounds is not None and ctx.bounds.chain_depth is not None
        else 0
    )
    # Copy before stamping so the caller's Bounds (often the inbound request's)
    # is untouched — both carriers ride on the copy.
    new_bounds = ctx.bounds.copy() if ctx.bounds is not None else Bounds()
    new_bounds.chain_id = chain_id
    new_bounds.chain_depth = inherited_depth + 1
    # §4a de-confound: at chain ORIGIN (no inherited depth) seed the chain TTL
    # above the depth ceiling so depth is the primary, observable brake (Ruling
    # 2; mirrors Go's seed-at-origin). Only raise — never reduce an already-
    # higher inherited budget (a cross-peer chain carries its origin's TTL over
    # the wire and just decrements). Downstream hops inherit depth>0 → no re-seed.
    if inherited_depth == 0 and (
        new_bounds.ttl is None or new_bounds.ttl < DEFAULT_CHAIN_TTL
    ):
        new_bounds.ttl = DEFAULT_CHAIN_TTL
    ctx.bounds = new_bounds
    return ctx


def _chain_depth_exceeded(ctx: HandlerContext) -> bool:
    """§4 brake: has this advancement's (already-seeded) chain_depth passed the
    ceiling? Read the post-``_step6_chain_context`` value on ``ctx.bounds``.

    The tested value is the *global* chain length — it was inherited across the
    wire (Delta 1), not reset per peer — so a cross-peer causal ping-pong
    terminates at the same global count a single-peer runaway does.
    """
    depth = (
        ctx.bounds.chain_depth
        if ctx.bounds is not None and ctx.bounds.chain_depth is not None
        else 0
    )
    return depth > DEFAULT_MAX_CHAIN_DEPTH


def _suspend_chain_depth_exceeded(
    cont_data: dict[str, Any],
    continuation_path: str,
    ctx: HandlerContext,
) -> dict[str, Any]:
    """§3.9 / §4: the causal chain hit the ceiling — suspend instead of dispatch.

    Persists a ``system/continuation/suspended`` entity (operator-resumable via
    the resume op, which roots ``chain_depth`` at 0 per §7 so it does not
    immediately re-suspend) and returns a terminal 429. Per landed spec §3.9 the
    429 result code is ``bounds_exceeded`` (and §3.10.5 makes the lost-marker
    ``{reason}`` == that code), matching Go (Ruling 3); the suspended entity
    keeps ``chain_depth_exceeded`` as its internal ``reason`` (§3.9 line, O1
    attributability). This is what makes the self-referential runaway
    *terminate* rather than recurse to stack overflow.
    """
    chain_id = ctx.chain_id or CHAIN_ID_UNSPECIFIED
    suspended_path = f"system/continuation/suspended/{chain_id}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(suspended_path)
    suspended = Entity(
        type=CONTINUATION_SUSPENDED_TYPE,
        data={
            "target": cont_data.get("target"),
            "operation": cont_data.get("operation"),
            "resource": cont_data.get("resource"),
            "params": cont_data.get("params") or {},
            "reason": CHAIN_DEPTH_EXCEEDED_REASON,
            "chain_id": chain_id,
            "suspended_at": int(time.time() * 1000),
        },
    )
    emit_ctx = EmitContext.from_handler_grant(ctx, "advance")
    ctx.emit_pathway.emit(full_uri, suspended, emit_ctx)
    # §4a observability: bind a chain-error-lost marker so the depth brake is
    # attributable in the tree event log — the signal a cross-impl probe reads
    # to confirm the *depth* brake fired. Per §3.10.5 the marker `{reason}`
    # segment IS the result `code` (§3.9 → `bounds_exceeded`), so this marker
    # lands at `.../bounds_exceeded/…`, byte-agreeing with Go's depth-brake
    # marker. It stays distinct from a local-bound brake because ttl/budget
    # exhaustion bind `ttl_exhausted`/`budget_exhausted` markers (unchanged) —
    # the depth-vs-local distinction §4a O1 is about is preserved.
    request_id_for_marker = (
        ctx.request_id
        if getattr(ctx, "request_id", None)
        else _synthesized_step_key("depth", continuation_path)
    )
    _bind_lost_marker(
        ctx,
        code=CHAIN_DEPTH_BRAKE_CODE,
        status=429,
        request_id=request_id_for_marker,
        continuation_path=continuation_path,
        extra_body={"suspended_path": suspended_path},
    )
    logger.info(
        "continuation chain_depth exceeded ceiling %d (chain_id=%s) — suspended "
        "at %s", DEFAULT_MAX_CHAIN_DEPTH, chain_id, suspended_path,
    )
    return _error_response(
        429,
        CHAIN_DEPTH_BRAKE_CODE,
        f"continuation chain_depth exceeded ceiling {DEFAULT_MAX_CHAIN_DEPTH}",
        reason=CHAIN_DEPTH_BRAKE_CODE,
        chain_id=chain_id,
        suspended_path=suspended_path,
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
    # §3.6 step 6: seed the chain before anything reads it — the dispatch and
    # every marker bound around it MUST key on the same chain id, and the §5
    # increment stamps this advancement's chain_depth.
    ctx = _step6_chain_context(ctx)

    # §4 brake: a causal chain that has climbed past the ceiling suspends here
    # instead of dispatching — the sole thing that makes a self-referential /
    # cross-peer runaway terminate rather than recurse without bound.
    if _chain_depth_exceeded(ctx):
        return _suspend_chain_depth_exceeded(cont_data, continuation_path, ctx)

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
                _synthesized_step_key("error", continuation_path),
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
            # CONTINUATION v1.14 §3.4 (F1 ratification): {step_index} is
            # the ORIGINAL request_id of the dispatch, same pin as the
            # other marker sites — synthesized key only when the EXECUTE
            # carried none.
            request_id_for_marker = (
                ctx.request_id
                if getattr(ctx, "request_id", None)
                else _synthesized_step_key("error", continuation_path)
            )
            _bind_lost_marker(
                ctx,
                code=ENGINE_CODE_ON_ERROR_DISPATCH_FAILED,
                status=effective_status,
                request_id=request_id_for_marker,
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
                else _synthesized_step_key("merge", continuation_path)
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
    gate_capability = dispatch_cap_entity.data
    if _remote_peer_of(ctx, eff_target) is not None:
        cross_peer_kwargs = {
            "dispatch_capability_entity": dispatch_cap_entity.to_dict(),
            "dispatch_capability_chain": _dispatch_chain_bundle(
                ctx, dispatch_cap_entity
            ),
        }
        # §1.4 PD-2 (0.8.2.19): **a credential is not a grant.** On the
        # cross-peer arm the `dispatch_capability` is the PRESENTED
        # credential — it relaxes Dimension 4 and is verified on its own four
        # dimensions in the TARGET's frame. The gate for Dimensions 1-3 is
        # the executing handler's own grant, evaluated in the LOCAL frame.
        #
        # This site used to pass the credential as BOTH, and that is the
        # confused-deputy conflation F67 is about, arriving from the other
        # side: while the presented arm short-circuited, the duplicate was
        # harmless because the credential was only ever read in the target's
        # frame. Composing the gate made it fatal — measured, as
        # `convergence.rexec_delivered` FAIL:
        #
        #     request target  system/validate/rexec-src-.../item
        #                     -> canonicalizes in OUR frame  -> /{A}/...
        #     grant pattern   /{B}/system/validate/rexec-src-.../item
        #
        # A B-rooted credential's resource patterns are authored in B's
        # namespace, so evaluating it as a local grant can never match a
        # target naming B — it is §1.4's *"looks implemented and denies
        # everything"* reached through the resource dimension. Handing the
        # handler's grant to the gate is what the ruling says and is also
        # what makes the two frames consistent.
        #
        # Nothing is loosened: the credential's own narrow scope is still
        # enforced, in the frame it was authored in, by the presented-arm
        # verification.
        gate_capability = ctx.handler_grant

    # Dispatch to target using stored capability. Transport-layer failures
    # discriminate per V7 §6.12 into recv_timeout / connection_broken /
    # protocol_error so the chain-error marker {reason} matches the
    # operationally-distinguishable failure shape (operators can match
    # specific paths without parsing bodies — §1.2b.3 granularity choice).
    try:
        dispatch_result = await ctx.execute_with_capability(
            eff_target, eff_operation, params,
            capability_data=gate_capability,
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
                    _synthesized_step_key("error", continuation_path),
                    transport_status,
                    {"error": str(e), "continuation_path": continuation_path,
                     "code": transport_code},
                    on_error,
                )
            except Exception as e2:
                logger.error(f"Error routing to on_error: {e2}")
                # F1 ratification: {step_index} = original request_id.
                request_id_for_marker = (
                    ctx.request_id
                    if getattr(ctx, "request_id", None)
                    else _synthesized_step_key("error", continuation_path)
                )
                _bind_lost_marker(
                    ctx,
                    code=ENGINE_CODE_ON_ERROR_DISPATCH_FAILED,
                    status=500,
                    request_id=request_id_for_marker,
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
                else _synthesized_step_key("forward", continuation_path)
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
                _synthesized_step_key("chain", continuation_path),
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
        # §4a: a dispatch REFUSED because a local resource bound (ttl/budget)
        # is exhausted is NOT a delivered non-2xx — the peer refused it
        # pre-handler. Attribute the honest brake reason so the terminal of a
        # continuation causal chain that hit its LOCAL bound is observable and
        # correctly named (not the misleading `protocol_error` a missing
        # downstream code would otherwise yield). This is what makes the
        # self-referential runaway's terminal attributable to *ttl*, keeping it
        # distinct from the *chain_depth* brake (§4a O1: cause must not
        # collapse). The depth brake fires (and suspends) at its own site.
        resource_reason = _resource_bound_reason(dispatch_result)
        dispatch_code = resource_reason or (
            _extract_response_code(dispatch_result.result)
            or TRANSPORT_CODE_PROTOCOL_ERROR
        )
        origination_ms = int(time.time() * 1000)
        # CONTINUATION v1.14 §3.4: {step_index} MUST be the original
        # request_id of the forward dispatch — pinned cross-impl. Fall
        # back to a continuation-keyed string only when the EXECUTE
        # wasn't carrying a request_id (synthesized internal dispatch).
        request_id_for_marker = (
            ctx.request_id
            if getattr(ctx, "request_id", None)
            else _synthesized_step_key("forward", continuation_path)
        )
        _bind_lost_marker(
            ctx,
            code=dispatch_code,
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


def _persist_join_progress(
    ctx: HandlerContext,
    full_uri: str,
    cont_data: dict[str, Any],
    received: dict[str, Any],
    round_id: int | None,
    round_started_at_ms: int | None,
    completion_deadline_ms: int | None,
) -> None:
    """Write the join's accumulation/round state without changing lifecycle
    fields (target/operation/expected/dispatch_capability/etc. untouched)."""
    new_cont_data = dict(cont_data)
    new_cont_data["received"] = received
    if completion_deadline_ms is not None:
        new_cont_data["round_id"] = round_id
        new_cont_data["round_started_at_ms"] = round_started_at_ms
    new_cont_entity = Entity(type=CONTINUATION_JOIN_TYPE, data=new_cont_data)
    emit_ctx = EmitContext.from_handler_grant(ctx, "advance")
    ctx.emit_pathway.emit(full_uri, new_cont_entity, emit_ctx)


class _JoinSweepState:
    """Per-peer O5 sweep bookkeeping: the set of tracked deadline-carrying
    join paths, plus the throttle timestamp. Keyed off ``ctx.emit_pathway``
    identity (one EmitPathway per peer, alive for the peer's lifetime) via a
    WeakKeyDictionary — no Extension/peer-lifecycle hook needed, and state
    for a torn-down peer/test fixture is reclaimed automatically."""

    __slots__ = ("paths", "last_sweep_ms")

    def __init__(self) -> None:
        self.paths: set[str] = set()
        self.last_sweep_ms: int = 0


_join_sweep_states: "weakref.WeakKeyDictionary[Any, _JoinSweepState]" = (
    weakref.WeakKeyDictionary()
)


def _join_sweep_state_for(ctx: HandlerContext) -> _JoinSweepState:
    emit_pathway = ctx.emit_pathway
    state = _join_sweep_states.get(emit_pathway)
    if state is None:
        state = _JoinSweepState()
        _join_sweep_states[emit_pathway] = state
    return state


def _note_join_path(
    ctx: HandlerContext, continuation_path: str, completion_deadline_ms: Any,
) -> None:
    """O5: register a deadline-carrying join as sweepable — called from
    install and from every advance that touches it, so the index fills from
    ordinary traffic (mirrors Go's ``noteJoinPath``). A wait-forever join
    (no ``completion_deadline_ms``) is never reapable and is not tracked."""
    if completion_deadline_ms is None:
        return
    _join_sweep_state_for(ctx).paths.add(continuation_path)


async def _maybe_sweep_joins(ctx: HandlerContext) -> None:
    """O5 (STANDING-MODEL §4, RULED 2026-07-28): a throttled pass over ALL
    tracked deadline-carrying joins, reaping any whose round has expired —
    not just the one the current advance is about to touch. A standing join
    that goes silent while the peer stays continuation-active must still be
    reaped off SOMEONE ELSE's traffic, or the cross-peer `join_incomplete`
    marker becomes a permanent, unobservable divergence (the touched-only
    predecessor's defect, ARCH-ruled 2026-07-28 third pass).

    Bind-time and throttled: nothing here owns a background timer/goroutine
    (mirrors Go/rust; O6 quiescent-peer abandon stays deferred). An expired
    round is therefore reaped at the next continuation traffic ANYWHERE on
    this peer, not at the instant of the deadline — the deadline is an
    eligibility threshold, never reaped early. A peer restart forgets joins
    installed before it, but that only delays the marker: the touched-only
    reap-on-touch in ``_advance_join`` still self-heals on that join's own
    next arrival.
    """
    emit_pathway = getattr(ctx, "emit_pathway", None)
    if emit_pathway is None:
        return
    state = _join_sweep_state_for(ctx)
    now_ms = int(time.time() * 1000)
    if state.last_sweep_ms and (now_ms - state.last_sweep_ms) < JOIN_SWEEP_THROTTLE_MS:
        return
    state.last_sweep_ms = now_ms
    for continuation_path in list(state.paths):
        await _sweep_one_join(ctx, continuation_path, state)


async def _sweep_one_join(
    ctx: HandlerContext, continuation_path: str, state: _JoinSweepState,
) -> None:
    """Reap a single tracked join, dropping it from the sweep set if it is
    no longer a deadline-carrying join at that path (exhausted, deleted, or
    replaced by a non-join entity)."""
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(continuation_path)
    content_hash = ctx.emit_pathway.entity_tree.get(full_uri)
    if content_hash is None:
        state.paths.discard(continuation_path)
        return
    entity = ctx.emit_pathway.content_store.get(content_hash)
    if entity is None or entity.type != CONTINUATION_JOIN_TYPE:
        state.paths.discard(continuation_path)
        return
    cont_data = entity.data
    if cont_data.get("completion_deadline_ms") is None:
        state.paths.discard(continuation_path)
        return
    # A fresh chain id per swept join (mirrors Go's dispatchChainID: inherit
    # the advancing request's chain if it already carries one, else mint
    # fresh) — this is housekeeping on a DIFFERENT join than the one this
    # advance is for, so it must not pollute the advancing continuation's
    # own chain_id. ctx is shared with the caller, so restore it after.
    saved_chain_id = ctx.chain_id
    ctx.chain_id = ctx.chain_id or f"chain-{secrets.token_hex(8)}"
    try:
        await _reap_expired_join_round(ctx, full_uri, continuation_path, cont_data)
    finally:
        ctx.chain_id = saved_chain_id


async def _reap_expired_join_round(
    ctx: HandlerContext,
    full_uri: str,
    continuation_path: str,
    cont_data: dict[str, Any],
) -> tuple[bool, dict[str, Any] | None]:
    """§4 mechanism 2 / O5: if ``cont_data``'s round has exceeded its
    ``completion_deadline_ms`` with slots still missing, apply the join's
    ``on_incomplete`` policy (default ``abandon``, opt-in ``fire-partial``)
    and persist the outcome. Shared by the touched-only reap-on-touch path
    (``_advance_join``) and the O5 sweep-all pass (``_sweep_one_join``) so
    both reap identically regardless of which traffic discovers the expiry.

    Returns ``(False, cont_data)`` unchanged when the round has not expired.
    Returns ``(True, new_cont_data)`` when it acted — ``new_cont_data`` is
    the freshly-reset/aged state, or ``None`` if a fire-partial reap
    exhausted the join's ``remaining_executions`` and deleted it.
    """
    completion_deadline_ms = cont_data.get("completion_deadline_ms")
    round_started_at_ms = cont_data.get("round_started_at_ms")
    expected = cont_data.get("expected", [])
    received = dict(cont_data.get("received") or {})
    round_id = cont_data.get("round_id")
    now_ms = int(time.time() * 1000)

    if not (
        completion_deadline_ms is not None
        and round_started_at_ms is not None
        and expected
        and set(received.keys()) != set(expected)
        and (now_ms - round_started_at_ms) >= completion_deadline_ms
    ):
        return False, cont_data

    missing = [s for s in expected if s not in received]
    on_incomplete = cont_data.get("on_incomplete")

    if on_incomplete == JOIN_ON_INCOMPLETE_FIRE_PARTIAL:
        new_cont_data = await _fire_partial_round(
            ctx, full_uri, continuation_path, cont_data, received, missing, expected,
        )
        return True, new_cont_data

    # abandon (default/absent): bind a lost marker naming the missing slots,
    # reset the round — the next round starts clean.
    _bind_lost_marker(
        ctx,
        code=ENGINE_CODE_JOIN_ABANDONED,
        status=408,
        request_id=_synthesized_step_key("join-abandon", continuation_path),
        continuation_path=continuation_path,
        extra_body={"missing_slots": missing, "abandoned_round": round_id or 0},
    )
    new_round_id = (round_id or 0) + 1
    new_round_started_at_ms = now_ms
    # Persist the round turnover immediately (write-through) so it survives
    # even if the rest of this call later fails (e.g. a terminal dispatch
    # throws a transport error).
    _persist_join_progress(
        ctx, full_uri, cont_data, {}, new_round_id, new_round_started_at_ms,
        completion_deadline_ms,
    )
    new_cont_data = dict(cont_data)
    new_cont_data["received"] = {}
    new_cont_data["round_id"] = new_round_id
    new_cont_data["round_started_at_ms"] = new_round_started_at_ms
    return True, new_cont_data


async def _fire_partial_round(
    ctx: HandlerContext,
    full_uri: str,
    continuation_path: str,
    cont_data: dict[str, Any],
    received: dict[str, Any],
    missing: list[str],
    expected: list[str],
) -> dict[str, Any] | None:
    """§4 mechanism 2 (opt-in): dispatch the join's target with the partial
    ``received`` plus an explicit ``incomplete`` marker naming the missing
    slots — riding IN the assembled payload next to the slot values, not
    beside them, so a target that opted into fire-partial and then ignores
    the marker has chosen partial input by that choice (mirrors Go's
    ``firePartialRound`` / rust's ``fire_partial_round``; ``JOIN_INCOMPLETE_FIELD``
    == Go's ``JoinIncompleteField`` == ``"incomplete"``). Best-effort: a
    dispatch failure logs and still ages the join — a short round that could
    not be delivered is not retried, it is aged like any other fire.

    Returns the freshly-aged cont_data (standing reset, or finite-remaining
    decremented), or None if this fire exhausted remaining_executions and
    the join entity was deleted.
    """
    target = cont_data.get("target")
    operation = cont_data.get("operation")
    dispatch_cap_hash = cont_data.get("dispatch_capability")
    dispatch_cap_entity = (
        ctx.emit_pathway.content_store.get(dispatch_cap_hash)
        if dispatch_cap_hash is not None else None
    )
    if target and operation and dispatch_cap_entity is not None:
        payload = dict(received)
        payload[JOIN_INCOMPLETE_FIELD] = {"missing": missing, "expected": expected}

        resource_data = cont_data.get("resource")
        dispatch_resource_targets = (
            resource_data.get("targets")
            if isinstance(resource_data, dict) and resource_data.get("targets")
            else None
        )
        cross_peer_kwargs: dict[str, Any] = {}
        if _remote_peer_of(ctx, target) is not None:
            cross_peer_kwargs = {
                "dispatch_capability_entity": dispatch_cap_entity.to_dict(),
                "dispatch_capability_chain": _dispatch_chain_bundle(
                    ctx, dispatch_cap_entity
                ),
            }
        try:
            await ctx.execute_with_capability(
                target, operation, payload,
                capability_data=dispatch_cap_entity.data,
                resource_targets=dispatch_resource_targets,
                **cross_peer_kwargs,
            )
        except Exception as e:
            logger.warning(
                "join %s: fire-partial dispatch failed: %s", continuation_path, e,
            )
    else:
        logger.warning(
            "join %s: fire-partial missing target/operation/dispatch_capability "
            "— firing skipped, join still ages", continuation_path,
        )

    return _age_join_after_fire(ctx, full_uri, cont_data)


def _age_join_after_fire(
    ctx: HandlerContext,
    full_uri: str,
    cont_data: dict[str, Any],
) -> dict[str, Any] | None:
    """Age a join after ANY terminal fire of a round — clean, abandoned, or
    fire-partial: decrement a finite join's ``remaining_executions``
    (deleting it at zero) or reset a standing one for the next round.
    Extracted so a deadline-driven fire-partial ages the join exactly like a
    slot-driven fire (mirrors Go's ``advanceJoinLifecycle`` / rust's
    ``finish_join_round``) — a fire-partial that skipped this would let a
    counted join fire more times than it was installed for.

    Returns the freshly-persisted cont_data, or None if the join was deleted
    (``remaining_executions`` exhausted).
    """
    remaining = cont_data.get("remaining_executions")
    completion_deadline_ms = cont_data.get("completion_deadline_ms")
    round_id = cont_data.get("round_id")
    emit_ctx = EmitContext.from_handler_grant(ctx, "advance")

    if remaining is not None and remaining - 1 <= 0:
        ctx.emit_pathway.delete(full_uri, emit_ctx)
        return None

    new_cont_data = dict(cont_data)
    if remaining is not None:
        new_cont_data["remaining_executions"] = remaining - 1
    new_cont_data["received"] = {}
    if completion_deadline_ms is not None:
        new_cont_data["round_id"] = (round_id or 0) + 1
        new_cont_data["round_started_at_ms"] = int(time.time() * 1000)
    new_cont_entity = Entity(type=CONTINUATION_JOIN_TYPE, data=new_cont_data)
    ctx.emit_pathway.emit(full_uri, new_cont_entity, emit_ctx)
    return new_cont_data


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
    # §3.6 step 6 — same seeding as the forward path; the join's terminal
    # dispatch is a chain dispatch too.
    ctx = _step6_chain_context(ctx)

    target = cont_data.get("target")
    operation = cont_data.get("operation")
    expected = cont_data.get("expected", [])
    received = dict(cont_data.get("received") or {})
    remaining = cont_data.get("remaining_executions")
    deliver_to_data = cont_data.get("deliver_to")
    on_error_data = cont_data.get("on_error")

    # PROPOSAL-CONTINUATION-STANDING-MODEL §4/§4.1 — round bookkeeping.
    # Absent completion_deadline_ms these stay None and every branch below
    # that reads them is a no-op: byte-identical to a pre-§4 join.
    completion_deadline_ms = cont_data.get("completion_deadline_ms")
    round_id = cont_data.get("round_id")
    round_started_at_ms = cont_data.get("round_started_at_ms")

    if not target or not operation:
        return _error_response(400, "invalid_continuation", "Continuation missing target or operation")

    # Check lifecycle - exhausted?
    if remaining is not None and remaining <= 0:
        return _error_response(410, "continuation_exhausted", "Continuation has no remaining executions")

    # O5: register this deadline-carrying join as sweepable from ordinary
    # advance traffic too (install already does this at its own site) — the
    # sweep index fills without a separate registration subsystem.
    _note_join_path(ctx, continuation_path, completion_deadline_ms)

    # §4 mechanism 2 — lazy reap-on-touch, the same-join fallback for the
    # round THIS advance is about to touch (the O5 sweep at the top of
    # _handle_advance already reaps independent of this join's own traffic,
    # but a throttled sweep can legitimately skip a round that just expired,
    # so this re-checks). The wire-observable outcome (self-heal: `lost`
    # marker, received reset, round_id turned over — or a fire-partial
    # dispatch) is what's cross-impl-pinned, not which of the two call sites
    # actually reaped it.
    acted, new_cont_data = await _reap_expired_join_round(
        ctx, full_uri, continuation_path, cont_data,
    )
    if acted:
        if new_cont_data is None:
            # A fire-partial reap exhausted remaining_executions and deleted
            # the join — nothing left for this slot to accumulate into.
            return _advancement_not_found()
        cont_data = new_cont_data
        received = dict(cont_data.get("received") or {})
        round_id = cont_data.get("round_id")
        round_started_at_ms = cont_data.get("round_started_at_ms")
        remaining = cont_data.get("remaining_executions")

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

    # §4.1 — round_id straggler guard (MUST). Engages only when the join is
    # deadline-carrying AND this advance is round-tagged; an untagged
    # advance into a deadline-carrying join stays admitted as before
    # (additive, no-silent-change).
    advance_round_id = params.get("round_id")
    if (
        completion_deadline_ms is not None
        and advance_round_id is not None
        and advance_round_id != round_id
    ):
        _bind_lost_marker(
            ctx,
            code=ENGINE_CODE_JOIN_LATE,
            status=200,
            request_id=_synthesized_step_key("join-late", continuation_path),
            continuation_path=continuation_path,
            extra_body={
                "slot": slot,
                "targeted_round": advance_round_id,
                "current_round": round_id,
            },
        )
        return {
            "status": 200,
            "result": {
                "type": "system/continuation/advance-result",
                "data": {
                    "advanced": False,
                    "dropped": "stale_round",
                    "slot": slot,
                    "targeted_round": advance_round_id,
                    "current_round": round_id,
                },
            },
        }

    # Exactly-once: reject if slot already filled
    if slot in received:
        return _error_response(409, "slot_already_filled", f"Slot {slot} already received")

    # §4 mechanism 1 — preserve a delivered-error slot's status rather than
    # coercing it; the downstream target/stitch decides whether to reject
    # on it (the join itself still fires normally — §4 mechanism 1).
    if status is not None and status >= 300:
        _bind_lost_marker(
            ctx,
            code=ENGINE_CODE_JOIN_ERROR_SLOT,
            status=status,
            request_id=_synthesized_step_key("join-error-slot", continuation_path),
            continuation_path=continuation_path,
            extra_body={"slot": slot},
        )

    # Accumulate result in slot
    received[slot] = result

    # Check if all slots filled
    if set(received.keys()) == set(expected):
        # All slots filled - dispatch to target
        logger.debug(f"Join continuation complete: {continuation_path}")

        # §4 brake: the join's terminal dispatch is a chain hop too — suspend if
        # the causal chain has climbed past the ceiling. Guarded here (at the
        # terminal dispatch), NOT at accumulation: filling a slot is a fresh
        # delivery, not a causal advancement.
        if _chain_depth_exceeded(ctx):
            return _suspend_chain_depth_exceeded(cont_data, continuation_path, ctx)

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
                        _synthesized_step_key("error", continuation_path),
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
                        request_id=_synthesized_step_key("error", continuation_path),
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
                    else _synthesized_step_key("join", continuation_path)
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

        # Update lifecycle via the same aging shared with fire-partial's
        # terminal fire (mirrors Go's advanceJoinLifecycle / rust's
        # finish_join_round): decrement a finite join's remaining_executions,
        # deleting it at zero, or reset a standing one (remaining is None)
        # for the next round — a standing join owns its completion policy
        # the same as a bounded one (§4's "owns its liveness independent of
        # any trigger").
        _age_join_after_fire(ctx, full_uri, cont_data)

        # Chain to deliver_to
        if deliver_to_data and dispatch_result.ok:
            deliver_to = DeliverySpec.from_dict(deliver_to_data)
            try:
                await ctx.deliver_async(
                    _synthesized_step_key("chain", continuation_path),
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
        if completion_deadline_ms is not None:
            new_cont_data["round_id"] = round_id
            new_cont_data["round_started_at_ms"] = round_started_at_ms
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


class _MarkerCollectState:
    """Per-peer throttle bookkeeping for the v1.23 collection sweep.

    Keyed off ``emit_pathway`` identity in a WeakKeyDictionary, exactly as
    :class:`_JoinSweepState` is — one EmitPathway per peer, alive for the
    peer's lifetime, and reclaimed automatically when a test fixture or a
    torn-down peer drops it. No Extension hook and no peer-lifecycle wiring,
    which is what keeps this free of a start/stop/leak-on-drop lifecycle.
    """

    __slots__ = ("last_collect_ms",)

    def __init__(self) -> None:
        self.last_collect_ms: int = 0


_marker_collect_states: weakref.WeakKeyDictionary[Any, _MarkerCollectState] = (
    weakref.WeakKeyDictionary()
)


def _marker_collect_state_for(emit_pathway: Any) -> _MarkerCollectState:
    state = _marker_collect_states.get(emit_pathway)
    if state is None:
        state = _MarkerCollectState()
        _marker_collect_states[emit_pathway] = state
    return state


def marker_retention_from_config(emit_pathway: Any) -> int | None:
    """Read the v1.23 operator knob — ``retention_ms`` on the config entity at
    :data:`MARKER_RETENTION_CONFIG_PATH` — out of this peer's own tree.

    Returns the configured window in milliseconds, or ``None`` when the
    operator has set nothing here (unresolved path, missing entity, absent or
    non-integer field). Best-effort and read-only, like everything else on this
    tree: the config is **advisory over a working default**, never a
    precondition, so no failure mode here is an error — it just means "fall
    back to :data:`DEFAULT_MARKER_RETENTION_MS`".

    Unknown fields on the entity are ignored (V7 forward-compat MUST-ignore);
    only ``retention_ms`` is defined today. An explicit ``0`` is returned as
    ``0`` and is meaningful — :data:`RETAIN_MARKERS_FOREVER`, the operator
    turning collection off — which is why "absent" is ``None`` and not ``0``.
    """
    if emit_pathway is None:
        return None
    try:
        entity_tree = emit_pathway.entity_tree
        content_hash = entity_tree.get(MARKER_RETENTION_CONFIG_PATH)
        if content_hash is None:
            return None
        config = emit_pathway.content_store.get(content_hash)
        if config is None:
            return None
        value = config.data.get(MARKER_RETENTION_FIELD)
    except Exception:  # a config read must never affect a chain
        return None
    # bool is an int subclass and `retention_ms: true` is not a window.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def collect_expired_markers(
    emit_pathway: Any, retention_ms: int, now_ms: int,
) -> int:
    """Remove every §3.10 chain-error marker older than ``retention_ms``,
    returning how many were collected.

    **Self-collection** (v1.23 §3.4 A.1): a peer reaping its own markers out of
    its own tree under its own authority. Both kinds are in scope — the sweep
    walks :data:`CHAIN_ERROR_MARKER_ROOT` and reads the timestamp each marker
    body carries, so `lost` and `rejected` age out identically.

    Only the **tree binding** is dropped; the body stays content-addressed and
    auditable, which is the same call `_gc_decided_pending` makes for registry
    pending heads and preserves the ruling's "independently of the pointer".

    Best-effort and strictly non-reactive, like every other operation on this
    tree. An entity that does not resolve, does not decode, or is not a marker
    is **skipped rather than deleted** — deleting something we did not identify
    is how a reaper becomes a data-loss bug. Collection MUST NOT be able to
    affect a chain: it removes observations, never behaviour.

    ``retention_ms == RETAIN_MARKERS_FOREVER`` collects nothing.
    """
    if retention_ms == RETAIN_MARKERS_FOREVER or emit_pathway is None:
        return 0
    if now_ms <= retention_ms:
        # Clock before epoch+window (a test clock, or a peer with no wall
        # time yet) — nothing can be expired yet, and an underflowed cutoff
        # would sweep the whole tree.
        return 0
    cutoff = now_ms - retention_ms

    collected = 0
    try:
        entity_tree = emit_pathway.entity_tree
        paths = list(entity_tree.list_prefix(CHAIN_ERROR_MARKER_ROOT))
    except Exception:
        return 0
    for path in paths:
        try:
            content_hash = entity_tree.get(path)
            if content_hash is None:
                continue
            entity = emit_pathway.content_store.get(content_hash)
            if entity is None or entity.type != LOST_ERROR_MARKER_TYPE:
                # An intermediate binding, or something else's entity.
                continue
            timestamp = entity.data.get("timestamp")
            if isinstance(timestamp, bool) or not isinstance(timestamp, int):
                continue
            # The timestamp is captured at failure-ORIGINATION (§3.10.6), not
            # at bind time — which is exactly what makes it a sound age: a
            # redelivered marker does not look younger than the failure it
            # records. A marker with no timestamp is never aged out; absent
            # evidence is not evidence of age.
            if timestamp == 0 or timestamp > cutoff:
                continue
            if entity_tree.remove(path) is not None:
                collected += 1
        except Exception:  # one bad marker must not stop the sweep
            continue
    return collected


def maybe_collect_markers(emit_pathway: Any, now_ms: int | None = None) -> int:
    """Run a throttled collection sweep from a marker-bind path.

    **Bind-time rather than a background task**, deliberately, and the same
    call `_maybe_sweep_joins` and `_gc_decided_pending` already make in this
    repo: nothing here owns a timer or a task, so there is no lifecycle to
    start, stop, or leak on drop. Binding is precisely when this tree grows, so
    it is precisely when a bounded sweep is worth paying for — and a peer that
    has stopped failing has nothing left to collect. The throttle
    (:data:`MARKER_COLLECT_THROTTLE_MS`) keeps the amortized cost off the
    dispatch path.

    The consequence, stated plainly: the last batch of markers outlives the
    window until something binds again. That is conformant — §3.4 A.1 makes the
    window an **eligibility** threshold ("GC-eligible after"), not a deadline —
    and on an idle peer it is bounded by one window's worth of markers.

    Precedence: the operator's tree config wins when present (including an
    explicit ``0``), else :data:`DEFAULT_MARKER_RETENTION_MS`. Go carries an
    additional deploy-time builder default between those two; Python does not,
    because v1.23 made the tree config *the* knob and a second one would be a
    place for the two impls to disagree about which wins.

    Returns the number collected (0 when throttled or disabled). Never raises.
    """
    if emit_pathway is None:
        return 0
    moment = int(time.time() * 1000) if now_ms is None else now_ms
    state = _marker_collect_state_for(emit_pathway)
    if (
        state.last_collect_ms
        and (moment - state.last_collect_ms) < MARKER_COLLECT_THROTTLE_MS
    ):
        return 0
    state.last_collect_ms = moment

    configured = marker_retention_from_config(emit_pathway)
    retention = DEFAULT_MARKER_RETENTION_MS if configured is None else configured
    if retention == RETAIN_MARKERS_FOREVER:
        return 0
    collected = collect_expired_markers(emit_pathway, retention, moment)
    if collected:
        logger.debug(
            "collected %d expired chain-error marker(s) (retention %dms)",
            collected, retention,
        )
    return collected


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
    # Neither coordinate is necessarily locally-minted: the subscription engine
    # reaches this binder with a chain_id taken straight from wire-supplied
    # notification bounds, and `code` is a remote handler's own error code.
    # Sanitized before the body is built so the recorded coordinate matches
    # where the marker is actually bound.
    raw_chain_id = getattr(ctx, "chain_id", None) or "unknown"
    chain_id = sanitize_path_segment(raw_chain_id, CHAIN_ID_UNSPECIFIED)
    step_index_value = sanitize_path_segment(request_id, STEP_INDEX_UNSPECIFIED)
    sanitized_reason = _sanitize_reason(code)
    marker_path = "<unknown>"
    try:
        marker_data: dict[str, Any] = {
            # §3.10.6 reserved across both kinds. THE BODY IS THE RECORD; THE
            # PATH IS AN INDEX (ROUTING-2026-07-17 §2): each field holds the
            # ORIGINAL value, and the path holds the sanitized form. This is
            # §3.10.5's landed shape generalized — path {reason} =
            # `unspecified_error` while body `code` = the raw code — and it is
            # what makes a quarantined coordinate forensically recoverable.
            "reason": sanitized_reason,
            "code": code,  # raw code; equals reason when path-safe
            "status": status,
            "timestamp": timestamp_ms,
            "chain_id": raw_chain_id,
            "step_index": request_id,
        }
        if extra_body:
            marker_data.update(extra_body)
        marker = Entity(type=LOST_ERROR_MARKER_TYPE, data=marker_data)
        marker_hash = marker.compute_hash()
        marker_path = (
            f"system/runtime/chain-errors/{kind}/{chain_id}/{step_index_value}/"
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
        # v1.23 §3.4 A.1 MUST-collect: the binder is the collector. Throttled,
        # and after the bind so a sweep can never cost us the marker we came
        # here to write.
        maybe_collect_markers(ctx.emit_pathway)
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
    # Both coordinates are WIRE-SUPPLIED here and this bind happens BECAUSE the
    # sender's cap check failed — an unauthorized caller reaches this site by
    # construction, so neither value may be trusted as a path component.
    # Sanitized before the body is built so the recorded coordinate matches
    # where the marker is actually bound.
    raw_chain_id = chain_id or "unknown"
    chain_id_value = sanitize_path_segment(raw_chain_id, CHAIN_ID_UNSPECIFIED)
    step_index_value = sanitize_path_segment(request_id, STEP_INDEX_UNSPECIFIED)
    sanitized_reason = _sanitize_reason(code)
    marker_path = "<unknown>"
    try:
        marker_data: dict[str, Any] = {
            # Body = originals, path = sanitized (ROUTING-2026-07-17 §2). This
            # is the marker whose whole purpose is to observe a hostile
            # failure, so these two fields ARE the forensic record: they are
            # the only surviving evidence of what the sender actually sent.
            "reason": sanitized_reason,
            "code": code,
            "status": status,
            "timestamp": timestamp_ms,
            "chain_id": raw_chain_id,
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
            f"{step_index_value}/{sanitized_reason}/{marker_hash.hex()}"
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
        # v1.23 §3.4 A.1 MUST-collect. The `rejected` kind grows the same tree
        # from the dispatcher side, so it pays for the same sweep — otherwise a
        # peer that only ever *receives* rejected chains would bind forever and
        # never collect, which is the leak wearing a different hat.
        maybe_collect_markers(emit_pathway)
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

    # §7: resume roots chain_depth at 0. Resume is an operator-authorized fresh
    # dispatch (often *caused by* a chain_depth_exceeded suspension); if it
    # inherited the suspending chain's depth it would immediately re-suspend.
    # Fresh operator intent = fresh root, same as a fresh external trigger.
    if ctx.bounds is not None and ctx.bounds.chain_depth is not None:
        ctx.bounds = ctx.bounds.copy()
        ctx.bounds.chain_depth = None

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
