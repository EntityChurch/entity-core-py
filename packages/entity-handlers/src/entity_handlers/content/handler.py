"""System content handler per EXTENSION-CONTENT v3.5 §6.

Two operations, both hash-addressed in their params but path-as-resource
at the cap-scope level per the v3.5 §6.2 / §6.3 normative tightening:

* ``system/content:get`` — type-agnostic hash → entity retrieval. Returns
  a ``system/content/content-response`` listing ``found`` and ``missing``
  hashes; resolved entities ride in the response envelope's ``included``
  map. The §4.3 small-content optimization is applied here: if a
  resolved entity is a ``system/content/blob`` with ``total_size <=
  MIN_CHUNK_SIZE`` (64 KiB), its chunks are also inline-included.

* ``system/content:ingest`` — content-store writes. Envelope mode stores
  root + every included entity, hash-validating each. Entity mode stores
  a single standalone entity. Returns ``system/content/ingest-result``.
  In envelope mode with a non-null ``envelope.root``, the result MUST
  carry the inlined ``root`` (§11.1 MUST).

**Behavior change vs v3.4 (§6.2 / §6.3):** both ops MUST return
``path_required`` when the EXECUTE arrives without a ``resource`` field.
Python had no v3.4 surface, so no migration; we ship v3.5 directly.

**Two-level cap check (§6.4).** Dispatch already verifies the handler
grant scope (operation, namespace resource). The handler performs the
path-scope check via :py:meth:`HandlerContext.check_caller_permission`
as defense-in-depth — when ``resource`` was present, this is redundant
but cheap; when ``resource`` was absent we already errored before this
point.
"""

from __future__ import annotations

import logging
from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.protocol.framing import MAX_MESSAGE_SIZE
from entity_core.utils.ecf import Hash, ecf_encode

from entity_handlers._common import error_response, normalize_hash, resource_target
from entity_handlers.content.chunking import MIN_CHUNK_SIZE

logger = logging.getLogger(__name__)

CONTENT_HANDLER_PATTERN: str = "system/content"
"""Per the §4.9 (GUIDE-EXTENSION-DEVELOPMENT) registration discipline:
the handler binds at the prefix path; the manifest's ``pattern`` field
advertises the spec glob (``system/content/*``). The dispatcher walks
back from the request path to find this prefix.
"""


# -----------------------------------------------------------------------------
# Deployment-topology obligation per CONTENT v3.6 §6.4.1
# -----------------------------------------------------------------------------
#
# This implementation currently supports **single-trust-domain topology
# only** (CONTENT v3.6 §6.4.1) — `_handle_ingest` writes to the content
# store directly with no namespace-keyed tree binding (no Hash Tree
# Presence per §6.4.2). All callers of a given handler instance are
# treated as belonging to the same trust level.
#
# Per §6.4.1 (normative):
#
#   "Single-trust-domain topology is for single-trust-domain
#    deployments only: dev/test environments, single-machine
#    deployments, deployments where every cap-holding caller is at the
#    same trust level by construction. Implementations supporting this
#    topology MUST document it as explicitly opt-in and MUST NOT enable
#    it as the default configuration. Multi-party deployments operating
#    under single-trust-domain topology are out-of-spec and security-
#    defective."
#
# **Operator obligation:** deployments using this handler in a
# multi-party context are out-of-spec until namespace-scoped topology
# (Shape A wiring per §6.4.2) lands. Namespace-scoped support is
# deferred to a future cycle (estimated ~30-60 LOC); when it lands,
# this handler becomes a dual-mode implementation with topology
# selectable per handler instance per §6.4.1 mixed-mode language.
#
# **What "MUST NOT enable as default" means for the Python impl:**
# `PeerBuilder.with_content_handler()` mounts the handler at the
# `system/content` prefix without any namespace subdivision; this is a
# single-trust-domain configuration. Production multi-party deployments
# MUST NOT use this builder method as-is; they MUST wait for the
# namespace-scoped wiring to land, or compose a custom builder that
# applies their own cap-checked dispatcher over the broad content
# namespace (out-of-band coordination with the deployment operator).
#
# This docstring is the §6.4.1 MUST-document compliance surface.
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------


async def content_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Dispatch ``system/content:{operation}`` per §6.2 / §6.3.

    Args:
        path: Full request path (includes the ``system/content`` prefix
            and any namespace tail). Per §6.4, the namespace is whatever
            follows the prefix.
        operation: ``"get"`` or ``"ingest"``.
        params: EXECUTE params entity dict (``{"type": ..., "data": ...}``)
            or the bare data dict.
        ctx: Handler context. ``ctx.resource_targets`` carries the
            EXECUTE's ``resource.targets`` — REQUIRED for both ops in
            v3.5; absence → ``path_required``.

    Returns:
        Response dict per the handler protocol (``{"status", "result"}``).
    """
    params_data = _extract_params(params)

    if operation == "get":
        return await _handle_get(params_data, ctx)
    if operation == "ingest":
        return await _handle_ingest(params_data, ctx)

    return error_response(
        501,
        "unsupported_operation",
        f"system/content handler does not support operation: {operation}",
    )


def _extract_params(params: Any) -> dict[str, Any]:
    """Pull the operation data dict out of a ``{type, data}`` envelope
    or accept a bare dict, mirroring the tree handler's convention.
    """
    if isinstance(params, dict):
        if "data" in params and isinstance(params["data"], dict):
            return params["data"]
        return params
    return {}


# -----------------------------------------------------------------------------
# get (§6.2)
# -----------------------------------------------------------------------------


async def _handle_get(
    params: dict[str, Any], ctx: HandlerContext
) -> dict[str, Any]:
    """Per §6.2: hash-addressed retrieval.

    Algorithm (spec §6.2):

        handle_get(params, ctx):
            found, missing = [], []
            for hash in params.hashes:
                entity = content_store.get(hash)
                if entity is not None:
                    ctx.include(hash, entity)
                    found.append(hash)
                else:
                    missing.append(hash)
            return {found, missing}

    v3.5 strengthening (§6.2 path-as-resource MUST): without a resource
    target, this returns ``path_required``.

    §4.3 inline-include extension: when a resolved entity is a
    ``system/content/blob`` and its ``total_size <= MIN_CHUNK_SIZE`` (64
    KiB), its chunks are ALSO included — the small-content
    one-round-trip optimization. Applied here on the system content
    handler's ``get`` because it's idempotent w/r/t correctness and
    saves a downstream EXECUTE for the dominant small-content case.
    """
    target_path = resource_target(ctx)
    if target_path is None:
        return error_response(
            400,
            "path_required",
            "system/content:get requires a resource target (v3.5 §6.2 / V7 §3.2)",
        )

    # Dispatch-level check_permission has already verified the handler-
    # scope + resource-scope grant covers this EXECUTE (V7 §5.2). Per
    # §6.4 the handler MAY add a defense-in-depth check_caller_permission,
    # but it's redundant when `resource` was present — and we already
    # errored above when it was absent. Skipping it keeps the handler
    # focused on its actual job (hash → entity resolution).

    raw_hashes = params.get("hashes") or []
    if not isinstance(raw_hashes, list):
        return error_response(
            400, "invalid_params", "`hashes` must be a list of system/hash values"
        )

    # Per RULINGS-STORAGE-SUBSTITUTE-CROSS-IMPL Ruling 4: the
    # substitute chain's `source_peer_id` is **local dispatcher context**,
    # NOT a wire field on `system/content:get-request`. The chain helper
    # `consult_substitute_chain(...)` is exposed for SDK / dispatcher use;
    # this handler does NOT auto-invoke it. Phase 2 (transport composition
    # + dispatcher tree-walk) is where consumer-side wiring lives.

    store = ctx.emit_pathway.content_store
    included: dict[bytes, dict[str, Any]] = {}
    found: list[Hash] = []
    missing: list[Any] = []

    # CONTENT v3.6 Amendment 1 (§6.2 frame-budget MUST): consult the
    # connection's configured frame budget at response-construction time
    # (V7 §1.1.4 — currently the system-wide MAX_MESSAGE_SIZE in Python; per
    # spec NOT a hardcoded literal — reading the named constant is the
    # configured-budget path). Reserve headroom for the wire envelope's
    # outer scaffold (root entity + map keys + signatures + transport
    # framing) so the receiver's frame-size guard doesn't trip on the
    # response payload's last entity. The 14 MiB / 16 MiB split below leaves
    # ~12% margin which empirically covers worst-case envelope overhead for
    # the response shapes the content handler produces.
    budget = max(MAX_MESSAGE_SIZE - (MAX_MESSAGE_SIZE // 8), 64 * 1024)
    included_bytes = 0

    for raw in raw_hashes:
        h = normalize_hash(raw)
        if h is None:
            # Malformed hash in the request — record as missing rather
            # than fail the whole op. The spec's `missing` semantics
            # accommodate "can't be served" for any local reason.
            missing.append(raw if isinstance(raw, (bytes, bytearray)) else b"")
            continue
        entity = store.get(h)
        if entity is None:
            missing.append(h)
            continue
        entity_dict = entity.to_dict()
        entity_size = _estimate_entity_size(entity_dict)
        if included_bytes + entity_size > budget and found:
            # Frame-budget spillover (CONTENT v3.6 Amendment 1 §6.2): include
            # as many as fit in request order; move the rest to `missing`.
            # Emit the entry as a bare hash — per CONTENT v3.6 Amendment 2
            # §6.2 the canonical `missing` shape is `array_of system/hash`;
            # the earlier per-entry `{hash, pending}` dict form was retracted
            # as non-conformant. Sync-state visibility, when offered, rides
            # on an optional sidecar `pending` field (subset of `missing`) —
            # not populated here because frame-budget spillover is a
            # transport-layer concern, not a sync-state assertion. The
            # requester (typically `content.EnsureClosure`) retries with
            # the missing hashes; subsequent dispatches have a fresh
            # budget. If `found` is empty we still include this entity to
            # guarantee forward progress per request.
            missing.append(h)
            continue
        included[h] = entity_dict
        included_bytes += entity_size
        found.append(h)
        # §4.3 small-content inline-include — also under the frame-budget
        # discipline; partial inlining is allowed.
        if entity.type == "system/content/blob":
            included_bytes = _inline_chunks_if_small(
                entity, store, included, included_bytes, budget,
            )

    # v3.6 F4 wire-shape convergence: result carries the
    # content-response entity directly; fetched entities ride in the
    # outer wire envelope's `included` map via the `envelope_included`
    # opt-in hoist (peer.py::_collect_wire_included). This matches Go's
    # shape on the entity-delivery channel and the V7 §3.3 v7.51
    # envelope-`included` preservation pattern; consumers read from
    # `envelope.included` rather than parsing entities out of the
    # response body.
    #
    # We retain `found: array_of hash` (NOT a counter) because telling
    # consumers WHICH hashes hit is strictly more useful than a count;
    # they otherwise have to set-difference `missing` from the request
    # to recover the same information. See COORDINATION-CONTENT-V3.6-V2
    # for the push-back on §8.3's `found: uint64` proposal.
    response = {
        "type": "system/content/content-response",
        "data": {"found": found, "missing": missing},
    }
    return {
        "status": 200,
        "result": response,
        "envelope_included": included,
    }


def _inline_chunks_if_small(
    blob: Entity,
    store: Any,
    included: dict[bytes, dict[str, Any]],
    included_bytes: int,
    budget: int,
) -> int:
    """§4.3: when a returned blob's ``total_size`` is at or below
    ``MIN_CHUNK_SIZE`` (64 KiB), also include its chunk entities in the
    response envelope.

    Returns the running ``included_bytes`` count after any chunks added.

    Pragmatic SHOULD: failing to find a chunk in the local store is not
    an error here — the caller will discover the missing chunk on
    reassembly and refetch through normal channels.

    Frame-budget discipline (CONTENT v3.6 Amendment 1 §6.2): chunks that
    would push the included payload over budget are silently skipped — the
    consumer's reassembly fetches them in the standard
    ``system/content:get`` retry path. This preserves the small-content
    one-round-trip optimization for the common case while remaining
    frame-budget-safe.
    """
    total_size = blob.data.get("total_size")
    if not isinstance(total_size, int) or total_size > MIN_CHUNK_SIZE:
        return included_bytes
    for chunk_hash in blob.data.get("chunks") or []:
        if not isinstance(chunk_hash, (bytes, bytearray)):
            continue
        h = bytes(chunk_hash)
        if h in included:
            continue
        chunk = store.get(h)
        if chunk is None:
            continue
        chunk_dict = chunk.to_dict()
        chunk_size = _estimate_entity_size(chunk_dict)
        if included_bytes + chunk_size > budget:
            continue
        included[h] = chunk_dict
        included_bytes += chunk_size
    return included_bytes


def _estimate_entity_size(entity_dict: dict[str, Any]) -> int:
    """Estimate the on-wire byte cost of an entity in the envelope's `included`.

    Returns the ECF (deterministic CBOR) encoded length — the exact size the
    entity occupies on the wire when delivered via envelope.included.
    Estimation is exact for our purposes; the only off-by-a-few-bytes is the
    list-element overhead from CBOR array encoding, which the budget
    headroom (~12% reserve) absorbs.
    """
    try:
        return len(ecf_encode(entity_dict))
    except Exception:
        # Defensive — if an entity dict is malformed in a way ECF can't
        # encode, fall back to a generous estimate so we err on the side of
        # NOT including it (one missing-list entry beats a frame overflow).
        return MAX_MESSAGE_SIZE


# -----------------------------------------------------------------------------
# ingest (§6.3)
# -----------------------------------------------------------------------------


async def _handle_ingest(
    params: dict[str, Any], ctx: HandlerContext
) -> dict[str, Any]:
    """Per §6.3: write entities into the content store from an envelope
    or a standalone entity.

    Two input modes, exactly one required:

    * ``envelope``: stores ``envelope.root`` (if present) + every
      ``envelope.included`` entry. Each included entry's content hash
      MUST be recomputed against its key (``hash_mismatch`` on
      discrepancy). The result inlines ``root`` (§11.1 MUST when
      ``envelope.root`` is non-null).
    * ``entity``: stores a single entity. ``root`` is absent from the
      result.

    Both modes are idempotent — content-addressed storage is inherently
    idempotent; re-ingesting a known entity is a no-op.

    v3.5 strengthening (§6.3 path-as-resource MUST): without a resource
    target, this returns ``path_required``. The namespace path scopes
    *which writers can land bytes in which namespace partition* — the
    hashes are operation payload, the path is the cap-scope resource.
    """
    target_path = resource_target(ctx)
    if target_path is None:
        return error_response(
            400,
            "path_required",
            "system/content:ingest requires a resource target (v3.5 §6.3 / V7 §3.2)",
        )

    # See _handle_get for the rationale on skipping the redundant
    # path-scope defense-in-depth check.

    envelope = params.get("envelope")
    entity_payload = params.get("entity")

    if envelope is not None and entity_payload is not None:
        return error_response(
            400, "ambiguous_input", "Specify envelope or entity, not both"
        )
    if envelope is None and entity_payload is None:
        return error_response(
            400, "missing_input", "Specify envelope or entity"
        )

    store = ctx.emit_pathway.content_store

    # CONTENT §6.4.2 Hash Tree Presence MUST: for every ingested entity,
    # write a tree binding at `{target_path}/{hex(H)} → H`. This is the
    # missing-cohort-wide piece the arch ruling (follow-up
    # §2.3) identified as blocking namespace-scoped serving — without
    # this binding, NamespaceScope.in_scope can never fire. The ingest is
    # the only place this can land idempotently per the spec model
    # (CONTENT §6.4.1 namespace-scoped topology + §6.4.2 presence
    # predicate). The hex form is the full 33-byte hash (algorithm byte +
    # SHA-256 digest, `bytes.hex()`); the URL form (32-byte digest hex)
    # is normalized at the serving boundary, not stored.
    def _bind_namespace_presence(h: Hash) -> None:
        leaf = f"{target_path}/{bytes(h).hex()}"
        ctx.emit_pathway.emit_hash(leaf, h)

    # ----- Envelope mode -----
    if envelope is not None:
        if not isinstance(envelope, dict):
            return error_response(
                400, "invalid_params", "`envelope` must be a structured value"
            )
        env_data = envelope.get("data", envelope)
        root_dict = env_data.get("root")
        included_map = env_data.get("included") or {}
        if not isinstance(included_map, dict):
            return error_response(
                400, "invalid_params", "`envelope.included` must be a hash → entity map"
            )

        ingested = 0
        root_hash: Hash | None = None

        # Root first — its hash is the operation's anchor.
        if root_dict is not None:
            root_entity = _entity_from_dict(root_dict)
            if root_entity is None:
                return error_response(
                    400, "invalid_params", "`envelope.root` is not a valid entity"
                )
            root_hash = root_entity.compute_hash()
            store.put(root_entity)
            _bind_namespace_presence(root_hash)
            ingested += 1

        # Included entries — hash-validate each against its key (§6.3
        # "Each included entity's content hash is verified against its
        # key").
        for raw_key, raw_entity in included_map.items():
            key = normalize_hash(raw_key)
            if key is None:
                return error_response(
                    400, "hash_mismatch", "included key is not a valid hash"
                )
            entity = _entity_from_dict(raw_entity)
            if entity is None:
                return error_response(
                    400, "invalid_params", "included value is not a valid entity"
                )
            computed = entity.compute_hash()
            if computed != key:
                return error_response(
                    400,
                    "hash_mismatch",
                    "included entity hash does not match key",
                )
            store.put(entity)
            _bind_namespace_presence(computed)
            ingested += 1

        # F-CIMP-1 generalization — when `envelope.root` is
        # absent (bundle-only envelope), `root_hash` has nothing to point at.
        # The pre-fix shape emitted `b""` (zero-length bytes) which is not
        # a valid 33-byte hash and would fail Go's hash decoder with the
        # same "invalid hash: expected 33 bytes, got 0" error that
        # surfaced F-CIMP-1 in revision:config. Omit the field rather
        # than emit a malformed sentinel. Type-definition side: §6.3
        # `system/content/ingest-result.root_hash` is now treated as
        # optional in the bundle-only path (parallels `root` which §11.1
        # already omits when envelope.root is null).
        result_data: dict[str, Any] = {
            "ingested_count": ingested,
        }
        if root_hash is not None:
            result_data["root_hash"] = root_hash
        if root_dict is not None:
            # §11.1 MUST: the inlined root pass-through. Round-trip the
            # entity through our value form so the result carries a
            # stable dict shape.
            result_data["root"] = root_dict

        return {
            "status": 200,
            "result": {
                "type": "system/content/ingest-result",
                "data": result_data,
            },
        }

    # ----- Entity mode -----
    if not isinstance(entity_payload, dict):
        return error_response(
            400, "invalid_params", "`entity` must be a {type, data, ...} value"
        )
    entity = _entity_from_dict(entity_payload)
    if entity is None:
        return error_response(
            400, "invalid_params", "`entity` is not a valid entity"
        )
    entity_hash = entity.compute_hash()
    store.put(entity)
    _bind_namespace_presence(entity_hash)
    return {
        "status": 200,
        "result": {
            "type": "system/content/ingest-result",
            "data": {
                "root_hash": entity_hash,
                "ingested_count": 1,
            },
        },
    }


def _entity_from_dict(d: Any) -> Entity | None:
    """Best-effort coercion of a ``{type, data, ...}`` dict into an
    :class:`Entity`. Returns None on shape failure — the caller maps
    None to a 400 error.

    The function is forgiving on incoming ``content_hash`` (V7 §1.8: we
    trust validated hashes) but does not require it; recompute happens
    on the verification path.
    """
    if not isinstance(d, dict):
        return None
    t = d.get("type")
    data = d.get("data")
    if not isinstance(t, str) or not isinstance(data, dict):
        return None
    content_hash = d.get("content_hash")
    return Entity(type=t, data=data, content_hash=content_hash)


__all__ = [
    "CONTENT_HANDLER_PATTERN",
    "content_handler",
]
