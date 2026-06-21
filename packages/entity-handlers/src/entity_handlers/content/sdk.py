"""SDK closure-completion surface for the content extension.

Per ``SDK-EXTENSION-OPERATIONS.md`` v0.8 §11 — Amendment A of the
content-materialization closure-completion proposal.

Exposes two affordances:

* :func:`ensure_closure` — cap-checked sequencer over ``system/content:get``
  that drains ``missing`` until the requested blob's full closure (blob
  entity + every chunk it references) is locally present in the content
  store.
* :func:`at_peer` — peer-aimed :class:`Dispatcher` for handler-cross-peer
  dispatch (workbench Option B).

**Byte extraction is NOT in this module.** Per the proposal's load-bearing
reframe: the SDK speaks closures; reassembly is a pure local helper
:func:`entity_handlers.content.reassemble_content` already exported from
``entity_handlers.content``. Callers chain ``ensure_closure`` →
``reassemble_content`` to obtain bytes.

The cap-flow story (proposal §3): each ``system/content:get`` is independently
cap-checked at the dispatcher; the caller's cap must cover that op on
``namespace``. Handler-internal callers ride their handler's ``internal_scope``;
cross-peer callers ride standard V7 §5.10 cap delegation. No privilege
amplification beyond what direct ``system/content:get`` would already permit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from entity_core.handlers.context import ExecuteResult
from entity_core.protocol.entity import Entity
from entity_core.sdk.dispatcher import (
    Dispatcher,
    ExecuteRequest,
    HandlerContextDispatcher,
)
from entity_core.storage.content_store import ContentStore
from entity_core.utils.ecf import normalize_hash

from entity_handlers.content.chunking import GET_BATCH_SIZE

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext

logger = logging.getLogger(__name__)


DEFAULT_NAMESPACE = "system/content"
"""Default cap-scope target for the system content handler (per CONTENT v3.6 §6.4 + §6.2)."""


class ClosureError(RuntimeError):
    """Raised when :func:`ensure_closure` cannot complete the closure.

    The ``status`` attribute carries the partial-sync taxonomy code per the
    proposal's §4.1 step 2 / CONTENT v3.6 §3.4:

    * 403 — capability denial on a sub-dispatch (terminal)
    * 404 — referenced entity not expected to arrive (terminal)
    * 503 — ``blob_pending_sync`` — closure-incomplete; caller retries on the
      next sync event (transient)
    * other — bad request / internal error from the underlying dispatch
    """

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


@dataclass
class _PeerAimedDispatcher:
    """Internal: a Dispatcher that rewrites URIs to ``entity://{peer}/...``.

    Backs :func:`at_peer`. Reuses :class:`HandlerContextDispatcher`'s routing
    discipline so cross-peer ``HandlerContext.execute`` continues to land in
    the existing :meth:`Peer._execute_internal` → ``_remote_execute`` path.
    """

    inner: Dispatcher
    peer_id: str

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        rewritten = self._rewrite_uri(request.uri)
        if rewritten == request.uri:
            return await self.inner.execute(request)
        # Lean copy — only the uri changes, every other field is preserved
        # by reference. ExecuteRequest is a dataclass so this is cheap.
        new_request = ExecuteRequest(
            uri=rewritten,
            operation=request.operation,
            params=request.params,
            resource_targets=request.resource_targets,
            included=request.included,
            capability=request.capability,
            capability_chain=request.capability_chain,
        )
        return await self.inner.execute(new_request)

    def _rewrite_uri(self, uri: str) -> str:
        if uri.startswith("entity://"):
            return uri
        # Bare path → peer-aimed URI.
        return f"entity://{self.peer_id}/{uri.lstrip('/')}"


def at_peer(handler_ctx: HandlerContext, source_peer_id: str) -> Dispatcher:
    """Return a Dispatcher that routes against ``source_peer_id`` from a handler.

    Per ``SDK-EXTENSION-OPERATIONS.md`` v0.8 §11 ``content.AtPeer``. The
    handler-cross-peer shape (workbench Option B): a handler running on peer
    B that needs to dispatch ``system/content:get`` against peer A's
    namespace (subscription-driven materialization per workbench Stage 3
    case 1.5) gets a peer-aimed dispatcher and passes it to
    :func:`ensure_closure`.

    The ``namespace`` argument to :func:`ensure_closure` stays purely
    cap-scope; peer authority is this dispatcher's concern.
    """
    return _PeerAimedDispatcher(
        inner=HandlerContextDispatcher(handler_ctx),
        peer_id=source_peer_id,
    )


async def ensure_closure(
    dispatcher: Dispatcher,
    blob_hash: Any,
    store: ContentStore,
    namespace: str = DEFAULT_NAMESPACE,
    *,
    get_batch_size: int = GET_BATCH_SIZE,
    max_loops: int = 64,
) -> None:
    """Drain ``system/content:get`` until the blob's closure is locally complete.

    Per ``SDK-EXTENSION-OPERATIONS.md`` v0.8 §11 ``content.EnsureClosure`` —
    the cap-checked sequencer. After this returns the blob entity and every
    chunk it references are present in ``store``; callers can then invoke
    :func:`entity_handlers.content.reassemble_content` (or a streaming
    variant) to obtain bytes.

    Args:
        dispatcher: Dispatcher contract — handler-internal (wrap a
            :class:`HandlerContext` with
            :class:`entity_core.sdk.HandlerContextDispatcher`), outer-caller
            cross-peer (wrap a :class:`Connection` with
            :class:`entity_core.sdk.ConnectionDispatcher`), or peer-aimed
            (:func:`at_peer`).
        blob_hash: The blob's hash (raw bytes, ``{algorithm, digest}`` dict,
            or hex string). Normalized via :func:`normalize_hash`.
        store: The local content store to drain into. Reassembly callers
            read from this same store afterward.
        namespace: Cap-scope target — the namespace prefix the cap covers
            per CONTENT v3.6 §6.4. Default ``"system/content"`` is the
            namespace for the system content handler.
        get_batch_size: Maximum hashes per ``system/content:get`` dispatch.
            Per CONTENT v3.6 §10.2 the recommended ceiling is 64; for
            streaming-eligible blobs (``total_size`` ≥ 64 MiB per §7.1) the
            initial value is 16. Caller-tunable; defaults to the package
            constant (currently 64).
        max_loops: Loop safety bound for the drain. Prevents pathological
            spin on a peer returning identical ``missing`` responses; a
            real-world closure resolves in O(total_chunks / batch_size)
            loops, so 64 is generous.

    Raises:
        ClosureError: When a sub-dispatch returns a terminal error (403 /
            404) or remains transient (503) past ``max_loops``. The
            ``status`` / ``code`` attributes carry the partial-sync
            taxonomy code.
    """
    normalized = normalize_hash(blob_hash)
    if normalized is None:
        raise ClosureError(
            400,
            "invalid_params",
            f"ensure_closure: blob_hash is not a valid hash ({blob_hash!r})",
        )

    cap_scope_path = namespace.rstrip("/")
    resource_targets = [cap_scope_path]

    # Step 1 — blob check. Fetch the blob entity if it's not already local.
    if not store.has(normalized):
        await _drain_batch(
            dispatcher=dispatcher,
            hashes=[normalized],
            store=store,
            cap_scope_path=cap_scope_path,
            resource_targets=resource_targets,
        )
        if not store.has(normalized):
            # The dispatch succeeded but the blob entity didn't arrive — the
            # peer's classification (pending vs not_found) was surfaced via
            # _drain_batch's missing-list handling. If we reach here without
            # a raise, the peer returned the blob as 404 silently; treat as
            # terminal.
            raise ClosureError(
                404,
                "not_found",
                f"blob {normalized.hex()[:16]}... not delivered by peer "
                f"in namespace {namespace!r}",
            )

    blob_entity = store.get(normalized)
    if blob_entity is None or blob_entity.type != "system/content/blob":
        raise ClosureError(
            500,
            "invalid_blob",
            f"hash {normalized.hex()[:16]}... resolves to non-blob entity "
            f"(type={blob_entity.type if blob_entity else 'None'})",
        )

    # Step 2 — enumerate the chunk list. Normalize each hash to canonical
    # bytes once; the resulting list is the universe we drain against.
    chunk_hashes: list[bytes] = []
    for raw in blob_entity.data.get("chunks") or []:
        h = normalize_hash(raw)
        if h is None:
            raise ClosureError(
                500,
                "invalid_blob",
                f"blob {normalized.hex()[:16]}... lists a non-hash chunk entry",
            )
        chunk_hashes.append(h)

    # Step 3 + 4 — drain in GET_BATCH_SIZE windows, looping until empty.
    # Cap with max_loops as defense against a misbehaving peer.
    for loop_idx in range(max_loops):
        needed = [h for h in chunk_hashes if not store.has(h)]
        if not needed:
            return
        # Take the front of `needed` per the spec's batching shape. The next
        # loop iteration recomputes against the store, so we don't need to
        # track which slice was sent vs which still missing — the store IS
        # the truth.
        batch = needed[:get_batch_size]
        await _drain_batch(
            dispatcher=dispatcher,
            hashes=batch,
            store=store,
            cap_scope_path=cap_scope_path,
            resource_targets=resource_targets,
        )
        # Progress check — if the batch landed exactly nothing in the store,
        # we'd otherwise spin. _drain_batch raises on 403/404 terminal; only
        # 503 / frame-budget-spillover survives. Promote to 503 if we made
        # zero progress and there's still work to do.
        if all(not store.has(h) for h in batch):
            logger.debug(
                "ensure_closure: loop %d made no progress on %d hashes "
                "(namespace=%s); promoting to 503 blob_pending_sync",
                loop_idx,
                len(batch),
                namespace,
            )
            raise ClosureError(
                503,
                "blob_pending_sync",
                f"chunks unavailable in {namespace!r}: "
                f"{[h.hex()[:8] for h in batch[:4]]}...",
            )

    # Should be unreachable given the progress-check raise above, but guard
    # explicitly so a bug doesn't cause silent infinite-loop-shaped errors.
    raise ClosureError(
        503,
        "blob_pending_sync",
        f"ensure_closure: closure incomplete after {max_loops} drain loops",
    )


async def _drain_batch(
    *,
    dispatcher: Dispatcher,
    hashes: list[bytes],
    store: ContentStore,
    cap_scope_path: str,
    resource_targets: list[str],
) -> None:
    """Dispatch one ``system/content:get`` batch and persist found entities.

    Raises :class:`ClosureError` on terminal failures (403, 404 on a hash
    annotated ``pending: false``). Missing hashes annotated ``pending: true``
    are left for the caller's outer loop (retry → 503 promotion).
    """
    request = ExecuteRequest(
        uri=cap_scope_path,
        operation="get",
        params={"hashes": list(hashes)},
        resource_targets=resource_targets,
    )
    result = await dispatcher.execute(request)

    if result.status == 403:
        # V7 §3.3 line 736 canonical 403 code (three-way cross-impl
        # convergence as of EXTENSION-CONTINUATION v1.19 ratification —
        # was `forbidden` in Python prior).
        raise ClosureError(
            403, "capability_denied",
            f"cap denial on system/content:get for namespace {cap_scope_path!r}",
        )
    if result.status >= 400:
        raise ClosureError(
            int(result.status),
            "dispatch_error",
            result.error or f"system/content:get failed (status={int(result.status)})",
        )

    # Persist found entities into the local store. They ride in
    # envelope_included per V3.6 F4 wire-shape; if the dispatcher came from
    # ConnectionDispatcher the map is normalized there already.
    included = result.envelope_included or {}
    for entity_dict in included.values():
        entity = Entity.from_dict(entity_dict)
        if entity is None:
            continue
        store.put(entity)

    # Classify any per-entry `missing` annotations. Per CONTENT v3.6 §8.3,
    # entries MAY be {hash, pending: bool}; the annotation is informational
    # and "does not change the `missing` list shape" — most impls emit bare
    # hashes (including frame-budget spillover per Amendment 1 §6.2). Bare
    # entries are retry-eligible at this layer; only an explicit
    # `pending: false` annotation classifies as terminal-404 here. The
    # outer drain loop's no-progress check is the universal terminal
    # signal — it fires regardless of annotation, so we don't need to
    # interpret bare entries as terminal.
    response_body = result.result if isinstance(result.result, dict) else {}
    response_data = response_body.get("data", {}) if isinstance(response_body, dict) else {}
    missing_raw = response_data.get("missing") if isinstance(response_data, dict) else None
    if not isinstance(missing_raw, list):
        return

    requested_set = {bytes(h) for h in hashes}
    for entry in missing_raw:
        miss_hash, annotation_present, pending = _split_missing_entry(entry)
        if miss_hash is None:
            continue
        if miss_hash not in requested_set:
            # The peer's `missing` carries something we didn't ask for; ignore
            # rather than misclassify.
            continue
        if not annotation_present:
            # Bare entry — retry-eligible per the canonical EnsureClosure
            # loop; no-progress check (outer loop) drives terminal.
            continue
        if pending:
            # Explicit transient — same outcome as bare; retry.
            continue
        # Explicit `pending: false` — peer is signaling terminal 404. The
        # only case we promote eagerly because the peer has positively
        # asserted no-arrival.
        raise ClosureError(
            404,
            "not_found",
            f"hash {miss_hash.hex()[:16]}... not found in namespace "
            f"{cap_scope_path!r} (peer marked pending=false)",
        )


def _split_missing_entry(
    entry: Any,
) -> tuple[bytes | None, bool, bool]:
    """Return ``(normalized_hash, annotation_present, pending_flag)``.

    Per CONTENT v3.6 §8.3 a `missing` entry MAY be a bare hash (unannotated
    — retry-eligible at the sequencer layer per the canonical EnsureClosure
    loop) or an ``{hash, pending: bool}`` dict (explicit annotation). The
    annotation-present flag lets the caller distinguish "peer didn't say"
    from "peer explicitly said pending=False" — the latter is the only
    eager-terminal signal at this layer.
    """
    if isinstance(entry, (bytes, bytearray)):
        return bytes(entry), False, False
    if isinstance(entry, dict):
        if "hash" in entry and "pending" in entry:
            return normalize_hash(entry.get("hash")), True, bool(entry["pending"])
        if "hash" in entry:
            return normalize_hash(entry.get("hash")), False, False
        if "algorithm" in entry and "digest" in entry:
            return normalize_hash(entry), False, False
    if isinstance(entry, str):
        return normalize_hash(entry), False, False
    return None, False, False


__all__ = [
    "ClosureError",
    "DEFAULT_NAMESPACE",
    "at_peer",
    "ensure_closure",
]
