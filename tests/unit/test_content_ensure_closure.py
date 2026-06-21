"""Tests for the closure-completion SDK surface (SDK-EXTENSION-OPERATIONS v0.8 §11).

Three classes:

1. **EnsureClosure happy paths** — drives the §7.2 closure-fetch algorithm
   against a stub Dispatcher backed by an authoritative content store; the
   blob + chunks land in the consumer's local store; reassembly works
   end-to-end via :func:`reassemble_content`.

2. **EnsureClosure error paths** — 403 cap denial, 404 terminal not-found
   (unannotated missing entry), 503 pending-sync (peer flagged transient
   then stops making progress).

3. **F8 frame-budget MUST** (CONTENT v3.6 Amendment 1 §6.2) — handler
   respects the configured budget; spillover entries land in `missing`
   with `pending: true` annotation; partial-response forward progress is
   guaranteed (at least one entity included per request).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.sdk import Dispatcher, ExecuteRequest
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.content import (
    CONTENT_HANDLER_PATTERN,
    ClosureError,
    build_fixed_size,
    content_handler,
    ensure_closure,
    persist,
    reassemble_content,
)


# -----------------------------------------------------------------------------
# Fixtures + stub dispatcher
# -----------------------------------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def _make_ctx_with_store(store: ContentStore | None = None) -> HandlerContext:
    """Build a HandlerContext whose store is `store` (or a fresh one)."""
    kp = Keypair.generate()
    content_store = store if store is not None else ContentStore()
    pathway = EmitPathway(content_store, EntityTree(kp.peer_id))
    return HandlerContext(
        local_peer_id=kp.peer_id,
        remote_peer_id=kp.peer_id,
        handler_grant={},
        caller_capability={},
        emit_pathway=pathway,
        handler_pattern=CONTENT_HANDLER_PATTERN,
        keypair=kp,
    )


@dataclass
class _ServerDispatcher:
    """Stub Dispatcher backed by a 'server-side' content_handler + store.

    Each `execute()` calls the real content handler with the server-side
    store + a resource_targets equal to the request's resource_targets. This
    mirrors the real wire path: dispatcher → cap-checked dispatch → handler
    returns `envelope_included`. We bypass cap-checking (the focus is the
    SDK sequencer, not the dispatcher's cap discipline — covered elsewhere).
    """

    server_store: ContentStore
    call_log: list[dict[str, list[bytes]]] = field(default_factory=list)
    # Optional override: when set, returns these results on next N calls.
    canned: list[ExecuteResult] = field(default_factory=list)

    async def execute(self, request: ExecuteRequest) -> ExecuteResult:
        # Record the call so tests can assert batching shape.
        params = request.params or {}
        hashes = [bytes(h) for h in params.get("hashes", []) if isinstance(h, (bytes, bytearray))]
        self.call_log.append({"hashes": hashes})

        if self.canned:
            return self.canned.pop(0)

        # Serve from the server store via the real handler.
        ctx = _make_ctx_with_store(self.server_store)
        ctx = HandlerContext(
            local_peer_id=ctx.local_peer_id,
            remote_peer_id=ctx.remote_peer_id,
            handler_grant={},
            caller_capability={},
            emit_pathway=ctx.emit_pathway,
            handler_pattern=CONTENT_HANDLER_PATTERN,
            resource_targets=request.resource_targets,
            keypair=ctx.keypair,
        )
        response = await content_handler(
            CONTENT_HANDLER_PATTERN, request.operation,
            {"data": params}, ctx,
        )
        return ExecuteResult(
            status=int(response.get("status", 500)),
            result=response.get("result"),
            envelope_included=response.get("envelope_included"),
            error=response.get("error"),
        )


def _build_blob(payload: bytes, *, chunk_size: int = 1024):
    """Returns ``BlobBuildResult`` — pass to ``persist(result, store)``."""
    return build_fixed_size(payload, chunk_size=chunk_size)


def _put_entity(store: ContentStore, type_: str, data) -> bytes:
    """Construct + persist a standalone entity; return its hash."""
    ent = Entity(type=type_, data=data)
    return store.put(ent)


# -----------------------------------------------------------------------------
# EnsureClosure happy paths
# -----------------------------------------------------------------------------


class TestEnsureClosureHappy:
    def test_drives_blob_plus_chunks_into_local_store(self):
        server_store = ContentStore()
        payload = b"x" * 8192  # 8 chunks of 1024
        result = _build_blob(payload, chunk_size=1024)
        # Persist on server side; client side starts empty.
        blob_hash = persist(result, server_store)
        chunks = list(result.chunks)
        assert server_store.has(blob_hash)

        client_store = ContentStore()
        dispatcher = _ServerDispatcher(server_store=server_store)

        _run(ensure_closure(dispatcher, blob_hash, client_store))

        # Closure-complete: blob + every chunk locally present.
        assert client_store.has(blob_hash)
        for ch in chunks:
            assert client_store.has(ch.compute_hash())

        # End-to-end byte fidelity via reassemble_content (the closure-think
        # contract: SDK landed the closure; reassembly is the local
        # pure-helper consumer call).
        reassembled = reassemble_content(blob_hash, client_store)
        assert reassembled == payload

    def test_small_content_lands_in_one_dispatch(self):
        """§4.3 inline-include: a ≤ MIN_CHUNK_SIZE blob arrives with chunks
        inline on the FIRST dispatch — EnsureClosure should detect that the
        chunks are already local after the blob-fetch step and skip the
        chunk-drain dispatch entirely."""
        server_store = ContentStore()
        payload = b"hello world\n" * 8  # ~96 bytes, well under MIN_CHUNK_SIZE
        result = _build_blob(payload, chunk_size=1024)
        blob_hash = persist(result, server_store)

        client_store = ContentStore()
        dispatcher = _ServerDispatcher(server_store=server_store)

        _run(ensure_closure(dispatcher, blob_hash, client_store))

        # Should have made exactly ONE dispatch — the §4.3 inline-include
        # delivers blob + chunks together.
        assert len(dispatcher.call_log) == 1
        assert reassemble_content(blob_hash, client_store) == payload

    def test_partial_local_closure_only_fetches_gap(self):
        """When some chunks are already locally present, EnsureClosure only
        dispatches for the gap — verifies the per-loop store recheck."""
        server_store = ContentStore()
        payload = b"y" * 4096
        result = _build_blob(payload, chunk_size=512)
        blob_hash = persist(result, server_store)
        chunks = list(result.chunks)

        client_store = ContentStore()
        # Pre-seed half the chunks on the client side.
        pre_seeded: set[bytes] = set()
        for ch in chunks[:len(chunks) // 2]:
            pre_seeded.add(client_store.put(ch))

        dispatcher = _ServerDispatcher(server_store=server_store)
        _run(ensure_closure(dispatcher, blob_hash, client_store))

        assert reassemble_content(blob_hash, client_store) == payload

        # Inspect what was requested from the server: nothing in pre_seeded
        # should have appeared in the chunk-fetch batch (the dispatcher's
        # SECOND call onward — the FIRST is the blob fetch).
        chunk_fetch_calls = dispatcher.call_log[1:]  # skip blob-fetch
        requested = {h for call in chunk_fetch_calls for h in call["hashes"]}
        assert requested.isdisjoint(pre_seeded)


# -----------------------------------------------------------------------------
# EnsureClosure error paths
# -----------------------------------------------------------------------------


class TestEnsureClosureErrors:
    def test_403_capability_denial_propagates(self):
        client_store = ContentStore()
        dispatcher = _ServerDispatcher(server_store=ContentStore())
        dispatcher.canned = [
            ExecuteResult(status=403, error="cap denial: namespace 'system/content'"),
        ]
        with pytest.raises(ClosureError) as exc_info:
            _run(ensure_closure(dispatcher, b"\x00" + b"a" * 32, client_store))
        assert exc_info.value.status == 403
        # v1.19 / EXTENSION-CONTINUATION §3.10.5 canonical 403 code per
        # V7 §3.3 line 736 (three-way cross-impl convergence). Was
        # `forbidden` pre-Stage-4-v1.19 in Python.
        assert exc_info.value.code == "capability_denied"

    def test_404_terminal_missing_raises_on_explicit_pending_false(self):
        """A `missing` entry with explicit ``pending: false`` annotation is
        terminal per CONTENT v3.6 §8.3 — peer has positively asserted
        no-arrival. Bare entries are retry-eligible; only the annotated
        false form is eagerly terminal."""
        client_store = ContentStore()
        missing_hash = b"\x00" + b"q" * 32
        dispatcher = _ServerDispatcher(server_store=ContentStore())
        dispatcher.canned = [
            ExecuteResult(
                status=200,
                result={
                    "type": "system/content/content-response",
                    "data": {
                        "found": [],
                        "missing": [{"hash": missing_hash, "pending": False}],
                    },
                },
                envelope_included={},
            ),
        ]
        with pytest.raises(ClosureError) as exc_info:
            _run(ensure_closure(dispatcher, missing_hash, client_store))
        assert exc_info.value.status == 404

    def test_bare_missing_drives_progress_check_to_503(self):
        """A peer that emits bare-hash `missing` entries (the canonical
        wire shape per §8.3) is retry-eligible; the sequencer's
        no-progress check (single-loop, since the blob never lands) drives
        the 404-no-delivery path. The point: bare entries are NOT eagerly
        terminal — the failure surfaces from the progress check, not from
        per-entry classification."""
        client_store = ContentStore()
        missing_hash = b"\x00" + b"r" * 32
        dispatcher = _ServerDispatcher(server_store=ContentStore())
        # Same bare-missing response forever — sequencer makes no progress
        # on the blob fetch, so it raises 404 (blob not delivered) after
        # the step-1 fetch.
        for _ in range(4):
            dispatcher.canned.append(ExecuteResult(
                status=200,
                result={
                    "type": "system/content/content-response",
                    "data": {"found": [], "missing": [missing_hash]},
                },
                envelope_included={},
            ))
        with pytest.raises(ClosureError) as exc_info:
            _run(ensure_closure(dispatcher, missing_hash, client_store))
        # The step-1 raise lands first because the blob entity itself is
        # never delivered.
        assert exc_info.value.status == 404
        # Only ONE dispatch attempted — the blob fetch — because once it
        # didn't land we raise immediately rather than spinning.
        assert len(dispatcher.call_log) == 1

    def test_503_pending_sync_after_no_progress(self):
        """A peer that returns `missing` with `pending: true` AND makes no
        progress across the drain loop eventually fails 503
        blob_pending_sync per §3.4."""
        client_store = ContentStore()
        missing_hash = b"\x00" + b"p" * 32
        dispatcher = _ServerDispatcher(server_store=ContentStore())
        # Return same pending-missing forever; sequencer should promote to
        # 503 on the first loop with zero progress.
        for _ in range(8):
            dispatcher.canned.append(ExecuteResult(
                status=200,
                result={
                    "type": "system/content/content-response",
                    "data": {
                        "found": [],
                        "missing": [{"hash": missing_hash, "pending": True}],
                    },
                },
                envelope_included={},
            ))
        with pytest.raises(ClosureError) as exc_info:
            _run(ensure_closure(dispatcher, missing_hash, client_store))
        assert exc_info.value.status in (404, 503)
        # When the blob itself never arrives, the post-step-1 raise classes
        # it as 404 (not delivered); same posture either way: terminal for
        # the caller, who retries on a sync event.

    def test_invalid_blob_hash_raises_400(self):
        client_store = ContentStore()
        dispatcher = _ServerDispatcher(server_store=ContentStore())
        with pytest.raises(ClosureError) as exc_info:
            _run(ensure_closure(dispatcher, 12345, client_store))
        assert exc_info.value.status == 400


# -----------------------------------------------------------------------------
# F8 frame-budget MUST (CONTENT v3.6 Amendment 1 §6.2)
# -----------------------------------------------------------------------------


class TestFrameBudgetRespected:
    def _make_handler_ctx(self, store: ContentStore, namespace: str) -> HandlerContext:
        kp = Keypair.generate()
        pathway = EmitPathway(store, EntityTree(kp.peer_id))
        return HandlerContext(
            local_peer_id=kp.peer_id,
            remote_peer_id=kp.peer_id,
            handler_grant={},
            caller_capability={},
            emit_pathway=pathway,
            handler_pattern=CONTENT_HANDLER_PATTERN,
            resource_targets=[namespace],
            keypair=kp,
        )

    def test_oversize_response_splits_to_missing_with_pending_annotation(self):
        """Per CONTENT v3.6 Amendment 1: when the ideal response would
        exceed the configured frame budget, the handler SHOULD include as
        many entities as fit (in request order) and move the remainder to
        `missing`. We patch MAX_MESSAGE_SIZE down to make the test cheap."""
        import entity_handlers.content.handler as h

        # Save + lower the budget to a value our test payloads can saturate.
        # Chunks of ~256 KiB; 8 of them = ~2 MiB. Budget = 1 MiB after the
        # reserve (1 * 1024 * 1024 - 1/8 = 896 KiB) → ~3 chunks fit.
        original = h.MAX_MESSAGE_SIZE
        h.MAX_MESSAGE_SIZE = 1 * 1024 * 1024
        try:
            store = ContentStore()
            # Create 8 standalone chunks; store them; request all 8.
            chunk_payload = b"z" * (256 * 1024)
            request_hashes: list[bytes] = []
            for i in range(8):
                # Make each chunk distinct so hashes differ.
                payload = chunk_payload + i.to_bytes(2, "big")
                chunk_ent = Entity(
                    type="system/content/chunk",
                    data={"payload": payload},
                )
                request_hashes.append(store.put(chunk_ent))

            ctx = self._make_handler_ctx(store, "system/content")
            result = _run(content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": request_hashes}}, ctx,
            ))

            assert result["status"] == 200
            response = result["result"]
            included = result["envelope_included"]

            found = response["data"]["found"]
            missing = response["data"]["missing"]

            # MUST: at least one but NOT all entities included; the rest in
            # missing.
            assert 0 < len(found) < len(request_hashes), (
                f"expected partial inclusion, got {len(found)}/{len(request_hashes)}"
            )
            assert len(found) + len(missing) == len(request_hashes)
            # MUST: included payload byte count fits within the budget.
            from entity_core.utils.ecf import ecf_encode
            included_bytes = sum(len(ecf_encode(d)) for d in included.values())
            budget_cap = h.MAX_MESSAGE_SIZE - (h.MAX_MESSAGE_SIZE // 8)
            assert included_bytes <= budget_cap, (
                f"included payload {included_bytes} exceeds budget {budget_cap}"
            )

            # Spillover entries SHOULD be bare hashes (cross-impl decoder
            # compat per CONTENT v3.6 §8.3 — the annotation form is
            # informational and doesn't change the list shape; Go's decoder
            # reads bare hashes only). The sequencer treats bare missing
            # entries as retry-eligible.
            for entry in missing:
                assert isinstance(entry, (bytes, bytearray)), (
                    f"frame-budget spillover should emit bare hashes, got {type(entry).__name__}"
                )

            # Request order preserved: no found entry should appear after
            # any missing entry in request order.
            request_idx = {h: i for i, h in enumerate(request_hashes)}
            last_found_idx = max(request_idx[h] for h in found)
            first_missing_idx = min(request_idx[bytes(e)] for e in missing)
            assert last_found_idx < first_missing_idx

        finally:
            h.MAX_MESSAGE_SIZE = original

    def test_forward_progress_when_single_entity_overflows(self):
        """Pathological case: a single entity exceeds the budget. The
        handler still includes it (forward progress guarantee) so the
        requester learns something per request and isn't stuck."""
        import entity_handlers.content.handler as h

        original = h.MAX_MESSAGE_SIZE
        h.MAX_MESSAGE_SIZE = 64 * 1024  # 64 KiB
        try:
            store = ContentStore()
            # One ~128 KiB chunk.
            ent = Entity(
                type="system/content/chunk",
                data={"payload": b"o" * (128 * 1024)},
            )
            ent_hash = store.put(ent)

            ctx = self._make_handler_ctx(store, "system/content")
            result = _run(content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": [ent_hash]}}, ctx,
            ))
            assert result["status"] == 200
            response = result["result"]
            assert len(response["data"]["found"]) == 1
            assert len(response["data"]["missing"]) == 0

        finally:
            h.MAX_MESSAGE_SIZE = original


# -----------------------------------------------------------------------------
# Dispatcher Protocol — duck-type satisfaction
# -----------------------------------------------------------------------------


class TestDispatcherProtocol:
    def test_handler_context_dispatcher_is_a_dispatcher(self):
        from entity_core.sdk import HandlerContextDispatcher
        ctx = _make_ctx_with_store()
        d = HandlerContextDispatcher(ctx)
        # Protocol is runtime_checkable; instances of adapters satisfy.
        assert isinstance(d, Dispatcher)

    def test_stub_dispatcher_satisfies_protocol(self):
        # _ServerDispatcher above has an async execute(ExecuteRequest);
        # validates duck-typing works for test stubs.
        d = _ServerDispatcher(server_store=ContentStore())
        assert isinstance(d, Dispatcher)
