"""Reverse write — tree changes under a root-mapping prefix project to
disk. The §5 mechanism that makes sync produce actual files.

Per DOMAIN-LOCAL-FILES v1.2 §5.1 Amendment 1 F-4, implementations MAY
satisfy the §10.1 MUST ("Reverse write via subscription on configured
root mapping prefixes") via either (a) per-root subscribe + inbox
delivery or (b) a single global tree-change stream filtered by
configured root prefixes. The Python impl takes shape (b): an
:class:`InternalHook` on the EmitPathway sees every emit, and the hook
filters by root prefix in process. Same observable behavior; simpler
wiring; conformant per F-4.

The hook is *synchronous and fast*: it filters, looks up the matching
root, checks the recent-write tracker (loop-prevention circuit breaker),
and either schedules the disk write through an executor or skips. The
actual disk I/O happens inline because the local in-process write path
is short — atomic write of reassembled bytes — and the EmitPathway
internal-hook contract demands fast hooks. For large blob writes we
could push the heavy work onto an executor; that's a follow-up
optimization, not a conformance requirement.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import TYPE_CHECKING

from entity_core.storage.emit import (
    AsyncChangeListener,
    ChangeEvent,
    ChangeKind,
)

from entity_handlers.content.chunking import (
    DEFAULT_CHUNK_SIZE,
    build_fastcdc,
    reassemble_content,
    stream_reassemble,
)
from entity_handlers.local_files.config import (
    RootMapping,
    find_root_mapping,
    resolve_fs_path,
)
from entity_handlers.local_files.operations import (
    _STREAMING_THRESHOLD,
    _open_read_nofollow,
    atomic_write_file,
    atomic_write_file_stream,
)
from entity_handlers.local_files.types import TYPE_FILE

if TYPE_CHECKING:
    from entity_handlers.local_files.extension import LocalFilesExtension

logger = logging.getLogger(__name__)


_RECENT_WRITE_WINDOW_SECONDS: float = 5.0


class RecentWriteTracker:
    """Tracks recently-written tree paths for loop prevention.

    The blob-hash circuit breaker in :func:`reverse_write` is the
    primary defense — when both sides chunk the same bytes with the
    same FastCDC params, on-disk hash == incoming hash and the write
    is skipped. The tracker is a performance optimization that lets us
    skip the read-and-rechunk work entirely on the loop-back path
    (spec §5.5 MAY).
    """

    def __init__(self, window_seconds: float = _RECENT_WRITE_WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        self._written: dict[str, float] = {}

    def mark_written(self, tree_path: str) -> None:
        with self._lock:
            self._written[tree_path] = time.monotonic()

    def is_recently_written(self, tree_path: str) -> bool:
        with self._lock:
            t = self._written.get(tree_path)
            if t is None:
                return False
            if time.monotonic() - t > self._window:
                del self._written[tree_path]
                return False
            return True


class _ReverseWriteHook:
    """Async change listener that drives reverse-write off the EmitPathway.

    Implements the :class:`AsyncChangeListener` protocol — the listener
    is fired via ``loop.create_task`` after the cascade completes
    (`storage/emit.py:Phase 2 Subscriptions`), so the FS work doesn't
    block the producing write. Inside ``on_change`` we additionally
    push the disk I/O + FastCDC rechunk onto the default thread-pool
    executor (`loop.run_in_executor(None, ...)`) so we don't stall the
    event loop with blocking syscalls — same pattern the asyncio docs
    recommend for any operation that does sync FS I/O.

    Why not an ``InternalHook`` (the prior shape)? Internal hooks fire
    inline during emit and **must be fast** — they block all writes
    while executing. The reverse-write does a full file rechunk via
    pure-Python FastCDC for the circuit-breaker compare; at the
    measured ~10 MiB/s that's seconds-to-minutes of cascade block for
    files ≥ a few MiB. Async listener + executor moves that off the
    hot path entirely. (Review finding F-1.)
    """

    def __init__(self, extension: "LocalFilesExtension") -> None:
        self._ext = extension

    async def on_change(self, event: ChangeEvent) -> None:
        # Cheap filters run on the event loop — they only touch
        # in-memory state and the recent-write tracker.
        if not self._should_handle(event):
            return
        # Heavy work (disk read + FastCDC + atomic write) goes to the
        # default thread-pool executor so we don't stall the loop.
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._handle, event)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "local/files reverse-write error at %s: %s", event.uri, exc
            )

    def _should_handle(self, event: ChangeEvent) -> bool:
        bare_path = _strip_local_peer(event.uri, self._ext.local_peer_id)
        if bare_path is None:
            return False
        if bare_path.startswith("system/"):
            return False
        root = find_root_mapping(self._ext.roots, bare_path)
        if root is None or root.read_only:
            return False
        if self._ext.reverse_tracker.is_recently_written(bare_path):
            return False
        if event.kind != ChangeKind.DELETED:
            if event.entity is None or event.entity.type != TYPE_FILE:
                return False
        return True

    def _handle(self, event: ChangeEvent) -> None:
        bare_path = _strip_local_peer(event.uri, self._ext.local_peer_id)
        if bare_path is None:
            return  # cross-peer change; reverse-write only applies locally

        # system/* is never a file path; skip cheaply before scanning roots.
        if bare_path.startswith("system/"):
            return

        root = find_root_mapping(self._ext.roots, bare_path)
        if root is None:
            return
        if root.read_only:
            return
        if self._ext.reverse_tracker.is_recently_written(bare_path):
            return

        if event.kind == ChangeKind.DELETED:
            _reverse_delete(root, bare_path, self._ext)
            return

        # Only reverse-write file entities; other entities under the
        # mapped prefix would be misuse and we let them ride in the tree
        # without touching disk (the spec §5.2 "Only reverse-write file
        # entities" guard).
        if event.entity is None or event.entity.type != TYPE_FILE:
            return

        _reverse_write(
            root, bare_path, event.entity, self._ext
        )


def install_reverse_write_hook(extension: "LocalFilesExtension") -> _ReverseWriteHook:
    """Attach the reverse-write listener to the EmitPathway.

    Returns the listener so the extension can detach it during
    shutdown. Registered via ``emit.subscribe`` (the Phase-2 async
    path), not ``_add_internal_hook`` (the Phase-1 sync path), so the
    FS work runs off the producing write's cascade — see
    :class:`_ReverseWriteHook` for the rationale.
    """
    listener = _ReverseWriteHook(extension)
    emit = extension.emit_pathway
    if emit is None:
        raise RuntimeError(
            "LocalFilesExtension: emit_pathway not bound — cannot install "
            "reverse-write listener"
        )
    # Pattern "*" = listen to all changes; we filter per-root inside the
    # listener (one root-table lookup per event is cheap, and lets us
    # add / remove root mappings at runtime without rewiring listeners).
    emit.subscribe("*", listener)
    return listener


def _strip_local_peer(uri: str, local_peer_id: str | None) -> str | None:
    """Strip the ``/{local_peer_id}/`` prefix off a normalized URI.

    Returns the bare entity path if the URI is in the local namespace,
    else None. URIs without a peer prefix (already bare) pass through.
    """
    if not uri.startswith("/"):
        return uri
    rest = uri[1:]
    slash = rest.find("/")
    if slash == -1:
        return None
    peer = rest[:slash]
    bare = rest[slash + 1:]
    if local_peer_id and peer != local_peer_id:
        return None
    return bare


def _reverse_write(
    root: RootMapping,
    tree_path: str,
    file_entity,
    extension: "LocalFilesExtension",
) -> None:
    """Project a tree-bound file entity to disk per §5.3."""
    blob_hash = file_entity.data.get("content")
    if not isinstance(blob_hash, (bytes, bytearray)) or not blob_hash:
        return
    blob_hash = bytes(blob_hash)

    try:
        fs_path, _ = resolve_fs_path(root, tree_path)
    except PermissionError as exc:
        logger.warning("local/files reverse-write path traversal: %s", exc)
        return

    # v1.3 Amendment 3 §5.5 (normative MUST): the circuit-breaker
    # recompute MUST use the *incoming* blob's chunk_size field, not
    # the consumer's local DEFAULT_CHUNK_SIZE. Otherwise a peer
    # running a different default re-chunks the on-disk file at the
    # wrong size, hashes diverge, the circuit-breaker spuriously
    # decides "differs," and we rewrite identical content (which
    # loops back to the sender). Under CONTENT v3.5 (all impls at 4
    # MiB) this was latent; under CONTENT v3.6's A2 1 MiB recommended
    # default it becomes acute. Fetch the blob entity early so we
    # have chunk_size in scope for the rechunk path. The cost on the
    # cache-hit path is one content-store dict lookup (negligible).
    store = extension.emit_pathway.content_store
    blob_entity = store.get(blob_hash)
    if blob_entity is None:
        # Per Amendment 1 F-3: silent return on missing blob; the
        # next subscription event after the blob lands will refire.
        return
    incoming_chunk_size = int(
        blob_entity.data.get("chunk_size", DEFAULT_CHUNK_SIZE)
    )

    # Loop-prevention §5.3: if the on-disk content would hash to the
    # same blob (using the SAME chunk_size as the incoming blob), the
    # write is a no-op. Same bytes + same chunk_size ⇒ same FastCDC
    # chunks ⇒ same blob hash (CONTENT v3.5 §3.6 + §1.1).
    if os.path.lexists(fs_path):
        try:
            st = os.stat(fs_path, follow_symlinks=False)
        except OSError:
            st = None

        # v1.3 §10.2 L7 stat-cache fast path. If our cache says the
        # on-disk file's blob-hash hasn't changed since we last saw it,
        # we skip the rechunk entirely. The cache's racy-clean rule
        # makes this safe: an mtime ≥ cache_write_ns forces a miss
        # (Git's discipline), so we only get hits when we can prove
        # the file hasn't been touched after the cache write.
        if st is not None:
            cached = extension.stat_cache.lookup(fs_path, st)
            if cached is not None:
                if cached == blob_hash:
                    return
                # Cache says disk differs from blob_hash; we still
                # have to write the new content. Fall through.
            else:
                # Cache miss — pay the rechunk cost and warm the cache.
                # §5.5 normative MUST: use incoming_chunk_size, not the
                # local DEFAULT_CHUNK_SIZE. The ELOOP/symlink-rejection
                # logic from F-4 still applies via _open_read_nofollow.
                try:
                    current_bytes = _open_read_nofollow(fs_path)
                    current = build_fastcdc(current_bytes, incoming_chunk_size)
                    extension.stat_cache.store(fs_path, st, current.blob_hash)
                    if current.blob_hash == blob_hash:
                        return
                except OSError:
                    # ELOOP (leaf symlink) or other read failure. Fall
                    # through — atomic-write's rename(2) replaces the
                    # entry safely. Don't cache: the read didn't
                    # produce a hash we trust for this path.
                    pass

    try:
        os.makedirs(os.path.dirname(fs_path) or ".", exist_ok=True)
    except OSError as exc:
        logger.warning(
            "local/files reverse-write mkdir failed for %s: %s", fs_path, exc
        )
        return

    # v1.3 §5.3 L4 SHOULD: streaming reassembly for blob sizes ≥ 64 MiB.
    # The reverse-write path is the more critical streaming site (input
    # is incoming sync payload — could be arbitrarily large per Stage 3
    # use case). Below the threshold we buffer; above, we stream chunk
    # payloads from the content store directly into the atomic-write
    # pipeline so peak memory stays ~max_chunk_size regardless of blob.
    total_size = int(blob_entity.data.get("total_size", 0) or 0)
    extension.reverse_tracker.mark_written(tree_path)
    try:
        if total_size >= _STREAMING_THRESHOLD:
            stream = stream_reassemble(blob_hash, store)
            atomic_write_file_stream(fs_path, stream)
        else:
            try:
                raw_bytes = reassemble_content(blob_hash, store)
            except Exception:
                # Chunks missing from the local store — see Amendment 1
                # F-3: this is a partial-sync state, not an error.
                return
            atomic_write_file(fs_path, raw_bytes)
    except Exception as exc:
        # Streaming reassembly raises ContentReassemblyError lazily on
        # missing chunks (Amendment 1 F-3 partial-sync state) — silent
        # return. OSError surfaces as a warning per the spec.
        if isinstance(exc, OSError):
            logger.warning(
                "local/files reverse-write failed for %s: %s", fs_path, exc
            )
        return

    # v1.3 §10.2 L7 cache the post-write stat → blob hash mapping so
    # the next reverse-write event short-circuits. The cache's Git
    # smudge-to-zero discipline handles the within-same-ns write race
    # automatically — if mtime_ns races with our cache-write time, the
    # stored size is zeroed and the next lookup is a forced miss.
    try:
        new_st = os.stat(fs_path, follow_symlinks=False)
        extension.stat_cache.store(fs_path, new_st, blob_hash)
    except OSError:
        # Stat failed (race with delete?) — don't cache. Next event
        # pays a rechunk; correctness intact.
        pass


def _reverse_delete(
    root: RootMapping,
    tree_path: str,
    extension: "LocalFilesExtension | None" = None,
) -> None:
    """Project a tree delete to disk per §5.4."""
    try:
        fs_path, _ = resolve_fs_path(root, tree_path)
    except PermissionError as exc:
        logger.warning("local/files reverse-delete path traversal: %s", exc)
        return
    try:
        os.remove(fs_path)
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning(
            "local/files reverse-delete failed for %s: %s", fs_path, exc
        )
        return
    # Invalidate the stat-cache entry so a subsequent recreate at the
    # same path doesn't trigger a stale-hash hit. ``fs_path`` is the
    # canonical key the lookup/store paths use; ``invalidate`` is a
    # no-op when the entry isn't present.
    if extension is not None:
        extension.stat_cache.invalidate(fs_path)


__all__ = [
    "RecentWriteTracker",
    "install_reverse_write_hook",
]
