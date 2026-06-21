"""Read / write / list / delete / watch implementations.

The five operations follow the v1.2 §4 pseudocode closely; this module
is the chunky one, the handler shell in ``handler.py`` is just dispatch
plus root-mapping lookup. Each operation builds its response as either
a plain entity dict or a ``system/envelope`` carrying the file entity
+ inline-included blob and chunks (CONTENT v3.5 §4.3 + §5.2; v1.2 §10.1
strengthens both to MUST).

What lives outside this module:

* The extension shell (root mappings, internal hooks, type
  registration) lives in :mod:`entity_handlers.local_files.extension`.
* The dispatcher (operation switch) lives in
  :mod:`entity_handlers.local_files.handler`.
* The reverse-write subscription loop lives in
  :mod:`entity_handlers.local_files.reverse`.
"""

from __future__ import annotations

import logging
import mimetypes
import os
import unicodedata
from typing import TYPE_CHECKING, Any

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.protocol.framing import MAX_MESSAGE_SIZE
from entity_core.storage.emit import EmitContext
from entity_core.utils.ecf import Hash

# v1.3 §3.2 L1 bytes-mode ceiling. Tracks the framing layer's
# negotiated frame max so the constraint stays consistent if the wire
# limit ever moves. The CBOR + envelope overhead leaves a few KB
# headroom; we don't try to compute it exactly — the framing layer
# is the authoritative gate, this is the defensive in-handler net.
_BYTES_MODE_MAX_SIZE: int = MAX_MESSAGE_SIZE

from entity_handlers._common import error_response, resource_target
from entity_handlers.content.chunking import (
    DEFAULT_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    build_blob_streaming,
    build_fastcdc,
    reassemble_content,
)
from entity_handlers.local_files.config import (
    RootMapping,
    file_admitted,
    find_root_mapping,
    matches_exclude,
    matches_include,
    resolve_fs_path,
)
from entity_handlers.local_files.types import (
    TYPE_DELETED,
    TYPE_DIRECTORY,
    TYPE_FILE,
)

if TYPE_CHECKING:
    from entity_handlers.local_files.extension import LocalFilesExtension

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Media-type derivation (§4.1, §4.3 — guess via the standard mime registry)
# -----------------------------------------------------------------------------

def _guess_media_type(path: str) -> str | None:
    """Mirror Go's ``mime.TypeByExtension`` via Python's stdlib.

    Returns None when the extension is unknown — the ``media_type``
    field stays absent rather than carrying a guessed-wrong value
    (v1.2 §2.1 prefers absence over guess).
    """
    mt, _ = mimetypes.guess_type(path, strict=False)
    return mt


def _pick_media_type(supplied: Any, path: str) -> str | None:
    """Caller-supplied wins; fall back to the path-extension guess."""
    if isinstance(supplied, str) and supplied:
        return supplied
    return _guess_media_type(path)


# -----------------------------------------------------------------------------
# Atomic FS write (§4.3 SHOULD; §5.3 same SHOULD on reverse-write)
# -----------------------------------------------------------------------------

def atomic_write_file(fs_path: str, data: bytes) -> None:
    """Sibling-temp + fsync(file) + rename + fsync(dir): a power loss
    leaves either the prior content intact or the new content fully
    committed, and the rename itself is durable.

    The full POSIX recipe (PostgreSQL ``durable_rename``, SQLite
    ``unixSync``, LWN "Ensuring data reaches disk"):

    1. Open a sibling temp file in the same directory.
    2. Write all bytes; ``fsync(tmp_fd)``; close.
    3. ``rename(tmp, final)`` — atomic on POSIX within one directory.
    4. ``fsync(parent_dir_fd)`` — POSIX does NOT promise the rename
       is durable until the directory inode is sync'd, so portable
       code MUST sync the parent dir after a rename. This is not an
       ext4-specific quirk; it applies to every POSIX filesystem.

    Security hardening (F-4): the temp file is opened with
    ``O_NOFOLLOW`` so a leaf-symlink at the temp path itself can't
    escape the directory. The final rename target is checked by the
    caller-side ``resolve_fs_path`` for path traversal but a symlink
    *at the leaf* needs the read-side ``O_NOFOLLOW`` in
    :func:`_open_read_nofollow` to be defeated end-to-end. Atomic
    write itself only writes to the temp path then renames over the
    target, so a leaf symlink at the target wouldn't be followed —
    ``rename`` doesn't traverse symlinks, it replaces the target name.
    """
    dir_name = os.path.dirname(fs_path) or "."
    base = os.path.basename(fs_path)
    # tempfile.mkstemp doesn't expose O_NOFOLLOW or let us tune the
    # umask precisely. We build the temp open ourselves so the flags
    # are explicit and a leaf-symlink at the temp path can't escape.
    tmp_path = _make_temp_path(dir_name, base)
    fd = os.open(
        tmp_path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, fs_path)
        # POSIX rename durability: fsync the parent dir so the rename
        # itself survives a power loss (file data was already fsync'd
        # above). Mirrors PostgreSQL's `durable_rename`.
        try:
            dirfd = os.open(dir_name, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            # Some POSIX-y filesystems (FUSE, network mounts) refuse
            # O_DIRECTORY open of a path. Fall back to a plain open;
            # if the FS refuses fsync too, we've done what we can.
            dirfd = os.open(dir_name, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        # Best-effort 0644 to match the Path.write_bytes UX. Race with
        # readers seeing 0600 is brief; not a security boundary.
        try:
            os.chmod(fs_path, 0o644)
        except OSError:
            pass  # Windows quirks shouldn't fail the write.
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _make_temp_path(dir_name: str, base: str) -> str:
    """Build a unique sibling-temp path inside ``dir_name``.

    Mirrors ``tempfile.mkstemp``'s name shape but lets us own the
    ``os.open`` call (so we can pass ``O_NOFOLLOW``). The name is
    dot-prefixed so default ``ls`` hides it during the rename window.
    """
    import secrets

    while True:
        candidate = os.path.join(
            dir_name, f".{base}.{secrets.token_hex(6)}.tmp"
        )
        if not os.path.lexists(candidate):
            return candidate


def _open_read_nofollow(fs_path: str) -> bytes:
    """Read ``fs_path`` with ``O_NOFOLLOW`` on the leaf.

    Defeats the F-4 leaf-symlink hole: if the path resolved by the
    caller-side ``resolve_fs_path`` turns out to be a symlink at the
    leaf (either because the validation only canonicalized the parent
    dir, or because of TOCTOU between validation and open), the open
    fails with ``OSError(ELOOP)`` instead of escaping the root.

    Intermediate-component symlink swaps still slip through this
    defense — closing them requires ``openat2(RESOLVE_BENEATH)`` on
    Linux ≥5.6 or the userspace openat-walk on older / non-Linux.
    Tracked as a Phase-5 follow-up; ``O_NOFOLLOW`` is the cheap and
    correct-for-the-leaf-case fix that lands now.
    """
    fd = os.open(fs_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fp:
        return fp.read()


# -----------------------------------------------------------------------------
# Filename normalization at the FS boundary (v1.3 §10.2 L8 interim SHOULD)
# -----------------------------------------------------------------------------


def _normalize_filename(name: str) -> str | None:
    """NFC-normalize a filename per Unicode UAX #15.

    Returns the normalized string, or ``None`` if the filename cannot
    round-trip through strict UTF-8 (Linux ext4 surrogate-escape from
    undecodable bytes — ECF wire encoding can't carry these). v1.3
    §10.2 L8 interim SHOULD: normalize on ingest; reject non-UTF-8.
    Promotion to MUST tracked for Stage 3 cross-platform sync.

    Why we apply this even though the spec is interim SHOULD: the cost
    is one stdlib call per filename and the migration story when Stage
    3 promotes is "every ingest already used NFC, no rewrite needed."
    The alternative — defer NFC until forced — leaves accumulated
    unnormalized filenames in deployed trees that would need a
    migration sweep at promotion time.
    """
    # Reject non-UTF-8: surrogate-escape strings round-trip via the
    # `surrogateescape` codec but NOT via strict UTF-8.
    try:
        name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return None
    return unicodedata.normalize("NFC", name)


def _normalize_relative_path(relative_path: str) -> str | None:
    """Apply NFC normalization to each component of a relative path.

    Per-component because the FS uses ``/`` as a separator unchanged
    by Unicode normalization, and per-component normalization is what
    matches APFS/NTFS VFS-layer lookup semantics.
    """
    parts = relative_path.split("/")
    normalized = []
    for part in parts:
        if part == "":
            normalized.append(part)
            continue
        n = _normalize_filename(part)
        if n is None:
            return None
        normalized.append(n)
    return "/".join(normalized)


# v1.3 §4.3 + §5.3 L4 SHOULD: stream reassembly + streaming ingest for
# blob sizes ≥ 64 MiB. Threshold is RECOMMENDED, not normative — we
# MAY stream at any size. Python's pure-Python FastCDC throughput
# (~10 MiB/s measured) makes "stream everything ≥ a few MiB" a real
# benefit; we keep the 64 MiB threshold to match the spec's
# coordination value, with stream-at-any-size MAY-justification
# tracked for a follow-up impl decision.
_STREAMING_THRESHOLD: int = 64 * 1024 * 1024
_STREAM_READ_BLOCK: int = 4 * 1024 * 1024  # 4 MiB read granularity


def _open_read_nofollow_streaming(fs_path: str):
    """Open ``fs_path`` with ``O_NOFOLLOW`` and yield it in chunks.

    Pairs with :func:`stream_chunks` for streaming ingest. Returns the
    file object (so the caller controls close) and an iterator that
    yields ``_STREAM_READ_BLOCK``-sized blocks. The chunker buffers
    internally; this just controls how aggressively we pull bytes off
    disk.
    """
    fd = os.open(fs_path, os.O_RDONLY | os.O_NOFOLLOW)
    fp = os.fdopen(fd, "rb")

    def _stream():
        try:
            while True:
                block = fp.read(_STREAM_READ_BLOCK)
                if not block:
                    return
                yield block
        finally:
            fp.close()

    return _stream()


def atomic_write_file_stream(fs_path: str, blocks) -> int:
    """Streaming variant of :func:`atomic_write_file`.

    Same fsync(file) + rename + fsync(dir) recipe as the non-streaming
    version. Accepts an iterator of byte blocks instead of a single
    bytes; useful for blob sizes ≥ 64 MiB where buffering the full
    payload in memory is wasteful. Returns the total bytes written
    so the caller can stat-cache against the right size without an
    extra syscall.

    The temp open still uses ``O_NOFOLLOW`` per F-4. The rename(2)
    semantics that make leaf symlinks at the *target* safe also apply
    here — rename replaces the directory entry without following.
    """
    dir_name = os.path.dirname(fs_path) or "."
    base = os.path.basename(fs_path)
    tmp_path = _make_temp_path(dir_name, base)
    fd = os.open(
        tmp_path,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
        0o600,
    )
    written = 0
    try:
        with os.fdopen(fd, "wb") as fp:
            for block in blocks:
                if not block:
                    continue
                fp.write(block)
                written += len(block)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, fs_path)
        # POSIX dir-fsync per §10.2 L3 — same as atomic_write_file.
        try:
            dirfd = os.open(dir_name, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            dirfd = os.open(dir_name, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        try:
            os.chmod(fs_path, 0o644)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return written


# -----------------------------------------------------------------------------
# Helpers: chunk + persist via the CONTENT v3.5 substrate
# -----------------------------------------------------------------------------

def _chunk_and_persist(
    raw_bytes: bytes, ctx: HandlerContext
) -> tuple[Hash, Entity, list[Entity]]:
    """Run FastCDC over ``raw_bytes``, persist blob + chunks via the
    content store, and return (blob_hash, blob_entity, chunk_entities).

    The chunker reuse is the load-bearing v1.2 property: same bytes
    through any handler produces structurally-identical chunks +
    blob hash (CONTENT v3.5 §1.1 promised it; v1.2 is the first
    deployed surface that exercises it).
    """
    result = build_fastcdc(raw_bytes, DEFAULT_CHUNK_SIZE)
    store = ctx.emit_pathway.content_store
    for chunk in result.chunks:
        store.put(chunk)
    store.put(result.blob)
    return result.blob_hash, result.blob, result.chunks


def _build_included(
    blob_hash: Hash,
    blob: Entity,
    chunks: list[Entity] | None,
    *,
    ctx: HandlerContext,
) -> dict[bytes, dict[str, Any]]:
    """Build the response envelope's ``included`` map.

    CONTENT v3.5 §5.2 / v1.2 §10.1 MUST: the blob entity is always
    included. CONTENT v3.5 §4.3 / v1.2 §10.1 MUST: chunks are also
    included iff ``blob.total_size <= MIN_CHUNK_SIZE`` (64 KiB).

    When ``chunks`` is None (the dedup-write branch, where we don't
    have the freshly-built chunks in scope), the small-blob branch
    looks them up from the content store by hash. Missing chunks at
    this point would be a system invariant violation — for the dedup-
    write path we just wrote them, and for the read path we just
    chunked them — so absence here is a quiet skip rather than an
    error, mirroring CONTENT §6.2 "best-effort SHOULD inline".
    """
    included: dict[bytes, dict[str, Any]] = {blob_hash: blob.to_dict()}
    total_size = int(blob.data.get("total_size", 0))
    if total_size > MIN_CHUNK_SIZE:
        return included

    if chunks is not None:
        for c in chunks:
            included[c.compute_hash()] = c.to_dict()
        return included

    # Dedup-write branch: enumerate from the blob's chunk-hash list.
    store = ctx.emit_pathway.content_store
    for ch in blob.data.get("chunks", []):
        if not isinstance(ch, (bytes, bytearray)):
            continue
        key = bytes(ch)
        if key in included:
            continue
        ent = store.get(key)
        if ent is not None:
            included[key] = ent.to_dict()
    return included


def _envelope_response(
    file_entity: Entity, included: dict[bytes, dict[str, Any]]
) -> dict[str, Any]:
    """Return the file entity as ``result`` + the inline bundle in
    ``envelope_included`` for the outer wire envelope.

    DOMAIN-LOCAL-FILES v1.2 §4.1 uses ``result: file_entity`` +
    ``ctx.include(blob_hash, blob)`` — the bundle rides on the wire
    envelope's outer ``included``, not inside a ``system/envelope``
    wrapper. The peer dispatch consumes ``envelope_included`` at
    wire-send time (see :func:`entity_core.peer.peer._collect_wire_included`)
    and merges it into the outgoing wire envelope.

    Returning the file entity directly as ``result`` also matches the
    validate-peer's expectation that ``respData.Result`` decodes as a
    ``local/files/file`` entity (not a ``system/envelope``).
    """
    return {
        "status": 200,
        "result": file_entity.to_dict(),
        "envelope_included": included,
    }


# -----------------------------------------------------------------------------
# read (§4.1)
# -----------------------------------------------------------------------------


async def handle_read(
    ext: "LocalFilesExtension", ctx: HandlerContext
) -> dict[str, Any]:
    """Read a file from disk, chunk via FastCDC, persist into the
    content store, bind the file entity into the tree, and return the
    file entity with the blob (and chunks when small) inline-included.
    """
    tree_path = resource_target(ctx)
    if tree_path is None:
        return error_response(
            400,
            "invalid_resource",
            "local/files:read requires a resource target (v1.2 §4.1)",
        )

    root = find_root_mapping(ext.roots, tree_path)
    if root is None:
        return error_response(
            404, "no_root_mapping", f"no root mapping for path: {tree_path}"
        )

    try:
        fs_path, relative_path = resolve_fs_path(root, tree_path)
    except PermissionError as exc:
        return error_response(403, "path_traversal_rejected", str(exc))

    if not os.path.exists(fs_path):
        return error_response(
            404, "file_not_found", f"file not found: {relative_path}"
        )
    if os.path.isdir(fs_path):
        return error_response(
            400,
            "use_list_for_directories",
            "use list operation for directories",
        )

    # v1.3 §4.3 L4 SHOULD: streaming ingest for files ≥ 64 MiB. Below
    # the threshold we keep the in-memory chunker (fewer syscalls,
    # simpler error surface). Above, we read in 4 MiB blocks straight
    # into the FastCDC stream chunker so peak memory stays bounded
    # regardless of file size. Boundaries are byte-identical to the
    # in-memory chunker per CONTENT v3.5 §3.6.5.
    try:
        size_hint = os.path.getsize(fs_path)
    except OSError as exc:
        return error_response(500, "io_error", f"stat: {exc}")

    if size_hint >= _STREAMING_THRESHOLD:
        try:
            block_iter = _open_read_nofollow_streaming(fs_path)
            blob, blob_hash, _ = build_blob_streaming(
                block_iter, ctx.emit_pathway.content_store, DEFAULT_CHUNK_SIZE
            )
        except OSError as exc:
            if getattr(exc, "errno", None) == 40:  # ELOOP
                return error_response(
                    403,
                    "path_traversal_rejected",
                    f"read: target is a symlink (leaf-symlink rejected): {relative_path}",
                )
            return error_response(500, "io_error", f"read: {exc}")
        # Streaming ingest doesn't keep the chunk entity list around —
        # we pass None to _build_included; it'll enumerate from the
        # blob (which only matters when total_size ≤ MIN_CHUNK_SIZE,
        # i.e. small files; ≥64 MiB files are far above that boundary).
        chunks = None
    else:
        try:
            raw_bytes = _open_read_nofollow(fs_path)
        except OSError as exc:
            if getattr(exc, "errno", None) == 40:  # ELOOP
                return error_response(
                    403,
                    "path_traversal_rejected",
                    f"read: target is a symlink (leaf-symlink rejected): {relative_path}",
                )
            return error_response(500, "io_error", f"read: {exc}")
        blob_hash, blob, chunks = _chunk_and_persist(raw_bytes, ctx)

    stat = os.stat(fs_path, follow_symlinks=False)
    # v1.3 §10.2 L7: warm the stat-cache on read so a subsequent
    # reverse-write event for this path short-circuits the rechunk.
    # The cache's smudge-to-zero discipline handles the within-same-ns
    # race (file modified within the same nanosecond window we cache).
    ext.stat_cache.store(fs_path, stat, blob_hash)

    # v1.3 §10.2 L8: NFC-normalize the relative_path before binding
    # into the tree. Non-UTF-8 (surrogate-escape) names → 400.
    normalized_path = _normalize_relative_path(relative_path)
    if normalized_path is None:
        return error_response(
            400,
            "invalid_filename",
            f"path contains non-UTF-8 bytes (ECF requires strict UTF-8): "
            f"{relative_path!r}",
        )
    relative_path = normalized_path

    file_data: dict[str, Any] = {
        "path": relative_path,
        "size": int(stat.st_size),
        "modified_at": int(stat.st_mtime * 1000),
        "content": blob_hash,
    }
    media_type = _guess_media_type(relative_path)
    if media_type is not None:
        file_data["media_type"] = media_type

    file_entity = Entity(type=TYPE_FILE, data=file_data)

    # Cache the read in the tree (§4.1: subsequent tree:get returns the
    # cached entity without touching the filesystem). Marks the path as
    # recently written so the reverse-write subscription's blob-hash
    # circuit breaker is the primary defense — the recent-write tracker
    # avoids the cost of re-reading and re-chunking the same bytes.
    ext.reverse_tracker.mark_written(tree_path)
    ctx.emit_pathway.emit(
        tree_path, file_entity, EmitContext.from_handler_grant(ctx, "read")
    )

    included = _build_included(blob_hash, blob, chunks, ctx=ctx)

    if root.publish_descriptors and media_type is not None:
        _publish_descriptor(ctx, blob_hash, media_type)

    return _envelope_response(file_entity, included)


def _publish_descriptor(
    ctx: HandlerContext, blob_hash: Hash, media_type: str
) -> None:
    """Bind a ``system/content/descriptor`` at the §5.3 canonical path
    when the root has ``publish_descriptors`` enabled.

    The path embeds both ``B_hex`` (blob hash) and ``D_hex`` (descriptor
    hash) so the CONTENT v3.5 §5.3 MUST integrity check on the consumer
    side gates against any path-corruption mismatch (a descriptor at
    the wrong B_hex is rejected on receipt).
    """
    descriptor = Entity(
        type="system/content/descriptor",
        data={"content": blob_hash, "media_type": media_type},
    )
    descriptor_hash = descriptor.compute_hash()
    path = (
        f"system/content/descriptor/{blob_hash.hex()}/{descriptor_hash.hex()}"
    )
    try:
        ctx.emit_pathway.emit(
            path, descriptor, EmitContext.from_handler_grant(ctx, "read")
        )
    except Exception as exc:  # noqa: BLE001 — descriptor publish is best-effort
        logger.warning("local/files: descriptor publish failed: %s", exc)


# -----------------------------------------------------------------------------
# write (§4.3)
# -----------------------------------------------------------------------------


async def handle_write(
    ext: "LocalFilesExtension",
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Write content to the filesystem and bind the file entity into
    the tree. Two-mode input: ``bytes`` (raw payload — handler chunks
    via FastCDC) XOR ``content`` (existing blob hash — first-class dedup
    write; reassemble bytes from chunks already in the store).
    """
    tree_path = resource_target(ctx)
    if tree_path is None:
        return error_response(
            400,
            "invalid_resource",
            "local/files:write requires a resource target (v1.2 §4.3)",
        )

    root = find_root_mapping(ext.roots, tree_path)
    if root is None:
        return error_response(
            404, "no_root_mapping", f"no root mapping for path: {tree_path}"
        )
    if root.read_only:
        return error_response(
            403, "read_only_root", "root mapping is read-only"
        )

    try:
        fs_path, relative_path = resolve_fs_path(root, tree_path)
    except PermissionError as exc:
        return error_response(403, "path_traversal_rejected", str(exc))

    raw_bytes_in = params.get("bytes")
    content_ref = params.get("content")
    has_bytes = isinstance(raw_bytes_in, (bytes, bytearray)) and len(raw_bytes_in) > 0
    has_content = isinstance(content_ref, (bytes, bytearray)) and len(content_ref) > 0

    # v1.2 §3.2 input-mode invariant: exactly one of bytes / content.
    if has_bytes and has_content:
        return error_response(
            400,
            "invalid_params",
            "exactly one of bytes / content must be set (ambiguous_input)",
        )
    if not has_bytes and not has_content:
        return error_response(
            400,
            "invalid_params",
            "exactly one of bytes / content must be set (missing_input)",
        )

    # v1.3 §3.2 L1: bytes-mode is bounded by the negotiated frame
    # max (~16 MiB on TCP). Transport already rejects oversized
    # frames; this in-handler ceiling catches any code path that
    # bypasses framing (internal dispatch, future transports) and
    # surfaces V1 behavioral-gate-compliant error rather than a
    # hung connection or OOM. For payloads exceeding the wire frame,
    # the spec's principled path is content-mode (the SDK wrapper
    # routes between modes per §3.2 L1).
    if has_bytes and len(raw_bytes_in) > _BYTES_MODE_MAX_SIZE:
        return error_response(
            400,
            "invalid_params",
            f"bytes-mode payload ({len(raw_bytes_in)} bytes) exceeds "
            f"the frame ceiling ({_BYTES_MODE_MAX_SIZE} bytes); use "
            f"content-mode for larger payloads (v1.3 §3.2 L1)",
        )

    chunks: list[Entity] | None = None
    store = ctx.emit_pathway.content_store
    if has_bytes:
        raw_bytes = bytes(raw_bytes_in)
        blob_hash, blob, chunks = _chunk_and_persist(raw_bytes, ctx)
    else:
        # Dedup write — the bytes already live in the content store as
        # a blob + chunks; reassemble for the disk write but don't
        # re-chunk (the input blob hash is preserved verbatim).
        blob_hash = bytes(content_ref)
        blob_entity = store.get(blob_hash)
        if blob_entity is None:
            return error_response(
                404, "content_not_found", "blob not found in content store"
            )
        try:
            raw_bytes = reassemble_content(blob_hash, store)
        except Exception as exc:  # noqa: BLE001
            return error_response(
                500, "internal_error", f"reassemble blob: {exc}"
            )
        blob = blob_entity

    if params.get("create_dirs"):
        try:
            os.makedirs(os.path.dirname(fs_path) or ".", exist_ok=True)
        except OSError as exc:
            return error_response(500, "io_error", f"mkdir: {exc}")

    try:
        atomic_write_file(fs_path, raw_bytes)
    except OSError as exc:
        return error_response(500, "io_error", f"write: {exc}")

    stat = os.stat(fs_path, follow_symlinks=False)
    # v1.3 §10.2 L7: warm the stat-cache on write so a reverse-write
    # event triggered by *our own* tree emit (the loop-back) doesn't
    # rechunk. The recent-write tracker also covers this within its
    # 5s window; the stat-cache covers it indefinitely.
    ext.stat_cache.store(fs_path, stat, blob_hash)

    # v1.3 §10.2 L8: NFC-normalize before binding into the tree.
    normalized_path = _normalize_relative_path(relative_path)
    if normalized_path is None:
        return error_response(
            400,
            "invalid_filename",
            f"path contains non-UTF-8 bytes (ECF requires strict UTF-8): "
            f"{relative_path!r}",
        )
    relative_path = normalized_path

    file_data: dict[str, Any] = {
        "path": relative_path,
        "size": int(stat.st_size),
        "modified_at": int(stat.st_mtime * 1000),
        "content": blob_hash,
        "written": True,
    }
    media_type = _pick_media_type(params.get("media_type"), relative_path)
    if media_type is not None:
        file_data["media_type"] = media_type

    file_entity = Entity(type=TYPE_FILE, data=file_data)

    # Mark before emit — the subscription hook fires synchronously from
    # the emit, and the recent-write tracker is what short-circuits the
    # reverse-write feedback loop on the local path.
    ext.reverse_tracker.mark_written(tree_path)
    ctx.emit_pathway.emit(
        tree_path, file_entity, EmitContext.from_handler_context(ctx, "write")
    )

    included = _build_included(blob_hash, blob, chunks, ctx=ctx)
    return _envelope_response(file_entity, included)


# -----------------------------------------------------------------------------
# list (§4.2)
# -----------------------------------------------------------------------------


async def handle_list(
    ext: "LocalFilesExtension", ctx: HandlerContext
) -> dict[str, Any]:
    """List a directory: filesystem readdir filtered through the root's
    ``exclude`` and ``include`` globs. Directory descent is governed by
    exclude only (include never refuses subdir traversal).
    """
    tree_path = resource_target(ctx)
    if tree_path is None:
        return error_response(
            400,
            "invalid_resource",
            "local/files:list requires a resource target (v1.2 §4.2)",
        )

    root = find_root_mapping(ext.roots, tree_path)
    if root is None:
        return error_response(
            404, "no_root_mapping", f"no root mapping for path: {tree_path}"
        )

    try:
        fs_path, relative_path = resolve_fs_path(root, tree_path)
    except PermissionError as exc:
        return error_response(403, "path_traversal_rejected", str(exc))

    if not os.path.exists(fs_path):
        return error_response(
            404,
            "directory_not_found",
            f"directory not found: {relative_path}",
        )

    children: list[dict[str, Any]] = []
    try:
        entries = sorted(os.listdir(fs_path))
    except OSError as exc:
        return error_response(500, "io_error", f"readdir: {exc}")

    for name in entries:
        if matches_exclude(name, root.exclude):
            continue
        full = os.path.join(fs_path, name)
        is_dir = os.path.isdir(full)
        if not is_dir and not matches_include(name, root.include):
            continue
        try:
            st = os.stat(full)
        except OSError:
            continue
        # v1.3 §10.2 L8: NFC-normalize each name; skip non-UTF-8
        # entries (silent skip rather than 400 — a single bad entry
        # shouldn't fail the whole listing; the caller can read
        # individual files and get the explicit error per-entry).
        normalized = _normalize_filename(name)
        if normalized is None:
            logger.warning(
                "local/files list: skipping non-UTF-8 filename in %s",
                fs_path,
            )
            continue
        child: dict[str, Any] = {
            "name": normalized,
            "entity_path": _join_tree_path(tree_path, normalized),
            "entry_type": "directory" if is_dir else "file",
            "modified_at": int(st.st_mtime * 1000),
        }
        if not is_dir:
            child["size"] = int(st.st_size)
        children.append(child)

    normalized_relative = _normalize_relative_path(relative_path)
    if normalized_relative is None:
        return error_response(
            400,
            "invalid_filename",
            f"path contains non-UTF-8 bytes: {relative_path!r}",
        )
    dir_data = {
        "path": normalized_relative,
        "children": children,
    }
    return {
        "status": 200,
        "result": {"type": TYPE_DIRECTORY, "data": dir_data},
    }


def _join_tree_path(tree_path: str, name: str) -> str:
    """Concatenate ``tree_path`` + ``name`` with a single ``/`` separator."""
    if tree_path.endswith("/"):
        return tree_path + name
    return tree_path + "/" + name


# -----------------------------------------------------------------------------
# delete (§4.4)
# -----------------------------------------------------------------------------


async def handle_delete(
    ext: "LocalFilesExtension", ctx: HandlerContext
) -> dict[str, Any]:
    """Remove a file from disk and unbind its tree path. Blob + chunks
    in the content store are NOT removed (CONTENT v3.5 §6.6 persistence-
    by-default; EXTENSION-GC will eventually define reachability).
    """
    tree_path = resource_target(ctx)
    if tree_path is None:
        return error_response(
            400,
            "invalid_resource",
            "local/files:delete requires a resource target (v1.2 §4.4)",
        )

    root = find_root_mapping(ext.roots, tree_path)
    if root is None:
        return error_response(
            404, "no_root_mapping", f"no root mapping for path: {tree_path}"
        )
    if root.read_only:
        return error_response(
            403, "read_only_root", "root mapping is read-only"
        )

    try:
        fs_path, relative_path = resolve_fs_path(root, tree_path)
    except PermissionError as exc:
        return error_response(403, "path_traversal_rejected", str(exc))

    existed = os.path.exists(fs_path)
    if existed:
        try:
            os.remove(fs_path)
        except OSError as exc:
            return error_response(500, "io_error", f"delete: {exc}")

    # v1.3 §10.2 L7 — invalidate the stat-cache so a future recreate
    # at this path doesn't get a stale-hash hit.
    ext.stat_cache.invalidate(fs_path)
    ext.reverse_tracker.mark_written(tree_path)
    ctx.emit_pathway.entity_tree.remove(
        ctx.emit_pathway.entity_tree.normalize_uri(tree_path)
    )

    return {
        "status": 200,
        "result": {
            "type": TYPE_DELETED,
            "data": {"path": relative_path, "existed": existed},
        },
    }


# `handle_watch` deleted in the Amendment 1 conformance pass.
# Per DOMAIN-LOCAL-FILES v1.3 §10.1 L2 MUST: a `watch` operation that
# returns success without actually monitoring the filesystem is
# non-conformant. The prior config-only impl shipped exactly that
# silent-success surface. Until the platform-native watcher
# (inotify/FSEvents/ReadDirectoryChangesW + §10.2 L9 overflow
# recovery) lands, `watch` is omitted from the manifest and the
# dispatcher routes it to `unknown_operation`. Re-add when the
# watcher driver is wired.


__all__ = [
    "atomic_write_file",
    "handle_delete",
    "handle_list",
    "handle_read",
    "handle_write",
]
