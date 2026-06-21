"""Blob + chunk entity construction, verification, and reassembly per
EXTENSION-CONTENT v3.5 §3.2 (fixed-size), §3.3 (verify), §3.4 (reassemble),
and §3.6 (FastCDC, via :mod:`entity_handlers.content.fastcdc`).

Pure-ish: ``build_blob`` returns entity objects without touching any
content store; the caller persists. ``verify_content`` and
``reassemble_content`` take a content-store reference because they read
chunks back. The split lets unit tests run without store fixtures while
the handler can compose normally.

§3.7 classifies both chunkers as Conformance — Python MUST produce byte-
identical chunk entities (and therefore byte-identical entity hashes) to
Go and Rust on the same input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.utils.ecf import Hash

from entity_handlers.content import fastcdc

# -----------------------------------------------------------------------------
# Chunking algorithm identifiers (§2.1 standardized values)
# -----------------------------------------------------------------------------

CHUNKING_FIXED_SIZE: int = 0
"""Fixed-size chunking per §3.2; chunks at every `chunk_size` bytes."""

CHUNKING_FASTCDC_NC2: int = 1
"""FastCDC with the §3.6.1 gear table, NC=2, min=target/4, max=target*2."""


# -----------------------------------------------------------------------------
# Constants per §10
# -----------------------------------------------------------------------------

DEFAULT_CHUNK_SIZE: int = 1 * 1024 * 1024  # 1 MiB (CONTENT v3.6 §3.5 A2)
MIN_CHUNK_SIZE: int = 64 * 1024  # 64 KiB (§10.1) — also the §4.3 inline threshold
MAX_CHUNK_SIZE: int = 8 * 1024 * 1024  # 8 MiB (§10.1)
GET_BATCH_SIZE: int = 64  # §10.2


# -----------------------------------------------------------------------------
# Build result
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class BlobBuildResult:
    """Result of ``build_blob`` — the constructed blob + chunk entities
    plus the blob's content hash. Pure values; caller chooses where to
    persist (typically the local content store, or a transfer pipe).
    """

    blob: Entity
    """The ``system/content/blob`` manifest entity (§2.1)."""

    chunks: list[Entity]
    """The ``system/content/chunk`` payload entities in order (§2.2).
    Index-aligned with ``blob.data["chunks"]`` (same hashes in same
    order).
    """

    blob_hash: Hash
    """Content hash of the blob entity — convenience; equal to
    ``blob.compute_hash()``.
    """


# -----------------------------------------------------------------------------
# Chunkers
# -----------------------------------------------------------------------------


def _chunk_entity(payload: bytes) -> Entity:
    """Construct a ``system/content/chunk`` entity. Hash falls out of
    construction via ``Entity.compute_hash`` on demand.
    """
    return Entity(type="system/content/chunk", data={"payload": payload})


def _blob_entity(
    *, total_size: int, chunk_size: int, chunking: int, chunk_hashes: list[Hash]
) -> Entity:
    """Construct a ``system/content/blob`` entity per §2.1. `chunks` is
    a flat list of `system/hash` byte strings — the §2.8 wire-shape pin
    handles this naturally because Python lists of bytes round-trip via
    ECF as flat CBOR arrays (covered by tests/unit/test_content_types).
    """
    return Entity(
        type="system/content/blob",
        data={
            "total_size": total_size,
            "chunk_size": chunk_size,
            "chunking": chunking,
            "chunks": list(chunk_hashes),
        },
    )


def _slice_offsets_fixed(data: bytes, chunk_size: int) -> Iterable[tuple[int, int]]:
    """Yield ``(start, end)`` half-open intervals for fixed-size chunking
    (§3.2). The final chunk MAY be smaller than `chunk_size`.
    """
    n = len(data)
    offset = 0
    while offset < n:
        end = min(offset + chunk_size, n)
        yield offset, end
        offset = end


def build_fixed_size(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> BlobBuildResult:
    """Build a blob using fixed-size chunking (§3.2).

    For ``chunk_size`` ``S``, all chunks except possibly the final one
    are exactly ``S`` bytes. The blob carries ``chunking: 0``.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    chunks: list[Entity] = []
    chunk_hashes: list[Hash] = []
    for start, end in _slice_offsets_fixed(data, chunk_size):
        chunk = _chunk_entity(data[start:end])
        chunks.append(chunk)
        chunk_hashes.append(chunk.compute_hash())

    blob = _blob_entity(
        total_size=len(data),
        chunk_size=chunk_size,
        chunking=CHUNKING_FIXED_SIZE,
        chunk_hashes=chunk_hashes,
    )
    return BlobBuildResult(blob=blob, chunks=chunks, blob_hash=blob.compute_hash())


def build_fastcdc(data: bytes, target_size: int = DEFAULT_CHUNK_SIZE) -> BlobBuildResult:
    """Build a blob using FastCDC/NC2 chunking (§3.6).

    ``target_size`` is the nominal target — derived parameters: min =
    target/4, max = target*2. The blob carries ``chunking: 1``,
    ``chunk_size = target_size``.

    Cross-impl-load-bearing: Python, Go, and Rust MUST produce byte-
    identical chunks for the same input + ``target_size``.
    """
    if target_size <= 0:
        raise ValueError("target_size must be positive")

    chunks: list[Entity] = []
    chunk_hashes: list[Hash] = []
    for slice_bytes in fastcdc.chunks_of(data, target_size):
        chunk = _chunk_entity(slice_bytes)
        chunks.append(chunk)
        chunk_hashes.append(chunk.compute_hash())

    blob = _blob_entity(
        total_size=len(data),
        chunk_size=target_size,
        chunking=CHUNKING_FASTCDC_NC2,
        chunk_hashes=chunk_hashes,
    )
    return BlobBuildResult(blob=blob, chunks=chunks, blob_hash=blob.compute_hash())


# Algorithm dispatch — convenience for callers that carry the algorithm
# identifier as data (e.g., from a config or wire field).
_BUILDERS = {
    CHUNKING_FIXED_SIZE: build_fixed_size,
    CHUNKING_FASTCDC_NC2: build_fastcdc,
}


def build_blob(
    data: bytes,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    chunking: int = CHUNKING_FASTCDC_NC2,
) -> BlobBuildResult:
    """Build a blob using the algorithm identified by ``chunking``.

    Convenience dispatch over the two built-in chunkers; custom values
    (256+) per §2.1 are not handled here — callers using custom
    configurations build directly with their own chunker.
    """
    builder = _BUILDERS.get(chunking)
    if builder is None:
        raise ValueError(
            f"Unknown chunking algorithm {chunking}; "
            "values 0–255 are reserved (only 0 and 1 are implemented in this module). "
            "For custom values (256+), call build_fixed_size / build_fastcdc directly "
            "or provide your own builder."
        )
    return builder(data, chunk_size)


def persist(result: BlobBuildResult, store: ContentStore) -> Hash:
    """Persist a build result to a content store. Returns the blob hash.

    Idempotent: the content store is content-addressed and append-only,
    so re-persisting the same blob is a no-op.
    """
    for chunk in result.chunks:
        store.put(chunk)
    store.put(result.blob)
    return result.blob_hash


# -----------------------------------------------------------------------------
# Verification (§3.3)
# -----------------------------------------------------------------------------


class ContentVerificationError(Exception):
    """Raised when a blob fails the §3.3 verification gate.

    ``reason`` is one of: ``"missing_chunk"``, ``"empty_chunk"``,
    ``"size_mismatch"``. The optional ``chunk_hash`` identifies the
    offending chunk for ``"missing_chunk"`` / ``"empty_chunk"``.
    """

    def __init__(self, reason: str, *, chunk_hash: Hash | None = None) -> None:
        msg = f"content verification failed: {reason}"
        if chunk_hash is not None:
            msg += f" (chunk_hash={chunk_hash.hex()})"
        super().__init__(msg)
        self.reason = reason
        self.chunk_hash = chunk_hash


def verify_content(blob: Entity, store: ContentStore) -> None:
    """Run the §3.3 verification gate: every chunk present, non-empty,
    and total declared size matches the sum of chunk payload sizes.

    Per-chunk entity-hash verification is the receiver's responsibility
    on receipt (V7 §1.8 entity fidelity) — not re-run here.

    Raises :class:`ContentVerificationError` on failure.
    """
    if blob.type != "system/content/blob":
        raise ContentVerificationError(
            f"verify_content called on non-blob entity (type={blob.type})"
        )
    chunk_hashes: list[Hash] = blob.data["chunks"]
    declared_total = int(blob.data["total_size"])

    total = 0
    for chunk_hash in chunk_hashes:
        chunk = store.get(chunk_hash)
        if chunk is None:
            raise ContentVerificationError("missing_chunk", chunk_hash=chunk_hash)
        payload = chunk.data.get("payload", b"")
        if len(payload) == 0:
            raise ContentVerificationError("empty_chunk", chunk_hash=chunk_hash)
        total += len(payload)

    if total != declared_total:
        raise ContentVerificationError("size_mismatch")


# -----------------------------------------------------------------------------
# Reassembly (§3.4)
# -----------------------------------------------------------------------------


class ContentReassemblyError(Exception):
    """Raised when content cannot be reassembled (blob or a chunk
    missing). ``missing_hash`` carries the offending hash.
    """

    def __init__(self, reason: str, *, missing_hash: Hash | None = None) -> None:
        msg = f"content reassembly failed: {reason}"
        if missing_hash is not None:
            msg += f" (hash={missing_hash.hex()})"
        super().__init__(msg)
        self.reason = reason
        self.missing_hash = missing_hash


def reassemble_content(blob_hash: Hash, store: ContentStore) -> bytes:
    """Reassemble raw content bytes from a blob hash per §3.4.

    Concatenates chunk payloads in the order recorded by the blob's
    ``chunks`` list. Raises :class:`ContentReassemblyError` if the blob
    or any chunk is missing.

    For blobs ≥ 64 MiB DOMAIN-LOCAL-FILES v1.3 §5.3 SHOULD a streaming
    consumer instead — see :func:`stream_reassemble`. This function
    materializes the full payload in memory and is appropriate for
    blobs below the streaming threshold.
    """
    blob = store.get(blob_hash)
    if blob is None:
        raise ContentReassemblyError("blob_not_found", missing_hash=blob_hash)
    if blob.type != "system/content/blob":
        raise ContentReassemblyError(
            f"hash resolves to non-blob entity (type={blob.type})"
        )
    parts: list[bytes] = []
    for chunk_hash in blob.data["chunks"]:
        chunk = store.get(chunk_hash)
        if chunk is None:
            raise ContentReassemblyError("missing_chunk", missing_hash=chunk_hash)
        parts.append(chunk.data["payload"])
    return b"".join(parts)


def stream_reassemble(
    blob_hash: Hash, store: ContentStore
) -> Iterator[bytes]:
    """Yield chunk payloads in order for streaming reassembly per §3.4.

    DOMAIN-LOCAL-FILES v1.3 §5.3 L4 SHOULD: for blob sizes ≥ 64 MiB,
    consume this iterator directly into the FS write pipeline (atomic
    temp + fsync + rename) rather than materializing
    :func:`reassemble_content`'s full byte buffer in memory. CONTENT
    v3.5 §3.4 reassembly is Reference-classified — both shapes are
    conformant.

    Raises :class:`ContentReassemblyError` lazily when consumed (on
    first missing chunk). Callers SHOULD wrap iteration in a
    try/except.
    """
    blob = store.get(blob_hash)
    if blob is None:
        raise ContentReassemblyError("blob_not_found", missing_hash=blob_hash)
    if blob.type != "system/content/blob":
        raise ContentReassemblyError(
            f"hash resolves to non-blob entity (type={blob.type})"
        )
    for chunk_hash in blob.data["chunks"]:
        chunk = store.get(chunk_hash)
        if chunk is None:
            raise ContentReassemblyError(
                "missing_chunk", missing_hash=chunk_hash
            )
        yield chunk.data["payload"]


# -----------------------------------------------------------------------------
# Streaming ingest — feed an input stream through FastCDC, persist chunks
# as they're produced, return blob entity at the end. DOMAIN-LOCAL-FILES
# v1.3 §4.3 L4 SHOULD; CONTENT v3.5 §3.6 conformance gate unaffected
# (same FastCDC boundaries).
# -----------------------------------------------------------------------------


def build_blob_streaming(
    blocks: Iterator[bytes],
    store: ContentStore,
    target_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[Entity, Hash, int]:
    """Stream-chunk ``blocks`` through FastCDC, persist each chunk as
    it's produced, and return ``(blob_entity, blob_hash, total_size)``.

    Memory bound: at most one chunk's worth of payload (≤ ``max_size``
    = ``target_size * 2``) plus the FastCDC sliding buffer (≤
    ``max_size + read_block``). For default 4 MiB target that's ~16
    MiB peak regardless of input size — versus ``build_fastcdc``
    which holds the entire input + chunk list + blob in memory.

    Equivalent output to ``build_fastcdc(b"".join(blocks),
    target_size)`` then ``persist(...)`` — same chunk boundaries, same
    blob hash, same persisted state. The CONTENT v3.5 §3.6.5 / §3.7
    conformance gate is unaffected (boundary determinism is a property
    of the FastCDC algorithm, not the input shape).
    """
    from entity_handlers.content.fastcdc import stream_chunks

    chunk_hashes: list[Hash] = []
    total_size = 0
    for chunk_payload in stream_chunks(blocks, target_size):
        total_size += len(chunk_payload)
        chunk = _chunk_entity(chunk_payload)
        store.put(chunk)
        chunk_hashes.append(chunk.compute_hash())

    blob = _blob_entity(
        total_size=total_size,
        chunk_size=target_size,
        chunking=CHUNKING_FASTCDC_NC2,
        chunk_hashes=chunk_hashes,
    )
    store.put(blob)
    return blob, blob.compute_hash(), total_size


__all__ = [
    "BlobBuildResult",
    "CHUNKING_FIXED_SIZE",
    "CHUNKING_FASTCDC_NC2",
    "DEFAULT_CHUNK_SIZE",
    "MIN_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "GET_BATCH_SIZE",
    "ContentVerificationError",
    "ContentReassemblyError",
    "build_blob",
    "build_fixed_size",
    "build_fastcdc",
    "persist",
    "verify_content",
    "reassemble_content",
    "stream_reassemble",
    "build_blob_streaming",
]
