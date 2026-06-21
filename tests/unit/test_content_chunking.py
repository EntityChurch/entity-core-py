"""Tests for blob/chunk entity construction, verification, and reassembly
per EXTENSION-CONTENT v3.5 §3.2 / §3.3 / §3.4.

Three classes:

1. **Fixed-size chunker** (§3.2) — boundary discipline (all non-final
   chunks exact, final MAY be smaller), blob construction shape,
   round-trip.
2. **Verification** (§3.3) — completeness, non-empty-chunk, size match.
3. **Reassembly** (§3.4) — bytes round-trip, missing-chunk error, blob-
   not-found error.

Plus a dedup property test: same content + same chunker + same params →
same blob hash, regardless of how many times we build it.
"""

from __future__ import annotations

import random

import pytest

from entity_core.storage.content_store import ContentStore
from entity_handlers.content import chunking
from entity_handlers.content.chunking import (
    CHUNKING_FASTCDC_NC2,
    CHUNKING_FIXED_SIZE,
    BlobBuildResult,
    ContentReassemblyError,
    ContentVerificationError,
    build_blob,
    build_blob_streaming,
    build_fastcdc,
    build_fixed_size,
    persist,
    reassemble_content,
    stream_reassemble,
    verify_content,
)


def _seeded_bytes(n: int, seed: int = 0xC0FFEE) -> bytes:
    return random.Random(seed).randbytes(n)


# -----------------------------------------------------------------------------
# Fixed-size chunker (§3.2)
# -----------------------------------------------------------------------------


class TestFixedSize:
    def test_empty(self):
        result = build_fixed_size(b"", chunk_size=1024)
        assert result.blob.data["total_size"] == 0
        assert result.blob.data["chunk_size"] == 1024
        assert result.blob.data["chunking"] == CHUNKING_FIXED_SIZE
        assert result.blob.data["chunks"] == []
        assert result.chunks == []

    def test_single_chunk_smaller_than_size(self):
        data = b"hello world"
        result = build_fixed_size(data, chunk_size=1024)
        assert result.blob.data["total_size"] == len(data)
        assert len(result.blob.data["chunks"]) == 1
        assert len(result.chunks) == 1
        assert result.chunks[0].data["payload"] == data

    def test_exact_boundary(self):
        data = b"X" * 1024
        result = build_fixed_size(data, chunk_size=1024)
        # Exactly one full-size chunk; no final remainder.
        assert len(result.chunks) == 1
        assert result.chunks[0].data["payload"] == data

    def test_multi_chunk_with_remainder(self):
        data = b"A" * 1024 + b"B" * 1024 + b"C" * 500
        result = build_fixed_size(data, chunk_size=1024)
        assert len(result.chunks) == 3
        assert result.chunks[0].data["payload"] == b"A" * 1024
        assert result.chunks[1].data["payload"] == b"B" * 1024
        assert result.chunks[2].data["payload"] == b"C" * 500
        # Hashes in blob.chunks align with chunk entity hashes
        for i, ch in enumerate(result.chunks):
            assert result.blob.data["chunks"][i] == ch.compute_hash()

    def test_rejects_zero_chunk_size(self):
        with pytest.raises(ValueError):
            build_fixed_size(b"X", chunk_size=0)


# -----------------------------------------------------------------------------
# FastCDC chunker (§3.6) — sanity over the chunking.py wrapper
# -----------------------------------------------------------------------------


class TestFastCDCWrapper:
    def test_round_trips_via_persistence(self):
        data = _seeded_bytes(64 * 1024 * 5, seed=0xAB)
        result = build_fastcdc(data, target_size=64 * 1024)
        store = ContentStore()
        blob_hash = persist(result, store)

        # The blob hash equals what we built.
        assert blob_hash == result.blob_hash

        recovered = reassemble_content(blob_hash, store)
        assert recovered == data

    def test_blob_carries_chunking_one(self):
        data = b"\x00" * 8192
        result = build_fastcdc(data, target_size=64 * 1024)
        assert result.blob.data["chunking"] == CHUNKING_FASTCDC_NC2
        assert result.blob.data["chunk_size"] == 64 * 1024


# -----------------------------------------------------------------------------
# build_blob dispatch
# -----------------------------------------------------------------------------


class TestBuildBlobDispatch:
    def test_fixed_size_via_dispatch(self):
        result = build_blob(b"hello", chunk_size=4, chunking=CHUNKING_FIXED_SIZE)
        # 5 bytes / 4 → two chunks: "hell", "o"
        assert len(result.chunks) == 2
        assert result.chunks[0].data["payload"] == b"hell"
        assert result.chunks[1].data["payload"] == b"o"

    def test_fastcdc_via_dispatch(self):
        result = build_blob(b"\x00" * 100, chunk_size=64 * 1024, chunking=CHUNKING_FASTCDC_NC2)
        # Below min_size → single chunk.
        assert len(result.chunks) == 1

    def test_unknown_algorithm_rejected(self):
        with pytest.raises(ValueError, match="Unknown chunking"):
            build_blob(b"x", chunking=99)


# -----------------------------------------------------------------------------
# Verification (§3.3)
# -----------------------------------------------------------------------------


class TestVerification:
    def test_complete_blob_passes(self):
        data = _seeded_bytes(8192, seed=1)
        result = build_fixed_size(data, chunk_size=1024)
        store = ContentStore()
        persist(result, store)
        # Should not raise.
        verify_content(result.blob, store)

    def test_missing_chunk(self):
        # Distinct chunk contents so they hash differently — otherwise
        # the content store dedups them to one entity and "only persist
        # the first chunk" effectively persists both.
        data = b"A" * 1024 + b"B" * 1024
        result = build_fixed_size(data, chunk_size=1024)
        store = ContentStore()
        # Persist blob + only the FIRST chunk
        store.put(result.chunks[0])
        store.put(result.blob)
        with pytest.raises(ContentVerificationError) as ei:
            verify_content(result.blob, store)
        assert ei.value.reason == "missing_chunk"
        assert ei.value.chunk_hash == result.blob.data["chunks"][1]

    def test_size_mismatch_via_doctored_blob(self):
        data = b"X" * 1024
        result = build_fixed_size(data, chunk_size=1024)
        store = ContentStore()
        persist(result, store)
        # Doctor the blob to claim a wrong total_size; then verify against
        # the doctored view (we don't put it back into the store — verify
        # walks the given blob entity, looks up chunks in the store).
        doctored_blob = result.blob.__class__(
            type=result.blob.type,
            data={**result.blob.data, "total_size": 9999},
        )
        with pytest.raises(ContentVerificationError) as ei:
            verify_content(doctored_blob, store)
        assert ei.value.reason == "size_mismatch"

    def test_non_blob_entity_rejected(self):
        from entity_core.protocol.entity import Entity

        not_a_blob = Entity(type="system/content/chunk", data={"payload": b"x"})
        store = ContentStore()
        with pytest.raises(ContentVerificationError):
            verify_content(not_a_blob, store)


# -----------------------------------------------------------------------------
# Reassembly (§3.4)
# -----------------------------------------------------------------------------


class TestReassembly:
    def test_round_trip_fixed_size(self):
        data = _seeded_bytes(10 * 1024, seed=2)
        result = build_fixed_size(data, chunk_size=1024)
        store = ContentStore()
        persist(result, store)
        assert reassemble_content(result.blob_hash, store) == data

    def test_blob_not_found(self):
        store = ContentStore()
        fake_hash = b"\x00" + b"\xab" * 32
        with pytest.raises(ContentReassemblyError) as ei:
            reassemble_content(fake_hash, store)
        assert ei.value.reason == "blob_not_found"

    def test_missing_chunk_raises(self):
        # Distinct per-chunk content so dedup doesn't persist them
        # together when we only ``store.put`` the first.
        data = b"A" * 1024 + b"B" * 1024 + b"C" * 1024 + b"D" * 1024
        result = build_fixed_size(data, chunk_size=1024)
        store = ContentStore()
        # Only persist the blob and the first chunk
        store.put(result.blob)
        store.put(result.chunks[0])
        with pytest.raises(ContentReassemblyError) as ei:
            reassemble_content(result.blob_hash, store)
        assert ei.value.reason == "missing_chunk"


class TestStreamingConformance:
    """v1.3 §4.3 + §5.3 L4 SHOULD streaming.

    The cross-impl gate per CONTENT v3.5 §3.6.5 is byte-identical chunk
    boundaries on the same input. Streaming MUST produce the same
    boundaries as the in-memory chunker for any input split shape —
    otherwise impls that stream and impls that buffer would diverge.
    """

    @pytest.mark.parametrize("size", [128 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024])
    def test_build_blob_streaming_matches_in_memory(self, size):
        data = _seeded_bytes(size, seed=42)
        # In-memory reference
        ref = build_fastcdc(data, target_size=1024 * 1024)
        # Streaming — feed the data in arbitrary block sizes
        block = 64 * 1024 + 7  # an awkward size to stress the buffer
        def _blocks():
            for i in range(0, len(data), block):
                yield data[i:i + block]
        store = ContentStore()
        blob_ent, blob_hash, total = build_blob_streaming(
            _blocks(), store, target_size=1024 * 1024
        )
        assert blob_hash == ref.blob_hash, (
            "streaming chunker MUST produce the same blob hash as the "
            "in-memory chunker (§3.6.5 cross-impl conformance)"
        )
        assert total == size
        assert blob_ent.data["chunks"] == ref.blob.data["chunks"]

    def test_stream_reassemble_matches_buffered(self):
        data = _seeded_bytes(2 * 1024 * 1024, seed=99)
        result = build_fastcdc(data, target_size=256 * 1024)
        store = ContentStore()
        persist(result, store)
        # Streaming reassembly concatenated == buffered reassembly
        streamed = b"".join(stream_reassemble(result.blob_hash, store))
        buffered = reassemble_content(result.blob_hash, store)
        assert streamed == buffered == data


# -----------------------------------------------------------------------------
# Dedup / determinism
# -----------------------------------------------------------------------------


class TestDeduplication:
    def test_same_input_same_chunker_same_params_same_blob_hash(self):
        """The dedup invariant from §2.1 / §2.3: identical content +
        identical `(chunking, chunk_size)` produces identical entity
        hashes regardless of producer.
        """
        data = _seeded_bytes(16 * 1024, seed=42)
        a = build_fastcdc(data, target_size=64 * 1024)
        b = build_fastcdc(data, target_size=64 * 1024)
        assert a.blob_hash == b.blob_hash
        assert [c.compute_hash() for c in a.chunks] == [
            c.compute_hash() for c in b.chunks
        ]

    def test_different_chunk_size_different_blob_hash(self):
        """§2.1 dedup-identity table row 2: same algorithm, different
        chunk_size → different chunks, different blob hash.
        """
        data = _seeded_bytes(16 * 1024, seed=42)
        a = build_fastcdc(data, target_size=64 * 1024)
        b = build_fastcdc(data, target_size=128 * 1024)
        # Even when the byte content is identical, the chunk_size field
        # is in blob.data, so blob hashes differ.
        assert a.blob_hash != b.blob_hash

    def test_different_algorithm_different_blob_hash(self):
        """§2.1 dedup-identity table row 3: same content, different
        algorithm → different chunks (in general) and different blob
        hash.
        """
        data = _seeded_bytes(32 * 1024, seed=42)
        a = build_fixed_size(data, chunk_size=64 * 1024)
        b = build_fastcdc(data, target_size=64 * 1024)
        assert a.blob_hash != b.blob_hash


# -----------------------------------------------------------------------------
# Constants — guard against accidental drift from §10
# -----------------------------------------------------------------------------


class TestConstants:
    def test_default_chunk_size_is_4_mib(self):
        assert chunking.DEFAULT_CHUNK_SIZE == 1 * 1024 * 1024  # v3.6 §3.5 A2

    def test_min_chunk_size_is_64_kib(self):
        # Equal to the §4.3 inline-include threshold (and §10.1).
        assert chunking.MIN_CHUNK_SIZE == 65536

    def test_max_chunk_size_is_8_mib(self):
        assert chunking.MAX_CHUNK_SIZE == 8 * 1024 * 1024

    def test_get_batch_size_is_64(self):
        assert chunking.GET_BATCH_SIZE == 64
