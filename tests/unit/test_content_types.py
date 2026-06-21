"""Tests for EXTENSION-CONTENT v3.5 entity type registrations + ECF wire shape.

The §2.8 (ENTITY-NATIVE-TYPE-SYSTEM) wire-shape rule pins that `array_of`
over a named-but-primitive type (`system/hash`, which is a 33-byte byte
string) emits flat byte strings — NOT envelope-wrapped {type, data}. This
was the exact cross-impl divergence that the TYPE v1.1 closeout caught in
Python's first pass; landing the pin before CONTENT v3.5 means we don't
recur it on blob `chunks`, response `found` / `missing`, or descriptor
`content`.

These tests grade:

1. All 7 content types register and resolve through `get_type_entity`.
2. Blob, chunk, and descriptor field specs match the spec text.
3. ECF round-trip of representative blob / chunk / descriptor entities
   produces flat-byte-string arrays — the §2.8 guard.
"""

from __future__ import annotations

import cbor2

from entity_core.protocol.entity import Entity
from entity_core.types.definitions import (
    get_all_type_entities,
)
from entity_core.utils.ecf import ecf_encode

_CONTENT_TYPE_NAMES = {
    "system/content/blob",
    "system/content/chunk",
    "system/content/descriptor",
    "system/content/get-request",
    "system/content/content-response",
    "system/content/ingest-request",
    "system/content/ingest-result",
}


def _types_by_name() -> dict[str, Entity]:
    return {e.data["name"]: e for e in get_all_type_entities()}


# -----------------------------------------------------------------------------
# Registration
# -----------------------------------------------------------------------------


class TestContentTypeRegistrations:
    def test_all_seven_types_registered(self):
        names = {e.data["name"] for e in get_all_type_entities()}
        missing = _CONTENT_TYPE_NAMES - names
        assert not missing, f"missing content types: {missing}"

    def test_blob_field_shape(self):
        blob = _types_by_name()["system/content/blob"]
        fields = blob.data["fields"]
        assert set(fields) == {"total_size", "chunk_size", "chunking", "chunks"}
        assert fields["total_size"] == {"type_ref": "primitive/uint"}
        assert fields["chunk_size"] == {"type_ref": "primitive/uint"}
        assert fields["chunking"] == {"type_ref": "primitive/uint"}
        # §2.8: array_of system/hash is flat
        assert fields["chunks"] == {"array_of": {"type_ref": "system/hash"}}

    def test_chunk_field_shape(self):
        chunk = _types_by_name()["system/content/chunk"]
        fields = chunk.data["fields"]
        assert set(fields) == {"payload"}
        assert fields["payload"] == {"type_ref": "primitive/bytes"}

    def test_descriptor_field_shape(self):
        desc = _types_by_name()["system/content/descriptor"]
        fields = desc.data["fields"]
        assert set(fields) == {"content", "media_type", "type_ref", "name", "metadata"}
        # content is required, the rest are optional
        assert fields["content"] == {"type_ref": "system/hash"}
        assert fields["media_type"].get("optional") is True
        assert fields["type_ref"].get("optional") is True
        assert fields["name"].get("optional") is True
        assert fields["metadata"].get("optional") is True

    def test_get_request_shape(self):
        req = _types_by_name()["system/content/get-request"]
        fields = req.data["fields"]
        assert fields == {"hashes": {"array_of": {"type_ref": "system/hash"}}}

    def test_content_response_shape(self):
        resp = _types_by_name()["system/content/content-response"]
        fields = resp.data["fields"]
        assert fields["found"] == {"array_of": {"type_ref": "system/hash"}}
        assert fields["missing"] == {"array_of": {"type_ref": "system/hash"}}

    def test_ingest_request_shape(self):
        req = _types_by_name()["system/content/ingest-request"]
        fields = req.data["fields"]
        # Both envelope and entity optional — caller MUST provide exactly one.
        # Enforcement is handler-side; type definition records the surface.
        assert fields["envelope"] == {"type_ref": "system/envelope", "optional": True}
        assert fields["entity"] == {"type_ref": "core/entity", "optional": True}

    def test_ingest_result_shape(self):
        res = _types_by_name()["system/content/ingest-result"]
        fields = res.data["fields"]
        assert fields["root"] == {"type_ref": "core/entity", "optional": True}
        # F-CIMP-1 generalization: `root_hash` is optional in
        # bundle-only envelopes (no envelope.root). Parallels `root` above —
        # both omitted together when the envelope is included-only.
        assert fields["root_hash"] == {"type_ref": "system/hash", "optional": True}
        assert fields["ingested_count"] == {"type_ref": "primitive/uint"}


# -----------------------------------------------------------------------------
# §2.8 wire-shape guard — ECF round-trip of representative entities
# -----------------------------------------------------------------------------


class TestContentEntityWireShape:
    """The TYPE v1.1 cross-impl closeout pinned (in §2.8) that `array_of`
    over named-but-primitive types like `system/hash` emits flat values
    on the wire. The same rule applies to CONTENT v3.5 §5.3 descriptor
    surfaces and to `blob.chunks`. These tests catch wrap-vs-flat
    divergence at the canonical-encoding boundary before it propagates
    to cross-impl runs.
    """

    @staticmethod
    def _hash(b: int) -> bytes:
        # A real system/hash is `algo_byte || 32-byte digest`. Fixture
        # values: algorithm 0x00 (ECFv1-SHA256) + a sentinel digest.
        return bytes([0x00]) + bytes([b]) * 32

    def test_blob_chunks_emit_flat_byte_strings(self):
        """Blob `chunks` MUST be a CBOR array of bare byte strings, not
        envelopes. §2.8 pin; §2.1 type definition.
        """
        h1 = self._hash(0xAA)
        h2 = self._hash(0xBB)
        blob = Entity(
            type="system/content/blob",
            data={
                "total_size": 8388608,
                "chunk_size": 4194304,
                "chunking": 1,
                "chunks": [h1, h2],
            },
        )
        decoded = cbor2.loads(ecf_encode({"type": blob.type, "data": blob.data}))
        chunks = decoded["data"]["chunks"]
        assert isinstance(chunks, list) and len(chunks) == 2
        for el in chunks:
            # Flat: each entry IS the byte string, not a dict-shaped envelope.
            assert isinstance(el, (bytes, bytearray)), (
                f"§2.8 violation: chunks element should be bytes, got {type(el).__name__}"
            )
        assert chunks[0] == h1
        assert chunks[1] == h2

    def test_chunk_payload_round_trips_as_raw_bytes(self):
        """Chunk `payload` is `primitive/bytes` — encodes as CBOR
        major-type-2 (bytes), no base64, no expansion.
        """
        payload = b"\x00\x01\x02" * 1024
        chunk = Entity(
            type="system/content/chunk",
            data={"payload": payload},
        )
        decoded = cbor2.loads(ecf_encode({"type": chunk.type, "data": chunk.data}))
        assert decoded["data"]["payload"] == payload
        assert isinstance(decoded["data"]["payload"], (bytes, bytearray))

    def test_descriptor_content_field_emits_flat_hash(self):
        """Descriptor `content` is `system/hash` — flat byte string, not
        wrapped. §2.4 + §2.8.
        """
        blob_hash = self._hash(0x42)
        desc = Entity(
            type="system/content/descriptor",
            data={
                "content": blob_hash,
                "media_type": "application/pdf",
            },
        )
        decoded = cbor2.loads(ecf_encode({"type": desc.type, "data": desc.data}))
        assert decoded["data"]["content"] == blob_hash
        assert isinstance(decoded["data"]["content"], (bytes, bytearray))
        assert decoded["data"]["media_type"] == "application/pdf"

    def test_get_request_hashes_emit_flat(self):
        req = Entity(
            type="system/content/get-request",
            data={"hashes": [self._hash(1), self._hash(2), self._hash(3)]},
        )
        decoded = cbor2.loads(ecf_encode({"type": req.type, "data": req.data}))
        assert all(isinstance(h, (bytes, bytearray)) for h in decoded["data"]["hashes"])

    def test_content_response_found_missing_emit_flat(self):
        resp = Entity(
            type="system/content/content-response",
            data={
                "found": [self._hash(0x10), self._hash(0x11)],
                "missing": [self._hash(0xFF)],
            },
        )
        decoded = cbor2.loads(ecf_encode({"type": resp.type, "data": resp.data}))
        assert all(isinstance(h, (bytes, bytearray)) for h in decoded["data"]["found"])
        assert all(isinstance(h, (bytes, bytearray)) for h in decoded["data"]["missing"])
