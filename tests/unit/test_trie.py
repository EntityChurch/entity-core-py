"""Unit tests for the content-addressed hash-keyed HAMT (EXTENSION-TREE v4.0).

Substrate fork sign-off: node moved from v3.x path-keyed
compressed trie to v4.0 IPLD HashMap with CHAMP canonicalization. Tests
focus on the structural invariants the v4.0 substrate exists to provide:

- Empty-root canonical CBOR (§3.1 conformance fixture #1)
- Single-binding canonical CBOR (§3.1 conformance fixture #2)
- Determinism: same bindings → same root, any insertion order
- Round-trip: build_trie → collect_all_bindings recovers binding set
- collect_trie_hashes enumerates all reachable hashes
- Routing helpers match the spec's worked example

CHAMP-on-delete invariance is exercised in detail by
``test_trie_incremental.py``; this file focuses on the static properties.
"""

from __future__ import annotations

import hashlib

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.trie import (
    BIT_WIDTH,
    BUCKET_SIZE,
    EMPTY_NODE_CBOR,
    K,
    TRIE_NODE_TYPE,
    build_trie,
    canonical_normalize,
    collect_all_bindings,
    collect_trie_hashes,
    empty_trie,
    hash_bytes_of,
    join_path,
    load_trie_node,
    position_at_level,
    trie_put,
)
from entity_core.utils.ecf import ecf_encode


@pytest.fixture
def content_store() -> ContentStore:
    return ContentStore()


@pytest.fixture
def sample_hashes(content_store: ContentStore) -> dict[str, bytes]:
    entities = {
        "readme": Entity(type="file", data={"name": "readme"}),
        "config": Entity(type="file", data={"name": "config"}),
        "main": Entity(type="file", data={"name": "main"}),
        "test": Entity(type="file", data={"name": "test"}),
        "lib": Entity(type="file", data={"name": "lib"}),
    }
    return {name: content_store.put(e) for name, e in entities.items()}


def _vh(label: str) -> bytes:
    """Make a deterministic 33-byte value_hash for fuzzer-style tests."""
    return bytes([0x00]) + hashlib.sha256(label.encode()).digest()


class TestParameters:
    """Spec-pinned parameters: drift here = silent root divergence."""

    def test_bit_width_pinned(self):
        assert BIT_WIDTH == 5

    def test_k_is_32(self):
        assert K == 32

    def test_bucket_size_pinned(self):
        assert BUCKET_SIZE == 3


class TestConformanceFixtures:
    """§3.1 literal-hex conformance fixtures — anchors for cross-impl
    byte-identity. Any deviation breaks ``convergent_mirror`` at the
    substrate."""

    def test_empty_node_cbor_matches_fixture(self):
        encoded = ecf_encode({"map": b"\x00\x00\x00\x00", "data": []})
        assert encoded == EMPTY_NODE_CBOR
        # Verify the literal hex sequence (sanity — this is the canonical
        # seed the fuzzer pins to).
        assert EMPTY_NODE_CBOR.hex() == "a2636d61704400000000646461746180"

    def test_single_binding_position_28(self):
        # SHA-256("") byte 0 = 0xe3 = 0b11100011 → bits 0-4 MSB-first = 28
        routing = hash_bytes_of("")
        assert routing[0] == 0xE3
        assert position_at_level(routing, 0) == 28

    def test_single_binding_cbor(self):
        h = bytes([0x00]) + bytes(32)
        bucket = [["", h]]
        encoded = ecf_encode(
            {"map": bytes.fromhex("10000000"), "data": [bucket]}
        )
        expected = bytes.fromhex(
            "a2636d61704410000000646461746181818260" + "5821" + h.hex()
        )
        assert encoded == expected


class TestPositionAtLevel:
    """Routing helpers: 5-bit MSB-first slices through 32-byte hash."""

    def test_level_0_first_5_bits(self):
        # 0b11100011 -> first 5 = 11100 = 28
        assert position_at_level(b"\xe3" + b"\x00" * 31, 0) == 28
        # 0b00000111 -> first 5 = 00000 = 0
        assert position_at_level(b"\x07" + b"\x00" * 31, 0) == 0
        # 0b11111000 -> first 5 = 11111 = 31
        assert position_at_level(b"\xf8" + b"\x00" * 31, 0) == 31

    def test_level_1_spans_two_bytes(self):
        # Level 1 = bits 5-9; in byte 0 bits 5-7 (lower 3 bits) and byte 1
        # bits 0-1 (upper 2 bits MSB-first).
        # byte0=0b11100011 → low 3 bits = 011; byte1=0b11000000 → high 2 bits = 11
        # → 01111 = 15
        assert position_at_level(b"\xe3\xc0" + b"\x00" * 30, 1) == 15

    def test_canonical_normalize_passthrough_ascii(self):
        assert canonical_normalize("data/file") == "data/file"


class TestJoinPath:
    def test_empty_prefix(self):
        assert join_path("", "foo") == "foo"

    def test_empty_suffix(self):
        assert join_path("foo", "") == "foo"

    def test_normal(self):
        assert join_path("data", "file") == "data/file"


class TestBuildTrieEmpty:
    def test_empty_bindings_is_canonical(self, content_store):
        root = build_trie([], content_store)
        node = content_store.get(root)
        assert node is not None
        assert node.type == TRIE_NODE_TYPE
        # v4.0 shape: {map: bytes(4), data: []}
        assert node.data["map"] == b"\x00\x00\x00\x00"
        assert node.data["data"] == []

    def test_empty_trie_determinism(self, content_store):
        root1 = build_trie([], content_store)
        root2 = build_trie([], content_store)
        assert root1 == root2

    def test_empty_trie_helper_matches_build(self, content_store):
        assert empty_trie(content_store) == build_trie([], content_store)


class TestBuildTrieSingleBinding:
    def test_single_root_binding(self, content_store, sample_hashes):
        """Binding at relative_key = '' lives in a bucket at position 28
        (SHA-256(\"\") routing)."""
        h = sample_hashes["readme"]
        root = build_trie([("", h)], content_store)
        node = load_trie_node(root, content_store)
        assert node is not None
        # bitmap has only bit 28 set
        assert node["map"] == bytes.fromhex("10000000")
        # data is a single Bucket with one tuple [(", h)]
        assert len(node["data"]) == 1
        bucket = node["data"][0]
        assert isinstance(bucket, list)
        assert bucket == [["", h]]

    def test_single_deep_path_inline_bucket(self, content_store, sample_hashes):
        """A single binding under any key lives inline as a single-tuple
        bucket — no descent into sub-nodes regardless of path depth."""
        h = sample_hashes["readme"]
        root = build_trie([("data/project/readme", h)], content_store)
        node = load_trie_node(root, content_store)
        assert node is not None
        # Exactly one set bit, one data entry, one bucket tuple.
        bitmap_int = int.from_bytes(node["map"], "big")
        assert bin(bitmap_int).count("1") == 1
        assert len(node["data"]) == 1
        bucket = node["data"][0]
        assert bucket == [["data/project/readme", h]]


class TestBucketOverflowSplit:
    """When more than bucketSize=3 keys hash to the same level-0 position,
    the bucket overflows and a sub-node is materialized."""

    def test_overflow_forces_sub_node(self, content_store, sample_hashes):
        # Find 4 distinct relative keys that share position-0
        target_position = position_at_level(hash_bytes_of("key-0"), 0)
        keys: list[str] = []
        i = 0
        while len(keys) < 4 and i < 100_000:
            candidate = f"k{i}"
            if position_at_level(hash_bytes_of(candidate), 0) == target_position:
                keys.append(candidate)
            i += 1
        assert len(keys) == 4, "Could not find 4 colliding keys in 100k tries"

        h = sample_hashes["readme"]
        bindings = sorted([(k, h) for k in keys])
        root = build_trie(bindings, content_store)
        node = load_trie_node(root, content_store)
        # The colliding position now holds a Link (CBOR bytes), not a Bucket
        bitmap_int = int.from_bytes(node["map"], "big")
        # The position should be set
        assert (bitmap_int >> target_position) & 1
        # Entry at the popcount index is a 33-byte hash (Link), not a list
        # (Bucket)
        popcount_before = bin(
            bitmap_int & ((1 << target_position) - 1)
        ).count("1")
        entry = node["data"][popcount_before]
        assert isinstance(entry, (bytes, bytearray))
        assert len(entry) == 33


class TestDeterminism:
    def test_same_bindings_same_hash(self, content_store, sample_hashes):
        bindings = sorted(
            [
                ("data/config", sample_hashes["config"]),
                ("data/readme", sample_hashes["readme"]),
                ("src/main", sample_hashes["main"]),
            ]
        )
        root1 = build_trie(bindings, content_store)
        root2 = build_trie(bindings, content_store)
        assert root1 == root2

    def test_insertion_order_invariance(self, content_store, sample_hashes):
        a = [
            ("data/readme", sample_hashes["readme"]),
            ("data/config", sample_hashes["config"]),
            ("src/main", sample_hashes["main"]),
        ]
        b = list(reversed(a))
        # build_trie sorts internally; test trie_put order independence.
        root_a = empty_trie(content_store)
        for k, v in a:
            root_a = trie_put(root_a, k, v, content_store)
        root_b = empty_trie(content_store)
        for k, v in b:
            root_b = trie_put(root_b, k, v, content_store)
        assert root_a == root_b

    def test_different_bindings_different_hash(self, content_store, sample_hashes):
        root1 = build_trie([("a", sample_hashes["readme"])], content_store)
        root2 = build_trie([("b", sample_hashes["readme"])], content_store)
        assert root1 != root2


class TestRoundTrip:
    def test_empty(self, content_store):
        root = build_trie([], content_store)
        assert collect_all_bindings(root, "", content_store) == []

    def test_single(self, content_store, sample_hashes):
        bindings = [("readme", sample_hashes["readme"])]
        root = build_trie(bindings, content_store)
        result = sorted(collect_all_bindings(root, "", content_store))
        assert result == bindings

    def test_multiple(self, content_store, sample_hashes):
        bindings = sorted(
            [
                ("data/config", sample_hashes["config"]),
                ("data/readme", sample_hashes["readme"]),
                ("src/main", sample_hashes["main"]),
            ]
        )
        root = build_trie(bindings, content_store)
        result = sorted(collect_all_bindings(root, "", content_store))
        assert result == bindings

    def test_with_prefix(self, content_store, sample_hashes):
        bindings = [("file", sample_hashes["readme"])]
        root = build_trie(bindings, content_store)
        result = collect_all_bindings(root, "my/prefix", content_store)
        assert result == [("my/prefix/file", sample_hashes["readme"])]

    def test_binding_at_root_and_children(self, content_store, sample_hashes):
        bindings = sorted(
            [
                ("", sample_hashes["readme"]),  # binding at root
                ("child", sample_hashes["config"]),
            ]
        )
        root = build_trie(bindings, content_store)
        result = sorted(collect_all_bindings(root, "", content_store))
        assert result == bindings

    def test_large_round_trip(self, content_store):
        """50 bindings — exercises bucket overflow and sub-node walks."""
        bindings = sorted([(f"k-{i}", _vh(f"v-{i}")) for i in range(50)])
        root = build_trie(bindings, content_store)
        result = sorted(collect_all_bindings(root, "", content_store))
        assert result == bindings


class TestLoadTrieNode:
    def test_load_valid(self, content_store, sample_hashes):
        root = build_trie([("file", sample_hashes["readme"])], content_store)
        data = load_trie_node(root, content_store)
        assert data is not None
        assert isinstance(data, dict)
        assert "map" in data
        assert "data" in data

    def test_load_nonexistent(self, content_store):
        assert load_trie_node(b"\x00" * 33, content_store) is None


class TestCollectTrieHashes:
    def test_collects_node_and_binding_hashes(self, content_store, sample_hashes):
        bindings = sorted(
            [
                ("a", sample_hashes["readme"]),
                ("b", sample_hashes["config"]),
            ]
        )
        root = build_trie(bindings, content_store)
        all_hashes = collect_trie_hashes(root, content_store)
        assert root in all_hashes
        assert sample_hashes["readme"] in all_hashes
        assert sample_hashes["config"] in all_hashes

    def test_empty_trie(self, content_store):
        root = build_trie([], content_store)
        all_hashes = collect_trie_hashes(root, content_store)
        assert root in all_hashes
        assert len(all_hashes) == 1  # Just the root node

    def test_collects_sub_node_hashes_after_overflow(self, content_store):
        """When bucket overflow forces sub-nodes, collect_trie_hashes MUST
        enumerate them (else fetch-diff misses subtree nodes)."""
        bindings = sorted([(f"k-{i}", _vh(f"v-{i}")) for i in range(50)])
        root = build_trie(bindings, content_store)
        all_hashes = collect_trie_hashes(root, content_store)
        # Root + at least 1 sub-node (50 bindings can't all fit at K=32 in
        # one node) + all 50 value_hashes
        assert root in all_hashes
        for _, v in bindings:
            assert v in all_hashes
        # At least 2 trie nodes (root + at least one sub-node)
        trie_node_hashes = {
            h for h in all_hashes
            if (e := content_store.get(h)) is not None
            and e.type == TRIE_NODE_TYPE
        }
        assert len(trie_node_hashes) >= 2
