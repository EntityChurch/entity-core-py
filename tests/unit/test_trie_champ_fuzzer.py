"""CHAMP-on-delete byte-identical-output fuzzer for the v4.0 HAMT.

EXTENSION-TREE v4.0 §12.1 MUST: implementations MUST verify
CHAMP-on-delete correctness via a fuzzer that runs random insert/delete
sequences and compares root hashes. Insert-only tests do NOT exercise the
canonical-form collapse-and-inline logic — without this fuzzer, two peers
building "the same" tree by different histories produce different root
hashes silently, and ``convergent_mirror`` breaks at the substrate.

Four properties exercised here (the four called out in the
cross-impl stage-7 impl-start kickoff):

1. **CHAMP-on-delete invariant** — final binding set determines root hash
   regardless of insert/delete history (the silent-bug class).
2. **Reorder invariance** — pure insertion order does not affect root.
3. **Bucket-collision stress** — force ≥4 keys at the same 5-bit slice at
   multiple levels, ensuring sub-node split + cross-level descent run.
4. **Literal-byte vector regression** — re-assert the two §3.1 conformance
   fixtures as a structural property (already verified at module import in
   ``trie.py``; we re-test here so this fuzzer is the single canonical
   harness for cross-impl re-pinning).

Cross-impl portability: the seeded ``(operation, key)`` sequences here use
purely deterministic inputs — no system entropy. A Go/Rust port that
generates the same sequence with the same value_hashes MUST produce the
same root hashes. When ``entity-core-go`` and ``entity-core-rust`` come
online, lift these seeds to ``entity-workbench-go`` as the three-way
convergence harness.
"""

from __future__ import annotations

import hashlib
import random

import pytest

from entity_core.storage.content_store import ContentStore
from entity_core.storage.trie import (
    EMPTY_NODE_CBOR,
    build_trie,
    collect_all_bindings,
    empty_trie,
    hash_bytes_of,
    position_at_level,
    trie_put,
    trie_remove,
)
from entity_core.utils.ecf import ecf_encode


# ---------------------------------------------------------------------------
# Helpers — keep these mechanically portable across languages
# ---------------------------------------------------------------------------


def _vh(label: str) -> bytes:
    """Deterministic 33-byte value_hash from a label.

    Same scheme as ``test_trie_incremental.py``; portable to Go/Rust by
    construction: byte 0 = 0x00 (ECFv1-SHA256 algorithm marker) + SHA-256
    of UTF-8(label).
    """
    return bytes([0x00]) + hashlib.sha256(label.encode("utf-8")).digest()


def _from_scratch(bindings: dict[str, bytes], cs: ContentStore) -> bytes:
    return build_trie(sorted(bindings.items()), cs)


def _find_keys_at_position(level: int, target_position: int, n: int) -> list[str]:
    """Find ``n`` distinct keys whose routing position at ``level`` matches.

    Used to seed bucket-collision stress: ``n ≥ 4`` keys collide at one
    level, forcing the bucket to overflow and split into a sub-node.
    """
    found: list[str] = []
    i = 0
    while len(found) < n and i < 1_000_000:
        candidate = f"k{i}"
        routing = hash_bytes_of(candidate)
        if position_at_level(routing, level) == target_position:
            found.append(candidate)
        i += 1
    if len(found) < n:
        raise RuntimeError(
            f"Could not find {n} keys at level={level}, position={target_position}"
        )
    return found


# ---------------------------------------------------------------------------
# Property 1: CHAMP-on-delete invariance — the silent-bug class
# ---------------------------------------------------------------------------


class TestCHAMPOnDelete:
    """Final binding set determines root regardless of insert/delete history.

    Without CHAMP canonicalization, a node that grew via overflow then
    shrank via delete would leave behind a sub-node with <4 reachable
    entries — silently producing a different root than the same final set
    inserted directly. This is the v3.x silent-divergence bug class Stage 7
    eliminated.
    """

    @pytest.mark.parametrize("seed", range(8))
    def test_insert_then_delete_extras_matches_direct(self, seed):
        """Insert (target + extras), then delete extras → must equal direct
        build of target alone."""
        rng = random.Random(seed)
        cs = ContentStore()

        # Generate target binding set (20 keys)
        target_keys = [f"target-{seed}-{i}" for i in range(20)]
        target = {k: _vh(f"v-{seed}-{k}") for k in target_keys}

        # Generate extras (10 keys) NOT in target
        extras = {f"extra-{seed}-{i}": _vh(f"x-{seed}-{i}") for i in range(10)}

        # Direct build of target
        direct_root = _from_scratch(target, cs)

        # Insert all + delete extras in random order
        combined = {**target, **extras}
        items = list(combined.items())
        rng.shuffle(items)

        root = empty_trie(cs)
        for k, v in items:
            root = trie_put(root, k, v, cs)
        delete_order = list(extras.keys())
        rng.shuffle(delete_order)
        for k in delete_order:
            root = trie_remove(root, k, cs)

        assert root == direct_root, (
            f"seed={seed}: CHAMP-on-delete invariance broken — "
            f"insert+delete diverged from direct build"
        )
        # Round-trip sanity
        assert dict(collect_all_bindings(root, "", cs)) == target

    @pytest.mark.parametrize("seed", range(8))
    def test_interleaved_insert_delete_matches_live_set(self, seed):
        """Randomly interleaved put/remove; final root must equal the direct
        build of the resulting live set."""
        rng = random.Random(seed * 31 + 1)
        cs = ContentStore()
        # Larger key pool than the existing test_trie_incremental fuzzer
        # to push more bucket collisions.
        paths = [f"p-{seed}-{i}" for i in range(40)]
        live: dict[str, bytes] = {}
        root = empty_trie(cs)
        for step in range(200):
            p = rng.choice(paths)
            op = rng.choices(["put", "remove"], weights=[3, 1])[0]
            if op == "put":
                h = _vh(f"v-{seed}-{step}-{p}")
                live[p] = h
                root = trie_put(root, p, h, cs)
            else:
                live.pop(p, None)
                root = trie_remove(root, p, cs)
        assert root == _from_scratch(live, cs), (
            f"seed={seed}: interleaved insert/delete root != direct build"
        )


# ---------------------------------------------------------------------------
# Property 2: reorder invariance — insert order does not affect root
# ---------------------------------------------------------------------------


class TestReorderInvariance:
    @pytest.mark.parametrize("seed", range(8))
    def test_random_insertion_orders_same_root(self, seed):
        rng = random.Random(seed * 17 + 7)
        cs = ContentStore()
        bindings = {f"k-{seed}-{i}": _vh(f"v-{seed}-{i}") for i in range(30)}
        items = list(bindings.items())

        # Reference: from-scratch (sorted)
        ref = _from_scratch(bindings, cs)

        # Five random shuffles, all must produce ref
        for run in range(5):
            shuffled = list(items)
            rng.shuffle(shuffled)
            root = empty_trie(cs)
            for k, v in shuffled:
                root = trie_put(root, k, v, cs)
            assert root == ref, f"seed={seed} run={run}: reorder broke root"


# ---------------------------------------------------------------------------
# Property 3: bucket-collision stress — force overflow at multiple levels
# ---------------------------------------------------------------------------


class TestBucketCollisionStress:
    """Force ≥4 keys at the same 5-bit slice → bucket overflow → sub-node
    split. Insert-then-delete those colliding keys exercises the collapse
    path through a level boundary.
    """

    def test_overflow_at_level_0(self):
        cs = ContentStore()
        colliding = _find_keys_at_position(level=0, target_position=15, n=6)
        bindings = {k: _vh(f"c-{k}") for k in colliding}
        # Direct build forces overflow at level 0 → sub-node materialized
        root_direct = _from_scratch(bindings, cs)
        # Incremental build, same final set
        root_inc = empty_trie(cs)
        for k, v in bindings.items():
            root_inc = trie_put(root_inc, k, v, cs)
        assert root_direct == root_inc
        # Delete 3 of the 6 → sub-node should collapse to bucket again
        # (since 3 reachable < bucketSize+1=4 in the sub-node)
        to_delete = list(bindings.keys())[:3]
        remaining = {k: v for k, v in bindings.items() if k not in to_delete}
        for k in to_delete:
            root_inc = trie_remove(root_inc, k, cs)
        assert root_inc == _from_scratch(remaining, cs)

    def test_overflow_at_level_1(self):
        """Find 5 keys that share level-0 AND level-1 positions, forcing
        cascade overflow through two levels."""
        cs = ContentStore()
        # Pick a level-0 position; find many candidates at it, then
        # cluster by level-1 position until we have 5 at one (level-0,
        # level-1) cell.
        target_pos_0 = 7
        candidates: list[str] = []
        i = 0
        while len(candidates) < 200 and i < 2_000_000:
            k = f"k{i}"
            if position_at_level(hash_bytes_of(k), 0) == target_pos_0:
                candidates.append(k)
            i += 1
        # Cluster candidates by level-1 position
        clusters: dict[int, list[str]] = {}
        for k in candidates:
            p1 = position_at_level(hash_bytes_of(k), 1)
            clusters.setdefault(p1, []).append(k)
        # Find a cluster with ≥5
        chosen = next(
            (group for group in clusters.values() if len(group) >= 5), None
        )
        if chosen is None:
            pytest.skip("Could not find 5-key (level-0, level-1) collision in 2M tries")
        chosen = chosen[:5]
        bindings = {k: _vh(f"d-{k}") for k in chosen}
        root_direct = _from_scratch(bindings, cs)
        root_inc = empty_trie(cs)
        for k, v in bindings.items():
            root_inc = trie_put(root_inc, k, v, cs)
        assert root_direct == root_inc
        # Delete 2 → both level-1 and level-0 sub-nodes should collapse
        for k in chosen[:2]:
            root_inc = trie_remove(root_inc, k, cs)
        remaining = {k: v for k, v in bindings.items() if k not in chosen[:2]}
        assert root_inc == _from_scratch(remaining, cs)


# ---------------------------------------------------------------------------
# Property 4: literal-byte vector regression — §3.1 conformance fixtures
# ---------------------------------------------------------------------------


class TestLiteralVectorRegression:
    """Re-assert the two §3.1 literal-hex conformance fixtures as a fuzzer
    property. ``trie.py`` asserts these at import; we re-test here so this
    file is the single canonical harness for re-pinning across impls.
    """

    def test_empty_root_literal_cbor(self):
        encoded = ecf_encode({"map": b"\x00\x00\x00\x00", "data": []})
        assert encoded == EMPTY_NODE_CBOR

    def test_single_binding_literal_cbor(self):
        # Conformance fixture #2: relative_key = ""; value_hash = 0x00 || 0..0
        h = bytes([0x00]) + bytes(32)
        bucket = [["", h]]
        encoded = ecf_encode(
            {"map": bytes.fromhex("10000000"), "data": [bucket]}
        )
        expected = bytes.fromhex(
            "a2636d61704410000000646461746181818260" + "5821" + h.hex()
        )
        assert encoded == expected
