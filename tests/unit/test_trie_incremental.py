"""Equivalence tests for incremental trie_put/trie_remove.

Per EXTENSION-TREE v3.8 §3.4.2: the result of any incremental update sequence
MUST be hash-equivalent to `build_trie` over the equivalent binding set,
including path compression behavior on inserts (split) and removes (merge).
"""

from __future__ import annotations

import hashlib
import random

import pytest

from entity_core.storage.content_store import ContentStore
from entity_core.storage.trie import (
    build_trie,
    collect_all_bindings,
    empty_trie,
    trie_put,
    trie_remove,
)


def _h(label: str) -> bytes:
    """Make a deterministic 33-byte hash from a label."""
    return bytes([0x00]) + hashlib.sha256(label.encode()).digest()


def _from_scratch(bindings: dict[str, bytes], cs: ContentStore) -> bytes:
    sorted_b = sorted(bindings.items())
    return build_trie(sorted_b, cs)


def _apply_inserts(seq: list[tuple[str, bytes]], cs: ContentStore) -> bytes:
    root = empty_trie(cs)
    for path, h in seq:
        root = trie_put(root, path, h, cs)
    return root


# ============================================================================
# Insert: structural cases
# ============================================================================


class TestInsertStructure:
    def test_single_insert_matches_build(self):
        cs = ContentStore()
        b = {"a/b/c": _h("X")}
        inc = trie_put(empty_trie(cs), "a/b/c", b["a/b/c"], cs)
        assert inc == _from_scratch(b, cs)

    def test_two_disjoint_inserts(self):
        cs = ContentStore()
        b = {"a/b": _h("1"), "x/y": _h("2")}
        inc = _apply_inserts(list(b.items()), cs)
        assert inc == _from_scratch(b, cs)

    def test_insert_extends_compressed_key(self):
        """Insert under an existing compressed-key leaf-with-binding."""
        cs = ContentStore()
        b = {"a/b": _h("1"), "a/b/c": _h("2")}
        # Insert in order so the second one descends into the first leaf.
        inc = _apply_inserts([("a/b", _h("1")), ("a/b/c", _h("2"))], cs)
        assert inc == _from_scratch(b, cs)

    def test_insert_lifts_above_existing(self):
        """New path is a strict prefix of an existing compressed key."""
        cs = ContentStore()
        b = {"a/b/c": _h("1"), "a/b": _h("2")}
        inc = _apply_inserts([("a/b/c", _h("1")), ("a/b", _h("2"))], cs)
        assert inc == _from_scratch(b, cs)

    def test_insert_splits_compressed_key(self):
        """Diverging suffixes after a shared prefix must split the key."""
        cs = ContentStore()
        b = {"a/b/c": _h("1"), "a/x/y": _h("2")}
        inc = _apply_inserts([("a/b/c", _h("1")), ("a/x/y", _h("2"))], cs)
        assert inc == _from_scratch(b, cs)

    def test_update_existing_binding(self):
        cs = ContentStore()
        b1 = {"a/b": _h("v1")}
        b2 = {"a/b": _h("v2")}
        root = trie_put(empty_trie(cs), "a/b", _h("v1"), cs)
        root = trie_put(root, "a/b", _h("v2"), cs)
        assert root == _from_scratch(b2, cs)

    def test_independent_of_insert_order(self):
        cs = ContentStore()
        b = {
            "a/b/c": _h("1"),
            "a/b/d": _h("2"),
            "a/x": _h("3"),
            "z": _h("4"),
            "a/b/c/d/e": _h("5"),
        }
        items = list(b.items())
        for _ in range(5):
            random.shuffle(items)
            cs2 = ContentStore()
            inc = _apply_inserts(items, cs2)
            assert inc == _from_scratch(b, cs2)


# ============================================================================
# Remove: structural cases
# ============================================================================


class TestRemoveStructure:
    def test_remove_makes_trie_empty(self):
        cs = ContentStore()
        root = trie_put(empty_trie(cs), "a/b", _h("1"), cs)
        root = trie_remove(root, "a/b", cs)
        assert root == empty_trie(cs)

    def test_remove_recompresses_after_delete(self):
        """Removing a binding from a node that becomes 1-entry-no-binding
        must merge the orphan's key into the parent's entry."""
        cs = ContentStore()
        # Start with two bindings sharing a/b prefix.
        b_full = {"a/b": _h("v"), "a/b/c": _h("c")}
        root = _apply_inserts(list(b_full.items()), cs)

        # Remove "a/b" — node holding binding=v drops binding, leaving one
        # child {"c": leaf}. Parent must re-compress to "a/b/c".
        root = trie_remove(root, "a/b", cs)

        b_after = {"a/b/c": _h("c")}
        assert root == _from_scratch(b_after, cs)

    def test_remove_leaf_keeps_sibling(self):
        cs = ContentStore()
        b = {"a/b": _h("1"), "a/c": _h("2")}
        root = _apply_inserts(list(b.items()), cs)
        root = trie_remove(root, "a/b", cs)
        assert root == _from_scratch({"a/c": _h("2")}, cs)

    def test_remove_nonexistent_path_is_noop(self):
        cs = ContentStore()
        b = {"a/b/c": _h("1")}
        root = _apply_inserts(list(b.items()), cs)
        before = root
        root = trie_remove(root, "a/x", cs)
        assert root == before
        # Also: descend into existing leaf but ask for a deeper missing path
        root2 = trie_remove(root, "a/b/c/d", cs)
        assert root2 == before

    def test_remove_one_then_re_add(self):
        cs = ContentStore()
        b = {"a/b": _h("1"), "x/y": _h("2")}
        root = _apply_inserts(list(b.items()), cs)
        root = trie_remove(root, "x/y", cs)
        root = trie_put(root, "x/y", _h("2"), cs)
        assert root == _from_scratch(b, cs)


# ============================================================================
# Randomized equivalence
# ============================================================================


def _random_paths(n: int, rng: random.Random) -> list[str]:
    segments = ["a", "b", "c", "x", "y", "z", "alpha", "beta"]
    paths: set[str] = set()
    while len(paths) < n:
        depth = rng.randint(1, 5)
        paths.add("/".join(rng.choice(segments) for _ in range(depth)))
    return list(paths)


class TestRandomEquivalence:
    @pytest.mark.parametrize("seed", range(8))
    def test_random_insert_sequence(self, seed):
        rng = random.Random(seed)
        cs = ContentStore()
        paths = _random_paths(20, rng)
        bindings = {p: _h(f"{seed}-{p}") for p in paths}
        items = list(bindings.items())
        rng.shuffle(items)
        inc = _apply_inserts(items, cs)
        assert inc == _from_scratch(bindings, cs)

    @pytest.mark.parametrize("seed", range(8))
    def test_random_insert_remove_sequence(self, seed):
        rng = random.Random(seed)
        cs = ContentStore()
        paths = _random_paths(15, rng)
        live: dict[str, bytes] = {}
        root = empty_trie(cs)

        # Mix of inserts and removes
        for step in range(60):
            p = rng.choice(paths)
            op = rng.choice(["put", "put", "put", "remove"])
            if op == "put":
                h = _h(f"{seed}-{step}-{p}")
                live[p] = h
                root = trie_put(root, p, h, cs)
            else:
                live.pop(p, None)
                root = trie_remove(root, p, cs)

        assert root == _from_scratch(live, cs)

        # Sanity: collect_all_bindings on the incremental root agrees
        collected = dict(collect_all_bindings(root, "", cs))
        assert collected == live
