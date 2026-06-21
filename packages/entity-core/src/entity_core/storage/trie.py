"""Content-addressed hash-keyed HAMT for tree snapshots (EXTENSION-TREE v4.0).

Stage 7 substrate fork: the trie node moves from a path-keyed
compressed trie (v3.x) to a hash-keyed bounded-fanout IPLD HashMap with
CHAMP-equivalent canonical-form invariant. See ``EXTENSION-TREE.md`` v4.0
§3.1 / §3.3 / §3.4.2 / §4.3 for the normative spec, and
``proposals/implemented/PROPOSAL-TREE-NODE-SHAPE-BOUNDED-FANOUT.md`` v4.3 for
the rationale.

Node shape (``system/tree/snapshot/node``)::

    {map: bytes(4), data: [Entry, ...]}

Where ``map`` is a 32-bit bitmap (LSB-indexed, big-endian serialized) of
occupied positions, ``data`` is a dense popcount-compressed array of entries,
and each ``Entry`` is discriminated by its CBOR major type at decode:

- CBOR array  → ``Bucket`` ``[[key, value_hash], ...]``, ``len ≤ bucketSize=3``,
  sorted lex by key.
- CBOR bytes  → ``Link`` 33-byte ``system/hash`` of a sub-node entity.

Routing uses 5-bit slices of
``SHA-256(UTF-8-bytes(canonical_normalize(relative_key)))``, MSB-first per
byte. The first 5 bits select the level-0 position; bits 5-9 (spanning bytes
0 and 1) select level-1; etc.

Parameters are pinned in spec (MUST NOT be exposed per-tree)::

    bitWidth   = 5   →  K = 32
    bucketSize = 3
    hashFn     = SHA-256

CHAMP-equivalent canonical-form invariant (MUST, §3.1): no non-root node may
contain (directly or through links) fewer than ``bucketSize + 1 = 4``
reachable entries. On deletion, violations are collapsed and inlined into the
parent bucket. Without this, two peers building "the same" tree by different
histories produce different root hashes — the v3.x silent-divergence bug
class is eliminated by enforcement here.

Bucket-sort invariant (MUST, §3.1): tuples within any bucket are sorted lex
by key on both insertion and deletion.

Wire format is ours (ECF + ``system/hash``); IPLD HashMap is adopted as
algorithm + parameters reference only — no dag-cbor / multihash / spec-
tracking commitment. Two literal-hex conformance fixtures are pinned below
(``EMPTY_NODE_CBOR``, single-binding) and asserted at module import time so
divergence surfaces at construction, not at fuzzer-touch time.
"""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.utils.ecf import Hash, ecf_encode

# Entity type for trie nodes (unchanged across the v3.x → v4.0 fork — the
# entity-type name is stable; only the data-field encoding changed).
TRIE_NODE_TYPE = "system/tree/snapshot/node"

# Parameters (pinned in spec §3.1; not exposed on wire, not per-tree config).
BIT_WIDTH = 5
K = 1 << BIT_WIDTH  # 32
BUCKET_SIZE = 3
BITMAP_BYTES = K // 8  # 4
HASH_BITS = 256  # SHA-256
MAX_LEVELS = HASH_BITS // BIT_WIDTH  # 51 levels of bit-slice routing


# ---------------------------------------------------------------------------
# Public path utility
# ---------------------------------------------------------------------------


def join_path(prefix: str, suffix: str) -> str:
    """Join two path segments with ``/`` (callers use this for diff output).

    Defined per ``EXTENSION-TREE.md`` v4.0 §4.3 ``join_path``: empty side
    passes through unchanged; otherwise ``prefix + "/" + suffix``.
    """
    if not prefix:
        return suffix
    if not suffix:
        return prefix
    return f"{prefix}/{suffix}"


# ---------------------------------------------------------------------------
# Canonical normalization for routing
# ---------------------------------------------------------------------------


def canonical_normalize(relative_key: str) -> str:
    """Canonicalize a relative_key prior to hashing for routing (§3.1, §5.4).

    The SHA-256 input for trie routing is
    ``UTF-8-bytes(canonical_normalize(relative_key))``. Two impls using
    different normalization would produce different positions and silently
    divergent root hashes — pin this to NFC per core protocol §5.4.
    """
    return unicodedata.normalize("NFC", relative_key)


def hash_bytes_of(relative_key: str) -> bytes:
    """Return ``SHA-256(UTF-8(canonical_normalize(relative_key)))``.

    The 32-byte routing hash whose 5-bit slices drive HAMT descent (§3.1,
    §3.4.2).
    """
    return hashlib.sha256(canonical_normalize(relative_key).encode("utf-8")).digest()


def position_at_level(routing_hash: bytes, level: int) -> int:
    """Extract the 5-bit position at ``level`` from a 32-byte routing hash.

    Reads bits MSB-first within each byte: level 0 = bits 0-4 of byte 0;
    level 1 = bits 5-9 spanning bytes 0-1; etc. The spec's worked example
    (``0xe3`` → position 28 at level 0) is asserted at import below.
    """
    if level < 0 or level >= MAX_LEVELS:
        raise ValueError(f"trie level {level} out of range (0..{MAX_LEVELS - 1})")
    bit_start = level * BIT_WIDTH
    byte_idx = bit_start // 8
    bit_offset = bit_start % 8  # 0..7
    if bit_offset + BIT_WIDTH <= 8:
        # Wholly inside one byte
        return (routing_hash[byte_idx] >> (8 - bit_offset - BIT_WIDTH)) & 0x1F
    # Spans two bytes (high bits in byte i, low bits in byte i+1)
    high_bits = 8 - bit_offset
    low_bits = BIT_WIDTH - high_bits
    high = routing_hash[byte_idx] & ((1 << high_bits) - 1)
    low = routing_hash[byte_idx + 1] >> (8 - low_bits)
    return (high << low_bits) | low


# ---------------------------------------------------------------------------
# Bitmap helpers
# ---------------------------------------------------------------------------


def _bitmap_from_bytes(b: bytes) -> int:
    """Decode the 4-byte big-endian bitmap to an integer."""
    return int.from_bytes(b, "big")


def _bitmap_to_bytes(bitmap: int) -> bytes:
    """Encode the bitmap integer as 4 big-endian bytes."""
    return bitmap.to_bytes(BITMAP_BYTES, "big")


def _popcount(x: int) -> int:
    return x.bit_count()


def _data_index(bitmap: int, position: int) -> int:
    """popcount(bitmap & ((1 << position) - 1)) — dense index for the entry."""
    return _popcount(bitmap & ((1 << position) - 1))


def _set_bits(bitmap: int) -> Iterable[int]:
    """Yield positions of set bits in ascending order."""
    while bitmap:
        lsb = bitmap & -bitmap  # isolate lowest set bit
        yield lsb.bit_length() - 1
        bitmap ^= lsb


# ---------------------------------------------------------------------------
# Node model (in-memory representation)
# ---------------------------------------------------------------------------


@dataclass
class _Node:
    """In-memory mirror of a ``system/tree/snapshot/node`` data payload.

    ``data`` carries entries in dense, sorted-by-position order; each entry
    is either a ``list[tuple[str, bytes]]`` (Bucket — tuples lex-sorted by
    key) or a ``bytes`` (Link — 33-byte sub-node hash). Use the
    ``_load_node`` / ``_store_node`` helpers to round-trip via the content
    store; these enforce the canonical-form invariant on write.
    """

    bitmap: int
    data: list[Any]  # Each element: list[list[key, value_hash]] (bucket) | bytes (link)


def _empty_node() -> _Node:
    return _Node(bitmap=0, data=[])


def _is_bucket(entry: Any) -> bool:
    return isinstance(entry, list)


def _is_link(entry: Any) -> bool:
    return isinstance(entry, (bytes, bytearray))


def _node_to_entity_data(node: _Node) -> dict[str, Any]:
    """Convert a ``_Node`` to its on-wire ``{map, data}`` dict payload.

    Bucket tuples are emitted as plain Python lists so cbor2 canonical
    encoding produces the spec's ``[[key, value_hash], ...]`` shape.
    """
    return {"map": _bitmap_to_bytes(node.bitmap), "data": node.data}


def _load_node(node_hash: bytes, cs: ContentStore) -> _Node:
    """Load a node from the content store, asserting type and shape."""
    ent = cs.get(node_hash)
    if ent is None or ent.type != TRIE_NODE_TYPE:
        # Caller may treat this as empty; the trie's root contract guarantees
        # every reachable hash IS a trie node entity.
        return _empty_node()
    bitmap_bytes = ent.data.get("map", b"\x00" * BITMAP_BYTES)
    data_list = ent.data.get("data", [])
    # Normalize the in-memory shape: buckets become lists of [key, hash] pairs
    # (some CBOR decoders may surface them as tuples — coerce to lists so
    # round-trip equality holds).
    normalized: list[Any] = []
    for entry in data_list:
        if isinstance(entry, (bytes, bytearray)):
            normalized.append(bytes(entry))
        else:
            # Bucket: list of [key, value_hash]
            bucket = [[str(pair[0]), bytes(pair[1])] for pair in entry]
            normalized.append(bucket)
    return _Node(bitmap=_bitmap_from_bytes(bytes(bitmap_bytes)), data=normalized)


def _store_node(node: _Node, cs: ContentStore) -> bytes:
    """Write a node entity and return its content hash."""
    entity = Entity(type=TRIE_NODE_TYPE, data=_node_to_entity_data(node))
    return cs.put(entity)


# ---------------------------------------------------------------------------
# Empty-root + literal-hex conformance fixtures
# ---------------------------------------------------------------------------


# Conformance fixture #1 (§3.1): the canonical CBOR encoding of the empty-root
# node's data field. Any deviation breaks cross-peer trie root comparison.
EMPTY_NODE_CBOR: bytes = bytes.fromhex("a2636d61704400000000646461746180")


def _assert_empty_node_cbor() -> None:
    encoded = ecf_encode({"map": b"\x00\x00\x00\x00", "data": []})
    if encoded != EMPTY_NODE_CBOR:
        raise RuntimeError(
            "Empty-root node CBOR encoding does not match §3.1 conformance "
            f"fixture #1: got {encoded.hex()!r}, expected "
            f"{EMPTY_NODE_CBOR.hex()!r}"
        )


def _assert_single_binding_cbor() -> None:
    # SHA-256("") = e3b0... → byte 0 = 0xe3 = 0b11100011; bits 0-4 MSB-first
    # = 0b11100 = position 28; bitmap int = 1 << 28 = 0x10000000.
    routing = hash_bytes_of("")
    if position_at_level(routing, 0) != 28:
        raise RuntimeError(
            "position_at_level routing mismatch: empty-string SHA-256 byte 0 "
            f"({routing[0]:#04x}) → level-0 position "
            f"{position_at_level(routing, 0)}, expected 28 per §3.1."
        )
    h = bytes([0x00]) + bytes(32)  # placeholder value_hash
    bucket = [["", h]]
    data = {"map": bytes.fromhex("10000000"), "data": [bucket]}
    encoded = ecf_encode(data)
    # Expected: a2 63 6d6170 44 10000000 64 64617461 81 81 82 60 58 21 <H>
    expected = bytes.fromhex(
        "a2636d61704410000000646461746181818260" + "5821" + h.hex()
    )
    if encoded != expected:
        raise RuntimeError(
            "Single-binding node CBOR encoding does not match §3.1 "
            f"conformance fixture #2: got {encoded.hex()!r}, expected "
            f"{expected.hex()!r}"
        )


_assert_empty_node_cbor()
_assert_single_binding_cbor()


# ---------------------------------------------------------------------------
# Public API: build_trie / empty_trie
# ---------------------------------------------------------------------------


def empty_trie(content_store: ContentStore) -> Hash:
    """Return the canonical empty-root content hash (§3.1 fixture #1)."""
    return _store_node(_empty_node(), content_store)


def build_trie(
    bindings: list[tuple[str, bytes]],
    content_store: ContentStore,
) -> Hash:
    """Build the v4.0 IPLD HashMap from a sorted binding set.

    Equivalent to ``empty_trie`` + ``trie_put`` for each binding (§3.3); the
    CHAMP-canonical-form invariant guarantees same-input → same-bytes
    regardless of insertion order.

    Args:
        bindings: Sorted ``(relative_key, value_hash)`` pairs. Sort is for
            determinism of intermediate content-store writes only — the final
            root hash is order-independent.
        content_store: Sink for trie node entities.

    Returns:
        Content hash of the root trie node.
    """
    root = empty_trie(content_store)
    for relative_key, value_hash in bindings:
        root = trie_put(root, relative_key, value_hash, content_store)
    return root


# ---------------------------------------------------------------------------
# Public API: trie_put — IPLD HashMap descent with bucket overflow → split
# ---------------------------------------------------------------------------


def trie_put(
    root_hash: Hash,
    relative_key: str,
    value_hash: Hash,
    content_store: ContentStore,
) -> Hash:
    """Insert or replace ``relative_key → value_hash`` in the trie (§3.4.2).

    Walks 5-bit slices of ``SHA-256(canonical_normalize(relative_key))``
    descending into sub-nodes on bucket-overflow per §3.4.2. The result is
    hash-equivalent to ``build_trie`` over the updated binding set.
    """
    routing = hash_bytes_of(relative_key)
    root_node = _load_node(root_hash, content_store)
    new_root = _put_at(root_node, routing, 0, relative_key, value_hash, content_store)
    return _store_node(new_root, content_store)


def _put_at(
    node: _Node,
    routing: bytes,
    level: int,
    key: str,
    value_hash: bytes,
    cs: ContentStore,
) -> _Node:
    p = position_at_level(routing, level)
    bit = 1 << p
    new_bitmap = node.bitmap
    new_data = list(node.data)

    if not (node.bitmap & bit):
        # Position empty: install a single-tuple bucket at the popcount index.
        idx = _data_index(node.bitmap, p)
        new_bitmap |= bit
        new_data.insert(idx, [[key, value_hash]])
        return _Node(bitmap=new_bitmap, data=new_data)

    idx = _data_index(node.bitmap, p)
    entry = node.data[idx]

    if _is_bucket(entry):
        bucket = entry
        # If key already present → replace value_hash, keep sort order.
        for i, (k, _) in enumerate(bucket):
            if k == key:
                if bucket[i][1] == value_hash:
                    return node  # no-op; preserve existing identity
                new_bucket = [list(t) for t in bucket]
                new_bucket[i][1] = value_hash
                new_data[idx] = new_bucket
                return _Node(bitmap=new_bitmap, data=new_data)
        # New key; bucket has room → insert and keep lex-sorted by key.
        if len(bucket) < BUCKET_SIZE:
            new_bucket = [list(t) for t in bucket] + [[key, value_hash]]
            new_bucket.sort(key=lambda t: t[0])
            new_data[idx] = new_bucket
            return _Node(bitmap=new_bitmap, data=new_data)
        # Overflow: bucket is full and the key is new. Convert this entry to
        # a sub-node by redistributing all bucketSize + 1 tuples at the next
        # level. Tuples that collide at the next level recurse further.
        all_tuples = [(k, v) for k, v in bucket] + [(key, value_hash)]
        sub_node = _build_sub_node(all_tuples, level + 1, cs)
        sub_hash = _store_node(sub_node, cs)
        new_data[idx] = sub_hash
        return _Node(bitmap=new_bitmap, data=new_data)

    # Link: descend into the sub-node and rewrite on ascent.
    sub_node = _load_node(entry, cs)
    new_sub = _put_at(sub_node, routing, level + 1, key, value_hash, cs)
    if new_sub.bitmap == sub_node.bitmap and new_sub.data == sub_node.data:
        return node  # no-op
    new_sub_hash = _store_node(new_sub, cs)
    new_data[idx] = new_sub_hash
    return _Node(bitmap=new_bitmap, data=new_data)


def _build_sub_node(
    tuples: list[tuple[str, bytes]],
    level: int,
    cs: ContentStore,
) -> _Node:
    """Distribute ``tuples`` into a fresh node at ``level`` per §3.4.2.

    Used when a bucket overflows on insert: all ``bucketSize + 1`` tuples
    are re-routed by their next-level position. Tuples that share a position
    re-overflow at this level → recursive sub-node construction.
    """
    # Group tuples by next-level position
    groups: dict[int, list[tuple[str, bytes]]] = {}
    for k, v in tuples:
        routing = hash_bytes_of(k)
        p = position_at_level(routing, level)
        groups.setdefault(p, []).append((k, v))

    bitmap = 0
    data: list[Any] = []
    for p in sorted(groups.keys()):
        bitmap |= 1 << p
        group = groups[p]
        if len(group) <= BUCKET_SIZE:
            bucket = [[k, v] for k, v in group]
            bucket.sort(key=lambda t: t[0])
            data.append(bucket)
        else:
            # Re-overflow at this level: recurse into a deeper sub-node.
            sub = _build_sub_node(group, level + 1, cs)
            sub_hash = _store_node(sub, cs)
            data.append(sub_hash)
    return _Node(bitmap=bitmap, data=data)


# ---------------------------------------------------------------------------
# Public API: trie_remove — descent + CHAMP collapse-and-inline on ascent
# ---------------------------------------------------------------------------


def trie_remove(
    root_hash: Hash,
    relative_key: str,
    content_store: ContentStore,
) -> Hash:
    """Remove ``relative_key`` from the trie (§3.4.2).

    Walks the SHA-256 bit path; on ascent, enforces the CHAMP-equivalent
    canonical-form invariant: any non-root node that ends up with fewer than
    ``bucketSize + 1 = 4`` reachable entries is collapsed and its tuples
    inlined into the parent's bucket at the link position (lex-sorted). The
    root is exempt from the lower bound.

    No-op if ``relative_key`` is absent. Result is hash-equivalent to
    ``build_trie`` over the updated binding set — verified by the cross-impl
    byte-identical-output fuzzer (§12.1).
    """
    routing = hash_bytes_of(relative_key)
    root_node = _load_node(root_hash, content_store)
    new_root, _changed = _remove_at(
        root_node, routing, 0, relative_key, content_store, is_root=True
    )
    return _store_node(new_root, content_store)


def _remove_at(
    node: _Node,
    routing: bytes,
    level: int,
    key: str,
    cs: ContentStore,
    *,
    is_root: bool,
) -> tuple[_Node, bool]:
    """Remove ``key`` from ``node``. Returns ``(new_node, changed)``.

    The parent invokes ``_maybe_collapse`` on this entry's link slot after
    seeing ``changed = True``; we do not collapse ``node`` itself here. The
    root exemption (``is_root``) only matters for the parent's collapse
    decision and is not used in this function's branches directly.
    """
    p = position_at_level(routing, level)
    bit = 1 << p
    if not (node.bitmap & bit):
        return node, False  # key not present

    idx = _data_index(node.bitmap, p)
    entry = node.data[idx]

    if _is_bucket(entry):
        bucket = entry
        for i, (k, _) in enumerate(bucket):
            if k == key:
                new_bucket = [list(t) for t in bucket[:i] + bucket[i + 1 :]]
                new_data = list(node.data)
                if not new_bucket:
                    # Position now unoccupied
                    del new_data[idx]
                    new_bitmap = node.bitmap & ~bit
                    return _Node(bitmap=new_bitmap, data=new_data), True
                new_data[idx] = new_bucket
                return _Node(bitmap=node.bitmap, data=new_data), True
        return node, False  # key not in bucket

    # Link: recurse, then enforce canonical form on ascent.
    sub_node = _load_node(entry, cs)
    new_sub, changed = _remove_at(
        sub_node, routing, level + 1, key, cs, is_root=False
    )
    if not changed:
        return node, False

    return _replace_link_with_canonical(node, idx, p, new_sub, cs), True


def _replace_link_with_canonical(
    parent: _Node,
    idx: int,
    position: int,
    new_sub: _Node,
    cs: ContentStore,
) -> _Node:
    """Replace ``parent.data[idx]`` (a link) with the result of recursion.

    If ``new_sub`` now has fewer than ``bucketSize + 1 = 4`` reachable
    entries, collapse it: inline all reachable tuples into a single bucket
    at the position, lex-sorted by key. Otherwise re-link by the sub-node's
    new content hash.
    """
    reachable = _collect_reachable_tuples(new_sub, cs)
    new_data = list(parent.data)

    if len(reachable) < BUCKET_SIZE + 1:
        # CHAMP collapse: inline tuples into a bucket at this position.
        bucket = [[k, v] for k, v in reachable]
        bucket.sort(key=lambda t: t[0])
        if not bucket:
            # All entries gone — clear the bit.
            del new_data[idx]
            return _Node(bitmap=parent.bitmap & ~(1 << position), data=new_data)
        new_data[idx] = bucket
        return _Node(bitmap=parent.bitmap, data=new_data)

    # No collapse: persist the sub-node and re-link.
    new_hash = _store_node(new_sub, cs)
    new_data[idx] = new_hash
    return _Node(bitmap=parent.bitmap, data=new_data)


def _collect_reachable_tuples(
    node: _Node, cs: ContentStore
) -> list[tuple[str, bytes]]:
    """Walk a sub-node and return all reachable ``(key, value_hash)`` tuples.

    Used by the CHAMP collapse path on delete (§3.4.2). Order is unspecified
    here — the caller sorts before installing as a bucket.
    """
    result: list[tuple[str, bytes]] = []
    for p in _set_bits(node.bitmap):
        idx = _data_index(node.bitmap, p)
        entry = node.data[idx]
        if _is_bucket(entry):
            for k, v in entry:
                result.append((k, v))
        else:
            sub = _load_node(entry, cs)
            result.extend(_collect_reachable_tuples(sub, cs))
    return result


# ---------------------------------------------------------------------------
# Walkers used by handlers
# ---------------------------------------------------------------------------


def collect_all_bindings(
    node_hash: Hash,
    path_prefix: str,
    content_store: ContentStore,
) -> list[tuple[str, bytes]]:
    """Flatten the trie at ``node_hash`` to a list of ``(key, value_hash)``.

    Per §5.4: under hash-keyed routing keys live directly in leaf-level
    buckets — there is no per-node path-prefix to accumulate. The ``key``
    field of each tuple is the full relative_key (the value originally
    inserted via ``trie_put``). ``path_prefix`` is prepended to each key
    via ``join_path`` — this preserves the v3.x caller contract used by
    revision and tree handlers for full-path materialization.

    Output order is hash-bit-traversal order; callers needing lex sort MUST
    sort at output (§4.3, §5.4).
    """
    node = _load_node(node_hash, content_store)
    result: list[tuple[str, bytes]] = []
    for k, v in _collect_reachable_tuples(node, content_store):
        result.append((join_path(path_prefix, k), v))
    return result


def collect_trie_hashes(
    node_hash: Hash,
    content_store: ContentStore,
) -> set[bytes]:
    """Collect all hashes reachable through the trie (nodes + bound entities).

    Used by fetch-entities to validate requested hashes against the trie
    and by revision ``fetch-diff`` as the skip-set when threading a
    closure bundle. Returns the trie-node hashes (root + all sub-node
    links) plus the value_hashes from every bucket tuple.
    """
    result: set[bytes] = set()
    _collect_hashes_recursive(node_hash, content_store, result)
    return result


def _collect_hashes_recursive(
    node_hash: bytes,
    content_store: ContentStore,
    result: set[bytes],
) -> None:
    if node_hash in result:
        return
    result.add(node_hash)
    ent = content_store.get(node_hash)
    if ent is None or ent.type != TRIE_NODE_TYPE:
        return
    bitmap = _bitmap_from_bytes(bytes(ent.data.get("map", b"\x00" * BITMAP_BYTES)))
    data_list = ent.data.get("data", [])
    for i, _p in enumerate(_set_bits(bitmap)):
        entry = data_list[i]
        if isinstance(entry, (bytes, bytearray)):
            _collect_hashes_recursive(bytes(entry), content_store, result)
        else:
            # Bucket — emit value_hashes
            for pair in entry:
                result.add(bytes(pair[1]))


def load_trie_node(
    node_hash: Hash,
    content_store: ContentStore,
) -> dict | None:
    """Return the on-wire ``{map, data}`` data dict for a trie node.

    Returns ``None`` if the hash doesn't resolve to a trie node entity.
    Callers that want the structured ``_Node`` should use ``_load_node``
    internally; this is the public boundary for diagnostic / debugging
    consumers.
    """
    ent = content_store.get(node_hash)
    if ent is None or ent.type != TRIE_NODE_TYPE:
        return None
    return ent.data


def collect_trie_entities_except(
    node_hash: Hash,
    skip: set[bytes],
    content_store: ContentStore,
    collected: dict[bytes, dict],
) -> None:
    """Collect trie-node + leaf-binding entities reachable from ``node_hash``,
    skipping any hash in ``skip``.

    Closure-bundle primitive behind cross-peer transport
    (``EXTENSION-REVISION`` §4.4.19 ``fetch-diff``, ``EXTENSION-TREE`` §6).
    Pair with ``collect_trie_hashes(base_root)`` as ``skip`` — content-
    addressed equality means a subtree whose root hash the caller already
    has is shared verbatim and need not be transmitted; same for any leaf
    data entity already in the caller's base closure.

    Mirrors ``core-go`` ``tree.CollectTrieEntitiesExcept`` for wire
    convergence.
    """
    if node_hash in skip or node_hash in collected:
        return
    ent = content_store.get(node_hash)
    if ent is None:
        return
    collected[node_hash] = ent.to_dict()
    if ent.type != TRIE_NODE_TYPE:
        return
    bitmap = _bitmap_from_bytes(bytes(ent.data.get("map", b"\x00" * BITMAP_BYTES)))
    data_list = ent.data.get("data", [])
    for i, _p in enumerate(_set_bits(bitmap)):
        entry = data_list[i]
        if isinstance(entry, (bytes, bytearray)):
            collect_trie_entities_except(
                bytes(entry), skip, content_store, collected
            )
        else:
            # Bucket — include leaf data entities at value_hashes (if local).
            for pair in entry:
                value_hash = bytes(pair[1])
                if value_hash in skip or value_hash in collected:
                    continue
                bind_ent = content_store.get(value_hash)
                if bind_ent is not None:
                    collected[value_hash] = bind_ent.to_dict()


# ---------------------------------------------------------------------------
# Diff (§4.3) — parallel walk with hash-equality early-exit
# ---------------------------------------------------------------------------


@dataclass
class _Change:
    kind: str  # "added" | "removed" | "changed"
    key: str
    a_hash: bytes | None = None
    b_hash: bytes | None = None


def trie_diff(
    base_root_hash: Hash,
    target_root_hash: Hash,
    content_store: ContentStore,
) -> tuple[
    list[tuple[str, bytes]],  # added: (key, target_hash)
    list[tuple[str, bytes]],  # removed: (key, base_hash)
    list[tuple[str, bytes, bytes]],  # changed: (key, base_hash, target_hash)
]:
    """Diff two trie roots (§4.3). Returns ``(added, removed, changed)``
    each lex-sorted by key.

    Hash-equality early-exit at every node skips entire unchanged subtrees;
    the compression-mismatch machinery from v3.x (``LongestCommonPrefix`` /
    ``DecomposeEntries`` / ``ResolveAtDivergence``) is gone — IPLD HashMap
    nodes are fixed-position by bitmap, so there is no compressed-key
    divergence to resolve.
    """
    if base_root_hash == target_root_hash:
        return [], [], []
    base = _load_node(base_root_hash, content_store)
    target = _load_node(target_root_hash, content_store)
    changes = _diff_nodes(base, target, content_store)
    added: list[tuple[str, bytes]] = []
    removed: list[tuple[str, bytes]] = []
    changed: list[tuple[str, bytes, bytes]] = []
    for ch in changes:
        if ch.kind == "added":
            added.append((ch.key, ch.b_hash))
        elif ch.kind == "removed":
            removed.append((ch.key, ch.a_hash))
        else:
            changed.append((ch.key, ch.a_hash, ch.b_hash))
    added.sort(key=lambda t: t[0])
    removed.sort(key=lambda t: t[0])
    changed.sort(key=lambda t: t[0])
    return added, removed, changed


def _diff_nodes(a: _Node, b: _Node, cs: ContentStore) -> list[_Change]:
    if a.bitmap == b.bitmap and a.data == b.data:
        return []
    out: list[_Change] = []
    combined = a.bitmap | b.bitmap
    for p in _set_bits(combined):
        bit = 1 << p
        in_a = bool(a.bitmap & bit)
        in_b = bool(b.bitmap & bit)
        entry_a = a.data[_data_index(a.bitmap, p)] if in_a else None
        entry_b = b.data[_data_index(b.bitmap, p)] if in_b else None
        if not in_a:
            out.extend(_walk_entry_collect("added", entry_b, cs))
            continue
        if not in_b:
            out.extend(_walk_entry_collect("removed", entry_a, cs))
            continue
        if _is_bucket(entry_a) and _is_bucket(entry_b):
            out.extend(_diff_buckets(entry_a, entry_b))
        elif _is_link(entry_a) and _is_link(entry_b):
            if bytes(entry_a) == bytes(entry_b):
                continue
            sub_a = _load_node(bytes(entry_a), cs)
            sub_b = _load_node(bytes(entry_b), cs)
            out.extend(_diff_nodes(sub_a, sub_b, cs))
        elif _is_bucket(entry_a) and _is_link(entry_b):
            bindings_b = _walk_entry_collect_bindings(entry_b, cs)
            out.extend(_diff_bucket_vs_bindings(entry_a, bindings_b))
        else:  # link, bucket
            bindings_a = _walk_entry_collect_bindings(entry_a, cs)
            out.extend(_diff_bindings_vs_bucket(bindings_a, entry_b))
    return out


def _walk_entry_collect(kind: str, entry: Any, cs: ContentStore) -> list[_Change]:
    out: list[_Change] = []
    if _is_bucket(entry):
        for k, v in entry:
            if kind == "added":
                out.append(_Change(kind="added", key=k, b_hash=bytes(v)))
            else:
                out.append(_Change(kind="removed", key=k, a_hash=bytes(v)))
        return out
    # Link: walk the sub-node
    sub = _load_node(bytes(entry), cs)
    for p in _set_bits(sub.bitmap):
        sub_entry = sub.data[_data_index(sub.bitmap, p)]
        out.extend(_walk_entry_collect(kind, sub_entry, cs))
    return out


def _walk_entry_collect_bindings(
    entry: Any, cs: ContentStore
) -> list[tuple[str, bytes]]:
    if _is_bucket(entry):
        return [(k, bytes(v)) for k, v in entry]
    sub = _load_node(bytes(entry), cs)
    return _collect_reachable_tuples(sub, cs)


def _diff_buckets(a: list, b: list) -> list[_Change]:
    out: list[_Change] = []
    map_a = {k: bytes(v) for k, v in a}
    map_b = {k: bytes(v) for k, v in b}
    for k in set(map_a.keys()) | set(map_b.keys()):
        if k not in map_b:
            out.append(_Change(kind="removed", key=k, a_hash=map_a[k]))
        elif k not in map_a:
            out.append(_Change(kind="added", key=k, b_hash=map_b[k]))
        elif map_a[k] != map_b[k]:
            out.append(
                _Change(kind="changed", key=k, a_hash=map_a[k], b_hash=map_b[k])
            )
    return out


def _diff_bucket_vs_bindings(
    bucket_a: list, bindings_b: list[tuple[str, bytes]]
) -> list[_Change]:
    return _diff_buckets(bucket_a, [[k, v] for k, v in bindings_b])


def _diff_bindings_vs_bucket(
    bindings_a: list[tuple[str, bytes]], bucket_b: list
) -> list[_Change]:
    return _diff_buckets([[k, v] for k, v in bindings_a], bucket_b)
