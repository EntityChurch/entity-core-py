"""FastCDC content-defined chunking per EXTENSION-CONTENT v3.5 §3.6.

Pure functions over raw bytes. No content-store side effects, no entity
construction — just the boundary-finding kernel. The blob/chunk entity
construction sits in `chunking.py` and composes this module.

**Why this is cross-impl-load-bearing.** §3.7 classifies the gear table
(§3.6.1) and the boundary algorithm (§3.6.3) as Conformance — Python
MUST produce byte-identical chunk boundaries to Go and Rust on the same
input + `target_size`. Two specific traps:

1. **64-bit overflow discipline.** Python ints are arbitrary precision;
   Go's `uint64` wraps modulo 2⁶⁴. We mask `fp` on every update with
   `& MASK64` to match wrap semantics. Without this, divergence appears
   on long inputs after `fp` would have overflowed in a uint64 lang.

2. **Gear table derivation.** §3.6.1: `gear_table[i] =
   uint64_le(SHA-256("FastCDC" || byte(i))[0:8])`. The 7-byte ASCII
   "FastCDC" literal, single byte i appended, first 8 bytes of digest
   read as little-endian. We derive at import; the table is `tuple[int,
   ...]` of length 256 for cheap immutability + lookup.

The boundary algorithm has the two-phase normalized mask discipline
verbatim from §3.6.3. The masks are derived from `target_size` per
§3.6.2 (NC=2, the recommended normalization level). The `min_size` skip
avoids scanning bytes that would produce undersized chunks; the
`max_size` cap forces a boundary when neither mask hits.

Boundary algorithm return value: a list of byte offsets where each
chunk begins, plus an implicit final offset at `len(data)`. Equivalently,
the list of `(start, end)` half-open intervals. We expose `chunk_offsets`
which returns the start offsets only; `chunks_of` slices the bytes.
"""

from __future__ import annotations

import hashlib
from math import log2
from typing import Iterator

# 64-bit truncation mask. Applied to the rolling fingerprint on every
# update so Python's unbounded ints behave like Go/Rust `uint64`. This is
# the single most likely cross-impl trap on long inputs.
MASK64 = 0xFFFFFFFF_FFFFFFFF


def _derive_gear_table() -> tuple[int, ...]:
    """Per §3.6.1: ``gear_table[i] = uint64_le(SHA-256("FastCDC" || byte(i))[0:8])``.

    The 7-byte ASCII string "FastCDC" is concatenated with a single byte
    of value ``i``; we SHA-256 the 8-byte preimage and read the first 8
    bytes of the digest as a little-endian uint64.
    """
    table: list[int] = []
    for i in range(256):
        digest = hashlib.sha256(b"FastCDC" + bytes([i])).digest()
        table.append(int.from_bytes(digest[:8], byteorder="little", signed=False))
    return tuple(table)


# Computed once at import. All conforming impls produce the same 256-entry
# table from the same SHA-256 derivation.
GEAR_TABLE: tuple[int, ...] = _derive_gear_table()


def derive_params(target_size: int) -> tuple[int, int, int, int]:
    """Return ``(min_size, max_size, mask_s, mask_l)`` per §3.6.2.

    NC (normalization level) is fixed at 2 — the recommended FastCDC
    paper value, baked into ``chunking: 1`` (FastCDC/NC2) per §2.1.

    The two masks define the two-phase boundary discipline:
    * ``mask_s`` (harder, more bits) covers the below-target phase —
      fewer matches, pushes chunk size toward target.
    * ``mask_l`` (easier, fewer bits) covers the above-target phase —
      more matches, pulls oversized chunks back to target.

    `bits = floor(log2(target_size))` per §3.6.2.
    """
    if target_size <= 0:
        raise ValueError("target_size must be positive")
    min_size = target_size // 4
    max_size = target_size * 2
    bits = int(log2(target_size))
    mask_s = (1 << (bits + 2)) - 1
    mask_l = (1 << (bits - 2)) - 1
    return (min_size, max_size, mask_s, mask_l)


def find_boundary(
    data: bytes,
    offset: int,
    min_size: int,
    target_size: int,
    max_size: int,
    mask_s: int,
    mask_l: int,
) -> int:
    """Find the next chunk boundary starting from ``offset``.

    Direct transcription of §3.6.3 ``find_boundary``. Returns the absolute
    byte offset at which the chunk ends (half-open: the next chunk starts
    at the returned value). The boundary is in ``[offset + min_size + 1,
    offset + max_size]`` inclusive.

    Two phases:

    * Phase 1 ("harder mask"): scan ``[offset + min_size, offset +
      target_size)`` testing ``fp & mask_s == 0``. Few matches → chunks
      grow toward target.
    * Phase 2 ("easier mask"): scan ``[offset + target_size, offset +
      max_size)`` testing ``fp & mask_l == 0``. More matches → cap
      oversize.
    * Fallthrough: at ``offset + max_size``, force a boundary.

    ``fp`` is masked to 64 bits on every update so Python tracks Go/Rust
    ``uint64`` wrap exactly.
    """
    fp = 0
    n = len(data)
    i = offset + min_size

    # Phase 1: harder mask (below target — push toward target_size).
    limit1 = min(offset + target_size, n)
    while i < limit1:
        fp = ((fp << 1) + GEAR_TABLE[data[i]]) & MASK64
        if (fp & mask_s) == 0:
            return i + 1
        i += 1

    # Phase 2: easier mask (above target — pull back toward target_size).
    limit2 = min(offset + max_size, n)
    while i < limit2:
        fp = ((fp << 1) + GEAR_TABLE[data[i]]) & MASK64
        if (fp & mask_l) == 0:
            return i + 1
        i += 1

    # Forced boundary at max_size (or end-of-data).
    return i


def stream_chunks(
    blocks: Iterator[bytes], target_size: int
) -> Iterator[bytes]:
    """Yield FastCDC chunks from a stream of input blocks.

    Equivalent to running :func:`chunk_offsets` on
    ``b"".join(blocks)`` then slicing — but consumes at most one
    chunk's worth of memory at a time. Boundaries are byte-identical
    to the in-memory chunker so the §3.6.5 / §3.7 cross-impl
    conformance gate still holds for streaming consumers.

    The sliding buffer holds up to ``max_size + read_block`` bytes at
    a peak — enough to always have ``max_size`` lookahead when we
    call ``find_boundary``. We slice off complete chunks as boundaries
    are found; the tail rolls into the next iteration.

    At EOF, the residual buffer is emitted as the final chunk
    (mirroring the in-memory chunker's final-piece rule: when
    ``remaining <= min_size`` the final chunk is emitted as-is).

    DOMAIN-LOCAL-FILES v1.3 §4.3 L4 promotion: streaming ingest is a
    conformant alternative SHOULD for blob sizes ≥ 64 MiB.
    """
    if target_size <= 0:
        raise ValueError("target_size must be positive")
    min_size, max_size, mask_s, mask_l = derive_params(target_size)
    buf = bytearray()

    for block in blocks:
        if not block:
            continue
        buf.extend(block)
        # Emit as many complete chunks as we can while keeping at
        # least ``max_size`` bytes of lookahead for find_boundary's
        # phase-2 cap. (We only call find_boundary when buf has more
        # than max_size bytes — guaranteed find within range.)
        while len(buf) > max_size:
            data = bytes(buf)
            end = find_boundary(
                data, 0, min_size, target_size, max_size, mask_s, mask_l
            )
            yield data[:end]
            del buf[:end]

    # Flush residual — same final-piece rule as chunk_offsets.
    while buf:
        if len(buf) <= min_size:
            yield bytes(buf)
            buf.clear()
        else:
            data = bytes(buf)
            end = find_boundary(
                data, 0, min_size, target_size, max_size, mask_s, mask_l
            )
            yield data[:end]
            del buf[:end]


def chunk_offsets(data: bytes, target_size: int) -> list[int]:
    """Return the list of chunk start offsets for ``data`` under FastCDC.

    Equivalent to running ``find_boundary`` repeatedly until ``data`` is
    consumed. The returned list always starts with ``0`` and never
    contains ``len(data)`` (the final chunk runs to end-of-data
    implicitly).

    Final-piece rule per §3.6.3: when ``remaining <= min_size``, the
    final chunk is emitted as-is — no further boundary search. This
    handles the empty-data case (returns ``[]``) and the under-min final
    fragment.
    """
    if not data:
        return []
    min_size, max_size, mask_s, mask_l = derive_params(target_size)
    n = len(data)
    starts: list[int] = []
    offset = 0
    while offset < n:
        starts.append(offset)
        remaining = n - offset
        if remaining <= min_size:
            # Final piece: too small to split further.
            offset = n
        else:
            offset = find_boundary(
                data, offset, min_size, target_size, max_size, mask_s, mask_l
            )
    return starts


def chunks_of(data: bytes, target_size: int) -> Iterator[bytes]:
    """Yield FastCDC chunk byte slices of ``data`` under ``target_size``.

    Convenience wrapper around :func:`chunk_offsets`. Each yielded
    ``bytes`` object is a half-open slice ``data[start:next_start]``.
    """
    if not data:
        return
    starts = chunk_offsets(data, target_size)
    starts_iter = iter(starts)
    prev = next(starts_iter)
    for start in starts_iter:
        yield data[prev:start]
        prev = start
    yield data[prev:]


__all__ = [
    "GEAR_TABLE",
    "MASK64",
    "derive_params",
    "find_boundary",
    "chunk_offsets",
    "chunks_of",
]
