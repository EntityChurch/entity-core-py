"""Stat-cache for skipping FastCDC rechunks per DOMAIN-LOCAL-FILES v1.3 §10.2 L7.

The reverse-write circuit breaker (§5.3) needs the blob hash of the
on-disk file to decide "skip — disk already matches" vs "write — disk
differs." The naive impl rechunks the full file via FastCDC on every
event; in pure-Python that costs ~10 MiB/s (measured), so a 64 MiB
same-content sync event burns ~6 seconds of compute per fire.

The L7 SHOULD pins the cache shape canonically:

* **Cache entry:** ``path → (dev, ino, mtime_ns, ctime_ns, size,
  mode_bits, blob_hash)``.
* **Hit predicate (Git "racy-clean" rule from
  https://git-scm.com/docs/index-format):** all stat fields match AND
  ``mtime_ns < cache_write_time_ns``. A file modified strictly before
  the cache was written can't have a stale entry; a file modified at or
  after is "racily clean" and we MUST rehash.
* **Smudge discipline (Git's smudge-to-zero):** on cache write, if the
  stat's ``mtime_ns >= cache_write_time_ns``, we store ``size = 0``
  so a subsequent stat that reads the file's real non-zero size is a
  forced miss. This converts the within-same-second-write race into a
  value-based mismatch that survives cache rewrites.

**What the cache does NOT promise.** It is a fast-path for the
circuit breaker; the slow path (full rechunk) is still correct. False
negatives (cache miss when content unchanged) cost a rechunk; false
positives (cache hit when content changed) would corrupt — but the
racy-clean rule + smudge discipline together close the false-positive
window down to the kernel's mtime resolution, and modern filesystems
ship nanosecond mtime via ``statx`` so the window is effectively the
duration of a ``write+close``.

**Persistence.** This impl keeps the cache in-memory only, lazy-warmed
on demand. A peer restart loses the cache; the first reverse-write
event for each path pays one rechunk to repopulate. Persistent caches
(e.g., a sidecar file or a tree-bound entity) are a Phase-5 follow-up
and are implementation-defined per §10.4.

**Cross-references.** Spec text at §10.2 L7. The Git index-format
reference is the canonical source for racy-clean + smudge.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from entity_core.utils.ecf import Hash


@dataclass(frozen=True, slots=True)
class StatKey:
    """The seven-tuple a stat-cache entry pins (excluding the hash).

    A successful match against this tuple lets the cache return the
    cached ``blob_hash`` instead of rechunking the file. ``dev`` +
    ``ino`` together pin the filesystem object across path-rename
    (rename within the same FS preserves both); ``mtime_ns`` is the
    primary change signal; ``ctime_ns`` catches metadata-only changes
    (chmod, owner) without affecting the chunk hash but still worth
    revalidating; ``size`` is the cheapest fail-fast field; ``mode_bits``
    closes the "file replaced with same content but different perms"
    silent case.
    """

    dev: int
    ino: int
    mtime_ns: int
    ctime_ns: int
    size: int
    mode_bits: int

    @classmethod
    def from_stat(cls, st: os.stat_result) -> "StatKey":
        # st_mode includes file-type bits; we mask to the permission
        # bits + file-type so a regular-vs-symlink swap shows up.
        return cls(
            dev=int(st.st_dev),
            ino=int(st.st_ino),
            mtime_ns=int(st.st_mtime_ns),
            ctime_ns=int(st.st_ctime_ns),
            size=int(st.st_size),
            mode_bits=int(st.st_mode),
        )


@dataclass(frozen=True, slots=True)
class _Entry:
    key: StatKey
    blob_hash: bytes
    # Wall-clock ns at which we wrote this entry. The Git racy-clean
    # rule compares stat's mtime_ns against this; the smudge
    # discipline rewrites size=0 when mtime_ns >= cache_write_time_ns.
    written_at_ns: int


class StatCache:
    """In-memory stat-cache for the reverse-write circuit breaker.

    Thread-safe (the reverse-write listener fires on the asyncio loop
    but the actual rechunk work runs in `loop.run_in_executor`'s
    thread-pool, so concurrent puts/gets happen from worker threads).

    Persistence is out of scope per §10.4; this impl is in-memory only.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    # ------------------------------------------------------------------
    # Hit path — the hot read
    # ------------------------------------------------------------------

    def lookup(self, fs_path: str, st: os.stat_result) -> "Hash | None":
        """Return the cached blob hash if it's safe to skip a rechunk.

        Implements the Git racy-clean rule: all stat fields must match
        the cached entry AND the stat's ``mtime_ns`` must be strictly
        less than the time we wrote the cache entry. A racy-clean
        entry (mtime equal or later than cache write) MUST rehash;
        only a strictly-older mtime gives us the cache hit.
        """
        with self._lock:
            entry = self._entries.get(fs_path)
        if entry is None:
            return None
        observed = StatKey.from_stat(st)
        if observed != entry.key:
            return None
        # Racy-clean rule: an mtime at-or-after our cache write time is
        # in the race window. We MUST rehash.
        if observed.mtime_ns >= entry.written_at_ns:
            return None
        return entry.blob_hash

    # ------------------------------------------------------------------
    # Write path — the cold-miss restore
    # ------------------------------------------------------------------

    def store(self, fs_path: str, st: os.stat_result, blob_hash: "Hash") -> None:
        """Cache the blob hash for ``fs_path``.

        Implements Git's smudge-to-zero discipline: if the file's
        ``mtime_ns`` is at-or-after the cache write time (i.e., the
        write that produced these bytes happened in the same nanosecond
        window we're writing the cache), the entry is "racily clean."
        We smudge ``size = 0`` so the next stat (which will read the
        real non-zero size) is a forced miss. This converts the
        time-based race into a value-based mismatch that survives the
        cache itself.
        """
        cache_write_ns = time.time_ns()
        key = StatKey.from_stat(st)
        if key.mtime_ns >= cache_write_ns:
            # Smudge: rewrite size to zero. A subsequent stat sees the
            # real size != 0 → fast-path miss → forced rechunk.
            key = StatKey(
                dev=key.dev,
                ino=key.ino,
                mtime_ns=key.mtime_ns,
                ctime_ns=key.ctime_ns,
                size=0,
                mode_bits=key.mode_bits,
            )
        entry = _Entry(
            key=key,
            blob_hash=bytes(blob_hash),
            written_at_ns=cache_write_ns,
        )
        with self._lock:
            self._entries[fs_path] = entry

    # ------------------------------------------------------------------
    # Eviction (implementation-defined)
    # ------------------------------------------------------------------

    def invalidate(self, fs_path: str) -> None:
        """Drop the cache entry for ``fs_path`` (e.g., on delete)."""
        with self._lock:
            self._entries.pop(fs_path, None)

    def clear(self) -> None:
        """Drop all cache entries (e.g., on root-mapping reconfig)."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


__all__ = ["StatCache", "StatKey"]
