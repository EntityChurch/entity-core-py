"""Canonical deletion-marker constants.

Per ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §4.9 — the `system/deletion-marker`
entity is a zero-field canonical entity used by EXTENSION-REVISION (and
any future extension that needs an explicit deletion signal in a
content-addressed structure) to record intentional path deletion in a
version's trie.

Live-tree invariant: deletion markers MUST NOT appear in the live
location index. Version-transcription operations (merge, fast-forward,
checkout, push recipient-side apply, cherry-pick, revert) translate
marker bindings to live-tree unbinds at apply time. Live deletion is
expressed by `tree:put(path, null)` (V7 core §6.3), unchanged.

Format-relativity (V7 v7.70 §4.9 ruling): the marker is **format-relative
to the trie's own home format**, NOT a hardcoded SHA-256 constant. Each
trie binds and recognizes the marker authored under that trie's format.
`ecf-sha256:689ae4…` is the SHA-256-space instance — the standard-
compliance floor and the ECF conformance gate — but a peer whose home
format is SHA-384 binds the SHA-384-space instance into its own substrate
(§1.2 erratum: persistent state is uniformly the home format).

Because a `content_hash` is self-describing (its leading varint is the
format code), recognition is pure hash arithmetic: `is_deletion_marker`
computes the zero-field marker under the hash's own format and compares.
This is correct for a home-format trie AND a foreign-format trie alike,
with no entity load — the v7.70 "entity-layer fallback" for foreign-format
tries is unnecessary here precisely because the marker is a fixed
zero-field entity whose hash under any format is deterministic.
"""

from __future__ import annotations

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    UnsupportedContentHashFormatError,
    decode_content_hash_format,
    get_default_hash_algorithm,
)


def deletion_marker_entity(algorithm: int | None = None) -> Entity:
    """The canonical `system/deletion-marker` entity (zero-field), authored
    under `algorithm` — the peer's home/default format when ``None``.

    The entity's `{type, data}` is format-independent; only its
    `content_hash` is format-relative.
    """
    return Entity(
        type="system/deletion-marker",
        data={},
        hash_algorithm=(
            algorithm if algorithm is not None else get_default_hash_algorithm()
        ),
    )


# Per-format marker-hash cache. The marker is a fixed zero-field entity, so
# its hash under a given format is computed once and reused.
_MARKER_HASH_CACHE: dict[int, bytes] = {}


def deletion_marker_hash(algorithm: int | None = None) -> bytes:
    """`content_hash` of the deletion marker under `algorithm` — the peer's
    home/default format when ``None``.

    This is the value a peer binds into its own trie to express deletion.
    For a SHA-256 home peer this is :data:`CANONICAL_DELETION_MARKER_HASH`
    (``ecf-sha256:689ae4…``); for a SHA-384 home peer it is the SHA-384-space
    instance. Resolving ``None`` at call time (not import time) lets a peer
    booted under `--hash-type X` pick up its home format after startup.
    """
    algo = algorithm if algorithm is not None else get_default_hash_algorithm()
    h = _MARKER_HASH_CACHE.get(algo)
    if h is None:
        h = deletion_marker_entity(algo).compute_hash()
        _MARKER_HASH_CACHE[algo] = h
    return h


# Canonical deletion-marker INSTANCE in the SHA-256 address space — the
# standard-compliance reference and the ECF conformance gate. A peer's actual
# binding value is :func:`deletion_marker_hash` under its home format; this
# constant is the SHA-256 instance specifically.
DELETION_MARKER_ENTITY: Entity = deletion_marker_entity(ALG_ECFV1_SHA256)

# Canonical hash of the SHA-256-space deletion-marker entity. Format:
# ECFv1-SHA256 (33 bytes: 0x00 format code + 32-byte SHA256 digest).
#
# Per ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §4.9:
#   CANONICAL_DELETION_MARKER_HASH = ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6
CANONICAL_DELETION_MARKER_HASH: bytes = bytes.fromhex(
    "00689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6"
)

# Conformance gate: verify the SHA-256-space canonical hash on import. Any
# deviation signals an ECF-encoding bug (e.g., emitting `0x40` empty byte
# string or `0xf6` null instead of the `0xa0` empty map for zero-field types)
# that MUST be fixed before this implementation can claim conformance.
_computed = deletion_marker_hash(ALG_ECFV1_SHA256)
if _computed != CANONICAL_DELETION_MARKER_HASH:
    raise RuntimeError(
        "ECF conformance failure: computed deletion-marker hash "
        f"{_computed.hex()} does not match the canonical value "
        f"{CANONICAL_DELETION_MARKER_HASH.hex()} (ENTITY-NATIVE-TYPE-"
        "SYSTEM v4.2.0 §4.9). This indicates an ECF encoding bug — "
        "zero-field entities MUST encode `data` as the CBOR empty map "
        "(0xa0), NOT empty bytes (0x40) and NOT null (0xf6)."
    )


def is_deletion_marker(h: bytes | None) -> bool:
    """Return True iff `h` is the deletion-marker hash **under its own format**.

    Format-relative per V7 v7.70 §4.9: the marker is recognized in whatever
    format the `content_hash` self-describes (leading varint = format code),
    so this is correct for a home-format trie and a foreign-format trie alike,
    with no entity load. A hash in a format this peer cannot author is not the
    marker — fail closed.

    O(1), no I/O. Per ENTITY-NATIVE-TYPE-SYSTEM §4.9 the direct hash-equality
    check is normatively SHOULD.
    """
    if h is None:
        return False
    try:
        code, _ = decode_content_hash_format(h)
    except (UnsupportedContentHashFormatError, ValueError):
        return False
    return h == deletion_marker_hash(code)


__all__ = [
    "DELETION_MARKER_ENTITY",
    "CANONICAL_DELETION_MARKER_HASH",
    "deletion_marker_entity",
    "deletion_marker_hash",
    "is_deletion_marker",
]
