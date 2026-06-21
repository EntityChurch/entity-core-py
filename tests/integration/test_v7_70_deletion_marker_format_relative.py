"""V7 v7.70 §4.9 — deletion marker is FORMAT-RELATIVE to the home format.

Arch ruling (IMPL-TEAM-ALIGNMENT-V7.70, item 3): the deletion marker is not a
hardcoded SHA-256 constant. Each trie binds and recognizes the marker authored
under that trie's own home format; ``ecf-sha256:689ae4…`` is the SHA-256-space
instance (standard-compliance floor) only. §1.2 erratum: a peer's persistent
state — including its trie marker bindings — is uniformly the home format, so a
SHA-384 home peer binding a SHA-256 marker would be non-conformant.

These pins overturn the v7.69 Python assumption (R3: "pinned-SHA-256"), which
arch answered "format-relative."
"""

from __future__ import annotations

from entity_core.types.deletion_marker import (
    CANONICAL_DELETION_MARKER_HASH,
    deletion_marker_entity,
    deletion_marker_hash,
    is_deletion_marker,
)
from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    get_default_hash_algorithm,
    set_default_hash_algorithm,
)


class TestDeletionMarkerFormatRelative:
    def test_sha256_instance_is_the_canonical_floor(self) -> None:
        # The SHA-256-space instance is the published canonical value.
        assert deletion_marker_hash(ALG_ECFV1_SHA256) == CANONICAL_DELETION_MARKER_HASH
        assert CANONICAL_DELETION_MARKER_HASH[0] == ALG_ECFV1_SHA256

    def test_sha384_instance_is_distinct_and_self_describing(self) -> None:
        sha384 = deletion_marker_hash(ALG_ECFV1_SHA384)
        # Different address space → different hash, with the SHA-384 format byte
        # and a 48-byte digest (49 bytes total).
        assert sha384 != CANONICAL_DELETION_MARKER_HASH
        assert sha384[0] == ALG_ECFV1_SHA384
        assert len(sha384) == 49

    def test_entity_data_is_format_independent(self) -> None:
        # Only the hash differs by format; the {type, data} is identical.
        e256 = deletion_marker_entity(ALG_ECFV1_SHA256)
        e384 = deletion_marker_entity(ALG_ECFV1_SHA384)
        assert e256.type == e384.type == "system/deletion-marker"
        assert e256.data == e384.data == {}

    def test_recognition_is_format_relative(self) -> None:
        # is_deletion_marker recognizes the marker in EITHER format — pure hash
        # arithmetic off the self-describing format byte, no entity load.
        assert is_deletion_marker(deletion_marker_hash(ALG_ECFV1_SHA256))
        assert is_deletion_marker(deletion_marker_hash(ALG_ECFV1_SHA384))

    def test_recognition_fails_closed_on_non_marker_and_garbage(self) -> None:
        assert not is_deletion_marker(None)
        # A real hash of a different entity, in a supported format.
        assert not is_deletion_marker(b"\x00" + b"\x42" * 32)
        # Unsupported format byte → not our marker, no exception.
        assert not is_deletion_marker(b"\x7e" + b"\x00" * 32)
        # Truncated / empty.
        assert not is_deletion_marker(b"")

    def test_home_format_follows_process_default(self) -> None:
        # deletion_marker_hash() with no arg tracks the peer's home format —
        # the value bound into the trie by the revision handler. A peer booted
        # under --hash-type sha384 binds the SHA-384 marker, not 689ae4.
        original = get_default_hash_algorithm()
        try:
            set_default_hash_algorithm(ALG_ECFV1_SHA384)
            assert deletion_marker_hash() == deletion_marker_hash(ALG_ECFV1_SHA384)
            assert deletion_marker_hash() != CANONICAL_DELETION_MARKER_HASH
            set_default_hash_algorithm(ALG_ECFV1_SHA256)
            assert deletion_marker_hash() == CANONICAL_DELETION_MARKER_HASH
        finally:
            set_default_hash_algorithm(original)
