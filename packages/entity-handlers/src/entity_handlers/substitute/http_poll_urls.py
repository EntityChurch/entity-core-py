"""URL-layer helpers for http-poll consumer URLs.

Per EXTENSION-NETWORK §6.4 + D9 (v1.4 Amendment 2,
PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS): consumer-side http-poll
URLs use a `{prefix}/{X}/{rest}` structure where the `{X}` slot is
either a valid peer-ID OR one of the reserved words ``content`` /
``manifest`` (collision-safe by construction — peer-IDs are >=46-char
Base58 strings, reserved words are short lowercase ASCII).

This is **deliberately separate from `validate_absolute_path`**: that
validator stays strict (peer-ID-only) because the reserved-word redirect
is a URL-layer concept, NOT a tree-path concept. Mixing the two would
break §6.4's collision-safety reasoning.
"""

from __future__ import annotations

from typing import Literal

from entity_core.utils.identity import is_peer_id

#: §6.4 D9 reserved words at the {X} URL position.
#:   `content`  → content-store URL: `{prefix}/content/{layout-path}/{hash}`
#:   `manifest` → signed manifest / published-root URL: `{prefix}/manifest`
RESERVED_X_SEGMENTS: frozenset[str] = frozenset({"content", "manifest"})

XSegmentKind = Literal["peer_id", "content", "manifest"]


def classify_x_segment(segment: str) -> XSegmentKind | None:
    """Classify the ``{X}`` segment of a http-poll consumer URL.

    Returns one of ``"peer_id"`` / ``"content"`` / ``"manifest"`` when
    the segment matches §6.4's universal-path-compliance rule; returns
    ``None`` otherwise.

    Collision-safety: peer-IDs are at least 46 Base58 characters
    (encoding ``varint(key_type) || varint(hash_type) || SHA256(pubkey)``
    per V7 §1.5). The reserved words are short lowercase ASCII and can
    never satisfy the peer-ID encoding rule. So the three return values
    are mutually exclusive by construction.

    Args:
        segment: The candidate {X} segment.

    Returns:
        Classification, or None if the segment is neither a peer-ID nor
        a reserved word.
    """
    if segment in RESERVED_X_SEGMENTS:
        # Cast safe — segment is one of two literal values in the set.
        return segment  # type: ignore[return-value]
    if is_peer_id(segment):
        return "peer_id"
    return None


def is_valid_x_segment(segment: str) -> bool:
    """Convenience: True iff `segment` is a valid {X} value per §6.4."""
    return classify_x_segment(segment) is not None
