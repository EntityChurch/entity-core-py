"""V7 v7.65 §6 — cap pattern peer-reference canonicalization + lazy canon.

Cap patterns (`peers: IdScope.include`) reference peers via wire peer_id
embedded in the pattern string. Per §6 three normative behaviors:

1. **Mint with pubkey available**: canonicalize before storage (storage holds
   canonical form only). Available when the impl has prior contact with the
   named peer (pubkey recorded at handshake).

2. **Match-time**: runtime peer_id is canonical per §4 mandate + §5 carve-out
   storage rule, so string-comparison against stored canonical patterns works.

3. **Lazy canonicalization** (mint without pubkey): when the operator pastes
   a non-canonical Base58 handle for a peer the impl has not previously
   contacted, accept the mint with the non-canonical form, mark the pattern
   as ``pending-canonicalization``, and rewrite on first contact with the
   named peer (handshake reveals pubkey). Idempotent; emits a debug log.

This module exposes the helper canonicalize_cap_pattern_peer_refs that
distinguishes the three cases for callers (handler + dual-form policy entry).
"""

from __future__ import annotations

import logging
import re
from enum import Enum

from entity_core.crypto.identity import (
    canonicalize_peer_id,
    decode_peer_id,
    is_canonical_pair,
)


logger = logging.getLogger(__name__)


class PolicyEntryCanonState(str, Enum):
    """Canonicalization state for cap-pattern peer references.

    CANONICAL: every peer reference in the pattern is canonical form per
        §1.5 v7.65 (Ed25519 → identity-multihash). Stored patterns SHOULD
        be in this state.
    PENDING:   at least one peer reference is non-canonical AND its pubkey
        is unavailable. The caller MUST mark the policy entry
        ``pending-canonicalization`` and re-run this helper after each
        handshake until the state becomes CANONICAL (§6 rule 3).
    """

    CANONICAL = "canonical"
    PENDING = "pending-canonicalization"


# Matches the leading peer_id segment of a tree path: /{peer_id}/...
# Per V7 §1.5 + §3.13, paths bind to a peer_id at the first path segment.
# We treat the segment between the first "/" and the next "/" as a candidate
# peer_id and probe it with decode_peer_id.
_PEER_SEGMENT_RE = re.compile(r"^/([^/]+)(/.*)?$")


def canonicalize_cap_pattern_peer_refs(
    pattern: str,
    *,
    known_pubkeys: dict[str, bytes] | None = None,
) -> tuple[str, PolicyEntryCanonState]:
    """V7 v7.65 §6 — canonicalize the peer reference inside a cap pattern.

    The pattern's leading segment may be a wire peer_id. If it is, and is
    non-canonical, this helper rewrites it to canonical form when the pubkey
    is available (either decodable from identity-form OR supplied in
    ``known_pubkeys``).

    Args:
        pattern: cap pattern string (e.g. ``/{peer_id}/system/files``).
        known_pubkeys: optional mapping of wire peer_id (any form) → raw
            32-byte public_key. Populated from per-connection handshake state
            for the lazy-canon trigger (§6 rule 3 second phase).

    Returns:
        (canonical_pattern, state) — when state is CANONICAL the pattern is
        ready to store; when PENDING the caller marks the policy entry
        ``pending-canonicalization`` and retries on next handshake.

    Non-peer_id-leading patterns (wildcards, role-scoped patterns, etc.) pass
    through unchanged with state=CANONICAL.
    """
    known_pubkeys = known_pubkeys or {}

    m = _PEER_SEGMENT_RE.match(pattern)
    if not m:
        # Not a tree-path-shape pattern; nothing to canonicalize.
        return pattern, PolicyEntryCanonState.CANONICAL

    candidate, rest = m.group(1), m.group(2) or ""

    # Probe whether the leading segment is a wire peer_id.
    try:
        key_type, hash_type, _digest = decode_peer_id(candidate)
    except Exception:
        # Wildcards (``*``), bare role names, etc. — not a peer_id.
        return pattern, PolicyEntryCanonState.CANONICAL

    # V7 v7.66 §4.4 surface 5 — per-key_type canonical-pair check
    # (generalized from the v7.65 Ed25519 short-circuit so the agility path
    # runs for 0xFE peer-refs: canonical pair is (0xFE, 0x01) SHA-256-form).
    if is_canonical_pair(key_type, hash_type):
        # Already canonical — no rewrite needed.
        return pattern, PolicyEntryCanonState.CANONICAL

    # Non-canonical. Try to canonicalize.
    pubkey = known_pubkeys.get(candidate)
    canonical = canonicalize_peer_id(candidate, public_key=pubkey)
    if canonical is None:
        # Lazy-canon path: caller marks pending; re-run on next handshake.
        return pattern, PolicyEntryCanonState.PENDING

    if canonical != candidate:
        logger.debug(
            "cap pattern peer-ref canonicalized: %s -> %s",
            candidate, canonical,
        )
    return f"/{canonical}{rest}", PolicyEntryCanonState.CANONICAL


def canonicalize_pattern_list(
    patterns: list[str],
    *,
    known_pubkeys: dict[str, bytes] | None = None,
) -> tuple[list[str], PolicyEntryCanonState]:
    """Apply ``canonicalize_cap_pattern_peer_refs`` to every pattern in a list.

    Returns the rewritten list plus the joint state: CANONICAL iff every
    pattern is CANONICAL; PENDING iff any pattern is PENDING. The caller
    stores the rewritten list (rewriting in place is idempotent so partial
    rewrites under PENDING are safe — the next handshake completes them).
    """
    state = PolicyEntryCanonState.CANONICAL
    out: list[str] = []
    for p in patterns:
        rewritten, s = canonicalize_cap_pattern_peer_refs(
            p, known_pubkeys=known_pubkeys,
        )
        out.append(rewritten)
        if s == PolicyEntryCanonState.PENDING:
            state = PolicyEntryCanonState.PENDING
    return out, state
