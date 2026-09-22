"""Peer identity utilities.

Functions for working with peer IDs and identity validation.

Peer ID format per spec:
- Ed25519 + SHA-256 = 34 bytes (1 key_type + 1 hash_type + 32 digest)
- Base58 encoded = 46 characters
"""

from __future__ import annotations

# Base58 alphabet (Bitcoin)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# MINIMUM peer ID length: Base58(34 bytes) = 46 characters. §5.4 is explicit
# that this is a floor and not an equality — *"Future algorithms (larger keys,
# longer hashes) produce longer peer IDs. 46 is the minimum — no supported
# algorithm produces fewer bytes."*
PEER_ID_LENGTH = 46


def is_peer_id(segment: str) -> bool:
    """Check if a path segment looks like a peer ID.

    §5.4's ``is_peer_id``: ``if len(segment) < 46: return false``, then every
    character in the Base58 alphabet.

    .. rubric:: This was an equality check, and equality is a different rule

    Ed25519 + SHA-256 gives exactly 46, so ``!= 46`` and ``< 46`` agree on
    every peer this cohort has ever minted — which is why it survived, and
    which is the standing *"two readings that agree everywhere your fixtures
    live"* shape with a **length** as the subject. They disagree on a peer id
    from any longer algorithm, and there the equality form fails in the
    dangerous direction rather than the strict one: :func:`extract_peer`
    classifies a segment it rejects as *not a peer*, so an absolute path
    naming a **foreign** peer would be read as a peer-relative **local** one —
    §1.4's address gate answering "local" for someone else's namespace. The
    strictness is the visible half (``validate_absolute_path`` refusing a
    legitimate path); the misclassification is the half worth the entry.

    Found by wiring §5.2's G6 verdict-consumption rule into
    ``check_resource_scope``, which put this predicate on an authorization
    path for the first time — a fixture peer id of 48 legal Base58 characters
    then refused, and it was the *fixture* that was right.

    Args:
        segment: Path segment to check.

    Returns:
        True if segment is a valid peer ID format.
    """
    if len(segment) < PEER_ID_LENGTH:
        return False
    for ch in segment:
        if ch not in BASE58_ALPHABET:
            return False
    return True
