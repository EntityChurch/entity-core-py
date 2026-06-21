"""Peer identity utilities.

Functions for working with peer IDs and identity validation.

Peer ID format per spec:
- Ed25519 + SHA-256 = 34 bytes (1 key_type + 1 hash_type + 32 digest)
- Base58 encoded = 46 characters
"""

from __future__ import annotations

# Base58 alphabet (Bitcoin)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Expected peer ID length: Base58(34 bytes) = 46 characters
PEER_ID_LENGTH = 46


def is_peer_id(segment: str) -> bool:
    """Check if a path segment looks like a peer ID.

    Per spec §5.4: Ed25519 + SHA-256 = 34 bytes = 46 Base58 characters.

    Args:
        segment: Path segment to check.

    Returns:
        True if segment is a valid peer ID format.
    """
    if len(segment) != PEER_ID_LENGTH:
        return False
    for ch in segment:
        if ch not in BASE58_ALPHABET:
            return False
    return True
