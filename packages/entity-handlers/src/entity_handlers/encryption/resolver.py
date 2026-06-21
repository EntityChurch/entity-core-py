"""EXTENSION-ENCRYPTION §10 / §11 — Tier-A recipient resolution + refusal.

Sender-side discipline for Tier A (V7 floor): before encrypting to a recipient,
walk the rotation handoff chain forward to the current pubkey (§10.1) and refuse
to encrypt to any pubkey carrying a live revocation (§11.1). Pure logic over
collections of handoff / revocation entities so it is unit-testable without a
live tree; the handler layer feeds it the recipient-namespace sweep.

Refless convention: ``previous_pubkey`` / ``next_pubkey`` / ``revokes`` are raw
33-byte ``system/hash`` byte strings embedded in entity data.
"""

from __future__ import annotations

from collections.abc import Iterable

from entity_core.protocol.entity import Entity

from .errors import KEY_REVOKED, EncryptionError


def next_in_handoff_chain(
    pubkey_hash: bytes, handoffs: Iterable[Entity]
) -> bytes | None:
    """Return the ``next_pubkey`` of the handoff whose ``previous_pubkey`` is
    ``pubkey_hash``, or ``None`` if this pubkey is terminal (§10.1)."""
    for h in handoffs:
        if h.data.get("previous_pubkey") == pubkey_hash:
            return h.data.get("next_pubkey")
    return None


def resolve_current_pubkey(
    start_hash: bytes, handoffs: Iterable[Entity]
) -> bytes:
    """Walk the handoff chain forward from ``start_hash`` to the terminal
    (current) pubkey (§10.1). Loop-guarded against a cyclic chain."""
    handoffs = list(handoffs)
    seen = {start_hash}
    current = start_hash
    while True:
        nxt = next_in_handoff_chain(current, handoffs)
        if nxt is None:
            return current
        if nxt in seen:  # defensive: malformed cyclic chain
            return current
        seen.add(nxt)
        current = nxt


def is_pubkey_revoked(pubkey_hash: bytes, revocations: Iterable[Entity]) -> bool:
    """True if any revocation targets ``pubkey_hash`` (§11.1)."""
    return any(r.data.get("revokes") == pubkey_hash for r in revocations)


def resolve_current_recipient(
    *,
    start_hash: bytes,
    handoffs: Iterable[Entity],
    revocations: Iterable[Entity],
) -> bytes:
    """Resolve the live current recipient pubkey for Tier-A sending.

    Walks the handoff chain to the terminal pubkey, then refuses if that pubkey
    is revoked (`encryption_key_revoked`). The sender binds the returned hash as
    ``recipient_key``; a revoked terminal is a hard stop (§11 — senders MUST
    stop encrypting to revoked pubkeys).
    """
    revocations = list(revocations)
    current = resolve_current_pubkey(start_hash, handoffs)
    if is_pubkey_revoked(current, revocations):
        raise EncryptionError(
            KEY_REVOKED, "current recipient pubkey is revoked"
        )
    return current
