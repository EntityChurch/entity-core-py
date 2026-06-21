"""PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND Part A — the reader seam.

The peer-issued backend is **trust logic over transport-agnostic reads**
(proposal §2.1): it says "read this binding from the registry peer, then
verify the signature against the key I pinned." It does **not** know or
care whether the registry is reached over http-poll (a static coral-reef,
the demo case) or a live socket — *how* you reach the registry is the
transport layer's job (NETWORK §6.5).

This module is that thin transport seam, NOT a new transport. A
``RegistryReader`` exposes exactly two reads the backend needs —
``tree_get(path) → hash`` and ``content_get(hash) → entity`` — and the
concrete satisfier for a static coral-reef wraps the **already-built**
``HttpPollClient`` (entity_core.peer.http_poll_client). The backend
(registry.py ``_peer_issued_resolve``) is blind to which satisfier it
holds.

Read safety mirrors http-poll's threat model: ``content_get`` is
hash-verified (``0x00‖SHA-256(body) == hash``), so a hostile host cannot
serve wrong bytes for a hash; the host-claimed ``tree_get`` pointer is
safe only because the binding body it points at is then both
hash-verified (content) AND signature-verified against the pinned
registry key (registry.py step 3). A hostile host can at worst serve a
stale/older binding the registry really signed — bounded by ttl +
revocation, exactly as the proposal §5 states.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from entity_core.peer.http_poll_client import HttpPollClient, HttpPollError
from entity_core.protocol.entity import Entity


@runtime_checkable
class RegistryReader(Protocol):
    """The two transport-agnostic reads the peer-issued backend performs
    against a registry peer. Satisfiers pick the wire (http-poll for a
    static coral-reef; a live socket otherwise) — the backend never branches
    on transport."""

    async def tree_get(self, path: str) -> bytes | None:
        """Resolve a tree path on the registry peer to its bare
        ``system/hash`` pointer bytes, or ``None`` if the path is absent."""
        ...

    async def content_get(self, h: bytes) -> Entity | None:
        """Fetch + hash-verify the entity at ``h`` from the registry peer,
        or ``None`` if absent / fails verification (fail closed)."""
        ...


class HttpPollRegistryReader:
    """A ``RegistryReader`` backed by the built http-poll consumer — the
    transport for a static coral-reef registry (SUBSTITUTE §7 Mode S)."""

    def __init__(self, base_url: str, registry_peer_id: str, *, timeout: float = 5.0) -> None:
        self._registry_peer_id = registry_peer_id
        self._client = HttpPollClient(base_url, timeout=timeout)

    async def tree_get(self, path: str) -> bytes | None:
        try:
            return await self._client.tree_pointer(self._registry_peer_id, path)
        except HttpPollError:
            # tree_not_found / bad_pointer / transport_error → a miss; the
            # resolver advances the chain (fail closed, never an exception).
            return None

    async def content_get(self, h: bytes) -> Entity | None:
        try:
            return await self._client.content_get(h)
        except HttpPollError:
            # content_not_found / content_hash_mismatch → fail closed.
            return None


def make_reader(entry: dict[str, Any]) -> RegistryReader | None:
    """Build the ``RegistryReader`` for a resolver-chain entry, or ``None``
    when the entry carries no remote registry endpoint (offline-only — the
    backend then resolves from precedes / local store alone).

    The registry endpoint lives in the chain entry's ``hints`` (proposal
    §2.2a: "endpoint already lives in the resolver-chain config"). The
    backend itself never reads this — selecting the transport from config is
    the seam's job, not the backend's.
    """
    backend_id = entry.get("backend_id")
    if not isinstance(backend_id, str) or not backend_id:
        return None
    hints = entry.get("hints")
    if not isinstance(hints, dict):
        return None
    endpoint = hints.get("endpoint") or hints.get("http_poll_endpoint") or hints.get("url")
    if not isinstance(endpoint, str) or not endpoint:
        return None
    return HttpPollRegistryReader(endpoint, backend_id)
