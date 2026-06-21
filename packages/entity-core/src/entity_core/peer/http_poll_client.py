"""http-poll outbound connector — the dialer half (Phase P / C2).

The read-only static-transport *consumer*: dials a peer's http-poll
profile (or base URL), fetches its signed ``published-root`` via
``MANIFEST_GET``, verifies the root's signature (C1), then walks the
CHAMP trie hash-chain FROM the verified ``root_hash`` so every path it
resolves is cryptographically committed by the publisher — never trusting
the host's raw bytes (PEER-MANIFEST §1.1 threat model).

Distinct from ``RemoteConnectionPool`` (the tcp/http *live* EXECUTE
transport): http-poll is GET-only, uncapability-gated, request-less. This
client speaks the pinned Chunk-E routes (three-way GREEN):

  - ``GET {base}/manifest``                  → ``published-root`` entity ECF
  - ``GET {base}/{peer_id}/{path}.bin``      → bare ``system/hash`` pointer
  - ``GET {base}/content/{hex33(H)}``        → bare ``ECF({type,data})``, rehash-verified

Verification properties:
  - **Content** is hash-safe: every ``CONTENT_GET`` body MUST satisfy
    ``0x00 ‖ SHA-256(body) == H`` (Mechanism A) — a host cannot serve wrong
    bytes for a hash.
  - **Root** is signature-safe: ``MANIFEST_GET`` + ``verify_published_root``
    (signature against the publisher's peer-id pubkey + seq rollback).
  - **Path→hash bindings** are endorsement-safe ONLY when reached by walking
    the trie from the signed root (``walk_from_root``). The bare
    ``TREE_GET`` pointer is host-claimed; the client exposes it
    (``tree_pointer``) but the *endorsed* resolution is the walk.

Cross-impl note: the consumer walk + hash-verification are impl-agnostic;
the precise validate-peer vector + the publisher's serving-scope policy
(see ``ClosureScope``) converge with Go's P2 reference at the reconvene.
This client runs blocking HTTP in an executor — fine for static fetch;
a native async transport can replace the seam without changing callers.
"""

from __future__ import annotations

import asyncio
import hashlib
import urllib.error
import urllib.request
from typing import Any

from entity_core.peer.published_root import PublishedRootError, verify_published_root
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.trie import collect_all_bindings
from entity_core.utils.ecf import ecf_decode

TRIE_NODE_TYPE = "system/tree/snapshot/node"


class HttpPollError(Exception):
    """Raised on a transport / verification failure (fail closed)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _rehash(body: bytes) -> bytes:
    """``0x00 ‖ SHA-256(body)`` — Mechanism A content verification (default
    ECFv1-SHA256 format). Multi-hash formats are a follow-on; the C2 gate
    uses the default format."""
    return bytes([0x00]) + hashlib.sha256(body).digest()


class HttpPollClient:
    """A read-only http-poll consumer anchored to a verified signed root."""

    def __init__(self, base_url: str, *, content_store: ContentStore | None = None, timeout: float = 5.0) -> None:
        self.base = base_url.rstrip("/")
        # Local cache for fetched trie nodes (so collect_all_bindings can read
        # them after the BFS) and verified entities.
        self.cs = content_store or ContentStore()
        self.timeout = timeout
        self._cached_seq: int | None = None

    # -- raw HTTP (blocking, run in executor) -------------------------------

    def _get_sync(self, path: str) -> tuple[int, bytes]:
        url = f"{self.base}{path}"
        req = urllib.request.Request(url, method="GET")
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read() or b""
        except urllib.error.URLError as e:  # pragma: no cover - network shape
            raise HttpPollError("transport_error", str(e))

    async def _get(self, path: str) -> tuple[int, bytes]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._get_sync, path)

    # -- fetch primitives ---------------------------------------------------

    async def content_get(self, h: bytes) -> Entity:
        """``CONTENT_GET`` a hash, verifying ``0x00‖SHA-256(body)==h`` before
        decoding. Caches the entity locally. Fails closed on mismatch."""
        h = bytes(h)
        status, body = await self._get(f"/content/{h.hex()}")
        if status != 200:
            raise HttpPollError("content_not_found", f"CONTENT_GET {h.hex()} -> {status}")
        if _rehash(body) != h:
            raise HttpPollError(
                "content_hash_mismatch",
                f"CONTENT_GET body does not rehash to {h.hex()} (hostile-CDN guard)",
            )
        entity = Entity.from_dict(ecf_decode(body))
        self.cs.put(entity)
        return entity

    async def tree_pointer(self, peer_id: str, path: str) -> bytes:
        """``TREE_GET`` a leaf → the bare ``system/hash`` pointer's bytes.
        Host-claimed; safe only because the second-hop ``CONTENT_GET`` is
        hash-verified and the root walk is the endorsed path."""
        status, body = await self._get(f"/{peer_id}/{path}.bin")
        if status != 200:
            raise HttpPollError("tree_not_found", f"TREE_GET {path} -> {status}")
        decoded = ecf_decode(body)
        ptr = decoded.get("data") if isinstance(decoded, dict) else None
        if not isinstance(ptr, (bytes, bytearray)):
            raise HttpPollError("bad_pointer", f"TREE_GET {path} pointer not a hash")
        return bytes(ptr)

    async def manifest(self) -> Entity:
        """``MANIFEST_GET`` → the publisher's ``published-root`` entity."""
        status, body = await self._get("/manifest")
        if status != 200:
            raise HttpPollError("no_manifest", f"MANIFEST_GET -> {status}")
        return Entity.from_dict(ecf_decode(body))

    # -- the signed-root walk ----------------------------------------------

    async def fetch_verified_root(self) -> tuple[Entity, bytes]:
        """Fetch + verify the signed ``published-root``. Returns
        ``(published_root_entity, trusted_root_hash)``. Rejects rollback via
        cached seq (monotonic across calls on this client)."""
        pr = await self.manifest()
        peer_id = pr.data.get("peer_id")
        if not isinstance(peer_id, str):
            raise HttpPollError("invalid_manifest", "published-root missing peer_id")
        pr_hash = pr.compute_hash()
        sig_ptr = await self.tree_pointer(peer_id, f"system/signature/{pr_hash.hex()}")
        sig = await self.content_get(sig_ptr)
        try:
            root_hash = verify_published_root(pr, sig, cached_seq=self._cached_seq)
        except PublishedRootError as exc:
            raise HttpPollError(exc.code, exc.message)
        self._cached_seq = pr.data.get("seq")
        return pr, root_hash

    async def _fetch_trie_nodes(self, root_hash: bytes) -> None:
        """BFS-fetch every trie node reachable from ``root_hash`` into the
        local store (each ``CONTENT_GET`` hash-verified). Bucket value-hashes
        are the bound entities — fetched lazily by the caller, not here."""
        queue = [bytes(root_hash)]
        seen: set[bytes] = set()
        while queue:
            node_hash = queue.pop()
            if node_hash in seen:
                continue
            seen.add(node_hash)
            node = await self.content_get(node_hash)
            if node.type != TRIE_NODE_TYPE:
                continue
            for entry in node.data.get("data", []):
                if isinstance(entry, (bytes, bytearray)):  # a link → child node
                    queue.append(bytes(entry))

    async def walk_from_root(self, root_hash: bytes) -> dict[str, bytes]:
        """Walk the trie from the verified ``root_hash`` and return the
        endorsed ``{path: value_hash}`` map. Every binding is committed by the
        signed root — a host cannot inject a path the publisher didn't sign."""
        await self._fetch_trie_nodes(root_hash)
        return {k: v for k, v in collect_all_bindings(root_hash, "", self.cs)}

    async def fetch(self) -> tuple[Entity, dict[str, bytes]]:
        """Convenience: verify the root and return ``(published_root,
        endorsed_bindings)``."""
        pr, root_hash = await self.fetch_verified_root()
        return pr, await self.walk_from_root(root_hash)

    async def fetch_entity(self, path: str, bindings: dict[str, bytes]) -> Entity:
        """Fetch + hash-verify the entity at an endorsed ``path`` (a key from
        ``walk_from_root``)."""
        value_hash = bindings.get(path)
        if value_hash is None:
            raise HttpPollError("not_endorsed", f"path {path!r} not in the signed root")
        return await self.content_get(value_hash)
