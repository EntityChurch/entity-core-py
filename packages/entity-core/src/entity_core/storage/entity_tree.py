"""URI -> Hash mutable location index.

The entity tree is one of the two storage layers in Entity Core.
It maps URIs to content hashes and is mutable (same URI can point to different hashes).

Key properties:
- Location-addressed (absolute path -> hash)
- Mutable (path can be updated to point to new content)
- Peer-namespaced (paths include /{peer_id}/ prefix)

V4 Changes:
- Hash is now bytes (algorithm byte + digest)
"""

from __future__ import annotations

from entity_core.utils.ecf import Hash
from entity_core.utils.identity import is_peer_id


class EntityTree:
    """Mutable URI -> Hash mapping.

    Maps URIs to content hashes. This is an in-memory implementation for testing.
    """

    def __init__(self, local_peer_id: str) -> None:
        """Initialize entity tree.

        Args:
            local_peer_id: This peer's ID (for URI normalization).
        """
        self.local_peer_id = local_peer_id
        self._tree: dict[str, bytes] = {}

    def normalize_uri(self, path: str) -> str:
        """Normalize path to absolute form.

        Per spec v7.18 R5:
        - entity:// URI -> strip scheme, prepend / -> /{peer_id}/rest
        - Already absolute (starts with /) -> pass through
        - Peer ID first segment -> prepend / -> /{peer_id}/rest
        - Peer-relative path -> /{local_peer_id}/path

        All paths in the location index are stored as absolute paths.

        Args:
            path: Path or URI to normalize.

        Returns:
            Absolute path (/{peer_id}/rest).
        """
        # Strip entity:// scheme, produce absolute path
        if path.startswith("entity://"):
            return "/" + path[len("entity://"):]
        # Already absolute
        if path.startswith("/"):
            return path
        # Check if first segment is already a peer ID
        slash = path.find("/")
        first_segment = path if slash < 0 else path[:slash]
        if is_peer_id(first_segment):
            return f"/{path}"
        # Short-form path: prepend local peer ID
        return f"/{self.local_peer_id}/{path}"

    def set(self, uri: str, h: Hash) -> None:
        """Map URI to hash.

        Args:
            uri: The URI (will be normalized).
            h: The content hash bytes.
        """
        full_uri = self.normalize_uri(uri)
        self._tree[full_uri] = h

    def get(self, uri: str) -> Hash | None:
        """Get hash at URI.

        Args:
            uri: The URI to look up (will be normalized).

        Returns:
            The hash bytes if found, None otherwise.
        """
        full_uri = self.normalize_uri(uri)
        return self._tree.get(full_uri)

    def remove(self, uri: str) -> Hash | None:
        """Remove mapping, return old hash if any.

        Args:
            uri: The URI to remove (will be normalized).

        Returns:
            The previous hash bytes if it existed, None otherwise.
        """
        full_uri = self.normalize_uri(uri)
        return self._tree.pop(full_uri, None)

    def all_bindings(self) -> list[tuple[str, bytes]]:
        """Return all (uri, hash) bindings in the tree.

        Used for index rebuild operations.

        Returns:
            List of (uri, hash_bytes) tuples.
        """
        return list(self._tree.items())

    def paths_for_hash(self, h: bytes) -> list[str]:
        """Return all URIs currently bound to hash `h`.

        Reverse of `get()`. Used by `CapTokenScope`'s content-face per
        EXTENSION-NETWORK §6.5.6: a hash is in serve-scope iff some
        in-scope tree path binds to it. The same path index used by
        §6.4.2 Hash Tree Presence — there is no separate content-side
        ACL.

        v1 walks `_tree.items()` linearly. The served namespace is
        bounded in practice (operator-curated cap scope), so a linear
        walk over the namespace prefix is the right shape. A reverse
        index lands when validate-peer-perf surfaces a hot path.

        Args:
            h: The content hash bytes to look up.

        Returns:
            Sorted list of URIs bound to `h` (empty if none).
        """
        return sorted(uri for uri, bound in self._tree.items() if bound == h)

    def list_prefix(self, prefix: str) -> list[str]:
        """List all URIs with given prefix.

        Args:
            prefix: The prefix to match (will be normalized).

        Returns:
            List of matching full URIs.
        """
        full_prefix = self.normalize_uri(prefix)
        return sorted([uri for uri in self._tree if uri.startswith(full_prefix)])

    def __len__(self) -> int:
        """Return number of URIs in tree."""
        return len(self._tree)

    def __contains__(self, uri: str) -> bool:
        """Support 'uri in tree' syntax."""
        return self.get(uri) is not None

