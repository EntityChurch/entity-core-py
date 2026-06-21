"""Registry for managing non-default trees.

Per EXTENSION-TREE.md §7, this module provides create/destroy operations
for non-default trees. The default tree is managed separately and cannot
be destroyed.
"""

from __future__ import annotations

from typing import Any

from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree


class TreeRegistry:
    """Registry for non-default trees.

    Manages tree instances beyond the default tree. Each tree has:
    - A unique tree_id
    - An EntityTree instance (bindings storage)
    - A configuration dict (per system/tree/config type)

    The default tree is NOT managed by this registry - it exists independently.
    """

    def __init__(self, default_tree: EntityTree, content_store: ContentStore) -> None:
        """Initialize the tree registry.

        Args:
            default_tree: The default tree (for reference, not stored here).
            content_store: Shared content store for all trees.
        """
        self._default = default_tree
        self._content_store = content_store
        self._trees: dict[str, EntityTree] = {}
        self._configs: dict[str, dict[str, Any]] = {}

    @property
    def default_tree(self) -> EntityTree:
        """Get the default tree."""
        return self._default

    @property
    def content_store(self) -> ContentStore:
        """Get the shared content store."""
        return self._content_store

    def get(self, tree_id: str | None) -> EntityTree | None:
        """Get a tree by ID.

        Args:
            tree_id: The tree ID to look up, or None for default tree.

        Returns:
            The EntityTree if found, None if not found.
            Returns the default tree if tree_id is None or empty.
        """
        if not tree_id:
            return self._default
        return self._trees.get(tree_id)

    def get_config(self, tree_id: str) -> dict[str, Any] | None:
        """Get a tree's configuration.

        Args:
            tree_id: The tree ID to look up.

        Returns:
            The configuration dict if found, None otherwise.
        """
        return self._configs.get(tree_id)

    def exists(self, tree_id: str) -> bool:
        """Check if a tree with the given ID exists.

        Args:
            tree_id: The tree ID to check.

        Returns:
            True if the tree exists.
        """
        return tree_id in self._trees

    def create(self, config: dict[str, Any]) -> EntityTree:
        """Create a new tree with the given configuration.

        Args:
            config: Tree configuration dict with:
                - tree_id: Required unique identifier
                - root_structure: "peer-namespaced" or "relaxed"
                - purpose: Optional purpose string
                - ephemeral: Optional bool (default False)
                - source: Optional source tree_id for view trees
                - capability: Optional capability hash for view trees

        Returns:
            The newly created EntityTree.

        Raises:
            ValueError: If tree_id already exists or is empty.
        """
        tree_id = config.get("tree_id")
        if not tree_id:
            raise ValueError("tree_id is required")
        if tree_id in self._trees:
            raise ValueError(f"Tree already exists: {tree_id}")

        # Create new tree with same peer_id as default
        tree = EntityTree(self._default.local_peer_id)
        self._trees[tree_id] = tree
        self._configs[tree_id] = config
        return tree

    def destroy(self, tree_id: str) -> bool:
        """Destroy a tree and remove all its bindings.

        Args:
            tree_id: The tree ID to destroy.

        Returns:
            True if the tree was destroyed.

        Raises:
            ValueError: If tree_id is empty (cannot destroy default tree).
            KeyError: If tree_id does not exist.
        """
        if not tree_id:
            raise ValueError("Cannot destroy default tree")
        if tree_id not in self._trees:
            raise KeyError(f"Tree not found: {tree_id}")

        del self._trees[tree_id]
        del self._configs[tree_id]
        return True

    def list_trees(self) -> list[str]:
        """List all non-default tree IDs.

        Returns:
            List of tree IDs (not including default tree).
        """
        return list(self._trees.keys())

    def __len__(self) -> int:
        """Return number of non-default trees."""
        return len(self._trees)

    def __contains__(self, tree_id: str) -> bool:
        """Support 'tree_id in registry' syntax."""
        return self.exists(tree_id)
