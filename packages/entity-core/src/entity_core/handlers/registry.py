"""Path-based handler dispatch.

Handlers register at path patterns. When an EXECUTE message arrives,
the handler registry finds the appropriate handler based on the path.

Pattern matching:
- "system/*" matches system/status, system/peer/info, etc.
- "local/files/*" matches local/files/doc.txt, local/files/subdir/file.txt
- "*" is a fallback that matches anything
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from entity_core.handlers.context import HandlerContext

if TYPE_CHECKING:
    from entity_core.capability.grant import Grant

# Handler type: async function that processes requests
Handler = Callable[
    [str, str, dict[str, Any], HandlerContext],
    Awaitable[dict[str, Any]],
]


@dataclass
class RegisteredHandler:
    """A handler registered at a pattern.

    Attributes:
        pattern: The path pattern to match.
        priority: Higher priority handlers are checked first.
        handler: The async handler function.
        name: Optional human-readable name.
        max_scope: Maximum capability scope for this handler.
            If set, the effective capability passed to the handler
            is the intersection of the request capability and max_scope.
            If None, the full request capability is passed.
    """

    pattern: str
    priority: int
    handler: Handler
    name: str = ""
    max_scope: list[Grant] | None = None


class HandlerRegistry:
    """Registry for path-based handler dispatch.

    Handlers are checked in priority order (highest first).
    Within the same priority, more specific patterns are preferred.
    """

    def __init__(self) -> None:
        self._handlers: list[RegisteredHandler] = []

    def register(
        self,
        pattern: str,
        handler: Handler,
        priority: int = 0,
        name: str = "",
        max_scope: list[Grant] | None = None,
    ) -> None:
        """Register a handler at a path pattern.

        Args:
            pattern: Path pattern (e.g., "system/*", "local/files/*", "*").
            handler: Async function to handle requests.
            priority: Higher = checked first. Default handlers use 0.
            name: Optional human-readable name for logging.
            max_scope: Optional list of grants defining max capabilities.
                If set, effective capability = intersection of request
                capability and max_scope.
        """
        self._handlers.append(
            RegisteredHandler(pattern, priority, handler, name, max_scope)
        )
        # Sort by priority descending, then by pattern length (specificity) descending
        self._handlers.sort(key=lambda h: (-h.priority, -len(h.pattern)))

    def find_handler(self, path: str) -> Handler | None:
        """Find handler matching path (most specific wins).

        Args:
            path: The path to match.

        Returns:
            The matching handler, or None if no handler matches.
        """
        for registered in self._handlers:
            if self._matches(registered.pattern, path):
                return registered.handler
        return None

    def find_handler_info(self, path: str) -> RegisteredHandler | None:
        """Find handler info (including name) matching path.

        Args:
            path: The path to match.

        Returns:
            The RegisteredHandler, or None if no handler matches.
        """
        for registered in self._handlers:
            if self._matches(registered.pattern, path):
                return registered
        return None

    def find_exact(self, pattern: str) -> RegisteredHandler | None:
        """Find handler registered with exactly this pattern (no globbing).

        Used by V7 §6.6 tree-walk dispatch: after the tree walk identifies
        the pattern, this looks up the bound function for that exact pattern.
        """
        for registered in self._handlers:
            if registered.pattern == pattern:
                return registered
        return None

    def list_handlers(self) -> list[RegisteredHandler]:
        """List all registered handlers.

        Returns:
            List of all registered handlers.
        """
        return list(self._handlers)

    def _matches(self, pattern: str, path: str) -> bool:
        """Check if path matches handler pattern.

        Pattern matching rules:
        - "*" matches everything (fallback handler)
        - "pattern/*" matches prefix explicitly (e.g., "system/*" matches "system/foo")
        - "pattern" matches exact path OR prefix (e.g., "system/inbox" matches
          "system/inbox" and "system/inbox/foo")

        Args:
            pattern: The handler's pattern.
            path: The path to check.

        Returns:
            True if path matches pattern.
        """
        # Extract handler-relative path from URI or absolute path
        from entity_core.utils.path import extract_handler_path
        path = extract_handler_path(path)

        if pattern == "*":
            return True

        if pattern.endswith("/*"):
            prefix = pattern[:-1]  # Keep trailing /
            return path.startswith(prefix) or path == prefix.rstrip("/")

        # Exact match or prefix match (handler owns pattern and all subpaths)
        # e.g., "system/inbox" matches "system/inbox" and "system/inbox/foo"
        if path == pattern:
            return True
        if path.startswith(pattern + "/"):
            return True

        return False
