"""Request bounds for resource limits.

Per IMPLEMENTATION-SPEC §5.3: Bounds limit resource consumption during request processing.
Every EXECUTE can carry bounds; peers apply defaults when absent.

Default bounds (applied by peer when not present in request):
- ttl: 64 (maximum hop count)
- budget: 100000 (abstract resource units)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from entity_core.primitives import TreePath

# Default bounds applied when not specified in request
DEFAULT_TTL = 64
DEFAULT_BUDGET = 100000


@dataclass
class Bounds:
    """Resource bounds for a request.

    Attributes:
        ttl: Remaining hop count. Decremented on each dispatch.
            Request rejected when ttl <= 0.
        budget: Abstract resource units. Decremented by handlers.
            Request rejected when budget <= 0.
        chain_id: Optional identifier for request chains (correlation).
        visited: Optional list of peer IDs this request has visited (loop detection).
        cascade_depth: Current cascade depth in the emit pathway. Propagated
            across peer boundaries via subscription notification bounds.
            See SYSTEM-COMPOSITION.md §3.4.
    """

    TYPE_NAME = "system/bounds"

    ttl: int | None = None
    budget: int | None = None
    chain_id: str | None = None
    parent_chain_id: str | None = None
    visited: list[TreePath] | None = None
    cascade_depth: int | None = None

    def apply_defaults(self) -> Bounds:
        """Apply peer defaults for missing bounds fields.

        Returns:
            Self with defaults applied (mutates in place and returns).
        """
        if self.ttl is None:
            self.ttl = DEFAULT_TTL
        if self.budget is None:
            self.budget = DEFAULT_BUDGET
        return self

    def decrement_ttl(self) -> None:
        """Decrement TTL by one (called on each dispatch)."""
        if self.ttl is not None:
            self.ttl -= 1

    @property
    def ttl_exhausted(self) -> bool:
        """Whether TTL has been exhausted."""
        return self.ttl is not None and self.ttl <= 0

    @property
    def budget_exhausted(self) -> bool:
        """Whether budget has been exhausted."""
        return self.budget is not None and self.budget <= 0

    def copy(self) -> Bounds:
        """Create a shallow copy of the bounds.

        Returns:
            New Bounds instance with same values.
        """
        return Bounds(
            ttl=self.ttl,
            budget=self.budget,
            chain_id=self.chain_id,
            parent_chain_id=self.parent_chain_id,
            visited=list(self.visited) if self.visited else None,
            cascade_depth=self.cascade_depth,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for wire format.

        Only includes non-None fields.
        """
        result: dict[str, Any] = {}
        if self.ttl is not None:
            result["ttl"] = self.ttl
        if self.budget is not None:
            result["budget"] = self.budget
        if self.chain_id is not None:
            result["chain_id"] = self.chain_id
        if self.parent_chain_id is not None:
            result["parent_chain_id"] = self.parent_chain_id
        if self.visited is not None:
            result["visited"] = self.visited
        if self.cascade_depth is not None:
            result["cascade_depth"] = self.cascade_depth
        return result

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> Bounds:
        """Parse from dictionary.

        Args:
            d: Dictionary with bounds fields, or None.

        Returns:
            Bounds instance (empty if d is None).
        """
        if d is None:
            return cls()
        return cls(
            ttl=d.get("ttl"),
            budget=d.get("budget"),
            chain_id=d.get("chain_id"),
            parent_chain_id=d.get("parent_chain_id"),
            visited=d.get("visited"),
            cascade_depth=d.get("cascade_depth"),
        )
