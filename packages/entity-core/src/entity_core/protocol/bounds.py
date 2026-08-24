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

# Canonical rejection messages for a dispatch refused because a *local*
# resource bound (a per-request hop/work budget) is exhausted. Shared so the
# producing site (peer dispatch) and the consuming site (continuation advance,
# which attributes the chain-terminating brake honestly) agree on one spelling
# rather than matching a scattered literal. These are LOCAL bounds — distinct
# from the continuation causal-chain `chain_depth` GLOBAL brake
# (PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION §4a): TTL/budget exhaustion is an
# additional local bound, never a substitute for the depth brake.
TTL_EXHAUSTED_MESSAGE = "TTL exhausted"
BUDGET_EXHAUSTED_MESSAGE = "Budget exhausted"

# Wire error CODES for the same refusal. Unlike the human message, the code is
# the attributable identifier a *caller* keys on: a cross-peer continuation
# chain that hits a bound at a peer's ingress is refused pre-dispatch, and the
# terminal the caller observes MUST name the bound rather than collapse to a
# generic `bad_request` (which cannot be told from a malformed request). Shared
# here so the producing site (peer ingress) and the continuation handler's
# chain-error `{reason}` agree on one spelling. Matches `relay.py`'s
# source-route `ttl_hops` code.
TTL_EXHAUSTED_CODE = "ttl_exhausted"
BUDGET_EXHAUSTED_CODE = "budget_exhausted"


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
        chain_depth: Continuation causal-chain length (§3.9). Like cascade_depth
            it rides in bounds on the wire and is inherited across the peer
            boundary — the value tested at the ceiling is the *global* chain
            length, not a per-peer counter. Non-negative integer; incremented
            only at a causal advancement dispatch (EXTENSION-CONTINUATION §5 /
            PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION). TTL/budget refill does
            NOT reset it (§6.2). Absent = a fresh external trigger roots at 0.
    """

    TYPE_NAME = "system/bounds"

    ttl: int | None = None
    budget: int | None = None
    chain_id: str | None = None
    parent_chain_id: str | None = None
    visited: list[TreePath] | None = None
    cascade_depth: int | None = None
    chain_depth: int | None = None

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
            chain_depth=self.chain_depth,
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
        if self.chain_depth is not None:
            result["chain_depth"] = self.chain_depth
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
            chain_depth=d.get("chain_depth"),
        )
