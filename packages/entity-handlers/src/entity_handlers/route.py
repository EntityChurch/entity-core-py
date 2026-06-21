"""EXTENSION-ROUTE v1.0 — the routing-table storage plane.

ROUTE is a **storage plane**: it holds a peer's routing table as a set of
``system/route`` entities ("to reach destination D, the next hop is N, or D is
direct"). That is the whole job (§1). ROUTE **stores** routes and defines how
the table is **read**; it does **not** compute routes, does not decide how the
table is populated, and owns no resolver registry. RELAY (the consumer) reads
this table via :func:`resolve_from_table` when a ``forward-request`` carries no
source route and no explicit ``next_hop`` (RELAY §3.1.1 source 3); production —
manual config / DISCOVERY-learned / GOSSIP-learned — is the peer's job (§4).

v1 conformance floor (§7.1):

1. The ``system/route`` entity (§2) — shape, tree-binding at
   ``system/route/{hex(content_hash)}``, signature per V7 §5.2, the
   ``route-configure`` cap (§5).
2. The documented match relay applies (§3) — exact + ``*`` default, lowest
   metric, expiry-skip, precedence (source-route > table > direct), no-match →
   ``no_route``/502.

Cross-impl traps carried from the Go build-test
(the source-route and route cohort handoff):

- **Use the canonical wire-form hash for the tree path** — ``Hash.hex()`` here
  is already algorithm-byte + effective-digest (66 hex for SHA-256), so the
  Go ``Digest[:]`` padding trap (130-char paths with trailing zeros) cannot
  occur in Python.
- **``*`` is a string token (``primitive/string``), NOT a peer-id.** Only
  ``via`` is a peer-id. Python stores ``match`` as a plain string in ``data``;
  there is no field-type registry that would mis-decode ``"*"`` as a peer-id.
- **The table resolver runs ONLY when both ``route`` and ``next_hop`` are
  absent** on the inbound forward-request (precedence: source-route > table >
  direct). RELAY's :func:`_handle_forward` enforces that ordering;
  :func:`resolve_from_table` is the source-3 leg.
"""

from __future__ import annotations

from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_handlers._common import now_ms as _now_ms

# -- Type + path ------------------------------------------------------------

ROUTE_TYPE = "system/route"
# Listing prefix for the route subtree (RELAY's table-read resolver enumerates
# the local route table here). Trailing slash matches list_prefix semantics.
ROUTE_PREFIX = "system/route/"

# §2 actions — the per-route disposition relay applies when a route matches.
ROUTE_ACTION_DELIVER = "deliver"  # terminal hop — deliver locally
ROUTE_ACTION_FORWARD = "forward"  # forward one hop to ``via``

# §2/§3 default-route token. ``*`` reflects to primitive/string (NOT a peer-id);
# exact match outranks ``*`` on ties (longest-match-wins, degenerate over a
# non-hierarchical peer-id space).
ROUTE_MATCH_DEFAULT = "*"

# §5 capability — guards writes to the system/route subtree. Reads need no extra
# caller cap (relay's local read of substrate state is internal).
CAPABILITY_ROUTE_CONFIGURE = "system/capability/route-configure"


# ===========================================================================
# Entity constructor (§2)
# ===========================================================================


def make_route(
    *,
    match: str,
    action: str,
    via: str | None = None,
    metric: int | None = None,
    expires_at: int | None = None,
) -> Entity:
    """Construct a ``system/route`` entity (§2).

    ``match`` is a Base58 peer_id (the destination this route covers) or the
    literal ``"*"`` default-route token. ``action`` is ``"deliver"`` (terminal —
    deliver locally) or ``"forward"`` (one hop to ``via``). ``via`` is REQUIRED
    iff ``action == "forward"`` and is a Base58 peer_id; it is OMITTED when
    ``None`` (omitempty — matches Go's ``Via,omitempty``). ``metric`` (lower
    wins on ties; ``null`` == 0) and ``expires_at`` (ms since epoch; ``null`` ==
    until superseded) are OMITTED when ``None`` / 0 (omitempty).

    AUTHORED + SIGNED by the configuring authority per V7 §5.2 (signature at the
    invariant pointer ``system/signature/{hex(content_hash)}``; no ``refs:``
    block). Tree-bound at ``system/route/{hex(content_hash)}`` — per-route
    cap-scoping flows through the standard tree handler.

    Mirrors Go's ``RouteData{Match, Action, Via, Metric, ExpiresAt}`` byte
    shape (omitempty on via/metric/expires_at).
    """
    data: dict[str, Any] = {"match": match, "action": action}
    if via:  # omitempty — empty/None dropped (matches Go cbor omitempty)
        data["via"] = via
    if metric:  # omitempty — 0/None dropped (null == 0 per §2)
        data["metric"] = int(metric)
    if expires_at:  # omitempty — 0/None dropped (null == until superseded)
        data["expires_at"] = int(expires_at)
    return Entity(type=ROUTE_TYPE, data=data)


def route_storage_path(route_hash_hex: str) -> str:
    """Canonical tree path for a route entity (§2):
    ``system/route/{hex(content_hash)}``. The id segment is the lowercase hex
    of the route entity's canonical hash bytes (algorithm byte + effective
    digest) — ``Hash.hex()`` already yields this form."""
    return f"{ROUTE_PREFIX}{route_hash_hex}"


# ===========================================================================
# The match relay applies (§3) — the table-read resolver
# ===========================================================================


def resolve_from_table(
    ctx: HandlerContext, destination: str
) -> tuple[str | None, bool]:
    """Apply the EXTENSION-ROUTE §3 match against the local ``system/route``
    subtree to pick a next-hop, when the forward-request carries neither a
    source route nor an explicit ``next_hop`` (RELAY §3.1.1 source 3).

    Behavior (§3):

    1. Enumerate route entities under ``system/route/*`` via the local index;
       decode each, skipping type/decode errors.
    2. Filter to routes whose ``match`` is exactly ``destination`` or the ``*``
       default-route token, and whose ``expires_at`` is null/0 or in the future
       (expired routes are silently skipped — never surfaced as ``no_route``).
    3. Cross-field validity: ``action == "forward"`` requires non-empty
       ``via`` (else silently skipped).
    4. Tie-break: exact ``match`` outranks ``*`` default; within the same
       cohort, lowest ``metric`` wins (``metric: null`` == 0).
    5. Action: ``deliver`` → return ``destination`` (RELAY's ``next ==
       destination`` gate then detects the terminal hop). ``forward`` → return
       ``via`` (the next intermediate hop).

    Returns ``(next, True)`` on a match, or ``(None, False)`` when the table is
    empty / fully expired / has no match — the caller falls through to
    ``no_route``/502. Reads need no caller cap (§5 — relay's internal read of
    substrate state).
    """
    tree = ctx.emit_pathway.entity_tree
    listed = tree.list_prefix(ROUTE_PREFIX)
    if not listed:
        return None, False

    now = _now_ms()
    best: dict[str, Any] | None = None
    best_exact = False

    for uri in listed:
        ent = _get_entity(ctx, uri)
        if ent is None or ent.type != ROUTE_TYPE or not isinstance(ent.data, dict):
            continue
        rd = ent.data
        match = rd.get("match")
        exact = match == destination
        dflt = match == ROUTE_MATCH_DEFAULT
        if not exact and not dflt:
            continue
        # Expiry: 0/null == never expires; skip iff past.
        exp = rd.get("expires_at")
        if isinstance(exp, int) and exp != 0 and exp <= now:
            continue
        # Cross-field validity: forward action requires via.
        if rd.get("action") == ROUTE_ACTION_FORWARD and not rd.get("via"):
            continue
        # Tie-break: prefer (exact, lower metric).
        if best is None:
            best, best_exact = rd, exact
            continue
        if exact and not best_exact:
            best, best_exact = rd, True
            continue
        if exact == best_exact and _metric(rd) < _metric(best):
            best = rd

    if best is None:
        return None, False
    action = best.get("action")
    if action == ROUTE_ACTION_DELIVER:
        # Terminal — RELAY detects ``next == destination``.
        return destination, True
    if action == ROUTE_ACTION_FORWARD:
        return best.get("via"), True
    # Unknown action — treat as no match.
    return None, False


def _metric(rd: dict[str, Any]) -> int:
    """Route metric, treating null/missing/non-int as 0 (§2 ``null = 0``)."""
    m = rd.get("metric")
    return m if isinstance(m, int) else 0


def _get_entity(ctx: HandlerContext, path: str) -> Entity | None:
    """Resolve a tree path to its bound entity (or None)."""
    h = ctx.emit_pathway.entity_tree.get(path)
    if h is None:
        return None
    return ctx.emit_pathway.content_store.get(h)
