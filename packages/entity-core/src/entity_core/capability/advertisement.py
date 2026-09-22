"""V7 §3 advertisement discipline — the grant-assembly filter.

A peer MUST NOT grant authority it does not advertise it serves. An
assembled entry naming a handler this peer never registered, or an
operation it does not serve, produces `404 handler_not_found` at the
dispatch boundary — the grant implied a contract the peer cannot honour,
and the caller cannot tell a withheld authority from a broken one.

.. rubric:: Two corrections to the sentence above, both landed 0.8.2.7

**It was false when written, and arch found it by reading it.** `handler_not_
found` occurred **zero** times in this tree: the dispatch boundary emitted
`not_found`. That is the L20 corollary — *a comment asserting a behaviour is
the highest-value line in a file to write a test against, because it is where
the author said what they believed* — and it took a sibling reading our source
to notice, because nothing here drove the boundary. It is true now
(`ExecuteResponse.handler_not_found`, one call site in `peer/peer.py`).

**And it is still narrower than it reads.** *"An operation it does not serve"*
is §3.3's **501** row, not this one — a handler IS registered, so the boundary
is never reached. Only the *"handler this peer never registered"* half is this
404. Worse, on a peer built with `with_default_handlers()` that half is not
reachable either: `storage_handler` is registered at `*` with priority 0, so
`_resolve_handler` never returns None. See
`tests/integration/test_status_code_slot_3_3.py::TestThe404Row`, which asserts
both facts rather than leaving this paragraph as the only record of them.

**The matching rule is pinned** (`EXTENSION-SIGNALING.md` §6.5 (b)
"Contents", arch `977667f`): an assembled entry is retained iff the peer's
advertised served-scope **covers** it on the *same four axes the chain uses
for attenuation* — handlers ∧ operations ∧ resources ∧ peers,
`entry ⊆ advertised`, with the chain's own pattern semantics
(:func:`matches_pattern`, resources :func:`canonicalize`d). An uncovered
entry is **dropped, not narrowed**. Exact-op-match and namespace-prefix
match are explicitly non-conformant: they split across the seam (one impl
drops `system/tree:put` on `foo/bar` against an advertised `foo/*`, another
keeps it), which is the latent interop bug the MUST forecloses.

Two things this deliberately does **not** do, both matching what
`entity-core-go` shipped and reasoned out (`core/protocol/connect.go`,
`coversFourAxes` / `advertisedCovers`) — reproduced here from the
consequences rather than adopted on trust; each is verified by a test in
`tests/unit/test_advertisement_filter.py`:

1. **It is not** :func:`grant_subset` **(the full attenuation relation).**
   The ruling's phrase "the same `scope_subset` relation" invites it, but
   `grant_subset` additionally enforces exclude-inheritance, constraint and
   allowance attenuation, and expiry — the rest of a *delegation* check. An
   advertisement is a statement about what this peer serves, not a parent
   capability: it carries no constraints and no allowances, so every grant
   that *has* an allowance fails against it (a child "adding an allowance
   key the parent lacks" is an attenuation violation). Running the full
   relation costs the entire `query` category, whose v7.14 entries carry
   `constraints` / `allowances` by requirement. **Four axes means four.**

2. **A universal `handlers: ["*"]` claim is carved out** — retained iff
   this peer serves anything at all. A peer's advertised scope is a finite
   set of registered handlers, so no union of advertised entries can ever
   cover `*`; under a literal "drop, not narrow" every open-access peer
   hands its counterparts exactly nothing. That is a consequence the ruling
   does not address — its worked example is a *narrower* mismatch, which is
   the divergence the four-axis relation genuinely closes. Dropping the
   universal case closes no divergence: a `*` grant dispatched at a
   registered handler works, and at an unregistered one 404s — the same
   outcome an absent grant produces, one layer later. The carve-out stands
   until arch rules (`entity-core-go` filed and routed it; this repo
   seconds it with its own measurement — see the handoff).

This governs the §4.4 inbound-dialer assembly and the §6.5 (b) reciprocal
mint **identically** — the reciprocal grant *is* the grant an inbound
dialer would receive (Q2) — so there is one filter behind one seam,
:meth:`Peer.assemble_inbound_grants`.
"""

from __future__ import annotations

from collections.abc import Callable

from entity_core.capability.checking import (
    canonicalize,
    matches_pattern,
    patterns_overlap,
)
from entity_core.capability.token import CapabilityScope, Grant


def _scope_include(scope: CapabilityScope | None) -> list[str]:
    return list(scope.include) if scope is not None else []


def _scope_exclude(scope: CapabilityScope | None) -> list[str]:
    return list(scope.exclude or []) if scope is not None else []


def _scope_covered(
    claimed: list[str],
    offered: list[str],
    excluded: list[str] | None = None,
    canon: Callable[[str], str] | None = None,
) -> bool:
    """Is every pattern the entry claims matched by one the advertisement offers
    and carved out by none it withholds?

    ``canon`` canonicalizes both sides before matching when the axis is a
    path axis (resources); handlers and operations are not paths.

    .. rubric:: The ``excluded`` arm is INERT today, and that is stated rather
       than left to be discovered

    This function read ``include`` alone until 2026-09-12 — the `G-3` shape
    (*a site that reads a scope's include and drops its exclude*) at a third
    site, found sweeping the H1 matrix past the four coordinates 0.8.2.21
    enumerates. An advertisement reading *"I serve everything except
    ``system/network``"* retained an assembled entry claiming
    ``system/network``, so the **minted** reciprocal grant handed a
    counterparty authority this peer advertises it does not serve — which is
    the one thing this module's own docstring exists to prevent.

    It was never reachable: :meth:`Peer.advertised_served_scope` builds one
    include-only entry per registered handler and has no channel for an
    exclude at all. So the arm changes no behaviour, no mutation of it
    reddens anything, and a reader would be right to ask why it is here.
    It is here because the absence is **somebody else's** invariant — an
    operator policy withholding a handler is the obvious next feature, and
    the failure mode is silent widening at mint time. Reachability is pinned
    by ``test_advertisement_filter.py::TestTheExcludeArmIsInertToday``, which
    goes red the day the scope can carry one.

    The overlap rule matches §6.3's pattern arm rather than
    :func:`matches_pattern`: a **claim** is itself a pattern, so a concrete
    withholding compared against it by string equality would carve out
    nothing — the same defect one module over.
    """
    for claim in claimed:
        if canon is not None:
            claim = canon(claim)
        matched = False
        for offer in offered:
            if canon is not None:
                offer = canon(offer)
            # `matches_pattern(pattern, uri)` — the offer is the pattern,
            # the claim is what must fall inside it.
            if matches_pattern(offer, claim):
                matched = True
                break
        if not matched:
            return False
        for withheld in excluded or []:
            if canon is not None:
                withheld = canon(withheld)
            # Drop, not narrow (the ruling's own disposition): a claim that
            # reaches into withheld space is not covered.
            if patterns_overlap(claim, withheld):
                return False
    return True


def is_universal_handler_claim(entry: Grant) -> bool:
    """Does this entry claim the whole handler space?

    The one shape no finite advertised scope can cover — see the module
    docstring's carve-out.
    """
    return "*" in _scope_include(entry.handlers)


def covers_four_axes(
    advertised: Grant,
    entry: Grant,
    local_peer_id: str,
) -> bool:
    """The ruled relation: handlers ∧ operations ∧ resources ∧ peers.

    Both sides canonicalize resources against the **local** peer-id: the
    advertised scope and the grant being assembled are both authored by
    this peer, about its own namespace, so there is one granter here —
    unlike a delegation walk, where parent and child have different
    granters (§PR-8).
    """
    if not _scope_covered(
        _scope_include(entry.handlers),
        _scope_include(advertised.handlers),
        _scope_exclude(advertised.handlers),
    ):
        return False
    if not _scope_covered(
        _scope_include(entry.operations),
        _scope_include(advertised.operations),
        _scope_exclude(advertised.operations),
    ):
        return False

    def canon(path: str) -> str:
        return canonicalize(path, local_peer_id)

    if not _scope_covered(
        _scope_include(entry.resources),
        _scope_include(advertised.resources),
        _scope_exclude(advertised.resources),
        canon,
    ):
        return False
    # The peers axis is optional on both sides. An advertisement naming no
    # peer scope constrains none; an entry naming none claims none.
    if entry.peers is not None and advertised.peers is not None:
        if not _scope_covered(
            _scope_include(entry.peers),
            _scope_include(advertised.peers),
            _scope_exclude(advertised.peers),
        ):
            return False
    return True


def advertised_covers(
    advertised: list[Grant],
    entry: Grant,
    local_peer_id: str,
) -> bool:
    """Does this peer's advertised served-scope cover ``entry``?"""
    if is_universal_handler_claim(entry):
        # Backed by construction: retained iff this peer serves anything.
        return len(advertised) > 0
    return any(covers_four_axes(adv, entry, local_peer_id) for adv in advertised)


def filter_advertised_grants(
    grants: list[Grant],
    advertised: list[Grant],
    local_peer_id: str,
) -> list[Grant]:
    """Drop every assembled entry the advertised served-scope does not cover.

    An empty ``advertised`` reads as "advertises nothing", so everything
    drops — deliberately fail-closed, including the universal carve-out.
    Passing entries through when the served-scope is unknown would
    reinstate the unfiltered behaviour exactly when we know least.
    """
    if not grants:
        return grants
    return [g for g in grants if advertised_covers(advertised, g, local_peer_id)]
