"""V7 §3 advertisement discipline — the grant-assembly filter.

A peer MUST NOT grant authority it does not advertise it serves. An
assembled entry naming a handler this peer never registered, or an
operation it does not serve, produces `404 handler_not_found` at the
dispatch boundary — the grant implied a contract the peer cannot honour,
and the caller cannot tell a withheld authority from a broken one.

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

from entity_core.capability.checking import canonicalize, matches_pattern
from entity_core.capability.token import CapabilityScope, Grant


def _scope_include(scope: CapabilityScope | None) -> list[str]:
    return list(scope.include) if scope is not None else []


def _scope_covered(
    claimed: list[str],
    offered: list[str],
    canon: Callable[[str], str] | None = None,
) -> bool:
    """Is every pattern the entry claims matched by one the advertisement offers?

    ``canon`` canonicalizes both sides before matching when the axis is a
    path axis (resources); handlers and operations are not paths.
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
        _scope_include(entry.handlers), _scope_include(advertised.handlers),
    ):
        return False
    if not _scope_covered(
        _scope_include(entry.operations), _scope_include(advertised.operations),
    ):
        return False

    def canon(path: str) -> str:
        return canonicalize(path, local_peer_id)

    if not _scope_covered(
        _scope_include(entry.resources),
        _scope_include(advertised.resources),
        canon,
    ):
        return False
    # The peers axis is optional on both sides. An advertisement naming no
    # peer scope constrains none; an entry naming none claims none.
    if entry.peers is not None and advertised.peers is not None:
        if not _scope_covered(
            _scope_include(entry.peers), _scope_include(advertised.peers),
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
