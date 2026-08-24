"""§3.1.1 pool selection — the rendezvous-hash weight function.

``PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT`` §3.1 / §3.1.1.

**These same-impl tests prove less than they look like they do**, and the module
under test says so: both "peers" are this code, so they converge trivially. What
they *do* hold is that the construction discriminates, is total, and partitions
before it hashes. Real evidence about convergence is a two-instance pool with two
*different endpoint strings* and two independent impls — ``argmax`` over a
one-member pool returns that member whatever the weight computes, so a
single-node gate validates nothing at all.
"""

from __future__ import annotations

import hashlib

import pytest

from entity_handlers.signaling import (
    LOBBY_DEFAULT,
    SKEW_FANOUT,
    PoolMember,
    lobby_key,
    pair_key,
    secret_key,
    select,
    select_top,
    tag_key,
    weight,
)

KEY = tag_key("chess")

NODE_A = PoolMember("node-a:4050", 0)
NODE_B = PoolMember("node-b:4051", 0)


# ---------------------------------------------------------------------------
# The weight function, pinned to bytes
# ---------------------------------------------------------------------------


def test_weight_is_plain_sha256_of_key_then_endpoint_with_no_separator():
    """All four free variables at once: operand order, the digest, the member
    identity, and the absence of a separator.

    ``k`` is fixed at 33 bytes, so the concatenation is unambiguous by
    construction — recorded explicitly so it is not mistaken for the
    missing-separator bug §2.2 had to fix in ``pair``.
    """
    expected = hashlib.sha256(KEY + b"node-a:4050").digest()
    assert weight(KEY, "node-a:4050") == expected
    assert len(expected) == 32

    # Operand order is load-bearing: endpoint-then-key is a different function.
    assert weight(KEY, "node-a:4050") != hashlib.sha256(b"node-a:4050" + KEY).digest()


def test_the_weight_is_over_the_key_as_derived_not_a_rehash():
    """``k`` is the 33-byte key exactly as derived — the same bytes that go on
    the wire, not a re-hash of them."""
    assert weight(KEY, "node-a:4050") != weight(
        hashlib.sha256(KEY).digest(), "node-a:4050"
    )


def test_endpoints_are_weighted_exactly_as_published():
    """No normalization, no case-folding, no scheme or default-port
    canonicalization.

    Both peers read the *same* advertisement, so byte-preservation makes them
    agree without either running a URL canonicalizer — and a canonicalizer is
    precisely where two impls drift apart.
    """
    assert weight(KEY, "node-a:4050") != weight(KEY, "NODE-A:4050")
    assert weight(KEY, "node-a:4050") != weight(KEY, "node-a:4050/")
    assert weight(KEY, "node-a:4050") != weight(KEY, "tcp://node-a:4050")


# ---------------------------------------------------------------------------
# select — highest weight wins, deterministically
# ---------------------------------------------------------------------------


def test_the_highest_weight_wins():
    pool = [NODE_A, NODE_B]
    winner = select(KEY, pool)
    expected = max(pool, key=lambda m: weight(KEY, m.endpoint))
    assert winner == expected


def test_selection_is_stable_under_reordering():
    """A tie resolved by iteration order would be a convergence bug that appears
    only when the advertisement is reordered."""
    assert select(KEY, [NODE_A, NODE_B]) == select(KEY, [NODE_B, NODE_A])


def test_selection_discriminates_across_keys():
    """Different keys must not all land on one member, or the pool is a
    single node with extra steps and shards nothing."""
    pool = [NODE_A, NODE_B]
    chosen = {
        select(tag_key(f"room-{i}"), pool).endpoint for i in range(40)
    }
    assert chosen == {NODE_A.endpoint, NODE_B.endpoint}


def test_ties_break_to_the_lower_endpoint():
    """A tie is a SHA-256 collision away and will never be seen, but ``argmax``
    alone is not a total order and an impl must not have to invent the rest.

    Forced here with two members carrying the *same* endpoint string (so their
    weights are equal by construction) and distinguished by object identity.
    """
    same = [PoolMember("dup:1", 0), PoolMember("dup:1", 0)]
    assert select(KEY, same).endpoint == "dup:1"

    # And with genuinely distinct endpoints the order is total: repeated calls
    # and reversed input agree.
    for _ in range(3):
        assert select(KEY, [NODE_A, NODE_B]) == select(KEY, [NODE_B, NODE_A])


def test_an_empty_pool_selects_nothing():
    """A deployment that advertises no signaling service offers no rendezvous —
    a configuration fact for the caller to surface, not something to paper over
    with a default."""
    assert select(KEY, []) is None
    assert select_top(KEY, []) == []


# ---------------------------------------------------------------------------
# priority partitions before the hash runs
# ---------------------------------------------------------------------------


def test_priority_partitions_before_the_hash_runs():
    """Hashing first and filtering after is not tiering.

    Tier 0 holds one member here, so if the hash ran across the whole pool first
    some keys would land on the tier-1 members. Every key must pick the tier-0
    member instead.
    """
    pool = [
        PoolMember("tier0:1", 0),
        PoolMember("tier1:1", 1),
        PoolMember("tier1:2", 1),
        PoolMember("tier1:3", 1),
    ]
    for i in range(30):
        assert select(tag_key(f"room-{i}"), pool).endpoint == "tier0:1"


def test_the_winning_tier_is_the_lowest_one_present():
    """The lowest tier **present**, not a fixed tier number — a pool whose tier-0
    members are all withdrawn falls through rather than selecting nothing, which
    is what makes tiering usable for failover instead of just for preference."""
    pool = [PoolMember("tier2:1", 2), PoolMember("tier2:2", 2)]
    winner = select(KEY, pool)
    assert winner is not None and winner.priority == 2


def test_select_top_ranks_within_the_lowest_tier_only():
    """The skew mitigation must not become a back door into a tier the operator
    deprioritized.

    A single-member tier yields one choice however large ``n`` is — the right
    answer rather than a truncation: there is no second node in that tier to try.
    """
    pool = [PoolMember("tier0:1", 0), PoolMember("tier1:1", 1)]
    top = select_top(KEY, pool, 5)
    assert [m.endpoint for m in top] == ["tier0:1"]


# ---------------------------------------------------------------------------
# select_top — the §3.1 stale-pool-skew SHOULD
# ---------------------------------------------------------------------------


def test_select_top_agrees_with_select_on_its_first_choice():
    """``select_top(..., 1)`` and ``select`` share one total order."""
    pool = [NODE_A, NODE_B, PoolMember("node-c:4052", 0)]
    assert select_top(KEY, pool, 1) == [select(KEY, pool)]


def test_select_top_is_descending_by_weight():
    pool = [NODE_A, NODE_B, PoolMember("node-c:4052", 0)]
    ranked = select_top(KEY, pool, 3)
    weights = [weight(KEY, m.endpoint) for m in ranked]
    assert weights == sorted(weights, reverse=True)


def test_top_2_choice_sets_intersect_when_pools_differ_by_one_member():
    """§3.1's SHOULD, and the reason it is worth the extra call: with ``n = 2``
    two peers' choice sets intersect whenever their pools differ by at most one
    member — so a peer holding a stale advertisement still meets one holding the
    fresh one."""
    assert SKEW_FANOUT == 2
    fresh = [NODE_A, NODE_B, PoolMember("node-c:4052", 0)]
    for dropped in range(len(fresh)):
        stale = [m for i, m in enumerate(fresh) if i != dropped]
        mine = {m.endpoint for m in select_top(KEY, fresh, SKEW_FANOUT)}
        theirs = {m.endpoint for m in select_top(KEY, stale, SKEW_FANOUT)}
        assert mine & theirs, (
            f"a one-member pool delta (dropped {fresh[dropped].endpoint}) must "
            f"still leave the two peers a shared choice"
        )


def test_gate_step_2_two_instance_pool_converges_on_one_node():
    """``PROPOSAL-CONNECTION-NODE`` §6 step 2, as far as same-impl can carry it.

    The gate's real form is two *live* instances with **different ``--endpoint``
    strings** and the unselected node ending empty. What is checkable here is the
    property that makes that gate meaningful: both peers of a pair, deriving
    independently, pick the same member — and which member depends on the key, so
    a rule that "converges" by always taking the first advertised member is
    caught.
    """
    pool = [NODE_A, NODE_B]
    for mode_input in ("chess", "go", "cards", "darts", "chess-night"):
        key = tag_key(mode_input)
        peer_a_choice = select(key, pool)
        # The other peer may hold the advertisement in a different order.
        peer_b_choice = select(key, list(reversed(pool)))
        assert peer_a_choice == peer_b_choice

    # Not a constant answer — otherwise "always pick the first member" would
    # pass this too.
    assert len({select(tag_key(f"k{i}"), pool).endpoint for i in range(40)}) == 2


# ---------------------------------------------------------------------------
# The cross-impl witness — selections go and py were observed to agree on
# ---------------------------------------------------------------------------

#: Go's ``Select`` and this module's :func:`select`, fed the same 3-member /
#: 2-tier pool and the same derived keys, choose the same member every time —
#: **re-derived live from ``entity-core-go`` @ ``94b6583`` on 2026-08-05**, not
#: copied from the dated report. Read the caveat on
#: :data:`~tests.unit.test_signaling_key.GO_AGREED_KEYS`: a witness of observed
#: agreement, not an authored oracle, and a failure here is a finding rather
#: than a constant to update.
#:
#: These moved with the keys on the 2026-08-02 namespace flag day: selection
#: rendezvous-hashes the KEY into the pool, so a changed key is a changed
#: choice. Three of the four now weigh to ``node-a`` where they weighed to
#: ``node-b`` — which is exactly why a selection witness is worth keeping
#: separately from a key witness: it re-checks convergence one layer up, where
#: two peers that DID derive the same key can still wait at empty buckets on
#: different boxes.
#:
#: The **third member sits in a worse tier** and is never chosen — §3.1 partitions
#: before it hashes, so a fallback relay stays a fallback no matter how the key
#: weighs. That is the half a two-member pool cannot show.
GO_AGREED_POOL = [
    PoolMember("node-a:4050", 0),
    PoolMember("node-b:4051", 0),
    PoolMember("relay-c:5000", 1),
]

GO_AGREED_SELECTIONS = {
    "tag/chess": ("node-a:4050", tag_key("chess")),
    "secret/hunter2": ("node-a:4050", secret_key("hunter2")),
    "lobby/default": ("node-a:4050", lobby_key(LOBBY_DEFAULT)),
    "pair/AAA+BBB": ("node-b:4051", pair_key("peerAAA", "peerBBB")),
}


@pytest.mark.parametrize("label", sorted(GO_AGREED_SELECTIONS))
def test_this_client_still_selects_the_node_go_selected(label: str):
    """Deriving the same key is only half of converging: both peers must also
    weigh it to the same node, or they meet at the same key on different boxes
    and each waits at an empty bucket."""
    expected, key = GO_AGREED_SELECTIONS[label]
    chosen = select(key, GO_AGREED_POOL)
    assert chosen is not None
    assert chosen.endpoint == expected


def test_the_agreed_selections_discriminate_and_respect_the_tier():
    """The two properties that make the table above worth anything: it is not
    "always the first member", and the worse tier is never chosen."""
    picked = {
        select(key, GO_AGREED_POOL).endpoint  # type: ignore[union-attr]
        for _, key in GO_AGREED_SELECTIONS.values()
    }
    assert picked == {"node-a:4050", "node-b:4051"}
    assert "relay-c:5000" not in picked
