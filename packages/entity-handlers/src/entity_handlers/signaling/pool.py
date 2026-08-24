"""Provider selection — **which node of a pool a peer talks to**.

``PROPOSAL-REGISTRY-SERVICE-ADVERTISEMENT`` §3.1 / §3.1.1.

The rule
--------

    **Both peers of a handshake must meet at the same provider.**

It holds for *every* key mode — ``pair``, ``tag``, ``secret`` and ``lobby`` all
rendezvous-hash ``K`` into the configured pool — so provider selection is
invariant across modes, and a mismatch is a silent never-meet exactly like a
key-derivation mismatch. §3.1 pins selection per service type, and ``signaling``
is the odd one out: **client-side rendezvous-hash (MUST)**, because two peers
must meet at the *same* server for the seconds of the handshake. Not
lowest-``priority``, and never a round-robin load balancer — either one splits
the pair across servers and the punch never completes.

The weight function is pinned to bytes (§3.1.1)
-----------------------------------------------

"Highest-random-weight" is a family, not a function: two impls can each write
textbook-correct HRW — disagreeing on operand order, the digest, what identifies
a member, or how weights compare — and **split every pair**. §3.1.1 pins all
four free variables::

    weight(k, endpoint) = SHA-256( k ‖ endpoint_bytes )
    server              = argmax over the tier, weights compared lexicographically

- ``k`` is the **33-byte key exactly as derived** (§2.2) — the same bytes that go
  on the wire, not a re-hash of them.
- ``endpoint_bytes`` are the advertised string **exactly as published**: no
  normalization, no case-folding, no scheme or default-port canonicalization.
  Both peers read the *same* advertisement, so byte-preservation makes them agree
  without either running a URL canonicalizer — and a canonicalizer is precisely
  where two impls drift apart.
- **No separator**, because ``k`` is fixed at 33 bytes so the concatenation is
  unambiguous by construction. Recorded explicitly so it is not read as the
  missing-separator bug §2.2 had to fix in ``pair``.
- **Highest** weight wins; ties break to the **lower** endpoint string. A tie is
  a SHA-256 collision away and will never be seen, but ``argmax`` alone is not a
  total order and an impl must not have to invent the rest.
- A **plain SHA-256, not the substrate content-hash primitive**: a
  format-carrying digest would reintroduce the very home-format divergence §2.2
  exists to pin away.

``priority`` **partitions; it does not weight.** :func:`select` takes the lowest
``priority`` tier *present* and rendezvous-hashes within it. Hashing first and
filtering after is not tiering at all.

Why a one-node deployment cannot validate any of this
-----------------------------------------------------

``argmax`` over a one-member pool returns that member *whatever the weight
computes*, so every construction agrees and a green single-node gate says
nothing. ``PROPOSAL-CONNECTION-NODE`` §6 step 2 therefore requires a
**two-instance** pool with **different endpoint strings** — two ports behind one
advertised name weigh identically and a two-member pool silently behaves as one.
The same-impl tests beside this module also prove less than they look like they
do: both "peers" are this code, so they converge trivially. What they do hold is
that the construction *discriminates* and is total.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from entity_core.utils.ecf import Hash

#: §3.1's stale-pool-skew SHOULD — "try your top-2".
SKEW_FANOUT = 2


@dataclass(frozen=True)
class PoolMember:
    """One member of a service pool, as it appears in the deployment's
    ``system/registry/service-advertisement``.

    Attributes:
        endpoint: The member's endpoint URL. This is the identity the weight is
            computed over, so it must be the **advertised** string
            byte-for-byte — a peer that normalizes it (strips a trailing slash,
            lowercases a host) weights a different string and lands on a
            different member.
        priority: Priority tier from the advertisement. **Partitions the pool
            before the hash runs** (§3.1.1). Lowest-numbered wins, MX-style —
            and it is the lowest tier **present**, not a fixed tier number, so a
            pool whose tier-0 members are all withdrawn falls through to tier 1
            rather than selecting nothing.
    """

    endpoint: str
    priority: int = 0


def weight(key: Hash, endpoint: str) -> bytes:
    """The per-member weight — ``SHA-256( k ‖ endpoint_bytes )``, pinned by §3.1.1.

    Compared as a big-endian unsigned integer, i.e. lexicographically over the
    32 digest bytes, **highest wins**. See the module docstring for why each of
    those four choices is spelled out rather than left to the implementer.
    """
    return hashlib.sha256(key + endpoint.encode("utf-8")).digest()


def _lowest_tier(pool: list[PoolMember]) -> int | None:
    """The lowest ``priority`` tier **present** in the pool. ``None`` if empty."""
    return min((m.priority for m in pool), default=None)


def _ranked(key: Hash, pool: list[PoolMember]) -> list[PoolMember]:
    """Members of the lowest tier present, in the §3.1.1 total order.

    Descending weight, then ascending endpoint — so :func:`select` and
    ``select_top(..., 1)`` always agree.
    """
    tier = _lowest_tier(pool)
    if tier is None:
        return []
    in_tier = [m for m in pool if m.priority == tier]
    # The digest compares as a big-endian unsigned integer (§3.1.1), so negating
    # that integer expresses "highest weight first" while leaving the endpoint
    # tiebreak ascending in the same single sort — a `reverse=True` would flip
    # the tiebreak too, and break-to-the-lower-endpoint is pinned.
    return sorted(
        in_tier,
        key=lambda m: (
            -int.from_bytes(weight(key, m.endpoint), "big"),
            m.endpoint,
        ),
    )


def select(key: Hash, pool: list[PoolMember]) -> PoolMember | None:
    """Pick the member both peers will independently pick for ``key``.

    **Two steps, in this order** (§3.1.1): partition to the lowest ``priority``
    tier present, *then* rendezvous-hash within it. The order matters — hashing
    first and filtering after would let the tier a peer lands in depend on the
    key, which is not tiering.

    Ties break on the endpoint string (byte-wise, lower wins) so the result is
    total and deterministic even for the vanishingly unlikely digest collision —
    a tie resolved by iteration order would be a convergence bug that appears
    only under reordering of the advertisement.

    Returns ``None`` for an empty pool: a deployment that advertises no signaling
    service offers no rendezvous, and that is a configuration fact for the caller
    to surface rather than something to paper over with a default.
    """
    ranked = _ranked(key, pool)
    return ranked[0] if ranked else None


def select_top(
    key: Hash, pool: list[PoolMember], n: int = SKEW_FANOUT
) -> list[PoolMember]:
    """The **top ``n``** members in descending weight — the §3.1 stale-pool-skew
    mitigation.

    Two peers may hold advertisements that differ by a member (one is stale, or
    the pool just scaled), in which case they rendezvous-hash to different
    servers and never meet. §3.1's SHOULD: each peer tries its **top-2** choices,
    which is cheap and covers a single-member pool delta — with ``n = 2`` the two
    peers' choice sets intersect whenever their pools differ by at most one
    member.

    **Ranks within the lowest tier only**, exactly as :func:`select` does — the
    skew mitigation must not become a back door into a tier the operator
    deprioritized. A single-member tier therefore yields one choice however large
    ``n`` is, which is the right answer rather than a truncation: there is no
    second node in that tier to try.
    """
    return _ranked(key, pool)[:n]
