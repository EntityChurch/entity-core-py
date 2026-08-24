"""V7 §3 advertisement discipline — the assembly filter's ruled semantics.

`EXTENSION-SIGNALING.md` §6.5 (b) "Contents" (arch `977667f`) pins the
matching rule for both the §4.4 inbound-dialer assembly and the §6.5 (b)
reciprocal mint: an assembled entry is retained iff the advertised
served-scope **covers** it on four axes — handlers ∧ operations ∧ resources
∧ peers, `entry ⊆ advertised` — with the chain's own pattern semantics, and
an uncovered entry is **dropped, not narrowed**.

Each pin below is a place two implementations could silently disagree, so
each is asserted rather than assumed.
"""

from __future__ import annotations

from entity_core.capability.advertisement import (
    advertised_covers,
    filter_advertised_grants,
    is_universal_handler_claim,
)
from entity_core.capability.token import Grant

PEER = "2KDUKVErCia4muKd9gczh2YAiCSwrf4hiW9nfHFRsYQUTJ"


def _adv(handlers: list[str], operations: list[str] | None = None) -> Grant:
    return Grant.create(
        handlers=handlers, resources=["*"], operations=operations or ["*"],
    )


def test_an_entry_naming_an_unregistered_handler_drops() -> None:
    """The discipline's whole point: never grant what we do not serve.

    The cross-peer behaviour of granting it is `404 handler_not_found` at
    the dispatch boundary, which breaks the contract the grant implied.
    """
    advertised = [_adv(["system/tree"]), _adv(["system/capability"])]
    entry = Grant.create(
        handlers=["local/files"], resources=["*"], operations=["get"],
    )
    assert not advertised_covers(advertised, entry, PEER)
    assert filter_advertised_grants([entry], advertised, PEER) == []


def test_an_entry_the_peer_serves_is_retained() -> None:
    advertised = [_adv(["system/tree"], ["get", "put"])]
    entry = Grant.create(
        handlers=["system/tree"],
        resources=["system/type/*"],
        operations=["get"],
    )
    assert advertised_covers(advertised, entry, PEER)


def test_the_matching_rule_is_pattern_match_not_prefix_or_exact() -> None:
    """The named divergence: `foo/bar` against an advertised `foo/*`.

    A namespace-prefix or exact-op matcher splits here — one impl drops
    `system/tree:put` on `foo/bar`, another keeps it — which is precisely
    the latent interop bug the MUST forecloses. Under the chain's
    `matches_pattern` the entry is covered.
    """
    advertised = [_adv(["foo/*"], ["*"])]
    entry = Grant.create(
        handlers=["foo/bar"], resources=["*"], operations=["put"],
    )
    assert advertised_covers(advertised, entry, PEER)


def test_an_operation_the_peer_does_not_serve_drops_the_entry() -> None:
    """The operations axis is consulted, not just handlers.

    Go's pre-ruling filter checked the handlers axis only, so a grant
    naming an operation the peer does not serve survived and produced its
    404 at the dispatch boundary — the failure the discipline exists to
    prevent.
    """
    advertised = [_adv(["system/tree"], ["get"])]
    entry = Grant.create(
        handlers=["system/tree"], resources=["*"], operations=["put"],
    )
    assert not advertised_covers(advertised, entry, PEER)


def test_a_grant_carrying_allowances_survives_the_filter() -> None:
    """Four axes means four — NOT the full attenuation relation.

    `grant_subset` also enforces constraint/allowance attenuation, under
    which a child "adding an allowance key the parent lacks" is a
    violation. An advertisement is a statement about what this peer serves,
    not a parent capability: it carries no allowances, so running the full
    relation would drop every `query`-category grant (v7.14 entries carry
    `constraints`/`allowances` by requirement).
    """
    advertised = [_adv(["system/query"], ["find", "count"])]
    entry = Grant.create(
        handlers=["system/query"],
        resources=["*"],
        operations=["find"],
        constraints={"type_scope": {"include": ["*"]}},
        allowances={"scope": "content_store"},
    )
    assert advertised_covers(advertised, entry, PEER)

    # And the relation it is NOT: the full delegation check rejects it.
    from entity_core.capability.delegation import grant_subset

    assert not grant_subset(
        entry.to_dict(), advertised[0].to_dict(), PEER, PEER, PEER,
    )


def test_a_universal_handler_claim_is_carved_out() -> None:
    """`handlers: ["*"]` is retained iff this peer serves anything at all.

    No finite advertised scope can cover the whole handler space, so a
    literal "drop, not narrow" deletes every open-access grant and an
    open-access peer hands its counterparts exactly nothing. The ruling's
    worked example is a *narrower* mismatch; dropping the universal case
    closes no divergence (a `*` grant dispatched at a registered handler
    works and at an unregistered one 404s — the same outcome an absent
    grant produces, one layer later). Carve-out filed and routed by
    `entity-core-go`; seconded here.
    """
    star = Grant.create(handlers=["*"], resources=["*", "/*/*"], operations=["*"])
    assert is_universal_handler_claim(star)
    assert advertised_covers([_adv(["system/tree"])], star, PEER)
    # ... and nothing at all is served → nothing is granted.
    assert not advertised_covers([], star, PEER)


def test_an_empty_advertised_scope_drops_everything() -> None:
    """Fail closed when the served-scope is unknown.

    Passing entries through when we know least would reinstate exactly the
    unfiltered behaviour the discipline removes.
    """
    entries = [
        Grant.create(handlers=["system/tree"], resources=["*"], operations=["get"]),
        Grant.create(handlers=["*"], resources=["*"], operations=["*"]),
    ]
    assert filter_advertised_grants(entries, [], PEER) == []


def test_the_peers_axis_is_optional_on_both_sides() -> None:
    """An advertisement naming no peer scope constrains none."""
    advertised = [_adv(["system/tree"])]
    entry = Grant.create(
        handlers=["system/tree"],
        resources=["*"],
        operations=["get"],
        peers=["*"],
    )
    assert advertised_covers(advertised, entry, PEER)


def test_bare_star_on_the_resource_axis_does_not_cover_cross_namespace() -> None:
    """`*` is NOT "everything" on the resource axis — it is local-only.

    V7 §5.4 canonicalization resolves bare `*` to `/{granter}/*`, and
    `covers_four_axes` canonicalizes both sides. So an advertisement
    offering `resources=["*"]` offers the LOCAL namespace and cannot cover
    an entry claiming `/*/*`. This is the trap that silently emptied the
    assembled grant set of everything except the universal carve-out.
    """
    advertised = [_adv(["system/query"], ["find", "count"])]
    entry = Grant.create(
        handlers=["system/query"],
        resources=["*", "/*/*"],
        operations=["find"],
    )
    assert not advertised_covers(advertised, entry, PEER)


def test_advertised_scope_covers_the_universal_address_space() -> None:
    """The peer serves foreign namespaces, so it must advertise them.

    `Peer.advertised_served_scope()` offers `["*", "/*/*"]` precisely so
    the resource axis is unconstraining, as its contract says. Asserted
    against the real peer rather than a hand-built advertisement, because
    the defect was in what the peer offered, not in the matching rule.
    """
    from entity_core.crypto.identity import Keypair
    from entity_core.peer.builder import PeerBuilder

    peer = (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    entry = Grant.create(
        handlers=["system/query"],
        resources=["*", "/*/*"],
        operations=["find", "count"],
        peers=["*"],
    )
    assert advertised_covers(
        peer.advertised_served_scope(), entry, peer.peer_id,
    )


def test_open_access_assembly_keeps_the_query_constraint_entry() -> None:
    """QUERY §5.5 / v7.14: the counterpart MUST receive a query-specific
    grant carrying `constraints` and `allowances`.

    `create_full_access_grant()` has always minted one, but the assembly
    filter dropped it on the resource axis, so an open-access peer handed
    its counterpart only the universal `handlers:["*"]` entry. Three
    consequences, all measured against a live peer before this was found:
    the query constraint/allowance pathway was unreachable from the wire
    (`grant_query_entry` + 2 dependents), and a delegation narrowed from
    those constraints looked like a child adding keys its parent lacked,
    so it 403'd (`deleg_narrowed_ops_find`, `deleg_add_constraint_key` +
    1 dependent). Six failures, one cause.
    """
    from entity_core.crypto.identity import Keypair
    from entity_core.peer.builder import PeerBuilder

    peer = (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    grants = peer.assemble_inbound_grants(Keypair.generate().peer_id, None)

    query_entries = [
        g for g in grants if "system/query" in list(g.handlers.include)
    ]
    assert query_entries, (
        "no query-specific grant entry survived assembly — v7.14 requires "
        "constraints/allowances on query grants"
    )
    entry = query_entries[0]
    assert entry.constraints is not None
    assert entry.allowances is not None
    assert entry.constraints["type_scope"]["include"] == ["*"]
    assert entry.allowances["scope"] == "content_store"
