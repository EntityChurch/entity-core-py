"""§6.2's default per-handler self-grant — pinned normatively at 0.8.2.3.

A handler that declares neither ``requested_scope`` nor ``internal_scope``
gets this grant, and for that handler it is not a default in the harmless
sense: it **is** its §5.2 Dimension 3 ceiling on the in-process sub-dispatch
path. *"The silent case is not the harmless case when the silent value is a
ceiling."*

The pinned shape::

    { handlers:   {include: ["*"]}
    , operations: {include: ["*"]}
    , resources:  {include: ["/*/*"]}   ; the whole LOCAL store, including
                                        ; the foreign-namespace regions it holds
    ; peers: OMITTED — defaults to {include: [local_peer_id]} (§3.6)
    }

The two dimensions pull opposite ways on purpose and the reasoning is what
these rows protect, because both halves look wrong to someone holding only one
of them:

- ``resources`` spans namespaces. A peer's store is one local address space
  keyed by peer id (§1.4), so ``/{them}/…`` is a **local** region and writing
  there is a local write. A proposal to narrow this to ``/{local}/*`` was
  **withdrawn** at 0.8.2.3 (`entity-core-go` refuted it by building it: the
  narrowing 403s a default-scope handler's follow-mirror write).
- ``peers`` is omitted, and that is where the whole network bound lives. This
  repo shipped ``peers: ["*"]`` — the spec names that *"specifically wrong …
  the one direction that must not be widened"*, because it authorizes
  sub-dispatch at foreign peers' **handlers**, an authority nobody minted.

`entity-core-go` routed the divergence as spec-issue ``2026-08-23-a`` in
August and deliberately did **not** ask rust and py to converge by count
(GUIDE-CONFORMANCE §4: one-differs → spec arbitrates, do not vote). It was
ruled in go's shape at 0.8.2.3, so what lands here is convergence on a ruling.
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import (
    create_default_handler_self_grant,
    create_full_access_grant,
)
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder


class TestThePinnedShape:
    def test_peers_is_omitted_not_wildcarded(self):
        for grant in create_default_handler_self_grant():
            d = grant.to_dict()
            assert "peers" not in d, (
                f"the default self-grant carries peers={d['peers']!r}; §6.2 "
                f"omits the field so §5.2 Dimension 4 defaults it to the "
                f"local peer. An explicit wildcard is the one widening the "
                f"spec calls out by name"
            )

    def test_resources_spans_namespaces(self):
        """The other half, asserted beside it. A reader who absorbs only the
        `peers` row above is one plausible tidy-up away from narrowing
        `resources` to match it — which is the edit 0.8.2.3 withdrew."""
        resources = [
            r
            for grant in create_default_handler_self_grant()
            for r in grant.to_dict()["resources"]["include"]
        ]
        assert "/*/*" in resources, (
            f"resources={resources!r} — §6.2 pins `/*/*`, the whole local "
            f"store including the foreign-namespace regions it holds. "
            f"Narrowing it to the local namespace 403s a default-scope "
            f"handler's follow-mirror write"
        )

    def test_handlers_and_operations_are_open(self):
        d = create_default_handler_self_grant()[0].to_dict()
        assert d["handlers"]["include"] == ["*"]
        assert d["operations"]["include"] == ["*"]


class TestTheHelperItWasSplitFrom:
    def test_full_access_still_reaches_across_peers(self):
        """`create_full_access_grant` keeps `peers: ["*"]`, and must.

        It serves two surfaces where cross-peer reach IS the point — the
        debug-mode grants handed to connecting peers, and the extension
        execute pathway that delivers notifications to remote subscribers.
        The bug was one helper carrying three different authorities, so this
        row pins the split: a later "consolidation" back onto one function
        re-widens the ceiling silently.
        """
        assert any(
            g.to_dict().get("peers", {}).get("include") == ["*"]
            for g in create_full_access_grant()
        ), "the open-access helper lost its cross-peer reach"


class TestWhatThePeerActuallyMints:
    """The seeded shape above is a claim about what the peer writes at init.

    A hand-built grant is the one claim in a test nobody re-checks, so this
    reads the grant entity out of the started peer's own tree.
    """

    @pytest.fixture
    def peer(self):
        return (
            PeerBuilder().with_keypair(Keypair.generate())
            .with_all_handlers().build()
        )

    def test_the_stored_handler_grant_omits_peers(self, peer):
        checked = 0
        for pattern in ("system/tree", "system/query"):
            path = f"system/capability/grants/{pattern}"
            bound = peer.entity_tree.get(peer.entity_tree.normalize_uri(path))
            if bound is None:
                continue
            entity = peer.content_store.get(bytes(bound))
            for grant in entity.data["grants"]:
                assert "peers" not in grant, (
                    f"the grant minted at "
                    f"system/capability/grants/{pattern} carries "
                    f"peers={grant['peers']!r} — the handler declares no "
                    f"scope, so this entity IS its Dimension 4 ceiling"
                )
                checked += 1

        assert checked, (
            "no default handler grant was found in the tree — the row read "
            "nothing and would pass against a peer that mints none"
        )
