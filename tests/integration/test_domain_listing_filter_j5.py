"""§6.3's listing filter binds ANY bulk enumerator, not only the tree handler (J5).

0.8.2.22 widened the §6.3 sentence. It read *"When the **tree handler** returns
a listing"*; it now reads:

    **Listing filter.** When **any handler returns a multi-entry result whose
    entries are tree paths** — a tree listing, a domain listing, or any bulk
    enumerator — each entry MUST be individually checked using
    ``check_path_permission``. Entries for which ``check_path_permission``
    returns DENY MUST be omitted. The result's ``count`` field MUST reflect the
    filtered entry count, not the source tree's total count.

and the fold's own parenthetical names why the old wording was narrower than
its principle:

    *this rule read "When the tree handler returns a listing" while §6.8's
    discriminator is general over handlers. A domain listing is a set of
    caller-derived paths whose existence reaches the caller, so it was covered
    by the rule and not by the sentence.*

.. rubric:: What that widening costs THIS peer

`entity-core-go` reported J5 **CONFORMS** at their seat and relayed it to us as
*"same as rust"* — a behaviour-change delta to confirm. Confirmed by driving
it, per the standing rule that a routed report's claims about our repo are
hearsay: **py had a second, unfiltered enumerator, and it is the wildcard
`system/*` handler.**

``entity_handlers/system.py``'s catch-all branch (``operation == "get"`` and a
path ending ``/``) calls ``entity_tree.list_prefix(prefix)``, expands child
names, attaches each child's **content hash**, and returns
``type: "tree/listing"`` with ``count``. It is the same result type the tree
handler emits and it ran **no per-entry check and no prefix check at all**.

.. rubric:: Why this is the bulk-read disclosure re-opened, not a second copy
   of it

`H1` and the 2026-09-12 snapshot sweep closed the bulk reads on ``system/tree``
— listing, extract, snapshot — and the whole point of that sweep is that an
excluded binding must not be enumerable. This branch reaches the **same
`EntityTree`** through a different handler pattern, so a caller refused by
``system/tree:get`` on ``data/alpha`` can enumerate it, and read its content
hash, by asking ``system/*`` for ``data/`` instead. The exclude is not evaded
by re-spelling the path (SA-PY-54) or by an unmatchable pattern (SA-PY-52) —
it is evaded by **re-routing to a handler the sweep did not enumerate**, which
is the SA-PY-59 shape (*"a cell table measures a MATCHER; it does not measure
whether the matcher is REACHED"*) with a listing rather than a revision op.

.. rubric:: Why no instrument in the cohort could see it

go's `exclude_matrix` drives ``listing_cap_filter`` / ``extract_cap_filter`` /
``snapshot_diff_no_leak`` — all three against **`system/tree`**, because that
is the handler the rule named when the vectors were written. A vector set
keyed on the handler that owns the rule cannot discriminate a peer whose
*other* handler answers the same question. And locally every listing test in
this tree drives ``system/tree`` for the same reason, so landing the filter
here reddened nothing among 4641.

The rows below are therefore written against the **`system/*`** handler
deliberately, and :class:`TestTheTreeHandlerControl` keeps the ``system/tree``
arm beside them as the **non-discriminator** — it passed before this fix and
after it, and a reader counting rows would otherwise read it as coverage.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

#: The excluded child sorts before the visible one, matching
#: ``test_bulk_read_per_entry_filter_6_3.py`` so the two files' fixtures are
#: comparable at a glance.
EXCLUDED = "data/alpha"
VISIBLE = "data/zulu"

OPEN = {"grants": [{
    "handlers": {"include": ["*"]},
    "resources": {"include": ["*"]},
    "operations": {"include": ["*"]},
}]}

#: The caller: everything under ``data/`` **except** one child. Identical to
#: the shape the tree-handler filter is already driven at, so any difference in
#: outcome is attributable to the handler that answered and to nothing else.
SCOPED = {"grants": [{
    "handlers": {"include": ["*"]},
    "operations": {"include": ["*"]},
    "resources": {"include": ["data/*"], "exclude": [EXCLUDED]},
}]}


@pytest.fixture
def peer():
    p = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    for path in (EXCLUDED, VISIBLE):
        p.emit_pathway.emit(
            path, Entity(type="t/d", data={"at": path}), EmitContext.bootstrap(),
        )
    return p


def _ctx(peer, caller: dict, handler_pattern: str) -> HandlerContext:
    """A context whose **caller** capability is the scoped one.

    ``handler_grant`` stays open: the executing handler's grant is not the
    bound under test here, and narrowing it would make every row attributable
    to two refusals at once.

    ``handler_pattern`` is passed explicitly rather than left to default.
    §6.3 (0.8.2.23) makes the frame REQUIRED and fail-closed, and a fixture
    that omits it is claiming production omits it — which the dispatcher does
    not (``peer.py`` passes ``handler_pattern=handler_pattern`` into every
    context it builds).
    """
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=OPEN,
        caller_capability=caller,
        handler_pattern=handler_pattern,
        emit_pathway=peer.emit_pathway,
    )


async def _system(peer, path: str, caller: dict, params: dict | None = None) -> dict:
    handler = peer.handlers.find_handler("system/status")
    return await handler(
        path, "get", params or {}, _ctx(peer, caller, "system/*"),
    )


async def _tree_list(peer, data: dict, caller: dict) -> dict:
    handler = peer.handlers.find_handler("system/tree")
    return await handler(
        "system/tree", "get", {"data": data}, _ctx(peer, caller, "system/tree"),
    )


def _entry_names(result: dict) -> set[str]:
    return set(result["result"]["data"]["entries"].keys())


# ---------------------------------------------------------------------------
# The domain listing — the enumerator the sweep did not reach
# ---------------------------------------------------------------------------

class TestTheDomainListingFilters:
    """``system/*``'s catch-all listing is a bulk enumerator of tree paths."""

    @pytest.mark.asyncio
    async def test_an_excluded_child_is_omitted(self, peer):
        """The headline row. Measured 200 with both children before the fix."""
        res = await _system(peer, "data/", SCOPED)
        assert res["status"] == 200
        assert _entry_names(res) == {"zulu"}, (
            "the domain listing enumerated a binding the caller's own grant "
            "excludes — the H1 bulk-read disclosure reached through the "
            "`system/*` handler instead of `system/tree`"
        )

    @pytest.mark.asyncio
    async def test_the_count_reflects_the_filtered_set(self, peer):
        """§6.3's second MUST, and it is a separate claim from the first.

        A peer that omits the entry but reports the source count has still
        disclosed that something is there.
        """
        res = await _system(peer, "data/", SCOPED)
        assert res["result"]["data"]["count"] == 1

    @pytest.mark.asyncio
    async def test_the_excluded_childs_content_hash_does_not_ride_out(self, peer):
        """Each entry carries ``hash``, so an unfiltered entry discloses the
        **content address** and not merely the name — the caller can then fetch
        it from any peer that serves content by hash."""
        res = await _system(peer, "data/", SCOPED)
        hashes = {e.get("hash") for e in res["result"]["data"]["entries"].values()}
        excluded_hash = peer.emit_pathway.entity_tree.get(
            peer.emit_pathway.entity_tree.normalize_uri(EXCLUDED),
        )
        assert excluded_hash is not None, "fixture premise: the binding exists"
        assert excluded_hash not in hashes

    @pytest.mark.asyncio
    async def test_teeth_a_broad_capability_still_sees_everything(self, peer):
        """Without this the filter could be a blanket refusal and every row
        above would pass on a peer that returns nothing at all."""
        res = await _system(peer, "data/", OPEN)
        assert _entry_names(res) == {"alpha", "zulu"}
        assert res["result"]["data"]["count"] == 2


class TestTheTreeHandlerControl:
    """Kept and LABELLED as the non-discriminator.

    This is the arm `H1` and the snapshot sweep already closed, and the arm
    every cohort vector drives. It was green before this fix and is green
    after it. It is here so the two enumerators can be compared in one file —
    **not** as evidence for the rule above.
    """

    @pytest.mark.asyncio
    async def test_the_tree_handler_already_filtered_this(self, peer):
        res = await _tree_list(peer, {"path": "data/"}, SCOPED)
        assert res["status"] == 200
        assert _entry_names(res) == {"zulu"}

    @pytest.mark.asyncio
    async def test_the_two_enumerators_now_agree(self, peer):
        """The property that makes the fix a fix rather than a second opinion.

        One tree, one caller, one exclude — two handlers. A peer where these
        disagree is disagreeing with **itself**, which is never a spec
        question (the CE-1 law).
        """
        via_system = _entry_names(await _system(peer, "data/", SCOPED))
        via_tree = _entry_names(await _tree_list(peer, {"path": "data/"}, SCOPED))
        assert via_system == via_tree
