"""§6.3's listing filter, and the three bulk reads that route around it.

Found auditing `entity-core-go`'s ``ROUTING-2026-09-11-f`` — the completed H1
sweep, whose fifth coordinate is rust's *"listings and extracts shipped every
entry under a folder regardless of the exclude."* Verified here at the line
before implementing, per the standing rule that a routed report's claims about
our repo are hearsay. All of it was live here.

.. rubric:: The rule is CORE and unconditional, not `EXTENSION-TREE` §8.2

go and rust both cite `EXTENSION-TREE` §8.2 (View Trees, Read Behavior). That
section is scoped by §12.2, which files view trees under **SHOULD** — *"when
view trees are implemented, the following are MUST"* — and **this peer
implements no view trees** (zero occurrences of ``view_tree`` in the tree).
Cited that way the obligation does not bind us at all, and a seat that checks
the citation before the behaviour closes the finding as out of scope.

`ENTITY-CORE-PROTOCOL` §6.3 states it unconditionally, three MUSTs in one
paragraph, for *the tree handler* rather than for a view:

    **Listing filter.** When the tree handler returns a listing, each entry
    MUST be individually checked against the request's capability using
    ``check_path_permission``. Entries for which ``check_path_permission``
    returns DENY MUST be omitted from the listing. The listing's ``count``
    field MUST reflect the filtered entry count, not the source tree's total
    count.

    Pagination (``offset``, ``limit``) applies to the filtered result set.
    Implementations MUST first filter entries against the request capability,
    then apply offset and limit to the filtered entries.

**The citation is the finding, not a pedantic correction.** §8.2 is a property
of a *projection* a peer MAY build; §6.3 is an obligation on the handler every
peer has. The two produce the same code and completely different answers to
*"does this bind me?"* — and the seat most likely to answer *no* is the one
without view trees, which is the seat whose listings are unfiltered.

.. rubric:: Measured here before the fix, under
   ``resources: {include: ["data/*"], exclude: ["data/alpha"]}``

=====================  ==================================================
``get`` ``data/``      both children returned, ``count`` 2
``limit: 1``           returned **the excluded child**, because pagination
                       ran over the unfiltered set
``extract data/``      the excluded entity in ``included``, verbatim
``snapshot data/``     root commits to the excluded binding, and the trie
                       **nodes** ride out in ``envelope_included`` — so the
                       caller walks the excluded key locally
=====================  ==================================================

.. rubric:: ``snapshot`` is the row neither sibling closed, and it subsumes
   the two they did

go's `77da7ea` filters ``handleListing`` and ``handleExtract``.
``handleSnapshot`` builds its trie from ``LocationIndex.List(prefix)``
unfiltered (``core/tree/operations.go``, ``handleSnapshot``), checked at the
prefix alone — and `EXTENSION-TREE` §8.4's table has **four** rows, of which
*"snapshot — captures only bindings visible through the filter"* is one. This
is the standing *walk every row of the table when a sibling reports N* law with
§8.4 as the table.

It matters more than a fourth row usually would, because ``diff`` is
**deliberately exempt** from path checks — `EXTENSION-TREE` §11's table says
*"diff: operates on stored snapshots; no path-level check"*. That exemption is
sound only if a snapshot cannot commit to bindings the caller may not see. With
an unfiltered snapshot the filtered listing and the filtered extract are both
reachable around: snapshot the prefix, diff it against an empty snapshot, read
the excluded keys out of ``removed``. :class:`TestSnapshotIsTheRowThatSubsumes`
drives exactly that.

.. rubric:: The authority is the CALLER's capability, and the corpus is not
   unanimous — SA-PY-55

§6.3's filter paragraph and §6.7's *no-read-carve-out* argument both say the
per-entry check runs against **the request's capability**. §6.8's authority
table (0.8.2.21) names *"a listing entry"* in the **handler-derived** row,
whose authority is *"the executing handler's own grant"*. Implemented the first
way: it is stated twice, it is the only reading with a security purpose (the
tree handler's own grant covers what it serves, so filtering against it removes
nothing), and §6.7 leans on it explicitly when it refuses a read carve-out.
Pinned by :meth:`TestTheAuthorityIsTheCallers.test_the_filter_reads_the_caller_capability`
so the choice is a row rather than an accident, and routed rather than settled.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

#: The excluded child sorts **before** the visible one, deliberately. With the
#: names the other way round a ``limit: 1`` request returns the visible entry
#: under either implementation, and the pagination MUST becomes untestable.
EXCLUDED = "data/alpha"
VISIBLE = "data/zulu"

OPEN_GRANTS = [{"handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]}}]
OPEN = {"grants": OPEN_GRANTS}

#: The caller: everything under ``data/`` **except** one child.
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


def _ctx(peer, caller: dict) -> HandlerContext:
    """A context whose **caller** capability is the scoped one.

    ``handler_grant`` stays open throughout: the tree handler's own grant is
    not the bound under test, and narrowing it would make every row below
    attributable to two refusals at once.
    """
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=OPEN,
        caller_capability=caller,
        # §6.3 (0.8.2.23) — the frame is REQUIRED and fail-closed, so a context
        # without one now refuses rather than matching every handler. These
        # rows drive `system/tree`'s three bulk reads, and the dispatcher
        # supplies that pattern on every context it builds (`peer.py`).
        #
        # This file's own docstring named the omission as the second reason
        # SA-PY-58 was invisible; leaving it here would have kept these rows on
        # the arm where a wrong frame and a right frame agree.
        handler_pattern="system/tree",
        emit_pathway=peer.emit_pathway,
    )


async def _tree(peer, operation: str, data: dict, caller: dict) -> dict:
    handler = peer.handlers.find_handler("system/tree")
    return await handler("system/tree", operation, {"data": data}, _ctx(peer, caller))


def _bindings_of(peer, snapshot_result: dict) -> set[str]:
    """Every relative key the snapshot root commits to.

    Walks the trie the way a **receiver** does, which is the point: the keys
    are recoverable by anyone holding the root and the nodes, so a root that
    commits to an excluded binding has disclosed it whatever the response
    envelope looks like.
    """
    from entity_core.storage.trie import collect_all_bindings

    root = snapshot_result["data"]["root"]
    return {
        key
        for key, _ in collect_all_bindings(root, "", peer.emit_pathway.content_store)
    }


# ---------------------------------------------------------------------------
# The listing — §6.3's three MUSTs
# ---------------------------------------------------------------------------

class TestTheListingFilter:
    """Each entry checked individually; ``count`` filtered; pagination after."""

    @pytest.mark.asyncio
    async def test_an_excluded_child_is_omitted(self, peer):
        """⭐ The headline. A grant covering ``data/*`` except ``data/alpha``
        must not name ``alpha`` in a listing of ``data/``."""
        r = await _tree(peer, "get", {"path": "data/"}, SCOPED)
        assert r["status"] == 200
        entries = r["result"]["data"]["entries"]
        assert "alpha" not in entries, (
            f"§6.3 — the listing named {sorted(entries)!r} under a capability "
            f"whose resources exclude {EXCLUDED!r}. The prefix check passed "
            f"(the grant does cover `data/`), and nothing then checked the "
            f"entries, so the exclude carved out nothing on the highest-volume "
            f"read the peer serves. The entry also carries the child's content "
            f"hash, so this is the entity's identity and not only its name"
        )
        assert "zulu" in entries, "the visible child must survive the filter"

    @pytest.mark.asyncio
    async def test_the_count_reflects_the_filtered_set(self, peer):
        """A ``count`` of 2 beside one entry leaks the hidden child's
        existence even once its name is gone — which is why the MUST is
        written about ``count`` separately."""
        r = await _tree(peer, "get", {"path": "data/"}, SCOPED)
        assert r["result"]["data"]["count"] == 1, (
            f"count was {r['result']['data']['count']} with "
            f"{len(r['result']['data']['entries'])} entries returned"
        )

    @pytest.mark.asyncio
    async def test_pagination_runs_over_the_filtered_set(self, peer):
        """⭐ The row that separates *filter* from *filter somewhere*.

        A peer that filters the page it has already cut answers ``limit: 1``
        with **nothing** here (the first unfiltered entry is the excluded one)
        — right in the disclosure and wrong in the result. A peer that never
        filters answers with the excluded entry itself. Only filter-then-
        paginate returns ``zulu``.
        """
        r = await _tree(peer, "get", {"path": "data/", "limit": 1}, SCOPED)
        entries = r["result"]["data"]["entries"]
        assert list(entries) == ["zulu"], (
            f"limit=1 over a prefix whose first entry is excluded returned "
            f"{list(entries)!r}; §6.3 requires the filter to run first and the "
            f"page to be cut from the filtered set"
        )

    @pytest.mark.asyncio
    async def test_teeth_a_broad_capability_still_sees_everything(self, peer):
        """Without this every row above passes on a peer that returns an empty
        listing to everyone."""
        r = await _tree(peer, "get", {"path": "data/"}, OPEN)
        entries = r["result"]["data"]["entries"]
        assert set(entries) == {"alpha", "zulu"}, f"got {sorted(entries)!r}"
        assert r["result"]["data"]["count"] == 2


class TestTheAuthorityIsTheCallers:
    """SA-PY-55 — §6.3/§6.7 say the request's capability, §6.8's table names a
    listing entry as handler-derived. The reading is a row, not an accident."""

    @pytest.mark.asyncio
    async def test_the_filter_reads_the_caller_capability(self, peer):
        """An **open** handler grant must not restore the excluded entry.

        This is the whole difference between the two readings: filtering
        against the handler's own grant (open, as every tree-handler grant is)
        removes nothing at all, so a seat implementing §6.8's table literally
        ships a filter that is vacuous by construction and passes every teeth
        control.
        """
        ctx = _ctx(peer, SCOPED)
        assert ctx.handler_grant is OPEN, "fixture premise: the handler grant is broad"
        r = await _tree(peer, "get", {"path": "data/"}, SCOPED)
        assert "alpha" not in r["result"]["data"]["entries"]


# ---------------------------------------------------------------------------
# extract — the same disclosure carrying the entity BODIES
# ---------------------------------------------------------------------------

class TestExtractFiltersItsBindings:

    @pytest.mark.asyncio
    async def test_the_excluded_entity_is_not_bundled(self, peer):
        """``extract`` ships ``included``, so the leak here is the entity
        itself rather than its name and hash."""
        r = await _tree(peer, "extract", {"prefix": "data/"}, SCOPED)
        assert r["status"] == 200
        included = r["result"]["data"]["included"]
        leaked = [
            h for h, ent in included.items()
            if ent.get("data", {}).get("at") == EXCLUDED
        ]
        assert leaked == [], (
            f"the envelope carried the entity bound at {EXCLUDED!r}, which the "
            f"caller's own capability excludes"
        )

    @pytest.mark.asyncio
    async def test_the_envelope_root_does_not_commit_to_it(self, peer):
        """§12.1's extract-completeness MUST cuts the other way once entries
        are filtered: the root is re-rooted over the visible bindings, so
        walking it reaches nothing outside ``included``."""
        r = await _tree(peer, "extract", {"prefix": "data/"}, SCOPED)
        root = r["result"]["data"]["root"]
        assert _bindings_of(peer, root) == {"zulu"}

    @pytest.mark.asyncio
    async def test_teeth_a_broad_capability_extracts_both(self, peer):
        r = await _tree(peer, "extract", {"prefix": "data/"}, OPEN)
        assert _bindings_of(peer, r["result"]["data"]["root"]) == {"alpha", "zulu"}


# ---------------------------------------------------------------------------
# snapshot — the row neither sibling closed
# ---------------------------------------------------------------------------

class TestSnapshotIsTheRowThatSubsumes:
    """`EXTENSION-TREE` §8.4: *"snapshot — captures only bindings visible
    through the filter."* Unfiltered, it routes around the two filters that
    were fixed."""

    @pytest.mark.asyncio
    async def test_the_root_commits_only_to_visible_bindings(self, peer):
        r = await _tree(peer, "snapshot", {"prefix": "data/"}, SCOPED)
        assert r["status"] == 200
        assert _bindings_of(peer, r["result"]) == {"zulu"}, (
            "the snapshot root commits to a binding the caller's capability "
            "excludes — and a root is not an opaque receipt: §3.8's walk "
            "contract is how every consumer reads one"
        )

    @pytest.mark.asyncio
    async def test_the_hoisted_trie_nodes_carry_no_excluded_key(self, peer):
        """This peer hoists the trie **nodes** into ``envelope_included`` so a
        caller can walk without round-trips. That convenience is what turns a
        committed key into a delivered one — no second request needed."""
        r = await _tree(peer, "snapshot", {"prefix": "data/"}, SCOPED)
        keys: set[str] = set()
        for node in r.get("envelope_included", {}).values():
            for entry in node.get("data", {}).get("data", []):
                if isinstance(entry, list):
                    for pair in entry:
                        if isinstance(pair, list) and pair and isinstance(pair[0], str):
                            keys.add(pair[0])
        assert "alpha" not in keys, (
            f"the hoisted trie nodes spell out {sorted(keys)!r}; the excluded "
            f"key is delivered in the response body"
        )

    @pytest.mark.asyncio
    async def test_diff_against_the_snapshot_enumerates_nothing_excluded(self, peer):
        """⭐ Why the snapshot row is not merely a fourth row.

        `EXTENSION-TREE` §11 exempts ``diff`` from path checks *"operates on
        stored snapshots; no path-level check"*. That exemption is sound only
        while a snapshot cannot commit to bindings the caller may not see —
        so an unfiltered snapshot makes the filtered listing and the filtered
        extract both reachable around, using an operation the spec says needs
        no authorization at all.
        """
        scoped = await _tree(peer, "snapshot", {"prefix": "data/"}, SCOPED)
        empty = await _tree(peer, "snapshot", {"prefix": "nothing-here/"}, OPEN)

        # `diff` keys on the SNAPSHOT entity's content hash, and a caller
        # holding one stores it — over the wire that is a `tree:put` or a
        # `content:ingest` of an entity the peer just handed them. Doing it
        # directly here keeps the row about `diff`'s exemption rather than
        # about which of the two ingest verbs is in scope.
        cs = peer.emit_pathway.content_store
        base = cs.put(Entity.from_dict(empty["result"]))
        target = cs.put(Entity.from_dict(scoped["result"]))

        d = await _tree(peer, "diff", {"base": base, "target": target}, SCOPED)
        assert d["status"] == 200
        added = d["result"]["data"].get("added", [])
        assert "alpha" not in added, (
            f"diff enumerated {added!r} from a snapshot the caller took under "
            f"a capability excluding {EXCLUDED!r} — the listing filter and the "
            f"extract filter are both bypassed, via the one operation that is "
            f"deliberately unauthorized"
        )
        assert "zulu" in added, "teeth: the visible binding must still appear"

    @pytest.mark.asyncio
    async def test_teeth_a_broad_capability_snapshots_both(self, peer):
        r = await _tree(peer, "snapshot", {"prefix": "data/"}, OPEN)
        assert _bindings_of(peer, r["result"]) == {"alpha", "zulu"}
