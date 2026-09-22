"""The HANDLER argument of `check_path_permission` — the frame every one of
this peer's cross-handler checks supplies from the wrong source.

.. rubric:: The finding

§6.3's signature takes a ``handler_pattern`` that filters the caller's grants
before the resource scope is read. Four extensions write the argument
**literally** at the site, and they do not all write the same literal:

=========================  ==========================  =====================
site                       corpus                      what it means
=========================  ==========================  =====================
SUBSCRIPTION §2.3          ``"system/tree"``           the *read* is a tree
                                                       read; the subscribe
                                                       grant does not
                                                       authorize it
HISTORY §4.2               ``"system/tree"``           same
COMPUTE §7.2 (v3.9)        ``"system/tree"``           same
QUERY §5.2 step 6b         ``"system/query"``          the corpus's one
                                                       *own-handler* spelling
                                                       of a per-entry read
=========================  ==========================  =====================

This peer routes **every** one of them through
:py:meth:`HandlerContext.check_caller_permission`, which supplies
``self.handler_pattern`` — *the handler currently dispatching* — and has no
override. So the argument is right only where the dispatching handler happens
to be the one the corpus names, which is `system/tree` and `system/query` and
nowhere else.

.. rubric:: Why no test in this repo could see it

``handler_pattern`` defaults to ``None`` on ``HandlerContext``, and ``None``
means *do not filter by handler at all*. Every in-process fixture in this tree
builds a context without it, so every row runs with the filter disabled — the
one configuration in which the wrong frame and the right frame agree. The value
is supplied only by ``peer.py``'s two dispatch sites, i.e. only on the wire.
*A fixture is a claim about what production supplies, and this one claimed
nothing.*

And the pre-existing class for this rule
(``test_pattern_subject_at_the_handler_level_check.py``, SA-PY-56) mints
``handlers: {"include": ["*"]}`` in every row, which matches under either
frame — so it is blind for a second, independent reason.

.. rubric:: How it was found

`entity-core-go`'s ``include_payload_overlapping_exclude`` arm measured
go 403/200 · rust 403/200 · **py 403/403** and routed the divergence to arch
as an open question about §2.3's *pattern-subject* semantics (their "Q2"),
with two candidate causes: py reads the pattern check as denying any
non-concrete subject, or py qualifies the resource differently. **Neither.**
Their vector is the only one of the nine narrow-cap arms that mints a *split*
capability — a ``subscribe`` grant scoped to ``system/subscription`` and a
``get`` grant scoped to ``system/tree``, which is the shape §2.3's own prose
describes. py drops the second grant on the floor, so both the overlapping
subject and the non-overlapping control refuse, and the control's refusal is
what made the arm inconclusive rather than a FAIL.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import check_path_permission
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext
from entity_core.storage.entity_tree import EntityTree

PEER = "1" * 46

EXCLUDED = "data/secret"
VISIBLE = "data/public"

OPEN = {"grants": [{"handlers": {"include": ["*"]},
                    "resources": {"include": ["*"]},
                    "operations": {"include": ["*"]}}]}


def _grant(handlers: list[str], operations: list[str],
           include: list[str], exclude: list[str] | None = None) -> dict:
    resources: dict = {"include": include}
    if exclude is not None:
        resources["exclude"] = exclude
    return {"handlers": {"include": handlers},
            "operations": {"include": operations},
            "resources": resources}


#: The capability shape §2.3's prose describes in words: *"a caller may
#: legitimately hold `subscribe` without `get`"* — so the two are separate
#: grants, each scoped to the handler that serves it. This is also the shape
#: `entity-core-go`'s wire arm mints, and the only shape in the cohort's
#: nine narrow-cap arms that separates the two handler scopes.
def _spec_shaped_cap(exclude: list[str] | None = None) -> dict:
    return {"grants": [
        _grant(["system/subscription"], ["subscribe"], ["data/*"]),
        _grant(["system/tree"], ["get"], ["data/*"], exclude),
    ]}


# ---------------------------------------------------------------------------
# The unit the wire arm measures: the argument itself.
# ---------------------------------------------------------------------------


class TestTheArgumentIsTheDefect:
    """Driven at `check_path_permission` directly, with no handler in the way,
    so the verdict is attributable to the one argument that differs."""

    def test_the_frame_the_corpus_names_ALLOWS_the_spec_shaped_cap(self):
        """§2.3's literal fourth argument. This is what go passes."""
        assert check_path_permission(
            _spec_shaped_cap(), "get", "data/*", PEER,
            handler_pattern="system/tree",
        ) is True

    def test_the_frame_THIS_PEER_supplies_denies_it(self):
        """⭐ The defect, isolated. The dispatching handler is
        ``system/subscription``; the grant that carries ``get`` is scoped to
        ``system/tree``; filtering by the former discards the latter, and the
        caller is refused a read the corpus says it holds."""
        assert check_path_permission(
            _spec_shaped_cap(), "get", "data/*", PEER,
            handler_pattern="system/subscription",
        ) is False

    def test_the_wildcard_cap_every_existing_row_mints_cannot_tell_them_apart(self):
        """Why SA-PY-56's class is blind. Kept and **labelled as the
        non-discriminator** — four passing rows read as four rows of coverage
        unless one of them says otherwise.

        The ``None`` arm was in this loop until 0.8.2.23 and has moved to
        :py:meth:`test_an_ABSENT_frame_is_now_REFUSED`: a wildcard cap and an
        absent frame were two *independent* reasons the row could not
        discriminate, and only one of them is still a reason.
        """
        wildcard = {"grants": [_grant(["*"], ["*"], ["data/*"])]}
        for frame in ("system/tree", "system/subscription"):
            assert check_path_permission(
                wildcard, "get", "data/*", PEER, handler_pattern=frame,
            ) is True

    def test_an_ABSENT_frame_is_now_REFUSED(self):
        """⭐ **This row asserted ``is True`` until 0.8.2.23.**

        It was written to record the *second, independent* reason no in-process
        row could see SA-PY-58: ``HandlerContext.handler_pattern`` defaults to
        ``None``, ``None`` disabled the handlers filter, and every fixture in
        this tree left it there — so every existing row ran with the filter
        off, the one configuration in which the wrong frame and the right frame
        agree.

        §6.3 (0.8.2.23) closed it, and the direction matters: an absent frame
        was the **widening** arm, not a neutral one. *"Supplying nothing
        widens: a grant scoped to any handler at all authorized a tree read
        through a compute lookup."*

        Re-pointed rather than deleted — the blind spot is why this file
        exists, and a reader who finds the row gone learns nothing about why
        the default was load-bearing.
        """
        for absent in (None, ""):
            assert check_path_permission(
                _spec_shaped_cap(), "get", "data/*", PEER, handler_pattern=absent,
            ) is False


# ---------------------------------------------------------------------------
# The behaviour, through the handler, with the frame production supplies.
# ---------------------------------------------------------------------------


@pytest.fixture
def peer():
    p = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    for path in (EXCLUDED, VISIBLE):
        p.emit_pathway.emit(
            path, Entity(type="t/d", data={"at": path}), EmitContext.bootstrap(),
        )
    return p


def _ctx(peer, caller: dict, handler_pattern: str) -> HandlerContext:
    """A context carrying the handler_pattern **the wire dispatch supplies**
    (``peer.py`` sets it on both dispatch sites). Passing it is the whole
    difference between this class and every other in-process row."""
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=OPEN,
        caller_capability=caller,
        emit_pathway=peer.emit_pathway,
        handler_pattern=handler_pattern,
    )


def _deliver_token(peer) -> bytes:
    return peer.emit_pathway.content_store.put(
        Entity(type="system/capability/token", data={"grants": [{
            "handlers": {"include": ["system/inbox"]},
            "operations": {"include": ["receive"]},
            "resources": {"include": ["system/inbox/*"]},
        }]}),
    )


async def _subscribe(peer, caller: dict, pattern: str) -> dict:
    handler = peer.handlers.find_handler("system/subscription")
    return await handler("system/subscription", "subscribe", {"data": {
        "pattern": pattern,
        "events": ["created", "updated"],
        "deliver_to": {"uri": "system/inbox/probe", "operation": "receive"},
        "deliver_token": _deliver_token(peer),
        "include_payload": True,
    }}, _ctx(peer, caller, "system/subscription"))


def _code(r: dict) -> str | None:
    return r.get("result", {}).get("data", {}).get("code")


class TestSubscriptionTwoThree:
    """EXTENSION-SUBSCRIPTION §2.3, driven at the capability shape its own
    prose describes."""

    @pytest.mark.asyncio
    async def test_the_spec_shaped_cap_passes_the_read_auth_gate(self, peer):
        """⭐ go's non-overlapping control, restated in-tree. A caller holding
        exactly what §2.3 says it should hold is refused."""
        r = await _subscribe(peer, _spec_shaped_cap(), "data/public/*")
        assert _code(r) != "payload_unauthorized", (
            "a payload subscription whose cap carries `get` on a `system/tree`-"
            "scoped grant — the shape §2.3's prose describes and the shape the "
            "cohort's wire arm mints — was refused by the §2.3 read-auth check. "
            "The grant was discarded by the handler filter before its resources "
            "were ever read"
        )

    @pytest.mark.asyncio
    async def test_teeth_the_spanning_subject_is_still_refused(self, peer):
        """The security half, at the spec-shaped cap. It must stay 403 — and
        **before the fix it was 403 for the wrong reason**, which is the whole
        point of pairing it with the row above."""
        r = await _subscribe(peer, _spec_shaped_cap(exclude=[EXCLUDED]), "data/*")
        assert r["status"] == 403
        assert _code(r) == "payload_unauthorized"

    @pytest.mark.asyncio
    async def test_teeth_a_cap_with_no_tree_grant_at_all_is_refused(self, peer):
        """The cohort's `include_payload_unauthorized` arm — the *neither*
        arm. Passes on a peer with the defect and on one without it; kept as a
        control that the gate has not been deleted outright."""
        subscribe_only = {"grants": [
            _grant(["system/subscription"], ["subscribe"], ["data/*"]),
        ]}
        r = await _subscribe(peer, subscribe_only, "data/public/*")
        assert r["status"] == 403
        assert _code(r) == "payload_unauthorized"


class TestHistoryFourTwo:
    """EXTENSION-HISTORY §4.2's `check_history_access` writes the same literal
    ``"system/tree"``. Nothing in the cohort probes it — there is no
    narrow-cap history arm in any of the nine."""

    @pytest.mark.asyncio
    async def test_the_spec_shaped_cap_passes_the_target_path_check(self, peer):
        handler = peer.handlers.find_handler("system/history")
        caller = {"grants": [
            _grant(["system/history"], ["query"], [VISIBLE]),
            _grant(["system/tree"], ["get"], [VISIBLE]),
        ]}
        r = await handler(
            "system/history", "query", {"data": {"path": VISIBLE}},
            _ctx(peer, caller, "system/history"),
        )
        assert _code(r) != "access_denied", (
            "history `query` refused a caller holding §4.2's own shape — "
            "`get` on the target path under a `system/tree` grant"
        )

    @pytest.mark.asyncio
    async def test_teeth_a_caller_with_no_tree_read_is_still_refused(self, peer):
        handler = peer.handlers.find_handler("system/history")
        caller = {"grants": [_grant(["system/history"], ["query"], [VISIBLE])]}
        r = await handler(
            "system/history", "query", {"data": {"path": VISIBLE}},
            _ctx(peer, caller, "system/history"),
        )
        assert r["status"] == 403
        assert _code(r) == "access_denied"


class TestComputeLookupTreeIsTheWIDENING_direction:
    """EXTENSION-COMPUTE §7.2's ``compute/lookup/tree`` block writes
    ``"system/tree"`` on the line directly above ``ctx.entity_tree.get(path)``,
    and `entity-core-go` writes it at the same site (``ext/compute/eval.go``).

    This peer's ``EvalContext.check_read_permission`` **omitted** the argument,
    which is not the same mistake as the two above: omitting passes ``None``,
    and ``None`` disables grant filtering entirely. So this site was *wider*
    than the corpus, not narrower — a grant scoped to any handler at all
    authorized a compute tree read.

    Recorded because the fix **reddened nothing** in 4622 tests: every compute
    fixture in this tree mints ``handlers: ["*"]``, so the argument had never
    been observable. That is the finding, not a shortfall in the rows — these
    two are the configuration that makes it observable.
    """

    def _drive(self, cap: dict):
        from entity_handlers.compute import Budget, EvalContext, Scope, evaluate

        tree = EntityTree(PEER)
        store = ContentStore()
        tree.set(tree.normalize_uri(VISIBLE),
                 store.put(Entity(type="t/d", data={"at": VISIBLE})))
        ctx = EvalContext(
            content_store=store, entity_tree=tree, local_peer_id=PEER,
            capability=cap, included={}, has_content_store_access=True,
        )
        expr = Entity(type="compute/lookup/tree", data={"path": VISIBLE})
        return evaluate(expr, Scope(), Budget(), ctx)

    def test_a_COMPUTE_scoped_grant_no_longer_authorizes_a_tree_read(self):
        """⭐ The widening, closed."""
        from entity_handlers.compute import ERR_PERMISSION_DENIED, is_error

        r = self._drive({"grants": [_grant(["system/compute"], ["get"], ["data/*"])]})
        assert is_error(r)
        assert r["data"]["code"] == ERR_PERMISSION_DENIED

    def test_teeth_a_TREE_scoped_grant_still_does(self):
        """The control that keeps the row above from passing on a peer that
        simply refuses every compute tree read."""
        from entity_handlers.compute import is_error

        r = self._drive({"grants": [_grant(["system/tree"], ["get"], ["data/*"])]})
        assert not is_error(r), r


class TestQueryIsTheOneSiteTheCorpusFramesDIFFERENTLY:
    """EXTENSION-QUERY §5.2 step 6b writes ``"system/query"``, not
    ``"system/tree"`` — the corpus's single own-handler spelling of a per-entry
    read filter.

    This peer follows the pseudocode; **`entity-core-go` writes
    ``"system/tree"`` at the same site** (`ext/query/handler.go`). Both are
    faithful to a sentence in QUERY: §5.2's code says one thing and §747's
    prose says *"same pattern as tree listing"*, which is the other. Routed —
    and pinned here so a sweep that "fixes the class everywhere" cannot move
    this site without arguing for it.

    The cohort's ``query_bulk_read_cap_filter`` arm cannot see the divergence:
    it mints ONE grant whose handlers scope names **both** ``system/query`` and
    ``system/tree``, so it matches under either frame.
    """

    def test_this_peer_reads_the_pseudocode_literally(self):
        query_scoped = {"grants": [_grant(["system/query"], ["get"], ["data/*"])]}
        assert check_path_permission(
            query_scoped, "get", VISIBLE, PEER, handler_pattern="system/query",
        ) is True

    def test_and_a_tree_scoped_grant_does_NOT_satisfy_it_here(self):
        """The half that differs from go. Not asserted as correct — asserted as
        *measured*, with the filing named, so the next reader does not
        re-derive it."""
        tree_scoped = {"grants": [_grant(["system/tree"], ["get"], ["data/*"])]}
        assert check_path_permission(
            tree_scoped, "get", VISIBLE, PEER, handler_pattern="system/query",
        ) is False, (
            "if this flips, the QUERY §5.2-vs-§747 divergence has been ruled "
            "or silently swept — see SA-PY-57"
        )

    def test_the_cohort_vectors_grant_matches_under_BOTH_frames(self):
        """Why no wire arm discriminates it."""
        both = {"grants": [
            _grant(["system/query", "system/tree"], ["find", "count", "get"], ["data/*"]),
        ]}
        for frame in ("system/query", "system/tree"):
            assert check_path_permission(
                both, "get", VISIBLE, PEER, handler_pattern=frame,
            ) is True
