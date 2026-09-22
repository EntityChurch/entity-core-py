"""N6 (0.8.2.24) — an absent `resource` and an emptied one are DIFFERENT.

§3.3, for an operation that does **not** require a resource:

    *"a **genuinely absent** ``resource`` takes that operation's own
    absent-case behaviour (for ``system/tree:get``, the root listing — its
    specification reads "Path ending with ``/`` **or empty**: listing"), while
    a ``resource`` that is **present** and whose effective list is empty MUST
    be refused ``400 path_required`` and MUST NOT be served the absent-case
    behaviour."*

The caller named a target and its own ``exclude`` removed it. Serving the
absent-case behaviour answers the **wider** thing — §5.2's subject rule (*a
handler MUST NOT widen the set*) reached through the front door.

.. rubric:: Why every site here had it, and why no fixture could see it

The distinction was already carried: the dispatcher sets
``ctx.resource_targets`` to ``None`` when ``EXECUTE.resource`` is absent and to
a **list** when it is present, then narrows that list to the effective set
(F68). Every consumer then wrote ``if ctx.resource_targets:`` — and ``None``
and ``[]`` are both falsy, so the two empties took the same branch and fell
through to the params path.

A truthiness test on an `Optional[list]` is the `min(binding.ttl, local_max)`
shape: **a construct with no arm for one of the cases is a ruling, not a null
check.** Nothing looked wrong, because the two cases agree on every input a
person writes — you have to send a resource and exclude all of it, which
nobody does by accident.

.. rubric:: ⛔ This binds more than ``system/tree:get`` — thirteen operations

§3.3's sentence is about *"an operation"*; ``get`` is the example keystone's
vanguards happened to surface. Censused by the row's INPUT (*is this a
resource-optional operation?*) rather than by the named operation, this seat
has **thirteen** — all eight of ``system/tree``, two inbox operations and
three continuation ones:

===============================  ==========================================
site                             what the absent case falls back to
===============================  ==========================================
``system/tree`` — ALL EIGHT      ``params.path`` / ``params.prefix`` → ``""``
``system/inbox`` ×2              the handler-URI subpath
``system/continuation`` ×3       ``params.*_path``
===============================  ==========================================

**The named one is not the dangerous one**, and the first cut of this fix got
the unit wrong in a way worth recording. It placed a guard in the three tree
operations that *read* ``ctx.resource_targets`` — ``get``, ``put``,
``extract``. **Five of the eight do not read it at all**: ``snapshot``,
``diff``, ``merge``, ``create`` and ``destroy`` take their path from
``params`` unconditionally. That is SA-PY-59's class (*"the handler that takes
its path from ``params`` is reached by nothing"*) on the most-dispatched
handler in the peer — and it is exactly the params-only operations where
serving the absent-case behaviour is widest: ``snapshot``'s default prefix is
``""``, the whole tree, and ``snapshot`` is the row ``EXTENSION-TREE`` §8.4
*exempts* from the path-level check on the argument that it cannot commit to
bindings the caller may not see.

**A census keyed on *reads the field* shrinks as you fix things; a census
keyed on *is this handler's operation resource-optional* does not.** The guard
is therefore at the tree handler's ENTRY, once, ahead of the operation
dispatch — so an operation added later inherits it without knowing it exists.

``entity-core-go`` landed N6 at ``tree:get`` alone. Routed, because the
sentence is general and the six others are reachable the same way.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

QA = "data/alpha"
QB = "data/beta"

OPEN = {"grants": [{
    "handlers": {"include": ["*"]},
    "resources": {"include": ["*"]},
    "operations": {"include": ["*"]},
}]}


@pytest.fixture
def peer():
    p = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    for path in (QA, QB):
        p.emit_pathway.emit(
            path, Entity(type="t/d", data={"at": path}), EmitContext.bootstrap(),
        )
    return p


def _ctx(peer, resource_targets) -> HandlerContext:
    """``resource_targets=None`` is ABSENT; ``[]`` is PRESENT-AND-EMPTIED.

    This is the whole discriminator, and it is why no new context field was
    added: the dispatcher already distinguishes them (`peer.py` sets `None`
    unless `EXECUTE.resource` is present, then narrows the list through
    `effective_resource_targets`). A `resource_present` flag beside the list
    would be a second derivation of one fact — the F68 defect restated.
    """
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=OPEN,
        caller_capability=OPEN,
        handler_pattern="system/tree",
        emit_pathway=peer.emit_pathway,
        resource_targets=resource_targets,
    )


async def _tree(peer, operation, data, resource_targets):
    handler = peer.handlers.find_handler("system/tree")
    return await handler(
        "system/tree", operation, {"data": data}, _ctx(peer, resource_targets),
    )


class TestTheDiscriminatingVector:
    """⭐ go's vector: ``targets:[qA] exclude:[qA]`` → ``400 path_required``
    vs an absent resource → the listing.

    The dispatcher hands the handler the EFFECTIVE set, so *"targets:[qA]
    exclude:[qA]"* arrives here as ``[]``. Driving the handler with ``[]``
    drives exactly that request.
    """

    @pytest.mark.asyncio
    async def test_an_emptied_resource_is_refused_path_required(self, peer):
        r = await _tree(peer, "get", {}, [])
        assert r["status"] == 400, (
            "a request naming one target and excluding it was served the "
            "ABSENT-case behaviour — on `get` that is a listing of the tree "
            "in answer to a request for one excluded path (0.8.2.24 N6)"
        )
        assert r["result"]["data"]["code"] == "path_required"

    @pytest.mark.asyncio
    async def test_an_ABSENT_resource_still_gets_the_root_listing(self, peer):
        """The other half, and the half a "be stricter" fix breaks.

        ``system/tree:get`` does **not** require a resource — keystone's `F86`
        asked and the answer was already in `get`'s own operation table
        (*"Path ending with `/` **or empty**: listing"*). A peer that refuses
        both empties is non-conformant in the other direction.
        """
        r = await _tree(peer, "get", {}, None)
        assert r["status"] == 200
        assert r["result"]["type"] == "system/tree/listing"

    @pytest.mark.asyncio
    async def test_the_two_empties_do_not_collapse(self, peer):
        """The row that states the MUST. Asserting each arm separately still
        passes a peer that answers one thing to both inputs."""
        emptied = await _tree(peer, "get", {}, [])
        absent = await _tree(peer, "get", {}, None)
        assert emptied["status"] != absent["status"], (
            "the two empties answered the same thing — they are DISTINCT "
            "inputs with distinct remedies (§3.3, 0.8.2.24)"
        )

    @pytest.mark.asyncio
    async def test_teeth_a_NON_empty_resource_is_served_normally(self, peer):
        """Without this, every row above passes on a handler that refuses
        every request carrying a resource at all."""
        r = await _tree(peer, "get", {}, [QA])
        assert r["status"] == 200
        assert r["result"]["data"]["at"] == QA


class TestTheSitesBeyondTheNamedOne:
    """⛔ The six sites §3.3's sentence reaches and its example does not.

    A class that drove only ``get`` would read as N6 coverage and leave the
    two worst arms open — which is what makes this the row-vs-example law
    rather than extra diligence.
    """

    @pytest.mark.asyncio
    async def test_snapshot_does_not_snapshot_the_WHOLE_TREE(self, peer):
        """The worst of the eight, and the one a read-the-field census misses.

        ``_handle_snapshot`` never consults ``ctx.resource_targets`` — its
        prefix is ``params.get("prefix", "")``, i.e. **everything** — so no
        guard placed at a *reading* site could ever reach it. §8.4 exempts
        ``snapshot`` from the path-level check on the argument that it cannot
        commit to bindings the caller may not see; an emptied resource served
        as absent is that exemption's premise falsified by a request the
        caller writes itself.

        This row failed against the first cut of the fix. That failure is the
        reason the guard sits at the handler entry.
        """
        r = await _tree(peer, "snapshot", {}, [])
        assert r["status"] == 400
        assert r["result"]["data"]["code"] == "path_required"

    @pytest.mark.asyncio
    async def test_snapshot_teeth_an_absent_resource_still_snapshots(self, peer):
        r = await _tree(peer, "snapshot", {"prefix": "data/"}, None)
        assert r["status"] == 200

    @pytest.mark.asyncio
    async def test_put_does_not_fall_back_to_a_caller_supplied_params_path(
        self, peer,
    ):
        """A WRITE. The params fallback is caller-supplied, so an emptied
        resource would bind at a path the authorizer never saw — F68's shape
        reached through the absent-case door instead of the raw-list one."""
        ent = Entity(type="t/d", data={"x": 1})
        r = await _tree(peer, "put", {
            "path": "data/smuggled",
            "entity": ent.to_dict() | {"content_hash": ent.compute_hash()},
        }, [])
        assert r["status"] == 400
        assert r["result"]["data"]["code"] == "path_required"
        assert peer.emit_pathway.entity_tree.get(
            peer.emit_pathway.entity_tree.normalize_uri("data/smuggled"),
        ) is None, "the write landed anyway"

    @pytest.mark.asyncio
    async def test_put_teeth_an_absent_resource_still_writes_via_params(
        self, peer,
    ):
        """V7 §3.2's sanctioned alternative — the path may ride in params when
        no resource is given. N6 must not close that door.

        The first draft of this row sent ``{"type", "data"}`` and got a 400 —
        **the fixture was wrong, not the code**: 0.8.2.11 §6.3 makes ``put`` a
        RECEIPT path, so the submitter authors the hash and the peer does not
        (SA-PY-41). A row that had been read as *"N6 broke put"* was this
        repo's own conformance working.
        """
        ent = Entity(type="t/d", data={"x": 1})
        r = await _tree(peer, "put", {
            "path": "data/legit",
            "entity": ent.to_dict() | {"content_hash": ent.compute_hash()},
        }, None)
        assert r["status"] == 200, r


class TestTheContextStillCarriesTheDistinction:
    """Structural. The fix rests entirely on ``None`` vs ``[]`` surviving the
    dispatcher, and nothing else in the tree asserts that it does.

    If a later refactor normalizes an absent resource to ``[]`` — the obvious
    tidy-up, since every consumer treats them alike — every behavioural row
    above keeps passing in the *refusing* direction and ``tree:get`` stops
    serving the root listing at all. That failure is a 400 where a 200 is
    owed, on the most dispatched read in the peer.
    """

    def test_absent_is_None_and_emptied_is_the_empty_list(self):
        import inspect

        from entity_core.peer import peer as peer_mod

        src = inspect.getsource(peer_mod)
        assert 'resource_targets: list[str] | None = None' in src, (
            "the dispatcher no longer distinguishes an ABSENT `resource` from "
            "one that is present and emptied. That distinction IS N6's "
            "discriminator (§3.3, 0.8.2.24): `None` takes the operation's "
            "absent-case behaviour, `[]` is refused `400 path_required`. "
            "Normalizing either way silently breaks one of the two arms."
        )
