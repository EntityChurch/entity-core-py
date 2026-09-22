"""The eight `system/revision` operations that authorize nothing.

.. rubric:: The finding

`EXTENSION-REVISION` has nineteen handler operations. This peer calls
``check_caller_permission`` on **eight** of them; `entity-core-go` calls
``CheckPathCapability`` on **sixteen**. The eight with no check here are

===================  ==============================================
operation            what it hands back
===================  ==============================================
``log``              the version history of any prefix
``status``           head + pending state of any prefix
``diff``             every added/removed/modified **path and content
                     hash** between two versions of any prefix
``fetch``            versions of any prefix
``fetch-entities``   **entity bodies**, by hash
``branch``           creates/deletes a ref under any prefix (write)
``tag``              creates/deletes a tag under any prefix (write)
``push``             writes versions into any prefix (write)
===================  ==============================================

.. rubric:: Why the dispatch-level check does not cover them

The revision handler reads ``ctx.resource_targets`` **zero times** — measured,
and asserted below. Every prefix comes from ``params.prefix``. §5.2's
resource-scope check is conditioned on ``resource_target is not null``, so a
caller that simply omits the ``resource`` field on its EXECUTE reaches the
handler with *nothing* having looked at a path, and the handler then takes the
prefix from the caller's own params. V7's standing invariant — *the tree
handler's path comes from* ``resource.targets[0]``, *not* ``params.data.path``
— is exactly this rule, and this is the largest surface in the peer that does
not follow it.

The eight ops that **do** check are the reason this is invisible: they pass
``params.prefix`` to ``check_caller_permission``, which is the correct
behaviour, so the file reads as authorized. The defect is not a wrong check —
it is eleven operations with no check and eight with one, in one dispatch
table, sorted by nothing.

.. rubric:: Why no arm in the cohort's sweep reaches it

`entity-core-go`'s nine narrow-cap exclude arms are the first vectors in the
cohort to drive a **narrow** capability at all — and all nine drive
``system/tree``, ``system/query`` and ``system/subscription``. No conformance
category anywhere drives a revision operation under a cap that does not
already cover the prefix, so every revision row in the 1653-check gate runs
under the broad connection cap: *the one shape where the correct and the
buggy authorization answers agree*, which is the gap go's own headline names.
"""

from __future__ import annotations

import pytest

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.storage.tree_registry import TreeRegistry
from entity_handlers.revision import revision_handler

PEER = "test-peer"

#: The prefix the caller legitimately holds.
MINE = "app/"
#: The prefix it does not.
THEIRS = "secret/"

OPEN = {"grants": [{"handlers": {"include": ["*"]},
                    "resources": {"include": ["*"]},
                    "operations": {"include": ["*"]}}]}

#: A cap granting EVERY revision operation — but only over ``app/*``. The
#: operations scope is deliberately wide: this class is about the **resource**
#: dimension, and a narrow operations scope would refuse for the other reason.
NARROW = {"grants": [{
    "handlers": {"include": ["system/revision"]},
    "operations": {"include": ["*"]},
    "resources": {"include": [f"{MINE}*", MINE]},
}]}


@pytest.fixture
def env():
    tree = EntityTree(PEER)
    store = ContentStore()
    ep = EmitPathway(store, tree)
    registry = TreeRegistry(tree, store)
    for path in (f"{THEIRS}doc", f"{MINE}doc"):
        ep.emit(path, Entity(type="t/d", data={"at": path}))
    return ep, registry


def _ctx(env, capability: dict) -> HandlerContext:
    ep, registry = env
    return HandlerContext(
        local_peer_id=PEER,
        remote_peer_id="remote-peer",
        handler_grant=OPEN,
        caller_capability=capability,
        emit_pathway=ep,
        tree_registry=registry,
        # What the wire dispatch supplies. Note there is no `resource_targets`
        # here, and that is the point: a caller omits the field and §5.2's
        # resource arm never runs.
        handler_pattern="system/revision",
    )


async def _run(env, capability, operation, **params):
    return await revision_handler(
        "system/revision", operation, {"data": params}, _ctx(env, capability),
    )


async def _commit_theirs(env) -> str:
    r = await _run(env, OPEN, "commit", prefix=THEIRS)
    assert r["status"] == 200, r
    return r["result"]["data"]["version"]


class TestTheRevisionHandlerNeverReadsTheResourceField:
    """The structural half. A reviewer reading any single operation sees a
    correct-looking `params.get("prefix")`; what they cannot see is that the
    field V7 says the path comes from is read **nowhere in the module**."""

    def test_the_module_reads_resource_targets_zero_times(self):
        import inspect

        import entity_handlers.revision as rev

        src = inspect.getsource(rev)
        assert "resource_targets" not in src, (
            "the revision handler now reads `ctx.resource_targets` — if that "
            "is deliberate, the per-operation prefix sources below need "
            "re-deriving, because they were all `params.prefix`"
        )


class TestTheEightUncheckedOperations:
    """⭐ Each row drives an operation at a prefix the caller's capability does
    not cover, with the prefix supplied in ``params`` and no ``resource`` field
    on the request — the shape §5.2's resource arm cannot see."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation,params", [
        ("log", {}),
        ("status", {}),
        ("fetch", {}),
        ("fetch-entities", {"hashes": []}),
        ("branch", {"action": "list"}),
        ("tag", {"action": "list"}),
    ])
    async def test_a_read_or_ref_op_at_a_foreign_prefix_is_refused(
        self, env, operation, params,
    ):
        await _commit_theirs(env)
        r = await _run(env, NARROW, operation, prefix=THEIRS, **params)
        assert r["status"] == 403, (
            f"`system/revision:{operation}` answered {r['status']} at prefix "
            f"{THEIRS!r} under a capability scoped to {MINE!r}. The prefix came "
            f"from params and nothing authorized it"
        )

    @pytest.mark.asyncio
    async def test_diff_at_a_foreign_prefix_is_refused(self, env):
        """The widest of the eight: `diff` returns every path AND content hash
        that changed between two versions — the same disclosure shape as the
        `snapshot` + `diff`-against-empty composition the cohort's
        `snapshot_diff_no_leak` arm exists for, reached through a handler that
        arm does not touch."""
        v1 = await _commit_theirs(env)
        ep, _ = env
        ep.emit(f"{THEIRS}doc2", Entity(type="t/d", data={"at": "2"}))
        v2 = await _commit_theirs(env)

        r = await _run(env, NARROW, "diff", prefix=THEIRS, base=v1, target=v2)
        assert r["status"] == 403, (
            f"`system/revision:diff` answered {r['status']} at a foreign "
            f"prefix; result={r.get('result', {}).get('data')}"
        )

    @pytest.mark.asyncio
    async def test_push_at_a_foreign_prefix_is_refused(self, env):
        """A write. `push` installs versions into a prefix."""
        v1 = await _commit_theirs(env)
        r = await _run(env, NARROW, "push", prefix=THEIRS, remote="peer-x", versions=[v1])
        assert r["status"] == 403, (
            f"`system/revision:push` answered {r['status']} at a foreign prefix"
        )


class TestTheThreeBOTH_SEATS_LEAVE_UNCHECKED:
    """The cohort half. With the eight above landed this peer checks **16 of
    19**, which is exactly `entity-core-go`'s count — and the three neither
    seat checks are the same three:

    ``find-ancestor`` · ``config`` · ``merge-config``

    Two of them are **writes to the revision configuration of a prefix**, and
    `merge-config` is not an ordinary write: §5.1's `pattern` -> strategy map
    decides which side wins a merge, which decides the merged bytes, which
    decides the version root. An unauthorized `merge-config` at a foreign
    prefix is an integrity hole, not a disclosure one. ``find-ancestor``
    discloses DAG structure.

    **Two ground-up seats converging is evidence about implementers, not about
    the text** — `EXTENSION-REVISION` has no §-level statement of which of its
    nineteen operations are path-authorized, and both seats derived the set
    operation-by-operation and landed on the same 16. Routed rather than
    unilaterally closed: refusing where go accepts manufactures the divergence
    this repo exists to find. These rows assert **today's measured answer** and
    carry their own retirement condition.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation,params", [
        ("find-ancestor", {"a": "x", "b": "y"}),
        ("config", {}),
        ("merge-config", {"action": "list"}),
    ])
    async def test_is_NOT_path_authorized_at_either_seat_today(
        self, env, operation, params,
    ):
        await _commit_theirs(env)
        r = await _run(env, NARROW, operation, prefix=THEIRS, **params)
        assert r["status"] != 403, (
            f"`system/revision:{operation}` now refuses a foreign prefix. If "
            f"that is deliberate, check `entity-core-go` still agrees before "
            f"shipping it — the two seats were converged at 16/19 and this row "
            f"exists so the 17th is a decision and not a drift (SA-PY-59)"
        )


class TestTeethTheNarrowCapIsActuallyNarrow:
    """Controls. Without these, every row above passes on a peer that refuses
    every revision operation outright, and the class would be measuring the
    fixture rather than the gate."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", ["log", "status", "branch", "tag"])
    async def test_the_same_operation_at_the_callers_OWN_prefix_is_allowed(
        self, env, operation,
    ):
        await _run(env, OPEN, "commit", prefix=MINE)
        params = {"action": "list"} if operation in ("branch", "tag") else {}
        r = await _run(env, NARROW, operation, prefix=MINE, **params)
        assert r["status"] != 403, (
            f"`{operation}` refused the caller's OWN prefix — the fix is "
            f"over-refusing, which is a denial of service wearing a security "
            f"fix's clothes"
        )

    @pytest.mark.asyncio
    async def test_an_op_this_peer_ALREADY_checked_refuses_the_foreign_prefix(
        self, env,
    ):
        """`commit` is one of the eight that always carried a check. It is the
        proof that the capability shape in this file is a refusing one, so the
        rows above are attributable to their own operations."""
        r = await _run(env, NARROW, "commit", prefix=THEIRS)
        assert r["status"] == 403
