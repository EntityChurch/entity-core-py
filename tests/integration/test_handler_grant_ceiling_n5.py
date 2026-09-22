"""N5 (0.8.2.24) — §6.8 row 1's ceiling binds, and it is never absent.

    *"the handler is about to touch a path **in service of the caller's
    request** — one the caller named … or one the handler derived within that
    request … the authority is **the caller's verified capability (§6.7) — and
    the executing handler's own grant as an additional ceiling. Both MUST
    pass ``[MUST]``**."*

    ⛔ *"Row 1's ceiling is the executing handler's OWN GRANT, and it is never
    absent. It is **not** ``EXTENSION-TREE`` §8.5's ``max_scope``, and §8.5's
    reduction DOES NOT REDUCE THIS ROW."*

.. rubric:: Why all three ground-up seats concluded the ceiling was not owed

0.8.2.22 derived row 1 from §8.1/§8.5's dual-check and **generalized**
``max_scope`` to *the executing handler's own grant*. §8.5 carries a
**reduction** — absent ``max_scope``, the dual check reduces to the single
request-capability check — and three independent readers carried that
qualifier across with the rest of the derivation. go flagged the convergence
as *"weak, one shared sentence"* in advance, which is the cohort-consistency
discipline working, and all three were still wrong.

0.8.2.24 says what the generalization did to the qualifier: **the thing it
generalized to cannot be absent.** §6.8's dispatch-time grant validation
requires the grant entity to exist at ``system/capability/grants/{pattern}``,
treats a missing or invalid one as ``permission_denied``, and forbids falling
back to the caller's capability. A handler with no valid grant does not run,
so the ceiling is present at every dispatch and *"Both MUST pass"* always
binds.

.. rubric:: ⭐ The fixture the cohort is blocked on already exists, at two seats

Arch's §3/`KB-16`: ``N5``, `K4`/`K5`'s owner-frame arm and rust's frame vector
*"all need the same thing: a peer where the executing handler's own grant is
NARROWER than the caller's. **Nobody ships one.**"* keystone reached it from a
45-peer census (*"a core peer has one path-resource handler, so owner and
runner coincide at every reachable site"*); go reached it from 161 cross-impl
rows.

**Measured here: py ships one, and so does go.**
``system/validate/dispatch-outbound`` is registered with a narrow
``max_scope`` — ``handlers:[system/validate/echo]``, ``operations:[echo]``,
``resources:[/*/system/validate/echo]`` — per GUIDE-CONFORMANCE §7a.1's
scaffold-contract requirement, and py's own comment records it as byte-parallel
with go's ``DispatchOutboundHandler.Manifest().InternalScope``. The premise is
true of the **generated** lineage and false of the two ground-up seats that
were asked to build it.

That is the standing hearsay law on its architecture axis, and the direction is
the expensive one: a premise saying *the fixture does not exist* terminates in
a cross-repo build, and the thing being built is already here.

.. rubric:: What the ceiling was doing before: nothing, vacuously

Every handler this peer registers otherwise gets §6.2's default self-grant —
``handlers:["*"] operations:["*"] resources:["/*/*"]`` — which is wider than
any caller capability, so the conjunction is satisfied by the caller's check
alone at every reachable site. Landing N5 reddened **one row in 4350**, and
that row's fixture passed ``handler_grant={}``: *a fixture is a claim about
what production supplies, and that one claimed nothing.*
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import create_default_handler_self_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

TARGET = "data/alpha"

#: The caller: authorized for everything. The ceiling is the ONLY thing that
#: can refuse in these rows, which is what makes a refusal attributable.
CALLER_OPEN = {"grants": [{
    "handlers": {"include": ["*"]},
    "operations": {"include": ["*"]},
    "resources": {"include": ["*"]},
}]}

#: The executing handler: narrower than the caller. The configuration §6.8 row
#: 1 exists for, and the one no core peer was thought to ship.
HANDLER_NARROW = {"grants": [{
    "handlers": {"include": ["*"]},
    "operations": {"include": ["*"]},
    "resources": {"include": ["data/public/*"]},
}]}

HANDLER_DEFAULT = {"grants": [g.to_dict() for g in
                              create_default_handler_self_grant()]}


@pytest.fixture
def peer():
    p = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    for path in (TARGET, "data/public/ok"):
        p.emit_pathway.emit(
            path, Entity(type="t/d", data={"at": path}), EmitContext.bootstrap(),
        )
    return p


def _ctx(peer, *, handler_grant, caller=CALLER_OPEN) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=handler_grant,
        caller_capability=caller,
        handler_pattern="system/tree",
        emit_pathway=peer.emit_pathway,
    )


class TestBothMustPass:
    """⭐ The discriminating vector: the two authorities DISAGREE.

    The standing compose-vs-bypass law — *when a rule composes two
    authorities, the discriminating vector is the one where they disagree*.
    `caller allows + handler allows` and `caller denies + handler denies` are
    the two vectors everyone writes, and neither can tell a conjunction from
    a peer that consults the caller alone.
    """

    def test_the_handler_grant_ceilings_a_caller_the_grant_does_not_cover(
        self, peer,
    ):
        ctx = _ctx(peer, handler_grant=HANDLER_NARROW)
        assert ctx.check_caller_permission("get", TARGET) is False, (
            "the caller's capability alone authorized a path the EXECUTING "
            "HANDLER's own grant does not cover — §6.8 row 1: *the caller's "
            "verified capability AND the executing handler's own grant. Both "
            "MUST pass* (0.8.2.24 N5)"
        )

    def test_teeth_the_same_caller_on_a_path_the_ceiling_DOES_cover(
        self, peer,
    ):
        """One dimension apart. Without this the row above passes on a peer
        whose check is simply broken closed, and the refusal is attributable
        to nothing."""
        ctx = _ctx(peer, handler_grant=HANDLER_NARROW)
        assert ctx.check_caller_permission("get", "data/public/ok") is True

    def test_the_caller_is_still_checked_the_ceiling_does_not_REPLACE_it(
        self, peer,
    ):
        """Row 1's converse, and the reason the conjunction is not a swap.

        §6.8: *"Row 2 is the confused-deputy rule … Row 1 is its converse: a
        handler MUST NOT substitute its own grant for the caller's capability
        on a path whose result reaches the caller."* A peer that "implemented"
        N5 by consulting the handler grant INSTEAD of the caller's would pass
        the headline row and hand a narrow caller everything the broad
        handler grant reaches — which is the defect 0.8.2.22 named, since
        handler grants are broad by construction.
        """
        narrow_caller = {"grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["data/public/*"]},
        }]}
        ctx = _ctx(peer, handler_grant=HANDLER_DEFAULT, caller=narrow_caller)
        assert ctx.check_caller_permission("get", TARGET) is False, (
            "the broad handler grant authorized a path the CALLER's "
            "capability does not cover — the ceiling replaced the caller "
            "check instead of composing with it"
        )
        assert ctx.check_caller_permission("get", "data/public/ok") is True

    def test_an_ABSENT_handler_grant_fails_closed(self, peer):
        """*"A handler with no valid grant does not run."*

        This is the arm that makes N5's *"never absent"* clause mean
        something. A peer that read an empty grant as *"no ceiling declared,
        so no ceiling applies"* has implemented §8.5's REDUCTION — which is
        precisely the qualifier 0.8.2.24 says did not survive the
        generalization, and precisely the reading all three seats reached.
        """
        assert _ctx(peer, handler_grant={}).check_caller_permission(
            "get", TARGET,
        ) is False
        assert _ctx(peer, handler_grant={"grants": []}).check_caller_permission(
            "get", TARGET,
        ) is False


class TestTheDefaultGrantIsWhyNobodyCouldSeeThis:
    """The vacuity, asserted rather than described.

    If this stops being true the ceiling starts biting real traffic, and the
    next reader needs to know that the rule was landed against a grant that
    could not refuse anything.
    """

    def test_the_default_self_grant_ceilings_nothing_a_caller_can_reach(
        self, peer,
    ):
        ctx = _ctx(peer, handler_grant=HANDLER_DEFAULT)
        for path in (TARGET, "data/public/ok", "system/anything/at/all"):
            assert ctx.check_caller_permission("get", path) is True, path


class TestTheFixtureTheCohortIsBlockedOn:
    """⛔ `KB-16`'s premise — *"nobody ships a peer whose executing handler's
    own grant is narrower than the caller's"* — is false at this seat.

    Asserted against the registration rather than described in prose, because
    the claim is being routed back to arch, keystone and go and it should fail
    here if it ever stops being true.
    """

    def test_this_peer_ships_a_narrow_handler_grant(self):
        from entity_handlers.conformance import dispatch_outbound_narrow_grant

        grants = [g.to_dict() for g in dispatch_outbound_narrow_grant()]
        assert len(grants) == 1
        grant = grants[0]
        # Narrow on all three path/id dimensions, and `peers` omitted.
        assert grant["handlers"]["include"] == ["system/validate/echo"]
        assert grant["operations"]["include"] == ["echo"]
        assert grant["resources"]["include"] == ["/*/system/validate/echo"]
        assert "peers" not in grant

    def test_it_is_actually_REGISTERED_not_merely_defined(self):
        """A grant helper nobody calls is not a fixture.

        `with_conformance_handlers()` is what wires it, and the registration
        is what makes the narrow grant reachable on the wire — which is the
        difference between *"we have the shape"* and *"a cross-impl vector
        can drive it."*
        """
        import inspect

        from entity_core.peer import builder

        src = inspect.getsource(builder)
        assert "max_scope=dispatch_outbound_narrow_grant()" in src, (
            "system/validate/dispatch-outbound is no longer registered with "
            "its narrow max_scope. That grant is GUIDE-CONFORMANCE §7a.1's "
            "scaffold contract, it is what makes §1.4's compose-vs-bypass "
            "discriminator constructible at this seat, and it is the "
            "narrower-handler-grant fixture arch's KB-16 is blocked on."
        )
