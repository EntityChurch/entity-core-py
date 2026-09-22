"""V7 §5.2 — the `peers` grant dimension, which we parsed and never checked.

`check_permission` matches **four** axes and one grant must satisfy all of
them: `operations`, `handlers`, `peers`, and (when `execute.resource` is
present) `resources`. The peers axis is::

    target_peer = extract_peer(execute.data.uri, local_peer_id)
    peers_scope = grant.peers or {include: [local_peer_id]}
    if not matches_scope(target_peer, peers_scope, local_peer_id): continue

Two halves, and this implementation had neither: the target peer comes from
**the request URI**, not from `local_peer_id`; and an **absent** `peers` field
defaults to the local peer and is *still checked*. `system/capability/token`
has parsed the field since V6.0 — nothing ever read it.

**What that costs.** Every ordinary grant omits `peers` (none of the spec's own
examples set it), so under the old behaviour every capability this peer issued
authorized dispatch into *any* peer's namespace. `entity-core-go`'s
`authz_peers_target_from_uri` probe is a self-checking trio, and we returned
`allow` on all three rows:

===  ==============================  ==========  =====================
row  grant.peers / request uri       required    what we did
===  ==============================  ==========  =====================
P-1  ``{R}`` / ``/{R}/system/tree``  ALLOW       allow  (control)
P-2  ``{L}`` / ``/{R}/system/tree``  **DENY**    allow  (escalation)
P-3  absent / ``/{R}/system/tree``   **DENY**    allow  (escalation)
===  ==============================  ==========  =====================

P-1 is the control: without it a peer that denies everything scores two green
rows.

.. rubric:: Which seam these drive, and why it took two tries

The escalation lives on the **inbound wire** path. An in-process dispatch at a
foreign URI never reaches local authorization at all — `_is_remote_uri` routes
it to the connection pool — so a test built on `_dispatch_local_execute` proves
nothing about it.

Nor is the inner scope check the right seam. The first version of this fix
derived the target peer inside `_resolve_for_dispatch`, which runs *after*
`extract_handler_path` has stripped the peer segment: it read `system/tree`,
answered "local", and passed every row. The test agreed, because the test
handed that inner function a full URI that production never gives it — the same
argument name carrying two different representations at two call sites, which
is a law this repo already has on the books and which caught the author of the
fix rather than a reviewer.

So the default-grant case is driven over a **real connection**, and the
explicitly-scoped rows are pinned at the predicate. `target_peer` is now a
required keyword argument on `_resolve_for_dispatch` so a future call site has
to say which peer it means instead of silently inheriting a pass.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import extract_peer, grant_allows_peer
from entity_core.capability.token import Grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder

#: Syntactic but unowned — 46 Base58 chars, which is what every implementation's
#: `is_peer_id` accepts. Matching the probe's constant keeps the two comparable.
FOREIGN = "1FZfarForeignPeerRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _cap(peers: list[str] | None) -> dict:
    """A full-access grant, optionally scoped on the peers axis."""
    grant: dict = {
        "handlers": {"include": ["*"]},
        "resources": {"include": ["*", "/*/*"]},
        "operations": {"include": ["*"]},
    }
    if peers is not None:
        grant["peers"] = {"include": peers}
    return {"grants": [grant]}


class TestExtractPeer:
    def test_a_foreign_uri_names_the_foreign_peer(self, peer):
        assert extract_peer(f"entity://{FOREIGN}/system/tree", peer.peer_id) == FOREIGN
        assert extract_peer(f"/{FOREIGN}/system/tree", peer.peer_id) == FOREIGN

    def test_a_peer_relative_path_names_the_local_peer(self, peer):
        assert extract_peer("system/tree", peer.peer_id) == peer.peer_id
        assert extract_peer("*", peer.peer_id) == peer.peer_id

    def test_the_local_peers_own_absolute_uri_names_it(self, peer):
        assert extract_peer(f"entity://{peer.peer_id}/app/x", peer.peer_id) == peer.peer_id


class TestTheDefaultIsCheckedNotSkipped:
    def test_absent_peers_defaults_to_the_local_peer(self, peer):
        grant = {"handlers": {"include": ["*"]}, "operations": {"include": ["*"]}}
        assert grant_allows_peer(grant, peer.peer_id, peer.peer_id) is True
        assert grant_allows_peer(grant, FOREIGN, peer.peer_id) is False

    def test_an_explicit_wildcard_still_covers_everyone(self, peer):
        grant = {"peers": {"include": ["*"]}}
        assert grant_allows_peer(grant, FOREIGN, peer.peer_id) is True

    def test_peers_is_an_id_scope_not_a_path_scope(self, peer):
        """§5.2 F40 (0.8.1): `peers` values are literal identifiers.

        Canonicalized as a path, a peer id would become ``/{local}/{id}`` and
        match nothing — the dimension would deny everything, including the
        local peer, which is the failure mode in the other direction.
        """
        grant = {"peers": {"include": [peer.peer_id]}}
        assert grant_allows_peer(grant, peer.peer_id, peer.peer_id) is True

    def test_an_exclude_still_applies(self, peer):
        grant = {"peers": {"include": ["*"], "exclude": [FOREIGN]}}
        assert grant_allows_peer(grant, FOREIGN, peer.peer_id) is False
        assert grant_allows_peer(grant, peer.peer_id, peer.peer_id) is True


class TestTheCompositionThatBroke:
    """`_resolve_for_dispatch` sees a stripped path; the target peer must arrive
    separately, and correctly, from the caller that still has the URI."""

    def test_the_scope_check_honours_the_target_peer_it_is_given(self, peer):
        from entity_core.peer.peer import _DispatchDenied

        def resolve(capability, target_peer):
            return peer._resolve_for_dispatch(
                "system/tree", "get", capability, target_peer=target_peer,
            )

        # P-1: a foreign-scoped grant reaches the foreign namespace. The
        # control — without it, the denials below would also hold for a peer
        # that simply refuses everything.
        assert not isinstance(resolve(_cap([FOREIGN]), FOREIGN), _DispatchDenied)
        # P-2: a local-scoped grant does not.
        assert isinstance(resolve(_cap([peer.peer_id]), FOREIGN), _DispatchDenied)
        # P-3: an absent `peers` field does not.
        assert isinstance(resolve(_cap(None), FOREIGN), _DispatchDenied)
        # And the ordinary local dispatch every grant in this repo relies on.
        assert not isinstance(resolve(_cap(None), peer.peer_id), _DispatchDenied)

    def test_the_target_peer_is_required_not_defaulted(self, peer):
        """A default would mean a new call site silently gets `local` — which
        is exactly the bug, re-introduced by omission."""
        with pytest.raises(TypeError):
            peer._resolve_for_dispatch("system/tree", "get", _cap(None))


class TestOverARealConnection:
    """The seam this used to drive, and what PD-1h did to it.

    These rows were written against `authz_peers_target_from_uri`, whose P-3
    row asserted that an inbound EXECUTE naming a foreign namespace under a
    grant with no `peers` field is refused **403** by §5.2 Dimension 4. That
    was right when it was written and is wrong now, in a way worth keeping
    rather than deleting.

    **0.8.2.2 / PD-1h made the refusal earlier and different.** §1.4 requires
    an inbound EXECUTE whose handler uri names a non-local peer to be refused
    at canonicalization with **400 `invalid_request`**, and §6.5 step 3 makes
    that a *gate*: it MUST NOT be reached by stripping the peer id, resolving
    the local handler and letting §5.2 decide — which is exactly what a 403
    here would mean. So the status these rows assert had to change, and a
    403 is now a **failure**, not a pass.

    The consequence for this file is the finding, not a detail: **the peers
    dimension is no longer observable over the wire at all.** Both rows below
    now answer 400 regardless of the grant, so neither can discriminate the
    dimension any more. They are kept because they still discriminate the
    *gate* — including the case a lazy gate would get wrong, a grant that
    would have been allowed — and because a reader who finds this class
    deleted has no way to learn that the seam moved.

    Where the dimension's teeth actually live now:
    `TestTheDefaultIsCheckedNotSkipped` and `TestTheCompositionThatBroke`
    above (the predicate and the resolver), and the outbound branch measured
    in `test_peers_dimension_outbound_gap.py` — where it is currently not
    checked at all, filed as SA-PY-29. The gate itself is
    `test_dispatch_foreign_namespace_pd1.py`.
    """

    async def _serve(self, port: int, grants):
        server = (
            PeerBuilder().with_keypair(Keypair.generate())
            .with_default_handlers().with_default_grants(grants)
            .debug_mode(True).build()
        )
        await server.start("127.0.0.1", port)
        return server

    async def _statuses(self, server, port):
        """(local status, foreign status) for the same EXECUTE."""
        from entity_core.peer.connection import Connection

        conn = await Connection.connect("127.0.0.1", port, Keypair.generate())
        try:
            local = await conn.execute(
                f"entity://{server.peer_id}/system/tree", "get",
                {"data": {"path": "app/anything"}},
            )
            foreign = await conn.execute(
                f"entity://{FOREIGN}/system/tree", "get",
                {"data": {"path": "app/anything"}},
            )
            return local.status, foreign.status
        finally:
            conn.close()
            await conn.wait_closed()

    @pytest.mark.asyncio
    async def test_a_grant_without_peers_does_not_reach_a_foreign_namespace(self):
        """Formerly P-3 (403 by Dimension 4); now the gate (400 by §1.4)."""
        no_peers = [Grant.create(
            handlers=["*"], resources=["*", "/*/*"], operations=["*"],
        )]
        server = await self._serve(19077, no_peers)
        try:
            local, foreign = await self._statuses(server, 19077)
        finally:
            await server.stop()

        assert local != 403, (
            f"the control failed — the local dispatch was denied ({local}), so a "
            f"foreign denial would not be attributable to the peer segment"
        )
        assert foreign == 400, (
            f"a foreign namespace answered {foreign}; §1.4 refuses it at "
            f"canonicalization with 400. A 403 here means the refusal came "
            f"from §5.2 after resolving the local handler, which §6.5 step 3 "
            f"forbids"
        )

    @pytest.mark.asyncio
    async def test_a_wildcard_peers_grant_is_gated_too(self):
        """Formerly P-1, and this is the row that carries the weight now.

        Under `peers: ["*"]` §5.2 would **allow** this dispatch, so a peer
        that only ever refused via the authorization path answers 200 here —
        which is the PD-1 escalation, and was this peer's measured behaviour.
        The gate has to fire on a request the grant permits, or it is not a
        gate. Open-access mode used to depend on the opposite answer; §1.4
        says the address is refused regardless of what any grant permits.
        """
        wildcard = [Grant.create(
            handlers=["*"], resources=["*", "/*/*"], operations=["*"], peers=["*"],
        )]
        server = await self._serve(19078, wildcard)
        try:
            local, foreign = await self._statuses(server, 19078)
        finally:
            await server.stop()

        assert local != 400, f"control: a local handler uri was refused ({local})"
        assert foreign == 400, (
            f"a `peers: [*]` grant reached peer {FOREIGN}'s namespace (status "
            f"{foreign}) — §1.4's gate is pre-authorization and does not "
            f"consult the grant at all"
        )
