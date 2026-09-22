"""SA-PY-29 — where the §5.2 `peers` dimension is still live, and where it is not.

0.8.2.3 pins the §6.2 default per-handler self-grant with `peers` **omitted**,
and gives the reason: *"A default-scope handler consequently **cannot**
dispatch at a foreign peer, which is the escalation that matters."* That
sentence is a claim about an enforcement point. This file measures whether the
enforcement point exists here.

It does not — on either path, and for two different reasons:

- **Inbound wire:** PD-1h now refuses a foreign handler uri at canonicalization
  with `400 invalid_request`, *before* `check_permission`. So Dimension 4 never
  runs there any more. That is correct and intended (§6.5 step 3), and it is
  what `entity-core-go` records as PD-1d #2 — the dimension is
  "unconstructible from an external wire probe".
- **In-process sub-dispatch:** `_dispatch_local_execute` routes a foreign uri
  to `_remote_execute` **before** `_resolve_for_dispatch`, so the caller's own
  grant is never consulted on the outbound branch. `target_peer` is computed
  after that return, which means it can only ever be the local peer.

So the ruled grant shape is **inert in this peer**: omitting `peers` changes
what the grant says and nothing about what the peer permits.

.. rubric:: Why this is filed rather than fixed

`entity-core-go` has the identical gap and wrote it down first — spec-issue
`2026-08-23-a`, *"the handler-grant ceiling runs only on the local branch of
`makeLocalExecute`: a cross-peer URI returns at `d.RemoteExecute(...)` before
the `CheckPermission` call … Dimension 4 of this grant is not a live decision
in go today"*, and they asked arch for *"a conformance vector that can
actually observe the dimension (i.e. one that reaches the ceiling with a
cross-peer uri)"*. 0.8.2.3 ruled the **grant shape** and did not add that
vector or say where the outbound check binds.

Inventing the check here would refuse a sub-dispatch that go permits —
manufacturing a cross-impl divergence out of a spec gap, which is the trade
SA-PY-24 already declined. So the gap is pinned as behaviour and routed.

**These rows are written to FAIL when the enforcement point lands.** That is
deliberate: the retirement condition is written into each assertion message,
so nobody has to re-derive whether the pin is still owed.
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import create_default_handler_self_grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder

FOREIGN = "1FZfarForeignPeerRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"


@pytest.fixture
def peer():
    return (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_all_handlers().build()
    )


def _default_scope_capability() -> dict:
    """Exactly what §6.2 gives a handler that declares no scope."""
    return {"grants": [g.to_dict() for g in create_default_handler_self_grant()]}


class TestTheDimensionIsLiveAtThePredicate:
    """The half that IS enforced, asserted first so the gap below is scoped.

    `grant_allows_peer` is correct and `_resolve_for_dispatch` honours the
    `target_peer` it is handed. Nothing in this file says otherwise — the
    finding is about which values ever reach them.
    """

    def test_the_default_grant_denies_a_foreign_peer_at_the_predicate(self, peer):
        from entity_core.capability.checking import grant_allows_peer

        grant = create_default_handler_self_grant()[0].to_dict()
        assert grant_allows_peer(grant, peer.peer_id, peer.peer_id) is True
        assert grant_allows_peer(grant, FOREIGN, peer.peer_id) is False, (
            "the ruled default no longer denies a foreign peer at the "
            "predicate — that is the one place this dimension does work"
        )

    def test_and_the_resolver_honours_it_when_handed_a_foreign_target(self, peer):
        from entity_core.peer.peer import _DispatchDenied

        denied = peer._resolve_for_dispatch(
            "system/tree", "get", _default_scope_capability(),
            target_peer=FOREIGN,
        )
        assert isinstance(denied, _DispatchDenied), (
            "the resolver admitted a foreign target under the default grant"
        )


class TestTheValueNeverReachesIt:
    @pytest.mark.asyncio
    async def test_an_outbound_sub_dispatch_is_not_checked_against_the_grant(
        self, peer,
    ):
        """The finding. A foreign uri returns at the remote branch, so the
        caller's grant is never consulted.

        The discriminator is the *kind* of failure. If Dimension 4 ran, this
        would be a `403` decided locally with no network activity at all.
        What happens instead is a routing/transport failure — the peer tried
        to **dial** `FOREIGN`, which means it had already decided the
        dispatch was permitted.

        Measured 2026-09-01: `502 "Remote execute failed: No live transport
        profile …"`. The peer got as far as looking for a route. A 403 would
        have been decided before that; the 502 is the evidence the grant was
        never consulted, and it is why this row asserts the *absence* of 403
        rather than the presence of any particular error.
        """
        result = await peer._dispatch_local_execute(
            f"entity://{FOREIGN}/system/tree", "get", {"data": {"path": "app/x"}},
            _default_scope_capability(), None, None,
        )

        assert result.status != 403, (
            "RETIREMENT CONDITION MET — an outbound cross-peer sub-dispatch "
            "is now refused under the default self-grant. The §5.2 Dimension "
            "4 check has an enforcement point on the outbound branch; "
            "SA-PY-29 is closed and this row should be inverted into a "
            "positive assertion (and the pin removed from the SA entry)."
        )

    def test_the_target_peer_is_computed_after_the_remote_return(self, peer):
        """Why it is structural rather than a missing `if`.

        `_dispatch_local_execute` computes `target_peer` *below* the
        `_is_remote_uri` early return, so by construction the only value that
        can reach `_resolve_for_dispatch` is the local peer. A reviewer
        looking at the check alone sees a correct four-dimension call site and
        cannot see that one of its arguments is a constant.
        """
        import inspect

        from entity_core.peer.peer import Peer

        src = inspect.getsource(Peer._dispatch_local_execute)
        remote_return = src.index("return await self._remote_execute(")
        target_peer_read = src.index("target_peer = extract_peer(")

        assert remote_return < target_peer_read, (
            "RETIREMENT CONDITION MET — `target_peer` is now read before the "
            "remote branch, so the outbound path can see it. Re-check "
            "SA-PY-29: the structural reason for the gap is gone."
        )
