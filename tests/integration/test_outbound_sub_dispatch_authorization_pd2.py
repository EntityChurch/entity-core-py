"""0.8.2.17 PD-2 — outbound sub-dispatch authorization, and the authority it
runs against.

**This file was `test_peers_dimension_outbound_gap.py`, and it was a pin.** It
recorded SA-PY-29: the §6.2 default handler self-grant omits `peers`, 0.8.2.3
justified that shape with the sentence *"a default-scope handler consequently
cannot dispatch at a foreign peer, which is the escalation that matters"*, and
this peer had no enforcement point that made the sentence true. The rows were
written to **fail when one landed**, with the retirement condition in each
assertion message. 0.8.2.17 landed it; the condition fired as written; the
rows are inverted here rather than deleted, so the history stays legible.

.. rubric:: The rule

`check_permission` MUST run **before a locally-originated sub-dispatch leaves
the peer**, four dimensions, `target_peer = extract_peer(uri, local_peer_id)`.
*Which* authority it runs against depends on what the sub-dispatch spends:

- **Ambient** — nothing presented, riding the executing handler's grant.
  Dimension 4 binds that grant.
- **Presented** — a capability minted **by the target** naming **this peer**
  as grantee. Its own four dimensions authorize; the handler's `peers` scope
  is not consulted.

.. rubric:: One arm is not a check

Arch states this and it is the reason the two classes below are one file: *"a
check that only exercises the refusal passes on a peer that refuses
everything."* The negative arm alone is satisfied by a peer with no outbound
dispatch at all.

.. rubric:: What discriminates the arms here, and why it is not a status pair

Both arms are driven at a peer id nothing is listening on, so an *authorized*
outbound dispatch does not succeed — it proceeds to the transport and fails
there. So the discriminator is **403 (refused before dialing) vs 502 (went
looking for a route)**, which is the same discriminator the pin used, read in
the other direction: a 502 is positive evidence that the check ran and
allowed, because the peer only looks for a route after it has decided the
dispatch is permitted.

A row asserting merely `!= 403` would pass against a peer that refuses with
some other status, so each positive row asserts the 502 and each negative row
asserts the 403.
"""

from __future__ import annotations

import inspect
import time

import pytest

from entity_core.capability.grant import (
    Grant,
    create_capability_token,
    create_default_handler_self_grant,
)
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import create_identity_entity, create_signature_entity

FOREIGN_KEYPAIR = Keypair.generate()


@pytest.fixture
def peer():
    return (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_all_handlers().build()
    )


@pytest.fixture
def target_peer_id():
    """The foreign peer every row in this file dispatches at. Derived from a
    real keypair because the presented arm has to be able to *sign* as it."""
    from entity_core.crypto.identity import peer_id_from_identity_entity

    return peer_id_from_identity_entity(
        {"data": create_identity_entity(FOREIGN_KEYPAIR).data},
    )


def _default_scope_capability() -> dict:
    """Exactly what §6.2 gives a handler that declares no scope."""
    return {"grants": [g.to_dict() for g in create_default_handler_self_grant()]}


def _grant_reaching(target_peer_id: str) -> dict:
    """A handler grant that DOES name the target in its `peers` scope."""
    return {
        "grants": [
            Grant.create(
                handlers=["*"], operations=["*"], resources=["/*/*"],
                peers=[target_peer_id],
            ).to_dict(),
        ],
    }


def _target_minted_capability(peer, target_peer_id, *, grants=None, grantee=None):
    """A credential the TARGET minted naming THIS peer as grantee — the
    presented-authority shape, built the way `MintReentryCapability` builds it.

    Returns `(capability_entity, chain)` where the chain carries the granter
    identity and the signature, as they ride in the dispatched envelope.
    """
    grantee_identity = grantee if grantee is not None else create_identity_entity(
        peer.keypair,
    )
    cap, granter_identity, signature = create_capability_token(
        FOREIGN_KEYPAIR,
        grantee_identity,
        grants or [Grant.create(
            handlers=["*"], operations=["*"], resources=["/*/*"],
        )],
    )
    return cap.to_dict(), [granter_identity.to_dict(), signature.to_dict()]


def _delegate(*, delegator_kp, parent_hash, grantee_identity, grants):
    """A child capability minted under `parent_hash` by its grantee.

    The shape `capability:delegate` produces: granter is the delegator's own
    identity, `parent` points at the capability being attenuated. Returns
    `(leaf_dict, delegator_identity_dict, signature_dict)`.
    """
    from entity_core.protocol.entity import Entity

    identity = create_identity_entity(delegator_kp)
    identity_hash = identity.compute_hash()
    leaf = Entity(
        type="system/capability/token",
        data={
            "grants": [g.to_dict() for g in grants],
            "granter": identity_hash,
            "grantee": grantee_identity.compute_hash(),
            "created_at": int(time.time() * 1000),
            "parent": parent_hash,
        },
    )
    signature = create_signature_entity(
        delegator_kp, leaf.compute_hash(), identity_hash,
    )
    return leaf.to_dict(), identity.to_dict(), signature.to_dict()


async def _dispatch(peer, target_peer_id, capability, **kw):
    return await peer._dispatch_local_execute(
        f"entity://{target_peer_id}/system/tree", "get",
        {"data": {"path": "app/x"}},
        capability, None, None, **kw,
    )


class TestTheDimensionIsLiveAtThePredicate:
    """The half that was ALWAYS enforced, asserted first so the rest is scoped.

    `grant_allows_peer` was correct and `_resolve_for_dispatch` honoured the
    `target_peer` it was handed all along. The finding was never about the
    predicate — it was about which values ever reached it.
    """

    def test_the_default_grant_denies_a_foreign_peer_at_the_predicate(
        self, peer, target_peer_id,
    ):
        from entity_core.capability.checking import grant_allows_peer

        grant = create_default_handler_self_grant()[0].to_dict()
        assert grant_allows_peer(grant, peer.peer_id, peer.peer_id) is True
        assert grant_allows_peer(grant, target_peer_id, peer.peer_id) is False

    def test_and_the_resolver_honours_it_when_handed_a_foreign_target(
        self, peer, target_peer_id,
    ):
        from entity_core.peer.peer import _DispatchDenied

        denied = peer._resolve_for_dispatch(
            "system/tree", "get", _default_scope_capability(),
            target_peer=target_peer_id,
        )
        assert isinstance(denied, _DispatchDenied)


class TestTheAmbientArm:
    """The negative arm. NEW at 0.8.2.17 and the reason this file inverted."""

    @pytest.mark.asyncio
    async def test_ambient_authority_at_a_foreign_peer_is_refused(
        self, peer, target_peer_id,
    ):
        """SA-PY-29's row, inverted.

        Measured before the fix: `502 "Remote execute failed: No live
        transport profile …"` — the peer got as far as looking for a route,
        which is what proved the grant was never consulted.
        """
        result = await _dispatch(peer, target_peer_id, _default_scope_capability())

        assert result.status == 403, (
            f"ambient authority reached a foreign peer (status={result.status}, "
            f"error={result.error!r}) — §1.4 PD-2's negative arm is unarmed, "
            "and 0.8.2.3's justification for the default grant shape is "
            "inert again"
        )
        assert "PD-2" in (result.error or "")

    @pytest.mark.asyncio
    async def test_but_a_grant_that_names_the_peer_reaches_it(
        self, peer, target_peer_id,
    ):
        """The teeth control for the negative arm: the ceiling is a *scope*,
        not a blanket refusal of outbound dispatch.

        Without this row, a peer that refuses every cross-peer sub-dispatch
        outright passes the row above.
        """
        result = await _dispatch(peer, target_peer_id, _grant_reaching(target_peer_id))

        assert result.status == 502, (
            f"a grant explicitly naming {target_peer_id[:12]}… in `peers` was "
            f"refused (status={result.status}, error={result.error!r}) — the "
            "check is refusing on something other than Dimension 4"
        )

    @pytest.mark.asyncio
    async def test_a_local_sub_dispatch_is_untouched_by_any_of_this(self, peer):
        """The default grant still authorizes local sub-dispatch, which is the
        whole point of `{include: [local_peer_id]}` being a default rather
        than an empty set."""
        result = await peer._dispatch_local_execute(
            "system/tree", "get", {"data": {"path": "app/x"}},
            _default_scope_capability(), None, None,
        )
        assert result.status != 403, result.error

    @pytest.mark.asyncio
    async def test_the_resource_dimension_binds_outbound_too(
        self, peer, target_peer_id,
    ):
        """All four dimensions, not just the fourth.

        A grant that names the target peer but not the resource must still be
        refused — otherwise `peers` is the only outbound dimension and the
        other three are decoration on this path.
        """
        capability = {
            "grants": [
                Grant.create(
                    handlers=["*"], operations=["*"],
                    resources=[f"/{target_peer_id}/app/allowed/*"],
                    peers=[target_peer_id],
                ).to_dict(),
            ],
        }
        refused = await peer._dispatch_local_execute(
            f"entity://{target_peer_id}/system/tree", "get",
            {"data": {"path": "app/x"}}, capability, None, None,
            resource_targets=[f"/{target_peer_id}/app/denied/x"],
        )
        assert refused.status == 403, (
            "the resource dimension does not bind on the outbound branch"
        )

        allowed = await peer._dispatch_local_execute(
            f"entity://{target_peer_id}/system/tree", "get",
            {"data": {"path": "app/x"}}, capability, None, None,
            resource_targets=[f"/{target_peer_id}/app/allowed/x"],
        )
        assert allowed.status == 502, (
            f"an in-scope resource target was refused: {allowed.error!r}"
        )


class TestThePresentedArm:
    """A credential minted by the target, naming this peer as grantee.

    This arm is exercised on the wire by the reentry probe
    (`t1_2_concurrent_reentry`, driven by `entity-core-go`'s validator through
    `system/validate/dispatch-outbound`). Nothing in this repo's own suite
    drove it before this class — which is the reason it is here: an arm whose
    only coverage lives in a sibling's harness is an arm we cannot regress
    against locally.
    """

    @pytest.mark.asyncio
    async def test_a_target_minted_capability_authorizes_what_the_grant_refuses(
        self, peer, target_peer_id,
    ):
        """The positive arm, driven against the ambient refusal as its own
        control: the handler grant is the §6.2 default — the exact capability
        that gets 403 in the class above — and the dispatch is nonetheless
        authorized, because the authority being spent is the target's.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)

        result = await _dispatch(
            peer, target_peer_id, _default_scope_capability(),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 502, (
            f"a capability minted by the target and granted to this peer did "
            f"not authorize the sub-dispatch (status={result.status}, "
            f"error={result.error!r}) — the presented arm is refusing "
            "credentials the target deliberately issued"
        )

    @pytest.mark.asyncio
    async def test_a_capability_minted_by_someone_else_is_not_presented_authority(
        self, peer, target_peer_id,
    ):
        """Verification 1, the **easy** half: a credential from an unrelated
        root is not presented authority.

        **This row does not discriminate the granter check** and is labelled
        so nobody counts it. Measured: disabling the granter comparison leaves
        it green, because the chain verification underneath rejects the same
        capability for a different reason — its root is not the target. Two
        paths, one answer. It is kept as the ordinary-case control; the row
        below is the one with teeth.
        """
        third_party = Keypair.generate()
        cap, granter_identity, signature = create_capability_token(
            third_party,
            create_identity_entity(peer.keypair),
            [Grant.create(handlers=["*"], operations=["*"], resources=["/*/*"])],
        )

        result = await _dispatch(
            peer, target_peer_id, _default_scope_capability(),
            dispatch_capability_entity=cap.to_dict(),
            dispatch_capability_chain=[
                granter_identity.to_dict(), signature.to_dict(),
            ],
        )
        assert result.status == 403

    @pytest.mark.asyncio
    async def test_a_capability_the_target_DELEGATED_is_not_presented_authority(
        self, peer, target_peer_id,
    ):
        """Verification 1, the discriminating configuration.

        A chain **rooted at the target** — so chain verification in the
        target's frame passes — whose *leaf* was minted by an intermediate and
        granted to this peer. Everything else about it is valid. The only
        thing that refuses it is §1.4's *"the capability's `granter` resolves
        to the target peer's identity"*, read as the leaf's own granter.

        That reading is a **narrowing** and it is the interpretive call
        SA-PY-42 files: a credential the target *delegated* through a third
        party does not qualify as presented authority here and falls back to
        the ambient arm. Fail-closed, and the only reading under which §1.4's
        granter sentence and §5.5's root rule are simultaneously satisfiable.
        This row is what makes the narrowing measurable rather than a comment
        — if arch rules the other way, it is the row that changes.
        """
        intermediate = Keypair.generate()
        parent, root_identity, root_sig = create_capability_token(
            FOREIGN_KEYPAIR,
            create_identity_entity(intermediate),
            [Grant.create(handlers=["*"], operations=["*"], resources=["/*/*"])],
        )
        leaf, leaf_identity, leaf_sig = _delegate(
            delegator_kp=intermediate,
            parent_hash=parent.compute_hash(),
            grantee_identity=create_identity_entity(peer.keypair),
            grants=[Grant.create(
                handlers=["*"], operations=["*"], resources=["/*/*"],
            )],
        )

        result = await _dispatch(
            peer, target_peer_id, _default_scope_capability(),
            dispatch_capability_entity=leaf,
            dispatch_capability_chain=[
                leaf_identity, leaf_sig, parent.to_dict(),
                root_identity.to_dict(), root_sig.to_dict(),
            ],
        )
        assert result.status == 403, (
            "a capability whose leaf granter is NOT the target was accepted "
            "as presented authority — the granter check is the only thing "
            "standing between 'the target minted this for me' and 'something "
            "in this chain once touched the target'"
        )

    @pytest.mark.asyncio
    async def test_a_capability_granted_to_someone_else_is_not_presented_authority(
        self, peer, target_peer_id,
    ):
        """Verification 2: `grantee` must resolve to **this** peer.

        The target minted it, correctly, rooted at itself — for a **different
        peer**, whose identity is bundled so it resolves. Presenting a bearer
        credential addressed to someone else is precisely what this check
        exists to refuse, and with the grantee identity resolvable nothing
        else in the arm refuses it.

        The first draft of this row left the third party's identity out of the
        bundle, so `grantee` did not resolve and the row passed with the
        grantee check disabled — measured, not assumed. An unresolvable
        grantee is a different (and weaker) refusal than a mismatched one.
        """
        someone_else = create_identity_entity(Keypair.generate())
        cap, chain = _target_minted_capability(
            peer, target_peer_id, grantee=someone_else,
        )

        result = await _dispatch(
            peer, target_peer_id, _default_scope_capability(),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=[*chain, someone_else.to_dict()],
        )
        assert result.status == 403, (
            "a target-minted capability naming a DIFFERENT grantee authorized "
            "this peer's dispatch — the credential is being treated as a "
            "bearer token"
        )

    @pytest.mark.asyncio
    async def test_an_unverifiable_chain_is_not_presented_authority(
        self, peer, target_peer_id,
    ):
        """Verification 3: valid — chain-verified.

        The signature is dropped from the chain, so nothing binds the
        capability to the granter it names. A check that read `granter` and
        `grantee` off the data and stopped there would accept this, and the
        data is attacker-supplied.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)
        chain_without_signature = [
            e for e in chain if e.get("type") != "system/signature"
        ]

        result = await _dispatch(
            peer, target_peer_id, _default_scope_capability(),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain_without_signature,
        )
        assert result.status == 403, (
            "an unsigned capability was accepted as presented authority — "
            "§1.4: 'or it is forgeable'"
        )

    @pytest.mark.asyncio
    async def test_a_capability_whose_own_dimensions_refuse_is_not_authority(
        self, peer, target_peer_id,
    ):
        """Verification 4: its own four dimensions authorize THIS request.

        The target minted a credential for this peer, correctly signed, that
        authorizes `put` and not `get`. Presented authority is scoped
        authority.
        """
        cap, chain = _target_minted_capability(
            peer, target_peer_id,
            grants=[Grant.create(
                handlers=["*"], operations=["put"], resources=["/*/*"],
            )],
        )

        result = await _dispatch(
            peer, target_peer_id, _default_scope_capability(),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 403, (
            "a target-minted capability scoped to `put` authorized a `get` — "
            "the presented arm is checking that a credential exists rather "
            "than what it says"
        )

    @pytest.mark.asyncio
    async def test_a_failed_presented_capability_falls_back_rather_than_erroring(
        self, peer, target_peer_id,
    ):
        """§1.4: *"A capability failing any of these is not presented
        authority"* — and falls back to the **ambient arm**, which may still
        authorize. It is not an error in its own right.

        Same third-party credential as the granter row, but the handler grant
        names the target. Ambient authorizes, so the dispatch proceeds: the
        bad credential neither helped nor poisoned it.
        """
        third_party = Keypair.generate()
        cap, granter_identity, signature = create_capability_token(
            third_party,
            create_identity_entity(peer.keypair),
            [Grant.create(handlers=["*"], operations=["*"], resources=["/*/*"])],
        )

        result = await _dispatch(
            peer, target_peer_id, _grant_reaching(target_peer_id),
            dispatch_capability_entity=cap.to_dict(),
            dispatch_capability_chain=[
                granter_identity.to_dict(), signature.to_dict(),
            ],
        )
        assert result.status == 502, (
            "a capability that is not presented authority turned into a "
            "refusal instead of falling back to the ambient arm "
            f"(status={result.status}, error={result.error!r})"
        )


class TestTheStructureOfTheCheck:
    def test_the_check_runs_before_the_dispatch_leaves_the_peer(self, peer):
        """§1.4 says *before it leaves the peer*, and where the call sits is
        the difference between a check and a log line.

        **This row replaces one that stopped discriminating.** The pin's
        structural row asserted `target_peer = extract_peer(` appears *after*
        `return await self._remote_execute(` in `_dispatch_local_execute` —
        true then, and **still true now**, because the outbound check reads
        the target inside a helper. A negative assertion survives the change
        that empties it: that row would have gone on passing while measuring
        nothing, which is why it is re-pointed here rather than left in place.
        """
        from entity_core.peer.peer import Peer

        src = inspect.getsource(Peer._dispatch_local_execute)
        check = src.index("self._authorize_outbound_sub_dispatch(")
        remote = src.index("return await self._remote_execute(")
        assert check < remote, (
            "the outbound authorization no longer precedes the transport"
        )

    def test_both_arms_compose_the_same_two_dimension_checks(self, peer):
        """The local arm and the outbound arm are two call sites of one
        predicate. Two hand-rolled copies that agree today is the shape that
        produced the `connect_ping_before_hello` split — one predicate, two
        boundaries, two classifiers drifting in opposite directions.
        """
        from entity_core.peer.peer import Peer

        outbound = inspect.getsource(Peer._authorize_outbound_sub_dispatch)
        local = inspect.getsource(Peer._dispatch_local_execute)
        for fn in ("check_handler_scope", "check_resource_scope"):
            assert fn in outbound, f"the outbound arm dropped {fn}"
        assert "check_resource_scope" in local

    def test_the_resource_check_is_gated_on_the_field_on_both_arms(self, peer):
        """§5.2, 0.8.2: *a sub-dispatch that names no resource has no
        resource.* The outbound arm must not invent one, and must not skip
        the first check when one is absent."""
        from entity_core.peer.peer import Peer

        src = inspect.getsource(Peer._authorize_outbound_sub_dispatch)
        assert "if resource_targets and not check_resource_scope(" in src
