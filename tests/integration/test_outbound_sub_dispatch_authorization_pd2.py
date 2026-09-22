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

.. rubric:: The rule, as corrected at 0.8.2.19

`check_permission` MUST run **before a locally-originated sub-dispatch leaves
the peer**, four dimensions, `target_peer = extract_peer(uri, local_peer_id)`.
**There is ONE gate and ONE exemption:**

> The executing handler's grant is the gate on all four dimensions (§6.8). A
> valid credential minted by the **target** peer relaxes **Dimension 4 — and
> only Dimension 4** — to the peers that credential covers, and must
> additionally authorize the request on its own four dimensions.
> **The target answers *where*; the handler's grant answers *what*.**

.. rubric:: This file described a two-arm model until 0.8.2.19, and that
   reading was F67

The 0.8.2.17 wording said the presented capability's *"own four dimensions
authorize the sub-dispatch"* while exempting only the handler's `peers` scope
by name. **All three ground-up peers resolved that as a bypass of the whole
grant** — and the credential arrives as a caller-supplied parameter, so a
caller holding a copy of any `target -> us` capability could steer any handler
here past its own grant. `entity-core-keystone` found it auditing the ruling it
had itself authored; `entity-core-go` routed it. See `TestTheConfusedDeputy`
below, which is the class that can see it — **nothing above that class can**,
and every row above it passed on both sides of the fix.

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
    async def test_a_capability_the_target_ROOTED_but_delegated_IS_presented_authority(
        self, peer, target_peer_id,
    ):
        """Verification 1, and this row asserted the **opposite** for one
        commit. It is the shipped `EXTENSION-CONTINUATION` §4.2 case 3 shape.

        A chain **rooted at the target**, whose leaf was minted by an
        installer and granted to this peer:

            target grants the installer  ->  the installer grants us

        §1.4 says *"the capability's `granter` resolves to the target peer's
        identity"*, which reads naturally as the **leaf's** granter, and we
        implemented that. Measured against the corpus it is wrong: in the
        cohort's own cross-peer continuation flow the leaf granter is the
        **installer**, and only the root is the target. Under the leaf
        reading every cross-peer continuation advance in the cohort is
        refused — measured as `convergence.rexec_delivered` FAIL, which
        additionally skipped the ~20 checks that declare it a prerequisite
        (pass 1 total 1637 -> 1617).

        **The root reading is also the safe one.** §5.5's attenuation walk
        binds every link, so the leaf can only carry what the target granted
        the installer. The target decided what could be sub-delegated, at mint
        time. A leaf-granter check adds nothing to that and subtracts a
        shipped, conformant flow.
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
        assert result.status == 502, (
            "a capability ROOTED at the target and granted to this peer was "
            "refused as presented authority (status="
            f"{result.status}, error={result.error!r}). This is the shipped "
            "§4.2 case 3 shape — if this row is red, cross-peer continuation "
            "advance is broken and `convergence.rexec_delivered` is too"
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


def _grant_scoped(*, handlers=None, operations=None, resources=None) -> dict:
    """A handler grant with `peers` OMITTED — so Dimension 4 refuses a foreign
    target on its own, and the credential is the only thing that can relax it.

    Every row in `TestTheConfusedDeputy` uses this shape deliberately: with
    `peers` omitted, a 502 is positive evidence that the relaxation ran, and a
    403 is attributable to whichever of Dimensions 1-3 the row narrowed.
    """
    return {
        "grants": [
            Grant.create(
                handlers=handlers if handlers is not None else ["*"],
                operations=operations if operations is not None else ["*"],
                resources=resources if resources is not None else ["/*/*"],
            ).to_dict(),
        ],
    }


class TestTheConfusedDeputy:
    """F67 / 0.8.2.19 — the discriminator whose absence shipped the bypass in
    all three ground-up implementations.

    .. rubric:: Why every other class in this file is blind to it

    The two obvious vectors are *credential + covering grant -> allow* and
    *no credential -> refuse*. **Both pass a peer whose credential path
    bypasses the grant entirely**, which is exactly how this survived a cohort
    conformance run, a 358-vector cross-bless and three green suites. The
    discriminating input is the one no arm-scoped author writes: a **valid**
    credential presented to a handler whose **own grant does not cover the
    request**. It belongs to both arms at once, so neither arm's author owns
    it — the same shape as the `EXTENSION-TREE` Appendix A row-ordering law.

    .. rubric:: The warning `entity-core-go` sent with the fix, taken

    *"A negative security test can PASS for the wrong reason — refused
    upstream of the gate."* `403` is the expected outcome here, so a row that
    refuses for an unrelated reason is indistinguishable from a row with
    teeth. Every refusal row below is paired with a **502 control differing in
    exactly one dimension**, so the pair localizes the refusal to that
    dimension; and each was mutation-verified by restoring the bypass form
    (`if relaxes: return None` ahead of the gate), which turns the refusal rows
    RED and leaves every control green. Measured, not predicted.
    """

    @pytest.mark.asyncio
    async def test_a_valid_credential_does_not_carry_a_handler_past_its_own_grant(
        self, peer, target_peer_id,
    ):
        """**The row F67 was.** A broad, valid, target-minted credential —
        all handlers, all operations, all resources — presented to a handler
        whose grant authorizes `put` and not `get`.

        Under the bypass this is authorized on the credential's dimensions and
        the handler's grant is never read: measured `502` before the fix. The
        caller cannot use the credential itself (its leaf `grantee` is us),
        which is precisely the confused deputy — and `operations` is the
        dimension a caller most wants to widen.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)

        result = await _dispatch(
            peer, target_peer_id,
            _grant_scoped(operations=["put"]),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 403, (
            f"a target-minted credential carried a handler past its own "
            f"`operations` scope (status={result.status}, "
            f"error={result.error!r}) — F67 is live: the credential is "
            "authorizing instead of relaxing Dimension 4 (§1.4, §6.8, "
            "0.8.2.19)"
        )

    @pytest.mark.asyncio
    async def test_and_the_same_credential_relaxes_dimension_4_when_1_to_3_cover(
        self, peer, target_peer_id,
    ):
        """The relaxation control, and the reason the row above is
        attributable.

        **Identical credential, identical peer, one dimension changed** — the
        grant now covers `get`. `peers` is still omitted, so ambient alone
        refuses (that is `TestTheAmbientArm`'s first row). The dispatch
        therefore proceeds *only* if the credential relaxed Dimension 4 while
        Dimensions 1-3 were read from the grant, which is the whole ruling in
        one assertion.

        Without this row the row above passes against a peer that refuses
        every presented credential — the vacuous-green shape, and the reason
        `dispatch_outbound_ambient_refused` was reported as non-discriminating.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)

        result = await _dispatch(
            peer, target_peer_id,
            _grant_scoped(operations=["get"]),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 502, (
            f"a valid target-minted credential did NOT relax Dimension 4 for "
            f"a grant that covers the request on 1-3 (status={result.status}, "
            f"error={result.error!r}) — the presented arm has become a "
            "blanket refusal, which satisfies the negative row while "
            "implementing nothing"
        )

    @pytest.mark.asyncio
    async def test_dimension_1_stays_with_the_handler_too(
        self, peer, target_peer_id,
    ):
        """Not just `operations`: §1.4 says Dimensions **1-3**.

        The grant names a different handler; the credential names all of them.
        A fix that relaxed `peers` *and* `handlers` — the two path-scope
        dimensions, which is an easy slip since both canonicalize — passes the
        `operations` row above and fails here.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)

        result = await _dispatch(
            peer, target_peer_id,
            _grant_scoped(handlers=["system/handler/other"]),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 403, (
            "a target-minted credential carried a handler past its own "
            f"`handlers` scope (status={result.status}) — Dimension 1 is "
            "being relaxed along with Dimension 4"
        )

    @pytest.mark.asyncio
    async def test_dimension_3_stays_with_the_handler_too(
        self, peer, target_peer_id,
    ):
        """The resource dimension, which runs in the *second* of the gate's
        two calls — so a fix that threaded `relax_peers` into
        `check_handler_scope` and forgot `check_resource_scope` passes both
        rows above and fails here.

        That omission is not hypothetical: the two checks each run their own
        per-grant-entry peers test, and relaxing one and not the other leaves
        the resource dimension silently carrying the network bound.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)

        refused = await peer._dispatch_local_execute(
            f"entity://{target_peer_id}/system/tree", "get",
            {"data": {"path": "app/x"}},
            _grant_scoped(resources=[f"/{target_peer_id}/app/allowed/*"]),
            None, None,
            resource_targets=[f"/{target_peer_id}/app/denied/x"],
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert refused.status == 403, (
            "a target-minted credential carried a handler past its own "
            f"`resources` scope (status={refused.status}) — Dimension 3 is "
            "being relaxed along with Dimension 4"
        )

        allowed = await peer._dispatch_local_execute(
            f"entity://{target_peer_id}/system/tree", "get",
            {"data": {"path": "app/x"}},
            _grant_scoped(resources=[f"/{target_peer_id}/app/allowed/*"]),
            None, None,
            resource_targets=[f"/{target_peer_id}/app/allowed/x"],
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert allowed.status == 502, (
            "the in-scope resource control was refused "
            f"(status={allowed.status}, error={allowed.error!r}) — the "
            "refusal above is not attributable to Dimension 3"
        )

    @pytest.mark.asyncio
    async def test_a_credential_is_not_a_grant_so_no_grant_means_no_dispatch(
        self, peer, target_peer_id,
    ):
        """§1.4: *"A credential is **not** a grant — with no handler grant
        there is nothing to supply Dimensions 1-3 and the sub-dispatch is
        refused."*

        This is the row keystone's F63(b) is about from the other side: their
        bootstrap grant carries **zero** grant entries, so §5.2's
        all-four-from-a-single-entry rule matches nothing and an ambient arm
        implemented literally denies everything. Here the credential is
        perfect and the grant is empty; the answer is still refuse, and a peer
        that authorizes this has a credential path that does not consult the
        grant at all.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)

        result = await _dispatch(
            peer, target_peer_id, {"grants": []},
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 403, (
            f"a valid credential authorized a dispatch with NO handler grant "
            f"to relax (status={result.status}) — the credential is being "
            "treated as a grant"
        )

    @pytest.mark.asyncio
    async def test_the_relaxation_is_scoped_to_the_entry_not_the_capability(
        self, peer, target_peer_id,
    ):
        """§5.2 requires all four dimensions from a **single** grant entry,
        and the relaxation must not become a way around that.

        Two entries: one covers `get` on nothing useful, the other covers the
        resources but only `put`. No single entry covers the request, so the
        dispatch must be refused even with Dimension 4 relaxed. A fix that
        applied `relax_peers` by widening the *search* — collecting matching
        dimensions across entries — passes every other row in this class and
        authorizes here.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)
        split = {
            "grants": [
                Grant.create(
                    handlers=["system/handler/other"], operations=["get"],
                    resources=["/*/*"],
                ).to_dict(),
                Grant.create(
                    handlers=["*"], operations=["put"], resources=["/*/*"],
                ).to_dict(),
            ],
        }

        result = await _dispatch(
            peer, target_peer_id, split,
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 403, (
            f"dimensions were satisfied across two grant entries "
            f"(status={result.status}) — §5.2's single-entry rule did not "
            "survive the Dimension 4 relaxation"
        )


class TestTheMultiGranterRootIsFailClosed:
    """§1.4 *Root granter under multi-signature* `[MUST]` (0.8.2.19) — E3/F66's
    sub-item, and a **live over-acceptance** here rather than a no-op absorb.

    The ruling: a K-of-N root *"satisfies the root-granter check only when the
    target peer's identity is the multi-granter itself; a root whose signer set
    merely includes the target does not."*

    **Measured before the fix: we accepted the signer-set form.** Not by
    oversight — `verify_capability_chain`'s M6 rule is *"the local peer is
    among the root's signers"*, which is correct for its own job, and this gate
    calls it with the frame set to `target_peer`. So M6 answered *"the target
    is among the signers"* and a group credential relaxed Dimension 4 on one
    constituent's say-so, which is the escalation the ruling names: *treating a
    constituent as the granter would let any one signer's target confer the
    group's grant.*

    That is why the rule is enforced at **this gate** and not by tightening M6
    — tightening M6 would refuse every legitimate local multi-sig root. The
    two rules disagree on purpose, and the frame is what makes them disagree.

    .. rubric:: The first fixture here did not discriminate, and that is a
       finding about the code

    Disarming the rule reddened **nothing** — measured, 24/24 green with the
    check `and False`-ed out. Traced (A1) rather than patched: this gate calls
    `verify_capability_chain` **without** a `find_signature_by_signer`, so the
    walk refuses *every* multi-signature root at depth 0 with *"Multi-sig
    capability requires by-signer signature finder"* — including one where the
    target genuinely IS the multi-granter. The rule is therefore **correct and
    currently unreachable**, refused one layer earlier by a mechanical gap.

    Per the standing law the two paths refuse for **different reasons**, and
    the broader one is the accident: the fail-closed property rests on an
    *absence* — a finder nobody passed — which reads as an oversight and is
    exactly what a later seat wires up as an improvement. On that day the
    over-acceptance returns with nothing watching it. So the rule stays, and
    the row below is written at the configuration that isolates it: the chain
    walk is made to succeed, leaving this rule as the only thing between a
    K-of-N root and Dimension 4. `test_the_rule_is_unreachable_today_and_this_
    is_why` pins the mechanism so the reachability change is visible when it
    lands, rather than being discovered by its consequence.
    """

    def test_the_rule_is_unreachable_today_and_this_is_why(
        self, peer, target_peer_id,
    ):
        """Not a coverage row — a **reachability** row, and it is the one that
        will fail first when this stops being true.

        It asserts the mechanism named above: the outbound gate passes no
        by-signer finder, so multi-signature roots are refused by the chain
        walk before the §1.4 rule is consulted. When a seat wires a by-signer
        finder in, this row goes red and points at the row below, which is the
        one that then starts doing the work.
        """
        src = inspect.getsource(
            type(peer)._presented_credential_relaxes_peers,
        )
        assert "verify_capability_chain(" in src
        assert "find_signature_by_signer" not in src, (
            "the outbound gate now passes a by-signer signature finder, so "
            "multi-signature roots reach the §1.4 root-granter rule for the "
            "first time. That rule is live now: confirm "
            "test_a_k_of_n_root_whose_signers_include_the_target_relaxes_"
            "nothing still discriminates WITHOUT its monkeypatch, and delete "
            "the patch if so"
        )

    @pytest.mark.asyncio
    async def test_a_k_of_n_root_whose_signers_include_the_target_relaxes_nothing(
        self, peer, target_peer_id, monkeypatch,
    ):
        """The rule, driven at the one configuration that isolates it.

        `verify_capability_chain` is forced to succeed, so the chain walk's
        blanket multi-sig refusal (see the class docstring) is out of the way
        and **this rule is the only thing left**. Without the patch the row
        passes with the rule deleted; with it, deleting the rule turns this
        row RED and nothing else — measured both ways.
        """
        from entity_core.capability.delegation import DelegationResult
        from entity_core.crypto.identity import peer_id_from_identity_entity
        from entity_core.protocol.entity import Entity

        monkeypatch.setattr(
            "entity_core.capability.delegation.verify_capability_chain",
            lambda *a, **kw: DelegationResult(valid=True),
        )

        other_signer = create_identity_entity(Keypair.generate())
        target_identity = create_identity_entity(FOREIGN_KEYPAIR)
        assert peer_id_from_identity_entity(
            {"data": target_identity.data},
        ) == target_peer_id

        root = Entity(
            type="system/capability/token",
            data={
                "grants": [Grant.create(
                    handlers=["*"], operations=["*"], resources=["/*/*"],
                ).to_dict()],
                "granter": {
                    "signers": [
                        target_identity.compute_hash(),
                        other_signer.compute_hash(),
                    ],
                    "threshold": 2,
                    "n": 2,
                },
                "grantee": create_identity_entity(peer.keypair).compute_hash(),
                "created_at": int(time.time() * 1000),
                "parent": None,
            },
        )
        signature = create_signature_entity(
            FOREIGN_KEYPAIR, root.compute_hash(), target_identity.compute_hash(),
        )

        result = await _dispatch(
            peer, target_peer_id, _grant_scoped(operations=["get"]),
            dispatch_capability_entity=root.to_dict(),
            dispatch_capability_chain=[
                target_identity.to_dict(), other_signer.to_dict(),
                signature.to_dict(),
            ],
        )
        assert result.status == 403, (
            "a K-of-N-rooted credential whose signer set merely INCLUDES the "
            f"target relaxed Dimension 4 (status={result.status}, "
            f"error={result.error!r}) — one constituent's target is "
            "conferring the group's grant (§1.4, 0.8.2.19)"
        )

    @pytest.mark.asyncio
    async def test_and_a_single_sig_target_root_still_relaxes(
        self, peer, target_peer_id,
    ):
        """The teeth control. Without it the row above is satisfied by a peer
        that refuses every credential, and the whole multi-granter rule reads
        as implemented while being a blanket refusal — the exact shape §1.4
        calls *looks implemented and denies everything*.
        """
        cap, chain = _target_minted_capability(peer, target_peer_id)

        result = await _dispatch(
            peer, target_peer_id, _grant_scoped(operations=["get"]),
            dispatch_capability_entity=cap,
            dispatch_capability_chain=chain,
        )
        assert result.status == 502, (
            f"the ordinary single-signature target-minted root stopped "
            f"relaxing (status={result.status}, error={result.error!r})"
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
