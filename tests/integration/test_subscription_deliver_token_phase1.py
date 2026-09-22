"""Subscription **Phase 1** — this seat mints a conformant `deliver_token`.

Arch's sequencing (`entity-system-architecture`
`ROUTING-2026-09-10-b` §3, relayed by `entity-core-go`
`ROUTING-2026-09-10-e`):

    *Phase 1 — every seat mints a conformant `deliver_token`. No seat gates.
    Two properties together: **A-rooted** (`EXTENSION-SUBSCRIPTION` §1.2 —
    issued by the authority of the peer that owns the target inbox) **and
    `grantee` = the delivering engine**, not the subscriber. Receivers accept
    either shape throughout this phase.*

    *Phase 2 — every seat presents-and-gates. Only after all three mint
    correctly. No seat presents before all three mint.*

.. rubric:: Why the two properties need rows and not just a constructor

They fail in opposite directions and **neither fails loudly**. A B-rooted
token (go's measured gap) is a peer authorizing itself, which every local test
accepts because the same peer is on both sides. A self-granted token (rust's
measured gap, and the shape every fixture in this repo used) is A-rooted and
therefore *looks* conformant — it is inert instead: §1.4 relaxes Dimension 4
only for a credential whose leaf `grantee` is the peer about to spend it, so a
token granted back to the subscriber gives B's engine nothing. **Inert
authority is the failure mode with no moment at which it looks wrong**, and it
only surfaces two peers and one async hop from the mint.

.. rubric:: What this file does NOT claim

It does not claim py gates on the token. Nothing here presents it on the
outbound delivery path — that is Phase 2. See SA-PY-46 and
``test_autonomous_origination_dimension_4.py`` for the measured reason the
gating half is not landable at this seat until the cohort reaches Phase 2.
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import mint_deliver_token
from entity_core.capability.token import CapabilityToken
from entity_core.crypto.identity import Keypair
from entity_core.protocol.auth import create_identity_entity


@pytest.fixture
def subscriber() -> Keypair:
    """A — owns the inbox, roots the token."""
    return Keypair.generate()


@pytest.fixture
def engine() -> Keypair:
    """B — runs the subscription engine that will deliver."""
    return Keypair.generate()


def _mint(subscriber: Keypair, engine: Keypair):
    inbox_uri = f"entity://{subscriber.peer_id}/system/inbox/phase1"
    return mint_deliver_token(
        subscriber,
        create_identity_entity(engine),
        inbox_uri,
        ttl_ms=300_000,
    )


class TestTheTwoPhase1Properties:
    def test_the_token_is_A_rooted(self, subscriber, engine):
        """§1.2: *issued by the authority of the peer that owns the target
        inbox*. The granter is the SUBSCRIBER, and the accompanying granter
        identity is the subscriber's — not the engine's.
        """
        cap, granter_identity, _sig = _mint(subscriber, engine)
        token = CapabilityToken.from_entity(cap.to_dict())

        subscriber_hash = create_identity_entity(subscriber).compute_hash()
        engine_hash = create_identity_entity(engine).compute_hash()

        assert token.granter == subscriber_hash, (
            "the deliver_token is not A-rooted — §1.2 puts the root at the "
            "peer that owns the target inbox. A B-rooted token is the "
            "delivering peer authorizing itself."
        )
        assert token.granter != engine_hash
        assert granter_identity.compute_hash() == subscriber_hash

    def test_the_grantee_is_the_delivering_engine(self, subscriber, engine):
        """The half that is A-rooted-and-still-wrong.

        §1.2's §7 pseudocode: *"the deliver token (granter = subscriber,
        grantee = server)"*. A token granted back to the subscriber passes an
        A-rooted check and authorizes nobody to deliver anything.
        """
        cap, _granter_identity, _sig = _mint(subscriber, engine)
        token = CapabilityToken.from_entity(cap.to_dict())

        assert token.grantee == create_identity_entity(engine).compute_hash(), (
            "the deliver_token's grantee is not the delivering engine — "
            "§1.4 relaxes Dimension 4 only for a credential whose leaf "
            "grantee is the peer spending it, so this token is inert"
        )
        assert token.grantee != create_identity_entity(subscriber).compute_hash()

    def test_the_two_properties_are_not_the_same_property(
        self, subscriber, engine,
    ):
        """The control that keeps the two rows from collapsing.

        `granter` and `grantee` must be *different* peers. A row set that
        checked only "granter == subscriber" scores a self-grant green, and a
        row set that checked only "grantee == engine" scores a B-rooted token
        green. Both cohort gaps live in the gap between the two assertions.
        """
        cap, _gi, _sig = _mint(subscriber, engine)
        token = CapabilityToken.from_entity(cap.to_dict())
        assert token.granter != token.grantee


class TestTheInertSelfGrantIsRefusedAtTheMint:
    """rust's measured gap, refused here rather than left to fail at delivery.

    A self-grant is well-formed, correctly signed, A-rooted, and does nothing.
    There is no error anywhere in the pipeline: the subscribe succeeds, the
    subscription entity persists, and deliveries are refused later by a peer
    that is not the one that made the mistake. Refusing at the mint is the
    only point where the caller who made the error is still on the stack.
    """

    def test_granting_the_token_back_to_the_subscriber_raises(self, subscriber):
        with pytest.raises(ValueError, match="self-grant"):
            mint_deliver_token(
                subscriber,
                create_identity_entity(subscriber),
                f"entity://{subscriber.peer_id}/system/inbox/phase1",
            )

    def test_and_a_distinct_engine_is_accepted(self, subscriber, engine):
        """The teeth control: the refusal above must be attributable to the
        self-grant and not to anything else about the construction."""
        cap, _gi, _sig = _mint(subscriber, engine)
        assert cap.data["grants"]


class TestTheScopeIsTheInboxAndNothingElse:
    def test_the_grant_names_the_inbox_path_and_receive_only(
        self, subscriber, engine,
    ):
        """A deliver_token that over-grants is a standing cross-peer authority
        the subscriber never intended to hand out. §1.2 scopes it to the one
        inbox and the one operation."""
        cap, _gi, _sig = _mint(subscriber, engine)
        entries = cap.data["grants"]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["operations"]["include"] == ["receive"]
        assert entry["handlers"]["include"] == ["system/inbox/*"]
        assert entry["resources"]["include"] == ["system/inbox/phase1"]

    def test_the_token_is_not_delegable(self, subscriber, engine):
        """One named engine, one named inbox — there is no onward party, so
        `no_delegation` is part of the shape rather than hardening."""
        cap, _gi, _sig = _mint(subscriber, engine)
        assert cap.data["delegation_caveats"]["no_delegation"] is True

    def test_the_signature_covers_the_caveated_bytes(self, subscriber, engine):
        """The caveat is added after the generic mint, so the token is
        re-signed. A signature over the pre-caveat bytes verifies against
        nothing — and `no_delegation` is precisely the field an attacker would
        strip, so a stale signature makes the caveat advisory."""
        from entity_core.crypto.signing import verify_signature

        cap, granter_identity, sig = _mint(subscriber, engine)
        assert sig.data["target"] == cap.compute_hash(), (
            "the signature does not target the caveated capability bytes"
        )
        assert verify_signature(
            subscriber.public_key, cap.compute_hash(), sig.data["signature"],
        )
        assert sig.data["signer"] == granter_identity.compute_hash()


class TestTheOneImplementation:
    def test_create_inbox_token_is_the_same_construction(
        self, subscriber, engine,
    ):
        """`entity_handlers.inbox.create_inbox_token` is the exported name for
        this shape and MUST NOT be a second copy of it — two constructions of
        one capability is how the two drift, and only one of them would get
        the Phase 1 properties.
        """
        from entity_handlers.inbox import create_inbox_token

        inbox_uri = f"entity://{subscriber.peer_id}/system/inbox/phase1"
        engine_identity = create_identity_entity(engine)

        a_cap, _, _ = mint_deliver_token(
            subscriber, engine_identity, inbox_uri, ttl_ms=300_000,
        )
        b_cap, _, _ = create_inbox_token(
            subscriber, engine_identity, inbox_uri, ttl_ms=300_000,
        )
        # created_at/expires_at are wall-clock, so compare the shape that
        # carries the authority rather than the whole entity.
        assert a_cap.data["grants"] == b_cap.data["grants"]
        assert a_cap.data["granter"] == b_cap.data["granter"]
        assert a_cap.data["grantee"] == b_cap.data["grantee"]
        assert (
            a_cap.data["delegation_caveats"] == b_cap.data["delegation_caveats"]
        )

    def test_and_it_refuses_the_self_grant_too(self, subscriber):
        """The delegation is real, not a same-shape reimplementation: the
        refusal reaches through the exported name."""
        from entity_handlers.inbox import create_inbox_token

        with pytest.raises(ValueError, match="self-grant"):
            create_inbox_token(
                subscriber,
                create_identity_entity(subscriber),
                f"entity://{subscriber.peer_id}/system/inbox/phase1",
            )
