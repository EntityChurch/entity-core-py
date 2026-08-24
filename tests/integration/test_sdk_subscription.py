"""Subscription operations — `SDK-EXTENSION-OPERATIONS` §3, against a real peer.

The interesting tests here are the two vocabulary ones. §3 is *the SDK spec*,
and on two fields it contradicts `EXTENSION-SUBSCRIPTION`, which is what the
handlers implement:

* `events` — §3 says ("put", "remove"); the engine filters on
  ("created", "updated", "deleted"). Following §3 literally subscribes to
  nothing, silently. (SA-PY-2)
* `rate_limit` — §3 says per second, the extension and the engine's 60s window
  say per minute. 60× apart, indistinguishable from the result. (SA-PY-3)

`test_the_raw_sdk_spelling_would_match_nothing_on_the_wire` is the one that
proves the first is real rather than a reading of ours: it drives the engine's
own filter with the §3 spelling and shows the event dropped.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.sdk import HandlerContextDispatcher
from entity_core.storage.emit import ChangeKind

from entity_sdk import (
    BadRequest,
    EntityClient,
    SubscriptionInfo,
    SubscriptionLimits,
    normalize_events,
    subscribe,
    unsubscribe,
)
from entity_sdk.subscription import WIRE_EVENTS

BLANKET = {
    "grants": [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]
}


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


@pytest.fixture
def subscriber_identity(peer) -> bytes:
    """The subscriber's identity entity, stored, and its hash.

    SB1 (`EXTENSION-SUBSCRIPTION` §3.1) compares identity **hashes**, not
    peer-id strings: the subscriber must appear as a granter somewhere in the
    deliver token's authority chain, so an actor cannot embed someone else's
    token and force deliveries into that peer's inbox.
    """
    from entity_core.protocol.auth import create_identity_entity

    identity = create_identity_entity(peer.keypair)
    peer.emit_pathway.content_store.put(identity)
    return identity.compute_hash()


@pytest.fixture
def ctx(peer, subscriber_identity) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        # `grantee` is how the handler learns who is subscribing (§3.1 — it is
        # also what unsubscribe checks ownership against). It goes on
        # `handler_grant` because `HandlerContext.execute` passes *that* as the
        # sub-dispatch's caller capability, which is what the handler reads.
        handler_grant={**BLANKET, "grantee": subscriber_identity},
        caller_capability={**BLANKET, "grantee": subscriber_identity},
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
        remote_identity_hash=subscriber_identity,
    )


@pytest.fixture
def client(peer, ctx) -> EntityClient:
    return EntityClient.for_peer(peer, HandlerContextDispatcher(ctx))


@pytest.fixture
def deliver(peer, subscriber_identity) -> tuple[str, bytes]:
    """A deliver URI plus a token hash the peer can resolve.

    The handler validates the token out of the content store, checks expiry,
    checks it grants the deliver operation on the deliver URI, and runs the SB1
    chain check — so a stub hash is not enough; the token has to be real,
    stored, and granted by the subscriber.
    """
    uri = f"entity://{peer.keypair.peer_id}/system/inbox/sub-test"
    token = Entity(
        type="system/capability/token",
        data={
            "granter": subscriber_identity,
            "grantee": subscriber_identity,
            "grants": [
                {
                    "handlers": {"include": ["system/inbox"]},
                    "resources": {"include": [uri]},
                    "operations": {"include": ["receive"]},
                }
            ],
        },
    )
    peer.emit_pathway.content_store.put(token)
    return uri, token.compute_hash()


# ---------------------------------------------------------------------------
# SA-PY-2 — the event vocabulary
# ---------------------------------------------------------------------------


class TestEventVocabulary:
    def test_the_ruled_vocabulary_is_the_only_one(self):
        assert normalize_events(["created"]) == ["created"]
        assert normalize_events(["deleted", "created"]) == ["created", "deleted"]
        assert normalize_events(list(WIRE_EVENTS)) == list(WIRE_EVENTS)

    def test_put_and_remove_are_rejected_and_the_error_names_the_confusion(self):
        """`put`/`remove` were accepted while SA-PY-2 was open. Arch ruled SA-2
        at 0.8.1 and §3 now carries the three-value vocabulary, recording
        `("put","remove")` only as what the line wrongly said — so for *this*
        parameter the spelling names nothing, and keeping it would be a
        divergence of our own making.

        But they remain normative as `ChangeEvent.event_type` at L1
        (`SDK-OPERATIONS` §6.1), so a caller who read an event off `watch()` is
        confusing two real vocabularies. The error says which is which.
        """
        for name, expected in (("put", "created + updated"), ("remove", "deleted")):
            with pytest.raises(BadRequest) as exc:
                normalize_events([name])
            assert exc.value.status == 400
            assert exc.value.code == "invalid_events"
            msg = exc.value.message or ""
            assert "§6.1" in msg, "the error must point at where put/remove IS valid"
            assert expected in msg, "the error must give the mapping, not just refuse"

    def test_a_mixed_list_is_rejected_on_the_invalid_member(self):
        with pytest.raises(BadRequest):
            normalize_events(["created", "put"])

    def test_none_means_all_events(self):
        """Distinct from an empty list — the handler's absent-parameter shape."""
        assert normalize_events(None) is None

    def test_an_unknown_event_is_a_400_not_a_silent_no_match(self):
        """The failure being prevented. The engine compares event names by
        equality, so a typo subscribes to nothing and looks healthy forever."""
        with pytest.raises(BadRequest) as exc:
            normalize_events(["putt"])
        assert exc.value.status == 400
        assert exc.value.code == "invalid_events"

        with pytest.raises(BadRequest):
            normalize_events(["updated", "nonsense"])

    def test_an_empty_list_is_refused(self):
        with pytest.raises(BadRequest):
            normalize_events([])

    def test_the_result_is_order_stable(self):
        """Two callers asking for the same set store the same subscription."""
        assert normalize_events(["deleted", "created"]) == normalize_events(
            ["created", "deleted"]
        )

    def test_the_pre_ruling_spelling_would_have_matched_nothing(self):
        """Why SA-2 was worth routing, kept as the standing regression.

        This is the engine's own filter expression
        (`event.kind.value not in subscription.events`,
        `SubscriptionExtension._on_tree_change`) driven with the vocabulary §3
        carried before 0.8.1. Every change kind is dropped — a subscription
        created successfully that never fires.

        It stays after the ruling because the *engine* is what makes the
        failure silent, and that has not changed: any future filter value the
        engine does not emit behaves exactly this way. The guard is that
        `normalize_events` refuses anything outside the emitted set.
        """
        pre_ruling = ["put", "remove"]
        for kind in ChangeKind:
            assert kind.value not in pre_ruling

        # Every value we *do* accept is one the engine actually emits — the
        # property that makes a silent no-match unreachable.
        accepted = normalize_events(list(WIRE_EVENTS))
        emitted = {kind.value for kind in ChangeKind}
        assert set(accepted) == emitted


# ---------------------------------------------------------------------------
# SA-PY-3 — the rate-limit unit
# ---------------------------------------------------------------------------


class TestRateLimitUnit:
    def test_the_parameter_carries_its_unit_and_maps_to_the_wire_field(self):
        """§3 says per-second, the extension and the engine say per-minute.
        Naming the parameter for the unit makes the wrong reading unspellable;
        the wire field keeps its pinned name."""
        limits = SubscriptionLimits(rate_limit_per_minute=10)
        assert limits.to_data() == {"rate_limit": 10}

    def test_absent_limits_serialize_to_nothing(self):
        """An unset limit is unset, not zero — a zero rate limit would drop
        every notification."""
        assert SubscriptionLimits().to_data() == {}

    def test_limits_round_trip(self):
        limits = SubscriptionLimits(
            max_events=5, max_duration_ms=1000, rate_limit_per_minute=7
        )
        assert SubscriptionLimits.from_data(limits.to_data()) == limits


# ---------------------------------------------------------------------------
# §3 — subscribe / unsubscribe against the handler
# ---------------------------------------------------------------------------


class TestSubscribe:
    async def test_subscribe_returns_the_stored_subscription(self, client, deliver):
        uri, token = deliver

        info = await subscribe(
            client, "data/*", deliver_to=uri, deliver_token=token
        )

        assert isinstance(info, SubscriptionInfo)
        assert info.subscription_id
        assert info.pattern == "data/*"
        # No `events` requested → the handler's documented default, all three.
        assert info.events == list(WIRE_EVENTS)

    async def test_a_filtered_subscription_stores_the_ruled_vocabulary(
        self, client, deliver
    ):
        uri, token = deliver

        info = await subscribe(
            client, "data/*", deliver_to=uri, deliver_token=token,
            events=["created", "updated"],
        )

        assert info.events == ["created", "updated"]

    async def test_the_pre_ruling_spelling_never_reaches_the_peer(
        self, client, deliver
    ):
        """Rejected client-side, so it cannot become a stored dead filter."""
        uri, token = deliver
        with pytest.raises(BadRequest) as exc:
            await subscribe(
                client, "data/*", deliver_to=uri, deliver_token=token, events=["put"]
            )
        assert exc.value.code == "invalid_events"

    async def test_requested_limits_are_returned_as_the_server_merged_them(
        self, client, deliver
    ):
        """§3: the server may tighten and never loosen. The effective set comes
        back so the caller can see what it got."""
        uri, token = deliver

        info = await subscribe(
            client, "data/*", deliver_to=uri, deliver_token=token,
            limits=SubscriptionLimits(max_events=3, rate_limit_per_minute=12),
        )

        assert info.limits.max_events == 3
        assert info.limits.rate_limit_per_minute == 12

    async def test_a_bad_event_name_never_reaches_the_peer(self, client, deliver):
        uri, token = deliver
        with pytest.raises(BadRequest) as exc:
            await subscribe(
                client, "data/*", deliver_to=uri, deliver_token=token, events=["put!"]
            )
        assert exc.value.code == "invalid_events"

    async def test_an_empty_pattern_is_refused(self, client, deliver):
        uri, token = deliver
        with pytest.raises(BadRequest) as exc:
            await subscribe(client, "", deliver_to=uri, deliver_token=token)
        assert exc.value.code == "missing_pattern"

    async def test_an_unresolvable_deliver_token_is_refused_by_the_peer(
        self, client, deliver
    ):
        """The token is validated against the content store, so a plausible but
        absent hash is a 400 rather than a subscription that never delivers."""
        uri, _ = deliver
        from entity_sdk import EntityError

        with pytest.raises(EntityError) as exc:
            await subscribe(
                client, "data/*", deliver_to=uri,
                deliver_token=b"\x00" + b"\xcd" * 32,
            )
        assert exc.value.status in (400, 404)

    async def test_the_subscription_is_stored_and_readable(self, client, deliver):
        uri, token = deliver
        info = await subscribe(client, "data/*", deliver_to=uri, deliver_token=token)

        stored = await client.get(f"system/subscription/{info.subscription_id}")
        assert stored is not None
        assert stored["data"]["pattern"] == "data/*"


class TestUnsubscribe:
    async def test_unsubscribe_removes_the_subscription(self, client, deliver):
        uri, token = deliver
        info = await subscribe(client, "data/*", deliver_to=uri, deliver_token=token)

        await unsubscribe(client, info.subscription_id)

        assert await client.get(f"system/subscription/{info.subscription_id}") is None

    async def test_an_empty_id_is_refused_client_side(self, client):
        with pytest.raises(BadRequest) as exc:
            await unsubscribe(client, "")
        assert exc.value.code == "invalid_params"
