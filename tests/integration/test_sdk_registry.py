"""Registry operations — `EXTENSION-REGISTRY` §6a.9 / §6a.9.2, against a real peer.

These run through `entity_sdk.registry` onto the genuine registry handler, so
the assertions below are about the **wire the handler actually accepts**, not
about a fixture agreeing with the wrapper that built it.

Three of them exist because §6a.9's own history says the value is
cross-impl-observable and was got wrong by somebody:

* the replay-defense discriminator (`revoke` omits `nonce`/`issued_at` while
  `register`/`renew` carry them),
* the §3.2 empty-params shape on `get-issuer-policy`, which §6a.9.2 notes a
  direct handler unit test cannot see fail,
* the three `register-result` statuses, where an undeclared outcome made three
  implementations invent three different carriers.
"""

from __future__ import annotations

import time

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.sdk import HandlerContextDispatcher

from entity_sdk import (
    BadRequest,
    EntityClient,
    IssuerPolicy,
    NotFound,
    get_issuer_policy,
    normalize_registry_name,
    register,
    revoke,
    set_issuer_policy,
)
from entity_sdk.registry import (
    REGISTER_REQUEST_TYPE,
    RENEW_REQUEST_TYPE,
    REVOKE_REQUEST_TYPE,
    RegisterResult,
)

BLANKET = {
    "grants": [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]
}

#: §6a.9.2 D11 — a live-registration policy MUST carry a `default_ttl`, so
#: every policy in this file that is meant to be *stored* names one. Until D11
#: landed they all omitted it, which means the whole registry surface here was
#: exercised against a policy that could only mint bindings §6a.3 forbids: the
#: helpers were minting the one form the rule now refuses, and nothing looked
#: wrong because no test read the ttl a binding ended up with.
_LIVE_TTL = 86_400_000

#: §6a.9.1 v1.11 — and a live policy MUST carry `max_ttl` too. Generous, for
#: the same reason: these tests are not about the ceiling, and a low one would
#: clamp every binding they assert on without saying so.
_LIVE_MAX_TTL = 365 * 86_400_000


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


@pytest.fixture
def client(peer) -> EntityClient:
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=BLANKET,
        caller_capability=BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )
    return EntityClient.for_peer(peer, HandlerContextDispatcher(ctx))


@pytest.fixture
def publisher() -> Keypair:
    """The self-registering publisher — a different key from the registry's."""
    return Keypair.generate()


# ---------------------------------------------------------------------------
# §6.3 — name safety, before anything reaches the wire
# ---------------------------------------------------------------------------


class TestNameSafety:
    def test_a_slash_is_refused_rather_than_escaped(self):
        """A name is one path segment in the by-name index, so a `/` would
        write a different path than the caller asked for."""
        with pytest.raises(BadRequest) as exc:
            normalize_registry_name("evil/name")
        assert exc.value.status == 400
        assert exc.value.code == "invalid_params"

    def test_control_characters_are_refused(self):
        with pytest.raises(BadRequest):
            normalize_registry_name("bad\x00name")
        with pytest.raises(BadRequest):
            normalize_registry_name("bad\nname")

    def test_empty_is_refused(self):
        with pytest.raises(BadRequest):
            normalize_registry_name("")

    def test_names_are_nfc_normalized(self):
        """Two spellings of the same name must reach the same tree path."""
        decomposed = "café"  # e + combining acute
        composed = "café"
        assert normalize_registry_name(decomposed) == composed
        assert normalize_registry_name(composed) == composed


# ---------------------------------------------------------------------------
# §6a.9.2 — policy management
# ---------------------------------------------------------------------------


class TestIssuerPolicy:
    async def test_unset_is_not_a_mode(self, client):
        """A registry with no stored policy is curated-only (§6a.8) and answers
        404 — it MUST NOT synthesize a default `open`, which would silently
        turn curation into first-come-first-serve. The SDK propagates rather
        than absorbing it."""
        with pytest.raises(NotFound) as exc:
            await get_issuer_policy(client)
        assert exc.value.status == 404

    async def test_set_then_get_round_trips(self, client):
        stored = await set_issuer_policy(client, IssuerPolicy(mode="open", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))
        assert stored.mode == "open"

        read_back = await get_issuer_policy(client)
        assert read_back.mode == "open"

    async def test_get_uses_the_empty_params_shape_the_envelope_accepts(self, client):
        """§6a.9.2: `get-issuer-policy` takes the §3.2 empty-params shape — a
        `primitive/any` whose data is canonical-CBOR `a0`.

        The two obvious alternatives are both rejected *at the envelope layer*:
        a zero-value entity with `400 invalid_params`, a `primitive/map` with
        `400 unexpected_params`. The spec flags that a unit test calling the
        handler directly never crosses that layer and so cannot see either
        failure. This goes through the client, and the assertion is simply that
        it comes back with the policy rather than a 400.
        """
        await set_issuer_policy(client, IssuerPolicy(mode="allowlist", allowlist=[], default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))
        assert (await get_issuer_policy(client)).mode == "allowlist"

    async def test_the_policy_is_replaced_whole_not_merged(self, client):
        """`[MUST]` — an absent optional field means *unset*, never
        *unchanged*. A merge would make the stored policy depend on write
        order, which two peers cannot reconstruct.

        Demonstrated on `name_constraints`, not on `default_ttl`. This test
        used to drop the ttl, and D11 has since made that the one field a live
        policy cannot drop — so it stopped being able to prove replace-whole
        without also proving something the spec forbids. The rule is unchanged;
        only the field carrying the demonstration moved.
        """
        await set_issuer_policy(
            client,
            IssuerPolicy(
                mode="allowlist", allowlist=["a"],
                name_constraints="*.lab", default_ttl=60_000, max_ttl=_LIVE_MAX_TTL,
            ),
        )
        stored = await get_issuer_policy(client)
        assert stored.name_constraints == "*.lab" and stored.default_ttl == 60_000

        # Same mode, no constraint. The stored one must be gone, not retained.
        await set_issuer_policy(
            client, IssuerPolicy(mode="allowlist", allowlist=["a"], default_ttl=60_000,
                         max_ttl=_LIVE_MAX_TTL),
        )
        after = await get_issuer_policy(client)
        assert after.name_constraints is None
        assert after.allowlist == ["a"]

    async def test_a_live_policy_without_a_default_ttl_is_refused(self, client):
        """§6a.9.2 D11 `[MUST]` — the refusal, at the SDK boundary.

        Every mode that can reach *approve* is covered, because "live" is the
        property that matters and `manual` reaches approve by a slower route.
        The negative half matters as much as the status: a peer that answers
        400 and stores the policy anyway passes a status-only check.
        """
        await set_issuer_policy(client, IssuerPolicy(mode="open", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))

        for policy in (
            IssuerPolicy(mode="open", max_ttl=_LIVE_MAX_TTL),
            IssuerPolicy(mode="allowlist", allowlist=["a"], max_ttl=_LIVE_MAX_TTL),
            IssuerPolicy(mode="manual", max_ttl=_LIVE_MAX_TTL),
        ):
            with pytest.raises(BadRequest) as exc:
                await set_issuer_policy(client, policy)
            assert exc.value.status == 400, policy.mode

        assert (await get_issuer_policy(client)).default_ttl == _LIVE_TTL

    async def test_domain_control_is_refused_by_the_registry_not_pre_empted(self, client):
        """§6a.9.1 — the registry refuses to *store* a mode it cannot enforce,
        with `400 unsupported_mode`. The SDK surfaces that rather than
        rejecting client-side, so the ratified server-side rule stays the thing
        under test."""
        with pytest.raises(BadRequest) as exc:
            await set_issuer_policy(client, IssuerPolicy(mode="domain-control"))
        assert exc.value.status == 400
        assert exc.value.code == "unsupported_mode"


# ---------------------------------------------------------------------------
# §6a.9 — live registration
# ---------------------------------------------------------------------------


class TestRegister:
    async def test_open_mode_binds_and_returns_the_binding_hash(self, client, publisher):
        await set_issuer_policy(client, IssuerPolicy(mode="open", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))

        result = await register(client, publisher, "alice")

        assert isinstance(result, RegisterResult)
        assert result.status == "bound"
        assert result.bound is True
        assert result.pending is False
        assert result.binding_hash is not None, "`binding_hash` is REQUIRED on bound"
        assert result.pending_hash is None, "absent on anything but pending_review"

    async def test_manual_mode_queues_and_202_is_not_a_failure(self, client, publisher):
        """§6a.9: the 202 is accepted-pending, and `system/protocol/error` MUST
        NOT carry it — so this must return a result, not raise."""
        await set_issuer_policy(client, IssuerPolicy(mode="manual", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))

        result = await register(client, publisher, "bob")

        assert result.status == "pending_review"
        assert result.pending is True
        assert result.bound is False
        assert result.pending_hash is not None, "REQUIRED on pending_review"
        assert result.binding_hash is None, "absent on anything but bound"

    async def test_target_peer_id_is_the_signing_key_and_cannot_diverge(
        self, client, publisher
    ):
        """§6a.9 layer-1: the signature must be *by* `target_peer_id`, so the
        two can never legitimately differ. The wrapper takes only a keypair —
        there is no parameter with which to express a mismatch."""
        await set_issuer_policy(client, IssuerPolicy(mode="open", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))
        await register(client, publisher, "carol")

        binding = await client.get("system/registry/binding/by-name/carol")
        assert binding is not None
        assert binding["data"]["target_peer_id"] == publisher.peer_id

    async def test_an_allowlist_refusal_surfaces_as_a_typed_error(self, client, publisher):
        """Layer-2 admission: proof accepted, policy says no → 403."""
        await set_issuer_policy(
            client, IssuerPolicy(mode="allowlist", allowlist=["someone-else"], default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL)
        )

        from entity_sdk import AuthorizationError

        with pytest.raises(AuthorizationError) as exc:
            await register(client, publisher, "dave")
        assert exc.value.status == 403
        assert exc.value.code in {"not_entitled", "policy_rejected"}

    async def test_a_replayed_nonce_is_rejected(self, client, publisher):
        """`REG-REGISTER-REPLAY-1`. The nonce is injectable precisely so this
        is drivable without racing a clock or hoping for a collision."""
        await set_issuer_policy(client, IssuerPolicy(mode="open", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))
        nonce = b"\x01" * 16

        first = await register(client, publisher, "erin", nonce=nonce)
        assert first.bound

        from entity_sdk import EntityError

        with pytest.raises(EntityError):
            await register(client, publisher, "erin-again", nonce=nonce)


# ---------------------------------------------------------------------------
# §6a.9.2 — the replay-defense discriminator, which is the cross-impl seam
# ---------------------------------------------------------------------------


class TestReplayDefenseDiscriminator:
    """The discriminator is *"replay has a non-idempotent state effect"*, not
    the operation name. Getting this wrong is invisible locally and diverges on
    contact: a revoke carrying `nonce`/`issued_at` is a *different request*.

    These assert on the request entity this SDK builds, because that is the
    thing that crosses the seam. Asserting only that the peer accepted it would
    pass for a peer that ignores extra fields — which ours does.
    """

    def _register_data(self, keypair: Keypair) -> dict:
        # Rebuild exactly what `register` puts on the wire.
        from entity_sdk.registry import _replay_fields

        return {
            "name": "x",
            "target_peer_id": keypair.peer_id,
            "transports": [],
            "requested_ttl": None,
            **_replay_fields(None, None),
        }

    def test_register_carries_the_replay_fields(self, publisher):
        data = self._register_data(publisher)
        assert isinstance(data["nonce"], bytes) and len(data["nonce"]) == 16
        assert isinstance(data["issued_at"], int)

    async def test_revoke_carries_no_nonce_and_no_issued_at(
        self, client, publisher, monkeypatch
    ):
        """Revocation is monotonic and target-pinned, so replay is a provable
        no-op. §6a.9: the fields *"would be harmless but add no security and
        break cohort convergence."*
        """
        await set_issuer_policy(client, IssuerPolicy(mode="open", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))
        bound = await register(client, publisher, "frank")
        assert bound.binding_hash is not None

        seen: dict = {}

        real_execute = client.execute

        async def _spy(target, operation, params=None, **kw):
            if operation == "revoke-request":
                seen.update(params or {})
            return await real_execute(target, operation, params, **kw)

        monkeypatch.setattr(client, "execute", _spy)
        await revoke(client, publisher, bound.binding_hash, reason="done")

        assert seen.get("type") == REVOKE_REQUEST_TYPE
        data = seen.get("data") or {}
        assert "nonce" not in data, "revoke MUST NOT carry a nonce (§6a.9.2)"
        assert "issued_at" not in data, "revoke MUST NOT carry issued_at (§6a.9.2)"
        assert data.get("binding_hash") == bound.binding_hash
        assert data.get("reason") == "done"

    def test_the_three_request_types_are_distinct(self):
        """Each op has its own request type — borrowing another operation's
        type because the payload happens to match breaks silently the first
        time either grows a field (§6a.9's ruling on result types)."""
        assert len({REGISTER_REQUEST_TYPE, RENEW_REQUEST_TYPE, REVOKE_REQUEST_TYPE}) == 3


# ---------------------------------------------------------------------------
# The handler-level invariant the SDK surfaced
# ---------------------------------------------------------------------------


class TestLayer1ProofReachesTheHandlerOnBothDispatchPaths:
    """§6a.9 layer-1 proof must be findable however the request arrived.

    The registry handler located the bundled `system/peer` + `system/signature`
    by searching the tree and the content store. Both are populated on the
    **wire** path, where `_store_included_entities` persists `included` on
    receipt (V7 §1.5). An **in-process** dispatch has no receive step, so the
    bundle lives only in `ctx.included` (V7 §3.3 v7.51) — which registry alone
    never read, though `capability.py`, `relay.py` and `identity.py` all do.

    The result was `401 signature_invalid` on a correctly signed request: an
    authentication verdict handed to a caller who failed no authentication.
    It stayed invisible because every caller was a CLI reaching a peer over a
    connection; it surfaced the moment an SDK client composed over a local
    dispatcher — the first in-process caller registry ever had.

    Asserted at the handler boundary rather than through `register()` so it
    keeps binding if the SDK wrapper changes shape.
    """

    async def test_a_locally_dispatched_signed_request_is_accepted(
        self, client, peer, publisher
    ):
        from entity_core.protocol.auth import (
            create_identity_entity,
            create_signature_entity,
        )
        from entity_core.protocol.entity import Entity

        await set_issuer_policy(client, IssuerPolicy(mode="open", default_ttl=_LIVE_TTL, max_ttl=_LIVE_MAX_TTL))

        data = {
            "name": "grace",
            "target_peer_id": publisher.peer_id,
            "transports": [],
            "requested_ttl": None,
            "nonce": b"\x07" * 16,
            # Live clock: the registry enforces a replay window on `issued_at`,
            # so a frozen timestamp is refused as `stale_request` long before
            # the layer-1 lookup this test is about.
            "issued_at": int(time.time() * 1000),
        }
        request = Entity(type=REGISTER_REQUEST_TYPE, data=data)
        identity = create_identity_entity(publisher)
        signature = create_signature_entity(
            publisher, request.compute_hash(), identity.compute_hash()
        )

        # Neither bundled entity is in the content store — this is the
        # in-process path, so nothing persisted them.
        store = peer.emit_pathway.content_store
        assert store.get(identity.compute_hash()) is None
        assert store.get(signature.compute_hash()) is None

        result = await client.execute(
            "system/registry",
            "register-request",
            {"type": REGISTER_REQUEST_TYPE, "data": data},
            included=[identity.to_dict(), signature.to_dict()],
        )

        assert (result.get("data") or {}).get("status") == "bound"

    async def test_a_bundle_entry_filed_under_the_wrong_hash_is_not_trusted(
        self, client, publisher
    ):
        """Strict entity fidelity (§1.8): the map key is the *sender's* claim.

        An entity is only usable if it hashes to the key it arrived under —
        otherwise a bundle could name one identity and deliver another.
        """
        from entity_core.protocol.auth import create_identity_entity
        from entity_handlers.registry import _bundled

        identity = create_identity_entity(publisher)
        wrong_key = b"\x00" + b"\xff" * 32

        class _Ctx:
            included = {wrong_key: identity.to_dict()}

        assert _bundled(_Ctx(), wrong_key) is None
        assert _bundled(_Ctx(), identity.compute_hash()) is None  # not under its own key
