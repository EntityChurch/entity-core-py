"""EXTENSION-RELAY v1.3 §8 store bounds + §3.1 `forward-request.expires_at`.

The `[RL-P]` worklist arch routed in `ROUTING-2026-08-31-a §5`: D4 (the §8.1
retention ceiling — configured, published, clamping), D5 (§8.2 — a full store
refuses with `storage_full`/507 and evicts nothing), D7 (§3.1 — the
originator's deadline reaches the §6.2.1 fallback store-entry, clamped, never
extended), plus the one item that was only ours: **`storage_full` did not
exist in this tree at all**, not as a constant and not as a call site.

.. rubric:: What each row is watching, and why the obvious assertion is not it

*The clamp is only conformance if the STORED entry carries it.* go's own
`v4c_ttl_resolver_ceiling` lesson, one extension over: a peer that stamps the
ceiling into the response and stores the caller's value passes every check
that reads the response and honors a "bounded" entry forever. So
`TestRetentionCeiling` asserts the put-result echo, the stored entity, **and**
that the entry stops surfacing on `:poll` once the clamped deadline passes.
The last one is the security property; the first two are how you debug it.

*A bound that is always applied is not a bound.* Every clamp row is paired
with an unconfigured-relay row. Without them a relay that clamps everything to
a hardcoded ceiling scores the whole §8.1 family green, and §8.1 is explicit
that an absent ceiling does **not** mean unbounded — it means the relay
declares none and honors `expires_at`.

*Refuse-and-do-not-evict is two claims.* `test_a_full_store_refuses` catches
a relay with no bound; only `test_nothing_is_evicted_to_make_room` catches the
one that makes room, which is the behaviour §8.2 actually forbids and the one
a cache-shaped implementation reaches for first.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.utils.ecf import ecf_encode

from entity_handlers.relay import (
    CONFIG_MAX_STORAGE_BYTES,
    CONFIG_STORE_RETENTION_MS,
    LIMIT_MAX_RETENTION_MS,
    LIMIT_MAX_STORAGE_BYTES,
    RELAY_CONFIG_PATH,
    STORE_ENTRY_TYPE,
    make_forward_request,
    make_store_entry,
)

_BLANKET = {
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


def _ctx(peer, *, included=None, dispatcher=None) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=peer.keypair.peer_id,
        handler_grant=_BLANKET,
        caller_capability=_BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=dispatcher or peer._dispatch_local_execute,
        handler_pattern="system/relay",
        included=included or {},
        keypair=peer.keypair,
    )


async def _call(peer, op, data, *, included=None, dispatcher=None):
    handler = peer.handlers.find_handler("system/relay")
    ctx = _ctx(peer, included=included, dispatcher=dispatcher)
    return await handler("system/relay", op, {"data": data}, ctx)


def _inner(payload: int = 1):
    ent = Entity(
        type="system/envelope", data={"root": {"x": payload}, "included": {}}
    )
    h = ent.compute_hash()
    return ent, h, {h: ent.to_dict()}


def _configure(peer, **bounds):
    """Seed `system/relay/config` — the one place the handler reads operator
    knobs. Written through `emit` exactly as the CLI's start-up path does, so
    these fixtures cannot drift from the shape production produces."""
    peer.emit_pathway.emit(
        RELAY_CONFIG_PATH,
        Entity(type="system/relay/config", data=dict(bounds)),
        EmitContext.bootstrap(),
    )


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


def _stored_entry(peer, stored_at: str) -> Entity:
    """The store-entry as the relay actually persisted it — not as it echoed
    it. Everything about §8.1 that matters is on this side."""
    h = peer.emit_pathway.entity_tree.get(stored_at)
    assert h is not None, f"nothing bound at {stored_at}"
    entry = peer.emit_pathway.content_store.get(h)
    assert entry is not None and entry.type == STORE_ENTRY_TYPE
    return entry


async def _put(peer, namespace: str, *, expires_at=None, payload: int = 1):
    _, inner_hash, included = _inner(payload)
    entry = make_store_entry(
        namespace=namespace,
        envelope_inner=inner_hash,
        put_by=peer.keypair.peer_id,
        expires_at=expires_at,
    )
    return await _call(peer, "put", entry.data, included=included)


# ==========================================================================
# D4 — §8.1 the retention ceiling
# ==========================================================================


class TestRetentionCeiling:
    @pytest.mark.asyncio
    async def test_an_expiry_beyond_the_ceiling_is_clamped_not_refused(self, peer):
        """§8.1's headline. Refusing is the tempting implementation and it is
        explicitly wrong: it converts an operator's capacity policy into a
        delivery failure the sender cannot tell from an outage."""
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 3_600_000})
        far = _now_ms() + 100 * 365 * 24 * 3600 * 1000
        res = await _put(peer, "ns-far", expires_at=far)

        assert res["status"] == 200, (
            f"a far expires_at was answered {res['status']}; §8.1 requires the "
            f"ceiling to CLAMP, never refuse"
        )
        stored = res["result"]["data"]["expires_at"]
        assert stored is not None and stored < far, (
            f"put-result echoed {stored} for a submitted {far} — not clamped"
        )
        assert abs(stored - (_now_ms() + 3_600_000)) < 60_000, (
            f"clamped to {stored}, expected ≈ now+ceiling"
        )

    @pytest.mark.asyncio
    async def test_the_clamp_is_on_the_stored_entity_not_only_the_echo(self, peer):
        """The row that separates a real ceiling from a cosmetic one.

        A relay that returns `now+ceiling` and stores the caller's value passes
        every check that reads the response — including the cross-impl one,
        which reads the put-result — and holds the entry for a century. The
        entry is content-addressed on its own data, so the clamped deadline has
        to be what was hashed, which is why the clamp runs before authoring.
        """
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 3_600_000})
        far = _now_ms() + 100 * 365 * 24 * 3600 * 1000
        res = await _put(peer, "ns-stored", expires_at=far)

        entry = _stored_entry(peer, res["result"]["data"]["stored_at"])
        assert entry.data["expires_at"] == res["result"]["data"]["expires_at"], (
            "the stored expires_at and the echoed one disagree — the echo is "
            "the only half a wire check can see, and the stored half is the "
            "one that decides how long the entry lives"
        )
        assert entry.data["expires_at"] < far

    @pytest.mark.asyncio
    async def test_the_clamped_entry_actually_stops_surfacing(self, peer):
        """Teeth for the whole family: the ceiling is only a bound if the
        clamped deadline is HONORED. Clamps to ~now, then polls past it."""
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 30})
        res = await _put(peer, "ns-honor", expires_at=_now_ms() + 3_600_000)
        assert res["status"] == 200

        poll = await _call(peer, "poll", {"namespace": "ns-honor"})
        assert len(poll["result"]["data"]["entries"]) == 1, (
            "the entry should be live before the clamped deadline — without "
            "this the row below passes against a put that stored nothing"
        )
        await asyncio.sleep(0.08)
        poll = await _call(peer, "poll", {"namespace": "ns-honor"})
        assert poll["result"]["data"]["entries"] == [], (
            "an entry past its clamped expires_at still surfaced on :poll — "
            "§4.2 makes expiry a READ-side obligation, so a relay that clamps "
            "the number and never honors it holds the entry indefinitely"
        )

    @pytest.mark.asyncio
    async def test_a_null_expiry_takes_the_ceiling(self, peer):
        """§8.1 states the null arm rather than deriving it, because
        `min(x, ceiling)` has no arm for null — the REGISTRY §6a.9.1 shape
        where a guard reading as a type check silently narrowed the MUST to
        the values that already had a bound. A null expiry is the entire
        reason the ceiling exists: it is the unbounded case."""
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 3_600_000})
        res = await _put(peer, "ns-null", expires_at=None)

        stored = res["result"]["data"]["expires_at"]
        assert stored is not None, (
            "a null expires_at stayed null under a configured ceiling — the "
            "arm the ceiling exists for is the one that went unbounded"
        )
        assert abs(stored - (_now_ms() + 3_600_000)) < 60_000
        assert _stored_entry(peer, res["result"]["data"]["stored_at"]).data[
            "expires_at"
        ] == stored

    @pytest.mark.asyncio
    async def test_an_expiry_below_the_ceiling_survives_verbatim(self, peer):
        """The clamp lowers and never raises. A relay that stamped every entry
        with `now+ceiling` would pass both clamp rows above and silently
        EXTEND every short-lived entry, which §3.1 forbids in terms."""
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 3_600_000})
        soon = _now_ms() + 60_000
        res = await _put(peer, "ns-short", expires_at=soon)
        assert res["result"]["data"]["expires_at"] == soon

    @pytest.mark.asyncio
    async def test_an_unconfigured_relay_clamps_nothing(self, peer):
        """The control that keeps the ceiling a *configured* bound. §8.1: an
        absent ceiling does not mean unbounded — it means the relay declares
        none and honors what it was given."""
        far = _now_ms() + 100 * 365 * 24 * 3600 * 1000
        res = await _put(peer, "ns-unbounded", expires_at=far)
        assert res["result"]["data"]["expires_at"] == far

        null_res = await _put(peer, "ns-unbounded-null", expires_at=None, payload=2)
        assert null_res["result"]["data"]["expires_at"] is None

    @pytest.mark.asyncio
    async def test_a_malformed_ceiling_declares_no_bound(self, peer):
        """A config value that is not a positive int is not a bound. Fails
        open HERE and only here: the CLI refuses a malformed flag while the
        operator is present to be told, and a relay that refused every :put
        because a tree key is a string would be down rather than unbounded."""
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: "an hour"})
        far = _now_ms() + 100 * 365 * 24 * 3600 * 1000
        res = await _put(peer, "ns-malformed", expires_at=far)
        assert res["result"]["data"]["expires_at"] == far


# ==========================================================================
# D5 — §8.2 the storage bound
# ==========================================================================


def _cost(peer, namespace: str, payload: int, expires_at: int | None = None) -> int:
    """The §8.2 metric for one entry, computed the way the handler computes it.

    ``expires_at`` is a parameter because it changes the answer: the field is
    part of the store-entry's ECF, so an entry that carries a deadline costs
    ~12 bytes more than one that does not. Sizing a bound from the wrong shape
    is how the first draft of `test_expiry_frees_bytes` refused its own seed
    and then measured an empty store — caught by the seed's status control,
    which is why every row here asserts what it seeded.
    """
    inner, inner_hash, _ = _inner(payload)
    entry = make_store_entry(
        namespace=namespace,
        envelope_inner=inner_hash,
        put_by=peer.keypair.peer_id,
        expires_at=expires_at,
    )
    return len(ecf_encode(entry.data)) + len(ecf_encode(inner.data))


class TestStorageBound:
    @pytest.mark.asyncio
    async def test_a_full_store_refuses_with_storage_full_507(self, peer):
        """§4.3's 507 row, whose code did not exist anywhere in this tree —
        arch's §5 measured it as *"absent: the code does not exist"*, which is
        a step past go's and rust's dead constant."""
        first = _cost(peer, "ns-full", 1)
        _configure(peer, **{CONFIG_MAX_STORAGE_BYTES: first})

        assert (await _put(peer, "ns-full", payload=1))["status"] == 200
        res = await _put(peer, "ns-full", payload=2)

        assert res["status"] == 507, (
            f"a put past max_storage_bytes answered {res['status']}; §4.3 pins "
            f"507"
        )
        assert res["result"]["data"]["code"] == "storage_full"

    @pytest.mark.asyncio
    async def test_nothing_is_evicted_to_make_room(self, peer):
        """The half `test_a_full_store_refuses` cannot see. A store that
        evicted the old entry would ALSO have refused nothing... and would
        pass no row here, because the first entry is gone. §8.2's MUST NOT is
        the reason this is a separate assertion: reject-new over evict-old is
        the same call EXTENSION-NETWORK §8.4 made for the pending queue, and
        an accepted entry is a promise."""
        first = _cost(peer, "ns-evict", 1)
        _configure(peer, **{CONFIG_MAX_STORAGE_BYTES: first})
        accepted = await _put(peer, "ns-evict", payload=1)
        refused = await _put(peer, "ns-evict", payload=2)
        assert refused["status"] == 507

        poll = await _call(peer, "poll", {"namespace": "ns-evict"})
        assert len(poll["result"]["data"]["entries"]) == 1, (
            "the already-accepted entry did not survive a refused put — §8.2 "
            "forbids evicting to make room"
        )
        assert peer.emit_pathway.entity_tree.get(
            accepted["result"]["data"]["stored_at"]
        ) is not None

    @pytest.mark.asyncio
    async def test_a_refused_put_leaves_nothing_behind(self, peer):
        """§4.3 is fail-closed. The refusal is checked before the inner
        envelope is tree-bound, so a full store does not accumulate payloads
        for entries it rejected — the failure mode where the bound is enforced
        on the pointer and not on the bytes."""
        first = _cost(peer, "ns-nothing", 1)
        _configure(peer, **{CONFIG_MAX_STORAGE_BYTES: first})
        await _put(peer, "ns-nothing", payload=1)
        _, refused_inner, _ = _inner(2)
        res = await _put(peer, "ns-nothing", payload=2)
        assert res["status"] == 507

        bound = peer.emit_pathway.entity_tree.list_prefix(
            "system/relay/store/ns-nothing/"
        )
        assert not any(refused_inner.hex() in uri for uri in bound), (
            "the refused put's inner envelope was tree-bound anyway — a "
            "fail-closed refusal must leave nothing behind"
        )

    @pytest.mark.asyncio
    async def test_a_hash_equal_reput_is_not_refused_on_a_full_store(self, peer):
        """Dedup stability. The store path keys on the entry hash, so an
        identical re-put costs no new bytes — and a retry is exactly what a
        sender does when it is unsure whether the first attempt landed. A
        bound that refuses retries turns uncertainty into loss."""
        first = _cost(peer, "ns-dedup", 1)
        _configure(peer, **{CONFIG_MAX_STORAGE_BYTES: first})
        one = await _put(peer, "ns-dedup", payload=1)
        two = await _put(peer, "ns-dedup", payload=1)

        assert two["status"] == 200, (
            "a hash-equal re-put was refused on a full store; it adds no bytes"
        )
        assert two["result"]["data"]["stored_at"] == one["result"]["data"]["stored_at"]

    @pytest.mark.asyncio
    async def test_expiry_frees_bytes_and_that_is_not_eviction(self, peer):
        """The distinction §8.2 turns on. An entry past its own deadline is
        already invisible to a poller (§4.2), so not counting it is honoring
        the sender's terms — unlike removing a LIVE entry, which is the thing
        forbidden."""
        deadline = _now_ms() + 40
        first = _cost(peer, "ns-gc", 1, expires_at=deadline)
        _configure(peer, **{CONFIG_MAX_STORAGE_BYTES: first})
        seeded = await _put(peer, "ns-gc", expires_at=deadline, payload=1)
        assert seeded["status"] == 200, (
            f"the short-lived seed was not stored ({seeded['status']}) — every "
            f"assertion below would then be measuring an empty store"
        )
        assert (await _put(peer, "ns-gc", payload=2))["status"] == 507

        await asyncio.sleep(0.09)
        assert (await _put(peer, "ns-gc", payload=2))["status"] == 200, (
            "bytes held by an EXPIRED entry still counted against the bound — "
            "the store fills permanently with entries nobody can poll"
        )

    @pytest.mark.asyncio
    async def test_an_unconfigured_relay_refuses_nothing(self, peer):
        """The control. Without it, a relay that 507s on the second put of any
        namespace scores every row above."""
        await _put(peer, "ns-nobound", payload=1)
        assert (await _put(peer, "ns-nobound", payload=2))["status"] == 200


# ==========================================================================
# D7 — §3.1 `forward-request.expires_at`
# ==========================================================================


def _recording_dispatcher(result: ExecuteResult | None = None):
    calls: list[dict] = []
    ret = result or ExecuteResult(status=200, result={"data": {"status": "forwarded"}})

    async def disp(uri, operation, params, dispatch_capability, bounds,
                   chain_id, resource_targets, included=None, **_kwargs):
        calls.append({"uri": uri, "params": params})
        return ret

    return disp, calls


async def _fallback(peer, *, expires_at=None, retention=None):
    """Drive a terminal-hop forward with no live session → §6.2.1 fallback,
    and return the store-entry the relay CONSTRUCTED. The relay picks this
    entry's expiry on the originator's behalf, which is the whole of D7."""
    if retention is not None:
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: retention})
    dest = Keypair.generate().peer_id
    _, inner_hash, included = _inner()
    fr = make_forward_request(
        destination=dest,
        envelope_inner=inner_hash,
        ttl_hops=4,
        next_hop=dest,
        expires_at=expires_at,
    )
    res = await _call(peer, "forward", fr.data, included=included)
    assert res["result"]["data"]["status"] == "queued-fallback"
    uris = peer.emit_pathway.entity_tree.list_prefix(f"system/relay/store/{dest}/")
    entries = [
        e for e in (_stored_entry(peer, u) for u in uris if "/inner/" not in u)
    ]
    assert len(entries) == 1
    return entries[0]


class TestForwardRequestExpiresAt:
    @pytest.mark.asyncio
    async def test_the_fallback_honors_the_originators_deadline(self, peer):
        """Before D7 this path wrote no expiry at all — the relay picked the
        lifetime for a message it holds on someone else's behalf, and the one
        party who knew how long it was worth holding had no field to say so."""
        deadline = _now_ms() + 600_000
        entry = await _fallback(peer, expires_at=deadline)
        assert entry.data["expires_at"] == deadline

    @pytest.mark.asyncio
    async def test_the_fallback_expiry_is_clamped_by_the_ceiling(self, peer):
        """The §6.2.1 fallback is the SECOND producer of the store shape.
        go landed §8.1 on `:put` alone and left this path writing an
        unconditional null, then had to file the miss against itself — so
        both producers here go through one `_clamp_expiry`."""
        far = _now_ms() + 100 * 365 * 24 * 3600 * 1000
        entry = await _fallback(peer, expires_at=far, retention=3_600_000)
        assert entry.data["expires_at"] < far
        assert abs(entry.data["expires_at"] - (_now_ms() + 3_600_000)) < 60_000

    @pytest.mark.asyncio
    async def test_a_null_deadline_on_the_fallback_takes_the_ceiling(self, peer):
        entry = await _fallback(peer, expires_at=None, retention=3_600_000)
        assert entry.data["expires_at"] is not None
        assert abs(entry.data["expires_at"] - (_now_ms() + 3_600_000)) < 60_000

    @pytest.mark.asyncio
    async def test_a_short_deadline_is_never_extended_to_the_ceiling(self, peer):
        """§3.1's MUST NOT, and the row that fails a clamp written as an
        assignment rather than a minimum."""
        soon = _now_ms() + 5_000
        entry = await _fallback(peer, expires_at=soon, retention=3_600_000)
        assert entry.data["expires_at"] == soon

    @pytest.mark.asyncio
    async def test_an_unbounded_relay_stores_the_fallback_verbatim(self, peer):
        entry = await _fallback(peer, expires_at=None)
        assert entry.data.get("expires_at") is None

    @pytest.mark.asyncio
    async def test_a_v12_forward_request_encodes_byte_identically(self, peer):
        """`expires_at` is omitempty: a request that does not set it is the
        v1.2 entity, byte for byte, so v1.3 is not a wire break."""
        v12 = make_forward_request(
            destination="D", envelope_inner=b"\x00" * 33, ttl_hops=4, next_hop="D"
        )
        v13 = make_forward_request(
            destination="D", envelope_inner=b"\x00" * 33, ttl_hops=4, next_hop="D",
            expires_at=None,
        )
        assert "expires_at" not in v12.data
        assert ecf_encode(v12.data) == ecf_encode(v13.data)

    @pytest.mark.asyncio
    async def test_the_deadline_travels_to_the_next_hop(self, peer):
        """SA-PY-30. `expires_at` is §3.1's own analogue of `ttl_hops` — an
        outer copy of a bound because the inner one is opaque — and `ttl_hops`
        is carried hop to hop. A relay that drops it when rebuilding the
        relayed request leaves hop 2's fallback storing with no bound at all,
        which is "MUST NOT extend a deadline the originator set" reached by
        omission rather than by assignment.

        `entity-core-go` rebuilds the relayed `ForwardRequestData` without the
        field (`ext/relay/relay.go`), so this row is a measured cross-impl
        divergence and not a style choice; routed rather than assumed.
        """
        deadline = _now_ms() + 600_000
        dest, hop = Keypair.generate().peer_id, Keypair.generate().peer_id
        _, inner_hash, included = _inner()
        fr = make_forward_request(
            destination=dest, envelope_inner=inner_hash, ttl_hops=8,
            route=[hop, dest], expires_at=deadline,
        )
        disp, calls = _recording_dispatcher()
        res = await _call(peer, "forward", fr.data, included=included, dispatcher=disp)

        assert res["status"] == 200 and calls, "the intermediate forward did not fire"
        assert calls[0]["params"]["data"].get("expires_at") == deadline, (
            "the originator's deadline was dropped when the request was "
            "relayed onward; the next relay's §6.2.1 fallback then stores it "
            "unbounded"
        )

    @pytest.mark.asyncio
    async def test_the_relayed_deadline_is_not_clamped_by_our_ceiling(self, peer):
        """Our §8.1 ceiling bounds what THIS relay stores. Clamping a request
        we are only transiting would impose our operator's capacity policy on
        a peer we have no authority over — and would be indistinguishable, at
        the next hop, from the originator having asked for less."""
        deadline = _now_ms() + 100 * 365 * 24 * 3600 * 1000
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 3_600_000})
        dest, hop = Keypair.generate().peer_id, Keypair.generate().peer_id
        _, inner_hash, included = _inner()
        fr = make_forward_request(
            destination=dest, envelope_inner=inner_hash, ttl_hops=8,
            route=[hop, dest], expires_at=deadline,
        )
        disp, calls = _recording_dispatcher()
        await _call(peer, "forward", fr.data, included=included, dispatcher=disp)
        assert calls[0]["params"]["data"]["expires_at"] == deadline


# ==========================================================================
# §4.1 — publishing the bound
# ==========================================================================


class TestAdvertisePublishesTheBounds:
    @pytest.mark.asyncio
    async def test_an_enforced_ceiling_is_published(self, peer):
        """§4.1 `[MUST when present]`. §8.1's reason is the load-bearing part:
        a sender choosing a relay, and a peer naming relays in its §3.5
        inbox-relay declaration, both depend on how long an entry is held —
        *"a ceiling that is enforced but unpublished configures behaviour no
        counterparty can observe before depending on it."*"""
        _configure(
            peer,
            **{CONFIG_STORE_RETENTION_MS: 3_600_000, CONFIG_MAX_STORAGE_BYTES: 4096},
        )
        res = await _call(
            peer, "advertise", {"modes": ["S"], "endpoints": [], "caps_required": []}
        )
        adv = _advertise(peer, res)
        assert adv.data["limits"][LIMIT_MAX_RETENTION_MS] == 3_600_000
        assert adv.data["limits"][LIMIT_MAX_STORAGE_BYTES] == 4096

    @pytest.mark.asyncio
    async def test_an_unenforced_bound_is_omitted_not_published_as_zero(self, peer):
        """Absent means *"this relay declares no ceiling"* — which §8.1 is
        careful to say does NOT mean unbounded. Publishing 0 would assert a
        bound of zero, and an unconfigured relay's advertise stays
        byte-identical to v1.2."""
        res = await _call(
            peer, "advertise", {"modes": ["S"], "endpoints": [], "caps_required": []}
        )
        limits = _advertise(peer, res).data["limits"]
        assert LIMIT_MAX_RETENTION_MS not in limits
        assert LIMIT_MAX_STORAGE_BYTES not in limits

    @pytest.mark.asyncio
    async def test_the_enforced_value_overrides_what_the_caller_asked_for(self, peer):
        """A published ceiling that is not the enforced one is worse than an
        absent one: it is observable and wrong, and every counterparty that
        reads it plans against a bound this relay does not honor."""
        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 3_600_000})
        res = await _call(peer, "advertise", {
            "modes": ["S"], "endpoints": [], "caps_required": [],
            "limits": {LIMIT_MAX_RETENTION_MS: 99_999_999},
        })
        assert _advertise(peer, res).data["limits"][LIMIT_MAX_RETENTION_MS] == 3_600_000

    @pytest.mark.asyncio
    async def test_the_advertise_is_signed_and_the_signature_verifies(self, peer):
        """§4.1 requires the advertise to be signed by `relay_peer_id`, and it
        was published unsigned — while the module docstring, the operation's
        docstring and a test *named* `test_advertise_publishes_signed_entity`
        all said otherwise. That test asserted only that the path was bound:
        **the name claimed the property and the assertion never reached it.**

        It is load-bearing now that the advertise carries the §8 bounds. An
        unsigned advertise at a well-known path is a ceiling anyone who can
        write the tree can forge — the shape §3.5's own forged-redirection
        defense exists to stop, one entity over.
        """
        from entity_core.crypto.signing import (
            public_key_from_bytes,
            verify_signature,
        )
        from entity_core.protocol.auth import create_identity_entity

        _configure(peer, **{CONFIG_STORE_RETENTION_MS: 3_600_000})
        res = await _call(
            peer, "advertise", {"modes": ["S"], "endpoints": [], "caps_required": []}
        )
        adv_hash = res["result"]["data"]["advertise_hash"]

        sig_ref = peer.emit_pathway.entity_tree.get(f"system/signature/{adv_hash.hex()}")
        assert sig_ref is not None, (
            "no signature at the V7 §5.2 invariant pointer for the advertise"
        )
        sig = peer.emit_pathway.content_store.get(sig_ref)
        assert sig.data["target"] == adv_hash
        assert sig.data["signer"] == create_identity_entity(peer.keypair).compute_hash()
        assert verify_signature(
            public_key_from_bytes(peer.keypair.public_key_bytes()),
            adv_hash,
            sig.data["signature"],
        ), "the advertise signature does not verify against the relay's own key"

    @pytest.mark.asyncio
    async def test_the_startup_seam_publishes_the_same_shape(self, peer):
        """The `:advertise` operation cannot discharge §4.1 on its own: an
        operator who sets a ceiling and never calls it would enforce a bound
        no counterparty can read. One authoring path, two callers — two would
        be two advertise shapes, and the shape is signed."""
        from entity_handlers.relay import publish_self_advertise

        published = publish_self_advertise(
            peer.emit_pathway, peer.keypair, peer.keypair.peer_id,
            {CONFIG_STORE_RETENTION_MS: 3_600_000},
        )
        assert published is not None
        path, adv_hash = published
        adv = peer.emit_pathway.content_store.get(
            peer.emit_pathway.entity_tree.get(path)
        )
        assert adv.data["limits"][LIMIT_MAX_RETENTION_MS] == 3_600_000
        assert peer.emit_pathway.entity_tree.get(
            f"system/signature/{adv_hash.hex()}"
        ) is not None

    @pytest.mark.asyncio
    async def test_an_unbounded_relay_publishes_no_self_advertise(self, peer):
        """There is no ceiling to declare, and an empty advertise would assert
        a reachability this relay was never configured to offer."""
        from entity_handlers.relay import publish_self_advertise

        assert publish_self_advertise(
            peer.emit_pathway, peer.keypair, peer.keypair.peer_id, {}
        ) is None


def _advertise(peer, res) -> Entity:
    path = res["result"]["data"]["published_at"]
    return peer.emit_pathway.content_store.get(peer.emit_pathway.entity_tree.get(path))


# ==========================================================================
# The declared type is a surface too
# ==========================================================================


class TestTheDeclaredTypesCarryTheNewFields:
    """A wire field this peer can EMIT and does not DECLARE is half a landing.

    This was the miss in the first cut of v1.3 here: the behaviour landed, the
    `system/type` definitions did not, and nothing local noticed. It surfaced
    on a cross-impl run as `type_system_relay_forward_request_match` — *"field
    `expires_at`: optional locally, missing remotely"* — i.e. a sibling's type
    census reading our declaration and finding the field absent. Tolerable
    under open-type rules and still wrong: a peer that type-checks against our
    published definition would reject a request we ourselves send.

    So the rows below are written against the CONSTRUCTORS rather than against
    a field list, because a hand-maintained list is the thing that goes stale.
    Anything `make_*` can put on the wire has to be declared.
    """

    def _declared(self, factory) -> set[str]:
        return set(factory().data["fields"].keys())

    def test_forward_request_declares_every_field_the_constructor_emits(self):
        from entity_core.types.definitions import type_system_relay_forward_request

        emitted = set(
            make_forward_request(
                destination="D",
                envelope_inner=b"\x00" * 33,
                ttl_hops=4,
                next_hop="D",
                route=["X", "D"],
                expires_at=1,
            ).data.keys()
        )
        undeclared = emitted - self._declared(type_system_relay_forward_request)
        assert not undeclared, (
            f"forward-request emits {sorted(undeclared)} on the wire and does "
            f"not declare them in system/type — a type-checking peer would "
            f"reject a request this peer sends"
        )

    def test_store_entry_declares_every_field_the_constructor_emits(self):
        from entity_core.types.definitions import type_system_relay_store_entry

        emitted = set(
            make_store_entry(
                namespace="ns", envelope_inner=b"\x00" * 33, put_by="P",
                expires_at=1,
            ).data.keys()
        )
        assert not emitted - self._declared(type_system_relay_store_entry)

    def test_advertise_limits_declares_the_retention_ceiling(self):
        """The §4.1 half. `max_retention_ms` is what a counterparty READS to
        decide whether this relay is worth depending on, so an undeclared
        ceiling is a published number with no type behind it."""
        from entity_core.types.definitions import type_system_relay_advertise_limits

        declared = self._declared(type_system_relay_advertise_limits)
        assert LIMIT_MAX_RETENTION_MS in declared
        assert LIMIT_MAX_STORAGE_BYTES in declared
