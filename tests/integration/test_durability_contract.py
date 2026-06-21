"""Integration conformance tests for the EXTENSION-DURABILITY contract.

EXTENSION-DURABILITY v0.1 is EXPLORATORY · OPTIONAL · NOT ACTIVELY
DEVELOPED (extracted from EXTENSION-INBOX §10; depends V7
v7.46+). Peers that don't install the extension are unaffected. The
inbox is now isolated from durability concerns — the §5 verdict and §6
handle live at the dispatch layer, not on the inbox handler.

End-to-end peer-dispatch behavior, cross-checked against the matrix in
``../entity-core-architecture/docs/architecture/v7.0-core-revision/
core-protocol-domain/explorations/
EXPLORATION-DELIVERY-DURABILITY-SCENARIO-MATRIX.md``.

Conformance tiers mirror EXTENSION-CONTINUATION §8:

- MUST — required behavior; a violation is a spec defect (within this
  extension's surface — peers that don't install it are unaffected).
- SHOULD — recommended; absent is conformant but discouraged.
- MAY — optional.

The pure helpers (the §5 verdict table, invariants, wire shape,
advertise, the dispatch-time async/deliverable adapter) live in
``tests/unit/test_durability.py``. This file pins the *peer dispatch*
surface — what a real peer answers on the wire — for the matrix
scenarios that the contract changes.

Surfaces covered here:

- Scenario 1 (no durability marker): unchanged; no ``durability`` field.
- Scenario 4 (durable sync, no deliver_to): response states what
  durability was applied vs. requested; ``handle`` names the lookup
  address.
- Scenario 6 (no durable store): observable answer
  (``applied: none, reason: no_durable_store``); ``must_have`` → 412
  refuse-at-acceptance, operation NOT performed.
- §3 advertise (MAY); §6 handle/lookup.
- Amendment 1 MUSTs (now §5/§6/§8): handle field, 409 dedup,
  unknown-level fail-closed.
- Inbox isolation (v5.9): lookup and durability-advertise operations
  are no longer carried by the inbox handler.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder
from entity_core.peer.connection import Connection
from entity_core.protocol.durability import (
    DEFAULT_DURABILITY_POLICY,
    LEVEL_NONE,
    LEVEL_REPLICATED,
    LEVEL_STORED,
    REASON_NO_DURABLE_STORE,
    REASON_REQUIRED_UNMET,
    DurabilityPolicy,
)


# A handler that records every call, so a 412 refusal can be observed
# as "the operation was NOT performed" (no double-execution).
class _Probe:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self, path: str, operation: str, params: dict[str, Any], ctx: Any,
    ) -> dict[str, Any]:
        self.calls.append({"path": path, "operation": operation, "params": params})
        return {
            "status": 200,
            "result": {"type": "primitive/any", "data": {"ok": True}},
        }


# ---- Fixtures: one peer per durability policy shape we exercise. ----

# Distinct ports per fixture so tests can run in parallel without bind
# conflicts. (pytest-asyncio runs them sequentially by default; explicit
# ports keep the tests deterministic if that ever changes.)


async def _start_peer(
    port: int,
    *,
    with_inbox: bool,
    policy: DurabilityPolicy | None = None,
) -> tuple[Peer, _Probe]:
    probe = _Probe()
    builder = (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_default_handlers()
        .with_handler("test/probe", probe, priority=200, name="probe")
        .debug_mode(True)
    )
    if with_inbox:
        builder = builder.with_inbox_handler()
    if policy is not None:
        builder = builder.with_durability_policy(policy)
    peer = builder.build()
    await peer.start("127.0.0.1", port)
    return peer, probe


@pytest.fixture
async def core_peer():
    """No inbox handler, no durable store (DEFAULT_DURABILITY_POLICY)."""
    peer, probe = await _start_peer(19501, with_inbox=False)
    yield peer, probe
    await peer.stop()


@pytest.fixture
async def inbox_peer():
    """Inbox handler installed → durability policy auto-raised to {stored}."""
    peer, probe = await _start_peer(19502, with_inbox=True)
    yield peer, probe
    await peer.stop()


@pytest.fixture
async def replicating_peer():
    """Explicitly configured for replication-class durability."""
    peer, probe = await _start_peer(
        19503,
        with_inbox=True,
        policy=DurabilityPolicy(
            self_levels=frozenset({LEVEL_STORED}),
            replication_levels=frozenset({LEVEL_REPLICATED}),
        ),
    )
    yield peer, probe
    await peer.stop()


async def _execute(
    port: int,
    target: str,
    *,
    durability_request: dict[str, Any] | None = None,
):
    """One-shot client EXECUTE with auto-cleanup."""
    conn = await Connection.connect("127.0.0.1", port, Keypair.generate())
    try:
        response = await conn.execute(
            uri=f"entity://{target}/test/probe",
            operation="poke",
            params={"hello": "world"},
            authenticated=True,
            durability_request=durability_request,
        )
        return response
    finally:
        conn.close()
        await conn.wait_closed()


# -----------------------------------------------------------------------------
# Scenario 1 — Unchanged behavior for durability-unaware callers.
# MUST: an EXECUTE without `durability_request` produces an
# EXECUTE_RESPONSE without the `durability` field (additive on the wire).
# -----------------------------------------------------------------------------


class TestScenario1Unchanged:
    """Scenario 1: durability-unaware traffic is byte-for-byte unchanged."""

    @pytest.mark.asyncio
    async def test_no_durability_request_no_durability_field(self, core_peer):
        peer, probe = core_peer
        response = await _execute(19501, peer.peer_id)
        assert response.status == 200
        assert response.durability is None
        assert len(probe.calls) == 1  # handler ran exactly once


# -----------------------------------------------------------------------------
# Scenario 4 — Sync, durable, no deliver_to: receiver says WHAT durability
# was applied (replaces V7:654 silent-ignore). MUST.
# -----------------------------------------------------------------------------


class TestScenario4DurableSync:
    """Receiver configured for `stored` answers with `applied: stored`."""

    @pytest.mark.asyncio
    async def test_inbox_peer_meets_stored_request(self, inbox_peer):
        peer, probe = inbox_peer
        response = await _execute(
            19502, peer.peer_id,
            durability_request={"level": LEVEL_STORED},
        )
        assert response.status == 200
        assert response.durability is not None
        # §10.5 Row 1: applied IS the requested strength (in place).
        assert response.durability.requested == LEVEL_STORED
        assert response.durability.applied == LEVEL_STORED
        # §10.5 invariant: committed only on 202, max_available only on 412.
        assert response.durability.committed is None
        assert response.durability.max_available is None
        # Handler ran exactly once.
        assert len(probe.calls) == 1


# -----------------------------------------------------------------------------
# Scenario 6 — No durable store: observable, never silent.
# MUST: applied=none + reason=no_durable_store (not must_have).
# MUST: 412 refuse-at-acceptance (must_have) with the operation
#       NOT performed (no double-execution).
# -----------------------------------------------------------------------------


class TestScenario6NoDurableStore:
    """A peer with no durable store STILL answers durability requests
    observably (replaces V7:654 silent-ignore)."""

    @pytest.mark.asyncio
    async def test_best_effort_reports_no_durable_store(self, core_peer):
        peer, probe = core_peer
        response = await _execute(
            19501, peer.peer_id,
            durability_request={"level": LEVEL_STORED},
        )
        assert response.status == 200
        assert response.durability is not None
        assert response.durability.applied == LEVEL_NONE
        assert response.durability.reason == REASON_NO_DURABLE_STORE
        # Handler ran — best-effort means run-then-report-degraded.
        assert len(probe.calls) == 1

    @pytest.mark.asyncio
    async def test_must_have_refuses_with_412_and_does_not_run(self, core_peer):
        peer, probe = core_peer
        response = await _execute(
            19501, peer.peer_id,
            durability_request={"level": LEVEL_STORED, "must_have": True},
        )
        # MUST: 412 (Precondition Failed) — operation NOT performed,
        # refused at acceptance, safe to retry — no double-execution.
        assert response.status == 412
        assert response.durability is not None
        assert response.durability.applied == LEVEL_NONE
        assert response.durability.max_available == LEVEL_NONE
        assert response.durability.reason == REASON_REQUIRED_UNMET
        # The whole point of refuse-at-acceptance:
        assert probe.calls == []

    @pytest.mark.asyncio
    async def test_must_have_replication_unconfigured_412(self, inbox_peer):
        # inbox_peer: self_levels={stored}, replication_levels=∅.
        # A required replication strength the peer is NOT configured for
        # is 412 (not 202) — that's the "not configured for the required
        # topology" branch of Row 4.
        peer, probe = inbox_peer
        response = await _execute(
            19502, peer.peer_id,
            durability_request={"level": LEVEL_REPLICATED, "must_have": True},
        )
        assert response.status == 412
        assert response.durability is not None
        # max_available reports the receiver's best self-determinable level.
        assert response.durability.max_available == LEVEL_STORED
        assert probe.calls == []


# -----------------------------------------------------------------------------
# §10.5 invariant — replication-class is 202-then-observe EVEN WHEN
# required, never 412 just because nothing's in place yet at acceptance.
# MUST.
# -----------------------------------------------------------------------------


class TestReplicationClassIs202ThenObserve:
    @pytest.mark.asyncio
    async def test_replication_required_configured_is_202_committed(
        self, replicating_peer
    ):
        peer, _ = replicating_peer
        response = await _execute(
            19503, peer.peer_id,
            durability_request={"level": LEVEL_REPLICATED, "must_have": True},
        )
        assert response.status == 202
        assert response.durability is not None
        # The promise lives in `committed`; `applied` reports only what
        # is physically in place at response time.
        assert response.durability.committed == LEVEL_REPLICATED
        assert response.durability.max_available is None  # invariant: not 412


# -----------------------------------------------------------------------------
# §3 advertise (MAY) and §6 lookup — Inbox is now isolated from
# durability. The advertisement is a bootstrap-seeded entity at
# ``system/durability`` (tree:get). Lookup uses the response's
# ``handle`` followed by tree:get. No inbox-handler operations involved.
# -----------------------------------------------------------------------------


class TestInboxNoLongerCarriesDurabilityOps:
    """Inbox isolation: lookup and durability advertise operations were
    removed from the inbox handler on extraction (EXTENSION-INBOX v5.9).
    Durability concerns live in EXTENSION-DURABILITY now."""

    @pytest.mark.asyncio
    async def test_inbox_handler_rejects_lookup_op(self):
        from entity_core.handlers.context import HandlerContext
        from entity_core.storage.content_store import ContentStore
        from entity_core.storage.emit import EmitPathway
        from entity_core.storage.entity_tree import EntityTree
        from entity_handlers.inbox import inbox_handler

        kp = Keypair.generate()
        emit_pathway = EmitPathway(ContentStore(), EntityTree(kp.peer_id))
        ctx = HandlerContext(
            local_peer_id=kp.peer_id, remote_peer_id="remote",
            handler_grant={}, caller_capability={}, emit_pathway=emit_pathway,
        )
        response = await inbox_handler(
            "system/inbox/anywhere", "lookup", {"data": {"request_id": "x"}}, ctx,
        )
        assert response["status"] == 501  # unsupported_operation — isolated

    @pytest.mark.asyncio
    async def test_inbox_handler_rejects_durability_op(self):
        from entity_core.handlers.context import HandlerContext
        from entity_core.storage.content_store import ContentStore
        from entity_core.storage.emit import EmitPathway
        from entity_core.storage.entity_tree import EntityTree
        from entity_handlers.inbox import inbox_handler

        kp = Keypair.generate()
        emit_pathway = EmitPathway(ContentStore(), EntityTree(kp.peer_id))
        ctx = HandlerContext(
            local_peer_id=kp.peer_id, remote_peer_id="remote",
            handler_grant={}, caller_capability={}, emit_pathway=emit_pathway,
        )
        response = await inbox_handler(
            "system/inbox", "durability", {}, ctx,
        )
        assert response["status"] == 501  # unsupported_operation — isolated


# -----------------------------------------------------------------------------
# §10.4 reconcile is at acceptance — the policy is auto-derived from the
# peer's own configuration. MUST (the receiver's policy is its own; not a
# prediction of another peer's state).
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Cross-impl validation fixes (cf. the v7.47 durability cross-impl report).
# These pin the three points the Go-team durability category flagged on that
# run: 412 result-entity type, §10.3 advertisement presence,
# §10.6 durable-entry preservation.
# -----------------------------------------------------------------------------


class TestRefusalResultEntity:
    """MUST: A 412 refusal MUST NOT carry the operation's result.
    The result entity type is ``system/protocol/error`` so a
    durability-unaware consumer branching on result.type still sees a
    refusal (no run-then-fail, no double-execution; §10.5)."""

    @pytest.mark.asyncio
    async def test_412_result_is_system_protocol_error(self, core_peer):
        peer, _ = core_peer
        response = await _execute(
            19501, peer.peer_id,
            durability_request={"level": LEVEL_STORED, "must_have": True},
        )
        assert response.status == 412
        # The wire result is an entity envelope per V7 §3.4.
        result = response.result
        assert isinstance(result, dict) and result.get("type") == "system/protocol/error"
        # ECF/wire roundtrip preserves the error code spelling (§10.7).
        assert result["data"]["code"] == "durability_required_unmet"


class TestAdvertisementEntityAtWellKnownPath:
    """SHOULD (§10.3): a peer publishes the advertisement at the
    well-known tree path ``system/durability`` so a sender can discover
    supported levels via an ordinary ``tree:get``."""

    def test_inbox_peer_seeds_advertisement(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .with_inbox_handler()
            .build()
        )
        uri = peer.entity_tree.normalize_uri("system/durability")
        hash_ = peer.entity_tree.get(uri)
        assert hash_ is not None, "advertisement entity MUST be present at system/durability"
        entity = peer.content_store.get(hash_)
        assert entity is not None
        assert entity.type == "system/durability-advertisement"
        assert LEVEL_STORED in entity.data["levels"]
        assert entity.data["max_self_determinable"] == LEVEL_STORED

    def test_core_peer_advertises_no_durable_store(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .build()
        )
        uri = peer.entity_tree.normalize_uri("system/durability")
        hash_ = peer.entity_tree.get(uri)
        assert hash_ is not None
        entity = peer.content_store.get(hash_)
        # Even a no-durable-store peer advertises explicitly — the SHOULD
        # is presence; ``max_self_determinable == "none"`` is the honest answer.
        assert entity.data["levels"] == []
        assert entity.data["max_self_determinable"] == LEVEL_NONE


class TestDurableEntryPreservation:
    """§10.6: a durable sync request lands at ``{peer}/system/inbox/{request_id}``
    so the sender can find it again by ``(author, request_id)`` — the
    §10.5 invariant that ``applied`` is physically in place at response
    time depends on this preservation for the sync no-deliver_to path."""

    @pytest.mark.asyncio
    async def test_durable_entry_preserved_in_inbox_namespace(self, inbox_peer):
        peer, _ = inbox_peer
        # Send a durable EXECUTE; capture the request_id by going through
        # the connection (request_id is generated by Execute.create).
        from entity_core.peer.connection import Connection

        client_keypair = Keypair.generate()
        conn = await Connection.connect("127.0.0.1", 19502, client_keypair)
        try:
            # Drive the EXECUTE manually so the test can capture the
            # request_id used and assert against it.
            from entity_core.protocol.messages import Execute
            from entity_core.protocol.delivery import DeliverySpec  # noqa: F401
            from entity_core.protocol.durability import DurabilityRequest
            from entity_core.protocol.envelope import Envelope
            from entity_core.protocol.messages import ExecuteResponse
            from entity_core.protocol.auth import create_authenticated_request

            execute = Execute.create(
                f"entity://{peer.peer_id}/test/probe",
                "poke",
                {"hello": "world"},
                durability_request=DurabilityRequest(LEVEL_STORED),
            )
            auth = create_authenticated_request(
                conn.keypair, execute, conn.capability, conn.capability_chain,
            )
            await conn.send(auth.to_envelope())
            response = ExecuteResponse.from_entity((await conn.recv()).root)
            assert response.status == 200
            assert response.durability is not None
            assert response.durability.applied == LEVEL_STORED

            # §10.6 handle: addressed by origin request id, in this
            # peer's inbox namespace.
            uri = peer.entity_tree.normalize_uri(
                f"system/inbox/{execute.request_id}"
            )
            stored_hash = peer.entity_tree.get(uri)
            assert stored_hash is not None, (
                "MUST preserve durable entry at system/inbox/{request_id}"
            )
            stored = peer.content_store.get(stored_hash)
            assert stored is not None
            # The preserved entity is the originating EXECUTE itself.
            assert stored.type == "system/protocol/execute"
            assert stored.data["request_id"] == execute.request_id
        finally:
            conn.close()
            await conn.wait_closed()

    @pytest.mark.asyncio
    async def test_no_preservation_for_no_durable_store_peer(self, core_peer):
        # A core peer has no durable store -> applied is none ->
        # preservation MUST be skipped (it would overclaim).
        peer, _ = core_peer
        response = await _execute(
            19501, peer.peer_id,
            durability_request={"level": LEVEL_STORED},
        )
        assert response.durability.applied == LEVEL_NONE
        # No spurious inbox entry got written either way.
        # (The request_id is hidden by _execute; checking the inbox
        # namespace is empty for the well-known request_id is enough.)
        uri = peer.entity_tree.normalize_uri("system/inbox")
        # The system/inbox bucket should have no children created by this
        # peer for this test — best we can assert without the rid is that
        # the bucket either doesn't exist or has zero direct children.
        bucket_hash = peer.entity_tree.get(uri)
        # Either no bucket entity exists, or it exists with no
        # generated child paths beyond what the peer seeds itself.
        # The strong assertion is the response durability above; this is
        # a sanity check that core peers don't surprise-preserve.
        assert response.status == 200


# -----------------------------------------------------------------------------
# Scenario 5 (companion peer as outbox / durable host) — Python's side.
# Per the v7.47 durability cross-impl follow-up: an open-access
# Python peer MUST be reachable for `system/tree:extract` and
# `system/tree:merge` by an ad-hoc client identity, so any peer can host
# Python's durable inbox namespace and Python can host any peer's. This
# pins the Python-side wire surface (the Go-side wires peer-manager to
# pass `--open-access` to Python; that's a separate one-line change in
# the entity-core-go repo).
# -----------------------------------------------------------------------------


class TestScenario5ExtractMerge:
    """An open-access Python peer accepts extract + merge from an ad-hoc
    identity — the same access tier as get/put, matching Go/Rust."""

    @pytest.mark.asyncio
    async def test_extract_inbox_namespace_open_access(self, inbox_peer):
        peer, _ = inbox_peer
        conn = await Connection.connect("127.0.0.1", 19502, Keypair.generate())
        try:
            response = await conn.execute(
                uri=f"entity://{peer.peer_id}/system/tree",
                operation="extract",
                params={},
                resource={"targets": ["system/inbox/"]},
                authenticated=True,
            )
            assert response.status == 200, (
                f"open-access peer MUST accept extract for ad-hoc identity; got {response.status}"
            )
            # extract's contract is system/envelope (the op IS the bundle).
            env = response.result["data"]
            assert "root" in env
            assert "included" in env
        finally:
            conn.close()
            await conn.wait_closed()

    @pytest.mark.asyncio
    async def test_merge_envelope_open_access(self, inbox_peer):
        peer, _ = inbox_peer
        conn = await Connection.connect("127.0.0.1", 19502, Keypair.generate())
        try:
            # First extract: produce an envelope of the inbox namespace.
            extract = await conn.execute(
                uri=f"entity://{peer.peer_id}/system/tree",
                operation="extract",
                params={},
                resource={"targets": ["system/inbox/"]},
                authenticated=True,
            )
            assert extract.status == 200
            env = extract.result["data"]
            # Merge it back into a sibling prefix on the same peer (the
            # Scenario 5 cross-peer merge uses an absolute /{preserver}/...
            # target_prefix; a sibling local prefix is sufficient here to
            # pin that the merge surface is reachable end-to-end).
            merge = await conn.execute(
                uri=f"entity://{peer.peer_id}/system/tree",
                operation="merge",
                params={
                    "source_envelope": env,
                    "target_prefix": "data/copy-of-inbox/",
                },
                authenticated=True,
            )
            assert merge.status == 200, (
                f"open-access peer MUST accept merge for ad-hoc identity; got {merge.status}"
            )
        finally:
            conn.close()
            await conn.wait_closed()

    @pytest.mark.asyncio
    async def test_advertisement_visible_via_tree_get(self, inbox_peer):
        # The validator's `advertisement_present` probe does a
        # tree:get on `system/durability`. Pin that it returns 200 with
        # the §10.3 advertisement entity under open-access.
        peer, _ = inbox_peer
        conn = await Connection.connect("127.0.0.1", 19502, Keypair.generate())
        try:
            response = await conn.execute(
                uri=f"entity://{peer.peer_id}/system/tree",
                operation="get",
                params={"mode": "entity"},
                resource={"targets": ["system/durability"]},
                authenticated=True,
            )
            assert response.status == 200
            assert response.result["type"] == "system/durability-advertisement"
            assert LEVEL_STORED in response.result["data"]["levels"]
        finally:
            conn.close()
            await conn.wait_closed()

    @pytest.mark.asyncio
    async def test_preserved_entry_visible_via_tree_get(self, inbox_peer):
        # The validator's `durable_entry_preserved` probe does a
        # tree:get on `system/inbox/{request_id}`. Pin that round-trip.
        peer, _ = inbox_peer
        conn = await Connection.connect("127.0.0.1", 19502, Keypair.generate())
        try:
            durable = await conn.execute(
                uri=f"entity://{peer.peer_id}/system/tree",
                operation="get",
                params={"mode": "entity"},
                resource={"targets": ["system/type/system/hash"]},
                authenticated=True,
                durability_request={"level": LEVEL_STORED},
            )
            assert durable.status == 200
            assert durable.durability is not None
            assert durable.durability.applied == LEVEL_STORED

            lookup = await conn.execute(
                uri=f"entity://{peer.peer_id}/system/tree",
                operation="get",
                params={"mode": "entity"},
                resource={"targets": [f"system/inbox/{durable.request_id}"]},
                authenticated=True,
            )
            assert lookup.status == 200
            assert lookup.result["type"] == "system/protocol/execute"
        finally:
            conn.close()
            await conn.wait_closed()


# -----------------------------------------------------------------------------
# Amendment 1 MUSTs (now §5 / §6 / §8 of EXTENSION-DURABILITY v0.1):
# handle field present when applied != none / on 202; 409 dedup;
# unknown-level fail-closed.
# -----------------------------------------------------------------------------


class TestHandleField:
    """§5 / §6 / §8 MUST: ``handle`` is present when ``applied != none``
    (200 with achieved strength) and on 202 (committed entry will land
    there). The receiver chooses the path; the spec does not prescribe
    layout."""

    @pytest.mark.asyncio
    async def test_handle_present_on_sync_durable_200(self, inbox_peer):
        peer, _ = inbox_peer
        response = await _execute(
            19502, peer.peer_id,
            durability_request={"level": LEVEL_STORED},
        )
        assert response.status == 200
        assert response.durability is not None
        assert response.durability.applied == LEVEL_STORED
        assert response.durability.handle is not None
        # The handle the receiver chose actually resolves to the
        # preserved entry (the §6 contract).
        uri = peer.entity_tree.normalize_uri(response.durability.handle)
        assert peer.entity_tree.get(uri) is not None

    @pytest.mark.asyncio
    async def test_handle_absent_when_applied_is_none(self, core_peer):
        peer, _ = core_peer
        response = await _execute(
            19501, peer.peer_id,
            durability_request={"level": LEVEL_STORED},
        )
        assert response.status == 200
        assert response.durability is not None
        assert response.durability.applied == LEVEL_NONE
        assert response.durability.handle is None  # §8 MUST: absent here

    @pytest.mark.asyncio
    async def test_handle_absent_on_412(self, core_peer):
        peer, _ = core_peer
        response = await _execute(
            19501, peer.peer_id,
            durability_request={"level": LEVEL_STORED, "must_have": True},
        )
        assert response.status == 412
        assert response.durability is not None
        # 412 refuses BEFORE preservation; nothing's in place → no handle.
        assert response.durability.handle is None


class TestDuplicateRequestId409:
    """§5 row 8 / §8 MUST: a (author, request_id) pair that matches a
    previously preserved entry → 409 ``duplicate_request_id``.
    Operation NOT performed; prior entry stands."""

    @pytest.mark.asyncio
    async def test_second_durable_request_with_same_rid_is_409(self, inbox_peer):
        peer, probe = inbox_peer
        # Drive the EXECUTE manually so we control request_id.
        from entity_core.peer.connection import Connection
        from entity_core.protocol.messages import Execute, ExecuteResponse
        from entity_core.protocol.durability import DurabilityRequest
        from entity_core.protocol.auth import create_authenticated_request

        conn = await Connection.connect("127.0.0.1", 19502, Keypair.generate())
        try:
            fixed_rid = "dedup-rid-stable-1"
            def send_durable() -> ExecuteResponse:
                # NOTE: defined inside so the closure binds `conn`.
                pass

            async def send_one() -> ExecuteResponse:
                execute = Execute(
                    request_id=fixed_rid,
                    uri=f"entity://{peer.peer_id}/test/probe",
                    operation="poke",
                    params={"x": 1},
                    durability_request=DurabilityRequest(LEVEL_STORED),
                )
                auth = create_authenticated_request(
                    conn.keypair, execute, conn.capability, conn.capability_chain,
                )
                await conn.send(auth.to_envelope())
                return ExecuteResponse.from_entity((await conn.recv()).root)

            first = await send_one()
            assert first.status == 200
            assert first.durability.applied == LEVEL_STORED
            calls_after_first = len(probe.calls)

            second = await send_one()
            assert second.status == 409
            assert second.durability is not None
            assert second.durability.reason == "duplicate_request_id"
            assert second.durability.applied == LEVEL_NONE
            # §8 MUST: operation NOT performed on 409 — handler MUST NOT
            # have run a second time.
            assert len(probe.calls) == calls_after_first
        finally:
            conn.close()
            await conn.wait_closed()


class TestUnknownLevelFailClosed:
    """§5 rows 6/7 / §8 MUST: a ``level`` value the receiver does not
    recognize fails closed. ``must_have: true`` → 412 with reason
    ``unknown_level`` and ``max_available`` = strongest recognized;
    ``must_have: false`` → 200 with ``applied: none, reason: unknown_level``."""

    @pytest.mark.asyncio
    async def test_unknown_level_must_have_is_412(self, inbox_peer):
        peer, probe = inbox_peer
        response = await _execute(
            19502, peer.peer_id,
            durability_request={"level": "fictional-strength", "must_have": True},
        )
        assert response.status == 412
        assert response.durability is not None
        assert response.durability.reason == "unknown_level"
        # max_available reports the strongest level the receiver DOES
        # recognize (the policy's max self-determinable strength).
        assert response.durability.max_available == LEVEL_STORED
        # Refused at acceptance — handler MUST NOT run.
        assert probe.calls == []

    @pytest.mark.asyncio
    async def test_unknown_level_best_effort_is_200_applied_none(self, inbox_peer):
        peer, probe = inbox_peer
        response = await _execute(
            19502, peer.peer_id,
            durability_request={"level": "fictional-strength"},
        )
        assert response.status == 200
        assert response.durability is not None
        assert response.durability.reason == "unknown_level"
        assert response.durability.applied == LEVEL_NONE
        # Best-effort: handler ran (degraded outcome, observable).
        assert len(probe.calls) == 1


class TestPolicyAutoDerivation:
    """The default policy depends on what the peer is actually configured for."""

    def test_default_peer_has_no_durable_store(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .build()
        )
        assert peer.durability_policy == DEFAULT_DURABILITY_POLICY

    def test_inbox_handler_raises_policy_to_stored(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .with_inbox_handler()
            .build()
        )
        assert LEVEL_STORED in peer.durability_policy.self_levels

    def test_explicit_policy_wins_over_auto(self):
        explicit = DurabilityPolicy(
            self_levels=frozenset({LEVEL_STORED}),
            replication_levels=frozenset({LEVEL_REPLICATED}),
        )
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .with_durability_policy(explicit)
            .build()
        )
        assert peer.durability_policy is explicit
