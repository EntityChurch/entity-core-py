"""Unit tests for the EXTENSION-DURABILITY v0.1 contract.

EXTENSION-DURABILITY is EXPLORATORY · OPTIONAL · NOT ACTIVELY DEVELOPED
(extracted from EXTENSION-INBOX §10; depends V7 v7.46+).
Peers that don't install the extension are unaffected.

Covers the pure reconciliation: the §5 status + pinned-field table, the
dispatch-time adapter for async/deliver_to, the §5 / §8 invariants
(``applied`` never overstates; ``committed`` only on 202;
``max_available`` only on 412; ``handle`` only when ``applied != none``
or on 202), the §2 / §5 wire roundtrips, §3 advertise, and the
Amendment-1 MUSTs (now §5/§6/§8: handle field, 409 dedup, unknown-level
fail-closed, pinned reason spellings).

Mirrors the EXTENSION-CONTINUATION §8 conformance-tiered test layout:
the pure helpers are isolated here, the peer-dispatch surface is in
``tests/integration/test_durability_contract.py``.
"""

from __future__ import annotations

import pytest

from entity_core.protocol.durability import (
    DEFAULT_DURABILITY_POLICY,
    LEVEL_NONE,
    LEVEL_REPLICATED,
    LEVEL_STORED,
    REASON_DUPLICATE_REQUEST_ID,
    REASON_NO_DURABLE_STORE,
    REASON_NO_INBOX_HANDLER,
    REASON_REQUIRED_UNMET,
    REASON_UNKNOWN_LEVEL,
    STATUS_ACCEPTED,
    STATUS_CONFLICT,
    STATUS_PRECONDITION_FAILED,
    DurabilityPolicy,
    DurabilityRequest,
    DurabilityResult,
    advertise,
    is_known_level,
    is_replication_class,
    level_rank,
    reconcile,
    reconcile_for_dispatch,
)
from entity_core.protocol.messages import Execute, ExecuteResponse


_STORE = DurabilityPolicy(self_levels=frozenset({LEVEL_STORED}))
_STORE_AND_REPLICATE = DurabilityPolicy(
    self_levels=frozenset({LEVEL_STORED}),
    replication_levels=frozenset({LEVEL_REPLICATED}),
)


# -----------------------------------------------------------------------------
# §10.5 verdict table — five rows, one distinct meaning per status number.
# -----------------------------------------------------------------------------


class TestReconcileTable:
    """The pure §10.5 table; the only branch a consumer needs is status."""

    def test_row1_can_do_at_or_above_requested(self) -> None:
        v = reconcile(DurabilityRequest(LEVEL_STORED), _STORE)
        assert v.status == 200 and not v.refuse and not v.accepted_async
        assert v.result.to_dict() == {
            "requested": LEVEL_STORED,
            "applied": LEVEL_STORED,
        }

    def test_row2_best_effort_weaker_when_not_must_have(self) -> None:
        # Requested replicated; policy supports only stored; not must_have.
        v = reconcile(DurabilityRequest(LEVEL_REPLICATED), _STORE)
        assert v.status == 200
        assert v.result.applied == LEVEL_STORED
        assert v.result.committed is None
        assert v.result.max_available is None

    def test_row3_no_durable_store_not_must_have(self) -> None:
        v = reconcile(DurabilityRequest(LEVEL_STORED), DEFAULT_DURABILITY_POLICY)
        assert v.status == 200
        assert v.result.applied == LEVEL_NONE
        assert v.result.reason == REASON_NO_DURABLE_STORE

    def test_row4_must_have_unmet_refuses_with_412(self) -> None:
        v = reconcile(
            DurabilityRequest(LEVEL_STORED, must_have=True),
            DEFAULT_DURABILITY_POLICY,
        )
        assert v.status == STATUS_PRECONDITION_FAILED and v.refuse
        assert v.result.applied == LEVEL_NONE
        assert v.result.max_available == LEVEL_NONE
        assert v.result.reason == REASON_REQUIRED_UNMET

    def test_row4_must_have_replication_not_configured(self) -> None:
        v = reconcile(
            DurabilityRequest(LEVEL_REPLICATED, must_have=True), _STORE
        )
        assert v.status == STATUS_PRECONDITION_FAILED and v.refuse
        # max_available reports the receiver's best self-determinable level.
        assert v.result.max_available == LEVEL_STORED
        assert v.result.committed is None  # invariant: not 202

    def test_row5_replication_configured_is_202_then_observe(self) -> None:
        # Even when must_have: replication-class is inherently
        # 202-then-observe (§10.5 invariant).
        v = reconcile(
            DurabilityRequest(LEVEL_REPLICATED, must_have=True),
            _STORE_AND_REPLICATE,
        )
        assert v.status == STATUS_ACCEPTED and v.accepted_async
        assert v.result.applied == LEVEL_STORED  # what's physically in place now
        assert v.result.committed == LEVEL_REPLICATED
        assert v.result.max_available is None  # invariant: not 412


# -----------------------------------------------------------------------------
# §10.5 invariants — applied never overstates; committed only on 202;
# max_available only on 412. These are MUSTs.
# -----------------------------------------------------------------------------


class TestInvariants:
    @pytest.mark.parametrize(
        "request_,policy",
        [
            (DurabilityRequest(LEVEL_STORED), _STORE),
            (DurabilityRequest(LEVEL_STORED), DEFAULT_DURABILITY_POLICY),
            (DurabilityRequest(LEVEL_STORED, must_have=True), DEFAULT_DURABILITY_POLICY),
            (DurabilityRequest(LEVEL_REPLICATED), _STORE),
            (DurabilityRequest(LEVEL_REPLICATED, must_have=True), _STORE),
            (DurabilityRequest(LEVEL_REPLICATED, must_have=True), _STORE_AND_REPLICATE),
        ],
    )
    def test_committed_only_on_202(self, request_, policy) -> None:
        v = reconcile(request_, policy)
        if v.result.committed is not None:
            assert v.status == STATUS_ACCEPTED, (
                "committed MUST appear only with status 202"
            )

    @pytest.mark.parametrize(
        "request_,policy",
        [
            (DurabilityRequest(LEVEL_STORED, must_have=True), DEFAULT_DURABILITY_POLICY),
            (DurabilityRequest(LEVEL_REPLICATED, must_have=True), _STORE),
            (DurabilityRequest(LEVEL_STORED), _STORE),
            (DurabilityRequest(LEVEL_REPLICATED), _STORE),
            (DurabilityRequest(LEVEL_REPLICATED, must_have=True), _STORE_AND_REPLICATE),
        ],
    )
    def test_max_available_only_on_412(self, request_, policy) -> None:
        v = reconcile(request_, policy)
        if v.result.max_available is not None:
            assert v.status == STATUS_PRECONDITION_FAILED, (
                "max_available MUST appear only with status 412"
            )

    def test_applied_never_exceeds_self_determinable(self) -> None:
        # Asking for replication with stored-only policy: applied MUST be
        # at most "stored" (the peer's best self-determinable strength),
        # never the requested "replicated" — never overstates.
        v = reconcile(DurabilityRequest(LEVEL_REPLICATED), _STORE)
        assert level_rank(v.result.applied) <= level_rank(LEVEL_STORED)

    def test_unknown_level_is_fail_closed_for_must_have(self) -> None:
        # §5 row 7 / §8 MUST: unknown level + must_have → 412 with
        # reason: unknown_level and max_available = strongest recognized.
        v = reconcile(
            DurabilityRequest("nonsense", must_have=True), _STORE_AND_REPLICATE
        )
        assert v.refuse and v.status == STATUS_PRECONDITION_FAILED
        assert v.result.reason == REASON_UNKNOWN_LEVEL
        # max_available reports the receiver's strongest recognized level,
        # NOT the requested unknown one.
        assert v.result.max_available == LEVEL_STORED

    def test_unknown_level_best_effort_is_200_applied_none(self) -> None:
        # §5 row 6 / §8 MUST: unknown level + best-effort → 200 with
        # applied: none, reason: unknown_level.
        v = reconcile(DurabilityRequest("nonsense"), _STORE_AND_REPLICATE)
        assert v.status == 200 and not v.refuse
        assert v.result.applied == LEVEL_NONE
        assert v.result.reason == REASON_UNKNOWN_LEVEL


# -----------------------------------------------------------------------------
# EXTENSION-DURABILITY §8 dispatch-time adapter — async deliver_to (the
# applied-vs-committed transformation) and the no-inbox-handler
# silent-loss case.
# -----------------------------------------------------------------------------


class TestReconcileForDispatch:
    def test_no_request_and_deliverable_returns_none(self) -> None:
        # Nothing to reconcile; durability-unaware callers unaffected.
        assert (
            reconcile_for_dispatch(
                None, DEFAULT_DURABILITY_POLICY,
                async_completion=False, deliverable=True,
            )
            is None
        )

    def test_no_request_but_undeliverable_still_reports(self) -> None:
        # deliver_to set, no inbox handler — never silently lost.
        v = reconcile_for_dispatch(
            None, DEFAULT_DURABILITY_POLICY,
            async_completion=False, deliverable=False,
        )
        assert v is not None and v.status == 200 and not v.refuse
        assert v.result.applied == LEVEL_NONE
        assert v.result.reason == REASON_NO_INBOX_HANDLER

    def test_must_have_undeliverable_is_412(self) -> None:
        v = reconcile_for_dispatch(
            DurabilityRequest(LEVEL_STORED, must_have=True),
            _STORE,
            async_completion=True, deliverable=False,
        )
        assert v.refuse and v.status == STATUS_PRECONDITION_FAILED

    def test_async_deliver_to_promotes_met_strength_to_committed(self) -> None:
        # Peer is configured for stored; deliver_to runs async — so
        # applied MUST be none at response time; the strength is
        # committed to the async pathway.
        v = reconcile_for_dispatch(
            DurabilityRequest(LEVEL_STORED),
            _STORE,
            async_completion=True, deliverable=True,
        )
        assert v.status == STATUS_ACCEPTED and v.accepted_async
        assert v.result.applied == LEVEL_NONE
        assert v.result.committed == LEVEL_STORED

    def test_async_required_configured_is_202_not_412(self) -> None:
        # Required stored, async, configured: per the §10.5 invariant
        # ("Replication-class is inherently 202-then-observe even when
        # required") — for any async-completion path, a configured
        # strength is 202-committed, sender verifies via §10.6. NEVER
        # 412 just because the strength is not in place at response.
        v = reconcile_for_dispatch(
            DurabilityRequest(LEVEL_STORED, must_have=True),
            _STORE,
            async_completion=True, deliverable=True,
        )
        assert v.status == STATUS_ACCEPTED and not v.refuse
        assert v.result.committed == LEVEL_STORED

    def test_sync_path_matches_reconcile(self) -> None:
        # Without async completion, the dispatch adapter is the §10.5
        # table verbatim — no transformation.
        req = DurabilityRequest(LEVEL_STORED)
        base = reconcile(req, _STORE)
        adapted = reconcile_for_dispatch(
            req, _STORE, async_completion=False, deliverable=True
        )
        assert adapted.status == base.status
        assert adapted.result.to_dict() == base.result.to_dict()


# -----------------------------------------------------------------------------
# §10.2 / §10.5 wire shape — additive + roundtrip-stable.
# -----------------------------------------------------------------------------


class TestWireShape:
    def test_durability_request_must_have_default_omitted(self) -> None:
        # Minimal shape on the wire for the common (must_have=False) case.
        assert DurabilityRequest(LEVEL_STORED).to_dict() == {"level": LEVEL_STORED}

    def test_durability_request_roundtrip(self) -> None:
        for must in (False, True):
            req = DurabilityRequest(LEVEL_REPLICATED, must_have=must)
            assert DurabilityRequest.from_dict(req.to_dict()) == req

    def test_durability_result_optional_fields_omitted_when_absent(self) -> None:
        r = DurabilityResult(LEVEL_STORED, LEVEL_STORED)
        d = r.to_dict()
        assert "committed" not in d
        assert "max_available" not in d
        assert "reason" not in d

    def test_durability_result_roundtrip(self) -> None:
        r = DurabilityResult(
            LEVEL_REPLICATED, LEVEL_NONE,
            max_available=LEVEL_STORED, reason=REASON_REQUIRED_UNMET,
        )
        assert DurabilityResult.from_dict(r.to_dict()) == r

    def test_execute_durability_field_additive(self) -> None:
        # An EXECUTE without durability_request emits no extra field —
        # durability-unaware callers/receivers are unaffected.
        e = Execute.create("system/tree", "put", {"x": 1})
        assert "durability_request" not in e.to_entity()["data"]

    def test_execute_durability_field_roundtrip(self) -> None:
        e = Execute.create(
            "system/tree", "put", {"x": 1},
            durability_request=DurabilityRequest(LEVEL_STORED, must_have=True),
        )
        e2 = Execute.from_entity(e.to_entity())
        assert e2.durability_request == DurabilityRequest(
            LEVEL_STORED, must_have=True
        )

    def test_response_durability_field_additive(self) -> None:
        # An EXECUTE_RESPONSE without durability emits no extra field.
        r = ExecuteResponse.success("rid", {"ok": True})
        assert "durability" not in r.to_entity()["data"]

    def test_response_412_factory_sets_durability(self) -> None:
        df = DurabilityResult(
            LEVEL_STORED, LEVEL_NONE,
            max_available=LEVEL_NONE, reason=REASON_REQUIRED_UNMET,
        )
        r = ExecuteResponse.precondition_failed("rid", durability=df)
        r2 = ExecuteResponse.from_entity(r.to_entity())
        assert r2.status == 412
        assert r2.durability == df

    def test_response_202_factory_carries_committed(self) -> None:
        df = DurabilityResult(LEVEL_REPLICATED, LEVEL_STORED, committed=LEVEL_REPLICATED)
        r = ExecuteResponse.accepted("rid", durability=df)
        r2 = ExecuteResponse.from_entity(r.to_entity())
        assert r2.status == 202
        assert r2.durability.committed == LEVEL_REPLICATED


# -----------------------------------------------------------------------------
# §10.3 advertise — SHOULD; discovery only.
# -----------------------------------------------------------------------------


class TestAdvertise:
    """§10.3 advertise — cross-impl-aligned shape: ``{levels,
    max_self_determinable}`` matching the Go reference, so the
    advertisement entity at ``system/durability`` is discoverable
    uniformly across implementations."""

    def test_default_policy_advertises_no_durable_store(self) -> None:
        ad = advertise(DEFAULT_DURABILITY_POLICY)
        assert ad["levels"] == []
        assert ad["max_self_determinable"] == LEVEL_NONE

    def test_inbox_equipped_policy_advertises_stored(self) -> None:
        ad = advertise(_STORE)
        assert LEVEL_STORED in ad["levels"]
        assert ad["max_self_determinable"] == LEVEL_STORED

    def test_replication_configured_policy_advertises_it(self) -> None:
        ad = advertise(_STORE_AND_REPLICATE)
        # Union of self + replication, weakest → strongest.
        assert ad["levels"] == [LEVEL_STORED, LEVEL_REPLICATED]
        # max_self_determinable still reports only what's synchronously
        # guaranteed at acceptance — replication is 202-then-observe.
        assert ad["max_self_determinable"] == LEVEL_STORED


class TestLevelHelpers:
    def test_replication_class_recognition(self) -> None:
        assert is_replication_class(LEVEL_REPLICATED)
        assert not is_replication_class(LEVEL_STORED)
        assert not is_replication_class(LEVEL_NONE)

    def test_level_rank_total_order(self) -> None:
        assert level_rank(LEVEL_NONE) < level_rank(LEVEL_STORED) < level_rank(LEVEL_REPLICATED)
        # Unknown ranks strictly above all known.
        assert level_rank("zzz-unknown") > level_rank(LEVEL_REPLICATED)

    def test_is_known_level(self) -> None:
        # §5 / §7: the receiver's recognized vocabulary turns on the §5
        # fail-closed rule.
        assert is_known_level(LEVEL_NONE)
        assert is_known_level(LEVEL_STORED)
        assert is_known_level(LEVEL_REPLICATED)
        assert not is_known_level("fictional-strength")


class TestHandleFieldShape:
    """§5 / §8: ``handle`` is roundtrip-stable; absent by default; not
    pinned to a particular layout (the receiver chooses)."""

    def test_handle_absent_when_not_set(self) -> None:
        r = DurabilityResult(LEVEL_STORED, LEVEL_STORED)
        assert "handle" not in r.to_dict()

    def test_handle_roundtrip(self) -> None:
        r = DurabilityResult(
            LEVEL_STORED, LEVEL_STORED, handle="system/inbox/abc-123",
        )
        wire = r.to_dict()
        assert wire["handle"] == "system/inbox/abc-123"
        assert DurabilityResult.from_dict(wire) == r

    def test_handle_independent_of_layout_choice(self) -> None:
        # §6: receiver chooses layout. Any absolute tree path is valid.
        for path in (
            "system/inbox/rid-1",
            "system/inbox/alice_hex/rid-1",
            "system/durable/by-rid/rid-1",
            "/some_peer/system/inbox/rid-1",
        ):
            r = DurabilityResult(LEVEL_STORED, LEVEL_STORED, handle=path)
            assert DurabilityResult.from_dict(r.to_dict()).handle == path


class TestPinnedReasonSpellings:
    """§7 / §8 MUST: spec-enumerated reason codes use PINNED spellings."""

    def test_spec_enumerated_reasons_are_pinned(self) -> None:
        # If any of these change, cross-impl tooling that branches on
        # the strings breaks. Pinning the values here surfaces breakage.
        assert REASON_NO_DURABLE_STORE == "no_durable_store"
        assert REASON_REQUIRED_UNMET == "durability_required_unmet"
        assert REASON_UNKNOWN_LEVEL == "unknown_level"
        assert REASON_DUPLICATE_REQUEST_ID == "duplicate_request_id"

    def test_status_constants_pinned(self) -> None:
        assert STATUS_ACCEPTED == 202
        assert STATUS_PRECONDITION_FAILED == 412
        assert STATUS_CONFLICT == 409
