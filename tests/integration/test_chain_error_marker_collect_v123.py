"""EXTENSION-CONTINUATION v1.23 §3.4 A.1 — marker retention and self-collection.

v1.23 elevated the marker bind SHOULD → MUST and, in the same move, elevated
collection to MUST: *"A MUST-write paired with a MAY-collect is a leak by
construction."* Until this landed, this peer bound markers and reaped none — a
permanently-failing chain mints ~1,440 markers/day into a tree nothing
collected. Go routed the gap here after building the reference
(`ext/continuation/marker_collect.go`).

The tests that matter are the ones a self-consistent-but-wrong reaper still
fails: that it reaps by the **body's origination timestamp** and not by bind
order, that it refuses to delete anything it did not positively identify as a
marker, and that the **operator's tree config actually reaches the sweep** —
which is the half Go found it had been missing for months (it had named a key
and never read it, so the knob was a name and not a control).
"""

from __future__ import annotations

import pytest

from entity_core.capability.grant import create_full_access_grant
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import ExecuteResult, HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.continuation import (
    CHAIN_ERROR_MARKER_ROOT,
    DEFAULT_MARKER_RETENTION_MS,
    LOST_ERROR_MARKER_TYPE,
    MARKER_COLLECT_THROTTLE_MS,
    MARKER_RETENTION_CONFIG_PATH,
    RETAIN_MARKERS_FOREVER,
    collect_expired_markers,
    marker_retention_from_config,
    maybe_collect_markers,
)

#: A fixed "now" well past the 24h default so a cutoff never underflows.
NOW_MS = 10 * DEFAULT_MARKER_RETENTION_MS


def _pathway() -> EmitPathway:
    kp = Keypair.generate()
    return EmitPathway(ContentStore(), EntityTree(kp.peer_id))


def _bind(
    pathway: EmitPathway,
    *,
    timestamp,
    kind: str = "lost",
    reason: str = "on_error_dispatch_failed",
    entity_type: str = LOST_ERROR_MARKER_TYPE,
) -> str:
    """Put a marker-shaped entity in the tree and return its bound path.

    Built directly rather than through the binder so a test can place a marker
    at an arbitrary age without a clock fixture — the sweep reads the body's
    `timestamp`, which is exactly what is being pinned.
    """
    marker = Entity(
        type=entity_type,
        data={
            "reason": reason,
            "code": reason,
            "status": 500,
            "timestamp": timestamp,
            "chain_id": "collect-test-chain",
            "step_index": "step-1",
        },
    )
    content_hash = pathway.content_store.put(marker)
    path = (
        f"{CHAIN_ERROR_MARKER_ROOT}{kind}/collect-test-chain/step-1/"
        f"{reason}/{content_hash.hex()}"
    )
    full = pathway.entity_tree.normalize_uri(path)
    pathway.entity_tree.set(full, content_hash)
    return full


def _write_config(pathway: EmitPathway, data: dict) -> None:
    """Bind the v1.23 operator knob entity at `system/config/chain-errors`."""
    config = Entity(type="system/config/chain-errors", data=data)
    content_hash = pathway.content_store.put(config)
    pathway.entity_tree.set(
        pathway.entity_tree.normalize_uri(MARKER_RETENTION_CONFIG_PATH),
        content_hash,
    )


def _marker_paths(pathway: EmitPathway) -> list[str]:
    return list(pathway.entity_tree.list_prefix(CHAIN_ERROR_MARKER_ROOT))


class TestTheSweepItself:
    def test_an_expired_marker_is_collected_and_a_fresh_one_is_not(self):
        pathway = _pathway()
        retention = 60_000
        old = _bind(pathway, timestamp=NOW_MS - retention - 1, reason="old_code")
        fresh = _bind(pathway, timestamp=NOW_MS - 1, reason="fresh_code")

        assert collect_expired_markers(pathway, retention, NOW_MS) == 1

        remaining = _marker_paths(pathway)
        assert fresh in remaining
        assert old not in remaining

    def test_the_cutoff_boundary_matches_gos_to_the_millisecond(self):
        """A marker whose age is *exactly* `retention_ms` is collected; one a
        millisecond younger is not. The rule is "`timestamp > cutoff`
        survives", which is Go's `d.Timestamp > cutoff` in
        `CollectExpiredMarkers` verbatim.

        Pinned because it is the kind of off-by-one two impls settle
        differently for no reason, and then a cross-impl marker-count check
        disagrees by one at a boundary nobody can reproduce on demand. Which
        side of the millisecond it falls on does not matter; that both impls
        pick the same side does.
        """
        pathway = _pathway()
        retention = 60_000
        exactly_aged = _bind(pathway, timestamp=NOW_MS - retention, reason="aged")
        one_ms_younger = _bind(
            pathway, timestamp=NOW_MS - retention + 1, reason="younger",
        )

        assert collect_expired_markers(pathway, retention, NOW_MS) == 1
        remaining = _marker_paths(pathway)
        assert exactly_aged not in remaining
        assert one_ms_younger in remaining

    def test_the_body_survives_the_tree_binding(self):
        """Only the pointer is dropped. The body stays content-addressed and
        auditable — the same call `_gc_decided_pending` makes for registry
        pending heads, and what keeps collection a reap of the index rather
        than destruction of the record."""
        pathway = _pathway()
        path = _bind(pathway, timestamp=1)
        content_hash = pathway.entity_tree.get(path)

        assert collect_expired_markers(pathway, 60_000, NOW_MS) == 1
        assert pathway.entity_tree.get(path) is None
        assert pathway.content_store.get(content_hash) is not None

    def test_both_kinds_age_out_identically(self):
        """`lost` (sender-side) and `rejected` (receiver-side) share one root
        and one timestamp field, so the sweep is indifferent to which."""
        pathway = _pathway()
        _bind(pathway, timestamp=1, kind="lost")
        _bind(pathway, timestamp=1, kind="rejected")

        assert collect_expired_markers(pathway, 60_000, NOW_MS) == 2
        assert _marker_paths(pathway) == []

    def test_retain_forever_collects_nothing(self):
        pathway = _pathway()
        _bind(pathway, timestamp=1)
        assert collect_expired_markers(pathway, RETAIN_MARKERS_FOREVER, NOW_MS) == 0
        assert len(_marker_paths(pathway)) == 1

    def test_a_clock_inside_the_window_does_not_sweep_the_tree(self):
        """`now <= retention` would underflow the cutoff and, on unsigned
        arithmetic, sweep everything. Nothing can be expired yet, so nothing is."""
        pathway = _pathway()
        _bind(pathway, timestamp=1)
        assert collect_expired_markers(pathway, 60_000, 60_000) == 0
        assert collect_expired_markers(pathway, 60_000, 59_999) == 0
        assert len(_marker_paths(pathway)) == 1


class TestItRefusesToDeleteWhatItCannotIdentify:
    """Deleting an entity the reaper did not positively identify is how a
    reaper becomes a data-loss bug. Every one of these lives under the marker
    root and every one survives."""

    def test_a_foreign_entity_under_the_marker_root_survives(self):
        pathway = _pathway()
        foreign = _bind(
            pathway, timestamp=1, entity_type="system/runtime/something-else",
        )
        assert collect_expired_markers(pathway, 60_000, NOW_MS) == 0
        assert foreign in _marker_paths(pathway)

    @pytest.mark.parametrize(
        ("timestamp", "because"),
        [
            (None, "absent timestamp — absent evidence is not evidence of age"),
            (0, "the zero sentinel is not an age"),
            ("1700000000000", "a stringified timestamp is not an int"),
            (True, "bool is an int subclass but not a timestamp"),
        ],
    )
    def test_a_marker_without_a_usable_timestamp_is_never_aged_out(
        self, timestamp, because,
    ):
        pathway = _pathway()
        path = _bind(pathway, timestamp=timestamp)
        assert collect_expired_markers(pathway, 60_000, NOW_MS) == 0, because
        assert path in _marker_paths(pathway)

    def test_a_dangling_binding_is_skipped_not_counted(self):
        """A path whose entity is not in the content store resolves to nothing
        — skip it rather than treat the absence as a collectable marker."""
        pathway = _pathway()
        dangling = pathway.entity_tree.normalize_uri(
            f"{CHAIN_ERROR_MARKER_ROOT}lost/c/s/r/deadbeef",
        )
        pathway.entity_tree.set(dangling, b"\x00" + b"\xff" * 32)
        assert collect_expired_markers(pathway, 60_000, NOW_MS) == 0


class TestTheOperatorKnobIsRead:
    """The half Go found it had been missing: it had *named* the retention key
    and never read it from the tree, so the knob was a name and not a control.
    These pin that the config entity actually reaches the sweep."""

    def test_absent_config_reads_as_unset(self):
        assert marker_retention_from_config(_pathway()) is None

    def test_the_configured_window_is_read(self):
        pathway = _pathway()
        _write_config(pathway, {"retention_ms": 1000})
        assert marker_retention_from_config(pathway) == 1000

    def test_unknown_fields_do_not_defeat_the_read(self):
        """V7 forward-compat MUST-ignore: a v1.24 field alongside it must not
        cost the operator their window."""
        pathway = _pathway()
        _write_config(pathway, {"retention_ms": 1000, "future_knob": "whatever"})
        assert marker_retention_from_config(pathway) == 1000

    @pytest.mark.parametrize(
        "value", [None, "86400000", -1, True, {"ms": 5}],
    )
    def test_an_unusable_value_falls_back_rather_than_failing(self, value):
        """The config is advisory over a working default, never a
        precondition — a malformed knob must not disable collection."""
        pathway = _pathway()
        _write_config(pathway, {"retention_ms": value})
        assert marker_retention_from_config(pathway) is None

    def test_tree_config_overrides_the_default(self):
        """Go's `TestTreeConfigOverridesBuilderRetention`, applied here: a
        1000ms tree config collects a marker the 24h default would keep. This
        is the assertion that fails if the sweep silently ignores the tree."""
        pathway = _pathway()
        # Two hours old: inside the 24h default, far outside a 1000ms window.
        path = _bind(pathway, timestamp=NOW_MS - 2 * 60 * 60 * 1000)

        # With no config, the default keeps it.
        assert maybe_collect_markers(pathway, now_ms=NOW_MS) == 0
        assert path in _marker_paths(pathway)

        _write_config(pathway, {"retention_ms": 1000})
        # Past the throttle so the second sweep actually runs.
        collected = maybe_collect_markers(
            pathway, now_ms=NOW_MS + MARKER_COLLECT_THROTTLE_MS,
        )
        assert collected == 1, "the tree config did not reach the sweep"
        assert path not in _marker_paths(pathway)

    def test_an_explicit_zero_turns_collection_off(self):
        """`retention_ms: 0` is RETAIN_MARKERS_FOREVER — distinguishable from
        an absent field, which is why the reader returns None for absent."""
        pathway = _pathway()
        _write_config(pathway, {"retention_ms": 0})
        assert marker_retention_from_config(pathway) == RETAIN_MARKERS_FOREVER

        _bind(pathway, timestamp=1)
        assert maybe_collect_markers(pathway, now_ms=NOW_MS) == 0
        assert len(_marker_paths(pathway)) == 1


class TestTheThrottle:
    def test_a_second_sweep_inside_the_window_is_a_no_op(self):
        """The throttle keeps the amortized cost off the dispatch path."""
        pathway = _pathway()
        _write_config(pathway, {"retention_ms": 1000})
        _bind(pathway, timestamp=1)
        _bind(pathway, timestamp=2, reason="second_code")

        assert maybe_collect_markers(pathway, now_ms=NOW_MS) == 2
        _bind(pathway, timestamp=3, reason="third_code")
        # Inside the throttle window — not swept, so the new marker survives.
        assert maybe_collect_markers(pathway, now_ms=NOW_MS + 1) == 0
        assert len(_marker_paths(pathway)) == 1

    def test_the_throttle_is_per_peer(self):
        """State is keyed on the EmitPathway, so one peer's sweep does not
        silence another's — two peers in one process are two trees."""
        a, b = _pathway(), _pathway()
        for pathway in (a, b):
            _write_config(pathway, {"retention_ms": 1000})
            _bind(pathway, timestamp=1)

        assert maybe_collect_markers(a, now_ms=NOW_MS) == 1
        assert maybe_collect_markers(b, now_ms=NOW_MS) == 1


class TestTheBinderCollects:
    """v1.23's actor answer: *the collector is the binder*. It falls out of
    §3.10.7 — markers are bound in the observing peer's own tree under its own
    authority, so nobody else can collect them. These prove the wiring, which
    is the part that makes the sweep reachable in a real run at all."""

    def _ctx(self, pathway: EmitPathway) -> HandlerContext:
        async def _noop_dispatch(*a, **k) -> ExecuteResult:
            return ExecuteResult(status=200, result={})

        permissive = create_full_access_grant()
        ctx = HandlerContext(
            local_peer_id=pathway.entity_tree.normalize_uri("x").split("/")[1],
            remote_peer_id="remote-peer-id",
            handler_grant=permissive,
            caller_capability=permissive,
            emit_pathway=pathway,
            _execute_dispatcher=_noop_dispatch,
        )
        ctx.chain_id = "collect-wiring-chain"  # type: ignore[attr-defined]
        return ctx

    def test_binding_a_lost_marker_collects_an_expired_one(self):
        from entity_handlers.continuation import _bind_chain_error_marker

        pathway = _pathway()
        _write_config(pathway, {"retention_ms": 1000})
        stale = _bind(pathway, timestamp=1, reason="stale_code")

        bound = _bind_chain_error_marker(
            self._ctx(pathway),
            kind="lost",
            code="on_error_dispatch_failed",
            status=500,
            request_id="step-9",
        )
        assert bound is not None, "the marker bind itself failed"

        remaining = _marker_paths(pathway)
        assert stale not in remaining, "binding did not trigger collection"
        # The marker just written is younger than the window and survives —
        # a sweep that ate its own bind would be worse than no sweep.
        assert len(remaining) == 1

    def test_binding_a_rejected_marker_collects_too(self):
        """A peer that only ever *receives* rejected chains binds from the
        dispatcher side. Without this hook it would bind forever and never
        collect — the same leak wearing a different hat."""
        from entity_handlers.continuation import bind_dispatcher_rejected_marker

        pathway = _pathway()
        _write_config(pathway, {"retention_ms": 1000})
        stale = _bind(pathway, timestamp=1, kind="rejected", reason="stale_code")
        peer_id = pathway.entity_tree.normalize_uri("x").split("/")[1]

        bound = bind_dispatcher_rejected_marker(
            pathway,
            peer_id,
            chain_id="collect-wiring-chain",
            request_id="step-9",
            code="capability_denied",
            status=403,
            requesting_peer_id="stranger",
            attempted_uri="entity://x/system/tree",
        )
        assert bound is not None, "the rejected marker bind itself failed"
        assert stale not in _marker_paths(pathway)
