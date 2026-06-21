"""Clock extension handler (EXTENSION-CLOCK v1.0).

Provides unified timing mechanism with multiple clock disciplines:
- Wall-clock: Simple millisecond timestamps
- Logical: Lamport-style causal ordering
- Vector: Peer-indexed counters for concurrency detection
- HLC: Hybrid logical clock for total ordering

Operations:
- now: Read current clock state
- compare: Compare two clock values
- tick: Subscribe to periodic clock events (via subscription handler)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import ChangeEvent, EmitContext

logger = logging.getLogger(__name__)

CLOCK_HANDLER_PATTERN = "system/clock"

# Constants per EXTENSION-CLOCK v1.0 §8
DEFAULT_TICK_INTERVAL_MS = 1000
MAX_VECTOR_ENTRIES = 1024
MAX_HLC_DRIFT_MS = 60000
DEFAULT_CLOCK_MODE = "wall"


def system_clock_ms() -> int:
    """Return wall-clock milliseconds since Unix epoch.

    Per EXTENSION-CLOCK v1.0 §2.1.
    """
    return int(time.time() * 1000)


@dataclass
class ClockState:
    """Current clock state for a peer."""

    mode: str
    timestamp_ms: int | None = None
    logical_counter: int | None = None
    vector_entries: dict[str, int] | None = None
    hlc_physical: int | None = None
    hlc_logical: int | None = None
    hlc_peer: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to entity data dict."""
        result: dict[str, Any] = {"mode": self.mode}

        if self.timestamp_ms is not None:
            result["timestamp"] = {"ms": self.timestamp_ms}

        if self.logical_counter is not None:
            result["logical"] = {"counter": self.logical_counter}

        if self.vector_entries is not None:
            result["vector"] = {"entries": self.vector_entries}

        if self.hlc_physical is not None:
            result["hlc"] = {
                "physical": self.hlc_physical,
                "logical": self.hlc_logical or 0,
                "peer": self.hlc_peer,
            }

        return result


def _get_config(ctx: HandlerContext) -> dict[str, Any]:
    """Get clock configuration from tree."""
    config_uri = ctx.emit_pathway.entity_tree.normalize_uri("system/clock/config")
    config_hash = ctx.emit_pathway.entity_tree.get(config_uri)
    if config_hash:
        entity = ctx.emit_pathway.content_store.get(config_hash)
        if entity:
            return entity.data
    return {"mode": DEFAULT_CLOCK_MODE, "wall_clock": True}


def _read_logical(ctx: HandlerContext) -> int:
    """Read current logical clock counter."""
    uri = ctx.emit_pathway.entity_tree.normalize_uri("system/clock/logical")
    h = ctx.emit_pathway.entity_tree.get(uri)
    if h:
        entity = ctx.emit_pathway.content_store.get(h)
        if entity:
            return entity.data.get("counter", 0)
    return 0


def _read_vector(ctx: HandlerContext) -> dict[str, int]:
    """Read current vector clock entries."""
    uri = ctx.emit_pathway.entity_tree.normalize_uri("system/clock/vector")
    h = ctx.emit_pathway.entity_tree.get(uri)
    if h:
        entity = ctx.emit_pathway.content_store.get(h)
        if entity:
            return entity.data.get("entries", {})
    return {}


def _read_hlc(ctx: HandlerContext) -> tuple[int, int, bytes | None]:
    """Read current HLC state (physical, logical, peer)."""
    uri = ctx.emit_pathway.entity_tree.normalize_uri("system/clock/hlc")
    h = ctx.emit_pathway.entity_tree.get(uri)
    if h:
        entity = ctx.emit_pathway.content_store.get(h)
        if entity:
            data = entity.data
            return (
                data.get("physical", system_clock_ms()),
                data.get("logical", 0),
                data.get("peer"),
            )
    return (system_clock_ms(), 0, None)


def _read_clock_state(ctx: HandlerContext) -> ClockState:
    """Read current clock state based on configuration.

    Per EXTENSION-CLOCK v1.0 §3.2.
    """
    config = _get_config(ctx)
    mode = config.get("mode", DEFAULT_CLOCK_MODE)
    wall_clock = config.get("wall_clock", True)

    state = ClockState(mode=mode)

    # Wall clock timestamp
    if mode == "wall" or wall_clock:
        state.timestamp_ms = system_clock_ms()

    # Logical clock (used by logical, vector, hlc modes)
    if mode in ("logical", "vector", "hlc"):
        state.logical_counter = _read_logical(ctx)

    # Vector clock
    if mode == "vector":
        state.vector_entries = _read_vector(ctx)

    # HLC
    if mode == "hlc":
        physical, logical, peer = _read_hlc(ctx)
        state.hlc_physical = physical
        state.hlc_logical = logical
        state.hlc_peer = peer

    return state


def _compare_timestamps(a: dict[str, Any], b: dict[str, Any]) -> str:
    """Compare two timestamp values.

    Per EXTENSION-CLOCK v1.0 §6.4.1.
    """
    a_ms = a.get("ms", 0)
    b_ms = b.get("ms", 0)
    if a_ms < b_ms:
        return "before"
    if a_ms > b_ms:
        return "after"
    return "equal"


def _compare_logical(a: dict[str, Any], b: dict[str, Any]) -> str:
    """Compare two logical clock values.

    Per EXTENSION-CLOCK v1.0 §6.4.2.
    """
    a_counter = a.get("counter", 0)
    b_counter = b.get("counter", 0)
    if a_counter < b_counter:
        return "before"
    if a_counter > b_counter:
        return "after"
    return "equal"


def _compare_vector(a: dict[str, Any], b: dict[str, Any]) -> str:
    """Compare two vector clock values.

    Per EXTENSION-CLOCK v1.0 §6.4.3.
    """
    a_entries = a.get("entries", {})
    b_entries = b.get("entries", {})
    all_peers = set(a_entries.keys()) | set(b_entries.keys())

    a_leq_b = True
    b_leq_a = True
    equal = True

    for peer_id in all_peers:
        a_val = a_entries.get(peer_id, 0)
        b_val = b_entries.get(peer_id, 0)
        if a_val > b_val:
            a_leq_b = False
            equal = False
        if b_val > a_val:
            b_leq_a = False
            equal = False

    if equal:
        return "equal"
    if a_leq_b:
        return "before"
    if b_leq_a:
        return "after"
    return "concurrent"


def _compare_hlc(a: dict[str, Any], b: dict[str, Any]) -> str:
    """Compare two HLC values.

    Per EXTENSION-CLOCK v1.0 §6.4.4.
    """
    a_phys = a.get("physical", 0)
    b_phys = b.get("physical", 0)
    if a_phys < b_phys:
        return "before"
    if a_phys > b_phys:
        return "after"

    a_log = a.get("logical", 0)
    b_log = b.get("logical", 0)
    if a_log < b_log:
        return "before"
    if a_log > b_log:
        return "after"

    # Compare peer identity for total order
    a_peer = a.get("peer")
    b_peer = b.get("peer")
    if a_peer is not None and b_peer is not None:
        if a_peer < b_peer:
            return "before"
        if a_peer > b_peer:
            return "after"

    return "equal"


def _detect_clock_type(value: dict[str, Any]) -> str:
    """Detect the type of clock value."""
    if "ms" in value:
        return "timestamp"
    if "counter" in value:
        return "logical"
    if "entries" in value:
        return "vector"
    if "physical" in value:
        return "hlc"
    return "unknown"


def _compare_clocks(a: Any, b: Any) -> str:
    """Compare two clock values of the same type.

    Per EXTENSION-CLOCK v1.0 §3.3.
    """
    if not isinstance(a, dict) or not isinstance(b, dict):
        return "equal"

    a_type = _detect_clock_type(a)
    b_type = _detect_clock_type(b)

    if a_type != b_type:
        # Can't compare different types meaningfully
        return "equal"

    if a_type == "timestamp":
        return _compare_timestamps(a, b)
    if a_type == "logical":
        return _compare_logical(a, b)
    if a_type == "vector":
        return _compare_vector(a, b)
    if a_type == "hlc":
        return _compare_hlc(a, b)

    return "equal"


async def clock_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle system/clock operations.

    Per EXTENSION-CLOCK v1.0 §3.

    Operations:
    - now: Return current clock state
    - compare: Compare two clock values
    - tick: Create tick subscription (delegates to subscription handler)
    """
    params_data = params.get("data", params) if isinstance(params, dict) else {}

    if operation == "now":
        return await _handle_now(ctx)
    elif operation == "compare":
        return await _handle_compare(params_data, ctx)
    elif operation == "tick":
        return await _handle_tick(params_data, ctx)
    else:
        return {
            "status": 501,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "unsupported_operation",
                    "message": f"Clock handler does not support operation: {operation}",
                },
            },
        }


async def _handle_now(ctx: HandlerContext) -> dict[str, Any]:
    """Handle now operation - return current clock state.

    Per EXTENSION-CLOCK v1.0 §3.2.
    """
    state = _read_clock_state(ctx)
    return {
        "status": 200,
        "result": {
            "type": "system/clock/state",
            "data": state.to_dict(),
        },
    }


async def _handle_compare(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle compare operation - compare two clock values.

    Per EXTENSION-CLOCK v1.0 §3.3.
    """
    a = params.get("a")
    b = params.get("b")

    if a is None or b is None:
        return {
            "status": 400,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "invalid_params",
                    "message": "Both 'a' and 'b' clock values are required",
                },
            },
        }

    order = _compare_clocks(a, b)
    return {
        "status": 200,
        "result": {
            "type": "system/clock/compare-result",
            "data": {"order": order},
        },
    }


async def _handle_tick(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle tick operation - create subscription for periodic clock events.

    Per EXTENSION-CLOCK v1.0 §3.4.
    Delegates to subscription handler with pattern system/clock/tick/latest.
    """
    # This delegates to the subscription handler
    # The tick interval is configured in system/clock/config
    result = await ctx.execute(
        uri="system/subscription",
        operation="subscribe",
        params={
            "type": "system/subscription/request",
            "data": {
                "pattern": "system/clock/tick/latest",
                "events": ["update"],
                "deliver_to": params.get("deliver_to"),
                "deliver_token": params.get("deliver_token"),
            },
        },
    )

    if result.ok:
        return {"status": 200, "result": result.result}
    else:
        return {"status": result.status, "error": result.error}


# =============================================================================
# Clock Advancement (Emit Integration)
# Per EXTENSION-CLOCK v1.0 §4
# =============================================================================


_CLOCK_ENGINE_PATHS = frozenset({
    "system/clock/logical",
    "system/clock/vector",
    "system/clock/hlc",
})


def _is_clock_engine_path(path: str) -> bool:
    """Check if path is a clock engine output path (MUST guard).

    Per EXTENSION-CLOCK §4.1 + §4.3: Only engine state paths are guarded.
    Config paths (system/clock/config) advance the clock like any other write.
    """
    return path in _CLOCK_ENGINE_PATHS


def advance_clock(
    emit_pathway: Any,
    local_peer_id: str,
    path: str,
) -> dict[str, Any] | None:
    """Advance the clock on a tree write.

    Per EXTENSION-CLOCK v1.0 §4.1-4.2.
    Called by emit pathway before other consumers.

    Args:
        emit_pathway: The emit pathway (for tree/content store access).
        local_peer_id: This peer's ID.
        path: The path being written (clock paths are excluded).

    Returns:
        Clock state dict for execution_context, or None if no advancement.
    """
    # G-1: Guard only engine output paths. Config changes at
    # system/clock/config advance the clock like any other write.
    if _is_clock_engine_path(path):
        return None

    # Read config
    config_uri = emit_pathway.entity_tree.normalize_uri("system/clock/config")
    config_hash = emit_pathway.entity_tree.get(config_uri)
    config: dict[str, Any] = {"mode": DEFAULT_CLOCK_MODE, "wall_clock": True}
    if config_hash:
        entity = emit_pathway.content_store.get(config_hash)
        if entity:
            config = entity.data

    mode = config.get("mode", DEFAULT_CLOCK_MODE)
    clock_result: dict[str, Any] = {"mode": mode}

    # Wall clock only
    if mode == "wall":
        clock_result["timestamp"] = {"ms": system_clock_ms()}
        return clock_result

    # Logical clock (used by all non-wall modes)
    logical_uri = emit_pathway.entity_tree.normalize_uri("system/clock/logical")
    logical_hash = emit_pathway.entity_tree.get(logical_uri)
    current_counter = 0
    if logical_hash:
        entity = emit_pathway.content_store.get(logical_hash)
        if entity:
            current_counter = entity.data.get("counter", 0)

    new_counter = current_counter + 1
    new_logical = Entity(
        type="system/clock/logical",
        data={"counter": new_counter},
    )
    # Store directly without triggering emit (to avoid recursion)
    logical_content_hash = emit_pathway.content_store.put(new_logical)
    emit_pathway.entity_tree.set(logical_uri, logical_content_hash)
    clock_result["logical"] = {"counter": new_counter}

    # Vector clock
    if mode == "vector":
        vector_uri = emit_pathway.entity_tree.normalize_uri("system/clock/vector")
        vector_hash = emit_pathway.entity_tree.get(vector_uri)
        current_entries: dict[str, int] = {}
        if vector_hash:
            entity = emit_pathway.content_store.get(vector_hash)
            if entity:
                current_entries = dict(entity.data.get("entries", {}))

        # Increment our entry
        current_entries[local_peer_id] = new_counter

        # Prune if exceeds max entries
        if len(current_entries) > MAX_VECTOR_ENTRIES:
            # Remove entry with lowest counter
            min_peer = min(current_entries, key=lambda p: current_entries[p])
            del current_entries[min_peer]

        new_vector = Entity(
            type="system/clock/vector",
            data={"entries": current_entries},
        )
        vector_content_hash = emit_pathway.content_store.put(new_vector)
        emit_pathway.entity_tree.set(vector_uri, vector_content_hash)
        clock_result["vector"] = {"entries": current_entries}

    # HLC
    if mode == "hlc":
        hlc_uri = emit_pathway.entity_tree.normalize_uri("system/clock/hlc")
        hlc_hash = emit_pathway.entity_tree.get(hlc_uri)
        current_physical = 0
        current_logical = 0
        if hlc_hash:
            entity = emit_pathway.content_store.get(hlc_hash)
            if entity:
                current_physical = entity.data.get("physical", 0)
                current_logical = entity.data.get("logical", 0)

        # HLC local event algorithm (§6.2)
        wall = system_clock_ms()
        new_physical = max(wall, current_physical)

        if new_physical == current_physical:
            new_hlc_logical = current_logical + 1
        else:
            new_hlc_logical = 0  # Physical advanced, reset logical

        # Get peer identity hash
        peer_hash = _get_peer_identity_hash(emit_pathway, local_peer_id)

        new_hlc = Entity(
            type="system/clock/hlc",
            data={
                "physical": new_physical,
                "logical": new_hlc_logical,
                "peer": peer_hash,
            },
        )
        hlc_content_hash = emit_pathway.content_store.put(new_hlc)
        emit_pathway.entity_tree.set(hlc_uri, hlc_content_hash)
        clock_result["hlc"] = {
            "physical": new_physical,
            "logical": new_hlc_logical,
            "peer": peer_hash,
        }

    # Add wall clock timestamp if configured
    if config.get("wall_clock", True):
        clock_result["timestamp"] = {"ms": system_clock_ms()}

    return clock_result


def _get_peer_identity_hash(emit_pathway: Any, peer_id: str) -> bytes | None:
    """Get the content hash of the peer-keypair entity (V7 system/peer)."""
    identity_uri = emit_pathway.entity_tree.normalize_uri("system/peer")
    h = emit_pathway.entity_tree.get(identity_uri)
    return h


# =============================================================================
# Clock Extension (emit-pathway hook for automatic advancement)
# =============================================================================


class _ClockAdvancementHook:
    """Internal hook that advances the clock on tree writes."""

    def __init__(self, ext: ClockExtension) -> None:
        self._ext = ext

    CONTEXT_FIELD = "clock"
    CONTEXT_OWNER = "clock/advancement"

    def on_change_sync(self, event: ChangeEvent) -> int | None:
        path = event.uri
        peer_id = self._ext._peer_id
        if peer_id and path.startswith(f"/{peer_id}/"):
            path = path[len(f"/{peer_id}/"):]
        try:
            clock_state = advance_clock(self._ext._emit, peer_id, path)
            if clock_state is not None:
                self._ext._emit.set_context_field(
                    self.CONTEXT_FIELD, clock_state, self.CONTEXT_OWNER,
                )
        except Exception:
            logger.debug("Clock advancement failed for %s", event.uri, exc_info=True)
        return None


class ClockExtension(Extension):
    """Extension that advances the clock on every tree write.

    Per EXTENSION-CLOCK §4: the clock advances on all tree writes
    (create/update). Deletes and clock engine paths are excluded.
    """

    def initialize(self, ctx: ExtensionContext) -> None:
        self._emit = ctx.emit_pathway
        self._peer_id = ctx.peer_id

        ctx.emit_pathway.register_context_field(
            _ClockAdvancementHook.CONTEXT_FIELD,
            _ClockAdvancementHook.CONTEXT_OWNER,
        )
        self._hook = _ClockAdvancementHook(self)
        ctx.emit_pathway._add_internal_hook(self._hook, name="clock/advancement")
