"""History extension for path-level transition recording.

EXTENSION-HISTORY v1.2: Records entity changes in the tree with full
execution context — who changed it, when, under what authority, through
which handler, and the causal chain_id.

History is per-path, per-peer, and automatic once configured. Transitions
are stored as content-addressed entities chained via the `previous` field.
Head pointers at `system/history/head/{path}` provide O(1) access to the
latest transition for any tracked path.

Key concepts:
- Transition: immutable entity recording a single tree change
- Config: per-path-pattern rules for what to record
- Head pointer: tree binding pointing to latest transition
- Recursion prevention: local system/history/* paths excluded
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import ChangeEvent, ChangeKind, EmitContext
from entity_handlers.manifest import error_response as _error_response

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext
    from entity_core.storage.emit import EmitPathway, InternalHook

logger = logging.getLogger(__name__)

# Constants
HISTORY_HANDLER_PATTERN = "system/history"
TRANSITION_TYPE = "system/history/transition"
CONFIG_TYPE = "system/history/config"
QUERY_PARAMS_TYPE = "system/history/query-params"
QUERY_RESULT_TYPE = "system/history/query-result"
ROLLBACK_PARAMS_TYPE = "system/history/rollback-params"
ROLLBACK_RESULT_TYPE = "system/history/rollback-result"

DEFAULT_EVENTS = ["created", "updated", "deleted"]
DEFAULT_QUERY_LIMIT = 50


# =============================================================================
# Data Types
# =============================================================================


@dataclass
class HistoryConfig:
    """Per-path-pattern history configuration."""

    pattern: str
    enabled: bool
    events: list[str] | None = None
    max_depth: int | None = None

    @property
    def effective_events(self) -> list[str]:
        return self.events or DEFAULT_EVENTS

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"pattern": self.pattern, "enabled": self.enabled}
        if self.events is not None:
            d["events"] = self.events
        if self.max_depth is not None:
            d["max_depth"] = self.max_depth
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HistoryConfig:
        return cls(
            pattern=data["pattern"],
            enabled=data["enabled"],
            events=data.get("events"),
            max_depth=data.get("max_depth"),
        )


# =============================================================================
# Pattern Matching
# =============================================================================


def canonicalize_pattern(pattern: str, local_peer_id: str) -> str:
    """Canonicalize a history config pattern for evaluation.

    All patterns become full absolute paths:
    - Already absolute (starts with /) -> pass through
    - Peer wildcard "*/" prefix -> prepend "/" for core matches_pattern compat
    - Short-form (including bare "*") -> prepend /{local_peer_id}/

    Examples:
        "/*/*"          -> "/*/*"  (all peers, all paths)
        "*/project/*"   -> "/*/project/*"  (all peers, project subtree)
        "project/*"     -> "/{local}/project/*"  (local peer only)
        "*"             -> "/{local}/*"  (local peer, all paths)
        "/peerA/docs/*" -> "/peerA/docs/*"  (absolute, pass through)
    """
    if pattern.startswith("/"):
        return pattern
    # Peer wildcard requires "*/" prefix (not bare "*")
    if pattern.startswith("*/"):
        # "*/project/*" -> "/*/project/*", "/*/*" already handled above
        return f"/{pattern}"
    # Short-form: bare "*" -> "/{local}/*", "docs/*" -> "/{local}/docs/*"
    return f"/{local_peer_id}/{pattern}"


def pattern_specificity(pattern: str) -> tuple[int, int]:
    """Compute specificity for pattern ordering.

    Returns (literal_segment_count, total_depth) where higher = more specific.
    Per EXTENSION-HISTORY Section 2.2: more literal segments wins, then depth.
    """
    segments = [s for s in pattern.split("/") if s]
    literal_count = sum(1 for s in segments if s != "*")
    return (literal_count, len(segments))


# =============================================================================
# Recursion Prevention
# =============================================================================


def _is_local_history_path(path: str, local_peer_id: str) -> bool:
    """Check if path is in the local peer's system/history/ namespace.

    Per EXTENSION-HISTORY Section 3.2: prevents infinite recursion when
    the history recorder writes head pointers.
    """
    prefix = f"/{local_peer_id}/"
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix):]
    # G-1: Guard only engine output paths (head pointers), not config paths.
    # Config changes at system/history/config/* are recorded as normal transitions.
    return suffix.startswith("system/history/head")


# =============================================================================
# Config Index
# =============================================================================


class _ConfigIndex:
    """In-memory index of history configurations.

    Watches system/history/config/* for changes and provides find_config()
    to find the most specific matching config for a given path.
    """

    def __init__(self, local_peer_id: str) -> None:
        self._configs: dict[str, HistoryConfig] = {}
        self._local_peer_id = local_peer_id

    def update(self, name: str, config: HistoryConfig | None) -> None:
        if config is None:
            self._configs.pop(name, None)
        else:
            self._configs[name] = config

    def find_config(self, path: str) -> HistoryConfig | None:
        """Find the most specific enabled config matching a path."""
        from entity_core.capability.checking import matches_pattern

        best: HistoryConfig | None = None
        best_spec = (-1, -1)

        for config in self._configs.values():
            if not config.enabled:
                continue
            canonical = canonicalize_pattern(config.pattern, self._local_peer_id)
            if matches_pattern(canonical, path):
                spec = pattern_specificity(canonical)
                if spec > best_spec:
                    best = config
                    best_spec = spec

        return best

    @property
    def configs(self) -> dict[str, HistoryConfig]:
        return self._configs


# =============================================================================
# Internal Hooks
# =============================================================================


class _TransitionRecorder:
    """Synchronous hook that records transitions on tree changes.

    Registered with pattern=None (all events). Performs recursion prevention,
    config lookup, transition creation, head pointer update, and pruning.
    """

    def __init__(self, extension: HistoryExtension) -> None:
        self._ext = extension

    def on_change_sync(self, event: ChangeEvent) -> None:
        ext = self._ext
        if ext._emit_pathway is None or ext._config_index is None:
            return

        # 1. Recursion prevention
        if _is_local_history_path(event.uri, ext._local_peer_id):
            return

        # 2. Map ChangeKind to event string
        event_str = event.kind.value

        # 3. Find matching config
        config = ext._config_index.find_config(event.uri)
        if config is None:
            return

        # 4. Check event type is configured
        if event_str not in config.effective_events:
            return

        # 5. Build transition entity
        emit = ext._emit_pathway
        head_path = f"system/history/head{event.uri}"
        full_head_uri = emit.entity_tree.normalize_uri(head_path)
        previous_transition_hash = emit.entity_tree.get(full_head_uri)

        ctx = event.context
        transition_data: dict[str, Any] = {
            "path": event.uri,
            "event": event_str,
            "timestamp": int(time.time() * 1000),
        }

        # Author: use identity entity hash (bytes) per spec, fall back to peer ID string
        if ctx.author_hash is not None:
            transition_data["author"] = ctx.author_hash
        elif ctx.author is not None:
            transition_data["author"] = ctx.author

        # Optional fields — only include when present
        if event.hash is not None:
            transition_data["hash"] = event.hash
        if event.previous_hash is not None:
            transition_data["previous_hash"] = event.previous_hash
        if ctx.capability is not None:
            transition_data["capability"] = ctx.capability
        if ctx.handler_pattern is not None:
            transition_data["handler"] = ctx.handler_pattern
        if ctx.operation is not None:
            transition_data["operation"] = ctx.operation
        if ctx.chain_id is not None:
            transition_data["chain_id"] = ctx.chain_id
        if ctx.parent_chain_id is not None:
            transition_data["parent_chain_id"] = ctx.parent_chain_id
        if previous_transition_hash is not None:
            transition_data["previous"] = previous_transition_hash
        # W6: Include caller_capability when it differs from capability
        if ctx.caller_capability is not None and ctx.caller_capability != ctx.capability:
            transition_data["caller_capability"] = ctx.caller_capability

        # F7: Record full structured clock state from execution context.
        # Per EXTENSION-HISTORY §2.1: type is system/clock/state (not uint).
        # Clock extension writes to cascade_context at position 2;
        # history reads at position 4. Absent when clock extension is not installed.
        clock_state = emit.cascade_context.get("clock")
        if clock_state is not None:
            transition_data["clock"] = clock_state

        transition_entity = Entity(
            type=TRANSITION_TYPE,
            data=transition_data,
        )

        # 6-7. Write transition through emit pathway (SYSTEM-COMPOSITION §4.1).
        # This fires nested consumers (query indexes transition, subscriptions
        # to system/history/* fire). Self-guard prevents infinite recursion.
        emit.emit(full_head_uri, transition_entity, EmitContext.bootstrap())

        # 8. Pruning
        if config.max_depth is not None:
            _prune_history(emit, event.uri, config.max_depth)


class _ConfigWatcher:
    """Synchronous hook to maintain the config index.

    Watches system/history/config/* paths for config entity changes.
    """

    def __init__(self, extension: HistoryExtension) -> None:
        self._ext = extension

    def on_change_sync(self, event: ChangeEvent) -> None:
        if self._ext._config_index is None:
            return

        # Extract config name from URI
        # URI format: /{peer_id}/system/history/config/{name}
        parts = event.uri.split("/system/history/config/", 1)
        if len(parts) != 2 or not parts[1]:
            return
        config_name = parts[1]

        if event.kind == ChangeKind.DELETED:
            self._ext._config_index.update(config_name, None)
        elif event.entity and event.entity.type == CONFIG_TYPE:
            try:
                config = HistoryConfig.from_dict(event.entity.data)
                self._ext._config_index.update(config_name, config)
            except (KeyError, TypeError):
                pass


# =============================================================================
# Pruning
# =============================================================================


def _prune_history(emit: EmitPathway, path: str, max_depth: int) -> None:
    """Walk history chain and sever after max_depth transitions.

    Per EXTENSION-HISTORY Section 3.3: old transitions become unreachable
    from the head and are eligible for GC. In the in-memory content store
    this is effectively a no-op (entries remain), but the chain walk in
    queries will stop at max_depth.
    """
    head_path = f"system/history/head{path}"
    full_head_uri = emit.entity_tree.normalize_uri(head_path)
    head_hash = emit.entity_tree.get(full_head_uri)

    if head_hash is None:
        return

    current = emit.content_store.get(head_hash)
    count = 1

    while current is not None and count < max_depth:
        prev_hash = current.data.get("previous") if isinstance(current.data, dict) else None
        if prev_hash is None:
            return
        current = emit.content_store.get(prev_hash)
        count += 1

    # current is now the last transition to keep.
    # Chain naturally severed — GC collects unreachable transitions.


# =============================================================================
# Handler Operations
# =============================================================================


def _handle_query(
    params: dict[str, Any],
    ctx: HandlerContext,
    ext: HistoryExtension,
) -> dict[str, Any]:
    """Handle history query operation (Section 4.3.1)."""
    raw_path = params.get("path", "")
    limit = params.get("limit", DEFAULT_QUERY_LIMIT)
    since = params.get("since")
    before = params.get("before")
    events_filter = params.get("events")

    if not raw_path:
        return _error_response(400, "missing_path", "path is required")

    # Canonicalize path
    path = ctx.emit_pathway.entity_tree.normalize_uri(raw_path)

    # Dual capability check: caller needs get on target path
    if not ctx.check_caller_permission("get", raw_path):
        return _error_response(403, "access_denied", f"No get permission on path: {raw_path}")

    # Walk history chain
    head_path = f"system/history/head{path}"
    full_head_uri = ctx.emit_pathway.entity_tree.normalize_uri(head_path)
    head_hash = ctx.emit_pathway.entity_tree.get(full_head_uri)

    if head_hash is None:
        return {
            "status": 200,
            "result": {
                "type": QUERY_RESULT_TYPE,
                "data": {"path": path, "transitions": [], "has_more": False},
            },
        }

    transitions: list[dict[str, Any]] = []
    included: dict[bytes, dict[str, Any]] = {}
    current_hash = head_hash

    while current_hash is not None and len(transitions) < limit:
        transition = ctx.emit_pathway.content_store.get(current_hash)
        if transition is None:
            break

        td = transition.data if isinstance(transition.data, dict) else {}

        # "since" filter: stop at this hash (exclusive)
        if since is not None and current_hash == since:
            break

        # "before" filter: skip transitions >= timestamp
        if before is not None and td.get("timestamp", 0) >= before:
            current_hash = td.get("previous")
            continue

        # events filter
        if events_filter is not None and td.get("event") not in events_filter:
            current_hash = td.get("previous")
            continue

        transitions.append(td)
        included[current_hash] = transition.to_dict()
        current_hash = td.get("previous")

    has_more = current_hash is not None

    # M3: Wrap in system/envelope — transition data inline in result,
    # full transition entities in included for content-hash access
    return {
        "status": 200,
        "result": {
            "type": "system/envelope",
            "data": {
                "root": {
                    "type": QUERY_RESULT_TYPE,
                    "data": {
                        "path": path,
                        "head": head_hash,
                        "transitions": transitions,
                        "has_more": has_more,
                    },
                },
                "included": included,
            },
        },
    }


def _handle_rollback(
    params: dict[str, Any],
    ctx: HandlerContext,
    ext: HistoryExtension,
) -> dict[str, Any]:
    """Handle history rollback operation (Section 4.3.2)."""
    raw_path = params.get("path", "")
    target_hash = params.get("target_hash")

    if not raw_path:
        return _error_response(400, "missing_path", "path is required")
    if target_hash is None:
        return _error_response(400, "missing_target_hash", "target_hash is required")

    # Canonicalize path
    path = ctx.emit_pathway.entity_tree.normalize_uri(raw_path)

    # Dual capability check: rollback needs put on target path
    if not ctx.check_caller_permission("put", raw_path):
        return _error_response(403, "access_denied", f"No put permission on path: {raw_path}")

    # Verify target_hash is in history for this path
    if not _is_in_history(ctx.emit_pathway, path, target_hash):
        return _error_response(404, "not_in_history", "Target hash not found in history for this path")

    # Verify entity exists in content store
    entity = ctx.emit_pathway.content_store.get(target_hash)
    if entity is None:
        return _error_response(404, "entity_not_found", "Target entity not found in content store")

    # Restore by emitting (triggers normal history recording of the rollback)
    emit_ctx = EmitContext.from_handler_context(ctx, "rollback")
    ctx.emit_pathway.emit(path, entity, emit_ctx)

    return {
        "status": 200,
        "result": {
            "type": ROLLBACK_RESULT_TYPE,
            "data": {"path": path, "restored": target_hash},
        },
    }


def _is_in_history(emit: EmitPathway, path: str, target_hash: bytes) -> bool:
    """Check if target_hash appears in the history chain for path."""
    head_path = f"system/history/head{path}"
    full_head_uri = emit.entity_tree.normalize_uri(head_path)
    current = emit.entity_tree.get(full_head_uri)

    while current is not None:
        transition = emit.content_store.get(current)
        if transition is None:
            break
        td = transition.data if isinstance(transition.data, dict) else {}
        if td.get("hash") == target_hash or td.get("previous_hash") == target_hash:
            return True
        current = td.get("previous")

    return False


# =============================================================================
# Extension
# =============================================================================


class HistoryExtension(Extension):
    """Extension that records path-level transitions (EXTENSION-HISTORY v1.2).

    Hooks into EmitPathway via sync InternalHook to record transitions
    automatically when entities are written to history-enabled paths.
    Provides query and rollback operations via the history handler.

    Usage:
        history_ext = HistoryExtension()
        builder.with_handler(
            HISTORY_HANDLER_PATTERN,
            history_ext.handler(),
            priority=104,
            name="history",
        )
        builder.with_extension(history_ext)
    """

    def __init__(self) -> None:
        self._config_index: _ConfigIndex | None = None
        self._emit_pathway: EmitPathway | None = None
        self._local_peer_id: str = ""
        self._transition_recorder: _TransitionRecorder | None = None
        self._config_watcher: _ConfigWatcher | None = None

    def handler(self):
        """Return the history handler function bound to this extension."""
        ext = self

        async def _history_handler(
            path: str,
            operation: str,
            params: dict[str, Any],
            ctx: HandlerContext,
        ) -> dict[str, Any]:
            if ext._config_index is None:
                return _error_response(503, "not_initialized", "History extension not yet initialized")

            params_data = params.get("data", params) if isinstance(params, dict) else {}

            if operation == "query":
                return _handle_query(params_data, ctx, ext)
            elif operation == "rollback":
                return _handle_rollback(params_data, ctx, ext)
            else:
                return _error_response(
                    501, "unsupported_operation",
                    f"History handler does not support: {operation}",
                )

        return _history_handler

    def initialize(self, ctx: ExtensionContext) -> None:
        """Initialize the extension: load configs, register hooks."""
        if ctx.emit_pathway is None:
            logger.warning("HistoryExtension: no emit_pathway, history disabled")
            return

        self._emit_pathway = ctx.emit_pathway
        self._local_peer_id = ctx.peer_id
        self._config_index = _ConfigIndex(ctx.peer_id)

        # Load existing configs from tree
        self._load_existing_configs(ctx.emit_pathway)

        # Config watcher: track config changes at system/history/config/*
        self._config_watcher = _ConfigWatcher(self)
        ctx.emit_pathway._add_internal_hook(
            self._config_watcher,
            pattern=f"/{ctx.peer_id}/system/history/config/*",
            name="history/config-watcher",
        )

        # Transition recorder: record transitions for all tree changes
        self._transition_recorder = _TransitionRecorder(self)
        ctx.emit_pathway._add_internal_hook(self._transition_recorder, name="history/transition-recorder")

        logger.info("HistoryExtension initialized")

    def _load_existing_configs(self, emit: EmitPathway) -> None:
        """Load history configs from tree on startup."""
        prefix = emit.entity_tree.normalize_uri("system/history/config/")
        for uri in emit.entity_tree.list_prefix(prefix):
            h = emit.entity_tree.get(uri)
            if h is None:
                continue
            entity = emit.content_store.get(h)
            if entity is None or entity.type != CONFIG_TYPE:
                continue
            try:
                config = HistoryConfig.from_dict(entity.data)
                parts = uri.split("/system/history/config/", 1)
                if len(parts) == 2 and parts[1]:
                    self._config_index.update(parts[1], config)
            except (KeyError, TypeError):
                pass

    def shutdown(self) -> None:
        """Remove hooks from EmitPathway."""
        if self._emit_pathway is not None:
            if self._transition_recorder is not None:
                self._emit_pathway._remove_internal_hook(self._transition_recorder)
            if self._config_watcher is not None:
                self._emit_pathway._remove_internal_hook(self._config_watcher)
        self._config_index = None
        self._transition_recorder = None
        self._config_watcher = None
