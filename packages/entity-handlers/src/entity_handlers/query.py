"""Query handler for the query extension (EXTENSION-QUERY v1.0).

Registered at system/query. Provides:
- find: Evaluate query expression, return matching entities
- count: Return count of matching entities

Level 1 conformance: type_filter, ref_filter, path_prefix, eq/not_eq/in/exists
operators, cursor-based pagination, capability-filtered results.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from entity_core.capability.checking import find_matching_grant, get_scope, matches_scope
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.storage.indexes import (
    IndexManager,
    InMemoryReverseHashIndex,
    InMemoryTypeIndex,
    collect_hash_refs,
)
from entity_handlers._common import error_response as _error

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext

logger = logging.getLogger(__name__)

QUERY_HANDLER_PATTERN = "system/query"

DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 10_000
MAX_FIELD_FILTERS = 16
MAX_IN_VALUES = 100


# ---------------------------------------------------------------------------
# Internal match representation
# ---------------------------------------------------------------------------

@dataclass
class _Match:
    """Internal representation of a query match."""

    path: str
    hash: bytes
    type_name: str


# ---------------------------------------------------------------------------
# Query handler factory
# ---------------------------------------------------------------------------

def create_query_handler(index_manager: IndexManager):
    """Create a query handler bound to an IndexManager.

    The returned handler function closes over the IndexManager so it can
    access indexes without modifying HandlerContext.

    Args:
        index_manager: The IndexManager maintaining secondary indexes.

    Returns:
        An async handler function for system/query.
    """

    async def query_handler(
        path: str,
        operation: str,
        params: dict[str, Any],
        ctx: HandlerContext,
    ) -> dict[str, Any]:
        """Handle system/query operations."""
        params_data = params.get("data", params) if isinstance(params, dict) else {}

        if operation == "find":
            return _handle_find(params_data, ctx, index_manager)
        elif operation == "count":
            return _handle_count(params_data, ctx, index_manager)
        else:
            return {
                "status": 501,
                "result": {
                    "type": "system/protocol/error",
                    "data": {
                        "code": "unsupported_operation",
                        "message": f"Query handler does not support operation: {operation}",
                    },
                },
            }

    return query_handler


# ---------------------------------------------------------------------------
# find operation
# ---------------------------------------------------------------------------

def _handle_find(
    expr: dict[str, Any],
    ctx: "HandlerContext",
    index_manager: "IndexManager",
) -> dict[str, Any]:
    """Handle find operation (§5.2)."""
    # Validate expression structure
    err = _validate_expression(expr)
    if err:
        return err

    # §5.2 Step 1: Resolve query constraints and allowances (v7.14)
    constraints, allowances = _resolve_grant_fields(ctx, "find")
    scope = allowances.get("scope", "tree")  # scope is an allowance (expands access)
    type_scope = constraints.get("type_scope")  # type_scope is a constraint (narrows)

    # §5.2 Step 2: Content store scope requires type_scope
    if scope == "content_store" and type_scope is None:
        return _error(403, "content_store_requires_type_scope",
                      "content_store scope requires type_scope on grant constraints")

    # §5.2 Step 3: Validate type_filter against type_scope
    err = _check_type_scope(expr.get("type_filter"), type_scope, ctx)
    if err:
        return err

    # Execute query against indexes
    matches = _execute_query(expr, ctx, index_manager, constraints)

    # Sort
    order_by = expr.get("order_by", "path")
    descending = expr.get("descending", False)
    matches = _sort_matches(matches, order_by, descending, ctx)

    total = len(matches)

    # §5.2 Step 8: Cap limit by grant constraints
    effective_limit = min(
        expr.get("limit") or DEFAULT_QUERY_LIMIT,
        constraints.get("max_results") or MAX_QUERY_LIMIT,
        MAX_QUERY_LIMIT,
    )

    # Pagination
    cursor = expr.get("cursor")
    start, cursor_err = _resolve_cursor(cursor)
    if cursor_err:
        return cursor_err
    page = matches[start : start + effective_limit]
    has_more = start + effective_limit < total

    # Build result matches
    result_matches = []
    included: dict[bytes, dict[str, Any]] = {}

    for m in page:
        match_entry: dict[str, Any] = {
            "hash": m.hash,
            "type": m.type_name,
        }
        if m.path:
            match_entry["path"] = m.path
        result_matches.append(match_entry)

        # Include entities if requested
        if expr.get("include_entities"):
            entity = ctx.emit_pathway.content_store.get(m.hash)
            if entity:
                included[m.hash] = entity.to_dict()

    result_data: dict[str, Any] = {
        "matches": result_matches,
        "total": total,
        "has_more": has_more,
    }
    if has_more:
        result_data["cursor"] = _encode_cursor(start + effective_limit)

    # M3: When entities are included, wrap in system/envelope
    if included:
        return {
            "status": 200,
            "result": {
                "type": "system/envelope",
                "data": {
                    "root": {"type": "system/query/result", "data": result_data},
                    "included": included,
                },
            },
        }

    return {
        "status": 200,
        "result": {
            "type": "system/query/result",
            "data": result_data,
        },
    }


# ---------------------------------------------------------------------------
# count operation
# ---------------------------------------------------------------------------

def _handle_count(
    expr: dict[str, Any],
    ctx: "HandlerContext",
    index_manager: "IndexManager",
) -> dict[str, Any]:
    """Handle count operation (§5.3)."""
    err = _validate_expression(expr)
    if err:
        return err

    constraints, allowances = _resolve_grant_fields(ctx, "count")
    scope = allowances.get("scope", "tree")
    type_scope = constraints.get("type_scope")

    if scope == "content_store" and type_scope is None:
        return _error(403, "content_store_requires_type_scope",
                      "content_store scope requires type_scope on grant constraints")

    err = _check_type_scope(expr.get("type_filter"), type_scope, ctx)
    if err:
        return err

    matches = _execute_query(expr, ctx, index_manager, constraints)

    return {
        "status": 200,
        "result": {
            "type": "primitive/uint",
            "data": len(matches),
        },
    }


# ---------------------------------------------------------------------------
# Expression validation
# ---------------------------------------------------------------------------

def _validate_expression(expr: dict[str, Any]) -> dict[str, Any] | None:
    """Validate a query expression. Returns error response or None."""
    type_filter = expr.get("type_filter")
    field_filters = expr.get("field_filters")
    ref_filter = expr.get("ref_filter")
    path_filter = expr.get("path_filter")
    path_prefix = expr.get("path_prefix")

    # field_filters requires type_filter
    if field_filters and not type_filter:
        return {
            "status": 400,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "type_filter_required",
                    "message": "type_filter is required when field_filters is present",
                },
            },
        }

    # Empty query check
    if not type_filter and not ref_filter and not path_filter and not path_prefix:
        return {
            "status": 400,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "empty_query",
                    "message": "At least one filter must be specified",
                },
            },
        }

    # Validate field_filters count
    if field_filters and len(field_filters) > MAX_FIELD_FILTERS:
        return {
            "status": 400,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "too_many_filters",
                    "message": f"Maximum {MAX_FIELD_FILTERS} field filters allowed",
                },
            },
        }

    # Validate operators in field_filters
    if field_filters:
        for fp in field_filters:
            operator = fp.get("operator", "")
            if operator not in _VALID_OPERATORS:
                return {
                    "status": 400,
                    "result": {
                        "type": "system/protocol/error",
                        "data": {
                            "code": "invalid_operator",
                            "message": f"Unknown operator: {operator}",
                        },
                    },
                }
            if operator == "in":
                vals = fp.get("value", [])
                if isinstance(vals, list) and len(vals) > MAX_IN_VALUES:
                    return {
                        "status": 400,
                        "result": {
                            "type": "system/protocol/error",
                            "data": {
                                "code": "too_many_values",
                                "message": f"Maximum {MAX_IN_VALUES} values for 'in' operator",
                            },
                        },
                    }

    return None


_VALID_OPERATORS = {
    # Level 1
    "eq", "not_eq", "in", "exists",
    # Level 2
    "gt", "lt", "gte", "lte", "prefix", "substring", "contains",
}


# ---------------------------------------------------------------------------
# Constraint resolution (§5.2 steps 1-3)
# ---------------------------------------------------------------------------

def _resolve_grant_fields(
    ctx: "HandlerContext", operation: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract query constraints and allowances from the matching grant.

    V7.14 / EXTENSION-QUERY v1.1: constraints and allowances are separate
    fields on the grant entry. Constraints narrow access (absent = unconstrained).
    Allowances expand access (absent = most restricted).

    Returns (constraints_dict, allowances_dict). Both may be empty.
    """
    cap_data = getattr(ctx, "caller_capability", None)
    if not cap_data or not isinstance(cap_data, dict):
        return {}, {}

    grant = find_matching_grant(
        cap_data, operation, QUERY_HANDLER_PATTERN, ctx.local_peer_id,
    )
    if grant is None:
        return {}, {}

    constraints = grant.get("constraints") or {}
    allowances = grant.get("allowances") or {}

    if not isinstance(constraints, dict):
        constraints = {}
    if not isinstance(allowances, dict):
        allowances = {}

    return constraints, allowances


def _check_type_scope(
    type_filter: str | None,
    type_scope: dict[str, Any] | None,
    ctx: "HandlerContext",
) -> dict[str, Any] | None:
    """Validate type_filter against type_scope constraint (§5.2 step 3).

    Returns error response if type_filter is outside type_scope, or None if OK.
    """
    if type_scope is None or type_filter is None:
        return None

    # type_scope is an id-scope: {include: [...], exclude: [...]}
    from entity_core.capability.token import CapabilityScope
    scope = CapabilityScope(
        include=type_scope.get("include", ["*"]),
        exclude=type_scope.get("exclude"),
    )

    if not matches_scope(scope, type_filter):
        return _error(403, "type_not_authorized",
                      f"type_filter '{type_filter}' not authorized by type_scope")

    return None


def _type_authorized_by_scope(
    type_name: str,
    type_scope: dict[str, Any] | None,
) -> bool:
    """Check if a specific type name is authorized by the type_scope constraint."""
    if type_scope is None:
        return True

    from entity_core.capability.token import CapabilityScope
    scope = CapabilityScope(
        include=type_scope.get("include", ["*"]),
        exclude=type_scope.get("exclude"),
    )
    return matches_scope(scope, type_name)


# ---------------------------------------------------------------------------
# Query execution
# ---------------------------------------------------------------------------

def _execute_query(
    expr: dict[str, Any],
    ctx: "HandlerContext",
    index_manager: "IndexManager",
    constraints: dict[str, Any] | None = None,
) -> list[_Match]:
    """Execute a query expression against indexes and return filtered matches."""
    type_filter = expr.get("type_filter")
    ref_filter = expr.get("ref_filter")
    path_filter = expr.get("path_filter")
    path_prefix = expr.get("path_prefix")
    field_filters = expr.get("field_filters")

    if constraints is None:
        constraints = {}
    type_scope = constraints.get("type_scope")

    candidates: dict[str, _Match] | None = None

    # Strategy: start with the most selective index, intersect remaining

    # 1. Type filter → type index
    if type_filter:
        entries = index_manager.type_index.lookup_pattern(type_filter)
        type_matches = {
            e.path: _Match(path=e.path, hash=e.hash, type_name=e.type_name)
            for e in entries
        }
        candidates = _intersect(candidates, type_matches)

    # 2. Ref filter → reverse hash index
    if ref_filter:
        ref_hash = ref_filter if isinstance(ref_filter, bytes) else ref_filter
        reverse_entries = index_manager.reverse_index.lookup(ref_hash)
        ref_matches: dict[str, _Match] = {}
        for entry in reverse_entries:
            h = ctx.emit_pathway.entity_tree.get(entry.source_path)
            if h is not None:
                ref_matches[entry.source_path] = _Match(
                    path=entry.source_path,
                    hash=h,
                    type_name=entry.source_type,
                )
        candidates = _intersect(candidates, ref_matches)

    # 3. Path filter → scan candidates for entities referencing this path
    if path_filter:
        if index_manager.path_link_index is not None:
            link_entries = index_manager.path_link_index.lookup(path_filter)
            link_matches: dict[str, _Match] = {}
            for entry in link_entries:
                h = ctx.emit_pathway.entity_tree.get(entry.source_path)
                if h is not None:
                    link_matches[entry.source_path] = _Match(
                        path=entry.source_path,
                        hash=h,
                        type_name=entry.source_type,
                    )
            candidates = _intersect(candidates, link_matches)
        elif candidates is not None:
            # Fallback: scan candidates for path references in entity data
            candidates = _filter_by_path_ref(candidates, path_filter, ctx)

    # 4. Path prefix filter
    if path_prefix and candidates is not None:
        full_prefix = ctx.emit_pathway.entity_tree.normalize_uri(path_prefix)
        candidates = {
            p: m for p, m in candidates.items()
            if p.startswith(full_prefix)
        }
    elif path_prefix and candidates is None:
        # Path prefix alone: get all URIs with prefix, look up types
        uris = ctx.emit_pathway.entity_tree.list_prefix(path_prefix)
        prefix_matches: dict[str, _Match] = {}
        for uri in uris:
            h = ctx.emit_pathway.entity_tree.get(uri)
            if h is not None:
                entity = ctx.emit_pathway.content_store.get(h)
                if entity is not None:
                    prefix_matches[uri] = _Match(
                        path=uri, hash=h, type_name=entity.type,
                    )
        candidates = prefix_matches

    if candidates is None:
        candidates = {}

    # 5. Field filters (type scan fallback)
    if field_filters:
        candidates = _apply_field_filters(candidates, field_filters, ctx)

    # 6. Capability filtering per candidate (§5.2 steps 6a, 6b)
    filtered: list[_Match] = []
    for match in candidates.values():
        # 6a. Type scope check
        if type_scope is not None:
            if not _type_authorized_by_scope(match.type_name, type_scope):
                continue

        # 6b. Path permission check
        rel_path = _uri_to_relative_path(match.path, ctx)
        if rel_path is not None and ctx.check_caller_permission("get", rel_path):
            filtered.append(match)

    return filtered


def _intersect(
    current: dict[str, _Match] | None,
    new: dict[str, _Match],
) -> dict[str, _Match]:
    """Intersect two candidate sets by path key."""
    if current is None:
        return new
    return {p: current[p] for p in current if p in new}


def _filter_by_path_ref(
    candidates: dict[str, _Match],
    path_filter: str,
    ctx: "HandlerContext",
) -> dict[str, _Match]:
    """Filter candidates to those whose entity data contains a reference to the given path.

    Fallback for path_filter when no path link index is available.
    Scans entity data for string values matching the path.
    """
    result: dict[str, _Match] = {}
    for path, match in candidates.items():
        entity = ctx.emit_pathway.content_store.get(match.hash)
        if entity is None:
            continue
        if _data_contains_path(entity.data, path_filter):
            result[path] = match
    return result


def _data_contains_path(data: dict[str, Any], target_path: str) -> bool:
    """Check if entity data contains a string value matching target_path."""
    for value in data.values():
        if _value_contains_path(value, target_path):
            return True
    return False


def _value_contains_path(value: Any, target_path: str) -> bool:
    """Recursively check if a value contains the target path string."""
    if isinstance(value, str) and value == target_path:
        return True
    if isinstance(value, dict):
        for v in value.values():
            if _value_contains_path(v, target_path):
                return True
    if isinstance(value, (list, tuple)):
        for item in value:
            if _value_contains_path(item, target_path):
                return True
    return False


def _apply_field_filters(
    candidates: dict[str, _Match],
    field_filters: list[dict[str, Any]],
    ctx: "HandlerContext",
) -> dict[str, _Match]:
    """Apply field predicates via type scan fallback.

    For each candidate, resolve the entity and check all field predicates.
    This is the Level 1 fallback (no field indexes).
    """
    result: dict[str, _Match] = {}
    for path, match in candidates.items():
        entity = ctx.emit_pathway.content_store.get(match.hash)
        if entity is None:
            continue
        if _entity_matches_field_filters(entity.data, field_filters):
            result[path] = match
    return result


def _entity_matches_field_filters(
    data: dict[str, Any],
    field_filters: list[dict[str, Any]],
) -> bool:
    """Check if entity data matches all field predicates (conjunctive)."""
    for fp in field_filters:
        field = fp.get("field", "")
        operator = fp.get("operator", "")
        value = fp.get("value")

        field_value = data.get(field)

        if not _check_predicate(field_value, operator, value):
            return False
    return True


def _check_predicate(field_value: Any, operator: str, value: Any) -> bool:
    """Evaluate a single field predicate."""
    if operator == "exists":
        return field_value is not None

    if operator == "eq":
        return field_value == value

    if operator == "not_eq":
        return field_value != value

    if operator == "in":
        if not isinstance(value, list):
            return False
        return field_value in value

    # Level 2 operators
    if operator == "gt":
        return field_value is not None and field_value > value

    if operator == "lt":
        return field_value is not None and field_value < value

    if operator == "gte":
        return field_value is not None and field_value >= value

    if operator == "lte":
        return field_value is not None and field_value <= value

    if operator == "prefix":
        return (
            isinstance(field_value, str)
            and isinstance(value, str)
            and field_value.startswith(value)
        )

    if operator == "substring":
        return (
            isinstance(field_value, str)
            and isinstance(value, str)
            and value in field_value
        )

    if operator == "contains":
        return isinstance(field_value, (list, tuple)) and value in field_value

    return False


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

def _sort_matches(
    matches: list[_Match],
    order_by: str,
    descending: bool,
    ctx: "HandlerContext",
) -> list[_Match]:
    """Sort matches by the specified field."""
    if order_by == "path":
        # Default: sort by path, ascending. Null paths last.
        matches.sort(key=lambda m: (m.path is None, m.path or ""), reverse=descending)
    else:
        # Sort by entity field value
        def _field_sort_key(m: _Match) -> tuple[bool, Any]:
            entity = ctx.emit_pathway.content_store.get(m.hash)
            if entity is None:
                return (True, "")  # Nulls last
            val = entity.data.get(order_by)
            if val is None:
                return (True, "")  # Nulls last
            return (False, val)

        matches.sort(key=_field_sort_key, reverse=descending)

    return matches


# ---------------------------------------------------------------------------
# Cursor encoding (opaque, offset-based)
# ---------------------------------------------------------------------------

def _encode_cursor(offset: int) -> str:
    """Encode a pagination cursor (opaque to callers)."""
    payload = json.dumps({"o": offset}).encode()
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _resolve_cursor(
    cursor: str | None,
) -> tuple[int, dict[str, Any] | None]:
    """Decode a pagination cursor to an offset.

    Returns (offset, None) on success, or (0, error_response) on invalid cursor.
    """
    if not cursor:
        return 0, None
    try:
        payload = base64.urlsafe_b64decode(cursor.encode("ascii"))
        data = json.loads(payload)
        offset = int(data.get("o", 0))
        if offset < 0:
            return 0, _error(400, "invalid_cursor", "Cursor offset is negative")
        return offset, None
    except Exception:
        return 0, _error(400, "invalid_cursor",
                         "Cursor is expired, malformed, or from a different query")


# ---------------------------------------------------------------------------
# URI helpers
# ---------------------------------------------------------------------------

def _uri_to_relative_path(uri: str, ctx: "HandlerContext") -> str | None:
    """Extract relative path from an absolute path.

    Strips the /{peer_id}/ prefix to get the path for permission checks.
    """
    prefix = f"/{ctx.local_peer_id}/"
    if uri.startswith(prefix):
        return uri[len(prefix):]
    # For remote peer paths, strip the leading /peer_id/
    if uri.startswith("/"):
        parts = uri[1:].split("/", 1)
        return parts[1] if len(parts) > 1 else ""
    return uri


# ---------------------------------------------------------------------------
# QueryExtension - wires IndexManager + query handler into a peer
# ---------------------------------------------------------------------------

class QueryExtension(Extension):
    """Extension that provides secondary indexes and query handler.

    Creates an IndexManager with in-memory indexes, hooks it into the
    EmitPathway for synchronous index maintenance, and rebuilds indexes
    from existing tree data on initialization.

    Usage:
        query_ext = QueryExtension()
        builder.with_handler(
            QUERY_HANDLER_PATTERN,
            query_ext.handler(),
            priority=109,
            name="query",
        )
        builder.with_extension(query_ext)
    """

    def __init__(self) -> None:
        self._index_manager: IndexManager | None = None

    @property
    def index_manager(self) -> IndexManager | None:
        """Access the IndexManager (available after initialize)."""
        return self._index_manager

    def handler(self):
        """Return the query handler function bound to this extension's IndexManager.

        Must be called before build() but the returned function captures
        the extension instance, so the IndexManager is resolved at call time.
        """
        ext = self

        async def _query_handler(
            path: str,
            operation: str,
            params: dict[str, Any],
            ctx: HandlerContext,
        ) -> dict[str, Any]:
            if ext._index_manager is None:
                return {
                    "status": 503,
                    "result": {
                        "type": "system/protocol/error",
                        "data": {
                            "code": "not_initialized",
                            "message": "Query extension not yet initialized",
                        },
                    },
                }
            params_data = params.get("data", params) if isinstance(params, dict) else {}

            if operation == "find":
                return _handle_find(params_data, ctx, ext._index_manager)
            elif operation == "count":
                return _handle_count(params_data, ctx, ext._index_manager)
            else:
                return {
                    "status": 501,
                    "result": {
                        "type": "system/protocol/error",
                        "data": {
                            "code": "unsupported_operation",
                            "message": f"Query handler does not support: {operation}",
                        },
                    },
                }

        return _query_handler

    def initialize(self, ctx: ExtensionContext) -> None:
        """Initialize indexes and hook into EmitPathway."""
        if ctx.emit_pathway is None:
            logger.warning("QueryExtension: no emit_pathway, indexes disabled")
            return

        self._index_manager = IndexManager(
            content_store=ctx.emit_pathway.content_store,
            type_index=InMemoryTypeIndex(),
            reverse_index=InMemoryReverseHashIndex(),
        )

        # Hook into EmitPathway for synchronous index maintenance
        ctx.emit_pathway._add_internal_hook(self._index_manager, name="query/index-manager")

        # Rebuild indexes from existing tree data
        self._index_manager.rebuild(ctx.emit_pathway.entity_tree)

        logger.info("QueryExtension initialized with in-memory indexes")

    def shutdown(self) -> None:
        """Clean up (indexes are in-memory, nothing to persist)."""
        self._index_manager = None
