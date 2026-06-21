"""System tree handler for entity tree operations.

Per ENTITY-CORE-PROTOCOL-V7 §6.3, the tree handler provides direct access to
the entity tree (location index + content store) with two-level capability checks.

Core operations:
- get: Read an entity or listing (trailing / = listing)
- put: Store entity or remove binding (null entity = remove)

Extension operations (EXTENSION-TREE):
- snapshot: Capture tree state as content-addressable entity
- diff: Compare two snapshots
- merge: Apply snapshot bindings into a tree
- extract: Bundle subtree as transferable envelope
- create: Create a non-default tree
- destroy: Remove a non-default tree
"""

from __future__ import annotations

import logging
from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.storage.entity_tree import EntityTree
from entity_core.types.deletion_marker import is_deletion_marker
from entity_core.utils.ecf import Hash, hash_to_display, is_zero_hash
from entity_core.utils.path import validate_path_chars
from entity_handlers.manifest import error_response as _error_response

logger = logging.getLogger(__name__)

TREE_HANDLER_PATTERN = "system/tree"


async def tree_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle system/tree operations.

    V4 Two-level capability check:
    1. Handler scope: system/tree with operation (checked by dispatch)
    2. Path scope: actual path with get/put

    Args:
        path: The full path (including system/tree prefix).
        operation: The operation (get, put, snapshot, diff, merge, extract, create, destroy).
        params: Operation parameters.
        ctx: Handler context.

    Returns:
        Response dict with status and result.
    """
    # Extract params data (params is a full entity per spec §3.4)
    params_data = params.get("data", params) if isinstance(params, dict) else {}

    if operation == "get":
        return await _handle_get(params_data, ctx)
    elif operation == "put":
        return await _handle_put(params_data, ctx)
    elif operation == "snapshot":
        return await _handle_snapshot(params_data, ctx)
    elif operation == "diff":
        return await _handle_diff(params_data, ctx)
    elif operation == "merge":
        return await _handle_merge(params_data, ctx)
    elif operation == "extract":
        return await _handle_extract(params_data, ctx)
    elif operation == "create":
        return await _handle_create(params_data, ctx)
    elif operation == "destroy":
        return await _handle_destroy(params_data, ctx)
    else:
        return {
            "status": 501,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "unsupported_operation",
                    "message": f"Tree handler does not support operation: {operation}",
                },
            },
        }


async def _handle_get(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle get operation - entity read or listing.

    Per spec §6.3:
    - path without trailing /: return entity at path
    - path with trailing / or empty: return listing
    - mode "hash": return only content hash

    V7 §3.2: the authorization-bearing path SHOULD ride in
    execute.resource.targets (then the dispatch layer's capability check
    covers it). Taking it from params is the sanctioned alternative — but
    then the handler MUST perform its own auth check against that path,
    which the check_caller_permission below does for both sources.

    Args:
        params: Request parameters (mode, limit, offset, path).
        ctx: Handler context with resource_targets.

    Returns:
        Response dict with status and result.
    """
    # V7 §3.2: prefer the resource target; else the path rides in params
    # (sanctioned — the handler-side check below carries the auth obligation).
    if ctx.resource_targets:
        request_path = ctx.resource_targets[0]
    else:
        request_path = params.get("path", "")
    mode = params.get("mode", "entity")
    limit = params.get("limit")
    offset = params.get("offset", 0)

    # Defense-in-depth: check caller's capability grants access to this path
    if not ctx.check_caller_permission("get", request_path):
        return {
            "status": 403,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "forbidden",
                    "message": f"Capability doesn't grant get on path: {request_path}",
                },
            },
        }

    # Trailing slash or empty = listing
    if request_path.endswith("/") or request_path == "":
        return _handle_tree_listing(request_path, ctx, limit, offset)

    # Get by path
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(request_path)
    content_hash = ctx.emit_pathway.entity_tree.get(full_uri)

    if content_hash is None:
        return {
            "status": 404,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "not_found",
                    "message": f"Not found: {request_path}",
                },
            },
        }

    # Mode "hash" = return only the hash (as bytes for wire format)
    if mode == "hash":
        return {
            "status": 200,
            "result": {
                "type": "system/hash",
                "data": {"hash": content_hash},
            },
        }

    # Mode "entity" = return full entity
    entity = ctx.emit_pathway.content_store.get(content_hash)
    if entity is None:
        return {
            "status": 404,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "entity_missing",
                    "message": f"Entity missing from content store: {hash_to_display(content_hash)}",
                },
            },
        }

    return {
        "status": 200,
        "result": entity.to_dict(),
    }


def _handle_tree_listing(
    path: str,
    ctx: HandlerContext,
    limit: int | None,
    offset: int,
) -> dict[str, Any]:
    """Handle tree listing for paths ending with / or empty.

    Args:
        path: The prefix path (ends with / or empty).
        ctx: Handler context.
        limit: Maximum entries to return.
        offset: Skip this many entries.

    Returns:
        Response dict with tree/listing entity.
    """
    prefix = ctx.emit_pathway.entity_tree.normalize_uri(path)
    uris = ctx.emit_pathway.entity_tree.list_prefix(prefix)

    # Build entries: extract child names and their info
    entries: dict[str, dict[str, Any]] = {}
    seen_prefixes: set[str] = set()

    for uri in uris:
        # Get the part after the prefix
        suffix = uri[len(prefix):]
        if not suffix:
            continue

        # Get immediate child name (first path segment)
        parts = suffix.split("/")
        child_name = parts[0]

        if child_name in seen_prefixes:
            continue
        seen_prefixes.add(child_name)

        # Check if this is a direct entity or a subtree
        child_uri = prefix + child_name
        content_hash = ctx.emit_pathway.entity_tree.get(child_uri)
        has_children = len(parts) > 1 or any(
            u.startswith(child_uri + "/") for u in uris
        )

        entries[child_name] = {
            "hash": content_hash,  # bytes or None for wire format
            "has_children": has_children,
        }

    # V7 §6.3 + v7.72 §9.5a CORE-TREE-DELETE-1: a direct child bound to a
    # system/deletion-marker is omitted from the listing. O(1) format-relative
    # hash test, no store I/O. A marker-bound leaf with no nested children
    # drops entirely; one that still has nested children stays as a
    # directory-only entry (its binding indicator suppressed). Filter runs
    # before pagination so count reflects the live (non-tombstoned) set.
    for child_name in list(entries.keys()):
        info = entries[child_name]
        if is_deletion_marker(info["hash"]):
            info["hash"] = None
            if not info["has_children"]:
                del entries[child_name]

    # Apply offset and limit
    sorted_entries = sorted(entries.items())
    total_count = len(sorted_entries)

    if offset > 0:
        sorted_entries = sorted_entries[offset:]
    if limit is not None:
        sorted_entries = sorted_entries[:limit]

    paginated_entries = dict(sorted_entries)

    result = {
        "type": "system/tree/listing",
        "data": {
            "path": path,
            "entries": paginated_entries,
            "count": total_count,
            "offset": offset,
        },
    }
    return {"status": 200, "result": result}


async def _handle_put(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle put operation - store entity or remove binding.

    Per spec §6.3:
    - entity present: store entity and bind path
    - entity absent/null: remove binding at path

    V7 §3.2: the authorization-bearing path SHOULD ride in
    execute.resource.targets (then the dispatch layer's capability check
    covers it). Taking it from params is the sanctioned alternative — but
    then the handler MUST perform its own auth check against that path,
    which the check_caller_permission below does for both sources.

    Args:
        params: Request parameters (entity, path).
        ctx: Handler context with resource_targets.

    Returns:
        Response dict with status and result.
    """
    # V7 §3.2: prefer the resource target; else the path rides in params
    # (sanctioned — the handler-side check below carries the auth obligation).
    if ctx.resource_targets:
        request_path = ctx.resource_targets[0]
    else:
        request_path = params.get("path", "")
    entity_data = params.get("entity")
    expected_hash = params.get("expected_hash")

    # V7 §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1: reject control characters
    # (NUL, C0 range, DEL) in the write path before any binding. Form-agnostic
    # char scan — runs ahead of the auth check so a malformed path fails
    # structurally with 400 invalid_path rather than leaking an authz verdict.
    path_char_error = validate_path_chars(request_path)
    if path_char_error is not None:
        return _error_response(400, "invalid_path", f"invalid path: {path_char_error}")

    # Defense-in-depth: check caller's capability grants access to this path
    if not ctx.check_caller_permission("put", request_path):
        return {
            "status": 403,
            "result": {
                "type": "system/protocol/error",
                "data": {
                    "code": "forbidden",
                    "message": f"Capability doesn't grant put on path: {request_path}",
                },
            },
        }

    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(request_path)

    # CAS check (V7 §3.9, three cases; the zero-hash case is v7.50 CAS-create).
    # Applies to both write and remove. ABSENT (None) → unconditional.
    if expected_hash is not None:
        current_hash = ctx.emit_pathway.entity_tree.get(full_uri)
        if is_zero_hash(expected_hash):
            # CAS-create: the zero hash means "expect the path unbound". Succeed
            # only if currently unbound; a binding already present → 409. This is
            # what lets the mirror recipe bootstrap a fresh path from a created
            # event (previous_hash zero/absent → expected_hash zero) as a clean
            # create instead of an unconditional overwrite (EXTENSION-SUBSCRIPTION
            # §2.2 mirror recipe).
            if current_hash is not None:
                return _error_response(
                    409,
                    "hash_mismatch",
                    f"CAS-create expected path unbound, but {request_path} is bound",
                )
        elif current_hash != expected_hash:
            # CAS-replace: a known prior hash gates the replace (differs or
            # unbound → 409).
            return _error_response(
                409,
                "hash_mismatch",
                f"expected_hash does not match current binding at {request_path}",
            )

    # Remove binding if entity is null/absent
    if entity_data is None:
        ctx.emit_pathway.entity_tree.remove(full_uri)
        return {
            "status": 200,
            "result": {
                "type": "system/tree/put-result",
                "data": {"path": request_path, "removed": True},
            },
        }

    # Store entity
    entity = Entity.from_dict(entity_data)
    emit_ctx = EmitContext.from_handler_context(ctx, "put")
    emit_result = ctx.emit_pathway.emit(full_uri, entity, emit_ctx)

    if emit_result.status >= 500:
        return _error_response(
            503, "cascade_depth_exceeded",
            "Write refused: cascade depth limit exceeded",
        )

    if emit_result.status == 207:
        halted_list = []
        if emit_result.consumers_halted:
            halted_list.append({
                "name": emit_result.consumers_halted.name,
                "error": {
                    "type": "system/protocol/error",
                    "data": {
                        "code": "cascade_halt",
                        "message": f"Consumer returned status {emit_result.consumers_halted.status}",
                    },
                },
            })
        return {
            "status": 207,
            "result": {
                "type": "system/tree/partial-result",
                "data": {
                    "binding_committed": True,
                    "consumers_completed": list(emit_result.consumers_completed),
                    "consumers_halted": halted_list,
                    "consumers_skipped": list(emit_result.consumers_skipped),
                    "cascade_depth": emit_result.cascade_depth,
                },
            },
        }

    return {
        "status": 200,
        "result": {
            "type": "system/tree/put-result",
            "data": {"path": request_path, "hash": emit_result.hash, "uri": full_uri},
        },
    }


# =============================================================================
# Tree Extension Operations (EXTENSION-TREE.md v3.0)
# =============================================================================


def _get_tree(ctx: HandlerContext, tree_id: str | None) -> EntityTree | None:
    """Get tree by ID, defaulting to default tree.

    Args:
        ctx: Handler context with tree registry.
        tree_id: Tree ID to look up, or None for default tree.

    Returns:
        The EntityTree if found, None if tree_id specified but not found.
    """
    if not tree_id:
        return ctx.emit_pathway.entity_tree
    if ctx.tree_registry:
        return ctx.tree_registry.get(tree_id)
    return None


async def _handle_snapshot(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle snapshot operation - capture tree state.

    Per EXTENSION-TREE.md §3:
    - Captures tree bindings as content-addressable entity
    - Same bindings produce same snapshot (deterministic)
    - Non-empty prefix must end with /

    Args:
        params: Request parameters (prefix, tree_id).
        ctx: Handler context.

    Returns:
        Response dict with snapshot entity.
    """
    prefix = params.get("prefix", "")
    tree_id = params.get("tree_id")

    # Validate prefix format
    if prefix and not prefix.endswith("/"):
        return _error_response(400, "invalid_prefix", "Non-empty prefix must end with /")

    # Get the target tree
    tree = _get_tree(ctx, tree_id)
    if tree is None:
        return _error_response(404, "tree_not_found", f"Tree not found: {tree_id}")

    # Check get permission on prefix
    if not ctx.check_caller_permission("get", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant get on prefix: {prefix}")

    # Build bindings with relative paths
    full_prefix = tree.normalize_uri(prefix)
    bindings: dict[str, bytes] = {}

    for uri in tree.list_prefix(full_prefix):
        h = tree.get(uri)
        if h:
            # Extract relative path
            relative = uri[len(full_prefix):]
            bindings[relative] = h

    # Build content-addressed trie per EXTENSION-TREE v3.2 §3
    from entity_core.storage.trie import build_trie, collect_trie_hashes, TRIE_NODE_TYPE

    sorted_bindings = sorted(bindings.items())
    trie_root = build_trie(sorted_bindings, ctx.emit_pathway.content_store)

    # Per I3: snapshot is pure content — no prefix field.
    # Prefix is operational context provided by the consumer.
    snapshot = Entity(
        type="system/tree/snapshot",
        data={"root": trie_root},
    )

    # Include trie nodes so callers can traverse without extra round-trips.
    # v3.6 F4-cycle wire-shape pattern: result carries the snapshot entity
    # directly; trie nodes ride in the outer wire envelope's `included`
    # map via the `envelope_included` opt-in hoist (peer.py drains it at
    # send time). This matches the cross-impl wire convention Go's
    # validate-peer expects — decoding result.data as snapshot shape
    # rather than peeling a system/envelope wrapper off first.
    included: dict[bytes, dict[str, Any]] = {}
    trie_hashes = collect_trie_hashes(trie_root, ctx.emit_pathway.content_store)
    for th in trie_hashes:
        node = ctx.emit_pathway.content_store.get(th)
        if node and node.type == TRIE_NODE_TYPE:
            included[th] = node.to_dict()

    return {
        "status": 200,
        "result": snapshot.to_dict(),
        "envelope_included": included,
    }


def _collect_trie_entities(
    content_store: "ContentStore",
    node_hash: bytes,
    collected: dict[bytes, dict[str, Any]],
) -> None:
    """Recursively collect trie node entities for extract envelope.

    Per TREE §6.2: extract envelope MUST include all reachable trie nodes
    so the receiver can walk the trie to resolve bindings. v4.0 walks the
    ``{map, data}`` shape — buckets terminate (their tuples reference
    leaf data entities, not child nodes); only ``Link`` entries (33-byte
    sub-node hashes encoded as CBOR byte strings) recurse.
    """
    if node_hash in collected:
        return
    ent = content_store.get(node_hash)
    if ent is None:
        return
    collected[node_hash] = ent.to_dict()
    if ent.type != "system/tree/snapshot/node":
        return
    # v4.0 node shape: data is a dense array of Entry (Bucket | Link).
    # Bucket = list[[key, value_hash]] — terminates here; Link = 33-byte
    # sub-node hash — recurse.
    for entry in ent.data.get("data", []):
        if isinstance(entry, (bytes, bytearray)):
            _collect_trie_entities(content_store, bytes(entry), collected)


def _extract_bindings_from_snapshot(
    snapshot: Entity,
    content_store: "ContentStore",
) -> dict[str, bytes]:
    """Extract flat bindings from a snapshot (handles both trie and legacy formats).

    Args:
        snapshot: A system/tree/snapshot entity.
        content_store: Content store for loading trie nodes.

    Returns:
        Dict mapping relative paths to entity hashes.
    """
    root_hash = snapshot.data.get("root")
    if root_hash is not None:
        from entity_core.storage.trie import collect_all_bindings
        return dict(collect_all_bindings(root_hash, "", content_store))

    # Legacy flat format fallback
    return snapshot.data.get("bindings", {})


async def _handle_diff(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle diff operation - compare two snapshots.

    Per EXTENSION-TREE.md §4:
    - Pure computation on snapshot entities
    - No tree access required
    - Both snapshots must be in content store or included

    Args:
        params: Request parameters (base, target hashes).
        ctx: Handler context.

    Returns:
        Response dict with diff entity.
    """
    base_hash = params.get("base")
    target_hash = params.get("target")

    if not base_hash or not target_hash:
        return _error_response(400, "invalid_request", "Both base and target hashes required")

    # Get snapshots from content store
    base_entity = ctx.emit_pathway.content_store.get(base_hash)
    target_entity = ctx.emit_pathway.content_store.get(target_hash)

    if base_entity is None:
        return _error_response(404, "snapshot_not_found", "Base snapshot not found")
    if target_entity is None:
        return _error_response(404, "snapshot_not_found", "Target snapshot not found")

    # Verify they are snapshots
    if base_entity.type != "system/tree/snapshot":
        return _error_response(400, "invalid_type", "Base is not a snapshot")
    if target_entity.type != "system/tree/snapshot":
        return _error_response(400, "invalid_type", "Target is not a snapshot")

    # Extract bindings (handles both trie and legacy formats)
    base_bindings = _extract_bindings_from_snapshot(base_entity, ctx.emit_pathway.content_store)
    target_bindings = _extract_bindings_from_snapshot(target_entity, ctx.emit_pathway.content_store)

    # Compute diff
    added: dict[str, bytes] = {}
    removed: dict[str, bytes] = {}
    changed: dict[str, dict[str, bytes]] = {}
    unchanged = 0

    for path, h in target_bindings.items():
        if path not in base_bindings:
            added[path] = h
        elif base_bindings[path] != h:
            changed[path] = {"base_hash": base_bindings[path], "target_hash": h}
        else:
            unchanged += 1

    for path, h in base_bindings.items():
        if path not in target_bindings:
            removed[path] = h

    diff_entity = Entity(
        type="system/tree/diff",
        data={
            "base": base_hash,
            "target": target_hash,
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": unchanged,
        },
    )

    return {
        "status": 200,
        "result": diff_entity.to_dict(),
    }


def _apply_prefix(
    relative_path: str,
    source_prefix: str | None,
    target_prefix: str | None,
) -> str:
    """Apply prefix to a relative path for merge placement.

    Per I3 (EXTENSION-TREE.md §5.4 amended):
    - target_prefix takes priority: place at target_prefix + relative_path
    - source_prefix as fallback: place at source_prefix + relative_path
    - Neither: use relative_path as-is

    Args:
        relative_path: Path relative to snapshot root.
        source_prefix: Where the snapshot content logically resides.
        target_prefix: Where merged bindings should be placed.

    Returns:
        The target path for this binding.
    """
    if target_prefix is not None:
        return target_prefix + relative_path
    if source_prefix is not None:
        return source_prefix + relative_path
    return relative_path


async def _handle_merge(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle merge operation - apply snapshot into tree.

    Per EXTENSION-TREE.md §5:
    - Applies snapshot bindings to target tree
    - Supports conflict strategies: no-overwrite, source-wins, target-wins
    - Pre-checks all paths for put permission (atomic)
    - Merge is additive (does not remove paths)

    Args:
        params: Request parameters (source, target_tree, strategy, prefixes, dry_run).
        ctx: Handler context.

    Returns:
        Response dict with merge result.
    """
    source_hash = params.get("source")
    source_envelope = params.get("source_envelope")
    target_tree_id = params.get("target_tree")
    strategy = params.get("strategy", "no-overwrite")
    source_prefix = params.get("source_prefix")
    target_prefix = params.get("target_prefix")
    dry_run = params.get("dry_run", False)

    # If source_envelope is provided, ingest its entities and use root as source.
    # Accepts either a raw envelope or an entity wrapping an envelope
    # (from continuation chains where extract result is wrapped as entity).
    if source_envelope is not None:
        env_data = source_envelope
        # If it's an entity wrapping an envelope, unwrap to get envelope data.
        if isinstance(env_data, dict) and env_data.get("type") in ("system/envelope", "system/protocol/envelope"):
            env_data = env_data.get("data", {})

        root_entity = env_data.get("root")
        included = env_data.get("included", {})

        if root_entity is None:
            return _error_response(400, "invalid_params", "source_envelope missing root")

        # Ingest all included entities into content store.
        cs = ctx.emit_pathway.content_store
        for entity_data in (included.values() if isinstance(included, dict) else included):
            if isinstance(entity_data, dict):
                ent = Entity.from_dict(entity_data)
                cs.put(ent)

        # Store the root (snapshot) entity and use its hash as source.
        root_ent = Entity.from_dict(root_entity)
        source_hash = cs.put(root_ent)

    if not source_hash:
        return _error_response(400, "invalid_request", "Source snapshot hash or source_envelope required")

    # Validate strategy
    valid_strategies = ("no-overwrite", "source-wins", "target-wins")
    if strategy not in valid_strategies:
        return _error_response(400, "invalid_strategy", f"Strategy must be one of: {valid_strategies}")

    # Get source snapshot
    snapshot = ctx.emit_pathway.content_store.get(source_hash)
    if snapshot is None:
        return _error_response(404, "snapshot_not_found", "Source snapshot not found")
    if snapshot.type != "system/tree/snapshot":
        return _error_response(400, "invalid_type", "Source is not a snapshot")

    # Get target tree
    tree = _get_tree(ctx, target_tree_id)
    if tree is None:
        return _error_response(404, "tree_not_found", f"Tree not found: {target_tree_id}")

    # Per I3: snapshot has no prefix — use source_prefix/target_prefix from params
    bindings = _extract_bindings_from_snapshot(snapshot, ctx.emit_pathway.content_store)

    # Pre-check: verify put authorization on all target paths (atomic)
    for relative in bindings:
        target_path = _apply_prefix(relative, source_prefix, target_prefix)
        if not ctx.check_caller_permission("put", target_path):
            return _error_response(
                403,
                "capability_denied",
                f"Capability doesn't grant put on path: {target_path}",
            )

    # Execute merge
    applied = 0
    skipped = 0
    conflicts: dict[str, dict[str, Any]] = {}

    # Merged bindings MUST flow through the EmitPathway so secondary indexes
    # (the query handler's type/reverse/path-link indexes) stay consistent —
    # a bare `tree.set` binds the hash but never fires the index hook, so
    # synced entities become fetchable via listing+get yet invisible to
    # `system/query:find` (the psync_query_namespace 0-match WARN). The
    # entities are already in the content store (ingested from the snapshot),
    # so `emit_hash` is the right primitive (its own docstring names merge as
    # the use case). Only the *default* tree is wired to the IndexManager;
    # a non-default registry tree isn't, and `emit_hash` would mis-route to
    # the default tree — so fall back to `tree.set` there.
    emit_ctx = EmitContext.from_handler_context(ctx, "put")
    is_default_tree = tree is ctx.emit_pathway.entity_tree

    def _apply_binding(uri: str, h: Hash) -> None:
        if is_default_tree:
            ctx.emit_pathway.emit_hash(uri, h, emit_ctx)
        else:
            tree.set(uri, h)

    for relative, h in bindings.items():
        target_path = _apply_prefix(relative, source_prefix, target_prefix)
        uri = tree.normalize_uri(target_path)
        existing = tree.get(uri)

        if existing is None:
            # New path - apply (and count as applied even in dry-run, so
            # `applied` reports the would-apply count). Cross-impl: this
            # mirrors Go's `core/tree/operations.go` (`applied++`
            # unconditionally on the `!exists` branch).
            if not dry_run:
                _apply_binding(uri, h)
            applied += 1
        elif existing == h:
            # Same hash - skip
            skipped += 1
        else:
            # Conflict - handle per strategy
            if strategy == "source-wins":
                if not dry_run:
                    _apply_binding(uri, h)
                applied += 1
                conflicts[target_path] = {
                    "existing_hash": existing,
                    "incoming_hash": h,
                    "resolution": "used-incoming",
                }
            elif strategy == "target-wins":
                skipped += 1
                conflicts[target_path] = {
                    "existing_hash": existing,
                    "incoming_hash": h,
                    "resolution": "kept-existing",
                }
            else:  # no-overwrite
                skipped += 1
                conflicts[target_path] = {
                    "existing_hash": existing,
                    "incoming_hash": h,
                    "resolution": "unresolved",
                }

    result_entity = Entity(
        type="system/tree/merge-result",
        data={
            "applied": applied,
            "skipped": skipped,
            "conflicts": conflicts,
            "strategy": strategy,
        },
    )

    return {
        "status": 200,
        "result": result_entity.to_dict(),
    }


async def _handle_extract(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle extract operation - bundle subtree as envelope.

    Per EXTENSION-TREE.md §6:
    - Creates snapshot as root
    - Bundles referenced entities in included
    - Optional paths filter for selective extraction

    For *incremental* cross-peer transport (only what changed since a
    version the caller already has), use `revision:fetch-diff`
    (EXTENSION-REVISION §4.4.19), not `tree:extract`. The `since` parameter
    prototyped here in v3.14 was withdrawn in TREE v3.15: its input is a
    version hash and version→trie-root deref is the revision extension's
    job, so the capability is correctly homed on revision, not tree.

    Args:
        params: Request parameters (prefix, tree_id, paths).
        ctx: Handler context.

    Returns:
        Response dict with envelope containing snapshot and entities.
    """
    # V7: Prefix from resource target first, fallback to params.
    prefix = params.get("prefix", "")
    if ctx.resource_targets:
        prefix = ctx.resource_targets[0]
    tree_id = params.get("tree_id")
    paths_filter = params.get("paths")

    # Validate prefix format
    if prefix and not prefix.endswith("/"):
        return _error_response(400, "invalid_prefix", "Non-empty prefix must end with /")

    # Get the target tree
    tree = _get_tree(ctx, tree_id)
    if tree is None:
        return _error_response(404, "tree_not_found", f"Tree not found: {tree_id}")

    # Check get permission on prefix
    if not ctx.check_caller_permission("get", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant get on prefix: {prefix}")

    full_prefix = tree.normalize_uri(prefix)
    bindings: dict[str, bytes] = {}

    if paths_filter:
        # Filtered: read specific paths directly
        for path in paths_filter:
            uri = full_prefix + path
            h = tree.get(uri)
            if h:
                bindings[path] = h
    else:
        # Full prefix: all bindings under prefix
        for uri in tree.list_prefix(full_prefix):
            h = tree.get(uri)
            if h:
                relative = uri[len(full_prefix):]
                bindings[relative] = h

    from entity_core.storage.trie import build_trie

    sorted_bindings = sorted(bindings.items())
    trie_root = build_trie(sorted_bindings, ctx.emit_pathway.content_store)

    # Per I3: snapshot is pure content — no prefix field
    snapshot = Entity(
        type="system/tree/snapshot",
        data={"root": trie_root},
    )

    # Bundle trie node entities (per TREE §6.2 — MUST include all reachable nodes).
    cs = ctx.emit_pathway.content_store
    included: dict[bytes, dict[str, Any]] = {}
    _collect_trie_entities(cs, trie_root, included)

    # Bundle data entities from bindings.
    for h in bindings.values():
        entity = cs.get(h)
        if entity:
            included[h] = entity.to_dict()

    # extract's contract is intentionally the system/envelope wrapper
    # shape (the operation IS the bundle — that's its purpose). The
    # cross-impl wire contract (Go's validate_peer: `extract result
    # type is "system/tree/snapshot" (expected system/envelope)`)
    # confirms this. snapshot is the one that returns the typed
    # entity directly + envelope_included hoist; extract is the bundle.
    return {
        "status": 200,
        "result": {
            "type": "system/envelope",
            "data": {
                "root": snapshot.to_dict(),
                "included": included,
            },
        },
    }


async def _handle_create(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle create operation - create non-default tree.

    Per EXTENSION-TREE.md §7.2:
    - Creates a new tree with given configuration
    - tree_id must not already exist
    - If source present, capability must also be present

    Args:
        params: Tree configuration (tree_id, root_structure, purpose, etc.).
        ctx: Handler context.

    Returns:
        Response dict with tree config.
    """
    if ctx.tree_registry is None:
        return _error_response(501, "not_implemented", "Tree registry not available")

    tree_id = params.get("tree_id")
    if not tree_id:
        return _error_response(400, "invalid_config", "tree_id is required")

    # Check if tree already exists
    if ctx.tree_registry.exists(tree_id):
        return _error_response(409, "tree_exists", f"Tree already exists: {tree_id}")

    # Validate source/capability relationship
    source = params.get("source")
    capability = params.get("capability")
    if source and not capability:
        return _error_response(400, "invalid_config", "capability required when source is present")

    # Validate capability exists if provided
    if capability:
        if not ctx.emit_pathway.content_store.has(capability):
            return _error_response(404, "capability_not_found", "Referenced capability not in content store")

    # Create the tree
    try:
        ctx.tree_registry.create(params)
    except ValueError as e:
        return _error_response(400, "invalid_config", str(e))

    return {
        "status": 200,
        "result": {
            "type": "system/tree/config",
            "data": params,
        },
    }


async def _handle_destroy(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle destroy operation - remove non-default tree.

    Per EXTENSION-TREE.md §7.3:
    - Removes tree and all its bindings
    - Cannot destroy default tree

    Args:
        params: Tree ID as string or dict with data field.
        ctx: Handler context.

    Returns:
        Response dict with boolean result.
    """
    # Handle both string params and wrapped params
    if isinstance(params, str):
        tree_id = params
    else:
        tree_id = params.get("data", "") if isinstance(params, dict) else ""
        # Also check for direct tree_id field
        if not tree_id and isinstance(params, dict):
            tree_id = params.get("tree_id", "")

    if not tree_id:
        return _error_response(400, "default_tree", "Cannot destroy default tree")

    if ctx.tree_registry is None:
        return _error_response(501, "not_implemented", "Tree registry not available")

    if not ctx.tree_registry.exists(tree_id):
        return _error_response(404, "tree_not_found", f"Tree not found: {tree_id}")

    try:
        ctx.tree_registry.destroy(tree_id)
    except ValueError as e:
        return _error_response(400, "default_tree", str(e))
    except KeyError as e:
        return _error_response(404, "tree_not_found", str(e))

    return {
        "status": 200,
        "result": {
            "type": "primitive/bool",
            "data": True,
        },
    }
