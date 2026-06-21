"""System revision handler for version control operations.

Per EXTENSION-REVISION v2.1 and PROPOSAL-STRUCTURAL-VERSION-ENTRIES v4,
the revision handler provides Git-like versioning with content-addressed
tries and structural version entries.

Key design:
- Version entries are structural: {root, parents} only (no metadata)
- Parents are sorted by binary hash bytes
- Snapshots use content-addressed tries (system/tree/snapshot/node)
- No LWW merge strategy (timestamps not in version entries)
- Oscillation detection prevents merge cycles
- Merge ordering modes: deterministic (default), caller-perspective
- fetch-entities for incremental trie retrieval

Operations (17 total):
  Core (MUST):  commit, log, status, merge, resolve, find-ancestor, diff
  Convenience:  branch, checkout, tag, cherry-pick, revert, pull
  Transfer:     fetch, fetch-entities, fetch-diff, push
"""

from __future__ import annotations

import fnmatch
import logging
from collections import deque
from enum import Enum
from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.storage.trie import (
    TRIE_NODE_TYPE,
    build_trie,
    collect_all_bindings,
    collect_trie_entities_except,
    collect_trie_hashes,
)
from entity_core.types.deletion_marker import (
    deletion_marker_hash,
    is_deletion_marker,
)
from entity_core.utils.ecf import Hash, compute_ecf_hash, hash_to_display, is_zero_hash
from entity_handlers.manifest import error_response as _error_response

logger = logging.getLogger(__name__)

REVISION_HANDLER_PATTERN = "system/revision"

# Version entry entity type (structural: root + sorted parents only)
VERSION_ENTRY_TYPE = "system/revision/entry"

# Conflict entity type
CONFLICT_TYPE = "system/revision/conflict"


# =============================================================================
# Data Types
# =============================================================================


class VersionRelationship(Enum):
    """Relationship between two versions."""

    IN_SYNC = "in_sync"
    AHEAD = "ahead"
    BEHIND = "behind"
    DIVERGED = "diverged"
    UNRELATED = "unrelated"


# =============================================================================
# Storage Path Helpers
# =============================================================================


def _compute_prefix_hash(ctx: HandlerContext, prefix: str) -> str:
    """Compute hash-addressed prefix segment per §3.1.

    Returns 66-char hex string: hex(content_hash("system/tree/path", absolute_prefix)).
    """
    tree = ctx.emit_pathway.entity_tree
    absolute = tree.normalize_uri(prefix)
    h = compute_ecf_hash({"type": "system/tree/path", "data": absolute})
    return h.hex()


def _head_path(ph: str) -> str:
    return f"system/revision/{ph}/head"


def _branch_path(ph: str, name: str) -> str:
    return f"system/revision/{ph}/branches/{name}"


def _active_branch_path(ph: str) -> str:
    return f"system/revision/{ph}/active-branch"


def _tag_path(ph: str, name: str) -> str:
    return f"system/revision/{ph}/tags/{name}"


def _conflict_path(ph: str, path: str) -> str:
    return f"system/revision/{ph}/conflicts/{path}"


def _remote_head_path(ph: str, peer_id_hex: str) -> str:
    """Per V7 v7.64 §1.4 / EXTENSION-REVISION path-encoding alignment:
    ``{peer_id_hex}`` is lowercase hex of the remote peer's
    ``system/peer`` content_hash."""
    return f"system/revision/{ph}/remotes/{peer_id_hex}"


def _config_path_for_prefix(ph: str) -> str:
    return f"system/revision/{ph}/config"


# =============================================================================
# Auto-version config validation (PROPOSAL-REVISION-AUTO-VERSION-FIX §6.1, §6D)
# =============================================================================

# Required excludes when auto_version: true and the tracked prefix encompasses
# engine-owned paths. Enumerated per §4 "Reentrancy" (MUST) and §6D.4.
REQUIRED_EXCLUDE_PATHS: tuple[str, ...] = (
    "system/revision/",
    "system/tree/root/",
    "system/tree/tracking-config/",
    "system/history/",
    "system/clock/",
)


def _canonical_prefix(prefix: str) -> str:
    """Strip leading and trailing '/' to get canonical form P."""
    return prefix.strip("/")


def _prefix_encompasses(prefix: str, required_path: str) -> bool:
    """True if the tracked prefix covers (or IS) the required-exclude path.

    The tracked prefix `"/"` (universal) encompasses everything. A non-universal
    prefix encompasses a required path only when the required path lies at or
    below the canonical prefix.
    """
    canonical = _canonical_prefix(prefix)
    if canonical == "":
        return True
    # required_path is like "system/revision/"; treat the canonical prefix as
    # a literal path segment boundary.
    canonical_slash = canonical + "/"
    return required_path.startswith(canonical_slash) or canonical_slash.startswith(required_path)


def _exclude_covers(exclude_patterns: list[str], required_path: str) -> bool:
    """True if the exclude list covers the required path.

    Accepts both `"system/revision/**"` and `"system/revision/"` style patterns.
    """
    for pat in exclude_patterns:
        norm = pat.rstrip("*").rstrip("/")
        req = required_path.rstrip("/")
        if norm == req or req.startswith(norm + "/"):
            return True
    return False


# Per EXTENSION-REVISION v3.1 §2.3 Amendment 4 (deletion_resolution).
# Default — silently drops the DELETE signal in concurrent delete-vs-edit.
# Recommended for collaborative-edit workflows.
DELETION_RESOLUTION_DEFAULT = "preserve-on-conflict"
DELETION_RESOLUTION_VALID = (
    "preserve-on-conflict",
    "deletion-wins",
    "three-way-fallthrough",
    "deterministic",
)
# v3.1 §2.3 Amendment 4 §217–219: rejected at config-write time.
# `keep-both` is meaningless when one side is a deletion; `lww` requires
# commit metadata canonical deletion markers do not carry.
DELETION_RESOLUTION_REJECTED = ("lww", "keep-both")


def validate_merge_config(config_data: dict[str, Any]) -> list[str]:
    """Validate a `system/revision/merge-config` entity's data.

    Per EXTENSION-REVISION v3.1 §2.3 (Amendment 4):
    `deletion_resolution`, when present, MUST be one of
    ``preserve-on-conflict`` (default), ``deletion-wins``,
    ``three-way-fallthrough``, or ``deterministic``. Implementations
    MUST reject ``lww`` and ``keep-both`` with ``invalid_strategy`` at
    config-write time. Callers writing merge-config entities via
    ``tree:put`` SHOULD invoke this validator first; ``_find_merge_strategy``
    additionally guards at read time so a non-conforming entity that
    bypassed write-time validation cannot drive merge classification.

    Returns a list of validation errors; empty list means valid.
    """
    errors: list[str] = []
    dr = config_data.get("deletion_resolution")
    if dr is not None:
        if not isinstance(dr, str):
            errors.append(
                f"deletion_resolution must be a string; got {type(dr).__name__}"
            )
        elif dr in DELETION_RESOLUTION_REJECTED:
            errors.append(
                f"invalid_strategy: deletion_resolution={dr!r} is rejected "
                "(§2.3 Amendment 4); use three-way-fallthrough for "
                "keep-both-style conflict surfacing"
            )
        elif dr not in DELETION_RESOLUTION_VALID:
            errors.append(
                f"unknown deletion_resolution: {dr!r}; valid values: "
                + ", ".join(DELETION_RESOLUTION_VALID)
            )
    return errors


def _effective_deletion_resolution(strategy: str | None) -> str:
    """Return the effective `deletion_resolution` value, defending against
    non-conforming entities at read time.

    A merge-config entity that bypassed write-time validation might carry
    a rejected/unknown value; per §2.3 Amendment 4 we MUST NOT honor those
    — fall back to the default (`preserve-on-conflict`).
    """
    if isinstance(strategy, str) and strategy in DELETION_RESOLUTION_VALID:
        return strategy
    return DELETION_RESOLUTION_DEFAULT


def validate_revision_config(config_data: dict[str, Any]) -> list[str]:
    """Return a list of validation errors; empty list means valid.

    Per PROPOSAL-REVISION-AUTO-VERSION-FIX §6D.4: configs with
    `auto_version: true` whose prefix encompasses a required-exclude path
    MUST have that path in the exclude list. This is fail-closed.
    """
    errors: list[str] = []
    if not config_data.get("auto_version"):
        return errors

    prefix = config_data.get("prefix", "")
    if not prefix or not prefix.endswith("/"):
        errors.append(
            f"auto_version requires a valid prefix ending with '/'; got {prefix!r}"
        )
        return errors

    excludes = list(config_data.get("exclude") or [])
    missing = [
        req for req in REQUIRED_EXCLUDE_PATHS
        if _prefix_encompasses(prefix, req) and not _exclude_covers(excludes, req)
    ]
    if missing:
        errors.append(
            "auto_version: true requires excludes covering: "
            + ", ".join(sorted(missing))
        )
    return errors


# =============================================================================
# =============================================================================
# Core Algorithms
# =============================================================================


def sorted_parents(parents: list[bytes]) -> list[bytes]:
    """Sort parent hashes lexicographically by binary hash bytes.

    Python's sorted() on bytes already does lexicographic comparison
    on raw byte values, which matches the spec requirement.
    """
    return sorted(parents)


def _get_version_entity(ctx: HandlerContext, version_hash: bytes) -> Entity | None:
    """Get a version entity from content store."""
    entity = ctx.emit_pathway.content_store.get(version_hash)
    if entity and entity.type == VERSION_ENTRY_TYPE:
        return entity
    return None


def _walk_history(
    ctx: HandlerContext,
    start_hash: bytes,
    limit: int | None = None,
) -> list[bytes]:
    """BFS through version parents."""
    if not start_hash:
        return []

    visited: list[bytes] = []
    queue: deque[bytes] = deque([start_hash])
    seen: set[bytes] = set()

    while queue:
        if limit and len(visited) >= limit:
            break

        current = queue.popleft()
        if current in seen:
            continue

        seen.add(current)
        visited.append(current)

        version = _get_version_entity(ctx, current)
        if version:
            for parent_hash in version.data.get("parents", []):
                if parent_hash and parent_hash not in seen:
                    queue.append(parent_hash)

    return visited


def _find_common_ancestor(
    ctx: HandlerContext,
    version_a: bytes,
    version_b: bytes,
) -> bytes | None:
    """Find common ancestor using bidirectional BFS."""
    if version_a == version_b:
        return version_a

    ancestors_a: set[bytes] = set()
    ancestors_b: set[bytes] = set()
    queue_a: deque[bytes] = deque([version_a])
    queue_b: deque[bytes] = deque([version_b])

    while queue_a or queue_b:
        if queue_a:
            current = queue_a.popleft()
            if current in ancestors_b:
                return current
            if current not in ancestors_a:
                ancestors_a.add(current)
                version = _get_version_entity(ctx, current)
                if version:
                    for parent in version.data.get("parents", []):
                        if parent and parent not in ancestors_a:
                            queue_a.append(parent)

        if queue_b:
            current = queue_b.popleft()
            if current in ancestors_a:
                return current
            if current not in ancestors_b:
                ancestors_b.add(current)
                version = _get_version_entity(ctx, current)
                if version:
                    for parent in version.data.get("parents", []):
                        if parent and parent not in ancestors_b:
                            queue_b.append(parent)

    return None


def _is_ancestor(
    ctx: HandlerContext,
    potential_ancestor: bytes,
    descendant: bytes,
) -> bool:
    """Check if potential_ancestor is in descendant's ancestry."""
    if potential_ancestor == descendant:
        return True

    visited: set[bytes] = set()
    queue: deque[bytes] = deque([descendant])

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        if current == potential_ancestor:
            return True

        version = _get_version_entity(ctx, current)
        if version:
            for parent in version.data.get("parents", []):
                if parent and parent not in visited:
                    queue.append(parent)

    return False


def _check_relationship(
    ctx: HandlerContext,
    local_hash: bytes | None,
    remote_hash: bytes | None,
) -> VersionRelationship:
    """Determine relationship between local and remote versions."""
    if local_hash is None and remote_hash is None:
        return VersionRelationship.IN_SYNC
    if local_hash is None:
        return VersionRelationship.BEHIND
    if remote_hash is None:
        return VersionRelationship.AHEAD
    if local_hash == remote_hash:
        return VersionRelationship.IN_SYNC

    local_is_ancestor = _is_ancestor(ctx, local_hash, remote_hash)
    remote_is_ancestor = _is_ancestor(ctx, remote_hash, local_hash)

    if local_is_ancestor and not remote_is_ancestor:
        return VersionRelationship.BEHIND
    if remote_is_ancestor and not local_is_ancestor:
        return VersionRelationship.AHEAD
    if _find_common_ancestor(ctx, local_hash, remote_hash):
        return VersionRelationship.DIVERGED
    return VersionRelationship.UNRELATED


def _detect_oscillation(
    ctx: HandlerContext,
    proposed_root: bytes,
    local_head: bytes | None,
    *,
    proposed_parents: list[bytes] | None = None,
    depth_limit: int = 4,
) -> bool:
    """Check if proposed full identity `{root, sorted_parents}` appeared
    in recent ancestry.

    Per EXTENSION-REVISION v3.2 invariant 3 (A.3):
    oscillation MUST be detected on the **full identity** of a version
    `{root, sorted_parents}`, NOT on the root hash alone. Same root with
    a different parent set is a legitimate cross-link version (standard
    CRDT convergence path: two branches that independently arrived at
    the same logical state, recorded as separate version entries) — it
    MUST NOT be classified as an oscillation. Pre-v3.2 implementations
    that compared root-only would spuriously treat convergence as a
    merge cycle.
    """
    if local_head is None:
        return False

    proposed_sorted = sorted_parents(list(proposed_parents or []))

    visited: set[bytes] = set()
    queue: list[bytes] = [local_head]
    depth = 0

    while queue and depth < depth_limit:
        next_queue: list[bytes] = []
        for current in queue:
            if current is None or current in visited:
                continue
            visited.add(current)

            version = _get_version_entity(ctx, current)
            if version is None:
                continue
            if version.data.get("root") == proposed_root:
                # Full identity compare (v3.2 invariant 3): only oscillate
                # if the parent set ALSO matches. Different parents at the
                # same root = legitimate CRDT cross-link.
                existing_parents = sorted_parents(
                    list(version.data.get("parents") or [])
                )
                if existing_parents == proposed_sorted:
                    return True  # True oscillation

            for parent in version.data.get("parents", []):
                if parent:
                    next_queue.append(parent)

        queue = next_queue
        depth += 1

    return False


def _normalize_merge_sides(
    head_a: bytes, head_b: bytes, mode: str
) -> tuple[bytes, bytes]:
    """Normalize merge sides per merge ordering mode.

    deterministic (default): lower hash = local, higher hash = remote
    caller-perspective: (head_a, head_b) unchanged
    """
    if mode == "deterministic":
        if head_a <= head_b:
            return head_a, head_b
        else:
            return head_b, head_a
    return head_a, head_b


# =============================================================================
# Snapshot Helpers
# =============================================================================


def _get_snapshot_bindings(
    ctx: HandlerContext,
    prefix: str,
) -> dict[str, bytes]:
    """Get current tree bindings for a prefix (excluding system/ paths)."""
    tree = ctx.emit_pathway.entity_tree
    full_prefix = tree.normalize_uri(prefix)
    bindings: dict[str, bytes] = {}

    for uri in tree.list_prefix(full_prefix):
        h = tree.get(uri)
        if h:
            relative = uri[len(full_prefix):]
            bindings[relative] = h

    return bindings


def _get_version_bindings(
    ctx: HandlerContext,
    version_hash: bytes,
) -> dict[str, bytes] | None:
    """Get flat bindings from a version's trie root."""
    version = _get_version_entity(ctx, version_hash)
    if not version:
        return None
    root_hash = version.data.get("root")
    if not root_hash:
        return None
    flat = collect_all_bindings(root_hash, "", ctx.emit_pathway.content_store)
    return dict(flat)


def _apply_bindings_to_tree(
    ctx: HandlerContext,
    bindings: dict[str, bytes],
    prefix: str,
    emit_ctx: EmitContext | None = None,
    *,
    preserve_unknown: bool = False,
) -> dict[str, Any]:
    """Apply bindings to tree under prefix, returning cascade warnings.

    Per EXTENSION-REVISION v3.1 §4.4.4 Amendment 3 (apply translation,
    A.8): bindings whose hash equals the canonical
    `system/deletion-marker` are translated to live-tree UNBINDS — they
    MUST NOT appear in the live location index. Direct hash equality
    against the canonical constant is O(1) (no I/O).

    Per EXTENSION-REVISION v3.2 §4.4.4 the version-transcription
    invariant (A.3) requires callers that previously diffed
    against the live tree (fast-forward, checkout) to diff against the
    committed-local-head trie instead. Callers wanting the old
    behavior — "remove every live path not in `bindings`" — pass
    ``preserve_unknown=False`` (current behavior, used by merge); for
    transcription callers that pass an already-correctly-augmented set
    they pass ``preserve_unknown=True`` to skip the live-vs-set removal
    pass. See `_handle_checkout` / fast-forward sites for usage.

    Writes go through emit pathway so cascade consumers fire. Returns
    cascade_warnings for any writes that produced status 207.
    """
    tree = ctx.emit_pathway.entity_tree
    emit = ctx.emit_pathway
    full_prefix = tree.normalize_uri(prefix)

    current_data_paths = set()
    for uri in tree.list_prefix(full_prefix):
        relative = uri[len(full_prefix):]
        if not relative.startswith("system/"):
            current_data_paths.add(relative)

    cascade_warnings: list[dict[str, Any]] = []

    applied = 0
    marker_unbinds = 0
    for relative, h in bindings.items():
        uri = tree.normalize_uri(prefix + relative)
        if is_deletion_marker(h):
            # §4.4.4 Amendment 3: marker bindings translate to live-tree
            # unbinds at apply time. Idempotent — `delete` on an absent
            # path is a no-op at the pathway level.
            if tree.get(uri) is not None:
                result = emit.delete(uri, emit_ctx)
                if result.status == 207 and result.consumers_halted:
                    cascade_warnings.append({
                        "path": relative,
                        "consumer_halted": result.consumers_halted.name,
                        "error_code": f"cascade_halt/{result.consumers_halted.status}",
                    })
            marker_unbinds += 1
            continue
        result = emit.emit_hash(uri, h, emit_ctx)
        if result.status == 207 and result.consumers_halted:
            cascade_warnings.append({
                "path": relative,
                "consumer_halted": result.consumers_halted.name,
                "error_code": f"cascade_halt/{result.consumers_halted.status}",
            })
        elif result.status >= 400:
            cascade_warnings.append({
                "path": relative,
                "consumer_halted": "",
                "error_code": f"write_rejected/{result.status}",
            })
        applied += 1

    removed = 0
    if not preserve_unknown:
        for relative in current_data_paths - set(bindings.keys()):
            uri = tree.normalize_uri(prefix + relative)
            result = emit.delete(uri, emit_ctx)
            if result.status == 207 and result.consumers_halted:
                cascade_warnings.append({
                    "path": relative,
                    "consumer_halted": result.consumers_halted.name,
                    "error_code": f"cascade_halt/{result.consumers_halted.status}",
                })
            removed += 1

    return {
        "applied": applied,
        "removed": removed + marker_unbinds,
        "cascade_warnings": cascade_warnings,
    }


def _compute_snapshot_diff(
    base_bindings: dict[str, bytes],
    target_bindings: dict[str, bytes],
) -> dict[str, Any]:
    """Compute diff between two binding sets.

    Per EXTENSION-REVISION v3.1 (A.8): deletion markers are
    bound hashes (not absence) — a marker on the target side means the
    path was intentionally deleted between base and target. The diff API
    surface (added/removed/changed/unchanged) MUST translate marker
    bindings back to logical deletion semantics for callers (Git-style
    UX, push/fetch diff payloads, etc.):

      base \\ target | non-marker hash    | marker hash       | absent
      --------------+--------------------+-------------------+----------
      non-marker    | unchanged (eq) /   | removed (logical  | removed
                    | changed (ne)       | delete)           |
      marker        | added (resurrect)  | unchanged         | (-)
      absent        | added              | (-)               | (-)

    Marker-bound paths that are absent from the "other" side are treated
    as if they were absent on this side too (the marker means "deleted,"
    not "still bound"). This keeps cherry-pick / revert / diff outputs
    legible and avoids leaking marker hashes through the public API.
    """
    added: dict[str, bytes] = {}
    removed: dict[str, bytes] = {}
    changed: dict[str, dict[str, bytes]] = {}
    unchanged = 0

    all_paths = set(base_bindings) | set(target_bindings)
    for path in all_paths:
        base_h = base_bindings.get(path)
        target_h = target_bindings.get(path)
        base_is_marker = is_deletion_marker(base_h)
        target_is_marker = is_deletion_marker(target_h)
        # Logical presence: a path is "present" iff bound to a non-marker.
        base_present = base_h is not None and not base_is_marker
        target_present = target_h is not None and not target_is_marker

        if base_present and target_present:
            if base_h == target_h:
                unchanged += 1
            else:
                changed[path] = {
                    "base_hash": base_h,
                    "target_hash": target_h,
                }
        elif target_present and not base_present:
            # Added (either fresh path or resurrected from a prior delete).
            added[path] = target_h  # type: ignore[assignment]
        elif base_present and not target_present:
            # Removed (logical delete: target absent or marker-bound).
            removed[path] = base_h  # type: ignore[assignment]
        else:
            # Both absent or both markers — no opinion either way.
            if base_is_marker and target_is_marker:
                unchanged += 1

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }


def _pattern_specificity(pattern: str) -> int:
    """Score a glob pattern by specificity — more literal characters = higher."""
    return len(pattern) - pattern.count("*") - pattern.count("?")


def _find_merge_strategy(
    ctx: HandlerContext,
    prefix: str,
    path: str,
    local_hash: bytes | None,
    remote_hash: bytes | None,
) -> str:
    """Per-path merge strategy lookup per §5.1 cascade.

    1. Per-type config at system/revision/config/merge/type/{type_name}
    2. Per-path config at system/revision/config/merge/path/* with glob matching
    3. Default: "three-way"
    """
    cs = ctx.emit_pathway.content_store
    tree = ctx.emit_pathway.entity_tree

    local_entity = cs.get(local_hash) if local_hash else None
    remote_entity = cs.get(remote_hash) if remote_hash else None

    types_to_check: list[str] = []
    if local_entity:
        types_to_check.append(local_entity.type)
    if remote_entity and (not local_entity or remote_entity.type != local_entity.type):
        types_to_check.append(remote_entity.type)

    for type_name in types_to_check:
        config_path = f"system/revision/config/merge/type/{type_name}"
        config_entity = _get_entity_at_path(ctx, config_path)
        if config_entity and config_entity.data.get("strategy"):
            return config_entity.data["strategy"]

    config_prefix = "system/revision/config/merge/path/"
    full_config_prefix = tree.normalize_uri(config_prefix)
    best_strategy: str | None = None
    best_specificity = -1

    for uri in tree.list_prefix(full_config_prefix):
        config_hash = tree.get(uri)
        if not config_hash:
            continue
        config = cs.get(config_hash)
        if not config or not config.data:
            continue
        pattern = config.data.get("pattern")
        if not pattern:
            continue
        full_path = prefix + path
        if fnmatch.fnmatch(full_path, pattern):
            specificity = _pattern_specificity(pattern)
            if specificity > best_specificity:
                best_strategy = config.data.get("strategy")
                best_specificity = specificity

    if best_strategy:
        return best_strategy

    return "three-way"


def _find_deletion_resolution(
    ctx: HandlerContext,
    prefix: str,
    path: str,
) -> str:
    """Per EXTENSION-REVISION v3.1 §2.3 Amendment 4 (A.8):
    look up the `deletion_resolution` strategy from merge-config for a
    delete-vs-entity divergence.

    Lookup mirrors `_find_merge_strategy`:
      1. Per-path config at `system/revision/config/merge/path/*` with
         glob matching; most-specific match wins.
      2. Default `preserve-on-conflict`.

    Per Amendment 4: `lww` and `keep-both` MUST be rejected at config-
    write time. Defensive read-time guard collapses any non-conforming
    value back to the default via `_effective_deletion_resolution`.
    """
    cs = ctx.emit_pathway.content_store
    tree = ctx.emit_pathway.entity_tree

    config_prefix = "system/revision/config/merge/path/"
    full_config_prefix = tree.normalize_uri(config_prefix)
    best_value: str | None = None
    best_specificity = -1

    for uri in tree.list_prefix(full_config_prefix):
        config_hash = tree.get(uri)
        if not config_hash:
            continue
        config = cs.get(config_hash)
        if not config or not config.data:
            continue
        pattern = config.data.get("pattern")
        if not pattern:
            continue
        full_path = prefix + path
        if fnmatch.fnmatch(full_path, pattern):
            dr = config.data.get("deletion_resolution")
            if dr is not None:
                specificity = _pattern_specificity(pattern)
                if specificity > best_specificity:
                    best_value = dr
                    best_specificity = specificity

    return _effective_deletion_resolution(best_value)


def _merge_bindings(
    ctx: HandlerContext,
    ancestor_bindings: dict[str, bytes],
    local_bindings: dict[str, bytes],
    remote_bindings: dict[str, bytes],
    strategy: str,
    prefix: str = "",
) -> tuple[dict[str, bytes], dict[str, dict[str, Any]], list[tuple[str, bytes]]]:
    """Three-way merge of flat binding sets (Phase 1: flatten-then-compare).

    Returns (merged_bindings, conflicts, additional_bindings).
    """
    merged: dict[str, bytes] = {}
    conflicts: dict[str, dict[str, Any]] = {}
    additional_bindings: list[tuple[str, bytes]] = []

    all_paths = set(local_bindings.keys()) | set(remote_bindings.keys())

    for path in all_paths:
        ancestor_h = ancestor_bindings.get(path)
        local_h = local_bindings.get(path)
        remote_h = remote_bindings.get(path)

        if local_h == remote_h:
            # Both sides agree
            if local_h:
                merged[path] = local_h
        elif strategy == "source-wins":
            if remote_h:
                merged[path] = remote_h
        elif strategy == "target-wins":
            if local_h:
                merged[path] = local_h
        elif local_h == ancestor_h:
            # Only remote changed
            if remote_h:
                merged[path] = remote_h
        elif remote_h == ancestor_h:
            # Only local changed
            if local_h:
                merged[path] = local_h
        else:
            # Per EXTENSION-REVISION v3.1 §2.3 Amendment 4 (A.8):
            # when EXACTLY ONE side is the canonical deletion marker and
            # the other is a regular entity hash, this is a delete-vs-edit
            # divergence — resolved by `deletion_resolution`, not the
            # generic merge strategy. `keep-both` is meaningless when one
            # side is a deletion (§2.3 Amendment 4 §215, §217); the
            # default `preserve-on-conflict` silently drops the DELETE.
            local_is_marker = is_deletion_marker(local_h)
            remote_is_marker = is_deletion_marker(remote_h)
            both_non_none = local_h is not None and remote_h is not None
            if both_non_none and (local_is_marker ^ remote_is_marker):
                dr = _find_deletion_resolution(ctx, prefix, path)
                if dr == "preserve-on-conflict":
                    # Entity supersedes the marker; delete is dropped.
                    entity_h = remote_h if local_is_marker else local_h
                    merged[path] = entity_h  # type: ignore[assignment]
                elif dr == "deletion-wins":
                    # Marker propagates; later apply will translate to
                    # live-tree unbind per §4.4.4 Amendment 3. Format-relative
                    # to this peer's home format (V7 v7.70 §4.9).
                    merged[path] = deletion_marker_hash()
                elif dr == "three-way-fallthrough":
                    conflicts[path] = {
                        "base": ancestor_h,
                        "local": local_h,
                        "remote": remote_h,
                    }
                    if local_h:
                        merged[path] = local_h
                elif dr == "deterministic":
                    # Stable cross-impl: lexicographic-min wins.
                    pick = min(local_h, remote_h)  # type: ignore[type-var]
                    merged[path] = pick
                else:
                    # `_effective_deletion_resolution` collapses unknowns
                    # to the default already; defensive belt-and-braces.
                    entity_h = remote_h if local_is_marker else local_h
                    merged[path] = entity_h  # type: ignore[assignment]
                continue

            # Both changed differently — resolve via strategy cascade (§5.1)
            effective = strategy if strategy != "three-way" else _find_merge_strategy(
                ctx, prefix, path, local_h, remote_h)

            if effective == "keep-both" and local_h is not None and remote_h is not None:
                merged[path] = local_h
                hash_prefix = remote_h[0:4].hex()
                additional_bindings.append((path + ".keep-both-" + hash_prefix, remote_h))
            elif effective == "source-wins":
                if remote_h:
                    merged[path] = remote_h
            elif effective == "target-wins":
                if local_h:
                    merged[path] = local_h
            else:
                conflicts[path] = {
                    "base": ancestor_h,
                    "local": local_h,
                    "remote": remote_h,
                }
                if local_h:
                    merged[path] = local_h

    return merged, conflicts, additional_bindings


# =============================================================================
# Storage Helpers
# =============================================================================


def _get_hash_at_path(ctx: HandlerContext, path: str) -> bytes | None:
    tree = ctx.emit_pathway.entity_tree
    uri = tree.normalize_uri(path)
    return tree.get(uri)


def _get_entity_at_path(ctx: HandlerContext, path: str) -> Entity | None:
    h = _get_hash_at_path(ctx, path)
    if h:
        return ctx.emit_pathway.content_store.get(h)
    return None


def _put_hash_at_path(ctx: HandlerContext, path: str, h: bytes) -> None:
    tree = ctx.emit_pathway.entity_tree
    uri = tree.normalize_uri(path)
    tree.set(uri, h)


def _remove_path(ctx: HandlerContext, path: str) -> None:
    tree = ctx.emit_pathway.entity_tree
    uri = tree.normalize_uri(path)
    tree.remove(uri)


def _list_prefix(ctx: HandlerContext, prefix: str) -> list[str]:
    tree = ctx.emit_pathway.entity_tree
    full_prefix = tree.normalize_uri(prefix)
    uris = tree.list_prefix(full_prefix)
    return [uri[len(full_prefix):] for uri in uris]


def _resolve_ref(ctx: HandlerContext, ph: str, ref: str | bytes) -> bytes | None:
    """Resolve a ref to a version hash (branch name, tag name, or hash)."""
    if isinstance(ref, bytes):
        if _get_version_entity(ctx, ref):
            return ref
        return None

    # Try branch name
    branch_entity = _get_entity_at_path(ctx, _branch_path(ph, ref))
    if branch_entity and branch_entity.type == "system/hash":
        return branch_entity.data.get("hash")

    # Try tag name
    tag_entity = _get_entity_at_path(ctx, _tag_path(ph, ref))
    if tag_entity and tag_entity.type == "system/hash":
        return tag_entity.data.get("hash")

    return None


def _get_config(ctx: HandlerContext, ph: str) -> dict[str, Any]:
    """Get revision config by prefix hash, or defaults."""
    config_entity = _get_entity_at_path(ctx, _config_path_for_prefix(ph))
    if config_entity and config_entity.type == "system/revision/config":
        return config_entity.data
    return {}


def _update_head_and_branch(
    ctx: HandlerContext,
    ph: str,
    version_hash: bytes,
    operation: str = "commit",
) -> None:
    """Update HEAD and advance active branch pointer."""
    emit_ctx = EmitContext.from_handler_grant(ctx, operation)
    head_entity = Entity(type="system/hash", data={"hash": version_hash})
    ctx.emit_pathway.emit(_head_path(ph), head_entity, emit_ctx)

    active_branch_entity = _get_entity_at_path(ctx, _active_branch_path(ph))
    if active_branch_entity and active_branch_entity.type == "primitive/string":
        branch_name = active_branch_entity.data
        ctx.emit_pathway.emit(_branch_path(ph, branch_name), head_entity, emit_ctx)


# =============================================================================
# Handler Entry Point
# =============================================================================


async def revision_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle system/revision operations (19 operations)."""
    params_data = params.get("data", params) if isinstance(params, dict) else {}

    # Core operations (MUST)
    if operation == "commit":
        return await _handle_commit(params_data, ctx)
    elif operation == "log":
        return await _handle_log(params_data, ctx)
    elif operation == "status":
        return await _handle_status(params_data, ctx)
    elif operation == "merge":
        return await _handle_merge(params_data, ctx)
    elif operation == "resolve":
        return await _handle_resolve(params_data, ctx)
    elif operation == "find-ancestor":
        return await _handle_find_ancestor(params_data, ctx)
    elif operation == "diff":
        return await _handle_diff(params_data, ctx)

    # Convenience operations (SHOULD)
    elif operation == "branch":
        return await _handle_branch(params_data, ctx)
    elif operation == "checkout":
        return await _handle_checkout(params_data, ctx)
    elif operation == "tag":
        return await _handle_tag(params_data, ctx)
    elif operation == "cherry-pick":
        return await _handle_cherry_pick(params_data, ctx)
    elif operation == "revert":
        return await _handle_revert(params_data, ctx)

    # Transfer operations (SHOULD)
    elif operation == "fetch":
        return await _handle_fetch(params_data, ctx)
    elif operation == "fetch-entities":
        return await _handle_fetch_entities(params_data, ctx)
    elif operation == "fetch-diff":
        return await _handle_fetch_diff(params_data, ctx)
    elif operation == "pull":
        return await _handle_pull(params_data, ctx)
    elif operation == "push":
        return await _handle_push(params_data, ctx)

    # Configuration (per PROPOSAL-CASCADE-SEMANTICS §7.2)
    elif operation == "config":
        return await _handle_config(params_data, ctx)

    # Merge-config canonical write path (REVISION v3.3 §4.4.18, D1).
    elif operation == "merge-config":
        return await _handle_merge_config(params_data, ctx)

    else:
        return _error_response(
            501, "unsupported_operation",
            f"Revision handler does not support operation: {operation}",
        )


# =============================================================================
# Core Operations
# =============================================================================


async def _handle_commit(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Create a structural version from current tree state.

    Builds a trie, creates a version entry with {root, sorted_parents}.
    No metadata (author, timestamp, message) in the version entity.
    """
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)

    if prefix and not prefix.endswith("/"):
        return _error_response(400, "invalid_prefix", "Non-empty prefix must end with /")

    if not ctx.check_caller_permission("commit", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant commit on: {prefix}")

    # Get current bindings
    bindings = _get_snapshot_bindings(ctx, prefix)

    # Get current HEAD (resolve before computing the trie so we can
    # diff against the parent version's bindings — required by §6.1
    # Amendment 2 below).
    content_store = ctx.emit_pathway.content_store
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    head_hash: bytes | None = None
    if head_entity and head_entity.type == "system/hash":
        head_hash = head_entity.data.get("hash")

    # Per EXTENSION-REVISION v3.1 §6.1 Amendment 2 (A.8):
    # every path bound in the parent version's trie MUST have an explicit
    # entry in the new version's trie — live binding if still bound, or
    # the canonical deletion marker if unbound between parent and commit.
    # Without this, deletions are expressed by absence and cannot be
    # distinguished from "not-bound-in-this-version" (the F10 in-flight-
    # write data-loss class). Markers in the trie are NOT live-tree
    # bindings (the live location index never carries them — see §4.4.4
    # Amendment 3 / apply translation).
    if head_hash is not None:
        parent_bindings = _get_version_bindings(ctx, head_hash) or {}
        for parent_path in parent_bindings.keys() - bindings.keys():
            # Format-relative to this peer's home format (V7 v7.70 §4.9).
            bindings[parent_path] = deletion_marker_hash()

    sorted_bindings = sorted(bindings.items())

    # Build content-addressed trie
    trie_root = build_trie(sorted_bindings, content_store)

    # §6.2 no-op commit dedup: if the current head already describes the
    # freshly-computed trie root, return it without creating a redundant
    # entry. Mirrors the dedup in §6.1 auto-version.
    if head_hash is not None:
        current_head_entity = content_store.get(head_hash)
        if (
            current_head_entity is not None
            and current_head_entity.type == VERSION_ENTRY_TYPE
            and current_head_entity.data.get("root") == trie_root
        ):
            commit_result = Entity(
                type="system/revision/commit-result",
                data={"version": head_hash, "root": trie_root},
            )
            return {
                "status": 200,
                "result": commit_result.to_dict(),
            }

    # Build parents list (sorted)
    parents: list[bytes] = []
    if head_hash:
        parents.append(head_hash)
    parents = sorted_parents(parents)

    # Create structural version entry
    version = Entity(
        type=VERSION_ENTRY_TYPE,
        data={"root": trie_root, "parents": parents},
    )
    version_hash = content_store.put(version)

    # Update HEAD and active branch
    _update_head_and_branch(ctx, ph,version_hash)

    logger.debug("[revision/commit] prefix=%r version=%s root=%s",
                 prefix, hash_to_display(version_hash), hash_to_display(trie_root))

    commit_result = Entity(
        type="system/revision/commit-result",
        data={"version": version_hash, "root": trie_root},
    )
    return {
        "status": 200,
        "result": commit_result.to_dict(),
    }


async def _handle_log(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """List version history with pagination."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    limit = params.get("limit")
    since = params.get("since")

    # Get starting point
    if since:
        start_hash = since
    else:
        head_entity = _get_entity_at_path(ctx, _head_path(ph))
        if head_entity is None:
            return {
                "status": 200,
                "result": {
                    "type": "system/envelope",
                    "data": {
                        "root": {
                            "type": "system/revision/log-result",
                            "data": {"prefix": prefix, "versions": []},
                        },
                        "included": {},
                    },
                },
            }
        start_hash = head_entity.data.get("hash")

    # Walk history (fetch one extra to detect has_more)
    fetch_limit = limit + 1 if limit else None
    version_hashes = _walk_history(ctx, start_hash, fetch_limit)

    has_more = False
    if limit and len(version_hashes) > limit:
        has_more = True
        version_hashes = version_hashes[:limit]

    result_data: dict[str, Any] = {"prefix": prefix, "versions": version_hashes}
    if has_more:
        result_data["has_more"] = True

    # M3: Wrap in system/envelope — domain entities inside result, not outer included
    included: dict[bytes, dict[str, Any]] = {}
    for vh in version_hashes:
        ve = _get_version_entity(ctx, vh)
        if ve:
            included[vh] = ve.to_dict()

    return {
        "status": 200,
        "result": {
            "type": "system/envelope",
            "data": {
                "root": {"type": "system/revision/log-result", "data": result_data},
                "included": included,
            },
        },
    }


async def _handle_status(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Current HEAD, remote HEADs, conflict count, pending changes."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)

    # Get local HEAD
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    local_hash = head_entity.data.get("hash") if head_entity else None

    # Build remotes map. Per V7 v7.64 §1.4 the trailing segment is
    # `peer_id_hex` (lowercase hex of the remote's `system/peer`
    # content_hash); callers that want the Base58 form must convert via
    # the remote's `system/peer` entity.
    remotes: dict[str, bytes] = {}
    tree = ctx.emit_pathway.entity_tree
    remotes_prefix = f"system/revision/{ph}/remotes/"
    full_remotes_prefix = tree.normalize_uri(remotes_prefix)
    for uri in tree.list_prefix(full_remotes_prefix):
        peer_id_hex = uri[len(full_remotes_prefix):]
        if peer_id_hex:
            remote_hash = tree.get(uri)
            if remote_hash:
                remotes[peer_id_hex] = remote_hash

    # Count conflicts
    conflicts_prefix = f"system/revision/{ph}/conflicts/"
    full_conflicts_prefix = tree.normalize_uri(conflicts_prefix)
    conflict_count = len(list(tree.list_prefix(full_conflicts_prefix)))

    # Count pending changes (compare HEAD trie root against current tree)
    pending = 0
    if local_hash:
        head_bindings = _get_version_bindings(ctx, local_hash)
        if head_bindings is not None:
            current_bindings = _get_snapshot_bindings(ctx, prefix)
            for path in current_bindings:
                if path not in head_bindings:
                    pending += 1
                elif current_bindings[path] != head_bindings[path]:
                    pending += 1
            for path in head_bindings:
                if path not in current_bindings:
                    pending += 1

    # Encode absent head as the 33-byte canonical zero hash
    # (algorithm byte 0x00 + 32 zero-digest bytes) rather than an empty
    # byte string. This matches Go/Rust peer encoding and the ECF hash
    # type's 33-byte requirement. Per Go team review of the
    # auto-version convention.
    head_field = local_hash if local_hash else (b"\x00" + b"\x00" * 32)

    # Scan for keep-both paths
    keep_both_paths: list[str] = []
    full_prefix = tree.normalize_uri(prefix)
    for uri in tree.list_prefix(full_prefix):
        relative = uri[len(full_prefix):]
        if ".keep-both-" in relative:
            keep_both_paths.append(relative)

    status_data: dict[str, Any] = {
        "prefix": prefix,
        "head": head_field,
        "remotes": remotes if remotes else None,
        "conflicts": conflict_count,
        "pending": pending,
    }
    if keep_both_paths:
        status_data["keep_both_paths"] = keep_both_paths

    return {
        "status": 200,
        "result": {
            "type": "system/revision/status",
            "data": status_data,
        },
    }


async def _handle_find_ancestor(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Find common ancestor of two versions."""
    version_a = params.get("version_a")
    version_b = params.get("version_b")

    if not version_a or not version_b:
        return _error_response(400, "invalid_params", "version_a and version_b required")

    ancestor = _find_common_ancestor(ctx, version_a, version_b)

    return {
        "status": 200,
        "result": {
            "type": "system/revision/ancestor-result",
            "data": {
                "version_a": version_a,
                "version_b": version_b,
                "ancestor": ancestor if ancestor else None,
            },
        },
    }


async def _handle_merge(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Three-way merge per EXTENSION-REVISION v2.1 section 4.4.4.

    Supports: three-way, source-wins, target-wins, manual strategies.
    No LWW (timestamps removed from version entries).
    Includes oscillation detection and merge ordering modes.
    """
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    source_ref = params.get("remote_version")
    strategy = params.get("strategy", "three-way")
    dry_run = params.get("dry_run", False)

    if not source_ref:
        return _error_response(400, "invalid_params", "remote_version required")

    valid_strategies = ("three-way", "source-wins", "target-wins", "manual", "keep-both")
    if strategy not in valid_strategies:
        return _error_response(400, "invalid_strategy", f"Strategy must be one of: {valid_strategies}")

    if not ctx.check_caller_permission("merge", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant merge on: {prefix}")

    # Resolve source
    source_hash = _resolve_ref(ctx, ph,source_ref)
    if source_hash is None:
        return _error_response(404, "ref_not_found", f"Source not found: {source_ref}")

    # Get local HEAD
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    if head_entity is None:
        # No local commits -- fast-forward to source
        cascade_warnings: list[dict[str, Any]] = []
        if not dry_run:
            source_bindings = _get_version_bindings(ctx, source_hash)
            _update_head_and_branch(ctx, ph,source_hash, "merge")
            if source_bindings:
                emit_ctx = EmitContext.from_handler_grant(ctx, "merge")
                # A.3 / v3.2 §4.4.4 first-ever sync: empty-trie baseline.
                # In-flight writes (paths not in source's trie) MUST be
                # preserved; deletions in source come through as markers
                # and `_apply_bindings_to_tree` translates them to live
                # unbinds (§4.4.4 Amendment 3).
                result = _apply_bindings_to_tree(
                    ctx, source_bindings, prefix, emit_ctx,
                    preserve_unknown=True,
                )
                cascade_warnings = result.get("cascade_warnings", [])

        result_data: dict[str, Any] = {
            "prefix": prefix,
            "status": "fast_forward",
            "version": source_hash,
            "dry_run": dry_run,
        }
        if cascade_warnings:
            result_data["cascade_warnings"] = cascade_warnings
        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-result",
                "data": result_data,
            },
        }

    local_hash = head_entity.data.get("hash")

    # Check relationship
    relationship = _check_relationship(ctx, local_hash, source_hash)

    if relationship == VersionRelationship.IN_SYNC:
        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-result",
                "data": {
                    "prefix": prefix,
                    "status": "already_in_sync",
                    "version": local_hash,
                    "dry_run": dry_run,
                },
            },
        }

    if relationship == VersionRelationship.BEHIND:
        # Fast-forward
        cascade_warnings_ff: list[dict[str, Any]] = []
        if not dry_run:
            source_bindings = _get_version_bindings(ctx, source_hash)
            _update_head_and_branch(ctx, ph,source_hash, "merge")
            if source_bindings:
                emit_ctx_ff = EmitContext.from_handler_grant(ctx, "merge")
                # A.3 / v3.2 §4.4.4 (BEHIND branch): diff baseline is the
                # committed local head trie, not the live tree. Use
                # preserve_unknown so in-flight unversioned writes are NOT
                # wiped by FF; explicit deletions in source come through
                # as marker bindings and translate to live unbinds.
                result_ff = _apply_bindings_to_tree(
                    ctx, source_bindings, prefix, emit_ctx_ff,
                    preserve_unknown=True,
                )
                cascade_warnings_ff = result_ff.get("cascade_warnings", [])

        result_data_ff: dict[str, Any] = {
            "prefix": prefix,
            "status": "fast_forward",
            "version": source_hash,
            "dry_run": dry_run,
        }
        if cascade_warnings_ff:
            result_data_ff["cascade_warnings"] = cascade_warnings_ff
        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-result",
                "data": result_data_ff,
            },
        }

    if relationship == VersionRelationship.AHEAD:
        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-result",
                "data": {
                    "prefix": prefix,
                    "status": "already_ahead",
                    "version": local_hash,
                    "dry_run": dry_run,
                },
            },
        }

    # Diverged or unrelated -- need actual merge
    # Get merge ordering config
    config = _get_config(ctx, ph)
    merge_order = config.get("merge_order", "deterministic")
    oscillation_depth = config.get("oscillation_depth", 4)

    # Normalize merge sides
    effective_local, effective_remote = _normalize_merge_sides(
        local_hash, source_hash, merge_order
    )

    # Find common ancestor
    if relationship == VersionRelationship.UNRELATED:
        ancestor_hash = None
    else:
        ancestor_hash = _find_common_ancestor(ctx, effective_local, effective_remote)

    # Flatten tries (Phase 1 approach: flatten-then-compare)
    local_bindings = _get_version_bindings(ctx, effective_local) or {}
    remote_bindings = _get_version_bindings(ctx, effective_remote) or {}
    ancestor_bindings = _get_version_bindings(ctx, ancestor_hash) if ancestor_hash else {}
    if ancestor_bindings is None:
        ancestor_bindings = {}

    # Content-identity check: if both have same trie root, no merge needed
    local_version = _get_version_entity(ctx, effective_local)
    remote_version = _get_version_entity(ctx, effective_remote)
    if (local_version and remote_version and
            local_version.data.get("root") == remote_version.data.get("root")):
        # Same content -- create merge version with both parents
        if not dry_run:
            content_store = ctx.emit_pathway.content_store
            merge_version = Entity(
                type=VERSION_ENTRY_TYPE,
                data={
                    "root": local_version.data["root"],
                    "parents": sorted_parents([local_hash, source_hash]),
                },
            )
            merge_hash = content_store.put(merge_version)
            _update_head_and_branch(ctx, ph,merge_hash, "merge")

            return {
                "status": 200,
                "result": {
                    "type": "system/revision/merge-result",
                    "data": {
                        "prefix": prefix,
                        "status": "merged",
                        "version": merge_hash,
                        "dry_run": dry_run,
                    },
                },
            }

    # Three-way merge
    merged_bindings, conflicts, additional_bindings = _merge_bindings(
        ctx, ancestor_bindings, local_bindings, remote_bindings, strategy,
        prefix=prefix,
    )

    for add_path, add_hash in additional_bindings:
        merged_bindings[add_path] = add_hash

    # Build merged trie
    content_store = ctx.emit_pathway.content_store
    merged_trie_root = build_trie(sorted(merged_bindings.items()), content_store)

    # Oscillation detection — v3.2 invariant 3: compare full identity
    # `{root, sorted_parents}`. The proposed merge version's parents are
    # (local_hash, source_hash); same root with different parents is a
    # legitimate cross-link and MUST NOT trip oscillation.
    proposed_merge_parents = [local_hash, source_hash]
    if _detect_oscillation(
        ctx, merged_trie_root, local_hash,
        proposed_parents=proposed_merge_parents,
        depth_limit=oscillation_depth,
    ):
        if not dry_run:
            # Create conflict entities for all divergent paths
            emit_ctx = EmitContext.from_handler_grant(ctx, "merge")
            diff = _compute_snapshot_diff(local_bindings, remote_bindings)
            for path in list(diff["added"].keys()) + list(diff["removed"].keys()) + list(diff["changed"].keys()):
                conflict_entity = Entity(
                    type=CONFLICT_TYPE,
                    data={
                        "path": path,
                        "base": ancestor_bindings.get(path),
                        "local": local_bindings.get(path),
                        "remote": remote_bindings.get(path),
                        "strategy": strategy,
                        "version_local": local_hash,
                        "version_remote": source_hash,
                    },
                )
                ctx.emit_pathway.emit(_conflict_path(ph,path), conflict_entity, emit_ctx)

        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-result",
                "data": {
                    "prefix": prefix,
                    "status": "oscillation_detected",
                    "dry_run": dry_run,
                },
            },
        }

    if not dry_run:
        emit_ctx = EmitContext.from_handler_grant(ctx, "merge")

        # Store conflicts as side-channel metadata
        if conflicts:
            for path, conflict_data in conflicts.items():
                # Check if there's an existing conflict (supersedes)
                existing_conflict = _get_entity_at_path(ctx, _conflict_path(ph,path))
                supersedes = None
                if existing_conflict and existing_conflict.type == CONFLICT_TYPE:
                    supersedes = existing_conflict.compute_hash()

                conflict_entity = Entity(
                    type=CONFLICT_TYPE,
                    data={
                        "path": path,
                        "base": conflict_data.get("base"),
                        "local": conflict_data.get("local"),
                        "remote": conflict_data.get("remote"),
                        "strategy": strategy,
                        "version_local": local_hash,
                        "version_remote": source_hash,
                        "supersedes": supersedes,
                    },
                )
                ctx.emit_pathway.emit(_conflict_path(ph,path), conflict_entity, emit_ctx)

        # Create merge version (structural: root + sorted parents)
        merge_version = Entity(
            type=VERSION_ENTRY_TYPE,
            data={
                "root": merged_trie_root,
                "parents": sorted_parents([local_hash, source_hash]),
            },
        )
        merge_hash = content_store.put(merge_version)

        # Advance head + active-branch BEFORE applying bindings (§6A.1).
        # Under auto-version, per-write consumers fire on each binding apply
        # and chain from current head. If bindings applied first, the auto-version
        # intermediates would be orphaned by the final head overwrite.
        _update_head_and_branch(ctx, ph,merge_hash, "merge")

        # Apply merged bindings to tree.
        # A.3 / v3.2 §4.4.4: three-way merge is a version-transcription
        # operation. Paths outside the merge's purview (in-flight writes
        # not tracked by either local or remote version) MUST be
        # preserved. Marker bindings produced by §4.4.4 Amendment 3
        # (deletion semantics) translate to live-tree unbinds at apply.
        apply_result = _apply_bindings_to_tree(
            ctx, merged_bindings, prefix, emit_ctx,
            preserve_unknown=True,
        )
        merge_cascade_warnings = apply_result.get("cascade_warnings", [])

        status = "merged_with_conflicts" if conflicts else "merged"
        result_data: dict[str, Any] = {
            "prefix": prefix,
            "status": status,
            "version": merge_hash,
            "dry_run": dry_run,
        }
        if conflicts:
            result_data["conflicts"] = list(conflicts.keys())
        if merge_cascade_warnings:
            result_data["cascade_warnings"] = merge_cascade_warnings

        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-result",
                "data": result_data,
            },
        }
    else:
        # C10: dry-run uses would_merge/would_conflict status strings
        status = "would_conflict" if conflicts else "would_merge"
        result_data = {
            "prefix": prefix,
            "status": status,
            "version": None,
            "dry_run": True,
        }
        if conflicts:
            result_data["conflicts"] = list(conflicts.keys())

        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-result",
                "data": result_data,
            },
        }


async def _handle_resolve(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Resolve merge conflict."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    path = params.get("path")
    resolved = params.get("resolved")

    if not path:
        return _error_response(400, "invalid_params", "path required")

    if not ctx.check_caller_permission("resolve", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant resolve on: {prefix}")

    content_store = ctx.emit_pathway.content_store
    if resolved is not None:
        if not content_store.has(resolved):
            return _error_response(404, "resolved_not_found",
                                   "Resolved entity hash not found in content store")

    conflict_full_path = _conflict_path(ph,path)
    conflict_entity = _get_entity_at_path(ctx, conflict_full_path)
    if conflict_entity is None:
        return _error_response(404, "conflict_not_found", f"No conflict at path: {path}")

    tree = ctx.emit_pathway.entity_tree
    uri = tree.normalize_uri(prefix + path)

    if resolved is not None:
        tree.set(uri, resolved)
    else:
        tree.remove(uri)

    # Remove conflict entry
    _remove_path(ctx, conflict_full_path)

    # Count remaining conflicts for this prefix
    conflicts_prefix = f"system/revision/{ph}/conflicts/"
    full_conflicts_prefix = tree.normalize_uri(conflicts_prefix)
    remaining = len(list(tree.list_prefix(full_conflicts_prefix)))

    return {
        "status": 200,
        "result": {
            "type": "system/revision/resolve-result",
            "data": {"path": path, "resolved": resolved, "remaining_conflicts": remaining},
        },
    }


async def _handle_diff(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Compare two versions (flatten-then-compare)."""
    base_ref = params.get("base")
    target_ref = params.get("target")
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)

    if not base_ref or not target_ref:
        return _error_response(400, "invalid_params", "base and target required")

    base_hash = _resolve_ref(ctx, ph,base_ref)
    target_hash = _resolve_ref(ctx, ph,target_ref)

    if base_hash is None:
        return _error_response(404, "ref_not_found", f"Base not found: {base_ref}")
    if target_hash is None:
        return _error_response(404, "ref_not_found", f"Target not found: {target_ref}")

    base_bindings = _get_version_bindings(ctx, base_hash)
    target_bindings = _get_version_bindings(ctx, target_hash)

    if base_bindings is None or target_bindings is None:
        return _error_response(500, "invalid_version", "Could not load version bindings")

    diff = _compute_snapshot_diff(base_bindings, target_bindings)

    return {
        "status": 200,
        "result": {
            "type": "system/tree/diff",
            "data": {
                "base": base_hash,
                "target": target_hash,
                **diff,
            },
        },
    }


# =============================================================================
# Convenience Operations
# =============================================================================


async def _handle_branch(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Create, list, or delete branches."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    action = params.get("action", "list")
    name = params.get("name")
    from_ref = params.get("from")

    # If name is provided without explicit action, assume create
    if name and action == "list":
        action = "create"

    emit_ctx = EmitContext.from_handler_grant(ctx, "branch")

    if action == "create":
        if not name:
            return _error_response(400, "invalid_params", "Branch name required for create")

        bp = _branch_path(ph,name)
        if _get_hash_at_path(ctx, bp) is not None:
            return _error_response(409, "branch_exists", f"Branch already exists: {name}")

        if from_ref:
            start_hash = from_ref
        else:
            head_entity = _get_entity_at_path(ctx, _head_path(ph))
            if head_entity is None:
                return _error_response(400, "no_head", "No HEAD to create branch from")
            start_hash = head_entity.data.get("hash")

        branch_entity = Entity(type="system/hash", data={"hash": start_hash})
        ctx.emit_pathway.emit(bp, branch_entity, emit_ctx)

        return {
            "status": 200,
            "result": {
                "type": "system/revision/branch-result",
                "data": {"status": "created", "branch": name, "version": start_hash},
            },
        }

    elif action == "delete":
        if not name:
            return _error_response(400, "invalid_params", "Branch name required for delete")

        active_branch_entity = _get_entity_at_path(ctx, _active_branch_path(ph))
        if (active_branch_entity
                and active_branch_entity.type == "primitive/string"
                and active_branch_entity.data == name):
            return _error_response(400, "cannot_delete", "Cannot delete active branch")

        bp = _branch_path(ph,name)
        if _get_hash_at_path(ctx, bp) is None:
            return _error_response(404, "branch_not_found", f"Branch not found: {name}")

        _remove_path(ctx, bp)

        return {
            "status": 200,
            "result": {
                "type": "system/revision/branch-result",
                "data": {"status": "deleted", "branch": name},
            },
        }

    else:
        # List branches
        branches: dict[str, bytes] = {}
        branch_prefix = f"system/revision/{ph}/branches/"

        for branch_name in _list_prefix(ctx, branch_prefix):
            be = _get_entity_at_path(ctx, _branch_path(ph,branch_name))
            if be:
                branches[branch_name] = be.data.get("hash")

        active_branch_entity = _get_entity_at_path(ctx, _active_branch_path(ph))
        active_branch = (
            active_branch_entity.data
            if active_branch_entity and active_branch_entity.type == "primitive/string"
            else None
        )

        return {
            "status": 200,
            "result": {
                "type": "system/revision/branch-result",
                "data": {"prefix": prefix, "branches": branches, "active": active_branch},
            },
        }


async def _handle_checkout(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Switch to branch or version, update tree."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    branch_name = params.get("branch")
    version_param = params.get("version")

    if not ctx.check_caller_permission("checkout", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant checkout on: {prefix}")

    active_branch = None
    if branch_name:
        branch_entity = _get_entity_at_path(ctx, _branch_path(ph,branch_name))
        if branch_entity is None:
            return _error_response(404, "branch_not_found", f"Branch not found: {branch_name}")
        version_hash = branch_entity.data.get("hash")
        active_branch = branch_name
    elif version_param:
        version_hash = version_param
        active_branch = None
    else:
        return _error_response(400, "invalid_params", "branch or version required")

    # Get version
    version_bindings = _get_version_bindings(ctx, version_hash)
    if version_bindings is None:
        return _error_response(404, "version_not_found", "Version not found")

    # A.3 / REVISION v3.2 §4.4.12 (transcription baseline): the diff
    # baseline is the **committed-local-head trie**, NOT the live tree.
    # Capture the source-version's bindings BEFORE advancing head — this
    # is the "source" side of the checkout's force-state diff.
    source_head_entity = _get_entity_at_path(ctx, _head_path(ph))
    source_head_hash = (
        source_head_entity.data.get("hash")
        if source_head_entity and source_head_entity.type == "system/hash"
        else None
    )
    source_bindings: dict[str, bytes] = (
        _get_version_bindings(ctx, source_head_hash) or {}
        if source_head_hash else {}
    )

    # Advance head + active branch BEFORE applying bindings (§6A.4).
    emit_ctx = EmitContext.from_handler_grant(ctx, "checkout")
    head_entity = Entity(type="system/hash", data={"hash": version_hash})
    ctx.emit_pathway.emit(_head_path(ph), head_entity, emit_ctx)

    if active_branch:
        ab_entity = Entity(type="primitive/string", data=active_branch)
        ctx.emit_pathway.emit(_active_branch_path(ph), ab_entity, emit_ctx)
    else:
        _remove_path(ctx, _active_branch_path(ph))

    # Apply bindings to tree. Per Python validator's `checkout_file3_removed`
    # FAIL (post-v3.3): checkout's semantics differ from FF/three-way merge:
    #
    # - FF/merge:   in-flight live paths NOT named by either side preserve
    #               (A.3 invariant 1).
    # - Checkout:   FORCE-STATE — paths present in the SOURCE version's
    #               trie but absent from the TARGET version's trie MUST
    #               be unbound from live. Paths in NEITHER version
    #               (in-flight writes outside the prefix's tracked set)
    #               still preserve.
    #
    # We implement this by passing `preserve_unknown=True` (so paths in
    # neither version's trie are preserved) and then explicitly removing
    # the source-only set (paths the source-trie acknowledged that the
    # target-trie doesn't). Marker bindings in target's trie translate
    # to live unbinds via `_apply_bindings_to_tree`'s normal path.
    checkout_apply = _apply_bindings_to_tree(
        ctx, version_bindings, prefix, emit_ctx,
        preserve_unknown=True,
    )
    checkout_warnings = checkout_apply.get("cascade_warnings", [])

    # Force-state removal: paths bound by the source version's trie but
    # absent from the target version's trie. Skip source-side markers
    # (they represented a delete in source; absence in target = same).
    pathway = ctx.emit_pathway
    full_prefix = pathway.entity_tree.normalize_uri(prefix)
    removed_force = 0
    for relative in source_bindings.keys() - version_bindings.keys():
        if is_deletion_marker(source_bindings[relative]):
            continue
        uri = pathway.entity_tree.normalize_uri(prefix + relative)
        if pathway.entity_tree.get(uri) is None:
            continue
        r = pathway.delete(uri, emit_ctx)
        if r.status == 207 and r.consumers_halted:
            checkout_warnings.append({
                "path": relative,
                "consumer_halted": r.consumers_halted.name,
                "error_code": f"cascade_halt/{r.consumers_halted.status}",
            })
        removed_force += 1
    # Keep the prefix-scoping check explicit (avoid stray var warnings).
    _ = full_prefix

    checkout_data: dict[str, Any] = {
        "status": "checked_out",
        "version": version_hash,
        "branch": active_branch,
    }
    if checkout_warnings:
        checkout_data["cascade_warnings"] = checkout_warnings
    return {
        "status": 200,
        "result": {
            "type": "system/revision/checkout-result",
            "data": checkout_data,
        },
    }


async def _handle_tag(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Create, list, or delete tags (immutable named pointers)."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    action = params.get("action", "list")
    name = params.get("name")
    version_param = params.get("version")

    if name and action == "list":
        action = "create"

    emit_ctx = EmitContext.from_handler_grant(ctx, "tag")

    if action == "delete":
        if not name:
            return _error_response(400, "invalid_params", "Tag name required for delete")

        tp = _tag_path(ph,name)
        if _get_hash_at_path(ctx, tp) is None:
            return _error_response(404, "tag_not_found", f"Tag not found: {name}")

        _remove_path(ctx, tp)

        return {
            "status": 200,
            "result": {
                "type": "system/revision/tag-result",
                "data": {"status": "deleted", "tag": name},
            },
        }

    elif action == "create":
        if not name:
            return _error_response(400, "invalid_params", "Tag name required for create")

        tp = _tag_path(ph,name)
        if _get_hash_at_path(ctx, tp) is not None:
            return _error_response(409, "tag_exists", f"Tag already exists: {name}")

        target_hash = version_param
        if not target_hash:
            head_entity = _get_entity_at_path(ctx, _head_path(ph))
            if head_entity is None:
                return _error_response(400, "no_head", "No HEAD to create tag from")
            target_hash = head_entity.data.get("hash")

        tag_entity = Entity(type="system/hash", data={"hash": target_hash})
        ctx.emit_pathway.emit(tp, tag_entity, emit_ctx)

        return {
            "status": 200,
            "result": {
                "type": "system/revision/tag-result",
                "data": {"status": "created", "tag": name, "version": target_hash},
            },
        }

    else:
        # List tags
        tags: dict[str, bytes] = {}
        tag_prefix = f"system/revision/{ph}/tags/"

        for tag_name in _list_prefix(ctx, tag_prefix):
            te = _get_entity_at_path(ctx, _tag_path(ph,tag_name))
            if te:
                tags[tag_name] = te.data.get("hash")

        return {
            "status": 200,
            "result": {
                "type": "system/revision/tag-result",
                "data": {"tags": tags},
            },
        }


async def _handle_cherry_pick(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Apply single version's delta via three-way merge."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    version_ref = params.get("version")

    if not version_ref:
        return _error_response(400, "invalid_params", "version required")

    if not ctx.check_caller_permission("cherry-pick", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant cherry-pick on: {prefix}")

    version_hash = _resolve_ref(ctx, ph,version_ref)
    if version_hash is None:
        return _error_response(404, "ref_not_found", f"Version not found: {version_ref}")

    version = _get_version_entity(ctx, version_hash)
    if not version:
        return _error_response(500, "invalid_version", "Could not load version")

    parents = version.data.get("parents", [])
    if not parents:
        return _error_response(400, "no_parent", "Cannot cherry-pick initial commit")

    # C7: explicit parent selection for merge versions
    parent_param = params.get("parent")
    if parent_param is not None:
        if parent_param not in parents:
            return _error_response(400, "invalid_parent",
                                   "Specified parent is not in version's parent list")
        parent_hash = parent_param
    elif len(parents) > 1:
        return _error_response(400, "ambiguous_parent",
                               "Merge version has multiple parents -- specify which parent to diff against")
    else:
        parent_hash = parents[0]

    # Get bindings (flatten tries)
    version_bindings = _get_version_bindings(ctx, version_hash)
    parent_bindings = _get_version_bindings(ctx, parent_hash)

    if version_bindings is None or parent_bindings is None:
        return _error_response(500, "invalid_version", "Could not load version bindings")

    # Compute diff (changes from parent to version)
    diff = _compute_snapshot_diff(parent_bindings, version_bindings)

    # Compute target tree bindings (current + diff) WITHOUT mutating the tree,
    # so we can build the trie, create the version, and advance head BEFORE
    # applying bindings (§6A.2 structural rule).
    current_bindings = _get_snapshot_bindings(ctx, prefix)
    target_bindings = dict(current_bindings)
    for path, h in diff["added"].items():
        target_bindings[path] = h
    for path, change in diff["changed"].items():
        target_bindings[path] = change["target_hash"]
    for path in diff["removed"]:
        target_bindings.pop(path, None)

    content_store = ctx.emit_pathway.content_store
    trie_root = build_trie(sorted(target_bindings.items()), content_store)

    # Create cherry-pick commit (single parent = current HEAD)
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    head_hash = head_entity.data.get("hash") if head_entity else None

    cherry_parents = [head_hash] if head_hash else []
    cherry_version = Entity(
        type=VERSION_ENTRY_TYPE,
        data={"root": trie_root, "parents": sorted_parents(cherry_parents)},
    )
    cherry_hash = content_store.put(cherry_version)

    # Advance head + active branch BEFORE applying bindings (§6A.2).
    _update_head_and_branch(ctx, ph,cherry_hash, "cherry-pick")

    # Apply changes to tree via emit pathway for cascade tracking.
    # A.3 / v3.2 §4.4.4: cherry-pick is a version-transcription operation
    # — paths outside its diff are NOT touched (preserve-unknown is the
    # natural mode here: we iterate only the diff). A.8 / §4.4.4
    # Amendment 3: marker-valued target hashes translate to live-tree
    # unbinds.
    emit = ctx.emit_pathway
    emit_ctx = EmitContext.from_handler_grant(ctx, "cherry-pick")
    cp_cascade_warnings: list[dict[str, Any]] = []
    applied = 0
    for path, h in diff["added"].items():
        uri = emit.entity_tree.normalize_uri(prefix + path)
        if is_deletion_marker(h):
            # Adding a marker at a path means the cherry-picked version
            # deletes a path that didn't exist in the local base. Idempotent
            # delete: nothing to do unless the live tree happens to bind it.
            if emit.entity_tree.get(uri) is not None:
                r = emit.delete(uri, emit_ctx)
            else:
                applied += 1
                continue
        else:
            r = emit.emit_hash(uri, h, emit_ctx)
        if r.status == 207 and r.consumers_halted:
            cp_cascade_warnings.append({
                "path": path, "consumer_halted": r.consumers_halted.name,
                "error_code": f"cascade_halt/{r.consumers_halted.status}",
            })
        applied += 1
    for path, change in diff["changed"].items():
        uri = emit.entity_tree.normalize_uri(prefix + path)
        target_h = change["target_hash"]
        if is_deletion_marker(target_h):
            r = emit.delete(uri, emit_ctx)
        else:
            r = emit.emit_hash(uri, target_h, emit_ctx)
        if r.status == 207 and r.consumers_halted:
            cp_cascade_warnings.append({
                "path": path, "consumer_halted": r.consumers_halted.name,
                "error_code": f"cascade_halt/{r.consumers_halted.status}",
            })
        applied += 1
    for path in diff["removed"]:
        uri = emit.entity_tree.normalize_uri(prefix + path)
        r = emit.delete(uri, emit_ctx)
        if r.status == 207 and r.consumers_halted:
            cp_cascade_warnings.append({
                "path": path, "consumer_halted": r.consumers_halted.name,
                "error_code": f"cascade_halt/{r.consumers_halted.status}",
            })
        applied += 1

    cp_result_data: dict[str, Any] = {
        "prefix": prefix,
        "status": "cherry_picked",
        "source": version_hash,
        "version": cherry_hash,
        "applied": applied,
    }
    if cp_cascade_warnings:
        cp_result_data["cascade_warnings"] = cp_cascade_warnings
    return {
        "status": 200,
        "result": {
            "type": "system/revision/cherry-pick-result",
            "data": cp_result_data,
        },
    }


async def _handle_revert(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Undo single version's delta."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    version_ref = params.get("version")

    if not version_ref:
        return _error_response(400, "invalid_params", "version required")

    if not ctx.check_caller_permission("revert", prefix):
        return _error_response(403, "forbidden", f"Capability doesn't grant revert on: {prefix}")

    version_hash = _resolve_ref(ctx, ph,version_ref)
    if version_hash is None:
        return _error_response(404, "ref_not_found", f"Version not found: {version_ref}")

    version = _get_version_entity(ctx, version_hash)
    if not version:
        return _error_response(500, "invalid_version", "Could not load version")

    parents = version.data.get("parents", [])
    if not parents:
        return _error_response(400, "no_parent", "Cannot revert initial commit")

    parent_param = params.get("parent")
    if parent_param is not None:
        if parent_param not in parents:
            return _error_response(400, "invalid_parent",
                                   "Specified parent is not in version's parent list")
        parent_hash = parent_param
    elif len(parents) > 1:
        return _error_response(400, "ambiguous_parent",
                               "Merge version has multiple parents -- specify which parent to diff against")
    else:
        parent_hash = parents[0]

    # Compute inverse diff (version -> parent)
    version_bindings = _get_version_bindings(ctx, version_hash)
    parent_bindings = _get_version_bindings(ctx, parent_hash)

    if version_bindings is None or parent_bindings is None:
        return _error_response(500, "invalid_version", "Could not load version bindings")

    diff = _compute_snapshot_diff(version_bindings, parent_bindings)

    # Compute target tree bindings (current + inverse diff) without mutating
    # the tree, so head advances BEFORE binding application (§6A.3).
    current_bindings = _get_snapshot_bindings(ctx, prefix)
    target_bindings = dict(current_bindings)
    for path, h in diff["added"].items():
        target_bindings[path] = h
    for path, change in diff["changed"].items():
        target_bindings[path] = change["target_hash"]
    for path in diff["removed"]:
        target_bindings.pop(path, None)

    content_store = ctx.emit_pathway.content_store
    trie_root = build_trie(sorted(target_bindings.items()), content_store)

    # Create revert commit
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    head_hash = head_entity.data.get("hash") if head_entity else None

    revert_parents = [head_hash] if head_hash else []
    revert_version = Entity(
        type=VERSION_ENTRY_TYPE,
        data={"root": trie_root, "parents": sorted_parents(revert_parents)},
    )
    revert_hash = content_store.put(revert_version)

    # Advance head + active branch BEFORE applying bindings (§6A.3).
    _update_head_and_branch(ctx, ph,revert_hash, "revert")

    # Apply inverse changes via emit pathway for cascade tracking.
    # A.3 / v3.2 §4.4.4 + A.8 / §4.4.4 Amendment 3: revert is a
    # version-transcription operation; marker-valued target hashes
    # translate to live-tree unbinds.
    emit = ctx.emit_pathway
    emit_ctx = EmitContext.from_handler_grant(ctx, "revert")
    rv_cascade_warnings: list[dict[str, Any]] = []
    applied = 0
    for path, h in diff["added"].items():
        uri = emit.entity_tree.normalize_uri(prefix + path)
        if is_deletion_marker(h):
            if emit.entity_tree.get(uri) is not None:
                r = emit.delete(uri, emit_ctx)
            else:
                applied += 1
                continue
        else:
            r = emit.emit_hash(uri, h, emit_ctx)
        if r.status == 207 and r.consumers_halted:
            rv_cascade_warnings.append({
                "path": path, "consumer_halted": r.consumers_halted.name,
                "error_code": f"cascade_halt/{r.consumers_halted.status}",
            })
        applied += 1
    for path, change in diff["changed"].items():
        uri = emit.entity_tree.normalize_uri(prefix + path)
        target_h = change["target_hash"]
        if is_deletion_marker(target_h):
            r = emit.delete(uri, emit_ctx)
        else:
            r = emit.emit_hash(uri, target_h, emit_ctx)
        if r.status == 207 and r.consumers_halted:
            rv_cascade_warnings.append({
                "path": path, "consumer_halted": r.consumers_halted.name,
                "error_code": f"cascade_halt/{r.consumers_halted.status}",
            })
        applied += 1
    for path in diff["removed"]:
        uri = emit.entity_tree.normalize_uri(prefix + path)
        r = emit.delete(uri, emit_ctx)
        if r.status == 207 and r.consumers_halted:
            rv_cascade_warnings.append({
                "path": path, "consumer_halted": r.consumers_halted.name,
                "error_code": f"cascade_halt/{r.consumers_halted.status}",
            })
        applied += 1

    rv_result_data: dict[str, Any] = {
        "prefix": prefix,
        "status": "reverted",
        "reverted": version_hash,
        "version": revert_hash,
        "applied": applied,
    }
    if rv_cascade_warnings:
        rv_result_data["cascade_warnings"] = rv_cascade_warnings
    return {
        "status": 200,
        "result": {
            "type": "system/revision/revert-result",
            "data": rv_result_data,
        },
    }


# =============================================================================
# Transfer Operations
# =============================================================================


async def _handle_fetch(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Get version entries + root trie nodes from remote.

    Per EXTENSION-REVISION v2.1: fetch walks the DAG from HEAD,
    returns version entries and their root trie nodes in included.
    """
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    since = params.get("since")
    depth = params.get("depth")

    # Get HEAD
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    if head_entity is None:
        return {
            "status": 200,
            "result": {
                "type": "system/envelope",
                "data": {
                    "root": {
                        "type": "system/revision/fetch-result",
                        "data": {"head": None, "versions": [], "has_more": False},
                    },
                    "included": {},
                },
            },
        }

    head_hash = head_entity.data.get("hash")

    # Walk history
    version_hashes = _walk_history(ctx, head_hash, depth)

    # Filter by since (stop at since hash)
    if since:
        filtered = []
        for vh in version_hashes:
            if vh == since:
                break
            filtered.append(vh)
        version_hashes = filtered

    has_more = depth is not None and len(version_hashes) >= depth

    # Build included: version entities + their root trie nodes
    included: dict[bytes, dict[str, Any]] = {}
    for vh in version_hashes:
        ve = _get_version_entity(ctx, vh)
        if ve:
            included[vh] = ve.to_dict()
            # Also include root trie node
            root_hash = ve.data.get("root")
            if root_hash:
                root_node = ctx.emit_pathway.content_store.get(root_hash)
                if root_node:
                    included[root_hash] = root_node.to_dict()

    return {
        "status": 200,
        "result": {
            "type": "system/envelope",
            "data": {
                "root": {
                    "type": "system/revision/fetch-result",
                    "data": {
                        "head": head_hash,
                        "versions": version_hashes,
                        "has_more": has_more,
                    },
                },
                "included": included,
            },
        },
    }


async def _handle_fetch_entities(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Hash-validated incremental entity retrieval.

    Per EXTENSION-REVISION v2.1: validates requested hashes against
    the specified trie root before returning entities.
    """
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    snapshot_hash = params.get("snapshot")
    requested_hashes = params.get("hashes", [])

    if not snapshot_hash:
        return _error_response(400, "invalid_params", "snapshot required")
    if not requested_hashes:
        return _error_response(400, "invalid_params", "hashes required")

    # Validate snapshot is referenced by a version in the prefix's DAG
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    if head_entity is None:
        return _error_response(404, "no_versions", "No versions at prefix")

    head_hash = head_entity.data.get("hash")
    version_hashes = _walk_history(ctx, head_hash)

    snapshot_valid = False
    for vh in version_hashes:
        ve = _get_version_entity(ctx, vh)
        if ve and ve.data.get("root") == snapshot_hash:
            snapshot_valid = True
            break

    if not snapshot_valid:
        return _error_response(403, "invalid_snapshot",
                               "Snapshot not referenced by any version in prefix DAG")

    # Collect all valid hashes in the trie
    valid_hashes = collect_trie_hashes(snapshot_hash, ctx.emit_pathway.content_store)

    # Validate and return requested entities
    found: list[bytes] = []
    missing: list[bytes] = []
    included: dict[bytes, dict[str, Any]] = {}

    for h in requested_hashes:
        if h not in valid_hashes:
            missing.append(h)
            continue
        entity = ctx.emit_pathway.content_store.get(h)
        if entity:
            found.append(h)
            included[h] = entity.to_dict()
        else:
            missing.append(h)

    return {
        "status": 200,
        "result": {
            "type": "system/envelope",
            "data": {
                "root": {
                    "type": "system/revision/fetch-entities-result",
                    "data": {"found": found, "missing": missing},
                },
                "included": included,
            },
        },
    }


def _is_zero_hash(h: Any) -> bool:
    """True for the 'no base / full closure' sentinel.

    The caller signals 'I have nothing, send the full closure' by omitting
    `base` or sending an all-zero hash. Mirrors core-go `hash.Hash.IsZero`.
    Delegates to the shared `ecf.is_zero_hash` (also the V7 §3.9 CAS-create
    sentinel) so the predicate is defined once.
    """
    return is_zero_hash(h)


async def _handle_fetch_diff(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Incremental content transport (EXTENSION-REVISION v3.4 §4.4.19).

    Bundle the *content closure* of what changed between a caller-supplied
    base version and this peer's current head for `prefix`, in one round
    trip. The canonical 2-step cross-peer follow chain is
    `subscribe head → revision:fetch-diff(prefix, base) → tree:merge`.

    The target is **implicit** (this peer's current head) — that's what
    keeps the op single-dynamic-field and chain-expressible (a standing
    chain threads `base=$notification.previous_hash`; `prefix` stays
    static).

    Layering: this is a revision op because its inputs are versions
    (revision-layer). It derefs version → trie root here, then calls the
    tree-layer closure-bundle primitives downward (revision → tree). It
    deliberately mirrors the core-go skip-set bundle
    (`CollectReachableHashes` + `CollectTrieEntitiesExcept`) so the wire
    envelope is byte-identical across impls.

    Errors:
    - 400 invalid_params      — `prefix` missing or params undecodable
    - 403 capability_denied   — caller lacks `fetch-diff` cap on prefix
    - 404 no_local_state      — no revision head bound for prefix
    - 404 base_not_found      — base hash not in local content store
    - 400 base_not_a_version  — base resolves but isn't a version entry
    """
    # `prefix` is required, but "" is the valid universal-tree prefix —
    # only a missing (None) prefix is invalid.
    prefix = params.get("prefix")
    if prefix is None:
        return _error_response(400, "invalid_params", "prefix is required")

    if not ctx.check_caller_permission("fetch-diff", prefix):
        return _error_response(
            403, "capability_denied",
            f"Capability doesn't grant fetch-diff on: {prefix}",
        )

    cs = ctx.emit_pathway.content_store
    ph = _compute_prefix_hash(ctx, prefix)

    # target = current head (implicit). The head binding wraps the version
    # hash in a `system/hash` entity (see _update_head_and_branch).
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    if head_entity is None or head_entity.type != "system/hash":
        return _error_response(
            404, "no_local_state",
            f"No version history at prefix: {prefix}",
        )
    head_hash = head_entity.data.get("hash")
    target_version = _get_version_entity(ctx, head_hash)
    if target_version is None:
        return _error_response(
            500, "internal_error",
            "revision head version entry missing or undecodable",
        )
    target_root = target_version.data.get("root")

    # base — caller-supplied version (or zero/omitted for full closure).
    # F-CIMP-7: accept either form symmetrically with how target=head is
    # resolved above. The canonical follow chain `subscribe head →
    # fetch-diff(base=$notification.previous_hash) → merge` threads the
    # CONTENT HASH of the entity at the changed URI; for the head URI
    # that entity is a `system/hash` wrapper around the version-entry
    # hash, NOT the version-entry hash itself. Local callers (pull, diff
    # tests) pass the version-entry hash directly. Both must work.
    base = params.get("base")
    base_root: bytes | None = None
    if not _is_zero_hash(base):
        base_entity = cs.get(base)
        if base_entity is None:
            return _error_response(
                404, "base_not_found",
                "Base hash not in content store; "
                "caller may retry with base unset (full closure)",
            )
        # Unwrap one level if base resolves to a `system/hash` pointer
        # (notification-form). Mirrors target=head deref at line 2572.
        if base_entity.type == "system/hash":
            wrapped = base_entity.data.get("hash")
            if wrapped is None:
                return _error_response(
                    400, "base_not_a_version",
                    "Base resolves to system/hash with no `hash` field",
                )
            base_entity = cs.get(wrapped)
            if base_entity is None:
                return _error_response(
                    404, "base_not_found",
                    "Wrapped version not in content store",
                )
        if base_entity.type != VERSION_ENTRY_TYPE:
            return _error_response(
                400, "base_not_a_version",
                f"Base hash does not resolve to a version entry "
                f"(got type={base_entity.type!r})",
            )
        base_root = base_entity.data.get("root")

    # Bundle the diff closure. Everything reachable from base_root is the
    # "receiver already has" set; collect target-reachable entities except
    # those (content-addressed equality skips shared subtrees + leaves).
    skip: set[bytes] = set()
    if base_root is not None:
        skip = collect_trie_hashes(base_root, cs)
    included: dict[bytes, dict[str, Any]] = {}
    if target_root is not None:
        collect_trie_entities_except(target_root, skip, cs, included)

    snapshot = Entity(type="system/tree/snapshot", data={"root": target_root})
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


# Bound on the fetch-entities trie-walk loop. A complete closure resolves
# in O(tree depth) rounds; this cap guards against an inconsistent remote
# that never converges. Mirrors core-go `pullMaxRounds`.
PULL_MAX_ROUNDS = 32


def _collect_missing_pull_hashes(content_store, root: bytes | None) -> list[bytes]:
    """Walk the trie at `root`; return trie-node + leaf-binding hashes the
    local store does NOT have.

    Mirrors core-go `collectMissingPullHashes`. A trie node we don't have
    yet is itself requested (its children can't be walked until it arrives —
    `fetch` only ships the root trie node, so deeper nodes surface over
    successive rounds). For a node we do have, any absent leaf binding is
    requested.

    v4.0 node shape (EXTENSION-TREE.md §3.1): walk ``{map, data}`` where
    each Entry in ``data`` is either a Bucket (CBOR array of
    ``[key, value_hash]`` tuples — terminal) or a Link (33-byte CBOR byte
    string — sub-node, recurse).
    """
    if not root:
        return []
    seen: set[bytes] = set()
    missing: list[bytes] = []

    def visit(h: bytes) -> None:
        if not h or h in seen:
            return
        seen.add(h)
        node = content_store.get(h)
        if node is None:
            # Trie node not local yet — request it; can't walk its children.
            missing.append(h)
            return
        if node.type != TRIE_NODE_TYPE:
            # Not a trie node (a leaf data entity) — nothing to walk.
            return
        for entry in node.data.get("data", []):
            if isinstance(entry, (bytes, bytearray)):
                # Link → recurse into sub-node
                visit(bytes(entry))
            else:
                # Bucket → check each leaf value_hash for local presence
                for pair in entry:
                    value_hash = bytes(pair[1])
                    if not content_store.has(value_hash):
                        missing.append(value_hash)

    visit(root)
    return missing


async def _handle_pull(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Cross-peer pull (EXTENSION-REVISION §4.4.8).

    The follower-side convenience composition: outbound `fetch` to the
    remote + incremental `fetch-entities` trie walk until the head's
    closure is local + a local `merge` against the fetched remote head.
    Input reuses `system/revision/fetch-params`; the `remote` field names
    the peer to pull from. Output is `system/revision/merge-result`.

    Dispatched on the FOLLOWER (caller-local): the handler makes outbound
    EXECUTEs to the remote and merges into the local DAG. Folding the
    trie-walk loop into one op is what makes pull usable from a
    continuation chain (transforms cannot iterate caller-side; the
    iteration moves inside the op). Mirrors core-go `ext/revision/pull.go`.

    Errors:
    - 400 invalid_params       — prefix or remote missing/undecodable
    - 403 capability_denied    — caller lacks pull cap on prefix
    - 502 remote_fetch_failed  — outbound fetch/fetch-entities errored
    - 500 remote_empty         — remote has no head at the prefix
    - 500 internal_error       — version entity missing after ingest
    """
    # `prefix` is required, but "" is the valid universal-tree prefix —
    # only a missing (None) prefix is invalid.
    prefix = params.get("prefix")
    if prefix is None:
        return _error_response(400, "invalid_params", "prefix is required")
    remote = params.get("remote")
    if not remote:
        return _error_response(
            400, "invalid_params", "remote peer-id is required for pull",
        )

    if not ctx.check_caller_permission("pull", prefix):
        return _error_response(
            403, "capability_denied", f"Capability doesn't grant pull on: {prefix}",
        )

    cs = ctx.emit_pathway.content_store
    remote_uri = f"entity://{remote}/system/revision"
    remote_prefix = params.get("remote_prefix")
    # The prefix used when querying the remote's own revision handler.
    remote_query_prefix = remote_prefix if remote_prefix else prefix

    # 1. Outbound fetch on the remote (version DAG + root trie nodes).
    fetch_data: dict[str, Any] = {"prefix": remote_query_prefix}
    if remote_prefix:
        fetch_data["remote_prefix"] = remote_prefix
    if params.get("since") is not None:
        fetch_data["since"] = params["since"]
    if params.get("depth") is not None:
        fetch_data["depth"] = params["depth"]
    try:
        fetch_resp = await ctx.execute(
            remote_uri, "fetch",
            {"type": "system/revision/fetch-params", "data": fetch_data},
        )
    except Exception as e:
        return _error_response(
            502, "remote_fetch_failed", f"revision/fetch on {remote}: {e}",
        )
    if fetch_resp is None or fetch_resp.status >= 400:
        status = fetch_resp.status if fetch_resp else 0
        return _error_response(
            502, "remote_fetch_failed",
            f"revision/fetch on {remote}: status={status}",
        )

    # 2. Decode the envelope; ingest included (version entries + root nodes).
    result = fetch_resp.result if isinstance(fetch_resp.result, dict) else {}
    if result.get("type") != "system/envelope":
        return _error_response(
            502, "remote_fetch_failed",
            f"expected system/envelope from remote fetch; got {result.get('type')!r}",
        )
    env_data = result.get("data", {})
    for ent_dict in (env_data.get("included") or {}).values():
        if isinstance(ent_dict, dict):
            cs.put(Entity.from_dict(ent_dict))
    fetch_result = (env_data.get("root") or {}).get("data", {})
    head = fetch_result.get("head")
    if not head:
        return _error_response(
            500, "remote_empty",
            f"remote {remote} has no versions at prefix {prefix}",
        )

    # 3. Walk the remote's trie locally; iteratively fetch-entities until
    #    the head's closure is complete (or the remote stops supplying).
    version_ent = _get_version_entity(ctx, head)
    if version_ent is None:
        return _error_response(
            500, "internal_error", "version entity missing after fetch ingest",
        )
    root = version_ent.data.get("root")
    for _round in range(PULL_MAX_ROUNDS):
        missing = _collect_missing_pull_hashes(cs, root)
        if not missing:
            break
        fe_data = {
            "prefix": remote_query_prefix,
            "snapshot": root,
            "hashes": missing,
        }
        try:
            fe_resp = await ctx.execute(
                remote_uri, "fetch-entities",
                {"type": "system/revision/fetch-entities-params", "data": fe_data},
            )
        except Exception as e:
            return _error_response(
                502, "remote_fetch_failed",
                f"revision/fetch-entities on {remote}: {e}",
            )
        if fe_resp is None or fe_resp.status >= 400:
            status = fe_resp.status if fe_resp else 0
            return _error_response(
                502, "remote_fetch_failed",
                f"revision/fetch-entities on {remote}: status={status}",
            )
        fe_result = fe_resp.result if isinstance(fe_resp.result, dict) else {}
        if fe_result.get("type") != "system/envelope":
            break
        ingested = 0
        for ent_dict in (fe_result.get("data", {}).get("included") or {}).values():
            if isinstance(ent_dict, dict):
                cs.put(Entity.from_dict(ent_dict))
                ingested += 1
        if ingested == 0:
            # Remote reports nothing else available — stop rather than loop
            # forever against an inconsistent remote.
            break

    # 4. Local merge against the freshly-fetched remote head.
    return await _handle_merge({"prefix": prefix, "remote_version": head}, ctx)


async def _handle_push(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Update remote tracking pointer."""
    prefix = params.get("prefix", "")
    ph = _compute_prefix_hash(ctx, prefix)
    remote_peer = params.get("remote")
    remote_prefix = params.get("remote_prefix", prefix)
    force = params.get("force", False)

    if not remote_peer:
        return _error_response(400, "invalid_params", "remote required")

    if ctx._execute_dispatcher is None:
        return _error_response(501, "not_available", "Remote operations require execute dispatcher")

    # Get local HEAD
    head_entity = _get_entity_at_path(ctx, _head_path(ph))
    if head_entity is None:
        return _error_response(400, "no_head", "No local commits to push")

    local_head = head_entity.data.get("hash")

    # Get remote status
    status_result = await ctx.execute(
        f"entity://{remote_peer}/system/revision",
        "status",
        {"prefix": remote_prefix},
    )

    if not status_result.ok:
        return _error_response(status_result.status, "push_failed",
                               f"Failed to get remote status: {status_result.error}")

    remote_status = status_result.result
    remote_head = remote_status.get("data", {}).get("head")

    if remote_head:
        relationship = _check_relationship(ctx, local_head, remote_head)

        if relationship == VersionRelationship.IN_SYNC:
            return {
                "status": 200,
                "result": {
                    "type": "system/revision/push-result",
                    "data": {
                        "prefix": prefix,
                        "remote": remote_peer,
                        "status": "up-to-date",
                        "pushed": 0,
                    },
                },
            }

        if relationship == VersionRelationship.BEHIND:
            return _error_response(409, "non_fast_forward",
                                   "Push rejected - local is behind remote. Fetch and merge first.")

        if relationship == VersionRelationship.DIVERGED and not force:
            return _error_response(409, "diverged",
                                   "Push rejected - histories have diverged. Use force or fetch+merge first.")

    # Walk local history to find versions to push
    versions_to_push: list[bytes] = []
    queue: deque[bytes] = deque([local_head])
    seen: set[bytes] = set()

    while queue:
        version_hash = queue.popleft()
        if version_hash in seen:
            continue
        seen.add(version_hash)

        if remote_head and version_hash == remote_head:
            continue

        versions_to_push.append(version_hash)

        version = _get_version_entity(ctx, version_hash)
        if version:
            for parent in version.data.get("parents", []):
                if parent and parent not in seen:
                    queue.append(parent)

    # Push versions (oldest first)
    pushed = 0
    for version_hash in reversed(versions_to_push):
        version = _get_version_entity(ctx, version_hash)
        if not version:
            continue

        push_result = await ctx.execute(
            f"entity://{remote_peer}/system/revision",
            "receive-version",
            {"version": version.to_dict()},
        )

        if push_result.ok:
            pushed += 1

    if pushed > 0:
        await ctx.execute(
            f"entity://{remote_peer}/system/revision",
            "update-head",
            {"prefix": remote_prefix, "hash": local_head},
        )

    return {
        "status": 200,
        "result": {
            "type": "system/revision/push-result",
            "data": {
                "prefix": prefix,
                "remote": remote_peer,
                "status": "pushed",
                "pushed": pushed,
                "head": local_head,
            },
        },
    }


# =============================================================================
# Configuration (PROPOSAL-REVISION-CONFIG-OPERATION §3.1, R1)
# =============================================================================


def _tracking_config_path(prefix: str) -> str:
    """Derive tracking-config path from a revision prefix."""
    canonical = prefix.strip("/")
    key = "root" if not canonical else canonical.replace("/", "-")
    return f"system/tree/tracking-config/{key}"


async def _handle_config(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Validate and write/delete revision config.

    Per PROPOSAL-REVISION-CONFIG-OPERATION §3.1 (R1). Supports "set"
    and "delete" actions with CAS guard and tracking-config coordination.
    """
    name = params.get("name", "")
    if not name:
        return _error_response(400, "config/missing-name", "params must specify a config name")

    action = params.get("action", "")
    if action == "set":
        return await _handle_config_set(name, params, ctx)
    elif action == "delete":
        return await _handle_config_delete(name, params, ctx)
    else:
        return _error_response(
            400, "config/invalid-action",
            f'action must be "set" or "delete", got {action!r}',
        )


async def _handle_config_set(
    name: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle prefix-config set action (§4.4.17).

    Merge-config writes go through the separate `merge-config` operation
    (§4.4.18 / v3.3 D1), NOT this op. This op exists for the
    coordination need around prefix-config + tracking-config; merge-
    config has no such coordination need.
    """
    config_data = params.get("config")
    if config_data is None:
        return _error_response(400, "config/missing-config", 'config field is required when action is "set"')

    if isinstance(config_data, dict) and config_data.get("type") == "system/revision/config":
        cfg = config_data.get("data", config_data)
    else:
        cfg = config_data

    # V1: prefix must not be empty
    prefix = cfg.get("prefix", "")
    if not prefix:
        return _error_response(400, "config/invalid-prefix", "config prefix must not be empty")

    cfg_ph = _compute_prefix_hash(ctx, prefix)
    config_path = _config_path_for_prefix(cfg_ph)

    # V2: auto_version exclude enforcement
    if cfg.get("auto_version"):
        errors = validate_revision_config(cfg)
        if errors:
            return _error_response(400, "config/missing-required-exclude", "; ".join(errors))

    # V3: trie root exclude when prefix encompasses system/tree/root/
    if cfg.get("auto_version"):
        if _prefix_encompasses(prefix, "system/tree/root/"):
            excludes = list(cfg.get("exclude") or [])
            if not _exclude_covers(excludes, "system/tree/root/"):
                return _error_response(
                    400, "config/missing-trie-root-exclude",
                    f"auto_version with prefix {prefix!r} requires system/tree/root/** in exclude",
                )

    # merge_order validation
    merge_order = cfg.get("merge_order")
    if merge_order is not None and merge_order not in ("deterministic", "caller-perspective"):
        return _error_response(
            400, "config/invalid-merge-order",
            f'merge_order must be "deterministic" or "caller-perspective", got {merge_order!r}',
        )

    # V5: oscillation_depth minimum
    osc_depth = cfg.get("oscillation_depth")
    if osc_depth is not None and osc_depth < 2:
        return _error_response(
            400, "config/oscillation-depth-below-minimum",
            f"oscillation_depth must be >= 2, got {osc_depth}",
        )

    # CAS guard
    expected_hash = params.get("expected_hash")
    if expected_hash is not None:
        full_uri = ctx.emit_pathway.entity_tree.normalize_uri(config_path)
        current_hash = ctx.emit_pathway.entity_tree.get(full_uri)
        if current_hash != expected_hash:
            return _error_response(409, "config/concurrent-modification", "expected_hash does not match current binding")

    # Read previous state for tracking-config coordination
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(config_path)
    previous_hash = ctx.emit_pathway.entity_tree.get(full_uri)
    was_auto_version = False
    if previous_hash is not None:
        prev_entity = ctx.emit_pathway.content_store.get(previous_hash)
        if prev_entity and prev_entity.type == "system/revision/config":
            was_auto_version = bool(prev_entity.data.get("auto_version"))

    enabling = bool(cfg.get("auto_version")) and not was_auto_version
    disabling = not bool(cfg.get("auto_version")) and was_auto_version

    tracking_path = _tracking_config_path(prefix)
    tracking_action: str | None = None
    emit_ctx = EmitContext.from_handler_grant(ctx, "config")

    # Enable auto-version: write tracking-config FIRST (§6.1 ordering)
    if enabling:
        tc_uri = ctx.emit_pathway.entity_tree.normalize_uri(tracking_path)
        existed = ctx.emit_pathway.entity_tree.get(tc_uri) is not None
        tc_entity = Entity(
            type="system/tree/tracking-config",
            data={"prefix": prefix, "enabled": True},
        )
        tc_result = ctx.emit_pathway.emit(tracking_path, tc_entity, emit_ctx)
        if tc_result.status not in (200, 207):
            return _error_response(500, "config/tracking-config-write-failed", "tree.put refused (cascade depth)")
        tracking_action = "updated" if existed else "created"

    # Write the revision config
    config_entity = Entity(type="system/revision/config", data=cfg)
    cfg_result = ctx.emit_pathway.emit(config_path, config_entity, emit_ctx)
    if cfg_result.status not in (200, 207):
        return _error_response(500, "config/config-write-failed", "tree.put refused (cascade depth)")

    # Disable auto-version: remove tracking-config AFTER config write (§6.1 ordering)
    if disabling:
        ctx.emit_pathway.delete(tracking_path, emit_ctx)
        tracking_action = "deleted"

    # F-CIMP-1: omit `previous_hash` when absent. Emitting
    # `previous_hash: None` here landed `null` (or h'') on the wire; Go's
    # `omitzero` decoder reads either as an invalid 33-byte hash and rejects
    # the entire result envelope with "invalid hash: expected 33 bytes,
    # got 0". The substrate convergence suite (`validate-peer`) never
    # decoded `RevisionConfigResultData` so this bug rode underneath every
    # cross-impl auto-version run since v1.x. Mirror the conditional pattern
    # used below for `tracking_*`. See the queued arch-question on this
    # omitzero behavior + workbench-go's perf-stress memo §2.1.
    result_data: dict[str, Any] = {
        "config_path": config_path,
        "config_hash": cfg_result.hash,
    }
    if previous_hash is not None:
        result_data["previous_hash"] = previous_hash
    if tracking_action is not None:
        result_data["tracking_config_path"] = tracking_path
        result_data["tracking_config_action"] = tracking_action

    return {
        "status": 200,
        "result": {
            "type": "system/revision/config-result",
            "data": result_data,
        },
    }


_MERGE_CONFIG_PATH_PREFIX = "system/revision/config/merge/path/"
_MERGE_CONFIG_TYPE_PREFIX = "system/revision/config/merge/type/"


async def _handle_merge_config(
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """EXTENSION-REVISION v3.3 §4.4.18 — `merge-config` canonical op.

    Validates and writes (or deletes) the per-path or per-type merge-
    config entries at the global, handler-owned namespace
    ``system/revision/config/merge/{path,type}/*``. This op is the
    config-write-time enforcement surface for the §2.3 strategy-
    rejection contract — ``lww``/``keep-both`` MUST surface as
    ``400 invalid_strategy`` before any binding lands.

    Params shape (``system/revision/merge-config-params``):
        scope:         "path" | "type"
        name:          pattern (scope=path) or type name (scope=type)
        action:        "set" | "delete"
        config:        system/revision/merge-config (required when action="set")
        expected_hash: optional CAS guard

    Result shape (``system/revision/merge-config-result``):
        path:   binding path written or deleted
        hash:   new entity hash (action=set); absent on delete
        status: "set" | "deleted" | "no_change"
    """
    # Step 1: validate scope.
    scope = params.get("scope")
    if scope not in ("path", "type"):
        return _error_response(
            400, "invalid_scope",
            f'scope must be "path" or "type"; got {scope!r}',
        )

    name = params.get("name")
    if not isinstance(name, str) or not name:
        return _error_response(
            400, "invalid_params", "name is required (string)",
        )

    action = params.get("action")
    if action not in ("set", "delete"):
        return _error_response(
            400, "invalid_action",
            f'action must be "set" or "delete"; got {action!r}',
        )

    # Step 2: compute the write path. Merge configs are GLOBAL (not
    # prefix-scoped) per §3.1.1 + §5.1; their `pattern` field matches
    # trie-relative paths under any prefix.
    write_path = (
        _MERGE_CONFIG_PATH_PREFIX + name
        if scope == "path"
        else _MERGE_CONFIG_TYPE_PREFIX + name
    )

    pathway = ctx.emit_pathway
    full_uri = pathway.entity_tree.normalize_uri(write_path)

    # Step 3: CAS guard.
    expected_hash = params.get("expected_hash")
    if expected_hash is not None:
        current_hash = pathway.entity_tree.get(full_uri)
        if current_hash != expected_hash:
            return _error_response(
                409, "stale_expected_hash",
                "expected_hash does not match current binding",
            )

    emit_ctx = EmitContext.from_handler_grant(ctx, "merge-config")

    # Step 4a: delete action.
    if action == "delete":
        existing = pathway.entity_tree.get(full_uri)
        if existing is None:
            # Spec doesn't define a 404 for delete; idempotent — report
            # no_change without a hash.
            return {
                "status": 200,
                "result": {
                    "type": "system/revision/merge-config-result",
                    "data": {
                        "path": write_path,
                        "status": "no_change",
                    },
                },
            }
        pathway.delete(write_path, emit_ctx)
        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-config-result",
                "data": {
                    "path": write_path,
                    "status": "deleted",
                },
            },
        }

    # Step 4b: set action — validate the config entity.
    config_arg = params.get("config")
    if config_arg is None:
        return _error_response(400, "missing_config", "config is required for action=set")

    # Accept either entity-shape `{type, data}` or bare data dict.
    if (
        isinstance(config_arg, dict)
        and config_arg.get("type") == "system/revision/merge-config"
        and isinstance(config_arg.get("data"), dict)
    ):
        cfg = config_arg["data"]
    elif isinstance(config_arg, dict):
        cfg = config_arg
    else:
        return _error_response(
            400, "invalid_params",
            "config must be a system/revision/merge-config entity or its data",
        )

    # Strategy-rejection contract (§2.3 / Amendment 4): lww/keep-both
    # rejected at config-write time with 400 invalid_strategy. Other
    # field-shape errors (unknown deletion_resolution, wrong types) also
    # surface here.
    errors = validate_merge_config(cfg)
    if errors:
        return _error_response(400, "invalid_strategy", "; ".join(errors))

    # Per-path configs require a `pattern` field.
    if scope == "path" and not cfg.get("pattern"):
        return _error_response(
            400, "invalid_params",
            "per-path merge-config requires a `pattern` field",
        )

    # Step 5: idempotent write — re-issuing the same content_hash is a no_change.
    merge_entity = Entity(type="system/revision/merge-config", data=cfg)
    candidate_hash = merge_entity.compute_hash()
    current_hash = pathway.entity_tree.get(full_uri)
    if current_hash == candidate_hash:
        return {
            "status": 200,
            "result": {
                "type": "system/revision/merge-config-result",
                "data": {
                    "path": write_path,
                    "hash": candidate_hash,
                    "status": "no_change",
                },
            },
        }

    write_result = pathway.emit(write_path, merge_entity, emit_ctx)
    if write_result.status not in (200, 207):
        return _error_response(
            500, "config_write_failed",
            f"merge-config write refused (status {write_result.status})",
        )

    return {
        "status": 200,
        "result": {
            "type": "system/revision/merge-config-result",
            "data": {
                "path": write_path,
                "hash": write_result.hash,
                "status": "set",
            },
        },
    }


async def _handle_config_delete(
    name: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Handle prefix-config delete action (§4.4.17). Merge-config delete
    goes through the separate `merge-config` operation (§4.4.18)."""
    del_prefix = params.get("prefix", name)
    if not del_prefix:
        return _error_response(400, "config/missing-prefix", "prefix required for delete")
    del_ph = _compute_prefix_hash(ctx, del_prefix)
    config_path = _config_path_for_prefix(del_ph)

    # CAS guard
    expected_hash = params.get("expected_hash")
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(config_path)
    if expected_hash is not None:
        current_hash = ctx.emit_pathway.entity_tree.get(full_uri)
        if current_hash != expected_hash:
            return _error_response(409, "config/concurrent-modification", "expected_hash does not match current binding")

    previous_hash = ctx.emit_pathway.entity_tree.get(full_uri)
    if previous_hash is None:
        return _error_response(404, "config/not-found", f"no config at prefix {del_prefix!r}")

    prev_entity = ctx.emit_pathway.content_store.get(previous_hash)
    was_auto_version = False
    prev_prefix = ""
    if prev_entity and prev_entity.type == "system/revision/config":
        was_auto_version = bool(prev_entity.data.get("auto_version"))
        prev_prefix = prev_entity.data.get("prefix", "")

    emit_ctx = EmitContext.from_handler_grant(ctx, "config")
    tracking_action: str | None = None
    tracking_path: str | None = None

    # Delete config binding first
    ctx.emit_pathway.delete(config_path, emit_ctx)

    # Remove tracking-config if was auto_version
    if was_auto_version and prev_prefix:
        tracking_path = _tracking_config_path(prev_prefix)
        ctx.emit_pathway.delete(tracking_path, emit_ctx)
        tracking_action = "deleted"

    # F-CIMP-1 — same omitzero bug as `_handle_config_set`:
    # `config_hash` is absent on delete (there's no new entity), so omit it
    # rather than emit `None`. `previous_hash` is always present here (the
    # 404 short-circuit above guarantees not-None).
    result_data: dict[str, Any] = {
        "config_path": config_path,
        "previous_hash": previous_hash,
    }
    if tracking_action is not None:
        result_data["tracking_config_path"] = tracking_path
        result_data["tracking_config_action"] = tracking_action

    return {
        "status": 200,
        "result": {
            "type": "system/revision/config-result",
            "data": result_data,
        },
    }
