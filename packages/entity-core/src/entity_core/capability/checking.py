"""Capability verification and pattern matching.

V4 Two-Level Capability Model:
1. Handler scope - capability grants operation on handler via `handlers` field
2. Path scope - capability grants operation on path via `resources` field

Pattern syntax per spec v7.18 §5.4:
- "*" matches everything (recursive base case; bare * canonicalizes to /{local}/*)
- "pattern/*" subtree match (prefix)
- "/*/pattern/*" peer wildcard + subtree match
- "pattern" entity path (exact match)

All paths are absolute after canonicalization (start with /).
Peer-relative paths (no leading /) are resolved to /{local_peer_id}/path.

Handler matching:
- Grants have explicit `handlers` field for handler authorization
- No trailing slash convention - handlers field contains handler patterns directly

V6.0 Changes:
- handlers, resources, operations are now CapabilityScope objects
- Each scope has include/exclude arrays
- Added peers field for peer scope

v7.18 Changes:
- Absolute paths start with / (leading slash convention)
- normalize() produces /peer_id/path from entity://peer_id/path
- canonicalize() uses starts_with("/") instead of is_peer_id heuristic
- matches_pattern() uses /*/ for peer wildcard instead of */
- "self" token removed
"""

from __future__ import annotations

import time
from typing import Any, Callable

from entity_core.capability.temporal import temporal_validity
from entity_core.capability.token import CapabilityScope, get_scope
from entity_core.utils.identity import is_peer_id

# Re-export for backward compatibility (some code may import from here)
__all__ = [
    "is_peer_id",
    "normalize",
    "canonicalize",
    "matches_pattern",
    "matches_scope",
    "matches_id_scope",
    "id_scope_pattern_matches",
    "scope_type_for_dimension",
    "ID_SCOPE",
    "PATH_SCOPE",
    "granter_frame_peer_id",
]

# §3.6's two scope types. A grant dimension's type is fixed by the dimension,
# not carried per value: the spec's pseudocode reads `scope.type` because its
# scope entity is typed by the `type_ref` in the §3.6 field spec, and the field
# spec is what pins `handlers`/`resources` to path-scope and `operations`/
# `peers` to id-scope. Deriving it from the dimension name is the same fact
# read from the same place; nothing on the wire changes.
PATH_SCOPE = "system/capability/path-scope"
ID_SCOPE = "system/capability/id-scope"

_SCOPE_TYPE_BY_DIMENSION = {
    "handlers": PATH_SCOPE,
    "resources": PATH_SCOPE,
    "operations": ID_SCOPE,
    "peers": ID_SCOPE,
}


def scope_type_for_dimension(dimension: str) -> str:
    """The §3.6 scope type of a grant dimension.

    Raises for an unknown dimension rather than defaulting: a new dimension
    silently inheriting one of the two matchers is the F40 defect arriving
    from the other direction, and there is no correct default (a path
    dimension matched literally over-refuses; an id dimension canonicalized
    over-grants — the A-SQL-008 ALLOW-bug class §5.2 names).
    """
    try:
        return _SCOPE_TYPE_BY_DIMENSION[dimension]
    except KeyError:
        raise ValueError(
            f"no scope type declared for grant dimension {dimension!r} — "
            "§3.6 fixes the type per dimension; add it there rather than "
            "picking a matcher at the call site"
        ) from None


def granter_frame_peer_id(
    capability_data: dict[str, Any],
    local_peer_id: str,
    resolve_identity: Callable[[bytes], dict[str, Any] | None],
) -> str:
    """V7 §PR-8: the canonicalization frame for a capability's *own* RESOURCE
    patterns is the **granter's** peer_id, not the verifier's local peer_id.

    A peer-relative grant pattern (bare ``*`` or ``foo/bar``) names the
    granter's namespace. For self-issued caps (granter == local verifier) the
    granter frame is byte-identical to ``local_peer_id``, so the distinction is
    latent — which is why every impl shipped using ``local_peer_id`` throughout
    and passed the same-peer-dominant test path. For a foreign-granter cap
    presented cross-peer (granter A's bare ``*`` evaluated at verifier B) the
    frame is load-bearing: ``*`` MUST resolve to ``/A/*`` (peer-local to the
    granter), never ``/B/*``. Using the verifier's frame admits a peer-local
    cap over a cross-peer surface — an authz under-enforcement (V2(a)).

    Resolves the granter identity via ``resolve_identity(granter_hash)`` and
    derives its wire peer_id. Falls back to ``local_peer_id`` when the granter
    is absent, multi-valued (multi-sig caps are root-only and root MUST be the
    local peer, so the frame is local by construction), or unresolvable — each
    of which collapses to the correct self-issued frame.

    Args:
        capability_data: The ``data`` field of the capability whose grant
            resource patterns are being matched.
        local_peer_id: The verifier's local peer ID (the fallback frame).
        resolve_identity: Callable mapping a granter identity hash to that
            identity entity (a dict carrying ``data.public_key``), or None.

    Returns:
        The granter's peer_id, or ``local_peer_id`` when unresolvable.
    """
    granter = capability_data.get("granter")
    if not isinstance(granter, (bytes, bytearray)):
        return local_peer_id
    id_ent = resolve_identity(bytes(granter))
    if not id_ent:
        return local_peer_id
    from entity_core.crypto.identity import peer_id_from_identity_entity

    return peer_id_from_identity_entity(id_ent) or local_peer_id


def normalize(uri: str) -> str:
    """Normalize URI to absolute path by stripping entity:// scheme.

    Per spec v7.18 R3: entity://peer_id/path -> /peer_id/path.

    Args:
        uri: URI possibly with entity:// prefix.

    Returns:
        Absolute path (/peer_id/path) or unchanged input if no scheme.
    """
    if uri.startswith("entity://"):
        return "/" + uri[len("entity://"):]
    return uri


def canonicalize(path: str, local_peer_id: str) -> str:
    """Resolve path to absolute form per V7 §5.4 (R2).

    This is a **pure transform**, never a rejection point — it matches the
    spec pseudocode (`matches_scope`/`check_permission` call canonicalize then
    `matches_pattern` with no exception handling) and the §5.4 dispatch chain
    (line 290-291: canonicalize *then* `validate_absolute_path`). Rejection of
    a malformed *request* path is the job of `validate_absolute_path` at the
    dispatch boundary, not of canonicalize.

    - Strips entity:// scheme first (via normalize)
    - Reserved ./ and ../ prefixes and the ambiguous bare */ prefix
      **pass through unchanged** (they are not absolute, so they match no
      canonical `/{peer_id}/...` target — a malformed *grant* pattern is thus
      fail-closed by construction per §1.11, not a crash; a malformed *request*
      target is rejected downstream by validate_absolute_path)
    - Already absolute (starts with /) -> pass through
    - Bare "*" -> /{local_peer_id}/* (peer-relative wildcard)
    - Peer-relative path -> /{local_peer_id}/{path}

    Args:
        path: Path or pattern to canonicalize.
        local_peer_id: The local peer's ID for expansion.

    Returns:
        Absolute path starting with /, or the reserved/ambiguous input
        unchanged (which validate_absolute_path will reject for request paths,
        and which fails to match for grant patterns).
    """
    # First normalize (strip entity:// if present)
    path = normalize(path)

    # Reserved directory-relative and ambiguous bare-peer-wildcard prefixes
    # pass through unchanged. They are non-absolute, so they match no canonical
    # target (grant patterns fail closed) and validate_absolute_path rejects
    # them for request paths. Folding rejection in here instead made a malformed
    # *grant* pattern raise mid-capability-check and drop the connection
    # (V7 §1.11 fail-closed / F5 — the malformed-resource-pattern probe).
    if path.startswith("./") or path.startswith("../") or path.startswith("*/"):
        return path

    # Already absolute
    if path.startswith("/"):
        return path

    # Bare wildcard -> local peer, all paths
    if path == "*":
        return f"/{local_peer_id}/*"

    # Peer-relative -> prepend /{local_peer_id}/
    return f"/{local_peer_id}/{path}"


def matches_pattern(pattern: str, uri: str) -> bool:
    """Check if URI matches capability pattern per v7.18 R6.

    Both arguments MUST be canonicalized (absolute) before calling.
    The "*" check handles the recursive base case from peer wildcard stripping.

    Args:
        pattern: The canonicalized pattern (may contain wildcards).
        uri: The canonicalized URI to check.

    Returns:
        True if the URI matches the pattern.
    """
    # Universal match (also base case for /*/* recursion)
    if pattern == "*":
        return True

    # Peer wildcard: /*/rest — match any peer's subtree
    if pattern.startswith("/*/"):
        remainder = pattern[3:]  # Strip "/*/"
        # URI is /{peer_id}/rest — find the second /
        if not uri.startswith("/"):
            return False
        slash = uri.find("/", 1)
        if slash < 0:
            return False
        uri_after_peer = uri[slash + 1:]
        return matches_pattern(remainder, uri_after_peer)

    # Subtree match: pattern/*
    if pattern.endswith("/*"):
        prefix = pattern[:-1]  # Remove trailing *
        return uri.startswith(prefix)

    # Exact match
    return uri == pattern


def matches_scope(scope: CapabilityScope | dict[str, Any], value: str) -> bool:
    """Check if a value matches a capability scope.

    Per spec §5.2 matches_scope. A value matches if:
    1. At least one include pattern matches the value
    2. No exclude pattern matches the value

    Args:
        scope: The CapabilityScope or dict with include/exclude.
        value: The value to check.

    Returns:
        True if the value matches the scope.
    """
    if isinstance(scope, dict):
        scope = CapabilityScope.from_dict(scope)

    # Check if any include pattern matches
    matched = False
    for pattern in scope.include:
        if matches_pattern(pattern, value):
            matched = True
            break

    if not matched:
        return False

    # Check if any exclude pattern matches
    if scope.exclude:
        for pattern in scope.exclude:
            if matches_pattern(pattern, value):
                return False

    return True


def id_scope_pattern_matches(pattern: str, value: str) -> bool:
    """One id-scope pattern against one raw value — §5.2 `scope_value_matches`,
    the ``system/capability/id-scope`` arm.

    Exactly two wildcard forms and no path transforms: bare ``*`` matches any
    value, a trailing ``/*`` matches by **literal** segment-prefix, everything
    else is string equality. The §5.4 transforms are the thing this arm exists
    to refuse — no leading-``/`` universal-scope reading, no ``/*/`` interior
    peer-wildcard, no peer-relative qualification. So ``/*/*`` is a literal
    that matches nothing, not a universal wildcard, and ``entity://…`` is a
    string, not an address.
    """
    if pattern == "*":
        return True
    if pattern.endswith("/*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def matches_id_scope(
    scope: CapabilityScope | dict[str, Any], value: str,
) -> bool:
    """`matches_scope` for a ``system/capability/id-scope`` dimension
    (``operations``, ``peers``) — §5.2, pseudocode corrected at 0.8.2.16.

    Split out from :func:`matches_scope` rather than selected by a parameter
    so that **which matcher a dimension uses is visible at the call site**.
    §5.2 states the split as normative and says an id dimension canonicalized
    is a conformance defect; a defect that consists of reaching for the wrong
    helper is one a reader has to be able to see.

    Note for anyone measuring this: on the values these two dimensions can
    carry, this function and :func:`matches_scope` **agree** — the §5.4
    transforms all require a leading ``/`` on the *value*, and an operation
    name or a peer id never has one. The divergence this split forecloses is
    a future call site that canonicalizes the value before matching, which is
    exactly how the delegation path (:mod:`entity_core.capability.delegation`)
    came to canonicalize operation excludes.
    """
    if isinstance(scope, dict):
        scope = CapabilityScope.from_dict(scope)

    if not any(id_scope_pattern_matches(p, value) for p in scope.include):
        return False
    if scope.exclude:
        for pattern in scope.exclude:
            if id_scope_pattern_matches(pattern, value):
                return False
    return True


def extract_peer(uri_or_path: str, local_peer_id: str) -> str:
    """The peer a dispatch targets — V7 §5.2 ``extract_peer``.

    ``entity://{R}/system/tree`` and ``/{R}/system/tree`` both target R;
    a peer-relative path targets the local peer, because that is what
    :func:`canonicalize` resolves it to.
    """
    canonical = canonicalize(uri_or_path, local_peer_id)
    if not canonical.startswith("/"):
        # Reserved / ambiguous prefixes pass through canonicalize unchanged
        # (see its docstring). They name no peer; treat them as local so the
        # peers dimension neither grants nor invents authority here — the
        # path itself is rejected downstream by validate_absolute_path.
        return local_peer_id
    segment = canonical[1:].split("/", 1)[0]
    return segment or local_peer_id


def grant_allows_peer(
    grant: dict[str, Any],
    target_peer: str,
    local_peer_id: str,
) -> bool:
    """The §5.2 **peers** dimension for one grant.

    ``peers_scope = grant.peers or {include: [local_peer_id]}`` — an absent
    field defaults to the local peer **and is still checked**. Skipping the
    check on absence is the foreign-namespace privilege escalation: every
    ordinary grant, none of which name `peers`, would authorize a dispatch
    into any peer's namespace.

    `peers` is an ``id-scope`` (§5.2 F40, 0.8.1): values are compared as
    literal identifiers, never canonicalized as paths. Canonicalizing a peer
    id would turn it into ``/{local}/{id}`` and match nothing.
    """
    peers_scope = grant.get("peers")
    if peers_scope is None:
        peers_scope = {"include": [local_peer_id]}
    return matches_id_scope(peers_scope, target_peer)


def check_handler_scope(
    capability_data: dict[str, Any],
    handler_pattern: str,
    operation: str,
    local_peer_id: str,
    now: int | None = None,
    target_peer: str | None = None,
    relax_peers: bool = False,
) -> bool:
    """Check if capability grants operation on handler scope.

    Per spec §5.2 check_permission. Called after handler resolution
    in the dispatch chain. Uses the `handlers` field to match against
    the resolved handler pattern.

    V6.0: handlers, resources, operations are now CapabilityScope objects.

    Args:
        capability_data: The "data" field of a capability token entity.
        handler_pattern: The resolved handler's pattern (e.g., "system/tree").
        operation: The operation to check.
        local_peer_id: The local peer's ID.
        now: Current timestamp in milliseconds.
        relax_peers: §1.4 PD-2 (0.8.2.19) — **Dimension 4 only**. When a
            credential minted by the target peer has been verified at the
            outbound gate, it relaxes this grant's `peers` dimension to the
            peers that credential covers, *and nothing else*. Set by
            ``Peer._authorize_outbound_sub_dispatch`` and by no other caller.

            **This skips one dimension of the per-grant-entry test, never the
            entry itself.** §5.2 requires all four dimensions to match from a
            *single* grant entry, so the relaxation is applied inside the loop
            rather than by widening the search — a grant entry covering the
            handler and a *different* entry covering the operation still does
            not authorize. Mixing dimensions across entries is the escalation
            §5.2's single-entry rule exists to close, and it is one `or` away
            from here.

    Returns:
        True if the capability grants handler scope access.
    """
    if now is None:
        now = int(time.time() * 1000)

    # Temporal validity: representability, then bounds. §6.2 CAP-6a makes an
    # unrepresentable expires_at / not_before / created_at *malformed*, and a
    # malformed token grants nothing — fail closed here, and refuse with the
    # §5.2 disposition at the chain walk, which is the site that has one.
    if not temporal_validity(capability_data, now)[0]:
        return False

    # §5.2: `target_peer = extract_peer(execute.uri, local)`. A caller that
    # does not supply it is dispatching locally — passing local_peer_id there
    # is the same value extract_peer would return for a peer-relative URI, not
    # a bypass.
    peer = target_peer if target_peer is not None else local_peer_id

    for grant in capability_data.get("grants", []):
        # V6.0: operations is now a CapabilityScope
        operations_scope = get_scope(grant, "operations")
        if not matches_id_scope(operations_scope, operation):
            continue

        # §5.2 peers dimension — the same grant must cover the target peer,
        # unless a verified target-minted credential has relaxed exactly this
        # dimension (§1.4 PD-2, 0.8.2.19).
        if not relax_peers and not grant_allows_peer(grant, peer, local_peer_id):
            continue

        # V6.0: handlers is now a CapabilityScope
        handlers_scope = get_scope(grant, "handlers")
        if matches_scope(handlers_scope, handler_pattern):
            return True

    return False


def check_resource_scope(
    capability_data: dict[str, Any],
    handler_pattern: str,
    operation: str,
    resource_targets: list[str],
    resource_exclude: list[str] | None,
    local_peer_id: str,
    now: int | None = None,
    granter_peer_id: str | None = None,
    target_peer: str | None = None,
    relax_peers: bool = False,
) -> bool:
    """Check if capability grants operation on resource scope at dispatch level.

    Per V7 spec §5.2. When execute.resource is present, the dispatcher checks
    that the same grant matches handler, operation, AND all resource targets.

    Args:
        capability_data: The "data" field of a capability token entity.
        handler_pattern: The resolved handler's pattern (e.g., "system/tree").
        operation: The operation to check.
        resource_targets: List of resource paths from execute.resource.targets.
        resource_exclude: Optional exclusions from execute.resource.exclude.
        local_peer_id: The local peer's ID (frame for the *request* targets).
        now: Current timestamp in milliseconds.
        granter_peer_id: V7 §PR-8 — the frame for the *grant's own* resource
            patterns (the granter's peer_id). Defaults to local_peer_id (the
            self-issued case, where granter == verifier). See
            granter_frame_peer_id.
        relax_peers: §1.4 PD-2 (0.8.2.19) — Dimension 4 only, on the same
            terms as :func:`check_handler_scope`. It is threaded here as well
            as there because both checks run the per-grant-entry peers test,
            and relaxing it in one while the other still refuses would leave
            the resource dimension silently carrying the network bound.

    Returns:
        True if the capability grants access to all resource targets.
    """
    if now is None:
        now = int(time.time() * 1000)

    # V7 §PR-8: grant resource patterns canonicalize against the granter's
    # namespace; request targets against the verifier's. Self-issued caps make
    # the two identical (latent), foreign-granter caps make them differ.
    grant_frame = granter_peer_id if granter_peer_id is not None else local_peer_id

    # Temporal validity: representability, then bounds. §6.2 CAP-6a makes an
    # unrepresentable expires_at / not_before / created_at *malformed*, and a
    # malformed token grants nothing — fail closed here, and refuse with the
    # §5.2 disposition at the chain walk, which is the site that has one.
    if not temporal_validity(capability_data, now)[0]:
        return False

    # Each resource target must be covered by some grant that also matches handler and operation
    for target in resource_targets:
        # Skip targets that are in caller's exclude list
        if resource_exclude:
            excluded = False
            for excl in resource_exclude:
                canonical_excl = canonicalize(excl, local_peer_id)
                canonical_target = canonicalize(target, local_peer_id)
                if matches_pattern(canonical_excl, canonical_target):
                    excluded = True
                    break
            if excluded:
                continue

        # Find a grant that covers this target AND matches handler/operation
        target_covered = False
        canonical_target = canonicalize(target, local_peer_id)

        for grant in capability_data.get("grants", []):
            # Check handler scope
            handlers_scope = get_scope(grant, "handlers")
            if not matches_scope(handlers_scope, handler_pattern):
                continue

            # Check operation scope
            operations_scope = get_scope(grant, "operations")
            if not matches_id_scope(operations_scope, operation):
                continue

            # §5.2 peers dimension — one grant must cover all four axes,
            # unless a verified target-minted credential has relaxed exactly
            # this dimension (§1.4 PD-2, 0.8.2.19).
            if not relax_peers and not grant_allows_peer(
                grant,
                target_peer if target_peer is not None else local_peer_id,
                local_peer_id,
            ):
                continue

            # Check resource scope
            resources_scope = get_scope(grant, "resources")

            # Check if target matches any include pattern (grant-owned ->
            # granter frame per §PR-8)
            matched = False
            for resource in resources_scope.include:
                canonical_resource = canonicalize(resource, grant_frame)
                if matches_pattern(canonical_resource, canonical_target):
                    matched = True
                    break

            if not matched:
                continue

            # Check if target is excluded by grant's exclude (grant-owned ->
            # granter frame per §PR-8)
            grant_excluded = False
            if resources_scope.exclude:
                for excl in resources_scope.exclude:
                    canonical_excl = canonicalize(excl, grant_frame)
                    if matches_pattern(canonical_excl, canonical_target):
                        grant_excluded = True
                        break

            if grant_excluded:
                continue

            # This grant covers the target
            target_covered = True
            break

        if not target_covered:
            return False

    return True


def check_path_permission(
    capability_data: dict[str, Any],
    operation: str,
    path: str,
    local_peer_id: str,
    handler_pattern: str | None = None,
    now: int | None = None,
    granter_peer_id: str | None = None,
) -> bool:
    """Check if capability grants operation on specific path.

    Per spec §6.3 check_path_permission. Called by handlers to verify
    path-level access (the second level of the two-level model).

    If handler_pattern is provided, filters grants by those that match
    the handler first (ensuring consistent two-level checks).

    V6.0: handlers, resources, operations are now CapabilityScope objects.

    Args:
        capability_data: The "data" field of a capability token entity.
        operation: The operation to check (get, put, etc.).
        path: The data path being accessed (frame: local_peer_id).
        local_peer_id: The local peer's ID (frame for the *request* path).
        handler_pattern: Optional handler pattern to filter grants by.
        now: Current timestamp in milliseconds.
        granter_peer_id: V7 §PR-8 — the frame for the *grant's own* resource
            patterns (the granter's peer_id). Defaults to local_peer_id (the
            self-issued case). See granter_frame_peer_id.

    Returns:
        True if the capability grants path-level access.
    """
    if now is None:
        now = int(time.time() * 1000)

    # V7 §PR-8: grant resource patterns canonicalize against the granter's
    # namespace; the request path against the verifier's.
    grant_frame = granter_peer_id if granter_peer_id is not None else local_peer_id

    # Temporal validity: representability, then bounds. §6.2 CAP-6a makes an
    # unrepresentable expires_at / not_before / created_at *malformed*, and a
    # malformed token grants nothing — fail closed here, and refuse with the
    # §5.2 disposition at the chain walk, which is the site that has one.
    if not temporal_validity(capability_data, now)[0]:
        return False

    canonical_path = canonicalize(path, local_peer_id)

    for grant in capability_data.get("grants", []):
        # V6.0: operations is now a CapabilityScope
        operations_scope = get_scope(grant, "operations")
        if not matches_id_scope(operations_scope, operation):
            continue

        # If handler_pattern provided, filter by handlers scope first
        if handler_pattern is not None:
            handlers_scope = get_scope(grant, "handlers")
            if not matches_scope(handlers_scope, handler_pattern):
                continue

        # V6.0: resources is now a CapabilityScope with include/exclude
        resources_scope = get_scope(grant, "resources")

        # Check if path matches resources scope (include check; grant-owned ->
        # granter frame per §PR-8)
        matched = False
        for resource in resources_scope.include:
            canonical_resource = canonicalize(resource, grant_frame)
            if matches_pattern(canonical_resource, canonical_path):
                matched = True
                break

        if not matched:
            continue

        # Check excludes from resources scope (grant-owned -> granter frame)
        excluded = False
        if resources_scope.exclude:
            for excl in resources_scope.exclude:
                canonical_exclude = canonicalize(excl, grant_frame)
                if matches_pattern(canonical_exclude, canonical_path):
                    excluded = True
                    break

        if not excluded:
            return True

    return False


def find_matching_grant(
    capability_data: dict[str, Any],
    operation: str,
    handler_pattern: str,
    local_peer_id: str,
    now: int | None = None,
) -> dict[str, Any] | None:
    """Find the grant entry that authorizes an operation on a handler.

    Like check_path_permission but returns the matching grant dict instead
    of a boolean. Used by handlers that need to read grant constraints
    (e.g., the query handler reads type_scope and max_results from
    system/query/constraints).

    Args:
        capability_data: The "data" field of a capability token entity.
        operation: The operation to check (find, count, etc.).
        handler_pattern: The handler pattern to match grants against.
        local_peer_id: The local peer's ID.
        now: Current timestamp in milliseconds.

    Returns:
        The matching grant dict, or None if no grant matches.
    """
    if now is None:
        now = int(time.time() * 1000)

    # Temporal validity: representability, then bounds (§6.2 CAP-6a — see the
    # note at the first call site above).
    if not temporal_validity(capability_data, now)[0]:
        return None

    for grant in capability_data.get("grants", []):
        operations_scope = get_scope(grant, "operations")
        if not matches_id_scope(operations_scope, operation):
            continue

        handlers_scope = get_scope(grant, "handlers")
        if not matches_scope(handlers_scope, handler_pattern):
            continue

        return grant

    return None


def check_capability_refs(
    capability_entity: dict[str, Any],
    author_identity_hash: str,
) -> bool:
    """Check that capability grantee matches the request author.

    Args:
        capability_entity: The full capability token entity.
        author_identity_hash: Hash of the request author's identity entity.

    Returns:
        True if the grantee matches the author.
    """
    # Use data.grantee - this is authoritative (included in content_hash)
    data = capability_entity.get("data", {})
    grantee = data.get("grantee", "")
    return grantee == author_identity_hash


