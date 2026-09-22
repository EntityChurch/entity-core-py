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
from entity_core.utils.path import validate_absolute_path

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


# ---------------------------------------------------------------------------
# WITHDRAWN 0.8.2.24 (N1): there is NO matcher-side refusal of a contradicting
# `scope.type`, and re-adding one is a conformance defect, not hardening.
#
# 0.8.2.22's §5.2 had TWO clauses: (1) MUST NOT take the dispatch type from a
# received entity's `scope.type`, and (2) a `scope` whose declared `type`
# contradicts its dimension is a malformed token and MUST be refused
# `403 capability_denied`. This peer satisfied (1) structurally — the type
# comes from `scope_type_for_dimension`, keyed on the dimension name — and
# built (2) at four sites (SA-PY-60), on the argument that *dropping is not
# refusing*.
#
# **0.8.2.24 WITHDRAWS clause 2.** Three parties reached that independently
# (keystone's 45-peer wire census: `403` on zero; go's three-way source read;
# arch's own line-reads). The clause was unsatisfiable for the implementation
# clause 1 prescribes: a peer that does not read `scope.type` cannot observe a
# contradiction in it, so the refusal obliged re-introducing the exact field
# whose absence IS the safety property — plus a MUST-ignore exception — to
# reject a shape no conformant peer produces. Arch's §0: *"when a finding says
# nobody validates X, the fix is a rule about who SUPPLIES X; the refusal is
# what puts the mechanism back."*
#
# The replacement is a **MAY at admission** (`put`, §6.3), where a caller still
# exists to answer and the field has not yet been dropped. Deliberately NOT
# built here: it is a MAY, its cohort cost is zero, and a refusal go and rust
# do not make is a divergence this seat would be manufacturing out of an
# optional clause.
#
# Recorded rather than deleted silently, because a withdrawn rule leaves no
# failing test behind — the comment is the only thing that stops it coming
# back (the 0.8.2.13 `system/*` reservation, same shape, same file family).
# ---------------------------------------------------------------------------


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


NEVER_MATCH = "/never-match"
"""The unmatchable value — §5.4 (0.8.2.20).

A single-segment absolute path whose first segment **cannot** be a peer_id
(``is_peer_id`` requires >= 46 Base58 characters and ``-`` is outside the
Base58 alphabet), so it is unreachable as a canonical path *by construction
rather than by prohibition*. Star-free, plain ASCII, greppable.

Three consumers are ruled, and all three are in this tree:

==================================  ==========================================
consumer                            rule
==================================  ==========================================
:func:`matches_pattern`             MUST return False for **either** operand
``validate_absolute_path``          MUST error — it does, by construction, and
                                    this is the designed destination for the
                                    diagnostic :func:`canonicalize` no longer
                                    raises
storage / tree access               MUST NOT store, key, or resolve it
==================================  ==========================================
"""


def is_pattern(path: str) -> bool:
    """§5.2's ``is_pattern`` — does this path carry a wildcard?

    Named rather than inlined because three rules now key on it: §5.2's
    concrete-target validation (a pattern goes through matching, not tree
    access), §3.3's ``malformed_resource`` arm (a resource-**requiring**
    operation takes a concrete path), and §5.2's pattern-target grant-exclude
    walk.
    """
    return "*" in path


def canonicalize(path: str, local_peer_id: str) -> str:
    """Resolve path to absolute form per V7 §5.4 (R2). **Total** (0.8.2.20).

    .. rubric:: The return domain is *a canonical path OR* :data:`NEVER_MATCH`

    0.8.2.20 (R11) makes this function total: malformed input yields the
    sentinel rather than an error return or a pass-through, *"because every
    normative call site of this function is a matcher with no error channel to
    consume one."* The diagnostic belongs at admission (§6.5), which has a
    caller to answer — here that is `validate_absolute_path` at the dispatch
    boundary, which :data:`NEVER_MATCH` fails by construction.

    **What changed and what did not.** Reserved (``./``, ``../``) and
    ambiguous bare-peer-wildcard (``*/``) input used to pass through
    unchanged, on the argument that a non-absolute string matches no canonical
    ``/{peer_id}/...`` target and is therefore fail-closed anyway. That
    argument is *true of every input we could name* and is exactly the shape
    0.8.2.20 refuses to rest on: §5.4 says safety **MUST NOT** rest on a value
    merely *looking* unmatchable, because :func:`matches_pattern` returns True
    for a bare ``"*"`` operand and one recursion step can produce one. The
    sentinel moves the property from *nothing happens to match it* to *the
    matcher refuses it by name*.

    - Strips entity:// scheme first (via normalize)
    - Reserved ``./`` / ``../`` and bare ``*/`` -> :data:`NEVER_MATCH`
    - Already absolute (starts with /) -> pass through
    - Bare "*" -> /{local_peer_id}/* (peer-relative wildcard)
    - Peer-relative path -> /{local_peer_id}/{path}

    Args:
        path: Path or pattern to canonicalize.
        local_peer_id: The local peer's ID for expansion.

    Returns:
        An absolute path starting with ``/``, or :data:`NEVER_MATCH`.
    """
    # First normalize (strip entity:// if present)
    path = normalize(path)

    # Reserved directory-relative and ambiguous bare-peer-wildcard prefixes
    # are UNREPRESENTABLE, not merely unmatched (§5.4, 0.8.2.20). Returning the
    # sentinel rather than raising is what keeps a malformed *grant* pattern
    # from raising mid-capability-check and dropping the connection (§1.11
    # fail-closed / F5 — the malformed-resource-pattern probe), while making
    # the refusal a matcher rule instead of an accident of string shape.
    if path.startswith("./") or path.startswith("../") or path.startswith("*/"):
        return NEVER_MATCH

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
    # NEVER_MATCH never matches, in EITHER operand (§5.4, 0.8.2.20). This arm
    # is FIRST and is a matcher rule, not a property of the string: the arm
    # directly below returns True for a bare "*" operand, so safety MUST NOT
    # rest on a value merely looking unmatchable.
    if pattern == NEVER_MATCH or uri == NEVER_MATCH:
        return False

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


def strip_wildcard(pattern: str) -> str:
    """§5.2's ``strip_wildcard`` — the prefix a pattern constrains.

    A concrete path is returned unchanged, which is what makes
    :func:`patterns_overlap` correct for the mixed concrete/pattern case.
    """
    if pattern.endswith("/*"):
        return pattern[:-2]
    if pattern == "*":
        return ""
    return pattern


def patterns_overlap(a: str, b: str) -> bool:
    """§5.2's ``patterns_overlap`` — could any concrete path match both?"""
    prefix_a = strip_wildcard(a)
    prefix_b = strip_wildcard(b)
    return prefix_a.startswith(prefix_b) or prefix_b.startswith(prefix_a)


def is_covered_by(
    path_or_pattern: str, pattern_set: list[str], local_peer_id: str,
) -> bool:
    """§5.2's ``is_covered_by`` — does some pattern in the set cover the input?

    Note the argument order against :func:`matches_pattern`. The spec writes
    ``matches_pattern(path, pattern)`` and this module writes
    ``matches_pattern(pattern, uri)`` — the two are **reversed**, consistently,
    at every call site in this file. Stated here because this function is the
    one place both orders appear in one expression.
    """
    return any(
        matches_pattern(canonicalize(p, local_peer_id), path_or_pattern)
        for p in pattern_set
    )


#: The frame used when asking whether a pattern is unmatchable. The verdict is
#: **frame-independent** — :func:`canonicalize` decides ``NEVER_MATCH`` on the
#: ``./`` / ``../`` / ``*/`` prefix alone and never consults the peer id — so
#: any frame gives the same answer and passing a real one would imply a
#: dependence that does not exist. Pinned by
#: ``test_the_unmatchable_verdict_is_frame_independent``.
_ANY_FRAME = "1" * 46


def is_unmatchable_pattern(pattern: str) -> bool:
    """True iff *pattern* canonicalizes to :data:`NEVER_MATCH` (§5.4).

    .. rubric:: Why a predicate rather than an inline comparison

    The sentinel's safety is **directional** (§5.4, 0.8.2.21). *Matches
    nothing* is fail-**closed** in an ``include`` — covers nothing, so the
    grant grants nothing — and fail-**OPEN** in an ``exclude``: it carves out
    nothing, so **the grant is silently wider than its author wrote**, with no
    error anywhere, because the sentinel is designed not to raise.

    ``matches_pattern`` therefore stays **uniform over its operands** — it
    cannot know which side it is on, and a matcher that guessed would be
    untranscribable. The position-dependent reading belongs where the position
    is known, which is every ``exclude`` loop in this module.
    """
    return canonicalize(pattern, _ANY_FRAME) == NEVER_MATCH


#: The **path-scope** grant dimensions (§5.2). Only these are canonicalized, so
#: only these can yield the sentinel. ``operations`` and ``peers`` are
#: *id-scope* — compared as literal identifiers, and §5.2 says in terms that
#: *"an id dimension canonicalized is a conformance defect"* — so
#: ``canonicalize`` is never applied to them and 0.8.2.21's MUST, which is
#: written as ``canonicalize(pattern) == NEVER_MATCH``, cannot bind them.
#:
#: **An id-scope exclude can nonetheless match nothing** (``*/foo`` is a
#: literal no operation name can equal), which is the same fail-open shape one
#: dimension over and is NOT ruled. Deliberately not invented here — refusing
#: it would refuse capabilities `entity-core-go` and `entity-core-rust` mint.
#: Routed as SA-PY-53.
_PATH_SCOPE_DIMENSIONS = ("handlers", "resources")


def unmatchable_scope_pattern(grants: Any) -> tuple[str, str, str] | None:
    """The first ``(dimension, side, pattern)`` that is unmatchable, or None.

    §5.4 (0.8.2.21): *"a capability any of whose scope patterns canonicalizes
    to ``NEVER_MATCH`` MUST be refused"* — at mint, at delegation, and at chain
    verification.

    **Both sides, not just ``exclude``.** The security argument is about the
    exclude side, but the MUST is written over *any* scope pattern, and an
    unmatchable ``include`` is a grant that grants nothing — dead authority its
    author will debug later. Refusing at authoring is the only moment the
    **granter** — the party a silent widening harms — is still present to be
    told.
    """
    if not isinstance(grants, list):
        return None
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        for dimension in _PATH_SCOPE_DIMENSIONS:
            scope = grant.get(dimension)
            if not isinstance(scope, dict):
                continue
            for side in ("include", "exclude"):
                patterns = scope.get(side)
                if not isinstance(patterns, list):
                    continue
                for pattern in patterns:
                    if isinstance(pattern, str) and is_unmatchable_pattern(pattern):
                        return (dimension, side, pattern)
    return None


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
            # AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (§5.2, 0.8.2.21;
            # SCOPED TO PATH-SCOPE 0.8.2.24 N2). A granter writing
            # `exclude: ["*/secret"]` for *not `secret`, in any peer's
            # namespace* otherwise gets an exclusion that carves out nothing.
            #
            # ⛔ This comment used to read *"reached by every dimension of
            # every grant, so this is the widest of the three arms"* — and
            # that sentence is why nobody looked. It was FALSE as a design
            # statement (this is the PATH-scope matcher; `operations` and
            # `peers` take `matches_id_scope`) and TRUE as a description of
            # the call graph, because four call sites routed an id-scope
            # value here. 0.8.2.24 N2 is exactly that: the sentinel is a §5.4
            # PATH-canonicalization sentinel, it has no meaning on an id-scope
            # dimension, and applying it there denies the WHOLE dimension on a
            # property unrelated to whether the exclude carves anything out —
            # an `operations` exclude of `*/apply` is an ordinary literal to
            # the matcher that will evaluate it and an escaping path to the
            # canonicalizer. The guard is correct HERE; what was wrong was who
            # was calling here. Keep it path-scope-only by keeping the call
            # sites honest, not by adding a dimension parameter.
            if is_unmatchable_pattern(pattern):
                return False
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


def effective_resource_targets(
    resource_targets: list[str],
    resource_exclude: list[str] | None,
    local_peer_id: str,
) -> list[str]:
    """The §5.2 **effective** resource set: targets minus the caller's excludes.

    .. rubric:: F68 — this is the only derivation of the set, by construction

    ``check_resource_scope`` skips a target the caller's own ``exclude``
    covers (§5.2 calls such a target *"redundant but valid"*) and returns
    ALLOW when every target is skipped. A consumer that then reads the **raw**
    ``targets`` acts on a path the authorizer never checked against the grant:
    put the path you want in ``targets``, put it in ``exclude`` as well, and
    the resources dimension is neutralized. Ceiling is the executing handler's
    own grant — ``F67``'s shape one dimension over.

    The transferable rule (arch ``ROUTING-2026-09-10-d`` §2): *a handler MUST
    NOT act on a target the authorization check SKIPPED; where an authorizer
    and a consumer read the same request field they MUST derive the same set
    from it.* **A gate that narrows an input and a consumer that re-widens it
    is a bypass however correct each half is alone.**

    So this function exists to be the *single* derivation. The dispatcher calls
    it once and installs the result as the handler's ``resource_targets``;
    ``check_resource_scope`` calls it for its own loop. Nothing downstream is
    given the caller's ``exclude`` at all, which is what stops a second
    derivation appearing — see
    ``tests/integration/test_effective_resource_target_set_f68.py``.

    .. rubric:: The skip is decided CANONICALLY; the survivor is returned RAW

    §5.2's pseudocode appends the canonical form (``out.append(ct)``). We
    return the caller's spelling, deliberately, and so does ``entity-core-go``
    — independently and for the same reason, which is why it is written down
    here rather than filed as a departure: **§6.13's own worked example does a
    peer-relative prefix check on this return** (``system/handler/{pattern}``),
    and every handler in this tree resolves peer-relative paths through
    ``normalize_uri``. Canonicalizing the return would double-qualify them.

    The *security* property is unaffected: the skip decision is made on
    canonical forms, so the authorizer and every handler agree on WHICH
    targets survive, and the canonical form of the raw survivor is a member of
    the canonical effective set — ``subject ⊆ effective_targets`` holds either
    way. Routed to arch as **SA-PY-50**: two of three seats read a `[MUST]`
    whose literal pseudocode neither implements.

    A target that canonicalizes to :data:`NEVER_MATCH` is **not** skipped
    here — no exclude can cover it (§5.4's matcher rule), so it stays in the
    list and is refused by :func:`check_resource_scope`'s fail-closed
    validation. Dropping it instead would convert a malformed target into an
    *absent* one, i.e. a 400 for the wrong reason.

    Args:
        resource_targets: ``execute.resource.targets`` as sent.
        resource_exclude: ``execute.resource.exclude`` as sent, if any.
        local_peer_id: The verifier's frame — **request**-side paths
            canonicalize against the local peer (§PR-8), both halves of this
            reduction being caller-authored.

    Returns:
        The targets that survive the caller's own exclusions, order preserved,
        in the caller's own spelling.
    """
    if not resource_exclude:
        return list(resource_targets)

    canonical_excludes = [canonicalize(e, local_peer_id) for e in resource_exclude]
    survivors: list[str] = []
    for target in resource_targets:
        canonical_target = canonicalize(target, local_peer_id)
        if any(matches_pattern(e, canonical_target) for e in canonical_excludes):
            continue
        survivors.append(target)
    return survivors


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

    # Each resource target must be covered by some grant that also matches
    # handler and operation. The caller's own excludes come off first — via
    # `effective_resource_targets`, which is the SAME derivation the dispatcher
    # installs on the handler context. Skipping inline here is what let the two
    # halves disagree (F68); there is now one function and both callers use it.
    for target in effective_resource_targets(
        resource_targets, resource_exclude, local_peer_id
    ):
        # Find a grant that covers this target AND matches handler/operation
        target_covered = False
        canonical_target = canonicalize(target, local_peer_id)

        # G6 (0.8.2.20) — **consume the verdict and fail closed.** A concrete
        # target is validated at the protocol boundary; a pattern target goes
        # through pattern matching rather than tree access, so it is exempt by
        # the same sentence. The spec's own two call sites of this validator
        # invoked it *for effect* and discarded the return — one of them under
        # a comment reading `MUST — reject malformed peer_id segment` — and a
        # validator whose verdict is dropped enforces nothing. This peer had
        # neither the call nor the drop: the refusal was real but rested on
        # *no grant pattern happening to match a non-path*, which is the
        # accident §5.4 now refuses to rest on.
        if not is_pattern(canonical_target):
            if validate_absolute_path(canonical_target) is not None:
                return False

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
                    # Unmatchable exclude excludes everything (§5.2, 0.8.2.21)
                    # — the `CORE-EXCLUDE-UNMATCHABLE-1` arm. Without it a
                    # grant exclude the granter misspelled carves out NOTHING
                    # and the grant is wider than written.
                    if canonical_excl == NEVER_MATCH:
                        grant_excluded = True
                        break

                    if is_pattern(canonical_target):
                        # §5.2's PATTERN arm, which this peer did not have at
                        # all — no `patterns_overlap`, no `is_covered_by`.
                        #
                        # A concrete target is refused by the exact-match test
                        # below; a PATTERN target that SPANS the exclusion was
                        # not, because `matches_pattern(exclude, pattern)`
                        # compares the exclude against the pattern *string*
                        # and a concrete exclude never equals it. So a grant
                        # exclude was neutralized by re-spelling the request:
                        # grant `/{p}/*` except `/{p}/data/secret`, target
                        # `/{p}/data/*` -> ALLOW. Measured.
                        #
                        # Same family as `F68` — a gate caller-controlled
                        # input can make vacuous — with the SPELLING of the
                        # target as the input rather than an `exclude`.
                        #
                        # The rule: for each grant exclude overlapping this
                        # target, the CALLER must carve it out too, or the
                        # effective target includes paths the grant forbids.
                        if not patterns_overlap(canonical_target, canonical_excl):
                            continue
                        if not is_covered_by(
                            canonical_excl, resource_exclude or [], local_peer_id,
                        ):
                            grant_excluded = True
                            break
                        continue

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
    handler_pattern: str,
    now: int | None = None,
    granter_peer_id: str | None = None,
) -> bool:
    """Check if capability grants operation on specific path.

    Per spec §6.3 check_path_permission. Called by handlers to verify
    path-level access (the second level of the two-level model).

    .. rubric:: ``handler_pattern`` is REQUIRED and FAIL-CLOSED (§6.3, 0.8.2.23)

        *"An implementation MUST NOT treat an absent, null or empty
        ``handler_pattern`` as "match all handlers". The parameter has no
        permissive default, and a call site that cannot name its frame is a
        defect at that call site. Where an authority genuinely grants handler
        access with no path component, §5.2's ``{include: []}`` construction
        states that **at the grant**, where it is auditable — not at the call,
        where it is invisible."*

    This parameter defaulted to ``None`` here, and ``None`` **skipped the
    handlers filter entirely** — so a grant scoped to any handler at all
    authorized the path. The spec measured that direction: *"Supplying nothing
    widens: a grant scoped to any handler at all authorized a tree read through
    a compute lookup."*

    Two changes implement the MUST, and both are needed. The parameter has **no
    default**, so a site that does not name its frame fails to call rather than
    silently widening — which is what turns *"nobody wrote it"* from an
    invisible policy into a `TypeError` at the defect's own line. And an
    explicitly-passed ``None``/``""`` returns **False** rather than matching
    everything, because the argument can also arrive from a context field
    (:py:attr:`HandlerContext.handler_pattern`) that a caller never typed.

    *SA-PY-58 landed the owning-handler frame as an argument and swept the
    call sites it found; this pass swept the rest and found **five** still
    omitting it — including* ``compute``'s ``check_write_permission``, *whose
    sibling read arm had been fixed in that very commit. A row with two inputs
    censused on one of them, again.*

    Args:
        handler_pattern: The handler that **owns the operation being
            authorized** — never the handler running the check. A tree read
            reached through subscription, history, compute or query frames on
            ``system/tree``; a handler authorizing its own operation frames on
            its own pattern.

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

    # §6.3 (0.8.2.23) — the frame is REQUIRED and fail-closed. An absent, null
    # or empty frame is NOT "match all handlers": it is a call site that could
    # not name whose authority is being spent, and the spec assigns that a
    # defect rather than a permission. Guarded here as well as in the signature
    # because the value also arrives from `HandlerContext.handler_pattern`,
    # which is `str | None` and which no call site types.
    if not handler_pattern:
        return False

    canonical_path = canonicalize(path, local_peer_id)

    for grant in capability_data.get("grants", []):
        # V6.0: operations is now a CapabilityScope
        operations_scope = get_scope(grant, "operations")
        if not matches_id_scope(operations_scope, operation):
            continue

        # The handlers filter always runs (§6.3, 0.8.2.23): it ran only "if
        # provided" until the frame became mandatory, and "not provided" was
        # the widest possible reading of a dimension the caller never wrote.
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
                # Unmatchable exclude excludes everything (§5.2, 0.8.2.21).
                # 0.8.2.21 enumerates THREE sites — `matches_scope`'s exclude
                # loop, `check_resource_scope`'s concrete arm, and the pattern
                # arm. This is a FOURTH, and it is the **handler-level** check
                # (§6.3), which 0.8.2.20 promoted from defense-in-depth to the
                # enforcement for any subject derived after dispatch. Fixing
                # only the dispatch-level sites would leave the fail-open live
                # on exactly the path that carries the guarantee when the
                # dispatch-level check has been made vacuous. Routed as
                # SA-PY-52.
                if canonical_exclude == NEVER_MATCH:
                    excluded = True
                    break

                if is_pattern(canonical_path):
                    # §5.2's PATTERN arm, at the §6.3 site — the cell
                    # 0.8.2.21's `G-4` does not reach, because §6.3 describes
                    # its subject as *"the path this handler is ABOUT TO
                    # TOUCH"* and that reads as concrete by construction.
                    #
                    # It is not. `EXTENSION-SUBSCRIPTION` §2.3 requires this
                    # exact call on the **subscription pattern** — so the
                    # corpus itself routes a pattern in here, and the concrete
                    # test below then compares a concrete exclude against the
                    # pattern *string*, which no concrete path can equal. A
                    # grant reading *"everything under data except
                    # data/secret"* authorized an `include_payload`
                    # subscription on `data/*`, and delivery re-checks
                    # nothing: the excluded entity's BODY is pushed on every
                    # write to it, for the life of the subscription.
                    #
                    # **No new rule is invented here.** §5.2's arm is *for
                    # each grant exclude overlapping the target, the caller
                    # must also exclude it, else DENY*; §6.3 has no
                    # caller-exclude channel, so `is_covered_by(cge, [])` is
                    # vacuously false and the arm reduces to overlap → DENY.
                    # The missing SENTENCE is still owed — routed as SA-PY-56.
                    if patterns_overlap(canonical_path, canonical_exclude):
                        excluded = True
                        break
                    continue

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


