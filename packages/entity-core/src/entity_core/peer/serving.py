"""Serving-mode scope predicates and content-by-hash resolver.

Per EXTENSION-NETWORK §6.5.6 (v1.4 Amendment 5):

- **Axis 1 — request-side auth: ALWAYS hash-knowledge / path-presence.**
  Forced by use case (browsers, `curl`, CDNs can't present caps). The
  poll routes are unauthenticated by nature.
- **Axis 2 — serving-side scope: `serve_scope` IS the lever.**
  Which entities the routes answer for. **`serve_scope` is a capability
  token** (Amendment 5 — the one-ACL-machinery resolution). The
  serving impl passes the published cap as the *effective cap* to the
  same evaluator the live-EXECUTE surface uses
  (`check_path_permission`). One ACL machinery; drift between live and
  serving surfaces is structurally impossible.

The `ScopePredicate` Protocol is the seam; `CapTokenScope` is the
shipped impl. `WholeStoreScope` remains as an explicit-opt-in
debug/operator-tool escape hatch (CONTENT §6.4.1 marks multi-party
use of single-trust-domain "security-defective").

The resolver `resolve_content_bytes(H, store, scope)` is the bytes-side
of the route: returns bytes-or-None given scope. Identical 404 for
out-of-scope vs not-held (§6.5.6 T4 mitigation — no presence oracle).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from entity_core.capability.checking import check_path_permission

if TYPE_CHECKING:
    from entity_core.storage.content_store import ContentStore
    from entity_core.storage.entity_tree import EntityTree

logger = logging.getLogger(__name__)


@runtime_checkable
class ScopePredicate(Protocol):
    """Decides whether a hash / path is in-scope for the serving routes.

    Implementations are **stateless decision functions** — the serving
    impl's authorization context (Amendment 5: the published
    `serve_scope.cap` IS the effective cap for an unauthenticated
    request). Adding a new scope mechanism means writing a new
    predicate; the HTTP handler is unchanged.
    """

    def in_scope(self, h: bytes) -> bool:
        """Return True iff the content-by-hash route should answer for `h`."""
        ...

    def in_scope_path(self, path: str) -> bool:
        """Return True iff the tree route should answer for `path`
        (strict — the cap grants `get` on this exact path)."""
        ...

    def prefix_in_scope(self, prefix: str) -> bool:
        """Return True iff a listing at `prefix` should render.

        Loose membership: True iff the cap grants `get` on the prefix
        *or any descendant of it*. A directory whose only authority is
        "I have children under this subtree that the cap permits" must
        render its listing (scope-filtered) — otherwise navigation
        through the published set would be impossible.

        The strictness split (entity-fetch tight; listing-render loose)
        is what makes the `200 + entries={}` Q2 case work and the
        peer-root / `peers.list` / parent-directory listings reachable
        even when the cap is scoped to a deep subtree.
        """
        ...

    def describe(self) -> str:
        """One-line description for logging / profile metadata."""
        ...


class CapTokenScope:
    """`serve_scope` as a capability token (Amendment 5 — normative).

    Wraps the published `serve_scope.cap` data dict and evaluates every
    in-scope decision via `check_path_permission` — **the same call the
    live-EXECUTE dispatcher uses**. One ACL machinery; drift between
    live and serving surfaces is structurally impossible.

    **Wiring (Gap A — MUST).** The poll routes carry no request auth,
    so the published `serve_scope.cap` IS the entire authorization
    context. Where the live surface asks "does the connection's cap-set
    permit `get(path)`?", the serving surface asks "does
    `serve_scope.cap` permit `get(path)`?" Impls MUST pass the cap as
    the effective cap (no internals access, no fake connection state).

    **Two faces of the served set:**
    - **tree-face** (`in_scope_path`): cap evaluator decides directly.
    - **content-face** (`in_scope`): hash H is in scope iff some path
      currently bound to H is itself in scope per the cap. This routes
      content authorization through the existing tree-path authorization
      (§6.4.2 Hash Tree Presence + cap eval — no second ACL surface).

    The CONTENT §6.4.1 *published-set* topology is what this expresses:
    "Populate by binding shareable hashes under a content namespace
    (`system/content/{ns}/{hex33(H)}`)" → the cap grants `get` on the
    namespace; the namespace bindings define the served hash set.

    Construction conveniences (for CLI flag absorption) are provided as
    classmethods so the spec contract (a `system/capability` data dict)
    is the canonical input but operators can still write
    `--serve-namespace NS` without authoring a cap entity.
    """

    def __init__(
        self,
        cap_data: dict[str, Any],
        entity_tree: "EntityTree",
        local_peer_id: str,
        *,
        description: str | None = None,
    ) -> None:
        """Construct from a cap-token data dict.

        Args:
            cap_data: The "data" field of a `system/capability` entity
                (with `grants`, optional `expires_at`/`not_before`).
                Same shape `check_path_permission` consumes.
            entity_tree: The peer's entity tree (for the content-face
                hash → paths reverse walk).
            local_peer_id: For path canonicalization inside the cap
                evaluator.
            description: Human-readable label for logs / profile.
                Defaults to a fingerprint of the cap shape.
        """
        self.cap_data = cap_data
        self.tree = entity_tree
        self.local_peer_id = local_peer_id
        self._description = description or self._summarize(cap_data)

    @classmethod
    def from_namespace(
        cls,
        entity_tree: "EntityTree",
        namespace: str,
        local_peer_id: str,
    ) -> "CapTokenScope":
        """Convenience: synthesize a `published-set` cap for a namespace.

        Builds a `system/capability`-shaped data dict granting `get` on
        the namespace subtree under **any peer-id**
        (`/*/{namespace}/*`) — the universal-tree semantic per
        EXTENSION-NETWORK §6.5.6. `--serve-namespace ns` means "serve
        the `ns` namespace, regardless of which peer wrote it" —
        otherwise an operator running a multi-peer mirror would have to
        fall back to `whole-store`, which CONTENT §6.4.1 marks as
        security-defective.

        The peer-wildcard pattern `/*/ns/*` is the documented cap shape
        for cross-peer subtree grants (checking.py `matches_pattern`
        special-cases `/*/` as "any peer's subtree"). Cohort interop:
        Go's serveAllPeersListing surfaces foreign peer-ids
        unconditionally; this cap-shape choice makes the *fetch* side
        agree with the listing side under the same operator flag.

        For peer-scoped grants, author a literal `system/capability`
        cap entity and pass its `data` to the `CapTokenScope`
        constructor directly.
        """
        ns = namespace.rstrip("/")
        cap_data = {
            "grants": [
                {
                    "operations": {"include": ["get"]},
                    # `/*/ns/*` matches `/{any_peer_id}/ns/...` — the
                    # universal-tree semantic. See checking.py
                    # matches_pattern for the `/*/` peer-wildcard rule.
                    "resources": {"include": [f"/*/{ns}/*"]},
                    "handlers": {"include": ["*"]},
                },
            ],
        }
        return cls(
            cap_data,
            entity_tree,
            local_peer_id,
            description=f"cap:published-set:/*/{ns}",
        )

    def in_scope_path(self, path: str) -> bool:
        """Tree-face entity check: cap evaluator decides directly.

        The path is whatever was requested on `TREE_GET` entity-form
        (`{path}{leaf_suffix}`). The evaluator canonicalizes it (peer-id
        prefix) the same way it does for live-EXECUTE so the two
        surfaces enforce the same rule.
        """
        return check_path_permission(
            self.cap_data, "get", path, self.local_peer_id,
        )

    def prefix_in_scope(self, prefix: str) -> bool:
        """Listing-render check: is the prefix touched by any grant?

        True iff some cap-grant's resource pattern overlaps the prefix
        subtree (the grant is at the prefix, under it, or above it).
        This is what makes peer-root / parent-directory listings
        reachable when the cap is scoped to a deep subtree — the
        navigation handles render with the cap-filtered entries.
        """
        from entity_core.capability.checking import canonicalize
        p_norm = self._normalize_prefix(prefix)
        # Empty / root prefix is always in scope (the universal-tree-root
        # view), so the navigation entry point always renders.
        if p_norm == "" or p_norm == "/":
            return True
        for grant in self.cap_data.get("grants", []) or []:
            resources = (grant.get("resources") or {})
            for pattern in resources.get("include", []) or []:
                canon = canonicalize(pattern, self.local_peer_id)
                base = canon[:-2] if canon.endswith("/*") else canon
                base = self._normalize_prefix(base)
                if self._prefixes_overlap(p_norm, base):
                    return True
        return False

    @staticmethod
    def _normalize_prefix(p: str) -> str:
        if not p:
            return ""
        s = p
        # Treat trailing-slash forms as the same prefix.
        while len(s) > 1 and s.endswith("/"):
            s = s[:-1]
        return s

    @staticmethod
    def _segments(p: str) -> list[str]:
        s = p.strip("/")
        return s.split("/") if s else []

    @classmethod
    def _prefixes_overlap(cls, prefix: str, pattern_base: str) -> bool:
        """True iff the two subtrees intersect, treating `*` segments
        in `pattern_base` as peer-wildcards (matches_pattern §5.2).

        Two subtrees intersect when one is an ancestor of (or equal to)
        the other. Segment-by-segment match with `*` matching any single
        segment. An empty prefix (root) intersects everything.
        """
        p_segs = cls._segments(prefix)
        b_segs = cls._segments(pattern_base)
        # Root prefix or root base ⇒ everything intersects.
        if not p_segs or not b_segs:
            return True
        n = min(len(p_segs), len(b_segs))
        for i in range(n):
            if not cls._seg_match(p_segs[i], b_segs[i]):
                return False
        return True

    @staticmethod
    def _seg_match(a: str, b: str) -> bool:
        return a == b or a == "*" or b == "*"

    def in_scope(self, h: bytes) -> bool:
        """Content-face: H in-scope iff some in-scope path binds to H.

        Routes content authorization through tree-path authorization —
        the §6.4.2 Hash Tree Presence rule expressed via the same cap
        evaluator the tree-face uses. There is no separate content-side
        ACL; pre-rendered chain pages and content bindings live under
        the served namespace.
        """
        if not isinstance(h, (bytes, bytearray)) or len(h) == 0:
            return False
        for path in self.tree.paths_for_hash(bytes(h)):
            if self.in_scope_path(path):
                return True
        return False

    def describe(self) -> str:
        return self._description

    @staticmethod
    def _summarize(cap_data: dict[str, Any]) -> str:
        """One-line summary of the cap shape for logs."""
        grants = cap_data.get("grants", []) or []
        includes: list[str] = []
        for grant in grants:
            res = grant.get("resources") or {}
            includes.extend(res.get("include", []) or [])
        head = ",".join(includes[:3]) or "<none>"
        more = "" if len(includes) <= 3 else f" (+{len(includes) - 3})"
        return f"cap-token[{head}{more}]"


class WholeStoreScope:
    """Explicit-opt-in debug scope (CONTENT §6.4.1 single-trust-domain).

    Returns True for any hash / path. **Operator owns the consequence**
    — caps, signatures, private blobs all reachable if their hashes /
    paths leak. The CLI logs a T2/T3 warning when this is selected and
    `validate-peer` documents it as security-defective for multi-party
    use.

    Kept as a separate predicate type (not a cap shape) because the
    semantics — "no scope check whatsoever" — are deliberately *outside*
    the cap-token model, and the operator's explicit opt-in is the
    audit trail.
    """

    def in_scope(self, h: bytes) -> bool:
        return True

    def in_scope_path(self, path: str) -> bool:
        return True

    def prefix_in_scope(self, prefix: str) -> bool:
        return True

    def describe(self) -> str:
        return "whole-store"


class ClosureScope:
    """Subtree-closure scope — the publish-ceremony form (Phase P / C2).

    Serves the **transitive closure of a signed ``published-root``**: the
    trie root node, every reachable sub-node, and every bound entity
    value-hash (``collect_trie_hashes``), plus the published-root entity
    and its signature so a cold http-poll consumer can fetch + verify the
    root and then walk the hash-chain from it (PEER-MANIFEST §1.1 threat
    model — the consumer trusts the signed root, not the host's path
    claims). This is what makes ``CONTENT_GET`` of an unbound trie node
    answerable: under the default ``CapTokenScope`` (content gated by
    tree-path binding) trie nodes aren't path-bound, so the signed-root
    walk would 404; the closure scope serves exactly the reachable set.

    The closure is walked once at construction and cached (a static mirror
    re-derives on each republish). ``also_serve_*`` carry the
    published-root + signature (published *after* the trie was built, so
    not inside the closure).

    Cross-impl note: the consumer-side walk + hash-verification is
    impl-agnostic (pure hash-chain). The publisher-side "what scope a
    static mirror serves" is the cohort C2 convergence point — Go's P2
    reference + the validate-peer vector pin the canonical serving policy;
    this is the Python shape (serve the signed-root closure), surfaced for
    that reconciliation.
    """

    def __init__(
        self,
        entity_tree: "EntityTree",
        content_store: "Any",
        root_hash: bytes,
        *,
        also_serve_hashes: "Any" = (),
        also_serve_paths: "Any" = (),
    ) -> None:
        from entity_core.storage.trie import collect_trie_hashes

        self.entity_tree = entity_tree
        self.root_hash = bytes(root_hash)
        closure = collect_trie_hashes(self.root_hash, content_store)
        closure.add(self.root_hash)
        for h in also_serve_hashes:
            if h is not None:
                closure.add(bytes(h))
        self._closure = closure
        self._paths = {entity_tree.normalize_uri(p) for p in also_serve_paths}

    def in_scope(self, h: bytes) -> bool:
        return bytes(h) in self._closure

    def in_scope_path(self, path: str) -> bool:
        full = self.entity_tree.normalize_uri(path)
        if full in self._paths:
            return True
        h = self.entity_tree.get(path)
        return h is not None and bytes(h) in self._closure

    def prefix_in_scope(self, prefix: str) -> bool:
        # Listing render is loose (scope-filtered at render); the closure
        # set still gates which leaves materialize.
        return True

    def describe(self) -> str:
        return f"closure:{self.root_hash.hex()[:16]}"


def render_tree_listing(
    prefix: str,
    entity_tree: "EntityTree",
    scope: ScopePredicate,
    *,
    offset: int = 0,
    limit: int | None = None,
) -> dict[str, Any] | None:
    """Render a `system/tree/listing` entity for the named-object route.

    Per EXTENSION-NETWORK §6.5.3.1 (v1.4 Amendment 5):
    - Body = the existing `system/tree/listing` entity (V7 §3.9) — shape
      `{path, entries: {name → {hash?, has_children}}, count, offset,
      next_page?}`.
    - `count` = in-scope **filtered** total (never raw subtree total —
      TREE §1176 leak rule).
    - Offset/limit run **post-scope** (§6.5.6 security pin — numbering
      over raw children leaks an offset oracle).
    - Empty in-scope prefix ⇒ `200` + `entries={}` + `count=0`.
    - Out-of-scope or non-existent prefix ⇒ identical `404` (T4).

    Returns the entity dict ({"type", "data"}) ready for ECF encoding, or
    `None` if the prefix itself is out-of-scope (caller emits 404).

    Note: `next_page` is not emitted by v1 — single-page listings are
    universal until validate-peer-perf demands a paging proof. The
    type-system field is wired (V7 7.57) so chained pages decode
    correctly when an impl starts emitting them. Adding it on the
    publish side is straight-line follow-on.
    """
    # Scope-gate the prefix itself for the listing render. Out-of-scope
    # prefix returns None → caller renders identical 404 (no presence
    # oracle). `prefix_in_scope` is the LOOSE check — the prefix renders
    # iff the cap grants something at, under, or above it. The strict
    # entity check (`in_scope_path`) is reserved for leaf-entity fetches.
    normalized = entity_tree.normalize_uri(prefix.rstrip("/") or "/")
    if not scope.prefix_in_scope(normalized):
        return None

    # Enumerate raw children, then filter by scope (post-scope offset).
    prefix_with_slash = normalized if normalized.endswith("/") else normalized + "/"
    uris = entity_tree.list_prefix(prefix_with_slash)

    seen: set[str] = set()
    raw_children: list[tuple[str, bytes | None, bool]] = []
    for uri in uris:
        suffix = uri[len(prefix_with_slash):]
        if not suffix:
            continue
        parts = suffix.split("/")
        name = parts[0]
        if name in seen:
            continue
        seen.add(name)
        child_uri = prefix_with_slash + name
        bound = entity_tree.get(child_uri)
        has_children = len(parts) > 1 or any(
            u.startswith(child_uri + "/") for u in uris if u != child_uri
        )
        raw_children.append((name, bound, has_children))

    # Filter children by scope BEFORE counting / offsetting (TREE §1176
    # + §6.5.6 offset-oracle pin). The right check per child:
    # - leaf-only (`bound is not None` and `has_children is False`):
    #   strict `in_scope_path` — the cap must grant get on this exact
    #   leaf for it to be visible.
    # - directory (`has_children`): loose `prefix_in_scope` — the cap
    #   grants something *under* this subtree so it shows as a
    #   navigation handle.
    in_scope_children: list[tuple[str, bytes | None, bool]] = []
    for name, bound, has_children in raw_children:
        child_path = prefix_with_slash + name
        if has_children:
            permitted = scope.prefix_in_scope(child_path)
        else:
            permitted = scope.in_scope_path(child_path)
        if permitted:
            in_scope_children.append((name, bound, has_children))

    in_scope_children.sort(key=lambda x: x[0])
    filtered_count = len(in_scope_children)

    # Window the post-scope sequence.
    windowed = in_scope_children[offset:]
    if limit is not None:
        windowed = windowed[:limit]

    entries: dict[str, dict[str, Any]] = {}
    for name, bound, has_children in windowed:
        entry: dict[str, Any] = {"has_children": has_children}
        if bound is not None:
            entry["hash"] = bound
        entries[name] = entry

    return {
        "type": "system/tree/listing",
        "data": {
            "path": normalized,
            "entries": entries,
            "count": filtered_count,
            "offset": offset,
        },
    }


def resolve_content_bytes(
    h: bytes,
    content_store: "ContentStore",
    scope: ScopePredicate,
) -> bytes | None:
    """Bytes-side of the `CONTENT_GET` route.

    Returns the **bare hashable `ECF({type, data})`** if (a) the hash is
    in-scope per the scope predicate AND (b) the local content-store
    holds the entity. Returns None otherwise — caller emits an identical
    404 either way (§6.5.6 T4: no presence oracle).

    Per EXTENSION-NETWORK §6.5.3.1: the body MUST satisfy pure-body
    rehash. A consumer computes `0x00 ‖ SHA-256(body)` and accepts only
    if it equals the URL hash. That's Mechanism A — the hostile-CDN
    safety property. The only bytes that re-hash to H are
    `ECF({type, data})` — the 2-key bare form — NOT the 3-key wire
    entity carrying `content_hash` (that value hashes `{type, data}`
    and can't appear in its own preimage).
    """
    if not scope.in_scope(h):
        return None
    entity = content_store.get(h)
    if entity is None:
        return None
    from entity_core.utils.ecf import ecf_encode
    return ecf_encode({"type": entity.type, "data": entity.data})
