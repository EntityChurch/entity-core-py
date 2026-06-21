"""Capability revocation — V7 §5.1 (v7.62).

Implements ``is_revoked`` (the chain-walking root check + marker check) and
``capability_path_for`` (the storage-path lookup for a capability hash).

Per V7 §5.1 v7.62, an ``unknown_root_policy`` indirection is no longer part
of the algorithm: a cap with no known storage path is revoked iff a marker
exists at ``system/capability/revocations/{root_hash_hex}``. Path-bound and
wire-only caps converge on the same predicate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree


REVOCATIONS_ROOT = "system/capability/revocations"
GRANTS_ROOT = "system/capability/grants"


@runtime_checkable
class RevocationContext(Protocol):
    """Minimum surface for ``is_revoked``. See V7 §5.1 v7.62.

    The protocol is illustrative — any object that exposes equivalent
    methods (under any names) satisfies the algorithm. ``DefaultRevocationContext``
    is the concrete impl used by core; ``HandlerContext`` plays this role
    when handlers call ``is_revoked`` explicitly (compute reactive re-eval, etc.).
    """

    supports_revocation: bool
    included: dict[bytes, dict[str, Any]] | None

    @property
    def content_store(self) -> ContentStore: ...

    @property
    def entity_tree(self) -> EntityTree: ...

    def capability_path_for(self, cap_hash: bytes) -> str | None: ...


def capability_path_for(
    entity_tree: EntityTree, cap_hash: bytes,
) -> str | None:
    """Return the canonical storage path for ``cap_hash``, or None for wire-only.

    Per V7 §5.1: handler grants are stored at ``system/capability/grants/{pattern}``.
    Application caps land in deeper subtrees. We scan the binding map for any
    path bound to ``cap_hash`` whose normalized form contains the grants-root
    segment. The tree stores normalized (peer-prefixed) URIs, so we match the
    grants-root as a substring.

    A reverse index (cap content hash → stored tree path) is recommended in
    the spec for O(1) lookup; the linear scan here is correct and used by
    cohorts already (Go) until a perf path needs it.
    """
    needle = GRANTS_ROOT + "/"
    for path in entity_tree.paths_for_hash(cap_hash):
        if needle in path:
            return path
    return None


@dataclass
class DefaultRevocationContext:
    """Concrete ``RevocationContext`` for callers that don't already have one.

    Used by ``verify_request`` at the wire boundary and by extensions that
    need to do a one-off revocation check outside a handler frame.
    """

    entity_tree: EntityTree
    content_store: ContentStore
    included: dict[bytes, dict[str, Any]] | None = None
    supports_revocation: bool = True

    def capability_path_for(self, cap_hash: bytes) -> str | None:
        return capability_path_for(self.entity_tree, cap_hash)


def _resolve_parent(
    parent_hash: bytes,
    content_store: ContentStore,
    included: dict[bytes, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Try the content store first, fall back to the envelope's ``included``.

    Persisted caps live in the store; freshly-wired caps may only exist in
    the envelope's included map until the receiver opts to persist them.
    Returning a dict (not an Entity) keeps the algorithm cheap when ``current``
    is the wire form.
    """
    stored = content_store.get(parent_hash)
    if stored is not None:
        return stored.to_dict()
    if included is not None:
        raw = included.get(parent_hash)
        if isinstance(raw, dict):
            return raw
    return None


def _as_entity_dict(cap: Any) -> dict[str, Any] | None:
    if isinstance(cap, dict):
        return cap
    if isinstance(cap, Entity):
        return cap.to_dict()
    return None


def is_revoked(
    capability: dict[str, Any] | Entity,
    ctx: RevocationContext,
) -> bool:
    """V7 §5.1 (v7.62) ``is_revoked``.

    Walks the delegation chain to the root via content store, falling back
    to the envelope's ``included`` map. Then checks BOTH:

    1. The path binding (catches caps whose root path was deleted).
    2. An explicit revocation marker at ``system/capability/revocations/{hex}``
       (catches wire-only caps and provides defense in depth for path-bound
       caps).

    Returns true if the cap is revoked by either mechanism, or if the chain
    is unresolvable (defensive — an opaque chain is treated as revoked).

    Caps with no known storage path are no longer ambiguous (no
    ``unknown_root_policy`` indirection): they are revoked iff a marker exists.
    """
    current = _as_entity_dict(capability)
    if current is None:
        return True

    content_store = ctx.content_store
    included = getattr(ctx, "included", None)
    visited: set[bytes] = set()

    while True:
        data = current.get("data") or {}
        parent_hash = data.get("parent")
        if not isinstance(parent_hash, bytes) or not parent_hash:
            break
        cur_hash = current.get("content_hash")
        if isinstance(cur_hash, bytes):
            if cur_hash in visited:
                return True
            visited.add(cur_hash)
        parent = _resolve_parent(parent_hash, content_store, included)
        if parent is None:
            return True
        current = parent

    # current is the root capability.
    root_hash = current.get("content_hash")
    if not isinstance(root_hash, bytes):
        # If the root has no recorded content hash, recompute it. This
        # supports inline-wire root caps that haven't been hashed yet.
        try:
            root_entity = Entity.from_dict(current)
        except Exception:
            return True
        root_hash = root_entity.compute_hash()

    # 1. Path-binding check.
    root_path = ctx.capability_path_for(root_hash)
    if root_path is not None:
        bound = ctx.entity_tree.get(root_path)
        if bound is None:
            return True
        if bytes(bound) != bytes(root_hash):
            return True

    # 2. Explicit revocation marker.
    marker_path = f"{REVOCATIONS_ROOT}/{root_hash.hex()}"
    if ctx.entity_tree.get(marker_path) is not None:
        return True

    return False
