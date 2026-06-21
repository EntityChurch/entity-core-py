"""Unit tests for ``entity_core.capability.revocation`` (V7 §5.1 v7.62).

Pinned behaviors:
- ``capability_path_for(hash)`` returns the storage path under
  ``system/capability/grants/...`` (or None for wire-only caps).
- ``is_revoked`` walks parent links to the root, then checks BOTH the
  path binding AND an explicit revocation marker.
- Unknown root (wire-only cap, no marker) is NOT revoked — the
  ``unknown_root_policy`` indirection is gone.
- Marker presence revokes even a path-bound cap (defense in depth).
- Chain cycles and unresolvable parents are treated as revoked (defensive).
"""

from __future__ import annotations

from entity_core.capability.revocation import (
    DefaultRevocationContext,
    REVOCATIONS_ROOT,
    capability_path_for,
    is_revoked,
)
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree


def _peer_id() -> str:
    return "2KPzTESTpeeridforunittests1234567890"


def _ctx() -> tuple[EntityTree, ContentStore, DefaultRevocationContext]:
    tree = EntityTree(_peer_id())
    store = ContentStore()
    ctx = DefaultRevocationContext(entity_tree=tree, content_store=store)
    return tree, store, ctx


def _cap_token(grants: list[dict], parent: bytes | None = None) -> Entity:
    data: dict = {"grants": grants, "granter": b"\x00" * 33, "grantee": b"\x00" * 33,
                  "created_at": 1}
    if parent is not None:
        data["parent"] = parent
    return Entity(type="system/capability/token", data=data)


# ---------------------------------------------------------------------------
# capability_path_for
# ---------------------------------------------------------------------------

def test_capability_path_for_returns_grants_path() -> None:
    tree, store, _ = _ctx()
    cap = _cap_token([])
    h = cap.compute_hash()
    store.put(cap)
    tree.set(f"system/capability/grants/{h.hex()}", h)
    found = capability_path_for(tree, h)
    assert found is not None
    assert "system/capability/grants/" in found


def test_capability_path_for_returns_none_for_unbound_cap() -> None:
    tree, _, _ = _ctx()
    assert capability_path_for(tree, b"\x00" * 33) is None


def test_capability_path_for_ignores_non_grants_bindings() -> None:
    """A cap bound under an unrelated path (e.g. an app's own subtree) is
    not detected — handler-level revocation only fires for canonical
    grant storage."""
    tree, store, _ = _ctx()
    cap = _cap_token([])
    h = cap.compute_hash()
    store.put(cap)
    tree.set(f"local/app/some/path", h)
    assert capability_path_for(tree, h) is None


# ---------------------------------------------------------------------------
# is_revoked — root cases
# ---------------------------------------------------------------------------

def test_is_revoked_false_for_fresh_wire_only_cap() -> None:
    """Wire-only cap, no marker → not revoked."""
    _, _, ctx = _ctx()
    cap = _cap_token([])
    cap_dict = cap.to_dict()
    cap_dict["content_hash"] = cap.compute_hash()
    assert is_revoked(cap_dict, ctx) is False


def test_is_revoked_false_when_path_bound_and_no_marker() -> None:
    """Cap currently bound at its canonical path, no marker → not revoked."""
    tree, store, ctx = _ctx()
    cap = _cap_token([])
    h = cap.compute_hash()
    store.put(cap)
    tree.set(f"system/capability/grants/{h.hex()}", h)
    cap_dict = cap.to_dict()
    cap_dict["content_hash"] = h
    assert is_revoked(cap_dict, ctx) is False


_DOCSTRING_NOTE = """
Note on path-deletion mechanism: §5.1 specifies a path-deletion check that
fires when ``capability_path_for`` returns a non-null path AND that path
is unbound. Under the scan-fallback impl (no reverse index), the scan
itself returns null once a path is unbound — so the path-deletion branch
is effectively a no-op. The universal revoke op (§6.2) compensates by
ALSO writing the marker; the marker check below is what cohorts rely on.
"""


def test_is_revoked_true_for_marker_even_when_path_bound() -> None:
    """Defense in depth: marker alone revokes even when the path is intact."""
    tree, store, ctx = _ctx()
    cap = _cap_token([])
    h = cap.compute_hash()
    store.put(cap)
    tree.set(f"system/capability/grants/{h.hex()}", h)
    marker = Entity(
        type="system/capability/revocation",
        data={"token": h, "revoked_at": 0},
    )
    marker_hash = marker.compute_hash()
    store.put(marker)
    tree.set(f"{REVOCATIONS_ROOT}/{h.hex()}", marker_hash)
    cap_dict = cap.to_dict()
    cap_dict["content_hash"] = h
    assert is_revoked(cap_dict, ctx) is True


def test_is_revoked_true_for_wire_only_cap_with_marker() -> None:
    """Wire-only cap (no storage path) is revoked iff a marker exists.

    This is the case the unknown_root_policy indirection used to handle.
    """
    tree, store, ctx = _ctx()
    cap = _cap_token([])
    h = cap.compute_hash()
    marker = Entity(
        type="system/capability/revocation",
        data={"token": h, "revoked_at": 0},
    )
    marker_hash = marker.compute_hash()
    store.put(marker)
    tree.set(f"{REVOCATIONS_ROOT}/{h.hex()}", marker_hash)
    cap_dict = cap.to_dict()
    cap_dict["content_hash"] = h
    assert is_revoked(cap_dict, ctx) is True


# ---------------------------------------------------------------------------
# is_revoked — chain walking
# ---------------------------------------------------------------------------

def test_is_revoked_walks_chain_to_root() -> None:
    """The check fires on the chain root, not on intermediate links."""
    tree, store, ctx = _ctx()
    root = _cap_token([])
    root_hash = root.compute_hash()
    store.put(root)
    # Revoke the root via a marker (matches the revoke op's universal write).
    marker = Entity(
        type="system/capability/revocation",
        data={"token": root_hash, "revoked_at": 0},
    )
    marker_hash = marker.compute_hash()
    store.put(marker)
    tree.set(f"{REVOCATIONS_ROOT}/{root_hash.hex()}", marker_hash)

    child = _cap_token([], parent=root_hash)
    store.put(child)
    child_dict = child.to_dict()
    child_dict["content_hash"] = child.compute_hash()
    assert is_revoked(child_dict, ctx) is True


def test_is_revoked_falls_back_to_included_for_chain_walk() -> None:
    """Parent not in content store but present in envelope's included map."""
    tree, store, _ = _ctx()
    root = _cap_token([])
    root_hash = root.compute_hash()
    # Root marker exists in tree (revoked).
    marker = Entity(
        type="system/capability/revocation",
        data={"token": root_hash, "revoked_at": 0},
    )
    marker_hash = marker.compute_hash()
    store.put(marker)
    tree.set(f"{REVOCATIONS_ROOT}/{root_hash.hex()}", marker_hash)

    child = _cap_token([], parent=root_hash)
    # NB: root is NOT in store, only in `included`
    root_dict = root.to_dict()
    root_dict["content_hash"] = root_hash
    ctx = DefaultRevocationContext(
        entity_tree=tree,
        content_store=store,
        included={root_hash: root_dict},
    )
    child_dict = child.to_dict()
    child_dict["content_hash"] = child.compute_hash()
    assert is_revoked(child_dict, ctx) is True


def test_is_revoked_unresolvable_parent_is_revoked() -> None:
    _, _, ctx = _ctx()
    child = _cap_token([], parent=b"\x00" + b"\xff" * 32)  # bogus parent
    child_dict = child.to_dict()
    child_dict["content_hash"] = child.compute_hash()
    assert is_revoked(child_dict, ctx) is True


def test_is_revoked_chain_cycle_is_revoked() -> None:
    """A->A self-cycle (defensive — cycle = revoked)."""
    tree, store, ctx = _ctx()
    self_h = b"\x00" * 33
    cap = _cap_token([], parent=self_h)
    # Crafted with content_hash == its own parent.
    cap_dict = cap.to_dict()
    cap_dict["content_hash"] = self_h
    store.put(Entity.from_dict(cap_dict))
    assert is_revoked(cap_dict, ctx) is True
