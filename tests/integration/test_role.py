"""Integration tests for EXTENSION-ROLE v1.6 (post-spec-fixes).

Exercises the full lifecycle on a peer constructed via PeerBuilder:
- Role handler registers under `system/role` with ALL_HANDLER_MANIFESTS
- define -> assign -> exclude -> assign-again-blocked flow lands actual
  entities at the spec-pinned tree paths (using v1.6 hex peer-id
  encoding throughout).
- Layer-1 broad sweep deletes role-derived tokens at the pinned R4
  storage path (SI-7).
- Multi-role per peer (R6) — two assignments under the same (peer,
  context); the linkage entity at the sibling `derived-tokens/`
  subtree (SI-5) keeps unassign precise per role.
- RoleExtension installed via `with_all_handlers()`:
    * IA11 option (b) — direct tree:put to a role-definition path
      cascades through `re-derive` even when the `:define` op is not
      used.
    * IA8 — exclusion entities arriving by direct emit (simulating
      tree-sync from another peer) trigger the local sweep.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers import (
    ROLE_ASSIGNMENT_TYPE,
    ROLE_DERIVED_TOKEN_LINK_TYPE,
    ROLE_EXCLUSION_TYPE,
    ROLE_HANDLER_PATTERN,
    ROLE_TYPE,
    role_handler,
)
from entity_core.utils.path import invariant_signature_path

from entity_handlers.role import (
    role_assignment_path,
    role_definition_path,
    role_derived_token_link_path,
    role_derived_token_path,
    role_exclusion_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_peer():
    keypair = Keypair.generate()
    return (
        PeerBuilder()
        .with_keypair(keypair)
        .with_all_handlers()
        .build()
    )


def _full_grants() -> list[dict[str, Any]]:
    return [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]


def _make_handler_ctx(peer, *, resource_targets: list[str]) -> HandlerContext:
    """Construct a HandlerContext rooted at the peer's emit pathway."""
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=peer.keypair.peer_id,
        handler_grant={"grants": _full_grants()},
        caller_capability={"grants": _full_grants()},
        emit_pathway=peer.emit_pathway,
        handler_pattern=ROLE_HANDLER_PATTERN,
        keypair=peer.keypair,
        resource_targets=resource_targets,
    )


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _assignee_hex(kp: Keypair | None = None) -> str:
    """Compute the v1.6 SI-1 peer_id_hex for a fresh assignee.

    Generates a Keypair (or reuses the one passed in), constructs the
    `system/identity` entity, and returns lowercase hex of its
    content_hash. This is the form path segments and template
    substitutions take.
    """
    if kp is None:
        kp = Keypair.generate()
    return create_identity_entity(kp).compute_hash().hex()


# ---------------------------------------------------------------------------
# Registration / wiring
# ---------------------------------------------------------------------------


class TestRoleHandlerRegistration:
    def test_with_all_handlers_registers_role(self):
        peer = _build_peer()
        registered = peer.handlers.find_exact(ROLE_HANDLER_PATTERN)
        assert registered is not None
        assert registered.name == "role"
        assert registered.handler is role_handler

    def test_role_manifest_decomposed_into_tree(self):
        """register_handlers() decomposes the manifest into a
        system/handler/interface binding at system/handler/{pattern}
        so the tree records the operations system/role:* exposes."""
        peer = _build_peer()
        h = peer.emit_pathway.entity_tree.get(
            f"system/handler/{ROLE_HANDLER_PATTERN}",
        )
        assert h is not None
        entity = peer.emit_pathway.content_store.get(h)
        assert entity.type == "system/handler/interface"
        ops = entity.data.get("operations") or {}
        # All v1.6 ops should be reflected.
        for op in (
            "define", "assign", "unassign", "exclude", "unexclude",
            "re-derive", "delegate",
        ):
            assert op in ops, f"missing operation in manifest: {op}"


# ---------------------------------------------------------------------------
# Lifecycle: define -> assign -> exclude
# ---------------------------------------------------------------------------


class TestRoleLifecycleFlow:
    def test_define_assign_exclude_cycle(self):
        peer = _build_peer()
        assignee_hex = _assignee_hex()

        # 1. Define a role.
        def_path = role_definition_path("admin", "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[def_path])
        result = _run(role_handler(
            def_path, "define",
            {"data": {"grants": _full_grants()}}, ctx,
        ))
        assert result["status"] == 200
        h = peer.emit_pathway.entity_tree.get(def_path)
        role_entity = peer.emit_pathway.content_store.get(h)
        assert role_entity.type == ROLE_TYPE
        assert role_entity.data["name"] == "operator"

        # 2. Assign assignee to that role.
        assign_path = role_assignment_path("admin", assignee_hex, "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[assign_path])
        result = _run(role_handler(
            assign_path, "assign",
            {"data": {"role": "operator"}}, ctx,
        ))
        assert result["status"] == 200
        h = peer.emit_pathway.entity_tree.get(assign_path)
        assignment_entity = peer.emit_pathway.content_store.get(h)
        assert assignment_entity.type == ROLE_ASSIGNMENT_TYPE
        # Role-derived token at the pinned R4 path.
        token_hash = result["result"]["data"]["derived_tokens"][0]
        token_path = role_derived_token_path(
            "admin", assignee_hex, token_hash,
        )
        bound = peer.emit_pathway.entity_tree.get(token_path)
        assert bound == token_hash
        token_entity = peer.emit_pathway.content_store.get(bound)
        assert token_entity.type == "system/capability/token"
        assert token_entity.data["grants"] == _full_grants()
        # SI-8: cap grantee == raw bytes of the path's peer_id_hex.
        assert token_entity.data["grantee"] == bytes.fromhex(assignee_hex)
        # SI-5: linkage entity at sibling `derived-tokens/` subtree.
        link_path = role_derived_token_link_path(
            "admin", assignee_hex, "operator",
        )
        link_h = peer.emit_pathway.entity_tree.get(link_path)
        assert link_h is not None
        link_entity = peer.emit_pathway.content_store.get(link_h)
        assert link_entity.type == ROLE_DERIVED_TOKEN_LINK_TYPE
        assert link_entity.data["token_hash"] == token_hash

        # 3. Exclude the assignee from the context.
        excl_path = role_exclusion_path("admin", assignee_hex)
        ctx = _make_handler_ctx(peer, resource_targets=[excl_path])
        result = _run(role_handler(
            excl_path, "exclude",
            {"data": {"reason": "compromised"}}, ctx,
        ))
        assert result["status"] == 200
        excl_h = peer.emit_pathway.entity_tree.get(excl_path)
        excl_entity = peer.emit_pathway.content_store.get(excl_h)
        assert excl_entity.type == ROLE_EXCLUSION_TYPE
        assert excl_entity.data["reason"] == "compromised"
        # SI-3: no body peer_id field — path is canonical.
        assert "peer_id" not in excl_entity.data
        # Layer-1 broad sweep deleted the role-derived token.
        assert peer.emit_pathway.entity_tree.get(token_path) is None
        # SI-9: result key is `revoked_token_hashes` (renamed from
        # `revoked_tokens`).
        assert token_hash in result["result"]["data"]["revoked_token_hashes"]

        # 4. Subsequent assigns are blocked (layer 2).
        ctx = _make_handler_ctx(peer, resource_targets=[assign_path])
        retry = _run(role_handler(
            assign_path, "assign",
            {"data": {"role": "operator"}}, ctx,
        ))
        assert retry["status"] == 403
        assert retry["result"]["data"]["code"] == "assignee_excluded"

        # 5. Removing the exclusion restores eligibility.
        ctx = _make_handler_ctx(peer, resource_targets=[excl_path])
        result = _run(role_handler(
            excl_path, "unexclude", {}, ctx,
        ))
        assert result["status"] == 200
        ctx = _make_handler_ctx(peer, resource_targets=[assign_path])
        re_assign = _run(role_handler(
            assign_path, "assign",
            {"data": {"role": "operator"}}, ctx,
        ))
        assert re_assign["status"] == 200
        new_token = re_assign["result"]["data"]["derived_tokens"][0]
        new_token_path = role_derived_token_path(
            "admin", assignee_hex, new_token,
        )
        assert peer.emit_pathway.entity_tree.get(new_token_path) == new_token

    def test_role_derived_sig_at_invariant_path_not_sibling(self):
        """V7 §3.5 (v7.44, normative) + PROPOSAL Amendment 5/7: a
        role-derived cap is a plain V7 root cap that can root a
        cross-peer continuation chain, so its signature MUST be
        discoverable at the invariant pointer path
        `/{signer}/system/signature/{cap_hash_hex}` (the sole canonical
        location — ROLE pins no signature path). The legacy
        `{storage_path}/signature` sibling is removed outright (clean
        break, no dual-write); revocation MUST unbind the invariant
        entry so the signature does not leak.

        This is the in-repo mirror of Go's `tv_rd_21_cap_signature_valid`
        + the `ops_delegate_test` negative control. The sibling-asserting
        shape is exactly what masked this divergence before the v7.44
        correction — assert the *correct* location AND the absence of the
        old one.
        """
        peer = _build_peer()
        assignee_hex = _assignee_hex()
        signer_peer_id = peer.keypair.peer_id  # minting/local peer

        def_path = role_definition_path("admin", "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[def_path])
        assert _run(role_handler(
            def_path, "define",
            {"data": {"grants": _full_grants()}}, ctx,
        ))["status"] == 200

        assign_path = role_assignment_path("admin", assignee_hex, "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[assign_path])
        result = _run(role_handler(
            assign_path, "assign", {"data": {"role": "operator"}}, ctx,
        ))
        assert result["status"] == 200
        token_hash = result["result"]["data"]["derived_tokens"][0]

        tree = peer.emit_pathway.entity_tree
        inv_path = invariant_signature_path(signer_peer_id, token_hash)
        sib_path = (
            role_derived_token_path("admin", assignee_hex, token_hash)
            + "/signature"
        )

        # (B) V7-general invariant pointer: signature discoverable here.
        sig_h = tree.get(inv_path)
        assert sig_h is not None, (
            "role-derived cap signature NOT at the V7 §3.5 invariant "
            "pointer path — v7.44 non-conformance (the tv_rd_21 gap)"
        )
        sig = peer.emit_pathway.content_store.get(sig_h)
        assert sig.type == "system/signature"
        assert sig.data["target"] == token_hash
        assert sig.data["signer"] == (
            create_identity_entity(peer.keypair).compute_hash()
        )
        # Negative control: the extension-private sibling MUST be gone.
        assert tree.get(sib_path) is None, (
            "legacy {storage_path}/signature sibling still written — "
            "Amendment 7 mandates a clean break (invariant-path only)"
        )

        # Revocation unbinds the invariant entry (no signature leak).
        excl_path = role_exclusion_path("admin", assignee_hex)
        ctx = _make_handler_ctx(peer, resource_targets=[excl_path])
        assert _run(role_handler(
            excl_path, "exclude", {"data": {"reason": "x"}}, ctx,
        ))["status"] == 200
        assert tree.get(inv_path) is None, (
            "role-derived cap signature leaked at the invariant path "
            "after revocation — sweep must unbind it there"
        )

    def test_multi_role_per_peer_per_context(self):
        """R6 + SI-5 wire-level: a peer holds multiple roles; each
        assignment is paired with its own linkage entity at the
        sibling subtree."""
        peer = _build_peer()
        assignee_hex = _assignee_hex()

        for role_name in ("operator", "auditor"):
            path = role_definition_path("admin", role_name)
            ctx = _make_handler_ctx(peer, resource_targets=[path])
            res = _run(role_handler(
                path, "define",
                {"data": {"grants": _full_grants()}}, ctx,
            ))
            assert res["status"] == 200

        for role_name in ("operator", "auditor"):
            apath = role_assignment_path("admin", assignee_hex, role_name)
            ctx = _make_handler_ctx(peer, resource_targets=[apath])
            res = _run(role_handler(
                apath, "assign", {"data": {"role": role_name}}, ctx,
            ))
            assert res["status"] == 200

        # Both assignment entries coexist with their own linkage entities.
        op_h = peer.emit_pathway.entity_tree.get(
            role_assignment_path("admin", assignee_hex, "operator"),
        )
        au_h = peer.emit_pathway.entity_tree.get(
            role_assignment_path("admin", assignee_hex, "auditor"),
        )
        assert op_h is not None and au_h is not None
        op_link = peer.emit_pathway.entity_tree.get(
            role_derived_token_link_path("admin", assignee_hex, "operator"),
        )
        au_link = peer.emit_pathway.entity_tree.get(
            role_derived_token_link_path("admin", assignee_hex, "auditor"),
        )
        assert op_link is not None and au_link is not None


# ---------------------------------------------------------------------------
# Phase 3: RoleExtension wired through with_all_handlers
# ---------------------------------------------------------------------------


class TestRoleExtensionOnPeer:
    def test_with_all_handlers_installs_role_extension(self):
        peer = _build_peer()
        from entity_handlers import RoleExtension
        installed = [
            e for e in peer._extensions if isinstance(e, RoleExtension)
        ]
        assert len(installed) == 1

    def test_external_role_definition_write_triggers_cascade(self):
        """IA11 option (b): a direct emit of a role-definition entity
        (bypassing :define) triggers the watcher and re-derives all
        assignments for that role."""
        peer = _build_peer()
        assignee_hex = _assignee_hex()

        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        def_path = role_definition_path("admin", "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[def_path])
        _run(role_handler(
            def_path, "define",
            {"data": {"grants": narrow}}, ctx,
        ))
        apath = role_assignment_path("admin", assignee_hex, "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[apath])
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx,
        ))
        old_token = assign_res["result"]["data"]["derived_tokens"][0]

        wider = [
            {
                "handlers": {"include": ["system/tree", "system/query"]},
                "resources": {"include": ["public/*", "private/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        peer.emit_pathway.emit(
            def_path,
            Entity(
                type=ROLE_TYPE,
                data={"name": "operator", "grants": wider},
            ),
            EmitContext.bootstrap(),
        )

        old_path = role_derived_token_path(
            "admin", assignee_hex, old_token,
        )
        assert peer.emit_pathway.entity_tree.get(old_path) is None
        # Linkage now points to a different token.
        link_h = peer.emit_pathway.entity_tree.get(
            role_derived_token_link_path("admin", assignee_hex, "operator"),
        )
        link_entity = peer.emit_pathway.content_store.get(link_h)
        assert link_entity.data["token_hash"] != old_token

    def test_external_exclusion_write_triggers_fleet_sweep(self):
        """IA8: an exclusion entity written by direct emit (simulating
        tree-sync from another peer) triggers the local sweep."""
        peer = _build_peer()
        assignee_hex = _assignee_hex()

        def_path = role_definition_path("admin", "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[def_path])
        _run(role_handler(
            def_path, "define",
            {"data": {"grants": _full_grants()}}, ctx,
        ))
        apath = role_assignment_path("admin", assignee_hex, "operator")
        ctx = _make_handler_ctx(peer, resource_targets=[apath])
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx,
        ))
        token_hash = assign_res["result"]["data"]["derived_tokens"][0]
        token_path = role_derived_token_path(
            "admin", assignee_hex, token_hash,
        )
        assert peer.emit_pathway.entity_tree.get(token_path) is not None

        peer.emit_pathway.emit(
            role_exclusion_path("admin", assignee_hex),
            Entity(
                type=ROLE_EXCLUSION_TYPE,
                data={"excluded_by": b"a", "excluded_at": 0},
            ),
            EmitContext.bootstrap(),
        )
        assert peer.emit_pathway.entity_tree.get(token_path) is None
