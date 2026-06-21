"""Unit tests for EXTENSION-ROLE v1.6 (SI-1..SI-28 fixes).

Covers:
- Path decomposition (definition / assignment / exclusion) on hex peer-id segments
- Reserved role-name rejection (R10 + SI-5: `derived-tokens` reserved)
- Template resolution (§5.2) substituting {peer_id} → peer_id_hex
- is_excluded layer-2 helper (§6.2)
- Define op: RL2 + cascade through re-derive (IA11)
- Assign op: RL2, layer-2 exclusion check, role lookup, token issuance,
  hex-form peer_id everywhere, linkage entity at sibling derived-tokens/
- Unassign op: assignment removal + selective revocation via the
  linkage entity (IA12 + SI-5; multi-role aware per R6)
- Exclude op: exclusion entity write + layer-1 broad sweep (§6.1, SI-7);
  no body peer_id field (SI-3); revoked_token_hashes in result (SI-9)
- Re-derive op: ordered-write cascade per IA9 + per-assignee RL2
  skip-and-continue (SI-15) with skipped_grantees array
- Delegate op: locality 400 not 403 (SI-19), scope literal-only (SI-20),
  parent via linkage entity tie-broken by issued_at (SI-22), no
  delegator field in request (SI-21)
- Startup-time L0 helper (renamed from bootstrap, SI-28); runtime-check
  refuses post-handler-registration use (SI-12)
- RoleExtension fleet-wide sweep (§6.5 IA8) + IA11 option (b) cascade
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitContext, EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.role import (
    RESERVED_ROLE_NAMES,
    ROLE_ASSIGNMENT_TYPE,
    ROLE_DERIVED_TOKEN_LINK_TYPE,
    ROLE_EXCLUSION_TYPE,
    ROLE_HANDLER_PATTERN,
    ROLE_PREFIX,
    ROLE_TYPE,
    RoleExtension,
    is_excluded,
    parse_assignment_path,
    parse_assignment_peer_path,
    parse_exclusion_path,
    parse_role_definition_path,
    resolve_templates,
    role_assignment_path,
    role_definition_path,
    role_derived_token_link_path,
    role_derived_token_path,
    role_exclusion_path,
    role_handler,
    startup_time_role_derived_token,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class Ctx:
    keypair: Keypair
    pathway: EmitPathway
    handler: HandlerContext


def _full_access_grants() -> list[dict[str, Any]]:
    """Wildcard grant entries that satisfy any RL2 attenuation check.

    Per v1.6 SI-24, V7's grant_subset uses pattern-matching (`*`) for
    operations as well as handlers/resources, so this wildcard covers
    any narrower role grant.
    """
    return [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]


def _hex_id(seed: str) -> str:
    """Generate a deterministic 66-char hex string from a seed.

    Per v1.6 SI-1 + SI-8, peer_id_hex segments are lowercase hex of
    `system/hash` of the assignee's `system/identity` entity (33 bytes
    → 66 hex characters starting with `00` for ECFv1-SHA-256). For
    unit tests the bytes don't need to come from a real identity
    entity — the handler just decodes the hex; cross-impl
    byte-equivalence requires real identity-entity hashes (covered in
    integration tests).
    """
    return "00" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _make_ctx(
    *,
    caller_grants: list[dict[str, Any]] | None = None,
    resource_targets: list[str] | None = None,
) -> Ctx:
    """Build a minimal HandlerContext for direct role_handler() calls."""
    keypair = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(keypair.peer_id)
    pathway = EmitPathway(content_store, entity_tree)
    grants = (
        caller_grants if caller_grants is not None else _full_access_grants()
    )
    handler_ctx = HandlerContext(
        local_peer_id=keypair.peer_id,
        remote_peer_id=keypair.peer_id,
        handler_grant={"grants": _full_access_grants()},
        caller_capability={"grants": grants},
        emit_pathway=pathway,
        handler_pattern="system/role",
        keypair=keypair,
        resource_targets=resource_targets,
    )
    return Ctx(keypair=keypair, pathway=pathway, handler=handler_ctx)


def _local_peer_id_hex(ctx: Ctx) -> str:
    """Compute hex of the local peer's `system/identity` content_hash."""
    return create_identity_entity(ctx.keypair).compute_hash().hex()


def _emit_role_def(
    ctx: Ctx,
    context: str,
    role_name: str,
    grants: list[dict[str, Any]],
) -> None:
    role_entity = Entity(
        type=ROLE_TYPE,
        data={"name": role_name, "grants": grants},
    )
    ctx.pathway.emit(
        role_definition_path(context, role_name),
        role_entity,
        EmitContext.bootstrap(),
    )


def _set_resource(ctx: Ctx, *paths: str) -> None:
    ctx.handler.resource_targets = list(paths)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------


class TestParseRoleDefinitionPath:
    def test_simple_context(self):
        peer_id = "peer-A"
        assert parse_role_definition_path(
            "system/role/admin/operator", peer_id,
        ) == ("admin", "operator")

    def test_multi_segment_context(self):
        assert parse_role_definition_path(
            "system/role/group/team-alpha/member", "peer-A",
        ) == ("group/team-alpha", "member")

    def test_with_local_peer_prefix(self):
        peer_id = "peer-A"
        assert parse_role_definition_path(
            f"/{peer_id}/system/role/admin/operator", peer_id,
        ) == ("admin", "operator")

    def test_with_entity_uri(self):
        peer_id = "peer-A"
        assert parse_role_definition_path(
            f"entity://{peer_id}/system/role/group/g1/member", peer_id,
        ) == ("group/g1", "member")

    def test_rejects_assignment_subtree(self):
        assert parse_role_definition_path(
            f"system/role/admin/assignment/{_hex_id('x')}/operator", "peer-A",
        ) is None

    def test_rejects_excluded_subtree(self):
        assert parse_role_definition_path(
            f"system/role/admin/excluded/{_hex_id('x')}", "peer-A",
        ) is None

    def test_rejects_derived_tokens_subtree(self):
        """SI-5: derived-tokens is a reserved sibling subtree."""
        assert parse_role_definition_path(
            f"system/role/admin/derived-tokens/{_hex_id('x')}/operator",
            "peer-A",
        ) is None

    @pytest.mark.parametrize("reserved", sorted(RESERVED_ROLE_NAMES))
    def test_rejects_reserved_role_name(self, reserved: str):
        assert parse_role_definition_path(
            f"system/role/admin/{reserved}", "peer-A",
        ) is None

    def test_reserved_set_includes_derived_tokens(self):
        assert "derived-tokens" in RESERVED_ROLE_NAMES
        assert "assignment" in RESERVED_ROLE_NAMES
        assert "excluded" in RESERVED_ROLE_NAMES

    def test_rejects_too_short(self):
        assert parse_role_definition_path(
            "system/role/admin", "peer-A",
        ) is None
        assert parse_role_definition_path(
            "system/role/", "peer-A",
        ) is None

    def test_rejects_outside_role_prefix(self):
        assert parse_role_definition_path(
            "system/tree/admin/operator", "peer-A",
        ) is None


class TestParseAssignmentPath:
    def test_simple(self):
        h = _hex_id("x")
        assert parse_assignment_path(
            f"system/role/admin/assignment/{h}/operator", "peer-A",
        ) == ("admin", h, "operator")

    def test_multi_segment_context(self):
        h = _hex_id("x")
        assert parse_assignment_path(
            f"system/role/group/team-alpha/assignment/{h}/member", "peer-A",
        ) == ("group/team-alpha", h, "member")

    def test_rejects_missing_role_name(self):
        h = _hex_id("x")
        assert parse_assignment_path(
            f"system/role/admin/assignment/{h}", "peer-A",
        ) is None

    def test_rejects_extra_segments(self):
        h = _hex_id("x")
        assert parse_assignment_path(
            f"system/role/admin/assignment/{h}/role/extra", "peer-A",
        ) is None

    def test_rejects_no_assignment_marker(self):
        assert parse_assignment_path(
            "system/role/admin/operator", "peer-A",
        ) is None


class TestParseAssignmentPeerPath:
    """Per spec §4.4 unassign supports a per-peer (no role-name) form."""

    def test_simple(self):
        h = _hex_id("x")
        assert parse_assignment_peer_path(
            f"system/role/admin/assignment/{h}", "peer-A",
        ) == ("admin", h)

    def test_multi_segment_context(self):
        h = _hex_id("x")
        assert parse_assignment_peer_path(
            f"system/role/group/team-alpha/assignment/{h}", "peer-A",
        ) == ("group/team-alpha", h)

    def test_rejects_role_bearing_form(self):
        """The role-bearing form is parse_assignment_path's job; the
        per-peer parser MUST NOT accept it (so callers fall through to
        the right branch)."""
        h = _hex_id("x")
        assert parse_assignment_peer_path(
            f"system/role/admin/assignment/{h}/operator", "peer-A",
        ) is None

    def test_rejects_no_assignment_marker(self):
        assert parse_assignment_peer_path(
            "system/role/admin/operator", "peer-A",
        ) is None

    def test_rejects_missing_peer_segment(self):
        assert parse_assignment_peer_path(
            "system/role/admin/assignment/", "peer-A",
        ) is None
        assert parse_assignment_peer_path(
            "system/role/admin/assignment", "peer-A",
        ) is None


class TestParseExclusionPath:
    def test_simple(self):
        h = _hex_id("x")
        assert parse_exclusion_path(
            f"system/role/admin/excluded/{h}", "peer-A",
        ) == ("admin", h)

    def test_multi_segment_context(self):
        h = _hex_id("x")
        assert parse_exclusion_path(
            f"system/role/group/team-alpha/excluded/{h}", "peer-A",
        ) == ("group/team-alpha", h)

    def test_rejects_extra_segments(self):
        h = _hex_id("x")
        assert parse_exclusion_path(
            f"system/role/admin/excluded/{h}/extra", "peer-A",
        ) is None

    def test_rejects_no_excluded_marker(self):
        assert parse_exclusion_path(
            "system/role/admin/operator", "peer-A",
        ) is None


# ---------------------------------------------------------------------------
# Template resolution
# ---------------------------------------------------------------------------


class TestResolveTemplates:
    def test_substitutes_context_in_resources(self):
        grant = {
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["shared/{context}/*"]},
            "operations": {"include": ["get"]},
        }
        out = resolve_templates(grant, {"context": "group/team-alpha"})
        assert out["resources"]["include"] == ["shared/group/team-alpha/*"]
        # Original is unchanged.
        assert grant["resources"]["include"] == ["shared/{context}/*"]

    def test_substitutes_peer_id_to_hex(self):
        """SI-1: {peer_id} substitutes to the hex form (NOT a Base58 string)."""
        h = _hex_id("bob")
        grant = {
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["users/{peer_id}/*"]},
            "operations": {"include": ["put"]},
        }
        out = resolve_templates(grant, {"peer_id": h})
        assert out["resources"]["include"] == [f"users/{h}/*"]

    def test_substitutes_in_handlers_scope(self):
        grant = {
            "handlers": {"include": ["{context}/svc"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
        out = resolve_templates(grant, {"context": "group/g1"})
        assert out["handlers"]["include"] == ["group/g1/svc"]

    def test_substitutes_in_exclude(self):
        grant = {
            "handlers": {"include": ["system/tree"]},
            "resources": {
                "include": ["shared/{context}/*"],
                "exclude": ["shared/{context}/secrets"],
            },
            "operations": {"include": ["get"]},
        }
        out = resolve_templates(grant, {"context": "group/g1"})
        assert out["resources"]["exclude"] == ["shared/group/g1/secrets"]

    def test_does_not_touch_operations_or_constraints(self):
        grant = {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["{context}"]},
            "operations": {"include": ["{context}"]},  # left literal
            "constraints": {"key": "{context}"},        # left literal
        }
        out = resolve_templates(grant, {"context": "x"})
        assert out["resources"]["include"] == ["x"]
        assert out["operations"]["include"] == ["{context}"]
        assert out["constraints"]["key"] == "{context}"


# ---------------------------------------------------------------------------
# is_excluded helper
# ---------------------------------------------------------------------------


class TestIsExcluded:
    def test_returns_false_when_no_exclusion(self):
        ctx = _make_ctx()
        assert is_excluded("admin", _hex_id("x"), ctx.handler) is False

    def test_returns_true_when_exclusion_present(self):
        ctx = _make_ctx()
        h = _hex_id("x")
        # Per v1.6 SI-3, the exclusion entity has no body `peer_id` field.
        excl = Entity(
            type=ROLE_EXCLUSION_TYPE,
            data={"excluded_by": b"author", "excluded_at": 0},
        )
        ctx.pathway.emit(
            role_exclusion_path("admin", h), excl, EmitContext.bootstrap(),
        )
        assert is_excluded("admin", h, ctx.handler) is True

    def test_independent_per_context(self):
        ctx = _make_ctx()
        h = _hex_id("x")
        excl = Entity(
            type=ROLE_EXCLUSION_TYPE,
            data={"excluded_by": b"a", "excluded_at": 0},
        )
        ctx.pathway.emit(
            role_exclusion_path("admin", h), excl, EmitContext.bootstrap(),
        )
        assert is_excluded("admin", h, ctx.handler) is True
        assert is_excluded("group/g1", h, ctx.handler) is False


# ---------------------------------------------------------------------------
# Define op
# ---------------------------------------------------------------------------


class TestDefineOp:
    def test_writes_role_definition(self):
        ctx = _make_ctx()
        path = role_definition_path("admin", "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "define",
            {"data": {"grants": _full_access_grants()}}, ctx.handler,
        ))
        assert result["status"] == 200
        h = ctx.pathway.entity_tree.get(path)
        assert h is not None
        entity = ctx.pathway.content_store.get(h)
        assert entity.type == ROLE_TYPE
        assert entity.data["name"] == "operator"
        assert entity.data["grants"] == _full_access_grants()

    def test_rejects_missing_resource_target(self):
        ctx = _make_ctx()
        result = _run(role_handler(
            "system/role/admin/operator", "define",
            {"data": {"grants": _full_access_grants()}}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "path_required"

    def test_rejects_reserved_role_name(self):
        ctx = _make_ctx()
        path = "system/role/admin/assignment"
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "define",
            {"data": {"grants": _full_access_grants()}}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "malformed_resource"

    def test_rejects_derived_tokens_role_name(self):
        """SI-5: `derived-tokens` is reserved alongside assignment/excluded."""
        ctx = _make_ctx()
        path = "system/role/admin/derived-tokens"
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "define",
            {"data": {"grants": _full_access_grants()}}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "malformed_resource"

    def test_rejects_empty_grants(self):
        ctx = _make_ctx()
        path = role_definition_path("admin", "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "define", {"data": {"grants": []}}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"

    def test_rl2_fail_closed_when_caller_undercovers(self):
        """A caller with read-only access cannot define a write-granting role."""
        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["get"]},
            }
        ]
        ctx = _make_ctx(caller_grants=narrow)
        path = role_definition_path("admin", "operator")
        _set_resource(ctx, path)
        wide_grants = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["put"]},
            }
        ]
        result = _run(role_handler(
            path, "define",
            {"data": {"grants": wide_grants}}, ctx.handler,
        ))
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "assigner_authority_insufficient"

    def test_rl2_passes_when_caller_covers(self):
        ctx = _make_ctx()  # full-access caller
        path = role_definition_path("admin", "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "define",
            {"data": {"grants": _full_access_grants()}}, ctx.handler,
        ))
        assert result["status"] == 200
        # Re-derive cascade ran (no assignments yet → count 0).
        assert result["result"]["data"]["re_derived_count"] == 0

    def test_si24_wildcard_caller_covers_narrower_role_ops(self):
        """SI-24: wildcard `operations: ["*"]` parent covers narrower
        operations like `["get", "put"]` via pattern matching."""
        ctx = _make_ctx()  # full-access caller (operations: ["*"])
        path = role_definition_path("admin", "operator")
        _set_resource(ctx, path)
        narrow_role = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["get", "put"]},
            }
        ]
        result = _run(role_handler(
            path, "define", {"data": {"grants": narrow_role}}, ctx.handler,
        ))
        # Pre-SI-24 this would return 403 (set.issubset({"get","put"},{"*"})
        # is False). With SI-24 fix, matches_pattern("get", "*") is True.
        assert result["status"] == 200

    def test_define_under_broad_caller_cap_with_finite_expiry(self):
        """Cross-impl tv_rd_caller_expiry_inheritance shape: caller cap
        has broad wildcards `["*"]` for handlers/resources/operations
        AND a finite `expires_at`. RL2 hypothetical's `expires_at` is
        bound by the caller per v1.7 §5.3 (caller-only at define time;
        parent + role.ttl come in at assign). RL2 must accept the broad
        caller cap and `:define` must return 200."""
        now = 1_700_000_000_000
        broad_caller = [
            {
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }
        ]
        ctx = _make_ctx(caller_grants=broad_caller)
        # Mirror validate-peer's cap mint: broad grants + finite expiry.
        ctx.handler.caller_capability = {
            "grants": broad_caller,
            "expires_at": now + 3_600_000,
        }
        path = role_definition_path("tv-rd-caller-expiry", "reader")
        _set_resource(ctx, path)
        narrow_role = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["system/validate/role-test/*"]},
                "operations": {"include": ["get"]},
            }
        ]
        result = _run(role_handler(
            path, "define", {"data": {"grants": narrow_role}}, ctx.handler,
        ))
        assert result["status"] == 200, result


# ---------------------------------------------------------------------------
# Assign op
# ---------------------------------------------------------------------------


class TestAssignOp:
    def test_404_when_role_not_defined(self):
        ctx = _make_ctx()
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "role_not_found"

    def test_role_param_must_match_path_segment(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "auditor"}}, ctx.handler,
        ))
        # SI-25: 400 invalid_request on selector-vs-path mismatch.
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_request"

    def test_writes_assignment_and_derives_token(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 200
        assignment_h = ctx.pathway.entity_tree.get(path)
        assert assignment_h is not None
        assignment = ctx.pathway.content_store.get(assignment_h)
        assert assignment.type == ROLE_ASSIGNMENT_TYPE
        assert assignment.data["role"] == "operator"
        # Derived token is at the spec-pinned R4 path.
        token_hash = result["result"]["data"]["derived_tokens"][0]
        token_path = role_derived_token_path("admin", h, token_hash)
        assert ctx.pathway.entity_tree.get(token_path) == token_hash
        # SI-8: cap grantee == bytes.fromhex(peer_id_hex).
        token_entity = ctx.pathway.content_store.get(token_hash)
        assert token_entity.data["grantee"] == bytes.fromhex(h)

    def test_assigned_cap_inherits_caller_expiry_min_defined(self):
        """v1.7 §5.3 (SI-29): role-derived cap's `expires_at` is bound by
        MIN_DEFINED(parent.expires_at, role.ttl, caller.expires_at). When
        caller has finite expiry and role has no ttl, the minted cap's
        expires_at MUST equal the caller's expiry. This is the post-state
        cross-impl tv_rd_caller_expiry_inheritance asserts."""
        now = 1_700_000_000_000
        caller_exp = now + 3_600_000
        broad_caller = [
            {
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }
        ]
        ctx = _make_ctx(caller_grants=broad_caller)
        ctx.handler.caller_capability = {
            "grants": broad_caller,
            "expires_at": caller_exp,
        }
        # Role has no metadata.ttl; only the caller bound applies.
        _emit_role_def(ctx, "tv-rd-caller-expiry", "reader", [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["system/validate/role-test/*"]},
                "operations": {"include": ["get"]},
            }
        ])
        h = _local_peer_id_hex(ctx)
        apath = role_assignment_path("tv-rd-caller-expiry", h, "reader")
        _set_resource(ctx, apath)
        result = _run(role_handler(
            apath, "assign", {"data": {"role": "reader"}}, ctx.handler,
        ))
        assert result["status"] == 200, result
        token_hash = result["result"]["data"]["derived_tokens"][0]
        tok = ctx.pathway.content_store.get(token_hash)
        assert tok.data.get("expires_at") is not None, (
            "§5.3 v1.7 BYPASSED — minted cap has nil expires_at despite "
            "finite caller-cap expiry"
        )
        assert tok.data["expires_at"] <= caller_exp, (
            f"minted cap expires at {tok.data['expires_at']}, caller cap "
            f"expires at {caller_exp}; cap MUST NOT outlive caller"
        )

    def test_pr1_role_derived_cap_is_root(self):
        """TV-RD-NON-DEV-PEER (v2.0 §5.1 PR-1): runtime role-derived caps
        are root caps — `parent` is absent and `granter` is the local
        peer's identity content_hash. Use-time chain validation
        terminates at the cap, so a narrow handler grant no longer
        breaks attenuation."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 200
        token_hash = result["result"]["data"]["derived_tokens"][0]
        tok = ctx.pathway.content_store.get(token_hash)
        # Root-cap shape: no parent, granter is local peer's identity hash.
        assert "parent" not in tok.data, (
            "v2.0 PR-1: runtime role-derived caps MUST be root (no parent); "
            "got parent=" + repr(tok.data.get("parent"))
        )
        local_id_hash = create_identity_entity(ctx.keypair).compute_hash()
        assert tok.data["granter"] == local_id_hash

    def test_writes_linkage_entity_at_sibling_subtree(self):
        """SI-5: linkage entity at `derived-tokens/{peer_id_hex}/{role}`,
        NOT nested under the assignment path.
        """
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        token_hash = result["result"]["data"]["derived_tokens"][0]
        link_path = role_derived_token_link_path("admin", h, "operator")
        # Linkage entity must exist.
        link_h = ctx.pathway.entity_tree.get(link_path)
        assert link_h is not None
        link_entity = ctx.pathway.content_store.get(link_h)
        assert link_entity.type == ROLE_DERIVED_TOKEN_LINK_TYPE
        assert link_entity.data["token_hash"] == token_hash
        assert isinstance(link_entity.data["issued_at"], int)

    def test_sec18_rejects_zero_hash_assignee(self):
        """SEC-18 / V7 v7.39 PR-3: zero-hash assignee MUST be rejected at
        the role layer (defense-in-depth before chain-walk's
        `unresolvable_grantee 401`). Mirrors Go's `info.PeerHash.IsZero()`
        guard in `handleAssign`. Prevents a dud cap from binding under an
        unusable grantee — chain-walk would later reject the cap, but the
        assign appears successful in the meantime, creating an audit-trail
        confusion."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        zero_hex = "00" + "00" * 32  # algorithm + 32-byte zero digest
        path = role_assignment_path("admin", zero_hex, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 400, result
        assert result["result"]["data"]["code"] == "invalid_assign_request"
        # No assignment / cap left bound.
        assert ctx.pathway.entity_tree.get(path) is None

    def test_pr2_sec2_post_issue_rollback_on_assign(self):
        """TV-RD-RACE-AE (v2.0 §6.6 SEC-2): if an exclusion entity
        lands between the pre-check and the post-issue re-check during
        `:assign`, the freshly-issued cap MUST be rolled back. Forbidden
        terminal state: exclusion bound + cap also bound.

        The race is forced deterministically by writing the exclusion
        entity directly into the tree between the pre-check (which sees
        nothing) and the post-issue re-check (which now sees it). Real
        deployments hit this via concurrent `:exclude` from another
        operational key."""
        from unittest.mock import patch
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("racy")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)

        # Inject exclusion AFTER the pre-check passes but BEFORE the
        # post-issue re-check fires. Hook on _write_derived_token_link
        # — that's the last step before the SEC-2 re-check.
        from entity_handlers import role as role_mod
        original_write = role_mod._write_derived_token_link
        def racy_write(*args, **kwargs):
            original_write(*args, **kwargs)
            # Concurrent exclude-handler arrives now.
            ctx.pathway.emit(
                role_exclusion_path("admin", h),
                Entity(type=ROLE_EXCLUSION_TYPE,
                       data={"excluded_by": b"a", "excluded_at": 0}),
                EmitContext.bootstrap(),
            )
        with patch.object(role_mod, "_write_derived_token_link", racy_write):
            result = _run(role_handler(
                path, "assign", {"data": {"role": "operator"}}, ctx.handler,
            ))

        # Post-issue re-check fires → 403 + rollback.
        assert result["status"] == 403, result
        assert result["result"]["data"]["code"] == "assignee_excluded"
        # Forbidden terminal state never observable: no role-derived cap
        # bound under the assignee's path.
        prefix = f"system/capability/grants/role-derived/admin/{h}/"
        bound = list(ctx.pathway.entity_tree.list_prefix(prefix))
        assert bound == [], (
            f"SEC-2 violation: cap survived rollback under {prefix}: {bound}"
        )
        # Linkage and assignment entities also rolled back.
        link_path = role_derived_token_link_path("admin", h, "operator")
        assert ctx.pathway.entity_tree.get(link_path) is None
        assert ctx.pathway.entity_tree.get(path) is None

    def test_blocks_excluded_assignee_layer_2(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        excl = Entity(
            type=ROLE_EXCLUSION_TYPE,
            data={"excluded_by": b"a", "excluded_at": 0},
        )
        ctx.pathway.emit(
            role_exclusion_path("admin", h), excl, EmitContext.bootstrap(),
        )
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "assignee_excluded"

    def test_rl2_fail_closed_against_role_grants(self):
        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["get"]},
            }
        ]
        ctx = _make_ctx(caller_grants=narrow)
        wider_role_grants = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["private/*"]},
                "operations": {"include": ["put"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", wider_role_grants)
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "assigner_authority_insufficient"

    def test_template_substitution_in_derived_grants(self):
        """SI-1: {peer_id} in role-def grants substitutes to peer_id_hex."""
        templated = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": [
                    "shared/{context}/*", "users/{peer_id}/*",
                ]},
                "operations": {"include": ["get", "put"]},
            }
        ]
        ctx = _make_ctx()  # wildcard caller covers narrower ops post SI-24.
        _emit_role_def(ctx, "group/team-alpha", "member", templated)
        h = _hex_id("bob")
        path = role_assignment_path("group/team-alpha", h, "member")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "assign",
            {"data": {"role": "member"}}, ctx.handler,
        ))
        assert result["status"] == 200
        token_hash = result["result"]["data"]["derived_tokens"][0]
        token_path = role_derived_token_path("group/team-alpha", h, token_hash)
        token_h = ctx.pathway.entity_tree.get(token_path)
        token_entity = ctx.pathway.content_store.get(token_h)
        resources = token_entity.data["grants"][0]["resources"]["include"]
        assert "shared/group/team-alpha/*" in resources
        assert f"users/{h}/*" in resources


# ---------------------------------------------------------------------------
# Unassign op (multi-role aware via linkage entity, SI-5 / IA12)
# ---------------------------------------------------------------------------


class TestUnassignOp:
    def test_removes_assignment_and_revokes_specific_role_token(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        assign_res = _run(role_handler(
            path, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        token_hash = assign_res["result"]["data"]["derived_tokens"][0]
        token_path = role_derived_token_path("admin", h, token_hash)
        link_path = role_derived_token_link_path("admin", h, "operator")
        assert ctx.pathway.entity_tree.get(token_path) is not None
        assert ctx.pathway.entity_tree.get(link_path) is not None

        result = _run(role_handler(path, "unassign", {}, ctx.handler))
        assert result["status"] == 200
        # SI-9 dedicated unassign-result type carries
        # {assignment_path, revoked_token_hashes}.
        assert result["result"]["type"] == "system/role/unassign-result"
        assert result["result"]["data"]["assignment_path"] == path
        assert token_hash in result["result"]["data"]["revoked_token_hashes"]
        # Both the assignment and the linkage entity are removed.
        assert ctx.pathway.entity_tree.get(path) is None
        assert ctx.pathway.entity_tree.get(token_path) is None
        assert ctx.pathway.entity_tree.get(link_path) is None

    def test_unassign_idempotent_when_no_assignment(self):
        ctx = _make_ctx()
        h = _hex_id("bob")
        path = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(path, "unassign", {}, ctx.handler))
        assert result["status"] == 200
        # No assignment / no token to revoke — empty list, but the
        # result still echoes the requested path.
        assert result["result"]["data"]["assignment_path"] == path
        assert result["result"]["data"]["revoked_token_hashes"] == []

    def test_multi_role_unassign_only_revokes_named_role(self):
        """R6 + SI-5: unassign(peer, operator) must NOT revoke the
        peer's auditor token. The linkage entity at
        `derived-tokens/{peer_id_hex}/{role_name}` makes selective
        revocation precise.
        """
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        # Auditor: a slightly narrower set so the minted caps differ.
        _emit_role_def(
            ctx, "admin", "auditor",
            [
                {
                    "handlers": {"include": ["system/tree"]},
                    "resources": {"include": ["audit/*"]},
                    "operations": {"include": ["*"]},
                }
            ],
        )
        h = _hex_id("bob")
        for role_name in ("operator", "auditor"):
            apath = role_assignment_path("admin", h, role_name)
            _set_resource(ctx, apath)
            res = _run(role_handler(
                apath, "assign", {"data": {"role": role_name}}, ctx.handler,
            ))
            assert res["status"] == 200

        # Operator and auditor linkages should both exist.
        op_link = ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h, "operator"),
        )
        au_link = ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h, "auditor"),
        )
        assert op_link is not None and au_link is not None

        # Unassign only operator.
        unpath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, unpath)
        _run(role_handler(unpath, "unassign", {}, ctx.handler))

        # Operator gone; auditor survives.
        assert ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h, "operator"),
        ) is None
        assert ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h, "auditor"),
        ) is not None

    def test_unassign_all_roles_form_per_peer(self):
        """Spec §4.4 (TV-RD-17): the resource path
        `system/role/{context}/assignment/{peer_id_hex}` (no trailing
        role segment) removes ALL of a peer's assignments in the
        context, with each role's role-derived cap revoked."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        # Auditor with distinct grants so the minted caps' content
        # hashes differ from operator's.
        _emit_role_def(
            ctx, "admin", "auditor",
            [
                {
                    "handlers": {"include": ["system/tree"]},
                    "resources": {"include": ["audit/*"]},
                    "operations": {"include": ["*"]},
                }
            ],
        )
        h = _hex_id("bob")
        # Assign two roles for the same peer in the same context.
        token_hashes = []
        for role_name in ("operator", "auditor"):
            apath = role_assignment_path("admin", h, role_name)
            _set_resource(ctx, apath)
            res = _run(role_handler(
                apath, "assign", {"data": {"role": role_name}}, ctx.handler,
            ))
            assert res["status"] == 200
            token_hashes.extend(res["result"]["data"]["derived_tokens"])

        # Per-peer unassign form (no trailing role).
        per_peer = f"{ROLE_PREFIX}admin/assignment/{h}"
        _set_resource(ctx, per_peer)
        result = _run(role_handler(per_peer, "unassign", {}, ctx.handler))
        assert result["status"] == 200, result
        assert result["result"]["type"] == "system/role/unassign-result"
        # `assignment_path` echoes the per-peer form (not a synthesized
        # role-bearing path).
        assert result["result"]["data"]["assignment_path"] == per_peer
        # Both tokens reported revoked.
        revoked = result["result"]["data"]["revoked_token_hashes"]
        for t in token_hashes:
            assert t in revoked, (
                f"expected {t.hex()} in revoked set {[r.hex() for r in revoked]}"
            )

        # Both assignment entities + linkage entities + role-derived caps
        # are gone.
        for role_name in ("operator", "auditor"):
            assert ctx.pathway.entity_tree.get(
                role_assignment_path("admin", h, role_name),
            ) is None
            assert ctx.pathway.entity_tree.get(
                role_derived_token_link_path("admin", h, role_name),
            ) is None
        for t in token_hashes:
            assert ctx.pathway.entity_tree.get(
                role_derived_token_path("admin", h, t),
            ) is None

    def test_unassign_all_roles_form_idempotent_when_no_assignments(self):
        """Per-peer unassign on a peer with no assignments is a no-op
        and returns 200 with empty `revoked_token_hashes`."""
        ctx = _make_ctx()
        h = _hex_id("nobody")
        per_peer = f"{ROLE_PREFIX}admin/assignment/{h}"
        _set_resource(ctx, per_peer)
        result = _run(role_handler(per_peer, "unassign", {}, ctx.handler))
        assert result["status"] == 200
        assert result["result"]["data"]["assignment_path"] == per_peer
        assert result["result"]["data"]["revoked_token_hashes"] == []

    def test_unassign_all_roles_does_not_touch_other_peers_in_same_context(
        self,
    ):
        """The peer-id-segment scoping must be tight — unassigning all
        of bob's roles in admin must NOT touch carol's roles in admin."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h_bob = _hex_id("bob")
        h_carol = _hex_id("carol")
        for assignee in (h_bob, h_carol):
            apath = role_assignment_path("admin", assignee, "operator")
            _set_resource(ctx, apath)
            res = _run(role_handler(
                apath, "assign",
                {"data": {"role": "operator"}}, ctx.handler,
            ))
            assert res["status"] == 200
        carol_link_before = ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h_carol, "operator"),
        )
        assert carol_link_before is not None

        per_peer_bob = f"{ROLE_PREFIX}admin/assignment/{h_bob}"
        _set_resource(ctx, per_peer_bob)
        result = _run(role_handler(per_peer_bob, "unassign", {}, ctx.handler))
        assert result["status"] == 200
        # Bob's gone; carol's intact.
        assert ctx.pathway.entity_tree.get(
            role_assignment_path("admin", h_bob, "operator"),
        ) is None
        assert ctx.pathway.entity_tree.get(
            role_assignment_path("admin", h_carol, "operator"),
        ) is not None
        assert ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h_carol, "operator"),
        ) == carol_link_before


# ---------------------------------------------------------------------------
# Exclude / unexclude
# ---------------------------------------------------------------------------


class TestExcludeOp:
    def test_writes_exclusion_and_sweeps_role_derived_tokens(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        token_hash = assign_res["result"]["data"]["derived_tokens"][0]
        token_path = role_derived_token_path("admin", h, token_hash)
        assert ctx.pathway.entity_tree.get(token_path) is not None

        excl_path = role_exclusion_path("admin", h)
        _set_resource(ctx, excl_path)
        result = _run(role_handler(
            excl_path, "exclude",
            {"data": {"reason": "evicted"}}, ctx.handler,
        ))
        assert result["status"] == 200
        excl_h = ctx.pathway.entity_tree.get(excl_path)
        excl_entity = ctx.pathway.content_store.get(excl_h)
        assert excl_entity.type == ROLE_EXCLUSION_TYPE
        assert excl_entity.data["reason"] == "evicted"
        # SI-3: NO `peer_id` field in exclusion body. Path is canonical.
        assert "peer_id" not in excl_entity.data
        # SI-9: `revoked_token_hashes` (renamed from `revoked_tokens`).
        assert token_hash in result["result"]["data"]["revoked_token_hashes"]
        # Layer-1 broad sweep deleted the cap.
        assert ctx.pathway.entity_tree.get(token_path) is None
        # Layer 2: subsequent assigns blocked.
        _set_resource(ctx, apath)
        retry = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert retry["status"] == 403
        assert retry["result"]["data"]["code"] == "assignee_excluded"

    def test_rejects_malformed_resource(self):
        ctx = _make_ctx()
        _set_resource(ctx, "system/role/admin/operator")
        result = _run(role_handler(
            "system/role/admin/operator", "exclude", {}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "malformed_resource"


class TestUnexcludeOp:
    def test_removes_exclusion(self):
        ctx = _make_ctx()
        h = _hex_id("bob")
        excl_path = role_exclusion_path("admin", h)
        excl = Entity(
            type=ROLE_EXCLUSION_TYPE,
            data={"excluded_by": b"a", "excluded_at": 0},
        )
        ctx.pathway.emit(excl_path, excl, EmitContext.bootstrap())
        _set_resource(ctx, excl_path)
        result = _run(role_handler(excl_path, "unexclude", {}, ctx.handler))
        assert result["status"] == 200
        # SI-9 dedicated unexclude-result type carries {exclusion_path}.
        assert result["result"]["type"] == "system/role/unexclude-result"
        assert result["result"]["data"]["exclusion_path"] == excl_path
        assert ctx.pathway.entity_tree.get(excl_path) is None

    def test_idempotent_when_no_exclusion(self):
        ctx = _make_ctx()
        h = _hex_id("bob")
        excl_path = role_exclusion_path("admin", h)
        _set_resource(ctx, excl_path)
        result = _run(role_handler(excl_path, "unexclude", {}, ctx.handler))
        assert result["status"] == 200
        assert result["result"]["data"]["exclusion_path"] == excl_path


# ---------------------------------------------------------------------------
# Re-derive op (per-assignee RL2 + skipped_grantees per SI-15)
# ---------------------------------------------------------------------------


class TestReDeriveOp:
    def test_404_when_role_not_defined(self):
        ctx = _make_ctx()
        path = role_definition_path("admin", "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "re-derive", {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "role_not_found"

    def test_re_derive_walks_assignments_and_revokes_old_token(self):
        ctx = _make_ctx()
        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", narrow)
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        old_token = assign_res["result"]["data"]["derived_tokens"][0]
        old_path = role_derived_token_path("admin", h, old_token)
        assert ctx.pathway.entity_tree.get(old_path) == old_token

        wider = [
            {
                "handlers": {"include": ["system/tree", "system/query"]},
                "resources": {"include": ["public/*", "private/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", wider)
        rd_path = role_definition_path("admin", "operator")
        _set_resource(ctx, rd_path)
        result = _run(role_handler(
            rd_path, "re-derive",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 200
        data = result["result"]["data"]
        assert data["re_derived_count"] == 1
        new_token = data["new_token_hashes"][0]
        new_path = role_derived_token_path("admin", h, new_token)
        assert ctx.pathway.entity_tree.get(new_path) == new_token
        assert ctx.pathway.entity_tree.get(old_path) is None
        assert old_token in data["revoked_token_hashes"]
        # Linkage entity now points to T_new.
        link_h = ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h, "operator"),
        )
        link_entity = ctx.pathway.content_store.get(link_h)
        assert link_entity.data["token_hash"] == new_token
        # SI-15: empty skipped_grantees on the success path.
        assert data["skipped_grantees"] == []

    def test_skip_excluded_assignees(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h_bob = _hex_id("bob")
        h_carol = _hex_id("carol")
        for assignee in (h_bob, h_carol):
            apath = role_assignment_path("admin", assignee, "operator")
            _set_resource(ctx, apath)
            res = _run(role_handler(
                apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
            ))
            assert res["status"] == 200
        # Exclude bob.
        ctx.pathway.emit(
            role_exclusion_path("admin", h_bob),
            Entity(type=ROLE_EXCLUSION_TYPE,
                   data={"excluded_by": b"a", "excluded_at": 0}),
            EmitContext.bootstrap(),
        )
        _emit_role_def(
            ctx, "admin", "operator",
            [{
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["wider/*"]},
                "operations": {"include": ["*"]},
            }],
        )
        rd_path = role_definition_path("admin", "operator")
        _set_resource(ctx, rd_path)
        result = _run(role_handler(
            rd_path, "re-derive",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        # Excluded assignees are silently dropped (NOT in skipped_grantees
        # — that's reserved for RL2 mid-cascade failures per SI-15).
        assert result["result"]["data"]["re_derived_count"] == 1

    def test_pr2_sec2_post_issue_rollback_on_re_derive_cascade(self):
        """SEC-2 (cascade leg): if `:exclude(assignee)` lands during the
        per-assignee re-derive issue → write-link → revoke-T_old window,
        the freshly-issued T_new MUST be rolled back. Forbidden terminal
        state: exclusion bound + new role-derived cap also bound.

        Forces the race deterministically by hooking
        `_write_derived_token_link` (the last write before the per-leg
        SEC-2 re-check) — same shape as the assign-path test."""
        from unittest.mock import patch
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("victim")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert assign_res["status"] == 200
        old_token = assign_res["result"]["data"]["derived_tokens"][0]

        # Mutate role definition so re-derive triggers re-issue.
        _emit_role_def(ctx, "admin", "operator", [
            {
                "handlers": {"include": ["system/tree", "system/query"]},
                "resources": {"include": ["public/*", "private/*"]},
                "operations": {"include": ["*"]},
            }
        ])

        from entity_handlers import role as role_mod
        original_write = role_mod._write_derived_token_link

        def racy_write(*args, **kwargs):
            original_write(*args, **kwargs)
            ctx.pathway.emit(
                role_exclusion_path("admin", h),
                Entity(type=ROLE_EXCLUSION_TYPE,
                       data={"excluded_by": b"a", "excluded_at": 0}),
                EmitContext.bootstrap(),
            )

        rd_path = role_definition_path("admin", "operator")
        _set_resource(ctx, rd_path)
        with patch.object(role_mod, "_write_derived_token_link", racy_write):
            result = _run(role_handler(
                rd_path, "re-derive",
                {"data": {"role": "operator"}}, ctx.handler,
            ))
        assert result["status"] == 200, result
        data = result["result"]["data"]
        # SEC-2 rollback path: the leg is treated as a skipped grantee
        # (consistent with mid-cascade RL2 fail per SI-15).
        assert data["re_derived_count"] == 0
        assert bytes.fromhex(h) in data["skipped_grantees"]
        # Forbidden terminal state never observable: no role-derived cap
        # bound under the assignee's path.
        prefix = f"system/capability/grants/role-derived/admin/{h}/"
        bound = list(ctx.pathway.entity_tree.list_prefix(prefix))
        assert bound == [], (
            f"SEC-2 violation: cap survived rollback under {prefix}: {bound}"
        )
        # Old token also revoked (cascade revokes T_old before SEC-2
        # re-check fires).
        old_path = role_derived_token_path("admin", h, old_token)
        assert ctx.pathway.entity_tree.get(old_path) is None

    def test_si15_per_assignee_rl2_skip_and_continue(self):
        """SI-15: when RL2 fails for ONE assignee mid-cascade, that
        assignee retains T_old and is reported in `skipped_grantees`;
        the cascade continues for OTHER assignees.

        Use a `users/{peer_id}/*` template — a narrow caller covers
        `users/<bob>/*` but not `users/<carol>/*`. We set up the
        assignments with full-access caller, then drive the cascade
        helper directly with the narrow caller_grants to exercise the
        per-assignee RL2 check.
        """
        h_bob = _hex_id("bob")
        h_carol = _hex_id("carol")
        # Setup with wildcard caller so both assigns succeed.
        ctx = _make_ctx()
        templated = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["users/{peer_id}/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", templated)
        for assignee in (h_bob, h_carol):
            apath = role_assignment_path("admin", assignee, "operator")
            _set_resource(ctx, apath)
            res = _run(role_handler(
                apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
            ))
            assert res["status"] == 200

        # Drive cascade with a narrow caller-grants set that covers
        # bob's resolved grants but not carol's.
        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": [f"users/{h_bob}/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        from entity_handlers.role import _re_derive_role_internal
        cascade = _re_derive_role_internal(
            ctx.pathway, ctx.keypair,
            context="admin", role_name="operator",
            parent_hash=None,
            caller_grants=narrow,
            local_peer_id_for_attenuation=ctx.handler.local_peer_id,
            operation="re-derive",
        )
        # Only bob succeeded (his resolved `users/<bob>/*` is covered).
        assert cascade["re_derived_count"] == 1
        # Carol is in skipped_grantees, as raw bytes.
        carol_bytes = bytes.fromhex(h_carol)
        assert carol_bytes in cascade["skipped_grantees"]
        bob_bytes = bytes.fromhex(h_bob)
        assert bob_bytes not in cascade["skipped_grantees"]


class TestDefineCascade:
    def test_define_cascades_re_derive(self):
        ctx = _make_ctx()
        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", narrow)
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        old_token = assign_res["result"]["data"]["derived_tokens"][0]

        wider = [
            {
                "handlers": {"include": ["system/tree", "system/query"]},
                "resources": {"include": ["public/*", "private/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        rd_path = role_definition_path("admin", "operator")
        _set_resource(ctx, rd_path)
        result = _run(role_handler(
            rd_path, "define", {"data": {"grants": wider}}, ctx.handler,
        ))
        assert result["status"] == 200
        assert result["result"]["data"]["re_derived_count"] == 1
        old_path = role_derived_token_path("admin", h, old_token)
        assert ctx.pathway.entity_tree.get(old_path) is None


# ---------------------------------------------------------------------------
# Delegate op (SI-19, SI-20, SI-21, SI-22)
# ---------------------------------------------------------------------------


class TestDelegateOp:
    def test_si19_400_not_403_when_delegator_not_local(self):
        """SI-19: delegator-must-be-local-peer is a precondition error
        (400), not an authorization error (403)."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        # Use an arbitrary hex that doesn't equal the local peer's hash.
        not_local = _hex_id("not-the-local-peer")
        path = role_assignment_path("admin", not_local, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "delegate",
            {"data": {
                "delegate": _hex_id("charlie"),
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "delegator_must_be_local_peer"

    def test_si19_path_delegator_must_match_local_identity(self):
        """SI-19 (EXTENSION-ROLE §5.6.0): the locality invariant is
        enforced via the resource path's delegator segment, not the
        wire-transport peer. A wire-distinct caller is acceptable as
        long as the path encodes the local peer's identity hash; the
        handler signs the issued cap with the local keypair by
        construction. (Cross-impl: Go's
        `acme_14_1_delegate_under_controller_cap` fixture signs with
        the target peer's keypair and sends over an existing admin
        connection — Rust + Go accept; Python now matches.)"""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        # Wire-distinct caller — but the path encodes the local peer.
        ctx.handler.remote_peer_id = "wire-distinct-peer"
        local_hex = _local_peer_id_hex(ctx)
        path = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, path)
        # No assignment exists yet → expect 404 assignment_not_found
        # (NOT 400 delegator_must_be_local_peer — the locality rule
        # passes because the path's delegator IS the local peer).
        result = _run(role_handler(
            path, "delegate",
            {"data": {
                "delegate": _hex_id("charlie"),
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "assignment_not_found"

    def test_404_when_assignment_missing(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        # Use the local peer's hash as the path's delegator segment so
        # the locality check passes; assignment doesn't exist.
        local_hex = _local_peer_id_hex(ctx)
        path = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, path)
        result = _run(role_handler(
            path, "delegate",
            {"data": {
                "delegate": _hex_id("charlie"),
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 404
        assert result["result"]["data"]["code"] == "assignment_not_found"

    def test_happy_path_local_peer(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        # Local peer holds the role.
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        parent_token = assign_res["result"]["data"]["derived_tokens"][0]

        # Delegate full access to charlie.
        c_hex = _hex_id("charlie")
        _set_resource(ctx, apath)
        result = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": c_hex,
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 200
        del_hash = result["result"]["data"]["delegation_token_hash"]
        del_path = role_derived_token_path("admin", c_hex, del_hash)
        assert ctx.pathway.entity_tree.get(del_path) == del_hash
        # Parent of the delegation cap == delegator's role-derived cap (SI-22).
        del_entity = ctx.pathway.content_store.get(del_hash)
        assert del_entity.data["parent"] == parent_token
        # SI-8: cap grantee is bytes.fromhex(delegate_peer_id_hex).
        assert del_entity.data["grantee"] == bytes.fromhex(c_hex)

    def test_delegate_accepts_byte_string_hash(self):
        """Per V7 / EXTENSION-ATTESTATION wire form: the `delegate`
        field is a 33-byte system/hash (algorithm + digest) byte string.
        Python MUST accept it; the hex string remains accepted for
        backward compat. Cross-impl: Go's
        `acme_14_1_delegate_under_controller_cap` sends the byte form."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))

        # Build the delegate's hash as a 33-byte system/hash (0x00 +
        # 32-byte digest), matching the wire form Go uses.
        c_hex = _hex_id("charlie")
        c_bytes = bytes.fromhex(c_hex)
        assert len(c_bytes) == 33  # algorithm + sha256 digest

        _set_resource(ctx, apath)
        result = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": c_bytes,  # byte form, NOT hex
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 200, result
        # Delegation cap was issued under the delegate's hex namespace.
        del_hash = result["result"]["data"]["delegation_token_hash"]
        del_path = role_derived_token_path("admin", c_hex, del_hash)
        assert ctx.pathway.entity_tree.get(del_path) == del_hash

    def test_delegate_rejects_unparseable_field(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        result = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": 12345,  # not bytes / dict / hex string
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_request"

    def test_sec18_rejects_zero_hash_delegate(self):
        """SEC-18 / V7 v7.39 PR-3 (delegate path): zero-hash delegate
        MUST be rejected at the role layer. Same fail-fast rationale as
        :assign — chain-walk would reject the delegation cap, but
        rejecting at mint time keeps a dud cap from binding."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        zero_hex = "00" + "00" * 32
        result = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": zero_hex,
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 400, result
        assert result["result"]["data"]["code"] == "invalid_request"

    def test_si20_scope_must_be_literal(self):
        """SI-20: scope MUST NOT contain template variables. Reject
        with 400 `scope_must_be_literal`."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))

        templated_scope = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["users/{peer_id}/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        result = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": _hex_id("charlie"),
                "scope": templated_scope,
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "scope_must_be_literal"

    def test_rl2_against_delegator_authority(self):
        """Scope must be a subset of the delegator's role grants (resolved
        with peer_id = delegator_peer_id_hex)."""
        ctx = _make_ctx()
        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", narrow)
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        wider = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["private/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        result = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": _hex_id("charlie"),
                "scope": wider,
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "delegation_authority_insufficient"

    def test_blocks_excluded_delegate(self):
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        c_hex = _hex_id("charlie")
        ctx.pathway.emit(
            role_exclusion_path("admin", c_hex),
            Entity(type=ROLE_EXCLUSION_TYPE,
                   data={"excluded_by": b"a", "excluded_at": 0}),
            EmitContext.bootstrap(),
        )
        result = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": c_hex,
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        assert result["status"] == 403
        assert result["result"]["data"]["code"] == "delegate_excluded"

    def test_pr2_sec2_post_issue_rollback_on_delegate(self):
        """SEC-2 (delegate path): if `:exclude(delegate)` lands during
        the delegate's issue → bind window, the delegation cap MUST be
        rolled back. Forbidden terminal state: exclusion bound + delegate
        cap also bound.

        Forces the race by hooking `_issue_role_derived_token_pathway`
        — the last write before the delegate SEC-2 re-check fires."""
        from unittest.mock import patch
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        c_hex = _hex_id("charlie")

        from entity_handlers import role as role_mod
        original_issue = role_mod._issue_role_derived_token_pathway

        def racy_issue(*args, **kwargs):
            token_hash = original_issue(*args, **kwargs)
            ctx.pathway.emit(
                role_exclusion_path("admin", c_hex),
                Entity(type=ROLE_EXCLUSION_TYPE,
                       data={"excluded_by": b"a", "excluded_at": 0}),
                EmitContext.bootstrap(),
            )
            return token_hash

        with patch.object(
            role_mod, "_issue_role_derived_token_pathway", racy_issue,
        ):
            result = _run(role_handler(
                apath, "delegate",
                {"data": {
                    "delegate": c_hex,
                    "scope": _full_access_grants(),
                    "role": "operator",
                }}, ctx.handler,
            ))
        assert result["status"] == 403, result
        assert result["result"]["data"]["code"] == "delegate_excluded"
        # Forbidden terminal state: no delegation cap bound under
        # charlie's role-derived prefix.
        prefix = f"system/capability/grants/role-derived/admin/{c_hex}/"
        bound = list(ctx.pathway.entity_tree.list_prefix(prefix))
        assert bound == [], (
            f"SEC-2 violation: delegation cap survived rollback "
            f"under {prefix}: {bound}"
        )

    def test_pr6_delegation_chain_depth_2(self):
        """TV-RD-DELEGATE-CHAIN-DEPTH (v2.0 §5.1 + §5.6, SHOULD): with
        role-derived caps now root (PR-1), the most common delegation
        chain is depth 2 (delegation cap → role-derived root). Pre-PR-1
        was depth 3 (delegation → role-derived → handler-grant root)."""
        ctx = _make_ctx()
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        local_hex = _local_peer_id_hex(ctx)
        apath = role_assignment_path("admin", local_hex, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        role_cap_hash = assign_res["result"]["data"]["derived_tokens"][0]
        # Role-derived cap is root (PR-1 invariant).
        role_cap = ctx.pathway.content_store.get(role_cap_hash)
        assert "parent" not in role_cap.data

        c_hex = _hex_id("charlie")
        del_res = _run(role_handler(
            apath, "delegate",
            {"data": {
                "delegate": c_hex,
                "scope": _full_access_grants(),
                "role": "operator",
            }}, ctx.handler,
        ))
        del_hash = del_res["result"]["data"]["delegation_token_hash"]
        del_cap = ctx.pathway.content_store.get(del_hash)
        # Delegation cap chains: parent = role-derived root cap.
        assert del_cap.data.get("parent") == role_cap_hash
        # Walk depth: delegation (depth 1) → role-derived root (depth 2).
        # Depth convention per PR-6: link count from cap to root, root
        # included. Root cap has depth 1; one parent link → depth 2.
        depth = 1
        cur = del_cap.data
        while cur.get("parent") is not None:
            depth += 1
            parent = ctx.pathway.content_store.get(cur["parent"])
            cur = parent.data
        assert depth == 2, f"expected depth 2, got {depth}"


# ---------------------------------------------------------------------------
# Startup-time L0 helper (SI-12 + SI-28)
# ---------------------------------------------------------------------------


class TestStartupTimeL0:
    def test_mints_root_cap(self):
        ctx = _make_ctx()
        role_def = Entity(
            type=ROLE_TYPE,
            data={"name": "operator", "grants": _full_access_grants()},
        )
        h = _hex_id("bob")
        cap_hash = startup_time_role_derived_token(
            ctx.pathway, ctx.keypair,
            context="admin", role_def=role_def, assignee_peer_id_hex=h,
        )
        token_path = role_derived_token_path("admin", h, cap_hash)
        assert ctx.pathway.entity_tree.get(token_path) == cap_hash
        token_entity = ctx.pathway.content_store.get(cap_hash)
        assert token_entity.type == "system/capability/token"
        assert "parent" not in token_entity.data
        # SI-8: grantee = bytes.fromhex(peer_id_hex).
        assert token_entity.data["grantee"] == bytes.fromhex(h)

    def test_layer_2_exclusion_check(self):
        ctx = _make_ctx()
        h = _hex_id("bob")
        ctx.pathway.emit(
            role_exclusion_path("admin", h),
            Entity(type=ROLE_EXCLUSION_TYPE,
                   data={"excluded_by": b"a", "excluded_at": 0}),
            EmitContext.bootstrap(),
        )
        role_def = Entity(
            type=ROLE_TYPE,
            data={"name": "operator", "grants": _full_access_grants()},
        )
        with pytest.raises(PermissionError):
            startup_time_role_derived_token(
                ctx.pathway, ctx.keypair,
                context="admin", role_def=role_def, assignee_peer_id_hex=h,
            )

    def test_si12_runtime_check_after_handler_registration(self):
        """SI-12 conformance: calling the L0 helper AFTER the role
        handler is registered raises RuntimeError. The presence of the
        manifest binding at `system/handler/system/role` is the
        registration marker."""
        ctx = _make_ctx()
        # Simulate handler registration by binding the manifest entry.
        manifest_entity = Entity(
            type="system/handler/interface",
            data={"name": "role", "operations": {}},
        )
        ctx.pathway.emit(
            f"system/handler/{ROLE_HANDLER_PATTERN}",
            manifest_entity, EmitContext.bootstrap(),
        )
        role_def = Entity(
            type=ROLE_TYPE,
            data={"name": "operator", "grants": _full_access_grants()},
        )
        with pytest.raises(RuntimeError, match="L0 derivation path is closed"):
            startup_time_role_derived_token(
                ctx.pathway, ctx.keypair,
                context="admin", role_def=role_def,
                assignee_peer_id_hex=_hex_id("bob"),
            )


# ---------------------------------------------------------------------------
# RoleExtension (§6.5 IA8 + IA11 option (b))
# ---------------------------------------------------------------------------


class TestRoleExtensionFleetSweep:
    def test_external_exclusion_write_triggers_sweep(self):
        from entity_core.peer.extensions import ExtensionContext
        ctx = _make_ctx()
        role_def = Entity(
            type=ROLE_TYPE,
            data={"name": "operator", "grants": _full_access_grants()},
        )
        h = _hex_id("bob")
        cap_hash = startup_time_role_derived_token(
            ctx.pathway, ctx.keypair,
            context="admin", role_def=role_def, assignee_peer_id_hex=h,
        )
        token_path = role_derived_token_path("admin", h, cap_hash)
        assert ctx.pathway.entity_tree.get(token_path) is not None

        ext = RoleExtension()
        ext.initialize(
            ExtensionContext(keypair=ctx.keypair, emit_pathway=ctx.pathway),
        )

        # Direct-emit an exclusion entity (NOT via the role handler):
        # bootstrap context attributes the write to "not the role
        # handler", so the watcher fires.
        ctx.pathway.emit(
            role_exclusion_path("admin", h),
            Entity(type=ROLE_EXCLUSION_TYPE,
                   data={"excluded_by": b"a", "excluded_at": 0}),
            EmitContext.bootstrap(),
        )
        assert ctx.pathway.entity_tree.get(token_path) is None

    def test_local_exclude_op_does_not_double_sweep(self):
        from entity_core.peer.extensions import ExtensionContext
        ctx = _make_ctx()
        ext = RoleExtension()
        ext.initialize(
            ExtensionContext(keypair=ctx.keypair, emit_pathway=ctx.pathway),
        )
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        token_hash = assign_res["result"]["data"]["derived_tokens"][0]

        excl_path = role_exclusion_path("admin", h)
        _set_resource(ctx, excl_path)
        result = _run(role_handler(
            excl_path, "exclude",
            {"data": {"reason": "evicted"}}, ctx.handler,
        ))
        assert result["status"] == 200
        # The handler's own sweep claimed the revoked-tokens list (the
        # extension watcher saw `handler_pattern == ROLE_HANDLER_PATTERN`
        # in the change context and short-circuited).
        assert token_hash in result["result"]["data"]["revoked_token_hashes"]


class TestRoleExtensionDefinitionCascade:
    def test_external_role_definition_write_triggers_cascade(self):
        from entity_core.peer.extensions import ExtensionContext
        ctx = _make_ctx()
        narrow = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["public/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", narrow)
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        old_token = assign_res["result"]["data"]["derived_tokens"][0]

        ext = RoleExtension()
        ext.initialize(
            ExtensionContext(keypair=ctx.keypair, emit_pathway=ctx.pathway),
        )

        # Direct-emit a role-definition mutation (not via :define).
        wider = [
            {
                "handlers": {"include": ["system/tree", "system/query"]},
                "resources": {"include": ["public/*", "private/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", wider)

        old_path = role_derived_token_path("admin", h, old_token)
        assert ctx.pathway.entity_tree.get(old_path) is None
        # Linkage now points to a new token.
        link_h = ctx.pathway.entity_tree.get(
            role_derived_token_link_path("admin", h, "operator"),
        )
        link_entity = ctx.pathway.content_store.get(link_h)
        assert link_entity.data["token_hash"] != old_token

    def test_handler_define_does_not_double_cascade(self):
        from entity_core.peer.extensions import ExtensionContext
        ctx = _make_ctx()
        ext = RoleExtension()
        ext.initialize(
            ExtensionContext(keypair=ctx.keypair, emit_pathway=ctx.pathway),
        )
        rd_path = role_definition_path("admin", "operator")
        _set_resource(ctx, rd_path)
        first = _run(role_handler(
            rd_path, "define",
            {"data": {"grants": _full_access_grants()}}, ctx.handler,
        ))
        assert first["status"] == 200
        assert first["result"]["data"]["re_derived_count"] == 0

        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        assign_res = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        old_token = assign_res["result"]["data"]["derived_tokens"][0]

        wider = [
            {
                "handlers": {"include": ["system/tree", "system/query"]},
                "resources": {"include": ["public/*", "private/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _set_resource(ctx, rd_path)
        result = _run(role_handler(
            rd_path, "define", {"data": {"grants": wider}}, ctx.handler,
        ))
        assert result["result"]["data"]["re_derived_count"] == 1
        old_path = role_derived_token_path("admin", h, old_token)
        assert ctx.pathway.entity_tree.get(old_path) is None


# ===========================================================================
# v1.7 §5.3 + SI-15 cascade-wide-abort fix (the cross-impl handoff)
# ===========================================================================


class TestSI15CascadeWideAbort:
    """TV-RD-19: when a templated role's per-assignee resolution makes
    SOME assignees' grants exceed the caller's per-peer authority, the
    cascade MUST skip those assignees and continue — NOT abort the
    whole cascade. The pre-fix behavior had a top-level RL2 against
    literal (templated) grants that 403'd before per-assignee logic
    could run.
    """

    def test_re_derive_does_not_abort_when_caller_misses_one_assignee(self):
        # Setup: full-access caller mints definitions and assigns two
        # peers. Then we re-derive with a narrower caller that covers
        # one peer's resolved grants but not the other's.
        h_bob = _hex_id("bob")
        h_carol = _hex_id("carol")
        ctx = _make_ctx()
        templated = [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["users/{peer_id}/*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _emit_role_def(ctx, "admin", "operator", templated)
        for assignee in (h_bob, h_carol):
            apath = role_assignment_path("admin", assignee, "operator")
            _set_resource(ctx, apath)
            res = _run(role_handler(
                apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
            ))
            assert res["status"] == 200

        # Narrow the caller's authority to bob's namespace only and
        # invoke re-derive through the handler (this is the path that
        # used to abort cascade-wide).
        ctx.handler.caller_capability = {"grants": [
            {
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": [f"users/{h_bob}/*"]},
                "operations": {"include": ["*"]},
            }
        ]}
        rd_path = role_definition_path("admin", "operator")
        _set_resource(ctx, rd_path)
        result = _run(role_handler(
            rd_path, "re-derive",
            {"data": {"role": "operator"}}, ctx.handler,
        ))
        # Cascade did not abort.
        assert result["status"] == 200, result
        data = result["result"]["data"]
        # Bob succeeded (1 re-derived); carol skipped (1 in
        # skipped_grantees as raw bytes).
        assert data["re_derived_count"] == 1
        assert bytes.fromhex(h_carol) in data["skipped_grantees"]
        assert bytes.fromhex(h_bob) not in data["skipped_grantees"]

    def test_re_derive_aborts_when_definition_missing(self):
        """The cascade-wide abort change does NOT relax 404 on missing
        role — that's still the right answer."""
        ctx = _make_ctx()
        rd_path = role_definition_path("admin", "no-such-role")
        _set_resource(ctx, rd_path)
        result = _run(role_handler(
            rd_path, "re-derive",
            {"data": {"role": "no-such-role"}}, ctx.handler,
        ))
        assert result["status"] == 404


class TestV17EffectiveExpiresAtHelpers:
    """Direct tests of the MIN_DEFINED expiry helpers (v1.7 §5.3)."""

    def test_min_defined_drops_none_values(self):
        from entity_handlers.role import _min_defined
        assert _min_defined() is None
        assert _min_defined(None, None) is None
        assert _min_defined(10) == 10
        assert _min_defined(10, None) == 10
        assert _min_defined(10, 20, 5) == 5
        assert _min_defined(None, 10, None, 20) == 10

    def test_role_metadata_ttl_reads_int(self):
        from entity_handlers.role import _role_metadata_ttl
        assert _role_metadata_ttl(Entity(
            type=ROLE_TYPE,
            data={"name": "r", "grants": [], "metadata": {"ttl": 3600000}},
        )) == 3600000
        assert _role_metadata_ttl(Entity(
            type=ROLE_TYPE,
            data={"name": "r", "grants": []},
        )) is None
        # Bool is not an int (rejected per impl).
        assert _role_metadata_ttl(Entity(
            type=ROLE_TYPE,
            data={"name": "r", "grants": [], "metadata": {"ttl": True}},
        )) is None

    def test_effective_expires_at_min_over_defined(self):
        from entity_handlers.role import _effective_expires_at
        # All three sources defined: take the min.
        # parent=200, ttl=10 (now=100 → role_absolute=110), caller=300
        # → MIN(200, 110, 300) == 110
        assert _effective_expires_at(
            parent_expires=200, role_ttl=10,
            caller_expires=300, now_ms=100,
        ) == 110
        # Only caller defined → caller wins.
        assert _effective_expires_at(
            parent_expires=None, role_ttl=None, caller_expires=500,
        ) == 500
        # All None → None (cap inherits no expiry).
        assert _effective_expires_at(
            parent_expires=None, role_ttl=None, caller_expires=None,
        ) is None


class TestV17CallerExpiryBound:
    """TV-RD-CALLER-EXPIRY: minted role-derived cap's expires_at MUST
    be ≤ caller_capability.expires_at (per v1.7 §5.3 SI-29). This
    closes 'RL2 OK at issue, chain-invalid at use' — V7 §5.6 strict
    nil-vs-finite would otherwise reject the cap at use-time.
    """

    def test_assigned_cap_inherits_caller_expiry(self):
        ctx = _make_ctx()
        # Caller cap with explicit finite expires_at.
        caller_expiry = _now_ms_helper() + 3600000  # +1h
        ctx.handler.caller_capability = {
            "grants": _full_access_grants(),
            "expires_at": caller_expiry,
        }
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        result = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 200
        token_hash = result["result"]["data"]["derived_tokens"][0]
        token_entity = ctx.pathway.content_store.get(token_hash)
        cap_expiry = token_entity.data.get("expires_at")
        # Per SI-29: minted cap MUST have a finite expiry ≤ caller's.
        assert cap_expiry is not None, (
            "minted cap escaped caller's expiry — §5.3 BYPASSED"
        )
        assert cap_expiry <= caller_expiry, (
            f"minted cap {cap_expiry} outlives caller {caller_expiry}"
        )

    def test_assigned_cap_inherits_role_ttl_when_tighter(self):
        """When role.metadata.ttl is the tightest bound it wins."""
        ctx = _make_ctx()
        far_future = _now_ms_helper() + 86400000  # +24h (caller)
        ctx.handler.caller_capability = {
            "grants": _full_access_grants(),
            "expires_at": far_future,
        }
        # Role with TTL of 1 hour.
        ctx.pathway.emit(
            role_definition_path("admin", "operator"),
            Entity(
                type=ROLE_TYPE,
                data={
                    "name": "operator",
                    "grants": _full_access_grants(),
                    "metadata": {"ttl": 3600000},  # 1h
                },
            ),
            EmitContext.bootstrap(),
        )
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        result = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 200
        token_hash = result["result"]["data"]["derived_tokens"][0]
        token_entity = ctx.pathway.content_store.get(token_hash)
        cap_expiry = token_entity.data.get("expires_at")
        assert cap_expiry is not None
        # Role TTL (1h) tighter than caller's far-future (24h).
        assert cap_expiry < far_future
        # Cap expiry should be approximately now + 1h (allow a small
        # window for the time elapsed during the test setup).
        approx_role_expiry = _now_ms_helper() + 3600000
        assert abs(cap_expiry - approx_role_expiry) < 5000

    def test_assigned_cap_no_expiry_when_no_source_defines_one(self):
        """When parent, role.ttl, AND caller all leave expiry
        undefined, the minted cap has no expiry either (not zero, not
        a default — None / omitted)."""
        ctx = _make_ctx()
        # Wildcard caller without expires_at.
        ctx.handler.caller_capability = {"grants": _full_access_grants()}
        # Handler grant in _make_ctx has no expires_at by default.
        _emit_role_def(ctx, "admin", "operator", _full_access_grants())
        h = _hex_id("bob")
        apath = role_assignment_path("admin", h, "operator")
        _set_resource(ctx, apath)
        result = _run(role_handler(
            apath, "assign", {"data": {"role": "operator"}}, ctx.handler,
        ))
        assert result["status"] == 200
        token_hash = result["result"]["data"]["derived_tokens"][0]
        token_entity = ctx.pathway.content_store.get(token_hash)
        # `expires_at` is omitted (not present, not None) when no
        # source defines one — that's the v1.7 MIN_DEFINED-over-empty
        # behavior + our cap-construction's `if expires_at is not None`
        # gate.
        assert "expires_at" not in token_entity.data


class TestV17NilVsFiniteParentRejected:
    """TV-RD-NIL-EXPIRY confirmation: V7 §5.6 strict — a child with no
    `expires_at` against a parent with finite `expires_at` is rejected
    by `is_attenuated`. The architecture team confirmed Python was
    already strict; this TV runs to confirm no regression after the
    v1.7 changes.
    """

    def test_is_attenuated_rejects_nil_child_against_finite_parent(self):
        from entity_core.capability.delegation import is_attenuated
        # Parent with finite expiry covers wildcards.
        parent = {
            "data": {
                "grants": [
                    {
                        "handlers": {"include": ["*"]},
                        "resources": {"include": ["*"]},
                        "operations": {"include": ["*"]},
                    }
                ],
                "expires_at": _now_ms_helper() + 3600000,
            }
        }
        # Child with NO expires_at — must be rejected.
        child_no_expiry = {
            "data": {
                "grants": [
                    {
                        "handlers": {"include": ["system/tree"]},
                        "resources": {"include": ["public/*"]},
                        "operations": {"include": ["get"]},
                    }
                ],
            }
        }
        result = is_attenuated(child_no_expiry, parent, "")
        assert not result.valid
        # Child with explicit shorter expiry — accepted.
        child_with_expiry = {
            "data": {
                "grants": child_no_expiry["data"]["grants"],
                "expires_at": _now_ms_helper() + 60000,
            }
        }
        result = is_attenuated(child_with_expiry, parent, "")
        assert result.valid

    def test_define_rl2_with_finite_caller_rejects_no_expiry_role(self):
        """RL2 at define-time uses the v1.7 hypothetical-cap form. With
        a finite-expiry caller and a role that wouldn't carry a finite
        expiry through (no metadata.ttl), the MIN_DEFINED reduces to
        the caller's expiry — and the hypothetical does inherit it.
        So the RL2 check passes. (Conversely: if we couldn't fold
        caller expiry into the hypothetical, the check would
        incorrectly fail under V7 §5.6 strict.)
        """
        ctx = _make_ctx()
        ctx.handler.caller_capability = {
            "grants": _full_access_grants(),
            "expires_at": _now_ms_helper() + 3600000,
        }
        rd_path = role_definition_path("admin", "operator")
        _set_resource(ctx, rd_path)
        result = _run(role_handler(
            rd_path, "define",
            {"data": {"grants": _full_access_grants()}}, ctx.handler,
        ))
        # With v1.7 hypothetical-cap RL2 + caller-expiry fold-in, this
        # must pass.
        assert result["status"] == 200, (
            f"define under finite-expiry caller failed: {result}"
        )


def _now_ms_helper() -> int:
    """Test-only wrapper around the role module's `_now_ms` to keep
    the wall-clock dependency explicit at test sites."""
    import time
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class TestDispatcher:
    def test_unknown_op_returns_501(self):
        ctx = _make_ctx()
        result = _run(role_handler(
            "system/role/admin/operator", "no-such-op", {}, ctx.handler,
        ))
        assert result["status"] == 501
        assert result["result"]["data"]["code"] == "unsupported_operation"
