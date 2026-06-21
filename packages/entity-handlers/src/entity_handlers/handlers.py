"""Handlers handler — V7 §6.2 system/handler.

Manages handler lifecycle. The `register` operation decomposes a manifest
into interface + handler entities, installs type definitions, and creates
the handler's capability grant. The `unregister` operation reverses these
steps. See V7 §6.1, §6.2, §3.12.
"""

from __future__ import annotations

from typing import Any

from entity_core.capability.grant_signing import (
    build_signed_handler_grant,
    grant_signature_path,
)
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.types.registry import _normalize_pattern
from entity_handlers._common import error_response as _error


HANDLERS_HANDLER_PATTERN = "system/handler"


# ---------------------------------------------------------------------------
# Type definitions (V7 §3.12)
# ---------------------------------------------------------------------------

HANDLERS_TYPE_DEFS: list[dict[str, Any]] = [
    {
        "name": "system/handler/register-request",
        "description": "Register-request entity for system/handler:register",
        "fields": {
            "manifest": {"type_ref": "system/handler/manifest"},
            "types": {"map_of": {"type_ref": "system/type"}, "optional": True},
            "requested_scope": {
                "array_of": {"type_ref": "system/capability/grant-entry"},
                "optional": True,
            },
        },
    },
    {
        "name": "system/handler/register-result",
        "description": "Register-result entity returned by system/handler:register",
        "fields": {
            "pattern": {"type_ref": "system/tree/path"},
            "grant": {"type_ref": "system/capability/token"},
        },
    },
]


def _register_type_defs(emit_pathway: Any) -> None:
    """Install handler type definitions at system/type/*."""
    ctx = EmitContext.bootstrap()
    for type_def in HANDLERS_TYPE_DEFS:
        type_entity = Entity(type="system/type", data=type_def)
        emit_pathway.emit(f"system/type/{type_def['name']}", type_entity, ctx)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decompose_manifest(manifest_data: dict[str, Any]) -> tuple[Entity, Entity, str, str]:
    """Decompose a manifest into (interface_entity, handler_entity,
    interface_path, storage_pattern) per V7 §6.2 process_registration.

    Returns the storage_pattern (canonical pattern path with trailing /*
    stripped) — that's where the handler entity is bound.
    """
    pattern = manifest_data["pattern"]
    storage_pattern = _normalize_pattern(pattern)
    interface_path = f"system/handler/{storage_pattern}"

    interface_entity = Entity(
        type="system/handler/interface",
        data={
            "pattern": pattern,
            "name": manifest_data["name"],
            "operations": manifest_data["operations"],
        },
    )

    handler_data: dict[str, Any] = {"interface": interface_path}
    if manifest_data.get("max_scope") is not None:
        handler_data["max_scope"] = manifest_data["max_scope"]
    if manifest_data.get("internal_scope") is not None:
        handler_data["internal_scope"] = manifest_data["internal_scope"]
    if manifest_data.get("expression_path") is not None:
        handler_data["expression_path"] = manifest_data["expression_path"]

    handler_entity = Entity(type="system/handler", data=handler_data)
    return interface_entity, handler_entity, interface_path, storage_pattern


# ---------------------------------------------------------------------------
# register / unregister
# ---------------------------------------------------------------------------

async def _handle_register(
    params_data: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 register: install interface + handler + grant + types.

    Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-V7-1): the handler pattern
    is derived from ctx.resource.targets[0] (= system/handler/{pattern}).
    manifest.pattern policy: absent → derive; present + matches → use;
    present + disagrees → reject 400 manifest_pattern_mismatch.
    """
    targets = getattr(ctx, "resource_targets", None) or []
    if len(targets) != 1:
        return _error(400, "ambiguous_resource",
                      "register requires exactly one resource target (system/handler/{pattern})")
    handler_path = targets[0]
    if not handler_path.startswith("system/handler/"):
        return _error(400, "malformed_resource",
                      "register resource must be system/handler/{pattern}")
    derived_pattern = handler_path[len("system/handler/"):]
    if not derived_pattern:
        return _error(400, "malformed_resource",
                      "register resource missing pattern after system/handler/")

    # Override prohibition (EXTENSION-COMPUTE §3.5): the compute builtins are
    # registered at bootstrap and MUST NOT be overridden, so that two peers
    # dispatching to e.g. system/compute/builtins/arithmetic cannot disagree on
    # what "add" means. Reject any registration targeting that namespace.
    if (
        derived_pattern == "system/compute/builtins"
        or derived_pattern.startswith("system/compute/builtins/")
    ):
        return _error(403, "builtin_override_prohibited",
                      "handlers under system/compute/builtins/* MUST NOT be "
                      "overridden (EXTENSION-COMPUTE §3.5)")

    manifest = params_data.get("manifest")
    if not isinstance(manifest, dict):
        return _error(400, "invalid_request",
                      "register requires manifest field (system/handler/manifest entity)")

    manifest_data = manifest.get("data") if "data" in manifest else manifest
    if not isinstance(manifest_data, dict):
        return _error(400, "invalid_request", "manifest.data missing or not an object")

    name = manifest_data.get("name")
    operations = manifest_data.get("operations")
    if not name or not isinstance(operations, dict):
        return _error(400, "invalid_request",
                      "manifest.data must include name and operations")

    declared_pattern = manifest_data.get("pattern")
    if declared_pattern is not None and declared_pattern != derived_pattern:
        return _error(400, "manifest_pattern_mismatch",
                      "manifest.pattern does not match resource-derived pattern")

    # Use the resource-derived pattern as authoritative; fill it into the
    # manifest data passed to _decompose_manifest so downstream entities
    # carry the agreed-upon pattern.
    if declared_pattern is None:
        manifest_data = {**manifest_data, "pattern": derived_pattern}
    pattern = derived_pattern

    interface_entity, handler_entity, interface_path, storage_pattern = (
        _decompose_manifest(manifest_data)
    )

    # Determine grant entries: requested_scope (caller-provided, attenuated
    # against handler grant) wins, falls back to manifest's internal_scope.
    requested_scope = params_data.get("requested_scope")
    if requested_scope is not None:
        if not isinstance(requested_scope, list):
            return _error(400, "invalid_request",
                          "requested_scope must be an array of grant entries")
        grant_entries = requested_scope
    elif manifest_data.get("internal_scope") is not None:
        grant_entries = manifest_data["internal_scope"]
    else:
        grant_entries = [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["*"]},
        }]

    if ctx.keypair is None:
        return _error(
            500, "internal_error",
            "system/handler:register requires peer keypair (not provided in HandlerContext)",
        )

    grant_entity, signature_entity, identity_entity = build_signed_handler_grant(
        ctx.keypair, grant_entries,
    )
    grant_path = f"system/capability/grants/{storage_pattern}"

    emit_ctx = EmitContext.bootstrap()
    ep = ctx.emit_pathway

    # Ensure local identity entity is in the content store so the granter
    # hash referenced by the grant resolves at validation time (spec-gap §S2).
    ep.content_store.put(identity_entity)

    # 1) Interface entity (discovery)
    ep.emit(interface_path, interface_entity, emit_ctx)
    # 2) Handler entity (dispatch target)
    ep.emit(storage_pattern, handler_entity, emit_ctx)
    # 3) Capability grant + signature (V7 §6.2 + spec-gap §S1). The
    # signature lives at the §3.5 invariant-pointer path
    # `system/signature/{grant_hash}` (v7.74 v0.4 §3.4 convergence).
    ep.emit(grant_path, grant_entity, emit_ctx)
    ep.emit(
        grant_signature_path(grant_entity.compute_hash()),
        signature_entity, emit_ctx,
    )
    # 4) Type definitions (optional)
    types_map = params_data.get("types") or {}
    if isinstance(types_map, dict):
        for type_name, type_def in types_map.items():
            type_entity_data = (
                type_def.get("data")
                if isinstance(type_def, dict) and "data" in type_def
                else type_def
            )
            type_entity = Entity(type="system/type", data=type_entity_data)
            ep.emit(f"system/type/{type_name}", type_entity, emit_ctx)

    # F-CIMP-4 — `grant` is `{type_ref: "system/capability/token"}`,
    # which in the cross-impl wire convention is the BARE CapabilityToken data
    # fields (grants / granter / grantee / created_at / ...), NOT a full
    # `{type, data, content_hash}` entity wrapper. Go decodes
    # `RegisterResultData.Grant` as `CapabilityTokenData` with cbor tags on
    # the data field names — emitting the entity wrapper hides `grantee`
    # under a `data` key, so Go's strict decoder finds `Grantee` = zero
    # and rejects with "register result grant.grantee is zero" (core-go
    # validate-peer entity_native hardening).
    #
    # Same wire-shape divergence class as F-CIMP-1: typed result field
    # whose Python-side shape doesn't match Go's struct-tag expectations.
    return {
        "status": 200,
        "result": {
            "type": "system/handler/register-result",
            "data": {
                "pattern": pattern,
                "grant": grant_entity.data,
            },
        },
    }


async def _handle_unregister(
    params_data: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 unregister: remove interface, handler, and grant entries.

    Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-V7-2): pattern is derived
    from ctx.resource.targets[0]; the unregister-request wrapper is
    eliminated and params is empty primitive/any.
    """
    targets = getattr(ctx, "resource_targets", None) or []
    if len(targets) != 1:
        return _error(400, "ambiguous_resource",
                      "unregister requires exactly one resource target (system/handler/{pattern})")
    handler_path = targets[0]
    if not handler_path.startswith("system/handler/"):
        return _error(400, "malformed_resource",
                      "unregister resource must be system/handler/{pattern}")
    pattern = handler_path[len("system/handler/"):]
    if not pattern:
        return _error(400, "malformed_resource",
                      "unregister resource missing pattern after system/handler/")

    storage_pattern = _normalize_pattern(pattern)
    interface_path = f"system/handler/{storage_pattern}"
    grant_path = f"system/capability/grants/{storage_pattern}"

    emit_ctx = EmitContext.bootstrap()
    ep = ctx.emit_pathway

    # v7.74 v0.4 §3.4 unregister teardown: the grant-signature now lives
    # at the invariant-pointer path `system/signature/{grant_hash}`, keyed
    # by the grant's content hash — so read the grant hash from the tree
    # BEFORE deleting the grant, then remove the signature alongside it.
    # (Prevents the half-removed state where the grant is gone but the
    # signature lingers — the writer/unregister symmetry §3.4 requires.)
    grant_uri = ep.entity_tree.normalize_uri(grant_path)
    grant_hash = ep.entity_tree.get(grant_uri)

    # Removal via emit_pathway.delete fires DELETED events so consumers
    # (subscriptions, history, etc.) observe the unregistration.
    ep.delete(storage_pattern, emit_ctx)
    ep.delete(interface_path, emit_ctx)
    ep.delete(grant_path, emit_ctx)
    if grant_hash is not None:
        ep.delete(grant_signature_path(grant_hash), emit_ctx)

    return {
        "status": 200,
        "result": {
            "type": "system/protocol/status",
            "data": {"pattern": pattern, "status": "unregistered"},
        },
    }


# ---------------------------------------------------------------------------
# Handler entry point
# ---------------------------------------------------------------------------

async def handlers_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """V7 §6.2 system/handler — the handlers handler.

    Operations:
      - register(register-request) → register-result
      - unregister(unregister-request)

    The dispatch chain enforces the caller's capability covers
    `system/handler:{operation}`. This handler validates the request body
    and writes the four locations atomically per §6.2.
    """
    params_data = params.get("data", params) if isinstance(params, dict) else {}

    if operation == "register":
        return await _handle_register(params_data, ctx)
    if operation == "unregister":
        return await _handle_unregister(params_data, ctx)

    return _error(
        501, "unsupported_operation",
        f"system/handler does not support operation: {operation}",
    )
