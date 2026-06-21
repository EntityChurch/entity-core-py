"""Type handler for EXTENSION-TYPE v1.1.

Registered at pattern ``system/type``. Implements the v1.1 §2.3
two-phase validation flow plus narrowing verification (§6.4 — landed
in T4 alongside this module).

Phase 1 — structural validation. Resolve the type definition (Strategy
1 path-convention lookup per §1.5: ``system/type/{name}``), then
check required-field presence and (where the field-spec has a
``type_ref`` to a primitive) check the value's shape. The
structural-validation surface is intentionally modest — the goal is
"a Level-2 conformant implementation of the spec's structural pass,"
not a full inferential type-checker. The deeper structural surfaces
(generic resolution, union matching, recursive type_ref walks) are
NATIVE-TYPE-SYSTEM §7 concerns that compose on top of this op.

Phase 2 — constraint dispatch. For each field-spec whose
``constraints`` array is non-empty, the type handler dispatches each
constraint via ``ctx.execute()`` to the standard pattern
``system/type/constraint/*`` (or any custom-handler pattern per §2.2).
The constraint handler returns ``{valid, reason?}`` per §5.3; the
type handler collects violations with the §1.2 ``kind``
discriminator. Dispatch failure on a constraint becomes a
``kind: unknown_constraint`` violation per §1.2.

Effective fields include the ``extends`` chain (§6): the
type-handler walks parents via the same Strategy-1 lookup and
unions their field surfaces; child field-specs override parent
field-specs on key collision.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from entity_core.types.registry import get_type_entity
from entity_handlers._common import error_response as _error
from entity_handlers.type_analysis import (
    COMPARE_RESULT_TYPE,
    COMPATIBILITY_REPORT_TYPE,
    RECONCILE_RESULT_TYPE,
    TYPE_ENTITY_TYPE,
    op_adopt,
    op_compare,
    op_compatible,
    op_converge,
    op_reconcile,
)
from entity_handlers.type_narrowing import verify_narrowing

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext

logger = logging.getLogger(__name__)

TYPE_HANDLER_PATTERN = "system/type"

# Owned by EXTENSION-TYPE v1.1 §8.4.
_VALIDATE_RESULT_TYPE = "system/type/validate-result"

# Field-spec extension surfaces this handler interprets. Anything else
# the validator encounters on a field-spec it doesn't understand is
# reported via `unevaluated_fields` per §8.4 so the caller knows the
# validation report is partial.
_FIELDSPEC_KNOWN_KEYS = frozenset({
    "type_ref",
    "array_of",
    "map_of",
    "key_type",
    "optional",
    "byte_size",
    "union_of",
    "type_param",
    "type_args",
    "default",
    "constraints",  # this extension's contract
})

# Type-definition surfaces the validator interprets at the top level
# of `data` (everything else surfaces in `unevaluated_fields` to
# match the §8.4 honesty contract).
_TYPEDEF_KNOWN_KEYS = frozenset({
    "name",
    "fields",
    "extends",
    "layout",
    "type_params",
    "type_args",
})


# ---------------------------------------------------------------------------
# Public handler
# ---------------------------------------------------------------------------


async def type_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: "HandlerContext",
) -> dict[str, Any]:
    """Dispatch the type-handler ops per EXTENSION-TYPE v1.1 §7.1.

    Only ``validate`` lands in T3; the SHOULD-implement ops
    (``compare``, ``compatible``) land in T5; the MAY-implement ops
    (``converge``, ``adopt``, ``reconcile``) are deferred per §12.3.
    """
    if operation == "validate":
        return await _op_validate(params, ctx)
    if operation == "compare":
        return _op_compare_dispatch(params, ctx)
    if operation == "compatible":
        return _op_compatible_dispatch(params, ctx)
    if operation == "converge":
        return _op_converge_dispatch(params, ctx)
    if operation == "adopt":
        return _op_adopt_dispatch(params, ctx)
    if operation == "reconcile":
        return _op_reconcile_dispatch(params, ctx)
    return _error(
        501,
        "unsupported_operation",
        f"system/type handler does not support operation: {operation}",
    )


# ---------------------------------------------------------------------------
# Analysis op dispatchers — thin adapters into type_analysis
# ---------------------------------------------------------------------------


def _op_compare_dispatch(
    params: dict[str, Any], ctx: "HandlerContext",
) -> dict[str, Any]:
    body = params.get("data", params) if isinstance(params, dict) else {}
    a = body.get("type_a")
    b = body.get("type_b")
    if not isinstance(a, str) or not isinstance(b, str):
        return _error(
            400,
            "invalid_request",
            "system/type:compare requires `type_a` and `type_b` paths",
        )
    data = op_compare(a, b, resolve=lambda n: _resolve_type(n, ctx))
    return {"status": 200, "result": {"type": COMPARE_RESULT_TYPE, "data": data}}


def _op_compatible_dispatch(
    params: dict[str, Any], ctx: "HandlerContext",
) -> dict[str, Any]:
    body = params.get("data", params) if isinstance(params, dict) else {}
    a = body.get("type_a")
    b = body.get("type_b")
    direction = body.get("direction", "bidirectional")
    if not isinstance(a, str) or not isinstance(b, str):
        return _error(
            400,
            "invalid_request",
            "system/type:compatible requires `type_a` and `type_b` paths",
        )
    if direction not in {"forward", "backward", "bidirectional"}:
        return _error(
            400,
            "invalid_request",
            "system/type:compatible `direction` must be forward/backward/bidirectional",
        )
    data = op_compatible(a, b, direction, resolve=lambda n: _resolve_type(n, ctx))
    return {
        "status": 200,
        "result": {"type": COMPATIBILITY_REPORT_TYPE, "data": data},
    }


def _op_converge_dispatch(
    params: dict[str, Any], ctx: "HandlerContext",
) -> dict[str, Any]:
    body = params.get("data", params) if isinstance(params, dict) else {}
    paths = body.get("type_paths")
    if not isinstance(paths, list) or len(paths) < 2:
        return _error(
            400,
            "invalid_request",
            "system/type:converge requires `type_paths` (>= 2 entries)",
        )
    try:
        result = op_converge(
            [p for p in paths if isinstance(p, str)],
            resolve=lambda n: _resolve_type(n, ctx),
        )
    except ValueError as exc:
        return _error(400, "invalid_request", str(exc))
    return {"status": 200, "result": result}


def _op_adopt_dispatch(
    params: dict[str, Any], ctx: "HandlerContext",
) -> dict[str, Any]:
    body = params.get("data", params) if isinstance(params, dict) else {}
    source_path = body.get("source_path")
    local_name = body.get("local_name")
    if not isinstance(source_path, str):
        return _error(
            400, "invalid_request", "system/type:adopt requires `source_path`",
        )
    if local_name is not None and not isinstance(local_name, str):
        return _error(
            400, "invalid_request", "`local_name` must be a string when present",
        )
    # Local + remote resolution both use the same emit pathway here —
    # cross-peer adopt is a wire/connection concern handled by the
    # peer's outbound dispatch elsewhere; the op itself just needs a
    # resolver for each side.
    try:
        result = op_adopt(
            source_path=source_path,
            local_name=local_name,
            resolve_remote=lambda n: _resolve_type(n, ctx),
            resolve_local=lambda n: _resolve_type(n, ctx),
        )
    except ValueError as exc:
        return _error(404, "not_found", str(exc))
    return {"status": 200, "result": result}


def _op_reconcile_dispatch(
    params: dict[str, Any], ctx: "HandlerContext",
) -> dict[str, Any]:
    body = params.get("data", params) if isinstance(params, dict) else {}
    paths = body.get("type_paths")
    strategy = body.get("strategy")
    if not isinstance(paths, list) or len(paths) < 2:
        return _error(
            400,
            "invalid_request",
            "system/type:reconcile requires `type_paths` (>= 2 entries)",
        )
    if not isinstance(strategy, str):
        return _error(
            400, "invalid_request",
            "system/type:reconcile requires `strategy` (intersect|union|prefer)",
        )
    try:
        result = op_reconcile(
            [p for p in paths if isinstance(p, str)],
            strategy=strategy,
            resolve=lambda n: _resolve_type(n, ctx),
        )
    except ValueError as exc:
        return _error(400, "invalid_request", str(exc))
    return {"status": 200, "result": {"type": RECONCILE_RESULT_TYPE, "data": result}}


# ---------------------------------------------------------------------------
# validate (§2.3)
# ---------------------------------------------------------------------------


@dataclass
class _Violation:
    field: str
    kind: str               # "structural" | "constraint" | "unknown_constraint"
    reason: str
    constraint: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Flat wire shape for `array_of system/type/violation`.

        Per the entity-field-annotation rule (matching Go + the
        existing core/query/match convention): only an explicit
        `type_ref: "core/entity"` carries a `{type, data}` wrapper.
        Named type_refs like `system/type/violation` mean a flat
        record matching that type's `fields` shape. The
        cross-impl validate-peer test decodes flat; Python now
        emits flat to match.
        """
        out: dict[str, Any] = {
            "field": self.field,
            "kind": self.kind,
            "reason": self.reason,
        }
        if self.constraint is not None:
            out["constraint"] = self.constraint
        return out


async def _op_validate(
    params: dict[str, Any],
    ctx: "HandlerContext",
) -> dict[str, Any]:
    body = params.get("data", params) if isinstance(params, dict) else {}
    entity = body.get("entity")
    if not isinstance(entity, dict):
        return _error(
            400,
            "invalid_request",
            "system/type:validate requires `entity` (a `{type, data}` dict)",
        )

    # §8.3: `type_path` is optional; when absent the validator uses
    # `entity.type`. The field is named `type_path` but typed as a
    # type name — Strategy 1 resolves the name via the
    # `system/type/{name}` path convention.
    type_name = body.get("type_path") or entity.get("type")
    if not isinstance(type_name, str) or not type_name:
        return _error(
            400,
            "invalid_request",
            "system/type:validate requires either params.type_path or entity.type",
        )

    type_def = _resolve_type(type_name, ctx)
    if type_def is None:
        # Spec is silent on the "type not found" case at the result
        # level. Reporting this as a structural violation on the
        # entity's `type` field is the §8.5 shape and mirrors the
        # "constraint type has no handler" honesty principle.
        return _ok_result(
            valid=False,
            violations=[
                _Violation(
                    field="type",
                    kind="structural",
                    reason=f"type definition not found: system/type/{type_name}",
                )
            ],
            unevaluated_fields=[],
        )

    # Walk extends chain to build effective field set + collect
    # unevaluated extension surfaces from every link in the chain.
    fields, unevaluated, walk_error = _effective_fields(type_def, ctx)
    if walk_error is not None:
        return _ok_result(
            valid=False,
            violations=[
                _Violation(field="extends", kind="structural", reason=walk_error)
            ],
            unevaluated_fields=sorted(unevaluated),
        )

    entity_data = entity.get("data")
    if not isinstance(entity_data, dict):
        return _ok_result(
            valid=False,
            violations=[
                _Violation(
                    field="data",
                    kind="structural",
                    reason="entity.data is not an object",
                )
            ],
            unevaluated_fields=sorted(unevaluated),
        )

    violations: list[_Violation] = []

    # Phase 1: structural validation. Required fields present + the
    # subset of shape checks this Level-2 surface owns.
    violations.extend(_structural_check(entity_data, fields))

    # Phase 2: constraint dispatch — only run when structural is clean
    # per §2.3. The spec permits early termination *or* comprehensive
    # collection; we early-terminate at the phase boundary per the
    # natural-fall-out of the pseudocode.
    if not violations:
        violations.extend(await _constraint_phase(entity_data, fields, ctx))

    # Phase 3 (this extension): narrowing verification per §6.4. Runs
    # only when the input entity *is* a type definition itself and
    # carries an ``extends`` chain — that's the case where Liskov
    # substitution applies and the §6.2 constraint table is meaningful.
    # The spec frames this as "verified when a type definition with
    # `extends` is registered or validated" (§6.4).
    if entity.get("type") == "system/type" and "extends" in entity_data:
        for vd in verify_narrowing(
            entity_data,
            resolve_type=lambda n: _resolve_type(n, ctx),
        ):
            violations.append(
                _Violation(
                    field=vd["field"],
                    kind=vd["kind"],
                    reason=vd["reason"],
                    constraint=vd.get("constraint"),
                )
            )

    return _ok_result(
        valid=not violations,
        violations=violations,
        unevaluated_fields=sorted(unevaluated),
    )


# ---------------------------------------------------------------------------
# Type resolution + effective-fields walking (§1.5 Strategy 1, §6)
# ---------------------------------------------------------------------------


def _resolve_type(name: str, ctx: "HandlerContext") -> dict[str, Any] | None:
    """Strategy 1 lookup: ``system/type/{name}`` via the local tree.

    Returns the type-definition entity's `data` dict, or None when
    the lookup misses. Per §1.5 graph-integrity invariant 1, name →
    definition is deterministic within a peer.
    """
    emit = getattr(ctx, "emit_pathway", None)
    if emit is None:
        return None
    entity = get_type_entity(name, emit.content_store, emit.entity_tree)
    if entity is None:
        return None
    if not isinstance(entity.data, dict):
        return None
    return entity.data


def _effective_fields(
    type_data: dict[str, Any],
    ctx: "HandlerContext",
) -> tuple[dict[str, dict[str, Any]], set[str], str | None]:
    """Walk the `extends` chain and union the field surfaces.

    Returns ``(fields, unevaluated, error)`` where ``error`` is
    populated when the walk fails (cycle, parent not found). Per
    §1.5 invariant 3, cycle detection MUST run at the graph level
    and fail closed.
    """
    fields: dict[str, dict[str, Any]] = {}
    unevaluated: set[str] = set()
    visited: set[str] = set()

    chain: list[dict[str, Any]] = []
    cursor: dict[str, Any] | None = type_data
    while cursor is not None:
        name = cursor.get("name")
        if isinstance(name, str):
            if name in visited:
                return fields, unevaluated, f"extends cycle detected at {name}"
            visited.add(name)

        chain.append(cursor)

        # Surface any unknown top-level keys on this link of the
        # chain (§8.4 honesty contract).
        for key in cursor:
            if key not in _TYPEDEF_KNOWN_KEYS:
                unevaluated.add(key)

        parent_name = cursor.get("extends")
        if not isinstance(parent_name, str) or not parent_name:
            break
        cursor = _resolve_type(parent_name, ctx)
        if cursor is None:
            return (
                fields,
                unevaluated,
                f"extends parent not resolvable: system/type/{parent_name}",
            )

    # Walk parents-to-child so child overrides win on key collision.
    for link in reversed(chain):
        link_fields = link.get("fields")
        if not isinstance(link_fields, dict):
            continue
        for fname, fspec in link_fields.items():
            if not isinstance(fspec, dict):
                # Unknown shape — surface and skip.
                unevaluated.add(f"fields.{fname}")
                continue
            fields[fname] = fspec
            # Also surface field-spec extension keys for visibility.
            for key in fspec:
                if key not in _FIELDSPEC_KNOWN_KEYS:
                    unevaluated.add(f"fields.{fname}.{key}")

    return fields, unevaluated, None


# ---------------------------------------------------------------------------
# Phase 1 — structural check
# ---------------------------------------------------------------------------


def _structural_check(
    entity_data: dict[str, Any],
    fields: dict[str, dict[str, Any]],
) -> list[_Violation]:
    """Required-field presence + the local shape checks this op owns.

    Per §2.4: absent fields skip constraints; absent required fields
    are a structural violation. Present-but-wrong-shape (e.g. an
    ``array_of`` field carrying a non-list) is also structural.

    Anything beyond this surface — primitive type narrowing, generic
    resolution, union matching — is NATIVE-TYPE-SYSTEM §7 territory
    that composes on top of this op. We do the shape checks that
    don't require resolving sub-types so this op is useful on its
    own; deeper checks are out of scope for v1.1 §12.1.
    """
    out: list[_Violation] = []
    for fname, fspec in fields.items():
        optional = fspec.get("optional") is True
        if fname not in entity_data:
            if not optional:
                out.append(
                    _Violation(
                        field=fname,
                        kind="structural",
                        reason="required field is missing",
                    )
                )
            continue

        value = entity_data[fname]

        # array_of must carry a list (or null when optional).
        if "array_of" in fspec:
            if value is None and optional:
                continue
            if not isinstance(value, list):
                out.append(
                    _Violation(
                        field=fname,
                        kind="structural",
                        reason="expected array (field has array_of)",
                    )
                )
                continue

        # map_of must carry a dict.
        if "map_of" in fspec:
            if value is None and optional:
                continue
            if not isinstance(value, dict):
                out.append(
                    _Violation(
                        field=fname,
                        kind="structural",
                        reason="expected map (field has map_of)",
                    )
                )
                continue

        # Primitive type_ref — narrow check.
        type_ref = fspec.get("type_ref")
        if isinstance(type_ref, str) and type_ref.startswith("primitive/"):
            err = _primitive_check(type_ref, value)
            if err is not None:
                out.append(
                    _Violation(field=fname, kind="structural", reason=err)
                )

    return out


def _primitive_check(type_ref: str, value: Any) -> str | None:
    """Best-effort shape check for primitive type_refs.

    Returns an error message or None when the value satisfies the
    primitive. Mirrors ENTITY-NATIVE-TYPE-SYSTEM §3 primitives.
    """
    if type_ref == "primitive/any":
        return None
    if type_ref == "primitive/null":
        return None if value is None else "expected null"
    if type_ref == "primitive/bool":
        return None if isinstance(value, bool) else "expected bool"
    if type_ref == "primitive/string":
        return None if isinstance(value, str) else "expected string"
    if type_ref == "primitive/bytes":
        return (
            None if isinstance(value, (bytes, bytearray)) else "expected bytes"
        )
    if type_ref == "primitive/uint":
        if isinstance(value, bool):
            return "expected uint"
        return (
            None
            if isinstance(value, int) and value >= 0
            else "expected uint"
        )
    if type_ref == "primitive/int":
        if isinstance(value, bool):
            return "expected int"
        return None if isinstance(value, int) else "expected int"
    if type_ref == "primitive/float":
        if isinstance(value, bool):
            return "expected float"
        return (
            None if isinstance(value, (int, float)) else "expected float"
        )
    return None  # non-primitive type_refs are out of v1.1 §12.1 scope


# ---------------------------------------------------------------------------
# Phase 2 — constraint dispatch (§2.2 / §5.4)
# ---------------------------------------------------------------------------


async def _constraint_phase(
    entity_data: dict[str, Any],
    fields: dict[str, dict[str, Any]],
    ctx: "HandlerContext",
) -> list[_Violation]:
    out: list[_Violation] = []
    for fname, fspec in fields.items():
        if fname not in entity_data:
            continue  # §2.4: absent optional fields skip constraints.
        constraints = fspec.get("constraints")
        if not isinstance(constraints, list) or not constraints:
            continue
        value = entity_data[fname]
        for constraint in constraints:
            if not isinstance(constraint, dict):
                out.append(
                    _Violation(
                        field=fname,
                        kind="unknown_constraint",
                        reason="constraint entry is not a `{type, data}` object",
                    )
                )
                continue
            c_type = constraint.get("type")
            c_data = constraint.get("data") or {}
            if not isinstance(c_type, str):
                out.append(
                    _Violation(
                        field=fname,
                        kind="unknown_constraint",
                        reason="constraint missing `type`",
                    )
                )
                continue

            verdict = await _dispatch_constraint(value, c_type, c_data, ctx)
            if verdict.get("valid") is True:
                continue
            kind = verdict.get("violation_kind", "constraint")
            out.append(
                _Violation(
                    field=fname,
                    kind=kind,
                    constraint=c_type,
                    reason=verdict.get("reason", "constraint failed"),
                )
            )
    return out


async def _dispatch_constraint(
    value: Any,
    constraint_type: str,
    constraint_data: dict[str, Any],
    ctx: "HandlerContext",
) -> dict[str, Any]:
    """Dispatch one constraint via `ctx.execute()` per §2.2.

    Returns `{valid, reason?, violation_kind?}`. ``violation_kind`` is
    set to ``"unknown_constraint"`` when the constraint handler is
    missing or when the handler itself reports unknown semantics
    (consistent with §1.2 fail-closed).
    """
    request = {
        "data": {
            "value": value,
            "constraint_type": constraint_type,
            "constraint_data": constraint_data,
        }
    }
    try:
        result = await ctx.execute(constraint_type, "validate", request)
    except Exception as exc:  # pragma: no cover — defensive; ctx.execute returns ExecuteResult
        return {
            "valid": False,
            "reason": f"constraint_dispatch_failed: {exc}",
            "violation_kind": "unknown_constraint",
        }

    if not result.ok:
        # Dispatch resolved but the handler refused — treat the
        # underlying constraint as unevaluable (§1.2 fail-closed).
        msg = result.error or f"dispatch failed with status {result.status}"
        return {
            "valid": False,
            "reason": f"constraint_dispatch_failed: {msg}",
            "violation_kind": "unknown_constraint",
        }

    body = (result.result or {}).get("data") or {}
    if body.get("valid") is True:
        return {"valid": True}

    reason = body.get("reason") or "constraint failed"
    # Heuristic: the standard handler's "unknown constraint type: …"
    # reason maps to §1.2's unknown_constraint kind. Same for "unknown
    # format: …". Anything else is a regular constraint failure.
    kind = (
        "unknown_constraint"
        if reason.startswith("unknown constraint type:")
        or reason.startswith("unknown format:")
        else "constraint"
    )
    return {"valid": False, "reason": reason, "violation_kind": kind}


# ---------------------------------------------------------------------------
# Result shaping
# ---------------------------------------------------------------------------


def _ok_result(
    *,
    valid: bool,
    violations: list[_Violation],
    unevaluated_fields: list[str],
) -> dict[str, Any]:
    data: dict[str, Any] = {"valid": valid}
    if violations:
        data["violations"] = [v.as_dict() for v in violations]
    if unevaluated_fields:
        data["unevaluated_fields"] = unevaluated_fields
    return {"status": 200, "result": {"type": _VALIDATE_RESULT_TYPE, "data": data}}


__all__ = [
    "TYPE_HANDLER_PATTERN",
    "type_handler",
]
