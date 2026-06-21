"""Narrowing verification for EXTENSION-TYPE v1.1 §6.

When a child type extends a parent type, the child's constraints MUST
be equal-to-or-more-restrictive than the parent's. This guarantees
Liskov substitution per §6.1 — any entity valid for the child type
is also valid for the parent type.

Hooked from ``type_handler:_op_validate`` whenever the input entity
itself is a ``system/type`` definition and carries an ``extends``
chain (§6.4). Tree-write-time validation is a separate concern that
lives on the tree handler per §9; this module only owns the
inline-validate surface.

Algorithm classification per §5.5: **Conformance** — two
implementations MUST accept/reject the same `extends` relationships.
The §6.2 rules table is the contract; the verification code is
illustrative.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from entity_core.utils.ecf import ecf_encode as _ecf_encode

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext

# Constraint kinds the narrowing rule table covers. Anything else
# (custom constraint types from §2.2) is **incomparable by default**:
# child must repeat byte-identical constraint data to narrow. The
# spec mandates this for `pattern` and `format` explicitly and
# implies it for arbitrary custom constraints (no normative
# narrowing recogniser exists).
_NUMERIC_MIN_KINDS = frozenset({
    "system/type/constraint/min",
    "system/type/constraint/min-length",
    "system/type/constraint/min-count",
})
_NUMERIC_MAX_KINDS = frozenset({
    "system/type/constraint/max",
    "system/type/constraint/max-length",
    "system/type/constraint/max-count",
})
_EQUAL_ONLY_KINDS = frozenset({
    "system/type/constraint/pattern",
    "system/type/constraint/format",
})
_ONE_OF_KIND = "system/type/constraint/one-of"
_NOT_ONE_OF_KIND = "system/type/constraint/not-one-of"
_TYPE_PATTERN_KIND = "system/type/constraint/type-pattern"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def verify_narrowing(
    child_def: dict[str, Any],
    resolve_type: "Any",
) -> list[dict[str, Any]]:
    """Verify that ``child_def`` narrows its ``extends`` parent chain.

    Returns a list of violation dicts shaped like ``{field, kind,
    reason, constraint?}`` matching the type-handler's violation
    contract. Empty list = narrowing OK.

    ``resolve_type`` is the (name -> type-def dict | None) resolver
    handed down by the caller — `type_handler` passes its
    Strategy-1 lookup so this module doesn't take a hard dependency
    on the handler context shape.
    """
    out: list[dict[str, Any]] = []
    parent_name = child_def.get("extends")
    if not isinstance(parent_name, str) or not parent_name:
        return out

    # Walk the parent chain. Each level's fields are compared against
    # the child's fields independently — every ancestor's constraint
    # set must be narrowed, not just the direct parent's, because
    # §6.3 says constraint sets only grow through `extends` and the
    # child can't remove a constraint introduced by *any* ancestor.
    visited: set[str] = set()
    name = child_def.get("name")
    if isinstance(name, str):
        visited.add(name)

    child_fields = _safe_fields(child_def)

    cursor_name = parent_name
    while cursor_name:
        if cursor_name in visited:
            # Cycle — surfaced separately by effective-fields walk; emit
            # nothing here so we don't double-report.
            return out
        visited.add(cursor_name)
        parent = resolve_type(cursor_name)
        if parent is None:
            # Parent not resolvable — surfaced separately by
            # effective-fields walk; don't double-report.
            return out

        parent_fields = _safe_fields(parent)
        for field_name, parent_spec in parent_fields.items():
            parent_constraints = _constraints(parent_spec)
            if not parent_constraints:
                continue
            child_spec = child_fields.get(field_name)
            child_constraints = _constraints(child_spec) if child_spec else []
            out.extend(
                _diff_constraints(
                    field_name, parent_constraints, child_constraints,
                )
            )

        cursor_name = parent.get("extends")
        if not isinstance(cursor_name, str) or not cursor_name:
            break

    return out


# ---------------------------------------------------------------------------
# Per-field constraint diff
# ---------------------------------------------------------------------------


def _diff_constraints(
    field_name: str,
    parent_constraints: list[dict[str, Any]],
    child_constraints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """For each parent constraint, find a matching child constraint of
    the same type and verify the child narrows it.

    §6.3: child MUST NOT remove a parent constraint. A missing child
    counterpart is a violation. The child MAY add constraints absent
    on the parent — adding always narrows — so child-only entries
    don't show up here.
    """
    out: list[dict[str, Any]] = []
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for c in child_constraints:
        if isinstance(c, dict) and isinstance(c.get("type"), str):
            by_kind.setdefault(c["type"], []).append(c)

    for parent_c in parent_constraints:
        if not isinstance(parent_c, dict):
            continue
        p_type = parent_c.get("type")
        if not isinstance(p_type, str):
            continue

        matches = by_kind.get(p_type, [])
        if not matches:
            out.append({
                "field": field_name,
                "kind": "structural",
                "constraint": p_type,
                "reason": (
                    f"narrowing violation: child removed parent constraint "
                    f"{p_type}"
                ),
            })
            continue

        # Any matching child entry that narrows the parent satisfies
        # the rule. (Standard CTOR generates one constraint of each
        # kind per field; multi-entry sets are atypical but
        # supported.)
        narrowed_by_any = False
        last_reason = ""
        for child_c in matches:
            ok, reason = _is_narrower(p_type, child_c.get("data") or {}, parent_c.get("data") or {})
            if ok:
                narrowed_by_any = True
                break
            last_reason = reason

        if not narrowed_by_any:
            out.append({
                "field": field_name,
                "kind": "structural",
                "constraint": p_type,
                "reason": f"narrowing violation on {p_type}: {last_reason}",
            })

    return out


# ---------------------------------------------------------------------------
# Per-kind narrowing predicates (§6.2)
# ---------------------------------------------------------------------------


def _is_narrower(
    kind: str,
    child_data: dict[str, Any],
    parent_data: dict[str, Any],
) -> tuple[bool, str]:
    """Return ``(narrower, reason_if_not)`` per the §6.2 table."""
    # Numeric lower bounds: child.min >= parent.min.
    if kind == "system/type/constraint/min":
        return _check_min_bound("min", child_data, parent_data)
    if kind == "system/type/constraint/min-length":
        return _check_min_bound("min_length", child_data, parent_data)
    if kind == "system/type/constraint/min-count":
        return _check_min_bound("min_count", child_data, parent_data)
    # Numeric upper bounds: child.max <= parent.max.
    if kind == "system/type/constraint/max":
        return _check_max_bound("max", child_data, parent_data)
    if kind == "system/type/constraint/max-length":
        return _check_max_bound("max_length", child_data, parent_data)
    if kind == "system/type/constraint/max-count":
        return _check_max_bound("max_count", child_data, parent_data)

    # §6.2 equal-only kinds: pattern, format.
    if kind == "system/type/constraint/pattern":
        return _check_equal_field(child_data, parent_data, "pattern")
    if kind == "system/type/constraint/format":
        return _check_equal_field(child_data, parent_data, "format")

    # §6.2 set kinds: one_of ⊆, not_one_of ⊇ (ECF byte equality per element).
    if kind == _ONE_OF_KIND:
        return _check_subset(child_data, parent_data)
    if kind == _NOT_ONE_OF_KIND:
        return _check_superset(child_data, parent_data)

    # §6.2 type_pattern: child more-specific (longer prefix or exact match).
    if kind == _TYPE_PATTERN_KIND:
        return _check_type_pattern(child_data, parent_data)

    # Unknown / custom constraint kind: equal-only by default.
    # Mirrors the §6.2 stance for pattern / format — no speculative
    # narrowing recogniser. Byte-identical `data` narrows trivially;
    # anything else is incomparable.
    if _ecf_encode(child_data) == _ecf_encode(parent_data):
        return True, ""
    return False, "custom constraint: child data not byte-equal to parent (incomparable)"


def _check_min_bound(
    field: str, child: dict[str, Any], parent: dict[str, Any],
) -> tuple[bool, str]:
    c = child.get(field)
    p = parent.get(field)
    if not _is_numeric(c) or not _is_numeric(p):
        return False, f"missing numeric '{field}'"
    if c >= p:
        return True, ""
    return False, f"child.{field}={c} < parent.{field}={p} (widens lower bound)"


def _check_max_bound(
    field: str, child: dict[str, Any], parent: dict[str, Any],
) -> tuple[bool, str]:
    c = child.get(field)
    p = parent.get(field)
    if not _is_numeric(c) or not _is_numeric(p):
        return False, f"missing numeric '{field}'"
    if c <= p:
        return True, ""
    return False, f"child.{field}={c} > parent.{field}={p} (widens upper bound)"


def _check_equal_field(
    child: dict[str, Any], parent: dict[str, Any], field: str,
) -> tuple[bool, str]:
    """Equal-only rule: child narrows iff byte-identical under ECF.

    §6.2: "Non-equal patterns default to incomparable" — same stance
    for `format`. No speculative subset-recogniser.
    """
    if _ecf_encode(child.get(field)) == _ecf_encode(parent.get(field)):
        return True, ""
    return False, (
        f"child.{field}={child.get(field)!r} != parent.{field}={parent.get(field)!r} "
        f"(non-equal → incomparable per §6.2)"
    )


def _check_subset(
    child: dict[str, Any], parent: dict[str, Any],
) -> tuple[bool, str]:
    """one_of: child.values ⊆ parent.values via ECF byte equality."""
    cv = child.get("values")
    pv = parent.get("values")
    if not isinstance(cv, list) or not isinstance(pv, list):
        return False, "missing 'values' array"
    parent_encoded = {_ecf_encode(v) for v in pv}
    for v in cv:
        if _ecf_encode(v) not in parent_encoded:
            return False, (
                f"one_of: child value {v!r} not in parent.values (widens enumeration)"
            )
    return True, ""


def _check_superset(
    child: dict[str, Any], parent: dict[str, Any],
) -> tuple[bool, str]:
    """not_one_of: child.values ⊇ parent.values via ECF byte equality.

    Larger denylist = narrower constraint.
    """
    cv = child.get("values")
    pv = parent.get("values")
    if not isinstance(cv, list) or not isinstance(pv, list):
        return False, "missing 'values' array"
    child_encoded = {_ecf_encode(v) for v in cv}
    for v in pv:
        if _ecf_encode(v) not in child_encoded:
            return False, (
                f"not_one_of: parent denied {v!r} but child does not (widens by allowing it)"
            )
    return True, ""


def _check_type_pattern(
    child: dict[str, Any], parent: dict[str, Any],
) -> tuple[bool, str]:
    """§6.2 type_pattern: child pattern is more specific.

    Concretely: child is more specific iff child equals parent OR
    parent uses ``**``/``*`` segments that child collapses to literal
    segments (longer literal prefix). The spec text is "more specific
    (longer prefix or exact match)" — we accept either.
    """
    c = child.get("pattern")
    p = parent.get("pattern")
    if not isinstance(c, str) or not isinstance(p, str):
        return False, "missing 'pattern' string"
    if c == p:
        return True, ""
    # Longer literal prefix (no glob characters in the extension)
    # qualifies as more specific.
    if c.startswith(_literal_prefix(p)) and len(c) > len(p):
        return True, ""
    return False, (
        f"child.pattern={c!r} not more specific than parent.pattern={p!r}"
    )


def _literal_prefix(pattern: str) -> str:
    """Return the leading literal segment of a glob pattern (up to the
    first ``*`` character)."""
    idx = pattern.find("*")
    return pattern if idx == -1 else pattern[:idx]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_fields(type_def: dict[str, Any]) -> dict[str, dict[str, Any]]:
    fields = type_def.get("fields")
    if not isinstance(fields, dict):
        return {}
    return {k: v for k, v in fields.items() if isinstance(v, dict)}


def _constraints(field_spec: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(field_spec, dict):
        return []
    cs = field_spec.get("constraints")
    if not isinstance(cs, list):
        return []
    return cs


def _is_numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


__all__ = ["verify_narrowing"]
