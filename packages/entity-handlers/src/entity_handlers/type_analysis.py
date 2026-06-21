"""Type analysis ops for EXTENSION-TYPE v1.1 §7.

This module owns the four read-only analysis ops on system/type:

* ``compare``  — structural diff (§7.2). SHOULD-implement per §12.2.
* ``compatible`` — directional compatibility check (§7.3). SHOULD.
* ``converge`` — intersection across N definitions (§7.4). MAY.
* ``adopt``    — install a remote peer's type def locally (§7.5). MAY.
* ``reconcile`` — strategy-merge diverged definitions (§7.6). MAY.

All ops are read-only — they return results inline; the caller
decides whether to ``put`` any derived definitions into the tree.
This matches §9 (no writes) and keeps capability requirements simple
(tree-read on `system/type/*`).

Algorithm classification (§5.5): Reference. The pseudocode in the
spec shows expected behavior; impls may use different walks as long
as the structural-equivalence result is the same.
"""

from __future__ import annotations

from typing import Any, Callable

from entity_core.utils.ecf import ecf_encode as _ecf_encode

# Result type names owned by EXTENSION-TYPE v1.1 §7.x / §8.x.
COMPARE_RESULT_TYPE = "system/type/compare-result"
COMPATIBILITY_REPORT_TYPE = "system/type/compatibility-report"
TYPE_ENTITY_TYPE = "system/type"
RECONCILE_RESULT_TYPE = "system/type/reconcile-result"

# Named-type_ref entries inside `array_of` / `map_of` are flat per the
# entity-field-annotation rule: only `type_ref: "core/entity"` carries
# a `{type, data}` wrapper. Both Go and the existing core/query/match
# convention emit flat records here; we follow that contract so the
# cross-impl validate-peer category sees byte-equivalent shapes.


# A type resolver is `(path_or_name) -> type_def_dict | None`. We
# accept tree paths (the §7.x request shape) or bare type names
# (Strategy 1) by stripping a leading "system/type/" if present.
TypeResolver = Callable[[str], dict[str, Any] | None]


# ---------------------------------------------------------------------------
# Helpers shared across ops
# ---------------------------------------------------------------------------


def _normalize_type_lookup(path_or_name: str) -> str:
    """Accept any of:

    * a bare type name (``app/user``)
    * a peer-relative tree path (``system/type/app/user``)
    * an absolute tree path (``/{peer_id}/system/type/app/user``)

    Returns the bare name suitable for Strategy-1 lookup.

    Cross-peer resolution (e.g. ``/peerB/system/type/foo`` resolved on
    peerA) is a transport concern — at the op level we just want the
    name to look up locally. Real cross-peer adopt routes through the
    peer's outbound dispatch separately.
    """
    s = path_or_name.lstrip("/")
    if s.startswith("system/type/"):
        return s[len("system/type/"):]
    # Absolute tree path: /{peer_id}/system/type/{name}
    parts = s.split("/", 2)
    if len(parts) == 3 and parts[1] == "system" and parts[2].startswith("type/"):
        return parts[2][len("type/"):]
    return s


def _effective_fields(
    type_def: dict[str, Any],
    resolve: TypeResolver,
) -> dict[str, dict[str, Any]]:
    """Walk the extends chain and return the effective field set.

    Mirrors `type_handler._effective_fields` but is intentionally
    standalone — analysis ops shouldn't need a handler context.
    Cycle and missing-parent are treated as "stop walking" rather
    than fatal errors here (the spec doesn't gate analysis ops on
    parent-resolution success).
    """
    visited: set[str] = set()
    fields: dict[str, dict[str, Any]] = {}

    chain: list[dict[str, Any]] = []
    cursor: dict[str, Any] | None = type_def
    while cursor is not None:
        name = cursor.get("name")
        if isinstance(name, str):
            if name in visited:
                break
            visited.add(name)
        chain.append(cursor)
        parent_name = cursor.get("extends")
        if not isinstance(parent_name, str) or not parent_name:
            break
        cursor = resolve(parent_name)

    # parents → child so child overrides win.
    for link in reversed(chain):
        link_fields = link.get("fields")
        if not isinstance(link_fields, dict):
            continue
        for fname, fspec in link_fields.items():
            if isinstance(fspec, dict):
                fields[fname] = fspec
    return fields


def _field_type_signature(field_spec: dict[str, Any]) -> str:
    """A compact signature for "what type is this field?".

    Used for the structural-compatibility check in `compare` /
    `compatible`. We deliberately strip `optional`, `constraints`,
    and `default` — those are independent of structural type per
    NATIVE-TYPE-SYSTEM §12.2.
    """
    if "type_ref" in field_spec:
        return f"type_ref:{field_spec['type_ref']}"
    if "array_of" in field_spec:
        inner = field_spec["array_of"]
        if isinstance(inner, dict):
            return f"array_of:{_field_type_signature(inner)}"
        return "array_of:?"
    if "map_of" in field_spec:
        inner = field_spec["map_of"]
        key = field_spec.get("key_type") or "primitive/string"
        if isinstance(inner, dict):
            return f"map_of[{key}]:{_field_type_signature(inner)}"
        return f"map_of[{key}]:?"
    if "union_of" in field_spec:
        alts = field_spec["union_of"]
        if isinstance(alts, list):
            parts = sorted(
                _field_type_signature(a) for a in alts if isinstance(a, dict)
            )
            return "union(" + "|".join(parts) + ")"
    return "?"


def _constraint_signature(field_spec: dict[str, Any]) -> bytes:
    """Canonical bytes for a field's constraint set, ignoring order."""
    cs = field_spec.get("constraints")
    if not isinstance(cs, list) or not cs:
        return b""
    encoded = sorted(_ecf_encode(c) for c in cs if isinstance(c, dict))
    return _ecf_encode(encoded)


# ---------------------------------------------------------------------------
# compare (§7.2)
# ---------------------------------------------------------------------------


def op_compare(
    type_a_path: str,
    type_b_path: str,
    resolve: TypeResolver,
) -> dict[str, Any]:
    """Structural diff per §7.2.

    Returns a ``system/type/compare-result``-shaped dict. Both paths
    are resolved via the shared ``resolve`` callable; missing types
    surface as empty effective-field sets so the caller can still
    see what's on the other side.
    """
    a_def = resolve(_normalize_type_lookup(type_a_path))
    b_def = resolve(_normalize_type_lookup(type_b_path))
    a_fields = _effective_fields(a_def, resolve) if a_def is not None else {}
    b_fields = _effective_fields(b_def, resolve) if b_def is not None else {}

    shared: dict[str, dict[str, Any]] = {}
    incompatible: list[dict[str, Any]] = []
    only_a: list[str] = []
    only_b: list[str] = []

    for fname in sorted(set(a_fields) | set(b_fields)):
        if fname in a_fields and fname in b_fields:
            a_spec = a_fields[fname]
            b_spec = b_fields[fname]
            a_sig = _field_type_signature(a_spec)
            b_sig = _field_type_signature(b_spec)
            type_match = a_sig == b_sig
            constraint_match = (
                _constraint_signature(a_spec) == _constraint_signature(b_spec)
            )
            row: dict[str, Any] = {
                "type_match": type_match,
                "constraint_match": constraint_match,
                "a_optional": a_spec.get("optional") is True,
                "b_optional": b_spec.get("optional") is True,
            }
            if not type_match:
                row["detail"] = f"a={a_sig} b={b_sig}"
            # Flat shape — `map_of system/type/field-comparison`
            # holds the field-comparison record directly, not an
            # entity envelope.
            shared[fname] = row

            if not type_match:
                # Flat shape — `array_of system/type/field-incompatibility`.
                incompatible.append({
                    "field_name": fname,
                    "a_type": a_sig,
                    "b_type": b_sig,
                    "reason": "field type mismatch",
                })
        elif fname in a_fields:
            only_a.append(fname)
        else:
            only_b.append(fname)

    result: dict[str, Any] = {
        "type_a_path": type_a_path,
        "type_b_path": type_b_path,
        "shared": shared,
        "only_a": only_a,
        "only_b": only_b,
    }
    if incompatible:
        result["incompatible"] = incompatible
    return result


# ---------------------------------------------------------------------------
# compatible (§7.3)
# ---------------------------------------------------------------------------


def op_compatible(
    type_a_path: str,
    type_b_path: str,
    direction: str,
    resolve: TypeResolver,
) -> dict[str, Any]:
    """Directional compatibility per §7.3.

    * forward — entities of type A can satisfy type B.
      Required: every required field of B is present in A with a
      compatible type.
    * backward — entities of type B can satisfy type A. Mirror of
      forward with A and B swapped.
    * bidirectional — both directions hold.
    """
    if direction not in {"forward", "backward", "bidirectional"}:
        raise ValueError(f"invalid direction: {direction}")

    a_def = resolve(_normalize_type_lookup(type_a_path))
    b_def = resolve(_normalize_type_lookup(type_b_path))
    a_fields = _effective_fields(a_def, resolve) if a_def is not None else {}
    b_fields = _effective_fields(b_def, resolve) if b_def is not None else {}

    shared_names = sorted(set(a_fields) & set(b_fields))
    incompatible: list[dict[str, Any]] = []
    for fname in shared_names:
        a_sig = _field_type_signature(a_fields[fname])
        b_sig = _field_type_signature(b_fields[fname])
        if a_sig != b_sig:
            # Flat shape — `array_of system/type/field-incompatibility`.
            incompatible.append({
                "field_name": fname,
                "a_type": a_sig,
                "b_type": b_sig,
                "reason": "field type mismatch",
            })

    # missing_required_X: a required field on X (i.e. !optional)
    # absent from the *other* side.
    missing_required_a = sorted(
        f for f in a_fields
        if a_fields[f].get("optional") is not True and f not in b_fields
    )
    missing_required_b = sorted(
        f for f in b_fields
        if b_fields[f].get("optional") is not True and f not in a_fields
    )

    # Direction semantics: "A satisfies B" iff B has no required
    # field that A is missing, AND there are no shared-name type
    # mismatches. (Symmetric type mismatches break both directions.)
    forward_ok = (not missing_required_b) and not incompatible
    backward_ok = (not missing_required_a) and not incompatible

    if forward_ok and backward_ok:
        level = "fully_compatible"
    elif direction == "forward":
        level = "forward_only" if forward_ok else (
            "partially_compatible" if shared_names else "incompatible"
        )
    elif direction == "backward":
        level = "backward_only" if backward_ok else (
            "partially_compatible" if shared_names else "incompatible"
        )
    else:  # bidirectional
        if forward_ok:
            level = "forward_only"
        elif backward_ok:
            level = "backward_only"
        elif shared_names:
            level = "partially_compatible"
        else:
            level = "incompatible"

    report: dict[str, Any] = {
        "type_a_path": type_a_path,
        "type_b_path": type_b_path,
        "direction": direction,
        "level": level,
        "shared_fields": shared_names,
    }
    if incompatible:
        report["incompatible_fields"] = incompatible
    if missing_required_a:
        report["missing_required_a"] = missing_required_a
    if missing_required_b:
        report["missing_required_b"] = missing_required_b
    return report


# ---------------------------------------------------------------------------
# converge (§7.4) — intersection
# ---------------------------------------------------------------------------


def op_converge(
    type_paths: list[str],
    resolve: TypeResolver,
) -> dict[str, Any]:
    """Intersection type across N definitions per §7.4.

    Keeps a field only when ALL definitions have it AND the field's
    type signatures match across all of them. The converged
    definition's `name` is synthesized from the source paths so the
    caller can identify it; the caller decides whether to publish it.
    """
    if len(type_paths) < 2:
        raise ValueError("converge requires at least 2 type paths (per §7.4 spec)")

    defs: list[dict[str, Any]] = []
    fields_list: list[dict[str, dict[str, Any]]] = []
    for path in type_paths:
        d = resolve(_normalize_type_lookup(path))
        if d is None:
            raise ValueError(f"converge: type not resolvable: {path}")
        defs.append(d)
        fields_list.append(_effective_fields(d, resolve))

    common = set(fields_list[0])
    for f in fields_list[1:]:
        common &= set(f)

    merged: dict[str, dict[str, Any]] = {}
    for fname in sorted(common):
        signatures = {
            _field_type_signature(f[fname]) for f in fields_list
        }
        if len(signatures) != 1:
            # Type mismatch across sources — drop the field (intersection
            # is the *common* structure, and divergent types share no
            # common structural meaning).
            continue
        # Use the first source's spec as the canonical entry, but
        # intersect constraints conservatively (most restrictive wins
        # — fold via op_reconcile's intersect constraint logic).
        base = dict(fields_list[0][fname])
        intersected = _intersect_constraints(
            [f[fname].get("constraints") for f in fields_list]
        )
        if intersected:
            base["constraints"] = intersected
        elif "constraints" in base:
            base.pop("constraints")
        merged[fname] = base

    # Optional unless every source marks it required.
    for fname, spec in merged.items():
        any_required = any(
            f[fname].get("optional") is not True for f in fields_list
        )
        if not any_required:
            spec["optional"] = True

    return {
        "type": TYPE_ENTITY_TYPE,
        "data": {
            "name": _synth_converge_name(type_paths),
            "fields": merged,
        },
    }


def _synth_converge_name(paths: list[str]) -> str:
    """Synthesize a stable name for the converged result."""
    names = [_normalize_type_lookup(p) for p in paths]
    return "converged/" + "+".join(sorted(names))


# ---------------------------------------------------------------------------
# adopt (§7.5) — install a remote definition locally
# ---------------------------------------------------------------------------


def op_adopt(
    source_path: str,
    local_name: str | None,
    resolve_remote: TypeResolver,
    resolve_local: TypeResolver,
    source_peer_prefix: str | None = None,
) -> dict[str, Any]:
    """Install a remote peer's type def locally per §7.5.

    * Rewrites ``data.name`` to ``local_name`` (or a derived name if
      absent — strip the peer prefix and the ``system/type/`` segment).
    * Resolves ``extends`` references that point at the source peer:
      if a local equivalent exists, the reference is rewritten;
      otherwise a flag in ``warnings.unresolved_extends`` surfaces it
      so the caller knows to adopt the parent first.
    * Returns the rewritten ``system/type`` entity. The caller
      decides whether to ``put`` it into the tree.

    Resolution failure on the source itself raises ``ValueError`` —
    there's nothing to adopt.
    """
    source = resolve_remote(_normalize_type_lookup(source_path))
    if source is None:
        raise ValueError(f"adopt: source type not resolvable: {source_path}")

    name = local_name
    if name is None or not isinstance(name, str) or not name.strip():
        # Derive from source_path by stripping peer prefix and
        # `system/type/`. Path shape: `/{peer_id}/system/type/{name}`.
        name = _derive_local_name(source_path)

    adopted: dict[str, Any] = dict(source)
    adopted["name"] = name

    warnings: dict[str, Any] = {}
    # Rewrite extends if it points to the source peer.
    parent_name = source.get("extends")
    if isinstance(parent_name, str) and parent_name:
        local_parent = resolve_local(_normalize_type_lookup(parent_name))
        if local_parent is None:
            warnings.setdefault("unresolved_extends", []).append(parent_name)
        # else: parent already exists locally under the same name;
        # no rewrite needed since names are local-namespace identifiers.

    # Collision detection per §7.5 step 3.
    if resolve_local(name) is not None:
        warnings["collision"] = (
            f"system/type/{name} already exists locally; adopt will "
            f"overwrite when put"
        )

    result: dict[str, Any] = {"type": TYPE_ENTITY_TYPE, "data": adopted}
    if warnings:
        # Open-type extension on the result envelope per §7.5.
        result["data"]["adopt_warnings"] = warnings
    return result


def _derive_local_name(source_path: str) -> str:
    s = source_path.strip("/")
    parts = s.split("/", 2)
    # Expected shape /{peer_id}/system/type/{rest}. Strip the peer and
    # the "system/type/" segment.
    if len(parts) >= 3 and parts[1] == "system" and parts[2].startswith("type/"):
        return parts[2][len("type/"):]
    return _normalize_type_lookup(source_path)


# ---------------------------------------------------------------------------
# reconcile (§7.6) — strategy merge
# ---------------------------------------------------------------------------


def op_reconcile(
    type_paths: list[str],
    strategy: str,
    resolve: TypeResolver,
) -> dict[str, Any]:
    """Strategy merge of N type definitions per §7.6.

    Strategies:
    * ``intersect`` — keep only fields present in ALL definitions
      with compatible types; use the **most restrictive** constraint
      from any source per §7.6.
    * ``union`` — keep ALL fields from all definitions; fields not
      in every definition become optional; use the **least
      restrictive** constraint from any source.
    * ``prefer`` — first path is preferred; others contribute
      additional fields as optional; **preferred constraints win**.
    """
    if strategy not in {"intersect", "union", "prefer"}:
        raise ValueError(f"reconcile: invalid strategy: {strategy}")
    if len(type_paths) < 2:
        raise ValueError("reconcile requires at least 2 type paths (per §7.6)")

    defs: list[dict[str, Any]] = []
    fields_list: list[dict[str, dict[str, Any]]] = []
    for path in type_paths:
        d = resolve(_normalize_type_lookup(path))
        if d is None:
            raise ValueError(f"reconcile: type not resolvable: {path}")
        defs.append(d)
        fields_list.append(_effective_fields(d, resolve))

    if strategy == "intersect":
        merged, dropped, incompatibilities = _reconcile_intersect(fields_list)
        fields_made_optional: list[str] = []
    elif strategy == "union":
        merged, fields_made_optional, incompatibilities = _reconcile_union(fields_list)
        dropped = []
    else:  # prefer
        merged, fields_made_optional, incompatibilities = _reconcile_prefer(fields_list)
        dropped = []

    reconciled: dict[str, Any] = {
        "type": TYPE_ENTITY_TYPE,
        "data": {
            "name": "reconciled/" + "+".join(
                sorted(_normalize_type_lookup(p) for p in type_paths)
            ),
            "fields": merged,
        },
    }
    result: dict[str, Any] = {
        "reconciled_type": reconciled,
        "strategy_used": strategy,
        "sources": list(type_paths),
    }
    if dropped:
        result["fields_dropped"] = dropped
    if fields_made_optional:
        result["fields_made_optional"] = fields_made_optional
    if incompatibilities:
        result["incompatibilities"] = incompatibilities
    return result


def _reconcile_intersect(
    fields_list: list[dict[str, dict[str, Any]]],
) -> tuple[dict[str, dict[str, Any]], list[str], list[dict[str, Any]]]:
    common = set(fields_list[0])
    for f in fields_list[1:]:
        common &= set(f)

    merged: dict[str, dict[str, Any]] = {}
    dropped: list[str] = []
    incompatibilities: list[dict[str, Any]] = []

    all_names = set().union(*fields_list)
    for fname in sorted(all_names):
        if fname not in common:
            dropped.append(fname)
            continue
        sigs = {_field_type_signature(f[fname]) for f in fields_list}
        if len(sigs) != 1:
            dropped.append(fname)
            # Flat shape — `array_of system/type/field-incompatibility`.
            incompatibilities.append({
                "field_name": fname,
                "a_type": next(iter(sigs)),
                "b_type": "(multiple)",
                "reason": "type signatures diverge across sources",
            })
            continue
        base = dict(fields_list[0][fname])
        intersected = _intersect_constraints(
            [f[fname].get("constraints") for f in fields_list]
        )
        if intersected:
            base["constraints"] = intersected
        elif "constraints" in base:
            base.pop("constraints")
        merged[fname] = base
    return merged, dropped, incompatibilities


def _reconcile_union(
    fields_list: list[dict[str, dict[str, Any]]],
) -> tuple[dict[str, dict[str, Any]], list[str], list[dict[str, Any]]]:
    all_names = set().union(*fields_list)
    common = set(fields_list[0])
    for f in fields_list[1:]:
        common &= set(f)

    merged: dict[str, dict[str, Any]] = {}
    made_optional: list[str] = []
    incompatibilities: list[dict[str, Any]] = []

    for fname in sorted(all_names):
        present_in = [f for f in fields_list if fname in f]
        sigs = {_field_type_signature(f[fname]) for f in present_in}
        if len(sigs) != 1:
            # Flat shape — `array_of system/type/field-incompatibility`.
            incompatibilities.append({
                "field_name": fname,
                "a_type": next(iter(sigs)),
                "b_type": "(multiple)",
                "reason": "type signatures diverge — field excluded",
            })
            continue
        base = dict(present_in[0][fname])
        unioned = _union_constraints(
            [f[fname].get("constraints") for f in present_in]
        )
        if unioned:
            base["constraints"] = unioned
        elif "constraints" in base:
            base.pop("constraints")
        if fname not in common:
            base["optional"] = True
            made_optional.append(fname)
        merged[fname] = base
    return merged, made_optional, incompatibilities


def _reconcile_prefer(
    fields_list: list[dict[str, dict[str, Any]]],
) -> tuple[dict[str, dict[str, Any]], list[str], list[dict[str, Any]]]:
    preferred = fields_list[0]
    rest = fields_list[1:]
    all_names = set().union(*fields_list)

    merged: dict[str, dict[str, Any]] = {}
    made_optional: list[str] = []
    incompatibilities: list[dict[str, Any]] = []

    for fname in sorted(all_names):
        if fname in preferred:
            base = dict(preferred[fname])
            # Record incompatibility for any other source that disagrees,
            # but the preferred definition's version wins.
            pref_sig = _field_type_signature(base)
            for f in rest:
                if fname in f and _field_type_signature(f[fname]) != pref_sig:
                    # Flat shape — `array_of system/type/field-incompatibility`.
                    incompatibilities.append({
                        "field_name": fname,
                        "a_type": pref_sig,
                        "b_type": _field_type_signature(f[fname]),
                        "reason": "preferred definition's type used",
                    })
            merged[fname] = base
        else:
            # Pick the first non-preferred source that has it.
            source = next(f for f in rest if fname in f)
            base = dict(source[fname])
            base["optional"] = True
            made_optional.append(fname)
            merged[fname] = base
    return merged, made_optional, incompatibilities


# ---------------------------------------------------------------------------
# Constraint reconciliation helpers
# ---------------------------------------------------------------------------


def _intersect_constraints(
    sets: list[list[dict[str, Any]] | None],
) -> list[dict[str, Any]]:
    """Most-restrictive constraint per kind across all sources.

    Bounded kinds (min, min_length, min_count) pick the **largest**
    bound; (max, max_length, max_count) pick the **smallest** bound.
    one_of intersects values; not_one_of unions. equal-only kinds
    (pattern, format) keep the entry only when byte-identical across
    sources. Custom kinds: byte-equal across sources or dropped.
    """
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for cs in sets:
        if not isinstance(cs, list):
            continue
        for c in cs:
            if isinstance(c, dict) and isinstance(c.get("type"), str):
                by_kind.setdefault(c["type"], []).append(c)

    out: list[dict[str, Any]] = []
    for kind, items in sorted(by_kind.items()):
        if len(items) == 1:
            out.append(items[0])
            continue
        merged = _merge_kind_restrictive(kind, items)
        if merged is not None:
            out.append(merged)
    return out


def _union_constraints(
    sets: list[list[dict[str, Any]] | None],
) -> list[dict[str, Any]]:
    """Least-restrictive constraint per kind across all sources.

    Mirror of `_intersect_constraints` — for bounded kinds pick the
    looser bound; one_of unions; not_one_of intersects.
    """
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for cs in sets:
        if not isinstance(cs, list):
            continue
        for c in cs:
            if isinstance(c, dict) and isinstance(c.get("type"), str):
                by_kind.setdefault(c["type"], []).append(c)

    out: list[dict[str, Any]] = []
    for kind, items in sorted(by_kind.items()):
        if len(items) == 1:
            out.append(items[0])
            continue
        merged = _merge_kind_permissive(kind, items)
        if merged is not None:
            out.append(merged)
    return out


def _merge_kind_restrictive(
    kind: str, items: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return _merge_kind(kind, items, restrictive=True)


def _merge_kind_permissive(
    kind: str, items: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return _merge_kind(kind, items, restrictive=False)


def _merge_kind(
    kind: str, items: list[dict[str, Any]], *, restrictive: bool,
) -> dict[str, Any] | None:
    if kind in (
        "system/type/constraint/min",
        "system/type/constraint/min-length",
        "system/type/constraint/min-count",
    ):
        field = kind.rsplit("/", 1)[1]
        vals = [c.get("data", {}).get(field) for c in items]
        nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if not nums:
            return None
        picked = max(nums) if restrictive else min(nums)
        return {"type": kind, "data": {field: picked}}
    if kind in (
        "system/type/constraint/max",
        "system/type/constraint/max-length",
        "system/type/constraint/max-count",
    ):
        field = kind.rsplit("/", 1)[1]
        vals = [c.get("data", {}).get(field) for c in items]
        nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
        if not nums:
            return None
        picked = min(nums) if restrictive else max(nums)
        return {"type": kind, "data": {field: picked}}
    if kind == "system/type/constraint/one-of":
        # restrictive = intersection (smaller set); permissive = union.
        encoded = [
            {_ecf_encode(v) for v in c.get("data", {}).get("values", [])}
            for c in items
        ]
        if restrictive:
            common = encoded[0]
            for e in encoded[1:]:
                common &= e
        else:
            common = set().union(*encoded)
        # Recover the values from the first set with byte equality.
        all_vals: list[Any] = []
        for c in items:
            for v in c.get("data", {}).get("values", []):
                if _ecf_encode(v) in common and not any(
                    _ecf_encode(v) == _ecf_encode(x) for x in all_vals
                ):
                    all_vals.append(v)
        return {"type": kind, "data": {"values": all_vals}}
    if kind == "system/type/constraint/not-one-of":
        # not_one_of inverts: restrictive = union of denylists;
        # permissive = intersection.
        encoded = [
            {_ecf_encode(v) for v in c.get("data", {}).get("values", [])}
            for c in items
        ]
        if restrictive:
            common = set().union(*encoded)
        else:
            common = encoded[0]
            for e in encoded[1:]:
                common &= e
        all_vals: list[Any] = []
        for c in items:
            for v in c.get("data", {}).get("values", []):
                if _ecf_encode(v) in common and not any(
                    _ecf_encode(v) == _ecf_encode(x) for x in all_vals
                ):
                    all_vals.append(v)
        return {"type": kind, "data": {"values": all_vals}}
    # equal-only / unknown kinds: keep only if byte-identical.
    first = _ecf_encode(items[0])
    if all(_ecf_encode(c) == first for c in items[1:]):
        return items[0]
    return None


__all__ = [
    "op_compare",
    "op_compatible",
    "op_converge",
    "op_adopt",
    "op_reconcile",
    "COMPARE_RESULT_TYPE",
    "COMPATIBILITY_REPORT_TYPE",
    "RECONCILE_RESULT_TYPE",
    "TYPE_ENTITY_TYPE",
    "FIELD_COMPARISON_TYPE",
    "FIELD_INCOMPATIBILITY_TYPE",
]


# Type-name constants kept around for tests + downstream introspection.
# They name the *type entity* — the wire shape inside array_of /
# map_of is flat per the entity-field-annotation rule.
FIELD_COMPARISON_TYPE = "system/type/field-comparison"
FIELD_INCOMPATIBILITY_TYPE = "system/type/field-incompatibility"
