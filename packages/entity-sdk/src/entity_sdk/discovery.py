"""Discovery — `SDK-OPERATIONS` v0.8 §9.

Both helpers are exactly what the spec says they are: *"Implemented as
`list("system/handler/")` + reading each manifest/interface entity"* and the
same over `system/type/`. They compose on the §3 operations and add nothing to
the wire.

What they *do* add is two projections the spec pins as normative, and both are
places a caller rolling their own would go wrong:

* **`HandlerInfo.pattern` is advertisement, not a dispatch URI** (§9.1). It MAY
  carry glob notation — `system/type/constraint/*` — and *"the dispatcher does
  NOT interpret this field."* A consumer building an EXECUTE target from it must
  strip the trailing `/*`. :func:`dispatch_prefix` is that operation, named, so
  the mistake has somewhere to not happen.
* **Types are stored as a map and reported as a list** (§9.2). The stored shape
  is `fields: Map<field_name, field-spec>`; the typed caller-facing output is
  `Array<FieldInfo>`. The spec is blunt that these are not interchangeable:
  *"Implementations writing type entities MUST use the storage shape … writing
  in the typed-output shape produces structurally invalid type entities even if
  the bytes are valid CBOR."* This module only ever reads, and the projection
  runs one way.

**Ordering and membership** (§9.3): ordering is implementation-defined and
consumers MUST NOT depend on it across SDKs — so these helpers sort (stable
output beats arbitrary output for anything rendering a list), and callers
needing a specific order still sort caller-side. Membership is whatever the
caller's capability scope reaches; entities blocked by scope simply do not
appear, and *"their absence is not an error and is not signaled."*

.. rubric:: The single-level `list` note in §9.1/§9.2 does not survive real paths

**§9's implementation note is under-specified, and taking it literally returns
nothing here.** Both §9.1 and §9.2 say the helper is *"implemented as
`list("system/handler/")` + reading each … entity"*, which reads as one
single-level listing. But §3.3 pins `list` as *"single-level, direct children
only, not recursive"* — a MUST — and these entities are **not** flat children:

* a handler interface is written to ``system/handler/{pattern}``
  (`register_handler_manifests`, `entity_core/types/registry.py`), and a pattern
  contains slashes, so ``system/tree`` lands at ``system/handler/system/tree``;
* a type is written to ``system/type/{name}``, and names contain slashes too, so
  ``system/tree/listing`` lands at ``system/type/system/tree/listing``.

A single-level ``list("system/handler/")`` therefore yields the branch
``system`` and no interfaces at all. The two clauses cannot both be satisfied
literally, so these helpers **walk** — the reading that makes §9.1's *membership*
requirement (*"MUST include every `system/handler/interface` entity reachable
under the caller's capability scope"*) achievable, since the alternative
satisfies the letter of one sentence and returns an empty list. Logged for
upstream: the note should say "walk", or the storage convention should flatten.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "OperationInfo",
    "HandlerInfo",
    "FieldInfo",
    "TypeInfo",
    "dispatch_prefix",
    "discover_handlers",
    "discover_types",
    "HANDLER_PREFIX",
    "TYPE_PREFIX",
]

HANDLER_PREFIX = "system/handler/"
TYPE_PREFIX = "system/type/"


@dataclass(frozen=True, slots=True)
class OperationInfo:
    """§9.1 — one operation on a handler."""

    name: str
    input_type: str | None = None
    output_type: str | None = None


@dataclass(frozen=True, slots=True)
class HandlerInfo:
    """§9.1 — one advertised handler."""

    #: The manifest's **advertisement** pattern. MAY contain a trailing `/*`.
    #: Not a dispatch URI — see :func:`dispatch_prefix`.
    pattern: str
    name: str
    operations: list[OperationInfo] = field(default_factory=list)

    @property
    def dispatch_prefix(self) -> str:
        """The literal prefix to build an EXECUTE target from (V7 §6.6)."""
        return dispatch_prefix(self.pattern)


@dataclass(frozen=True, slots=True)
class FieldInfo:
    """§9.2 — one field of a type, in the typed *output* shape."""

    name: str
    type_ref: str
    optional: bool = False


@dataclass(frozen=True, slots=True)
class TypeInfo:
    """§9.2 — one type definition, in the typed *output* shape."""

    type_path: str
    fields: list[FieldInfo] = field(default_factory=list)


def dispatch_prefix(pattern: str) -> str:
    """Turn an advertisement ``pattern`` into a dispatch prefix (§9.1, V7 §6.6).

    *"Consumers building EXECUTE targets from `HandlerInfo.pattern` MUST handle
    the convention … strip trailing `/*` to obtain the dispatch prefix."*

    Dispatching to the raw pattern is the failure this prevents: an EXECUTE at
    ``system/type/constraint/*`` addresses a literal path segment named ``*``,
    which no handler is registered at, so it 404s — and it 404s in a way that
    reads like the handler is missing rather than like the URI is malformed.
    """
    if pattern.endswith("/*"):
        return pattern[: -len("/*")]
    return pattern


def _field_type_ref(spec: Any) -> str:
    """Best-effort scalar name for a `system/type/field-spec`.

    §9.2's `FieldInfo.type_ref` is a single string, but the stored field-spec
    alphabet is exactly-one-of ``type_ref`` / ``array_of`` / ``map_of`` /
    ``union_of`` / ``type_param``. Only the first is a plain name; the rest are
    structural. Rendering them as ``array_of<...>`` keeps the typed output
    populated and honest about what it is, rather than silently emitting an
    empty ``type_ref`` for every collection field.
    """
    if not isinstance(spec, dict):
        return ""
    direct = spec.get("type_ref")
    if isinstance(direct, str):
        return direct
    for key in ("array_of", "map_of"):
        inner = spec.get(key)
        if inner is not None:
            return f"{key}<{_field_type_ref(inner)}>"
    union = spec.get("union_of")
    if isinstance(union, list):
        return "union_of<" + " | ".join(_field_type_ref(m) for m in union) + ">"
    param = spec.get("type_param")
    if isinstance(param, str):
        return f"type_param<{param}>"
    return ""


def _operations_from(data: Any) -> list[OperationInfo]:
    ops = data.get("operations") if isinstance(data, dict) else None
    if not isinstance(ops, dict):
        return []
    out = [
        OperationInfo(
            name=name,
            input_type=(spec or {}).get("input_type") if isinstance(spec, dict) else None,
            output_type=(spec or {}).get("output_type") if isinstance(spec, dict) else None,
        )
        for name, spec in ops.items()
        if isinstance(name, str)
    ]
    out.sort(key=lambda o: o.name)
    return out


def _handler_from(entity: Any, fallback_name: str) -> HandlerInfo | None:
    if not isinstance(entity, dict):
        return None
    # Only the public contract. The sibling `system/handler` dispatch-target
    # entity lives under this prefix too (the handlers handler's own interface
    # is at `system/handler/system/handler`) and carries `interface`, not
    # `pattern` — filtering on the envelope type says so, rather than relying
    # on the shape check below to reject it by accident.
    if entity.get("type") != "system/handler/interface":
        return None
    data = entity.get("data")
    if not isinstance(data, dict):
        return None
    pattern = data.get("pattern")
    if not isinstance(pattern, str):
        return None
    name = data.get("name")
    return HandlerInfo(
        pattern=pattern,
        name=name if isinstance(name, str) else fallback_name,
        operations=_operations_from(data),
    )


def _type_from(entity: Any, path: str) -> TypeInfo | None:
    if not isinstance(entity, dict):
        return None
    data = entity.get("data")
    if not isinstance(data, dict):
        return None
    raw_fields = data.get("fields")
    fields: list[FieldInfo] = []
    if isinstance(raw_fields, dict):
        # Storage shape is a MAP keyed by field name (§9.2 / ENTITY-NATIVE-TYPE
        # -SYSTEM §4.1); the typed output is a list. One-way projection.
        for fname, spec in raw_fields.items():
            if not isinstance(fname, str):
                continue
            fields.append(
                FieldInfo(
                    name=fname,
                    type_ref=_field_type_ref(spec),
                    optional=bool(spec.get("optional", False))
                    if isinstance(spec, dict)
                    else False,
                )
            )
        fields.sort(key=lambda f: f.name)
    name = data.get("name")
    return TypeInfo(
        type_path=name if isinstance(name, str) else path,
        fields=fields,
    )


#: Depth cap for the discovery walk. Handler and type paths are a handful of
#: segments deep; anything past this is a cycle or a pathological tree, and an
#: unbounded walk over a hostile peer's namespace is a denial-of-service the
#: caller never asked for.
MAX_WALK_DEPTH = 12


async def _walk(client: Any, prefix: str, depth: int = 0) -> list[Any]:
    """Depth-first collect of every leaf entry under ``prefix``.

    See the module docstring for why this walks rather than single-level lists.
    An entry with ``has_children`` is descended into; a leaf is collected. An
    entry can be both — a path may hold an entity *and* have children — so both
    branches run, not one or the other.

    Capability failures below the root are swallowed rather than aborting the
    walk: §9.3 says out-of-scope entities *"MUST NOT appear; their absence is
    not an error and is not signaled"*, so a scoped caller gets the subset it
    can see rather than a 403 for the whole call.
    """
    from entity_sdk.errors import AuthorizationError, NotFound

    if depth >= MAX_WALK_DEPTH:
        return []
    try:
        entries = await client.list(prefix)
    except (AuthorizationError, NotFound):
        return []

    collected: list[Any] = []
    for entry in entries:
        collected.append(entry)
        if entry.has_children:
            collected.extend(await _walk(client, entry.path + "/", depth + 1))
    return collected


async def discover_handlers(client: Any) -> list[HandlerInfo]:
    """Every handler advertised under the caller's scope (§9.1).

    Absence is not an error: a handler outside the caller's capability scope
    simply is not listed, and §9.3 says that is not signaled.
    """
    out: list[HandlerInfo] = []
    seen: set[str] = set()
    for entry in await _walk(client, HANDLER_PREFIX):
        entity = await client.get(entry.path)
        info = _handler_from(entity, entry.name)
        if info is not None and info.pattern not in seen:
            seen.add(info.pattern)
            out.append(info)
    out.sort(key=lambda h: h.pattern)
    return out


async def discover_types(client: Any) -> list[TypeInfo]:
    """Every type definition under the caller's scope (§9.2)."""
    out: list[TypeInfo] = []
    seen: set[str] = set()
    for entry in await _walk(client, TYPE_PREFIX):
        entity = await client.get(entry.path)
        if not isinstance(entity, dict) or entity.get("type") != "system/type":
            # A branch node on the way down to a real type, or an unrelated
            # entity parked under the prefix. Filtering on the envelope type
            # rather than on path shape keeps this honest if the layout moves.
            continue
        info = _type_from(entity, entry.name)
        if info is not None and info.type_path not in seen:
            seen.add(info.type_path)
            out.append(info)
    out.sort(key=lambda t: t.type_path)
    return out
