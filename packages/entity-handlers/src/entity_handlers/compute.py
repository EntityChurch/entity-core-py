"""Compute Extension — EXTENSION-COMPUTE v3.14.

Minimal expression language embedded in the entity type system. Programs are
entities — content-addressed, storable, transferable, and inspectable. The
compute handler evaluates expression entities and produces result entities.

Implements:
- Core evaluator with 16 expression types (§2.1, §2.2) — incl. index, length,
  numeric-cast (N.1, N.4)
- Tail call optimization via trampoline (§4.1, T1-T3)
- Compute handler with eval/install/uninstall operations (§3)
- Budget and depth constraints (§5)
- Purity classification and capability checks for impure operations (§6)
- Reactive mode with dependency tracking and re-evaluation (§7)
- Deterministic evaluation order (§8)
- Relative paths for transferable compute (R1-R2)
- Integer arithmetic: the WASM/LLVM/JVM 64-bit two's-complement model (§2.2
  rules 8-11, v3.16/v3.17). add/sub/mul are sign-agnostic; div/mod/compare are
  signed-default; numeric-cast → uint reaches the unsigned path only when it is
  the direct operand entity of the op (rule 11 Option A — syntactic, no value
  tag). Results are signed-canonical so CBOR encoding is deterministic (rule 10).
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import hashlib
import logging
import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from entity_core.capability.checking import (
    check_handler_scope,
    check_path_permission,
    check_resource_scope,
)
from entity_core.peer.extensions import Extension
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ecf_encode, is_hash_ref

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext
    from entity_core.peer.extensions import ExtensionContext
    from entity_core.storage.emit import ChangeEvent, EmitPathway

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMPUTE_HANDLER_PATTERN = "system/compute/*"

# Builtin handler paths (§3.5). The collection builtins and `store` have no
# inline expression form and are evaluated as internal aliases (N.2).
BUILTIN_PREFIX = "system/compute/builtins/"
BUILTIN_MAP = "system/compute/builtins/map"
BUILTIN_FILTER = "system/compute/builtins/filter"
BUILTIN_FOLD = "system/compute/builtins/fold"
BUILTIN_STORE = "system/compute/builtins/store"
# The v3.24 collection primitives. All four are MUST-given-COMPUTE (§10.1):
# they produce boundary bytes, so a peer computing a different result is
# divergent, not merely slower.
BUILTIN_RANGE = "system/compute/builtins/range"
BUILTIN_GROUP_BY = "system/compute/builtins/group-by"
BUILTIN_CONCAT = "system/compute/builtins/concat"
BUILTIN_ASSOC = "system/compute/builtins/assoc"

_COLLECTION_BUILTINS = frozenset({
    BUILTIN_MAP, BUILTIN_FILTER, BUILTIN_FOLD,
    BUILTIN_RANGE, BUILTIN_GROUP_BY, BUILTIN_CONCAT, BUILTIN_ASSOC,
})

#: `group-by`'s result element (§3.5, v3.25). A pinned type **name**, not a
#: type-extension registration: §2.3 N1 + §4.1 encode a constructed entity by
#: the *runtime kind* of the evaluated value and never by the declared
#: schema, so a peer with no type extension produces byte-identical groups.
TYPE_COMPUTE_GROUP = "system/compute/group"

#: §7.2 flow-through, arg axis (§3.5's table, v3.25). An arg listed here sits
#: in a **data position** — its value is *placed into* the output rather than
#: *consumed* — so a `compute/error` arriving there flows in as a value
#: instead of short-circuiting the whole apply.
#:
#: `store`'s `value` is the SA-9 write payload (ruled 2026-08-16); `assoc`'s
#: `value` is the same shape one primitive over. `fold`'s `initial` joined them
#: at the C-8 ruling (2026-08-21): it is **bound into the closure**, not read by
#: `fold`, so it is a contained position by the rule that ruling states —
#: *places-without-reading contains; reads-to-decide consumes*. **Every other
#: position of every other builtin is consumed and short-circuits** — that is
#: the half of v3.26 the ruling calls "add the carve-out, not remove the guard",
#: stated at the arg boundary instead of at materialization.
_CONTAINED_ARGS: dict[str, tuple[str, ...]] = {
    BUILTIN_STORE: ("value",),
    BUILTIN_ASSOC: ("value",),
    BUILTIN_FOLD: ("initial",),
}

#: The maximum array length `range` will produce (§3.5 v3.25: *"an `n`
#: exceeding the maximum representable array length"* is `count_out_of_range`).
#:
#: **Python has no such bound and that is the hazard.** In go and rust an `n`
#: above `MaxInt64` fails the decode into the index type and never reaches the
#: comparison; `cbor2` hands back an arbitrary-precision `int`, so the same
#: program would sail past a naive `n < 0` check and try to build the list.
#: Same class as the CAP-6a temporal-bounds defect (`capability/temporal.py`):
#: *where a peer language fails closed by decoding, we fail closed by
#: checking.* Pinned at go's own boundary so the refusal set is identical.
MAX_ARRAY_LENGTH = 2**63 - 1

# Inline-equivalent builtins (§3.5): the handler form IS an alias for the inline
# expression type. We synthesize the inline entity and evaluate it, so the
# result is hash-identical to the inline form (§10.2 / SA-COMPUTE-V314-2). The
# map gives each builtin path its inline type and the field(s) that are scalar
# (string) in the inline form but arrive in `args` as hashes-to-literals.
_INLINE_ALIAS_BUILTINS: dict[str, tuple[str, tuple[str, ...]]] = {
    "system/compute/builtins/arithmetic": ("compute/arithmetic", ("op",)),
    "system/compute/builtins/compare": ("compute/compare", ("op",)),
    "system/compute/builtins/logic": ("compute/logic", ("op",)),
    "system/compute/builtins/field": ("compute/field", ("name",)),
    "system/compute/builtins/construct": ("compute/construct", ("entity_type",)),
}

COMPUTE_EXPRESSION_TYPES = frozenset({
    "compute/literal",
    "compute/lookup/scope",
    "compute/lookup/tree",
    "compute/lookup/hash",
    "compute/apply",
    "compute/if",
    "compute/let",
    "compute/lambda",
    "compute/arithmetic",
    "compute/compare",
    "compute/logic",
    "compute/field",
    "compute/construct",
    "compute/index",         # N.1 (§2.2)
    "compute/length",        # N.1 (§2.2)
    "compute/numeric-cast",  # N.4 (§2.2)
})

COMPUTE_VALUE_TYPES = frozenset({
    "compute/closure",
    "compute/scope",
    "compute/result",
    "compute/error",
})

# All resolvable compute types — expression + value + metadata (D2, §4.2 v3.6)
COMPUTE_RESOLVABLE_TYPES = COMPUTE_EXPRESSION_TYPES | COMPUTE_VALUE_TYPES | frozenset({
    "system/compute/subgraph",
    "system/compute/install-request",
    "system/compute/install-result",
})

# Budget defaults (§9.3)
DEFAULT_MAX_OPS = 100_000
DEFAULT_MAX_DEPTH = 1024
MAX_CASCADE_DEPTH = 16

# Error codes (§9.1)
ERR_BUDGET_EXHAUSTED = "budget_exhausted"
ERR_DEPTH_EXCEEDED = "depth_exceeded"
ERR_TYPE_MISMATCH = "type_mismatch"
ERR_DIVISION_BY_ZERO = "division_by_zero"
ERR_NOT_FOUND = "not_found"
ERR_UNKNOWN_TYPE = "unknown_type"
ERR_MISSING_ARGUMENT = "missing_argument"
ERR_INVALID_EXPRESSION = "invalid_expression"
ERR_CASCADE_LIMIT = "cascade_limit"
ERR_PERMISSION_DENIED = "permission_denied"
ERR_INSTALLATION_GRANT_INVALID = "installation_grant_invalid"
ERR_AMBIGUOUS_RESOURCE = "ambiguous_resource"
#: §3.3 400 row (0.8.2.18) — the ABSENT-resource half of the pair above.
ERR_PATH_REQUIRED = "path_required"
ERR_INDEX_OUT_OF_RANGE = "index_out_of_range"  # compute/index + assoc (§9.1, N.1; v3.25)
ERR_CAST_OUT_OF_RANGE = "cast_out_of_range"    # compute/numeric-cast (§9.1, N.4)
ERR_COUNT_OUT_OF_RANGE = "count_out_of_range"  # range's n (§9.1, v3.25)
ERR_SCOPE_UNREACHABLE = "scope_unreachable"    # kind:entity binding unresolvable (§9.1, v3.19b N8)

#: The codes that **short-circuit even in a contained position** — the one
#: thing a CONTAINED position does not contain `[C-8; RULED 2026-08-21, arch
#: PROPOSAL-COMPUTE-CLOSURE-RESULT-POSITIONS §8 / ROUTING-2026-08-21-h §2]`.
#:
#: **The discriminator is not "limit-ness" and it is not the cohort vote — it is
#: one sentence of §5.1:** *"Every call to `evaluate()` decrements `operations`
#: by 1. Recursive calls decrement `depth` by 1 **(restored on return)**."* A
#: counter that is **not restored on unwind** makes element *i*'s outcome a
#: function of elements 1…*i*−1, and *that* is what a contained result forks
#: across peers:
#:
#: - `budget_exhausted` (§8.1) — `operations` is decremented once per
#:   `evaluate()` and restored nowhere, and §10.4 makes memoization
#:   implementation-defined, so two conformant peers on identical IR/inputs/
#:   budget can exhaust at a **different element**. Contained, that is
#:   `[v₁…v_{k−1}, E, E, …]` with a different *k* per peer — different boundary
#:   bytes for one program. Independently: a well-formed array with a readable
#:   boundary hash, reported for an evaluation the peer **aborted**.
#: - `cascade_limit` (§8.2) — §7.3's counter is shared across the entire causal
#:   chain (cross-peer, by `chain_id`) and reaching it **freezes the subgraph**.
#:
#: **`depth_exceeded` is deliberately NOT here (§8.3).** `depth` is *restored on
#: unwind*, so it is **element-local by the spec's own parenthetical**: element
#: *i* begins at the same depth every time, so whether it exceeds is a property
#: of that element's own sub-expression. `map(f, xs)` where `f` recurses too
#: deeply on element 2 is `[a, E, c]` — the element-wise §1.5 NaN model, and
#: every peer evaluates it identically. **It contains like any other error and
#: needs no carve-out at all.**
#:
#: **We apply it to the code, never to the provenance** (§8.4, `SA-PY-25`, and
#: rust's wording adopted verbatim by the ruling: *keyed on the CODE, never the
#: variant*). The value form is not hypothetical — §7.3 **mandates** writing a
#: `compute/error` to the `result_path` on reactive budget exhaustion, so a
#: downstream `compute/lookup/tree` reads a value-form `budget_exhausted`
#: produced by a conformant peer. go's pre-`0e1f604` carve-out fired on the
#: minted arm alone and so contained the value form while short-circuiting the
#: minted one; py has one representation and cannot express that split even by
#: accident. The check is :func:`is_short_circuit_limit`, kind-and-code based
#: exactly as :func:`is_error` is kind based.
_SHORT_CIRCUIT_LIMIT_CODES: frozenset[str] = frozenset({
    ERR_BUDGET_EXHAUSTED,
    ERR_CASCADE_LIMIT,
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_compute_type(entity: Entity | dict[str, Any]) -> bool:
    """Check if entity is any compute-resolvable type (§4.2 v3.6 D2)."""
    t = entity.type if isinstance(entity, Entity) else entity.get("type", "")
    return t in COMPUTE_RESOLVABLE_TYPES


def _validate_compute_resolvable(
    entity: Entity,
    h: bytes,
    has_content_store_access: bool,
    authorized_data_hashes: set[bytes] | None = None,
) -> Entity | None:
    """Post-resolution type check (§4.2 v3.6 D2 + v3.7 D5).

    Tier 0: content_store_access allowance — admin, any entity.
    Tier 1: compute-type — expression subgraph, always allowed.
    Tier 2: sealed set — installed subgraph authorized data hashes (D5).
    """
    if has_content_store_access:
        return entity
    if is_compute_type(entity):
        return entity
    if authorized_data_hashes is not None and h in authorized_data_hashes:
        return entity
    return None


def is_compute_expression(entity: Entity | dict[str, Any]) -> bool:
    """Check if entity is a compute expression type (§4.7)."""
    t = entity.type if isinstance(entity, Entity) else entity.get("type", "")
    return t in COMPUTE_EXPRESSION_TYPES


def _entity_type(v: Any) -> str | None:
    """Extract type string from an entity-like value."""
    if isinstance(v, Entity):
        return v.type
    if isinstance(v, dict):
        return v.get("type")
    return None


def _entity_data(v: Any) -> dict[str, Any] | None:
    """Unwrap the ``.data`` of a value already KNOWN to be an entity.

    Used at the eval-internal sites that have an entity in hand — a
    closure / lambda / apply-fn / eval-environment — and just need its
    payload. This is NOT the entity-vs-record kind distinction: that rule
    lives solely in ``_field_record`` (v3.19b N3), and it is deliberately
    compute-eval-internal (neither helper has callers outside this module).
    Here a dict is assumed to be an entity envelope because the caller only
    reaches this with an entity-shaped value.
    """
    if isinstance(v, Entity):
        return v.data
    if isinstance(v, dict):
        return v.get("data")
    return None


def _field_record(v: Any) -> dict[str, Any] | None:
    """Resolve the record a ``compute/field`` reads from — by KIND, not shape (v3.19b N3).

    Sole site of the entity-vs-record kind distinction, and it is
    compute-eval-internal — a *materialized* / *stored* entity carries no
    kind tag, so this rule never escapes the evaluator (cross-impl
    catch-up §7).

    An **entity** value (an ``Entity`` instance — Python's carrier of
    ``kind:"entity"``, the analog of a tagged ``ComputeValue::Entity``)
    navigates its ``.data``. A plain ``dict`` is a record/map value
    (``kind:"value"``) and navigates **flat**. Anything else is not navigable
    (the caller raises ``type_mismatch``).

    N3 (normative): implementations **MUST NOT** distinguish entity-vs-record by
    inspecting keys (e.g. the ``{type, data, content_hash}`` shape) — that
    heuristic misfires on legitimate records (a record with a ``name`` field
    alongside ``type``/``data`` would silently lose ``name``). The kind is
    carried by the value's *type*: entities flow as ``Entity`` instances
    (``compute/construct``/``closure``/``result`` results, and ``kind:"entity"``
    scope bindings resolved back to their entity); records flow as plain dicts.
    (Retires the v3.19a shape heuristic; the kind tag makes it unnecessary.)
    """
    if isinstance(v, Entity):
        # A non-record entity (e.g. a primitive/any wrapper whose data is a bare
        # value) has no navigable fields → type_mismatch, not a TypeError.
        return v.data if isinstance(v.data, dict) else None
    if isinstance(v, dict):
        return v
    return None


def _materialize_bare(value: Any, ctx: EvalContext) -> Any:
    """Materialize a compute value to its **bare** wire form (v3.19c Part A / α).

    Applied at every compute→non-compute crossing (eval result, `store`/tree
    write, `compute/apply` arg dispatch, cross-peer). The compute value model
    (typed in-flight entity values) is compute-internal; what is stored,
    returned, or sent is a normal bare entity — **byte-identical to a hand-built
    one** (the validate-peer hash gate).

    The rule is **runtime-kind-driven, never declared-type-driven** (so it is
    independent of the optional type extension — §3.7): an entity-valued field
    is recursively materialized, stored, and replaced by its **bare
    `system/hash` reference** (V7 §1.4 refless — exactly what a hand-built
    entity carries); a value-kind field stays inline. Non-entity values pass
    through unchanged.

    **Arrays materialize element-wise** — an entity-valued *element* becomes a
    bare `system/hash` exactly as an entity-valued *field* does. This branch
    was absent until v3.24 gave the evaluator array-of-entity values to
    produce (`group-by`'s result, `concat`'s output, a `map` closure returning
    a construct): before it, such an array reached the encoder with live
    `Entity` objects inside and died there, which is the `error_to_wire` shape
    one container out.

    **A CONTAINED `compute/error` materializes code-only** `[MUST, v3.26]`
    (§2.3 N1 / §3.5). See :func:`_materialize_contained_error` for why the
    array-element position is the right and only place to put it.
    """
    if isinstance(value, list):
        return [_materialize_element(el, ctx) for el in value]
    if not isinstance(value, Entity):
        return value
    if value.type == "compute/error":
        _reject_scalar_error_materialization(value)
    data = value.data
    if not isinstance(data, dict):
        # A non-record entity — e.g. a `primitive/any` wrapper whose `data` is a
        # bare value (the unwrapped result of an entity-native dispatch). A
        # *list* payload still needs element-wise treatment (an entity inside it
        # is as unencodable there as anywhere else); a scalar is already bare.
        if isinstance(data, list):
            return Entity(type=value.type, data=_materialize_bare(data, ctx))
        return value
    bare_data: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, Entity):
            bare_data[k] = ctx.content_store.put(_materialize_bare(v, ctx))
        elif isinstance(v, list):
            bare_data[k] = _materialize_bare(v, ctx)
        else:
            bare_data[k] = v
    return Entity(type=value.type, data=bare_data)


def _materialize_element(el: Any, ctx: EvalContext) -> Any:
    """Materialize one **array element** — the v3.26 contained position.

    Split out from :func:`_materialize_bare`'s array branch so the carve-out
    has a name a reader can grep, and so the *scalar* guard below cannot be
    reached from here by accident.
    """
    if is_error(el):
        return _materialize_contained_error(el, ctx)
    m = _materialize_bare(el, ctx)
    if isinstance(m, Entity):
        return ctx.content_store.put(m)
    return m


def _materialize_contained_error(v: Any, ctx: EvalContext) -> bytes:
    """A `compute/error` CONTAINED in a value materializes **code-only**, by
    bare `system/hash` `[MUST, v3.26]` (§2.3 N1, §3.5).

    v3.23's ruling B said an error is *never* placed into the data, so N1 never
    applies to it. That premise was true when written and stopped being true at
    v3.25: §3.5's collection primitives created **data positions** — `assoc`'s
    `value`, `concat`'s elements, `group-by`'s `members` — where an error is
    *contained in* a value rather than *consumed*. Ruling B is **scoped, not
    reversed**; arch's words are *"add the carve-out, not remove the guard."*

    **v3.26's "and ONLY those three" did not survive its first re-reading, and
    the count is now the rule instead** `[C-8, 2026-08-21]`. The enumeration was
    taken over the v3.25 table, which does not contain `map`/`filter`/`fold` —
    they predate it and place closure results into outputs too. The contained
    set is five (`map`'s output element and `fold`'s final accumulator join the
    three), and arch **replaced** the sentence rather than incrementing it:

        A position is CONTAINED when the primitive PLACES the value without
        reading it, and CONSUMED when it READS the value to decide control
        flow, ordering, membership, or a write location.

    A count is wrong again at the next primitive; a rule is not. **Note the
    normative text still says "exactly three"** — `EXTENSION-COMPUTE` is v3.26
    on disk and the C-8 deltas target v3.27, so a reader implementing from the
    spec alone gets the superseded answer. Routed (SA-PY-26).

    **Code-only is load-bearing, not tidiness.** If the contained element
    carried `message`, two conformant peers whose diagnostics differ would
    produce **different bytes for the containing array** — the array's content
    hash would fork cross-impl on a string no spec pins. That is the same
    argument :func:`error_materialized` makes for the two *write* boundaries,
    reaching a third boundary: an array element that gets hashed. So this
    function is `error_materialized` + `put`, and the reason it exists
    separately is the *position*, not the encoding.

    **Why the position is the array element and not the primitive.** All three
    §3.5 contained positions are a direct element of some materialized array
    (`members` is an array field of each group), so one carve-out at the
    element boundary covers all three uniformly. Placing it per-primitive
    instead would be three carve-outs that can drift apart, and would leave the
    fourth container — whatever v3.27 adds — silently uncovered.
    """
    return ctx.content_store.put(error_materialized(v))


def _reject_scalar_error_materialization(value: Entity) -> None:
    """The other half of v3.26: the guard ruling B put on the **scalar** path,
    kept exactly as strict as it was.

    An error reaching materialization as a scalar — a top-level result, a
    `compute/construct` field, a scope binding — means a §4.1 `is_error`
    short-circuit was missed upstream. The two places an error legitimately
    materializes as a scalar (the §7.2 `result_path` write and the SA-9 `store`
    payload) call :func:`error_materialized` directly and never arrive here.

    **The tell that the v3.26 carve-out was scoped wrong is a NON-element error
    materializing quietly** — so this raises rather than embedding. It is an
    internal-invariant violation, not an error-as-value: a `compute/error`
    silently re-embedded into a construct field is a wrong *answer* that
    hashes, sends, and is believed, which is strictly worse than a loud one.

    Note this makes the **ordering** at the three compute→non-compute crossings
    load-bearing: each checks `is_error(result)` *before* materializing, so a
    legitimate top-level error-as-value (the F10 status-200 return) leaves by
    its own door. Before v3.26 that ordering was free; it is now the difference
    between an F10 return and a raise, and the tests say so.
    """
    raise RuntimeError(
        "internal: compute/error reached _materialize_bare() as a SCALAR — a "
        "§4.1 is_error short-circuit was missed upstream (EXTENSION-COMPUTE "
        "v3.23 ruling B, scoped v3.26). A CONTAINED error (an array element) "
        "materializes code-only via _materialize_contained_error; a scalar "
        f"error propagates from its consumption site. code="
        f"{error_data(value).get('code', '')!r}"
    )


def is_error(v: Any) -> bool:
    """Is ``v`` a `compute/error`? §4.1's predicate, and it is **kind-based,
    not outcome-based** `[MUST]` (v3.23).

    True iff the value's kind is `compute/error`. It does **not** mean
    "evaluation failed": a `compute/error` **value** that evaluated
    *successfully* — a stored literal, or a `compute/lookup/hash` resolving to
    one, each returned unchanged by SA-1 — is an error for every purpose in
    §4.1, and every consumer short-circuits to it (§7.2 names construct,
    apply, field, arithmetic, compare, logic, and `if`'s condition).

    Arch ruled this in v3.23 against the outcome-based reading, under which an
    error reached during evaluation would instead be embedded and materialized
    into the consuming expression. Both readings are self-consistent, so
    neither is visible to same-impl testing — they split at the cross-peer
    seam, where the same input yielded an entity-kind boundary in one peer and
    an error-kind outcome in another, observed three ways with no two alike.

    Note both representations answer here: :func:`make_error` mints a **dict**,
    while a stored error literal resolves to an **`Entity`**. That split is
    invisible to this predicate and was *not* invisible at the wire boundary —
    see :func:`error_to_wire`.
    """
    return _entity_type(v) == "compute/error"


def is_short_circuit_limit(v: Any) -> bool:
    """Is ``v`` an error that short-circuits **even in a contained position**?
    `[C-8; RULED 2026-08-21, §8]`

    See :data:`_SHORT_CIRCUIT_LIMIT_CODES` for the derivation — it is §5.1's
    *restored on return* parenthetical, not "limit-ness", which is why
    `depth_exceeded` is **not** in the set. The discriminator is the **code**,
    read through :func:`error_data` so it answers identically for a minted dict
    and a stored-literal `Entity`: a discriminator that reads the
    *representation* is the §2.4 asymmetry the C-8 ruling exists to close, and
    re-introducing it inside the carve-out C-8 created is still re-introducing
    it (§8.4).

    **The residual, ruled explicitly rather than left to be discovered:** a
    caller can store a `compute/error{code: "budget_exhausted"}` literal and
    have a closure return it, and this predicate short-circuits a `map` that
    would otherwise contain it. `SA-PY-25` asked whether that was a hole; §8.4
    answers that it is not — §2.4 makes the stored and minted errors *the same
    materialized entity* (content-addressed over `code` alone), so treating them
    differently would require the evaluator to know something the boundary
    cannot express, and an author could already halt an expression by placing an
    error in a consumed position.
    """
    return is_error(v) and error_data(v).get("code") in _SHORT_CIRCUIT_LIMIT_CODES


def error_data(v: Any) -> dict[str, Any]:
    """The `data` map of a `compute/error` in either representation.

    Python carries a `compute/error` two ways and they are equally valid:
    :func:`make_error` returns a plain ``{"type", "data"}`` dict, and a
    `compute/error` **literal** resolved from the content store is an
    :class:`Entity`. Every *evaluator-internal* consumer goes through
    :func:`is_error`, which handles both — so the split stayed invisible right
    up to the boundary where a value stops being compute-internal.
    """
    if isinstance(v, Entity):
        data = v.data
    elif isinstance(v, dict):
        data = v.get("data", v)
    else:  # pragma: no cover — is_error() gates every caller
        return {}
    return data if isinstance(data, dict) else {}


def error_to_wire(v: Any) -> dict[str, Any]:
    """A `compute/error` in **wire form** — a plain ``{type, data}`` dict —
    from either representation.

    Use at every compute→non-compute crossing that returns an error. The
    `Entity` form is the one that bites: it is not a dict, so the protocol's
    ``_as_entity`` shim wraps it as `primitive/any` with an `Entity` as the
    payload, and the CBOR encoder raises `CBOREncodeTypeError: cannot
    serialize type Entity` — killing the inbound handler task. The peer then
    answers *nothing*, so the caller sees an i/o timeout rather than a
    diagnostic, which is the worst shape a failure can take: it looks like a
    network problem and is a serialization one.

    That was a real cross-impl finding (`entity-core-go` 2026-08-15-d), and it
    was invisible to this repo's own suite because every pre-existing
    error-propagation test triggers errors with *unresolvable hashes* — which
    mint the dict form and never exercise the `Entity` one.

    **Not the same boundary as** :func:`error_materialized`: this is the
    *in-flight / dispatch* form (§2.4 permits the diagnostics here), that one is
    the *content-addressed* form (`code` alone).
    """
    return {"type": "compute/error", "data": error_data(v)}


def error_materialized(v: Any) -> Entity:
    """A `compute/error` in **materialized** form — content over `code` alone
    `[MUST]` (§2.4), from either representation.

    Use at every site where an error is **written**: the §7.2 `result_path`
    (including the frozen-subgraph write) and the SA-9 `store` builtin. §2.4
    calls those the only surfaces its code-only content-hash rule governs.

    `message`, `at`, and `expression` are diagnostic-only and MUST NOT enter the
    bytes V7 content-addresses: `message` is unpinned prose, `at` is an
    impl-dependent attribution point, and `expression` is whichever
    sub-expression an impl chose to blame — so if any of the three entered the
    hash, two conformant peers writing the *same* error to the *same* path would
    produce *different* entity hashes, breaking AE-1 materialized-boundary
    equivalence, content dedup, sync, and any reactive consumer keyed on the
    result hash. Two errors with the same `code` **are** the same materialized
    entity.

    Distinct from :func:`error_to_wire`, which is the *in-flight* crossing (the
    F10 status-200 error-as-value return) where the diagnostics MAY appear. One
    value, two boundaries, two answers — and the call site picks by asking
    whether the bytes get content-addressed.
    """
    return Entity(type="compute/error", data={"code": error_data(v).get("code", "")})


def make_error(
    code: str,
    message: str,
    at: str | None = None,
    expression: bytes | None = None,
) -> dict[str, Any]:
    """Create a compute/error entity dict."""
    data: dict[str, Any] = {"code": code, "message": message}
    if at is not None:
        data["at"] = at
    if expression is not None:
        data["expression"] = expression
    return {"type": "compute/error", "data": data}


def truthy(value: Any) -> bool:
    """Truthiness per spec §4.5."""
    if value is None:
        return False
    if value is False:
        return False
    if isinstance(value, (int, float)) and value == 0:
        return False
    if isinstance(value, str) and value == "":
        return False
    if isinstance(value, list) and len(value) == 0:
        return False
    return True


def canonical_sorted(m: dict[str, Any]) -> list[tuple[str, Any]]:
    """Iterate map entries in ECF canonical key order (§8.2).

    Sort by encoded byte length of key, then lexicographically by byte value.
    Matches ENTITY-CBOR-ENCODING.md §4.1 Rule 2.
    """
    entries = list(m.items())
    entries.sort(key=lambda kv: (len(ecf_encode(kv[0])), ecf_encode(kv[0])))
    return entries


def _clean_path(path: str) -> str:
    """Normalize path — collapse double slashes, strip trailing slash."""
    while "//" in path:
        path = path.replace("//", "/")
    return path.rstrip("/")


# ---------------------------------------------------------------------------
# Integer model — 64-bit two's-complement, WASM/LLVM/JVM style (§2.2 rules 8-11)
# ---------------------------------------------------------------------------
#
# Integer values are 64-bit two's-complement bit patterns. `int`/`uint` are
# type-system *annotations* (a value's classification follows its CBOR major
# type), NOT a value type that steers evaluation:
#
#   - rule 8: add/sub/mul are sign-agnostic — operate on the bit patterns
#     (mod 2^64), so there is no int/uint decision and no "mixed operand" case.
#     `add(3, -1)` = 2. Arbitrary-precision host ints MUST truncate to 64 bits.
#   - rule 9: div/mod/compare use *signed* interpretation by default; unsigned
#     div/mod/compare on a value in [2^63, 2^64) is reached by a
#     `compute/numeric-cast → primitive/uint` on the operand immediately before
#     (the WASM `div_u` role).
#   - rule 10: an integer *result* is canonically encoded by its signed
#     interpretation (bit 63 clear → CBOR major 0; set → major 1) — one wire
#     form per result. So arithmetic results are reduced to signed-canonical
#     [-2^63, 2^63) before they become values. The lone exception is a
#     numeric-cast → uint result, which is the genuinely non-negative magnitude
#     in [0, 2^64) and encodes major 0.
#   - rule 11 (v3.17 SA-AMD3-1, Option A): numeric-cast is eager and the
#     unsigned interpretation lives *syntactically* at the operation — a
#     `compute/numeric-cast → primitive/uint` makes the consuming div/mod/compare
#     unsigned ONLY when the cast is the *direct operand entity* of that op. Any
#     indirection (compute/let, compute/if branch, compute/lookup/scope,
#     compute/construct field, closure-arg) drops the intent → signed-default.
#     There is NO value-level tag carrier — signedness is read from the
#     expression graph (the operand entity's type), consistent with rule 8.
#
# As a value, a numeric-cast → uint yields the non-negative magnitude in
# [0, 2^64) (encoding CBOR major type 0 — rule 10's cast exception); the
# unsigned-ness only manifests when that cast is read as a direct operand of a
# sign-sensitive op. Python's cbor2 encodes a non-negative int as major 0 and a
# negative int as major 1, so keeping arithmetic results signed-canonical and
# cast→uint results as non-negative magnitudes makes rule 10 fall out of the
# value representation with no separate encoder hook.

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
UINT64_MAX = (1 << 64) - 1
_U64 = 1 << 64
_MASK64 = _U64 - 1


def _bits64(v: int) -> int:
    """The 64-bit two's-complement bit pattern of v, as unsigned [0, 2^64)."""
    return v & _MASK64


def _signed64(bits: int) -> int:
    """Interpret a 64-bit pattern as signed two's-complement → [-2^63, 2^63)."""
    bits &= _MASK64
    return bits - _U64 if bits >= (1 << 63) else bits


def _is_uint_cast(target: Any) -> bool:
    """Syntactic Option A test (§2.2 rule 11): is this operand *expression* a
    direct `compute/numeric-cast → primitive/uint`? Only then does the consuming
    div/mod/compare go unsigned. Read from the operand entity, not its value —
    so any indirection (let/if/lookup-scope/construct/closure-arg) is naturally
    signed-default because the operand entity there is not the cast itself."""
    return (
        _entity_type(target) == "compute/numeric-cast"
        and (_entity_data(target) or {}).get("to_type") == "primitive/uint"
    )


def _operand_int(value: Any, is_unsigned: bool) -> int:
    """Integer operand value for a sign-sensitive op (div/mod/compare), rule 9.

    `is_unsigned` (the operand expression was a direct numeric-cast → uint) reads
    the 64-bit pattern unsigned [0, 2^64); otherwise signed two's-complement.
    """
    bits = _bits64(int(value))
    return bits if is_unsigned else _signed64(bits)


# ---------------------------------------------------------------------------
# Tail Call (§4.1 T1-T3)
# ---------------------------------------------------------------------------

class _TailCall:
    """Sentinel returned from tail positions to signal the trampoline."""
    __slots__ = ("entity", "scope")

    def __init__(self, entity: Entity, scope: Scope) -> None:
        self.entity = entity
        self.scope = scope


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

class Scope:
    """Evaluation scope — maps binding names to values."""

    __slots__ = ("_bindings",)

    def __init__(self, bindings: dict[str, Any] | None = None) -> None:
        self._bindings: dict[str, Any] = dict(bindings) if bindings else {}

    def has(self, name: str) -> bool:
        return name in self._bindings

    def get(self, name: str) -> Any:
        return self._bindings[name]

    def set(self, name: str, value: Any) -> None:
        self._bindings[name] = value

    def copy(self) -> Scope:
        return Scope(self._bindings.copy())

    @property
    def bindings(self) -> dict[str, Any]:
        return self._bindings

    def is_empty(self) -> bool:
        return len(self._bindings) == 0


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------

@dataclass
class Budget:
    """Evaluation budget — tracks remaining operations and depth."""
    operations: int = DEFAULT_MAX_OPS
    depth: int = DEFAULT_MAX_DEPTH


# ---------------------------------------------------------------------------
# EvalContext
# ---------------------------------------------------------------------------

@dataclass
class EvalContext:
    """Evaluation context — wraps storage, resolution, and authorization.

    `capability` is the authority the expression evaluates under. Per the
    three eval paths (V7 §6.8 / EXTENSION-COMPUTE §4.1 v3.9):
      - Explicit eval: caller's capability
      - Entity-native dispatch: handler grant (the ceiling)
      - Reactive: installation grant (autonomous)

    `caller_capability` is the original external caller's capability,
    propagated separately for V7 §6.8 history attribution. It is informational
    here — it is forwarded to sub-dispatches (so handler-managed writes record
    the right `caller_capability` on history transitions) but is not used to
    authorize tree reads or impure operations from this expression.
    """

    content_store: ContentStore
    entity_tree: EntityTree
    local_peer_id: str
    capability: dict[str, Any]
    caller_capability: dict[str, Any] | None = None
    # Optional reactive write pathway. When present, the `store` builtin (§3.5)
    # writes through it so tree changes trigger reactive cascades; otherwise it
    # falls back to a direct content-store + tree write.
    emit_pathway: EmitPathway | None = None
    included: dict[bytes, Entity] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    has_content_store_access: bool = False
    subgraph_root: str = ""
    _execute_fn: Callable[..., Any] | None = None
    _encountered: set[bytes] = field(default_factory=set)
    _tree_hashes: set[bytes] | None = field(default=None, repr=False)
    authorized_data_hashes: set[bytes] = field(default_factory=set)

    def resolve(self, h: bytes) -> Entity | None:
        """Resolve hash to entity (§4.2 v3.6).

        Three-tier resolution with expression-graph scoping (D2):
        1. Envelope included map (pre-authorized)
        2. Content store (if content_store_access allowance — bypasses type check)
        3. Tree-scoped: hash bound at any tree path (reverse hash set)
           Includes encountered-during-read as subset.

        Post-resolution: validate_compute_resolvable rejects non-compute
        entities when content_store_access is absent, preventing the
        evaluator from being used as a content store oracle.
        """
        # Tier 1: envelope included
        entity = self.included.get(h)
        if entity is not None:
            return _validate_compute_resolvable(
                entity, h, self.has_content_store_access, self.authorized_data_hashes,
            )

        # Tier 2: content store (with access gating)
        if self.has_content_store_access:
            return self.content_store.get(h)

        # Tier 3: tree-scoped — hash is resolvable if it is the content hash
        # of an entity bound at any tree path. Per §4.2: "if the hash
        # corresponds to a tree-bound entity within capability scope,
        # resolution MUST succeed."
        entity = None
        if h in self._encountered:
            entity = self.content_store.get(h)
        else:
            if self._tree_hashes is None:
                self._tree_hashes = {
                    bound_hash for _, bound_hash in self.entity_tree.all_bindings()
                }
            if h in self._tree_hashes:
                entity = self.content_store.get(h)

        if entity is None:
            # Tier 2 (D5): check sealed set — entity may be in content store
            # but not tree-bound (authorized via install path-hint)
            if self.authorized_data_hashes and h in self.authorized_data_hashes:
                entity = self.content_store.get(h)
                if entity is not None:
                    return entity
            return None
        return _validate_compute_resolvable(
            entity, h, self.has_content_store_access, self.authorized_data_hashes,
        )

    def resolve_or_error(self, h: bytes, label: str) -> Entity | dict[str, Any]:
        """Resolve hash or return not_found error (§4.1 V31 helper)."""
        entity = self.resolve(h)
        if entity is None:
            return make_error(ERR_NOT_FOUND, f"Cannot resolve hash for {label}")
        return entity

    def register_dependency(self, path: str) -> None:
        """Register a tree dependency for reactive mode (§7.1)."""
        self.dependencies.append(path)

    def mark_encountered(self, h: bytes) -> None:
        """Mark hash as encountered during a tree read."""
        self._encountered.add(h)

    def _granter_frame(self, cap: dict[str, Any] | None = None) -> str:
        """V7 §PR-8 — granter frame for a capability's own resource patterns.

        Resolves the cap's granter identity from the envelope included map or
        the content store and derives its peer_id; falls back to local_peer_id
        (the self-issued frame) when unresolvable. For a handler-grant authority
        (granter == local peer) this is local by construction; it is
        load-bearing only for a foreign-granter caller/apply cap. Defaults to
        self.capability when no cap is supplied.
        """
        from entity_core.capability.checking import granter_frame_peer_id

        def _resolve(h: bytes) -> dict[str, Any] | None:
            ent = self.included.get(h)
            if ent is None:
                ent = self.content_store.get(h)
            return {"data": ent.data} if ent is not None else None

        return granter_frame_peer_id(
            cap if cap is not None else self.capability, self.local_peer_id, _resolve
        )

    def check_read_permission(self, path: str) -> bool:
        """Check if capability covers read at path."""
        return check_path_permission(
            self.capability, "get", path, self.local_peer_id,
            granter_peer_id=self._granter_frame(),
        )

    def check_write_permission(self, path: str) -> bool:
        """Check if capability covers write at path."""
        return check_path_permission(
            self.capability, "put", path, self.local_peer_id,
            granter_peer_id=self._granter_frame(),
        )


# ---------------------------------------------------------------------------
# Core Evaluator (§4.1)
# ---------------------------------------------------------------------------

def evaluate(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """Evaluate a compute expression entity (§4.1 with TCO trampoline).

    Depth is checked and decremented once on entry. The trampoline loop
    reuses that depth slot for tail calls. Budget is decremented every
    iteration — every step costs one operation regardless of tail position.
    """
    if budget.depth <= 0:
        return make_error(ERR_DEPTH_EXCEEDED, "Maximum evaluation depth exceeded")
    budget.depth -= 1

    while True:
        budget.operations -= 1
        if budget.operations <= 0:
            budget.depth += 1
            return make_error(ERR_BUDGET_EXHAUSTED, "Computation budget exhausted")

        result = _evaluate_inner(entity, scope, budget, ctx)

        if isinstance(result, _TailCall):
            entity = result.entity
            scope = result.scope
            continue

        budget.depth += 1
        return result


def _evaluate_inner(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """Dispatch evaluation by expression type."""
    t = entity.type

    if t == "compute/literal":
        return entity.data.get("value")

    if t == "compute/lookup/scope":
        name = entity.data.get("name", "")
        if scope.has(name):
            return scope.get(name)
        return make_error(ERR_NOT_FOUND, f"No scope binding: {name}")

    if t == "compute/lookup/tree":
        return _eval_lookup_tree(entity, scope, budget, ctx)

    if t == "compute/lookup/hash":
        return _eval_lookup_hash(entity, scope, budget, ctx)

    if t == "compute/apply":
        return _eval_apply(entity, scope, budget, ctx)

    if t == "compute/if":
        return _eval_if(entity, scope, budget, ctx)

    if t == "compute/let":
        return _eval_let(entity, scope, budget, ctx)

    if t == "compute/lambda":
        return _eval_lambda(entity, scope, ctx)

    if t == "compute/arithmetic":
        return _eval_arithmetic(entity, scope, budget, ctx)

    if t == "compute/compare":
        return _eval_compare(entity, scope, budget, ctx)

    if t == "compute/logic":
        return _eval_logic(entity, scope, budget, ctx)

    if t == "compute/field":
        return _eval_field(entity, scope, budget, ctx)

    if t == "compute/construct":
        return _eval_construct(entity, scope, budget, ctx)

    if t == "compute/index":
        return _eval_index(entity, scope, budget, ctx)

    if t == "compute/length":
        return _eval_length(entity, scope, budget, ctx)

    if t == "compute/numeric-cast":
        return _eval_numeric_cast(entity, scope, budget, ctx)

    # Value types (§2.3/§2.4) evaluate to themselves — symmetric with the
    # compute/lookup/hash rule ("return non-expressions as values"). This lets a
    # pre-computed value (e.g. a compute/closure) be referenced directly as a
    # compute/apply arg. Adopts SA-COMPUTE-V314-1 Option A (recommended; pending
    # arch ratification). A compute/error returned here propagates as an error.
    if t in COMPUTE_VALUE_TYPES:
        return entity

    return make_error(ERR_UNKNOWN_TYPE, f"Unknown compute type: {t}")


# ---------------------------------------------------------------------------
# Expression evaluators
# ---------------------------------------------------------------------------

def _eval_lookup_tree(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    path = entity.data.get("path", "")
    if entity.data.get("relative") is True and ctx.subgraph_root:
        path = _clean_path(ctx.subgraph_root + "/" + path)

    if not ctx.check_read_permission(path):
        return make_error(ERR_PERMISSION_DENIED, f"No read access to path: {path}")

    ctx.register_dependency(path)

    h = ctx.entity_tree.get(path)
    if h is None:
        return make_error(ERR_NOT_FOUND, f"No entity at path: {path}")

    ctx.mark_encountered(h)

    tree_entity = ctx.content_store.get(h)
    if tree_entity is None:
        return make_error(ERR_NOT_FOUND, f"No entity at path: {path}")

    if is_compute_expression(tree_entity):
        return _TailCall(tree_entity, scope)

    return tree_entity


def _eval_lookup_hash(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """Hash lookup — pure, authorized via sealed set or content_store_access (D6 §4.3)."""
    target_hash = entity.data.get("hash")
    if target_hash is None or not isinstance(target_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "lookup/hash missing hash field")

    target = ctx.resolve_or_error(target_hash, "hash lookup")
    if is_error(target):
        return target
    if is_compute_expression(target):
        return _TailCall(target, scope)
    return target


def _eval_apply(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    data = entity.data

    if data.get("path") is not None:
        return _eval_apply_handler(entity, scope, budget, ctx)

    if data.get("fn") is not None:
        return _eval_apply_closure(entity, scope, budget, ctx)

    return make_error(ERR_INVALID_EXPRESSION, "compute/apply requires path or fn")


def _resolve_handler_input_type(path: str, operation: str, ctx: EvalContext) -> str | None:
    """Resolve the target operation's declared `input_type` (§2.1, §4.1 V30).

    Tree-walks `path` backward to the longest-prefix `system/handler` entity
    (mirroring the dispatcher's resolution), then reads
    `interface.operations[operation].input_type` from its interface entity.
    Returns None when no handler/operation/interface is resolvable (e.g. an
    in-memory wildcard handler with no tree manifest), letting the caller apply
    its own fallback.
    """
    segments = [s for s in path.split("/") if s]
    while segments:
        prefix = "/".join(segments)
        h = ctx.entity_tree.get(prefix)
        if h is not None:
            handler_entity = ctx.content_store.get(h)
            if handler_entity is not None and handler_entity.type == "system/handler":
                iface_path = handler_entity.data.get("interface")
                if isinstance(iface_path, str):
                    ih = ctx.entity_tree.get(iface_path)
                    if ih is not None:
                        iface = ctx.content_store.get(ih)
                        if iface is not None:
                            spec = (iface.data.get("operations") or {}).get(operation)
                            if isinstance(spec, dict):
                                return spec.get("input_type")
                return None  # handler found but no usable operation spec
        segments = segments[:-1]
    return None


def _eval_apply_handler(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """Handler dispatch mode for compute/apply (§4.1).

    Per EXTENSION-COMPUTE v3.10 (PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING):
      - F1: `resource` field is a system/hash reference resolving to a
        system/protocol/resource-target struct ({targets, exclude}).
      - F2: full-resolution dual-check uses (path, operation, resource)
        for both ctx.capability (handler-grant ceiling) and provided_cap.
      - F4: the resolved resource is forwarded to the dispatched EXECUTE.
      - F5: when `capability` is present, `resource` MUST also be present.
    """
    data = entity.data
    path = data["path"]
    operation = data.get("operation")

    if operation is None:
        return make_error(
            ERR_INVALID_EXPRESSION,
            "compute/apply handler mode requires operation",
        )

    # §2.1 Q23 `[MUST]` — ruled 2026-08-16 (arch `7fdeea7`,
    # ROUTING-2026-08-16-i; all three seats changed). **A builtin-path apply
    # carrying `capability` or `resource` is `invalid_expression`.** Both fields
    # are defined *only* as parameters of the dispatched EXECUTE, and a
    # `system/compute/builtins/*` path evaluates inline (§3.5) dispatching no
    # EXECUTE — so neither has a referent here.
    #
    # **Reject, never ignore**, and the direction is the point: the dual-check
    # can only ever NARROW, so a caller supplying a capability is asking for
    # *less* than ambient authority. Dropping it silently runs the operation
    # WIDER than asked — on `store`, the one impure builtin (§6.2), writing to a
    # caller-specified path. Nothing legitimate is lost: §6.2 fixes store's
    # authority at `check_write_permission`/the installation grant, never at a
    # field on the expression.
    #
    # **Placed EARLY — before the fields are evaluated — deliberately.** §4.1's
    # pseudocode puts this block *after* resource evaluation, so a builtin apply
    # with an error-valued `resource` would return that error instead of
    # `invalid_expression`. All three per-seat actions in ROUTING-i reject
    # early, and go landed it early (`ext/compute/eval_apply.go`,
    # `evalApplyHandler`); go filed the ordering as spec-issue 2026-08-16-d.
    # This is structural-check-before-runtime, and it is what keeps the three
    # byte-identical — do not "correct" it toward the pseudocode.
    #
    # Subsumes F5 on the builtin path: a capability-only builtin apply lands
    # here with the same `invalid_expression`, so no separate F5 fix is owed.
    if path.startswith(BUILTIN_PREFIX) and (
        data.get("capability") is not None or data.get("resource") is not None
    ):
        return make_error(
            ERR_INVALID_EXPRESSION,
            "compute/apply on a builtin path MUST NOT carry capability or resource",
        )

    args = data.get("args") or {}

    # Inline-equivalent builtin aliases (§3.5, SA-COMPUTE-V314-2): synthesize the
    # inline form and evaluate it, so the result is hash-identical to the inline
    # expression. Intercepted before the generic arg loop to preserve inline
    # semantics (e.g. compute/logic short-circuit, integer-domain handling) and
    # to avoid double-evaluating the operands.
    if path in _INLINE_ALIAS_BUILTINS:
        return _eval_inline_alias(path, args, scope, budget, ctx)

    # §2131 error short-circuit, and its one boundary `[MUST]` — ruled
    # 2026-08-16 (arch `662e409`, ROUTING-2026-08-16-f; go was correct, py and
    # rust changed). **An apply short-circuits on the operands it *consumes*:
    # `resource`, `capability`, and closure args bound to params. A builtin's
    # WRITE PAYLOAD is not a consumed operand.** SA-9 `store`'s `value` is
    # handed opaquely to the write site and materialized there under §2.4 — its
    # fields are never *read*, which is the hazard the short-circuit rule exists
    # to prevent, so the rule does not reach it. Two narrower things still
    # short-circuit and are deliberately outside this exemption:
    #   - `store`'s `path`, which IS consumed (read as a string);
    #   - an unresolvable `value` hash, which is a resolution failure rather
    #     than an error *value* the caller asked to store (matches go's
    #     `resolveOrError` propagating before `Evaluate`).
    #
    # **v3.26 generalizes the exemption from one arg to a table.** §3.5's
    # collection primitives created a second data position of exactly the SA-9
    # shape — `assoc`'s `value` — so the rule stopped being about `store` and
    # became about *consumed vs contained*. `_CONTAINED_ARGS` is that table;
    # anything not in it is consumed and short-circuits, which is the "add the
    # carve-out, not remove the guard" half stated at the arg boundary.
    contained_args = _CONTAINED_ARGS.get(path, ())

    # Evaluate args in canonical order
    resolved_args: dict[str, Any] = {}
    for name, h in canonical_sorted(args):
        if not isinstance(h, bytes):
            return make_error(ERR_INVALID_EXPRESSION, f"Arg {name} is not a hash reference")
        is_contained = name in contained_args
        # `resolve_or_error` folds two outcomes into one `is_error`: a
        # resolution FAILURE (a minted not_found) and a successfully resolved
        # `compute/error` LITERAL. For a consumed operand those are the same
        # thing — both short-circuit — which is why the conflation was
        # invisible. For the write payload they are opposites, so resolve
        # directly and keep them apart: `None` is the failure, anything else is
        # a value the caller asked to store.
        target = ctx.resolve(h)
        if target is None:
            return make_error(ERR_NOT_FOUND, f"Cannot resolve hash for arg {name}")
        if is_error(target) and not is_contained:
            return target
        value = evaluate(target, scope, budget, ctx)
        if is_error(value) and not is_contained:
            return value
        resolved_args[name] = value

    # Builtin aliases (§3.5, N.2). map/filter/fold/store have no inline form;
    # we evaluate them directly here rather than dispatching across the handler
    # boundary — the spec explicitly permits treating the builtin dispatches as
    # internal aliases. Their results are identical to a registered handler's.
    if path in _COLLECTION_BUILTINS or path == BUILTIN_STORE:
        return _eval_builtin(path, resolved_args, budget, ctx)

    # F1/F4 — resolve+evaluate the resource-target struct if present.
    resource_targets: list[str] | None = None
    resource_exclude: list[str] | None = None
    res_ref = data.get("resource")
    if res_ref is not None:
        if not isinstance(res_ref, bytes):
            return make_error(
                ERR_INVALID_EXPRESSION,
                "compute/apply resource field must be a hash reference",
            )
        res_target = ctx.resolve_or_error(res_ref, "apply resource")
        if is_error(res_target):
            return res_target

        if is_compute_expression(res_target):
            res_value: Any = evaluate(res_target, scope, budget, ctx)
            if is_error(res_value):
                return res_value
        else:
            res_value = res_target

        if isinstance(res_value, Entity):
            res_data = res_value.data
        elif isinstance(res_value, dict) and "type" in res_value:
            res_data = res_value.get("data", {})
        elif isinstance(res_value, dict):
            res_data = res_value
        else:
            return make_error(
                ERR_TYPE_MISMATCH,
                "compute/apply resource did not evaluate to a resource-target struct",
            )

        targets_v = res_data.get("targets")
        if not isinstance(targets_v, list) or not all(isinstance(t, str) for t in targets_v):
            return make_error(
                ERR_TYPE_MISMATCH,
                "compute/apply resource.targets must be a list of strings",
            )
        resource_targets = list(targets_v)

        exclude_v = res_data.get("exclude")
        if exclude_v is not None:
            if not isinstance(exclude_v, list) or not all(isinstance(t, str) for t in exclude_v):
                return make_error(
                    ERR_TYPE_MISMATCH,
                    "compute/apply resource.exclude must be a list of strings",
                )
            resource_exclude = list(exclude_v)

    # F2/F5 — dual-check at full resolution when `capability` is present.
    # The handler-grant ceiling (ctx.capability) MUST also cover the
    # resource, otherwise a broader caller cap could escape handler scope.
    dispatch_cap: dict[str, Any] | None = None
    cap_ref = data.get("capability")
    if cap_ref is not None:
        # F5 eval-time: capability without resource is a structural error.
        if res_ref is None:
            return make_error(
                ERR_INVALID_EXPRESSION,
                "compute/apply with capability field MUST also have resource field",
            )

        if not isinstance(cap_ref, bytes):
            return make_error(
                ERR_INVALID_EXPRESSION,
                "compute/apply capability field must be a hash reference",
            )
        cap_target = ctx.resolve_or_error(cap_ref, "apply capability")
        if is_error(cap_target):
            return cap_target

        # Resolve-then-evaluate: matches lookup/hash semantics. Compute
        # expressions are evaluated; data entities (including capability
        # tokens) are used directly.
        if is_compute_expression(cap_target):
            cap_value: Any = evaluate(cap_target, scope, budget, ctx)
            if is_error(cap_value):
                return cap_value
        else:
            cap_value = cap_target

        if isinstance(cap_value, Entity):
            cap_data = cap_value.data
        elif isinstance(cap_value, dict) and "grants" in cap_value:
            cap_data = cap_value
        else:
            return make_error(
                ERR_TYPE_MISMATCH,
                "compute/apply capability did not evaluate to a capability entity",
            )

        # Full-resolution check: handler+operation+resource on both caps.
        # resource_targets is non-None here (F5 guarantees res_ref present).
        assert resource_targets is not None
        if not check_resource_scope(
            ctx.capability, path, operation,
            resource_targets, resource_exclude, ctx.local_peer_id,
            granter_peer_id=ctx._granter_frame(),
        ):
            return make_error(
                ERR_PERMISSION_DENIED,
                f"Handler grant does not cover target: {path}.{operation} on {resource_targets}",
            )
        if not check_resource_scope(
            cap_data, path, operation,
            resource_targets, resource_exclude, ctx.local_peer_id,
            granter_peer_id=ctx._granter_frame(cap_data),
        ):
            return make_error(
                ERR_PERMISSION_DENIED,
                f"Provided capability does not cover target: {path}.{operation} on {resource_targets}",
            )
        dispatch_cap = cap_data

    if ctx._execute_fn is not None:
        # V30 params assembly (§2.1, §4.1): construct the dispatched EXECUTE's
        # params entity with the *target operation's declared input_type* (from
        # the handler manifest), not a hardcoded type. The {type, data} envelope
        # matches the wire EXECUTE shape — without it an entity-native target
        # reading `params.<field>` via compute/field sees a bare dict with no
        # `data` and fails. The arg values are inlined: this is the spec's
        # no-type-extension encoding fallback (§2.1 "Value encoding", line 184) —
        # Python does not resolve per-field hash-vs-inline encoding. input_type
        # falls back to primitive/any only when the target has no resolvable
        # tree manifest (e.g. an in-memory wildcard handler).
        input_type = _resolve_handler_input_type(path, operation, ctx) or "primitive/any"
        # v3.19c α: dispatching to a handler is a compute→non-compute crossing.
        # An entity-valued arg is materialized to its bare form, stored, and
        # passed as a bare system/hash ref (V7 §1.4 refless) — the handler
        # resolves it and never sees the compute value model. Primitive/record
        # args inline unchanged.
        wire_args = {
            k: ctx.content_store.put(_materialize_bare(v, ctx)) if isinstance(v, Entity) else v
            for k, v in resolved_args.items()
        }
        params_entity = {"type": input_type, "data": wire_args}
        dispatched = ctx._execute_fn(
            path, operation, params_entity, ctx, dispatch_cap,
            resource_targets, resource_exclude,
        )
        return _wrap_dispatch_result(dispatched)

    return make_error(ERR_NOT_FOUND, f"No handler dispatch available for path: {path}")


def _wrap_dispatch_result(result: Any) -> Any:
    """SA-4 (§2.1 "Return wrapping"): handler-mode compute/apply MUST wrap a
    bare-primitive dispatch return in `compute/result`, uniformly across handler
    shapes, so a downstream expression decodes every dispatch target the same
    way. An entity-typed return (Entity or {type, data} dict) — including a
    propagated compute/error — passes through unchanged.
    """
    if isinstance(result, Entity):
        return result
    # N3: an entity-typed dict return is carried as an Entity so downstream
    # field navigation reads it by kind (e.g. compute→compute, field over an
    # apply result). A bare primitive/record is wrapped in compute/result.
    if isinstance(result, dict) and "type" in result and "data" in result:
        return Entity(type=result["type"], data=result.get("data") or {})
    return Entity(type="compute/result", data={"value": result})


def _eval_apply_closure(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """Closure application mode for compute/apply."""
    data = entity.data
    fn_hash = data["fn"]

    if not isinstance(fn_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "fn is not a hash reference")

    fn_target = ctx.resolve_or_error(fn_hash, "closure fn")
    if is_error(fn_target):
        return fn_target

    fn_value = evaluate(fn_target, scope, budget, ctx)
    if is_error(fn_value):
        return fn_value

    fn_type = _entity_type(fn_value)
    if fn_type != "compute/closure":
        return make_error(ERR_TYPE_MISMATCH, "Apply target is not a closure")

    fn_data = _entity_data(fn_value)
    if fn_data is None:
        return make_error(ERR_TYPE_MISMATCH, "Closure has no data")

    # Load captured environment
    env_hash = fn_data.get("env")
    new_scope = _load_scope(env_hash, ctx)
    if is_error(new_scope):
        return new_scope

    params = fn_data.get("params", [])
    args = data.get("args") or {}

    for param in params:
        arg_hash = args.get(param)
        if arg_hash is None:
            return make_error(ERR_MISSING_ARGUMENT, f"Missing argument: {param}")

        if not isinstance(arg_hash, bytes):
            return make_error(ERR_INVALID_EXPRESSION, f"Arg {param} is not a hash reference")

        arg_target = ctx.resolve_or_error(arg_hash, f"closure arg {param}")
        if is_error(arg_target):
            return arg_target

        arg = evaluate(arg_target, scope, budget, ctx)
        if is_error(arg):
            return arg
        new_scope.set(param, arg)

    body_hash = fn_data.get("body")
    if body_hash is None:
        return make_error(ERR_INVALID_EXPRESSION, "Closure has no body")

    body_target = ctx.resolve_or_error(body_hash, "closure body")
    if is_error(body_target):
        return body_target

    return _TailCall(body_target, new_scope)


# ---------------------------------------------------------------------------
# Builtin handlers (§3.5, N.2) — collection ops + store
# ---------------------------------------------------------------------------

def _invoke_closure(
    fn_value: Any,
    arg_values: list[Any],
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """Apply an already-evaluated compute/closure to already-evaluated args.

    The closure-application path in _eval_apply_closure takes arg *hashes*; the
    collection builtins instead have concrete element values in hand, so this
    binds them directly. Consumes a depth slot per call (each element returns
    before the next) and decrements budget like any evaluation step.
    """
    if _entity_type(fn_value) != "compute/closure":
        return make_error(ERR_TYPE_MISMATCH, "builtin function argument is not a closure")
    fn_data = _entity_data(fn_value)
    if fn_data is None:
        return make_error(ERR_TYPE_MISMATCH, "closure has no data")

    new_scope = _load_scope(fn_data.get("env"), ctx)
    if is_error(new_scope):
        return new_scope

    params = fn_data.get("params", [])
    if len(params) != len(arg_values):
        return make_error(
            ERR_MISSING_ARGUMENT,
            f"closure expects {len(params)} argument(s), got {len(arg_values)}",
        )
    for param, val in zip(params, arg_values, strict=True):
        new_scope.set(param, val)

    body_hash = fn_data.get("body")
    if not isinstance(body_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "closure has no body")
    body_target = ctx.resolve_or_error(body_hash, "closure body")
    if is_error(body_target):
        return body_target
    return evaluate(body_target, new_scope, budget, ctx)


def _eval_builtin(path: str, args: dict[str, Any], budget: Budget, ctx: EvalContext) -> Any:
    """Dispatch a builtin alias (§3.5). args are already-evaluated values."""
    if path == BUILTIN_MAP:
        collection = args.get("collection")
        fn = args.get("fn")
        if not isinstance(collection, list):
            return make_error(ERR_TYPE_MISMATCH, "map collection must be an array")
        out: list[Any] = []
        for el in collection:
            r = _invoke_closure(fn, [el], budget, ctx)
            # The closure RESULT is a CONTAINED position `[C-8, 2026-08-21]`:
            # `map` never reads it, it *places* it — structurally `concat`'s
            # element and `assoc`'s `value` one primitive over. §1.5's model is
            # "the same model as NaN propagation in IEEE 754", which is
            # ELEMENT-WISE: `map(f, [1,2,3])` where `f` fails only on element 2
            # is `[a, E, c]`. Short-circuiting the whole array is exception
            # semantics — the model §1.5 explicitly declined.
            #
            # It materializes code-only, at `_materialize_element`, with no
            # carve-out of its own: the v3.26 boundary is per array element and
            # therefore already covered this position before the position
            # existed. That is what "the fourth container is silently
            # uncovered" was written to avoid, and it held.
            #
            # The carve-out is `budget_exhausted` / `cascade_limit` ONLY
            # `[RULED §8.3]` — `depth_exceeded` is element-local (`depth` is
            # restored on unwind) and contains here like any other error, which
            # is the `[a, E, c]` row CV-9a measures.
            if is_short_circuit_limit(r):
                return r
            out.append(r)
        return out

    if path == BUILTIN_FILTER:
        collection = args.get("collection")
        # F11: all three collection builtins (map/filter/fold) take their lambda
        # under the arg key `fn`; the filter-specific `predicate` name is gone.
        fn = args.get("fn")
        if not isinstance(collection, list):
            return make_error(ERR_TYPE_MISMATCH, "filter collection must be an array")
        kept: list[Any] = []
        for el in collection:
            r = _invoke_closure(fn, [el], budget, ctx)
            # The predicate RESULT is a CONSUMED position `[C-8, 2026-08-21]` —
            # `filter` READS it for truthiness (§4.5) to decide inclusion, which
            # is §7.2's plain definition of consumption. Identical in kind to
            # `group-by`'s derived key, and it fails the same way if contained:
            # an error has no truth value, so coercing it silently DROPS the
            # element — a well-formed wrong answer carrying no error, the exact
            # outcome §3.5 refused when it declined to clamp `range(-1)` to `[]`.
            #
            # This arm was already correct; the check stays here so the
            # asymmetry with `map` eight lines up is deliberate and legible,
            # rather than looking like one of them was forgotten.
            if is_error(r):
                return r
            if truthy(r):
                kept.append(el)
        return kept

    if path == BUILTIN_FOLD:
        collection = args.get("collection")
        fn = args.get("fn")
        acc = args.get("initial")
        if not isinstance(collection, list):
            return make_error(ERR_TYPE_MISMATCH, "fold collection must be an array")
        # `initial` is a CONTAINED arg (`_CONTAINED_ARGS`), so an error arrives
        # here as a value rather than short-circuiting at the arg loop — except
        # a short-circuit limit code, which reports an evaluation the peer
        # aborted rather than a value it produced.
        if is_short_circuit_limit(acc):
            return acc
        for el in collection:
            acc = _invoke_closure(fn, [acc, el], budget, ctx)
            # The accumulator is a CONTAINED position `[C-8, 2026-08-21]`, and
            # arch names it the one of the three with the widest blast radius if
            # wrong — the only one where the alternative reading produces a
            # different VALUE rather than a different cost.
            #
            # `fold` binds the accumulator into the next invocation and never
            # reads it, so **a closure that ignores its accumulator recovers**.
            # That is correct under the error-as-value model, where errors are
            # ordinary values a program may inspect (§4.1 `is_error` exists
            # precisely so a fold can branch on one). Short-circuiting here
            # would make recovery unexpressible and would be exception
            # semantics wearing a value model's clothes.
            if is_short_circuit_limit(acc):
                return acc
        return acc

    if path == BUILTIN_RANGE:
        return _eval_builtin_range(args, budget)

    if path == BUILTIN_GROUP_BY:
        return _eval_builtin_group_by(args, budget, ctx)

    if path == BUILTIN_CONCAT:
        return _eval_builtin_concat(args)

    if path == BUILTIN_ASSOC:
        return _eval_builtin_assoc(args)

    if path == BUILTIN_STORE:
        return _eval_builtin_store(args, ctx)

    return make_error(ERR_NOT_FOUND, f"Unknown builtin: {path}")


# ---------------------------------------------------------------------------
# The v3.24 collection primitives — range / group-by / concat / assoc (§3.5)
# ---------------------------------------------------------------------------
#
# Error-as-value flow-through is governed by §7.2, not by a rule of their own
# `[v3.25]`. §3.5's table applies the existing consumed-operand `[MUST]` to all
# seven positions so no implementer re-derives it:
#
#   range     n              consumed (sizes the array)      short-circuit
#   group-by  derived key    consumed (compared to group)    short-circuit
#   group-by  element        copied into `members`           CONTAIN
#   assoc     index          consumed (positions the write)  short-circuit
#   assoc     value          placed into the output          CONTAIN
#   concat    each collection consumed (length read to copy) short-circuit
#   concat    element        copied into the output          CONTAIN
#
# `[C-8, 2026-08-21]` extends the same table to the three closure primitives,
# which predate it — by the rule *places-without-reading contains*:
#
#   map       closure result placed into the output          CONTAIN
#   filter    predicate result read for truthiness (§4.5)    short-circuit
#   fold      accumulator    bound into the next invocation  CONTAIN
#
# with `budget_exhausted` / `cascade_limit` — and NOT `depth_exceeded` —
# carved out of the two closure-primitive CONTAIN rows `[RULED §8]`; see
# `_SHORT_CIRCUIT_LIMIT_CODES`.
#
# The *arg-level* half of that table lives in `_CONTAINED_ARGS` and is applied
# by `_eval_apply_handler`'s canonical-order arg loop, which is why these
# functions receive already-evaluated values and never resolve a hash. The
# *element-level* half is here, and its materialization is `_materialize_bare`.


def _as_array_index(v: Any) -> int | None:
    """`v` as an array index, or None if it is not an integer value.

    `bool` is an `int` subclass in Python and is **not** an index — the same
    exclusion `compute/index` already makes. Magnitude is not judged here:
    an out-of-domain magnitude is not a type error (§2.2's cross-impl ruling),
    so the caller decides between `index_out_of_range` and
    `count_out_of_range` on a value this function has already accepted.
    """
    if isinstance(v, bool) or not isinstance(v, int):
        return None
    return v


def _eval_builtin_range(args: dict[str, Any], budget: Budget) -> Any:
    """`range(n)` → `[0 … n-1]`, empty when `n` is `0` (§3.5, v3.24).

    Single-argument form only — a start offset is expressed inside the lambda,
    not as a second parameter. It exists because `map`/`filter`/`fold` pass an
    element and not its index.

    **A negative `n`, or an `n` exceeding the maximum representable array
    length, is `count_out_of_range`** `[MUST, v3.25]` — *not* `type_mismatch`
    (§2.2: an out-of-domain magnitude is not a type error) and *not* clamped to
    `[]` (`n` is a loop bound, so a silent empty propagates through every
    downstream `map`/`filter`/`fold` and yields a well-formed wrong answer
    carrying no error).
    """
    n = _as_array_index(args.get("n"))
    if n is None:
        return make_error(
            ERR_TYPE_MISMATCH,
            f"range n must be an integer, got {type(args.get('n')).__name__}",
        )
    if n < 0 or n > MAX_ARRAY_LENGTH:
        # The upper bound is where Python differs from every peer language and
        # therefore where it must check rather than decode — see
        # MAX_ARRAY_LENGTH.
        return make_error(
            ERR_COUNT_OUT_OF_RANGE,
            f"range n must be non-negative and representable, got {n}",
        )
    # Charge the budget per produced element so `range(huge)` exhausts rather
    # than OOMs — the same per-step cost `map`/`filter`/`fold` already pay.
    # Checked BEFORE allocating: the point is to refuse the allocation, and a
    # check that runs after it has already happened is a comment.
    if n > budget.operations:
        return make_error(
            ERR_BUDGET_EXHAUSTED,
            f"range({n}) exceeds remaining budget {budget.operations}",
        )
    budget.operations -= n
    return list(range(n))


def _eval_builtin_group_by(args: dict[str, Any], budget: Budget, ctx: EvalContext) -> Any:
    """`group-by(collection, fn)` — group elements by a derived key, one pass
    (§3.5, v3.24; result shape ruled v3.25).

    **The result is an array of `system/compute/group{key, members}`** `[MUST,
    v3.25]` — the key is carried, not dropped, because the shapes this
    primitive exists to serve (a histogram, a bucketed aggregation, a router)
    are exactly the ones whose output is unreadable without its labels.

    Within each group, elements keep input index order; **groups are ordered by
    first appearance of their key** — not by key sort order, which would need a
    total order over arbitrary key types this extension does not define.

    **Key equality is byte-identity over the canonical ECF encoding** of the
    derived key — the protocol's own value identity, defined for every key type
    `fn` may return.

    A `compute/error` **key** short-circuits even though the key now has an
    output position: grouping by an error would make its `message` string
    structurally load-bearing, so two failures worded differently would become
    two groups and one reworded message would change the result's shape. The
    **element** is a contained position and flows into `members` untouched.
    """
    collection = args.get("collection")
    fn = args.get("fn")
    if not isinstance(collection, list):
        return make_error(ERR_TYPE_MISMATCH, "group-by collection must be an array")

    order: list[bytes] = []
    members: dict[bytes, list[Any]] = {}
    key_values: dict[bytes, Any] = {}
    for el in collection:
        key = _invoke_closure(fn, [el], budget, ctx)
        if is_error(key):
            # Consumed position — §7.2 short-circuit.
            return key
        key_bytes = _canonical_key_bytes(key, ctx)
        if key_bytes is None:
            return make_error(
                ERR_TYPE_MISMATCH,
                f"group-by key is not encodable ({type(key).__name__})",
            )
        if key_bytes not in members:
            order.append(key_bytes)
            members[key_bytes] = []
            key_values[key_bytes] = key
        members[key_bytes].append(el)

    return [
        Entity(
            type=TYPE_COMPUTE_GROUP,
            data={"key": key_values[k], "members": members[k]},
        )
        for k in order
    ]


def _canonical_key_bytes(key: Any, ctx: EvalContext) -> bytes | None:
    """The ECF byte-identity of a `group-by` key, or None if unencodable.

    The key is materialized first: an entity-valued key must compare by the
    same bytes it would carry in the result, not by Python object identity.
    """
    try:
        return ecf_encode(_materialize_bare(key, ctx))
    except Exception:
        return None


def _eval_builtin_concat(args: dict[str, Any]) -> Any:
    """`concat(...collections)` — join arrays **order-preserving, one level**
    (§3.5, v3.24). It does **not** flatten recursively.

    `concat()` with no collections is the empty array; `concat(a)` is `a`.
    There is otherwise no way to join k arrays: `fold` cannot (the accumulator
    step needs the append that does not exist), `map` yields k arrays, and
    `construct` changes the entity shape, which boundary equivalence forbids.

    Element types MUST match across all collections; a mismatch is a
    `type_mismatch` **error-as-value**, not a fault.

    **A `compute/error` element is type-transparent to that check** `[MUST,
    v3.25]`: it neither matches nor mismatches, and flows through untouched.
    Per §1.5 an error is *"the same model as NaN propagation in IEEE 754"* — a
    poisoned value **of** the array's element type, not a value of a different
    type — and §7.2 scopes `concat` to consuming its `collections`, never their
    elements, so inspecting elements for errors is the one behaviour it must
    not have.
    """
    collections = args.get("collections")
    if not isinstance(collections, list):
        return make_error(
            ERR_TYPE_MISMATCH,
            "concat collections must be an array of arrays, got "
            f"{type(collections).__name__}",
        )

    out: list[Any] = []
    tag: str | None = None
    for sub in collections:
        if is_error(sub):
            # §3.5's table: each `collection` is a CONSUMED position — "its
            # length is read to copy" — so an error there short-circuits rather
            # than falling through to the array-shape check. Reading it as a
            # shape violation would answer `type_mismatch` and discard the
            # original code, which is exactly the substitution §7.2 forbids for
            # a consumed operand.
            return sub
        if not isinstance(sub, list):
            return make_error(
                ERR_TYPE_MISMATCH,
                f"concat: each collection must be an array, got {type(sub).__name__}",
            )
        for el in sub:
            if is_error(el):
                out.append(el)
                continue
            el_tag = _element_type_tag(el)
            if tag is None:
                tag = el_tag
            elif el_tag != tag:
                return make_error(
                    ERR_TYPE_MISMATCH,
                    f"concat: element type {el_tag!r} does not match {tag!r}",
                )
            out.append(el)
    return out


def _element_type_tag(v: Any) -> str:
    """Classify a compute value for `concat`'s element-type-match check.

    `int`/`uint` collapse to one `"integer"` tag — they are **annotations, not
    distinct value types** (§2.2), so a `concat` of an int array and a uint
    array is not a mismatch. `bool` is checked before `int` because it is an
    `int` subclass here and is a distinct value type on the wire.
    """
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "string"
    if isinstance(v, (bytes, bytearray)):
        return "bytes"
    if isinstance(v, list):
        return "array"
    if isinstance(v, Entity):
        return f"entity:{v.type}"
    if isinstance(v, dict) and "type" in v:
        return f"entity:{v['type']}"
    if isinstance(v, dict):
        return "record"
    return type(v).__name__


def _eval_builtin_assoc(args: dict[str, Any]) -> Any:
    """`assoc(collection, index, value)` — a new array identical to
    `collection` except at `index`, which carries `value` (§3.5, v3.24).

    **An out-of-range `index` — negative, or ≥ the collection's length — is
    `index_out_of_range`** `[MUST, v3.25]`: the same code and the same
    condition as `compute/index` (§2.2). *(v3.24 said `type_mismatch` here;
    that contradicted §2.2's ruling that an out-of-bounds magnitude is not a
    type error, and one document must not answer one malformed program with two
    codes depending on which array operation it reached.)*

    `value` is a **contained** position: an error-as-value is placed into the
    array and the whole `assoc` does **not** short-circuit. That exemption is
    applied upstream by `_CONTAINED_ARGS`, so by the time it reaches here it is
    simply a value.

    **`assoc` MUST NOT be an implicit lowering target** `[MUST]` — `map` and
    `fold` are never lowered onto it. This evaluator performs no such lowering,
    so there is nothing here to suppress; the rule is recorded because an
    "optimization" that rewrote a fold into a sequence of `assoc` updates would
    silently remove the parallelism the fold form buys.
    """
    collection = args.get("collection")
    if not isinstance(collection, list):
        return make_error(ERR_TYPE_MISMATCH, "assoc collection must be an array")

    idx = _as_array_index(args.get("index"))
    if idx is None:
        return make_error(
            ERR_TYPE_MISMATCH,
            f"assoc index must be an integer, got {type(args.get('index')).__name__}",
        )
    if idx < 0 or idx >= len(collection):
        return make_error(
            ERR_INDEX_OUT_OF_RANGE,
            f"assoc index {idx} out of range for array of length {len(collection)}",
        )

    if "value" not in args:
        return make_error(ERR_MISSING_ARGUMENT, "assoc requires a value arg")

    out = list(collection)
    out[idx] = args["value"]
    return out


def _eval_builtin_store(args: dict[str, Any], ctx: EvalContext) -> Any:
    """store builtin (§3.5) — write `value` to the tree at `path`. Impure.

    Dispatches through `system/tree:put` (matching core-go) so capability
    gating (§6.3), history, and reactive cascades are handled by the tree
    handler against the EXECUTE caller's grant. A bare primitive value is
    wrapped in a `primitive/any` entity (the wire shape primitives use); an
    entity-typed value is written as-is. When no dispatcher is wired (e.g. a
    bare eval context in a unit test), falls back to a direct, capability-gated
    tree write — which returns the same `system/tree/put-result` shape the
    dispatch does, so store has **one** return shape rather than one per path.

    **A `compute/error` `value` is written, code-only, and the store succeeds**
    `[MUST]` (§2131's SA-9 worked example, ruled 2026-08-16). It is not
    propagated: see the short-circuit note in `_eval_apply_handler` for why the
    write payload sits outside that rule, and :func:`error_materialized` for why
    only `code` reaches the bytes.
    """
    path_val = args.get("path")
    value = args.get("value")
    if not isinstance(path_val, str):
        return make_error(ERR_TYPE_MISMATCH, "store path must be a string")

    if is_error(value):
        # The SA-9 half of §2.4's materialization surface — the imperative
        # analog of the §7.2 `result_path` write. `is_error` is kind-based, so
        # **both** in-language representations land here identically: a minted
        # dict from `make_error`, and an `Entity` from an SA-1 literal or a
        # lookup onto a stored error. That split is exactly what went uncovered
        # at the wire crossing (see `error_to_wire`) — one answer, both forms.
        value = error_materialized(value)
    else:
        # v3.19c α: a tree write is a compute→non-compute crossing — materialize
        # the value to its bare wire form first (identity for an already-bare
        # entity or a primitive), so what lands in the tree is a normal bare
        # entity.
        value = _materialize_bare(value, ctx)

    # Coerce the value to an entity {type, data}. Entity-typed values pass
    # through; bare primitives are wrapped in primitive/any.
    if isinstance(value, Entity):
        ent_dict = {"type": value.type, "data": value.data}
    elif isinstance(value, dict) and "type" in value and "data" in value:
        ent_dict = {"type": value["type"], "data": value["data"]}
    else:
        ent_dict = {"type": "primitive/any", "data": value}

    if ctx._execute_fn is not None:
        # tree:put reads the path from resource.targets[0] and the entity from
        # params.entity; capability is checked by the tree handler.
        #
        # `to_dict()` rather than the two-key `ent_dict`: `put` is a receipt
        # path and the peer authors nothing (0.8.2.11 §6.3), so every submitter
        # constructs — including an in-process one. This site is the second
        # `put` submitter in the tree and it is not reachable from the SDK, so
        # nothing in `entity_sdk` covers it.
        return ctx._execute_fn(
            "system/tree", "put",
            {"entity": Entity(type=ent_dict["type"], data=ent_dict["data"]).to_dict()},
            ctx, None, [path_val], None,
        )

    # Fallback: no dispatcher wired — write directly, gated here.
    if not ctx.check_write_permission(path_val):
        return make_error(ERR_PERMISSION_DENIED, f"No write access to path: {path_val}")
    entity = Entity(type=ent_dict["type"], data=ent_dict["data"])
    if ctx.emit_pathway is not None:
        from entity_core.storage.emit import EmitContext
        emit_result = ctx.emit_pathway.emit(path_val, entity, EmitContext(source="handler"))
        written_hash = emit_result.hash
    else:
        written_hash = ctx.content_store.put(entity)
        ctx.entity_tree.set(path_val, written_hash)
    # Same shape the dispatch path returns (`system/tree:put`'s put-result), so
    # a successful store never evaluates to an error just because the value it
    # wrote was one — the divergence that a per-path return shape would smuggle
    # back in on the very rule this function implements.
    return {
        "type": "system/tree/put-result",
        "data": {"path": path_val, "hash": written_hash},
    }


def _eval_inline_alias(
    path: str,
    args: dict[str, Any],
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """Evaluate an inline-equivalent builtin (§3.5) by synthesizing its inline
    type and tail-calling into the normal evaluator.

    The inline expression types take their operator/name as a *string* field but
    a `compute/apply` args map is `map_of system/hash` — so the scalar fields
    (op/name/entity_type) arrive as hashes referencing literals and must be
    resolved to their string value. The remaining hash-typed fields (left/right/
    entity/fields) pass straight through; the inline evaluator resolves them.
    """
    inline_type, scalar_fields = _INLINE_ALIAS_BUILTINS[path]

    for name, h in args.items():
        if not isinstance(h, bytes):
            return make_error(
                ERR_INVALID_EXPRESSION,
                f"builtin {path} arg {name!r} is not a hash reference",
            )

    def _resolve_scalar(h: bytes, label: str) -> Any:
        target = ctx.resolve_or_error(h, label)
        if is_error(target):
            return target
        return evaluate(target, scope, budget, ctx)

    if inline_type == "compute/construct":
        # entity_type is the lone scalar; every other arg is a field hash.
        inline_data: dict[str, Any] = {"fields": {n: h for n, h in args.items() if n != "entity_type"}}
        et_hash = args.get("entity_type")
        if isinstance(et_hash, bytes):
            et = _resolve_scalar(et_hash, "construct entity_type")
            if is_error(et):
                return et
            inline_data["entity_type"] = et
        else:
            inline_data["entity_type"] = ""
    else:
        inline_data = {}
        for name, h in args.items():
            if name in scalar_fields:
                val = _resolve_scalar(h, f"builtin {path} arg {name!r}")
                if is_error(val):
                    return val
                inline_data[name] = val
            else:
                inline_data[name] = h  # raw hash — inline evaluator resolves it

    return _TailCall(Entity(type=inline_type, data=inline_data), scope)


def _eval_if(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    cond_hash = entity.data.get("condition")
    if cond_hash is None or not isinstance(cond_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "if missing condition hash")

    cond_target = ctx.resolve_or_error(cond_hash, "if condition")
    if is_error(cond_target):
        return cond_target
    condition = evaluate(cond_target, scope, budget, ctx)
    if is_error(condition):
        return condition

    if truthy(condition):
        then_hash = entity.data.get("then")
        if then_hash is None or not isinstance(then_hash, bytes):
            return make_error(ERR_INVALID_EXPRESSION, "if missing then hash")
        then_target = ctx.resolve_or_error(then_hash, "if then")
        if is_error(then_target):
            return then_target
        return _TailCall(then_target, scope)

    else_hash = entity.data.get("else")
    if else_hash is not None:
        if not isinstance(else_hash, bytes):
            return make_error(ERR_INVALID_EXPRESSION, "if else is not a hash")
        else_target = ctx.resolve_or_error(else_hash, "if else")
        if is_error(else_target):
            return else_target
        return _TailCall(else_target, scope)

    return None


def _eval_let(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    new_scope = scope.copy()
    bindings = entity.data.get("bindings", [])

    for binding in bindings:
        name = binding.get("name")
        value_hash = binding.get("value")

        if name is None:
            return make_error(ERR_INVALID_EXPRESSION, "let binding missing name")
        if value_hash is None or not isinstance(value_hash, bytes):
            return make_error(ERR_INVALID_EXPRESSION, f"let binding {name} missing value hash")

        value_target = ctx.resolve_or_error(value_hash, f"let binding {name}")
        if is_error(value_target):
            return value_target

        # Sequential binding (let* semantics)
        value = evaluate(value_target, new_scope, budget, ctx)
        if is_error(value):
            return value
        new_scope.set(name, value)

    body_hash = entity.data.get("body")
    if body_hash is None or not isinstance(body_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "let missing body hash")

    body_target = ctx.resolve_or_error(body_hash, "let body")
    if is_error(body_target):
        return body_target
    return _TailCall(body_target, new_scope)


def _eval_lambda(
    entity: Entity,
    scope: Scope,
    ctx: EvalContext,
) -> dict[str, Any]:
    params = entity.data.get("params", [])
    body_hash = entity.data.get("body")

    env_hash = _capture_scope(scope, ctx)

    # N3: a closure is an entity value — carry it as an Entity so that, when a
    # closure is itself captured into an enclosing scope, capture tags it
    # kind:"entity" (stored by hash, resolvable as a closure) rather than
    # inlining it as a record.
    return Entity(
        type="compute/closure",
        data={
            "params": params,
            "body": body_hash,
            "env": env_hash,
        },
    )


def _eval_arithmetic(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    op = entity.data.get("op", "")
    left, right, l_uint, r_uint = _resolve_binary_operands(entity, scope, budget, ctx)
    if is_error(left):
        return left
    if is_error(right):
        return right
    return _apply_arithmetic(op, left, right, l_uint, r_uint)


def _eval_compare(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    op = entity.data.get("op", "")
    left, right, l_uint, r_uint = _resolve_binary_operands(entity, scope, budget, ctx)
    if is_error(left):
        return left
    if is_error(right):
        return right
    return _apply_compare(op, left, right, l_uint, r_uint)


def _eval_logic(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    op = entity.data.get("op", "")

    left_hash = entity.data.get("left")
    if left_hash is None or not isinstance(left_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "logic missing left hash")

    left_target = ctx.resolve_or_error(left_hash, "logic left")
    if is_error(left_target):
        return left_target
    left = evaluate(left_target, scope, budget, ctx)
    if is_error(left):
        return left

    if op == "not":
        return not truthy(left)

    right_hash = entity.data.get("right")
    if right_hash is None or not isinstance(right_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "logic missing right hash")

    right_target = ctx.resolve_or_error(right_hash, "logic right")
    if is_error(right_target):
        return right_target
    right = evaluate(right_target, scope, budget, ctx)
    if is_error(right):
        return right

    if op == "and":
        return truthy(left) and truthy(right)
    if op == "or":
        return truthy(left) or truthy(right)

    return make_error(ERR_INVALID_EXPRESSION, f"Unknown logic op: {op}")


def _eval_field(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    name = entity.data.get("name", "")
    entity_hash = entity.data.get("entity")
    if entity_hash is None or not isinstance(entity_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "field missing entity hash")

    target_ref = ctx.resolve_or_error(entity_hash, "field target")
    if is_error(target_ref):
        return target_ref
    target = evaluate(target_ref, scope, budget, ctx)
    if is_error(target):
        return target

    # N.5: field navigation composes over an entity OR a bare record/map value
    # (see _field_record), so field(field(x,"a"),"b") and field(index(xs,0),"k")
    # evaluate by composing the inner result into the outer field.
    record = _field_record(target)
    if record is None:
        return make_error(
            ERR_TYPE_MISMATCH,
            f"Field access requires an entity or record value, got: {type(target).__name__}",
        )

    if name not in record:
        return make_error(ERR_NOT_FOUND, f"Field not found: {name}")
    return record[name]


def _eval_construct(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    entity_type = entity.data.get("entity_type", "")
    fields = entity.data.get("fields") or {}

    result_fields: dict[str, Any] = {}
    for name, h in canonical_sorted(fields):
        if not isinstance(h, bytes):
            return make_error(ERR_INVALID_EXPRESSION, f"Construct field {name} is not a hash")
        value_target = ctx.resolve_or_error(h, f"construct field {name}")
        if is_error(value_target):
            return value_target
        value = evaluate(value_target, scope, budget, ctx)
        if is_error(value):
            return value
        # v3.19c Part A (α): keep field values **typed** in-flight — an
        # entity-valued field stays an `Entity` object so navigation composes
        # by kind (N3: field→.data→Entity→.data), no kind-tags, no shape-sniff.
        # The compute value model is compute-internal; the constructed entity is
        # materialized to its **bare** wire form (entity fields → bare
        # system/hash refs, V7 §1.4) only at a compute→non-compute crossing
        # (`_materialize_bare`), where it is byte-identical to a hand-built
        # entity. (This in-flight representation is implementation-private; the
        # cross-impl surface is the materialized hash.)
        result_fields[name] = value

    return Entity(type=entity_type, data=result_fields)


def _eval_index(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """compute/index — element at a position (§2.2, N.1). Pure.

    Out-of-range or negative index → index_out_of_range. Index on null or a
    non-array value → type_mismatch. No from-end (Python-style) indexing.
    """
    array_hash = entity.data.get("array")
    index_hash = entity.data.get("index")
    if not isinstance(array_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "index missing array hash")
    if not isinstance(index_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "index missing index hash")

    arr_target = ctx.resolve_or_error(array_hash, "index array")
    if is_error(arr_target):
        return arr_target
    arr = evaluate(arr_target, scope, budget, ctx)
    if is_error(arr):
        return arr
    if not isinstance(arr, list):
        return make_error(
            ERR_TYPE_MISMATCH,
            f"compute/index requires an array, got {type(arr).__name__}",
        )

    idx_target = ctx.resolve_or_error(index_hash, "index value")
    if is_error(idx_target):
        return idx_target
    idx = evaluate(idx_target, scope, budget, ctx)
    if is_error(idx):
        return idx
    # bool is an int subclass but is not an integer index.
    if isinstance(idx, bool) or not isinstance(idx, int):
        return make_error(
            ERR_TYPE_MISMATCH,
            f"compute/index requires an integer index, got {type(idx).__name__}",
        )
    if idx < 0 or idx >= len(arr):
        return make_error(
            ERR_INDEX_OUT_OF_RANGE,
            f"index {int(idx)} out of range for array of length {len(arr)}",
        )
    return arr[idx]


def _eval_length(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """compute/length — element count of an array (§2.2, N.1). Pure.

    Empty array → 0. Length on null or a non-array value → type_mismatch.
    Returns the count as a plain (signed-canonical) integer.
    """
    array_hash = entity.data.get("array")
    if not isinstance(array_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "length missing array hash")

    arr_target = ctx.resolve_or_error(array_hash, "length array")
    if is_error(arr_target):
        return arr_target
    arr = evaluate(arr_target, scope, budget, ctx)
    if is_error(arr):
        return arr
    if not isinstance(arr, list):
        return make_error(
            ERR_TYPE_MISMATCH,
            f"compute/length requires an array, got {type(arr).__name__}",
        )
    return len(arr)


def _eval_numeric_cast(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> Any:
    """compute/numeric-cast — intra-numeric conversion (§2.2, N.4). Pure.

    Matrix is {primitive/int, primitive/uint, primitive/float}². int↔uint
    reinterpret the two's-complement bit pattern at 64-bit width; int/uint→float
    is defined-lossy above 2^53 (not an error); float→int/uint truncate toward
    zero with NaN/±Inf/out-of-range → cast_out_of_range. Non-numeric value or a
    non-numeric to_type → type_mismatch.
    """
    value_hash = entity.data.get("value")
    to_type = entity.data.get("to_type")
    if not isinstance(value_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "numeric-cast missing value hash")

    target = ctx.resolve_or_error(value_hash, "numeric-cast value")
    if is_error(target):
        return target
    val = evaluate(target, scope, budget, ctx)
    if is_error(val):
        return val

    return _apply_numeric_cast(to_type, val)


def _apply_numeric_cast(to_type: Any, val: Any) -> Any:
    """Core numeric-cast conversion (§2.2, rules 9-11).

    The cast is a pure value conversion with no carried tag. Its only sign
    effect is *syntactic* (rule 11 Option A): a `numeric-cast → uint` makes a
    div/mod/compare unsigned only when it is that op's direct operand entity
    (decided by `_is_uint_cast`, not by this value).

    - int ↔ uint: reinterpret the two's-complement bit pattern at 64-bit width.
      → primitive/int yields the signed-canonical value [-2^63, 2^63).
      → primitive/uint yields the non-negative magnitude [0, 2^64), which
        encodes as CBOR major type 0 (rule 10's cast→uint exception).
    - int/uint → float: IEEE 754 binary64, defined-lossy above 2^53.
    - float → int/uint: truncate toward zero; NaN/±Inf/out-of-range →
      cast_out_of_range.
    """
    if to_type not in ("primitive/int", "primitive/uint", "primitive/float"):
        return make_error(
            ERR_TYPE_MISMATCH,
            "compute/numeric-cast to_type must be primitive/int, primitive/uint, "
            f"or primitive/float; got {to_type!r}",
        )

    is_int = _is_int_operand(val)
    is_float = isinstance(val, float)
    if not (is_int or is_float):
        return make_error(
            ERR_TYPE_MISMATCH,
            f"compute/numeric-cast value must be numeric, got {type(val).__name__}",
        )

    if to_type == "primitive/float":
        # int/uint→float converts by the integer's numeric value.
        return float(int(val)) if is_int else float(val)

    # Target is an integer type.
    if is_float:
        if math.isnan(val) or math.isinf(val):
            return make_error(ERR_CAST_OUT_OF_RANGE, f"cannot cast {val} to {to_type}")
        t = int(math.trunc(val))  # truncate toward zero
        if to_type == "primitive/int":
            if t < INT64_MIN or t > INT64_MAX:
                return make_error(
                    ERR_CAST_OUT_OF_RANGE, f"float {val} out of range for primitive/int",
                )
            return t
        if t < 0 or t > UINT64_MAX:
            return make_error(
                ERR_CAST_OUT_OF_RANGE, f"float {val} out of range for primitive/uint",
            )
        return t

    # int/uint source → int/uint target: reinterpret the 64-bit pattern. There is
    # no value-level uint tag (rule 11, Option A): → int yields the signed-
    # canonical value; → uint yields the non-negative magnitude (encodes major 0
    # per rule 10's exception). The unsigned-ness of div/mod/compare is decided
    # syntactically at the operand (see _is_uint_cast), not from this value.
    bits = _bits64(int(val))
    if to_type == "primitive/int":
        return _signed64(bits)            # signed-canonical [-2^63, 2^63)
    return bits                            # non-negative magnitude [0, 2^64)


# ---------------------------------------------------------------------------
# Evaluator helpers
# ---------------------------------------------------------------------------

def _resolve_binary_operands(
    entity: Entity,
    scope: Scope,
    budget: Budget,
    ctx: EvalContext,
) -> tuple[Any, Any, bool, bool]:
    """Resolve+evaluate left and right operands, left before right (§8.2).

    Also reports, per operand, whether its *expression* is a direct
    `compute/numeric-cast → primitive/uint` (rule 11 Option A syntactic unsigned
    signal). The flags are read from the operand entity before evaluation, so an
    indirected cast (through let/if/lookup-scope/etc.) reports False.
    """
    left_hash = entity.data.get("left")
    if left_hash is None or not isinstance(left_hash, bytes):
        return make_error(ERR_INVALID_EXPRESSION, "missing left hash"), None, False, False

    left_target = ctx.resolve_or_error(left_hash, "left operand")
    if is_error(left_target):
        return left_target, None, False, False
    l_uint = _is_uint_cast(left_target)
    left = evaluate(left_target, scope, budget, ctx)
    if is_error(left):
        return left, None, False, False

    right_hash = entity.data.get("right")
    if right_hash is None or not isinstance(right_hash, bytes):
        return left, make_error(ERR_INVALID_EXPRESSION, "missing right hash"), l_uint, False

    right_target = ctx.resolve_or_error(right_hash, "right operand")
    if is_error(right_target):
        return left, right_target, l_uint, False
    r_uint = _is_uint_cast(right_target)
    right = evaluate(right_target, scope, budget, ctx)
    return left, right, l_uint, r_uint


def _is_int_operand(v: Any) -> bool:
    """A numeric integer operand. bool is NOT numeric (it is an int subclass but
    the type system has no bool→int coercion)."""
    return isinstance(v, int) and not isinstance(v, bool)


def _apply_arithmetic(
    op: str, left: Any, right: Any, l_uint: bool = False, r_uint: bool = False,
) -> Any:
    """Apply arithmetic operation (§2.2 rules 1-11, WASM/JVM integer model).

    Rule 1: float promotion — either operand float → both float, result float.
    Rules 2-3: integer arithmetic; div exact → integer, non-exact → float.
    Rule 4: truncated mod (signed, sign follows dividend); float operand →
            type_mismatch (mod is integer-only).
    Rule 5: integer div/mod by zero → division_by_zero; float div/0 → IEEE 754.
    Rule 6: non-numeric operand → type_mismatch.
    Rule 8: add/sub/mul are sign-agnostic 64-bit two's-complement — operate on
            the bit patterns, wrap mod 2^64, encode the result signed (rule 10).
    Rule 9/11: div/mod use signed interpretation by default; an operand is read
            unsigned only when `l_uint`/`r_uint` is set — i.e. that operand's
            *expression* was a direct numeric-cast → uint (syntactic, Option A).
    """
    l_int, r_int = _is_int_operand(left), _is_int_operand(right)
    l_float, r_float = isinstance(left, float), isinstance(right, float)
    if not (l_int or l_float) or not (r_int or r_float):
        return make_error(
            ERR_TYPE_MISMATCH,
            f"Arithmetic requires numeric operands, got {type(left).__name__} and {type(right).__name__}",
        )

    # Rule 1: float promotion takes precedence over the integer rules.
    if l_float or r_float:
        lf, rf = float(left), float(right)
        if op == "add":
            return lf + rf
        if op == "sub":
            return lf - rf
        if op == "mul":
            return lf * rf
        if op == "div":
            if rf == 0.0:
                # IEEE 754 (rule 5): 0/0 → NaN, else ±Inf by sign of dividend.
                return float("nan") if lf == 0.0 else math.copysign(float("inf"), lf)
            return lf / rf
        if op == "mod":
            # Rule 4: mod is integer-only — a float operand is a type_mismatch.
            return make_error(ERR_TYPE_MISMATCH, "Modulo requires integer operands")
        return make_error(ERR_INVALID_EXPRESSION, f"Unknown arithmetic op: {op}")

    # Rule 8: add/sub/mul sign-agnostic on the 64-bit bit patterns.
    if op in ("add", "sub", "mul"):
        a, b = _bits64(int(left)), _bits64(int(right))
        if op == "add":
            return _signed64(a + b)
        if op == "sub":
            return _signed64(a - b)
        return _signed64(a * b)

    # Rule 9/11: div/mod use signed interpretation by default; an operand is
    # unsigned only when its expression was a direct numeric-cast → uint
    # (l_uint/r_uint). Results are reduced to signed-canonical (rule 10).
    if op in ("div", "mod"):
        a, b = _operand_int(left, l_uint), _operand_int(right, r_uint)
        if b == 0:
            return make_error(ERR_DIVISION_BY_ZERO, "Division by zero")
        if op == "div":
            if a % b == 0:
                return _signed64(a // b)  # exact → integer (rule 3)
            return a / b  # non-exact → float (rule 3)
        # mod: truncated remainder, sign follows dividend (rule 4).
        m = abs(a) % abs(b)
        return _signed64(-m if a < 0 else m)

    return make_error(ERR_INVALID_EXPRESSION, f"Unknown arithmetic op: {op}")


def _apply_compare(
    op: str, left: Any, right: Any, l_uint: bool = False, r_uint: bool = False,
) -> Any:
    """Apply comparison operation (§2.2 comparison semantics + rule 9/11).

    eq/neq: incompatible types → false/true (never error). Ordered
    (lt/gt/lte/gte): both numeric or both strings. Integer operands use signed
    interpretation by default; an operand is read unsigned only when its
    expression was a direct numeric-cast → uint (l_uint/r_uint, syntactic).
    Mixed numeric: float promotion. String: lexicographic UTF-8 byte order.
    """
    l_num = _is_int_operand(left) or isinstance(left, float)
    r_num = _is_int_operand(right) or isinstance(right, float)

    if op in ("eq", "neq"):
        if l_num and r_num:
            equal = _cmp_num(left, l_uint) == _cmp_num(right, r_uint)
        elif _same_type_class(left, right):
            equal = left == right
        else:
            equal = False  # incompatible types are never equal
        return equal if op == "eq" else not equal

    if l_num and r_num:
        lv, rv = _cmp_num(left, l_uint), _cmp_num(right, r_uint)
        if op == "lt":
            return lv < rv
        if op == "gt":
            return lv > rv
        if op == "lte":
            return lv <= rv
        if op == "gte":
            return lv >= rv

    if isinstance(left, str) and isinstance(right, str):
        lb, rb = left.encode("utf-8"), right.encode("utf-8")
        if op == "lt":
            return lb < rb
        if op == "gt":
            return lb > rb
        if op == "lte":
            return lb <= rb
        if op == "gte":
            return lb >= rb

    return make_error(
        ERR_TYPE_MISMATCH,
        f"Ordering comparison requires numeric or string operands, got {type(left).__name__} and {type(right).__name__}",
    )


def _cmp_num(v: Any, is_unsigned: bool = False) -> Any:
    """Comparable numeric value: floats as-is; integers by their rule-9/11
    interpretation (signed-default, or unsigned when the operand expression was
    a direct numeric-cast → uint)."""
    if isinstance(v, float):
        return v
    return _operand_int(v, is_unsigned)


def _same_type_class(a: Any, b: Any) -> bool:
    """Check if two values are in the same type class for equality."""
    if (_is_int_operand(a) or isinstance(a, float)) and (
        _is_int_operand(b) or isinstance(b, float)
    ):
        return True
    return type(a) is type(b)


def _capture_scope(scope: Scope, ctx: EvalContext) -> bytes | None:
    """Capture scope as a content-addressed entity with kind-tagged bindings (v3.19b N1/N6).

    Each binding is **kind-tagged**: an entity value is stored in the content
    store and referenced by hash (``{kind:"entity", entity_hash}``); a
    record/primitive value is inlined (``{kind:"value", value}``). This is
    reference-don't-duplicate (N1) — the entity lives once in the content store
    and the scope refs it — and it fixes the v3.18 round-trip that flattened a
    captured entity to its envelope shape (the F9-B root). Entity-ness is
    carried by Python type (``Entity``), never inferred from dict shape.

    The scope entity MUST be written to the content store before the closure is
    returned, and is ``mark_encountered``'d so a just-captured scope resolves
    within the same evaluation (N6; the cross-peer path is §2.3 N7, deferred).
    """
    if scope.is_empty():
        return None

    bindings: dict[str, Any] = {}
    for name, value in scope.bindings.items():
        if isinstance(value, Entity):
            # Storing a binding into the content store is a crossing — materialize
            # to bare first (α), so a constructed entity captured into a closure
            # is stored in its bare, deterministic, CBOR-safe form (identity for
            # an already-bare entity).
            ent_hash = ctx.content_store.put(_materialize_bare(value, ctx))
            ctx.mark_encountered(ent_hash)
            bindings[name] = {"kind": "entity", "entity_hash": ent_hash}
        elif isinstance(value, list):
            # An ARRAY-valued binding is the same crossing as the branch above,
            # and it was unencodable until v3.24 gave the evaluator arrays of
            # entities to produce. `let g = group-by(…) in map(g, fn)` captures
            # `g` — a list of `system/compute/group` entities — and the encoder
            # died on the live `Entity` inside the `kind:"value"` binding,
            # killing the handler task and answering nothing.
            #
            # So the α rule the `Entity` branch already states applies
            # element-wise: an entity ELEMENT is stored and referenced by its
            # bare `system/hash`, exactly as an entity FIELD is. Read-back then
            # follows §2.3's rule for a materialized bare value — `index`
            # yields the hash, and the caller follows it with
            # `compute/lookup/hash` — rather than auto-resolving by shape,
            # which N3 forbids.
            bindings[name] = {"kind": "value", "value": _materialize_bare(value, ctx)}
        else:
            bindings[name] = {"kind": "value", "value": value}

    scope_entity = Entity(type="compute/scope", data={"bindings": bindings})
    h = ctx.content_store.put(scope_entity)
    ctx.mark_encountered(h)
    return h


def _load_scope(env_hash: bytes | None, ctx: EvalContext) -> Scope | dict[str, Any]:
    """Load scope from the content store, decoding kind-tagged bindings (v3.19b N4/N6/N8).

    Content-store-direct (N6): the scope entity and each ``kind:"entity"``
    binding ride the closure's authorization (N4) — resolved straight from the
    content store / envelope ``included``, bypassing the ``is_compute_type`` /
    sealed-set tiers (a binding may be an app type like ``app/user``). A binding
    hash that resolves nowhere yields ``compute/error{scope_unreachable}`` (N8)
    — an error *value* (status 200), not a transport failure. An entity binding
    is restored as its ``Entity`` so navigation reads it by kind, never by shape.
    """
    if env_hash is None:
        return Scope()
    env = ctx.content_store.get(env_hash)
    if env is None:
        return make_error(ERR_NOT_FOUND, "Closure scope entity not found")
    ctx.mark_encountered(env_hash)
    env_data = _entity_data(env)
    if env_data is None:
        return Scope()

    resolved: dict[str, Any] = {}
    for name, binding in (env_data.get("bindings") or {}).items():
        if isinstance(binding, dict) and "kind" in binding:
            kind = binding.get("kind")
            if kind == "value":
                resolved[name] = binding.get("value")
            elif kind == "entity":
                bh = binding.get("entity_hash")
                # N4: ride the closure's authorization — content-store-direct,
                # not gated by is_compute_type / the sealed set.
                ent = ctx.content_store.get(bh) if isinstance(bh, bytes) else None
                if ent is None and ctx.included:
                    ent = ctx.included.get(bh)
                if ent is None:
                    # N8: unresolvable binding → error-as-value at apply time.
                    return make_error(
                        ERR_SCOPE_UNREACHABLE,
                        f"Scope binding '{name}' references an unresolvable entity",
                    )
                ctx.mark_encountered(bh)
                resolved[name] = ent
            else:
                return make_error(
                    ERR_INVALID_EXPRESSION,
                    f"Scope binding '{name}' has unknown kind: {kind!r}",
                )
        else:
            # Pre-v3.19b / non-kind-tagged binding: treat as a raw value (compat).
            resolved[name] = binding

    return Scope(resolved)


# ---------------------------------------------------------------------------
# Budget initialization (§5.2)
# ---------------------------------------------------------------------------

def init_budget(
    params: dict[str, Any] | None,
    capability: dict[str, Any],
    bounds_budget: int | None = None,
) -> Budget:
    """Initialize budget from params, capability constraints, and bounds."""
    request_budget = params.get("budget") if params else None
    if request_budget is None:
        request_budget = float("inf")

    if bounds_budget is None:
        bounds_budget = DEFAULT_MAX_OPS

    compute_constraints = capability.get("constraints", {}).get("system/compute", {})
    ops_limit = compute_constraints.get("max_compute_operations", DEFAULT_MAX_OPS)
    depth_limit = compute_constraints.get("max_compute_depth", DEFAULT_MAX_DEPTH)

    return Budget(
        operations=min(request_budget, bounds_budget, ops_limit),
        depth=depth_limit,
    )


# ---------------------------------------------------------------------------
# Dependency Index (§7.1)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DepEntry:
    """A dependency index entry mapping a tree path to a subgraph."""
    expression_uri: str
    subgraph_path: str


class DependencyIndex:
    """Maps tree paths to subgraph entries for reactive re-evaluation.

    Uses exact-match only (§7.1) — no prefix or subtree matching.
    """

    def __init__(self) -> None:
        self._index: dict[str, set[DepEntry]] = {}

    def add(self, path: str, entry: DepEntry) -> None:
        if path not in self._index:
            self._index[path] = set()
        self._index[path].add(entry)

    def match(self, path: str) -> list[DepEntry]:
        entries = self._index.get(path)
        if entries is None:
            return []
        return list(entries)

    def remove_subgraph(self, subgraph_path: str) -> None:
        empty_keys = []
        for path, entries in self._index.items():
            to_remove = {e for e in entries if e.subgraph_path == subgraph_path}
            entries -= to_remove
            if not entries:
                empty_keys.append(path)
        for k in empty_keys:
            del self._index[k]

    def clear(self) -> None:
        self._index.clear()

    def __len__(self) -> int:
        return sum(len(v) for v in self._index.values())


# ---------------------------------------------------------------------------
# Subgraph audit walker (§3.3)
# ---------------------------------------------------------------------------

@dataclass
class AuditResult:
    """Result of auditing a subgraph for impure operations."""
    read_paths: list[str] = field(default_factory=list)
    # Each handler target is {path, operation, resource} where `resource` is
    # either a {targets, exclude} struct (static literal) or None (dynamic,
    # resolved at runtime per the dual-check in §4.1).
    handler_targets: list[dict[str, Any]] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    data_hashes: list[dict[str, Any]] = field(default_factory=list)
    # Static structural errors discovered during the walk (e.g., F5
    # install-time enforcement: compute/apply with capability but no
    # resource). The install handler MUST reject the install if non-empty.
    static_errors: list[dict[str, str]] = field(default_factory=list)
    # CP1 (PROPOSAL-COHERENT-CAPABILITY-AUTHORITY, EXTENSION-COMPUTE v3.11):
    # static-literal `compute/apply.capability` references. Each entry is
    # {path, operation, capability_entity} where capability_entity is the
    # resolved capability/token entity. The install handler runs an R1
    # chain-root check on each, BEFORE the F3 resource-coverage check.
    # Dynamic capabilities (non-literal expressions) defer to runtime
    # via the F2 dual-check.
    literal_capabilities: list[dict[str, Any]] = field(default_factory=list)


def audit_subgraph(
    expression: Entity, ctx: EvalContext, root_path: str = "",
) -> AuditResult:
    """Walk expression graph and collect impure operations (§3.3)."""
    result = AuditResult()
    visited: set[bytes] = set()
    _audit_walk(expression, result, visited, ctx, root_path)
    return result


def _audit_walk(
    entity: Entity,
    result: AuditResult,
    visited: set[bytes],
    ctx: EvalContext,
    root_path: str = "",
) -> None:
    h = entity.compute_hash()
    if h in visited:
        return
    visited.add(h)

    t = entity.type

    if t == "compute/lookup/tree":
        path = entity.data.get("path", "")
        if entity.data.get("relative") is True and root_path:
            path = _clean_path(root_path + "/" + path)
        result.read_paths.append(path)
        return

    if t == "compute/lookup/hash":
        hint_path = entity.data.get("path")
        if entity.data.get("relative") is True and root_path and hint_path:
            hint_path = _clean_path(root_path + "/" + hint_path)
        result.data_hashes.append({
            "hash": entity.data.get("hash"),
            "path": hint_path,
        })
        return

    if t == "compute/apply" and entity.data.get("path") is not None:
        apply_path = entity.data["path"]

        if apply_path.startswith(BUILTIN_PREFIX):
            # §2.1 Q23 install-time `[MUST]` — ruled 2026-08-16 (arch
            # `67708b1`, ROUTING-2026-08-16-j) on go spec-issue 2026-08-16-e.
            # A builtin-path apply carrying `capability`/`resource` is
            # `invalid_expression` (see the eval-time rejection in
            # `_eval_apply_handler`), and where `path` is a **static literal**
            # under the builtin prefix — which it is here, the walker reads it
            # straight off the entity — the whole condition is decidable
            # without evaluating anything. So the audit MUST reject it, on the
            # same conservative-static/dynamic-runtime split §2.1 already
            # applies to `store` builtin paths. A dynamic path is not knowable
            # until evaluation and the runtime rejection is its whole
            # enforcement.
            #
            # SHAPE check: `path` plus the PRESENCE of the fields, never their
            # values — nothing is resolved here, deliberately.
            #
            # It runs BEFORE the write_path collection below and subsumes F5 on
            # this branch, exactly as the eval-time rejection subsumes F5 at
            # runtime: capability-only was the one shape F5 would have caught,
            # while capability+resource and resource-only installed clean —
            # the gap the ruling closes. An audit that fail-fasts F5 while
            # installing this shape clean is internally inconsistent.
            if (
                entity.data.get("capability") is not None
                or entity.data.get("resource") is not None
            ):
                result.static_errors.append({
                    "code": ERR_INVALID_EXPRESSION,
                    "message": (
                        "compute/apply on a builtin path MUST NOT carry "
                        "capability or resource"
                    ),
                })
                return

            # SA-11 (§3.3): pure builtins (map/filter/fold + the inline-equivalent
            # arithmetic/compare/logic/field/construct) make no tree or capability
            # access, so they need NO install-time handler-target authorization.
            # Only `store` is gated — via its literal write_path.
            if apply_path == BUILTIN_STORE:
                args = entity.data.get("args") or {}
                path_hash = args.get("path")
                if is_hash_ref(path_hash):
                    path_expr = ctx.resolve(path_hash)
                    if path_expr is not None and path_expr.type == "compute/literal":
                        literal_path = path_expr.data.get("value")
                        if isinstance(literal_path, str):
                            result.write_paths.append(literal_path)
            # (fall through to the generic hash-reference recursion below)
        else:
            cap_ref = entity.data.get("capability")
            res_ref = entity.data.get("resource")

            # F5 install-time enforcement (PROPOSAL-COMPUTE-APPLY-RESOURCE-CEILING):
            # `capability` without `resource` is a static structural error.
            # Statically checkable (field presence, not resolved value).
            if cap_ref is not None and res_ref is None:
                result.static_errors.append({
                    "code": ERR_INVALID_EXPRESSION,
                    "message": (
                        "compute/apply with capability field MUST also have "
                        "resource field"
                    ),
                })

            # F3 — collect static literal resource so the install-time
            # check_grant_covers can use full resolution. Dynamic resources
            # (non-literal expressions) defer to runtime per §4.1.
            static_resource: dict[str, Any] | None = None
            if is_hash_ref(res_ref):
                res_expr = ctx.resolve(res_ref)
                if res_expr is not None and res_expr.type == "compute/literal":
                    lit_value = res_expr.data.get("value")
                    # Per the proposal: value is a system/protocol/resource-target
                    # struct ({targets: [...], exclude: [...]}). Either a bare
                    # struct or a typed entity dict with the same data shape.
                    if isinstance(lit_value, dict):
                        if "type" in lit_value and "data" in lit_value:
                            struct = lit_value.get("data", {})
                        else:
                            struct = lit_value
                        if isinstance(struct, dict) and isinstance(struct.get("targets"), list):
                            static_resource = struct

            # CP1 — collect static literal capability so the install handler
            # can run an R1 chain-root check (installer must be in the cap's
            # authority chain). Dynamic capabilities defer to the runtime F2
            # dual-check. The literal value is a hash of the capability entity.
            if is_hash_ref(cap_ref):
                cap_expr = ctx.resolve(cap_ref)
                if cap_expr is not None and cap_expr.type == "compute/literal":
                    cap_value = cap_expr.data.get("value")
                    cap_entity_hash: bytes | None = None
                    if is_hash_ref(cap_value):
                        cap_entity_hash = cap_value
                    if cap_entity_hash is not None:
                        cap_entity = ctx.resolve(cap_entity_hash)
                        if cap_entity is not None:
                            result.literal_capabilities.append({
                                "path": apply_path,
                                "operation": entity.data.get("operation", ""),
                                "capability_entity": cap_entity,
                            })

            result.handler_targets.append({
                "path": apply_path,
                "operation": entity.data.get("operation", ""),
                "resource": static_resource,
            })

    # Recursively walk hash references in entity data — the SAME traversal
    # `_walk_deps` uses (`_referenced_entities`), because this walker decides
    # which `compute/apply` gets its install-time capability/resource check and
    # a reference it fails to enter is a check that never runs.
    for referenced in _referenced_entities(entity, ctx):
        _audit_walk(referenced, result, visited, ctx, root_path)

    # Walk closure body and captured environment
    if t == "compute/closure":
        env_hash = entity.data.get("env")
        if isinstance(env_hash, bytes):
            env = ctx.resolve(env_hash)
            if env is not None:
                _audit_walk(env, result, visited, ctx, root_path)
        body_hash = entity.data.get("body")
        if isinstance(body_hash, bytes):
            body = ctx.resolve(body_hash)
            if body is not None:
                _audit_walk(body, result, visited, ctx, root_path)


def walk_tree_lookups(
    expression: Entity, ctx: EvalContext, root_path: str = "",
) -> list[str]:
    """Collect tree-read dependencies from expression graph (§7.1)."""
    deps: list[str] = []
    visited: set[bytes] = set()
    _walk_deps(expression, deps, visited, ctx, root_path)
    return deps


def _walk_deps(
    entity: Entity,
    deps: list[str],
    visited: set[bytes],
    ctx: EvalContext,
    root_path: str = "",
) -> None:
    h = entity.compute_hash()
    if h in visited:
        return
    visited.add(h)

    if entity.type == "compute/lookup/tree":
        path = entity.data.get("path", "")
        if entity.data.get("relative") is True and root_path:
            path = _clean_path(root_path + "/" + path)
        deps.append(path)
        return

    for referenced in _referenced_entities(entity, ctx):
        _walk_deps(referenced, deps, visited, ctx, root_path)


def _hash_refs_in(value: Any) -> Iterator[bytes]:
    """Every `system/hash` reference inside ``value``, **at any depth**.

    §7.1's `walk` `[MUST, D8 / RULED 2026-08-21 §10.3]`. The normative property
    is the prose one — *"all `compute/lookup/tree` paths reachable in the
    expression graph are registered"* — and it is measured against **that
    sentence, never against §7.1's pseudocode**, which recurses on scalar
    `system/hash` field values alone and therefore enters no container. On the
    grammar that exists, entering no container means registering no dependency
    inside any function argument (`compute/apply.args` is `{map_of:
    system/hash}`) or any `let` binding (`compute/let.bindings` is an array of
    `{name, value: system/hash}`) — most of every non-trivial expression,
    including §3.5's own *"Sequencing side effects"* worked example.

    **This function is recursive by rule, and the previous one was correct by
    enumeration** — a scalar; a list of hashes; a list of dicts keyed on the
    literal field name ``"value"``; a dict, one level. Those cases happen to
    cover today's grammar exactly. One args type nesting a reference a level
    deeper, or a binding field not called ``value``, and it silently registered
    **nothing** — and the failure is a reactive expression that evaluates
    correctly once and is never woken again, which **no boundary-hash vector
    can see** (§6.2: dependency registration produces no boundary, which is how
    three walkers of three different strengths passed everything).

    Over-registration is permitted and under-registration is not: §7.1 calls the
    walk *conservative* and lists paths behind untaken `compute/if` branches as
    registered on purpose. So this descends into a container without asking what
    the container means.
    """
    if is_hash_ref(value):
        yield value
        return
    if isinstance(value, (bytes, bytearray, str)):
        # A byte string that is not a reference is a leaf, not a container of
        # its own bytes — and `str` is iterable, which is the trap.
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from _hash_refs_in(item)
        return
    if isinstance(value, dict):
        for sub_value in value.values():
            yield from _hash_refs_in(sub_value)


def _referenced_entities(entity: Entity, ctx: EvalContext) -> Iterator[Entity]:
    """Every resolvable entity referenced from ``entity.data``, at any depth.

    The **one** traversal shared by both §7.1 walkers — `_walk_deps` (reactive
    dependency registration) and `_audit_walk` (install-time static audit).
    They were two hand-rolled copies of the same enumeration, so the D8 defect
    had two sites and only one of them was measured: at `_audit_walk` a
    reference nested past the enumerated shapes silently skips a
    `compute/apply`, i.e. an install-time capability/resource check that never
    runs. Keep it one function — a traversal that decides what gets registered
    and what gets authorized is not a place for two implementations of one
    concept.
    """
    for value in entity.data.values():
        for ref in _hash_refs_in(value):
            referenced = ctx.resolve(ref)
            if referenced is not None:
                yield referenced


# ---------------------------------------------------------------------------
# Deterministic subgraph ID (§3.3)
# ---------------------------------------------------------------------------

def deterministic_id(root_path: str) -> str:
    """Produce a stable path-safe ID from root path.

    base32_lower_no_padding(sha256(utf8_bytes(root_path))) → 52 chars.
    """
    digest = hashlib.sha256(root_path.encode("utf-8")).digest()
    return base64.b32encode(digest).decode("ascii").lower().rstrip("=")


# ---------------------------------------------------------------------------
# Handler dispatch bridge (sync evaluator → async handler context)
# ---------------------------------------------------------------------------

def _make_sync_dispatch(
    handler_ctx: HandlerContext,
    capability: dict[str, Any],
) -> Callable[..., Any]:
    """Create sync dispatch wrapper for compute/apply handler mode.

    Bridges the sync evaluator to the async handler dispatch by running
    the async call in a worker thread with its own event loop. Forwards
    the original external caller's capability and identity (V7 §6.8
    propagation) so history records correct attribution on
    handler-managed writes performed by the sub-dispatch chain.
    """
    propagated_caller_cap = handler_ctx.caller_capability
    propagated_author_peer_id = handler_ctx.remote_peer_id
    propagated_author_identity_hash = handler_ctx.remote_identity_hash

    def sync_dispatch(
        path: str,
        operation: str,
        resolved_args: dict[str, Any],
        eval_ctx: EvalContext,
        dispatch_cap: dict[str, Any] | None = None,
        resource_targets: list[str] | None = None,
        resource_exclude: list[str] | None = None,
    ) -> Any:
        cap_to_use = dispatch_cap if dispatch_cap is not None else capability
        # F4 — the dispatched EXECUTE carries the resolved resource targets
        # from compute/apply.resource. Without this, the dispatch-chain side
        # of the AND has no resource and the resource-scope check is skipped.
        targets_for_dispatch = (
            list(resource_targets) if resource_targets is not None else None
        )

        async def _do_dispatch() -> Any:
            return await handler_ctx.execute_with_capability(
                path, operation, resolved_args,
                capability_data=cap_to_use,
                resource_targets=targets_for_dispatch,
                propagated_caller_capability=propagated_caller_cap,
                propagated_author_peer_id=propagated_author_peer_id,
                propagated_author_identity_hash=propagated_author_identity_hash,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, _do_dispatch())
            exec_result = future.result(timeout=30)

        if not exec_result.ok:
            err_msg = exec_result.error or f"status {exec_result.status}"
            return make_error(ERR_NOT_FOUND, f"Handler dispatch failed: {err_msg}")
        return exec_result.result

    return sync_dispatch


# ---------------------------------------------------------------------------
# Entity-native dispatch helpers (V7 §6.6)
# ---------------------------------------------------------------------------

def _entity_native_error(status: int, code: str, message: str) -> dict[str, Any]:
    return {
        "status": status,
        "result": {"type": "compute/error", "data": {
            "code": code,
            "message": message,
        }},
    }


def _unwrap_entity_native_result(result: Any) -> dict[str, Any]:
    """Unwrap the evaluator result for V7 §6.6 entity-native dispatch.

    Per V7 §6.6 step 5:
      - compute/result   → extract `value` field, then re-apply the rules below
      - compute/error    → status 200 carrying the error entity (F10:
                            error-as-value; evaluation completed with an error
                            value, so it is returned, not raised)
      - bare primitive   → wrap as `{type: "primitive/any", data: <value>}`
                            (wire format requires typed entities in result)
      - entity           → return its dict shape unchanged
      - anything else    → return unchanged (lists, plain dicts; the wire-side
                            ``_as_entity`` shim normalizes these on egress)
    """
    # One shape for an error leaving compute, whichever crossing it leaves by
    # and whichever representation it arrived in (this path already handled
    # both; `error_to_wire` is now the single answer the other two share).
    if is_error(result):
        return {"status": 200, "result": error_to_wire(result)}

    if isinstance(result, dict) and result.get("type") == "compute/result":
        result = result.get("data", {}).get("value")
    elif isinstance(result, Entity) and result.type == "compute/result":
        result = result.data.get("value")

    # bool is a subclass of int in Python; covered by the int check.
    if isinstance(result, (bool, int, float, str)):
        return {
            "status": 200,
            "result": {"type": "primitive/any", "data": result},
        }
    if isinstance(result, Entity):
        return {"status": 200, "result": result.to_dict()}
    return {"status": 200, "result": result}


# ---------------------------------------------------------------------------
# Compute Handler (§3)
# ---------------------------------------------------------------------------

def _included_entities(handler_ctx: HandlerContext) -> dict[bytes, Entity]:
    """Build the resolution tier-1 map from the request envelope's ``included``
    (§4.2 — pre-authorized, always available during EXECUTE eval).

    ``handler_ctx.included`` is a hash → raw-entity-dict map preserved from the
    inbound envelope (peer.py::included=request_included). The evaluator's
    ``EvalContext.resolve`` expects hash → :class:`Entity`, so convert here,
    byte-faithfully: carry the validated wire hash via ``from_wire_dict`` (§1.8)
    and fall back to ``from_dict`` only for dicts without a ``content_hash``.
    Robust to a missing/non-dict attribute (e.g. a test mock) → empty map.
    """
    raw = getattr(handler_ctx, "included", None)
    if not isinstance(raw, dict):
        return {}
    out: dict[bytes, Entity] = {}
    for h, d in raw.items():
        if not isinstance(h, bytes) or not isinstance(d, dict):
            continue
        try:
            out[h] = Entity.from_wire_dict(d)[0]
        except Exception:
            try:
                out[h] = Entity.from_dict(d)
            except Exception:
                continue
    return out


async def _handle_eval(
    params_data: dict[str, Any],
    handler_ctx: HandlerContext,
    state: _ComputeState,
) -> dict[str, Any]:
    """Handle eval operation (§3.2).

    Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-COMPUTE-1): the expression
    path is read from ctx.resource.targets[0] — single target, URI-only.
    """
    targets = handler_ctx.resource_targets or []
    # §3.3's 400 row (0.8.2.18): ABSENT -> `path_required`, MORE THAN ONE ->
    # `ambiguous_resource`. Different inputs, different remedies; collapsing
    # them into `!= 1` is non-conformant on the absent case.
    if not targets:
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_PATH_REQUIRED,
                "message": "eval requires a resource target (the expression path)",
            }},
        }
    if len(targets) != 1:
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_AMBIGUOUS_RESOURCE,
                "message": "eval requires exactly one resource target (the expression path)",
            }},
        }
    expression_uri = targets[0]

    ep = handler_ctx.emit_pathway
    h = ep.entity_tree.get(expression_uri)
    if h is None:
        return {
            "status": 404,
            "result": {"type": "compute/error", "data": {
                "code": ERR_NOT_FOUND,
                "message": f"No entity at path: {expression_uri}",
            }},
        }

    expression = ep.content_store.get(h)
    if expression is None:
        return {
            "status": 404,
            "result": {"type": "compute/error", "data": {
                "code": ERR_NOT_FOUND,
                "message": f"No entity at path: {expression_uri}",
            }},
        }

    if not is_compute_expression(expression):
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_INVALID_EXPRESSION,
                "message": "Entity at path is not a compute expression",
            }},
        }

    capability = handler_ctx.caller_capability or {}
    bounds_budget = None
    if handler_ctx.bounds is not None:
        bounds_budget = getattr(handler_ctx.bounds, "budget", None)
    budget = init_budget(params_data, capability, bounds_budget)
    scope = Scope()

    allowances = capability.get("allowances", {})
    has_cs_access = bool(allowances.get("content_store_access"))

    dispatch_fn = None
    if handler_ctx._execute_dispatcher is not None:
        dispatch_fn = _make_sync_dispatch(handler_ctx, capability)

    eval_ctx = EvalContext(
        content_store=ep.content_store,
        entity_tree=ep.entity_tree,
        local_peer_id=handler_ctx.local_peer_id,
        capability=capability,
        caller_capability=handler_ctx.caller_capability,
        emit_pathway=ep,
        has_content_store_access=has_cs_access,
        included=_included_entities(handler_ctx),  # §4.2 tier 1
        subgraph_root=expression_uri,
        _execute_fn=dispatch_fn,
    )

    result = evaluate(expression, scope, budget, eval_ctx)
    # v3.19c α: bare at the compute→non-compute crossing. **Guarded on
    # is_error [v3.26]:** a top-level error-as-value leaves by its own door
    # below (F10 / the `result_path` write / the entity-native unwrap), and
    # since v3.26 `_materialize_bare` *raises* on a scalar error rather than
    # passing it through, so this order is load-bearing rather than cosmetic.
    if not is_error(result):
        result = _materialize_bare(result, eval_ctx)

    # F10 (PROPOSAL-COMPUTE-NAVIGATION-AND-ERROR-SURFACE): an evaluated
    # compute/error is a *value* (§1.5 — errors propagate like NaN). Evaluation
    # completed; its value is an error. Return it at status 200 with the
    # compute/error body so callers detect it via `result.type ==
    # "compute/error"` and error-as-value composes across nested apply. A 4xx
    # is reserved for failures of the dispatch itself — not-found, malformed,
    # not-a-compute-expression, ambiguous resource (all handled above).
    if is_error(result):
        # Wire form for BOTH representations — a stored `compute/error` literal
        # arrives here as an `Entity`, and returning it raw is what raised
        # CBOREncodeTypeError at the encoder and dropped the connection.
        return {"status": 200, "result": error_to_wire(result)}

    if isinstance(result, Entity):
        return {"status": 200, "result": result.to_dict()}

    if isinstance(result, dict) and "type" in result:
        return {"status": 200, "result": result}

    return {
        "status": 200,
        "result": {"type": "compute/result", "data": {
            "value": result,
            "expression": h,
        }},
    }


async def _handle_install(
    params_data: dict[str, Any],
    handler_ctx: HandlerContext,
    state: _ComputeState,
) -> dict[str, Any]:
    """Handle install operation (§3.3).

    Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-COMPUTE-2): the root
    expression path is read from ctx.resource.targets[0]. params retains
    only handler-write/options fields (result_path, budget).
    """
    targets = handler_ctx.resource_targets or []
    # §3.3's 400 row (0.8.2.18): ABSENT -> `path_required`, MORE THAN ONE ->
    # `ambiguous_resource`. Different inputs, different remedies; collapsing
    # them into `!= 1` is non-conformant on the absent case.
    if not targets:
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_PATH_REQUIRED,
                "message": "install requires a resource target (the root expression path)",
            }},
        }
    if len(targets) != 1:
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_AMBIGUOUS_RESOURCE,
                "message": "install requires exactly one resource target (the root expression path)",
            }},
        }
    root_path = targets[0]

    ep = handler_ctx.emit_pathway
    h = ep.entity_tree.get(root_path)
    if h is None:
        return {
            "status": 404,
            "result": {"type": "compute/error", "data": {
                "code": ERR_NOT_FOUND,
                "message": f"No expression at path: {root_path}",
            }},
        }

    expression = ep.content_store.get(h)
    if expression is None or not is_compute_expression(expression):
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_INVALID_EXPRESSION,
                "message": "Entity at path is not a compute expression",
            }},
        }

    capability = handler_ctx.caller_capability or {}
    eval_ctx = EvalContext(
        content_store=ep.content_store,
        entity_tree=ep.entity_tree,
        local_peer_id=handler_ctx.local_peer_id,
        capability=capability,
        emit_pathway=ep,
        has_content_store_access=True,
        included=_included_entities(handler_ctx),  # §4.2 tier 1 / §2.3 N7 closure transfer
    )

    # Phase 1: Audit (relative paths resolved against root_path)
    impure_ops = audit_subgraph(expression, eval_ctx, root_path)

    # Phase 1b: Reject any static structural errors collected during audit
    # (e.g., F5: compute/apply with capability but no resource).
    if impure_ops.static_errors:
        err = impure_ops.static_errors[0]
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": err},
        }

    # Phase 1c — CP1 (EXTENSION-COMPUTE §3.3) using the unified walker
    # from PROPOSAL-UNIFIED-CHAIN-WALK-PRIMITIVE §3.2. For each static-
    # literal `compute/apply.capability`, verify the installer's identity
    # is in the cap's authority chain. Runs BEFORE F3 resource-coverage —
    # cheaper and more fundamental; distinct error code lets callers tell
    # unauthorized embedding apart from scope mismatch.
    if impure_ops.literal_capabilities:
        from entity_core.capability.delegation import (
            ChainCollectStatus,
            check_creator_authority,
        )

        author_hash = handler_ctx.remote_identity_hash
        if author_hash is None:
            return {
                "status": 403,
                "result": {"type": "compute/error", "data": {
                    "code": "no_identity",
                    "message": "Installer identity not available for chain check",
                }},
            }

        def _chain_lookup(h: bytes) -> dict[str, Any] | None:
            ent = ep.content_store.get(h)
            return ent.to_dict() if ent is not None else None

        # Track unique chains to persist on success (avoid re-walking
        # for shared parents across multiple compute/apply nodes).
        chains_to_persist: list[list[dict[str, Any]]] = []
        for lit in impure_ops.literal_capabilities:
            cap_dict = lit["capability_entity"].to_dict()
            auth = check_creator_authority(cap_dict, author_hash, _chain_lookup)
            if auth.status != ChainCollectStatus.OK:
                return {
                    "status": 404,
                    "result": {"type": "compute/error", "data": {
                        "code": "chain_unreachable",
                        "message": (
                            "compute/apply.capability authority chain "
                            "incomplete in envelope and content store"
                        ),
                    }},
                }
            if not auth.found:
                return {
                    "status": 403,
                    "result": {"type": "compute/error", "data": {
                        "code": "embedded_cap_unauthorized",
                        "message": (
                            "Installer identity not in static "
                            "compute/apply.capability authority chain "
                            f"for {lit['path']}.{lit['operation']}"
                        ),
                    }},
                }
            chains_to_persist.append(auth.chain)

        # Persist embedded caps + chains so subsequent re-evaluations
        # can resolve them. Per §3.2, persistence runs only on found=True
        # — rejection paths above return before reaching this point.
        for chain_list in chains_to_persist:
            for chain_dict in chain_list:
                chain_entity = Entity.from_dict(chain_dict)
                if not ep.content_store.has(chain_entity.compute_hash()):
                    ep.put_content_only(chain_entity)

    # Phase 2: Verify capability
    _caller_frame = handler_ctx.caller_capability_granter_peer_id  # V7 §PR-8
    for read_path in impure_ops.read_paths:
        if not check_path_permission(
            capability, "get", read_path, handler_ctx.local_peer_id,
            granter_peer_id=_caller_frame,
        ):
            return {
                "status": 403,
                "result": {"type": "compute/error", "data": {
                    "code": ERR_PERMISSION_DENIED,
                    "message": f"Capability does not cover read: {read_path}",
                }},
            }

    for target in impure_ops.handler_targets:
        # F3 — when a static-literal resource is known, perform full-resolution
        # check_grant_covers (handler+operation+resource). Dynamic resources
        # defer to runtime per §4.1 (no regression for compute/apply calls
        # without a static resource).
        target_resource = target.get("resource")
        if isinstance(target_resource, dict):
            target_targets = target_resource.get("targets") or []
            target_exclude = target_resource.get("exclude")
            if target_targets and not check_resource_scope(
                capability, target["path"], target["operation"],
                list(target_targets),
                list(target_exclude) if target_exclude else None,
                handler_ctx.local_peer_id,
                granter_peer_id=_caller_frame,
            ):
                return {
                    "status": 403,
                    "result": {"type": "compute/error", "data": {
                        "code": ERR_PERMISSION_DENIED,
                        "message": (
                            f"Capability does not cover handler: "
                            f"{target['path']}.{target['operation']} "
                            f"on {list(target_targets)}"
                        ),
                    }},
                }
            continue

        # Dynamic resource (or no resource): keep current behavior — check
        # handler+operation coverage only, per proposal §3.3 "null resource
        # here keeps current behavior". The runtime dual-check (§4.1) is the
        # backstop for the resource dimension on dynamic cases.
        if not check_handler_scope(
            capability, target["path"], target["operation"],
            handler_ctx.local_peer_id,
        ):
            return {
                "status": 403,
                "result": {"type": "compute/error", "data": {
                    "code": ERR_PERMISSION_DENIED,
                    "message": f"Capability does not cover handler: {target['path']}.{target['operation']}",
                }},
            }

    result_path = params_data.get("result_path") or f"{root_path}/result"
    if not check_path_permission(
        capability, "put", result_path, handler_ctx.local_peer_id,
        granter_peer_id=_caller_frame,
    ):
        return {
            "status": 403,
            "result": {"type": "compute/error", "data": {
                "code": ERR_PERMISSION_DENIED,
                "message": f"Capability does not cover result write: {result_path}",
            }},
        }

    for wp in impure_ops.write_paths:
        if not check_path_permission(
            capability, "put", wp, handler_ctx.local_peer_id,
            granter_peer_id=_caller_frame,
        ):
            return {
                "status": 403,
                "result": {"type": "compute/error", "data": {
                    "code": ERR_PERMISSION_DENIED,
                    "message": f"Capability does not cover write: {wp}",
                }},
            }

    # Phase 2b: Validate compute/lookup/hash data references (D5)
    authorized_data_hashes: list[bytes] = []
    for entry in impure_ops.data_hashes:
        entry_hash = entry.get("hash")
        entry_path = entry.get("path")
        if not isinstance(entry_hash, bytes):
            continue
        if entry_path is not None:
            tree_h = ep.entity_tree.get(entry_path)
            if tree_h is None:
                return {
                    "status": 404,
                    "result": {"type": "compute/error", "data": {
                        "code": ERR_NOT_FOUND,
                        "message": f"No entity at hint path: {entry_path}",
                    }},
                }
            if tree_h != entry_hash:
                tree_entity = ep.content_store.get(tree_h)
                actual_hash = tree_entity.compute_hash() if tree_entity else None
                if actual_hash != entry_hash:
                    return {
                        "status": 400,
                        "result": {"type": "compute/error", "data": {
                            "code": "hash_mismatch",
                            "message": f"Entity at {entry_path} does not match referenced hash",
                        }},
                    }
            if not check_path_permission(
                capability, "get", entry_path, handler_ctx.local_peer_id,
                handler_pattern="system/tree",
                granter_peer_id=_caller_frame,
            ):
                return {
                    "status": 403,
                    "result": {"type": "compute/error", "data": {
                        "code": ERR_PERMISSION_DENIED,
                        "message": f"Caller grant does not cover tree GET at: {entry_path}",
                    }},
                }
            authorized_data_hashes.append(entry_hash)
        else:
            return {
                "status": 400,
                "result": {"type": "compute/error", "data": {
                    "code": "no_authorization_path",
                    "message": "compute/lookup/hash without path hint requires content_store_access",
                }},
            }

    # Phase 3: Create subgraph metadata
    subgraph_id = deterministic_id(root_path)
    subgraph_path = f"system/compute/processes/{subgraph_id}"

    cap_entity = Entity(type="system/capability", data=capability)
    cap_hash = ep.content_store.put(cap_entity)

    author_hash = None
    if handler_ctx.remote_peer_id:
        # V7 v7.65 §2: system/peer data = (public_key, key_type) only.
        # Derive pubkey from canonical identity-form peer_id (§4: Ed25519
        # canonical hash_type is 0x00). Post-§4 mandate every wire peer_id
        # is canonical, so derivation succeeds on conformant peers.
        from entity_core.crypto.identity import derive_peer_from_peer_id
        derived = derive_peer_from_peer_id(handler_ctx.remote_peer_id)
        if derived is not None:
            pkey, _key_type = derived
            # §4.5a item 1a — floor-pinned via the one constructor.
            from entity_core.protocol.auth import create_peer_entity

            author_entity = create_peer_entity(pkey, "ed25519")
            author_hash = ep.content_store.put(author_entity)

    from entity_core.storage.emit import EmitContext

    subgraph_entity = Entity(
        type="system/compute/subgraph",
        data={
            "root_expression_path": root_path,
            "root_expression": h,
            "installation_grant": cap_hash,
            "installed_by": author_hash,
            "result_path": result_path,
            "status": "active",
            "authorized_data_hashes": authorized_data_hashes,
        },
    )
    ep.emit(subgraph_path, subgraph_entity, EmitContext(source="handler"))

    # Phase 4: Register dependencies (relative paths resolved against root_path)
    tree_deps = walk_tree_lookups(expression, eval_ctx, root_path)
    dep_entry = DepEntry(expression_uri=root_path, subgraph_path=subgraph_path)
    for dep_path in tree_deps:
        state.dependency_index.add(
            ep.entity_tree.normalize_uri(dep_path), dep_entry,
        )

    return {
        "status": 200,
        "result": {
            "type": "system/compute/install-result",
            "data": {
                "subgraph_path": subgraph_path,
                "impure_operations": {
                    "read_paths": impure_ops.read_paths,
                    "handler_targets": impure_ops.handler_targets,
                    "write_paths": impure_ops.write_paths,
                },
                "result_path": result_path,
            },
        },
    }


async def _handle_uninstall(
    params_data: dict[str, Any],
    handler_ctx: HandlerContext,
    state: _ComputeState,
) -> dict[str, Any]:
    """Handle uninstall operation (§3.4).

    Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE (P-COMPUTE-3): the subgraph
    path is read from ctx.resource.targets[0]. The uninstall-request
    wrapper is eliminated; params is empty primitive/any.
    """
    targets = handler_ctx.resource_targets or []
    # §3.3's 400 row (0.8.2.18): ABSENT -> `path_required`, MORE THAN ONE ->
    # `ambiguous_resource`. Different inputs, different remedies; collapsing
    # them into `!= 1` is non-conformant on the absent case.
    if not targets:
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_PATH_REQUIRED,
                "message": "uninstall requires a resource target (the subgraph path)",
            }},
        }
    if len(targets) != 1:
        return {
            "status": 400,
            "result": {"type": "compute/error", "data": {
                "code": ERR_AMBIGUOUS_RESOURCE,
                "message": "uninstall requires exactly one resource target (the subgraph path)",
            }},
        }
    subgraph_path = targets[0]

    ep = handler_ctx.emit_pathway
    h = ep.entity_tree.get(subgraph_path)
    if h is None:
        return {
            "status": 404,
            "result": {"type": "compute/error", "data": {
                "code": ERR_NOT_FOUND,
                "message": f"No installed subgraph at path: {subgraph_path}",
            }},
        }

    subgraph = ep.content_store.get(h)
    if subgraph is None or subgraph.type != "system/compute/subgraph":
        return {
            "status": 404,
            "result": {"type": "compute/error", "data": {
                "code": ERR_NOT_FOUND,
                "message": f"No installed subgraph at path: {subgraph_path}",
            }},
        }

    state.dependency_index.remove_subgraph(
        ep.entity_tree.normalize_uri(subgraph_path),
    )
    ep.entity_tree.remove(subgraph_path)

    return {"status": 200, "result": {"type": "system/protocol/status", "data": {"status": "ok"}}}


# ---------------------------------------------------------------------------
# Reactive re-evaluation (§7.2)
# ---------------------------------------------------------------------------

def _re_evaluate(
    expression_uri: str,
    subgraph_path: str,
    state: _ComputeState,
    cascade_depth: int,
) -> None:
    """Re-evaluate an expression and write result if changed (§7.2)."""
    ep = state.emit_pathway
    if ep is None:
        return

    full_subgraph = ep.entity_tree.normalize_uri(subgraph_path)
    h = ep.entity_tree.get(full_subgraph)
    if h is None:
        state.dependency_index.remove_subgraph(full_subgraph)
        return

    subgraph = ep.content_store.get(h)
    if subgraph is None or subgraph.type != "system/compute/subgraph":
        state.dependency_index.remove_subgraph(full_subgraph)
        return

    # Check installation grant validity
    grant_hash = subgraph.data.get("installation_grant")
    if not isinstance(grant_hash, bytes):
        _freeze_subgraph(full_subgraph, expression_uri, subgraph,
                         ERR_INSTALLATION_GRANT_INVALID,
                         "Installation grant missing or invalid", state)
        return

    grant = ep.content_store.get(grant_hash)
    if grant is None:
        _freeze_subgraph(full_subgraph, expression_uri, subgraph,
                         ERR_INSTALLATION_GRANT_INVALID,
                         "Installation grant missing", state)
        return

    grant_data = grant.data if isinstance(grant, Entity) else grant.get("data", {})

    import time
    now_ms = int(time.time() * 1000)
    expires_at = grant_data.get("expires_at")
    if expires_at is not None and expires_at < now_ms:
        _freeze_subgraph(full_subgraph, expression_uri, subgraph,
                         ERR_INSTALLATION_GRANT_INVALID,
                         "Installation grant expired", state)
        return

    # Load expression
    expr_h = ep.entity_tree.get(expression_uri)
    if expr_h is None:
        state.dependency_index.remove_subgraph(full_subgraph)
        return

    expression = ep.content_store.get(expr_h)
    if expression is None or not is_compute_expression(expression):
        state.dependency_index.remove_subgraph(full_subgraph)
        return

    # Evaluate
    grant_allowances = grant_data.get("allowances", {})
    reactive_cs_access = bool(grant_allowances.get("content_store_access"))

    # Load sealed set from subgraph metadata (D5)
    sealed_hashes_raw = subgraph.data.get("authorized_data_hashes", [])
    sealed_hashes = {h for h in sealed_hashes_raw if isinstance(h, bytes)}

    re_eval_root = subgraph.data.get("root_expression_path", expression_uri)

    eval_ctx = EvalContext(
        content_store=ep.content_store,
        entity_tree=ep.entity_tree,
        local_peer_id=ep.entity_tree.local_peer_id,
        capability=grant_data,
        emit_pathway=ep,
        has_content_store_access=reactive_cs_access,
        authorized_data_hashes=sealed_hashes,
        subgraph_root=re_eval_root,
    )

    compute_constraints = grant_data.get("constraints", {}).get("system/compute", {})
    budget = Budget(
        operations=compute_constraints.get("max_compute_operations", DEFAULT_MAX_OPS),
        depth=compute_constraints.get("max_compute_depth", DEFAULT_MAX_DEPTH),
    )

    scope = Scope()
    result = evaluate(expression, scope, budget, eval_ctx)
    # v3.19c α: bare at the compute→non-compute crossing. **Guarded on
    # is_error [v3.26]:** a top-level error-as-value leaves by its own door
    # below (F10 / the `result_path` write / the entity-native unwrap), and
    # since v3.26 `_materialize_bare` *raises* on a scalar error rather than
    # passing it through, so this order is load-bearing rather than cosmetic.
    if not is_error(result):
        result = _materialize_bare(result, eval_ctx)

    from entity_core.storage.emit import EmitContext

    result_path = subgraph.data.get("result_path", f"{expression_uri}/result")

    if is_error(result):
        # §7.2: an error materializes where it is WRITTEN — this is the
        # `result_path` write, one of the two sites where that happens (SA-9
        # `store` is the other). `error_materialized` unwraps both
        # representations (the `Entity` form previously fell through as the
        # whole entity and became `data`, so compute_hash() hit the same encoder
        # failure as the eval return path) **and** strips to `code` alone: this
        # is a content-addressed write, and `message`/`at` are impl-private
        # prose that would fork the result hash between two conformant peers
        # writing the same error (§2.4).
        error_entity = error_materialized(result)
        error_hash = error_entity.compute_hash()
        old_error_hash = ep.entity_tree.get(result_path)
        if old_error_hash != error_hash:
            ep.emit(result_path, error_entity, EmitContext(source="handler"))
        return

    # Convergence check (§7.2)
    if isinstance(result, Entity):
        result_entity = result
    elif isinstance(result, dict) and "type" in result:
        result_entity = Entity(type=result["type"], data=result.get("data", {}))
    else:
        result_entity = Entity(
            type="compute/result",
            data={"value": result, "expression": expr_h},
        )

    new_hash = result_entity.compute_hash()
    old_hash = ep.entity_tree.get(result_path)

    if old_hash == new_hash:
        return  # Converged — no write needed

    ep.emit(result_path, result_entity, EmitContext(source="handler"))


def _freeze_subgraph(
    subgraph_path: str,
    expression_uri: str,
    subgraph: Entity,
    error_code: str,
    error_message: str,
    state: _ComputeState,
) -> None:
    """Freeze a subgraph by writing error and updating status."""
    ep = state.emit_pathway
    if ep is None:
        return

    from entity_core.storage.emit import EmitContext

    result_path = subgraph.data.get("result_path", f"{expression_uri}/result")
    # §2.4: the frozen-subgraph error goes to the `result_path` — a materialized
    # write, so code-only. `message` and `at` (the expression URI, which is
    # peer-local) are diagnostics; carrying them here would give two peers
    # freezing on the same cause two different result hashes.
    error_entity = error_materialized(
        {"type": "compute/error", "data": {
            "code": error_code, "message": error_message, "at": expression_uri,
        }},
    )
    ep.emit(result_path, error_entity, EmitContext(source="handler"))

    frozen_subgraph = Entity(
        type="system/compute/subgraph",
        data={**subgraph.data, "status": "frozen"},
    )
    ep.emit(subgraph_path, frozen_subgraph, EmitContext(source="handler"))


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

class _ComputeState:
    """Holds compute extension runtime state."""

    def __init__(self) -> None:
        self.dependency_index = DependencyIndex()
        self.emit_pathway: EmitPathway | None = None
        self.local_peer_id: str = ""

    def rebuild(self, entity_tree: EntityTree, content_store: ContentStore) -> None:
        """Rebuild dependency index from existing subgraph metadata (§7.1)."""
        self.dependency_index.clear()
        prefix = entity_tree.normalize_uri("system/compute/processes")

        for uri, h in entity_tree.all_bindings():
            if not uri.startswith(prefix):
                continue
            entity = content_store.get(h)
            if entity is None or entity.type != "system/compute/subgraph":
                continue
            if entity.data.get("status") != "active":
                continue

            root_path = entity.data.get("root_expression_path", "")
            expr_h = entity_tree.get(root_path)
            if expr_h is None:
                continue
            expression = content_store.get(expr_h)
            if expression is None or not is_compute_expression(expression):
                continue

            eval_ctx = EvalContext(
                content_store=content_store,
                entity_tree=entity_tree,
                local_peer_id=entity_tree.local_peer_id,
                capability={},
                has_content_store_access=True,
            )

            tree_deps = walk_tree_lookups(expression, eval_ctx, root_path)
            dep_entry = DepEntry(expression_uri=root_path, subgraph_path=uri)
            for dep_path in tree_deps:
                self.dependency_index.add(
                    entity_tree.normalize_uri(dep_path), dep_entry,
                )


# ---------------------------------------------------------------------------
# InternalHook for reactive mode (§7.2)
# ---------------------------------------------------------------------------

class _ComputeHook:
    """Synchronous hook that triggers reactive re-evaluation on tree changes."""

    def __init__(self, state: _ComputeState) -> None:
        self._state = state

    def on_change_sync(self, event: ChangeEvent) -> int | None:
        """Check dependency index and re-evaluate affected subgraphs."""
        entries = self._state.dependency_index.match(event.uri)
        if not entries:
            return None

        for entry in entries:
            ep = self._state.emit_pathway
            if ep is None:
                continue

            # Check subgraph status
            sh = ep.entity_tree.get(entry.subgraph_path)
            if sh is None:
                continue
            subgraph = ep.content_store.get(sh)
            if subgraph is None:
                continue
            if subgraph.data.get("status") == "frozen":
                continue

            # Check cascade depth (§7.3)
            cascade_depth = event.cascade_depth
            if cascade_depth >= MAX_CASCADE_DEPTH:
                _freeze_subgraph(
                    entry.subgraph_path,
                    entry.expression_uri,
                    subgraph,
                    ERR_CASCADE_LIMIT,
                    "Cascade depth exceeded during reactive re-evaluation",
                    self._state,
                )
                continue

            _re_evaluate(
                entry.expression_uri,
                entry.subgraph_path,
                self._state,
                cascade_depth,
            )

        return None


# ---------------------------------------------------------------------------
# Type registration
# ---------------------------------------------------------------------------

_COMPUTE_TYPE_DEFS: list[dict[str, Any]] = [
    {"name": "compute/literal", "description": "Literal value", "fields": {
        "value": {"type_ref": "primitive/any"},
    }},
    {"name": "compute/lookup/scope", "description": "Scope binding lookup", "fields": {
        "name": {"type_ref": "primitive/string"},
    }},
    {"name": "compute/lookup/tree", "description": "Tree path lookup", "fields": {
        "path": {"type_ref": "system/tree/path"},
        "relative": {"type_ref": "primitive/bool", "optional": True},
    }},
    {"name": "compute/lookup/hash", "description": "Content hash lookup", "fields": {
        "hash": {"type_ref": "system/hash"},
        "path": {"type_ref": "system/tree/path", "optional": True},
        "relative": {"type_ref": "primitive/bool", "optional": True},
    }},
    {"name": "compute/apply", "description": "Handler or closure application", "fields": {
        "path": {"type_ref": "system/tree/path", "optional": True},
        "operation": {"type_ref": "primitive/string", "optional": True},
        "resource": {"type_ref": "system/hash", "optional": True},
        "fn": {"type_ref": "system/hash", "optional": True},
        "args": {"map_of": {"type_ref": "system/hash"}, "optional": True},
        "capability": {"type_ref": "system/hash", "optional": True},
    }},
    {"name": "compute/if", "description": "Conditional evaluation", "fields": {
        "condition": {"type_ref": "system/hash"},
        "then": {"type_ref": "system/hash"},
        "else": {"type_ref": "system/hash", "optional": True},
    }},
    {"name": "compute/let", "description": "Scoped bindings", "fields": {
        "bindings": {"array_of": {"type_ref": "primitive/any"}},
        "body": {"type_ref": "system/hash"},
    }},
    {"name": "compute/lambda", "description": "Function definition", "fields": {
        "params": {"array_of": {"type_ref": "primitive/string"}},
        "body": {"type_ref": "system/hash"},
    }},
    {"name": "compute/arithmetic", "description": "Arithmetic operation", "fields": {
        "op": {"type_ref": "primitive/string"},
        "left": {"type_ref": "system/hash"},
        "right": {"type_ref": "system/hash"},
    }},
    {"name": "compute/compare", "description": "Comparison operation", "fields": {
        "op": {"type_ref": "primitive/string"},
        "left": {"type_ref": "system/hash"},
        "right": {"type_ref": "system/hash"},
    }},
    {"name": "compute/logic", "description": "Logic operation", "fields": {
        "op": {"type_ref": "primitive/string"},
        "left": {"type_ref": "system/hash"},
        "right": {"type_ref": "system/hash", "optional": True},
    }},
    {"name": "compute/field", "description": "Field extraction", "fields": {
        "name": {"type_ref": "primitive/string"},
        "entity": {"type_ref": "system/hash"},
    }},
    {"name": "compute/construct", "description": "Entity construction", "fields": {
        "entity_type": {"type_ref": "system/type/name"},
        "fields": {"map_of": {"type_ref": "system/hash"}},
    }},
    {"name": "compute/index", "description": "Array index", "fields": {
        "array": {"type_ref": "system/hash"},
        "index": {"type_ref": "system/hash"},
    }},
    {"name": "compute/length", "description": "Array length", "fields": {
        "array": {"type_ref": "system/hash"},
    }},
    {"name": "compute/numeric-cast", "description": "Intra-numeric conversion", "fields": {
        "value": {"type_ref": "system/hash"},
        "to_type": {"type_ref": "system/type/name"},
    }},
    {"name": "compute/closure", "description": "Closure value", "fields": {
        "params": {"array_of": {"type_ref": "primitive/string"}},
        "body": {"type_ref": "system/hash"},
        "env": {"type_ref": "system/hash", "optional": True},
    }},
    # v3.19b N1/N2: a scope binding is kind-tagged — {kind:"entity", entity_hash}
    # | {kind:"value", value}. Modeled here with the union members as optional
    # fields (the type registry has no native sum type); exactly one of
    # entity_hash/value is present per `kind`. Declared BEFORE compute/scope
    # (which references it in its map_of) to match the cross-impl canonical
    # dependency order — referenced type before referencer. (Python's registry
    # emits each type def independently, so this order is cosmetic here, not
    # load-bearing as it was in core-go's typed registry.)
    {"name": "system/compute/scope-binding", "description": "Kind-tagged scope binding (v3.19b)", "fields": {
        "kind": {"type_ref": "primitive/string"},
        "entity_hash": {"type_ref": "system/hash", "optional": True},
        "value": {"type_ref": "primitive/any", "optional": True},
    }},
    {"name": "compute/scope", "description": "Captured scope (v3.19b: kind-tagged bindings)", "fields": {
        "bindings": {"map_of": {"type_ref": "system/compute/scope-binding"}},
    }},
    {"name": "compute/result", "description": "Evaluation result", "fields": {
        "value": {"type_ref": "primitive/any"},
        "expression": {"type_ref": "system/hash"},
    }},
    {"name": "compute/error", "description": "Evaluation error", "fields": {
        "code": {"type_ref": "primitive/string"},
        "message": {"type_ref": "primitive/string"},
        "at": {"type_ref": "primitive/string", "optional": True},
        "expression": {"type_ref": "system/hash", "optional": True},
    }},
    {"name": "system/compute/subgraph", "description": "Installed subgraph metadata", "fields": {
        "root_expression_path": {"type_ref": "system/tree/path"},
        "root_expression": {"type_ref": "system/hash"},
        "installation_grant": {"type_ref": "system/hash"},
        "installed_by": {"type_ref": "system/hash"},
        "result_path": {"type_ref": "system/tree/path"},
        "status": {"type_ref": "primitive/string"},
        # D5 sealed-set tier: hashes the installed subgraph is authorized
        # to read beyond compute-typed entities (per §4.2 v3.7 D5). Surfaces
        # the runtime concept already in _validate_compute_resolvable's
        # authorized_data_hashes parameter.
        "authorized_data_hashes": {
            "array_of": {"type_ref": "system/hash"},
            "optional": True,
        },
    }},
    # Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-COMPUTE-2: root expression
    # path moves to ctx.resource; install-request retains only handler-write
    # fields (result_path, budget).
    {"name": "system/compute/install-request", "description": "Install request", "fields": {
        "result_path": {"type_ref": "system/tree/path", "optional": True},
    }},
    {"name": "system/compute/install-result", "description": "Install result", "fields": {
        "subgraph_path": {"type_ref": "system/tree/path"},
        "impure_operations": {"type_ref": "primitive/any"},
        "result_path": {"type_ref": "system/tree/path"},
    }},
    # Args types for the collection + store builtins (EXTENSION-COMPUTE §3.5,
    # N.2). These are pinned in the spec — not implementation-owned — because a
    # transferable IR requires every peer to agree on their shape; the
    # override-prohibition determinism guarantee extends to them.
    {"name": "system/compute/map-args", "description": "Args for compute map builtin", "fields": {
        "collection": {"type_ref": "system/hash"},
        "fn": {"type_ref": "system/hash"},
    }},
    {"name": "system/compute/filter-args", "description": "Args for compute filter builtin", "fields": {
        "collection": {"type_ref": "system/hash"},
        "fn": {"type_ref": "system/hash"},  # F11: unified with map/fold (was `predicate`)
    }},
    {"name": "system/compute/fold-args", "description": "Args for compute fold builtin", "fields": {
        "collection": {"type_ref": "system/hash"},
        "fn": {"type_ref": "system/hash"},
        "initial": {"type_ref": "system/hash"},
    }},
    {"name": "system/compute/store-args", "description": "Args for compute store builtin", "fields": {
        "path": {"type_ref": "system/tree/path"},
        "value": {"type_ref": "system/hash"},
    }},
    # The v3.24 collection primitives' args types — pinned in the spec on the
    # same reasoning as map/filter/fold above (a transferable IR requires every
    # peer to agree on their shape).
    {"name": "system/compute/range-args", "description": "Args for compute range builtin", "fields": {
        "n": {"type_ref": "system/hash"},  # non-negative integer expression
    }},
    {"name": "system/compute/group-by-args", "description": "Args for compute group-by builtin", "fields": {
        "collection": {"type_ref": "system/hash"},
        "fn": {"type_ref": "system/hash"},  # unary closure (element → key)
    }},
    # `collections` is ONE scalar hash resolving to an array of arrays — NOT an
    # array of hashes `[C-8 D3, 2026-08-21]`. All three seats evaluated the
    # scalar shape while declaring the array shape; arch ruled the evaluated
    # shape normative, and **not** because three seats agreed (that is
    # cohort-consistency, not evidence). The derivation is §7.1: the reactive
    # `walk` descends on scalar `system/hash` FIELD VALUES and does not enter
    # arrays, so under the declared shape every `lookup/tree` inside every
    # sub-collection of every `concat` goes unregistered and a reactive concat
    # silently never re-fires. It evaluates correctly once and is never woken.
    {"name": "system/compute/concat-args", "description": "Args for compute concat builtin", "fields": {
        "collections": {"type_ref": "system/hash"},
    }},
    {"name": "system/compute/assoc-args", "description": "Args for compute assoc builtin", "fields": {
        "collection": {"type_ref": "system/hash"},
        "index": {"type_ref": "system/hash"},
        "value": {"type_ref": "system/hash"},  # the replacement element
    }},
    # group-by's RESULT element (§3.5, v3.25) — the one result type §3.5 pins;
    # the other three return arrays of the input's own element type and need no
    # declaration. Registering the *name* costs one agreed string and buys
    # nothing at encode time: per §2.3 N1 / §4.1 a constructed entity is encoded
    # by the RUNTIME KIND of the evaluated value and never by the declared
    # schema, so a peer with no type extension produces byte-identical groups.
    {"name": "system/compute/group", "description": "group-by result element", "fields": {
        "key": {"type_ref": "primitive/any"},
        "members": {"array_of": {"type_ref": "primitive/any"}},
    }},
    # Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-COMPUTE-3: subgraph path
    # comes from ctx.resource; uninstall-request wrapper eliminated.
]


def _register_compute_types(emit_pathway: EmitPathway) -> None:
    """Register all compute type definitions at system/type/*."""
    from entity_core.storage.emit import EmitContext
    ctx = EmitContext.bootstrap()
    for type_def in _COMPUTE_TYPE_DEFS:
        type_entity = Entity(
            type="system/type",
            data=type_def,
        )
        path = f"system/type/{type_def['name']}"
        emit_pathway.emit(path, type_entity, ctx)


# ---------------------------------------------------------------------------
# ComputeExtension (§3)
# ---------------------------------------------------------------------------

class ComputeExtension(Extension):
    """Extension providing the compute handler and reactive evaluation."""

    def __init__(self) -> None:
        self._state = _ComputeState()
        self._hook: _ComputeHook | None = None

    @property
    def state(self) -> _ComputeState:
        return self._state

    def handler(self) -> Any:
        """Return compute handler function bound to this extension's state."""
        ext = self

        async def _compute_handler(
            path: str,
            operation: str,
            params: dict[str, Any],
            ctx: HandlerContext,
        ) -> dict[str, Any]:
            if ext._state is None:
                return {
                    "status": 503,
                    "result": {"type": "system/protocol/error", "data": {
                        "code": "not_initialized",
                        "message": "Compute extension not initialized",
                    }},
                }

            params_data = params.get("data", params) if isinstance(params, dict) else {}

            if operation == "eval":
                return await _handle_eval(params_data, ctx, ext._state)
            elif operation == "install":
                return await _handle_install(params_data, ctx, ext._state)
            elif operation == "uninstall":
                return await _handle_uninstall(params_data, ctx, ext._state)
            else:
                return {
                    "status": 501,
                    "result": {"type": "system/protocol/error", "data": {
                        "code": "unsupported_operation",
                        "message": f"Unsupported compute operation: {operation}",
                    }},
                }

        return _compute_handler

    def initialize(self, ctx: ExtensionContext) -> None:
        """Initialize compute state and hook into EmitPathway."""
        if ctx.emit_pathway is None:
            logger.warning("ComputeExtension: no emit_pathway, reactive mode disabled")
            return

        self._state.emit_pathway = ctx.emit_pathway
        self._state.local_peer_id = ctx.peer_id

        self._hook = _ComputeHook(self._state)
        ctx.emit_pathway._add_internal_hook(self._hook, name="compute/reactive")

        self._state.rebuild(
            ctx.emit_pathway.entity_tree,
            ctx.emit_pathway.content_store,
        )

        _register_compute_types(ctx.emit_pathway)

        logger.info("ComputeExtension initialized")

    def shutdown(self) -> None:
        """Clean up."""
        if self._hook is not None and self._state.emit_pathway is not None:
            self._state.emit_pathway._remove_internal_hook(self._hook)
        self._state = _ComputeState()
        self._hook = None

    def make_entity_native_handler(self, expression_path: str) -> Any:
        """Build a handler function that dispatches via this compute extension.

        Used by `PeerBuilder.with_entity_native_handler` to wire an
        entity-native handler (V7 §6.6). The returned function performs the
        fail-closed handler grant check (V7 §7.1) and forwards to
        `dispatch_entity_native` with the request context as scope bindings.
        """
        compute_ext = self

        async def entity_native_handler(
            path: str,
            operation: str,
            params: dict[str, Any],
            ctx: HandlerContext,
        ) -> dict[str, Any]:
            # V7 §7.1 fail-closed: handler grant MUST be present and non-empty.
            # The dispatcher (Peer._get_handler_grant) already rejects missing
            # or invalid grants before we get here; this is defense-in-depth
            # against test paths and future call sites that bypass dispatch.
            # `handler_grant_hash is None` ⇒ no grant entity in the tree.
            if ctx.handler_grant_hash is None:
                return _entity_native_error(
                    403, ERR_PERMISSION_DENIED,
                    f"Entity-native handler grant missing at "
                    f"system/capability/grants/{ctx.handler_pattern}",
                )
            if not ctx.handler_grant or not ctx.handler_grant.get("grants"):
                return _entity_native_error(
                    403, ERR_PERMISSION_DENIED,
                    f"Entity-native handler grant is empty at "
                    f"system/capability/grants/{ctx.handler_pattern}",
                )

            # v3.19b N3: bind `params` as an entity value (Entity) so the
            # handler body navigates it by kind — `field(params,"x")` reads
            # `params.data.x` — and so capturing it into a closure tags it
            # kind:"entity" rather than flattening it to a record (the F9-B
            # root at handler entry).
            params_binding = (
                Entity(type=params["type"], data=params.get("data") or {})
                if isinstance(params, dict) and "type" in params and "data" in params
                else params
            )
            scope_bindings = {
                "operation": operation,
                "params": params_binding,
                "resource": list(ctx.resource_targets) if ctx.resource_targets else [],
                "caller_capability": ctx.caller_capability or {},
            }

            return await compute_ext.dispatch_entity_native(
                expression_path=expression_path,
                scope_bindings=scope_bindings,
                eval_capability=ctx.handler_grant,
                handler_ctx=ctx,
            )

        return entity_native_handler

    async def dispatch_entity_native(
        self,
        expression_path: str,
        scope_bindings: dict[str, Any],
        eval_capability: dict[str, Any],
        handler_ctx: HandlerContext,
    ) -> dict[str, Any]:
        """V7 §6.6 entity-native handler dispatch.

        Evaluate the compute expression at `expression_path` with:
          - ctx.capability = `eval_capability` (the handler grant ceiling)
          - ctx.caller_capability = `handler_ctx.caller_capability` (V7 §6.8
            attribution propagation)
          - subgraph_root = `expression_path` (relative path resolution)
          - scope pre-populated with `scope_bindings` ({operation, params,
            resource, caller_capability})

        Returns an unwrapped handler response per V7 §6.6 step 5:
          - compute/result → {status: 200, result: data.value}
          - compute/error → {status: 200, result: <error entity>}  (F10: error-as-value)
          - any other value → {status: 200, result: <value>}
        """
        ep = handler_ctx.emit_pathway
        h = ep.entity_tree.get(expression_path)
        if h is None:
            return _entity_native_error(
                404, ERR_NOT_FOUND, f"No expression at path: {expression_path}",
            )

        expression = ep.content_store.get(h)
        if expression is None:
            return _entity_native_error(
                404, ERR_NOT_FOUND, f"No expression at path: {expression_path}",
            )

        if not is_compute_expression(expression):
            return _entity_native_error(
                400, ERR_INVALID_EXPRESSION,
                f"Entity at expression_path is not a compute expression: {expression_path}",
            )

        bounds_budget = None
        if handler_ctx.bounds is not None:
            bounds_budget = getattr(handler_ctx.bounds, "budget", None)
        budget = init_budget(None, eval_capability, bounds_budget)

        scope = Scope()
        for name, value in scope_bindings.items():
            scope.set(name, value)

        allowances = eval_capability.get("allowances", {}) if eval_capability else {}
        has_cs_access = bool(allowances.get("content_store_access"))

        dispatch_fn = None
        if handler_ctx._execute_dispatcher is not None:
            dispatch_fn = _make_sync_dispatch(handler_ctx, eval_capability)

        eval_ctx = EvalContext(
            content_store=ep.content_store,
            entity_tree=ep.entity_tree,
            local_peer_id=handler_ctx.local_peer_id,
            capability=eval_capability,
            caller_capability=handler_ctx.caller_capability,
            emit_pathway=ep,
            has_content_store_access=has_cs_access,
            included=_included_entities(handler_ctx),  # §4.2 tier 1
            subgraph_root=expression_path,
            _execute_fn=dispatch_fn,
        )

        result = evaluate(expression, scope, budget, eval_ctx)
        # v3.19c α: bare at the compute→non-compute crossing. **Guarded on
        # is_error [v3.26]:** a top-level error-as-value leaves by its own
        # door below (the entity-native unwrap), and since v3.26
        # `_materialize_bare` *raises* on a scalar error rather than passing
        # it through, so this order is load-bearing rather than cosmetic.
        if not is_error(result):
            result = _materialize_bare(result, eval_ctx)
        return _unwrap_entity_native_result(result)

    def manifest(self) -> Entity:
        """Return handler manifest (ManifestProvider protocol)."""
        from entity_handlers.manifest import build_handler_manifest
        return build_handler_manifest(
            name="compute",
            pattern="system/compute",
            operations={
                "eval": {
                    "input_type": "primitive/any",
                    "output_type": "primitive/any",
                },
                "install": {
                    "input_type": "system/compute/install-request",
                    "output_type": "system/compute/install-result",
                },
                # Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-COMPUTE-3:
                # subgraph path comes from ctx.resource; the
                # uninstall-request wrapper is eliminated.
                "uninstall": {
                    "input_type": "primitive/any",
                    "output_type": "system/protocol/status",
                },
            },
        )
