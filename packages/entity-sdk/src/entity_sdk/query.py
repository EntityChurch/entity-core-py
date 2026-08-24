"""Query operations and the L3 builder — `SDK-EXTENSION-OPERATIONS` v0.8 §6.

Closes `SDK-OPERATIONS` §16.2's `§5.1 query` SHOULD, and implements the fluent
builder §6 sketches:

    results = await (client.query()
        .type("app/state/setting")
        .field("category", eq="display")
        .path_prefix("app/browser/settings/")
        .limit(50)
        .find())

.. rubric:: §6's shapes disagreed with the normative extension — ruled (SA-4)

`EXTENSION-QUERY` §4.3/§4.4 is what the handler implements;
`SDK-EXTENSION-OPERATIONS` §6 is what an SDK author reads. §6 was wrong in four
places, filed as **SA-PY-4**, and **ruled at 0.8.1 as SA-4**:

===================  ==========================  =========================
concern              §6, before the ruling       normative, and §6 now
===================  ==========================  =========================
result list          ``entries``                 ``matches``
hash field           ``content_hash``            ``hash``
not-equal operator   ``neq``                     ``not_eq``
paging flag          *(absent)*                  ``has_more``
===================  ==========================  =========================

Unlike SA-2 these all failed **loudly** — a `KeyError` on ``entries``, a
``400 invalid_operator`` on ``neq`` — so they cost a debugging session rather
than correctness, and the routing said so explicitly rather than letting them
compete for attention.

**This module speaks the normative names only.** The compatibility aliases it
briefly carried (`QueryResult.entries`, `Match.content_hash`, `neq`) are gone:
they existed to bridge a defect in a document that has since been corrected,
and a name no spec defines is a local divergence — the thing this
implementation exists to find in other people's stacks, not to ship.

.. rubric:: The envelope, unwrapped

With ``include_entities`` the handler returns a ``system/envelope`` whose
``data.root`` is the query result and whose ``data.included`` holds the
entities, rather than the bare ``system/query/result``. That is a wire
convenience, not something a caller should branch on — so this module unwraps
it and hangs each entity off its :class:`Match`. A caller reads
``match.entity`` either way; only whether it is populated changes.

.. rubric:: A field filter needs a type filter

The handler rejects ``field_filters`` without ``type_filter`` with
``400 type_filter_required`` — field indexes are per-type, so there is nothing
to scan otherwise. The builder raises the same error client-side at
:meth:`QueryBuilder.find`, because the alternative is a round trip to be told
something the builder already knows.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _dc_field
from typing import Any, Iterator

from entity_sdk.errors import BadRequest

__all__ = [
    "QUERY_PATTERN",
    "QUERY_REQUEST_TYPE",
    "OPERATORS",
    "FieldFilter",
    "Match",
    "QueryResult",
    "QueryBuilder",
    "normalize_operator",
    "query",
]

#: The handler's dispatch pattern.
QUERY_PATTERN = "system/query"

QUERY_REQUEST_TYPE = "system/query/expression"

#: `EXTENSION-QUERY` §4.4 — the normative operator names.
OPERATORS = (
    "eq", "not_eq", "in", "exists",
    "gt", "lt", "gte", "lte", "prefix", "substring", "contains",
)

#: Operators taking no value (§4.4 "absent for unary operators").
_UNARY_OPERATORS = frozenset({"exists"})

#: Spellings §6 carried before the SA-4 ruling. Not accepted — named only so
#: the error can say *why*, since a caller working from a pre-0.8.1 copy of the
#: SDK doc is making a documented mistake rather than a typo.
_PRE_RULING_SPELLINGS = {"neq": "not_eq"}


def normalize_operator(operator: str) -> str:
    """Validate an operator against `EXTENSION-QUERY` §4.4.

    Raises:
        BadRequest: 400 ``invalid_operator`` — the same code the handler
            answers, so client-side and server-side rejection are
            indistinguishable to a caller.
    """
    if not isinstance(operator, str):
        raise BadRequest(400, "invalid_operator", f"operator must be a string, got {operator!r}")
    if operator in OPERATORS:
        return operator
    if operator in _PRE_RULING_SPELLINGS:
        raise BadRequest(
            400, "invalid_operator",
            f"{operator!r} is the spelling SDK-EXTENSION-OPERATIONS §6 carried "
            f"before the 0.8.1 SA-4 ruling — use "
            f"{_PRE_RULING_SPELLINGS[operator]!r} (EXTENSION-QUERY §4.4).",
        )
    raise BadRequest(
        400, "invalid_operator",
        f"unknown operator {operator!r} — one of {', '.join(OPERATORS)}",
    )


@dataclass(frozen=True, slots=True)
class FieldFilter:
    """§4.2 — one field predicate. ``value`` is absent for unary operators."""

    field: str
    operator: str
    value: Any = None

    def to_data(self) -> dict[str, Any]:
        out: dict[str, Any] = {"field": self.field, "operator": self.operator}
        if self.operator not in _UNARY_OPERATORS:
            out["value"] = self.value
        return out


@dataclass(frozen=True, slots=True)
class Match:
    """§4.3 `system/query/match`.

    ``path`` is optional by the spec — absent for content-store-only entities
    reached under `content_store` scope (§5.4), which is why it is not simply
    assumed present.
    """

    hash: bytes
    type: str | None = None
    path: str | None = None
    #: Populated only when the query asked for entities.
    entity: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class QueryResult:
    """§4.3 `system/query/result`.

    ``total`` is the full capability-filtered count, not the page size — so
    ``len(result) != result.total`` whenever a page was truncated, and that is
    the intended reading rather than an inconsistency.
    """

    matches: list[Match] = _dc_field(default_factory=list)
    total: int = 0
    has_more: bool = False
    cursor: str | None = None

    def __iter__(self) -> Iterator[Match]:
        return iter(self.matches)

    def __len__(self) -> int:
        return len(self.matches)


def _unwrap(result: Any) -> tuple[dict[str, Any], dict[bytes, dict[str, Any]]]:
    """Split a find response into (result data, included entities).

    Handles both shapes the handler emits: the bare `system/query/result`, and
    the `system/envelope` wrapper it switches to when entities are included.
    """
    if not isinstance(result, dict):
        return {}, {}
    if result.get("type") == "system/envelope":
        data = result.get("data") or {}
        root = data.get("root") or {}
        included = data.get("included") or {}
        root_data = root.get("data") if isinstance(root, dict) else None
        return (
            root_data if isinstance(root_data, dict) else {},
            included if isinstance(included, dict) else {},
        )
    inner = result.get("data")
    return (inner if isinstance(inner, dict) else result), {}


def _match_from(raw: Any, included: dict[bytes, dict[str, Any]]) -> Match | None:
    if not isinstance(raw, dict):
        return None
    h = raw.get("hash")
    if not isinstance(h, (bytes, bytearray)):
        return None
    h = bytes(h)
    return Match(
        hash=h,
        type=raw.get("type"),
        path=raw.get("path"),
        entity=included.get(h),
    )


class QueryBuilder:
    """The §6 fluent builder. Immutable-ish: each method mutates and returns self.

    Built by :func:`query` / ``client.query()``. Terminal operations are
    :meth:`find` and :meth:`count`; everything else is a filter.
    """

    def __init__(self, client: Any) -> None:
        self._client = client
        self._type: str | None = None
        self._fields: list[FieldFilter] = []
        self._path_prefix: str | None = None
        self._ref: bytes | None = None
        self._order_by: str | None = None
        self._descending = False
        self._limit: int | None = None
        self._cursor: str | None = None
        self._include_entities = False

    # -- filters ------------------------------------------------------------

    def type(self, pattern: str) -> QueryBuilder:  # noqa: A003 - the spec's name
        """Filter by type. Supports `*` and a trailing `/*` (§4.1)."""
        self._type = pattern
        return self

    def field(self, name: str, operator: str | None = None, value: Any = None, **kw: Any) -> QueryBuilder:
        """Add a field predicate (§4.2).

        Two spellings, because §6's example uses the keyword form and the
        positional form is what a programmatically-built query needs::

            .field("category", eq="display")
            .field("category", "eq", "display")
            .field("archived", "exists")

        Raises:
            BadRequest: 400 for an unknown operator, or for passing more than
                one keyword operator (which reads as an AND but would silently
                keep only one).
        """
        if kw:
            if operator is not None:
                raise BadRequest(
                    400, "invalid_params",
                    "pass the operator positionally or as a keyword, not both",
                )
            if len(kw) > 1:
                raise BadRequest(
                    400, "invalid_params",
                    f"one operator per field() call, got {sorted(kw)} — chain "
                    "field() twice for an AND",
                )
            operator, value = next(iter(kw.items()))
        if operator is None:
            raise BadRequest(400, "invalid_params", "field() requires an operator")
        self._fields.append(FieldFilter(name, normalize_operator(operator), value))
        return self

    def path_prefix(self, prefix: str) -> QueryBuilder:
        """Restrict to a tree path prefix (§4.1 `path_filter`)."""
        self._path_prefix = prefix
        return self

    def refs(self, content_hash: bytes) -> QueryBuilder:
        """Entities referencing ``content_hash`` (§4.1 `ref_filter`)."""
        self._ref = content_hash
        return self

    def order_by(self, field: str, *, descending: bool = False) -> QueryBuilder:
        self._order_by = field
        self._descending = descending
        return self

    def limit(self, n: int) -> QueryBuilder:
        """Page size. The peer caps this by its own grant constraints, so the
        effective page may be smaller than requested."""
        self._limit = n
        return self

    def cursor(self, cursor: str | None) -> QueryBuilder:
        """Resume from a previous page's :attr:`QueryResult.cursor`."""
        self._cursor = cursor
        return self

    def with_entities(self, include: bool = True) -> QueryBuilder:
        """Return the matched entities, not just their hashes."""
        self._include_entities = include
        return self

    # -- terminal -----------------------------------------------------------

    def to_expression(self) -> dict[str, Any]:
        """The wire expression this builder describes (§4.1).

        Exposed because a query worth debugging is worth being able to print,
        and because the tests assert on it rather than on a round trip.

        Raises:
            BadRequest: 400 ``empty_query`` with no filter at all, or
                ``type_filter_required`` for field filters without a type. Both
                mirror the handler's own codes — the builder already has enough
                to know, so it says so without a round trip.
        """
        if self._type is None and self._ref is None and self._path_prefix is None:
            raise BadRequest(
                400, "empty_query",
                "at least one of type() / refs() / path_prefix() is required",
            )
        if self._fields and self._type is None:
            raise BadRequest(
                400, "type_filter_required",
                "field() requires type() — field indexes are per-type",
            )

        expr: dict[str, Any] = {}
        if self._type is not None:
            expr["type_filter"] = self._type
        if self._fields:
            expr["field_filters"] = [f.to_data() for f in self._fields]
        if self._path_prefix is not None:
            expr["path_filter"] = self._path_prefix
        if self._ref is not None:
            expr["ref_filter"] = self._ref
        if self._order_by is not None:
            expr["order_by"] = self._order_by
        if self._descending:
            expr["descending"] = True
        if self._limit is not None:
            expr["limit"] = self._limit
        if self._cursor is not None:
            expr["cursor"] = self._cursor
        if self._include_entities:
            expr["include_entities"] = True
        return expr

    async def find(self) -> QueryResult:
        """Run the query (§6 `find`)."""
        raw = await self._client.execute(
            QUERY_PATTERN, "find", {"type": QUERY_REQUEST_TYPE, "data": self.to_expression()}
        )
        body, included = _unwrap(raw)
        by_hash = {
            bytes(h): e for h, e in included.items() if isinstance(h, (bytes, bytearray))
        }
        matches = [
            m for m in (_match_from(r, by_hash) for r in (body.get("matches") or []))
            if m is not None
        ]
        return QueryResult(
            matches=matches,
            total=int(body.get("total") or 0),
            has_more=bool(body.get("has_more", False)),
            cursor=body.get("cursor"),
        )

    async def count(self) -> int:
        """Count matching entities without transferring them (§6 `count`).

        The handler answers a bare ``primitive/uint``, so this returns an int
        rather than a wrapper — there is no other field on it.
        """
        raw = await self._client.execute(
            QUERY_PATTERN, "count", {"type": QUERY_REQUEST_TYPE, "data": self.to_expression()}
        )
        if isinstance(raw, dict):
            value = raw.get("data", raw)
        else:
            value = raw
        return int(value) if isinstance(value, int) else 0


def query(client: Any) -> QueryBuilder:
    """Start a query against ``client`` (§6's L3 builder)."""
    return QueryBuilder(client)
