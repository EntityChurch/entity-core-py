"""Standard constraint handler for EXTENSION-TYPE v1.1.

Registered at pattern ``system/type/constraint/*`` per spec §5.1. Dispatches
on the constraint entity's type path per §5.4 and serves the §5.2 / §5.3
request/result contract. This is the fixed, Class-1-convergence
evaluator for the 11 standard constraint kinds (§4); custom constraint
handlers (§2.2) are user-registered at separate patterns and are not
served by this handler.

Cross-impl interop notes:

* ``one_of`` / ``not_one_of`` use **ECF byte equality** — the
  load-bearing §5.5 normative interop gate. Same canonical-CBOR
  boundary that ``ENTITY-CBOR-ENCODING.md`` already pins.
* ``pattern`` uses google-re2 (linear-time, RE2 syntax); patterns
  containing PCRE-only constructs (backreferences, lookaround) are
  rejected at compile time per §4.3.
* ``format`` MUST-recognize names (§4.5) — uri, date-time, date, uuid,
  base58, re2 — fail closed on unknown names.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch as _fnmatch
import logging
import uuid as _uuid
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse as _urlparse

import re2 as _re2

from entity_core.crypto.identity_file import base58_decode as _b58decode
from entity_core.utils.ecf import ecf_encode as _ecf_encode
from entity_handlers._common import error_response as _error

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext

logger = logging.getLogger(__name__)

TYPE_CONSTRAINT_HANDLER_PATTERN = "system/type/constraint/*"

# Result type owned by EXTENSION-TYPE v1.1 §5.3.
_RESULT_TYPE = "system/type/constraint/validate-result"

# The MUST-recognize format names (§4.5). Order matches the spec table.
_WELL_KNOWN_FORMATS = ("uri", "date-time", "date", "uuid", "base58", "re2")


# ---------------------------------------------------------------------------
# Public handler
# ---------------------------------------------------------------------------


async def type_constraint_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: "HandlerContext",
) -> dict[str, Any]:
    """Dispatch one constraint check per EXTENSION-TYPE v1.1 §5.4.

    The handler pattern ``system/type/constraint/*`` is matched by the
    dispatcher; the actual constraint kind is read from
    ``params.constraint_type`` (spec §5.2 / §5.4). ``path`` and
    ``constraint_type`` are normally identical — the spec drives the
    decision off the request envelope so a single handler call can be
    routed by the dispatcher without re-parsing the path.
    """
    if operation != "validate":
        return _error(
            501,
            "unsupported_operation",
            f"system/type/constraint/* handler only supports 'validate'; got '{operation}'",
        )

    body = params.get("data", params) if isinstance(params, dict) else {}
    try:
        constraint_type = body["constraint_type"]
        constraint_data = body.get("constraint_data") or {}
    except KeyError as exc:
        return _error(
            400,
            "invalid_request",
            f"constraint validate-request missing required field: {exc.args[0]}",
        )
    if "value" not in body:
        # `value` is required but may be None; can't substitute a default.
        return _error(
            400,
            "invalid_request",
            "constraint validate-request missing required field: value",
        )
    value = body["value"]

    verdict = _dispatch(value, constraint_type, constraint_data, ctx)
    return {"status": 200, "result": {"type": _RESULT_TYPE, "data": verdict}}


# ---------------------------------------------------------------------------
# Per-kind dispatch (§5.4)
# ---------------------------------------------------------------------------


def _dispatch(
    value: Any,
    constraint_type: str,
    data: dict[str, Any],
    ctx: "HandlerContext",
) -> dict[str, Any]:
    """Evaluate one constraint, returning the §5.3 result body."""
    if constraint_type == "system/type/constraint/min":
        return _validate_min(value, data)
    if constraint_type == "system/type/constraint/max":
        return _validate_max(value, data)
    if constraint_type == "system/type/constraint/min-length":
        return _validate_min_length(value, data)
    if constraint_type == "system/type/constraint/max-length":
        return _validate_max_length(value, data)
    if constraint_type == "system/type/constraint/min-count":
        return _validate_min_count(value, data)
    if constraint_type == "system/type/constraint/max-count":
        return _validate_max_count(value, data)
    if constraint_type == "system/type/constraint/pattern":
        return _validate_pattern(value, data)
    if constraint_type == "system/type/constraint/one-of":
        return _validate_one_of(value, data)
    if constraint_type == "system/type/constraint/not-one-of":
        return _validate_not_one_of(value, data)
    if constraint_type == "system/type/constraint/format":
        return _validate_format(value, data)
    if constraint_type == "system/type/constraint/type-pattern":
        return _validate_type_pattern(value, data, ctx)

    # Per §5.4 default branch + §1.2: the standard handler does not
    # recognize this constraint type. Fail closed; the caller (the
    # type handler) maps this to a `kind: unknown_constraint` violation.
    return {"valid": False, "reason": f"unknown constraint type: {constraint_type}"}


# ---------------------------------------------------------------------------
# Numeric bounds (§4.1)
# ---------------------------------------------------------------------------


def _is_numeric(value: Any) -> bool:
    """Numeric per §4.1 — uint, int, float. Booleans excluded (Python
    quirk: ``bool`` is a subclass of ``int`` but is not numeric here)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_min(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    if not _is_numeric(value):
        return {"valid": False, "reason": "min: not numeric"}
    bound = data.get("min")
    if not _is_numeric(bound):
        return {"valid": False, "reason": "min: constraint data missing numeric 'min'"}
    # NaN comparisons return false per §4.1 — float('nan') >= anything is False already.
    return {"valid": value >= bound, "reason": f"must be >= {bound}"}


def _validate_max(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    if not _is_numeric(value):
        return {"valid": False, "reason": "max: not numeric"}
    bound = data.get("max")
    if not _is_numeric(bound):
        return {"valid": False, "reason": "max: constraint data missing numeric 'max'"}
    return {"valid": value <= bound, "reason": f"must be <= {bound}"}


# ---------------------------------------------------------------------------
# Length bounds (§4.2)
# ---------------------------------------------------------------------------


def _measure_length(value: Any) -> int | None:
    """Codepoint count for strings; byte count for bytes; None otherwise.

    Python ``len(str)`` is already the codepoint count (Python 3 strings
    are sequences of unicode codepoints, not UTF-16 units like Java).
    """
    if isinstance(value, str):
        return len(value)
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    return None


def _validate_min_length(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    length = _measure_length(value)
    if length is None:
        return {"valid": False, "reason": "min_length: value is not string or bytes"}
    bound = data.get("min_length")
    if not isinstance(bound, int) or bound < 0:
        return {"valid": False, "reason": "min_length: invalid bound"}
    return {"valid": length >= bound, "reason": f"length must be >= {bound}"}


def _validate_max_length(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    length = _measure_length(value)
    if length is None:
        return {"valid": False, "reason": "max_length: value is not string or bytes"}
    bound = data.get("max_length")
    if not isinstance(bound, int) or bound < 0:
        return {"valid": False, "reason": "max_length: invalid bound"}
    return {"valid": length <= bound, "reason": f"length must be <= {bound}"}


def _collection_size(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return None


def _validate_min_count(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    size = _collection_size(value)
    if size is None:
        return {"valid": False, "reason": "min_count: value is not array or map"}
    bound = data.get("min_count")
    if not isinstance(bound, int) or bound < 0:
        return {"valid": False, "reason": "min_count: invalid bound"}
    return {"valid": size >= bound, "reason": f"count must be >= {bound}"}


def _validate_max_count(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    size = _collection_size(value)
    if size is None:
        return {"valid": False, "reason": "max_count: value is not array or map"}
    bound = data.get("max_count")
    if not isinstance(bound, int) or bound < 0:
        return {"valid": False, "reason": "max_count: invalid bound"}
    return {"valid": size <= bound, "reason": f"count must be <= {bound}"}


# ---------------------------------------------------------------------------
# Pattern matching (§4.3)
# ---------------------------------------------------------------------------


def _validate_pattern(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, str):
        return {"valid": False, "reason": "pattern: value is not a string"}
    pattern = data.get("pattern")
    if not isinstance(pattern, str):
        return {"valid": False, "reason": "pattern: constraint data missing 'pattern' string"}
    # RE2 full-match semantics per §4.3. google-re2 raises on PCRE-only
    # constructs (backreferences, lookaround), which is exactly the
    # "not conformant" rejection the spec wants.
    try:
        compiled = _re2.compile(pattern)
    except _re2.error as exc:  # pragma: no cover — error path is straightforward
        return {"valid": False, "reason": f"pattern: invalid RE2 pattern: {exc}"}
    matched = compiled.fullmatch(value) is not None
    return {"valid": matched, "reason": f"must match pattern: {pattern}"}


# ---------------------------------------------------------------------------
# Enumeration via ECF byte equality (§4.4, §5.5 normative cross-impl gate)
# ---------------------------------------------------------------------------


def _ecf_bytes(value: Any) -> bytes:
    """Canonical ECF (deterministic CBOR) bytes for a single value.

    Per §5.5: two implementations MUST agree on whether a value matches
    a ``one_of`` list. ECF byte equality is the wire-level guarantee.
    """
    return _ecf_encode(value)


def _ecf_byte_equal_any(value: Any, candidates: Any) -> bool:
    if not isinstance(candidates, list):
        return False
    target = _ecf_bytes(value)
    return any(_ecf_bytes(c) == target for c in candidates)


def _validate_one_of(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    values = data.get("values")
    if not isinstance(values, list):
        return {"valid": False, "reason": "one_of: constraint data missing 'values' array"}
    return {
        "valid": _ecf_byte_equal_any(value, values),
        "reason": "must be one of the listed values",
    }


def _validate_not_one_of(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    values = data.get("values")
    if not isinstance(values, list):
        return {
            "valid": False,
            "reason": "not_one_of: constraint data missing 'values' array",
        }
    return {
        "valid": not _ecf_byte_equal_any(value, values),
        "reason": "must not be one of the listed values",
    }


# ---------------------------------------------------------------------------
# Format validation (§4.5)
# ---------------------------------------------------------------------------


def _validate_format(value: Any, data: dict[str, Any]) -> dict[str, Any]:
    name = data.get("format")
    if not isinstance(name, str):
        return {"valid": False, "reason": "format: constraint data missing 'format' string"}
    if not isinstance(value, str):
        return {"valid": False, "reason": f"format '{name}': value is not a string"}

    checker = _FORMAT_CHECKERS.get(name)
    if checker is None:
        # Per §4.5: unknown format names fail closed. The caller maps
        # this to `kind: unknown_constraint` per §1.2.
        return {"valid": False, "reason": f"unknown format: {name}"}

    ok = checker(value)
    return {"valid": ok, "reason": f"must be a valid {name}"}


def _check_uri(value: str) -> bool:
    """RFC 3986 URI — a value is a URI if it has a non-empty scheme.

    RFC 3986 §3 requires ``scheme ":" hier-part`` for a URI;
    ``urllib.parse.urlparse`` populates ``scheme`` only when the input
    starts with a non-empty scheme component. We additionally require
    the scheme to start with a letter and contain only the §3.1 set,
    catching ``urlparse``'s lenience.
    """
    try:
        parsed = _urlparse(value)
    except ValueError:
        return False
    scheme = parsed.scheme
    if not scheme or not scheme[0].isalpha():
        return False
    for ch in scheme[1:]:
        if not (ch.isalnum() or ch in "+-."):
            return False
    return True


def _check_date_time(value: str) -> bool:
    """RFC 3339 date-time — ``YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)``.

    Python 3.11+ ``datetime.fromisoformat`` accepts the RFC 3339 grammar
    including the trailing ``Z`` for UTC.
    """
    try:
        _dt.datetime.fromisoformat(value)
    except ValueError:
        return False
    # RFC 3339 requires a `T` between date and time, and an offset/Z.
    if "T" not in value and "t" not in value:
        return False
    return "Z" in value or "z" in value or "+" in value or value.count("-") > 2


def _check_date(value: str) -> bool:
    """RFC 3339 §5.6 full-date — ``YYYY-MM-DD``."""
    if len(value) != 10:
        return False
    try:
        _dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _check_uuid(value: str) -> bool:
    try:
        _uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    # Reject the form used by uuid.UUID for ints; require canonical hyphenated form.
    return len(value) == 36 and value.count("-") == 4


def _check_base58(value: str) -> bool:
    try:
        _b58decode(value)
    except Exception:
        return False
    return True


def _check_re2(value: str) -> bool:
    try:
        _re2.compile(value)
    except _re2.error:
        return False
    return True


_FORMAT_CHECKERS: dict[str, Any] = {
    "uri": _check_uri,
    "date-time": _check_date_time,
    "date": _check_date,
    "uuid": _check_uuid,
    "base58": _check_base58,
    "re2": _check_re2,
}


# ---------------------------------------------------------------------------
# Typed references (§4.6)
# ---------------------------------------------------------------------------


def _glob_to_re2(pattern: str) -> str:
    """Translate a `*`/`**` segment glob to an anchored RE2 regex.

    Per §4.6: ``*`` matches one path segment, ``**`` matches zero or
    more segments. Segments are separated by ``/``.
    """
    # Walk the pattern, expanding ** before * to avoid greedy ambiguity.
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*" and i + 1 < len(pattern) and pattern[i + 1] == "*":
            # `**` — zero or more segments, including separators.
            out.append("(?:[^/]+(?:/[^/]+)*)?")
            i += 2
            # Eat a trailing `/` so `**/foo` doesn't leave a stray `/`.
            if i < len(pattern) and pattern[i] == "/":
                out.append("(?:/)?")
                i += 1
        elif ch == "*":
            out.append("[^/]+")
            i += 1
        else:
            out.append(_re2.escape(ch))
            i += 1
    return "".join(out)


def _validate_type_pattern(
    value: Any,
    data: dict[str, Any],
    ctx: "HandlerContext",
) -> dict[str, Any]:
    pattern = data.get("pattern")
    if not isinstance(pattern, str):
        return {
            "valid": False,
            "reason": "type_pattern: constraint data missing 'pattern' string",
        }

    referenced_type = _resolve_referenced_type(value, ctx)
    if referenced_type is None:
        # Per §4.6: resolution failure SHOULD pass with a warning. We
        # treat resolution failure as a pass — type_pattern validates
        # the type of REACHABLE entities, not their existence.
        return {
            "valid": True,
            "reason": f"type_pattern: reference unresolved (pattern: {pattern})",
        }

    # Glob → RE2 full-match.
    regex = _glob_to_re2(pattern)
    try:
        compiled = _re2.compile(regex)
    except _re2.error as exc:  # pragma: no cover
        return {"valid": False, "reason": f"type_pattern: invalid pattern: {exc}"}
    matched = compiled.fullmatch(referenced_type) is not None
    return {
        "valid": matched,
        "reason": f"referenced type '{referenced_type}' must match: {pattern}",
    }


def _resolve_referenced_type(value: Any, ctx: "HandlerContext") -> str | None:
    """Resolve a hash or path reference to the referenced entity's type.

    Returns ``None`` when the reference cannot be resolved — §4.6
    treats unresolved references as a pass-with-warning, so callers
    use this signal to short-circuit accordingly.
    """
    emit = getattr(ctx, "emit_pathway", None)
    if emit is None:
        return None
    content_store = getattr(emit, "content_store", None)
    entity_tree = getattr(emit, "entity_tree", None)

    # Hash reference — raw bytes or {algorithm, digest} dict.
    if isinstance(value, (bytes, bytearray)):
        if content_store is None:
            return None
        entity = content_store.get(bytes(value))
        return entity.type if entity is not None else None
    if isinstance(value, dict) and "algorithm" in value and "digest" in value:
        if content_store is None:
            return None
        alg = value["algorithm"]
        digest = value["digest"]
        if isinstance(alg, int) and isinstance(digest, (bytes, bytearray)):
            entity = content_store.get(bytes([alg]) + bytes(digest))
            return entity.type if entity is not None else None
        return None

    # Path reference.
    if isinstance(value, str):
        if entity_tree is None or content_store is None:
            return None
        try:
            uri = entity_tree.normalize_uri(value)
        except Exception:  # pragma: no cover — defensive against unusual path shapes
            return None
        h = entity_tree.get(uri)
        if h is None:
            return None
        entity = content_store.get(h)
        return entity.type if entity is not None else None

    return None


# Re-exported helpers used by the type handler (T3) for narrowing and
# for evaluating `one_of` lists during compatibility analysis.
__all__ = [
    "TYPE_CONSTRAINT_HANDLER_PATTERN",
    "type_constraint_handler",
    "_ecf_byte_equal_any",  # T4 narrowing uses this; intentionally exported.
    "_glob_to_re2",
]


# fnmatch is imported but only kept as a fallback marker; the glob
# semantics in §4.6 differ enough from POSIX fnmatch that we hand-roll
# the segment-aware translation above. Keeping the import suppresses
# any future temptation to silently swap in fnmatch.translate.
_ = _fnmatch
