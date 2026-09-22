"""Shared runtime helpers for the standard handlers.

These were previously duplicated verbatim across several handler modules
(attestation, role, identity, quorum, query, ...). They live here now so there
is a single implementation. Handlers import them under their existing private
names, e.g.::

    from entity_handlers._common import ok_response as _ok

so call sites are unchanged.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from entity_core.capability.checking import NEVER_MATCH, canonicalize, is_pattern

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext


def error_response(
    status: int, code: str, message: str, **extra: Any
) -> dict[str, Any]:
    """Build a ``system/protocol/error`` response.

    Args:
        status: HTTP-style status code.
        code: Error code string.
        message: Human-readable error message.
        **extra: Additional keys merged into the error data payload.

    Returns:
        Response dict wrapping an error entity.
    """
    data: dict[str, Any] = {"code": code, "message": message}
    data.update(extra)
    return {
        "status": status,
        "result": {"type": "system/protocol/error", "data": data},
    }


def ok_response(
    result_type: str, data: dict[str, Any], status: int = 200
) -> dict[str, Any]:
    """Build a success response wrapping ``data`` as ``result_type``.

    ``status`` defaults to 200 and exists for the 2xx codes that carry a result
    body but are not "done" — e.g. 202 for work accepted but not yet performed.
    """
    return {"status": status, "result": {"type": result_type, "data": data}}


def params_data(params: Any) -> dict[str, Any]:
    """Extract the operation's data dict from EXECUTE params.

    Accepts either a bare data dict or a ``{"data": {...}}`` envelope.
    """
    if isinstance(params, dict):
        if "data" in params and isinstance(params["data"], dict):
            return params["data"]
        return params
    return {}


def resource_target(ctx: HandlerContext) -> str | None:
    """First resource-target path from the dispatch context, if any.

    **Lenient by design, and therefore wrong for an operation that REQUIRES a
    resource** — it answers the same thing for one target and for three. Use
    :func:`require_single_resource_target` at any site whose own specification
    requires a resource; this one is for the genuinely optional case.
    """
    targets = getattr(ctx, "resource_targets", None) or []
    if targets and isinstance(targets[0], str):
        return targets[0]
    return None


def require_single_resource_target(
    ctx: HandlerContext, what: str, *, result_type: str | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    """The §3.3 400-row split for an operation whose spec requires a resource.

    Returns ``(path, None)`` or ``(None, error_response)``.

    .. rubric:: Two inputs, two remedies, two codes

    ENTITY-CORE-PROTOCOL §3.3's 400 row (0.8.2.18, scope generalized at
    0.8.2.19): *"an operation that requires a resource answers ABSENT with
    `path_required` and MORE THAN ONE with `ambiguous_resource` — the two are
    different inputs with different remedies… a handler specification that
    collapses them into one code is non-conformant on the absent case."*
    *Supply a resource* is not *disambiguate the one you sent*.

    .. rubric:: Why this helper exists rather than the check being inlined

    The absent arm was inlined at ten sites and the **more-than-one arm at
    none of them** — every one called :func:`resource_target`, which silently
    returns ``targets[0]``. So ten resource-requiring operations *declared*
    the resource required (they refuse the absent case) and then accepted a
    three-target request as if it named one.

    That arm is invisible to a census keyed on emissions: grepping
    `ambiguous_resource` finds the sites that already answer it and can never
    find the sites that should. It is equally invisible to a probe, because
    nobody sends two resource targets by accident. Only a census keyed on the
    **row's input** — *is this an operation whose own spec requires a
    resource?* — reaches it, and the code's own `path_required` is that
    admission. One helper, so the class cannot re-open one call site at a
    time.

    .. rubric:: Three inputs, three codes — and the list is the EFFECTIVE one

    0.8.2.20 adds the third arm and moves the count: *"an operation that
    requires a resource resolves it through ``effective_targets`` (§5.2) and
    answers from THAT list, never from ``resource.targets`` ``[MUST]``"* —
    empty → ``path_required``, more than one → ``ambiguous_resource``, and
    **a single PATTERN target → ``malformed_resource``**, because *"a
    resource-requiring operation takes a CONCRETE path."* Pattern targets stay
    valid for an operation whose spec defines a set-valued subject; no such
    operation exists in the corpus today.

    ``ctx.resource_targets`` **is** the effective list — the dispatcher
    narrows it once, at the authorizer, and hands the result over (F68). So
    this helper counts and indexes the same list, which is the whole point:
    *"a handler that counts the effective list and then indexes
    ``resource.targets[0]`` has implemented the arithmetic completely and is
    still reading a path no authorization covered."* The reason this helper
    cannot get that wrong is that it is never given the raw list.

    Args:
        ctx: The dispatch context.
        what: Human-readable description of the required target, used in the
            messages (e.g. ``"system/role:assign requires a resource target
            (the assignment path)"``).
        result_type: The error entity's ``type``, for the handlers whose own
            specification gives them one — ``compute/error``. **This exists so
            that a differing result TYPE cannot be a reason to re-inline the
            rule**: four operations (`compute:eval`/`install`/`uninstall`,
            `continuation:install`) had their own copy of the two-arm check
            for exactly that reason, and 0.8.2.20's third arm reached none of
            them. The arms are the row; the envelope is the handler's.
    """
    def _refuse(code: str, message: str) -> dict[str, Any]:
        built = error_response(400, code, message)
        if result_type is not None:
            built["result"]["type"] = result_type
        return built

    targets = getattr(ctx, "resource_targets", None) or []
    if not targets:
        # §3.3: *"an EMPTY effective list IS the absent case — a request
        # naming one target and excluding it asks for nothing."* No separate
        # null check is needed and none should be added: an absent `resource`
        # and a fully self-excluded one are the same answer to the same
        # question, and giving them different codes is how a caller learns
        # which of its targets the authorizer skipped.
        return None, _refuse("path_required", f"{what}.")
    if len(targets) != 1:
        return None, _refuse(
            "ambiguous_resource",
            f"{what}, and exactly one — {len(targets)} were supplied "
            "(§3.3: absent and more-than-one are different inputs with "
            "different remedies).",
        )
    first = targets[0]
    if not isinstance(first, str):
        return None, _refuse("malformed_resource", f"{what}.")
    if is_pattern(first):
        return None, _refuse(
            "malformed_resource",
            f"{what}, and a CONCRETE path — {first!r} is a pattern "
            "(§3.3, 0.8.2.20). `malformed_resource` rather than "
            "`invalid_path`: the target is structurally fine and is simply "
            "not usable as *this* operation's subject.",
        )
    return first, None


def unresolvable_tree_path(
    path: str, local_peer_id: str,
) -> dict[str, Any] | None:
    """§5.4's **third** ruled consumer of the ``NEVER_MATCH`` sentinel.

    *"A path that canonicalizes to ``NEVER_MATCH`` MUST NOT be stored, used as
    a storage key, or resolved against the tree"* (0.8.2.20). The other two
    consumers answer in their own vocabulary — the matcher returns False, the
    validator returns an error — and this one is the reason those are not
    enough on their own: a handler that takes its path from ``params`` rather
    than from ``resource.targets`` never passes the dispatch-boundary
    validator at all.

    Returned as a **structural 400 ahead of the authorization check**, on
    R-27 clause 4's reasoning rather than on tidiness: a refusal that runs
    after authorization tells a caller with no authority *that its path was
    unresolvable*, and a refusal that runs before tells it nothing it did not
    supply itself.

    Returns None when the path is resolvable.
    """
    if canonicalize(path, local_peer_id) == NEVER_MATCH:
        return error_response(
            400, "invalid_path",
            f"path cannot be canonicalized: {path!r} (§1.4 reserves a "
            "leading `./` and `../`; a bare `*/` is ambiguous without a "
            "leading slash — use `/*/rest`)",
        )
    return None


def now_ms() -> int:
    """Current wall-clock time in milliseconds since the epoch."""
    return int(time.time() * 1000)


def normalize_hash(value: Any) -> bytes | None:
    """Coerce a hash-shaped value to its canonical byte form.

    Accepts raw bytes, an ``{algorithm, digest}`` dict, or a hex string.
    Returns None when the value is not a valid hash.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        algorithm = value.get("algorithm")
        digest = value.get("digest")
        if isinstance(algorithm, int) and isinstance(digest, bytes):
            return bytes([algorithm]) + digest
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return None
    return None
