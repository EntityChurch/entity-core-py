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
from entity_core.utils.path import validate_absolute_path, validate_path_chars

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
        #
        # 0.8.2.24 (N6) SEPARATES the two empties — but only for an operation
        # that does NOT require a resource, where the absent case has some
        # other behaviour to fall into. Here both empties answer the same code
        # (`path_required`), so this collapse stays correct and this helper is
        # untouched by N6. The resource-OPTIONAL row is
        # :func:`refuse_an_emptied_resource` below, and it is a different
        # question, not a stricter version of this one.
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


def refuse_an_emptied_resource(
    ctx: HandlerContext, what: str, *, result_type: str | None = None,
) -> dict[str, Any] | None:
    """The §3.3 row for an operation that does **not** require a resource.

    Returns an error response when the caller sent a ``resource`` whose
    effective target list is empty, else ``None``.

    .. rubric:: The two empties are distinct `[MUST]` (§3.3, 0.8.2.24 N6)

        *"For an operation that does NOT require one, the two empties are
        distinct: a **genuinely absent** ``resource`` takes that operation's
        own absent-case behaviour (for ``system/tree:get``, the root listing —
        its specification reads "Path ending with ``/`` **or empty**:
        listing"), while a ``resource`` that is **present** and whose effective
        list is empty MUST be refused ``400 path_required`` and MUST NOT be
        served the absent-case behaviour."*

    The caller named a target and its own ``exclude`` removed it. Serving the
    absent-case behaviour answers the **wider** thing — §5.2's subject rule
    (*a handler MUST NOT widen the set*) reached through the front door. On
    ``get`` it turns a request for one excluded path into a listing of the
    tree; on ``snapshot`` it turns it into a snapshot of the whole tree.

    .. rubric:: Why a truthiness test cannot express this, which is the bug

    Every site read ``if ctx.resource_targets:`` — and ``None`` and ``[]`` are
    both falsy, so *"the caller sent no resource"* and *"the caller sent a
    resource and excluded all of it"* took the same branch and fell through to
    the params path. The distinction was **already carried**: the dispatcher
    sets the attribute to ``None`` when ``EXECUTE.resource`` is absent and to a
    list when it is present, then narrows that list to the effective set
    (F68). No new context field is needed, and none should be added — the
    F68 law is that the reduction has ONE derivation, and a `resource_present`
    flag beside the list would be a second one.

    .. rubric:: This binds more than ``system/tree:get``

    §3.3's sentence is about *"an operation"*, and the ``get`` example is an
    example. Measured at this seat it is seven sites: ``tree:get``,
    ``tree:put``, ``tree:snapshot``, ``inbox`` delivery-path resolution and
    three ``continuation`` path resolutions — each one a resource-optional
    operation with a params fallback. The dangerous ones are not the named
    one: ``snapshot`` falls back to prefix ``""``, which is the whole tree,
    and ``put`` falls back to a caller-supplied params path on a **write**.

    Args:
        ctx: The dispatch context.
        what: Human-readable description of what the target would have named.
        result_type: The error entity's ``type``, for handlers whose own
            specification gives them one. Same reason as
            :func:`require_single_resource_target`: a differing result type
            must not become a reason to own a copy of the row.
    """
    targets = getattr(ctx, "resource_targets", None)
    # `None` is ABSENT — the operation's own absent-case behaviour applies and
    # this helper has nothing to say. `[]` is PRESENT-AND-EMPTIED.
    if targets is None or len(targets) > 0:
        return None
    built = error_response(
        400,
        "path_required",
        f"{what}, and the `resource` you sent names no target after your own "
        "`exclude` was applied (§3.3, 0.8.2.24). This is NOT the absent case: "
        "an absent `resource` would take this operation's default behaviour, "
        "but you named a target and excluded it, so serving that default "
        "would answer something wider than you asked for.",
    )
    if result_type is not None:
        built["result"]["type"] = result_type
    return built


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

    .. rubric:: Total, and a property of the BOUNDARY rather than the channel
       `[MUST]` — §5.4 (0.8.2.21)

    *"Every path that reaches the location index, the content store, or the
    tree is validated at that boundary — whatever carried it.* A resource
    target, a URI suffix, a ``params`` field, an entry of a caller-supplied
    array, or a path the handler built by concatenation are all the same kind
    of input at the point of use."

    This function tested **only** the sentinel until 0.8.2.21, which is one of
    three refusable shapes, and it was called on the two paths a caller names
    directly and on none of the paths a caller supplies through ``params``.
    Measured consequence in this tree: ``tree:extract`` with
    ``paths: ["\\x01x"]`` answered **200**, and ``tree:merge`` with
    ``target_prefix: "\\x01x"`` **bound a control character as a tree key**.
    Control characters are not reserved prefixes, so the sentinel test passed
    them through — the two validators that would have caught it
    (``validate_path_chars``, ``validate_absolute_path``) had one call site
    between them, on ``put``.

    **A comment asserting the input is pre-validated is not an enforcement
    point**, and a rule stated over an enumeration of channels invites an
    implementation that enumerates channels. So the three checks are composed
    HERE, once, and every caller-derived path is routed through this function.

    Returns None when the path is safe to resolve, store, or key on.
    """
    # 1. Control characters (§1.4) — form-agnostic, so run it on the RAW input
    #    before any transform can hide one.
    char_error = validate_path_chars(path)
    if char_error is not None:
        return error_response(400, "invalid_path", char_error)

    # 2. The sentinel (§5.4) — reserved `./` / `../` and ambiguous bare `*/`.
    canonical = canonicalize(path, local_peer_id)
    if canonical == NEVER_MATCH:
        return error_response(
            400, "invalid_path",
            f"path cannot be canonicalized: {path!r} (§1.4 reserves a "
            "leading `./` and `../`; a bare `*/` is ambiguous without a "
            "leading slash — use `/*/rest`)",
        )

    # 3. Structure (§5.4 R12). Patterns are exempt by the same sentence that
    #    exempts them at `check_resource_scope`: they go through pattern
    #    matching, not tree access. `is_pattern` is the same discriminator.
    if not is_pattern(canonical):
        # An empty segment is always the CALLER's, wherever the path came
        # from — `canonicalize` never introduces one.
        if "//" in canonical:
            return error_response(
                400, "invalid_path", f"empty segment in path: {canonical}",
            )

        # The peer_id segment is only the caller's claim when the caller wrote
        # an ABSOLUTE path. For a peer-relative path `canonicalize` prepends
        # OUR id, so validating it here tests this peer's own identity rather
        # than the caller's input — it would refuse every request on a peer
        # whose id is malformed, which is a misconfiguration to surface at
        # startup, not a `400` to hand a caller who supplied nothing wrong.
        #
        # This is the distinction `G6`'s discriminating row turns on: `/short/x`
        # is refusable precisely BECAUSE the caller named the peer segment. A
        # relative `x` is not the same input and must not inherit its verdict.
        if path.startswith("/"):
            structure_error = validate_absolute_path(canonical)
            if structure_error is not None:
                return error_response(400, "invalid_path", structure_error)

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
