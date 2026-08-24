"""Dynamic handler registration — `SDK-OPERATIONS` v0.8 §11.6, §12.5.

The last row of §16.1's MUST list. §11.6 exists because a language-native
handler body cannot be entity-encoded, so **the SDK is the only place the two
halves can be coupled**: the protocol-side declaration (tree entities anyone can
discover) and the implementation-side binding (an in-memory dispatch index entry
only this process has). Either one alone is a lie — a tree entry with no body
404s, and a dispatch entry with no tree entry is a handler nobody can find.

§11.6.5's litmus test is the boundary, and it is worth quoting because it is the
whole reason this module is not optional:

> Can some piece of code — internal or external — cause this callback to fire by
> performing a dispatch to a path?

Yes ⇒ it is a handler and MUST be tree-declared through here. No ⇒ it is not a
handler and MUST NOT be in the dispatch index. **No middle ground** — "in the
index but hidden from the tree" is the invariant violation §11.6 was written to
prevent.

**The dispatch index is not exposed.** §11.6: *"Direct access to the underlying
handler dispatch index MUST NOT be part of the SDK's public API surface."* So
`EntityClient` holds its peer privately, this module is the only mutation path,
and :class:`HandlerRegistration` is the only way back out.

**Level.** §11.6's *"Registration level progression"* puts V1.0 at L0 — direct
tree writes, caller is peer-owner code, no capability check on registration —
with V2.0 dispatching `system/handler:register` (L1, capability-checked) for the
declarative half. This is V1.0. The method name does not change when that moves,
which is why it is `client.register_handler(...)` rather than something under
`client.store`: the L0/L1 naming mandate (§6.5) is about *one operation existing
at two levels*, and this one exists at one level at a time.

**What is deliberately not built: §11.6.9 service-owning handlers.** A handler
that owns a listener or a background loop declares it at
`system/runtime/owned-services/{pattern}` and acquires start/stop obligations.
Three things there are cross-impl surface (the ordering, the failed-start
semantics, the declaration shape) and §16.1's MUST line does not name it — and
§11.6.9 itself says *"Retrofitting existing precompiled engines onto this
contract is out of scope. Prove the contract on a new extension first."* This
peer has no service-owning handler to prove it on. Building the declaration
entity with no producer would publish two type definitions for a surface nobody
drives, which is the type-census divergence `EXTENSION-REGISTRY` §6a.9.3 warns
against manufacturing out of a gap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from entity_sdk.errors import BadRequest, Conflict, InternalError

__all__ = [
    "OperationSpec",
    "HandlerSpec",
    "HandlerRegistration",
    "HandlerBody",
    "CODE_PATTERN_COLLISION",
    "CODE_INVALID_HANDLER_SPEC",
    "CODE_PARTIAL_REGISTRATION_FAILURE",
    "CODE_HANDLER_UNDECLARED",
]


# --- §12.5 the pinned code strings ------------------------------------------
#
# "These code strings MUST be consistent across SDK implementations", so they
# are constants rather than literals at the raise site: a cross-SDK contract
# spelled three times is a cross-SDK contract that drifts twice.

#: 409 — a handler is already registered at this pattern.
CODE_PATTERN_COLLISION = "pattern_collision"
#: 400 — spec is malformed (empty pattern, empty operations).
CODE_INVALID_HANDLER_SPEC = "invalid_handler_spec"
#: 500 — compensation succeeded but the original write failed.
CODE_PARTIAL_REGISTRATION_FAILURE = "partial_registration_failure"
#: 503 — tree-gated dispatch: in the index, not declared in the tree. Named
#: here for completeness; it is raised by the *dispatcher* under §11.7's
#: `require_tree_declared_handlers`, which this peer does not implement (it is
#: a §16.2 SHOULD and §11.7 is informative).
CODE_HANDLER_UNDECLARED = "handler_undeclared"


#: The handler body. §11.6.3: *"Dynamic handler bodies run under the same
#: handler contract as bootstrap handlers."* That sentence is the binding one,
#: and in this implementation the bootstrap contract is
#: ``(path, operation, params, ctx) -> dict`` — so that is the body shape here.
#:
#: §11.6.3's cross-language table shows Python as ``async def handler(ctx)``,
#: which reads as a narrower signature and is not: it describes a core whose
#: `HandlerContext` carries the request (rust's does — `execute` and `params`
#: are fields on it). Ours does not, so a ctx-only body could not see which
#: operation it was called for. The spec labels the signature *illustrative,
#: language-idiomatic* and pins the contract instead; we follow the contract.
HandlerBody = Callable[[str, str, dict[str, Any], Any], Awaitable[dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """One operation the handler accepts (`system/handler/operation-spec`).

    §11.6's `HandlerSpec` types this field as ``[OperationSpec]`` — an array —
    while `system/handler/interface.operations` is a **map** keyed by operation
    name (V7 §3.7), which is what the entity actually carries. So the name has
    to live on the element and the SDK does the projection; `entity-core-rust`
    reached the same shape independently. See SA-PY-18.
    """

    name: str
    input_type: str | None = None
    output_type: str | None = None

    def to_data(self) -> dict[str, Any]:
        """The stored value, with absent optionals **omitted** rather than
        written as null — the entity is content-addressed, so a null and an
        absence are different bytes and only one of them is what the type
        means by `optional: true`."""
        data: dict[str, Any] = {}
        if self.input_type is not None:
            data["input_type"] = self.input_type
        if self.output_type is not None:
            data["output_type"] = self.output_type
        return data


@dataclass(frozen=True, slots=True)
class HandlerSpec:
    """§11.6's `HandlerSpec` — the protocol-side declaration.

    ``pattern`` is **bare**: the SDK qualifies it to ``/{peer_id}/{pattern}``.
    A leading slash is an error rather than a courtesy, because a caller who
    writes one is either double-qualifying or naming another peer's namespace,
    and neither is something to guess about.

    ``description`` is accepted and **currently reaches no entity** — see
    :func:`register_handler` and SA-PY-18.
    """

    pattern: str
    name: str
    operations: list[OperationSpec]
    description: str | None = None
    internal_scope: list[dict[str, Any]] | None = None
    types: dict[str, Any] | None = field(default=None)


class HandlerRegistration:
    """The `Handle` §11.6 returns. Closing it unregisters **both** sides.

    §11.6.2's ordering is normative and runs opposite to registration:

    1. **Dispatch index first** — stop accepting dispatch immediately.
    2. **Tree entries second** — handler, interface, grant.

    Type definitions installed via ``types`` are **not** removed: they have an
    independent lifecycle and may be referenced by other handlers, by queries,
    or by remote peers.

    **Close is idempotent** and there is no GC path. §11.6.2 permits a
    finalizer as a safety net but forbids relying on one for correctness, so
    this class has none at all — a cleanup that only sometimes runs is harder
    to reason about than one that never does.
    """

    __slots__ = (
        "_peer", "_pattern", "_paths", "_closed",
        "pattern", "interface_path", "handler_path", "grant_path",
    )

    def __init__(
        self,
        peer: Any,
        pattern: str,
        interface_path: str,
        handler_path: str,
        grant_path: str,
        removal_paths: list[str],
    ) -> None:
        self._peer = peer
        self._pattern = pattern
        # Reverse of the write order — the signature before the grant it
        # covers, the grant before the handler, the handler before the
        # interface it references.
        self._paths = removal_paths
        self._closed = False
        #: The bare dispatch pattern.
        self.pattern = pattern
        #: Tree path of the `system/handler/interface` entity.
        self.interface_path = interface_path
        #: Tree path of the `system/handler` dispatch target.
        self.handler_path = handler_path
        #: Tree path of the handler's own self-grant.
        self.grant_path = grant_path

    @property
    def closed(self) -> bool:
        return self._closed

    async def close(self) -> None:
        """Unregister both sides. Idempotent — a second call is a no-op."""
        if self._closed:
            return
        self._closed = True
        # 1. Dispatch index first: stop accepting dispatch before the tree
        #    stops declaring it. The reverse order opens a window in which
        #    dispatch reaches a handler the tree does not declare, which is
        #    the §11.6.5 violation this whole module exists to prevent.
        self._peer.handlers.unregister(self._pattern)
        # 2. Tree entries, reverse of the write order.
        from entity_core.storage.emit import EmitContext

        ctx = EmitContext.bootstrap()
        for path in self._paths:
            try:
                self._peer.emit_pathway.delete(path, ctx)
            except Exception:  # pragma: no cover — best-effort, like §11.6.4
                pass

    async def __aenter__(self) -> HandlerRegistration:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    def __repr__(self) -> str:  # pragma: no cover — diagnostics
        state = "closed" if self._closed else "open"
        return f"<HandlerRegistration {self.pattern!r} {state}>"


def _validate(spec: HandlerSpec) -> None:
    """§11.6's 400 rows. Every refusal carries `invalid_handler_spec`, which
    §12.5 pins across SDKs."""
    if not spec.pattern:
        raise BadRequest(
            400, CODE_INVALID_HANDLER_SPEC,
            "HandlerSpec.pattern is empty — a handler with no pattern is "
            "unreachable by dispatch and undiscoverable in the tree",
        )
    if spec.pattern.startswith("/"):
        raise BadRequest(
            400, CODE_INVALID_HANDLER_SPEC,
            f"HandlerSpec.pattern {spec.pattern!r} has a leading slash: the "
            "pattern is BARE and the SDK qualifies it to /{peer_id}/{pattern} "
            "(§11.6). A leading slash is either a double-qualification or "
            "another peer's namespace, and neither is guessable",
        )
    if not spec.operations:
        raise BadRequest(
            400, CODE_INVALID_HANDLER_SPEC,
            "HandlerSpec.operations is empty — a handler that accepts no "
            "operation answers 501 to everything, so the registration is a "
            "tree entry that can never be used",
        )
    if not spec.name:
        raise BadRequest(
            400, CODE_INVALID_HANDLER_SPEC,
            "HandlerSpec.name is empty — `name` is REQUIRED on "
            "system/handler/interface (V7 §3.7), so this cannot be written",
        )
    seen: set[str] = set()
    for op in spec.operations:
        if not op.name:
            raise BadRequest(
                400, CODE_INVALID_HANDLER_SPEC,
                "an OperationSpec has no name — the interface entity stores "
                "operations as a map keyed by name, so an unnamed one has no "
                "key to occupy",
            )
        if op.name in seen:
            # Not in §11.6's list, and it has to be refused somewhere: the map
            # projection silently collapses duplicates, so the caller's second
            # OperationSpec would vanish with no error at any layer.
            raise BadRequest(
                400, CODE_INVALID_HANDLER_SPEC,
                f"operation {op.name!r} is declared twice — the interface "
                "entity is a map keyed by operation name, so the duplicate "
                "would be silently discarded",
            )
        seen.add(op.name)


def _build_interface(spec: HandlerSpec) -> Any:
    """The `system/handler/interface` entity — pattern, name, operations.

    **`description` is not written**, because `system/handler/interface` has no
    such field (V7 §3.7: pattern, name, operations). §11.6 declares
    `HandlerSpec.description` *"Human-readable, for discovery consumers"* and
    §11.6.1 says the interface *"Contains pattern, name, and operations"* —
    so the field the spec offers to discovery consumers reaches none of them.

    We drop it rather than smuggling it in as an open-type extra: §2.10 would
    preserve it, but it would move this entity's content hash away from every
    other implementation's for the same spec, and `discover_handlers` reads
    this entity across peers. Manufacturing a cross-impl hash divergence out of
    a spec gap makes the divergence ours. Filed as SA-PY-18;
    `entity-core-rust` drops it too.
    """
    from entity_core.protocol.entity import Entity

    return Entity(
        type="system/handler/interface",
        data={
            "pattern": spec.pattern,
            "name": spec.name,
            "operations": {op.name: op.to_data() for op in spec.operations},
        },
    )


async def register_handler(
    peer: Any,
    spec: HandlerSpec,
    body: HandlerBody,
) -> HandlerRegistration:
    """§11.6 — couple the tree declaration with the language-native body.

    Writes, in §11.6.1's order, all of them **after** the collision check:

    0. type definitions from ``spec.types`` at ``system/type/{name}``
    1. the interface entity at ``system/handler/{pattern}``
    2. the handler entity at ``{pattern}``, referencing the interface by path
    3. the self-grant at ``system/capability/grants/{pattern}`` (+ its
       signature at the §3.5 invariant pointer), if ``internal_scope`` is set
    4. the dispatch-index entry

    **Tree first, index second, and the order is a MUST.** The reverse creates
    a window in which dispatch reaches a handler the tree does not declare.

    **Compensation (§11.6.4).** If any step fails, the writes that succeeded
    are removed in reverse order and the original error is raised — no handle
    is returned, so the caller knows registration failed *entirely*. Type
    definitions are not compensated (independent lifecycle, §11.6.2), and
    compensation itself is best-effort: an orphaned tree entry with no body is
    harmless (dispatch 404s), so a failure to clean up must not mask the error
    that caused it.
    """
    from entity_core.protocol.entity import Entity
    from entity_core.storage.emit import EmitContext

    _validate(spec)

    pattern = spec.pattern
    interface_rel = f"system/handler/{pattern}"
    grant_rel = f"system/capability/grants/{pattern}"
    emit = peer.emit_pathway
    tree = emit.entity_tree
    ctx = EmitContext.bootstrap()

    # §11.6.1 collision check — BOTH sides, before any write. "Silent overwrite
    # is not permitted"; replacement is an explicit close followed by a fresh
    # register.
    #
    # Note the interaction with §11.6.6, which recommends applications
    # re-register dynamic handlers on startup and calls the tree writes
    # "idempotent if the entries already exist": after a restart with a
    # persistent tree the entries DO survive, so this check refuses the very
    # thing §11.6.6 recommends. §11.6.1's is the MUST and §11.6.6's is a
    # recommendation, so the MUST wins here; filed as SA-PY-19.
    if peer.handlers.find_exact(pattern) is not None:
        raise Conflict(
            409, CODE_PATTERN_COLLISION,
            f"a handler is already bound at {pattern!r} in the dispatch index "
            "— close its handle first (§11.6.1: silent overwrite is not "
            "permitted)",
        )
    if tree.get(tree.normalize_uri(pattern)) is not None:
        raise Conflict(
            409, CODE_PATTERN_COLLISION,
            f"the tree already declares a handler at {pattern!r} — close its "
            "handle first, or remove the stale declaration (§11.6.1)",
        )

    written: list[str] = []

    def _rollback() -> None:
        for path in reversed(written):
            try:
                emit.delete(path, ctx)
            except Exception:  # pragma: no cover — best-effort by §11.6.4
                pass

    try:
        # 0. Type definitions, before the interface. NOT tracked in `written`:
        #    §11.6.4 exempts them from compensation for the same reason
        #    §11.6.2 exempts them from close — independent lifecycle.
        for type_name, type_def in (spec.types or {}).items():
            entity = (
                type_def if isinstance(type_def, Entity)
                else Entity(type="system/type", data=dict(type_def))
            )
            emit.emit(f"system/type/{type_name}", entity, ctx)

        # 1. Interface — written first because the handler entity references
        #    it by path.
        emit.emit(interface_rel, _build_interface(spec), ctx)
        written.append(interface_rel)

        # 2. Handler entity — the dispatch target the V7 §6.6 tree walk finds.
        #    Security configuration lives here and not on the interface, so it
        #    is not exposed to remote peers through discovery.
        handler_data: dict[str, Any] = {"interface": interface_rel}
        if spec.internal_scope is not None:
            handler_data["internal_scope"] = spec.internal_scope
        emit.emit(pattern, Entity(type="system/handler", data=handler_data), ctx)
        written.append(pattern)

        # 3. The self-grant. §11.6.3 `[MUST NOT]`: a handler registered without
        #    `internal_scope` cannot call other handlers from its body, and the
        #    SDK MUST NOT silently default to a wildcard — *"that is the
        #    capability equivalent of running as root."* So there is no
        #    `or create_full_access_grant()` here, which is what this peer's own
        #    bootstrap path does for built-in handlers.
        #
        #    **A null scope writes an EMPTY grant, not no grant, and that is a
        #    deviation from §11.6.1 step 3 with a reason.** Step 3 writes the
        #    grant *"if `internal_scope` is non-null"*, but V7 §6.2 makes the
        #    handler's own grant a **dispatch prerequisite** here — the
        #    dispatcher fails closed with 403 when it is missing, for either
        #    dispatch path. Following step 3 literally therefore produces a
        #    handler that is declared, indexed, discoverable and answers 403 to
        #    everyone: registration succeeds and the handler can never run.
        #    An empty `grants: []` gives exactly the semantics §11.6.3
        #    *describes* — dispatchable, authorizing no outbound call — and is
        #    the minimum-authority end of the axis rather than the wildcard end.
        #    Filed as SA-PY-20.
        from entity_core.capability.grant_signing import (
            build_signed_handler_grant, grant_signature_path,
        )

        grant_entity, signature_entity, identity_entity = (
            build_signed_handler_grant(peer.keypair, list(spec.internal_scope or []))
        )
        # The granter hash has to resolve at validation time.
        emit.content_store.put(identity_entity)
        sig_rel = grant_signature_path(grant_entity.compute_hash())
        emit.emit(grant_rel, grant_entity, ctx)
        written.append(grant_rel)
        emit.emit(sig_rel, signature_entity, ctx)
        written.append(sig_rel)
        # The grant binding is removed before the handler entity on close,
        # signature first, matching the reverse-of-write rule.
        grant_removals = [sig_rel, grant_rel]

        # 4. Dispatch index last.
        peer.handlers.register(pattern, body, name=spec.name)
    except Exception as exc:
        _rollback()
        if isinstance(exc, (BadRequest, Conflict, InternalError)):
            raise
        raise InternalError(
            500, CODE_PARTIAL_REGISTRATION_FAILURE,
            f"registration of {pattern!r} failed and was compensated: {exc}",
        ) from exc

    return HandlerRegistration(
        peer, pattern, interface_rel, pattern, grant_rel,
        grant_removals + [pattern, interface_rel],
    )
