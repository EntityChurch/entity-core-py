"""The L1 operations client — `SDK-OPERATIONS` v0.8 §3, §4, §12.

This is the surface that did not exist. Every tree operation in this repo was,
until now, a hand-assembled ``{"type": "system/tree/get-request", "data": …}``
envelope written at the call site — seventeen times in the CLI, and nowhere
reusable. :class:`EntityClient` is that knowledge, written once.

**It composes over the `Dispatcher` Protocol**, not over a connection or a peer.
That is why one client serves the whole §2.6 peer spectrum: wrap a
``HandlerContext`` and it is L1 local dispatch, wrap a ``Connection`` and it is
L2 remote dispatch, and per §2.7 *"the application doesn't choose the level"* —
the peer id in the resolved path does.

Three normative details worth knowing before editing this file:

* **The path rides in ``resource.targets``, not in ``params``** (V7 §3.2). Both
  are accepted by the tree handler, but only the resource form is covered by
  the *dispatch layer's* capability check before the handler runs — the
  defense-in-depth the CLI's params-only calls never got.
* **L0 and L1 must not share names** (§2.7). This client is L1 only. Direct
  store access stays on ``peer.content_store`` / ``peer.emit_pathway``, which
  the spec names as the anti-pattern to avoid: *"Mixing dispatched and direct
  operations under the same names (both called `get`) … hides the security
  boundary."*
* **``put`` and ``put_cas`` are separate methods on purpose** (§3.2). The wire
  distinguishes *absent* ``expected_hash`` (unconditional) from *zero*
  ``expected_hash`` (create-only), and a single method with an
  ``expected_hash=None`` default cannot express both — ``None`` would have to
  mean "unconditional" and "must not exist" at the same time. Two methods make
  the three-value semantics representable without a sentinel object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from entity_core.protocol.entity import Entity
from entity_core.sdk import Dispatcher, ExecuteRequest

from entity_sdk.errors import raise_for_status
from entity_sdk.handlers import (
    HandlerBody,
    HandlerRegistration,
    HandlerSpec,
    register_handler,
)
from entity_sdk.events import ChangeStream, validate_watch_pattern
from entity_sdk.paths import ResolvedPath, resolve
from entity_sdk.store import LocalStore

if TYPE_CHECKING:
    # Deferred: `query.py` is a leaf that imports only `errors`, but importing
    # it at module level here would make every `import entity_sdk.client` pull
    # the builder in for a return annotation.
    from entity_sdk.query import QueryBuilder
    from entity_sdk.revision import RevisionClient

__all__ = ["Entry", "EntityClient", "TREE_PATTERN", "ZERO_HASH"]

#: The tree handler's dispatch pattern. Every operation in §3 lands here.
TREE_PATTERN = "system/tree"

#: V7 §3.9 CAS-create sentinel — flat `0x00 ‖ 32 zero bytes` (format code
#: 0x00 = ECFv1-SHA256, 33 bytes). The peer accepts empty bytes as equivalent
#: (`entity_core.utils.ecf.is_zero_hash`), but the SDK sends the full-width
#: form: it is self-describing, and an empty bstr on the wire is
#: indistinguishable from a field a buggy encoder dropped.
ZERO_HASH = b"\x00" * 33


@dataclass(frozen=True, slots=True)
class Entry:
    """One direct child, per the §3.3 Entry shape.

    All four fields are populated — that is the §3.3 conformance requirement,
    and it is the reason this type exists rather than the SDK handing back the
    raw ``system/tree/listing``. **The wire shape and the SDK shape differ**:
    the wire sends a *map* of ``name -> {hash?, has_children}``, where the name
    is the key and no entry carries its own path. §3.3 requires a flat list of
    entries each carrying ``name``, ``path``, ``content_hash`` and
    ``has_children``. Projecting one into the other is exactly the work an L1
    SDK is for, and every caller that skipped the SDK has been re-deriving the
    child's full path by hand.
    """

    name: str
    path: str
    content_hash: bytes | None
    has_children: bool


class EntityClient:
    """L1 operations against one namespace-addressable peer.

    Args:
        dispatcher: The cap-checked EXECUTE seam (``entity_core.sdk``). A
            ``HandlerContextDispatcher`` gives local dispatch; a
            ``ConnectionDispatcher`` gives cross-peer dispatch.
        local_peer_id: Whose namespace peer-relative paths resolve to (§2.5).
            Required, and deliberately not defaulted — a client that guesses
            this is the `none may assume the local peer's id` bug.
        emit_pathway: The local peer's emit pathway, when this client runs
            in-process. Supplying it enables the **Level 0** surface
            (:attr:`store`) and the local ``watch()`` backend. A client built
            over a ``Connection`` to a remote peer leaves it unset — per §2.7,
            L0 is *"for the peer owner's code"*, and there is no honest way to
            offer direct store access across a wire.
    """

    def __init__(
        self,
        dispatcher: Dispatcher,
        local_peer_id: str,
        *,
        emit_pathway: Any | None = None,
        peer: Any | None = None,
    ) -> None:
        if not local_peer_id:
            raise ValueError(
                "local_peer_id is required — peer-relative paths cannot be "
                "resolved without knowing whose namespace they mean (§2.5)"
            )
        self._dispatcher = dispatcher
        self._local_peer_id = local_peer_id
        self._store = (
            LocalStore(emit_pathway, local_peer_id)
            if emit_pathway is not None
            else None
        )
        # Held privately and never exposed. §11.6: "Direct access to the
        # underlying handler dispatch index MUST NOT be part of the SDK's
        # public API surface" — `register_handler` is the only mutation path
        # and the handle it returns is the only way back out, so there is no
        # `client.peer` accessor to reach `peer.handlers` through.
        self._peer = peer

    @classmethod
    def for_peer(cls, peer: Any, dispatcher: Dispatcher) -> EntityClient:
        """Build a client for an in-process ``peer``, L0 surface included."""
        return cls(
            dispatcher,
            peer.keypair.peer_id,
            emit_pathway=peer.emit_pathway,
            peer=peer,
        )

    @property
    def local_peer_id(self) -> str:
        return self._local_peer_id

    @property
    def store(self) -> LocalStore:
        """The **Level 0** surface — direct, local, no capability check (§6.5).

        Separate accessor by mandate: §6.5 requires the naming to carry the
        access-level boundary, and §2.7 names sharing method names across the
        two levels as the anti-pattern that hides it.

        Raises:
            RuntimeError: if this client has no local peer. L0 is local-only
                by construction, not by policy — see :mod:`entity_sdk.store`.
        """
        if self._store is None:
            raise RuntimeError(
                "no Level 0 surface: this client was built without an "
                "emit_pathway, so it has no local peer. L0 is direct store "
                "access and cannot cross a wire (§2.7); use the dispatched "
                "L1 operations instead."
            )
        return self._store

    @property
    def has_local_store(self) -> bool:
        """Whether :attr:`store` is available, without provoking the raise."""
        return self._store is not None

    # -- §11.6 dynamic handler registration ----------------------------------

    async def register_handler(
        self, spec: HandlerSpec, body: HandlerBody,
    ) -> HandlerRegistration:
        """Register a language-native handler — §11.6, §16.1's last MUST row.

        Couples the tree declaration (interface + handler + optional self-grant)
        with the in-memory dispatch binding, in that order, with §11.6.4
        compensation if any step fails. The returned handle's ``close()``
        unregisters both sides and is idempotent; it is also an async context
        manager, which is the idiom §11.6.2 asks Python for.

        Local-only, and by construction rather than by policy — same shape as
        :attr:`store`. §11.6's V1.0 level is L0 direct writes whose *"caller is
        peer-owner code"*, and a client built over a ``Connection`` has no peer
        to write to. The name will not change when V2.0 moves the declarative
        half onto `system/handler:register`: §6.5's naming mandate is about one
        operation existing at two levels simultaneously, which this never does.

        Raises:
            BadRequest: 400 ``invalid_handler_spec``.
            Conflict: 409 ``pattern_collision``.
            InternalError: 500 ``partial_registration_failure``.
            RuntimeError: if this client has no local peer.
        """
        if self._peer is None:
            raise RuntimeError(
                "no local peer: this client was built over a connection, and "
                "§11.6 registration writes tree entities and binds a "
                "language-native callable — neither crosses a wire. Register "
                "on the peer that will run the body."
            )
        return await register_handler(self._peer, spec, body)

    def resolve(self, path: str) -> ResolvedPath:
        """Resolve ``path`` against this client's local peer (§2.5)."""
        return resolve(path, self._local_peer_id)

    # -- §4.1 the dispatch primitive -----------------------------------------

    async def execute(
        self,
        target: str,
        operation: str,
        params: dict[str, Any] | None = None,
        *,
        resource_targets: list[str] | None = None,
        included: list[dict[str, Any]] | None = None,
        peer_id: str | None = None,
    ) -> Any:
        """Dispatch ``operation`` at ``target`` and return the result (§4.1).

        Raises the typed §12 exception on a non-2xx status. This is the escape
        hatch for handlers the SDK has no typed wrapper for — it is a supported
        surface, not a workaround, because §3.6-3.9 explicitly say *"SDKs reach
        them via the standard handler-dispatch primitive; typed wrappers are
        MAY-tier convenience."*

        Args:
            target: A handler pattern (``system/registry``) **or** an entity
                path (``docs/intro``). The two are not distinguished here and
                need not be: V7 §6.6 resolves a dispatch target by
                longest-prefix walk, so a path reaches whichever handler is
                registered above it. Resolved through §2.5 like any other path,
                so ``/{them}/system/registry`` dispatches at *their* peer.
            included: Entities to bundle into the request envelope (V7 §3.3).
                Keyed by content hash for the caller — a handler resolving a
                hash reference out of ``included`` needs the map, and making
                every caller build it is how the key ends up computed two
                different ways.
        """
        # Resolve first, then override the peer. Building the ResolvedPath
        # straight from `peer_id` + a stripped target would turn an absolute
        # `/peer-b/x` into the relative path `peer-b/x` under `peer_id` — an
        # explicit peer argument should redirect the dispatch, not corrupt the
        # path it carries.
        resolved = self.resolve(target)
        if peer_id is not None:
            resolved = ResolvedPath(peer_id, resolved.relative)
        return await self._raw(
            uri=f"entity://{resolved.peer_id}/{resolved.relative}",
            operation=operation,
            params=params,
            resource_targets=resource_targets,
            included=included,
            path=resolved.relative,
        )

    async def _raw(
        self,
        *,
        uri: str,
        operation: str,
        params: dict[str, Any] | None,
        resource_targets: list[str] | None,
        path: str,
        included: list[dict[str, Any]] | None = None,
    ) -> Any:
        response = await self._dispatcher.execute(
            ExecuteRequest(
                uri=uri,
                operation=operation,
                params=params,
                resource_targets=resource_targets,
                included=_by_hash(included) if included else None,
            )
        )
        raise_for_status(
            response.status, response.result, path=path, operation=operation
        )
        return response.result

    async def _tree(
        self,
        target: ResolvedPath,
        operation: str,
        request_type: str,
        data: dict[str, Any],
    ) -> Any:
        """Dispatch a tree operation with the path in ``resource.targets``.

        The typed params entity still carries ``path`` as well: the handler
        prefers the resource target, and the params copy is the sanctioned
        fallback (V7 §3.2) that keeps the request self-describing for a peer
        that logs or forwards it.
        """
        return await self._raw(
            uri=target.uri(TREE_PATTERN),
            operation=operation,
            params={"type": request_type, "data": {"path": target.relative, **data}},
            resource_targets=[target.relative],
            path=target.relative,
        )

    # -- §3.1 get ------------------------------------------------------------

    async def get(self, path: str) -> dict[str, Any] | None:
        """The entity at ``path``, or ``None`` if no binding exists (§3.1).

        ``None`` rather than an exception for the missing case is the spec's
        own signature (*"Returns: The entity at path, or null"*) — §3.1 lists
        403 and 500 as its errors and pointedly not 404. Use :meth:`has` when
        only existence matters; it does not transfer the entity.
        """
        target = self.resolve(path)
        try:
            return await self._tree(target, "get", "system/tree/get-request", {})
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is the 404
            from entity_sdk.errors import NotFound

            if isinstance(exc, NotFound):
                return None
            raise

    # -- §3.2 put / put_cas --------------------------------------------------

    async def put(self, path: str, type: str, data: Any) -> bytes:  # noqa: A002
        """Store an entity at ``path`` unconditionally; return its hash (§3.2).

        ``expected_hash`` is **absent** from the wire request — the first row of
        the §3.2 v7.50 table. Use :meth:`put_cas` for the conditional forms.
        """
        return await self._put(path, type, data, cas=False, expected_hash=None)

    async def put_cas(
        self, path: str, type: str, data: Any, expected_hash: bytes | None  # noqa: A002
    ) -> bytes:
        """Conditional put (§3.2).

        ``expected_hash=None`` is the **create-only** sentinel: the SDK
        translates it to V7's zero-hash on the wire, which the peer reads as
        *"succeeds only if the path is currently unbound."* That translation is
        a MUST — a language-native null must not reach the wire as an absent
        field, or create-only silently becomes unconditional.

        Raises:
            Conflict: 409, if the current binding does not match.
        """
        return await self._put(
            path,
            type,
            data,
            cas=True,
            expected_hash=ZERO_HASH if expected_hash is None else expected_hash,
        )

    async def _put(
        self,
        path: str,
        type: str,  # noqa: A002
        data: Any,
        *,
        cas: bool,
        expected_hash: bytes | None,
    ) -> bytes:
        target = self.resolve(path)
        # §3.2's signature IS the construction step: `put(path, type, data) →
        # hash` takes an unhashed payload and returns a content hash, and the
        # SDK cannot return a hash it did not compute. So the entity is
        # constructed *here*, before anything reaches the wire (0.8.2.11 §6.3;
        # SDK-OPERATIONS §3.2, normative since the same fold).
        #
        # This used to send `{"type": type, "data": data}` — two keys — and the
        # peer authored the third back. That is a compensating pair inside one
        # tree: our own round-trip was perfect and our whole suite was blind to
        # it, because the lenient peer and the stripping SDK were both ours.
        # It breaks only across a seat boundary, which is where it surfaced:
        # this client could not `put` to a go peer at all.
        #
        # The hash is authored under the process-global format, which is what
        # the peer's late authoring arm used, so no hash on any existing path
        # moves. §4.5a's connection-bound authoring would use the connection's
        # negotiated `active_hash_format` instead — not read here because the
        # `Dispatcher` Protocol is `execute` and nothing else, and widening it
        # is a tier-boundary change for a case the receipt path already covers:
        # validation reads the claimed hash's own leading format byte, so a
        # default-format hash verifies on a connection negotiated to anything
        # the peer supports.
        payload: dict[str, Any] = {"entity": Entity(type=type, data=data).to_dict()}
        if cas:
            payload["expected_hash"] = expected_hash
        result = await self._tree(
            target, "put", "system/tree/put-request", payload
        )
        return _extract_hash(result)

    # -- §3.3 list -----------------------------------------------------------

    async def list(self, prefix: str) -> list[Entry]:  # noqa: A003
        """Direct children of ``prefix`` (§3.3). Single-level, not recursive.

        Returns ``[]`` when the prefix has no children. Ordering is
        implementation-defined per §3.3; this returns them sorted by name so
        the same tree lists the same way twice — the wire map has no order, and
        an SDK that passes dict iteration order through makes every caller's
        output subtly unstable.
        """
        target = self.resolve(prefix)
        if not target.is_listing:
            target = ResolvedPath(target.peer_id, target.relative + "/")
        listing = await self._tree(target, "get", "system/tree/get-request", {})
        return _project_listing(listing, target)

    # -- §3.4 remove ---------------------------------------------------------

    async def remove(self, path: str) -> None:
        """Unbind ``path`` (§3.4). The entity remains in the content store.

        **Idempotent: removing an unbound path succeeds.** §3.4 lists 404 and
        then says *"implementations MAY silently succeed"* — which makes the
        missing-binding case a genuine cross-peer coin flip. This peer's tree
        handler silently succeeds; another conformant peer may 404.

        **A MAY is nondeterminism the SDK absorbs, not nondeterminism it
        forwards.** If ``remove`` passed the peer's choice through, the same
        caller code would raise against one peer and not against another, and
        the bug would surface only after someone pointed it at a second
        implementation — the exact class of defect this repo exists to catch.
        So the permissive branch is chosen once, here, and every peer looks the
        same from above. Callers who need "did it exist?" have :meth:`has`,
        which answers that question without racing the delete.

        A put with no ``entity`` is the tree handler's own unbind form (§6.3),
        which keeps remove on the same handler and the same resource target as
        get and put — one capability check to reason about, not two.
        """
        target = self.resolve(path)
        try:
            await self._tree(
                target, "put", "system/tree/put-request", {"entity": None}
            )
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is the 404
            from entity_sdk.errors import NotFound

            if isinstance(exc, NotFound):
                return
            raise

    # -- §3.5 has ------------------------------------------------------------

    async def has(self, path: str) -> bool:
        """Whether a binding exists at ``path`` (§3.5).

        §3.5 permits ``get(path) != null``, but that transfers the whole entity
        to answer a yes/no. This uses the tree handler's ``mode: "hash"``, which
        returns only the content hash — same answer, bounded response size.
        """
        target = self.resolve(path)
        try:
            await self._tree(
                target, "get", "system/tree/get-request", {"mode": "hash"}
            )
        except Exception as exc:  # noqa: BLE001 - re-raised unless it is the 404
            from entity_sdk.errors import NotFound

            if isinstance(exc, NotFound):
                return False
            raise
        return True

    # -- §6.1-6.2 watch / unwatch --------------------------------------------

    def watch(self, pattern: str) -> ChangeStream:
        """Stream changes matching ``pattern`` (§6.1).

        Two pattern forms only — an exact path, or a trailing ``/*`` prefix.
        Anything else raises :class:`~entity_sdk.errors.BadRequest` (400), which
        is what §6.1 assigns to invalid pattern syntax.

        ``watch()`` is backend-agnostic by design: §6 says it *"MAY be powered
        by the subscription extension …, the raw emit pathway event stream …,
        or polling"*, and that *"the backend choice is transparent to the
        application."* This implementation uses the **local emit pathway**,
        which needs no extension and is therefore available on a minimal peer.

        The consequence to be honest about: an emit-pathway watch observes the
        **local tree**, which includes writes into ``/{them}/…`` as remote data
        is materialized locally, but it is not itself a cross-peer
        subscription. For cross-peer reactivity with deliver tokens, rate
        limits and redirect, dispatch to ``system/subscription`` directly —
        §6 points there too, and `SDK-EXTENSION-OPERATIONS` §3 is its contract.

        Returns:
            An async-iterable :class:`~entity_sdk.events.ChangeStream` yielding
            §6.1 ``ChangeEvent``. Cancel with :meth:`unwatch`, ``async with``,
            or by dropping it (§6.2 SHOULD auto-cancel).

        Raises:
            BadRequest: 400, invalid pattern syntax.
            RuntimeError: if this client has no local peer to observe.
        """
        validate_watch_pattern(pattern)
        if self._store is None:
            raise RuntimeError(
                "watch() has no backend: this client was built without an "
                "emit_pathway. A remote-only client must dispatch to "
                "system/subscription for cross-peer change notification."
            )
        # Narrow shape: §6.1 promises three fields, and the L0 surface is where
        # the fourth is on offer.
        return self._store.open_change_stream(pattern, wide=False)

    def unwatch(self, handle: ChangeStream) -> None:
        """Cancel a :meth:`watch` stream (§6.2). Idempotent.

        §6.2 says implementations SHOULD auto-cancel on drop and that explicit
        unwatch MUST also be available. Both work; this is the explicit one,
        and it is the reliable one — ``__del__`` timing is not guaranteed.
        """
        handle.unwatch()

    # -- L3 query builder (SDK-EXTENSION-OPERATIONS §6) -----------------------

    def query(self) -> "QueryBuilder":
        """Start a query (`SDK-EXTENSION-OPERATIONS` §6's L3 builder).

        A method rather than a property, because §6 spells it ``peer.query``
        but a property returning fresh mutable state reads as a field and
        invites reuse of a half-built query across two call sites::

            settings = await (client.query()
                .type("app/state/setting")
                .field("category", eq="display")
                .limit(50)
                .find())

        Nothing dispatches until :meth:`~entity_sdk.query.QueryBuilder.find` or
        :meth:`~entity_sdk.query.QueryBuilder.count`.
        """
        from entity_sdk.query import QueryBuilder

        return QueryBuilder(self)

    # -- L3 revision surface (SDK-EXTENSION-OPERATIONS §4) --------------------

    def revision(self, prefix: str) -> "RevisionClient":
        """Revision operations bound to ``prefix`` (`EXTENSION-REVISION` §4).

        Every revision operation is prefix-scoped, so the prefix is bound once
        rather than repeated at nineteen call sites::

            rev = client.revision("project/")
            await rev.commit()
            state = await rev.status()

        The handle holds no state beyond the prefix and this client, so it is
        cheap to make and safe to keep.
        """
        from entity_sdk.revision import RevisionClient

        return RevisionClient(self, prefix)


def content_hash(type: str, data: Any) -> bytes:  # noqa: A002
    """The content hash of an entity, per V7 §1.2.

    ``SHA256(ECF({type, data}))`` with format code ``0x00`` — flat
    ``0x00 ‖ digest``, 33 bytes.

    **This exists because hashing the wrong thing is the single most-missed
    interop invariant in this stack.** The digest covers ``{type, data}`` and
    *nothing else* — never ``uri``, never ``content_hash`` — and it is computed
    over ECF (deterministic CBOR), never JSON. Every caller that assembles the
    hashable dict by hand is one absent-minded extra key away from a hash that
    disagrees with every other implementation, and the disagreement shows up as
    a cross-impl mismatch rather than as a local error.

    So: one function, and callers stop building the dict.
    """
    from entity_core.protocol.entity import Entity

    return Entity(type=type, data=data).compute_hash()


def _by_hash(entities: list[dict[str, Any]]) -> dict[bytes, dict[str, Any]]:
    """Key envelope-``included`` entities by their content hash (V7 §3.3).

    The hash is computed over ``{type, data}`` only — never over ``uri`` or
    ``content_hash`` — which is the repo's single most-missed interop
    invariant. Computing it here once means a caller bundling an identity and
    a signature cannot key one of them a different way from the other.
    """
    from entity_core.protocol.entity import Entity

    out: dict[bytes, dict[str, Any]] = {}
    for raw in entities:
        entity = Entity(type=raw["type"], data=raw["data"])
        out[entity.compute_hash()] = raw
    return out


def _extract_hash(result: Any) -> bytes:
    """Pull the content hash out of a ``system/tree/put-result``."""
    if isinstance(result, dict):
        data = result.get("data")
        if isinstance(data, dict):
            for key in ("hash", "content_hash"):
                value = data.get(key)
                if isinstance(value, (bytes, bytearray)):
                    return bytes(value)
    raise ValueError(f"put returned no content hash: {result!r}")


def _project_listing(listing: Any, target: ResolvedPath) -> list[Entry]:
    """Project a ``system/tree/listing`` onto the §3.3 Entry shape.

    The wire form is ``data.entries: {name -> {hash?, has_children}}``. §3.3
    requires a list of entries each carrying all four fields, so ``name`` comes
    from the map key and ``path`` is reconstructed against the listing's own
    prefix — never against the local peer, which is the `/{them}/…` trap.
    """
    if not isinstance(listing, dict):
        return []
    data = listing.get("data")
    if not isinstance(data, dict):
        return []
    entries = data.get("entries")
    if not isinstance(entries, dict):
        return []

    out: list[Entry] = []
    for name, raw in entries.items():
        if not isinstance(name, str):
            continue
        info = raw if isinstance(raw, dict) else {}
        content_hash = info.get("hash")
        out.append(
            Entry(
                name=name,
                path=target.child(name).absolute,
                content_hash=(
                    bytes(content_hash)
                    if isinstance(content_hash, (bytes, bytearray))
                    else None
                ),
                has_children=bool(info.get("has_children", False)),
            )
        )
    out.sort(key=lambda e: e.name)
    return out
