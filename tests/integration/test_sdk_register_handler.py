"""`SDK-OPERATIONS` §11.6 / §12.5 — dynamic handler registration.

The last row of §16.1's MUST list: *"`register_handler` primitive with
tree-paired writes, handle lifecycle, collision semantics, compensation."* Each
class below is one of those four, plus §12.5's pinned code strings.

**Why the tests drive real dispatch rather than inspecting the index.** §11.6.5's
invariant is that a callback reachable by dispatch is tree-declared and one that
is not is absent from the index — so the assertions that matter are *does an
EXECUTE reach the body* and *is the entity there for a discovery read*, not *is
there a row in a list*. A test that reads the registry back is testing the thing
it just called.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.sdk import HandlerContextDispatcher
from entity_sdk import EntityClient, HandlerSpec, OperationSpec
from entity_sdk.errors import BadRequest, Conflict, InternalError
from entity_sdk.handlers import (
    CODE_INVALID_HANDLER_SPEC,
    CODE_PARTIAL_REGISTRATION_FAILURE,
    CODE_PATTERN_COLLISION,
)

_BLANKET = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "resources": {"include": ["*"]},
        "operations": {"include": ["*"]},
    }]
}


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


@pytest.fixture
def client(peer):
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=peer.keypair.peer_id,
        handler_grant=_BLANKET,
        caller_capability=_BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
        handler_pattern="*",
        keypair=peer.keypair,
    )
    return EntityClient.for_peer(peer, HandlerContextDispatcher(ctx))


def _spec(pattern="app/greeter", **kw):
    kw.setdefault("name", "Greeter")
    kw.setdefault("operations", [OperationSpec("greet")])
    return HandlerSpec(pattern=pattern, **kw)


async def _greet(path, operation, params, ctx):
    return {"status": 200, "result": {"type": "app/greeting", "data": {"op": operation}}}


def _bound(peer, path):
    return peer.entity_tree.get(peer.entity_tree.normalize_uri(path))


def _entity(peer, path):
    h = _bound(peer, path)
    return None if h is None else peer.content_store.get(bytes(h))


# ===========================================================================
# §11.6.1 — the paired writes, and their order
# ===========================================================================


class TestPairedWrites:
    @pytest.mark.asyncio
    async def test_both_sides_land_and_the_body_is_reachable_by_dispatch(
        self, peer, client,
    ):
        """The whole point of the primitive: the declaration and the binding,
        coupled. Either alone is a lie — a tree entry with no body 404s, and a
        dispatch entry with no tree entry is a handler nobody can find."""
        await client.register_handler(_spec(), _greet)

        assert _bound(peer, "system/handler/app/greeter") is not None
        assert _bound(peer, "app/greeter") is not None

        r = await client.execute("app/greeter", "greet")
        assert r["data"]["op"] == "greet"

    @pytest.mark.asyncio
    async def test_the_interface_carries_pattern_name_and_operations(
        self, peer, client,
    ):
        """§11.6.1 — the interface is *"the handler's public contract and single
        source of truth for its external description"*, and it is what
        `discover_handlers()` reads."""
        # NOTE on the write ORDER, since no test here can see it: §11.6.1's
        # "tree first, dispatch index second" exists to close a window in which
        # dispatch reaches a handler the tree does not declare. This peer
        # cannot exhibit that window — V7 §6.2 already makes the handler entity
        # and its grant dispatch prerequisites, so an index-first
        # implementation would 403 rather than serve. The ordering is still
        # implemented as written, because the rule is cross-impl and a peer
        # that relaxes §6.2 later would inherit the window silently.
        await client.register_handler(
            _spec(operations=[
                OperationSpec("greet", input_type="app/greet-request",
                              output_type="app/greeting"),
                OperationSpec("wave"),
            ]),
            _greet,
        )
        iface = _entity(peer, "system/handler/app/greeter")
        assert iface.type == "system/handler/interface"
        assert iface.data["pattern"] == "app/greeter"
        assert iface.data["name"] == "Greeter"
        # A MAP keyed by operation name — the entity's shape (V7 §3.7), not
        # §11.6's `[OperationSpec]` array. See SA-PY-18.
        assert set(iface.data["operations"]) == {"greet", "wave"}
        assert iface.data["operations"]["greet"] == {
            "input_type": "app/greet-request", "output_type": "app/greeting",
        }
        # Absent optionals are OMITTED, not written as null: the entity is
        # content-addressed, so those are different bytes.
        assert iface.data["operations"]["wave"] == {}

    @pytest.mark.asyncio
    async def test_the_interface_does_not_carry_security_configuration(
        self, peer, client,
    ):
        """§11.6.1 — `max_scope` / `internal_scope` live on the **handler**
        entity, *"so it is not exposed to remote peers through discovery."*"""
        await client.register_handler(
            _spec(internal_scope=[{"handlers": {"include": ["system/tree"]}}]),
            _greet,
        )
        iface = _entity(peer, "system/handler/app/greeter")
        handler = _entity(peer, "app/greeter")

        assert "internal_scope" not in iface.data
        assert "max_scope" not in iface.data
        assert handler.data["internal_scope"] == [
            {"handlers": {"include": ["system/tree"]}}
        ]

    @pytest.mark.asyncio
    async def test_the_handler_entity_references_the_interface_by_path(
        self, peer, client,
    ):
        await client.register_handler(_spec(), _greet)
        handler = _entity(peer, "app/greeter")
        assert handler.type == "system/handler"
        assert handler.data["interface"] == "system/handler/app/greeter"
        assert _entity(peer, handler.data["interface"]) is not None

    @pytest.mark.asyncio
    async def test_no_internal_scope_means_an_empty_grant_never_a_wildcard(
        self, peer, client,
    ):
        """§11.6.3 `[MUST NOT]` — *"The SDK MUST NOT silently default to a
        wildcard grant — that is the capability equivalent of running as
        root."* This peer's own bootstrap path does exactly that for built-in
        handlers (`create_full_access_grant()` when no `max_scope`), so the
        assertion is not idle.

        The grant is **empty, not absent**, which departs from §11.6.1 step 3's
        *"if `internal_scope` is non-null"* — see SA-PY-20 and the test below.
        """
        reg = await client.register_handler(_spec(), _greet)
        grant = _entity(peer, reg.grant_path)
        assert grant.data["grants"] == []

    @pytest.mark.asyncio
    async def test_a_null_scope_handler_is_dispatchable_and_cannot_call_out(
        self, peer, client,
    ):
        """SA-PY-20 — the reason step 3 is not followed literally.

        V7 §6.2 makes the handler's own grant a **dispatch prerequisite** in
        this peer: the dispatcher fails closed with 403 when it is missing.
        Writing no grant therefore yields a handler that is declared, indexed,
        discoverable, and answers 403 to everyone — registration succeeds and
        the handler can never run. An empty grant gives exactly the semantics
        §11.6.3 *describes*: dispatchable, authorizing no outbound call.

        Both halves are asserted, because either alone is satisfiable by the
        wrong implementation — a wildcard grant passes the first, and no grant
        at all passes the second.
        """
        outbound = []

        async def body(path, operation, params, ctx):
            # `ctx.execute` RETURNS an ExecuteResult; it does not raise. A test
            # that wraps it in try/except passes against a peer that authorizes
            # everything, which is exactly the bug it is meant to catch.
            r = await ctx.execute("system/tree", "list", {"data": {"path": ""}})
            outbound.append(r.status)
            return {"status": 200, "result": {"type": "primitive/any", "data": {}}}

        await client.register_handler(_spec(), body)
        r = await client.execute("app/greeter", "greet")
        assert r is not None, "a null-scope handler was undispatchable"
        assert outbound == [403], (
            f"a handler with no declared internal_scope reached system/tree "
            f"(status {outbound})"
        )

    @pytest.mark.asyncio
    async def test_a_declared_scope_mints_a_signed_self_grant(self, peer, client):
        """§11.6.1 step 3 — *"The tree binding — not the content-store put — is
        the declaration."* So the assertion is on the binding, and on the
        signature being resolvable at the §3.5 invariant pointer, since a grant
        whose signature does not resolve fails validation at dispatch."""
        scope = [{"handlers": {"include": ["system/tree"]},
                  "resources": {"include": ["app/*"]},
                  "operations": {"include": ["get"]}}]
        reg = await client.register_handler(_spec(internal_scope=scope), _greet)

        assert reg.grant_path == "system/capability/grants/app/greeter"
        grant = _entity(peer, reg.grant_path)
        assert grant.data["grants"] == scope
        assert grant.data["granter"] == grant.data["grantee"]

        from entity_core.capability.grant_signing import grant_signature_path

        sig = _entity(peer, grant_signature_path(grant.compute_hash()))
        assert sig is not None and sig.type == "system/signature"

    @pytest.mark.asyncio
    async def test_types_are_installed_before_the_interface(self, peer, client):
        await client.register_handler(
            _spec(types={"app/greeting": {"name": "app/greeting",
                                          "fields": {"text": {"type_ref": "primitive/string"}}}}),
            _greet,
        )
        t = _entity(peer, "system/type/app/greeting")
        assert t is not None and t.type == "system/type"
        assert t.data["name"] == "app/greeting"

    @pytest.mark.asyncio
    async def test_the_authoritative_pattern_is_the_specs(self, peer, client):
        """§11.6.1 — *"The authoritative pattern is the one passed in
        `HandlerSpec.pattern`, not any pattern declared inside the body."*

        Trivially true for a bare callable, and asserted anyway because the
        body here carries a `pattern` attribute that disagrees, which is the
        shape a class-based body would have.
        """
        _greet.pattern = "app/imposter"  # type: ignore[attr-defined]
        try:
            await client.register_handler(_spec(), _greet)
            assert _bound(peer, "app/greeter") is not None
            assert _bound(peer, "app/imposter") is None
        finally:
            del _greet.pattern  # type: ignore[attr-defined]


# ===========================================================================
# §11.6.1 — collision, and §12.5's code
# ===========================================================================


class TestCollision:
    @pytest.mark.asyncio
    async def test_a_second_registration_at_one_pattern_is_409(self, client):
        """*"Silent overwrite is not permitted."* The status and the code are
        both asserted: §12.5 pins the string across SDKs, so a peer answering
        409 with its own wording is not conformant."""
        await client.register_handler(_spec(), _greet)
        with pytest.raises(Conflict) as e:
            await client.register_handler(_spec(name="Impostor"), _greet)
        assert e.value.status == 409
        assert e.value.code == CODE_PATTERN_COLLISION

    @pytest.mark.asyncio
    async def test_the_refused_registration_does_not_overwrite(self, peer, client):
        """The negative half. A peer that answers 409 and writes anyway passes
        a status-only check."""
        await client.register_handler(_spec(), _greet)
        with pytest.raises(Conflict):
            await client.register_handler(_spec(name="Impostor"), _greet)
        assert _entity(peer, "system/handler/app/greeter").data["name"] == "Greeter"

    @pytest.mark.asyncio
    async def test_a_tree_declaration_alone_also_collides(self, peer, client):
        """§11.6.1 checks *"either in the dispatch index or the tree."* The
        tree-only case is the one that matters: it is the state a peer restart
        leaves behind (§11.6.6), and it is the one an index-only check misses.

        **This is also SA-PY-19**: §11.6.6 recommends applications re-register
        on startup and calls the tree writes *"idempotent if the entries
        already exist"* — which this MUST refuses. §11.6.1 is the MUST, so it
        wins; the contradiction is filed rather than resolved locally.
        """
        from entity_core.protocol.entity import Entity
        from entity_core.storage.emit import EmitContext

        peer.emit_pathway.emit(
            "app/survivor",
            Entity(type="system/handler", data={"interface": "system/handler/app/survivor"}),
            EmitContext.bootstrap(),
        )
        with pytest.raises(Conflict) as e:
            await client.register_handler(_spec("app/survivor"), _greet)
        assert e.value.code == CODE_PATTERN_COLLISION

    @pytest.mark.asyncio
    async def test_replacement_is_close_then_register(self, peer, client):
        """*"Replacement requires explicit close followed by `register_handler`."*"""
        reg = await client.register_handler(_spec(), _greet)
        await reg.close()
        await client.register_handler(_spec(name="Second"), _greet)
        assert _entity(peer, "system/handler/app/greeter").data["name"] == "Second"


# ===========================================================================
# §11.6.2 — handle lifecycle
# ===========================================================================


class TestHandleLifecycle:
    @pytest.mark.asyncio
    async def test_close_unregisters_both_sides(self, peer, client):
        reg = await client.register_handler(
            _spec(internal_scope=[{"handlers": {"include": ["system/tree"]}}]), _greet,
        )
        await reg.close()

        assert _bound(peer, "app/greeter") is None
        assert _bound(peer, "system/handler/app/greeter") is None
        assert _bound(peer, "system/capability/grants/app/greeter") is None
        assert peer.handlers.find_exact("app/greeter") is None

    @pytest.mark.asyncio
    async def test_dispatch_stops_at_close(self, client):
        """After close, an EXECUTE to the pattern no longer reaches the body.

        **Not the discriminating test for the ordering**, and saying so is the
        point: removing the tree entries alone already stops dispatch here,
        because V7 §6.2 makes the handler grant and the handler entity dispatch
        prerequisites. So this passes against an implementation that forgets to
        unregister the index. `test_close_unregisters_both_sides` is what
        catches that (mutation-checked), and this one is here for the
        caller-visible behaviour rather than for the invariant.
        """
        reg = await client.register_handler(_spec(), _greet)
        assert (await client.execute("app/greeter", "greet"))["data"]["op"] == "greet"
        await reg.close()
        from entity_sdk.errors import EntityError

        with pytest.raises(EntityError):
            await client.execute("app/greeter", "greet")

    @pytest.mark.asyncio
    async def test_close_is_idempotent(self, client):
        """`[MUST]` — *"Repeated close is a no-op."*"""
        reg = await client.register_handler(_spec(), _greet)
        await reg.close()
        await reg.close()
        await reg.close()
        assert reg.closed is True

    @pytest.mark.asyncio
    async def test_the_scoped_construct_is_async_with(self, peer, client):
        """§11.6.2 `[MUST]` — the SDK provides both an explicit close **and**
        *"the most-idiomatic scoped construct the language has"*, which the
        spec's own cross-language table names for Python as ``async with``."""
        async with await client.register_handler(_spec(), _greet) as reg:
            assert _bound(peer, "app/greeter") is not None
            assert reg.closed is False
        assert _bound(peer, "app/greeter") is None

    @pytest.mark.asyncio
    async def test_the_scoped_construct_closes_on_an_exception(self, peer, client):
        """A scoped construct that only unwinds on the happy path is not one."""
        with pytest.raises(RuntimeError):
            async with await client.register_handler(_spec(), _greet):
                raise RuntimeError("body blew up")
        assert _bound(peer, "app/greeter") is None

    @pytest.mark.asyncio
    async def test_type_definitions_survive_close(self, peer, client):
        """§11.6.2 `[MUST]` — types *"are NOT removed — they have independent
        lifecycle and may be referenced by other handlers, queries, or remote
        peers."* Removing them would break a reader that never knew this
        handler existed."""
        reg = await client.register_handler(
            _spec(types={"app/greeting": {"name": "app/greeting", "fields": {}}}), _greet,
        )
        await reg.close()
        assert _bound(peer, "system/type/app/greeting") is not None

    @pytest.mark.asyncio
    async def test_there_is_no_gc_cleanup_path(self, peer, client):
        """§11.6.2 `[MUST NOT]` — *"The SDK MUST NOT rely on garbage collection
        or finalizers for correctness."* This peer has no finalizer at all:
        dropping the handle leaves the registration standing, which is the
        honest behaviour. A cleanup that only sometimes runs is harder to
        reason about than one that never does.
        """
        import gc

        await client.register_handler(_spec(), _greet)
        gc.collect()
        assert _bound(peer, "app/greeter") is not None
        assert not hasattr(
            __import__("entity_sdk.handlers", fromlist=["HandlerRegistration"])
            .HandlerRegistration, "__del__",
        )


# ===========================================================================
# §11.6.4 — partial-failure compensation
# ===========================================================================


class TestCompensation:
    @pytest.mark.asyncio
    async def test_a_failure_after_the_tree_writes_leaves_nothing_behind(
        self, peer, client, monkeypatch,
    ):
        """§11.6.4's worked example: interface OK, handler OK, grant FAILS →
        compensate both, return the error, **no handle** — so the caller knows
        registration failed entirely rather than partially."""
        import entity_core.capability.grant_signing as gs

        def boom(*a, **kw):
            raise OSError("signing device unplugged")

        monkeypatch.setattr(gs, "build_signed_handler_grant", boom)

        with pytest.raises(InternalError) as e:
            await client.register_handler(
                _spec(internal_scope=[{"handlers": {"include": ["*"]}}]), _greet,
            )
        assert e.value.status == 500
        assert e.value.code == CODE_PARTIAL_REGISTRATION_FAILURE

        assert _bound(peer, "system/handler/app/greeter") is None
        assert _bound(peer, "app/greeter") is None
        assert peer.handlers.find_exact("app/greeter") is None

    @pytest.mark.asyncio
    async def test_a_failure_at_the_dispatch_index_compensates_the_tree(
        self, peer, client, monkeypatch,
    ):
        """The ordering rule's own failure case. §11.6.1: *"If the dispatch
        index write fails after tree writes succeed, the SDK MUST compensate by
        removing the tree entries."*"""
        def boom(*a, **kw):
            raise RuntimeError("index full")

        monkeypatch.setattr(peer.handlers, "register", boom)

        with pytest.raises(InternalError):
            await client.register_handler(_spec(), _greet)
        assert _bound(peer, "app/greeter") is None
        assert _bound(peer, "system/handler/app/greeter") is None

    @pytest.mark.asyncio
    async def test_types_are_not_compensated(self, peer, client, monkeypatch):
        """§11.6.4 — *"Type definitions installed via `types` are NOT
        compensated — they have independent lifecycle."* Same rule as close,
        and the same reason."""
        def boom(*a, **kw):
            raise RuntimeError("index full")

        monkeypatch.setattr(peer.handlers, "register", boom)
        with pytest.raises(InternalError):
            await client.register_handler(
                _spec(types={"app/greeting": {"name": "app/greeting", "fields": {}}}),
                _greet,
            )
        assert _bound(peer, "system/type/app/greeting") is not None

    @pytest.mark.asyncio
    async def test_the_pattern_is_registrable_again_after_a_compensated_failure(
        self, client, monkeypatch,
    ):
        """The consequence that matters to a caller: a compensated failure must
        not leave a collision behind. Without it, one transient error makes the
        pattern permanently unusable until someone hand-edits the tree."""
        def boom(*a, **kw):
            raise RuntimeError("index full")

        monkeypatch.setattr(peer_handlers := peer_register_target(client), "register", boom)
        with pytest.raises(InternalError):
            await client.register_handler(_spec(), _greet)
        monkeypatch.undo()
        await client.register_handler(_spec(), _greet)  # no 409


def peer_register_target(client):
    """The peer's handler registry, reached the way a test may and the public
    API may not (§11.6 forbids exposing the dispatch index)."""
    return client._peer.handlers


# ===========================================================================
# §11.6 — spec validation, §12.5 codes
# ===========================================================================


class TestSpecValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("kwargs,why", [
        ({"pattern": ""}, "empty pattern"),
        ({"pattern": "/app/greeter"}, "leading slash"),
        ({"operations": []}, "empty operations"),
        ({"name": ""}, "empty name"),
        ({"operations": [OperationSpec("")]}, "unnamed operation"),
        ({"operations": [OperationSpec("greet"), OperationSpec("greet")]},
         "duplicate operation"),
    ])
    async def test_invalid_specs_are_400_with_the_pinned_code(
        self, client, kwargs, why,
    ):
        pattern = kwargs.pop("pattern", "app/greeter")
        with pytest.raises(BadRequest) as e:
            await client.register_handler(_spec(pattern, **kwargs), _greet)
        assert e.value.status == 400, why
        assert e.value.code == CODE_INVALID_HANDLER_SPEC, why

    @pytest.mark.asyncio
    async def test_nothing_is_written_by_a_refused_spec(self, peer, client):
        """Validation runs before any write — the check is that a 400 leaves
        no half-registration for the next caller to trip over."""
        with pytest.raises(BadRequest):
            await client.register_handler(_spec(operations=[]), _greet)
        assert _bound(peer, "system/handler/app/greeter") is None

    @pytest.mark.asyncio
    async def test_the_control_a_valid_spec_is_accepted(self, client):
        """Required beside the rejection rows: they pass trivially against an
        implementation that refuses everything."""
        reg = await client.register_handler(_spec(), _greet)
        assert reg.pattern == "app/greeter"


# ===========================================================================
# §11.6.3 — the body contract
# ===========================================================================


class TestBodyContract:
    @pytest.mark.asyncio
    async def test_the_body_receives_the_operation_and_params(self, client):
        seen = {}

        async def body(path, operation, params, ctx):
            seen.update(path=path, operation=operation, params=params)
            return {"status": 200, "result": {"type": "primitive/any", "data": {}}}

        await client.register_handler(
            _spec(operations=[OperationSpec("greet")]), body,
        )
        await client.execute("app/greeter", "greet", {"who": "world"})
        assert seen["operation"] == "greet"
        # The body sees the params exactly as the dispatcher hands them to a
        # bootstrap handler — no SDK-side reshaping, which is what §11.6.3's
        # "same handler contract" means in practice.
        assert seen["params"] == {"who": "world"}
        assert seen["path"].endswith("app/greeter")

    @pytest.mark.asyncio
    async def test_concurrent_dispatch_may_run_the_body_in_parallel(self, client):
        """§11.6.3 — *"The SDK does not guarantee serial invocation... Body
        implementers are responsible for their own synchronization."* Pinned as
        the documented non-guarantee rather than left to be discovered: a
        caller who assumes serialization writes a race, and §11.6.8's deferred
        `serial: bool` exists precisely because this bites subscription
        delivery.
        """
        overlap = asyncio.Event()
        entered = asyncio.Semaphore(0)

        async def body(path, operation, params, ctx):
            entered.release()
            await asyncio.wait_for(overlap.wait(), timeout=2)
            return {"status": 200, "result": {"type": "primitive/any", "data": {}}}

        await client.register_handler(_spec(), body)
        a = asyncio.create_task(client.execute("app/greeter", "greet"))
        b = asyncio.create_task(client.execute("app/greeter", "greet"))
        await entered.acquire()
        await entered.acquire()   # both bodies are in flight at once
        overlap.set()
        await asyncio.gather(a, b)

    @pytest.mark.asyncio
    async def test_cancellation_reaches_the_body(self, client):
        """§11.6.3 `[MUST]` — *"SDKs MUST propagate cancellation from the
        dispatch-level context to the handler body's runtime primitive."*

        In asyncio that is free: the body is awaited inside the dispatching
        task, so cancelling the caller raises `CancelledError` at the body's
        own await point. Free is not the same as verified — an SDK that ran the
        body in a detached task would satisfy every other test here and swallow
        cancellation silently.
        """
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def body(path, operation, params, ctx):
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return {"status": 200, "result": {"type": "primitive/any", "data": {}}}

        await client.register_handler(_spec(), body)
        task = asyncio.create_task(client.execute("app/greeter", "greet"))
        await asyncio.wait_for(started.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(cancelled.wait(), timeout=2)


# ===========================================================================
# The surface boundary
# ===========================================================================


class TestTheDispatchIndexIsNotPublic:
    def test_the_client_exposes_no_route_to_the_registry(self, client):
        """§11.6 `[MUST NOT]` — *"Direct access to the underlying handler
        dispatch index MUST NOT be part of the SDK's public API surface. The
        dispatch index is an internal implementation detail; the SDK primitive
        is the only public mutation path."*

        Enforced as an assertion about the public names rather than as a
        comment, because "we didn't add an accessor" is exactly the kind of
        property a later convenience method erases.
        """
        public = {n for n in dir(client) if not n.startswith("_")}
        assert "peer" not in public
        assert "handlers" not in public
        assert not any("registry" in n for n in public)

    @pytest.mark.asyncio
    async def test_a_connection_backed_client_cannot_register(self, peer):
        """Local-only by construction. §11.6's V1.0 caller is peer-owner code,
        and neither a tree write nor a callable binding crosses a wire — so the
        client raises instead of degrading, the same shape as `client.store`."""
        remote = EntityClient(
            HandlerContextDispatcher(HandlerContext(
                local_peer_id=peer.keypair.peer_id,
                remote_peer_id="someone-else",
                handler_grant=_BLANKET,
                caller_capability=_BLANKET,
                emit_pathway=peer.emit_pathway,
                handler_pattern="*",
            )),
            "some-remote-peer",
        )
        with pytest.raises(RuntimeError, match="no local peer"):
            await remote.register_handler(_spec(), _greet)
