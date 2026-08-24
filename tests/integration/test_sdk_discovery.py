"""Discovery helpers — `SDK-OPERATIONS` v0.8 §9, against a real peer.

A peer built with `with_all_handlers()` publishes real manifests and real type
definitions into its tree, so these run against the genuine article rather than
seeded fixtures. That matters for §9.2 in particular: the storage shape is a map
and the typed output is a list, and only real stored entities prove the
projection reads the shape the peer actually writes.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.sdk import HandlerContextDispatcher

from entity_sdk import (
    EntityClient,
    FieldInfo,
    HandlerInfo,
    OperationInfo,
    TypeInfo,
    discover_handlers,
    discover_types,
    dispatch_prefix,
)

BLANKET = {
    "grants": [
        {
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }
    ]
}


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


@pytest.fixture
def client(peer) -> EntityClient:
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=BLANKET,
        caller_capability=BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )
    return EntityClient.for_peer(peer, HandlerContextDispatcher(ctx))


# ---------------------------------------------------------------------------
# §9.1 — pattern is advertisement, not a dispatch URI
# ---------------------------------------------------------------------------


class TestDispatchPrefix:
    def test_trailing_glob_is_stripped(self):
        assert dispatch_prefix("system/type/constraint/*") == "system/type/constraint"

    def test_a_literal_pattern_is_unchanged(self):
        assert dispatch_prefix("system/tree") == "system/tree"

    def test_an_interior_star_is_not_touched(self):
        """Only a TRAILING `/*` is the advertisement convention (V7 §6.6)."""
        assert dispatch_prefix("system/*/thing") == "system/*/thing"

    def test_bare_star_is_not_a_trailing_glob(self):
        assert dispatch_prefix("*") == "*"

    async def test_dispatching_to_a_raw_glob_pattern_really_does_fail(self, client):
        """Pins the failure `dispatch_prefix` exists to prevent.

        An EXECUTE at a pattern ending `/*` addresses a literal segment named
        `*`. Asserting that this fails is what makes the helper more than
        decoration — and the failure reads like a missing handler rather than a
        malformed URI, which is why callers get it wrong.
        """
        from entity_sdk.errors import EntityError

        with pytest.raises(EntityError):
            await client.execute("system/type/constraint/*", "validate", {})


# ---------------------------------------------------------------------------
# §9.1 discover_handlers
# ---------------------------------------------------------------------------


class TestDiscoverHandlers:
    async def test_finds_the_standard_handlers(self, client):
        handlers = await discover_handlers(client)
        patterns = {h.pattern for h in handlers}

        assert handlers, "a peer with all handlers advertises some"
        for expected in (
            "system/tree",
            "system/query",
            "system/subscription",
            "system/revision",
            "system/capability",
        ):
            assert expected in patterns, f"{expected} not advertised"

    async def test_a_real_handler_advertises_a_glob_pattern(self, client):
        """§9.1's advertisement-vs-dispatch split is not hypothetical here.

        The content handler advertises `system/content/*` and the type
        constraint handler `system/type/constraint/*`. A consumer that built an
        EXECUTE target straight from `pattern` would address a literal `*`
        segment. This is the case `dispatch_prefix` exists for, measured on the
        handlers that actually ship.
        """
        by_pattern = {h.pattern: h for h in await discover_handlers(client)}

        content = by_pattern.get("system/content/*")
        assert content is not None, f"got {sorted(by_pattern)}"
        assert content.dispatch_prefix == "system/content"

        constraint = by_pattern.get("system/type/constraint/*")
        assert constraint is not None
        assert constraint.dispatch_prefix == "system/type/constraint"

    async def test_the_dispatch_prefix_actually_dispatches(self, client):
        """The stripped prefix reaches a handler; the raw pattern does not."""
        from entity_sdk.errors import EntityError, NotFound

        by_pattern = {h.pattern: h for h in await discover_handlers(client)}
        content = by_pattern["system/content/*"]

        with pytest.raises(EntityError):
            await client.execute(content.pattern, "get", {})

        # The stripped prefix resolves to the handler. The operation itself may
        # still fail on its params — what matters is that it is not a
        # handler-resolution failure, which is what the raw pattern produces.
        try:
            await client.execute(content.dispatch_prefix, "get", {})
        except NotFound:
            pytest.fail("the stripped dispatch prefix did not resolve to a handler")
        except EntityError:
            pass  # reached the handler; rejected on params. That is the point.

    async def test_entries_are_typed(self, client):
        handlers = await discover_handlers(client)
        assert all(isinstance(h, HandlerInfo) for h in handlers)
        assert all(isinstance(h.name, str) and h.name for h in handlers)

    async def test_operations_are_populated_and_typed(self, client):
        (tree,) = [h for h in await discover_handlers(client) if h.pattern == "system/tree"]
        assert tree.operations
        assert all(isinstance(o, OperationInfo) for o in tree.operations)

        names = {o.name for o in tree.operations}
        assert {"get", "put"} <= names

    async def test_operation_io_types_survive_the_projection(self, client):
        (tree,) = [h for h in await discover_handlers(client) if h.pattern == "system/tree"]
        (get,) = [o for o in tree.operations if o.name == "get"]
        assert get.output_type is not None

    async def test_ordering_is_stable(self, client):
        """§9.3 leaves ordering implementation-defined; we sort so it repeats."""
        first = [h.pattern for h in await discover_handlers(client)]
        second = [h.pattern for h in await discover_handlers(client)]
        assert first == second == sorted(first)

    async def test_handler_info_exposes_its_dispatch_prefix(self, client):
        for handler in await discover_handlers(client):
            assert not handler.dispatch_prefix.endswith("/*")

    async def test_scope_blocked_handlers_are_absent_not_an_error(self, peer):
        """§9.3: absence under capability scope is not signaled."""
        narrow = {
            "grants": [
                {
                    "handlers": {"include": ["*"]},
                    "resources": {"include": ["nothing/*"]},
                    "operations": {"include": ["*"]},
                }
            ]
        }
        ctx = HandlerContext(
            local_peer_id=peer.keypair.peer_id,
            remote_peer_id="test-remote",
            handler_grant=narrow,
            caller_capability=narrow,
            emit_pathway=peer.emit_pathway,
            _execute_dispatcher=peer._dispatch_local_execute,
        )
        scoped = EntityClient(HandlerContextDispatcher(ctx), peer.keypair.peer_id)

        from entity_sdk.errors import AuthorizationError

        try:
            handlers = await discover_handlers(scoped)
        except AuthorizationError:
            # A 403 on the listing itself is the other legitimate outcome —
            # what must NOT happen is a partial list presented as complete.
            return
        assert handlers == [], "out-of-scope handlers must not be listed"


# ---------------------------------------------------------------------------
# §9.2 discover_types — the map-to-list projection
# ---------------------------------------------------------------------------


class TestDiscoverTypes:
    async def test_finds_the_core_types(self, client):
        types = await discover_types(client)
        paths = {t.type_path for t in types}

        assert types
        assert "system/hash" in paths or "system/tree/listing" in paths, (
            f"expected core type definitions, got {sorted(paths)[:10]}"
        )

    async def test_entries_are_typed(self, client):
        types = await discover_types(client)
        assert all(isinstance(t, TypeInfo) for t in types)
        assert all(isinstance(f, FieldInfo) for t in types for f in t.fields)

    async def test_stored_map_becomes_an_output_list(self, client):
        """§9.2: `fields` is stored as Map<name, field-spec>, reported as a list.

        The two shapes are explicitly not interchangeable — the spec says
        writing the typed-output shape produces structurally invalid type
        entities. This asserts the read projection runs.
        """
        typed = {t.type_path: t for t in await discover_types(client)}
        listing = typed.get("system/tree/listing")
        assert listing is not None, "the tree listing type should be registered"

        names = [f.name for f in listing.fields]
        assert names == sorted(names), "field order is stable"
        assert {"path", "entries", "count", "offset"} <= set(names)

    async def test_optionality_survives_the_projection(self, client):
        typed = {t.type_path: t for t in await discover_types(client)}
        listing = typed["system/tree/listing"]
        (next_page,) = [f for f in listing.fields if f.name == "next_page"]
        assert next_page.optional is True

        (path,) = [f for f in listing.fields if f.name == "path"]
        assert path.optional is False

    async def test_structural_field_specs_are_not_reported_as_empty(self, client):
        """`map_of` / `array_of` fields have no scalar `type_ref`.

        §9.2's FieldInfo.type_ref is one string, but the stored alphabet is
        exactly-one-of type_ref / array_of / map_of / union_of / type_param.
        Emitting "" for every collection field would be lossy in a way a caller
        cannot detect.
        """
        typed = {t.type_path: t for t in await discover_types(client)}
        listing = typed["system/tree/listing"]
        (entries,) = [f for f in listing.fields if f.name == "entries"]
        assert entries.type_ref.startswith("map_of<")
        assert "system/tree/listing-entry" in entries.type_ref

    async def test_ordering_is_stable(self, client):
        first = [t.type_path for t in await discover_types(client)]
        second = [t.type_path for t in await discover_types(client)]
        assert first == second == sorted(first)


# ---------------------------------------------------------------------------
# §7 — the connection helper's shape
# ---------------------------------------------------------------------------


class TestConnectionHelper:
    def test_a_wire_client_has_no_level_0_surface(self):
        """§2.7: direct store access cannot cross a wire."""
        from entity_sdk import client_for_connection

        class FakeSession:
            remote_peer_id = "peer-remote"

        class FakeConnection:
            session = FakeSession()

        client = client_for_connection(FakeConnection())
        assert client.has_local_store is False
        with pytest.raises(RuntimeError, match="no Level 0 surface"):
            _ = client.store

    def test_paths_default_to_the_remote_namespace(self):
        """`ls docs/` against a dialed peer means THEIR docs/, not ours."""
        from entity_sdk import client_for_connection

        class FakeSession:
            remote_peer_id = "peer-remote"

        class FakeConnection:
            session = FakeSession()

        client = client_for_connection(FakeConnection())
        assert client.local_peer_id == "peer-remote"
        assert client.resolve("docs/x").peer_id == "peer-remote"

    def test_the_default_is_overridable(self):
        from entity_sdk import client_for_connection

        class FakeSession:
            remote_peer_id = "peer-remote"

        class FakeConnection:
            session = FakeSession()

        client = client_for_connection(FakeConnection(), local_peer_id="peer-me")
        assert client.resolve("docs/x").peer_id == "peer-me"
        assert client.resolve("/peer-remote/docs/x").peer_id == "peer-remote"
