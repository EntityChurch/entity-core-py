"""Integration tests for the query handler on a real peer.

Verifies that with_all_handlers() registers the query handler and
QueryExtension, and that find/count operations work end-to-end
through the peer's handler registry.
"""

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

from entity_handlers.query import QueryExtension


@pytest.fixture
def peer():
    """Build a peer with all standard handlers including query."""
    kp = Keypair.generate()
    return PeerBuilder().with_keypair(kp).with_all_handlers().build()


def _get_query_ext(peer) -> QueryExtension:
    """Extract the QueryExtension from a peer's extensions."""
    for ext_cfg in peer._extensions:
        ext = ext_cfg.extension if hasattr(ext_cfg, "extension") else ext_cfg
        if isinstance(ext, QueryExtension):
            return ext
    raise AssertionError("QueryExtension not found on peer")


def _make_ctx(peer) -> HandlerContext:
    """Create a HandlerContext wired to the peer's storage."""
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant={"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["*"]}}]},
        caller_capability={"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["*"]}}]},
        emit_pathway=peer.emit_pathway,
    )


def _seed(peer):
    """Store test entities."""
    ctx = EmitContext.bootstrap()
    peer.emit_pathway.emit("users/alice", Entity(type="app/user", data={"name": "alice", "city": "Seattle"}), ctx)
    peer.emit_pathway.emit("users/bob", Entity(type="app/user", data={"name": "bob", "city": "Portland"}), ctx)
    peer.emit_pathway.emit("orders/o1", Entity(type="app/order", data={"item": "widget", "qty": 5}), ctx)
    peer.emit_pathway.emit("orders/o2", Entity(type="app/order", data={"item": "gadget", "qty": 10}), ctx)


class TestQueryHandlerRegistration:
    """The query handler is registered and discoverable."""

    def test_query_handler_registered(self, peer) -> None:
        """with_all_handlers() registers a handler at system/query."""
        info = peer.handlers.find_handler_info("system/query")
        assert info is not None
        assert info.pattern == "system/query"
        assert info.name == "query"

    def test_query_handler_interface_in_tree(self, peer) -> None:
        """Query handler interface is stored in the entity tree."""
        uri = peer.entity_tree.normalize_uri("system/handler/system/query")
        h = peer.entity_tree.get(uri)
        assert h is not None

        entity = peer.content_store.get(h)
        assert entity is not None
        assert entity.type == "system/handler/interface"
        assert entity.data["name"] == "query"
        assert "find" in entity.data["operations"]
        assert "count" in entity.data["operations"]

    def test_query_extension_initialized(self, peer) -> None:
        """QueryExtension is initialized with working indexes."""
        ext = _get_query_ext(peer)
        assert ext.index_manager is not None


class TestQueryHandlerFind:
    """find operation works end-to-end through handler dispatch."""

    @pytest.mark.asyncio
    async def test_find_by_type(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "find",
            {"data": {"type_filter": "app/user"}}, ctx)

        assert result["status"] == 200
        data = result["result"]["data"]
        assert data["total"] == 2
        assert len(data["matches"]) == 2
        types = {m["type"] for m in data["matches"]}
        assert types == {"app/user"}

    @pytest.mark.asyncio
    async def test_find_by_type_glob(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "find",
            {"data": {"type_filter": "app/*"}}, ctx)

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 4

    @pytest.mark.asyncio
    async def test_find_with_path_prefix(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "find",
            {"data": {"type_filter": "app/*", "path_prefix": "users/"}}, ctx)

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 2

    @pytest.mark.asyncio
    async def test_find_with_field_filter(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "city", "operator": "eq", "value": "Seattle"}],
            }}, ctx)

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 1

    @pytest.mark.asyncio
    async def test_find_with_pagination(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        r1 = await handler("system/query", "find",
            {"data": {"type_filter": "app/*", "limit": 2}}, ctx)

        assert r1["status"] == 200
        d1 = r1["result"]["data"]
        assert len(d1["matches"]) == 2
        assert d1["total"] == 4
        assert d1["has_more"] is True
        assert "cursor" in d1

        r2 = await handler("system/query", "find",
            {"data": {"type_filter": "app/*", "limit": 2, "cursor": d1["cursor"]}}, ctx)

        d2 = r2["result"]["data"]
        assert len(d2["matches"]) == 2
        assert d2["has_more"] is False

    @pytest.mark.asyncio
    async def test_find_include_entities(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "find",
            {"data": {"type_filter": "app/user", "include_entities": True}}, ctx)

        assert result["status"] == 200
        # M3: entities now inside system/envelope result
        assert result["result"]["type"] == "system/envelope"
        assert len(result["result"]["data"]["included"]) == 2

    @pytest.mark.asyncio
    async def test_find_by_ref(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        # Store entities with a hash reference
        target = Entity(type="app/target", data={"value": "important"})
        target_hash = peer.emit_pathway.emit("targets/t1", target, EmitContext.bootstrap()).hash

        referrer = Entity(type="app/referrer", data={"target": target_hash})
        peer.emit_pathway.emit("refs/r1", referrer, EmitContext.bootstrap())

        result = await handler("system/query", "find",
            {"data": {"ref_filter": target_hash, "type_filter": "app/referrer"}}, ctx)

        assert result["status"] == 200
        assert result["result"]["data"]["total"] == 1


class TestQueryAfterMerge:
    """Regression: synced entities applied via `tree:merge` MUST be visible
    to `system/query:find` (P5 / convergence.psync_query_namespace).

    The cohort psync pathway lands synced entities on the receiver via
    `tree:merge`. A bare `tree.set` binds the hash but never fires the
    EmitPathway index hook, so the merged entities are fetchable via
    listing+get yet return 0 query matches — the `psync_query_namespace`
    WARN. This test mirrors the orchestrator: extract a `test/sync-doc`
    subtree, merge it into a destination prefix, then query that prefix.
    """

    @pytest.mark.asyncio
    async def test_merged_entities_are_queryable(self, peer) -> None:
        src_prefix = "system/validate/psync-src/"
        dst_prefix = "system/validate/psync-dst/"
        ctx = _make_ctx(peer)
        tree = peer.handlers.find_handler("system/tree")
        query = peer.handlers.find_handler("system/query")

        # Seed source entities (the "peer B" side).
        boot = EmitContext.bootstrap()
        files = ["file1", "file2", "subdir/file3"]
        for name in files:
            peer.emit_pathway.emit(
                src_prefix + name,
                Entity(type="test/sync-doc", data={"content": f"hello {name}"}),
                boot,
            )

        # Extract the subtree as a transport envelope, then merge it into the
        # destination prefix — the receiver's sync apply step.
        extracted = await tree(
            "system/tree", "extract", {"data": {"prefix": src_prefix}}, ctx
        )
        assert extracted["status"] == 200
        merged = await tree("system/tree", "merge", {"data": {
            "source_envelope": extracted["result"],
            "source_prefix": src_prefix,
            "target_prefix": dst_prefix,
        }}, ctx)
        assert merged["status"] == 200
        assert merged["result"]["data"]["applied"] == len(files)

        # The query over the destination prefix MUST find all merged entities
        # (this returned total=0 before the emit_hash fix).
        result = await query("system/query", "find", {"data": {
            "type_filter": "test/sync-doc",
            "path_prefix": dst_prefix,
        }}, ctx)
        assert result["status"] == 200
        assert result["result"]["data"]["total"] == len(files)
        for m in result["result"]["data"]["matches"]:
            assert dst_prefix in m["path"]


class TestQueryHandlerCount:
    @pytest.mark.asyncio
    async def test_count_by_type(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "count",
            {"data": {"type_filter": "app/user"}}, ctx)

        assert result["status"] == 200
        assert result["result"]["data"] == 2

    @pytest.mark.asyncio
    async def test_count_all_app_types(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "count",
            {"data": {"type_filter": "app/*"}}, ctx)

        assert result["status"] == 200
        assert result["result"]["data"] == 4


class TestQueryHandlerErrors:
    @pytest.mark.asyncio
    async def test_empty_query_returns_400(self, peer) -> None:
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "find", {"data": {}}, ctx)
        assert result["status"] == 400

    @pytest.mark.asyncio
    async def test_field_filter_without_type_returns_400(self, peer) -> None:
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "find",
            {"data": {"field_filters": [{"field": "name", "operator": "eq", "value": "alice"}]}}, ctx)
        assert result["status"] == 400

    @pytest.mark.asyncio
    async def test_unknown_operation_returns_501(self, peer) -> None:
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        result = await handler("system/query", "bogus", {"data": {}}, ctx)
        assert result["status"] == 501


class TestQueryIndexMaintenance:
    """Indexes stay consistent as entities are added/updated/deleted."""

    @pytest.mark.asyncio
    async def test_new_entity_appears_in_query(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        peer.emit_pathway.emit("users/carol", Entity(type="app/user", data={"name": "carol"}), EmitContext.bootstrap())

        result = await handler("system/query", "count",
            {"data": {"type_filter": "app/user"}}, ctx)
        assert result["result"]["data"] == 3

    @pytest.mark.asyncio
    async def test_deleted_entity_removed_from_query(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        peer.emit_pathway.delete("users/alice", EmitContext.bootstrap())

        result = await handler("system/query", "count",
            {"data": {"type_filter": "app/user"}}, ctx)
        assert result["result"]["data"] == 1

    @pytest.mark.asyncio
    async def test_updated_entity_reflected_in_query(self, peer) -> None:
        _seed(peer)
        handler = peer.handlers.find_handler("system/query")
        ctx = _make_ctx(peer)

        peer.emit_pathway.emit("users/alice",
            Entity(type="app/user", data={"name": "alice", "city": "Denver"}),
            EmitContext.bootstrap())

        result = await handler("system/query", "find",
            {"data": {
                "type_filter": "app/user",
                "field_filters": [{"field": "city", "operator": "eq", "value": "Denver"}],
            }}, ctx)
        assert result["result"]["data"]["total"] == 1
