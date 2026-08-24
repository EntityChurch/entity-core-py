"""Query operations and the L3 builder — `SDK-EXTENSION-OPERATIONS` §6.

Against a real peer with real indexes, because the builder's job is to produce
an expression the *handler* accepts, and an expression asserted only against
itself proves nothing about that.

SA-PY-4 (§6's `entries`/`content_hash`/`neq` against `EXTENSION-QUERY`'s
`matches`/`hash`/`not_eq`) was **ruled at 0.8.1 as SA-4** and §6 now carries the
normative names. The tests below assert we speak those and *only* those — the
compatibility aliases are gone, because a name no spec defines is a divergence
of our own making.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.sdk import HandlerContextDispatcher

from entity_sdk import (
    BadRequest,
    EntityClient,
    Match,
    QueryResult,
    normalize_operator,
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

SETTING = "app/state/setting"


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


@pytest.fixture
async def seeded(client) -> EntityClient:
    """Three settings and one unrelated entity, written through the SDK."""
    await client.put("app/browser/settings/theme", SETTING,
                     {"category": "display", "name": "theme", "order": 1})
    await client.put("app/browser/settings/font", SETTING,
                     {"category": "display", "name": "font", "order": 2})
    await client.put("app/browser/settings/proxy", SETTING,
                     {"category": "network", "name": "proxy", "order": 3})
    await client.put("app/notes/one", "app/note", {"body": "unrelated"})
    return client


# ---------------------------------------------------------------------------
# SA-PY-4 — the spelling divergences
# ---------------------------------------------------------------------------


class TestOperatorSpelling:
    def test_the_normative_spelling_is_the_only_one(self):
        assert normalize_operator("not_eq") == "not_eq"
        assert normalize_operator("eq") == "eq"
        assert normalize_operator("contains") == "contains"

    def test_the_pre_ruling_spelling_is_rejected_with_the_reason(self):
        """`neq` was §6's spelling until the 0.8.1 SA-4 ruling. It now names
        nothing, so accepting it would be a divergence of our own making — but
        a caller working from an older copy of the doc made a *documented*
        mistake, so the error says which ruling moved it."""
        with pytest.raises(BadRequest) as exc:
            normalize_operator("neq")
        assert exc.value.status == 400
        assert exc.value.code == "invalid_operator"
        assert "not_eq" in (exc.value.message or "")
        assert "SA-4" in (exc.value.message or "")

    def test_an_unknown_operator_is_the_handlers_own_code(self):
        with pytest.raises(BadRequest) as exc:
            normalize_operator("approximately")
        assert exc.value.status == 400
        assert exc.value.code == "invalid_operator"

    def test_the_builder_rejects_the_pre_ruling_spelling(self, client):
        with pytest.raises(BadRequest):
            client.query().type(SETTING).field("category", neq="display")

    def test_the_builder_carries_the_normative_spelling(self, client):
        expr = client.query().type(SETTING).field("category", not_eq="display").to_expression()
        assert expr["field_filters"] == [
            {"field": "category", "operator": "not_eq", "value": "display"}
        ]


class TestResultFieldNames:
    def test_only_the_normative_names_exist(self):
        """The `entries` / `content_hash` aliases bridged a defect in §6 that
        the SA-4 ruling has since fixed. A name no spec defines is a local
        divergence, so they are gone rather than kept for politeness."""
        result = QueryResult(matches=[Match(hash=b"\x00" + b"\x01" * 32)])
        assert not hasattr(result, "entries")
        assert not hasattr(result.matches[0], "content_hash")

    def test_len_and_iter_read_the_page_not_the_total(self):
        """`total` is the full capability-filtered count; the page may be
        shorter, and that is the intended reading."""
        result = QueryResult(
            matches=[Match(hash=b"\x00" + b"\x03" * 32)], total=99, has_more=True
        )
        assert len(result) == 1
        assert result.total == 99
        assert [m.hash for m in result] == [result.matches[0].hash]


# ---------------------------------------------------------------------------
# §4.1 — expression construction, and the two errors the builder pre-empts
# ---------------------------------------------------------------------------


class TestExpression:
    def test_the_spec_example_builds(self, client):
        expr = (
            client.query()
            .type(SETTING)
            .field("category", eq="display")
            .path_prefix("app/browser/settings/")
            .limit(50)
            .to_expression()
        )
        assert expr == {
            "type_filter": SETTING,
            "field_filters": [{"field": "category", "operator": "eq", "value": "display"}],
            "path_filter": "app/browser/settings/",
            "limit": 50,
        }

    def test_a_unary_operator_carries_no_value(self, client):
        """§4.4: value is 'absent for unary operators (exists)'. Sending
        `value: None` would be a null the handler has to decide about."""
        expr = client.query().type(SETTING).field("archived", "exists").to_expression()
        assert expr["field_filters"] == [{"field": "archived", "operator": "exists"}]

    def test_an_empty_query_is_refused_before_dispatch(self, client):
        with pytest.raises(BadRequest) as exc:
            client.query().limit(10).to_expression()
        assert exc.value.code == "empty_query"

    def test_field_without_type_is_refused_before_dispatch(self, client):
        """The handler's own `type_filter_required` — field indexes are
        per-type, so the builder already knows enough to say so."""
        with pytest.raises(BadRequest) as exc:
            client.query().path_prefix("app/").field("category", eq="display").to_expression()
        assert exc.value.code == "type_filter_required"

    def test_two_keyword_operators_are_refused(self, client):
        """`field("x", eq=1, gt=2)` reads as an AND but only one survives."""
        with pytest.raises(BadRequest) as exc:
            client.query().type(SETTING).field("order", eq=1, gt=2)
        assert exc.value.status == 400

    def test_positional_and_keyword_together_are_refused(self, client):
        with pytest.raises(BadRequest):
            client.query().type(SETTING).field("order", "eq", 1, gt=2)

    def test_chaining_field_twice_is_the_and(self, client):
        expr = (
            client.query().type(SETTING)
            .field("order", gte=1).field("order", lte=2)
            .to_expression()
        )
        assert len(expr["field_filters"]) == 2


# ---------------------------------------------------------------------------
# §6 — find / count against the handler
# ---------------------------------------------------------------------------


class TestFind:
    async def test_type_filter_finds_the_seeded_entities(self, seeded):
        result = await seeded.query().type(SETTING).find()

        assert isinstance(result, QueryResult)
        assert result.total == 3
        assert {m.path.split("/")[-1] for m in result} == {"theme", "font", "proxy"}
        assert all(m.type == SETTING for m in result)

    async def test_a_field_filter_narrows(self, seeded):
        result = await seeded.query().type(SETTING).field("category", eq="display").find()

        assert result.total == 2
        assert {m.path.split("/")[-1] for m in result} == {"theme", "font"}

    async def test_not_eq_works_end_to_end(self, seeded):
        """The §4.4 spelling reaches the handler and matches."""
        result = await seeded.query().type(SETTING).field("category", not_eq="display").find()

        assert result.total == 1
        assert result.matches[0].path.endswith("proxy")

    async def test_entities_are_returned_unwrapped_from_the_envelope(self, seeded):
        """With include_entities the handler answers a `system/envelope` whose
        data.root is the result and data.included holds the entities. The
        caller should not have to branch on that."""
        result = await seeded.query().type(SETTING).with_entities().find()

        assert result.total == 3
        assert all(m.entity is not None for m in result)
        names = {m.entity["data"]["name"] for m in result}
        assert names == {"theme", "font", "proxy"}

    async def test_without_entities_the_matches_carry_only_hashes(self, seeded):
        result = await seeded.query().type(SETTING).find()
        assert all(m.entity is None for m in result)
        assert all(isinstance(m.hash, bytes) for m in result)

    async def test_limit_pages_and_reports_more(self, seeded):
        first = await seeded.query().type(SETTING).order_by("path").limit(2).find()

        assert len(first) == 2
        assert first.total == 3, "total is the full count, not the page"
        assert first.has_more is True
        assert first.cursor

        second = await seeded.query().type(SETTING).order_by("path").limit(2).cursor(
            first.cursor
        ).find()
        assert len(second) == 1
        assert second.has_more is False

        seen = {m.path for m in first} | {m.path for m in second}
        assert len(seen) == 3, "the two pages do not overlap"

    async def test_descending_order_reverses(self, seeded):
        asc = await seeded.query().type(SETTING).order_by("path").find()
        desc = await seeded.query().type(SETTING).order_by("path", descending=True).find()

        assert [m.path for m in desc] == list(reversed([m.path for m in asc]))

    async def test_a_type_that_matches_nothing_is_an_empty_result_not_an_error(
        self, seeded
    ):
        result = await seeded.query().type("app/nonexistent").find()
        assert len(result) == 0
        assert result.total == 0
        assert result.has_more is False


class TestCount:
    async def test_count_returns_an_int(self, seeded):
        assert await seeded.query().type(SETTING).count() == 3

    async def test_count_respects_field_filters(self, seeded):
        n = await seeded.query().type(SETTING).field("category", eq="display").count()
        assert n == 2

    async def test_count_of_nothing_is_zero(self, seeded):
        assert await seeded.query().type("app/nonexistent").count() == 0
