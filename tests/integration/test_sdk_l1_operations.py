"""The L1 SDK against a real peer — `SDK-OPERATIONS` v0.8 §3, §12, §2.5.

No mocks. Every test drives :class:`entity_sdk.EntityClient` through the peer's
own local dispatcher, so the path under test is the real one: dispatch →
capability check → tree handler → emit pathway. That matters more than usual
here, because the whole point of the SDK is that it addresses operations the
way the handler expects, and a mocked dispatcher would assert only that the SDK
agrees with itself.

These are the §16.1 MUST tree operations. `watch`/`unwatch` (§6.1-6.2) are the
remaining MUST and are not yet built.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.sdk import HandlerContextDispatcher

from entity_sdk import (
    AuthorizationError,
    ClientError,
    Conflict,
    EntityClient,
    EntityError,
    NotFound,
    ResolvedPath,
    SystemFailure,
    ZERO_HASH,
    error_for_status,
    raise_for_status,
    resolve,
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
    """An `EntityClient` over the peer's real local dispatch seam."""
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=BLANKET,
        caller_capability=BLANKET,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )
    return EntityClient(HandlerContextDispatcher(ctx), peer.keypair.peer_id)


# ---------------------------------------------------------------------------
# §2.5 path model
# ---------------------------------------------------------------------------


class TestPathResolution:
    def test_peer_relative_resolves_to_local(self):
        r = resolve("knowledge/intro", "peer-a")
        assert r == ResolvedPath("peer-a", "knowledge/intro")
        assert r.absolute == "/peer-a/knowledge/intro"

    def test_absolute_path_keeps_its_peer(self):
        """The `/{them}/...` case — the SDK must not substitute the local id."""
        r = resolve("/peer-b/knowledge/intro", "peer-a")
        assert r.peer_id == "peer-b"
        assert r.relative == "knowledge/intro"

    def test_wire_uri_form_round_trips(self):
        r = resolve("entity://peer-b/knowledge/intro", "peer-a")
        assert r == ResolvedPath("peer-b", "knowledge/intro")

    def test_dispatch_uri_names_the_paths_own_peer(self):
        """A remote path dispatches at the remote peer, not the local one."""
        r = resolve("/peer-b/docs/x", "peer-a")
        assert r.uri("system/tree") == "entity://peer-b/system/tree"

    def test_trailing_slash_is_preserved_because_it_is_semantic(self):
        """`path/` means listing and `path` means entity — never normalize it."""
        assert resolve("docs/", "peer-a").is_listing
        assert not resolve("docs", "peer-a").is_listing
        assert resolve("", "peer-a").is_listing

    def test_bare_root_is_rejected_not_silently_localized(self):
        with pytest.raises(ValueError, match="names no peer"):
            resolve("/", "peer-a")

    def test_child_path_is_built_against_the_listing_peer(self):
        parent = resolve("/peer-b/docs/", "peer-a")
        assert parent.child("intro").absolute == "/peer-b/docs/intro"

    def test_client_requires_a_local_peer_id(self):
        with pytest.raises(ValueError, match="local_peer_id is required"):
            EntityClient(object(), "")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# §3.1-3.5 core tree operations
# ---------------------------------------------------------------------------


class TestCoreTreeOperations:
    async def test_put_then_get_round_trips(self, client):
        h = await client.put("docs/intro", "primitive/any", {"body": "hello"})
        assert isinstance(h, bytes) and h

        entity = await client.get("docs/intro")
        assert entity is not None
        assert entity["data"]["body"] == "hello"

    async def test_get_missing_returns_none_not_an_error(self, client):
        """§3.1 signature is `Entity | null`; 404 is not in its error list."""
        assert await client.get("docs/nope") is None

    async def test_has_is_true_only_when_bound(self, client):
        assert await client.has("docs/intro") is False
        await client.put("docs/intro", "primitive/any", {"body": "x"})
        assert await client.has("docs/intro") is True

    async def test_remove_unbinds(self, client):
        await client.put("docs/intro", "primitive/any", {"body": "x"})
        await client.remove("docs/intro")
        assert await client.has("docs/intro") is False

    async def test_remove_is_idempotent(self, client):
        """§3.4's 404 is a MAY, so the SDK picks the permissive branch once.

        This peer silently succeeds on an unbound path; another conformant peer
        may 404. Forwarding that choice would make the same caller code raise
        against one peer and not another — nondeterminism discovered only on
        contact with a second implementation. Absorbed here instead.
        """
        await client.remove("docs/nope")
        await client.put("docs/x", "primitive/any", {})
        await client.remove("docs/x")
        await client.remove("docs/x")
        assert await client.has("docs/x") is False

    async def test_a_404_from_a_peer_that_reports_one_is_also_absorbed(self):
        """The other side of the MAY, which this peer never produces."""

        class NotFoundDispatcher:
            async def execute(self, request):
                from entity_core.handlers.context import ExecuteResult

                return ExecuteResult(
                    status=404,
                    result={"data": {"code": "not_found"}},
                    error=None,
                )

        client = EntityClient(NotFoundDispatcher(), "peer-a")
        await client.remove("docs/nope")

    async def test_put_overwrites(self, client):
        await client.put("docs/intro", "primitive/any", {"body": "v1"})
        await client.put("docs/intro", "primitive/any", {"body": "v2"})
        entity = await client.get("docs/intro")
        assert entity["data"]["body"] == "v2"


# ---------------------------------------------------------------------------
# §3.3 list — the Entry projection
# ---------------------------------------------------------------------------


class TestList:
    async def test_empty_prefix_lists_nothing(self, client):
        assert await client.list("docs/") == []

    async def test_entries_carry_all_four_fields(self, client):
        """§3.3 conformance: name, path, content_hash, has_children — all four.

        The wire sends a map of `name -> {hash?, has_children}` with no path on
        any entry; populating `path` is the SDK's job and the reason this type
        exists.
        """
        await client.put("docs/intro", "primitive/any", {"n": 1})
        entries = await client.list("docs/")

        assert len(entries) == 1
        entry = entries[0]
        assert entry.name == "intro"
        assert entry.path == f"/{client.local_peer_id}/docs/intro"
        assert isinstance(entry.content_hash, bytes) and entry.content_hash
        assert entry.has_children is False

    async def test_list_is_single_level_not_recursive(self, client):
        await client.put("docs/a", "primitive/any", {})
        await client.put("docs/deep/b", "primitive/any", {})

        names = {e.name for e in await client.list("docs/")}
        assert names == {"a", "deep"}, "list is direct children only (§3.3)"

    async def test_has_children_marks_a_branch(self, client):
        await client.put("docs/deep/b", "primitive/any", {})
        (deep,) = [e for e in await client.list("docs/") if e.name == "deep"]
        assert deep.has_children is True

    async def test_missing_trailing_slash_still_lists(self, client):
        """A prefix is a prefix; the SDK adds the slash the handler needs."""
        await client.put("docs/a", "primitive/any", {})
        assert [e.name for e in await client.list("docs")] == ["a"]

    async def test_ordering_is_stable(self, client):
        """§3.3 leaves ordering implementation-defined; unstable is still wrong."""
        for name in ("c", "a", "b"):
            await client.put(f"docs/{name}", "primitive/any", {})
        assert [e.name for e in await client.list("docs/")] == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# §3.2 compare-and-swap — the three-value expected_hash
# ---------------------------------------------------------------------------


class TestCompareAndSwap:
    async def test_create_only_succeeds_on_unbound_path(self, client):
        """`put_cas(expected_hash=None)` -> zero-hash -> expect-absent."""
        h = await client.put_cas("docs/new", "primitive/any", {"v": 1}, None)
        assert isinstance(h, bytes) and h

    async def test_create_only_conflicts_on_bound_path(self, client):
        await client.put("docs/new", "primitive/any", {"v": 1})
        with pytest.raises(Conflict) as exc:
            await client.put_cas("docs/new", "primitive/any", {"v": 2}, None)
        assert exc.value.status == 409

    async def test_matching_hash_succeeds(self, client):
        first = await client.put("docs/x", "primitive/any", {"v": 1})
        second = await client.put_cas("docs/x", "primitive/any", {"v": 2}, first)
        assert second != first
        assert (await client.get("docs/x"))["data"]["v"] == 2

    async def test_stale_hash_conflicts(self, client):
        stale = await client.put("docs/x", "primitive/any", {"v": 1})
        await client.put("docs/x", "primitive/any", {"v": 2})
        with pytest.raises(Conflict):
            await client.put_cas("docs/x", "primitive/any", {"v": 3}, stale)

    async def test_plain_put_is_unconditional(self, client):
        """Row 1 of the §3.2 table: no CAS -> the field is absent, not zero.

        If `put` sent a zero `expected_hash` it would mean create-only, and
        this overwrite would 409 instead of succeeding.
        """
        await client.put("docs/x", "primitive/any", {"v": 1})
        await client.put("docs/x", "primitive/any", {"v": 2})
        assert (await client.get("docs/x"))["data"]["v"] == 2

    def test_zero_hash_is_the_full_width_form(self):
        """33 bytes: format code 0x00 + a 32-byte digest, all zero."""
        assert ZERO_HASH == b"\x00" * 33


# ---------------------------------------------------------------------------
# §12 error model
# ---------------------------------------------------------------------------


class TestErrorModel:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (400, "BadRequest"),
            (403, "AuthorizationError"),
            (404, "NotFound"),
            (409, "Conflict"),
            (429, "RateLimited"),
            (500, "InternalError"),
            (501, "NotSupported"),
            (503, "HandlerUndeclared"),
        ],
    )
    def test_each_status_maps_to_its_own_type(self, status, expected):
        """§12.3 MUST NOT collapse all errors into a single generic type."""
        assert type(error_for_status(status)).__name__ == expected

    def test_status_is_preserved_verbatim(self):
        """§12.3 MUST preserve status codes."""
        for status in (400, 403, 404, 409, 429, 500, 501, 503):
            assert error_for_status(status).status == status

    def test_categories_match_12_3(self):
        """Client-fixable / authorization / system are distinguishable."""
        assert isinstance(error_for_status(404), ClientError)
        assert isinstance(error_for_status(409), ClientError)
        assert isinstance(error_for_status(500), SystemFailure)
        assert isinstance(error_for_status(501), SystemFailure)
        # 403 is deliberately NOT a ClientError — a grant problem is not
        # something the caller fixes by editing the request.
        assert not isinstance(error_for_status(403), ClientError)
        assert isinstance(error_for_status(403), AuthorizationError)

    def test_code_and_message_come_off_the_error_entity(self):
        err = error_for_status(
            403,
            {
                "type": "system/protocol/error",
                "data": {"code": "forbidden", "message": "no grant"},
            },
        )
        assert err.code == "forbidden"
        assert err.message == "no grant"

    def test_error_entity_carries_no_status_field(self):
        """§12.2: `status` lives on the response, not on the error entity.

        Reading a `status` key out of the error entity would institutionalize
        the two-sources-for-one-fact the spec forbids, so the SDK does not.
        """
        err = error_for_status(403, {"data": {"code": "forbidden", "status": 500}})
        assert err.status == 403

    def test_207_is_not_a_failure(self):
        """§12.4: application code MUST NOT treat partial success as failure."""
        raise_for_status(207, None)

    def test_202_accepted_is_not_a_failure(self):
        raise_for_status(202, None)

    def test_303_redirect_is_not_swallowed_as_success(self):
        """A subscription redirect is a control signal, not an entity."""
        with pytest.raises(EntityError) as exc:
            raise_for_status(303, None)
        assert exc.value.status == 303

    def test_unmapped_status_is_still_typed(self):
        err = error_for_status(418)
        assert isinstance(err, EntityError)
        assert err.status == 418

    def test_message_survives_a_non_entity_result(self):
        assert error_for_status(500, "boom").message == "boom"

    async def test_a_real_403_arrives_typed(self, peer):
        """End-to-end: a constrained grant produces AuthorizationError."""
        narrow = {
            "grants": [
                {
                    "handlers": {"include": ["*"]},
                    "resources": {"include": ["allowed/*"]},
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
        constrained = EntityClient(
            HandlerContextDispatcher(ctx), peer.keypair.peer_id
        )

        with pytest.raises(AuthorizationError) as exc:
            await constrained.put("forbidden/x", "primitive/any", {})
        assert exc.value.status == 403


# ---------------------------------------------------------------------------
# §3.2 / V7 §3.2 — where the authorization-bearing path rides
# ---------------------------------------------------------------------------


class TestResourceTargets:
    async def test_path_rides_in_resource_targets(self, peer):
        """V7 §3.2 SHOULD: the path travels in `resource.targets`.

        Only then is it covered by the *dispatch layer's* capability check
        before the handler runs. The params copy is the sanctioned fallback and
        is sent too, but the resource form is what makes the check
        defense-in-depth rather than handler-only.
        """
        seen: list[dict] = []

        class RecordingDispatcher:
            async def execute(self, request):
                seen.append(
                    {
                        "uri": request.uri,
                        "targets": request.resource_targets,
                        "params": request.params,
                    }
                )
                from entity_core.handlers.context import ExecuteResult

                return ExecuteResult(status=404, result=None, error=None)

        client = EntityClient(RecordingDispatcher(), "peer-a")
        await client.get("docs/intro")

        (call,) = seen
        assert call["targets"] == ["docs/intro"]
        assert call["uri"] == "entity://peer-a/system/tree"
        assert call["params"]["data"]["path"] == "docs/intro"

    async def test_explicit_peer_id_redirects_without_corrupting_the_path(self):
        """`peer_id=` overrides *whose* namespace, not *which* path."""
        seen: list[str] = []

        class RecordingDispatcher:
            async def execute(self, request):
                seen.append(request.uri)
                from entity_core.handlers.context import ExecuteResult

                # 200, unlike the `get` cases above: `execute` surfaces a 404
                # as NotFound rather than swallowing it, and the assertion here
                # is about the URI, not the status path.
                return ExecuteResult(status=200, result={}, error=None)

        client = EntityClient(RecordingDispatcher(), "peer-a")
        await client.execute("/peer-b/system/registry", "ping", peer_id="peer-c")
        assert seen == ["entity://peer-c/system/registry"]

    async def test_remote_path_dispatches_at_the_remote_peer(self):
        """`/{them}/...` addresses their namespace, not ours."""
        seen: list[str] = []

        class RecordingDispatcher:
            async def execute(self, request):
                seen.append(request.uri)
                from entity_core.handlers.context import ExecuteResult

                return ExecuteResult(status=404, result=None, error=None)

        client = EntityClient(RecordingDispatcher(), "peer-a")
        await client.get("/peer-b/docs/intro")
        assert seen == ["entity://peer-b/system/tree"]
