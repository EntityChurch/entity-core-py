"""SA-PY-7 — the collision is removed, and this file pins the removal.

`ROUTING-2026-08-18-c` §4 confirmed that `since` was documented by two opposite
directional metaphors and asked the question that sized the fix: *did the two
code paths actually behave differently, or did the readings only diverge on the
page?* Measured here against the engine, over `v1 → v2 → v3`:

===============  ==================  =========================================
call             this peer returned  reading
===============  ==================  =========================================
``fetch(v2)``    ``[v3]``            exclusive watermark — "send what I lack"
``log(v2)``      ``[v2, v1]``        inclusive cursor — "start here, walk back"
===============  ==================  =========================================

**Disjoint**, from one field name, with nothing erroring. That measurement is
what promoted the rename from hygiene to a determinism pin, and arch ruled it
that way for all three seats: **`fetch` keeps `since`** (exclusive, toward
newer) and **`log` takes `start_at`** (inclusive, toward older). Both readings
were defensible for their own operation, which is exactly why the fix could not
be "pick an inclusivity" — the defect was the shared name.

The tests below were characterization asserting the pre-ruling behaviour, so
they would fail when the fix landed. It landed; they now assert the ruling.
The row that used to say *"log includes the marker, which §4.4.2's 'start after
this version' forbids"* is settled the other way: `start_at` is **inclusive**,
stated normatively, and the prose no longer describes a third behaviour.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.sdk.dispatcher import HandlerContextDispatcher
from entity_sdk.client import EntityClient
from entity_sdk.errors import BadRequest

PREFIX = "project/"
FILE_TYPE = "test/file"

BLANKET = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
        "peers": {"include": ["*"]},
    }]
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


@pytest.fixture
def rev(client):
    return client.revision(PREFIX)


async def _three_versions(client, rev) -> tuple[bytes, bytes, bytes]:
    """v1 → v2 → v3, oldest first."""
    await client.put(PREFIX + "a.txt", FILE_TYPE, {"c": "1"})
    v1 = (await rev.commit()).version
    await client.put(PREFIX + "a.txt", FILE_TYPE, {"c": "2"})
    v2 = (await rev.commit()).version
    await client.put(PREFIX + "a.txt", FILE_TYPE, {"c": "3"})
    v3 = (await rev.commit()).version
    assert len({v1, v2, v3}) == 3, "the three commits did not produce three versions"
    return v1, v2, v3


class TestTheTwoOperationsNowCarryTwoNames:
    @pytest.mark.asyncio
    async def test_fetch_keeps_since_as_an_exclusive_watermark(self, client, rev):
        """Unchanged by the ruling — `fetch` genuinely wants a watermark."""
        v1, v2, v3 = await _three_versions(client, rev)

        result = await rev.fetch(since=v2)

        assert list(result.versions) == [v3], (
            f"expected only the version newer than v2; got "
            f"{[h.hex()[:8] for h in result.versions]} "
            f"(v1={v1.hex()[:8]} v2={v2.hex()[:8]} v3={v3.hex()[:8]})"
        )

    @pytest.mark.asyncio
    async def test_log_start_at_is_an_inclusive_anchor(self, client, rev):
        """The anchor is the page's FIRST element, and the walk runs older.

        This is the assertion `entity-core-go`'s `log_start_at_inclusive` probe
        makes on the wire, driven here through the same handler.
        """
        v1, v2, v3 = await _three_versions(client, rev)

        page = await rev.log(start_at=v2)

        assert list(page.versions) == [v2, v1], (
            f"expected the anchor and its ancestors; got "
            f"{[h.hex()[:8] for h in page.versions]} "
            f"(v1={v1.hex()[:8]} v2={v2.hex()[:8]} v3={v3.hex()[:8]})"
        )
        assert page.versions[0] == v2, "start_at is INCLUSIVE — the anchor comes first"

    @pytest.mark.asyncio
    async def test_the_two_pages_are_still_disjoint_and_that_is_now_fine(
        self, client, rev,
    ):
        """The finding, preserved. The sets never intersected and still do not
        — what changed is that they no longer answer to one name, so a caller
        cannot reach the wrong one by carrying an intuition across operations.
        """
        _v1, v2, _v3 = await _three_versions(client, rev)

        from_fetch = set((await rev.fetch(since=v2)).versions)
        from_log = set((await rev.log(start_at=v2)).versions)

        assert from_fetch & from_log == set(), (
            f"the two readings overlap after all — fetch={len(from_fetch)}, "
            f"log={len(from_log)}, shared={len(from_fetch & from_log)}"
        )
        assert from_fetch and from_log, "one side returned nothing; the probe has no teeth"


class TestTheOldSpellingIsRefusedRatherThanIgnored:
    """*"Implementations MUST NOT accept `since` on `log`."*

    Refusing matters more than it looks. An ignored field silently answers from
    HEAD — a plausible page that is not the one the caller asked for, which is
    the same silent-wrong-answer shape the rename exists to remove. And the
    caller passing `since` here made a **documented** mistake against a
    pre-ruling copy of the spec, so the error names both operations rather than
    saying "invalid".
    """

    @pytest.mark.asyncio
    async def test_the_sdk_refuses_it_and_names_the_ruling(self, client, rev):
        await _three_versions(client, rev)

        with pytest.raises(BadRequest) as exc:
            await rev.log(since=b"\x00" * 33)

        assert "SA-PY-7" in str(exc.value)
        assert "start_at" in str(exc.value)

    @pytest.mark.asyncio
    async def test_and_so_does_the_handler_beneath_it(self, client, rev):
        """The SDK check is not the enforcement point — a peer is reachable
        without it. Driven at the operation, where a foreign client lands.
        """
        _v1, v2, _v3 = await _three_versions(client, rev)

        with pytest.raises(BadRequest) as exc:
            await client.execute(
                "system/revision", "log",
                params={
                    "type": "system/revision/log-params",
                    "data": {"prefix": PREFIX, "since": v2},
                },
            )

        assert exc.value.status == 400
        assert "start_at" in str(exc.value)

    @pytest.mark.asyncio
    async def test_a_log_with_no_anchor_still_starts_at_head(self, client, rev):
        """The control: refusing `since` must not have cost the default path."""
        v1, v2, v3 = await _three_versions(client, rev)

        page = await rev.log()

        assert list(page.versions) == [v3, v2, v1]
