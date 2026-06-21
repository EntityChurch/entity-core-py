"""Connection robustness — a single bad request must not crash the connection.

Cross-impl conformance surfaced that Python tore down the connection (broken
pipe) when an install from another impl carried an unexpected cap-chain wire
shape, instead of rejecting it gracefully the way Go does (403). The fix:
inert envelope ingestion (`_store_included_entities`, `_bind_envelope_signatures`)
is best-effort per-entity and never raises, and the serve loop answers a
request that blows up in pre-dispatch with a clean error response (the inline
ingestion exercised directly here; the serve-loop recovery wraps it).
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.utils.ecf import ALG_ECFV1_SHA256


@pytest.fixture
def peer():
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_default_handlers()
        .build()
    )


def _malformed_included() -> list[dict]:
    """Wire-included entries an unexpected impl shape might produce."""
    good = Entity(type="test/ok", data={"v": 1}).to_dict()
    return [
        good,                                   # a well-formed entity
        {"type": "broken/no-data"},             # missing `data` (KeyError risk)
        {"data": {"v": 2}},                     # missing `type`
        {"type": "x", "data": {}, "content_hash": "not-bytes"},  # bad hash type
        {"type": "y", "data": None},            # null data
    ]


def test_store_included_entities_skips_malformed(peer):
    """A malformed included entity is logged + skipped, never raises."""
    env = Envelope(root={"type": "system/protocol/execute", "data": {}},
                   included=_malformed_included())
    # Must not raise — the good entity is stored, the rest skipped.
    peer._store_included_entities(env)
    good_hash = Entity(type="test/ok", data={"v": 1}).compute_hash()
    assert peer.content_store.get(good_hash) is not None


def test_bind_envelope_signatures_skips_malformed(peer):
    """Malformed signature/peer entries don't crash signature binding."""
    env = Envelope(
        root={"type": "system/protocol/execute", "data": {}},
        included=[
            # A signature entry with garbage target/signer shapes.
            {"type": "system/signature", "data": {"target": 123, "signer": "nope"}},
            {"type": "system/signature", "data": {}},          # empty
            {"type": "system/peer", "data": {"peer_id": None}},  # bad peer_id
            {"type": "system/signature"},                       # missing data
        ],
    )
    # Must not raise.
    peer._bind_envelope_signatures(env)


@pytest.mark.asyncio
async def test_reject_request_with_error_answers_execute(peer):
    """A request that raised in pre-dispatch gets a clean error response."""
    sent: list[Envelope] = []

    class _Conn:
        def get_write_lock(self):
            import contextlib

            return contextlib.nullcontext()

    # Capture what _send_locked would write.
    async def _capture(writer, conn_state, envelope):
        sent.append(envelope)

    peer._send_locked = _capture  # type: ignore[assignment]

    env = Envelope(
        root={
            "type": "system/protocol/execute",
            "data": {"request_id": "req-1", "uri": "system/tree"},
        },
    )
    await peer._reject_request_with_error(None, _Conn(), env, RuntimeError("boom"))

    assert len(sent) == 1
    resp = sent[0].root
    assert resp["data"]["status"] >= 400
