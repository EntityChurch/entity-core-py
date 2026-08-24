"""Live interop: the Python client decoding Go's `reflection_endpoints`.

EXTENSION-SIGNALING §4.5.1 (added v1.1). Go built the reference and routed this
field to Rust and Python (`entity-core-go` @ `c9f2fe0`,
`docs/validation/reports/2026-08-15-b-reflection-endpoints-*`). Everything in
`tests/integration/test_signaling_node.py` is same-impl — this repo's node
talking to this repo's codec — and the entire point of the field is that a
*foreign* consumer reads it, so a wrong-but-self-consistent pair would pass
those exactly as a correct one does.

What this settles that the same-impl tests cannot: that Go's emitted bytes
arrive **verbatim** through this client (no `stun:` re-prefixing, no port
canonicalization, no reordering — a browser hands them to `RTCIceServer.urls`
as-is), and that Go's absent field decodes to the no-reflection state rather
than raising.

Two Go nodes, one serving reflection and one not — the absent case needs its
own node because absence is a property of the node's configuration, not of a
request::

    cd ../entity-core-go && go build -o /tmp/entity-peer-go ./cmd/entity-peer
    /tmp/entity-peer-go --addr 127.0.0.1:9200 --signaling-node --open-access \\
        --reflection-endpoint "stun:reflect.example.org:3478,stuns:[2001:db8::1]:5349"
    /tmp/entity-peer-go --addr 127.0.0.1:9201 --signaling-node --open-access

Then::

    uv run pytest tests/interop/test_signaling_reflection_go_node.py -v

Both nodes need `--open-access` (or a seed policy covering
`system/signaling:advertise`); a node started closed refuses every call 403 and
these skip with that named rather than as fifteen opaque failures.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from entity_core.crypto.identity import Keypair
from entity_handlers.signaling.data import advertisement_from_result

#: The Go node started WITH `--reflection-endpoint`.
REFLECTING_PORT = int(os.environ.get("GO_SIGNALING_REFLECTING_PORT", "9200"))
#: The Go node started WITHOUT it — the pre-v1.1 state every node was in.
PLAIN_PORT = int(os.environ.get("GO_SIGNALING_PLAIN_PORT", "9201"))

#: What the reflecting node was started with, in order. These are compared
#: **byte-for-byte**: the bracketed IPv6 literal and the mixed schemes are the
#: two shapes a transform would most plausibly mangle.
EXPECTED = [
    os.environ.get("GO_REFLECTION_URI_A", "stun:reflect.example.org:3478"),
    os.environ.get("GO_REFLECTION_URI_B", "stuns:[2001:db8::1]:5349"),
]


async def _advertise(port: int):
    """Connect as a stranger and run one `advertise`, or skip with a reason.

    Returns the result entity. The connecting identity is freshly generated —
    the deployment posture, and what makes the node's admission model part of
    what is under test rather than something the harness routes around.
    """
    # Handshake, not socket — see `peer_liveness`. The probe IS the connection
    # the test then uses, so a foreign listener costs one bounded timeout
    # instead of an unbounded hang inside `Connection.connect`.
    from tests.interop import peer_liveness

    conn = await peer_liveness.open_peer("127.0.0.1", port, Keypair.generate())
    if conn is None:
        pytest.skip(peer_liveness.skip_reason("127.0.0.1", port))
    try:
        response = await conn.execute(
            uri=f"entity://{conn.session.remote_peer_id}/system/signaling",
            operation="advertise",
            params={"type": "system/signaling/empty", "data": {}},
        )
        status = int(response.status)
        if status == 403:
            pytest.skip(
                f"the Go node at 127.0.0.1:{port} admits no stranger (403) — "
                f"it was started CLOSED; restart it with --open-access or a "
                f"seed policy covering system/signaling:advertise"
            )
        assert status == 200, f"advertise answered {status}"
        return response.result
    finally:
        conn.close()
        await conn.wait_closed()


class TestGoEmitsWhatThisClientReads:
    def test_gos_uris_arrive_byte_for_byte(self):
        async def run():
            result = await _advertise(REFLECTING_PORT)

            # Top-level, sibling to endpoint and limits — the shape §4.5.1
            # pins, and the one a reader skimming §4.5 would most likely nest
            # inside `limits` instead.
            data = result["data"]
            assert data["reflection_endpoints"] == EXPECTED
            assert "reflection_endpoints" not in data["limits"]

            # And through this repo's codec, which is what a caller actually
            # holds. Byte-for-byte: the IPv6 brackets survive, `stuns:` was
            # not folded to `stun:`, and 3478 was not dropped as a default.
            ad = advertisement_from_result(result)
            assert list(ad.reflection_endpoints) == EXPECTED
            for got, want in zip(ad.reflection_endpoints, EXPECTED, strict=True):
                assert got.encode("utf-8") == want.encode("utf-8")

        asyncio.run(run())

    def test_a_go_node_serving_no_reflection_omits_the_key(self):
        """Absent, never `[]` and never null — and absent decodes to the
        already-legal no-reflection state rather than raising, which is what
        makes v1.1 additive with no flag day."""
        async def run():
            result = await _advertise(PLAIN_PORT)
            assert "reflection_endpoints" not in result["data"]

            ad = advertisement_from_result(result)
            assert ad.reflection_endpoints == ()
            # The rest of the advertisement still decodes — an absent optional
            # field is not allowed to cost the endpoint and limits, which are
            # what a peer needs to meet anybody at all.
            assert ad.endpoint
            assert ad.limits.ttl_seconds > 0

        asyncio.run(run())
