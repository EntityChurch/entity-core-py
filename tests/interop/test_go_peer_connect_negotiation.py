"""The §4.5 `protocols` intersection, measured from the initiator seat.

**Why this file exists.** `entity-core-go` landed V7 §4.7 row 1 — a responder
MUST refuse a hello whose `protocols` set is disjoint from its own (§4.5's
*"Intersection, must be non-empty"*) — and relayed it to us as *"both siblings
owe the `handleHello` intersection check."* That claim is true and it is not the
whole finding.

Nobody in the cohort had ever validated `protocols`, so nobody had ever compared
the strings. This peer advertises **`entity-core/7.0`**; `entity-core-go`,
`entity-core-rust` and the spec's own §8.4 all say **`entity-core/1.0`**. The
field was carried on every hello either way and read by nothing, so the
disagreement was invisible for the life of the project — a dead field cannot
diverge observably. Row 1 is what makes it observable, and it makes it
observable as a **partition**: the first seat to implement the check refuses
every connection from the seat that has not.

That is why this file drives the **initiator** seat. Row 1 as relayed is a
responder-side obligation, and a peer that implements it against the wrong
version string still passes every responder-side check ever written — its own
and the cohort's — because a probe dialing *us* offers whatever we advertise.
The break is only visible when we dial **out**, at a responder that checks.

Run against a live go peer:

    cd ../entity-core-go && go run ./cmd/entity-peer -addr 127.0.0.1:19831 -open-access
    ENTITY_GO_PEER=127.0.0.1:19831 uv run pytest tests/interop/test_go_peer_connect_negotiation.py -v

**Opt-in by an explicit address with no default**, for the reason
`test_go_peer_compute_v324.py` sets out at length: a row asserting a sibling's
behaviour must not pin our gate to their release schedule, and a defaulted port
turns someone else's leftover peer into a red diff. The obligation that buys
moves to the calendar — run it on every cohort catch-up against core-go.

**And the go peer must be at a commit that HAS the check.** Three `entity-peer`
processes from 2026-08-21/22 were still listening on this host when this file
was written, all predating go's row-1 landing. Measuring against one of those
reports a clean handshake and proves nothing at all: the standing
*"a validator failure on a fixed port is a leftover peer until proven
otherwise"* rule, arriving as a **false green** rather than a false red. That is
what the second row is for — it drives a deliberately disjoint set, so a stale
go peer fails *it* rather than silently blessing the first row.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.connect import ConnectError
from entity_core.peer.connection import Connection

#: `host:port` of a live `entity-core-go` peer. Unset ⇒ every row skips.
GO_PEER_ADDR = os.environ.get("ENTITY_GO_PEER", "")

pytestmark = pytest.mark.skipif(
    not GO_PEER_ADDR,
    reason="set ENTITY_GO_PEER=host:port to a live entity-core-go peer",
)


async def _dial() -> Connection:
    host, _, port = GO_PEER_ADDR.partition(":")
    return await asyncio.wait_for(
        Connection.connect(host, int(port), Keypair.generate(), wait_for_capability=True),
        timeout=10.0,
    )


class TestTheProtocolsIntersectionAcrossTheSeam:
    """py dials go. The row that fails here is ours, not the harness's."""

    async def test_our_initiator_hello_is_accepted_by_a_go_responder(self) -> None:
        """The headline: a py→go handshake completes.

        This is the row that measures the partition. It fails with
        `400 incompatible_protocol` for exactly as long as this peer advertises
        a version string no other seat has heard of, and it is the only row in
        either tree that can fail that way — every responder-side check we or
        the cohort own dials *us*, and so offers our own string back to us.
        """
        conn = await _dial()
        try:
            assert conn.remote_peer_id, "handshake completed with no remote peer id"
        finally:
            conn.close()

    async def test_the_refusal_when_it_comes_is_the_ruled_pair_and_not_a_generic_400(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Teeth for the row above, and the reason it is a separate row.

        A dialer that folds a refusal into a message string can only assert
        that *something* was raised, which is satisfied by a peer that is
        simply down. Driving a deliberately disjoint set proves the go
        responder answers §4.7 row 1's `(400, incompatible_protocol)` pair —
        so when the row above fails, the code it fails with is attributable to
        the intersection and not to the connection.
        """
        from entity_core.peer import connection as connection_mod

        original = connection_mod.create_connect_hello_execute

        def _disjoint(keypair: Keypair):  # type: ignore[no-untyped-def]
            execute, nonce = original(keypair)
            execute.params["data"]["protocols"] = ["entity-core/99.0"]
            return execute, nonce

        # `connection.py` does a from-import, so the name has to be replaced in
        # the CALLER's namespace — patching `handlers.connect` rebinds a module
        # attribute nothing reads and the row passes for the wrong reason.
        monkeypatch.setattr(connection_mod, "create_connect_hello_execute", _disjoint)

        with pytest.raises(ConnectError) as caught:
            await _dial()

        assert caught.value.code == "incompatible_protocol", (
            f"go answered code={caught.value.code!r} for a disjoint protocols set; "
            "§4.7 row 1 pins `incompatible_protocol`"
        )
        assert caught.value.status == 400, (
            f"go answered status={caught.value.status!r}; §4.7 row 1 pins 400"
        )
