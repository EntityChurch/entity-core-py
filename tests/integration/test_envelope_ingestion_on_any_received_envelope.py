"""§6.5 envelope-`included` ingestion binds ANY received envelope (0.8.2.19).

Routed as **E4** by `entity-core-go`; found as **F64** by
`entity-core-keystone`, auditing 0.8.2.18's D7.

.. rubric:: The rule

    *"Ingestion binds ANY received envelope carrying an `included` map — it
    is a property of the envelope, not of a surface `[MUST]`."* — inbound
    EXECUTE, the connect/authenticate response a dialer receives, an
    `EXECUTE_RESPONSE` (notably the §6.2 `request`/`delegate` result), and
    async-delivery / subscription-notification envelopes.

.. rubric:: Why it is stated as an invariant rather than a list

A signature that arrives unbound is unreachable to chain-bundle collection,
which resolves signatures **solely** through the §3.5 invariant pointer — so
every chain rooted at that grant is unverifiable *locally* while remaining
perfectly verifiable at the issuer, where its own signature is bound. Nothing
surfaces that until a peer must verify a target-minted credential locally on
an **attenuated** chain — a presented-authority sub-dispatch (§1.4) — where it
presents as a missing root signature and reads as a capability defect.

**Two surfaces were enumerated one at a time, each after a failure.** §5.1's
own `v7.44` paragraph asserts the receive case is already handled *"via
envelope ingest"* — a sentence that was false for the connect response (which
is what D7 proved) and would have stayed false for `EXECUTE_RESPONSE`.

.. rubric:: What this peer did before the fix, measured

The dialer lifted the connect capability, its signature and the granter
identity into **in-memory fields** on `Connection` and stored none of them;
the `EXECUTE_RESPONSE` path hoisted `included` onto the response object for
callers to read and likewise stored nothing. All three ingestion call sites
were on the **inbound** path. 4368 tests green on both sides of the fix —
the whole suite is blind to it, because every local assertion reads the
in-memory field that was always correct.

.. rubric:: The blind spot has a shape, and it is the seat the test sits in

A test asserts what a caller *gets back*, and the dialer got the entities
back. The only assertion that can see this is one about the **store** — so
every row below reads `content_store` / `entity_tree`, never the response
object. That is the same law as the compensating-pair entry (`_put` omitting
`content_hash`): a same-tree round trip cannot distinguish *we are correct*
from *we are consistent with ourselves*.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder

DIALER_PORT = 19731
ACCEPTOR_PORT = 19732


@pytest.fixture
async def dialer_and_acceptor():
    """Two live peers on loopback. The dialer is the seat under test: it is
    the side that RECEIVES a connect/authenticate response, which is the
    surface D7 named and the one no cohort probe reaches (they all dial in).
    """
    dialer_kp = Keypair.generate()
    acceptor_kp = Keypair.generate()

    dialer = (
        PeerBuilder().with_keypair(dialer_kp)
        .with_all_handlers().debug_mode(True).build()
    )
    acceptor = (
        PeerBuilder().with_keypair(acceptor_kp)
        .with_all_handlers().debug_mode(True).build()
    )

    await dialer.start("127.0.0.1", DIALER_PORT)
    await acceptor.start("127.0.0.1", ACCEPTOR_PORT)
    dialer.register_remote(
        acceptor_kp.peer_id, f"127.0.0.1:{ACCEPTOR_PORT}",
        public_key=acceptor_kp.public_key_bytes(),
    )

    yield dialer, acceptor, acceptor_kp.peer_id

    await dialer.stop()
    await acceptor.stop()


class TestTheConnectAuthenticateResponse:
    """D7's surface (0.8.2.18), which we had never absorbed — this repo was
    on 0.8.2.17 and `.18` was never routed here.
    """

    @pytest.mark.asyncio
    async def test_the_capability_itself_is_in_our_store_NON_DISCRIMINATING(
        self, dialer_and_acceptor,
    ):
        """**This row does not discriminate, and is labelled so nobody counts
        it.** Kept as the ordinary-case control; the two rows below have the
        teeth.

        Measured: unwiring the ingestion sink leaves this row GREEN. Traced
        (A1) rather than patched — R6 session-entity persistence
        (`session_entity.py`, `_persist`) puts the capability **leaf and its
        parent caps** into the content store after a successful dial, for its
        own purpose: making the session entity's chain hashes resolvable
        later. Two independent paths, one observation.

        The arms genuinely differ, so this is defence in depth rather than
        redundancy — R6 stores *capabilities* and knows nothing about the
        `included` map, so it touches **neither the signature nor the granter
        identity**, which is why the next two rows can see what this one
        cannot.

        **Worth stating to whoever seeds the cross-impl vector:** a probe that
        asks *"is the received capability in the store?"* passes a peer with
        no §6.5 ingestion at all. The discriminating observation is the
        **signature at the §3.5 invariant pointer**.
        """
        dialer, _acceptor, acceptor_peer_id = dialer_and_acceptor

        endpoint = await dialer._remote_pool.get_connection(acceptor_peer_id)
        assert endpoint.capability is not None, (
            "the handshake produced no capability — this row cannot say "
            "anything about ingestion"
        )

        cap_hash = endpoint.capability.get("content_hash")
        assert cap_hash, "capability arrived with no content_hash"
        assert dialer.content_store.has(bytes(cap_hash)), (
            "the connect capability is in neither the ingestion path nor R6 "
            "session persistence — this row is the ordinary-case control and "
            "it has stopped holding"
        )

    @pytest.mark.asyncio
    async def test_and_its_SIGNATURE_is_bound_at_the_invariant_pointer(
        self, dialer_and_acceptor,
    ):
        """**The row with the teeth**, and the one the whole ruling is about.

        Storing the entities is not enough: chain-bundle collection resolves
        signatures *solely* through the §3.5 invariant pointer path, so a
        signature sitting in the content store and bound nowhere is still
        unreachable. `_bind_envelope_signatures` is the only thing that puts
        it there, and confining ingestion to one surface left that mechanism
        unreachable on every other.

        A fix that called `_store_included_entities` alone passes the row
        above and fails this one — which is exactly the shape of the
        half-fix, since storing is the obvious half.
        """
        dialer, _acceptor, acceptor_peer_id = dialer_and_acceptor

        endpoint = await dialer._remote_pool.get_connection(acceptor_peer_id)
        cap_hash = bytes(endpoint.capability["content_hash"])

        tree = dialer.entity_tree
        prefix = tree.normalize_uri(
            f"/{acceptor_peer_id}/system/signature/{cap_hash.hex()}",
        )
        assert tree.get(prefix) is not None, (
            f"no signature bound at the §3.5 invariant pointer {prefix} — "
            "the capability's signature is held in memory only, so every "
            "chain rooted at this grant is unverifiable locally while "
            "verifying perfectly at the issuer (§6.5, 0.8.2.19)"
        )

    @pytest.mark.asyncio
    async def test_the_granter_identity_is_ingested_too(
        self, dialer_and_acceptor,
    ):
        """§6.2 names three entities, not two: the token, its signature, and
        the **granter identity**. A chain walk that cannot resolve the granter
        cannot check `sig.signer == cap.granter`, so a missing identity fails
        the walk one step later than a missing signature and reads the same.
        """
        dialer, _acceptor, acceptor_peer_id = dialer_and_acceptor

        endpoint = await dialer._remote_pool.get_connection(acceptor_peer_id)
        granter_hash = endpoint.capability["data"].get("granter")
        assert granter_hash, "capability carries no granter"
        assert dialer.content_store.has(bytes(granter_hash)), (
            "the granter identity was received in `included` and not "
            "ingested (§6.2, §6.5)"
        )


class TestTheRuleIsStatedOverEnvelopesNotSurfaces:
    """The structural half. Two surfaces were enumerated one at a time, each
    after a failure — so a fix that enumerates a third has absorbed the
    instance and not the ruling.

    These rows assert the ingestion sink is applied at the points envelopes
    are **received**, rather than at the points particular messages are
    *handled*. They are the rows that go red when a fourth surface is added
    with its own private copy of the rule.
    """

    def test_the_tcp_reader_loop_ingests_before_it_demuxes(self):
        """Every frame the multiplexer reads — matched, unmatched, or an
        inbound origination — is ingested before `request_id` is even looked
        at. An `EXECUTE_RESPONSE` whose caller has timed out still carried
        entities we received.
        """
        import inspect

        from entity_core.peer.connection import Connection

        src = inspect.getsource(Connection._reader_loop)
        ingest = src.index("self._ingest(env)")
        demux = src.index('msg_type = env.root.get("type", "")')
        assert ingest < demux, (
            "the reader loop demuxes before it ingests, so ingestion has "
            "become a property of the message type again"
        )

    def test_the_http_transport_ingests_at_its_single_decode_point(self):
        """The HTTP boundary is the one no cohort probe dials (they all dial
        TCP), which is why it gets the shared rule rather than a second
        reading of it — the standing law from the CE-1 entry.
        """
        import inspect

        from entity_core.peer.http_client import HttpConnection

        src = inspect.getsource(HttpConnection._post_envelope)
        assert "_envelope_ingest" in src, (
            "the HTTP transport decodes response envelopes without running "
            "§6.5 ingestion — hello, authenticate and every EXECUTE_RESPONSE "
            "on this boundary arrive unbound"
        )

    def test_one_sink_serves_every_receipt_point(self):
        """`Peer.ingest_received_envelope` is the single implementation, and
        it runs BOTH steps. A second copy that stores without binding is the
        half-fix; a second copy that does both is the two-representations
        bug waiting for the two to drift.
        """
        import inspect

        from entity_core.peer.peer import Peer

        src = inspect.getsource(Peer.ingest_received_envelope)
        assert "_store_included_entities" in src
        assert "_bind_envelope_signatures" in src, (
            "the shared ingestion sink no longer binds signatures at the "
            "§3.5 invariant pointer — storing alone leaves them unreachable "
            "to chain-bundle collection"
        )
