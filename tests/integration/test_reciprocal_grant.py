"""EXTENSION-SIGNALING §6.5 (b) — symmetric origination authority, live.

The §6.6 handshake mints one-directionally (acceptor → dialer). On a
*symmetric* establishment — one reached by meeting at a §3 rendezvous key —
§6.5 (b) adds the one missing mirror: the **dialer** mints a capability for
the **acceptor** and delivers it over the connection it just opened, so
either side may originate.

Both halves are exercised over a real TCP wire, deliberately:

* the visible half — mint, carriage, acceptance, install;
* the **invisible** half — *serving* the reach-back. A peer that mints and
  installs but never dispatches an inbound EXECUTE on the connection it
  dialed passes every grant-shaped test and reaches no handler
  (`§11.5.1` loopback-invisible, the `fire_at` failure shape). Only
  `test_the_acceptor_reaches_a_handler_on_the_dialer` fails without it,
  and it fails as a timeout, not as a denial.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.reciprocal import (
    RECIPROCAL_GRANT_VECTOR_FLOOR,
    ReentryGrantError,
    accept_reentry_grant,
    build_reentry_grant_envelope,
    is_reentry_grant,
)
from entity_core.protocol.auth import create_identity_entity
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import normalize_hash


def _build_peer() -> tuple[Keypair, object]:
    keypair = Keypair.generate()
    peer = (
        PeerBuilder()
        .with_keypair(keypair)
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )
    return keypair, peer


@pytest.fixture
async def pair():
    """A dialer and an acceptor, both listening, neither yet connected."""
    dialer_kp, dialer = _build_peer()
    acceptor_kp, acceptor = _build_peer()
    await dialer.start("127.0.0.1", 19411)
    await acceptor.start("127.0.0.1", 19412)
    # The dialer needs a route to the acceptor. The acceptor deliberately
    # gets NO profile for the dialer: the reciprocal direction must ride the
    # accepted connection (V7 §6.11(b)), never a second dial.
    dialer.register_remote(acceptor_kp.peer_id, "127.0.0.1:19412")
    try:
        yield dialer, dialer_kp, acceptor, acceptor_kp
    finally:
        await dialer.stop()
        await acceptor.stop()


async def _installed_grant(acceptor, dialer_peer_id: str, timeout: float):
    """Wait for the acceptor's connection-scoped grant, bounded."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        channel = acceptor._inbound_for_reentry(dialer_peer_id)
        if channel is not None and channel.conn_state.originating_capability:
            return channel.conn_state.originating_capability
        await asyncio.sleep(0.01)
    return None


# ---------------------------------------------------------------------------
# The mint, and what fires it
# ---------------------------------------------------------------------------


async def test_a_rendezvous_establishment_mints_the_reciprocal_grant(pair):
    """Trigger (b): meeting at a §3 key is the mutual-authorization act."""
    dialer, dialer_kp, acceptor, acceptor_kp = pair
    acceptor.mark_rendezvous_establishment(dialer_kp.peer_id)

    await dialer.establish_via_rendezvous(acceptor_kp.peer_id)

    cap = await _installed_grant(
        acceptor, dialer_kp.peer_id, RECIPROCAL_GRANT_VECTOR_FLOOR,
    )
    assert cap is not None, "no reciprocal grant landed on the acceptor"
    # Granter is the dialer; grantee is US, by identity CONTENT HASH.
    data = cap["data"]
    assert normalize_hash(data["granter"]) == create_identity_entity(
        dialer_kp,
    ).compute_hash()
    assert normalize_hash(data["grantee"]) == create_identity_entity(
        acceptor_kp,
    ).compute_hash()


async def test_a_dial_by_address_acceptor_gains_no_reach_back(pair):
    """The §7 narrowing, as a non-regression vector.

    An ordinary dial to a resolved transport endpoint is *asymmetric* — one
    party requested service — so §6.6's one-directional mint stands alone
    and the acceptor gets nothing. A build whose mint is unconditional
    passes every positive test above and fails exactly here.
    """
    dialer, dialer_kp, acceptor, acceptor_kp = pair

    await dialer._remote_pool.get_connection(acceptor_kp.peer_id)

    cap = await _installed_grant(acceptor, dialer_kp.peer_id, 0.5)
    assert cap is None, "a dial-by-address acceptor must gain no authority"


async def test_the_grantee_is_the_identity_hash_not_the_peer_id(pair):
    """#67, one field over.

    The grantee is an ordinary capability grantee: exactly what the core
    verify contract resolves and compares to the author — the grantee
    identity entity's content hash — and never the §3.2 rendezvous
    `system/peer-id`. Conflating them mints a cap that fails
    `grantee_mismatch` at the far side.
    """
    dialer, dialer_kp, acceptor, acceptor_kp = pair
    acceptor.mark_rendezvous_establishment(dialer_kp.peer_id)
    await dialer.establish_via_rendezvous(acceptor_kp.peer_id)

    cap = await _installed_grant(
        acceptor, dialer_kp.peer_id, RECIPROCAL_GRANT_VECTOR_FLOOR,
    )
    assert cap is not None
    grantee = normalize_hash(cap["data"]["grantee"])
    assert grantee != acceptor_kp.peer_id.encode()
    assert grantee == create_identity_entity(acceptor_kp).compute_hash()
    assert len(grantee) == 33  # flat 0x00‖digest, never a Base58 string


async def test_the_reciprocal_grant_equals_the_inbound_dialers_grant(pair):
    """Q2, measured on both directions rather than against a fixed list.

    "The mirror of what an inbound dialer receives" names the grant an
    inbound dialer *actually* receives — the assembled set — so the same
    peer's two mints (the §6.6 handshake one, acceptor → dialer; and the
    §6.5 (b) reciprocal one, dialer → acceptor) must produce the same
    grants for the same counterpart. Two code paths, one assembly: a second
    copy of it is how the two directions drifted apart in the first place.

    Asserting equality rather than a hardcoded grant list means this stays
    true the next time the assembly changes.
    """
    dialer, dialer_kp, acceptor, acceptor_kp = pair
    acceptor.mark_rendezvous_establishment(dialer_kp.peer_id)
    await dialer.establish_via_rendezvous(acceptor_kp.peer_id)
    reciprocal = await _installed_grant(
        acceptor, dialer_kp.peer_id, RECIPROCAL_GRANT_VECTOR_FLOOR,
    )
    assert reciprocal is not None

    # Now the same acceptor dials the dialer the ordinary way, and takes
    # the §6.6 handshake cap the dialer issues an inbound dialer.
    acceptor.register_remote(dialer_kp.peer_id, "127.0.0.1:19411")
    inbound_conn = await acceptor._remote_pool.get_connection(dialer_kp.peer_id)
    assert inbound_conn.capability is not None

    assert reciprocal["data"]["grants"] == inbound_conn.capability["data"]["grants"]


async def test_the_dialer_keeps_the_chain_it_authored(pair):
    """The ruled Wielding shape resolves at our side, references and all.

    §6.5 (b) Carriage phase (2) has the acceptor carry the §7a.2a triple as
    **references** — cap hash / granter-identity hash / signature hash —
    and the dialer resolve all three "from its own content store, because
    it authored them", with no `included`-set chain. That sentence is only
    true of an implementation that actually keeps what it minted, so this
    asserts we do: a counterpart that adopts the ruled reference-only form
    interoperates with us whether or not it also inlines the chain.
    """
    dialer, dialer_kp, acceptor, acceptor_kp = pair
    acceptor.mark_rendezvous_establishment(dialer_kp.peer_id)
    await dialer.establish_via_rendezvous(acceptor_kp.peer_id)
    cap = await _installed_grant(
        acceptor, dialer_kp.peer_id, RECIPROCAL_GRANT_VECTOR_FLOOR,
    )
    assert cap is not None

    channel = acceptor._inbound_for_reentry(dialer_kp.peer_id)
    hashes = [normalize_hash(cap["content_hash"])] + [
        normalize_hash(e["content_hash"])
        for e in (channel.conn_state.originating_included or [])
    ]
    assert len(hashes) == 3
    for content_hash in hashes:
        assert dialer.content_store.get(content_hash) is not None, (
            "the dialer authored this entity and must be able to resolve it "
            "by reference — the ruled Wielding shape carries no included set"
        )


# ---------------------------------------------------------------------------
# The reach-back — the half that fails silently
# ---------------------------------------------------------------------------


async def test_the_acceptor_reaches_a_handler_on_the_dialer(pair):
    """The §8.1 vector: acceptor originates, dialer SERVES it.

    Everything here can be in place — grant minted, verified, installed —
    and this still times out if the dialer's reader treats an inbound
    EXECUTE as an orphan response. Authority without a serving path is not
    reach-back.

    The path read is outside the §4.4 floor's `system/tree` resource scope
    (`system/type/*` + `system/handler/*`) and genuinely exists on the
    dialer, so a 404 could not be mistaken for reach: it discriminates the
    ASSEMBLED grant from the flat floor (Q2). A 403 here is the pre-ruling
    flat-floor mint returning.
    """
    dialer, dialer_kp, acceptor, acceptor_kp = pair
    acceptor.mark_rendezvous_establishment(dialer_kp.peer_id)
    await dialer.establish_via_rendezvous(acceptor_kp.peer_id)
    assert await _installed_grant(
        acceptor, dialer_kp.peer_id, RECIPROCAL_GRANT_VECTOR_FLOOR,
    )

    owner_policy = (
        f"system/capability/policy/{dialer._get_local_identity_hash().hex()}"
    )
    result = await asyncio.wait_for(
        acceptor._remote_execute(
            f"entity://{dialer_kp.peer_id}/system/tree",
            "get",
            {"data": {"path": owner_policy, "mode": "hash"}},
            resource_targets=[owner_policy],
        ),
        timeout=10.0,
    )
    assert result.status == 200, (
        f"out-of-floor origination status={result.status} "
        f"error={result.error!r} — 403 means the mint carried the flat §4.4 "
        f"floor while an inbound dialer to this peer receives the assembled "
        f"set; a timeout means the dialer never served the reach-back"
    )


async def test_an_acceptor_without_a_grant_fails_closed_not_hangs(pair):
    """Delivery + timing: bounded wait, then fail closed — never block.

    A counterpart that never adopts the grant degrades the establishment to
    one-directional, not to a hang.
    """
    dialer, dialer_kp, acceptor, acceptor_kp = pair
    # Classified as rendezvous-met on the acceptor (so it DOES wait), but
    # the dialer dials asymmetrically and mints nothing.
    acceptor.mark_rendezvous_establishment(dialer_kp.peer_id)
    await dialer._remote_pool.get_connection(acceptor_kp.peer_id)

    result = await asyncio.wait_for(
        acceptor._remote_execute(
            f"entity://{dialer_kp.peer_id}/system/tree", "get", None,
        ),
        timeout=RECIPROCAL_GRANT_VECTOR_FLOOR + 8.0,
    )
    assert result.status == 502
    assert "reciprocal grant" in (result.error or "")


# ---------------------------------------------------------------------------
# Acceptance — exactly the legs the frame carries
# ---------------------------------------------------------------------------


def _mint(granter_kp: Keypair, grantee_kp: Keypair):
    from entity_core.capability.grant import create_connect_grants

    grantee_identity = create_identity_entity(grantee_kp)
    return build_reentry_grant_envelope(
        granter_kp, grantee_identity, create_connect_grants(), 0x00,
    )


def test_a_well_formed_grant_is_accepted() -> None:
    granter, grantee = Keypair.generate(), Keypair.generate()
    envelope = _mint(granter, grantee)
    assert is_reentry_grant(envelope)

    granter_hash = create_identity_entity(granter).compute_hash()
    cap, supporting = accept_reentry_grant(envelope, granter_hash)
    assert cap["type"] == "system/capability/token"
    # The supporting entities are what the far side needs to walk the chain
    # — its granter identity and the cap signature — and are absent from
    # either handshake, because the dialer authored them after it.
    assert len(supporting) == 2


def test_a_grant_from_another_granter_is_refused() -> None:
    """Checked against the peer we AUTHENTICATED, not against the frame.

    A grant claiming any other granter is both useless (the far side roots
    the chain at its own identity) and dishonest to store.
    """
    granter, grantee, stranger = (
        Keypair.generate(), Keypair.generate(), Keypair.generate(),
    )
    envelope = _mint(granter, grantee)
    with pytest.raises(ReentryGrantError, match="not the peer authenticated"):
        accept_reentry_grant(
            envelope, create_identity_entity(stranger).compute_hash(),
        )


def test_a_substituted_capability_is_refused() -> None:
    """The cap's claimed content hash must recompute.

    A substituted entity would otherwise be installed and indexed under the
    wrong hash.
    """
    granter, grantee = Keypair.generate(), Keypair.generate()
    envelope = _mint(granter, grantee)
    for entry in envelope.included:
        if entry.get("type") == "system/capability/token":
            entry["data"] = dict(entry["data"])
            entry["data"]["created_at"] = 1
    with pytest.raises(ReentryGrantError, match="hash validation"):
        accept_reentry_grant(
            envelope, create_identity_entity(granter).compute_hash(),
        )


def test_a_grant_without_its_granter_signature_is_refused() -> None:
    """A single-sig root cap is `missing_signature` at the §5.5 walk anyway.

    Failing fast here trades a named local drop for a `403` one dispatch
    later at the cross-peer seam, where it is hardest to attribute.
    """
    granter, grantee = Keypair.generate(), Keypair.generate()
    envelope = _mint(granter, grantee)
    envelope.included = [
        e for e in envelope.included if e.get("type") != "system/signature"
    ]
    with pytest.raises(ReentryGrantError, match="no granter signature"):
        accept_reentry_grant(
            envelope, create_identity_entity(granter).compute_hash(),
        )


def test_a_forged_granter_signature_is_refused() -> None:
    granter, grantee, forger = (
        Keypair.generate(), Keypair.generate(), Keypair.generate(),
    )
    envelope = _mint(granter, grantee)
    granter_hash = create_identity_entity(granter).compute_hash()
    for entry in envelope.included:
        if entry.get("type") == "system/signature":
            target = normalize_hash(entry["data"]["target"])
            entry["data"] = dict(entry["data"])
            entry["data"]["signature"] = forger.sign(target)
            entry["content_hash"] = Entity(
                type=entry["type"], data=entry["data"],
            ).compute_hash()
    with pytest.raises(ReentryGrantError, match="does not verify"):
        accept_reentry_grant(envelope, granter_hash)


def test_an_empty_assembly_declines_to_mint() -> None:
    """An all-denying cap would advertise authority that dispatches to
    nothing; declining leaves the counterpart pre-adoption, which fails
    closed."""
    granter, grantee = Keypair.generate(), Keypair.generate()
    with pytest.raises(ReentryGrantError, match="empty"):
        build_reentry_grant_envelope(
            granter, create_identity_entity(grantee), [], 0x00,
        )


def test_the_carriage_frame_matches_the_shipped_cross_impl_shape() -> None:
    """The wire shape both shipped impls run — pinned, and flagged.

    `entity-core-rust` (`build_reentry_grant_envelope`) and
    `entity-core-go` (`core/protocol/reentry_grant.go`) agree on
    uri / operation / request_id / params / included. The folded Carriage
    bullet names none of the first three, so this constant is matched to
    the cohort, not derived from the spec — the divergence is filed, not
    papered over. If arch rules the ruled shape into existence, this test
    is what tells us the frame moved.
    """
    granter, grantee = Keypair.generate(), Keypair.generate()
    envelope = _mint(granter, grantee)
    data = envelope.root["data"]
    assert data["uri"] == "system/protocol/connect"
    assert data["operation"] == "reentry-grant"
    assert data["request_id"] == "connect-reentry-grant"
    assert data["params"]["type"] == "system/capability/token"
    # No author, no capability, no signature of its own: the frame arrives
    # before any authority relationship exists that could authorize it.
    assert "author" not in data
    assert "capability" not in data
    types = sorted(e["type"] for e in envelope.included)
    assert types == [
        "system/capability/token", "system/peer", "system/signature",
    ]
