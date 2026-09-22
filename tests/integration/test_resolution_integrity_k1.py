"""K1 — resolution integrity: the author-identity forgery, driven at this seat.

`ENTITY-CORE-PROTOCOL` §1.8 item 1 (0.8.2.23) promotes the ``included``-map
keying from a *description of how senders build the map* to a **receiver
obligation**, and states it as a PROPERTY with two conformant mechanisms:

    **resolution integrity — an implementation MUST NOT resolve an entity used
    for any authority decision through an address it has not verified against
    that entity's content.** Two mechanisms satisfy this and an implementation
    MUST implement at least one: **(a) bind the key** … or **(b) discard the
    key** — drop wire-supplied keys at the decode boundary and address entities
    exclusively by a ``content_hash`` validated under this item. ⚠ **Mechanism
    (b) depends on this item running at EVERY ingress and MUST NOT be adopted
    without it.**

The attack the rule exists for: an attacker who knows a victim's identity hash
— the public ``grantee`` field of any capability the victim presents — files
**their own** ``system/peer`` under that key. Their own signature then verifies
against their own key while the peer attributes the request to the victim.

.. rubric:: Why the probe is owed even though this seat is immune

`entity-core-go`'s ``ROUTING-2026-09-13-f`` §7 relays: *"You are structurally
immune to K1 (mechanism 2)"* — and that is the **flattering direction**, the
branch that terminates in no work. The standing rule is that a routed report's
claims about our repo are hearsay, and the same packet says so itself: *"⚠ You
still owe the K1 PROBE."* Immunity by construction is a claim about a
mechanism; a probe is a measurement. The two are not the same artifact, and
this file is the second one.

.. rubric:: What was verified before writing it

``Envelope.from_dict`` discards the wire map key — ``list(included_raw.values())``
— and every rebuilt by-hash index in the tree
(``peer._collect_wire_included``-adjacent ``included_by_hash``, ``ctx.included``,
``relay._included_entity``) keys by the entity's **own** ``content_hash`` field,
which the framing layer validated against ``{type, data}`` on receipt. So
mechanism (b) is implemented.

Its precondition is the part that is not structural: ``ContentStore.put`` keys
by ``entity.compute_hash()``, and ``Entity.compute_hash`` **returns the carried
hash verbatim when one is set** (§1.8's *trust, do not recompute* half). So a
mis-stamped entity would be filed in the content store under an unverified
address — the store is content-addressed *because ingress validated*, not by
construction. That is the same non-local argument arch told go to close at
``Envelope.Include``; here it holds, and :class:`TestThePreconditionIsTheRule`
pins the ingress that makes it hold rather than leaving it as a comment.

.. rubric:: The two arms, and why py answers differently on each

An attacker filing their identity under the victim's key must choose what to
put in the entity's own ``content_hash`` field, and the two choices are refused
by two different mechanisms at two different layers:

=======================================  ==========================================
attacker stamps the VICTIM's hash        refused at the **decode boundary** —
(so key and field agree, and the map     ``validate_entity_hash`` recomputes from
looks internally consistent)             ``{type, data}`` and mismatches.
                                         §5.2a's corollary: **400** ``hash_mismatch``
attacker stamps their OWN true hash      passes ingress, then the victim's hash
(so the entity is self-consistent and    **resolves to nothing** — the key that
only the map KEY lies)                   said "victim" was discarded. A lookup
                                         MISS, not a detection: **401**
                                         ``authentication_failed``
=======================================  ==========================================

Both are conformant and §5.2a says so in terms — the three resolution-integrity
rows *"take the class of the lookup they corrupt, not of the check that detects
them"*, and *"a peer that discards the key … never detects it at all — the
lookup simply misses, and a miss inherits the row of the step that missed."*
The author row is **401 authentication_failed**, which is what the miss
produces. go's relay predicted this arm; it is measured here rather than
accepted.

**This is the cohort-comparable number.** go refuses by a receive-boundary
connection **close** with no status, and routed *"is a coded 400/401/403
required, or is fail-closed close conformant?"* to arch as finding (1). py
answers a coded **401** on one arm and a coded **400** on the other, so this
seat's data point is: *the coded response is reachable, and it is two different
codes for two different attacker spellings of one attack.*

.. rubric:: ⛔ CORRECTION (0.8.2.24) — the 400 half of that claim was FALSE

The paragraph above went into a routing packet as a cohort-comparable
measurement. **The 401 arm is true**; that request is admitted and refused by
`verify_request`. **The 400 arm was not.** Arm 1's row below asserts
``pytest.raises(HashValidationError)`` against ``recv_envelope`` called
directly, and its *"which the wire boundary renders as that pair"* was prose
in a docstring that nothing drove. Measured on a socket, the serve loop caught
the exception, logged it at INFO and closed — **a bare close with nothing on
the wire, byte-identical to the go behaviour this paragraph contrasts py
with.**

So py was arguing for a rule it did not implement, and go's finding (1) was
about both of us. `N4` now pins it and the fix is in `peer.py`
(`_emit_decode_refusal`); the claim is driven by
`test_decode_boundary_refusal_n4.py`, every row of which opens a socket.

**The arms below still measure what they say** — the two attacker spellings
really are refused by two different mechanisms at two different layers, and
that is the finding. What was wrong was the sentence about what reaches the
wire. *A row that asserts an exception is evidence about the exception; only a
row that reads the socket is evidence about the response.*
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import (
    create_authenticated_request,
    create_identity_entity,
    create_signature_entity,
    verify_request_integrity,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.protocol.framing import (
    HashValidationError,
    recv_envelope,
)
from entity_core.protocol.messages import Execute
from entity_core.utils.ecf import ecf_encode

from entity_handlers.capability import (
    CAPABILITY_HANDLER_PATTERN,
    capability_handler,
)


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _full_access_cap() -> dict[str, object]:
    return {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*", "/*/*"]},
            "operations": {"include": ["*"]},
            "peers": {"include": ["*"]},
        }]
    }


async def _authenticated_envelope(peer, victim_kp):
    """A genuine, valid EXECUTE authored by ``victim_kp``.

    This is the **positive control** and the base every forgery below mutates,
    so each arm differs from a request that works in exactly one respect.
    """
    victim_identity = create_identity_entity(victim_kp)
    ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=victim_kp.peer_id,
        handler_grant=_full_access_cap(),
        caller_capability=_full_access_cap(),
        handler_pattern=CAPABILITY_HANDLER_PATTERN,
        emit_pathway=peer.emit_pathway,
        keypair=peer.keypair,
        included={},
        author_identity_hash=victim_identity.compute_hash(),
        remote_identity_hash=victim_identity.compute_hash(),
    )
    mint = await capability_handler(
        CAPABILITY_HANDLER_PATTERN, "request",
        {"data": {"grants": [{
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["app/*"]},
            "operations": {"include": ["get"]},
        }]}}, ctx,
    )
    assert mint["status"] == 200, mint
    cap_hash = mint["result"]["data"]["token"]
    cap_dict = mint["envelope_included"][cap_hash]
    chain: list[dict] = []
    for h, ent in mint["envelope_included"].items():
        if h != cap_hash:
            chain.append(ent)
            peer.content_store.put(Entity.from_dict(ent))
    peer.content_store.put(Entity.from_dict(cap_dict))

    execute = Execute.create(
        uri=f"entity://{peer.keypair.peer_id}/app/anything", operation="get",
    )
    auth = create_authenticated_request(
        keypair=victim_kp, execute=execute,
        capability_dict=cap_dict, capability_chain=chain,
    )
    return auth.to_envelope(), victim_identity


def _forge_author_identity(
    envelope: Envelope, victim_identity: Entity, attacker_kp: Keypair,
    *, stamp_victim_hash: bool,
) -> Envelope:
    """Replace the victim's identity entity with the attacker's.

    The forged entity is filed **under the victim's hash** — which is what an
    attacker controls, because the map key is a wire field. ``execute.author``
    and the signature's ``signer`` both still name the victim, so
    ``signer == author == victim`` and the ``signer_author_mismatch`` check
    cannot fire: **nothing but the key binding distinguishes accept from
    refuse.** That isolation is what go's §5 ask requires of the probe.

    .. rubric:: The execute is RE-SIGNED with the attacker's key

    This is the half the first draft omitted, and the omission was invisible
    until the mutation: leaving the victim's signature in place means the
    forgery is refused because *the signature does not verify against the
    identity*, which is a **second, independent** refusal. The arm then cannot
    tell a peer that binds its keys from one that merely checks signatures —
    the standing law that a fixture satisfying two refusals at once has told
    you nothing about either.

    So the signature is re-minted by the **attacker's** keypair while still
    declaring ``signer = victim`` (go's ``signEntity(execHash, attackerKP,
    victimIdentity)``). It then verifies perfectly against the attacker's
    identity — the entity the peer will find if it trusts the wire key — and
    the ONLY thing left that can refuse is the address binding.

    ``stamp_victim_hash`` selects which of the two attacker spellings is used —
    see the table in the module docstring.
    """
    victim_hash = victim_identity.compute_hash()
    attacker_identity = create_identity_entity(attacker_kp)
    forged = attacker_identity.to_dict()
    forged["content_hash"] = victim_hash if stamp_victim_hash else attacker_identity.compute_hash()

    execute_hash = envelope.root.get("content_hash")
    attacker_signature = create_signature_entity(
        attacker_kp, execute_hash, signer_identity_hash=victim_hash,
    ).to_dict()

    replaced = []
    for e in envelope.included:
        if _is_identity_at(e, victim_hash):
            replaced.append(forged)
        elif e.get("type") == "system/signature" and e.get("data", {}).get("target") == execute_hash:
            replaced.append(attacker_signature)
        else:
            replaced.append(e)
    assert any(e is forged for e in replaced), "fixture premise: the victim identity was in `included`"
    assert any(e is attacker_signature for e in replaced), (
        "fixture premise: the execute's signature was in `included` and was replaced — "
        "without this the arm refuses on the signature and measures nothing about the binding"
    )
    return Envelope(root=envelope.root, included=replaced)


def _is_identity_at(entity_dict: dict, h: bytes) -> bool:
    return (
        entity_dict.get("type") == "system/peer"
        and entity_dict.get("content_hash") == h
    )


async def _through_the_wire(
    envelope: Envelope, *, rekey: dict[bytes, bytes] | None = None,
) -> Envelope:
    """Drive the real TCP ingress — the site mechanism (b)'s precondition names.

    ``Envelope.from_dict`` alone does NOT validate; validation lives in
    ``recv_envelope``. Calling ``from_dict`` here would test the decode and
    skip the obligation, which is the whole distinction §1.8 draws.

    .. rubric:: ``rekey`` exists because ``to_dict`` is a CONFORMANT sender

    ``Envelope.to_dict`` keys each entry by the entity's own ``content_hash``,
    so it cannot *build* a mis-keyed map — which is correct of a sender and
    useless for a probe. **An attacker does not use our serializer.** Without
    this, "file the attacker's identity under the victim's hash" silently
    degrades into "the victim's identity is absent", and the arm measures a
    lookup that finds nothing rather than a lookup that finds the wrong thing.
    Those two produce the same status here and completely different statuses on
    a peer that trusts the key — so the degraded arm would score a
    key-trusting peer green.

    *This was the first draft's defect, found by asking what the K1 mutation
    would do rather than by re-reading the arm: the mutation that should have
    made the forgery succeed could not, because nothing was filed where the
    peer would look. A probe whose attack cannot be expressed is not a control.*
    """
    wire = envelope.to_dict()
    if rekey:
        included = wire.get("included", {})
        wire["included"] = {
            rekey.get(k, k): v for k, v in included.items()
        }
    payload = ecf_encode(wire)
    reader = asyncio.StreamReader()
    reader.feed_data(struct.pack(">I", len(payload)) + payload)
    reader.feed_eof()
    return await recv_envelope(reader)


# ---------------------------------------------------------------------------
# The positive control — the anchor every refusal is measured against
# ---------------------------------------------------------------------------

class TestThePositiveControl:
    """Without this, every row below passes on a peer that refuses everything."""

    @pytest.mark.asyncio
    async def test_a_genuine_request_verifies(self, peer):
        envelope, _ = await _authenticated_envelope(peer, peer.keypair)
        received = await _through_the_wire(envelope)
        result = verify_request_integrity(received, local_peer_id=peer.peer_id)
        assert result.valid is True, result.error


# ---------------------------------------------------------------------------
# The forgery — both attacker spellings
# ---------------------------------------------------------------------------

class TestTheAuthorForgery:
    """``signer == author == victim``; only the map key lies."""

    @pytest.mark.asyncio
    async def test_stamping_the_victims_hash_is_refused_at_the_decode_boundary(
        self, peer,
    ):
        """Arm 1 — the attacker makes key and field agree.

        §5.2a's corollary: *"A peer that refuses at the decode boundary —
        before the envelope becomes a request — answers 400 ``hash_mismatch``
        … and reaches none of these rows."* Here the refusal is
        ``HashValidationError`` out of ``validate_entity_hash``, which the wire
        boundary renders as that pair.
        """
        envelope, victim_identity = await _authenticated_envelope(peer, peer.keypair)
        forged = _forge_author_identity(
            envelope, victim_identity, Keypair.generate(), stamp_victim_hash=True,
        )
        with pytest.raises(HashValidationError):
            await _through_the_wire(forged)

    @pytest.mark.asyncio
    async def test_stamping_the_attackers_own_hash_makes_the_author_UNRESOLVABLE(
        self, peer,
    ):
        """⭐ Arm 2 — the isolated forgery, and the arm mechanism (b) defines.

        The forged entity is self-consistent, so it survives ingress. The wire
        map key claiming *"this is the victim"* was **discarded at decode**, so
        the victim's hash resolves to nothing and the request is refused as an
        authentication failure — §5.2a's author row, reached by a **miss**
        rather than by a detection.

        The attacker's identity is present in ``included`` and verifies against
        the attacker's own key. Under a peer that kept the wire key as an
        address, this is an accepted request attributed to the victim.
        """
        envelope, victim_identity = await _authenticated_envelope(peer, peer.keypair)
        attacker = Keypair.generate()
        forged = _forge_author_identity(
            envelope, victim_identity, attacker, stamp_victim_hash=False,
        )
        # File it under the VICTIM's hash — the attacker controls the map key.
        attacker_hash = create_identity_entity(attacker).compute_hash()
        received = await _through_the_wire(
            forged, rekey={attacker_hash: victim_identity.compute_hash()},
        )

        result = verify_request_integrity(received, local_peer_id=peer.peer_id)
        assert result.valid is False, (
            "the author forgery was ACCEPTED — the peer resolved the author "
            "through a wire-supplied address it never verified (§1.8), and "
            "attributed the attacker's signed request to the victim"
        )
        assert result.error_code == "authentication_failed", (
            f"§5.2a assigns the author row the AUTH class (401); got "
            f"{result.error_code!r}. The row takes the class of the lookup it "
            f"corrupts, not of the check that detects it"
        )

    @pytest.mark.asyncio
    async def test_the_attacker_identity_really_did_ride_in(self, peer):
        """The row that makes the refusal attributable.

        A refusal proves nothing if the forged entity never reached the peer.
        This pins that the attacker's identity survived ingress intact — so
        arm 2's refusal is the *resolution* failing, not the transport.
        """
        envelope, victim_identity = await _authenticated_envelope(peer, peer.keypair)
        attacker = Keypair.generate()
        forged = _forge_author_identity(
            envelope, victim_identity, attacker, stamp_victim_hash=False,
        )
        attacker_hash = create_identity_entity(attacker).compute_hash()
        received = await _through_the_wire(
            forged, rekey={attacker_hash: victim_identity.compute_hash()},
        )

        assert received.find_included(attacker_hash) is not None, (
            "the attacker's identity did not survive ingress; arm 2's refusal "
            "would then be attributable to the transport rather than to the "
            "address binding"
        )
        assert received.find_included(victim_identity.compute_hash()) is None, (
            "the victim's hash still resolved — the wire key was retained as "
            "an address, which §1.8 calls non-conformant outright"
        )


# ---------------------------------------------------------------------------
# The control that keeps this a binding test and not a signature test
# ---------------------------------------------------------------------------

class TestTheSignerMismatchControl:
    """go's third arm: signature verification is independently live.

    Without it, a peer could refuse arm 2 for the wrong reason and this file
    would read as coverage of a binding it never exercised.
    """

    @pytest.mark.asyncio
    async def test_a_correct_identity_signed_by_someone_else_is_refused(self, peer):
        envelope, _ = await _authenticated_envelope(peer, peer.keypair)
        received = await _through_the_wire(envelope)
        # Corrupt the signature bytes in place: the identity is the genuine
        # one and correctly addressed, so only the signature can refuse.
        tampered = []
        for ent in received.included:
            if ent.get("type") == "system/signature":
                ent = {**ent, "data": {**ent["data"], "signature": b"\x00" * 64}}
            tampered.append(ent)
        result = verify_request_integrity(
            Envelope(root=received.root, included=tampered),
            local_peer_id=peer.peer_id,
        )
        assert result.valid is False


# ---------------------------------------------------------------------------
# Mechanism (b)'s PRECONDITION — the half that is not structural here
# ---------------------------------------------------------------------------

class TestThePreconditionIsTheRule:
    """§1.8: mechanism (b) *"MUST NOT be adopted without"* validation at every
    ingress.

    ``Entity.compute_hash`` returns the **carried** hash when one is set, and
    ``ContentStore.put`` keys by that — so the content store's addresses are
    verified *because ingress validated them*, not by construction. Narrowing
    the ingress pass would therefore not merely relax a check: it would
    invalidate the mechanism this peer's immunity rests on. go's relay says
    exactly that — *"its precondition is now normative … Do not narrow it."*

    These rows are the enforcement point for that sentence.
    """

    @pytest.mark.asyncio
    async def test_the_tcp_ingress_validates_every_included_entity(self, peer):
        """Not only the root, and not only entities that carry a hash."""
        envelope, victim_identity = await _authenticated_envelope(peer, peer.keypair)
        mutated = []
        for ent in envelope.included:
            if ent.get("type") == "system/peer":
                # Content changed, carried hash left alone: self-inconsistent.
                ent = {**ent, "data": {**ent["data"], "injected": "x"}}
            mutated.append(ent)
        with pytest.raises(HashValidationError):
            await _through_the_wire(Envelope(root=envelope.root, included=mutated))

    def test_the_carried_hash_is_what_the_content_store_keys_by(self, peer):
        """The structural fact that makes the precondition load-bearing.

        Pinned as a row rather than stated in a comment: if
        ``compute_hash`` ever recomputed instead, the store would be
        self-verifying and this file's reasoning would need revisiting — which
        is a thing a later reader should be told by a failing test, not left to
        re-derive.
        """
        entity = Entity(type="system/peer", data={"k": "v"})
        true_hash = entity.compute_hash()
        carried = Entity(
            type="system/peer", data={"k": "v", "different": True},
            content_hash=true_hash,
        )
        assert carried.compute_hash() == true_hash, (
            "compute_hash recomputed a carried hash — §1.8's trust half is "
            "gone, and with it the reason this peer stores by a validated "
            "address"
        )
