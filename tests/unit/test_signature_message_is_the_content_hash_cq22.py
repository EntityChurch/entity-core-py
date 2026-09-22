"""§7.3 / `CQ-22` (0.8.2.26) — what a signature signs, at BOTH of py's homes.

**Ruled:** the message is the target entity's **full `content_hash`** —
``varint(format_code) ‖ SHA256(ECF({type, data}))`` — never the bare digest,
never the entity's canonical-ECF bytes. §7.3 is now its *single normative
home*, and four other sections plus `ENTITY-CBOR-ENCODING` Appendix E are
declared downstream of it.

.. rubric:: ⛔ Why this file exists: arch's exculpation of py was half true

`ROUTING-2026-09-16-c` §1: *"Your peer is already right… **the sole
implementation of the losing reading is the conformance fixture.**"*

Measured here, that sentence is true of **one** of py's two implementations:

===========================  ==========================  ==============
home                         message                     verdict
===========================  ==========================  ==============
``auth.create_signature_     ``keypair.sign(target_      ✅ §7.3
entity``  (the peer)         hash)`` — the full hash
``conformance.emit.          ``keypair.sign(ecf_         ⛔ the LOSING
_emit_signature``            encode(entity))``           reading
===========================  ==========================  ==============

So py was a **second implementation of the losing reading**, in the one
component whose entire job is to produce bytes other seats bless against. `S-1`
item 4 asks for *"a second independent codec"* to cross-bless the regenerated
``signature`` vectors — had py been used, it would have **confirmed the wrong
bytes**, and two independent codecs agreeing is the most convincing green
there is.

⭐ **And the corpus's own defect had the identical shape in our source.** Arch:
*"The artifact contains its own correct input one category above —
``content_hash.1`` produces the exact value §7.3 names as the message, and the
``signature`` category three rows down does not use it."* In ``emit.py``,
:func:`_emit_content_hash` sat **directly above** ``_emit_signature`` and was
never called by it. That is the standing two-representations law with the
**conformance emitter and the peer** as the two representations of one rule,
in a repo that had never compared them.

.. rubric:: What these rows are for

py's local corpus leaves every ``canonical`` as ``h''`` (pre-cross-bless), so
**no vector could ever have caught this** — the emitter's output is compared
to nothing. The oracle has to be the rule itself, and the peer.
"""

from __future__ import annotations

import hashlib

from entity_core.conformance.emit import _emit_content_hash, _emit_signature
from entity_core.crypto.identity import Keypair
from entity_core.protocol.auth import create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ecf_encode

_SEED = bytes(32)
_ENTITY = {"type": "test/v1", "data": {"x": 1}}


def _ruled_message(entity: dict) -> bytes:
    """§7.3's message, written out rather than imported.

    Deliberately NOT ``_emit_content_hash(...)``: an oracle that calls the
    function under test moves with it. This is the spec sentence as code.
    """
    return b"\x00" + hashlib.sha256(
        ecf_encode({"type": entity["type"], "data": entity["data"]})
    ).digest()


class TestTheEmitterSignsTheRuledMessage:
    def test_the_signature_verifies_against_the_full_content_hash(self):
        sig = _emit_signature({"seed": _SEED, "entity": _ENTITY})
        keypair = Keypair.from_seed(_SEED)
        # Verifies iff the emitter signed exactly this message.
        keypair.public_key.verify(sig, _ruled_message(_ENTITY))

    def test_it_does_NOT_sign_the_ECF_BYTES(self):
        """The losing reading, pinned as refused.

        This is the assertion that would have gone RED on the pre-0.8.2.26
        emitter, and nothing in the corpus could produce it: every
        ``canonical`` in py's copy is ``h''``.
        """
        sig = _emit_signature({"seed": _SEED, "entity": _ENTITY})
        keypair = Keypair.from_seed(_SEED)
        import pytest
        from cryptography.exceptions import InvalidSignature

        with pytest.raises(InvalidSignature):
            keypair.public_key.verify(sig, ecf_encode(_ENTITY))

    def test_it_does_NOT_sign_the_BARE_DIGEST(self):
        """The third reading the corpus carried (`ENTITY-NATIVE-TYPE-SYSTEM`
        §10.2 said the bare digest while citing §7.3 as its authority).

        The format code is the **domain separator**: without it one signature
        validates for one entity under every hash format §1.2 allocates.
        """
        sig = _emit_signature({"seed": _SEED, "entity": _ENTITY})
        keypair = Keypair.from_seed(_SEED)
        import pytest
        from cryptography.exceptions import InvalidSignature

        bare = _ruled_message(_ENTITY)[1:]
        with pytest.raises(InvalidSignature):
            keypair.public_key.verify(sig, bare)

    def test_the_emitter_reuses_the_content_hash_category(self):
        """⭐ The structural row: the two categories cannot drift apart.

        The corpus defect was that ``signature`` did not use the value
        ``content_hash`` produces one category above. Asserting the two agree
        is what stops that recurring here — a behavioural row on each
        separately passes a tree where they have diverged again.
        """
        assert _emit_content_hash(_ENTITY) == _ruled_message(_ENTITY)


class TestThePeerAndTheEmitterAGREE:
    """The comparison this repo had never made.

    Two homes for one rule, in one process, and nothing had ever asserted
    they produce the same bytes. arch's exculpation of py rested on the peer;
    the emitter is what a cross-bless would have used.
    """

    def test_the_peer_signs_the_same_message_the_emitter_does(self):
        keypair = Keypair.from_seed(_SEED)
        entity = Entity(type=_ENTITY["type"], data=_ENTITY["data"])
        target_hash = entity.compute_hash()

        # The peer's message IS the content hash — pin that first, or the
        # agreement below could be two implementations sharing one defect.
        assert target_hash == _ruled_message(_ENTITY)

        sig_entity = create_signature_entity(keypair, target_hash)
        peer_sig = sig_entity.data["signature"]
        emitter_sig = _emit_signature({"seed": _SEED, "entity": _ENTITY})

        assert peer_sig == emitter_sig, (
            "py's peer and py's conformance emitter sign different messages. "
            "The emitter is what a cross-bless blesses; the peer is what the "
            "cohort handshakes against. They are one rule (§7.3) and must be "
            "one construction."
        )
