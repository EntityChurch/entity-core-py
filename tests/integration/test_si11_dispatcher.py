"""SI-11 dispatcher-level signature ingestion.

Per EXTENSION-IDENTITY v3.3 §6.2 (SI-11) and the Go cross-impl
python-failures report: signatures from envelope.included MUST
be bound at V7 invariant pointer paths
`/{signer_peer_id}/system/signature/{target_hex}` BEFORE any handler
body executes — so substrate ops like `system/attestation:verify`
observe the bindings even though they have no internal ingestion logic.

This file exercises the dispatcher hook directly (the wire-protocol
flow that the Go validator drives) and reproduces the TV-A4-style
scenario where signature-bearing envelopes drive substrate verification.
"""

from __future__ import annotations

from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_handlers.attestation import make_attestation


def _build_peer():
    kp = Keypair.generate()
    return PeerBuilder().with_keypair(kp).with_all_handlers().build(), kp


def test_dispatcher_binds_envelope_signature_at_v7_invariant_path():
    """The core invariant: when an envelope arrives carrying a
    `system/signature` entity in `included`, the dispatcher binds it at
    `{signer_peer_id}/system/signature/{target_hex}` so substrate
    handlers find it via `find_signature_by_signer`."""
    peer, kp = _build_peer()

    # Build an attestation entity locally + the signature over its hash.
    target = b"\x00" + b"P" * 32
    signer_identity = create_identity_entity(kp)
    signer_id_hash = signer_identity.compute_hash()
    att = make_attestation(
        attesting=signer_id_hash, attested=target,
        properties={"kind": "x"},
    )
    sig = create_signature_entity(kp, att.compute_hash(), signer_id_hash)

    # Synthesize the envelope shape the dispatcher would see at message
    # receipt — a root entity (whatever) plus included that carries the
    # signature + signer identity. The dispatcher hook is called from
    # Peer._store_included_entities + _bind_envelope_signatures.
    envelope = Envelope(
        root={"type": "primitive/any", "data": {}},
        included=[signer_identity.to_dict(), sig.to_dict()],
    )

    # Drive the dispatcher hooks directly — this is what _handle_connection
    # invokes per envelope.
    peer._store_included_entities(envelope)
    peer._bind_envelope_signatures(envelope)

    # Signature is now bound at the V7 invariant pointer path.
    expected_path = peer.emit_pathway.entity_tree.normalize_uri(
        f"{kp.peer_id}/system/signature/{att.compute_hash().hex()}",
    )
    bound = peer.emit_pathway.entity_tree.get(expected_path)
    assert bound == sig.compute_hash()


def test_substrate_attestation_verify_finds_dispatcher_bound_signature():
    """End-to-end: dispatcher binds the signature; substrate
    `system/attestation:verify` then validates successfully without any
    handler-level ingestion. This is the TV-A4-style flow that was
    failing before SI-11 moved to dispatcher level."""
    import asyncio
    from entity_core.handlers.context import HandlerContext
    from entity_core.storage.emit import EmitContext
    from entity_handlers.attestation import attestation_handler

    peer, kp = _build_peer()

    # Bind the attestation entity at SOME path (substrate path-as-resource
    # MUST per SI-7) so :verify can find it in the content store.
    target_peer = b"\x00" + b"P" * 32
    signer_identity = create_identity_entity(kp)
    signer_id_hash = signer_identity.compute_hash()
    att = make_attestation(
        attesting=signer_id_hash, attested=target_peer,
        properties={"kind": "x"},
    )
    att_hash = att.compute_hash()
    sig = create_signature_entity(kp, att_hash, signer_id_hash)

    # Step 1: simulate envelope arrival with sig in included.
    envelope = Envelope(
        root={"type": "primitive/any", "data": {}},
        included=[signer_identity.to_dict(), sig.to_dict()],
    )
    peer._store_included_entities(envelope)
    peer._bind_envelope_signatures(envelope)

    # Step 2: independently bind the attestation at its tree path
    # (the validator may send a separate tree:put or substrate :create).
    bind_path = f"test/attestation/{att_hash.hex()}"
    peer.emit_pathway.emit(bind_path, att, EmitContext.bootstrap())

    # Step 3: invoke substrate `system/attestation:verify` over the
    # attestation hash. The dispatcher-bound signature MUST be visible.
    handler_ctx = HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=peer.keypair.peer_id,
        handler_grant={},
        caller_capability={},
        emit_pathway=peer.emit_pathway,
        handler_pattern="system/attestation",
        keypair=peer.keypair,
    )
    result = asyncio.run(attestation_handler(
        "system/attestation", "verify",
        {"data": {"attestation_hash": att_hash}},
        handler_ctx,
    ))
    assert result["status"] == 200
    assert result["result"]["data"]["valid"] is True


def test_dispatcher_binding_is_idempotent_on_identical_hash():
    """Two envelopes carrying the same signature don't produce conflict
    errors; the second binding is a no-op."""
    peer, kp = _build_peer()
    target = b"\x00" + b"X" * 32
    signer_identity = create_identity_entity(kp)
    signer_id_hash = signer_identity.compute_hash()
    att = make_attestation(
        attesting=signer_id_hash, attested=target,
        properties={"kind": "x"},
    )
    sig = create_signature_entity(kp, att.compute_hash(), signer_id_hash)
    envelope = Envelope(
        root={"type": "primitive/any", "data": {}},
        included=[signer_identity.to_dict(), sig.to_dict()],
    )

    # Two passes; second is a no-op.
    peer._store_included_entities(envelope)
    peer._bind_envelope_signatures(envelope)
    peer._store_included_entities(envelope)
    peer._bind_envelope_signatures(envelope)

    expected_path = peer.emit_pathway.entity_tree.normalize_uri(
        f"{kp.peer_id}/system/signature/{att.compute_hash().hex()}",
    )
    assert peer.emit_pathway.entity_tree.get(expected_path) == sig.compute_hash()


def test_dispatcher_skips_when_no_matching_identity():
    """A signature whose `signer` references an unknown identity is
    skipped (peer_id can't be recovered). No error; downstream validator
    will reject when verifying."""
    peer, _ = _build_peer()
    # Synthesize a sig pointing at a nonexistent signer hash.
    bogus_signer = b"\x00" + b"\xFF" * 32
    sig = Entity(
        type="system/signature",
        data={
            "target": b"\x00" + b"T" * 32,
            "signer": bogus_signer,
            "algorithm": "ed25519",
            "signature": b"\x00" * 64,
        },
    )
    envelope = Envelope(
        root={"type": "primitive/any", "data": {}},
        included=[sig.to_dict()],
    )
    def _sig_paths() -> set[str]:
        return {
            u for u in peer.emit_pathway.entity_tree.list_prefix(
                peer.emit_pathway.entity_tree.normalize_uri("/")
            )
            if "/system/signature/" in u
        }

    # Snapshot the bootstrap handler-grant signatures (which now live at
    # the §3.5 invariant-pointer path `/system/signature/{grant_hash}` per
    # v7.74 v0.4 §3.4) so we measure only what this envelope binds.
    before = _sig_paths()
    peer._store_included_entities(envelope)
    peer._bind_envelope_signatures(envelope)
    # No NEW path was bound (no identity → no peer_id → skip).
    assert _sig_paths() == before
