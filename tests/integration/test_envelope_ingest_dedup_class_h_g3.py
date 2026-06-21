"""H-G3 / F2b — receiver-side write-amp dedup pin tests.

Regression-blocker fixture for the H-G3 cross-impl audit ask
(stage-6 closure handoff §2.3): receivers MUST short-circuit on
already-known content hashes so
identity + signature entities repeated across N envelopes don't pay the
full ingest cost on every delivery.

Two layers, both pinned here:

- **Layer 1** (`NotifyingContentStore.put`): unconditional re-puts of the
  same entity MUST be size-bounded (one entry per unique hash) and MUST
  fire content-store hooks only on the first put for that hash. Mirrors
  Go's `NotifyingContentStore.Put` early-return on `inner.Has(hash)`.

- **Layer 2** (`Peer._store_included_entities`): re-ingesting the same
  `envelope.included` N times MUST be content-store-size-bounded. The
  guard peeks the wire `content_hash` and skips the full
  `Entity.from_wire_dict` + `put_content_only` path for known entities.
  Mirrors Go's `IngestEnvelopeSignatures` Has-before-Put on identities +
  signatures.

If either guard regresses, the test name + this file's path identify
which layer broke.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.protocol.envelope import Envelope
from entity_core.storage.content_store import (
    ContentStoreEvent,
    NotifyingContentStore,
)


# ---------------------------------------------------------------------------
# Layer 1 — NotifyingContentStore.put idempotency
# ---------------------------------------------------------------------------


def test_notifying_content_store_put_is_size_idempotent_h_g3_layer_1():
    """Re-putting the same entity 100× MUST yield content store size 1.

    Pre-fix: `self._store[h] = entity` ran unconditionally on every call.
    Post-fix: early-return on `h in self._store`.
    """
    cs = NotifyingContentStore()
    entity = Entity(type="system/peer", data={"peer_id": "x", "k": 1})
    h = entity.compute_hash()

    for _ in range(100):
        ret = cs.put(entity)
        assert ret == h

    assert len(cs) == 1
    assert cs.has(h)


def test_notifying_content_store_hook_fires_once_per_hash_h_g3_layer_1():
    """Content-store hook MUST fire exactly once per unique hash even
    across many `put` calls — receiver-side hooks (persistence / query
    indexes per SYSTEM-COMPOSITION v1.2 positions 0/1) MUST NOT see
    repeats."""
    cs = NotifyingContentStore()
    events: list[ContentStoreEvent] = []

    class _Recorder:
        def on_content_stored(self, event: ContentStoreEvent) -> None:
            events.append(event)

    cs.add_content_hook(_Recorder(), name="recorder")

    entity = Entity(type="system/peer", data={"peer_id": "y"})
    for _ in range(50):
        cs.put(entity)

    assert len(events) == 1
    assert events[0].hash == entity.compute_hash()


# ---------------------------------------------------------------------------
# Layer 2 — Peer._store_included_entities idempotency
# ---------------------------------------------------------------------------


def _build_peer():
    return (
        PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
    )


def test_store_included_entities_is_size_idempotent_h_g3_layer_2():
    """Ingesting the same envelope N times MUST grow the content store
    by exactly the number of unique included entities (not N × that
    count). Pre-fix: every call ran `Entity.from_wire_dict` +
    `put_content_only` per included entity; the wire-hash peek skips
    both for entities already in the store.
    """
    peer = _build_peer()
    kp = Keypair.generate()

    identity = create_identity_entity(kp)
    target = b"\x00" + b"\xAB" * 32
    sig = create_signature_entity(kp, target, identity.compute_hash())

    # Use to_dict (carries content_hash on the wire per §1.8) so the
    # Layer-2 peek-hash short-circuit can fire.
    envelope = Envelope(
        root={"type": "primitive/any", "data": {}},
        included=[identity.to_dict(), sig.to_dict()],
    )

    baseline = len(peer.content_store)
    peer._store_included_entities(envelope)
    after_first = len(peer.content_store)
    assert after_first - baseline == 2, (
        "first ingest should add identity + signature"
    )

    for _ in range(20):
        peer._store_included_entities(envelope)

    assert len(peer.content_store) == after_first, (
        f"redundant ingests grew store: {after_first} → "
        f"{len(peer.content_store)} after 20 repeats"
    )
    # The included entities are still present.
    assert peer.content_store.has(identity.compute_hash())
    assert peer.content_store.has(sig.compute_hash())


def test_store_included_entities_skips_reconstruct_when_hash_known(monkeypatch):
    """Direct evidence the Layer 2 guard skips the work above
    `put_content_only` — `Entity.from_wire_dict` MUST NOT be called for
    included entities whose wire content_hash is already in the content
    store. This is the cost the guard actually saves.
    """
    peer = _build_peer()
    kp = Keypair.generate()
    identity = create_identity_entity(kp)

    envelope = Envelope(
        root={"type": "primitive/any", "data": {}},
        included=[identity.to_dict()],
    )

    # Prime: first ingest stores the entity.
    peer._store_included_entities(envelope)
    assert peer.content_store.has(identity.compute_hash())

    # Now count from_wire_dict invocations on the second pass.
    calls = 0
    original = Entity.from_wire_dict

    def _counting_from_wire_dict(d):
        nonlocal calls
        calls += 1
        return original(d)

    monkeypatch.setattr(Entity, "from_wire_dict", _counting_from_wire_dict)
    peer._store_included_entities(envelope)
    assert calls == 0, (
        f"Layer 2 guard regressed — from_wire_dict ran {calls}× for a known hash"
    )
