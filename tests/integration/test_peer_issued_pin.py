"""PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2 — the **pin**, both halves.

The backend logic (§2.1 steps 1–5) is exercised by the six REG-PEERISSUED
vectors in `test_registry.py`, which hand the resolver a fake reader directly.
What those cannot see is the thing an operator actually configures: the pin.

> *"Registering a backend is not the same as consulting one — with no
> resolver-config installed the §4 chain is empty and the pinned registry is
> never dialed."*

An un-armed chain answers `chain_exhausted`, which is precisely what four of
the six vectors expect on their negative paths. So a pin that installs only
half of what it needs makes those four go green having dialed nothing. These
vectors assert the two halves separately, and then assert the **fetch
pattern** — which paths the backend actually reads — rather than status alone.
"""

from __future__ import annotations

import unicodedata

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_handlers import registry as _registry_mod

RESOLVER_CONFIG_PATH = "system/registry/resolver-config"
BINDING_TYPE = "system/registry/binding"
ENDPOINT = "http://reef.invalid/tree/"


def _ctx(peer) -> HandlerContext:
    blanket = {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }],
    }
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test",
        handler_grant=blanket,
        caller_capability=blanket,
        emit_pathway=peer.emit_pathway,
        handler_pattern="system/registry",
    )


async def _resolve(peer, name: str):
    return await _registry_mod.registry_handler(
        "system/registry", "resolve", {"data": {"name": name}}, _ctx(peer),
    )


def _read_config(peer) -> dict:
    uri = peer.entity_tree.normalize_uri(RESOLVER_CONFIG_PATH)
    h = peer.entity_tree.get(uri)
    assert h is not None, "no resolver-config installed"
    return peer.content_store.get(h).data


class _RecordingReader:
    """A `RegistryReader` that records every path and hash it was asked for.

    The point is the fetch pattern: a backend that answered from somewhere
    else entirely (a lucky local precede, a cached result) would produce the
    same status with an empty log.
    """

    def __init__(self, tree: dict[str, bytes], content: dict[bytes, Entity]) -> None:
        self._tree = dict(tree)
        self._content = {bytes(k): v for k, v in content.items()}
        self.tree_reads: list[str] = []
        self.content_reads: list[bytes] = []

    async def tree_get(self, path: str) -> bytes | None:
        self.tree_reads.append(path)
        return self._tree.get(path)

    async def content_get(self, h: bytes) -> Entity | None:
        self.content_reads.append(bytes(h))
        return self._content.get(bytes(h))


def _published_binding(registry_kp: Keypair, name: str, target: str):
    """What the registry peer publishes for one name: the binding, its
    signature, and the by-name + invariant pointers."""
    nfc = unicodedata.normalize("NFC", name)
    binding = Entity(type=BINDING_TYPE, data={
        "name": nfc, "kind": "peer-issued", "target_peer_id": target,
        "transports": [], "issued_at": 1000, "ttl": None,
    })
    bh = binding.compute_hash()
    identity = create_identity_entity(registry_kp)
    sig = create_signature_entity(registry_kp, bh, identity.compute_hash())
    sh = sig.compute_hash()
    return _RecordingReader(
        tree={
            f"system/registry/binding/by-name/{nfc}": bh,
            f"system/signature/{bh.hex()}": sh,
        },
        content={bh: binding, sh: sig},
    ), binding


def _pinned_peer(registry_peer_id: str, endpoint: str = ENDPOINT):
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_all_handlers()
        .with_peer_issued_registry(registry_peer_id, endpoint)
        .build()
    )


class TestThePinInstallsBothHalves:
    def test_the_resolver_chain_carries_the_pinned_registry(self):
        registry_kp = Keypair.generate()
        peer = _pinned_peer(registry_kp.peer_id)
        chain = _read_config(peer)["resolver_chain"]

        entries = {e["backend_kind"]: e for e in chain}
        assert "peer-issued" in entries, (
            "pin installed no peer-issued chain entry — the §4 chain would "
            "never dial the registry and every resolve would be chain_exhausted"
        )
        entry = entries["peer-issued"]
        assert entry["backend_id"] == registry_kp.peer_id
        assert entry["hints"]["endpoint"] == ENDPOINT
        # The trust anchor is QUALIFIED by the backend id: §2.1 step 3 binds
        # the signer to THIS registry, not to "some peer-issued registry".
        assert entry["accepted_trust_anchors"] == [
            f"peer_issued:{registry_kp.peer_id}"
        ]

    def test_the_local_name_store_keeps_priority_zero(self):
        registry_kp = Keypair.generate()
        peer = _pinned_peer(registry_kp.peer_id)
        chain = sorted(_read_config(peer)["resolver_chain"], key=lambda e: e["priority"])
        # A peer's own names win over a remote registry's.
        assert chain[0]["backend_kind"] == "local-name"
        assert chain[1]["backend_kind"] == "peer-issued"

    def test_the_trust_root_is_pinned_locally(self):
        """The registry IDENTITY is never fetched from the registry — a trust
        root you download from the thing it authenticates is not one."""
        registry_kp = Keypair.generate()
        peer = _pinned_peer(registry_kp.peer_id)
        identity = create_identity_entity(registry_kp)
        stored = peer.content_store.get(identity.compute_hash())
        assert stored is not None, (
            "pin installed no trust root — every binding the registry serves "
            "would fail signature_failed with nothing to verify against"
        )
        assert stored.type == "system/peer"
        assert stored.data["public_key"] == registry_kp.public_key_bytes()

    def test_several_registries_pin_in_declaration_order(self):
        first, second = Keypair.generate(), Keypair.generate()
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_peer_issued_registry(first.peer_id, "http://one.invalid/")
            .with_peer_issued_registry(second.peer_id, "http://two.invalid/")
            .build()
        )
        chain = sorted(_read_config(peer)["resolver_chain"], key=lambda e: e["priority"])
        assert [e["backend_id"] for e in chain[1:]] == [first.peer_id, second.peer_id]

    def test_a_peer_id_with_no_public_key_is_refused(self):
        """A SHA-256-form PeerID carries no key to verify against. Refusing
        loudly beats installing a chain entry whose every answer fails
        `signature_failed` for a reason that looks like the registry's fault."""
        with pytest.raises(ValueError, match="identity-multihash"):
            _pinned_peer("2KthisIsNotAValidIdentityFormPeerId")

    def test_no_pin_leaves_the_default_local_name_only_chain(self):
        peer = PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()
        uri = peer.entity_tree.normalize_uri(RESOLVER_CONFIG_PATH)
        # §10's default is local-name-only and is synthesized on read, not
        # written — an unpinned peer installs nothing.
        assert peer.entity_tree.get(uri) is None


class TestThePinnedRegistryIsActuallyConsulted:
    @pytest.mark.asyncio
    async def test_resolve_dials_the_registry_and_reads_the_expected_paths(
        self, monkeypatch,
    ):
        registry_kp = Keypair.generate()
        target = Keypair.generate().peer_id
        peer = _pinned_peer(registry_kp.peer_id)
        reader, binding = _published_binding(registry_kp, "billslab.com", target)
        monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

        result = await _resolve(peer, "billslab.com")
        data = result["result"]["data"]
        assert data["status"] == "resolved"
        assert data["peer_id"] == target
        assert data["trust_anchor"] == f"peer_issued:{registry_kp.peer_id}"

        # The fetch pattern, not just the status: by-name pointer first, then
        # the binding body by hash. A resolve that answered from anywhere else
        # would report the same status with an empty log.
        assert reader.tree_reads[0] == "system/registry/binding/by-name/billslab.com"
        assert binding.compute_hash() in reader.content_reads

    @pytest.mark.asyncio
    async def test_the_endpoint_from_the_pin_is_what_the_reader_is_built_from(
        self, monkeypatch,
    ):
        """`make_reader` is handed the chain entry — so the endpoint the
        operator pinned is the one dialed, and a pin that dropped it would
        build no reader at all (an offline-only backend)."""
        registry_kp = Keypair.generate()
        peer = _pinned_peer(registry_kp.peer_id, "http://recorded.invalid/tree/")
        seen: list[dict] = []

        def _capture(entry):
            seen.append(entry)
            return _published_binding(registry_kp, "x.com", Keypair.generate().peer_id)[0]

        monkeypatch.setattr(_registry_mod, "make_reader", _capture)
        await _resolve(peer, "x.com")

        assert seen, "the peer-issued backend was never reached"
        assert seen[0]["hints"]["endpoint"] == "http://recorded.invalid/tree/"
        assert seen[0]["backend_id"] == registry_kp.peer_id

    @pytest.mark.asyncio
    async def test_a_name_absent_from_the_by_name_index_is_not_found(
        self, monkeypatch,
    ):
        """REG-PEERISSUED-OFFLINE-NOTFOUND-1's shape, reached through the pin:
        the registry WAS dialed and definitively had no such name — distinct
        from a fail-closed `chain_exhausted` that dialed nothing."""
        registry_kp = Keypair.generate()
        peer = _pinned_peer(registry_kp.peer_id)
        reader, _ = _published_binding(registry_kp, "present.com", Keypair.generate().peer_id)
        monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

        result = await _resolve(peer, "absent.com")
        assert result["result"]["data"]["status"] == "not_found"
        assert reader.tree_reads == ["system/registry/binding/by-name/absent.com"]

    @pytest.mark.asyncio
    async def test_a_binding_signed_by_a_non_pinned_key_is_rejected(
        self, monkeypatch,
    ):
        """The pin is load-bearing: the signature verifies (the attacker's
        identity is in the store), and only the signer≠pinned-registry guard
        rejects it. Never downgraded, never accepted."""
        registry_kp, attacker_kp = Keypair.generate(), Keypair.generate()
        peer = _pinned_peer(registry_kp.peer_id)
        peer.content_store.put(create_identity_entity(attacker_kp))
        reader, _ = _published_binding(attacker_kp, "evil.com", Keypair.generate().peer_id)
        monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

        result = await _resolve(peer, "evil.com")
        assert result["result"]["data"]["status"] == "chain_exhausted"
