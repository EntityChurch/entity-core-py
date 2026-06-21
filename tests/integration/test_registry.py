"""EXTENSION-REGISTRY v1.0 — substrate + local-name backend pins.

Python-side behaviour pins for the registry handler: local-name backend
(§6), meta-resolver precedence (§4.1), substrate validation (§3 / §5
signature verification, revocation honor, trust-anchor filter,
fail-closed), and the §11.2 resolution log.

The three-way cross-impl gate (`registry:resolve` returns identical
(peer_id, transports, trust_anchor) for a shared binding set) lives in
the cohort validate-peer run.
"""

from __future__ import annotations

import unicodedata

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

BINDING_TYPE = "system/registry/binding"
REVOCATION_TYPE = "system/registry/revocation"


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _ctx(peer, *, remote=None) -> HandlerContext:
    blanket = {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["*"]}}]}
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id=remote if remote is not None else "test",
        handler_grant=blanket,
        caller_capability=blanket,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
        handler_pattern="system/registry",
        keypair=peer.keypair,  # K_registry — the live-registration signing key (§6a.9)
    )


async def _call(peer, op, data, uri="system/registry", *, remote=None, included=None):
    h = peer.handlers.find_handler("system/registry")
    ctx = _ctx(peer, remote=remote)
    if included:
        ctx.included = included
    return await h(uri, op, {"data": data}, ctx)


def _emit(peer, path, entity):
    peer.emit_pathway.emit(path, entity, EmitContext.bootstrap())


def _emit_resolver_config(peer, chain, *, pins=None, dispatch=None):
    cfg = Entity(
        type="system/registry/resolver-config",
        data={
            "resolver_chain": chain,
            "pinned_bindings": pins or [],
            "name_format_dispatch": dispatch or [],
        },
    )
    _emit(peer, "system/registry/resolver-config", cfg)


def _emit_signed_binding(peer, issuer_kp, name, target, *, kind="peer-issued"):
    """Emit a signed binding at the universal location + its signature at the
    invariant pointer, and persist the issuer identity for pubkey resolution."""
    identity = create_identity_entity(issuer_kp)
    peer.content_store.put(identity)
    binding = Entity(
        type=BINDING_TYPE,
        data={
            "name": name,
            "kind": kind,
            "target_peer_id": target,
            "transports": [],
            "issued_at": 1000,
            "ttl": None,
        },
    )
    bh = binding.compute_hash()
    _emit(peer, f"system/registry/binding/{bh.hex()}", binding)
    sig = create_signature_entity(issuer_kp, bh, identity.compute_hash())
    _emit(peer, f"system/signature/{bh.hex()}", sig)
    return binding


# ---------------------------------------------------------------------------
# Petname backend (§6)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_local_name_bind_resolve_list_unbind(peer):
    target = Keypair.generate().peer_id
    r = await _call(peer, "bind", {"name": "alice", "target_peer_id": target}, uri="system/registry/local-name")
    assert r["status"] == 200

    r = await _call(peer, "resolve", {"name": "alice"})
    d = r["result"]["data"]
    assert d["status"] == "resolved"
    assert d["peer_id"] == target
    assert d["trust_anchor"] == "local_name"
    # P1 (arch ruling Q1): the local-name backend's REQUIRED backend_id is
    # default-filled with the local peer identity (§6.2) at config-load, so
    # a resolved local-name result always names the answering backend.
    assert d["backend_id"] == peer.keypair.peer_id

    r = await _call(peer, "list", {}, uri="system/registry/local-name")
    assert [e["name"] for e in r["result"]["data"]["entries"]] == ["alice"]

    await _call(peer, "unbind", {"name": "alice"}, uri="system/registry/local-name")
    r = await _call(peer, "resolve", {"name": "alice"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_nfc_normalization_symmetry(peer):
    """§6.5 — bind under NFD, resolve under NFC, same local-name."""
    target = Keypair.generate().peer_id
    nfd = unicodedata.normalize("NFD", "Café")
    nfc = unicodedata.normalize("NFC", "Café")
    assert nfd != nfc
    await _call(peer, "bind", {"name": nfd, "target_peer_id": target}, uri="system/registry/local-name")
    r = await _call(peer, "resolve", {"name": nfc})
    assert r["result"]["data"]["status"] == "resolved"


@pytest.mark.asyncio
async def test_invalid_name_rejected(peer):
    target = Keypair.generate().peer_id
    for bad in ["a/b", "a\x00b", "a\tb"]:
        r = await _call(peer, "bind", {"name": bad, "target_peer_id": target}, uri="system/registry/local-name")
        assert r["status"] == 400 and r["result"]["data"]["code"] == "bind_invalid_name"


@pytest.mark.asyncio
async def test_bind_already_exists_when_supersede_disabled(peer):
    target = Keypair.generate().peer_id
    cfg = Entity(
        type="system/registry/local-name-config",
        data={"default_pinned": True, "allow_supersede": False, "case_normalization": "none"},
    )
    _emit(peer, "system/registry/local-name-config", cfg)
    await _call(peer, "bind", {"name": "bob", "target_peer_id": target}, uri="system/registry/local-name")
    r = await _call(peer, "bind", {"name": "bob", "target_peer_id": target}, uri="system/registry/local-name")
    assert r["status"] == 409 and r["result"]["data"]["code"] == "bind_already_exists"


@pytest.mark.asyncio
async def test_rebind_sets_supersedes(peer):
    t1 = Keypair.generate().peer_id
    t2 = Keypair.generate().peer_id
    r1 = await _call(peer, "bind", {"name": "carol", "target_peer_id": t1}, uri="system/registry/local-name")
    first_hash = r1["result"]["data"]["binding_hash"]
    r2 = await _call(peer, "bind", {"name": "carol", "target_peer_id": t2}, uri="system/registry/local-name")
    new_hash = r2["result"]["data"]["binding_hash"]
    new_binding = peer.content_store.get(new_hash)
    assert new_binding.data["supersedes"] == first_hash
    # Resolve returns the new head.
    r = await _call(peer, "resolve", {"name": "carol"})
    assert r["result"]["data"]["peer_id"] == t2


@pytest.mark.asyncio
async def test_update_transports(peer):
    target = Keypair.generate().peer_id
    await _call(peer, "bind", {"name": "dave", "target_peer_id": target}, uri="system/registry/local-name")
    eps = [{"transport_type": "tcp", "url": "tcp://1.2.3.4:9000"}]
    r = await _call(peer, "update-transports", {"name": "dave", "transports": eps}, uri="system/registry/local-name")
    assert r["status"] == 200
    res = await _call(peer, "resolve", {"name": "dave"})
    assert res["result"]["data"]["transports"] == eps
    assert res["result"]["data"]["peer_id"] == target


@pytest.mark.asyncio
async def test_case_normalization_lower(peer):
    target = Keypair.generate().peer_id
    cfg = Entity(
        type="system/registry/local-name-config",
        data={"default_pinned": True, "allow_supersede": True, "case_normalization": "lower"},
    )
    _emit(peer, "system/registry/local-name-config", cfg)
    await _call(peer, "bind", {"name": "Erin", "target_peer_id": target}, uri="system/registry/local-name")
    r = await _call(peer, "resolve", {"name": "ERIN"})
    assert r["result"]["data"]["status"] == "resolved"


# ---------------------------------------------------------------------------
# Substrate verification (§3 / §5)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_peer_issued_binding_verifies_from_precedes(peer):
    """§7 bootstrap-with-precedes: a signed peer-issued binding in the local
    store resolves, validated against the issuer's pinned identity."""
    issuer = Keypair.generate()
    target = Keypair.generate().peer_id
    _emit_signed_binding(peer, issuer, "nad-ccf", target)
    _emit_resolver_config(peer, [
        {"backend_kind": "peer-issued", "backend_id": issuer.peer_id, "priority": 0,
         "accepted_trust_anchors": ["peer_issued"]},
    ])
    r = await _call(peer, "resolve", {"name": "nad-ccf"})
    d = r["result"]["data"]
    assert d["status"] == "resolved"
    assert d["peer_id"] == target
    assert d["trust_anchor"].startswith("peer_issued")


@pytest.mark.asyncio
async def test_unsigned_peer_issued_binding_fails_closed(peer):
    """§5 / §11.4 MUST NOT silently accept an unsigned non-self-cert binding."""
    target = Keypair.generate().peer_id
    binding = Entity(type=BINDING_TYPE, data={
        "name": "evil", "kind": "peer-issued", "target_peer_id": target,
        "transports": [], "issued_at": 1000, "ttl": None,
    })
    _emit(peer, f"system/registry/binding/{binding.compute_hash().hex()}", binding)
    _emit_resolver_config(peer, [
        {"backend_kind": "peer-issued", "priority": 0, "accepted_trust_anchors": ["peer_issued"]},
    ])
    r = await _call(peer, "resolve", {"name": "evil"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_revoked_binding_excluded(peer):
    """§3.1 — a verified revocation by the same authority excludes the binding."""
    issuer = Keypair.generate()
    target = Keypair.generate().peer_id
    binding = _emit_signed_binding(peer, issuer, "revoked-name", target)
    # Revocation signed by the same issuer.
    rev = Entity(type=REVOCATION_TYPE, data={
        "revokes": binding.compute_hash(), "revoked_at": 2000, "reason": "key rotation",
    })
    rh = rev.compute_hash()
    _emit(peer, f"system/registry/binding/revocation/{rh.hex()}", rev)
    sig = create_signature_entity(issuer, rh, create_identity_entity(issuer).compute_hash())
    _emit(peer, f"system/signature/{rh.hex()}", sig)
    _emit_resolver_config(peer, [
        {"backend_kind": "peer-issued", "priority": 0, "accepted_trust_anchors": ["peer_issued"]},
    ])
    r = await _call(peer, "resolve", {"name": "revoked-name"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_local_name_revocation_honored(peer):
    """v6 — a local-name revoked by an (unsigned) local revocation entity is
    excluded on re-resolve. The user's local store is the trust source, so
    no signature is required (the local-name carve-out, §6.3)."""
    target = Keypair.generate().peer_id
    r = await _call(peer, "bind", {"name": "judy", "target_peer_id": target}, uri="system/registry/local-name")
    bh = r["result"]["data"]["binding_hash"]
    assert (await _call(peer, "resolve", {"name": "judy"}))["result"]["data"]["status"] == "resolved"

    rev = Entity(type=REVOCATION_TYPE, data={"revokes": bh, "revoked_at": 9000, "reason": "lost contact"})
    _emit(peer, f"system/registry/binding/revocation/{rev.compute_hash().hex()}", rev)
    r = await _call(peer, "resolve", {"name": "judy"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_trust_anchor_filter_rejects(peer):
    """§5 receiver policy — a binding whose anchor isn't accepted is skipped."""
    issuer = Keypair.generate()
    target = Keypair.generate().peer_id
    _emit_signed_binding(peer, issuer, "filtered", target)
    _emit_resolver_config(peer, [
        {"backend_kind": "peer-issued", "priority": 0, "accepted_trust_anchors": ["self_certifying"]},
    ])
    r = await _call(peer, "resolve", {"name": "filtered"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_self_certifying_resolves(peer):
    kp = Keypair.generate()
    name = kp.peer_id  # self-certifying: name IS the peer-id
    binding = Entity(type=BINDING_TYPE, data={
        "name": name, "kind": "self-certifying", "target_peer_id": name,
        "transports": [], "issued_at": 1000, "ttl": None,
    })
    _emit(peer, f"system/registry/binding/{binding.compute_hash().hex()}", binding)
    _emit_resolver_config(peer, [
        {"backend_kind": "self-certifying", "priority": 0, "accepted_trust_anchors": ["self_certifying"]},
    ])
    r = await _call(peer, "resolve", {"name": name})
    d = r["result"]["data"]
    assert d["status"] == "resolved" and d["peer_id"] == name
    assert d["trust_anchor"] == "self_certifying"


# ---------------------------------------------------------------------------
# Meta-resolver precedence (§4.1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pinned_binding_short_circuits(peer):
    pinned_target = Keypair.generate().peer_id
    _emit_resolver_config(
        peer,
        [{"backend_kind": "local-name", "priority": 0, "accepted_trust_anchors": ["local_name"]}],
        pins=[{"name": "special", "target_peer_id": pinned_target, "reason": "ops pin"}],
    )
    # Even with a local-name for the same name, the pin wins.
    await _call(peer, "bind", {"name": "special", "target_peer_id": Keypair.generate().peer_id}, uri="system/registry/local-name")
    r = await _call(peer, "resolve", {"name": "special"})
    d = r["result"]["data"]
    assert d["status"] == "resolved"
    assert d["peer_id"] == pinned_target
    assert d["trust_anchor"] == "out_of_band"
    assert d["transports"] == []


@pytest.mark.asyncio
async def test_unknown_backend_kind_skipped(peer):
    """§4.2 forward-compat — unknown backend_kind skipped, not fatal."""
    target = Keypair.generate().peer_id
    await _call(peer, "bind", {"name": "frank", "target_peer_id": target}, uri="system/registry/local-name")
    _emit_resolver_config(peer, [
        {"backend_kind": "ens-future", "priority": 0, "accepted_trust_anchors": []},
        {"backend_kind": "local-name", "priority": 1, "accepted_trust_anchors": ["local_name"]},
    ])
    r = await _call(peer, "resolve", {"name": "frank"})
    assert r["result"]["data"]["status"] == "resolved"
    assert r["result"]["data"]["peer_id"] == target


@pytest.mark.asyncio
async def test_name_format_dispatch_filters_backends(peer):
    """§4.1 step 2 — a backend mentioned in name_format_dispatch is consulted
    ONLY when the pattern matches; the local-name store is dispatched to *.local
    names only here, so a non-matching name misses it."""
    target = Keypair.generate().peer_id
    await _call(peer, "bind", {"name": "grace", "target_peer_id": target}, uri="system/registry/local-name")
    _emit_resolver_config(
        peer,
        [{"backend_kind": "local-name", "priority": 0, "accepted_trust_anchors": ["local_name"]}],
        dispatch=[{"pattern": "*.local", "backend_kinds": ["local-name"]}],
    )
    # "grace" doesn't match "*.local" → local-name not consulted.
    r = await _call(peer, "resolve", {"name": "grace"})
    assert r["result"]["data"]["status"] == "chain_exhausted"
    # A matching name is consulted.
    await _call(peer, "bind", {"name": "grace.local", "target_peer_id": target}, uri="system/registry/local-name")
    r = await _call(peer, "resolve", {"name": "grace.local"})
    assert r["result"]["data"]["status"] == "resolved"


# ---------------------------------------------------------------------------
# Misc (§2.1 / §11.2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalidate_cache_ok(peer):
    r = await _call(peer, "invalidate-cache", {"name": None})
    assert r["status"] == 200


@pytest.mark.asyncio
async def test_resolution_log_emitted(peer):
    target = Keypair.generate().peer_id
    await _call(peer, "bind", {"name": "heidi", "target_peer_id": target}, uri="system/registry/local-name")
    await _call(peer, "resolve", {"name": "heidi"})
    logs = peer.entity_tree.list_prefix("system/registry/resolution-log/")
    assert len(logs) >= 1
    last = peer.content_store.get(peer.entity_tree.get(logs[-1]))
    assert last.data["name"] == "heidi"
    assert last.data["status"] == "resolved"
    assert last.data["is_fallback_reresolve"] is False


@pytest.mark.asyncio
async def test_fallback_reresolve_not_logged(peer):
    target = Keypair.generate().peer_id
    await _call(peer, "bind", {"name": "ivan", "target_peer_id": target}, uri="system/registry/local-name")
    await _call(peer, "resolve", {"name": "ivan", "is_fallback_reresolve": True})
    logs = peer.entity_tree.list_prefix("system/registry/resolution-log/")
    assert logs == []


# ---------------------------------------------------------------------------
# PROPOSAL-PEER-ISSUED Part A — REG-PEERISSUED-* vectors (§6)
#
# The live-fetch path reads the by-name index + binding from the registry
# peer through the transport-agnostic RegistryReader seam. We inject a fake
# reader (no real HTTP server) so the test exercises the BACKEND's trust
# logic, not the http-poll wire (that's the cohort validate-peer gate). The
# pinned registry identity is placed in the local store — the trust root.
# ---------------------------------------------------------------------------

import entity_handlers.registry as _registry_mod


class _FakeRegistryReader:
    """A RegistryReader serving fixed tree pointers + content (the registry
    peer's published tree, in-memory)."""

    def __init__(self, tree: dict[str, bytes], content: dict[bytes, Entity]) -> None:
        self._tree = tree
        self._content = {bytes(k): v for k, v in content.items()}

    async def tree_get(self, path):
        return self._tree.get(path)

    async def content_get(self, h):
        return self._content.get(bytes(h))


def _peerissued_fixture(registry_kp, name, target, *, ttl=None, issued_at=1000, signer_kp=None):
    """Build the registry peer's published artifacts for a peer-issued
    binding: the binding body, its signature (by ``signer_kp``, default the
    registry), and the by-name + invariant tree pointers. Returns
    (reader, binding)."""
    signer_kp = signer_kp or registry_kp
    nfc = unicodedata.normalize("NFC", name)
    binding = Entity(type=BINDING_TYPE, data={
        "name": nfc, "kind": "peer-issued", "target_peer_id": target,
        "transports": [], "issued_at": issued_at, "ttl": ttl,
    })
    bh = binding.compute_hash()
    signer_identity = create_identity_entity(signer_kp)
    sig = create_signature_entity(signer_kp, bh, signer_identity.compute_hash())
    sh = sig.compute_hash()
    reader = _FakeRegistryReader(
        tree={
            f"system/registry/binding/by-name/{nfc}": bh,
            f"system/signature/{bh.hex()}": sh,
        },
        content={bh: binding, sh: sig},
    )
    return reader, binding


def _pin_registry(peer, registry_kp):
    """Pin the registry's identity locally — the trust root the backend
    verifies the binding signature against (never fetched from the host)."""
    peer.content_store.put(create_identity_entity(registry_kp))


def _peerissued_config(peer, registry_kp, *, accepted=("peer_issued",), neg_ttl=None):
    hints = {"endpoint": "http://reef.invalid"}
    if neg_ttl is not None:
        hints["neg_ttl"] = neg_ttl
    _emit_resolver_config(peer, [
        {"backend_kind": "peer-issued", "backend_id": registry_kp.peer_id,
         "priority": 0, "accepted_trust_anchors": list(accepted), "hints": hints},
    ])


@pytest.mark.asyncio
async def test_reg_peerissued_resolve_1(peer, monkeypatch):
    """REG-PEERISSUED-RESOLVE-1 — by-name index → binding → verify against the
    pinned registry key → resolved."""
    registry_kp = Keypair.generate()
    target = Keypair.generate().peer_id
    reader, _ = _peerissued_fixture(registry_kp, "billslab.com", target)
    _pin_registry(peer, registry_kp)
    _peerissued_config(peer, registry_kp)
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

    r = await _call(peer, "resolve", {"name": "billslab.com"})
    d = r["result"]["data"]
    assert d["status"] == "resolved"
    assert d["peer_id"] == target
    assert d["trust_anchor"] == f"peer_issued:{registry_kp.peer_id}"
    assert d["backend_id"] == registry_kp.peer_id


@pytest.mark.asyncio
async def test_reg_peerissued_verify_fail_1(peer, monkeypatch):
    """REG-PEERISSUED-VERIFY-FAIL-1 — binding signed by a non-pinned key →
    rejected, chain advances (NOT accepted, NOT downgraded to a pin). The
    attacker's identity is even present in the store, so the signature
    *verifies* — only the signer≠pinned-registry guard rejects it."""
    registry_kp = Keypair.generate()
    attacker_kp = Keypair.generate()
    target = Keypair.generate().peer_id
    reader, _ = _peerissued_fixture(registry_kp, "evil.com", target, signer_kp=attacker_kp)
    _pin_registry(peer, registry_kp)
    peer.content_store.put(create_identity_entity(attacker_kp))  # attacker key resolvable
    _peerissued_config(peer, registry_kp)
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

    r = await _call(peer, "resolve", {"name": "evil.com"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_reg_peerissued_revoked_1(peer, monkeypatch):
    """REG-PEERISSUED-REVOKED-1 — a valid binding with a verifying revocation
    by the same registry authority → excluded."""
    registry_kp = Keypair.generate()
    target = Keypair.generate().peer_id
    reader, binding = _peerissued_fixture(registry_kp, "gone.com", target)
    _pin_registry(peer, registry_kp)
    _peerissued_config(peer, registry_kp)
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)
    # Revocation signed by the registry, placed locally (a precede).
    rev = Entity(type=REVOCATION_TYPE, data={
        "revokes": binding.compute_hash(), "revoked_at": 2000, "reason": "rotation",
    })
    rh = rev.compute_hash()
    _emit(peer, f"system/registry/binding/revocation/{rh.hex()}", rev)
    sig = create_signature_entity(registry_kp, rh, create_identity_entity(registry_kp).compute_hash())
    _emit(peer, f"system/signature/{rh.hex()}", sig)

    r = await _call(peer, "resolve", {"name": "gone.com"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_reg_peerissued_expired_1(peer, monkeypatch):
    """REG-PEERISSUED-EXPIRED-1 — issued_at + ttl < now → excluded."""
    registry_kp = Keypair.generate()
    target = Keypair.generate().peer_id
    reader, _ = _peerissued_fixture(registry_kp, "stale.com", target, ttl=1, issued_at=1000)
    _pin_registry(peer, registry_kp)
    _peerissued_config(peer, registry_kp)
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

    r = await _call(peer, "resolve", {"name": "stale.com"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_reg_peerissued_precede_1(peer, monkeypatch):
    """REG-PEERISSUED-PRECEDE-1 — the same binding resolved from precedes
    (offline, no reader) yields an identical verify + result as the live
    fetch. The live fetch caches the binding locally; the second resolve hits
    the warm cache with no reader configured."""
    registry_kp = Keypair.generate()
    target = Keypair.generate().peer_id
    reader, _ = _peerissued_fixture(registry_kp, "warm.com", target)
    _pin_registry(peer, registry_kp)
    _peerissued_config(peer, registry_kp)
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)
    live = (await _call(peer, "resolve", {"name": "warm.com"}))["result"]["data"]

    # Now go offline — no reader — and resolve from the cached precede.
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: None)
    offline = (await _call(peer, "resolve", {"name": "warm.com"}))["result"]["data"]

    assert offline["status"] == "resolved" == live["status"]
    assert offline["peer_id"] == live["peer_id"] == target
    assert offline["trust_anchor"] == live["trust_anchor"]
    assert offline["binding"] == live["binding"]


@pytest.mark.asyncio
async def test_reg_peerissued_offline_notfound_1(peer, monkeypatch):
    """REG-PEERISSUED-OFFLINE-NOTFOUND-1 — name absent from the by-name index
    → not_found with neg_ttl (distinct from a fail-closed chain_exhausted)."""
    registry_kp = Keypair.generate()
    _pin_registry(peer, registry_kp)
    _peerissued_config(peer, registry_kp, neg_ttl=300)
    reader = _FakeRegistryReader(tree={}, content={})  # registry reached, name absent
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

    r = await _call(peer, "resolve", {"name": "nope.com"})
    d = r["result"]["data"]
    assert d["status"] == "not_found"
    assert d["neg_ttl"] == 300


# ---------------------------------------------------------------------------
# EXTENSION-REGISTRY §6a.9 — live registration (REG-REGISTER-* vectors)
#
# A publisher self-registers against a registry that runs the handler. The
# registry is `peer` (it holds K_registry = peer.keypair). The request carries
# a layer-1 `system/signature` by `target_peer_id`; on the wire that signature
# + the requester's identity ride in `included` (→ content store on receipt),
# which we mimic by putting them straight into the store.
# ---------------------------------------------------------------------------

import time as _time


def _emit_issuer_policy(peer, mode, *, allowlist=None, name_constraints=None, default_ttl=None):
    pol = Entity(type="system/registry/issuer-policy", data={
        "mode": mode, "allowlist": allowlist,
        "name_constraints": name_constraints, "default_ttl": default_ttl,
    })
    _emit(peer, "system/registry/issuer-policy", pol)


def _register_data(target_peer_id, name, *, transports=None, requested_ttl=None,
                   nonce=b"\x11" * 16, issued_at=None):
    return {
        "name": unicodedata.normalize("NFC", name),
        "target_peer_id": target_peer_id,
        "transports": transports or [],
        "requested_ttl": requested_ttl,
        "nonce": nonce,
        "issued_at": issued_at if issued_at is not None else int(_time.time() * 1000),
    }


def _sign_into_store(peer, signer_kp, req_type, data):
    """Place a layer-1 signature over Entity(req_type, data) by ``signer_kp``
    into the content store, with the signer's identity — the shape that arrives
    in the request envelope's ``included``."""
    rh = Entity(type=req_type, data=data).compute_hash()
    identity = create_identity_entity(signer_kp)
    peer.content_store.put(identity)
    sig = create_signature_entity(signer_kp, rh, identity.compute_hash())
    peer.content_store.put(sig)


@pytest.mark.asyncio
async def test_reg_register_no_policy_disabled(peer):
    """A curated/static registry (no issuer-policy) rejects live registration."""
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "billslab.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    r = await _call(peer, "register-request", data)
    assert r["status"] == 403
    assert r["result"]["data"]["code"] == "registration_disabled"


@pytest.mark.asyncio
async def test_reg_register_proof_1(peer):
    """REG-REGISTER-PROOF-1 — a request whose signature is NOT by
    target_peer_id is rejected (layer-1 ownership proof, §6a.9)."""
    _emit_issuer_policy(peer, "open")
    reg_kp = Keypair.generate()
    attacker_kp = Keypair.generate()
    # Request claims reg_kp's peer-id but is signed by the attacker.
    data = _register_data(reg_kp.peer_id, "billslab.com")
    _sign_into_store(peer, attacker_kp, "system/registry/register-request", data)
    r = await _call(peer, "register-request", data)
    assert r["status"] == 403
    assert r["result"]["data"]["code"] == "proof_failed"


@pytest.mark.asyncio
async def test_reg_register_open_issues_and_resolves(peer):
    """`open` mode — a layer-1-valid request for a free name is signed and
    published; the issued binding then resolves against the registry's key."""
    _emit_issuer_policy(peer, "open")
    _peerissued_config(peer, peer.keypair)  # the registry resolves its own names
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "billslab.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)

    r = await _call(peer, "register-request", data)
    assert r["status"] == 200
    assert r["result"]["data"]["status"] == "registered"

    resolved = (await _call(peer, "resolve", {"name": "billslab.com"}))["result"]["data"]
    assert resolved["status"] == "resolved"
    assert resolved["peer_id"] == reg_kp.peer_id
    assert resolved["trust_anchor"] == f"peer_issued:{peer.keypair.peer_id}"


@pytest.mark.asyncio
async def test_reg_register_open_name_taken(peer):
    """`open` is first-come — a second registrant cannot take a bound name."""
    _emit_issuer_policy(peer, "open")
    first_kp, second_kp = Keypair.generate(), Keypair.generate()
    d1 = _register_data(first_kp.peer_id, "shared.com")
    _sign_into_store(peer, first_kp, "system/registry/register-request", d1)
    assert (await _call(peer, "register-request", d1))["status"] == 200

    d2 = _register_data(second_kp.peer_id, "shared.com")
    _sign_into_store(peer, second_kp, "system/registry/register-request", d2)
    r = await _call(peer, "register-request", d2)
    assert r["status"] == 409
    assert r["result"]["data"]["code"] == "name_taken"


@pytest.mark.asyncio
async def test_reg_register_policy_1(peer):
    """REG-REGISTER-POLICY-1 — `allowlist`: a non-listed peer is `not_entitled`;
    an allow-listed peer is issued + resolvable."""
    listed_kp = Keypair.generate()
    outsider_kp = Keypair.generate()
    _emit_issuer_policy(peer, "allowlist", allowlist=[listed_kp.peer_id])
    _peerissued_config(peer, peer.keypair)

    # Outsider → not_entitled.
    d_out = _register_data(outsider_kp.peer_id, "denied.com")
    _sign_into_store(peer, outsider_kp, "system/registry/register-request", d_out)
    r_out = await _call(peer, "register-request", d_out)
    assert r_out["status"] == 403
    assert r_out["result"]["data"]["code"] == "not_entitled"

    # Allow-listed → issued + resolvable.
    d_in = _register_data(listed_kp.peer_id, "allowed.com")
    _sign_into_store(peer, listed_kp, "system/registry/register-request", d_in)
    r_in = await _call(peer, "register-request", d_in)
    assert r_in["status"] == 200
    resolved = (await _call(peer, "resolve", {"name": "allowed.com"}))["result"]["data"]
    assert resolved["status"] == "resolved"
    assert resolved["peer_id"] == listed_kp.peer_id


@pytest.mark.asyncio
async def test_reg_register_name_constraints(peer):
    """`name_constraints` narrows every mode — a name outside the glob is
    rejected even under `open`."""
    _emit_issuer_policy(peer, "open", name_constraints="*.lab")
    reg_kp = Keypair.generate()
    bad = _register_data(reg_kp.peer_id, "billslab.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", bad)
    assert (await _call(peer, "register-request", bad))["result"]["data"]["code"] == "not_entitled"

    good = _register_data(reg_kp.peer_id, "bills.lab")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", good)
    assert (await _call(peer, "register-request", good))["status"] == 200


@pytest.mark.asyncio
async def test_reg_register_replay_1(peer):
    """REG-REGISTER-REPLAY-1 — a replayed request (seen nonce for the same
    requester) is rejected."""
    _emit_issuer_policy(peer, "open")
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "billslab.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)

    assert (await _call(peer, "register-request", data))["status"] == 200
    replay = await _call(peer, "register-request", data)
    assert replay["status"] == 403
    assert replay["result"]["data"]["code"] == "replay_detected"


@pytest.mark.asyncio
async def test_reg_register_stale_request(peer):
    """A request with issued_at outside the replay window is rejected."""
    _emit_issuer_policy(peer, "open")
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "billslab.com", issued_at=1000)  # 1970
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    r = await _call(peer, "register-request", data)
    assert r["status"] == 403
    assert r["result"]["data"]["code"] == "stale_request"


@pytest.mark.asyncio
async def test_reg_register_domain_control_unsupported(peer):
    """`domain-control` mode is deferred (§6a.9.1) — a v1 registry returns a
    clear 501 rather than inventing a second domain-proof scheme."""
    _emit_issuer_policy(peer, "domain-control")
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "billslab.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    r = await _call(peer, "register-request", data)
    assert r["status"] == 501
    assert r["result"]["data"]["code"] == "domain_control_unsupported"


@pytest.mark.asyncio
async def test_reg_register_manual_queue_then_approve(peer):
    """`manual` mode queues a request as pending_review; the operator approves
    it out-of-band, issuing the binding."""
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "queued.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)

    queued = (await _call(peer, "register-request", data))["result"]["data"]
    assert queued["status"] == "pending_review"
    pending_hash = queued["pending_hash"]

    # Not yet resolvable (queued, not issued).
    assert (await _call(peer, "resolve", {"name": "queued.com"}))["result"]["data"]["status"] != "resolved"

    # Operator (self-origin) approves.
    approved = await _call(peer, "approve-request", {"pending_hash": pending_hash},
                           remote=peer.keypair.peer_id)
    assert approved["status"] == 200
    assert approved["result"]["data"]["status"] == "registered"
    resolved = (await _call(peer, "resolve", {"name": "queued.com"}))["result"]["data"]
    assert resolved["status"] == "resolved"
    assert resolved["peer_id"] == reg_kp.peer_id


@pytest.mark.asyncio
async def test_reg_register_approve_is_operator_only(peer):
    """A non-operator caller cannot approve a queued request."""
    _emit_issuer_policy(peer, "manual")
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "queued.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    pending_hash = (await _call(peer, "register-request", data))["result"]["data"]["pending_hash"]

    r = await _call(peer, "approve-request", {"pending_hash": pending_hash})  # remote="test"
    assert r["status"] == 403
    assert r["result"]["data"]["code"] == "not_entitled"


@pytest.mark.asyncio
async def test_reg_revoke_request_by_registrant(peer):
    """`:revoke-request` — the registrant self-services via layer-1 proof; the
    revoked name frees up and the binding no longer resolves."""
    _emit_issuer_policy(peer, "open")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "gone.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    binding_hash = (await _call(peer, "register-request", data))["result"]["data"]["binding_hash"]
    assert (await _call(peer, "resolve", {"name": "gone.com"}))["result"]["data"]["status"] == "resolved"

    rev = _register_data(reg_kp.peer_id, "gone.com")  # reuse for nonce/issued_at fields
    revoke_data = {"binding_hash": binding_hash, "reason": "rotation",
                   "nonce": rev["nonce"], "issued_at": rev["issued_at"]}
    _sign_into_store(peer, reg_kp, "system/registry/revoke-request", revoke_data)
    r = await _call(peer, "revoke-request", revoke_data)
    assert r["status"] == 200 and r["result"]["data"]["revoked"] is True

    assert (await _call(peer, "resolve", {"name": "gone.com"}))["result"]["data"]["status"] == "chain_exhausted"


@pytest.mark.asyncio
async def test_reg_renew_request_supersedes(peer):
    """`:renew-request` re-issues with a fresh ttl, superseding the prior
    binding; the new binding resolves."""
    _emit_issuer_policy(peer, "open")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "renew.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    binding_hash = (await _call(peer, "register-request", data))["result"]["data"]["binding_hash"]

    renew_data = {"binding_hash": binding_hash, "ttl": 999999,
                  "nonce": b"\x22" * 16, "issued_at": int(_time.time() * 1000)}
    _sign_into_store(peer, reg_kp, "system/registry/renew-request", renew_data)
    r = await _call(peer, "renew-request", renew_data)
    assert r["status"] == 200
    new_hash = r["result"]["data"]["binding_hash"]
    assert new_hash != binding_hash

    new_binding = peer.content_store.get(bytes(new_hash))
    assert bytes(new_binding.data["supersedes"]) == bytes(binding_hash)
    assert (await _call(peer, "resolve", {"name": "renew.com"}))["result"]["data"]["status"] == "resolved"


@pytest.mark.asyncio
async def test_reg_set_get_issuer_policy(peer):
    """`:set-issuer-policy` installs the policy `:get-issuer-policy` reads back;
    a fresh registry reports mode=None (curated/static)."""
    assert (await _call(peer, "get-issuer-policy", {}))["result"]["data"]["mode"] is None
    r = await _call(peer, "set-issuer-policy", {"mode": "allowlist", "allowlist": ["p1"]})
    assert r["status"] == 200 and r["result"]["data"]["mode"] == "allowlist"
    got = (await _call(peer, "get-issuer-policy", {}))["result"]["data"]
    assert got["mode"] == "allowlist" and got["allowlist"] == ["p1"]
