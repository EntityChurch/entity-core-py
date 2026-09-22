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
    """§4.1 step 2 — the filter narrows **per name**: the eligible set is the
    union of `backend_kinds` over the entries whose pattern matches, and a
    backend outside that set is not consulted however the rest of the list
    reads.

    The list here is §4.1a's shape in miniature — a scoped row plus a catch-all
    naming a backend that is not in the chain. `grace` matches only the
    catch-all, so `local-name` is narrowed out; `grace.local` matches both, so
    it is back in.

    **This test asserted the same two statuses for the opposite reason until
    2026-08-18** — a per-backend reading in which `local-name` was excluded by
    being *mentioned and unmatched* rather than by *not being in the matched
    union*. The two agree on every configuration where the narrowed backend is
    in the chain, which is every configuration this suite had. See SA-PY-17.
    """
    target = Keypair.generate().peer_id
    await _call(peer, "bind", {"name": "grace", "target_peer_id": target}, uri="system/registry/local-name")
    _emit_resolver_config(
        peer,
        [{"backend_kind": "local-name", "priority": 0, "accepted_trust_anchors": ["local_name"]}],
        dispatch=[
            {"pattern": "*.local", "backend_kinds": ["local-name"]},
            {"pattern": "*", "backend_kinds": ["did-web"]},
        ],
    )
    # "grace" matches only the catch-all → eligible = {did-web} → local-name out.
    r = await _call(peer, "resolve", {"name": "grace"})
    assert r["result"]["data"]["status"] == "chain_exhausted"
    # "grace.local" matches both → eligible = {local-name, did-web}.
    await _call(peer, "bind", {"name": "grace.local", "target_peer_id": target}, uri="system/registry/local-name")
    r = await _call(peer, "resolve", {"name": "grace.local"})
    assert r["result"]["data"]["status"] == "resolved"


@pytest.mark.asyncio
async def test_a_name_matching_no_entry_reaches_nothing(peer):
    """§4.1 step 2 edge case **B**, **RULED 2026-08-19** (REGISTRY 1.14): a
    name matching no entry narrows the chain to the **empty set**, so it
    resolves nowhere — loudly (`chain_exhausted`), which is §4.1 step 4's own
    posture: *"fail-closed; no silent fallback."*

    Filed as SA-PY-17 while it was contested; go read it the other way
    (unmatched ⇒ unfiltered) and has since flipped, rust already excluded.
    The sentence go and this peer both once implemented — *"a name matching no
    entry is treated as matching the catch-all"* — is deleted: the catch-all is
    `*`, which matches every name, so it can never be the row an unmatched name
    falls to, and it is the most **restrictive** row in §4.1a's list rather
    than a licence to skip filtering.
    """
    target = Keypair.generate().peer_id
    await _call(peer, "bind", {"name": "grace", "target_peer_id": target}, uri="system/registry/local-name")
    _emit_resolver_config(
        peer,
        [{"backend_kind": "local-name", "priority": 0, "accepted_trust_anchors": ["local_name"]}],
        dispatch=[{"pattern": "*.local", "backend_kinds": ["local-name"]}],
    )
    r = await _call(peer, "resolve", {"name": "grace"})
    assert r["result"]["data"]["status"] == "chain_exhausted"


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
        # Which paths were actually read. A vector that asserts only the status
        # cannot tell a backend that performed the lookup from one that never
        # did — four of the six negative vectors expect `chain_exhausted`, which
        # is also what a backend that dialed nothing returns.
        self.tree_reads: list[str] = []

    async def tree_get(self, path):
        self.tree_reads.append(path)
        return self._tree.get(path)

    async def content_get(self, h):
        return self._content.get(bytes(h))

    def publish(self, path: str, entity: Entity) -> bytes:
        """Publish an entity into the registry's served tree at ``path``,
        returning its hash — the registry peer's side of the wire."""
        h = entity.compute_hash()
        self._tree[path] = h
        self._content[bytes(h)] = entity
        return h


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
    by the same registry authority → excluded.

    The revocation is served **by the registry**, at the §6a.6 by-target index,
    which is where a revocation actually lives: the registry publishes it after
    the binding, and the resolving peer has never heard of it. An earlier
    version of this vector pre-seeded the revocation into the local store, so
    it measured only the precedes path and stayed green against a backend that
    never probed the index at all — the binding is valid in every other
    respect, so that backend served a revoked name.
    """
    registry_kp = Keypair.generate()
    target = Keypair.generate().peer_id
    reader, binding = _peerissued_fixture(registry_kp, "gone.com", target)
    _pin_registry(peer, registry_kp)
    _peerissued_config(peer, registry_kp)
    monkeypatch.setattr(_registry_mod, "make_reader", lambda entry: reader)

    bh = binding.compute_hash()
    rev = Entity(type=REVOCATION_TYPE, data={
        "revokes": bh, "revoked_at": 2000, "reason": "rotation",
    })
    rh = reader.publish(f"system/registry/revocation/by-target/{bh.hex()}", rev)
    reader.publish(
        f"system/signature/{rh.hex()}",
        create_signature_entity(registry_kp, rh, create_identity_entity(registry_kp).compute_hash()),
    )

    r = await _call(peer, "resolve", {"name": "gone.com"})
    assert r["result"]["data"]["status"] == "chain_exhausted"
    assert f"system/registry/revocation/by-target/{bh.hex()}" in reader.tree_reads, (
        "the backend never probed the by-target revocation index — §6a.4's "
        "fail-closed rule cannot fire on a revocation it never looked for"
    )


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


#: A live policy MUST define `default_ttl` (§6a.9.2 D11) — a registry without
#: one can only mint null-ttl bindings, which §6a.3 forbids. This helper writes
#: the policy entity *directly*, which is exactly the out-of-band seeding path
#: D11 cannot reach, so it defaults to a valid ttl rather than inheriting the
#: null that every one of these tests used to arm. Pass `default_ttl=None`
#: deliberately to seed the bad-stored-policy case D12 answers.
_LIVE_DEFAULT_TTL_MS = 86_400_000

#: And a live policy MUST define `max_ttl` (§6a.9.1 v1.11), for the same reason
#: one field over: §6a.3 makes `ttl` the only bound on a withheld revocation, so
#: an uncapped requester-chosen `ttl` is a binding nobody can revoke in
#: practice. The default here is generous — these tests are not about the
#: ceiling and a low one would silently clamp every binding they assert on.
_LIVE_MAX_TTL_MS = 365 * 86_400_000


def _emit_issuer_policy(peer, mode, *, allowlist=None, name_constraints=None,
                        default_ttl=_LIVE_DEFAULT_TTL_MS,
                        max_ttl=_LIVE_MAX_TTL_MS):
    pol = Entity(type="system/registry/issuer-policy", data={
        "mode": mode, "allowlist": allowlist,
        "name_constraints": name_constraints, "default_ttl": default_ttl,
        "max_ttl": max_ttl,
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
    # 401: layer-1 is authentication (proof of key control), so a failure there
    # is "you did not prove it", not "policy says no" (403 not_entitled).
    assert r["status"] == 401
    assert r["result"]["data"]["code"] == "signature_invalid"


@pytest.mark.asyncio
async def test_reg_register_wholly_unsigned_rejected_401(peer):
    """§6a.9 layer-1 — a request with NO system/signature at its invariant
    pointer is refused 401, and issues nothing. Distinct from the wrong-signer
    case above: an absent proof and a bad proof are the same answer, because
    ownership proof is the floor beneath every policy mode. `open` mode is what
    makes this non-vacuous — the name is free and the only thing standing
    between the request and a signed binding is layer-1."""
    _emit_issuer_policy(peer, "open")
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "unsigned.com")
    # deliberately no _sign_into_store
    r = await _call(peer, "register-request", data)
    assert r["status"] == 401
    assert r["result"]["data"]["code"] == "signature_invalid"
    resolved = (await _call(peer, "resolve", {"name": "unsigned.com"}))["result"]["data"]
    assert resolved["status"] != "resolved"


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
    assert r["result"]["type"] == "system/registry/register-result"
    assert r["result"]["data"]["status"] == "bound"
    assert r["result"]["data"].get("binding_hash")

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
    clear 501 rather than inventing a second domain-proof scheme.

    **The code is `unsupported_mode`, and §6a.9.2 pins it as a `[MUST]`:** *"The
    registry MUST answer live registration `501 unsupported_mode` and MUST NOT
    fall back to `open`, `manual`, or an unset-style `404` … This is a
    cross-impl-observable answer with four plausible codes, so it is pinned
    rather than left to converge."*

    This row asserted `domain_control_unsupported` — a **fifth** spelling, ours
    — until 2026-09-03, and then briefly `unsupported_operation`, on the
    reading that §9.1's 501 synonym list forbade `unsupported_mode`. It does
    not: 0.8.2.7 ruling 2's escape clause is *"defined … in the owning domain
    handler's own table"*, and §6a.9.2 is that table. §9.1's list enumerates
    spellings seats were **emitting**, not spellings the corpus leaves
    undefined. SA-PY-37.

    Both wrong answers had the same cause and it is worth naming: the sweep was
    justified by *"no extension in this tree declares an error-code table"* —
    arch's sentence, true of the ~90 held 500 sites, inherited without being
    re-checked against the extension actually in front of us. **A sweep
    justified by "nothing defines a better code" is a negative claim about the
    corpus**, and the cheap check is one grep of the extension.
    """
    _emit_issuer_policy(peer, "domain-control")
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "billslab.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    r = await _call(peer, "register-request", data)
    assert (r["status"], r["result"]["data"]["code"]) == (501, "unsupported_mode")
    assert "domain-control" in r["result"]["data"]["message"]


@pytest.mark.asyncio
async def test_reg_register_manual_queue_then_approve(peer):
    """`manual` mode queues a request as pending_review; the operator approves
    it out-of-band, issuing the binding."""
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "queued.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)

    r = await _call(peer, "register-request", data)
    # 202 accepted-for-review, not 200 done: manual mode's whole point is that
    # nothing was signed yet.
    assert r["status"] == 202
    queued = r["result"]["data"]
    assert queued["status"] == "pending_review"
    pending_hash = queued["pending_hash"]

    # Not yet resolvable (queued, not issued).
    assert (await _call(peer, "resolve", {"name": "queued.com"}))["result"]["data"]["status"] != "resolved"

    # Operator (self-origin) approves.
    approved = await _call(peer, "approve-request", {"pending_hash": pending_hash},
                           remote=peer.keypair.peer_id)
    assert approved["status"] == 200
    # `approve-request` shares `register-result` with the 200 branch above, so
    # it shares the ruled value — an operator-issued binding is `bound` too.
    assert approved["result"]["type"] == "system/registry/register-result"
    assert approved["result"]["data"]["status"] == "bound"
    resolved = (await _call(peer, "resolve", {"name": "queued.com"}))["result"]["data"]
    assert resolved["status"] == "resolved"
    assert resolved["peer_id"] == reg_kp.peer_id


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["approve-request", "deny-request"])
async def test_reg_decision_requires_the_issue_binding_cap(peer, op):
    """§6a.9.3 — both decisions are gated by
    `system/capability/registry-issue-binding`, and a caller without it is
    refused whatever its origin.

    This test used to assert a self-origin floor ("approve-request is
    operator-only"), which was our pre-ruling invention and made the ruled
    capability undelegable: gating on origin means only the registry process
    itself can ever decide, so a cap whose purpose is handing operator
    authority to someone else could never be exercised by them. The gate is
    the grant, so the narrow-grant caller is what has to be refused."""
    _emit_issuer_policy(peer, "manual")
    reg_kp = Keypair.generate()
    ph = await _queue_call(peer, reg_kp, "queued.com")

    # A caller granted everything EXCEPT the decision ops.
    narrow = {"grants": [{
        "handlers": {"include": ["*"]},
        "resources": {"include": ["*"]},
        "operations": {"include": ["*"], "exclude": ["approve-request", "deny-request"]},
    }]}
    h = peer.handlers.find_handler("system/registry")
    ctx = _ctx(peer, remote="somebody-else")
    ctx.caller_capability = narrow
    r = await h("system/registry", op, {"data": {"pending_hash": ph}}, ctx)
    assert r["status"] == 403
    assert r["result"]["data"]["code"] == "not_entitled"

    # And the head is untouched — a refused decision decides nothing.
    assert _pending_body(peer, _by_request(peer, reg_kp.peer_id, "queued.com")
                         ).data["status"] == "pending_review"


@pytest.mark.asyncio
async def test_reg_decision_by_a_remote_holding_the_cap_is_allowed(peer):
    """The positive half, and the reason the floor had to go: a REMOTE
    operator holding the cap can decide. core-go's oracle drives exactly this
    shape, and a self-origin check answers 403 to a conformant client."""
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    ph = await _queue_call(peer, reg_kp, "queued.com")

    r = await _call(peer, "approve-request", {"pending_hash": ph}, remote="a-remote-operator")
    assert r["status"] == 200, r
    assert r["result"]["data"]["status"] == "bound"


# ---------------------------------------------------------------------------
# §6a.9.3 — the manual-approval path (RULED 2026-08-13)
# ---------------------------------------------------------------------------


def _queue(peer, target_kp, name, *, nonce=b"\x11" * 16, requested_ttl=None):
    """Build + sign a manual-mode request."""
    data = _register_data(target_kp.peer_id, name, nonce=nonce,
                          requested_ttl=requested_ttl)
    _sign_into_store(peer, target_kp, "system/registry/register-request", data)
    return data


async def _queue_call(peer, target_kp, name, *, nonce=b"\x11" * 16, requested_ttl=None):
    """Queue a manual-mode request; returns its pending_hash.

    Supersession cases vary `requested_ttl` rather than only the nonce, and the
    reason is a real property of §6a.9.3's schema: a pending-binding carries
    `{name, target_peer_id, transports, requested_ttl, queued_at, status}` and
    NOTHING request-unique — the request's `nonce` is not among its fields. Two
    retries for one pair with identical terms inside the same millisecond
    therefore hash identically, so `pending_hash` identifies (pair, terms,
    millisecond) rather than a request. Benign in production — supersession
    keeps one head either way and a byte-identical head is the same intent on
    the same terms — but a test that varies only the nonce is asserting a
    distinctness the schema does not provide, and fails whenever both calls land
    in one millisecond."""
    r = await _call(peer, "register-request",
                    _queue(peer, target_kp, name, nonce=nonce, requested_ttl=requested_ttl))
    assert r["status"] == 202, r
    return r["result"]["data"]["pending_hash"]


def _pending_body(peer, ph):
    return peer.emit_pathway.content_store.get(ph)


def _by_request(peer, target_peer_id, name):
    return peer.emit_pathway.entity_tree.get(
        f"system/registry/pending/by-request/{target_peer_id}/{name}"
    )


@pytest.mark.asyncio
async def test_reg_pending_handle_resolves_to_a_pending_binding(peer):
    """REG-PENDING-HANDLE-1 — the resolvability half, which is the reason
    §6a.9.3 exists: before the schema landed, a `pending_hash` that named
    nothing fetchable was indistinguishable from a conformant one."""
    _emit_issuer_policy(peer, "manual")
    reg_kp = Keypair.generate()
    data = _queue(peer, reg_kp, "queued.com")
    request_hash = Entity(type="system/registry/register-request", data=data).compute_hash()

    r = await _call(peer, "register-request", data)
    ph = r["result"]["data"]["pending_hash"]

    # Distinct from the request's own hash — a handle the client can already
    # compute is not a handle.
    assert ph != request_hash

    body = _pending_body(peer, ph)
    assert body is not None, "pending_hash resolves to nothing"
    assert body.type == "system/registry/pending-binding"
    assert body.data["status"] == "pending_review"
    assert body.data["target_peer_id"] == reg_kp.peer_id
    assert body.data["name"] == "queued.com"

    # Published at its own body path, and the by-request pointer names it.
    assert peer.emit_pathway.entity_tree.get(f"system/registry/pending/{ph.hex()}") == ph
    assert _by_request(peer, reg_kp.peer_id, "queued.com") == ph


@pytest.mark.asyncio
async def test_reg_pending_supersedes_leaving_one_head(peer):
    """§6a.9.3 [MUST] — one pending head per (target_peer_id, name). Every
    retry carries a fresh nonce and is a distinct request by construction, so
    without supersession one intent fills the operator's queue."""
    _emit_issuer_policy(peer, "manual")
    reg_kp = Keypair.generate()
    first = await _queue_call(peer, reg_kp, "queued.com",
                              nonce=b"\x11" * 16, requested_ttl=60_000)
    second = await _queue_call(peer, reg_kp, "queued.com",
                               nonce=b"\x22" * 16, requested_ttl=90_000)

    assert first != second
    # The pointer names the NEW body, and there is exactly one head for the pair.
    assert _by_request(peer, reg_kp.peer_id, "queued.com") == second
    heads = peer.emit_pathway.entity_tree.list_prefix(
        "system/registry/pending/by-request/"
    )
    assert len(heads) == 1, heads
    # The superseded body survives for audit — it is content-addressed history.
    assert _pending_body(peer, first) is not None


@pytest.mark.asyncio
async def test_reg_pending_superseded_head_is_not_decidable(peer):
    """The case §6a.9.3's own supersession rule creates and does not pin.

    Approving a superseded hash would mint a binding on terms the operator's
    queue no longer shows, and leave the pointer naming a different head than
    the one decided. Refused with the code §6a.9.3 DOES pin for an
    unresolvable handle rather than an invented one."""
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    stale = await _queue_call(peer, reg_kp, "queued.com",
                              nonce=b"\x11" * 16, requested_ttl=60_000)
    await _queue_call(peer, reg_kp, "queued.com",
                      nonce=b"\x22" * 16, requested_ttl=90_000)

    r = await _call(peer, "approve-request", {"pending_hash": stale},
                    remote=peer.keypair.peer_id)
    assert r["status"] == 404
    assert r["result"]["data"]["code"] == "not_found"
    # The negative half: nothing was issued off the stale head.
    assert (await _call(peer, "resolve", {"name": "queued.com"}))[
        "result"]["data"]["status"] != "resolved"


@pytest.mark.asyncio
async def test_reg_pending_approve_leaves_an_approved_head(peer):
    """REG-PENDING-DECIDE-1, approve half. Our pre-§6a.9.3 path removed the
    entry on issue; the ruling names that the one place our shape was not
    ratified. A requester polling a vanished pointer cannot distinguish
    *decided* from *never received*."""
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    ph = await _queue_call(peer, reg_kp, "queued.com")

    approved = await _call(peer, "approve-request", {"pending_hash": ph},
                           remote=peer.keypair.peer_id)
    assert approved["status"] == 200
    bh = approved["result"]["data"]["binding_hash"]

    head = _by_request(peer, reg_kp.peer_id, "queued.com")
    assert head is not None, "approve removed the head — deny/approve are not deletes"
    body = _pending_body(peer, head)
    assert body.data["status"] == "approved"
    # REQUIRED on "approved": the head carries the binding it produced.
    assert body.data["binding_hash"] == bh
    assert (await _call(peer, "resolve", {"name": "queued.com"}))[
        "result"]["data"]["status"] == "resolved"


@pytest.mark.asyncio
async def test_reg_pending_deny_leaves_a_denied_head_and_publishes_nothing(peer):
    """REG-PENDING-DECIDE-1, deny half — and the negative half is the
    load-bearing one: a deny that silently issued would pass an
    outcome-only check."""
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    ph = await _queue_call(peer, reg_kp, "queued.com")

    denied = await _call(peer, "deny-request",
                         {"pending_hash": ph, "reason": "not your name"},
                         remote=peer.keypair.peer_id)
    assert denied["status"] == 200
    assert denied["result"]["type"] == "system/registry/register-result"
    assert denied["result"]["data"]["status"] == "denied"

    head = _by_request(peer, reg_kp.peer_id, "queued.com")
    assert head is not None, "deny is not a delete (§6a.9.3 [MUST])"
    body = _pending_body(peer, head)
    assert body.data["status"] == "denied"
    assert body.data["reason"] == "not your name"
    assert "binding_hash" not in body.data
    # Nothing signed, nothing published.
    assert (await _call(peer, "resolve", {"name": "queued.com"}))[
        "result"]["data"]["status"] != "resolved"


@pytest.mark.asyncio
@pytest.mark.parametrize("first,second", [
    ("approve-request", "approve-request"),
    ("approve-request", "deny-request"),
    ("deny-request", "approve-request"),
    ("deny-request", "deny-request"),
])
async def test_reg_pending_second_decision_is_409(peer, first, second):
    """§6a.9.3 — approve and deny are not idempotent-by-replay. The dangerous
    failure is a 200: re-approving mints a second binding for one request, and
    approving an already-denied one overturns the operator by retry."""
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    ph = await _queue_call(peer, reg_kp, "queued.com")

    assert (await _call(peer, first, {"pending_hash": ph},
                        remote=peer.keypair.peer_id))["status"] == 200

    # A decision writes a NEW body and repoints, so the decided head is not the
    # hash the 202 handed out. The pointer is the poll surface (§6a.9.3 gives no
    # list-pending op precisely because a tree read answers it), and the second
    # decision is submitted against the current head — which is what core-go's
    # oracle does too. Submitting the pre-decision hash instead is the
    # superseded-head case above and correctly answers 404.
    decided_head = _by_request(peer, reg_kp.peer_id, "queued.com")
    assert decided_head is not None and decided_head != ph

    r = await _call(peer, second, {"pending_hash": decided_head},
                    remote=peer.keypair.peer_id)
    assert r["status"] == 409, r
    assert r["result"]["data"]["code"] == "already_decided"
    # The dangerous failure is a 200; assert nothing was published by the refusal.
    if first == "deny-request":
        assert (await _call(peer, "resolve", {"name": "queued.com"}))[
            "result"]["data"]["status"] != "resolved"


@pytest.mark.asyncio
async def test_reg_pending_decision_on_unknown_hash_is_404(peer):
    _emit_issuer_policy(peer, "manual")
    r = await _call(peer, "approve-request", {"pending_hash": b"\x00" * 33},
                    remote=peer.keypair.peer_id)
    assert r["status"] == 404
    assert r["result"]["data"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_reg_pending_retention_spares_live_queue_state(peer, monkeypatch):
    """§6a.9.3 retention [SHOULD] — a DECIDED head past the window is
    GC-eligible; a `pending_review` head is never eligible at any age.
    Expiring live queue state would silently drop a request no operator has
    seen, which is the same deliver-or-signal violation deny-is-not-a-delete
    forbids."""
    import entity_handlers.registry as _reg
    _emit_issuer_policy(peer, "manual")
    _peerissued_config(peer, peer.keypair)

    old_kp, live_kp = Keypair.generate(), Keypair.generate()
    decided = await _queue_call(peer, old_kp, "decided.com")
    await _call(peer, "deny-request", {"pending_hash": decided},
                remote=peer.keypair.peer_id)
    aged = await _queue_call(peer, live_kp, "still-waiting.com")

    # Both heads are now older than the window.
    monkeypatch.setattr(_reg, "PENDING_RETENTION_MS", -1)
    # Any queue triggers the opportunistic sweep.
    await _queue_call(peer, Keypair.generate(), "trigger.com")

    assert _by_request(peer, old_kp.peer_id, "decided.com") is None, \
        "a decided head past retention should be reclaimed"
    assert _by_request(peer, live_kp.peer_id, "still-waiting.com") == aged, \
        "a pending_review head is never GC-eligible, at any age"
    # The reclaimed body stays content-addressed and auditable.
    assert _pending_body(peer, decided) is not None


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

    # The ratified §6a.9 revoke schema is `{binding_hash, reason}` and nothing
    # else: revocation is monotonic on a content-addressed target, so replay is
    # a provable no-op and `nonce` / `issued_at` are deliberately absent. They
    # used to be sent here, which would have hashed to a request no sibling
    # authors — the signed hash covers `{type, data}` as written.
    revoke_data = {"binding_hash": binding_hash, "reason": "rotation"}
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
    """§6a.9.2 — `:set-issuer-policy` installs the policy `:get-issuer-policy`
    reads back, and `set` echoes the stored policy as written."""
    r = await _call(peer, "set-issuer-policy", {
        "mode": "allowlist", "allowlist": ["p1"], "default_ttl": 60_000,
        "max_ttl": _LIVE_MAX_TTL_MS,
    })
    assert r["status"] == 200
    assert r["result"]["type"] == "system/registry/issuer-policy"
    assert r["result"]["data"]["mode"] == "allowlist"
    got = (await _call(peer, "get-issuer-policy", {}))["result"]["data"]
    assert got["mode"] == "allowlist" and got["allowlist"] == ["p1"]


@pytest.mark.asyncio
async def test_reg_set_issuer_policy_null_default_ttl_400(peer):
    """§6a.9.2 D11 [MUST] — a live-registration policy with `default_ttl: null`
    can only mint null-ttl bindings (§6a.3 forbids them, §6a.4 cannot resolve
    them), so `set` refuses to *store* it. Same move, same subsection and same
    stated reason as the `domain-control` refusal above.

    The negative half is the point: a status-only check passes a peer that
    answers 400 and stores the policy anyway. `entity-core-go`'s probe says so
    in as many words, so the read-back is asserted here too.
    """
    await _call(peer, "set-issuer-policy", {
        "mode": "open", "default_ttl": 60_000, "max_ttl": _LIVE_MAX_TTL_MS,
    })

    for mode, extra in (("open", {}), ("allowlist", {"allowlist": ["p1"]}), ("manual", {})):
        r = await _call(peer, "set-issuer-policy", {
            "mode": mode, "max_ttl": _LIVE_MAX_TTL_MS, **extra,
        })
        assert r["status"] == 400, f"{mode}: a null-default_ttl policy was stored"

    # ...and the rejected write did not overwrite the good policy.
    got = (await _call(peer, "get-issuer-policy", {}))["result"]["data"]
    assert got["default_ttl"] == 60_000, "the refused policy was stored anyway"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["open", "manual"])
async def test_reg_null_ttl_stored_policy_fails_closed_403(peer, mode):
    """§6a.9 D12 [MUST] — the backstop D11 cannot reach.

    D11 refuses to *store* a null-`default_ttl` live policy, but §6a.9.2's
    store-first resolution admits three ways one is already there: seeded by a
    CLI flag, written straight to the tree, or predating the rule. This test
    takes the second, via `_emit_issuer_policy`, which is the only path that
    can still produce the bad state.

    Both halves are asserted. **403 `policy_rejected`**, and **nothing
    published** — for `manual` that means no queue entry either, which is why
    the refusal sits before the mode branch rather than on the issue path.
    Substituting an implementation-chosen default would be the same mistake
    §6a.9.2 rejects for `get-issuer-policy`: an operator's omission turned into
    a silently-invented policy, here on a field that sets binding lifetime.
    """
    _emit_issuer_policy(peer, mode, default_ttl=None)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "nullttl.lab")   # no requested_ttl
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)

    r = await _call(peer, "register-request", data)

    assert r["status"] == 403, f"{mode}: a null-ttl binding path was not refused"
    assert r["result"]["data"]["code"] == "policy_rejected"
    # Published nothing: the name never became resolvable, and — the half that
    # only `manual` can fail — no pending head was queued either. Refusing on
    # the issue path alone would leave the operator a queue entry to approve
    # whose terms are a null ttl.
    resolved = await _call(peer, "resolve", {"name": "nullttl.lab"})
    assert resolved["result"]["data"]["status"] != "resolved"
    assert _by_request(peer, reg_kp.peer_id, "nullttl.lab") is None, (
        f"{mode}: nothing may be published, and a queue entry is a publication"
    )


@pytest.mark.asyncio
async def test_reg_a_request_carrying_its_own_ttl_survives_the_null_policy(peer):
    """The teeth control beside D12.

    The refusal above must be attributable to the *resolved* ttl being null,
    not to the peer refusing every request against a seeded policy. §6a.9.2's
    resolution is `requested_ttl` first, `default_ttl` second — so the same
    stored policy with a request that names its own ttl resolves fine and MUST
    bind. Without this row, a peer that rejected all registration would read
    green on D12.
    """
    _emit_issuer_policy(peer, "open", default_ttl=None)
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "hasttl.lab", requested_ttl=60_000)
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)

    r = await _call(peer, "register-request", data)

    assert r["status"] == 200, "a request carrying its own ttl was refused"
    assert (await _call(peer, "resolve", {"name": "hasttl.lab"}))["result"]["data"]["status"] == "resolved"


@pytest.mark.asyncio
async def test_reg_get_issuer_policy_unset_is_404(peer):
    """§6a.9.2 [MUST] — unset is not a mode. A registry with no stored policy is
    a conformant curated-only one (§6a.8); `get` MUST return 404 and MUST NOT
    synthesize a default `open`, which would silently turn a curated registry
    into first-come-first-serve."""
    r = await _call(peer, "get-issuer-policy", {})
    assert r["status"] == 404
    assert r["result"]["data"]["code"] == "not_found"


@pytest.mark.asyncio
async def test_reg_set_issuer_policy_domain_control_400(peer):
    """§6a.9.2 [MUST] — `domain-control` is deferred until the challenge format
    lands (§6a.9.1), so `set` refuses to *store* a policy the registry could not
    enforce. The registry stays curated-only: nothing was written.

    **`400 unsupported_mode` is pinned by §6a.9.2 `[MUST]`** and this row
    briefly asserted `invalid_params` instead (2026-09-03), on the reading that
    core §9.1's 501 synonym list forbade the spelling. It does not — see the
    sibling row `test_reg_register_domain_control_unsupported` and SA-PY-37 —
    and `entity-core-go`'s `registry_issuer.set_issuer_policy_domain_control_
    rejected` is what caught it, which is the argument for running the
    validator on a code sweep even when the unit suite is green.

    The two `domain-control` refusals in this handler share a code and differ
    in status on purpose: `400` refuses to **store** the mode; `501` fails
    closed when a policy is already stored (seeded out-of-band or predating the
    refusal). §6a.9.2 gates them separately because the `set` refusal *"cannot
    be the only thing standing between a stored unenforceable mode and an open
    registry."*
    """
    r = await _call(peer, "set-issuer-policy", {"mode": "domain-control"})
    assert (r["status"], r["result"]["data"]["code"]) == (400, "unsupported_mode")
    assert "domain-control" in r["result"]["data"]["message"]
    assert (await _call(peer, "get-issuer-policy", {}))["status"] == 404


@pytest.mark.asyncio
async def test_reg_set_issuer_policy_replaces_whole(peer):
    """§6a.9.2 [MUST] — replace-whole, not merge. An optional field absent from
    the second write means *unset*, not *unchanged*; merge semantics would make
    the stored policy depend on write order, which two peers cannot
    reconstruct.

    Demonstrated on `allowlist` and `name_constraints` rather than on
    `default_ttl`, which this test used to unset: D11 now makes `default_ttl`
    the one field a live policy cannot drop, so it is the wrong field to prove
    replace-whole with. The rule itself is unchanged — every *droppable*
    optional field still drops."""
    await _call(peer, "set-issuer-policy", {
        "mode": "allowlist", "allowlist": ["p1"],
        "name_constraints": "*.lab", "default_ttl": 60_000,
        "max_ttl": _LIVE_MAX_TTL_MS,
    })
    await _call(peer, "set-issuer-policy", {
        "mode": "open", "default_ttl": 90_000, "max_ttl": _LIVE_MAX_TTL_MS,
    })
    got = (await _call(peer, "get-issuer-policy", {}))["result"]["data"]
    assert got["mode"] == "open"
    assert got["allowlist"] is None
    assert got["name_constraints"] is None
    assert got["default_ttl"] == 90_000


@pytest.mark.asyncio
async def test_reg_unsigned_revoke_refused_401(peer):
    """§6a.9 REG-REVOKE-PROOF-1 — revoke is *"Signed by target_peer_id or the
    operator"*. An unsigned revoke MUST be refused.

    The suite had the signed path only, on both revoke and renew. That is the
    gap the whole cohort shipped through: §6a.9 named a proof vector for
    `register` and none for these two, and *the vector list, not the prose, is
    what gets implemented against* — go and rust accepted unsigned revokes
    outright, a permanent denial-of-name against every binding in the registry
    since revocation is monotonic.

    401 `signature_invalid`, not 403 `not_entitled`: absent proof is an
    authentication result; 403 is "proof accepted, policy says no".
    """
    _emit_issuer_policy(peer, "open")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "keepme.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    binding_hash = (await _call(peer, "register-request", data))["result"]["data"]["binding_hash"]

    # No _sign_into_store for the revoke — that is the whole test.
    r = await _call(peer, "revoke-request", {"binding_hash": binding_hash,
                                             "reason": "not mine to revoke"})
    assert r["status"] == 401
    assert r["result"]["data"]["code"] == "signature_invalid"

    # §2.4a negative half: refused AND nothing published. A 401 that emitted
    # the revocation anyway would satisfy a status-only check while leaving the
    # name permanently dead — the failure this vector exists to catch.
    assert (await _call(peer, "resolve", {"name": "keepme.com"}))["result"]["data"]["status"] == "resolved"


@pytest.mark.asyncio
async def test_reg_unsigned_renew_refused_401(peer):
    """§6a.9 REG-RENEW-PROOF-1 — renew is *"Signed by target_peer_id"*
    (layer-1). Replay defense is not authorization: a nonce check stops a
    *captured* request being re-run while leaving a *fresh unsigned* one
    accepted."""
    _emit_issuer_policy(peer, "open")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()
    data = _register_data(reg_kp.peer_id, "renewme.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    binding_hash = (await _call(peer, "register-request", data))["result"]["data"]["binding_hash"]

    r = await _call(peer, "renew-request", {"binding_hash": binding_hash, "ttl": 999999})
    assert r["status"] == 401
    assert r["result"]["data"]["code"] == "signature_invalid"

    # Negative half: no superseding binding was issued.
    resolved = await _call(peer, "resolve", {"name": "renewme.com"})
    assert resolved["result"]["data"]["status"] == "resolved"
    assert bytes(resolved["result"]["data"]["binding"]) == bytes(binding_hash)


@pytest.mark.asyncio
async def test_layer1_row_is_401_signature_invalid_at_all_three_sites(peer):
    """§6a.9's ratified status table — layer-1 is **401 + `signature_invalid`**,
    and the three sites answer it identically.

    The three per-op vectors above each pin their own site. What none of them
    can see is *drift between* the sites, which is the shape this row actually
    failed in: register moved to 401 at `4cdf805`, revoke/renew followed at
    `9ac97bb`, and all three then carried `proof_failed` — a code the spec does
    not name — for a month, green the whole time, because go's instrument
    asserted the status and stopped (their R-3, fixed at `6aed8f1`, measured
    against py at `2c1aa1b`: three FAILs).

    So this asserts the tuple, once, across the row: same status, same code,
    from the same constant. A future site that hand-rolls its own literal
    fails here rather than at a cross-impl run three weeks later.
    """
    from entity_handlers.registry import LAYER1_PROOF_ERROR_CODE

    _emit_issuer_policy(peer, "open")
    _peerissued_config(peer, peer.keypair)
    reg_kp = Keypair.generate()

    # A live binding to aim the revoke/renew at (register signed; those two not).
    data = _register_data(reg_kp.peer_id, "threesites.com")
    _sign_into_store(peer, reg_kp, "system/registry/register-request", data)
    binding_hash = (await _call(peer, "register-request", data))["result"]["data"]["binding_hash"]

    answers = {
        "register-request": await _call(
            peer, "register-request", _register_data(reg_kp.peer_id, "unsigned-three.com")
        ),
        "revoke-request": await _call(
            peer, "revoke-request", {"binding_hash": binding_hash}
        ),
        "renew-request": await _call(
            peer, "renew-request", {"binding_hash": binding_hash}
        ),
    }
    for op, r in answers.items():
        assert r["status"] == 401, f"{op} layer-1 status"
        assert r["result"]["data"]["code"] == LAYER1_PROOF_ERROR_CODE, f"{op} layer-1 code"
    # The spec's value, not merely our own constant echoed back at us.
    assert LAYER1_PROOF_ERROR_CODE == "signature_invalid"
