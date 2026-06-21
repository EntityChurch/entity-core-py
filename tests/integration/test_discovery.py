"""EXTENSION-DISCOVERY v1.0 — substrate pins (§8 conformance).

Python-side behaviour pins for the discovery substrate, driven by an
in-memory ``FakeBackend`` so the MUSTs are exercised without multicast (the
live three-peer LAN convergence is the cohort validate-peer / D8 run). The
mDNS §3.2 wire pins live in ``test_discovery_mdns.py``.

Covers: entity round-trips + identity_hint determinism/fail-closed (§2.2.1),
hybrid ``:scan`` snapshot + watchable prefix (§3.0), reap rule (§3.0.1),
resource bounds 413/503 (§3.1), successor-candidate (§2.2), the ``:decide``
decision surface + refless bare-hash (§2.1), and the no-silent-admit MUSTs
(§8.4).
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.extensions import ExtensionContext

from entity_handlers.discovery import (
    CANDIDATE_PREFIX,
    CANDIDATE_TYPE,
    DECISION_PREFIX,
    DECISION_TYPE,
    DISCOVERY_CAPS,
    IDENTITY_CLAIM_TYPE,
    AnnounceSession,
    BrowseSession,
    CandidateObservation,
    DiscoveryBackend,
    DiscoveryExtension,
    identity_claim_from_peer_id,
    identity_hint_for_peer_id,
    make_candidate,
    make_decision,
    verify_identity_hint,
)


# ---------------------------------------------------------------------------
# Fake backend — drives the substrate deterministically (no multicast)
# ---------------------------------------------------------------------------


class _FakeBrowse(BrowseSession):
    def __init__(self, backend: "FakeBackend") -> None:
        self._backend = backend
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


class _FakeAnnounce(AnnounceSession):
    def __init__(self) -> None:
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True


class FakeBackend(DiscoveryBackend):
    name = "fake"

    def __init__(self) -> None:
        self.snapshot: list[CandidateObservation] = []
        self.on_arrive = None
        self.on_depart = None
        self.scan_raises: Exception | None = None
        self.announces: list[_FakeAnnounce] = []

    async def scan(self, filter):
        if self.scan_raises is not None:
            raise self.scan_raises
        return list(self.snapshot)

    async def start_browse(self, filter, on_arrive, on_depart):
        self.on_arrive = on_arrive
        self.on_depart = on_depart
        return _FakeBrowse(self)

    async def announce(self, profile_ref, txt):
        s = _FakeAnnounce()
        self.announces.append(s)
        return s

    # test driver helpers
    def arrive(self, obs: CandidateObservation):
        assert self.on_arrive is not None, "browse not started"
        self.on_arrive(obs)

    def depart(self, candidate_id: str):
        assert self.on_depart is not None, "browse not started"
        self.on_depart(candidate_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def peer():
    # enable_mdns=False so the suite never touches multicast / zeroconf sockets.
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_default_handlers()
        .build()
    )


@pytest.fixture
def ext(peer):
    e = DiscoveryExtension(scan_ceiling=4, max_candidate_payload=4096)
    e.register_backend(FakeBackend())
    e.initialize(ExtensionContext(keypair=peer.keypair, emit_pathway=peer.emit_pathway))
    return e


@pytest.fixture
def backend(ext) -> FakeBackend:
    return ext._backends["fake"]  # type: ignore[return-value]


def _ctx(peer) -> HandlerContext:
    blanket = {"grants": [{"handlers": {"include": ["*"]}, "resources": {"include": ["*"]}, "operations": {"include": ["*"]}}]}
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test",
        handler_grant=blanket,
        caller_capability=blanket,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
        handler_pattern="system/discovery",
    )


async def _call(ext, peer, op, data):
    return await ext.handler()("system/discovery", op, {"data": data}, _ctx(peer))


def _obs(cid="peerA", *, peer_id_hint=None, ttl_ms=120_000, endpoint=None):
    return CandidateObservation(
        candidate_id=cid,
        endpoint_hint=endpoint or {"addresses": ["1.2.3.4"], "port": 9000},
        peer_id_hint=peer_id_hint,
        ttl_ms=ttl_ms,
        observed_at=1000,
    )


# ---------------------------------------------------------------------------
# §2.1 / §2.2.1 — entity shapes + identity_hint
# ---------------------------------------------------------------------------


def test_candidate_entity_shape():
    # Ruling 6: None optionals are ABSENT (peer_id null until IDENTIFY §2.2 →
    # omitted; identity_hint + supersedes None → omitted). Required fields stay.
    c = make_candidate(
        backend="mdns", observed_at=1000,
        endpoint_hint={"port": 9000}, peer_id=None,
    )
    assert c.type == CANDIDATE_TYPE
    assert set(c.data) == {"backend", "observed_at", "endpoint_hint"}
    assert "peer_id" not in c.data  # absent, not CBOR-null
    assert len(c.compute_hash()) == 33  # format byte + SHA-256
    # populated optionals ARE present
    full = make_candidate(
        backend="mdns", observed_at=1000, endpoint_hint={"port": 9000},
        peer_id="P", identity_hint=b"\x00" * 33, supersedes=b"\x01" * 33,
    )
    assert set(full.data) == {
        "peer_id", "backend", "observed_at", "endpoint_hint",
        "identity_hint", "supersedes",
    }


def test_decision_entity_shape():
    # Ruling 6: grant None (track) → omitted; required fields stay.
    d = make_decision(candidate=b"\x00" * 33, outcome="track", decided_at=2000)
    assert d.type == DECISION_TYPE
    assert set(d.data) == {"candidate", "outcome", "decided_at"}
    assert "grant" not in d.data
    # grant present when supplied (grant-limited)
    dg = make_decision(candidate=b"\x00" * 33, outcome="grant-limited",
                       grant=b"\x02" * 33, decided_at=2000)
    assert dg.data["grant"] == b"\x02" * 33


def test_identity_claim_fields_decode_peer_id():
    kp = Keypair.generate()
    ic = identity_claim_from_peer_id(kp.peer_id)
    assert ic.type == IDENTITY_CLAIM_TYPE
    assert ic.data["peer_id"] == kp.peer_id
    assert ic.data["key_type"] == 0x01  # Ed25519 (V7 §1.5)
    assert ic.data["hash_type"] == 0x00  # identity multihash
    assert ic.data["public_key_digest"] == kp.public_key_bytes()


def test_identity_hint_deterministic_and_fail_closed():
    kp = Keypair.generate()
    other = Keypair.generate()
    hint = identity_hint_for_peer_id(kp.peer_id)
    assert hint == identity_hint_for_peer_id(kp.peer_id)  # deterministic
    # §2.2.1: non-null hint must match the post-IDENTIFY peer-id
    assert verify_identity_hint(hint, kp.peer_id) is True
    # §8.4 MUST fail closed on mismatch
    assert verify_identity_hint(hint, other.peer_id) is False
    # null hint = TOFU (admission at user discretion)
    assert verify_identity_hint(None, kp.peer_id) is True


# ---------------------------------------------------------------------------
# §3.0 — hybrid :scan (snapshot return + watchable prefix)
# ---------------------------------------------------------------------------


async def test_scan_returns_snapshot_and_writes_watchable_prefix(ext, peer, backend):
    backend.snapshot = [_obs("peerA"), _obs("peerB")]
    resp = await _call(ext, peer, "scan", {"backend": "fake"})
    assert resp["status"] == 200
    result = resp["result"]
    assert result["type"] == "system/discovery/scan-result"
    assert result["data"]["truncated"] is False
    assert result["data"].get("code") is None
    assert len(result["data"]["candidates"]) == 2  # bare hashes

    # watchable prefix: candidate entities written into the tree (§3.0)
    tree = peer.emit_pathway.entity_tree
    uri_a = tree.normalize_uri(f"{CANDIDATE_PREFIX}fake/peerA")
    h = tree.get(uri_a)
    assert h is not None
    ent = peer.emit_pathway.content_store.get(h)
    assert ent.type == CANDIDATE_TYPE


async def test_scan_unknown_backend_400(ext, peer):
    resp = await _call(ext, peer, "scan", {"backend": "nope"})
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "unknown_backend"


async def test_scan_unparseable_filter_surfaces_error_not_empty(ext, peer, backend):
    # §3.3: backends MUST NOT silently return zero on a bad filter.
    backend.scan_raises = ValueError("bad filter")
    resp = await _call(ext, peer, "scan", {"backend": "fake", "filter": {"x": 1}})
    assert resp["status"] == 503
    assert resp["result"]["data"]["code"] == "discovery_scan_failed"


async def test_browse_arrive_and_depart(ext, peer, backend):
    await _call(ext, peer, "scan", {"backend": "fake"})  # starts browse session
    tree = peer.emit_pathway.entity_tree
    backend.arrive(_obs("late"))
    uri = tree.normalize_uri(f"{CANDIDATE_PREFIX}fake/late")
    assert tree.get(uri) is not None  # arrival → written
    backend.depart("late")
    assert tree.get(uri) is None  # §3.0.1(1) goodbye → immediate removal


# ---------------------------------------------------------------------------
# §3.1 — resource bounds (413 per-candidate / 503 scan overflow)
# ---------------------------------------------------------------------------


async def test_scan_overflow_truncates_with_503(ext, peer, backend):
    # scan_ceiling=4 (fixture). Six observations → truncated + 503.
    backend.snapshot = [_obs(f"p{i}") for i in range(6)]
    resp = await _call(ext, peer, "scan", {"backend": "fake"})
    assert resp["status"] == 503
    data = resp["result"]["data"]
    assert data["truncated"] is True
    assert data["code"] == "discovery_scan_overflow"
    assert len(data["candidates"]) == 4  # ceiling; remainder dropped, NOT silent


async def test_oversized_candidate_dropped(ext, peer, backend):
    # max_candidate_payload=4096 (fixture). A huge endpoint_hint blows it.
    big = _obs("big", endpoint={"addresses": ["x" * 9000], "port": 1})
    backend.snapshot = [big, _obs("ok")]
    resp = await _call(ext, peer, "scan", {"backend": "fake"})
    assert resp["status"] == 200
    # oversized dropped (413), the small one emitted
    assert len(resp["result"]["data"]["candidates"]) == 1
    tree = peer.emit_pathway.entity_tree
    assert tree.get(tree.normalize_uri(f"{CANDIDATE_PREFIX}fake/big")) is None
    assert tree.get(tree.normalize_uri(f"{CANDIDATE_PREFIX}fake/ok")) is not None


# ---------------------------------------------------------------------------
# §3.0.1 — reap rule (liveness, not wall-clock)
# ---------------------------------------------------------------------------


async def test_reap_ages_out_after_grace_window(ext, peer, backend):
    backend.snapshot = [_obs("p", ttl_ms=1000)]  # last_seen=1000, ttl=1000
    await _call(ext, peer, "scan", {"backend": "fake"})
    tree = peer.emit_pathway.entity_tree
    uri = tree.normalize_uri(f"{CANDIDATE_PREFIX}fake/p")
    assert tree.get(uri) is not None
    # grace = 2 × ttl = 2000ms; still alive at last_seen + 2000
    assert ext.reap("fake", now=1000 + 2000) == []
    assert tree.get(uri) is not None
    # past the window → aged out
    assert ext.reap("fake", now=1000 + 2001) == ["p"]
    assert tree.get(uri) is None


async def test_reap_skips_oneshot_candidates(ext, peer, backend):
    # ttl_ms=None → one-shot (QR-like); never aged out by reap (§3.0.1(4))
    backend.snapshot = [_obs("qr", ttl_ms=None)]
    await _call(ext, peer, "scan", {"backend": "fake"})
    assert ext.reap("fake", now=10**12) == []


# ---------------------------------------------------------------------------
# §2.2 — successor-candidate (peer_id null-until-IDENTIFY)
# ---------------------------------------------------------------------------


def test_successor_candidate_supersedes_chain():
    kp = Keypair.generate()
    c0 = make_candidate(
        backend="mdns", observed_at=1000, endpoint_hint={"port": 9000},
        peer_id=None,  # null at observation (§2.2)
    )
    c0_hash = c0.compute_hash()
    # post-IDENTIFY successor: peer_id populated + supersedes chain head
    c1 = make_candidate(
        backend="mdns", observed_at=2000, endpoint_hint={"port": 9000},
        peer_id=kp.peer_id, supersedes=c0_hash,
        identity_hint=identity_hint_for_peer_id(kp.peer_id),
    )
    assert c1.data["peer_id"] == kp.peer_id
    assert c1.data["supersedes"] == c0_hash  # bare hash, refless (§2.1)
    assert c1.compute_hash() != c0_hash  # immutable; new entity


# ---------------------------------------------------------------------------
# §2.2 / §2.2.1 — admit_identified (IDENTIFY-completion → successor)
# ---------------------------------------------------------------------------


async def test_admit_identified_creates_successor(ext, peer, backend):
    kp = Keypair.generate()
    # candidate observed with a peer_id_hint → identity_hint pinned at scan time
    backend.snapshot = [_obs("p", peer_id_hint=kp.peer_id)]
    resp = await _call(ext, peer, "scan", {"backend": "fake"})
    c0_hash = resp["result"]["data"]["candidates"][0]

    res = ext.admit_identified(c0_hash, kp.peer_id)
    assert res.ok is True and res.successor is not None
    successor = peer.emit_pathway.content_store.get(res.successor)
    assert successor.data["peer_id"] == kp.peer_id  # null→populated (§2.2)
    assert successor.data["supersedes"] == c0_hash  # supersedes-chain
    assert successor.compute_hash() != c0_hash  # new immutable entity
    # live slot now points to the identified successor
    tree = peer.emit_pathway.entity_tree
    live_h = tree.get(tree.normalize_uri(f"{CANDIDATE_PREFIX}fake/p"))
    assert live_h == res.successor
    # candidate_0 survives in the content store (observation record, §7)
    assert peer.emit_pathway.content_store.get(c0_hash) is not None


async def test_admit_identified_fails_closed_on_mismatch(ext, peer, backend):
    claimed = Keypair.generate()
    impostor = Keypair.generate()
    backend.snapshot = [_obs("p", peer_id_hint=claimed.peer_id)]
    resp = await _call(ext, peer, "scan", {"backend": "fake"})
    c0_hash = resp["result"]["data"]["candidates"][0]

    # §2.2.1 / §8.4: IDENTIFY returns a DIFFERENT peer than advertised → reject
    res = ext.admit_identified(c0_hash, impostor.peer_id)
    assert res.ok is False
    assert res.reason == "identity_hint_mismatch"
    assert res.successor is None
    # no successor written; live slot unchanged (still candidate_0)
    tree = peer.emit_pathway.entity_tree
    assert tree.get(tree.normalize_uri(f"{CANDIDATE_PREFIX}fake/p")) == c0_hash


async def test_admit_identified_tofu_allows_any_peer(ext, peer, backend):
    # null identity_hint (no peer_id_hint) = TOFU; admission at user discretion
    backend.snapshot = [_obs("p", peer_id_hint=None)]
    resp = await _call(ext, peer, "scan", {"backend": "fake"})
    c0_hash = resp["result"]["data"]["candidates"][0]
    assert peer.emit_pathway.content_store.get(c0_hash).data.get("identity_hint") is None

    kp = Keypair.generate()
    res = ext.admit_identified(c0_hash, kp.peer_id)
    assert res.ok is True
    successor = peer.emit_pathway.content_store.get(res.successor)
    assert successor.data["peer_id"] == kp.peer_id


def test_admit_identified_unknown_candidate(ext):
    res = ext.admit_identified(b"\xff" * 33, "whoever")
    assert res.ok is False and res.reason == "candidate_not_found"


# ---------------------------------------------------------------------------
# §2.1 / §8.4 — :decide decision surface (no silent admit)
# ---------------------------------------------------------------------------


async def test_decide_records_decision(ext, peer):
    chash = b"\x00" * 33
    resp = await _call(ext, peer, "decide", {"candidate": chash, "outcome": "track"})
    assert resp["status"] == 200
    dhash = resp["result"]["data"]["decision"]
    tree = peer.emit_pathway.entity_tree
    uri = tree.normalize_uri(f"{DECISION_PREFIX}{dhash.hex()}")
    ent = peer.emit_pathway.content_store.get(tree.get(uri))
    assert ent.type == DECISION_TYPE
    assert ent.data["outcome"] == "track"
    assert ent.data.get("grant") is None


async def test_decide_grant_outcome_requires_grant(ext, peer):
    resp = await _call(ext, peer, "decide", {"candidate": b"\x01" * 33, "outcome": "grant-limited"})
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "grant_required"


async def test_decide_non_grant_outcome_rejects_grant(ext, peer):
    resp = await _call(ext, peer, "decide", {
        "candidate": b"\x01" * 33, "outcome": "ignore", "grant": b"\x02" * 33,
    })
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "unexpected_grant"


async def test_decide_invalid_outcome(ext, peer):
    resp = await _call(ext, peer, "decide", {"candidate": b"\x01" * 33, "outcome": "yolo"})
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "invalid_outcome"


async def test_decide_grant_outcome_stores_refless_bare_hash(ext, peer):
    grant = b"\x03" * 33
    resp = await _call(ext, peer, "decide", {
        "candidate": b"\x01" * 33, "outcome": "grant-limited", "grant": grant,
    })
    assert resp["status"] == 200
    tree = peer.emit_pathway.entity_tree
    dhash = resp["result"]["data"]["decision"]
    ent = peer.emit_pathway.content_store.get(
        tree.get(tree.normalize_uri(f"{DECISION_PREFIX}{dhash.hex()}"))
    )
    # §8.4: grant referenced by bare system/hash, not a refs: block
    assert ent.data["grant"] == grant
    assert "refs" not in ent.data


# ---------------------------------------------------------------------------
# §3 — announce / announce-stop
# ---------------------------------------------------------------------------


async def test_announce_and_stop(ext, peer, backend):
    resp = await _call(ext, peer, "announce", {"backend": "fake", "profile_ref": "p1"})
    assert resp["status"] == 200 and resp["result"]["data"]["announced"] is True
    assert len(backend.announces) == 1 and backend.announces[0].stopped is False
    resp = await _call(ext, peer, "announce-stop", {"backend": "fake", "profile_ref": "p1"})
    assert resp["status"] == 200 and resp["result"]["data"]["stopped"] is True
    assert backend.announces[0].stopped is True


async def test_announce_stop_idempotent(ext, peer):
    resp = await _call(ext, peer, "announce-stop", {"backend": "fake", "profile_ref": "ghost"})
    assert resp["status"] == 200 and resp["result"]["data"]["stopped"] is False


async def test_announce_requires_profile_ref(ext, peer):
    resp = await _call(ext, peer, "announce", {"backend": "fake"})
    assert resp["status"] == 400


# ---------------------------------------------------------------------------
# §4 — capability surface (named; no "discovery grants access" cap)
# ---------------------------------------------------------------------------


def test_capability_surface_is_exactly_two():
    assert DISCOVERY_CAPS == (
        "system/capability/discovery-scan",
        "system/capability/discovery-announce",
    )
    # §8.4: by construction there is no cap that admits a peer.
    assert not any("admit" in c or "grant-access" in c for c in DISCOVERY_CAPS)


async def test_unknown_operation_404(ext, peer):
    resp = await _call(ext, peer, "bogus", {})
    assert resp["status"] == 404
