"""Tier-1 publish→fetch end-to-end — the v1 relay/network gate (Thread B).

Python mirror of Go's ``publish_fetch_http_poll`` validate-peer category
(`entity-core-go/cmd/internal/validate/publish_fetch_http_poll.go`). A
publisher mints a signed root over a small blog tree, exposes its tree as a
static HTTP origin (the http-poll ``HttpServer`` — wire-equivalent to nginx /
R2 / S3 serving the same routes), and a consumer drives the full read flow:

    MANIFEST_GET → signature verify → TREE_GET (system/hash pointer,
    Amendment 6) → CONTENT_GET /content/{hex33(H)} → re-hash → ingest →
    byte-equality against publisher originals.

This is **Mechanism A** (NETWORK §6.5.3.1 — HTTP-as-storage-transport), NOT
BRIDGE-HTTP. Fully self-contained / in-process: the publisher + static origin
+ consumer all live inside the test. Self-PASS 6/6 = the Thread B gate per
arch §3.5 (cross-impl interop is bonus).

Six vectors (cohort pin matrix; see the publish-fetch http-poll
python-pickup handoff §1.3 for the Go↔Python vector map and the two
cross-impl notes):

    v1 publish_manifest_served      v4 content_fetch_hash_verified
    v2 manifest_signature_verified  v5 ingest_byte_equality
    v3 tree_leaf_pointer_resolves   v6 host_bytes_distrust
"""

from __future__ import annotations

import http.server
import threading

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.http_poll_client import HttpPollClient, HttpPollError
from entity_core.peer.published_root import closure_scope_for_published_root
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.utils.ecf import ecf_encode

# Cohort fixture — mirror of Go's hand-rolled blog tree. Same {title, body}
# shape; ECF (cbor2 canonical, RFC 8949 §4.2) emits the same bytes Go's
# cbor.CoreDetEncOptions does, so byte-equality is the cohort agreement signal.
BLOG_TYPE = "test/blog/post/v1"
BLOG_ENTRIES = [
    ("system/blog/post/entry-1", {"title": "first", "body": "hello"}),
    ("system/blog/post/entry-2", {"title": "second", "body": "world"}),
    ("system/blog/post/entry-3", {"title": "third", "body": "fin"}),
]


# -- harness (v1..v5): in-process publisher + static origin ------------------


def _make_blog_publisher():
    """Author the blog tree and mint a signed published-root over it."""
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    authored = []  # (peer_relative_path, entity, original_data_dict)
    for path, data in BLOG_ENTRIES:
        ent = Entity(type=BLOG_TYPE, data=data)
        peer.emit_pathway.emit(path, ent, EmitContext.bootstrap())
        authored.append((path, ent, data))
    peer.publish_root()
    return peer, kp, authored


async def _serve(peer):
    """Mount the published-root closure as a static http-poll origin."""
    scope = closure_scope_for_published_root(peer.entity_tree, peer.content_store)
    server = await peer.start_http_poll("127.0.0.1", 0, scope_predicate=scope, poll_prefix="")
    host, port = server.bound_socket()
    return server, f"http://{host}:{port}"


# -- v1: publisher mints, PollHandler serves the manifest --------------------


@pytest.mark.asyncio
async def test_v1_publish_manifest_served():
    """MANIFEST_GET serves a system/peer/published-root with correct type,
    non-zero root_hash, and matching PeerID. Unpinned fetch — the signature
    verify cycle is v2's gate."""
    peer, kp, _ = _make_blog_publisher()
    server, base = await _serve(peer)
    try:
        pr = await HttpPollClient(base).manifest()
        assert pr.type == "system/peer/published-root"
        root_hash = pr.data.get("root_hash")
        assert isinstance(root_hash, (bytes, bytearray)) and any(root_hash), "root_hash is zero/missing"
        assert pr.data.get("peer_id") == kp.peer_id
    finally:
        await server.stop()


# -- v2: pinned-identity signature verify reaches Verified=true --------------


@pytest.mark.asyncio
async def test_v2_manifest_signature_verified():
    """The consumer walks the V7 §5.2 invariant-pointer signature carriage and
    verifies. Python's verify is mandatory (no no-pin path), so the "pin" is the
    explicit assertion that the *verified* peer_id is the one we meant to trust
    — see pickup §1.4."""
    peer, kp, _ = _make_blog_publisher()
    server, base = await _serve(peer)
    try:
        pr, root_hash = await HttpPollClient(base).fetch_verified_root()
        assert isinstance(root_hash, bytes) and any(root_hash)
        # The pin: we verified, and we verified the identity we intended.
        assert pr.data.get("peer_id") == kp.peer_id
    finally:
        await server.stop()


# -- v3: each authored leaf resolves to its bound system/hash pointer ---------


@pytest.mark.asyncio
async def test_v3_tree_leaf_pointer_resolves():
    """For each authored peer-relative path, TREE_GET returns the bound
    system/hash pointer (Amendment 6) — byte-equal to the publisher's authored
    content_hash."""
    peer, kp, authored = _make_blog_publisher()
    server, base = await _serve(peer)
    try:
        client = HttpPollClient(base)
        for path, ent, _ in authored:
            ptr = await client.tree_pointer(kp.peer_id, path)
            assert ptr == ent.compute_hash(), f"pointer drift at {path}"
    finally:
        await server.stop()


# -- v4: CONTENT_GET returns a byte-equal entity that re-hashes to H ----------


@pytest.mark.asyncio
async def test_v4_content_fetch_hash_verified():
    """CONTENT_GET on each leaf pointer returns an entity that re-hashes to the
    requested H (the client enforces this — Mechanism A trust gate fires
    positively). v6 covers the negative path."""
    peer, kp, authored = _make_blog_publisher()
    server, base = await _serve(peer)
    try:
        client = HttpPollClient(base)
        for path, ent, _ in authored:
            got = await client.content_get(ent.compute_hash())
            assert got.compute_hash() == ent.compute_hash(), f"hash drift at {path}"
            assert got.type == BLOG_TYPE, f"type drift at {path}"
    finally:
        await server.stop()


# -- v5: end-to-end ingest byte-equality (the gate) --------------------------


@pytest.mark.asyncio
async def test_v5_ingest_byte_equality():
    """After the full publish→fetch round-trip, every consumer entity's .data
    is byte-equal (canonical ECF) to the publisher's original. Python has no
    cbor.RawMessage; byte-stability rests on ECF determinism — see pickup §1.5.
    This is the Tier-1 v1 gate."""
    peer, kp, authored = _make_blog_publisher()
    server, base = await _serve(peer)
    try:
        client = HttpPollClient(base)
        for path, ent, original_data in authored:
            ptr = await client.tree_pointer(kp.peer_id, path)
            got = await client.content_get(ptr)
            assert ecf_encode(got.data) == ecf_encode(original_data), (
                f"ingest data drift at {path} — wire round-trip changed bytes "
                "(ECF determinism broken)"
            )
    finally:
        await server.stop()


# -- v6: host-bytes-distrust gate fires on the blog-entity shape -------------


class _ImposterContentHandler(http.server.BaseHTTPRequestHandler):
    """A malicious static origin: serves imposter bytes for any /content/*
    request, regardless of the hash asked for."""

    imposter_body = b""

    def do_GET(self):  # noqa: N802 (stdlib API)
        if not self.path.startswith("/content/"):
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/cbor")
        self.send_header("Content-Length", str(len(self.imposter_body)))
        self.end_headers()
        self.wfile.write(self.imposter_body)

    def log_message(self, *args):  # silence test noise
        pass


@pytest.mark.asyncio
async def test_v6_host_bytes_distrust():
    """A swap-bytes static origin is rejected by the connector's CONTENT_GET
    re-hash check (§1.1 threat model), applied to the blog-entity shape —
    proving the gate is shape-agnostic."""
    real = Entity(type=BLOG_TYPE, data={"title": "real", "body": "post"})
    imposter = Entity(type=BLOG_TYPE, data={"title": "imposter", "body": "bytes"})
    # The body the malicious host serves: ECF of the imposter {type, data}.
    _ImposterContentHandler.imposter_body = ecf_encode(
        {"type": imposter.type, "data": imposter.data}
    )

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _ImposterContentHandler)
    host, port = httpd.server_address
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        client = HttpPollClient(f"http://{host}:{port}")
        with pytest.raises(HttpPollError) as exc:
            await client.content_get(real.compute_hash())
        # Rejection must cite the hash mismatch (not a generic transport error).
        assert exc.value.code == "content_hash_mismatch"
        assert "hash" in exc.value.message.lower()
    finally:
        httpd.shutdown()
        thread.join(timeout=5)
