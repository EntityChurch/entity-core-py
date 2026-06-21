"""Chunk E — `system/peer/transport/http-poll` route pin matrix.

Pre-Amendment-5: 10-row cohort matrix. Post Amendment 5 (NETWORK §6.5
v1.4): two-suffix named-object addressing — `.bin` for the leaf entity,
`.list` for the listing — no trailing slash anywhere; first-segment
demux is literal-or-peer-id-parse with reserved set
`{content, manifest, peers}`; `serve_scope` is a capability token
(`CapTokenScope`).

These are Python-side pins; the three-way matrix lives in
`entity-core-go/ext/httplive/crossimpl_all_test.go::TestHTTPPoll_CrossImpl_*`.
"""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request

import pytest

import hashlib

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.serving import CapTokenScope, WholeStoreScope
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ecf_decode, ecf_encode


def _url_hex(h: bytes) -> str:
    """Cohort canonical URL form (post arch §5B + F-PY-13
    ruling): hex of the full 33-byte hash — algorithm byte + 32-byte
    SHA-256 digest — per V7 §3.5. 66 hex chars. Strict; 64-char
    digest-only URLs return 400. Matches Go's `hash.FromBytes`."""
    assert len(h) == 33 and h[0] == 0x00, f"unexpected hash shape: {h!r}"
    return h.hex()


def _rehash(body: bytes) -> bytes:
    """Compute 0x00 || SHA-256(body) — the verify-by-rehash on the
    consumer side. Mirrors compute_hash for {type, data}."""
    return bytes([0x00]) + hashlib.sha256(body).digest()


def _make_peer():
    kp = Keypair.generate()
    return PeerBuilder().with_keypair(kp).with_all_handlers().build()


def _make_blob_entity(payload: bytes) -> Entity:
    """Build a small `system/content/chunk` entity for serving tests."""
    return Entity(
        type="system/content/chunk",
        data={"bytes": payload},
    )


def _bind_in_namespace(peer, namespace: str, h: bytes) -> None:
    """Bind {namespace}/{hex(h)} → h in the peer's tree (the namespace gate)."""
    leaf = f"{namespace}/{h.hex()}"
    peer.entity_tree.set(leaf, h)


def _do_request(
    *, method: str, host: str, port: int, path: str, data: bytes | None = None
) -> tuple[int, dict[str, str], bytes]:
    url = f"http://{host}:{port}{path}"

    def runner():
        req = urllib.request.Request(url, data=data, method=method)
        try:
            resp = urllib.request.urlopen(req, timeout=3.0)
            return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers.items()) if e.headers else {}, e.read() or b""

    return runner()


async def _run_against_isolated_poll(peer, namespace: str, fn):
    """Posture 1 setup: isolated poll port with namespace scope."""
    scope = CapTokenScope.from_namespace(peer.entity_tree, namespace, peer.peer_id)
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix=""
    )
    try:
        bound = server.bound_socket()
        assert bound is not None
        host, port = bound
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, fn, host, port)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_pin_1_inscope_hit_returns_200_and_entity_ecf():
    """Pin #1 (post-arch-ruling §1): body is the full entity ECF, NOT the
    inner payload. The body MUST re-hash to the URL hash — that's the
    verify-by-rehash Mechanism-A contract."""
    peer = _make_peer()
    namespace = "system/content/public"
    payload = b"hello chunk e world"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    _bind_in_namespace(peer, namespace, h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{_url_hex(h)}",
        )

    code, _headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200
    # Body is ECF({type, data}) — decode it and check the type+data round-trip.
    decoded = ecf_decode(body)
    assert decoded["type"] == "system/content/chunk"
    assert decoded["data"]["bytes"] == payload
    # And it MUST be EXACTLY what the hash hashed over.
    assert body == ecf_encode({"type": entity.type, "data": entity.data})


@pytest.mark.asyncio
async def test_pin_rehash_invariant():
    """The one-line cross-impl invariant from arch ruling §4: re-hash of
    response body equals the URL hash. This is the assertion that catches
    all three body-shape divergences at once. The cohort's
    `crossimpl_poll_test.go:114` is the Go-side equivalent."""
    peer = _make_peer()
    namespace = "system/content/public"
    # Use a non-chunk entity to be extra-rigorous — the body shape is
    # entity-type-agnostic.
    entity = Entity(
        type="example/thing",
        data={"name": "rehash-invariant", "n": 42},
    )
    h = peer.content_store.put(entity)
    _bind_in_namespace(peer, namespace, h)
    url_hex = _url_hex(h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{url_hex}",
        )

    code, _, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200
    rehashed = _rehash(body)
    assert rehashed == h, (
        f"verify-by-rehash failed: server body re-hashes to {rehashed.hex()} "
        f"but URL hash was {h.hex()}"
    )


@pytest.mark.asyncio
async def test_pin_url_hex_64char_rejected_strict():
    """F-PY-13 ruling: clean break, no shim. 64-char
    digest-only URLs return 400. {hash} means one thing everywhere —
    the 66-hex wire form. Matches Go's `hash.FromBytes` strict form.

    This pin replaces the prior `test_pin_url_hex_64char_back_compat`
    which exercised lenient acceptance; arch ruled "strict 66, no
    legacy data, no shim" and Python tightened."""
    peer = _make_peer()
    namespace = "system/content/public"
    entity = _make_blob_entity(b"strict")
    h = peer.content_store.put(entity)
    _bind_in_namespace(peer, namespace, h)
    # h.hex() is 66 chars; h[1:].hex() is the legacy 64-char digest form.
    legacy_64char = h[1:].hex()

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{legacy_64char}",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 400


@pytest.mark.asyncio
async def test_pin_sha384_content_served_format_relative():
    """Headline repro for the v7.70 §3.5 format-relative content GET fix.

    A SHA-384 home peer hashes its own content with SHA-384, yielding a
    49-byte / 98-hex wire hash. The pre-fix route hardcoded 66 hex +
    `h[0] == 0x00` and 400'd a peer out of serving its OWN store. The
    fix delegates width+format to `validate_hash`, so a structurally
    valid SHA-384 wire hash is served exactly like SHA-256.

    This is the http_server analog of the v7.70 capability `peer_pattern`
    fix (5c31e28) — same root-cause class, same structural gate."""
    from entity_core.utils.ecf import ALG_ECFV1_SHA384

    peer = _make_peer()
    namespace = "system/content/public"
    # Author the entity under SHA-384 — content_store keys on the home
    # format verbatim (49-byte wire hash).
    entity = Entity(
        type="system/content/chunk",
        data={"bytes": b"sha384-served"},
        hash_algorithm=ALG_ECFV1_SHA384,
    )
    h = peer.content_store.put(entity)
    assert len(h) == 49 and h[0] == ALG_ECFV1_SHA384, f"unexpected: {h!r}"
    _bind_in_namespace(peer, namespace, h)
    url_hex = h.hex()
    assert len(url_hex) == 98

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{url_hex}",
        )

    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, f"SHA-384 content should be served, got {code}"
    # Body re-hashes to the URL hash under SHA-384 (Mechanism A).
    h_lower = {k.lower(): v for k, v in headers.items()}
    assert h_lower.get("content-type") == "application/cbor"
    assert h_lower.get("etag") == f'"{url_hex}"'
    rehash = bytes([ALG_ECFV1_SHA384]) + hashlib.sha384(body).digest()
    assert rehash == h, "body MUST re-hash to the URL hash"


@pytest.mark.asyncio
async def test_pin_wrong_digest_width_returns_400():
    """A supported format byte with the wrong digest width → 400.

    `01` (ECFv1-SHA-384, supported) followed by a 32-byte digest (the
    SHA-256 width, not SHA-384's 48) is structurally invalid:
    `validate_hash` rejects it on digest-length mismatch. Fail-closed —
    the format byte being *recognized* is not enough; the width must
    match too."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        bad_width = "01" + ("aa" * 32)  # SHA-384 byte, SHA-256-width digest
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{bad_width}",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 400


@pytest.mark.asyncio
async def test_pin_unsupported_format_byte_returns_400():
    """A genuinely unsupported format byte → 400 fail-closed.

    `0x7f` is not in `SUPPORTED_CONTENT_HASH_FORMATS`. Even with a
    plausible digest length, `validate_hash` rejects it as
    `unsupported_content_hash_format` — a future fetcher gets a
    meaningful error instead of a silent miss against an unknown
    algorithm. Format-relativity widens the *accepted* set to the
    supported formats; it does not open the door to arbitrary bytes."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        bogus = "7f" + ("aa" * 32)  # unsupported format code 0x7f
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{bogus}",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 400


@pytest.mark.asyncio
async def test_pin_2_out_of_scope_held_returns_404():
    peer = _make_peer()
    namespace = "system/content/public"
    payload = b"private bytes - not bound under public namespace"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    # Deliberately do NOT bind under namespace — out-of-scope.

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{_url_hex(h)}",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_pin_3_not_held_returns_404_identical_body():
    """No presence oracle (§1.3 T4): not-held and out-of-scope share a body."""
    peer = _make_peer()
    namespace = "system/content/public"
    # Establish an out-of-scope hash baseline.
    held_payload = b"held but private"
    held_entity = _make_blob_entity(held_payload)
    held_h = peer.content_store.put(held_entity)
    # Build a never-held hash (random bytes, plausible-looking 33-byte hash).
    not_held_h = b"\x00" + (b"\xff" * 32)

    def probe_both(host, port):
        out_of_scope = _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{_url_hex(held_h)}",
        )
        not_held = _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{_url_hex(not_held_h)}",
        )
        return out_of_scope, not_held

    (oos_code, _, oos_body), (nh_code, _, nh_body) = await _run_against_isolated_poll(
        peer, namespace, probe_both
    )
    assert oos_code == 404
    assert nh_code == 404
    # Identical body — the route doesn't leak "we hold this".
    assert oos_body == nh_body


@pytest.mark.asyncio
async def test_pin_4_content_type_application_cbor_on_hit():
    """Pin #4 post-ruling: Content-Type is application/cbor (body is
    entity ECF), NOT application/octet-stream. Octet-stream is the
    Route-2 (rendering) shape that v1 doesn't ship."""
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"x"))
    _bind_in_namespace(peer, namespace, h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{_url_hex(h)}",
        )

    code, headers, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200
    ct = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
    assert ct == "application/cbor"


@pytest.mark.asyncio
async def test_pin_5_cache_control_and_etag_on_hit():
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"cacheable"))
    _bind_in_namespace(peer, namespace, h)
    url_hex = _url_hex(h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{url_hex}",
        )

    code, headers, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200
    h_lower = {k.lower(): v for k, v in headers.items()}
    cache = h_lower.get("cache-control", "")
    assert "immutable" in cache
    assert "max-age" in cache
    etag = h_lower.get("etag", "")
    # ETag mirrors the URL form — 32-byte digest hex per cohort canonical.
    assert etag == f'"{url_hex}"'


@pytest.mark.asyncio
async def test_pin_6_malformed_hex_returns_400():
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/content/not-hex-bytes-zzz",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 400


@pytest.mark.asyncio
async def test_pin_7_tree_get_returns_hash_pointer():
    """GET `/{peer_id}/{path}.bin` returns the **bound hash** as a
    bare 2-key `system/hash` pointer per Amendment 6, NOT the
    dereferenced wire entity.

    Per §6.5.3.1 (post-Amendment-6): body =
    `ECF({type: "system/hash", data: H})` where `H` is the bound
    33-byte hash. The consumer reads `H` and second-hops
    `CONTENT_GET /content/{hex33(H)}` for the entity bytes.

    One-hop (dereferenced entity) would defeat the V7 §1.7 content-
    store dedup invariant — every tree path bound to `H` would
    materialize a separate copy of the same bytes on a static CDN.

    Content-Type: application/cbor; ETag = bound hash (changes on
    rebind = correct mutable cache key); NO `immutable`."""
    peer = _make_peer()
    namespace = "system/content/public"
    entity = Entity(type="system/content/chunk", data={"bytes": b"tree-bytes"})
    h = peer.content_store.put(entity)
    _bind_in_namespace(peer, namespace, h)
    inner_path = f"{namespace}/published/thing"
    tree_path = f"/{peer.peer_id}/{inner_path}"
    peer.entity_tree.set(tree_path, h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{inner_path}.bin",
        )

    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, f"got {code}: {body!r}"
    h_lower = {k.lower(): v for k, v in headers.items()}
    assert h_lower.get("content-type") == "application/cbor"
    # Body is the 2-key bare hash pointer — NOT the wire entity.
    decoded = ecf_decode(body)
    assert decoded == {"type": "system/hash", "data": h}, (
        f"expected 2-key system/hash pointer, got {decoded!r}"
    )
    assert "content_hash" not in decoded, "2-key bare — no self-hash"
    # ETag = the bound hash, not the pointer's own self-hash.
    assert h_lower.get("etag") == f'"{h.hex()}"'


@pytest.mark.asyncio
async def test_pin_tree_get_no_immutable_cache_control():
    """Amendment 4 §6.5.3.1 (Rust's catch at the merge doorstep):
    tree bindings are MUTABLE by design — the URI→hash map changes as
    state evolves. `Cache-Control: immutable` on tree-get is a
    stale-serving bug. Content-only.

    Pin: tree-get response MUST NOT advertise immutable caching; the
    ETag stays so `If-None-Match` revalidation still works (the
    correct mutable-resource pattern)."""
    peer = _make_peer()
    namespace = "system/content/public"
    entity = Entity(type="custom/mutable-binding", data={"v": 1})
    h = peer.content_store.put(entity)
    _bind_in_namespace(peer, namespace, h)
    inner_path = f"{namespace}/mutable/thing"
    tree_path = f"/{peer.peer_id}/{inner_path}"
    peer.entity_tree.set(tree_path, h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{inner_path}.bin",
        )

    code, headers, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200
    h_lower = {k.lower(): v for k, v in headers.items()}
    cache = h_lower.get("cache-control", "")
    assert "immutable" not in cache.lower(), (
        f"tree-get must not claim immutable caching (Amendment 4 §6.5.3.1); "
        f"got Cache-Control: {cache!r}"
    )
    # ETag stays — that's the mutable-resource validation primitive.
    assert h_lower.get("etag") == f'"{h.hex()}"'


@pytest.mark.asyncio
async def test_pin_7b_tree_get_out_of_scope_returns_404():
    """Tree-get path that's OUTSIDE the cap's resource scope → 404
    identical to not-held (T4 presence oracle)."""
    peer = _make_peer()
    namespace = "system/content/public"
    entity = Entity(type="system/content/chunk", data={"bytes": b"x"})
    h = peer.content_store.put(entity)
    # Bound at a tree path outside the cap's `{namespace}/*` scope.
    tree_path = f"/{peer.peer_id}/private/thing"
    peer.entity_tree.set(tree_path, h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/private/thing.bin",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_pin_8_post_to_content_returns_405_allow_get():
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"x"))
    _bind_in_namespace(peer, namespace, h)

    def probe(host, port):
        return _do_request(
            method="POST", host=host, port=port,
            path=f"/content/{_url_hex(h)}", data=b"",
        )

    code, headers, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 405
    allow = {k.lower(): v for k, v in headers.items()}.get("allow", "")
    assert "GET" in allow


@pytest.mark.asyncio
async def test_pin_9_posture_2_prefix_serves_same_matrix():
    """Posture 2: poll routes mounted on the live listener under /poll/."""
    peer = _make_peer()
    namespace = "system/content/public"
    payload = b"posture-2-bytes"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    _bind_in_namespace(peer, namespace, h)
    url_hex = _url_hex(h)
    expected_body = ecf_encode({"type": entity.type, "data": entity.data})

    scope = CapTokenScope.from_namespace(peer.entity_tree, namespace, peer.peer_id)
    server = await peer.start_http(
        "127.0.0.1", 0,
        url_path="/entity",
        poll_prefix="/poll",
        scope_predicate=scope,
    )
    try:
        bound = server.bound_socket()
        host, port = bound  # type: ignore[misc]

        def probe(p: str, method: str = "GET", data: bytes | None = None):
            return _do_request(method=method, host=host, port=port, path=p, data=data)

        loop = asyncio.get_running_loop()
        # In-scope hit at the prefixed path — body is entity ECF, re-hashes to H.
        code, _, body = await loop.run_in_executor(
            None, lambda: probe(f"/poll/content/{url_hex}")
        )
        assert code == 200
        assert body == expected_body
        assert _rehash(body) == h
        # Live POST path still works (Chunk D pin survives).
        code, headers, _ = await loop.run_in_executor(None, lambda: probe("/entity"))
        # GET to live → 405 Allow:POST (the live route's own gate).
        assert code == 405
        assert "POST" in {k.lower(): v for k, v in headers.items()}.get("allow", "")
        # POST to poll content → 405 Allow:GET.
        code, headers, _ = await loop.run_in_executor(
            None, lambda: probe(f"/poll/content/{url_hex}", method="POST", data=b"")
        )
        assert code == 405
        assert "GET" in {k.lower(): v for k, v in headers.items()}.get("allow", "")
        # Unknown short first segment under prefix → 404 (demux step 5:
        # not a reserved literal, not a parseable peer-id).
        code, _, _ = await loop.run_in_executor(
            None, lambda: probe("/poll/nope")
        )
        assert code == 404
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_pin_10_whole_store_serves_any_held_hash():
    """Debug posture: WholeStoreScope returns True for any held hash,
    bypassing namespace bindings entirely. Body still re-hashes to H."""
    peer = _make_peer()
    payload = b"debug-whole-store"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    # Deliberately no namespace binding — whole-store scope ignores it.

    scope = WholeStoreScope()
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix=""
    )
    try:
        bound = server.bound_socket()
        host, port = bound  # type: ignore[misc]

        def probe():
            return _do_request(
                method="GET", host=host, port=port,
                path=f"/content/{_url_hex(h)}",
            )

        code, _, body = await asyncio.get_running_loop().run_in_executor(None, probe)
        assert code == 200
        assert body == ecf_encode({"type": entity.type, "data": entity.data})
        assert _rehash(body) == h
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_http_poll_profile_self_published():
    """E.2: starting a poll listener self-publishes the http-poll profile."""
    peer = _make_peer()
    scope = CapTokenScope.from_namespace(peer.entity_tree, "system/content/public", peer.peer_id)
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix=""
    )
    try:
        uri = peer.entity_tree.normalize_uri(
            f"system/peer/transport/{peer.peer_id_hex}/primary-http-poll"
        )
        h = peer.entity_tree.get(uri)
        assert h is not None, "http-poll profile should self-publish on start"
        ent = peer.content_store.get(h)
        assert ent is not None
        assert ent.type == "system/peer/transport/http-poll"
        assert ent.data["transport_type"] == "http-poll"
        assert "CONTENT_GET" in ent.data["supported_ops"]
        assert "TREE_GET" in ent.data["supported_ops"]
        assert ent.data["nonce_required"] is False
        # cap_flow "egress" — GET-class fetch/serving face, within the ratified
        # §6.5.1 enum (RULING-CYCLE-CLOSEOUT-0.3 R3; pre-ruling "none" retired).
        assert ent.data["cap_flow"] == "egress"
        # freshness "live" — live serving mode, also in the §6.5.1 enum.
        assert ent.data["freshness"] == "live"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_poll_only_listener_does_not_publish_live_profile():
    """Posture 1: start_http_poll() publishes ONLY the poll profile, not http."""
    peer = _make_peer()
    scope = CapTokenScope.from_namespace(peer.entity_tree, "system/content/public", peer.peer_id)
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix=""
    )
    try:
        live_uri = peer.entity_tree.normalize_uri(
            f"system/peer/transport/{peer.peer_id_hex}/primary-http"
        )
        assert peer.entity_tree.get(live_uri) is None, (
            "isolated poll listener must not publish live http profile"
        )
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_scope_predicate_required_when_poll_enabled():
    """Construct-time guard: poll_prefix without scope_predicate is a TypeError-class bug."""
    from entity_core.peer.http_server import HttpServer

    peer = _make_peer()
    with pytest.raises(ValueError, match="scope_predicate is required"):
        HttpServer(peer, poll_prefix="/poll", scope_predicate=None)


# =============================================================================
# Amendment 5 (NETWORK §6.5 v1.4) pin tests — named-object addressing,
# literal-or-peer-id-parse demux, cap-token serve_scope, status table.
# Mirrors the cross-impl matrix to be added in workbench-go validate-peer.
# =============================================================================


def _bind_inside_namespace_path(peer, namespace: str, sub: str, h: bytes) -> str:
    """Bind /{peer}/{namespace}/{sub} -> h (cap-token publish pattern)."""
    inner = f"{namespace}/{sub}"
    path = f"/{peer.peer_id}/{inner}"
    peer.entity_tree.set(path, h)
    return inner


@pytest.mark.asyncio
async def test_a5_pin_bijection_entity_foo_bin():
    """Bijection cell: entity `foo` addressed as `foo.bin` → 200
    `system/hash` pointer (Amendment 6 — two-hop)."""
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"foo-bytes"))
    inner = _bind_inside_namespace_path(peer, namespace, "foo", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{inner}.bin",
        )

    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded == {"type": "system/hash", "data": h}


@pytest.mark.asyncio
async def test_a5_pin_bijection_entity_foo_dot_bin_doubles_suffix():
    """Bijection: a path whose name ends in `.bin` ⇒ `foo.bin.bin`.

    The server strips ONE recognized suffix; the remaining inner path
    is `foo.bin` (a legitimate publisher key). No collision, no
    publish-time check (§6.5.3.1 Amendment 5). Body is the hash
    pointer for the entity bound at the inner path (Amendment 6).
    """
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"foo.bin-bytes"))
    inner = _bind_inside_namespace_path(peer, namespace, "foo.bin", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{inner}.bin",   # foo.bin.bin
        )

    code, _, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded == {"type": "system/hash", "data": h}


@pytest.mark.asyncio
async def test_a5_pin_bijection_listing_foo_list():
    """Listing form `foo.list` → 200 system/tree/listing in ECF."""
    peer = _make_peer()
    namespace = "system/content/public"
    a = peer.content_store.put(_make_blob_entity(b"a"))
    b = peer.content_store.put(_make_blob_entity(b"b"))
    _bind_inside_namespace_path(peer, namespace, "dir/a", a)
    _bind_inside_namespace_path(peer, namespace, "dir/b", b)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{namespace}/dir.list",
        )

    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded["type"] == "system/tree/listing"
    assert set(decoded["data"]["entries"].keys()) == {"a", "b"}
    assert decoded["data"]["count"] == 2
    assert decoded["data"]["offset"] == 0
    # Mutable view — no `immutable`.
    h_lower = {k.lower(): v for k, v in headers.items()}
    assert "immutable" not in h_lower.get("cache-control", "").lower()


@pytest.mark.asyncio
async def test_a5_pin_bijection_listing_empty_in_scope_returns_200():
    """Empty in-scope listing ⇒ 200 + entries={} + count=0 (§6.5.6 Q2)."""
    peer = _make_peer()
    namespace = "system/content/public"
    # Establish the namespace as in-scope by binding *something* under it
    # so the prefix exists (otherwise the prefix itself is not in scope
    # by the namespace cap — and that case is the next test below).
    h = peer.content_store.put(_make_blob_entity(b"x"))
    _bind_inside_namespace_path(peer, namespace, "anchor/sentinel", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{namespace}/empty.list",
        )

    code, _, body = await _run_against_isolated_poll(peer, namespace, probe)
    # Per Q2 / §6.5.6: an in-scope prefix with no children returns 200
    # + entries={} count=0. The cap permits `system/content/public/*`
    # so `empty` is in scope (its children would be too if there were
    # any).
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded["data"]["entries"] == {}
    assert decoded["data"]["count"] == 0


@pytest.mark.asyncio
async def test_a5_pin_bare_path_no_suffix_returns_404():
    """`/{peer_id}/path` with no recognized suffix ⇒ 404 (§6.5.3.1)."""
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"x"))
    inner = _bind_inside_namespace_path(peer, namespace, "thing", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{inner}",       # no suffix
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_peer_root_listing_via_dot_list():
    """`/{peer_id}.list` ⇒ peer-root listing."""
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"x"))
    _bind_inside_namespace_path(peer, namespace, "foo", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}.list",
        )

    code, _, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded["type"] == "system/tree/listing"
    # The root listing scope-gates by the cap; under `system/content/*`
    # scope the visible top-level child is `system`.
    assert "system" in decoded["data"]["entries"]


@pytest.mark.asyncio
async def test_a5_pin_peer_id_dot_bin_returns_404():
    """`{peer_id}{leaf_suffix}` ⇒ 404 (root is a directory; V7 §1.4)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}.bin",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_peers_list_root_view():
    """`/peers.list` ⇒ all-peers (universal-tree-root) listing.

    For single-peer Python serving this includes just our own peer-id
    (when in scope per the cap).
    """
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"x"))
    _bind_inside_namespace_path(peer, namespace, "anchor", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/peers.list",
        )

    code, _, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded["type"] == "system/tree/listing"
    assert peer.peer_id in decoded["data"]["entries"]
    assert decoded["data"]["entries"][peer.peer_id]["has_children"] is True


@pytest.mark.asyncio
async def test_a5_pin_bare_peers_returns_404():
    """Bare `/peers` (no listing suffix) ⇒ 404 (§6.5.6 Amendment 5)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/peers",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_peers_dot_bin_returns_404():
    """`/peers.bin` ⇒ 404 (the reserved literal is meaningful only with
    the listing suffix; leaf-suffix on `peers` is not a route)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/peers.bin",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_short_unknown_first_segment_returns_404():
    """Demux step 5: short non-reserved first segment ⇒ 404
    (length-disjoint from peer-id; not a recognized literal)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/abc/def.bin",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_manifest_route_not_published_returns_404():
    """`/manifest` with no published manifest ⇒ 404 (§6.5.3.1)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/manifest",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_manifest_with_trailing_slash_returns_404():
    """`/manifest/` ⇒ 404 (manifest is terminal — no suffix, no slash)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/manifest/",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_manifest_with_subpath_returns_404():
    """`/manifest/foo` ⇒ 404 (singular/terminal)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/manifest/foo",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_manifest_with_published_root_returns_200():
    """When a `system/peer/{peer}/published-root` is bound, MANIFEST_GET
    returns its wire entity. Not `immutable`-cached (manifest is
    mutable; revocation lives here)."""
    peer = _make_peer()
    namespace = "system/content/public"
    manifest_entity = Entity(
        type="system/peer/published-root",
        data={"signer": peer.peer_id, "epoch": 1},
    )
    h = peer.content_store.put(manifest_entity)
    peer.entity_tree.set(f"/{peer.peer_id}/system/peer/published-root", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path="/manifest",
        )

    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    h_lower = {k.lower(): v for k, v in headers.items()}
    assert h_lower["content-type"] == "application/cbor"
    assert "immutable" not in h_lower.get("cache-control", "").lower()
    decoded = ecf_decode(body)
    assert decoded["type"] == "system/peer/published-root"
    assert decoded["content_hash"] == h


@pytest.mark.asyncio
async def test_a5_pin_encoded_slash_returns_400():
    """`%2F` inside a path component ⇒ 400 (§6.5.3.1)."""
    peer = _make_peer()
    namespace = "system/content/public"

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/foo%2Fbar.bin",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 400


@pytest.mark.asyncio
async def test_a5_pin_over_long_url_returns_414():
    """URL exceeding the operator-configured cap ⇒ 414 (§6.5.3.1 MAY)."""
    peer = _make_peer()
    namespace = "system/content/public"
    # Build a URL longer than the default 8 KB cap.
    huge = "x" * (9 * 1024)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{huge}.bin",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 414


@pytest.mark.asyncio
async def test_a5_pin_listing_filtered_count_under_cap():
    """`count` is the in-scope filtered total — never the raw subtree
    total (TREE §1176 + §6.5.6 scope-gating). Out-of-scope siblings are
    NOT counted."""
    peer = _make_peer()
    namespace = "system/content/public"
    in_scope = peer.content_store.put(_make_blob_entity(b"in"))
    out_scope = peer.content_store.put(_make_blob_entity(b"out"))
    # Two children of `dir`: one in-scope, one out-of-scope.
    _bind_inside_namespace_path(peer, namespace, "dir/visible", in_scope)
    peer.entity_tree.set(f"/{peer.peer_id}/dir/hidden", out_scope)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{namespace}/dir.list",
        )

    code, _, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded["data"]["count"] == 1, "filtered count, not raw subtree total"
    assert list(decoded["data"]["entries"].keys()) == ["visible"]


@pytest.mark.asyncio
async def test_a5_pin_cap_token_content_face_via_namespace_binding():
    """Content-face: H is in scope iff some in-scope tree path binds to it.

    The cap permits `{ns}/*`; bind a hash via `{ns}/{hex}` and content
    fetches succeed. Bind only outside the namespace and content fetches
    404."""
    peer = _make_peer()
    namespace = "system/content/public"
    payload = b"content-face"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    # Bind under the namespace — in scope.
    _bind_in_namespace(peer, namespace, h)
    url_hex = _url_hex(h)

    def probe_in_scope(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{url_hex}",
        )

    code, _, body = await _run_against_isolated_poll(peer, namespace, probe_in_scope)
    assert code == 200, body
    assert _rehash(body) == h

    # Second hash, bound only outside the namespace — out of scope.
    h2 = peer.content_store.put(_make_blob_entity(b"hidden"))
    peer.entity_tree.set(f"/{peer.peer_id}/elsewhere/x", h2)

    def probe_out_scope(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{_url_hex(h2)}",
        )

    code, _, _ = await _run_against_isolated_poll(peer, namespace, probe_out_scope)
    assert code == 404


@pytest.mark.asyncio
async def test_a5_pin_paths_for_hash_reverse_lookup():
    """`EntityTree.paths_for_hash(h)` returns every URI bound to `h`."""
    peer = _make_peer()
    h = peer.content_store.put(_make_blob_entity(b"x"))
    a = f"/{peer.peer_id}/a/x"
    b = f"/{peer.peer_id}/b/x"
    peer.entity_tree.set(a, h)
    peer.entity_tree.set(b, h)
    found = peer.entity_tree.paths_for_hash(h)
    assert set(found) >= {a, b}, found

    # Unrelated hash returns empty.
    other = bytes([0x00]) + b"\x00" * 32
    assert peer.entity_tree.paths_for_hash(other) == []


@pytest.mark.asyncio
async def test_a5_pin_from_namespace_cap_covers_foreign_peers():
    """`CapTokenScope.from_namespace(ns)` synthesizes a peer-wildcard
    cap (`/*/ns/*`) so that under `--serve-namespace ns` the operator's
    intent is "serve the `ns` namespace, regardless of which peer wrote
    to it" — the universal-tree-root semantic. Without this, a
    multi-peer mirror would be forced into whole-store (security-
    defective per CONTENT §6.4.1).

    Verified end-to-end: TREE_GET on a foreign-peer-rooted path under
    the cap's namespace returns 200; an out-of-namespace foreign-peer
    path returns 404 identical to not-held.
    """
    peer = _make_peer()
    other = "1HtVqLgPqkScVxjVN8VFGFiH7T2P3aSDwJxQ8DGEoooo1z"
    namespace = "system/content/public"
    payload = b"foreign-peer-in-ns"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    foreign_in_scope = f"/{other}/{namespace}/thing"
    peer.entity_tree.set(foreign_in_scope, h)
    foreign_out_of_scope = f"/{other}/private/thing"
    peer.entity_tree.set(foreign_out_of_scope, h)

    def probe_in_scope(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{other}/{namespace}/thing.bin",
        )

    def probe_out_scope(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{other}/private/thing.bin",
        )

    code_in, _, body_in = await _run_against_isolated_poll(peer, namespace, probe_in_scope)
    assert code_in == 200, body_in
    # Amendment 6: the leaf body is the hash pointer, not the entity.
    decoded = ecf_decode(body_in)
    assert decoded == {"type": "system/hash", "data": h}

    code_out, _, _ = await _run_against_isolated_poll(peer, namespace, probe_out_scope)
    assert code_out == 404


@pytest.mark.asyncio
async def test_a5_pin_multi_peer_publish_surfaces_in_peers_list():
    """Cohort pin (mirror of validate-peer's `multi_peer_publish_via_tree_put`
    + `peers_list_surfaces_other_peer`): if any binding lands under a
    foreign peer-id (e.g. cross-peer publish via tree:put with an
    absolute /<other>/... target), `peers.list` MUST include that
    foreign peer-id. Hardcoding "local peer only" violates the
    universal-tree-root semantic (Amendment 5 §6.5.6).

    Uses WholeStoreScope so the test exercises only the enumeration
    contract — scope-bound caps are a separate orthogonal concern.
    """
    peer = _make_peer()
    other = "1HtVqLgPqkScVxjVN8VFGFiH7T2P3aSDwJxQ8DGEoooo1z"
    assert other != peer.peer_id

    # Direct storage-layer cross-peer publish (the wire-level cap-check
    # is orthogonal; here we're testing the listing enumeration).
    payload = b"amendment-5 cross-peer publish"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    peer.entity_tree.set(f"/{other}/system/validate/cross-peer/probe", h)

    # Also seed a binding under the local peer so peers.list has both.
    h2 = peer.content_store.put(_make_blob_entity(b"local-seed"))
    peer.entity_tree.set(f"/{peer.peer_id}/system/content/public/anchor", h2)

    scope = WholeStoreScope()
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix="",
    )
    try:
        bound = server.bound_socket()
        host, port = bound  # type: ignore[misc]
        loop = asyncio.get_running_loop()
        code, _, body = await loop.run_in_executor(
            None,
            lambda: _do_request(
                method="GET", host=host, port=port, path="/peers.list",
            ),
        )
        assert code == 200, body
        decoded = ecf_decode(body)
        assert decoded["type"] == "system/tree/listing"
        entries = decoded["data"]["entries"]
        # Both peer-ids MUST appear — local AND foreign.
        assert peer.peer_id in entries, (
            f"peers.list missing LOCAL peer-id; entries={list(entries)}"
        )
        assert other in entries, (
            f"peers.list missing FOREIGN peer-id after cross-peer publish "
            f"— universal-tree-root semantic broken; entries={list(entries)}"
        )
        # Both have has_children=True (descendant bindings exist).
        assert entries[peer.peer_id]["has_children"] is True
        assert entries[other]["has_children"] is True
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a5_pin_peers_list_skips_non_peer_id_top_level():
    """Defensive: non-peer-id top-level segments (V7 §1.4 forbids them
    but a stray binding shouldn't leak into peers.list)."""
    peer = _make_peer()
    h = peer.content_store.put(_make_blob_entity(b"x"))
    # Stray top-level: NOT a peer-id (too short, wrong alphabet).
    peer.entity_tree.set("/not-a-peer-id/foo", h)
    # Plus a legitimate local binding so the listing isn't empty.
    peer.entity_tree.set(f"/{peer.peer_id}/system/content/public/anchor", h)

    scope = WholeStoreScope()
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix="",
    )
    try:
        bound = server.bound_socket()
        host, port = bound  # type: ignore[misc]
        loop = asyncio.get_running_loop()
        code, _, body = await loop.run_in_executor(
            None,
            lambda: _do_request(
                method="GET", host=host, port=port, path="/peers.list",
            ),
        )
        assert code == 200, body
        decoded = ecf_decode(body)
        entries = decoded["data"]["entries"]
        assert peer.peer_id in entries
        assert "not-a-peer-id" not in entries, (
            "non-peer-id top-level segment MUST NOT appear in peers.list"
        )
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a5_pin_foreign_peer_root_listing_renders():
    """Follow-the-link from peers.list to /{foreign_peer}.list — under
    a wide enough scope, the foreign-peer root listing renders the
    foreign subtree (universal-tree semantic continued)."""
    peer = _make_peer()
    other = "1HtVqLgPqkScVxjVN8VFGFiH7T2P3aSDwJxQ8DGEoooo1z"
    h = peer.content_store.put(_make_blob_entity(b"y"))
    peer.entity_tree.set(f"/{other}/foo", h)

    scope = WholeStoreScope()
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix="",
    )
    try:
        bound = server.bound_socket()
        host, port = bound  # type: ignore[misc]
        loop = asyncio.get_running_loop()
        code, _, body = await loop.run_in_executor(
            None,
            lambda: _do_request(
                method="GET", host=host, port=port,
                path=f"/{other}.list",
            ),
        )
        assert code == 200, body
        decoded = ecf_decode(body)
        assert "foo" in decoded["data"]["entries"]
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_a6_pin_tree_entity_body_is_hash_pointer():
    """Amendment 6 cohort pin (mirrors validate-peer `body_is_hash_pointer`).

    `TREE_GET` leaf body MUST be the 2-key bare ECF
    `{type: "system/hash", data: <33-byte H>}` — NOT the dereferenced
    wire entity. Two-hop: this route resolves path→hash; consumer
    second-hops `CONTENT_GET` for the bytes. One-hop is non-conformant
    (V7 §1.7 dedup invariant violated).
    """
    peer = _make_peer()
    namespace = "system/content/public"
    h = peer.content_store.put(_make_blob_entity(b"a6-payload"))
    inner = _bind_inside_namespace_path(peer, namespace, "leaf", h)

    def probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/{peer.peer_id}/{inner}.bin",
        )

    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    # 2-key map exactly — no content_hash, no extra keys.
    assert set(decoded.keys()) == {"type", "data"}, (
        f"leaf body MUST be 2-key bare, got keys={list(decoded.keys())}"
    )
    assert decoded["type"] == "system/hash"
    assert isinstance(decoded["data"], (bytes, bytearray))
    assert len(decoded["data"]) == 33, (
        f"data MUST be a 33-byte hash (algo byte + SHA-256), got {len(decoded['data'])}"
    )
    assert decoded["data"][0] == 0x00, (
        f"algo byte must be 0x00 (ECFv1-SHA256), got 0x{decoded['data'][0]:02x}"
    )


@pytest.mark.asyncio
async def test_a6_pin_pointer_data_matches_bound_hash():
    """Amendment 6 cohort pin (mirrors `pointer_data_matches_bound_hash`).

    The `data` field of the hash pointer MUST equal the hash currently
    bound at the tree path. ETag MUST match. Rebinding the path
    produces a new pointer with the new bound hash + a new ETag.
    """
    peer = _make_peer()
    namespace = "system/content/public"
    h_first = peer.content_store.put(_make_blob_entity(b"first"))
    h_second = peer.content_store.put(_make_blob_entity(b"second"))
    inner = _bind_inside_namespace_path(peer, namespace, "leaf", h_first)
    leaf_url = f"/{peer.peer_id}/{inner}.bin"

    # First fetch — pointer's data = h_first.
    def probe(host, port):
        return _do_request(method="GET", host=host, port=port, path=leaf_url)

    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded["data"] == h_first
    assert {k.lower(): v for k, v in headers.items()}["etag"] == f'"{h_first.hex()}"'

    # Rebind, re-fetch — pointer's data = h_second, ETag follows.
    peer.entity_tree.set(f"/{peer.peer_id}/{inner}", h_second)
    code, headers, body = await _run_against_isolated_poll(peer, namespace, probe)
    assert code == 200, body
    decoded = ecf_decode(body)
    assert decoded["data"] == h_second
    assert {k.lower(): v for k, v in headers.items()}["etag"] == f'"{h_second.hex()}"'


@pytest.mark.asyncio
async def test_a6_pin_second_hop_dereferences_via_content_get():
    """Amendment 6 cohort pin (mirrors `second_hop_dereferences`).

    The full two-hop flow:
      1. `GET /{peer_id}/{path}.bin` → 200 system/hash pointer with
         `data` = the bound hash H.
      2. `GET /content/{hex33(H)}` → 200 bare entity ECF({type, data})
         where Mechanism A holds: 0x00 || SHA-256(body) == H.
    Confirms the two routes compose into the consumer's standard flow.
    """
    peer = _make_peer()
    namespace = "system/content/public"
    payload = b"a6 second-hop payload"
    entity = _make_blob_entity(payload)
    h = peer.content_store.put(entity)
    inner = _bind_inside_namespace_path(peer, namespace, "leaf", h)

    leaf_url = f"/{peer.peer_id}/{inner}.bin"
    content_url = f"/content/{h.hex()}"

    def hop1(host, port):
        return _do_request(method="GET", host=host, port=port, path=leaf_url)

    def hop2_factory(host, port):
        # Returned closure to be invoked after hop 1 decodes.
        def hop2():
            return _do_request(method="GET", host=host, port=port, path=content_url)
        return hop2

    # Hop 1: pointer.
    code1, _, body1 = await _run_against_isolated_poll(peer, namespace, hop1)
    assert code1 == 200, body1
    pointer = ecf_decode(body1)
    bound_h = pointer["data"]
    assert pointer == {"type": "system/hash", "data": h}

    # Hop 2: content-by-hash on the bound hash. Run inside a fresh
    # server so the content scope predicate fires on the in-scope hash.
    def hop2_probe(host, port):
        return _do_request(
            method="GET", host=host, port=port,
            path=f"/content/{bound_h.hex()}",
        )

    code2, _, body2 = await _run_against_isolated_poll(peer, namespace, hop2_probe)
    assert code2 == 200, body2
    # Mechanism A: 0x00 || SHA-256(body) == H.
    assert _rehash(body2) == bound_h, "pure-body rehash MUST equal H"
    # Body is the bare 2-key entity ECF({type, data}).
    second_hop = ecf_decode(body2)
    assert second_hop == {"type": entity.type, "data": entity.data}


@pytest.mark.asyncio
async def test_a5_pin_two_suffixes_must_differ():
    """Construct-time guard: `tree_leaf_suffix == tree_listing_suffix` is a config bug."""
    from entity_core.peer.http_server import HttpServer
    from entity_core.peer.serving import WholeStoreScope

    peer = _make_peer()
    with pytest.raises(ValueError, match="MUST differ"):
        HttpServer(
            peer,
            poll_prefix="/poll",
            scope_predicate=WholeStoreScope(),
            tree_leaf_suffix=".bin",
            tree_listing_suffix=".bin",
        )
