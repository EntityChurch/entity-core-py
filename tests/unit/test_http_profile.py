"""Chunk D — `system/peer/transport/http` live profile unit tests.

Per EXTENSION-NETWORK §6.5.2c (v1.4 Amendment 2). The profile mirrors
TCP's shape with a `{url: "https://..." | "http://..."}` endpoint (D4
shared live endpoint). POST EXECUTE / EXECUTE-RESPONSE is the wire
mechanism; this file covers the profile entity + resolver wiring only.
The real-wire round-trip is tested in
`tests/integration/test_http_live_transport.py`.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.remote import RemoteConnectionPool
from entity_core.protocol.auth import create_identity_entity


def _hex(kp: Keypair) -> str:
    return create_identity_entity(kp).compute_hash().hex()


class TestRegisterRemoteHttp:
    def _make_peer(self):
        kp = Keypair.generate()
        return PeerBuilder().with_keypair(kp).with_all_handlers().build()

    def test_writes_http_profile_entity_at_profile_id_path(self):
        peer = self._make_peer()
        remote_kp = Keypair.generate()
        peer.register_remote_http(
            remote_kp.peer_id, "https://api.example.com/entity",
            public_key=remote_kp.public_key_bytes(),
        )
        path = f"system/peer/transport/{_hex(remote_kp)}/primary-http"
        full_uri = peer.entity_tree.normalize_uri(path)
        h = peer.entity_tree.get(full_uri)
        assert h is not None
        ent = peer.content_store.get(h)
        assert ent.type == "system/peer/transport/http"

    def test_profile_carries_all_required_fields(self):
        peer = self._make_peer()
        remote_kp = Keypair.generate()
        peer.register_remote_http(
            remote_kp.peer_id, "https://api.example.com/entity",
            public_key=remote_kp.public_key_bytes(),
        )
        path = f"system/peer/transport/{_hex(remote_kp)}/primary-http"
        ent = peer.content_store.get(
            peer.entity_tree.get(peer.entity_tree.normalize_uri(path))
        )
        d = ent.data
        assert d["peer_id"] == remote_kp.peer_id
        assert d["transport_type"] == "http"
        assert d["endpoint"] == {"url": "https://api.example.com/entity"}
        assert d["supported_ops"] == ["EXECUTE"]
        assert d["freshness"] == "live"
        assert d["nonce_required"] is True
        assert d["cap_flow"] == "both"
        assert isinstance(d["advertised_at"], int)

    def test_rejects_non_http_scheme(self):
        peer = self._make_peer()
        remote_kp = Keypair.generate()
        with pytest.raises(ValueError, match="http:// or https://"):
            peer.register_remote_http(
                remote_kp.peer_id, "tcp://1.2.3.4:5678",
                public_key=remote_kp.public_key_bytes(),
            )
        with pytest.raises(ValueError, match="http:// or https://"):
            peer.register_remote_http(
                remote_kp.peer_id, "ftp://example.com",
                public_key=remote_kp.public_key_bytes(),
            )


class TestProfileResolver:
    """`_list_profile_candidates` covers both tcp + http in one pass.
    Selection order per §6.5.1a D1: `primary` first, then lex."""

    def _make_pool(self):
        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
        return peer, RemoteConnectionPool(kp, peer.content_store, peer.entity_tree)

    def test_http_only_peer_yields_http_candidate(self):
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        peer.register_remote_http(
            remote_kp.peer_id, "https://api.example.com/entity",
            public_key=remote_kp.public_key_bytes(),
        )
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        assert cands == [
            ("primary-http", "http", "https://api.example.com/entity")
        ]

    def test_dual_transport_peer_returns_both_d1_ordered(self):
        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        peer.register_remote(
            remote_kp.peer_id, "10.0.0.1:9000",
            public_key=remote_kp.public_key_bytes(),
        )  # tcp/primary
        peer.register_remote_http(
            remote_kp.peer_id, "https://api.example.com/entity",
            public_key=remote_kp.public_key_bytes(),
        )  # http/primary-http
        cands = pool._list_profile_candidates(remote_kp.peer_id)
        # primary (tcp) sorts before primary-http (lex after 'primary').
        assert [(p, t) for p, t, _ in cands] == [
            ("primary", "tcp"),
            ("primary-http", "http"),
        ]

    def test_d5_transport_type_match_enforced_for_http(self):
        """D5 — entity-type-suffix vs `transport_type` mismatch fail-closed."""
        from entity_core.protocol.entity import Entity
        from entity_core.storage.emit import EmitContext

        peer, pool = self._make_pool()
        remote_kp = Keypair.generate()
        bad = Entity(
            type="system/peer/transport/http",
            data={
                "peer_id": remote_kp.peer_id,
                "transport_type": "tcp",  # mismatch
                "endpoint": {"url": "https://api.example.com/entity"},
                "supported_ops": ["EXECUTE"],
                "freshness": "live",
                "nonce_required": True,
                "cap_flow": "both",
                "advertised_at": 1_000_000,
            },
        )
        peer.emit_pathway.emit(
            f"system/peer/transport/{_hex(remote_kp)}/primary-http",
            bad,
            EmitContext.bootstrap(),
        )
        with pytest.raises(ConnectionError, match="D5: MUST match suffix"):
            pool._list_profile_candidates(remote_kp.peer_id)


class TestHttpServerSelfPublication:
    """§6.5.1a D1: `Peer.start_http()` SHOULD self-publish own profile."""

    def test_start_http_writes_own_http_profile(self):
        import asyncio

        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

        async def run():
            server = await peer.start_http("127.0.0.1", 0)
            try:
                self_path = f"system/peer/transport/{peer.peer_id_hex}/primary-http"
                full_uri = peer.entity_tree.normalize_uri(self_path)
                h = peer.entity_tree.get(full_uri)
                assert h is not None
                ent = peer.content_store.get(h)
                assert ent.type == "system/peer/transport/http"
                assert ent.data["transport_type"] == "http"
                # URL was derived from bind (no base_url given).
                assert ent.data["endpoint"]["url"].startswith("http://127.0.0.1:")
            finally:
                await server.stop()

        asyncio.run(run())

    def test_start_http_with_base_url_advertises_public_url(self):
        import asyncio

        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

        async def run():
            server = await peer.start_http(
                "127.0.0.1", 0, base_url="https://public.example.com/entity"
            )
            try:
                self_path = f"system/peer/transport/{peer.peer_id_hex}/primary-http"
                ent = peer.content_store.get(
                    peer.entity_tree.get(peer.entity_tree.normalize_uri(self_path))
                )
                assert ent.data["endpoint"]["url"] == "https://public.example.com/entity"
            finally:
                await server.stop()

        asyncio.run(run())

    def test_start_http_coexists_with_start_tcp(self):
        """A peer MAY publish both tcp + http profiles (D1 multi-transport)."""
        import asyncio

        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

        async def run():
            await peer.start("127.0.0.1", 0)
            server = await peer.start_http("127.0.0.1", 0)
            try:
                tcp_path = f"system/peer/transport/{peer.peer_id_hex}/primary"
                http_path = f"system/peer/transport/{peer.peer_id_hex}/primary-http"
                assert peer.entity_tree.get(peer.entity_tree.normalize_uri(tcp_path)) is not None
                assert peer.entity_tree.get(peer.entity_tree.normalize_uri(http_path)) is not None
            finally:
                await server.stop()
                await peer.stop()

        asyncio.run(run())


class TestHttpRequestRejection:
    """Server-side acceptance rules per §5.2 / §5.3."""

    def test_get_returns_405(self):
        import asyncio
        import urllib.request

        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

        async def run():
            server = await peer.start_http("127.0.0.1", 0)
            try:
                bind = server.bound_socket()
                assert bind is not None
                host, port = bind
                url = f"http://{host}:{port}/entity"

                def do_get():
                    req = urllib.request.Request(url, method="GET")
                    try:
                        urllib.request.urlopen(req, timeout=3.0)
                        return None
                    except urllib.error.HTTPError as e:
                        return e.code

                code = await asyncio.get_running_loop().run_in_executor(
                    None, do_get
                )
                assert code == 405, f"expected HTTP 405 Method Not Allowed, got {code}"
            finally:
                await server.stop()

        asyncio.run(run())

    def test_invalid_envelope_returns_400(self):
        import asyncio
        import urllib.request

        kp = Keypair.generate()
        peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

        async def run():
            server = await peer.start_http("127.0.0.1", 0)
            try:
                bind = server.bound_socket()
                host, port = bind  # type: ignore[misc]
                url = f"http://{host}:{port}/entity"

                def do_post():
                    req = urllib.request.Request(
                        url, data=b"\x00not-cbor",
                        headers={"Content-Type": "application/cbor"},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(req, timeout=3.0)
                        return None
                    except urllib.error.HTTPError as e:
                        return e.code

                code = await asyncio.get_running_loop().run_in_executor(
                    None, do_post
                )
                assert code == 400, f"expected HTTP 400 Bad Request, got {code}"
            finally:
                await server.stop()

        asyncio.run(run())


class TestHttpUrlPathRouting:
    """Cohort §3.3 — exact-path routing. Unknown paths return 404 BEFORE
    method/body checks; matching path with non-POST returns 405. Verified
    cross-impl against Go + Rust."""

    def _make_peer(self):
        kp = Keypair.generate()
        return PeerBuilder().with_keypair(kp).with_all_handlers().build()

    def _probe(self, *, method: str, path: str, body: bytes | None = None) -> int:
        import asyncio
        import urllib.error
        import urllib.request

        peer = self._make_peer()

        async def run() -> int:
            server = await peer.start_http("127.0.0.1", 0)
            try:
                bind = server.bound_socket()
                assert bind is not None
                host, port = bind
                url = f"http://{host}:{port}{path}"

                def do_req() -> int | None:
                    req = urllib.request.Request(
                        url, data=body,
                        headers={"Content-Type": "application/cbor"} if body else {},
                        method=method,
                    )
                    try:
                        resp = urllib.request.urlopen(req, timeout=3.0)
                        return resp.status
                    except urllib.error.HTTPError as e:
                        return e.code

                code = await asyncio.get_running_loop().run_in_executor(None, do_req)
                assert code is not None
                return code
            finally:
                await server.stop()

        return asyncio.run(run())

    def test_post_unknown_path_returns_404(self):
        # Was 400 before the fix — Python decoded the body without
        # checking the path first.
        assert self._probe(method="POST", path="/nope", body=b"\x00bogus") == 404

    def test_get_unknown_path_returns_404(self):
        # Was 405 before the fix — Python applied method gating to all
        # paths instead of just the served path.
        assert self._probe(method="GET", path="/nope") == 404

    def test_get_served_path_returns_405(self):
        # Regression pin: matching path keeps 405 Method Not Allowed.
        assert self._probe(method="GET", path="/entity") == 405

    def test_post_unknown_path_skips_body_decode(self):
        # Even a syntactically-valid CBOR body to an unknown path
        # should 404 — path is checked before envelope decoding.
        import cbor2
        body = cbor2.dumps({"root": {}, "included": {}})
        assert self._probe(method="POST", path="/wrong", body=body) == 404

    def test_query_string_stripped_for_path_compare(self):
        # /entity?foo=bar still matches the served path.
        assert self._probe(method="GET", path="/entity?foo=bar") == 405

    def test_custom_url_path_routes_correctly(self):
        import asyncio
        import urllib.error
        import urllib.request

        peer = self._make_peer()

        async def run() -> tuple[int, int]:
            server = await peer.start_http(
                "127.0.0.1", 0, url_path="/custom"
            )
            try:
                bind = server.bound_socket()
                assert bind is not None
                host, port = bind

                def do_get(p: str) -> int | None:
                    req = urllib.request.Request(
                        f"http://{host}:{port}{p}", method="GET",
                    )
                    try:
                        return urllib.request.urlopen(req, timeout=3.0).status
                    except urllib.error.HTTPError as e:
                        return e.code

                loop = asyncio.get_running_loop()
                wrong = await loop.run_in_executor(None, do_get, "/entity")
                right = await loop.run_in_executor(None, do_get, "/custom")
                return wrong, right
            finally:
                await server.stop()

        wrong, right = asyncio.run(run())
        # Default /entity is now an unknown path; /custom is the served one.
        assert wrong == 404
        assert right == 405
