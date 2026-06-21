"""Phase P / C2 — http-poll outbound connector (the dialer) end-to-end.

A consumer dials a publisher's http-poll mirror, fetches + verifies the
signed ``published-root`` (C1), walks the CHAMP trie from the verified
root, and fetches a bound entity — all hash/signature-verified. Plus the
hostile-host guards: tampered content rejected, unverifiable root rejected.

The publisher serves the signed-root closure via ``ClosureScope`` so the
unbound trie nodes are answerable (the §1.1 walk needs them).
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.http_poll_client import HttpPollClient, HttpPollError
from entity_core.peer.published_root import closure_scope_for_published_root
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext


def _make_publisher_with_content():
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    # Bind a couple of content entities into the peer's tree.
    e1 = Entity(type="system/content/chunk", data={"bytes": b"hello world"})
    e2 = Entity(type="system/content/chunk", data={"bytes": b"second blob"})
    peer.emit_pathway.emit("docs/readme", e1, EmitContext.bootstrap())
    peer.emit_pathway.emit("docs/notes", e2, EmitContext.bootstrap())
    # Publish a signed root over the current tree.
    peer.publish_root()
    return peer, kp, e1, e2


async def _serve(peer):
    scope = closure_scope_for_published_root(peer.entity_tree, peer.content_store)
    server = await peer.start_http_poll("127.0.0.1", 0, scope_predicate=scope, poll_prefix="")
    host, port = server.bound_socket()
    return server, f"http://{host}:{port}"


@pytest.mark.asyncio
async def test_outbound_fetch_verify_walk_and_get_entity():
    peer, kp, e1, e2 = _make_publisher_with_content()
    server, base = await _serve(peer)
    try:
        client = HttpPollClient(base)
        pr, bindings = await client.fetch()
        assert pr.data["peer_id"] == kp.peer_id

        # The endorsed bindings include our content paths (absolute URIs).
        readme_key = next(k for k in bindings if k.endswith("/docs/readme"))
        notes_key = next(k for k in bindings if k.endswith("/docs/notes"))

        got1 = await client.fetch_entity(readme_key, bindings)
        got2 = await client.fetch_entity(notes_key, bindings)
        assert got1.compute_hash() == e1.compute_hash()
        assert got2.compute_hash() == e2.compute_hash()
        assert got1.data["bytes"] == b"hello world"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_content_get_rehash_guard():
    """Mechanism A: a hash that the body doesn't rehash to is rejected."""
    peer, kp, e1, e2 = _make_publisher_with_content()
    server, base = await _serve(peer)
    try:
        client = HttpPollClient(base)
        # Ask for a real entity's bytes under a WRONG hash → 404 (not served)
        # or mismatch; either way the client must not return bytes.
        wrong = bytes([0x00]) + b"\x99" * 32
        with pytest.raises(HttpPollError):
            await client.content_get(wrong)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_path_not_in_signed_root_is_rejected():
    peer, kp, e1, e2 = _make_publisher_with_content()
    server, base = await _serve(peer)
    try:
        client = HttpPollClient(base)
        _pr, bindings = await client.fetch()
        with pytest.raises(HttpPollError) as exc:
            await client.fetch_entity("/nobody/docs/ghost", bindings)
        assert exc.value.code == "not_endorsed"
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_unsigned_root_rejected():
    """A published-root whose signature can't be located fails closed — the
    consumer never trusts an unverified root."""
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    peer.publish_root()
    # Remove the signature pointer so the consumer can't verify the root.
    pr_hash = peer.entity_tree.get("system/peer/published-root")
    from entity_core.peer.published_root import published_root_signature_path

    peer.entity_tree.remove(published_root_signature_path(bytes(pr_hash)))
    scope = closure_scope_for_published_root(peer.entity_tree, peer.content_store)
    server = await peer.start_http_poll("127.0.0.1", 0, scope_predicate=scope, poll_prefix="")
    try:
        host, port = server.bound_socket()
        client = HttpPollClient(f"http://{host}:{port}")
        with pytest.raises(HttpPollError):
            await client.fetch_verified_root()
    finally:
        await server.stop()
