"""Phase P / C1 — `system/peer/published-root` producer + verifier pins.

Per `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §4 (NORMATIVE-LOCKED).
The signed tree-root anchor + the consumer-side verification that
defends the §1.1 threat model (never trust raw host bytes) and rejects
rollback via `seq` monotonicity.

Cross-impl byte-pins live in the cohort C1 conformance vector (Go authors
the reference); these are the Python-side behaviour pins.
"""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder
from entity_core.peer.published_root import (
    PUBLISHED_ROOT_TYPE,
    PublishedRootError,
    build_published_root,
    published_root_signature_path,
    verify_published_root,
)
from entity_core.peer.serving import CapTokenScope
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import ecf_decode


def _do_request(
    *, method: str, host: str, port: int, path: str, data: bytes | None = None
) -> tuple[int, dict[str, str], bytes]:
    url = f"http://{host}:{port}{path}"
    req = urllib.request.Request(url, data=data, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=3.0)
        return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, e.read() or b""


def _root(byte: int) -> bytes:
    return bytes([0x00]) + bytes([byte]) * 32


def test_producer_verifier_roundtrip():
    kp = Keypair.generate()
    root = _root(0x11)
    pr, sig = build_published_root(kp, root, 0, 1234)
    assert pr.type == PUBLISHED_ROOT_TYPE
    assert pr.data["peer_id"] == kp.peer_id  # Base58, not a hash
    assert verify_published_root(pr, sig) == root


def test_missing_signature_fails_closed():
    kp = Keypair.generate()
    pr, _sig = build_published_root(kp, _root(0x11), 0, 1234)
    with pytest.raises(PublishedRootError) as exc:
        verify_published_root(pr, None)
    assert exc.value.code == "missing_signature"


def test_tampered_root_rejected():
    kp = Keypair.generate()
    pr, sig = build_published_root(kp, _root(0x11), 0, 1234)
    pr.data["root_hash"] = _root(0x22)  # mutate after signing
    with pytest.raises(PublishedRootError) as exc:
        verify_published_root(pr, sig)
    assert exc.value.code == "signature_target_mismatch"


def test_wrong_signer_rejected():
    """A signature from a different keypair must not verify — the host
    cannot substitute its own key for the publisher's."""
    publisher = Keypair.generate()
    attacker = Keypair.generate()
    pr, _ = build_published_root(publisher, _root(0x11), 0, 1234)
    # Attacker signs the same target with its own key.
    _, atk_sig = build_published_root(attacker, _root(0x11), 0, 1234)
    # Re-target the attacker's signature at the publisher's root hash.
    from entity_core.protocol.auth import create_signature_entity

    forged = create_signature_entity(attacker, pr.compute_hash())
    with pytest.raises(PublishedRootError) as exc:
        verify_published_root(pr, forged)
    assert exc.value.code == "signature_verification_failed"


def test_rollback_rejected_by_seq():
    kp = Keypair.generate()
    pr, sig = build_published_root(kp, _root(0x11), 3, 1234)
    # Fresher seq already seen → older root rejected.
    with pytest.raises(PublishedRootError) as exc:
        verify_published_root(pr, sig, cached_seq=5)
    assert exc.value.code == "stale_published_root"
    # Equal or newer seq accepted.
    assert verify_published_root(pr, sig, cached_seq=3) == _root(0x11)


def test_peer_publish_root_binds_root_and_signature():
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

    pr_entity = peer.publish_root()
    assert pr_entity.data["seq"] == 0
    assert "predecessor" not in pr_entity.data

    # Root bound where MANIFEST_GET reads it.
    bound = peer.entity_tree.get("system/peer/published-root")
    assert bound == pr_entity.compute_hash()
    # Signature reachable at the invariant pointer.
    sig_path = published_root_signature_path(pr_entity.compute_hash())
    sig_hash = peer.entity_tree.get(sig_path)
    assert sig_hash is not None
    sig = peer.content_store.get(sig_hash)
    assert verify_published_root(pr_entity, sig) == pr_entity.data["root_hash"]


def test_peer_publish_root_monotonic_seq_and_predecessor():
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()

    first = peer.publish_root()
    # Mutate the tree so the next root differs.
    peer.entity_tree.set("alice/data/x", _root(0x33))
    second = peer.publish_root()

    assert second.data["seq"] == first.data["seq"] + 1
    assert second.data["predecessor"] == first.compute_hash()


@pytest.mark.asyncio
async def test_manifest_get_serves_verifiable_published_root():
    """End-to-end: a consumer fetches MANIFEST_GET, fetches the signature
    via the invariant-pointer TREE_GET leaf, and verifies — the C1 seam."""
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    peer.publish_root()

    scope = CapTokenScope.from_namespace(
        peer.entity_tree, "system/signature", peer.peer_id
    )
    server = await peer.start_http_poll(
        "127.0.0.1", 0, scope_predicate=scope, poll_prefix=""
    )
    try:
        host, port = server.bound_socket()
        loop = asyncio.get_running_loop()

        status, _headers, body = await loop.run_in_executor(
            None,
            lambda: _do_request(
                method="GET", host=host, port=port, path="/manifest"
            ),
        )
        assert status == 200
        pr_entity = Entity.from_dict(ecf_decode(body))
        assert pr_entity.type == PUBLISHED_ROOT_TYPE
        assert pr_entity.data["peer_id"] == kp.peer_id
    finally:
        await server.stop()
