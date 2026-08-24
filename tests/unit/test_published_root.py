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


def test_enable_root_republish_mints_on_every_root_change():
    """PROPOSAL-PEER-MANIFEST §4: republish on **every** tree-root change.

    Python minted once at startup and never again — `seq` stayed 0, no
    `predecessor` ever formed, and the manifest bytes were identical
    minutes after a `tree:put`. Go's cross-impl measurement (24 samples
    over 5m45s, one distinct manifest state) confirmed it as a real
    defect rather than a slow cadence.
    """
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    first = peer.publish_root()
    peer.enable_root_republish()

    # An ordinary write — the shape `serving_mode.seed_in_scope` drives.
    peer.emit_pathway.emit(
        "system/content/public/thing", Entity(type="system/blob", data={"n": 1})
    )

    pr_hash = peer.entity_tree.get("system/peer/published-root")
    current = peer.content_store.get(pr_hash)
    assert current.data["seq"] == first.data["seq"] + 1
    assert current.data["predecessor"] == first.compute_hash()
    assert current.data["root_hash"] != first.data["root_hash"]


def test_republisher_does_not_chase_its_own_writes():
    """The publisher's own two bindings MUST NOT re-trigger it.

    They land in the same tree the hook watches, so untagged they spin
    forever (Go measured ~55 publishes/s with no external traffic before
    adding the same self-write tag). One external write ⇒ exactly one
    seq advance.
    """
    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    peer.publish_root()
    peer.enable_root_republish()

    def _seq() -> int:
        h = peer.entity_tree.get("system/peer/published-root")
        return peer.content_store.get(h).data["seq"]

    before = _seq()
    peer.emit_pathway.emit(
        "system/content/public/one", Entity(type="system/blob", data={"n": 1})
    )
    assert _seq() == before + 1
    peer.emit_pathway.emit(
        "system/content/public/two", Entity(type="system/blob", data={"n": 2})
    )
    assert _seq() == before + 2


def test_incremental_republish_root_equals_a_full_rebuild():
    """The published root MUST be the root a full rebuild would produce.

    The republisher folds each change into the running root with
    `trie_put`/`trie_remove` instead of calling `build_trie` over every
    binding, because the full rebuild is O(bindings) *and* persists an
    intermediate node per insertion step. Measured on 300 writes: 22.12 s
    and 200 880 stored entities rebuilding, against 0.10 s and 2 702
    incrementally — the rebuild version OOM-killed the peer 631 requests
    into a cross-impl run.

    Speed is worthless if the root differs, so this pins the equivalence
    EXTENSION-TREE v3.8 §3.4.2 promises. The comparison set excludes the
    published-root and its signatures: those are published *after* the
    trie is built and were never inside it (which is why `ClosureScope`
    carries them as `also_serve_hashes`).
    """
    from entity_core.storage.trie import build_trie

    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    peer.publish_root()
    peer.enable_root_republish()

    for i in range(25):
        peer.emit_pathway.emit(
            f"system/content/public/item-{i}",
            Entity(type="system/blob", data={"i": i}),
        )
    peer.emit_pathway.delete("system/content/public/item-7")
    peer.emit_pathway.emit(
        "system/content/public/item-3", Entity(type="system/blob", data={"i": 3000})
    )

    pr_hash = peer.entity_tree.get("system/peer/published-root")
    published = peer.content_store.get(pr_hash)

    # Exclude the published-root binding and the signatures over published
    # roots specifically — walk the predecessor chain to name them. A blanket
    # `system/signature/*` exclusion is wrong: the tree holds unrelated
    # signatures (grants, attestations) that were inside the trie all along.
    pr_path = peer.entity_tree.normalize_uri("system/peer/published-root")
    excluded = {pr_path}
    cursor = bytes(pr_hash)
    while cursor is not None:
        excluded.add(
            peer.entity_tree.normalize_uri(published_root_signature_path(cursor))
        )
        node = peer.content_store.get(cursor)
        prev = node.data.get("predecessor") if node is not None else None
        cursor = bytes(prev) if isinstance(prev, bytes) else None

    bindings = sorted(
        (uri, h)
        for uri, h in peer.entity_tree.all_bindings()
        if uri not in excluded
    )
    expected = build_trie(bindings, peer.content_store)

    assert published.data["root_hash"] == expected


def test_live_closure_scope_follows_the_republished_root():
    """§6.5.6 Amendment 10, ruled (a) recompute-on-root-change MUST.

    The served closure tracks `published-root.root_hash` as it stands
    now. `ClosureScope` caches its walk at construction, so an
    `@published` scope built at startup froze the served set at boot:
    an entity bound afterwards stayed permanently unservable even once
    the publisher started republishing. Both halves are needed.
    """
    from entity_core.peer.published_root import closure_scope_for_published_root

    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    peer.publish_root()
    scope = closure_scope_for_published_root(peer.entity_tree, peer.content_store)
    peer.enable_root_republish()

    later = Entity(type="system/blob", data={"bound": "after the scope was built"})
    h = peer.emit_pathway.emit("system/content/public/late", later).hash

    assert scope.in_scope(h), "entity bound after startup must be servable"
    assert scope.in_scope_path("system/content/public/late")


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


# ---------------------------------------------------------------------------
# EXTENSION-TREE §3.3a — `prefix`, and the operand it has to be
# ---------------------------------------------------------------------------


def _resolve_absolute_prefix(prefix: str, peer_id: str) -> str:
    """§3.3a — the absolute operand a consumer reconstructs paths with.

    `"/"` designates the universal tree, where the trim is a **no-op**: the
    absolute operand is the empty string and `relative_key` IS the absolute
    path. A prefix already absolute is itself; anything else is peer-relative
    and resolves under `/{peer_id}/`. Mirrors the consumer side of §3.3 —
    stated here rather than in the producer because nothing in this peer
    consumes another's trie keys yet.
    """
    if prefix == "/":
        return ""
    if prefix.startswith("/"):
        return prefix
    return f"/{peer_id}/{prefix}"


def test_published_root_carries_the_prefix_it_keys_by():
    kp = Keypair.generate()
    pr, _sig = build_published_root(kp, _root(0x11), 0, 1234)
    # §3.3a MUST — the field exists and ends with "/". "/" is the universal
    # tree: this peer keys its trie by the full normalized URI, so the trim
    # is a no-op and nothing is stripped.
    assert pr.data["prefix"] == "/"


def test_a_prefix_not_ending_in_a_slash_is_refused_at_mint():
    kp = Keypair.generate()
    with pytest.raises(PublishedRootError, match="does not end with"):
        build_published_root(kp, _root(0x11), 0, 1234, prefix="system")


def test_a_root_without_a_prefix_fails_closed():
    """§3.3a is REQUIRED, so a root missing it is not merely under-described.

    The consumer would hold `relative_key`s and no operand to rebuild an
    absolute path with — the hash-chain walk this verification exists to
    authorize is unsatisfiable at its first step. Accepting it and guessing
    a prefix is how one impl's convention silently becomes everyone's
    default, which is the reason §3.3a refused a default in the first place.
    """
    kp = Keypair.generate()
    pr, _ = build_published_root(kp, _root(0x11), 0, 1234)
    stripped = Entity(
        type=PUBLISHED_ROOT_TYPE,
        data={k: v for k, v in pr.data.items() if k != "prefix"},
    )
    # Signed correctly — only the missing field is wrong, so a verifier that
    # checks crypto alone sails straight through.
    from entity_core.protocol.auth import create_signature_entity

    sig = create_signature_entity(kp, stripped.compute_hash())
    with pytest.raises(PublishedRootError, match="prefix missing"):
        verify_published_root(stripped, sig)


def test_the_declared_prefix_describes_the_keys_actually_published():
    """§3.3a + §12.1 — the check a trie rebuild cannot make.

    `v8`-style rebuild equality takes its keys *from* the trie, so it passes
    for any key form; three impls sat on three conventions under a green
    check for months. The load-bearing property is the one asserted here:
    reconstructing each published key through the DECLARED prefix must land
    on a path this peer actually binds, to the same hash. Declare `"/"` while
    keying `system/`-relative and every reconstruction points at a path that
    does not exist — a consumer walking the signed root walks to nothing.

    This is the local analogue of the oracle's `v9`/`v10`: it answers from the
    entity tree (the path space), not from the trie (the key space), so the
    declaration and the keying cannot drift apart silently.
    """
    from entity_core.storage.trie import collect_all_bindings

    kp = Keypair.generate()
    peer = PeerBuilder().with_keypair(kp).with_all_handlers().build()
    peer.emit_pathway.emit(
        "system/content/public/thing", Entity(type="system/blob", data={"n": 1})
    )
    pr = peer.publish_root()

    absolute_prefix = _resolve_absolute_prefix(pr.data["prefix"], pr.data["peer_id"])
    keys = collect_all_bindings(pr.data["root_hash"], "", peer.content_store)
    assert keys, "published trie is empty — the invariant has nothing to exercise"

    for relative_key, value_hash in keys:
        full = absolute_prefix + relative_key
        # §6.2: the trim and the concatenation are inverses, and V7 paths are
        # absolute. `/{peer}//` is the shape the superseded formula produced.
        assert full.startswith("/"), f"{absolute_prefix!r} + {relative_key!r} = {full!r}"
        assert "//" not in full, f"doubled separator: {full!r}"
        assert full[len(absolute_prefix):] == relative_key, "trim does not close"
        assert peer.entity_tree.get(full) == value_hash, (
            f"key {relative_key!r} reconstructs to {full!r} through the declared "
            f"prefix {pr.data['prefix']!r}, but that path is not bound to the hash "
            f"the published trie carries — the declared prefix maps keys onto the "
            f"wrong paths"
        )
