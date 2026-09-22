"""`system/peer/published-root` — the signed tree-root anchor (Phase P / C1).

Per `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §4 (NORMATIVE-LOCKED)
and the cohort resolution-substrate landing handoff (C1).

The published-root is the **mutable-claim anchor** for static (http-poll)
serving: a signed pointer to the publisher's current tree root. A poller
that fetches a peer's tree over an untrusted intermediary MUST anchor its
`TREE_GET` walk to a `published-root` the publisher *signed* (§1.1 threat
model) — otherwise the host can fabricate a `path → hash` binding the
publisher never committed to. Everything reachable by walking the
hash-chain from `root_hash` is endorsed; nothing else is.

Two halves:
  - **Producer** (``build_published_root`` / ``Peer.publish_root``): the
    publisher mints + signs the entity and binds it at
    ``system/peer/published-root``, with its signature at the invariant
    pointer ``system/signature/{hex(pr_hash)}`` so a cold http-poll fetch
    can verify it via target-matching (V7 §5.2 / §989).
  - **Consumer** (``verify_published_root``): the poller verifies the
    signature against the publisher's peer-id public key BEFORE trusting
    `root_hash`, and rejects rollback via `seq` monotonicity.

`peer_id` representation note (cohort-convergence): §4 of the proposal
spells `peer_id` as ``<hash>``, but that notation predates the V7 §1.5
peer-id pin. This impl carries `peer_id` as the **Base58 peer-id string**
(``system/peer-id``), consistent with (a) the NETWORK errata bdfb545 that
moved transport-profile `peer_id` from `system/hash` → Base58, and (b)
EXTENSION-REGISTRY F-PY-REG-5 (`target_peer_id` is Base58, not a hash).
The Base58 form is also what makes signature-verification-against-pubkey
work by local derivation (``derive_peer_from_peer_id``) for canonical
identity-form peer-ids. Flagged to the cohort so Go's P1 authoring
converges on the same representation; see the Phase-P feedback doc.
"""

from __future__ import annotations

from typing import Any

from entity_core.crypto.identity import (
    Keypair,
    UnsupportedKeyTypeError,
    derive_peer_from_peer_id,
)
from entity_core.crypto.signing import verify_for_key_type
from entity_core.protocol.auth import create_signature_entity
from entity_core.protocol.entity import Entity

PUBLISHED_ROOT_TYPE = "system/peer/published-root"

#: ``EmitContext.handler_pattern`` stamped on the republisher's own two
#: writes (the published-root binding and its signature invariant pointer).
#: The republisher hook checks for this tag and ignores the resulting
#: events — those writes land in the same tree it is watching, so without
#: the tag every publish would trigger the next one forever. Same value and
#: same mechanism as Go's ``publishedroot.PublisherHandlerPattern``, so the
#: two impls' debug logs line up when a cross-impl run is being read.
PUBLISHER_HANDLER_PATTERN = "publishedroot/publisher"

#: The prefix this peer's published trie keys are relative to
#: (EXTENSION-TREE §3.3a, ruled 2026-08-08). ``"/"`` designates the
#: **universal tree**: we key the trie by ``event.uri`` /
#: ``entity_tree.all_bindings()``, both of which are the full normalized
#: ``/{peer_id}/system/...`` path, so the §3.3 trim is a **no-op** and the
#: relative_key IS the absolute path. That is a legal §3.3 shape, not a
#: missing trim — Go declares ``"system/"`` and Rust ``"/{peer_id}/"``, and
#: all three key correctly for their own declared prefix.
#:
#: This value is load-bearing and not cosmetic: a consumer reconstructs
#: ``prefix + relative_key`` and resolves it on our tree-face, so declaring a
#: prefix that does not describe the actual keys yields a path we do not
#: have. It is single-sourced here because the declaration and the keying
#: must move together — the failure mode is a root that verifies and then
#: walks to nothing.
PUBLISHED_ROOT_PREFIX = "/"


class PublishedRootError(Exception):
    """Raised when a published-root fails verification.

    ``code`` is a short machine string for the surfacing layer; the
    transport/consumer maps it to a transport-level rejection (never
    trust raw host bytes — fail closed).
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def published_root_signature_path(pr_hash: bytes) -> str:
    """Invariant-pointer tree path for a published-root's signature.

    V7 §3.5 / §989: ``system/signature/{hex(pr_hash)}`` — the same
    convention the grant/attestation signatures use. The publisher binds
    the signature here so a cold http-poll consumer can fetch it by the
    root entity's own content hash (target-matching, no round-trip to the
    issuer). `pr_hash` is the published-root entity's content_hash bytes
    (lowercase hex, format-code prefix included).
    """
    return f"system/signature/{pr_hash.hex()}"


def build_published_root(
    keypair: Keypair,
    root_hash: bytes,
    seq: int,
    published_at: int,
    *,
    prefix: str = PUBLISHED_ROOT_PREFIX,
    predecessor: bytes | None = None,
    algorithm: int | None = None,
) -> tuple[Entity, Entity]:
    """Mint a signed ``system/peer/published-root`` (§4).

    Returns ``(published_root_entity, signature_entity)``. The caller binds
    the root at ``system/peer/published-root`` and the signature at
    ``published_root_signature_path(root.content_hash)``.

    Args:
        keypair: the publisher's keypair (its peer-id is the `peer_id`).
        root_hash: the current tree root the publisher commits to (bytes).
        seq: monotonic freshness counter (reject `seq < cached` on read).
        published_at: ms-since-epoch timestamp.
        prefix: §3.3a — the prefix the trie keys are relative to. Defaults to
            :data:`PUBLISHED_ROOT_PREFIX`, which is what this peer's keying
            actually is; a caller overriding it is asserting a different
            keying and MUST key that way.
        predecessor: prior published-root content hash for chain audit.
        algorithm: active content_hash_format (v7.69 §4.5a); None → default.

    Raises:
        PublishedRootError: if ``prefix`` does not end with ``/`` (§3.3a MUST).
    """
    if not prefix.endswith("/"):
        raise PublishedRootError(
            "invalid_published_root",
            f"prefix {prefix!r} does not end with '/' (§3.3a MUST)",
        )
    data: dict[str, object] = {
        "peer_id": keypair.peer_id,
        "root_hash": root_hash,
        "prefix": prefix,
        "seq": seq,
        "published_at": published_at,
    }
    if predecessor is not None:
        data["predecessor"] = predecessor

    pr_entity = Entity(type=PUBLISHED_ROOT_TYPE, data=data, hash_algorithm=algorithm)
    signature_entity = create_signature_entity(
        keypair, pr_entity.compute_hash(), algorithm=algorithm,
    )
    return pr_entity, signature_entity


class PublishedRootRepublisher:
    """Internal emit hook: re-mint the signed root on every root change.

    `PROPOSAL-PEER-MANIFEST` §4 requires a fresh signed
    ``system/peer/published-root`` **on every tree-root change**, with `seq`
    advancing and `predecessor` chaining. Python minted exactly once, at
    startup, so `seq` stayed 0 and the manifest never changed after boot.

    Two guards keep it from chasing its own tail:

    * **Self-write tag.** ``publish_root()`` stamps
      :data:`PUBLISHER_HANDLER_PATTERN` on its own two emits; events
      carrying it are ignored. They land in the same tree this hook
      watches, so untagged they would re-fire it indefinitely.
    * **Coalescing.** A burst of writes (a handler binding several
      entities, a cascade) should produce **one** republish, not one per
      binding. Under a running event loop the hook only marks work pending
      and ``call_soon`` runs the publish once the current callback chain
      unwinds; the trie rebuild is O(bindings), so per-write publishing
      would put it on the critical path of every write. With no loop
      running (unit tests, synchronous embedding) it publishes inline,
      which keeps the same observable contract.

    ``on_change_sync`` never raises: it runs inline inside ``emit()``, and
    a publish failure must not fail the operator's write. Failures are
    logged.
    """

    def __init__(self, peer: Any) -> None:
        self._peer = peer
        self._publishing = False
        self._scheduled = False
        self._dirty = False
        self._root = self._seed_root()

    def _seed_root(self) -> bytes | None:
        """Take the trie root the last publish committed to, if any."""
        pr_hash = self._peer.entity_tree.get("system/peer/published-root")
        if pr_hash is None:
            return None
        pr = self._peer.content_store.get(pr_hash)
        if pr is None or pr.type != PUBLISHED_ROOT_TYPE:
            return None
        root = pr.data.get("root_hash")
        return bytes(root) if isinstance(root, bytes) else None

    def on_change_sync(self, event: Any) -> int | None:
        ctx = getattr(event, "context", None)
        if ctx is not None and getattr(ctx, "handler_pattern", None) == (
            PUBLISHER_HANDLER_PATTERN
        ):
            return None
        if self._publishing:
            return None
        self._apply(event)
        self._schedule()
        return None

    def _apply(self, event: Any) -> None:
        """Fold one binding change into the running trie root.

        EXTENSION-TREE v3.8 §3.4.2: an incremental ``trie_put`` /
        ``trie_remove`` sequence is hash-equivalent to ``build_trie`` over
        the equivalent binding set (pinned in
        ``tests/unit/test_trie_incremental.py``), so the root published
        here is the same root a full rebuild would produce — at O(log N)
        per change instead of O(N log N).

        The republisher's own two bindings never reach this method (the
        self-write tag filters them upstream), so the committed set is the
        tree minus the published-root and its signature. That is the set
        the closure already assumed: both are published *after* the trie is
        built, which is why ``ClosureScope`` carries them as
        ``also_serve_hashes`` rather than finding them inside the walk.
        """
        from entity_core.storage.emit import ChangeKind
        from entity_core.storage.trie import empty_trie, trie_put, trie_remove

        cs = self._peer.content_store
        if self._root is None:
            self._root = empty_trie(cs)
        try:
            if event.kind is ChangeKind.DELETED:
                self._root = trie_remove(self._root, event.uri, cs)
            elif event.hash is not None:
                self._root = trie_put(self._root, event.uri, event.hash, cs)
            else:
                return
        except Exception:  # pragma: no cover - defensive
            import logging

            logging.getLogger(__name__).exception(
                "incremental trie update failed for %s; falling back to a "
                "full rebuild on the next publish",
                getattr(event, "uri", "?"),
            )
            self._root = None
        self._dirty = True

    def _schedule(self) -> None:
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self.publish_now()
            return
        if self._scheduled:
            return
        self._scheduled = True
        loop.call_soon(self.publish_now)

    def publish_now(self) -> None:
        """Run a pending republish immediately (also the ``call_soon`` target)."""
        import logging

        self._scheduled = False
        if self._publishing or not self._dirty:
            return
        self._publishing = True
        try:
            self._peer.publish_root(root_hash=self._root)
            self._dirty = False
        except Exception:  # pragma: no cover - defensive
            logging.getLogger(__name__).exception(
                "published-root republish failed",
            )
        finally:
            self._publishing = False


def _closure_scope_for_pr_hash(
    entity_tree: Any,
    content_store: Any,
    pr_hash: bytes,
    *,
    anchor_hashes: "Any" = (),
    anchor_paths: "Any" = (),
) -> Any:
    """Build a static ``ClosureScope`` over one specific published-root.

    ``anchor_hashes`` / ``anchor_paths`` carry the **superseded** roots'
    two anchor entities (the ``published-root`` and its signature) — see
    :class:`LivePublishedRootScope`. They widen only the anchor set, never
    the trie closure: a retired root's *content* stays unservable, which is
    what §6.5.6 Amendment 10 pins.
    """
    from entity_core.peer.serving import ClosureScope

    pr = content_store.get(pr_hash)
    if pr is None or pr.type != PUBLISHED_ROOT_TYPE:
        raise PublishedRootError("no_published_root", "published-root not in content store")
    root_hash = pr.data.get("root_hash")
    sig_path = published_root_signature_path(bytes(pr_hash))
    sig_hash = entity_tree.get(sig_path)
    return ClosureScope(
        entity_tree,
        content_store,
        root_hash,
        also_serve_hashes=[pr_hash, sig_hash, *anchor_hashes],
        also_serve_paths=[
            "system/peer/published-root",
            sig_path,
            *anchor_paths,
        ],
    )


class LivePublishedRootScope:
    """A ``ScopePredicate`` that tracks the **current** published-root.

    §6.5.6 Amendment 10 closure timing, ruled (a) recompute-on-root-change
    **MUST** (arch ``c78b3dc``): the served closure tracks
    ``published-root.root_hash`` *as it stands now*. An entity bound since
    the last publish becomes servable **at the republish** — so the scope
    cannot be a snapshot taken when the listener was built.

    ``ClosureScope`` walks its closure once at construction and caches it,
    which is right for a pinned root (``--serve-closure-root <hex>``) and
    wrong for ``@published``: it froze the served set at startup. Combined
    with a publisher that only minted once, every entity written after boot
    was permanently outside the served set — a publisher that could never
    publish anything.

    This wrapper re-derives the closure when — and only when — the
    published-root binding changes hash. Steady-state cost is one tree
    lookup per query; the trie walk happens once per republish.

    If the published-root binding disappears after construction, the last
    known closure is retained rather than failing open or throwing from a
    serving path: the old closure is a set the publisher genuinely signed,
    so serving it is conservative, whereas an exception mid-request would
    surface as a 500 on a route the spec pins at 200/404.

    **Superseded anchors are retained, and the verify cycle is why.** A cold
    consumer's handshake is two fetches: ``MANIFEST_GET`` hands it root *N*,
    then it fetches *N*'s signature by content hash and verifies before it
    walks anything (§1.1 — never trust raw host bytes). Recomputing the
    served set on a root change made that pair non-atomic: any write landing
    in the window republished to *N+1* and took *N*'s signature out of scope,
    so the consumer got a **404 on the signature for the root this peer had
    just handed it** and could not verify a root that was never invalid. The
    publisher's own self-tag comment already named the hazard ("each spin
    invalidates the served closure before any consumer's CONTENT_GET can
    complete"); the self-tag stopped the runaway spin and left the window.

    So the last :data:`_ANCHOR_RETENTION` roots keep their two anchor
    entities servable. This is not a relaxation of Amendment 10: the trie
    closure still tracks the current root alone, so a superseded root's
    *content* is as unservable as before — only the anchors a consumer needs
    to finish verifying a root it already holds survive. Serving them
    discloses nothing new (they are this peer's own signed anchors, reachable
    only by a hash the consumer was handed) and rollback stays closed on the
    consumer side, where `seq` monotonicity already lives.
    """

    #: How many superseded roots keep their anchors servable. Cost is two
    #: hashes per root; the bound exists so a long-lived publisher cannot
    #: accumulate without limit. Sized for a burst of republishes landing
    #: inside one consumer's fetch→verify window rather than for one.
    _ANCHOR_RETENTION = 64

    def __init__(self, entity_tree: Any, content_store: Any) -> None:
        self._entity_tree = entity_tree
        self._content_store = content_store
        pr_hash = entity_tree.get("system/peer/published-root")
        if pr_hash is None:
            raise PublishedRootError(
                "no_published_root",
                "no published-root bound; call publish_root() first",
            )
        self._pr_hash = bytes(pr_hash)
        #: Superseded roots, oldest first, as (pr_hash, sig_hash, sig_path).
        self._anchors: list[tuple[bytes, bytes | None, str]] = []
        self._inner = _closure_scope_for_pr_hash(
            entity_tree, content_store, self._pr_hash
        )

    def _retire(self, pr_hash: bytes) -> None:
        """Move a superseded root's anchors into the retention ring."""
        sig_path = published_root_signature_path(pr_hash)
        sig_hash = self._entity_tree.get(sig_path)
        self._anchors.append(
            (pr_hash, bytes(sig_hash) if sig_hash is not None else None, sig_path)
        )
        if len(self._anchors) > self._ANCHOR_RETENTION:
            del self._anchors[: -self._ANCHOR_RETENTION]

    def _current(self) -> Any:
        pr_hash = self._entity_tree.get("system/peer/published-root")
        if pr_hash is None:
            return self._inner
        pr_hash = bytes(pr_hash)
        if pr_hash != self._pr_hash:
            # Retire the outgoing root BEFORE rebuilding: its signature is
            # what an in-flight consumer is about to ask for.
            self._retire(self._pr_hash)
            hashes = [h for _pr, h, _p in self._anchors if h is not None]
            hashes += [pr for pr, _h, _p in self._anchors]
            paths = [p for _pr, _h, p in self._anchors]
            try:
                self._inner = _closure_scope_for_pr_hash(
                    self._entity_tree,
                    self._content_store,
                    pr_hash,
                    anchor_hashes=hashes,
                    anchor_paths=paths,
                )
            except PublishedRootError:
                self._anchors.pop()
                return self._inner
            self._pr_hash = pr_hash
        return self._inner

    def in_scope(self, h: bytes) -> bool:
        return self._current().in_scope(h)

    def in_scope_path(self, path: str) -> bool:
        return self._current().in_scope_path(path)

    def prefix_in_scope(self, prefix: str) -> bool:
        return self._current().prefix_in_scope(prefix)

    def describe(self) -> str:
        return f"closure:@published:{self._current().root_hash.hex()[:16]}"


def closure_scope_for_published_root(entity_tree: Any, content_store: Any) -> Any:
    """Serve the signed closure of the peer's **current** published-root.

    The publisher-side half of the C2 signed-root walk: it makes a static
    http-poll mirror serve exactly the set a consumer needs to fetch the
    root, verify its signature, and walk the hash-chain from it — and it
    follows the root as the publisher republishes (see
    :class:`LivePublishedRootScope`).

    Raises :class:`PublishedRootError` if ``publish_root()`` hasn't run.
    """
    return LivePublishedRootScope(entity_tree, content_store)


def verify_published_root(
    pr_entity: Entity,
    signature_entity: Entity | None,
    *,
    cached_seq: int | None = None,
) -> bytes:
    """Verify a published-root and return its trusted `root_hash`.

    Raises :class:`PublishedRootError` on any failure (fail closed — the
    consumer MUST NOT walk the tree from an unverified root, §1.1).

    Checks (in order):
      1. entity is a well-formed ``system/peer/published-root`` — including
         `prefix`, REQUIRED per §3.3a and MUST end with ``/``. A root without
         it is not merely under-described: the consumer holds `relative_key`s
         and no operand to reconstruct an absolute path with, so the
         hash-chain walk this verification exists to authorize cannot be
         performed. Fail closed rather than guess a prefix — guessing is how
         one impl's convention becomes everyone's default.
      2. publisher pubkey derivable from `peer_id` (canonical V7 §1.5 form).
      3. signature entity present, targets the root's content hash.
      4. signature verifies cryptographically against the publisher pubkey.
      5. `seq` monotonicity — reject `seq < cached_seq` (rollback defence).

    Args:
        pr_entity: the fetched published-root entity.
        signature_entity: the ``system/signature`` over it (target-matched).
        cached_seq: highest `seq` previously seen for this publisher, if any.
    """
    if pr_entity.type != PUBLISHED_ROOT_TYPE:
        raise PublishedRootError(
            "invalid_published_root",
            f"expected {PUBLISHED_ROOT_TYPE}, got {pr_entity.type}",
        )

    data = pr_entity.data
    peer_id = data.get("peer_id")
    root_hash = data.get("root_hash")
    prefix = data.get("prefix")
    seq = data.get("seq")
    if not isinstance(peer_id, str):
        raise PublishedRootError("invalid_published_root", "peer_id missing or not a string")
    if not isinstance(root_hash, bytes):
        raise PublishedRootError("invalid_published_root", "root_hash missing or not bytes")
    if not isinstance(prefix, str) or not prefix.endswith("/"):
        raise PublishedRootError(
            "invalid_published_root",
            "prefix missing, not a string, or does not end with '/' "
            "(§3.3a REQUIRED — without it the trie keys have no operand to "
            "reconstruct absolute paths from)",
        )
    if not isinstance(seq, int):
        raise PublishedRootError("invalid_published_root", "seq missing or not an int")

    derived = derive_peer_from_peer_id(peer_id)
    if derived is None:
        # SHA-256-form peer-ids need the pubkey out-of-band; v1 anchors on
        # canonical identity-form peer-ids only.
        raise PublishedRootError(
            "unresolvable_publisher",
            "peer_id is not canonical identity-form; cannot derive pubkey for verification",
        )
    public_key_bytes, key_type_byte = derived

    if signature_entity is None:
        raise PublishedRootError("missing_signature", "published-root signature not found")
    if signature_entity.type != "system/signature":
        raise PublishedRootError(
            "missing_signature",
            f"expected system/signature, got {signature_entity.type}",
        )
    sig_data = signature_entity.data
    sig_target = sig_data.get("target")
    sig_bytes = sig_data.get("signature")
    if sig_target != pr_entity.compute_hash():
        raise PublishedRootError(
            "signature_target_mismatch",
            "signature target does not match published-root content hash",
        )
    if not isinstance(sig_bytes, bytes):
        raise PublishedRootError("invalid_signature", "signature is not bytes")

    try:
        verified = verify_for_key_type(
            key_type_byte, public_key_bytes, sig_target, sig_bytes,
        )
    except UnsupportedKeyTypeError as exc:
        raise PublishedRootError("unsupported_key_type", str(exc))
    if not verified:
        raise PublishedRootError(
            "signature_verification_failed",
            "published-root signature did not verify against publisher pubkey",
        )

    # Rollback defence — a host replaying an older signed root must not
    # override a fresher one we've already seen (snapshot-manifest §3-RES.4).
    if cached_seq is not None and seq < cached_seq:
        raise PublishedRootError(
            "stale_published_root",
            f"published-root seq {seq} < cached seq {cached_seq} (rollback rejected)",
        )

    return root_hash
