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
        predecessor: prior published-root content hash for chain audit.
        algorithm: active content_hash_format (v7.69 §4.5a); None → default.
    """
    data: dict[str, object] = {
        "peer_id": keypair.peer_id,
        "root_hash": root_hash,
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


def closure_scope_for_published_root(entity_tree: "Any", content_store: "Any") -> "Any":
    """Build a ``ClosureScope`` serving the current published-root's signed
    closure — the trie nodes + bound entities reachable from ``root_hash``,
    plus the published-root entity and its signature.

    This is the publisher-side half of the C2 signed-root walk: it makes a
    static http-poll mirror serve exactly the set a consumer needs to fetch
    the root, verify its signature, and walk the hash-chain from it.

    Raises :class:`PublishedRootError` if ``publish_root()`` hasn't run.
    """
    from entity_core.peer.serving import ClosureScope

    pr_hash = entity_tree.get("system/peer/published-root")
    if pr_hash is None:
        raise PublishedRootError(
            "no_published_root", "no published-root bound; call publish_root() first",
        )
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
        also_serve_hashes=[pr_hash, sig_hash],
        also_serve_paths=["system/peer/published-root", sig_path],
    )


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
      1. entity is a well-formed ``system/peer/published-root``.
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
    seq = data.get("seq")
    if not isinstance(peer_id, str):
        raise PublishedRootError("invalid_published_root", "peer_id missing or not a string")
    if not isinstance(root_hash, bytes):
        raise PublishedRootError("invalid_published_root", "root_hash missing or not bytes")
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
