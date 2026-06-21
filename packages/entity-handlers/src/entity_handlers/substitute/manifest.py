"""Snapshot-manifest verification + freshness — v1.1 only.

A `system/substitute/snapshot-manifest` carries a publisher's path-index
for an HTTP storage-substitute drop. Consumers MUST verify the
manifest's Ed25519 signature before trusting `path_index`
(STORAGE-SUBSTITUTE-HTTP §3-RES.1). Without a valid signature, bare-hash
content fetch still works (content-trust is self-sufficient) — but
`path_index` MUST NOT be used.

Freshness rule (§3-RES.4): `seq` is monotonic per `source_peer_id`.
First-seen accepted; equal seq accepted (re-affirmation); strict-less
rejected as `manifest_stale_seq`.

**v1.0 conformance gate (Ruling 5):** the v1.0 CDN corridor ships
bare-hash fetch only — the manifest-processing path lands all-at-once in
v1.1 across all three impls. The verify + freshness functions below
remain in-tree as authoring + verify utilities (used by publisher
tooling and by future v1.1 consumers); nothing on the v1.0 default
content fetch path invokes them. Do NOT auto-hook this into the chain
orchestrator without coordinating the v1.1 cutover with the other impls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from entity_core.crypto.signing import public_key_from_bytes, verify_signature
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import Hash, compute_ecf_hash, hash_equals


class ManifestVerifyError(Exception):
    """Raised when a manifest fails signature verification."""


class ManifestFreshness(Enum):
    """Per §3-RES.4: accept on first-seen / equal / strictly-greater seq."""

    FIRST_SEEN = "first_seen"
    SAME_SEQ = "same_seq"
    NEWER = "newer"
    STALE = "stale"


def verify_manifest_signature(
    manifest_entity: Entity | dict[str, Any],
    signature_entity: Entity | dict[str, Any],
    publisher_public_key_bytes: bytes,
) -> None:
    """Verify the snapshot-manifest's Ed25519 signature.

    Per §3-RES.1, the consumer:
      1. Computes manifest_hash = content_hash({type, data}) over the manifest entity.
      2. Verifies the signature entity targets that hash.
      3. Ed25519_verify(publisher_pubkey, manifest_hash, signature_bytes).

    Raises:
        ManifestVerifyError: any step fails. The chain rejects the manifest
            (with `manifest_signature_invalid`) but bare-hash content fetch
            via the same endpoint still works.
    """
    manifest_dict = (
        manifest_entity.to_dict() if isinstance(manifest_entity, Entity) else manifest_entity
    )
    sig_dict = (
        signature_entity.to_dict() if isinstance(signature_entity, Entity) else signature_entity
    )

    manifest_hash = compute_ecf_hash(
        {"type": manifest_dict["type"], "data": manifest_dict["data"]}
    )

    sig_data = sig_dict.get("data") or {}
    sig_target = sig_data.get("target")
    if not isinstance(sig_target, (bytes, bytearray)):
        raise ManifestVerifyError(
            "signature target missing or not bytes; expected system/hash"
        )
    if not hash_equals(bytes(sig_target), manifest_hash):
        raise ManifestVerifyError(
            "signature targets a different hash than the manifest"
        )

    sig_bytes = sig_data.get("signature")
    if not isinstance(sig_bytes, (bytes, bytearray)):
        raise ManifestVerifyError("signature bytes missing or not bytes")

    try:
        public_key = public_key_from_bytes(publisher_public_key_bytes)
    except Exception as exc:
        raise ManifestVerifyError(f"invalid publisher public key: {exc}") from exc

    if not verify_signature(public_key, manifest_hash, bytes(sig_bytes)):
        raise ManifestVerifyError("Ed25519 verification failed")


@dataclass
class _SeqCacheEntry:
    seq: int


def accept_manifest(
    manifest_data: dict[str, Any],
    seq_cache: dict[bytes, int],
) -> ManifestFreshness:
    """Classify a manifest against `seq_cache` and update if accepted (§3-RES.4).

    `seq_cache` maps `source_peer_id` (bytes) to the highest `seq` seen.
    On STALE, returns the verdict without touching the cache (the
    manifest is rejected for path_index use; bare-hash fetch is still
    permitted).
    """
    source_peer_id = manifest_data["source_peer_id"]
    if isinstance(source_peer_id, (bytes, bytearray)):
        key = bytes(source_peer_id)
    else:
        key = bytes(source_peer_id)
    new_seq = int(manifest_data["seq"])

    cached = seq_cache.get(key)
    if cached is None:
        seq_cache[key] = new_seq
        return ManifestFreshness.FIRST_SEEN
    if new_seq > cached:
        seq_cache[key] = new_seq
        return ManifestFreshness.NEWER
    if new_seq == cached:
        # Re-affirmation; no cache change, still accepted.
        return ManifestFreshness.SAME_SEQ
    return ManifestFreshness.STALE
