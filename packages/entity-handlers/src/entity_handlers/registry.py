"""EXTENSION-REGISTRY v1.0 — registry substrate + local-name backend.

A registry is a function ``name → (peer_id, transports, attestations,
trust_anchor, ttl)``. This handler implements the substrate (§2 resolver
contract, §3 binding entity, §4 resolver-config + meta-resolver, §5
capability model) and the v1 concrete backend (§6 local-name).

Handler pattern ``system/registry`` — also catches ``system/registry/local-name``
URIs by the dispatcher's prefix-subtree match, so one handler serves both
the substrate ops (``:resolve`` / ``:invalidate-cache``) and the local-name
backend ops (``:bind`` / ``:unbind`` / ``:list`` / ``:update-transports``).

Design notes (v1, per the cohort impl dispatch — implement what's written,
fix-in-place if the spec has a gap):

- **peer_id is Base58** (``target_peer_id``, ResolutionResult.peer_id) per
  V7 §1.5 / F-PY-REG-5 — never a content-hash.
- **Signatures are refless** (V7 §5.2 / §989): non-self-certifying /
  non-local-name bindings carry a ``system/signature`` found by
  target-matching (``data.target == binding.content_hash``) or at the
  invariant pointer ``system/signature/{hex(binding_hash)}``.
- **Two-layer local-name storage** (§6.3): body at the universal
  ``system/registry/binding/{hash}``; tree pointer at
  ``system/registry/binding/local-name/{name}`` (the live name→hash index
  ``:list`` reads); supersedes-chain is the audit log.
- **Backends beyond local-name** (peer-issued, etc.) ship in their own
  proposals. v1 resolves a non-local-name binding only from the **local
  binding store** (the bootstrap-with-precedes path, §7 — a preloaded
  signed binding read locally). The cold http-poll *fetch* of a remote
  registry's tree rides the Phase-P http-poll outbound connector (C2);
  it layers on this substrate without changing it.
- **Resolution caching**: v1 resolves live off the tree (no positive
  cache), so ``:invalidate-cache`` is a satisfied no-op and the
  ``MUST NOT use cached bindings past expiry`` (§11.4) holds vacuously;
  TTL/neg_ttl hints are surfaced for the consumer's own cache.
- **7 caps (§5)** are covered for the local peer by the §6.9a owner-cap
  bootstrap (full ``/{peer_id}/*`` self-access). They're named here for
  discovery/inspectability; no separate seeding is needed (§5.2 floor met).
"""

from __future__ import annotations

import fnmatch
import logging
import unicodedata
from typing import Any

from entity_core.crypto.identity import decode_peer_id, peer_id_from_identity_entity
from entity_core.crypto.signing import public_key_from_bytes, verify_signature
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_handlers.registry_peerissued import make_reader
from entity_handlers._common import (
    error_response as _error,
    normalize_hash as _normalize_hash,
    now_ms as _now_ms,
    ok_response as _ok,
    params_data as _params_data,
)

logger = logging.getLogger(__name__)

# -- Patterns / paths -------------------------------------------------------

REGISTRY_HANDLER_PATTERN = "system/registry"

BINDING_TYPE = "system/registry/binding"
REVOCATION_TYPE = "system/registry/revocation"
RESOLVER_CONFIG_TYPE = "system/registry/resolver-config"
LOCAL_NAME_CONFIG_TYPE = "system/registry/local-name-config"
RESOLUTION_LOG_TYPE = "system/registry/resolution-log"

RESOLVER_CONFIG_PATH = "system/registry/resolver-config"
LOCAL_NAME_CONFIG_PATH = "system/registry/local-name-config"
BINDING_PREFIX = "system/registry/binding/"
LOCAL_NAME_POINTER_PREFIX = "system/registry/binding/local-name/"
# Peer-issued by-name index (PROPOSAL-PEER-ISSUED §2.2) — the direct analog
# of local-name's pointer, different prefix: name → bare hash of the binding.
BY_NAME_POINTER_PREFIX = "system/registry/binding/by-name/"
RESOLUTION_LOG_PREFIX = "system/registry/resolution-log/"

# -- Live registration (§6a.9) ----------------------------------------------
REGISTER_REQUEST_TYPE = "system/registry/register-request"
REVOKE_REQUEST_TYPE = "system/registry/revoke-request"
RENEW_REQUEST_TYPE = "system/registry/renew-request"
ISSUER_POLICY_TYPE = "system/registry/issuer-policy"
REGISTER_PENDING_TYPE = "system/registry/register-pending"
NONCE_RECORD_TYPE = "system/registry/nonce-record"

ISSUER_POLICY_PATH = "system/registry/issuer-policy"
REGISTER_PENDING_PREFIX = "system/registry/register-pending/"
NONCE_PREFIX = "system/registry/nonce/"
# Revocation by-target index (P7 NORMATIVE): name → free once revoked.
REVOCATION_PREFIX = "system/registry/binding/revocation/"
REVOCATION_BY_TARGET_PREFIX = "system/registry/revocation/by-target/"

ISSUER_MODES = {"open", "allowlist", "manual", "domain-control"}

# §6a.9.1 replay acceptance window: a request's issued_at MUST be within this
# many ms of now; nonce records older than the window may be GC'd. Generous by
# default — the load-bearing replay guard is the per-(requester, nonce) seen-set.
REPLAY_WINDOW_MS = 24 * 60 * 60 * 1000

# -- Vocabulary (§2.4.1 — hyphenated, normative) ----------------------------

KNOWN_BINDING_KINDS = {
    "self-certifying", "local-name", "dns-txt", "well-known-url",
    "did-web", "peer-issued", "out-of-band", "consensus-anchored",
}
KNOWN_BACKEND_KINDS = {
    "local-name", "self-certifying", "dns-txt", "well-known-url",
    "did-web", "peer-issued", "consensus-anchored", "out-of-band",
}
# Kinds with no issuer signature — the user / self is the trust source (§3).
SIG_EXEMPT_KINDS = {"self-certifying", "local-name"}

# trust_anchor variants (§2.4 — underscore enum form).
TA_SELF_CERTIFYING = "self_certifying"
TA_LOCAL_NAME = "local_name"
TA_OUT_OF_BAND = "out_of_band"

# §5 capability surface — named for discovery; the local peer holds them
# via the §6.9a owner-cap full-self-access floor (§5.2).
REGISTRY_CAPS = (
    "system/capability/registry-resolve",
    "system/capability/registry-configure",
    "system/capability/registry-pin",
    "system/capability/registry-cache-control",
    "system/capability/registry-local-name-bind",
    "system/capability/registry-local-name-unbind",
    "system/capability/registry-local-name-list",
    # §6a.9.1 live-registration caps. `registry-request-binding` gates the
    # external surface (open → granted broadly; allowlist → narrow);
    # `registry-issue-binding` gates the internal sign-and-publish act (operator
    # / policy logic only); `registry-manage-issuer-policy` gates editing the
    # policy. Named here for discovery; the local registry peer holds them via
    # the §6.9a owner-cap full-self-access floor.
    "system/capability/registry-request-binding",
    "system/capability/registry-issue-binding",
    "system/capability/registry-manage-issuer-policy",
)

# -- Operations -------------------------------------------------------------

_OP_RESOLVE = "resolve"
_OP_INVALIDATE = "invalidate-cache"
_OP_BIND = "bind"
_OP_UNBIND = "unbind"
_OP_LIST = "list"
_OP_UPDATE_TRANSPORTS = "update-transports"
# §6a.9 live registration
_OP_REGISTER = "register-request"
_OP_REVOKE = "revoke-request"
_OP_RENEW = "renew-request"
_OP_APPROVE = "approve-request"
_OP_SET_POLICY = "set-issuer-policy"
_OP_GET_POLICY = "get-issuer-policy"


# ===========================================================================
# Small helpers
# ===========================================================================


def _get_entity(ctx: HandlerContext, path: str) -> Entity | None:
    """Resolve a tree path to its bound entity (or None)."""
    h = ctx.emit_pathway.entity_tree.get(path)
    if h is None:
        return None
    return ctx.emit_pathway.content_store.get(h)


def _nfc(name: str) -> str:
    return unicodedata.normalize("NFC", name)


def _validate_name_path_safety(name: str) -> str | None:
    """§6.3 name-path safety; returns an error message or None if valid."""
    if "/" in name:
        return "name contains '/'"
    for ch in name:
        o = ord(ch)
        if o <= 0x20 or o == 0x7F:
            return "name contains a control character (C0/DEL)"
    return None


def _normalize_local_name(name: str, case_normalization: str) -> str:
    """NFC (+ optional lowercase) — the storage key (§6.5 symmetry)."""
    n = _nfc(name)
    if case_normalization == "lower":
        n = n.lower()
    return n


def _load_local_name_config(ctx: HandlerContext) -> dict[str, Any]:
    cfg = _get_entity(ctx, LOCAL_NAME_CONFIG_PATH)
    if cfg is not None and cfg.type == LOCAL_NAME_CONFIG_TYPE:
        return cfg.data
    return {"default_pinned": True, "allow_supersede": True, "case_normalization": "none"}


def _load_resolver_config(ctx: HandlerContext) -> dict[str, Any]:
    """Load resolver-config, defaulting to local-name-only (§10) so the local
    local-name store is usable without explicit configuration (§5.2).

    `backend_id` is REQUIRED on every chain entry (arch ruling Q1). For the
    local-name single-store case (§6.2) it defaults to the local peer's
    identity; we fill that here at config-construction time so the effective
    config always carries it — whether the config is the synthesized default
    or a stored one that omitted it for the local-name backend."""
    cfg = _get_entity(ctx, RESOLVER_CONFIG_PATH)
    if cfg is not None and cfg.type == RESOLVER_CONFIG_TYPE:
        return _fill_chain_backend_ids(dict(cfg.data), ctx.local_peer_id)
    return _fill_chain_backend_ids(
        {
            "resolver_chain": [
                {
                    "backend_kind": "local-name",
                    "priority": 0,
                    "accepted_trust_anchors": ["local_name"],
                }
            ],
            "pinned_bindings": [],
            "name_format_dispatch": [],
        },
        ctx.local_peer_id,
    )


def _fill_chain_backend_ids(config: dict[str, Any], local_peer_id: str) -> dict[str, Any]:
    """Default-fill the REQUIRED `backend_id` on local-name chain entries
    with the local peer's identity (§6.2 — exactly one local-name store per
    peer). Non-local-name backends carry their own authority identifier and
    are left untouched. The chain list is shallow-copied so a stored
    config's entities aren't mutated in place."""
    chain = config.get("resolver_chain") or []
    filled = []
    for entry in chain:
        if (
            isinstance(entry, dict)
            and entry.get("backend_kind") == "local-name"
            and not entry.get("backend_id")
        ):
            entry = {**entry, "backend_id": local_peer_id}
        filled.append(entry)
    config["resolver_chain"] = filled
    return config


# ===========================================================================
# Signature + revocation (substrate verification, §3 / §5)
# ===========================================================================


def _find_signature_for(ctx: HandlerContext, target_hash: bytes) -> Entity | None:
    """Locate a ``system/signature`` over ``target_hash`` — invariant
    pointer first (``system/signature/{hex}``), then a tree scan
    (target-matching). Refless per V7 §5.2 / §989."""
    by_pointer = _get_entity(ctx, f"system/signature/{target_hash.hex()}")
    if by_pointer is not None and by_pointer.type == "system/signature":
        if _normalize_hash(by_pointer.data.get("target")) == target_hash:
            return by_pointer
    for _uri, h in ctx.emit_pathway.entity_tree.all_bindings():
        ent = ctx.emit_pathway.content_store.get(h)
        if ent is None or ent.type != "system/signature":
            continue
        if _normalize_hash(ent.data.get("target")) == target_hash:
            return ent
    return None


def _resolve_pubkey(ctx: HandlerContext, signer_hash: bytes) -> tuple[bytes, str] | None:
    """Resolve a signer identity hash to ``(public_key, key_type)`` via the
    ``system/peer`` entity in the content store."""
    peer = ctx.emit_pathway.content_store.get(signer_hash)
    if peer is None or peer.type != "system/peer":
        return None
    pub = peer.data.get("public_key")
    kt = peer.data.get("key_type", "ed25519")
    if not isinstance(pub, bytes):
        return None
    return pub, kt


def _signer_peer_id(ctx: HandlerContext, signer_hash: bytes | None) -> str | None:
    """Map a signer identity hash to its Base58 peer-id via the local
    ``system/peer`` entity. Used to bind a peer-issued binding's signer to
    the pinned registry (``backend_id``)."""
    if signer_hash is None:
        return None
    ent = ctx.emit_pathway.content_store.get(signer_hash)
    if ent is None or ent.type != "system/peer":
        return None
    try:
        return peer_id_from_identity_entity(ent.to_dict())
    except Exception:
        return None


def _verify_signature_over(ctx: HandlerContext, target_hash: bytes) -> tuple[bool, bytes | None]:
    """Verify a target-matched signature over ``target_hash``. Returns
    ``(ok, signer_hash)`` — signer_hash is the authenticating identity, used
    by the revocation check to confirm same-authority."""
    sig = _find_signature_for(ctx, target_hash)
    if sig is None:
        return False, None
    signer = _normalize_hash(sig.data.get("signer"))
    sig_bytes = sig.data.get("signature")
    if signer is None or not isinstance(sig_bytes, bytes):
        return False, None
    resolved = _resolve_pubkey(ctx, signer)
    if resolved is None:
        return False, signer
    pub, _kt = resolved
    try:
        ok = verify_signature(public_key_from_bytes(pub), target_hash, sig_bytes)
    except Exception:
        return False, signer
    return ok, signer


def _is_revoked(
    ctx: HandlerContext, binding: Entity, issuer: bytes | None, *, sig_exempt: bool,
) -> bool:
    """§3.1 — a ``system/registry/revocation`` targeting this binding excludes
    it. For **signed** bindings the revocation MUST verify against the SAME
    authority (issuer). For **sig-exempt** bindings (local-name) the
    revocation needs no signature — it lives in the user's own local store,
    which is the trust source (the same carve-out the local-name itself enjoys,
    §6.3). This is the v6 ``revocation_honored`` path: a local local-name is
    revoked by writing an (unsigned) revocation into the local tree."""
    binding_hash = binding.compute_hash()
    for _uri, h in ctx.emit_pathway.entity_tree.all_bindings():
        ent = ctx.emit_pathway.content_store.get(h)
        if ent is None or ent.type != REVOCATION_TYPE:
            continue
        if _normalize_hash(ent.data.get("revokes")) != binding_hash:
            continue
        if sig_exempt:
            # Local revocation — user is the trust source; no signature needed.
            return True
        ok, rev_signer = _verify_signature_over(ctx, ent.compute_hash())
        if not ok:
            continue
        # Same-authority: signed by the binding's issuer.
        if issuer is not None and rev_signer != issuer:
            continue
        return True
    return False


def _anchor_accepted(accepted: list[str], trust_anchor: str) -> bool:
    """Receiver-policy filter (§5). Empty list = accept all. A family-level
    accepted entry (e.g. ``peer_issued``) accepts any qualified variant
    (``peer_issued:{id}``); a fully-qualified entry must match exactly."""
    if not accepted:
        return True
    actual_family = trust_anchor.split(":", 1)[0]
    for a in accepted:
        if a == trust_anchor:
            return True
        if ":" not in a and a == actual_family:
            return True
    return False


def _validate(
    ctx: HandlerContext,
    binding: Entity,
    trust_anchor: str,
    accepted: list[str],
) -> str | None:
    """Substrate validation (§2.2 ``validate(r)`` / §5). Returns a rejection
    ``reason`` string, or None if the binding is usable."""
    kind = binding.data.get("kind")

    # Receiver policy (trust-anchor filter).
    if not _anchor_accepted(accepted, trust_anchor):
        return "policy_rejected"

    # Self-certifying: name must BE the peer-id (no signature).
    if kind == "self-certifying":
        name = binding.data.get("name")
        tpid = binding.data.get("target_peer_id")
        if not isinstance(name, str) or name != tpid:
            return "self_certifying_name_mismatch"
        try:
            decode_peer_id(name)
        except Exception:
            return "self_certifying_invalid_peer_id"
        return None

    # Signature verification on every other non-local-name kind (§5 MUST).
    sig_exempt = kind in SIG_EXEMPT_KINDS
    issuer: bytes | None = None
    if not sig_exempt:
        ok, issuer = _verify_signature_over(ctx, binding.compute_hash())
        if not ok:
            return "signature_failed"

    # Peer-issued trust root (PROPOSAL-PEER-ISSUED §2.1 step 3): the signer
    # MUST be the PINNED registry, not merely *some* in-store identity whose
    # key happens to verify. The pinned registry is identified by the
    # qualified trust_anchor ``peer_issued:{backend_id}``. (REG-PEERISSUED-
    # VERIFY-FAIL-1: a binding signed by a non-pinned key is rejected, never
    # downgraded.)
    if kind == "peer-issued" and trust_anchor.startswith("peer_issued:"):
        expected_id = trust_anchor.split(":", 1)[1]
        if _signer_peer_id(ctx, issuer) != expected_id:
            return "issuer_not_pinned"

    # Revocation honor (§3.1) — checked after the binding's authority is known.
    if _is_revoked(ctx, binding, issuer, sig_exempt=sig_exempt):
        return "revoked"

    # TTL expiry (PROPOSAL-PEER-ISSUED §2.1 step 3): a binding with a non-null
    # ttl is excluded once issued_at + ttl has passed. ttl == null never
    # expires (local-name / self-certifying). (REG-PEERISSUED-EXPIRED-1.)
    ttl = binding.data.get("ttl")
    issued_at = binding.data.get("issued_at")
    if isinstance(ttl, int) and isinstance(issued_at, int) and issued_at + ttl <= _now_ms():
        return "expired"
    return None


# ===========================================================================
# Backends (§6 local-name + local-precedes for other kinds)
# ===========================================================================


def _trust_anchor_for_kind(kind: str, backend_id: str | None) -> str:
    """Map a binding kind to the trust_anchor variant it resolves under
    (§2.4 / §2.4.1)."""
    if kind == "local-name":
        return TA_LOCAL_NAME
    if kind == "self-certifying":
        return TA_SELF_CERTIFYING
    if kind == "peer-issued":
        return f"peer_issued:{backend_id}" if backend_id else "peer_issued"
    if kind == "out-of-band":
        return TA_OUT_OF_BAND
    # dns-txt / well-known-url / did-web / consensus-anchored carry
    # qualified anchors; v1 surfaces the family form.
    return kind.replace("-", "_")


def _binding_to_result(binding: Entity, trust_anchor: str, backend_id: str | None) -> dict[str, Any]:
    return {
        "status": "resolved",
        "binding": binding.compute_hash(),
        "peer_id": binding.data.get("target_peer_id"),
        "transports": binding.data.get("transports") or [],
        "attestations": [],
        "trust_anchor": trust_anchor,
        "ttl": binding.data.get("ttl"),
        "neg_ttl": None,
        "backend_id": backend_id,
    }


def _local_name_resolve(
    ctx: HandlerContext, name: str, local_name_cfg: dict[str, Any], backend_id: str | None,
) -> tuple[dict[str, Any] | None, Entity | None]:
    """§6.5 local-name ``:resolve`` — NFC + optional case-fold, tree-pointer
    lookup, fetch body. Returns (result, binding_entity)."""
    normalized = _normalize_local_name(name, local_name_cfg.get("case_normalization", "none"))
    pointer = LOCAL_NAME_POINTER_PREFIX + normalized
    binding = _get_entity(ctx, pointer)
    if binding is None or binding.type != BINDING_TYPE:
        return None, None
    return _binding_to_result(binding, TA_LOCAL_NAME, backend_id), binding


def _local_precedes_resolve(
    ctx: HandlerContext, name: str, backend_kind: str, backend_id: str | None,
) -> tuple[dict[str, Any] | None, Entity | None]:
    """Resolve a non-local-name binding from the LOCAL binding store (§7
    bootstrap-with-precedes). Scans ``system/registry/binding/{hash}`` for a
    binding with matching ``name`` + ``kind`` family. The cold http-poll
    fetch of a remote registry's tree is the C2 outbound-connector layer."""
    best: Entity | None = None
    best_issued = -1
    for uri in ctx.emit_pathway.entity_tree.list_prefix(BINDING_PREFIX):
        # Skip the local-name pointer subtree — those are local-name.
        if uri.split(BINDING_PREFIX, 1)[-1].startswith("local-name/"):
            continue
        ent = _get_entity(ctx, uri)
        if ent is None or ent.type != BINDING_TYPE:
            continue
        if ent.data.get("name") != name or ent.data.get("kind") != backend_kind:
            continue
        # Head-of-supersedes preference: pick the most recently issued.
        issued = ent.data.get("issued_at")
        issued = issued if isinstance(issued, int) else 0
        if issued >= best_issued:
            best_issued, best = issued, ent
    if best is None:
        return None, None
    ta = _trust_anchor_for_kind(backend_kind, backend_id)
    return _binding_to_result(best, ta, backend_id), best


async def _peer_issued_resolve(
    ctx: HandlerContext, name: str, entry: dict[str, Any], backend_id: str | None,
) -> tuple[dict[str, Any] | None, Entity | None]:
    """PROPOSAL-PEER-ISSUED §2.1 — resolve a peer-issued binding.

    Trust logic over transport-agnostic reads: try the local store first
    (precedes = warm cache, §2.2), and on a miss read the by-name index +
    binding from the registry peer through the ``RegistryReader`` seam (the
    transport — http-poll for a static coral-reef — is the seam's choice,
    not this backend's). Fetched entities are written into the local store
    so the shared substrate verification (``_validate``: signature against
    the pinned registry key + revocation + ttl) runs identically to the
    precedes path — and the next resolve is a warm-cache hit."""
    # 0. Warm cache — a precede / previously-fetched binding in the local store.
    result, binding = _local_precedes_resolve(ctx, name, "peer-issued", backend_id)
    if binding is not None:
        return result, binding

    # No local binding → fetch from the registry peer (if one is configured).
    reader = make_reader(entry)
    if reader is None:
        return None, None
    if _validate_name_path_safety(name) is not None:
        return None, None
    norm = _nfc(name)

    # 1. by-name index → binding hash.
    binding_hash = await reader.tree_get(BY_NAME_POINTER_PREFIX + norm)
    if binding_hash is None:
        neg_ttl = (entry.get("hints") or {}).get("neg_ttl")
        return {
            "status": "not_found", "transports": [], "attestations": [],
            "neg_ttl": neg_ttl, "backend_id": backend_id,
        }, None

    # 2. binding hash → binding body (content_get is hash-verified).
    fetched = await reader.content_get(binding_hash)
    if fetched is None or fetched.type != BINDING_TYPE:
        return None, None

    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_RESOLVE)
    # Pull the binding's signature (invariant pointer) into the local store so
    # the shared verify can find it. The pinned registry IDENTITY is NOT
    # fetched — it is the local trust root (verify uses the pinned key only;
    # a binding whose signer isn't the pin fails `issuer_not_pinned`).
    sig_hash = await reader.tree_get(f"system/signature/{binding_hash.hex()}")
    if sig_hash is not None:
        sig = await reader.content_get(sig_hash)
        if sig is not None and sig.type == "system/signature":
            ctx.emit_pathway.emit(f"system/signature/{binding_hash.hex()}", sig, emit_ctx)

    # 3. cache the binding at the universal location (it becomes a precede).
    ctx.emit_pathway.emit(BINDING_PREFIX + binding_hash.hex(), fetched, emit_ctx)

    ta = _trust_anchor_for_kind("peer-issued", backend_id)
    return _binding_to_result(fetched, ta, backend_id), fetched


# ===========================================================================
# Meta-resolver (§2.2 / §4.1)
# ===========================================================================


def _synthesize_pin_result(pin: dict[str, Any]) -> dict[str, Any]:
    """§4.1.2 synthesized ResolutionResult for a pinned binding."""
    return {
        "status": "resolved",
        "binding": None,
        "peer_id": pin.get("target_peer_id"),
        "transports": [],
        "attestations": [],
        "trust_anchor": TA_OUT_OF_BAND,
        "ttl": None,
        "neg_ttl": None,
        "backend_id": "pinned",
    }


def _dispatch_allows(
    config: dict[str, Any], name: str, backend_kind: str,
) -> bool:
    """§4.1 step 2 — name_format_dispatch filter. A backend kind with NO
    dispatch entry mentioning it is consulted always (match-all); a kind
    that appears in some dispatch entry is consulted ONLY when a matching
    entry's pattern matches the name. The primary privacy mechanism."""
    dispatch = config.get("name_format_dispatch") or []
    mentioned = False
    for entry in dispatch:
        kinds = entry.get("backend_kinds") or []
        if backend_kind in kinds:
            mentioned = True
            pattern = entry.get("pattern", "")
            if fnmatch.fnmatchcase(name, pattern):
                return True
    return not mentioned


async def _meta_resolve(
    ctx: HandlerContext, name: str, hints: Any,
) -> tuple[dict[str, Any], str | None, str | None]:
    """The meta-resolver. Returns (result, backend_id, reason). `reason` is
    a non-resolved diagnostic for the §11.2 log (e.g. signature_failed)."""
    config = _load_resolver_config(ctx)
    local_name_cfg = _load_local_name_config(ctx)

    # 1. Pinned bindings override everything (§4.1.1).
    for pin in config.get("pinned_bindings") or []:
        if pin.get("name") == name:
            return _synthesize_pin_result(pin), "pinned", "pin_short_circuit"

    # 2 + 3. name_format_dispatch filter, then chain in ascending priority.
    chain = sorted(
        config.get("resolver_chain") or [],
        key=lambda e: e.get("priority", 0),
    )
    last_reason: str | None = None
    last_not_found: dict[str, Any] | None = None
    for entry in chain:
        backend_kind = entry.get("backend_kind")
        backend_id = entry.get("backend_id")
        accepted = entry.get("accepted_trust_anchors") or []

        if backend_kind not in KNOWN_BACKEND_KINDS:
            logger.warning("registry: skipping unknown backend_kind %r (§4.2)", backend_kind)
            continue
        if not _dispatch_allows(config, name, backend_kind):
            continue

        if backend_kind == "local-name":
            result, binding = _local_name_resolve(ctx, name, local_name_cfg, backend_id)
        elif backend_kind == "peer-issued":
            result, binding = await _peer_issued_resolve(ctx, name, entry, backend_id)
        else:
            result, binding = _local_precedes_resolve(ctx, name, backend_kind, backend_id)

        # A backend that definitively reached its registry and found no name
        # surfaces not_found (+ neg_ttl) — remembered as the terminal answer
        # if the rest of the chain also misses (§2.1; REG-PEERISSUED-OFFLINE-
        # NOTFOUND-1), distinct from a fail-closed chain_exhausted.
        if result is not None and result.get("status") == "not_found" and binding is None:
            last_not_found = result

        if result is None or binding is None:
            continue

        reason = _validate(ctx, binding, result["trust_anchor"], accepted)
        if reason is not None:
            last_reason = reason
            continue  # failed validation; try next (§2.2)
        return result, backend_id, None

    # 4. Fail-closed on chain exhaustion (§4.1 step 4). A definitive
    # not_found (registry reached, name absent) is preferred over the
    # generic chain_exhausted so the consumer can honor neg_ttl.
    if last_not_found is not None:
        return last_not_found, last_not_found.get("backend_id"), last_reason
    return {"status": "chain_exhausted", "transports": [], "attestations": []}, None, last_reason


# ===========================================================================
# Resolution log (§11.2 SHOULD)
# ===========================================================================


def _next_log_seq(ctx: HandlerContext) -> int:
    """Per-peer monotonic seq, recovered as max+1 over the log prefix."""
    best = -1
    for uri in ctx.emit_pathway.entity_tree.list_prefix(RESOLUTION_LOG_PREFIX):
        tail = uri.rsplit("/", 1)[-1]
        try:
            best = max(best, int(tail))
        except ValueError:
            continue
    return best + 1


def _emit_resolution_log(
    ctx: HandlerContext,
    name: str,
    result: dict[str, Any],
    backend_id: str | None,
    reason: str | None,
    is_fallback: bool,
) -> None:
    """One entry per top-level meta_resolve (§11.2). Fallback re-resolves are
    tagged and NOT written on the hot path (no per-retry write amplification)."""
    if is_fallback:
        return
    seq = _next_log_seq(ctx)
    entry = Entity(
        type=RESOLUTION_LOG_TYPE,
        data={
            "seq": seq,
            "name": name,
            "backend_id": backend_id,
            "status": result.get("status"),
            "reason": reason,
            "binding": result.get("binding"),
            "attempted_at": _now_ms(),
            "is_fallback_reresolve": is_fallback,
        },
    )
    # Writing a log entry is not itself a resolution → no log-of-log.
    ctx.emit_pathway.emit(
        RESOLUTION_LOG_PREFIX + str(seq), entry, EmitContext.from_handler_grant(ctx, "log"),
    )


# ===========================================================================
# Operation handlers
# ===========================================================================


async def _handle_resolve(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    data = _params_data(params)
    name = data.get("name")
    if not isinstance(name, str) or not name:
        return _error(400, "invalid_params", "resolve requires a non-empty name")
    is_fallback = bool(data.get("is_fallback_reresolve", False))

    result, backend_id, reason = await _meta_resolve(ctx, name, data.get("hints"))
    try:
        _emit_resolution_log(ctx, name, result, backend_id, reason, is_fallback)
    except Exception:  # logging is SHOULD — never fail the resolve on it
        logger.debug("registry: resolution-log emit failed", exc_info=True)
    return _ok("system/registry/resolution-result", result)


async def _handle_invalidate_cache(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    # v1 resolves live off the tree — no positive cache to flush. The op is
    # satisfied by construction (the cache-control cap still has work as the
    # discovery surface). null name = flush all (no-op).
    return _ok("system/protocol/ack", {"invalidated": True})


async def _handle_bind(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    data = _params_data(params)
    name = data.get("name")
    target_peer_id = data.get("target_peer_id")
    if not isinstance(name, str) or not name:
        return _error(400, "invalid_params", "bind requires a name")
    if not isinstance(target_peer_id, str) or not target_peer_id:
        return _error(400, "invalid_params", "bind requires a target_peer_id")

    err = _validate_name_path_safety(name)
    if err is not None:
        return _error(400, "bind_invalid_name", err)

    local_name_cfg = _load_local_name_config(ctx)
    normalized = _normalize_local_name(name, local_name_cfg.get("case_normalization", "none"))
    pointer = LOCAL_NAME_POINTER_PREFIX + normalized
    existing_hash = ctx.emit_pathway.entity_tree.get(pointer)

    if existing_hash is not None and not local_name_cfg.get("allow_supersede", True):
        return _error(409, "bind_already_exists", f"local-name {name!r} already bound")

    transports = data.get("transports")
    notes = data.get("notes")
    binding_data: dict[str, Any] = {
        "name": normalized,
        "kind": "local-name",
        "target_peer_id": target_peer_id,
        "transports": transports if isinstance(transports, list) else [],
        "issued_at": _now_ms(),
        "ttl": None,
        "metadata": {
            "notes": notes if isinstance(notes, str) else None,
            "pinned": bool(local_name_cfg.get("default_pinned", True)),
        },
    }
    if existing_hash is not None:
        binding_data["supersedes"] = _normalize_hash(existing_hash)

    return _store_local_name_binding(ctx, normalized, binding_data)


async def _handle_update_transports(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    data = _params_data(params)
    name = data.get("name")
    transports = data.get("transports")
    if not isinstance(name, str) or not name:
        return _error(400, "invalid_params", "update-transports requires a name")
    if not isinstance(transports, list):
        return _error(400, "invalid_params", "transports must be an array")

    local_name_cfg = _load_local_name_config(ctx)
    normalized = _normalize_local_name(name, local_name_cfg.get("case_normalization", "none"))
    pointer = LOCAL_NAME_POINTER_PREFIX + normalized
    existing_hash = ctx.emit_pathway.entity_tree.get(pointer)
    existing = ctx.emit_pathway.content_store.get(existing_hash) if existing_hash else None
    if existing is None or existing.type != BINDING_TYPE:
        return _error(404, "not_found", f"local-name {name!r} not bound")

    binding_data = {
        "name": normalized,
        "kind": "local-name",
        "target_peer_id": existing.data.get("target_peer_id"),
        "transports": transports,
        "issued_at": _now_ms(),
        "ttl": None,
        "supersedes": _normalize_hash(existing_hash),
        "metadata": existing.data.get("metadata"),
    }
    return _store_local_name_binding(ctx, normalized, binding_data)


def _store_local_name_binding(
    ctx: HandlerContext, normalized: str, binding_data: dict[str, Any],
) -> dict[str, Any]:
    """Emit a local-name binding body at the universal location AND update the
    name-keyed tree pointer (the two-layer §6.3 storage)."""
    binding = Entity(type=BINDING_TYPE, data=binding_data)
    binding_hash = binding.compute_hash()
    emit_ctx = EmitContext.from_handler_grant(ctx, "bind")
    ctx.emit_pathway.emit(BINDING_PREFIX + binding_hash.hex(), binding, emit_ctx)
    ctx.emit_pathway.emit(LOCAL_NAME_POINTER_PREFIX + normalized, binding, emit_ctx)
    return _ok("system/registry/local-name/bind-result", {"binding_hash": binding_hash})


async def _handle_unbind(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    data = _params_data(params)
    name = data.get("name")
    if not isinstance(name, str) or not name:
        return _error(400, "invalid_params", "unbind requires a name")
    local_name_cfg = _load_local_name_config(ctx)
    normalized = _normalize_local_name(name, local_name_cfg.get("case_normalization", "none"))
    pointer = LOCAL_NAME_POINTER_PREFIX + normalized
    removed = ctx.emit_pathway.entity_tree.remove(pointer)
    # Binding body + supersedes-chain remain (auditable per ATTESTATION
    # discipline §6.5). Idempotent: unbinding an absent name is still ().
    return _ok("system/protocol/ack", {"unbound": removed is not None})


async def _handle_list(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6.5 ``:list`` — read the live name→hash index (tree-pointer prefix),
    NOT the supersedes audit log."""
    entries: list[dict[str, Any]] = []
    for uri in ctx.emit_pathway.entity_tree.list_prefix(LOCAL_NAME_POINTER_PREFIX):
        h = ctx.emit_pathway.entity_tree.get(uri)
        if h is None:
            continue
        binding = ctx.emit_pathway.content_store.get(h)
        if binding is None or binding.type != BINDING_TYPE:
            continue
        meta = binding.data.get("metadata") or {}
        entries.append({
            "name": binding.data.get("name"),
            "hash": h,
            "target_peer_id": binding.data.get("target_peer_id"),
            "notes": meta.get("notes"),
            "pinned": bool(meta.get("pinned", True)),
        })
    return _ok("system/registry/local-name/list-result", {"entries": entries})


# ===========================================================================
# Live registration (§6a.9) — publisher self-registration
# ===========================================================================
#
# Curated registration (§6a.8) is the operator signing by hand. Live
# registration lets a *publisher* self-register against a registry that runs
# this handler. Two separable proof layers (§6a.9.1):
#   Layer 1 — peer-id control (ALWAYS): the request is self-signed by
#             `target_peer_id`, proving the requester holds the key it is
#             binding the name to (no registering someone else's peer-id).
#   Layer 2 — name entitlement (POLICY): whether THIS requester may have THIS
#             name — `open` (first-come), `allowlist`, or `manual` (queue).
# `domain-control` is DEFERRED (§6a.9.1 / §6a.10): its DNS-challenge format
# MUST be the one mechanism shared with the web-native dns-txt/well-known
# backends, settled with that proposal — never invented a second time here.


def _find_signature_anywhere(ctx: HandlerContext, target_hash: bytes) -> Entity | None:
    """Locate a ``system/signature`` over ``target_hash`` — tree first (the
    resolve-path lookup: invariant pointer + target-matching scan), then the
    content store. A live `register-request` carries its signature in the
    request envelope's ``included`` (stored on receipt per V7 §1.5), so it
    lands in the content store, not the tree."""
    sig = _find_signature_for(ctx, target_hash)
    if sig is not None:
        return sig
    for _h, ent in ctx.emit_pathway.content_store.iter_all():
        if ent.type != "system/signature":
            continue
        if _normalize_hash(ent.data.get("target")) == target_hash:
            return ent
    return None


def _verify_proof_by(ctx: HandlerContext, target_hash: bytes, expected_peer_id: str) -> bool:
    """Layer-1 ownership proof (§6a.9): a ``system/signature`` over
    ``target_hash`` whose signer resolves to ``expected_peer_id`` and verifies
    cryptographically. Binds the request to the key it claims to control."""
    if not isinstance(expected_peer_id, str) or not expected_peer_id:
        return False
    sig = _find_signature_anywhere(ctx, target_hash)
    if sig is None:
        return False
    signer = _normalize_hash(sig.data.get("signer"))
    sig_bytes = sig.data.get("signature")
    if signer is None or not isinstance(sig_bytes, bytes):
        return False
    if _signer_peer_id(ctx, signer) != expected_peer_id:
        return False
    resolved = _resolve_pubkey(ctx, signer)
    if resolved is None:
        return False
    pub, _kt = resolved
    try:
        return verify_signature(public_key_from_bytes(pub), target_hash, sig_bytes)
    except Exception:
        return False


def _request_hash(req_type: str, data: dict[str, Any]) -> bytes:
    """Content-hash of the request entity exactly as the publisher signed it —
    ``{type, data}`` with no handler-added fields (§6a.9 layer-1 hashes the
    request as authored)."""
    return Entity(type=req_type, data=data).compute_hash()


def _load_issuer_policy(ctx: HandlerContext) -> dict[str, Any] | None:
    """The registry's local admission config (§6a.9.1), or None when absent —
    a peer with no issuer-policy is a curated/static registry (§6a.9) and does
    not accept live registration."""
    ent = _get_entity(ctx, ISSUER_POLICY_PATH)
    if ent is not None and ent.type == ISSUER_POLICY_TYPE:
        return ent.data
    return None


def _name_is_taken(ctx: HandlerContext, nfc_name: str) -> bool:
    """A peer-issued name is taken when its ``by-name`` pointer resolves to a
    binding that has NOT been revoked (a revocation frees the name, P7)."""
    h = ctx.emit_pathway.entity_tree.get(BY_NAME_POINTER_PREFIX + nfc_name)
    if h is None:
        return False
    bh = _normalize_hash(h)
    if bh is None:
        return False
    revoked = ctx.emit_pathway.entity_tree.get(REVOCATION_BY_TARGET_PREFIX + bh.hex())
    return revoked is None


def _nonce_path(requester: str, nonce: bytes) -> str:
    return f"{NONCE_PREFIX}{requester}/{nonce.hex()}"


def _nonce_seen(ctx: HandlerContext, requester: str, nonce: bytes) -> bool:
    return ctx.emit_pathway.entity_tree.get(_nonce_path(requester, nonce)) is not None


def _record_nonce(ctx: HandlerContext, requester: str, nonce: bytes, issued_at: int) -> None:
    rec = Entity(type=NONCE_RECORD_TYPE, data={"requester": requester, "issued_at": issued_at})
    ctx.emit_pathway.emit(
        _nonce_path(requester, nonce), rec, EmitContext.from_handler_grant(ctx, "register"),
    )


def _registry_identity(ctx: HandlerContext) -> Entity:
    """The registry's own identity entity (K_registry's ``system/peer``),
    persisted so a same-peer resolve can verify its freshly-issued bindings
    against the pinned trust root."""
    ident = create_identity_entity(ctx.keypair)
    ctx.emit_pathway.content_store.put(ident)
    return ident


def _issue_binding(
    ctx: HandlerContext,
    nfc_name: str,
    target_peer_id: str,
    transports: list[Any],
    ttl: int | None,
    *,
    supersedes: bytes | None = None,
) -> bytes:
    """The §6a.8 sign-and-publish act, server-side. Signs the binding with
    K_registry (``ctx.keypair``) and publishes the three artifacts: body at the
    universal location, signature at the invariant pointer, by-name index
    pointer. Returns the binding hash."""
    data: dict[str, Any] = {
        "name": nfc_name,
        "kind": "peer-issued",
        "target_peer_id": target_peer_id,
        "transports": transports if isinstance(transports, list) else [],
        "issued_at": _now_ms(),
        "ttl": ttl,
    }
    if supersedes is not None:
        data["supersedes"] = supersedes
    binding = Entity(type=BINDING_TYPE, data=data)
    bh = binding.compute_hash()
    ident = _registry_identity(ctx)
    sig = create_signature_entity(ctx.keypair, bh, ident.compute_hash())
    emit_ctx = EmitContext.from_handler_grant(ctx, "register")
    ctx.emit_pathway.emit(BINDING_PREFIX + bh.hex(), binding, emit_ctx)
    ctx.emit_pathway.emit(f"system/signature/{bh.hex()}", sig, emit_ctx)
    ctx.emit_pathway.emit(BY_NAME_POINTER_PREFIX + nfc_name, binding, emit_ctx)
    return bh


def _emit_revocation(ctx: HandlerContext, binding_hash: bytes, reason: Any) -> bytes:
    """Publish a registry-signed §3.1 revocation + the P7 by-target pointer
    (the read side of which frees the name and excludes the binding at resolve)."""
    rev = Entity(type=REVOCATION_TYPE, data={
        "revokes": binding_hash,
        "revoked_at": _now_ms(),
        "reason": reason if isinstance(reason, str) else None,
    })
    rh = rev.compute_hash()
    ident = _registry_identity(ctx)
    sig = create_signature_entity(ctx.keypair, rh, ident.compute_hash())
    emit_ctx = EmitContext.from_handler_grant(ctx, "revoke")
    ctx.emit_pathway.emit(REVOCATION_PREFIX + rh.hex(), rev, emit_ctx)
    ctx.emit_pathway.emit(f"system/signature/{rh.hex()}", sig, emit_ctx)
    ctx.emit_pathway.emit(REVOCATION_BY_TARGET_PREFIX + binding_hash.hex(), rev, emit_ctx)
    return rh


def _check_replay(
    ctx: HandlerContext, requester: str, nonce: Any, issued_at: Any,
) -> dict[str, Any] | None:
    """§6a.9.1 anti-replay. Returns an error response, or None when fresh.
    Does NOT record the nonce — the caller records it only on a processed
    outcome (issue / queue) so a rejected request can be legitimately retried."""
    if not isinstance(nonce, (bytes, bytearray)):
        return _error(400, "invalid_params", "request requires a bytes nonce")
    if not isinstance(issued_at, int):
        return _error(400, "invalid_params", "request requires issued_at (ms-since-epoch)")
    if abs(_now_ms() - issued_at) > REPLAY_WINDOW_MS:
        return _error(403, "stale_request", "issued_at outside the replay window")
    if _nonce_seen(ctx, requester, bytes(nonce)):
        return _error(403, "replay_detected", "nonce already seen for this requester")
    return None


async def _handle_register_request(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9 ``:register-request`` — layer-1 self-signature proof → issuer-policy
    admission → on approve the §6a.8 issue act; reject / queue otherwise."""
    policy = _load_issuer_policy(ctx)
    if policy is None:
        return _error(
            403, "registration_disabled",
            "this registry does not accept live registration (no issuer-policy configured)",
        )

    data = _params_data(params)
    name = data.get("name")
    target_peer_id = data.get("target_peer_id")
    if not isinstance(name, str) or not name:
        return _error(400, "invalid_params", "register-request requires a name")
    if not isinstance(target_peer_id, str) or not target_peer_id:
        return _error(400, "invalid_params", "register-request requires a target_peer_id")
    err = _validate_name_path_safety(name)
    if err is not None:
        return _error(400, "register_invalid_name", err)
    nfc_name = _nfc(name)

    # Layer-1 (ALWAYS): the request MUST be self-signed by target_peer_id.
    req_hash = _request_hash(REGISTER_REQUEST_TYPE, data)
    if not _verify_proof_by(ctx, req_hash, target_peer_id):
        return _error(
            403, "proof_failed",
            "register-request signature is not by target_peer_id (§6a.9 layer-1)",
        )

    # Anti-replay (§6a.9.1) — checked before any side effect.
    replay = _check_replay(ctx, target_peer_id, data.get("nonce"), data.get("issued_at"))
    if replay is not None:
        return replay
    nonce = bytes(data.get("nonce"))
    issued_at = data.get("issued_at")

    mode = policy.get("mode")
    if mode not in ISSUER_MODES:
        return _error(500, "policy_invalid", f"unknown issuer-policy mode {mode!r}")
    if mode == "domain-control":
        return _error(
            501, "domain_control_unsupported",
            "domain-control mode is deferred (§6a.9.1) — registry runs open/allowlist/manual",
        )

    # name_constraints narrows EVERY mode when set (e.g. a registry that only
    # issues "*.lab" regardless of who asks).
    constraint = policy.get("name_constraints")
    if isinstance(constraint, str) and not fnmatch.fnmatchcase(nfc_name, constraint):
        return _error(403, "not_entitled", f"name {name!r} not permitted by name_constraints")

    ttl = data.get("requested_ttl")
    if not isinstance(ttl, int):
        ttl = policy.get("default_ttl")

    # Layer-2 — name entitlement.
    if mode == "manual":
        # Queue for operator review; record the nonce (the request is processed).
        _record_nonce(ctx, target_peer_id, nonce, issued_at)
        pending = Entity(type=REGISTER_PENDING_TYPE, data={
            "name": nfc_name,
            "target_peer_id": target_peer_id,
            "transports": data.get("transports") or [],
            "requested_ttl": ttl,
            "queued_at": _now_ms(),
            "status": "pending_review",
        })
        ph = pending.compute_hash()
        ctx.emit_pathway.emit(
            REGISTER_PENDING_PREFIX + ph.hex(), pending,
            EmitContext.from_handler_grant(ctx, "register"),
        )
        return _ok("system/registry/register-result", {"status": "pending_review", "pending_hash": ph})

    if mode == "allowlist":
        allow = policy.get("allowlist") or []
        if target_peer_id not in allow:
            return _error(403, "not_entitled", f"{target_peer_id} is not on the registry allowlist")

    # open + allowlist(passed): first-come on a free name.
    if _name_is_taken(ctx, nfc_name):
        return _error(409, "name_taken", f"name {name!r} is already bound")

    _record_nonce(ctx, target_peer_id, nonce, issued_at)
    bh = _issue_binding(ctx, nfc_name, target_peer_id, data.get("transports") or [], ttl)
    return _ok("system/registry/register-result", {"status": "registered", "binding_hash": bh})


def _lookup_binding(ctx: HandlerContext, data: dict[str, Any]) -> tuple[bytes | None, Entity | None]:
    bh = _normalize_hash(data.get("binding_hash"))
    if bh is None:
        return None, None
    binding = ctx.emit_pathway.content_store.get(bh)
    if binding is None or binding.type != BINDING_TYPE:
        return bh, None
    return bh, binding


def _is_operator(ctx: HandlerContext) -> bool:
    """The operator is the registry peer acting on itself (a local-origin
    request). Fine-grained operator caps (``registry-issue-binding``) gate this
    at dispatch; here the self-origin check is the in-handler floor."""
    return ctx.remote_peer_id == ctx.local_peer_id


async def _handle_revoke_request(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9 ``:revoke-request`` — by the registrant (layer-1 proof by the
    binding's target_peer_id) or the operator. Emits a registry-signed §3.1
    revocation."""
    data = _params_data(params)
    bh, binding = _lookup_binding(ctx, data)
    if bh is None:
        return _error(400, "invalid_params", "revoke-request requires a binding_hash")
    if binding is None:
        return _error(404, "not_found", "no such binding")
    target_peer_id = binding.data.get("target_peer_id")
    req_hash = _request_hash(REVOKE_REQUEST_TYPE, data)
    if not (_is_operator(ctx) or _verify_proof_by(ctx, req_hash, target_peer_id)):
        return _error(403, "not_entitled", "revoke requires proof by the registrant or operator")
    rh = _emit_revocation(ctx, bh, data.get("reason"))
    return _ok("system/registry/revoke-result", {"revoked": True, "revocation_hash": rh})


async def _handle_renew_request(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9 ``:renew-request`` — re-issue with a fresh ttl, superseding the
    prior binding (supersedes-chain). Registrant-proof or operator."""
    data = _params_data(params)
    bh, binding = _lookup_binding(ctx, data)
    if bh is None:
        return _error(400, "invalid_params", "renew-request requires a binding_hash")
    if binding is None:
        return _error(404, "not_found", "no such binding")
    target_peer_id = binding.data.get("target_peer_id")
    req_hash = _request_hash(RENEW_REQUEST_TYPE, data)
    if not (_is_operator(ctx) or _verify_proof_by(ctx, req_hash, target_peer_id)):
        return _error(403, "not_entitled", "renew requires proof by the registrant or operator")
    policy = _load_issuer_policy(ctx)
    ttl = data.get("ttl")
    if not isinstance(ttl, int):
        ttl = policy.get("default_ttl") if policy else None
    new_bh = _issue_binding(
        ctx, binding.data.get("name"), target_peer_id,
        binding.data.get("transports") or [], ttl, supersedes=bh,
    )
    return _ok("system/registry/renew-result", {"binding_hash": new_bh})


async def _handle_approve_request(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9 ``:approve-request`` — operator approves a ``manual``-mode queued
    request, issuing the binding. Operator-only."""
    if not _is_operator(ctx):
        return _error(403, "not_entitled", "approve-request is operator-only")
    data = _params_data(params)
    ph = _normalize_hash(data.get("pending_hash"))
    if ph is None:
        return _error(400, "invalid_params", "approve-request requires a pending_hash")
    pending = ctx.emit_pathway.content_store.get(ph)
    if pending is None or pending.type != REGISTER_PENDING_TYPE:
        return _error(404, "not_found", "no such pending request")
    nfc_name = pending.data.get("name")
    if _name_is_taken(ctx, nfc_name):
        return _error(409, "name_taken", f"name {nfc_name!r} was taken since it was queued")
    bh = _issue_binding(
        ctx, nfc_name, pending.data.get("target_peer_id"),
        pending.data.get("transports") or [], pending.data.get("requested_ttl"),
    )
    # Dequeue the now-issued request (the body remains content-addressed/auditable).
    ctx.emit_pathway.entity_tree.remove(REGISTER_PENDING_PREFIX + ph.hex())
    return _ok("system/registry/register-result", {"status": "registered", "binding_hash": bh})


async def _handle_set_issuer_policy(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9.1 ``:set-issuer-policy`` — install/replace the registry's admission
    config (gated by ``registry-manage-issuer-policy``). Writing a policy is
    what turns a curated registry *live*."""
    data = _params_data(params)
    mode = data.get("mode")
    if mode not in ISSUER_MODES:
        return _error(400, "invalid_params", f"mode must be one of {sorted(ISSUER_MODES)}")
    policy = Entity(type=ISSUER_POLICY_TYPE, data={
        "mode": mode,
        "allowlist": data.get("allowlist"),
        "name_constraints": data.get("name_constraints"),
        "default_ttl": data.get("default_ttl"),
    })
    ctx.emit_pathway.emit(ISSUER_POLICY_PATH, policy, EmitContext.from_handler_grant(ctx, "configure"))
    return _ok("system/protocol/ack", {"configured": True, "mode": mode})


async def _handle_get_issuer_policy(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9.1 ``:get-issuer-policy`` — read the current policy (``mode: null``
    when the registry is curated/static)."""
    policy = _load_issuer_policy(ctx)
    if policy is None:
        return _ok(ISSUER_POLICY_TYPE, {"mode": None})
    return _ok(ISSUER_POLICY_TYPE, dict(policy))


async def registry_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Dispatch ``system/registry:*`` + ``system/registry/local-name:*`` ops
    (EXTENSION-REGISTRY v1.0)."""
    if operation == _OP_RESOLVE:
        return await _handle_resolve(ctx, params)
    if operation == _OP_INVALIDATE:
        return await _handle_invalidate_cache(ctx, params)
    if operation == _OP_BIND:
        return await _handle_bind(ctx, params)
    if operation == _OP_UNBIND:
        return await _handle_unbind(ctx, params)
    if operation == _OP_LIST:
        return await _handle_list(ctx, params)
    if operation == _OP_UPDATE_TRANSPORTS:
        return await _handle_update_transports(ctx, params)
    # §6a.9 live registration
    if operation == _OP_REGISTER:
        return await _handle_register_request(ctx, params)
    if operation == _OP_REVOKE:
        return await _handle_revoke_request(ctx, params)
    if operation == _OP_RENEW:
        return await _handle_renew_request(ctx, params)
    if operation == _OP_APPROVE:
        return await _handle_approve_request(ctx, params)
    if operation == _OP_SET_POLICY:
        return await _handle_set_issuer_policy(ctx, params)
    if operation == _OP_GET_POLICY:
        return await _handle_get_issuer_policy(ctx, params)
    return _error(
        404, "unknown_operation",
        f"system/registry has no operation {operation!r}",
    )
