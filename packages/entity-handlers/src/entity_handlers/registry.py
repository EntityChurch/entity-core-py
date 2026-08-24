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

import logging
import unicodedata
from typing import Any

from entity_core.capability.checking import check_handler_scope
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
# §6a.9.3 `[RULED 2026-08-13]`. This was our PROVISIONAL `register-pending` until
# the section landed; the note here tabulated four cohort postures and ended
# "this type renames with it." It renamed. Clean break, no alias — there is no
# old peer to stay compatible with, and a dual-name path is the drift the rename
# was for. The ruling ratified our body/pointer split and our `approve-request`
# and added the parts no one had built: the by-request pointer, the decision
# states, deny, supersession, retention.
PENDING_BINDING_TYPE = "system/registry/pending-binding"
NONCE_RECORD_TYPE = "system/registry/nonce-record"

ISSUER_POLICY_PATH = "system/registry/issuer-policy"
# §6a.9.3 storage, §6.3's body/pointer split exactly (the ruling is explicit that
# re-deriving the pattern here is how the two would drift):
#   body    — `pending/{pending_hash}`, immutable, content-addressed
#   pointer — `pending/by-request/{target_peer_id}/{name}`, the current head
# `target_peer_id` precedes `name` and the order is NORMATIVE: a peer-id is one
# Base58 segment but a name is not guaranteed single-segment, so the
# variable-depth value goes last or `by-request/{peer}/` stops being enumerable
# at a fixed depth.
PENDING_PREFIX = "system/registry/pending/"
PENDING_BY_REQUEST_PREFIX = "system/registry/pending/by-request/"
NONCE_PREFIX = "system/registry/nonce/"
# Revocation by-target index (P7 NORMATIVE): name → free once revoked.
REVOCATION_PREFIX = "system/registry/binding/revocation/"
REVOCATION_BY_TARGET_PREFIX = "system/registry/revocation/by-target/"

ISSUER_MODES = {"open", "allowlist", "manual", "domain-control"}

# §6a.9's ratified status table pins the layer-1 row as `401` + `signature_invalid`
# — status AND code, for every layer-1 site (register / revoke / renew). One
# constant rather than three literals: the three sites diverging is exactly the
# class of drift that let this one live.
#
# We answered `proof_failed` here until 2026-08-12, on an in-source note reading
# "the spec pins neither code; this converges on core-go". That was true when
# written and is now wrong twice over — the spec does pin it, and we matched go's
# *status* while diverging from go's *code*. Measured on the wire by core-go's
# `-category registry_issuer` at py `2c1aa1b` (three FAILs); arch retracted the
# ratification rationale that had claimed cohort convergence, since it was never
# verified against this tree.
#
# 401 and not 403: layer-1 is an *authentication* result — the requester failed to
# prove control of the key they are binding the name to. 403 `not_entitled` is the
# layer-2 answer (proof accepted, policy says no).
LAYER1_PROOF_ERROR_CODE = "signature_invalid"

# §6a.9's `register-result` `.status` — the two 2xx outcomes, `[MUST]`
# `[RULED 2026-08-12]`: `bound` on the 200 (binding issued, `binding_hash`
# present) and `pending_review` on the 202 (manual-mode queue, `pending_hash`
# present). Constants for the same reason as the layer-1 code above — `bound`
# has two emit sites (`register-request` approve and `approve-request`), and two
# literals is two places to drift.
#
# We answered `registered` on both until 2026-08-13. Nothing in the cohort caught
# it for a cycle: core-go emitted `registered` too, rust had already applied the
# ruling, and the cross-impl check for this path asserted the 200 and read the
# binding back without ever opening the result body. Our own wire test *did*
# assert `.status` — and pinned the wrong constant, so the assertion held the
# divergence in place rather than finding it. Measured by core-go's
# `registry_issuer.register_result_status_bound` at py `ad0ef98` (one FAIL).
#
# A value all three implementations quietly agreed on is not a value anyone
# checked; it is the branch where agreement stood in for the spec.
REGISTER_STATUS_BOUND = "bound"
REGISTER_STATUS_PENDING_REVIEW = "pending_review"
# §6a.9.3's decision table returns `register-result {status: "denied"}` from
# `deny-request`. NOTE the corpus conflict, routed rather than papered over:
# §6a.9's result-type block two screens up enumerates `"bound" | "pending_review"`
# and nothing else, so the section's own third outcome is undeclared in the type
# it returns — structurally the SAME defect §6a.9 recorded about itself in the
# 08-12 ruling ("an operation whose declared return type does not enumerate every
# branch of its own pseudocode is an interop bug already in flight"). We implement
# §6a.9.3's table: it is the later, more specific ruling and it is the one that
# defines deny at all. core-go filed this as gap 1 of spec-issues/2026-08-13-d.
REGISTER_STATUS_DENIED = "denied"

# §6a.9.3 pending-binding lifecycle. `pending_review` is live queue state;
# `approved` / `denied` are terminal and are what make deny not-a-delete.
PENDING_STATUS_APPROVED = "approved"
PENDING_STATUS_DENIED = "denied"
PENDING_DECIDED_STATUSES = frozenset({PENDING_STATUS_APPROVED, PENDING_STATUS_DENIED})

# §6a.9.3 — a second decision on a decided head. Approve and deny are not
# idempotent-by-replay: re-approving would mint a second binding for one request,
# and approving an already-denied one would overturn the operator by retry.
ALREADY_DECIDED_ERROR_CODE = "already_decided"

# §6a.9.3 retention `[SHOULD]`: a DECIDED head is GC-eligible once this much time
# has passed since it was queued; a `pending_review` head is NEVER eligible — it
# is live queue state, and expiring it silently drops a request no operator has
# seen (the deliver-or-signal violation that deny-is-not-a-delete already
# forbids). Only the tree entries are reclaimed; the body stays content-addressed
# and auditable, which is what the ruling means by "independently of the pointer."
#
# The window's CONFIGURATION SITE is not pinned by the ruling — it says "a
# configured retention window" and stops. A module default is the smallest thing
# that satisfies the SHOULD without inventing an issuer-policy field the other
# seats would not read.
PENDING_RETENTION_MS = 7 * 24 * 60 * 60 * 1000

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

# §4.1 step 2 [MUST, v1.14] — the kinds whose consultation puts the QUERIED
# NAME on the wire. The spec names exactly these four.
#
# **`peer-issued` is deliberately not here, and that is the v1.14 retarget.**
# The banned property is name transmission, not remoteness: §6a.4 resolution
# walks a signed root by content address, so a peer-issued read is remote and
# name-blind, and §4.1a row 6 *recommends* it in the catch-all. A check that
# asserted "no read against any remote registry" would fail the default list
# this spec ships (§11.1, `REG-DISPATCH-CATCHALL-LOCAL-1`, retargeted v1.14).
NAME_TRANSMITTING_KINDS = frozenset({
    "dns-txt", "well-known-url", "did-web", "consensus-anchored",
})

#: Last surfaced resolver-config hash, per peer — see `_surface_config_diagnostic`.
_last_surfaced_config: dict[str, bytes | None] = {}

# An **unscoped name** is a bare name carrying no explicit authority marker —
# `alice`, as opposed to `alice@example.com`, `alice.eth` or `did:web:alice`.
# These three bytes are the markers the spec's own §4.1a rows key on (`*@*.*`
# → DNS-style handles, `*.eth` → ENS, `did:web:*` → did:web).
_AUTHORITY_MARKERS = frozenset(".@:")

# trust_anchor variants (§2.4 — underscore enum form).
TA_SELF_CERTIFYING = "self_certifying"
TA_LOCAL_NAME = "local_name"
TA_OUT_OF_BAND = "out_of_band"

# §6a.9.1's internal sign-and-publish cap. §6a.9.3 reuses it verbatim as the
# gate on both operator decisions rather than minting a decision cap.
CAP_REGISTRY_ISSUE_BINDING = "system/capability/registry-issue-binding"

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
    CAP_REGISTRY_ISSUE_BINDING,
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
_OP_DENY = "deny-request"
_OP_SET_POLICY = "set-issuer-policy"
_OP_GET_POLICY = "get-issuer-policy"
# §4.3 [v1.18] resolver-config management, gated by registry-configure
_OP_SET_RESOLVER_CONFIG = "set-resolver-config"
_OP_GET_RESOLVER_CONFIG = "get-resolver-config"

SET_RESOLVER_CONFIG_REQUEST_TYPE = "system/registry/set-resolver-config-request"


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


def _pattern_reaches_unscoped_name(pattern: Any) -> bool:
    """Can this dispatch pattern match a name the user typed **bare** — with no
    authority they chose to disclose it to?

    A pattern is **scoped (narrow)** only when it requires one of the three
    shapes `§4.1a` ships as its non-catch-all rows, i.e. the shapes in which an
    authority is actually pinned:

    * an ``@``-authority anywhere — ``*@*``, ``*@*.*`` (rows 4-5): the *user*
      names the authority inside the name;
    * a ``:`` scheme prefix — ``did:web:*``, ``did:key:*`` (rows 1-2);
    * a dotted **literal** suffix — ``*.eth`` (row 3): the *rule* names the
      authority (ENS), and the star may not reach into it.

    Everything else is broad: the catch-all ``*``, a bare prefix ``a*``, a bare
    literal, and — the row worth stating — ``*.*``, whose suffix is a star and
    therefore pins no authority at all. This classifies §4.1a rows 1-5 narrow
    and row 6 broad, which is the fixture that matters: **the recommended
    default list contains the MUST, so a classifier that made row 3 broad would
    make the list this spec SHOULD-ships violate its own rule.**

    **Fail broad on anything unclassifiable** — `entity-browser-rust`'s
    `is_broad` argument, which the cohort has adopted: *"a pattern we cannot
    confidently classify is treated as broad, because calling a broad pattern
    narrow is what leaks."*

    **This is deliberately the conservative half of a live cross-impl
    divergence — see SA-PY-23.** Until 2026-08-19 this peer classified on a
    different and genuinely defensible argument: under the closed grammar every
    name a pattern matches carries all of the pattern's literal bytes, so a
    literal ``.``/``@``/``:`` anywhere means *every* match carries an authority
    marker, making ``*.*`` and ``a.b`` scoped. `entity-core-go` classifies both
    **broad**. §4.1a's default list cannot tell the two readings apart — every
    row it carries is classified identically by both — so the divergence is
    invisible to the one fixture the spec provides. We moved to the strictly
    larger broad-set, on §4.1's own asymmetry argument: the false positive is a
    visible edit with a documented override, and the false negative is
    ``my.private.handle`` and every dotted typo going to a third party.
    """
    if not isinstance(pattern, str):
        return True
    # An `@`-authority or a `:` scheme prefix: the name states where it goes.
    if "@" in pattern or ":" in pattern:
        return False
    # `*.<literal>` — one leading star, then a dotted literal suffix the star
    # cannot reach into. `*.*` does NOT qualify: its suffix is a star.
    if pattern.startswith("*."):
        rest = pattern[len("*."):]
        if rest and "*" not in rest:
            return False
    return True


def _disclosure_violations(config: dict[str, Any]) -> list[str]:
    """§4.1 step 2 `[MUST, v1.14]` — every way this config makes a
    **name-transmitting** backend eligible for an **unscoped** name. Returns
    one human-readable line per violation, **never just the first**: §4.3 says
    an operator repairing a chain wants the whole list, and a refusal that
    reports one violation at a time turns one edit into N round-trips.

    The rule binds **the configuration as a whole, not one row** (v1.14), and
    it has two doors:

    * **Door A — a rule whose pattern reaches unscoped names names the kind.**
    * **Door B — an absent or empty `name_format_dispatch` while such a kind
      sits in the `resolver_chain`.** The filter is disabled, every kind is
      eligible for every name, and there is no row to inspect.

    A third door — leaving the kind out of every rule so it "defaults to match
    all" — is closed **by construction** by the ruled `eligible_kinds` (see
    `_dispatch_allows`) and needs no clause here.

    **Door A is KIND-SCOPED `[MUST, v1.17]`** — a broad rule naming `did-web`
    violates whether or not the chain currently carries a `did-web` entry. We
    filed the opposite reading as SA-PY-21 and it was **ruled against us**; the
    deciding argument is worth carrying because it is not the one we argued.
    The MUST binds *a distribution*, and under the chain-scoped reading
    *"this shipped config is safe"* is not a property of the shipped artifact
    at all — it is a property of the artifact paired with whatever a downstream
    operator later adds to the chain, which the distribution cannot evaluate,
    cannot re-review, and (§1's bootstrap model) cannot reach again. **You
    cannot hold a party to a property they are structurally unable to
    evaluate.** Kind-scoped makes validity a function of `name_format_dispatch`
    alone — monotone under extension — so a reviewed artifact stays reviewed.
    *(Our own filed argument — that a chain-scoped config "arms silently" when
    the backend is added later — was recorded by arch as **not** the
    justification: whole-config validation at the write catches that edit under
    either reading. It is the monotonicity that decides it, not detectability.)*

    The set of name-transmitting kinds is **exactly the four §4.1 declares**;
    an unknown kind is not transmitting (§4.2), because refusing a config for
    naming a kind this build does not recognize would reject a deployment
    authored against a newer vocabulary — the case §4.2 exists to permit.
    """
    out: list[str] = []
    dispatch = config.get("name_format_dispatch") or []

    if not dispatch:
        for entry in config.get("resolver_chain") or []:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("backend_kind")
            if kind in NAME_TRANSMITTING_KINDS:
                out.append(
                    f"no name_format_dispatch, so the filter is disabled and "
                    f"{kind!r} in the resolver_chain is eligible for every "
                    f"unscoped name (§4.1 step 2, door B)"
                )
        return out

    for rule in dispatch:
        if not isinstance(rule, dict):
            continue
        if not _pattern_reaches_unscoped_name(rule.get("pattern")):
            continue
        for kind in rule.get("backend_kinds") or []:
            if kind in NAME_TRANSMITTING_KINDS:
                out.append(
                    f"dispatch pattern {rule.get('pattern')!r} matches unscoped "
                    f"names and names name-transmitting backend kind {kind!r} "
                    f"(§4.1 step 2, door A)"
                )
    return out


def _surface_config_diagnostic(
    peer_id: str, config_hash: bytes | None, violations: list[str],
) -> None:
    """§4.1 step 2 `[MUST, v1.17]` — **at load: surface it, never normalize it,
    never refuse to start.**

    This peer normalized at load until 2026-08-19 (narrowing the offending rows
    in the loaded view), on §11.1's *"refused or normalized at load"* — a
    sentence now **withdrawn**. Both halves of it were wrong, in opposite
    directions, and the argument is one to keep:

    * **Normalizing makes the operator's stored bytes lie.** The config says
      one thing and the peer does another, with no diagnostic. Ours narrowed
      only the in-memory view (never the stored entity), which is why the
      subtraction is small — but a silent behaviour change is the same defect
      whether or not it also corrupts the artifact.
    * **Refusing to start would delete the operator `MAY` granted in the same
      paragraph.** A peer that will not boot on a config the operator
      deliberately wrote has revoked the override it was given.

    The load path cannot do better than surface, because **at load the two acts
    are indistinguishable by construction**: §6a.9.2's store-first rule puts a
    distribution's seed and an operator's deliberate edit in the same entity at
    the same path. Provenance is a property of the *write*, so enforcement
    lives on `set-resolver-config` (§4.3) where an identified, capability-gated
    actor is present — and the out-of-band tree-write path stays open and
    *loud* rather than blocked.

    Deduped by config content hash so a per-resolution reload does not turn a
    diagnostic into a log flood — the same value repeated is not new
    information, and a diagnostic nobody can read is one nobody acts on. The
    dedup is keyed by **peer**, not module-wide: two peers in one process (the
    ordinary shape of an interop test) are two operators, and suppressing the
    second one's diagnostic because the first shares a config hash would make
    the surfacing MUST test green on a peer that never surfaced anything.
    """
    if config_hash is not None and _last_surfaced_config.get(peer_id) == config_hash:
        return
    _last_surfaced_config[peer_id] = config_hash
    logger.warning(
        "registry: the stored resolver-config discloses unscoped names to a "
        "name-transmitting backend (§4.1 step 2) — honored as written and "
        "surfaced, not normalized and not refused (§4.1 step 2 [MUST, v1.17]): "
        "%s",
        "; ".join(violations),
    )


def _load_resolver_config(ctx: HandlerContext) -> dict[str, Any]:
    """Load resolver-config, defaulting to local-name-only (§10) so the local
    local-name store is usable without explicit configuration (§5.2).

    `backend_id` is REQUIRED on every chain entry (arch ruling Q1). For the
    local-name single-store case (§6.2) it defaults to the local peer's
    identity; we fill that here at config-construction time so the effective
    config always carries it — whether the config is the synthesized default
    or a stored one that omitted it for the local-name backend.

    **The §4.1 step 2 privacy check does NOT run here — it surfaces here and
    binds at the write** (`set-resolver-config`, §4.3). This peer normalized on
    this path until 2026-08-19, when `[MUST, v1.17]` withdrew §11.1's *"refused
    or normalized at load"*: a load cannot distinguish a distribution's seed
    from an operator's deliberate edit (§6a.9.2 store-first puts both in one
    entity at one path), so load-time enforcement necessarily over-enforced and
    deleted the operator `MAY` in the same paragraph. What remains at load is
    the diagnostic — which is not nothing, because the out-of-band tree-write
    path carries no acknowledgement and a kind may have *become*
    name-transmitting since the config was written.

    The synthesized default is compliant by construction (local-name only, and
    local-name transmits nothing), so this is silent on an unconfigured peer.
    """
    cfg = _get_entity(ctx, RESOLVER_CONFIG_PATH)
    if cfg is not None and cfg.type == RESOLVER_CONFIG_TYPE:
        violations = _disclosure_violations(cfg.data)
        if violations:
            _surface_config_diagnostic(ctx.local_peer_id, cfg.compute_hash(), violations)
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


def _bundled(ctx: HandlerContext, h: bytes) -> Entity | None:
    """The entity at ``h`` from the request envelope's ``included`` map.

    **V7 §3.3 (v7.51) request-side included-preservation.** A `register-request`
    carries its layer-1 proof — the `system/peer` identity and the
    `system/signature` — bundled in `included`. On the *wire* path those are
    persisted on receipt (`_store_included_entities`, V7 §1.5) and so are
    reachable from the content store. On an **in-process dispatch there is no
    receive step**, and the bundle exists only as `ctx.included`. A lookup that
    reads the content store alone therefore answers "no proof supplied" for a
    perfectly well-formed request, and the caller sees `401 signature_invalid`
    — an authentication verdict on a request nobody failed to sign.

    That is why `ctx.included` is the map the other handlers already read
    (`capability.py`, `relay.py`, `identity.py`'s SI-11 ingestion); registry was
    the outlier, which is invisible while every caller is a CLI reaching a peer
    over a connection.

    **Strict entity fidelity (IMPLEMENTATION-SPEC §1.8): validate, then trust.**
    The map is keyed by hash but the key is the *sender's* claim, so an entity
    is returned only if it actually hashes to the key it was filed under.
    Skipping that would let a bundle name one entity and deliver another.
    """
    raw = (ctx.included or {}).get(h)
    if not isinstance(raw, dict):
        return None
    try:
        ent = Entity.from_dict(raw)
    except Exception:
        return None
    if ent.compute_hash() != h:
        return None
    return ent


def _entity_anywhere(ctx: HandlerContext, h: bytes) -> Entity | None:
    """Content store first, then the request's ``included`` bundle."""
    ent = ctx.emit_pathway.content_store.get(h)
    if ent is not None:
        return ent
    return _bundled(ctx, h)


def _resolve_pubkey(ctx: HandlerContext, signer_hash: bytes) -> tuple[bytes, str] | None:
    """Resolve a signer identity hash to ``(public_key, key_type)`` via the
    ``system/peer`` entity — content store or the request bundle."""
    peer = _entity_anywhere(ctx, signer_hash)
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
    ent = _entity_anywhere(ctx, signer_hash)
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


def _resolver_ceiling(entry: dict[str, Any] | None) -> int | None:
    """§6a.9.1 `[MUST, v1.16]` — the resolver's own local maximum, read from
    `resolver_chain[].hints.max_ttl` (ms), **per chain entry**.

    **This is the half that protects the consumer.** §6a.3's entire argument is
    about the consumer: a hostile byte-server withholds a revocation and `ttl`
    bounds the exposure. A ceiling the *registry* enforces cannot protect a
    consumer from that registry — a hostile issuer simply sets `max_ttl` high.
    Only the party bearing the risk can bound it. This is the split DNS settled
    decades ago: the authority sets the record's TTL, the resolver caps what it
    will honor.

    **The site was ours before it was the spec's, and filing it is what made
    it the spec's.** §4's `resolver-config` schema declared no ceiling field
    and v1.11's ruling named none — it said only *"a resolver MAY declare a
    local maximum"* — so this peer put it on `hints` (declared `<opaque
    object | null>`, backend-scoped, already carrying `neg_ttl`) rather than
    adding a top-level field that would move `system/registry/resolver-config`'s
    type hash for a name no other seat would read. Filed as **SA-PY-15** so
    the site got pinned rather than converged on by luck — and it did not
    converge by luck: four seats had put it in **three** places. **Ruled
    v1.16** at exactly this key, on this reasoning. (The filing also matters
    as a process fact: SA-PY-15 reached arch only inside `entity-core-go`'s
    cohort sweep, after arch had twice declared the registry board closed
    over it.)

    **It MUST be read at resolution, not latched** `[MUST, v1.16]` —
    `_load_resolver_config` runs per `_meta_resolve`, so an operator editing
    `resolver-config` is obeyed on a warm process. rust's argument, which is
    the one that decided it cohort-wide: a ceiling read at construction
    applies on a cold boot and silently does not on a warm one, and a security
    control present on one boot path and absent on the other tests green on
    whichever path the test happens to take.

    **A ceiling of `0` is dropped rather than honored** `[MUST, v1.16]`.
    Honored literally it expires every binding instantly and the operator sees
    *"no binding for this name"* — indistinguishable from a bad signature or a
    revocation. Ruled upheld for `entity-browser-rust` at `6927500`; all four
    implementing seats reached it independently before it was written down.
    """
    if not entry:
        return None
    ceiling = (entry.get("hints") or {}).get("max_ttl")
    if isinstance(ceiling, int) and not isinstance(ceiling, bool) and ceiling > 0:
        return ceiling
    return None


def _effective_lifetime(ttl: Any, local_max: int | None) -> int | None:
    """§6a.9.1 — the lifetime this resolver will honor, given a binding's own
    ``ttl`` and the chain entry's ceiling. **Three arms, and `min` supplies
    only two of them.**

    * no ceiling declared → the binding's `ttl`, untouched;
    * a ceiling and an int `ttl` → ``min(ttl, local_max)``;
    * a ceiling and **no** `ttl` → ``local_max`` `[MUST, v1.16]`.

    The third arm is the whole point of the rule and it is the one a guard
    written as ``if isinstance(ttl, int)`` silently skips: `min` over a null
    has no natural answer, so an implementation reaches for the guard and
    thereby applies the control **only where a bound already exists**, leaving
    the unbounded case — the sticky `local-name` / `pinned` kinds, which are
    the ones a resolver holds longest — uncovered. That inverts the control.
    (`peer-issued` never reaches this arm: §6a.4 requires a non-null `ttl`
    before a result is surfaced at all.)

    **One function, two call sites, by construction.** The lifetime is read in
    two places — the expiry verdict in `_validate` and the `ttl` surfaced to
    the consumer — and they must agree: a resolver that clamped only the
    surfaced number would still *honor* a binding past the ceiling, and one
    that clamped only the expiry check hands a caller a cache hint the
    resolver itself would not accept. Splitting them is the two-
    representations bug with an authorization decision on one side.
    """
    has_ttl = isinstance(ttl, int) and not isinstance(ttl, bool)
    if local_max is None:
        return ttl if has_ttl else None
    return min(ttl, local_max) if has_ttl else local_max


def _validate(
    ctx: HandlerContext,
    binding: Entity,
    trust_anchor: str,
    accepted: list[str],
    local_max_ttl: int | None = None,
) -> str | None:
    """Substrate validation (§2.2 ``validate(r)`` / §5). Returns a rejection
    ``reason`` string, or None if the binding is usable.

    ``local_max_ttl`` is the resolver's own ceiling (`_resolver_ceiling`). It
    bounds the **effective lifetime** used for the expiry check and is **never
    written back** into the binding — the binding's bytes and content hash are
    untouched, because this is a *use* bound and not a re-issue. A refactor
    that ever rewrote the binding to carry the clamped value would move its
    content address and every signature over it would stop verifying, which is
    why the enforcement point asserts the hash is byte-identical clamped and
    unclamped rather than asserting the clamped number.
    """
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
    # expires *absent a ceiling* (local-name / self-certifying) — under one it
    # takes `local_max` (§6a.9.1 v1.16). (REG-PEERISSUED-EXPIRED-1.)
    ttl = _effective_lifetime(binding.data.get("ttl"), local_max_ttl)
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

    # 3. the by-target revocation index (EXTENSION-REGISTRY §6a.6, normative)
    # — an O(1) index lookup, not a scan.
    #
    # This probe is the ONLY thing that can tell a revoked binding from a good
    # one: a revocation is a separate entity the registry publishes *after* the
    # binding, so the binding body carries no trace of it and a revoked binding
    # verifies, is in-date, and is signed by the pin. Skip the lookup and the
    # peer serves a revoked name while every other check passes
    # (REG-PEERISSUED-REVOKED-1). The revocation and its signature are pulled
    # into the local store so §6a.4's fail-closed exclusion runs in `_validate`
    # → `_is_revoked` — the same-authority check the precedes path already
    # gets, not a second implementation of it at the remote seam.
    rev_hash = await reader.tree_get(REVOCATION_BY_TARGET_PREFIX + binding_hash.hex())
    if rev_hash is not None:
        rev = await reader.content_get(rev_hash)
        if rev is not None and rev.type == REVOCATION_TYPE:
            ctx.emit_pathway.emit(
                REVOCATION_BY_TARGET_PREFIX + binding_hash.hex(), rev, emit_ctx,
            )
            rev_sig_hash = await reader.tree_get(f"system/signature/{rev_hash.hex()}")
            if rev_sig_hash is not None:
                rev_sig = await reader.content_get(rev_sig_hash)
                if rev_sig is not None and rev_sig.type == "system/signature":
                    ctx.emit_pathway.emit(f"system/signature/{rev_hash.hex()}", rev_sig, emit_ctx)

    # 4. cache the binding at the universal location (it becomes a precede).
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


def name_glob_match(pattern: str, name: str) -> bool:
    """`EXTENSION-REGISTRY` §4 — the **registry-local name matcher**, closed
    grammar `[MUST, REGISTRY v1.13]`, and **the ONLY one `[MUST, v1.15]`**.

    **Two call sites, one matcher, by mandate.** Every field in this extension
    that globs a user-facing name uses this function:
    `name_format_dispatch[].pattern` (§4) and the issuer policy's
    `name_constraints` (§6a.9.1). v1.13 closed the grammar and scoped it *"to
    this field"* — a sentence written to fence the matcher off from
    `ENTITY-CORE-PROTOCOL` §5.4, which it still does (below), and which fenced
    off `name_constraints` as collateral, leaving an **admission gate** with an
    undefined grammar. v1.15 removes that scoping: *"there is one matcher per
    registry."* We had already picked this one at `name_constraints` and filed
    the question as `SA-PY-14`; **the interim is the ruling** (arch `c984f93`).
    A second matcher over this domain diverges silently — the two fields sit
    two subsections apart, match the same flat name string in the same handler,
    and the one example the spec gave for each (`*.eth`, `*.lab`) is
    grammar-identical under every candidate reading, so nothing in the document
    discriminated them. `entity-core-rust` was measured on a shell-glob at
    `name_constraints` on 2026-08-19 and owes the landing.

    `*` matches any run of characters including none; **every other byte is a
    literal** — `?`, `[`, `]`, `\\`, `.`, `:`, `@` and `/` match only
    themselves. Any number of `*` is permitted (`*@*.*` is three and is row 4
    of §4.1a). `/` is **not** a separator: a name is a flat string with no
    segment structure, so `x*z` matches `x/y/z`. The match is anchored at both
    ends; there is no substring form.

    **The `/`-crossing property is pinned in-tree and NOT on the wire**, in
    both of its §11.1 rows (`REG-DISPATCH-GRAMMAR-1`, and
    `REG-NAME-CONSTRAINTS-GRAMMAR-1` row 3): §6.3 forbids `/` in a name and
    `_validate_name_path_safety` runs *before* admission, so no registerable
    name can carry a `/` for the `*` to cross. Same disposition as
    `entity-core-go`, whose spec-issue `2026-08-19-b` routes it upstream.

    **This delegates to no library, deliberately.** `fnmatch` (what this was
    until the v1.13 ruling) and Go's `path.Match` both give `?` and `[…]`
    character-class meaning this grammar does not grant, and most stop `*` at a
    `/`. *A matcher that merely omits those features and one that treats them
    as literals are indistinguishable until a pattern carries one* — the same
    argument that made `**` a rejection rather than an omission in
    `EXTENSION-REVISION` §2.4, transplanted to a grammar where nothing is
    rejected at all.

    **No pattern is invalid here**, and that is a real difference from
    REVISION's four forms: every string is well-formed because every non-`*`
    byte is a literal, so a registry MUST NOT refuse a pattern for carrying
    `?`, `[` or `\\`. There is no write-time validator to pair with this.

    **Not `ENTITY-CORE-PROTOCOL` §5.4** (§4 states it outright): §5.4 governs
    *paths*, where trailing `/*` is a subtree match and a leading `/*/` strips
    a peer segment. A name has neither. Two matchers, two domains, and neither
    confers a reading on the other.

    Two-pointer greedy rather than a regex: it is the whole algorithm in
    fifteen lines, it cannot backtrack pathologically on a pattern like
    `*a*a*a*`, and it borrows no semantics from a regex dialect.
    """
    p = n = 0
    star = -1          # index in `pattern` of the most recent `*`
    resume = 0         # index in `name` to resume from when we backtrack to it
    while n < len(name):
        if p < len(pattern) and pattern[p] == name[n]:
            p += 1
            n += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            resume = n
            p += 1
        elif star >= 0:
            # Mismatch under an open `*` — let it swallow one more byte. `/`
            # is not special, so this is where `x*z` reaches across `x/y/z`.
            p = star + 1
            resume += 1
            n = resume
        else:
            return False
    # Trailing `*`s may match the empty run; anything else must be consumed.
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def _dispatch_allows(
    config: dict[str, Any], name: str, backend_kind: str,
) -> bool:
    """§4.1 step 2 — the `name_format_dispatch` filter. **RULED 2026-08-19**
    (arch `6378606`, spec `86643f8`, REGISTRY 1.14). **Eligibility is a pure
    function of the name**, and this is that function:

    ```
    eligible_kinds(config, name):
      rules := config.name_format_dispatch
      if rules is absent or empty:  return ALL          ; filter disabled
      matched := [ r for r in rules if match(r.pattern, name) ]
      return union( r.backend_kinds for r in matched )  ; EMPTY if none matched
    ; consult entry IFF entry.backend_kind ∈ eligible_kinds(config, name)
    ```

    **A kind reaches eligibility only by being named.** No per-backend default,
    no "match all" for a kind named nowhere, and no fallback when nothing
    matches — that is the empty set, and the chain reports `chain_exhausted`
    (§4.1 step 4, fail-closed). Row order is irrelevant; the union is order-free
    and `resolver_chain[].priority` carries all the precedence (§4: this is a
    *filter, not a routing table* — evaluation does not stop at the first hit).

    **Nobody misread the spec and nobody won.** The paragraph answered the same
    question twice, differently: one sentence set-valued, the next per-backend.
    The per-backend sentence was a **category error** — rules name
    `backend_kinds`, not backends, so *"a backend without an entry"* had no
    referent — and it is deleted, not reworded. Three seats reached three
    behaviours from it; each changed exactly one branch.

    | Edge case | go had | rust had | py had | **ruled** |
    |---|---|---|---|---|
    | A — kind named by **no** entry, another entry matches | excluded | consulted | excluded | **excluded** |
    | B — kind named by an entry, **no** entry matches the name | consulted | excluded | excluded | **excluded** → `chain_exhausted` |

    **`SA-PY-17`'s row-A analysis is adopted as the ruling's rationale** — that
    a kind named in *no* row being consulted anyway makes §4.1a's privacy MUST
    evadable by leaving a row out. The catch-all sentence we and go had both
    implemented as *"no filtering"* (*"a name matching no entry is treated as
    matching the catch-all"*) is removed: the catch-all is `*`, which matches
    every name, so with one configured no name fails to match and without one
    the sentence names a row with no referent. *"No filtering"* is the one
    meaning it cannot carry — the catch-all is the most **restrictive** row in
    §4.1a's recommended list.

    This peer arrived here in two steps and only the first was argued at the
    time: case A changed on the privacy argument, and case B **rode along in
    the same commit** before being justified on its own (`c74f95e`). See
    `AGENTS.md` — an oracle failure that makes you change behaviour is a claim
    about the rows it names, not about the rows the same edit happens to touch.
    """
    dispatch = config.get("name_format_dispatch") or []
    if not dispatch:
        return True
    for entry in dispatch:
        if backend_kind not in (entry.get("backend_kinds") or []):
            continue
        if name_glob_match(entry.get("pattern", ""), name):
            return True
    return False


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

        # The resolver's own ceiling (§6a.9.1 v1.16) — applied to the expiry
        # check AND to the `ttl` surfaced to the consumer, through the one
        # `_effective_lifetime` so the two cannot drift, so a caller caching on
        # the returned value inherits the same bound. Never written into
        # `binding`: `result["binding"]` stays the unclamped content hash.
        local_max = _resolver_ceiling(entry)
        reason = _validate(ctx, binding, result["trust_anchor"], accepted, local_max)
        if reason is not None:
            last_reason = reason
            continue  # failed validation; try next (§2.2)
        result["ttl"] = _effective_lifetime(result.get("ttl"), local_max)
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
    lands in the content store, not the tree — **except on an in-process
    dispatch, where there is no receive step and the bundle is only
    ``ctx.included``.** See :func:`_bundled`."""
    sig = _find_signature_for(ctx, target_hash)
    if sig is not None:
        return sig
    for _h, ent in ctx.emit_pathway.content_store.iter_all():
        if ent.type != "system/signature":
            continue
        if _normalize_hash(ent.data.get("target")) == target_hash:
            return ent
    for h in (ctx.included or {}):
        ent = _bundled(ctx, h)
        if ent is None or ent.type != "system/signature":
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


def _clamp_to_policy_ceiling(ttl: int, policy: dict[str, Any] | None) -> int:
    """§6a.9.1 `[MUST, v1.11]` — `effective = min(resolved, policy.max_ttl)`.

    **Clamped, not refused**, and the reason is §6a.9.2's own: refusing bills a
    well-formed request for a policy the requester cannot read, and teaches
    requesters to probe for the ceiling. The clamp is silent to the requester by
    design — the issued binding carries the clamped value, which is signed,
    published and readable, so the disclosure is in the artifact rather than in
    the response.

    An absent `max_ttl` does not clamp. `set-issuer-policy` refuses to store a
    live policy without one, so the only way to reach this is a policy seeded
    out-of-band — and the spec pins no fail-closed answer for the ceiling the
    way it does for a null `ttl` (§6a.9's D12 backstop). Inventing a refusal
    here would be the implementation-chosen default that same paragraph
    forbids, one field over.
    """
    if policy is None:
        return ttl
    ceiling = policy.get("max_ttl")
    if isinstance(ceiling, int) and not isinstance(ceiling, bool) and ceiling > 0:
        return min(ttl, ceiling)
    return ttl


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


# -- §6a.9.3 pending-binding storage ---------------------------------------


def _pending_body_path(ph: bytes) -> str:
    return PENDING_PREFIX + ph.hex()


def _pending_pointer_path(target_peer_id: str, nfc_name: str) -> str:
    return f"{PENDING_BY_REQUEST_PREFIX}{target_peer_id}/{nfc_name}"


def _write_pending_head(ctx: HandlerContext, pending: Entity) -> bytes:
    """Publish a pending-binding as the head for its (target_peer_id, name):
    immutable body + repointed by-request pointer. Returns its hash.

    This is the whole of §6a.9.3's supersession rule — a second queued request
    for the same pair writes a new body and repoints, so exactly one head
    exists per pair. Replace-whole, never merge; same rule and same reason as
    §6a.9.2's policy write. Superseded bodies stay at their own paths on
    purpose: they are content-addressed audit, and `_load_pending_head` is what
    stops them being decidable."""
    ph = pending.compute_hash()
    emit_ctx = EmitContext.from_handler_grant(ctx, "register")
    ctx.emit_pathway.emit(_pending_body_path(ph), pending, emit_ctx)
    ctx.emit_pathway.emit(
        _pending_pointer_path(pending.data["target_peer_id"], pending.data["name"]),
        pending, emit_ctx,
    )
    return ph


def _load_pending_head(
    ctx: HandlerContext, ph: bytes,
) -> tuple[Entity | None, bool]:
    """Resolve a `pending_hash` to ``(entity, is_head)``.

    ``is_head`` is the half §6a.9.3 does not spell out and the one a decision
    MUST check. Supersession repoints the pointer but deliberately leaves the
    old body fetchable forever, so a stale `pending_review` body stays
    resolvable indefinitely. Deciding one would issue a binding on terms the
    operator's queue no longer shows AND leave the pointer naming a different
    head than the one decided — an inconsistency no later read can untangle.
    "One pending head per pair" is a rule about what is DECIDABLE, not only
    about what is listed.

    Requires the body to be published at its OWN path, not merely present in
    the content store: anything content-addressed is `get`-able, and a
    pending-binding that was never emitted here was never queued here."""
    stored = _normalize_hash(ctx.emit_pathway.entity_tree.get(_pending_body_path(ph)))
    if stored != ph:
        return None, False
    ent = ctx.emit_pathway.content_store.get(ph)
    if ent is None or ent.type != PENDING_BINDING_TYPE:
        return None, False
    head = _normalize_hash(ctx.emit_pathway.entity_tree.get(
        _pending_pointer_path(ent.data.get("target_peer_id"), ent.data.get("name"))
    ))
    return ent, head == ph


def _gc_decided_pending(ctx: HandlerContext) -> None:
    """§6a.9.3 retention `[SHOULD]` — reclaim decided heads past the window.

    Drops the tree entries only; the body remains content-addressed and
    auditable, which is the ruling's "independently of the pointer". A
    `pending_review` head is never eligible at any age. Swept opportunistically
    when a request queues rather than on a timer — a MUST-write paired with an
    unbounded queue is a leak by construction, and this keeps the queue an
    operator's inbox rather than a log without adding a background task."""
    cutoff = _now_ms() - PENDING_RETENTION_MS
    for path in list(ctx.emit_pathway.entity_tree.list_prefix(PENDING_BY_REQUEST_PREFIX)):
        h = _normalize_hash(ctx.emit_pathway.entity_tree.get(path))
        if h is None:
            continue
        ent = ctx.emit_pathway.content_store.get(h)
        if ent is None or ent.type != PENDING_BINDING_TYPE:
            continue
        if ent.data.get("status") not in PENDING_DECIDED_STATUSES:
            continue
        queued_at = ent.data.get("queued_at")
        if not isinstance(queued_at, int) or queued_at > cutoff:
            continue
        ctx.emit_pathway.entity_tree.remove(path)
        ctx.emit_pathway.entity_tree.remove(_pending_body_path(h))


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
        # §6a.9 layer-1 row: 401 + `signature_invalid` (see
        # LAYER1_PROOF_ERROR_CODE for why the code moved).
        return _error(
            401, LAYER1_PROOF_ERROR_CODE,
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
    #
    # The matcher is §4's registry-local name matcher — **RULED [MUST, v1.15]**
    # (arch `c984f93`; `SA-PY-14` closed, our interim adopted as the ruling).
    # §6a.9.1 declared the field as `<glob | null>` and defined the glob
    # nowhere, and v1.13's "scoped to this field" read §4's grammar out of
    # reach; we picked the one matcher this extension defines, over the same
    # domain, rather than a stdlib whose rules no reading sanctions. It was
    # `fnmatch` until the v1.13 ruling landed one field away, and `fnmatch`
    # grants `?` and `[…]` meaning nothing in the corpus grants anywhere.
    #
    # This is an **admission gate**: it decides `403 not_entitled` versus a
    # signed, published binding, so two registries running the same operator
    # policy admitted different names. The discriminating rows live in
    # `test_registry_ttl_and_dispatch_grammar.py::TestNameConstraintsGrammar`
    # and they are asserted HERE rather than only at the matcher, because the
    # defect this closes was a *call site* pointed at the wrong function while
    # the matcher itself was correct.
    constraint = policy.get("name_constraints")
    if isinstance(constraint, str) and not name_glob_match(constraint, nfc_name):
        return _error(403, "not_entitled", f"name {name!r} not permitted by name_constraints")

    # TTL resolution runs BEFORE the manual-mode branch on purpose: the queued
    # head records the terms the operator is being asked to approve, so an
    # approval weeks later issues *those* terms rather than whatever the policy
    # default happens to be at approval time.
    ttl = data.get("requested_ttl")
    if not isinstance(ttl, int):
        ttl = policy.get("default_ttl")

    # D12 (§6a.9 [MUST]) — fail closed when the *stored* policy is already bad.
    # D11 above binds `set-issuer-policy`; it cannot reach a policy seeded
    # out-of-band by a CLI flag, written straight to the tree, or predating the
    # rule — all three of which §6a.9.2's store-first resolution admits. So the
    # backstop lives here, and it refuses **before** both the manual queue and
    # the direct-issue path: "MUST publish nothing" means no binding *and* no
    # queue entry.
    #
    # It MUST NOT substitute an implementation-chosen default either. That is
    # the same mistake §6a.9.2 rejects one level up, where `get-issuer-policy`
    # MUST NOT synthesize a default `open` — it turns an operator's omission
    # into a silently-invented policy. On a security-relevant field it is
    # worse: two registries would answer identically-stored policies with
    # different binding lifetimes, a §5.10 determinism split the operator never
    # sees.
    if ttl is None:
        return _error(
            403, "policy_rejected",
            "resolved ttl is null: the request omitted requested_ttl and the stored "
            "issuer policy defines no default_ttl. Refusing rather than minting a "
            "null-ttl binding (§6a.3, unresolvable per §6a.4) or substituting an "
            "implementation-chosen default (§6a.9 D12). Set default_ttl on the "
            "issuer policy.",
        )

    # The ceiling applies AFTER the cascade resolves (§6a.9.1 v1.11), and
    # before the manual queue: the queued head records the terms the operator
    # is being asked to approve, so it must record the clamped ones.
    ttl = _clamp_to_policy_ceiling(ttl, policy)

    # Layer-2 — name entitlement.
    if mode == "manual":
        # Queue for operator review; record the nonce (the request is processed).
        _record_nonce(ctx, target_peer_id, nonce, issued_at)
        _gc_decided_pending(ctx)
        # Supersedes any existing head for this (target_peer_id, name) — every
        # retry carries a fresh nonce and is a distinct request by construction,
        # so without this one intent fills the operator's queue with duplicates.
        pending = Entity(type=PENDING_BINDING_TYPE, data={
            "name": nfc_name,
            "target_peer_id": target_peer_id,
            "transports": data.get("transports") or [],
            "requested_ttl": ttl,
            "queued_at": _now_ms(),
            "status": REGISTER_STATUS_PENDING_REVIEW,
        })
        ph = _write_pending_head(ctx, pending)
        # 202, not 200: the request was accepted for review, not acted on. A
        # 200 says "done" for an operation whose entire point is that nothing
        # was signed. The in-source note here read "the spec pins the body but
        # not the code; this converges on core-go" until 2026-08-13 — the
        # ruling's status table now pins the 202 outright, so this is
        # conformance, not convergence.
        return _ok(
            "system/registry/register-result",
            {"status": REGISTER_STATUS_PENDING_REVIEW, "pending_hash": ph},
            status=202,
        )

    if mode == "allowlist":
        allow = policy.get("allowlist") or []
        if target_peer_id not in allow:
            return _error(403, "not_entitled", f"{target_peer_id} is not on the registry allowlist")

    # open + allowlist(passed): first-come on a free name.
    if _name_is_taken(ctx, nfc_name):
        return _error(409, "name_taken", f"name {name!r} is already bound")

    _record_nonce(ctx, target_peer_id, nonce, issued_at)
    bh = _issue_binding(ctx, nfc_name, target_peer_id, data.get("transports") or [], ttl)
    return _ok(
        "system/registry/register-result",
        {"status": REGISTER_STATUS_BOUND, "binding_hash": bh},
    )


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
        # §6a.9 layer-1 row, same as register above: 401 + `signature_invalid`.
        # We answered 403 `not_entitled` here — the layer-2 code — for a
        # layer-1 failure until 9ac97bb, which is the same conflation 4cdf805
        # unpicked on register. Absent proof is an authentication result;
        # "policy says no" is the 403.
        return _error(
            401, LAYER1_PROOF_ERROR_CODE,
            "revoke-request is not signed by target_peer_id or the operator "
            "(§6a.9 layer-1)",
        )
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
        # 401 `signature_invalid` — see the revoke path; §6a.9 makes renew
        # "Signed by target_peer_id (layer-1)", same class, same answer.
        return _error(
            401, LAYER1_PROOF_ERROR_CODE,
            "renew-request is not signed by target_peer_id or the operator "
            "(§6a.9 layer-1)",
        )
    policy = _load_issuer_policy(ctx)

    # §6a.9.1's three-step cascade `[MUST, v1.9]`. `renew-request` is the
    # SECOND producer of peer-issued bindings and the null-ttl rules above
    # swept only `register-request`, so this path minted the exact binding
    # §6a.3 forbids without needing a bad policy at all: a CURATED registry
    # (no policy entity, which §6a.9.2 makes conformant) has no `default_ttl`
    # to fall back on. Filed from this tree as SA-PY-13; ruled at v1.9-v1.11.
    #
    #   1. the request's own `ttl`
    #   2. the policy's `default_ttl` — current operator intent outranks
    #      history, so an operator who lowers it sees renewals pick it up
    #   3. the SUPERSEDED binding's `ttl`
    #
    # Step 3 is a recovery, not an invented default, and that distinction is
    # the whole ruling: a synthesized number would have two registries answer
    # identically-stored policies differently, while the predecessor's `ttl` is
    # this registry's own prior signed act on this exact name — one value,
    # already published, byte-identical at every conformant peer.
    ttl = data.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        ttl = policy.get("default_ttl") if policy else None
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        ttl = binding.data.get("ttl")

    # The cascade is NOT total `[MUST, v1.10]`. Step 3 is non-null *on every
    # conformant mint path*, which is not the same as non-null — a predecessor
    # carrying `ttl: null` can be already there, seeded out-of-band or written
    # straight to the tree, the identical "stored state is already bad" case
    # D12 exists for. v1.9 asserted the branch unreachable; an implementation
    # that merely guards the dereference falls through and mints the null-ttl
    # successor the whole rule set exists to prevent. So it is enforced, not
    # asserted, and it is required precisely because nothing conformant reaches
    # it. Vector: REG-RENEW-TTL-NULLPRED-1.
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        return _error(
            403, "policy_rejected",
            "renew resolved no ttl: the request omitted it, the stored issuer "
            "policy defines no default_ttl, and the superseded binding carries "
            "ttl: null — which §6a.3 forbids and no conformant mint path "
            "produces. Refusing rather than minting a null-ttl successor or "
            "substituting a default (§6a.9.1 v1.10). Publishing nothing.",
        )

    ttl = _clamp_to_policy_ceiling(ttl, policy)
    new_bh = _issue_binding(
        ctx, binding.data.get("name"), target_peer_id,
        binding.data.get("transports") or [], ttl, supersedes=bh,
    )
    return _ok("system/registry/renew-result", {"binding_hash": new_bh})


def _load_for_decision(
    ctx: HandlerContext, op: str, params: dict[str, Any],
) -> tuple[Entity | None, bytes | None, dict[str, Any] | None]:
    """Shared front half of `approve-request` / `deny-request` (§6a.9.3).

    Returns ``(pending, pending_hash, error)`` — exactly one of the first pair
    or the last is meaningful.

    Gate: ``system/capability/registry-issue-binding``, the cap §6a.9.1 already
    defines for the internal sign-and-publish act. No new capability —
    approving a queued request IS issuing a binding, and minting a second cap
    for one act would let an operator hold either half alone.

    This replaced a self-origin floor (``_is_operator``) that predated the
    ruling and was wrong in a way only a cross-impl run could show: it made the
    ruled capability **undelegable**. Gating on origin means the registry
    operator must BE the registry process, so a capability whose entire purpose
    is handing operator authority to someone else could never be exercised by
    that someone else. core-go's oracle drives approve/deny as a remote client
    holding the cap and got `403 not_entitled` from us on all four decision
    vectors. Origin is not authority; the grant is."""
    cap = ctx.caller_capability if isinstance(ctx.caller_capability, dict) else {}
    cap_data = cap.get("data") if isinstance(cap.get("data"), dict) else cap
    if not check_handler_scope(cap_data, REGISTRY_HANDLER_PATTERN, op, ctx.local_peer_id):
        return None, None, _error(
            403, "not_entitled",
            f"{op} requires {CAP_REGISTRY_ISSUE_BINDING} (§6a.9.3)",
        )
    data = _params_data(params)
    ph = _normalize_hash(data.get("pending_hash"))
    if ph is None:
        return None, None, _error(400, "invalid_params", f"{op} requires a pending_hash")

    pending, is_head = _load_pending_head(ctx, ph)
    if pending is None:
        return None, None, _error(
            404, "not_found", f"no pending-binding is published at {_pending_body_path(ph)}",
        )
    if not is_head:
        # §6a.9.3 pins `404 not_found` for "names no stored pending-binding" and
        # pins NOTHING for "names a superseded one" — a case its own supersession
        # rule creates. Reusing the pinned code with a message that names
        # supersession beats inventing a cohort-divergent one; core-go reached
        # the same answer independently and routed it as gap 3 of
        # spec-issues/2026-08-13-d.
        return None, None, _error(
            404, "not_found",
            f"pending-binding {ph.hex()} is no longer the head for "
            f"({pending.data.get('target_peer_id')}, {pending.data.get('name')!r}) — a later "
            "register-request superseded it (§6a.9.3, one head per pair), or its retention "
            "window elapsed; the body remains for audit but is not decidable",
        )
    if pending.data.get("status") in PENDING_DECIDED_STATUSES:
        # Checked BEFORE name_taken so a replayed approve of an already-approved
        # request reports what actually happened rather than blaming the name it
        # bound itself.
        return None, None, _error(
            409, ALREADY_DECIDED_ERROR_CODE,
            f"pending request is already {pending.data.get('status')!r} — approve and deny "
            "are not idempotent-by-replay (§6a.9.3)",
        )
    return pending, ph, None


def _decided_body(pending: Entity, status: str, **extra: Any) -> Entity:
    """The next body in a pending-binding's life: same request fields, new
    terminal status. A decision writes a NEW immutable body and repoints — it
    does not mutate, and (§6a.9.3 `[MUST]`) it does not delete."""
    data = dict(pending.data)
    data["status"] = status
    data.update(extra)
    return Entity(type=PENDING_BINDING_TYPE, data=data)


async def _handle_approve_request(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9.3 ``:approve-request`` — the operator issues a queued request's
    binding, leaving an ``approved`` head that carries the binding_hash."""
    pending, ph, err = _load_for_decision(ctx, _OP_APPROVE, params)
    if err is not None:
        return err
    nfc_name = pending.data.get("name")
    if _name_is_taken(ctx, nfc_name):
        # The queue is not a reservation (§6a.9.3 [MUST]) — issuing anyway would
        # silently overwrite whoever took the name between queue and approval.
        return _error(409, "name_taken", f"name {nfc_name!r} was taken since it was queued")
    bh = _issue_binding(
        ctx, nfc_name, pending.data.get("target_peer_id"),
        pending.data.get("transports") or [], pending.data.get("requested_ttl"),
    )
    # Approve does NOT remove the head. Our pre-§6a.9.3 path dequeued it here;
    # the ruling calls that out as the one place our shape was not ratified. A
    # requester polling a vanished pointer cannot tell *decided* from *never
    # received*, which is a silent drop the substrate floor forbids.
    _write_pending_head(ctx, _decided_body(
        pending, PENDING_STATUS_APPROVED, binding_hash=bh,
    ))
    return _ok(
        "system/registry/register-result",
        {"status": REGISTER_STATUS_BOUND, "binding_hash": bh},
    )


async def _handle_deny_request(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9.3 ``:deny-request`` — the operator refuses a queued request.
    Nothing is signed and nothing is published; a ``denied`` head is left
    reachable through the by-request pointer, because deny is not a delete."""
    pending, ph, err = _load_for_decision(ctx, _OP_DENY, params)
    if err is not None:
        return err
    reason = _params_data(params).get("reason")
    extra: dict[str, Any] = {}
    if isinstance(reason, str):
        # Operator-supplied, never parsed (§6a.9.3).
        extra["reason"] = reason
    _write_pending_head(ctx, _decided_body(pending, PENDING_STATUS_DENIED, **extra))
    return _ok(
        "system/registry/register-result",
        {"status": REGISTER_STATUS_DENIED},
    )


async def _handle_set_issuer_policy(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9.2 ``:set-issuer-policy`` — install/replace the registry's admission
    config (gated by ``registry-manage-issuer-policy``). Writing a policy is
    what turns a curated registry *live*.

    **Replace-whole, not merge** [MUST]: every optional field is read from this
    request and an absent one means *unset*, never *unchanged* — a merge would
    make the resulting policy depend on write order, which two peers cannot
    reconstruct. Returns the stored policy as written (§6a.9.2 table)."""
    data = _params_data(params)
    mode = data.get("mode")
    if mode not in ISSUER_MODES:
        return _error(400, "invalid_params", f"mode must be one of {sorted(ISSUER_MODES)}")
    if mode == "domain-control":
        # §6a.9.2 [MUST]: the challenge format is deferred to the web-native
        # domain-proof co-design (§6a.9.1), so refuse to *store* a policy the
        # registry could not enforce rather than accept it and reject later.
        return _error(
            400, "unsupported_mode",
            "domain-control is deferred (§6a.9.1) until the challenge format lands "
            "— use open/allowlist/manual",
        )
    # D11 (§6a.9.2 [MUST]) — a live-registration policy MUST define
    # `default_ttl`. Every mode still standing here (open / allowlist /
    # manual) can reach *approve*, and a request omitting `requested_ttl`
    # against a policy with no default resolves to a **null** ttl — a binding
    # §6a.3 forbids and no conformant resolver honors (§6a.4). Refuse rather
    # than storing a policy that can only mint invalid bindings: the same move
    # as the domain-control refusal one branch up, for the same stated reason.
    #
    # The gate is *here*, not on the requester's register-request, because
    # this is where the missing input lives — `default_ttl` is the operator's
    # field on the operator's operation. Billing the requester for the
    # registry's own misconfiguration would teach clients to send
    # `requested_ttl` defensively, handing TTL selection to the party §6a.1a
    # treats as untrusted.
    if data.get("default_ttl") is None:
        return _error(
            400, "invalid_params",
            "a live-registration issuer policy MUST define default_ttl: a request "
            "omitting requested_ttl would otherwise mint a null-ttl binding, which "
            "§6a.3 forbids and §6a.4 makes unresolvable. Set default_ttl rather than "
            "storing a policy that can only mint invalid bindings (§6a.9.2 D11).",
        )
    # The ceiling `[MUST, v1.11]` — same trigger, same site and the same stated
    # reason as `default_ttl` one branch up: it is the operator's field on the
    # operator's operation, and this is where the missing input lives.
    #
    # §6a.3 makes `ttl` the ONLY bound on a withheld revocation, so a
    # requester-chosen `ttl` with nothing capping it reproduces the permanently
    # unrevokable binding that rule exists to prevent — without ever setting the
    # field to null, which is why D11 did not already catch it.
    max_ttl = data.get("max_ttl")
    if not isinstance(max_ttl, int) or isinstance(max_ttl, bool):
        return _error(
            400, "invalid_params",
            "a live-registration issuer policy MUST define max_ttl (ms): §6a.3 makes "
            "ttl the only bound on a withheld revocation, so an uncapped "
            "requester-chosen ttl is a binding that cannot be revoked in practice "
            "(§6a.9.1 v1.11). Requests above the ceiling are clamped, not refused.",
        )
    if data["default_ttl"] > max_ttl:
        return _error(
            400, "invalid_params",
            f"default_ttl ({data['default_ttl']}ms) MUST NOT exceed max_ttl "
            f"({max_ttl}ms) — a default above the ceiling is a policy whose own "
            "unstated-ttl path is immediately clamped (§6a.9.1 v1.11).",
        )
    stored = {
        "mode": mode,
        "allowlist": data.get("allowlist"),
        "name_constraints": data.get("name_constraints"),
        "default_ttl": data.get("default_ttl"),
        "max_ttl": max_ttl,
    }
    policy = Entity(type=ISSUER_POLICY_TYPE, data=stored)
    ctx.emit_pathway.emit(ISSUER_POLICY_PATH, policy, EmitContext.from_handler_grant(ctx, "configure"))
    return _ok(ISSUER_POLICY_TYPE, dict(stored))


async def _handle_get_issuer_policy(ctx: HandlerContext, params: dict[str, Any]) -> dict[str, Any]:
    """§6a.9.2 ``:get-issuer-policy`` — read the stored policy.

    **Unset is not a mode** [MUST]: with no policy entity stored this registry
    is a conformant curated-only one (§6a.8) that does not run live
    registration, so this returns ``404 not_found``. Synthesizing a default
    ``open`` would silently turn a curated registry into first-come-first-serve.
    """
    policy = _load_issuer_policy(ctx)
    if policy is None:
        return _error(
            404, "not_found",
            "no issuer-policy is stored — this registry is curated-only (§6a.8) "
            "and does not run live registration",
        )
    return _ok(ISSUER_POLICY_TYPE, dict(policy))


async def _handle_set_resolver_config(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """§4.3 ``:set-resolver-config`` `[v1.18]` — store the resolver-config,
    gated by ``system/capability/registry-configure``.

    **The operation exists because the capability named an act the corpus never
    defined.** `registry-configure` was declared as a bare tree-write against
    `system/registry/resolver-config`, so §4.1 step 2's write-time MUST had no
    surface to bind to, there was nowhere for an operator override to live, and
    `REG-TTL-CEILING-REREAD-1` was not constructible — a config surface with no
    write operation cannot be validated, cannot be rebound, and cannot be
    conformance-driven at all. Identical hole to `registry-manage-issuer-policy`
    before §6a.9.2, one entity over.

    Three MUSTs, and each has a row in the vector:

    * **Validate the WHOLE config before storing**, not the delta — §4.1 step 2
      against every rule and every chain entry.
    * **No partial application.** On refusal nothing is written and a following
      `get-resolver-config` returns the previous bytes unchanged. Here that is
      structural rather than compensated: the single `emit` happens after the
      check, so there is no half-applied state to unwind.
    * **`acknowledge_name_disclosure` is the operator `MAY`, made
      expressible** — absent or `false` refuses a violating config `403
      policy_rejected` **with the full violation list**; `true` stores it, and
      every subsequent load surfaces the disclosure.

    **The acknowledgement is a parameter of this operation and MUST NOT become
    a field of the config entity.** A field is written by whoever writes the
    bytes — so a distribution could set it and defeat the rule that bounds it —
    and it would move a content-addressed type's hash to carry a claim it
    cannot secure. Provenance is a property of the **act**, so it rides the
    capability-gated call by an identified actor, which is exactly the thing a
    stored byte cannot be. This is also the whole reason load-time enforcement
    could never honor the `MAY`.
    """
    data = _params_data(params)
    raw_config = data.get("config")
    if not isinstance(raw_config, dict):
        return _error(
            400, "invalid_params",
            "set-resolver-config requires a `config` entity "
            f"({RESOLVER_CONFIG_TYPE}) — §4.3",
        )
    if raw_config.get("type") != RESOLVER_CONFIG_TYPE:
        return _error(
            400, "invalid_params",
            f"config MUST be a {RESOLVER_CONFIG_TYPE} entity, got "
            f"{raw_config.get('type')!r}",
        )
    config_data = raw_config.get("data")
    if not isinstance(config_data, dict):
        return _error(400, "invalid_params", "config.data must be a map")

    config = Entity(type=RESOLVER_CONFIG_TYPE, data=config_data)
    # A caller-supplied hash is a claim about bytes we are about to store under
    # our own name (§1.8): validate it or drop it, never carry it unchecked.
    claimed = _normalize_hash(raw_config.get("content_hash"))
    if claimed is not None and claimed != config.compute_hash():
        return _error(
            400, "invalid_params",
            "config.content_hash does not match ECF({type, data}) — refusing "
            "to store bytes under a hash the caller asserted (§1.8)",
        )

    violations = _disclosure_violations(config_data)
    acknowledged = data.get("acknowledge_name_disclosure") is True
    if violations and not acknowledged:
        return _error(
            403, "policy_rejected",
            "this resolver-config would make a name-transmitting backend "
            "eligible for an unscoped name (§4.1 step 2) — set "
            "acknowledge_name_disclosure to store it deliberately. Violations: "
            + "; ".join(violations),
            violations=violations,
        )

    ctx.emit_pathway.emit(
        RESOLVER_CONFIG_PATH, config, EmitContext.from_handler_grant(ctx, "configure"),
    )
    return _ok(RESOLVER_CONFIG_TYPE, dict(config_data))


async def _handle_get_resolver_config(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """§4.3 ``:get-resolver-config`` `[v1.18]` — the stored config, as written,
    or `404 not_found` when unset. Takes no params (§3.2 empty-params shape).

    **Unset is not empty, and it is not the default either.** `_load_resolver_config`
    synthesizes a local-name-only chain so an unconfigured peer resolves its own
    local-names (§10) — returning *that* here would report a config the operator
    never wrote and would make a `set` → `get` round-trip unverifiable against
    a peer that stored nothing. Same call as `get-issuer-policy`'s: reading back
    a synthesized default is how a peer tells an operator their write landed
    when it did not.
    """
    stored = _get_entity(ctx, RESOLVER_CONFIG_PATH)
    if stored is None or stored.type != RESOLVER_CONFIG_TYPE:
        return _error(
            404, "not_found",
            "no resolver-config is stored (§4.3) — this peer runs the §10 "
            "local-name-only default, which is not a stored configuration",
        )
    return _ok(RESOLVER_CONFIG_TYPE, dict(stored.data))


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
    if operation == _OP_DENY:
        return await _handle_deny_request(ctx, params)
    if operation == _OP_SET_POLICY:
        return await _handle_set_issuer_policy(ctx, params)
    if operation == _OP_GET_POLICY:
        return await _handle_get_issuer_policy(ctx, params)
    # §4.3 resolver-config management
    if operation == _OP_SET_RESOLVER_CONFIG:
        return await _handle_set_resolver_config(ctx, params)
    if operation == _OP_GET_RESOLVER_CONFIG:
        return await _handle_get_resolver_config(ctx, params)
    return _error(
        404, "unknown_operation",
        f"system/registry has no operation {operation!r}",
    )
