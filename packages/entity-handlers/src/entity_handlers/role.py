"""EXTENSION-ROLE v1.6 — named grant bundles + context-scoped exclusion.

Role definitions are entities at `system/role/{context}/{role_name}` whose
`grants` field bundles capability grant entries. Assigning a peer to a role
issues capability tokens derived from the role's grants (with template
variables resolved). Excluding a peer from a context denies access within
that context: layer 1 sweeps role-derived tokens; layer 2 blocks new
derivation.

Operations (per EXTENSION-ROLE.md §4):
  - define     — write a role definition (RL2 at definition-write time, IA11);
                 cascades through `re-derive` (§5.5).
  - assign     — bind peer to role; derive role-derived tokens (RL1, RL2);
                 layer-2 exclusion check blocks excluded assignees.
  - unassign   — remove assignment + revoke that role's role-derived token
                 via the per-assignment linkage entity at the
                 sibling `derived-tokens/` subtree (IA12, SI-5).
  - exclude    — write exclusion entity + sweep all role-derived tokens
                 for (context, peer) (R7 layer 1, broad sweep per SI-7) +
                 block new derivation (R7 layer 2).
  - unexclude  — remove exclusion entity (re-assignment required to restore
                 access; previously-revoked tokens are not restored).
  - re-derive  — re-issue role-derived tokens for all assignments of a role
                 with ordered writes (T_new before T_old revocation, IA9);
                 honors per-assignee layer-2 exclusion check; per SI-15,
                 mid-cascade RL2 failures are skipped (skip-and-continue),
                 not aborted, and reported via `skipped_grantees`.
                 Delivery: tree-sync (T_new lands at the spec-pinned
                 role-derived storage path; assignees discover it via
                 standard tree-sync from the issuing peer or via
                 subscription on `system/capability/grants/role-derived/
                 {context}/{peer_id_hex}/*`).
  - delegate   — member-to-member delegation (IA22) — RL2 against the
                 delegator's role grants (not the operational key's);
                 cap is rooted at the delegator's runtime peer (granter
                 = local peer's identity); persisted at the role-derived
                 path so `unassign`, `exclude`, and `re-derive` reach it.
                 Locality invariant per SI-19: `:delegate` MUST run on
                 the delegator's own runtime peer (returns 400, not 403,
                 when the delegator segment doesn't match the local
                 peer). Scope is literal per SI-20.

Side machinery:
  - RoleExtension                       — fleet-wide reactive sweep
                                          (§6.5 IA8) when exclusion
                                          entities arrive via tree-sync;
                                          IA11 option (b) re-derive
                                          cascade when role definitions
                                          are mutated by direct
                                          `tree:put` rather than via
                                          `:define`.
  - startup_time_role_derived_token     — L0 SDK helper (§4.5 IA13) for
                                          issuing root caps BEFORE the
                                          role handler is registered.
                                          Skips RL2; honors layer-2
                                          exclusion check; produces
                                          `parent: None` root caps per
                                          V7 §5.5. Raises RuntimeError
                                          if invoked after registration
                                          (SI-12 conformance).

Path encoding (per v1.6 SI-1, SI-2, SI-8). All non-root path segments
encoding peer references — assignment, exclusion, role-derived,
derived-tokens, delegations — use **lowercase hex of `system/hash`** of
the peer's `system/identity` entity (NOT Base58 PeerID). Base58 is
reserved for the universal-root segment (V7 §1.4) and for the body
field of `system/identity` entities (V7 §3.5). The cap's `grantee`
field carries the same value as raw bytes (V7 §3.6); the handler reads
it directly from the path segment via `bytes.fromhex(...)`. No
PeerID-to-hash resolver, no type-index walk.

Linkage entity (per v1.6 SI-5). Each assignment is paired with a
`system/role/derived-token-link` entity at the sibling subtree
`system/role/{context}/derived-tokens/{peer_id_hex}/{role_name}`
referencing `{token_hash, issued_at}`. `unassign` reads it to revoke
the specific role's token (multi-role-aware, R6); `re-derive` rewrites
it to point at T_new before revoking T_old. Multiple linkage entities
per (peer, role) tuple are possible during re-derive overlap; tie-break
by `issued_at` desc (per SI-22).

Capability discipline (per v1.6 SI-10). The role handler is the
canonical entry point for role-namespace writes. There is no kernel
content-validation hook; capabilities are the only enforcement on raw
`system/tree:put`. Deployments wanting cascade through the role handler
MUST NOT grant raw `system/tree:put` on `system/role/*` paths to
entities that would write outside the handler. The RoleExtension
provides defense-in-depth by observing direct-`tree:put` arrivals and
triggering the equivalent cascade — but this is OPTIONAL (per
EXTENSION-ROLE.md v1.6 §4 intro), not the conformance baseline.

Terminology (per v1.6 SI-28). "Bootstrap" has been retired. The L0-time
peer-owner setup before handler registration is **startup-time L0
access** (§4.5); the first-contact cap-derivation policy is **initial
grant policy** (§4.7), with three modes: anonymous-allow,
anonymous-deny, recognize-on-attestation.
"""

from __future__ import annotations

import copy
from typing import Any

from entity_core.capability.delegation import grant_covered_by
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.auth import (
    create_identity_entity,
    create_signature_entity,
)
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import ChangeEvent, ChangeKind, EmitContext, EmitPathway
from entity_core.utils.path import invariant_signature_path
from entity_handlers._common import (
    error_response as _error,
    now_ms as _now_ms,
    ok_response as _ok,
    params_data as _params_data,
    resource_target as _resource_target,
)


# -- Constants --------------------------------------------------------------

ROLE_TYPE = "system/role"
ROLE_ASSIGNMENT_TYPE = "system/role/assignment"
ROLE_EXCLUSION_TYPE = "system/role/exclusion"
ROLE_DERIVED_TOKEN_LINK_TYPE = "system/role/derived-token-link"
ROLE_HANDLER_PATTERN = "system/role"

ROLE_PREFIX = "system/role/"
ROLE_DERIVED_PREFIX = "system/capability/grants/role-derived/"

# Path-segment markers used to tell role-definition / assignment / exclusion
# / derived-tokens subpaths apart. `assignment` and `excluded` are reserved
# role names per §3.2 R10; `derived-tokens` is reserved per SI-5 (v1.6).
_ASSIGNMENT_SEG = "assignment"
_EXCLUDED_SEG = "excluded"
_DERIVED_TOKENS_SEG = "derived-tokens"
RESERVED_ROLE_NAMES = frozenset({
    _ASSIGNMENT_SEG, _EXCLUDED_SEG, _DERIVED_TOKENS_SEG,
})

# Operations
_OP_DEFINE = "define"
_OP_ASSIGN = "assign"
_OP_UNASSIGN = "unassign"
_OP_EXCLUDE = "exclude"
_OP_UNEXCLUDE = "unexclude"
_OP_RE_DERIVE = "re-derive"
_OP_DELEGATE = "delegate"
_OP_STARTUP = "startup-time"
_OP_FLEET_SWEEP = "fleet-sweep"

# Path reservation per SI-26 (renamed from "bootstrap-policy" per SI-28).
INITIAL_GRANT_POLICY_PATH = "system/role/initial-grant-policy"
INITIAL_GRANT_POLICY_TYPE = "system/role/initial-grant-policy"

# Initial-grant-policy modes (§4.7).
INITIAL_GRANT_MODE_ANONYMOUS_DENY = "anonymous-deny"
INITIAL_GRANT_MODE_ANONYMOUS_ALLOW = "anonymous-allow"
INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION = "recognize-on-attestation"
INITIAL_GRANT_MODES = frozenset({
    INITIAL_GRANT_MODE_ANONYMOUS_DENY,
    INITIAL_GRANT_MODE_ANONYMOUS_ALLOW,
    INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
})


def _is_zero_hex_hash(peer_id_hex: str) -> bool:
    """Return True iff `peer_id_hex` decodes to a hash whose digest is
    all-zeros. SEC-18 / V7 v7.39 PR-3: the zero hash never resolves to a
    real `system/peer` entity (no keypair hashes to zero), so a cap with
    `grantee: zero-hash` is unusable by construction. Rejecting at mint
    time surfaces the error to the issuer instead of leaving a dud cap
    bound (PR-3 chain-walk would later return `unresolvable_grantee 401`,
    but the assign appears successful in the meantime).

    Tolerates a missing 0x00 algorithm prefix — the hex may be 64 chars
    (digest only) or 66 chars (algorithm + digest). Either way, the
    digest portion being all zeros is the diagnostic."""
    try:
        raw = bytes.fromhex(peer_id_hex)
    except ValueError:
        return False
    if not raw:
        return False
    return all(b == 0 for b in raw)


def _normalize_peer_id_hex(value: Any) -> str | None:
    """Normalize a peer-identity reference to lowercase hex of the
    `system/identity` content_hash (the canonical form used in role
    storage paths).

    Accepts:
    - bytes: a 33-byte `system/hash` value (algorithm + 32-byte digest)
      per V7 / EXTENSION-ATTESTATION wire form. Returns its lowercase
      hex.
    - str: an already-hex form (validated for hex characters; returned
      lowercase). Backward compat / human-friendly tooling.
    - dict: legacy `{algorithm, digest}` shape — flattens to bytes then
      hex-encodes.

    Returns None on any other input or on malformed values.
    """
    if isinstance(value, bytes):
        if not value:
            return None
        return value.hex()
    if isinstance(value, dict):
        algorithm = value.get("algorithm")
        digest = value.get("digest")
        if isinstance(algorithm, int) and isinstance(digest, bytes):
            return (bytes([algorithm]) + digest).hex()
        return None
    if isinstance(value, str):
        if not value:
            return None
        # Validate hex; reject anything that wouldn't round-trip.
        try:
            bytes.fromhex(value)
        except ValueError:
            return None
        return value.lower()
    return None


# =============================================================================
# Expiry inheritance — EXTENSION-ROLE v1.7 §5.3 (SI-29 MIN_DEFINED)
# =============================================================================


def _min_defined(*values: int | None) -> int | None:
    """Return MIN over the defined (non-None) values; None if all are None."""
    defined = [v for v in values if v is not None]
    return min(defined) if defined else None


def _role_metadata_ttl(role_def: Entity | None) -> int | None:
    """Read `role.metadata.ttl` (ms duration) if present.

    Per §5.3 item 3: a role MAY declare a default lifetime via
    `metadata.ttl`. Returns the integer TTL or None.
    """
    if role_def is None:
        return None
    md = role_def.data.get("metadata") if isinstance(role_def.data, dict) else None
    if not isinstance(md, dict):
        return None
    ttl = md.get("ttl")
    if isinstance(ttl, int) and not isinstance(ttl, bool):
        return ttl
    return None


def _capability_expires_at(capability: Any) -> int | None:
    """Extract `expires_at` from a capability, accepting either
    `{data: {expires_at}}` or bare `{expires_at}`."""
    if not isinstance(capability, dict):
        return None
    if "data" in capability and isinstance(capability["data"], dict):
        v = capability["data"].get("expires_at")
    else:
        v = capability.get("expires_at")
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _parent_cap_expires(ctx: HandlerContext) -> int | None:
    """`expires_at` of the parent cap for role-derived caps.

    For runtime derivation the parent IS the role handler's grant, so we
    read from `ctx.handler_grant`. For startup-time L0 derivation the
    parent is None (root cap) and this helper isn't called.
    """
    return _capability_expires_at(getattr(ctx, "handler_grant", None))


def _caller_cap_expires(ctx: HandlerContext) -> int | None:
    """`expires_at` of the caller's capability."""
    return _capability_expires_at(getattr(ctx, "caller_capability", None))


def _effective_expires_at(
    *,
    parent_expires: int | None,
    role_ttl: int | None,
    caller_expires: int | None,
    now_ms: int | None = None,
) -> int | None:
    """v1.7 §5.3: `MIN_DEFINED(parent.expires_at, now+role.ttl,
    caller.expires_at)` over only the defined sources.

    Item 3 (`role.ttl`) is a duration — converted to absolute by
    adding `now_ms` (default: current time). Items 1 (parent) and 4
    (caller) are already absolute. Returns None when all sources are
    undefined (the cap inherits no expiry).
    """
    role_absolute: int | None = None
    if role_ttl is not None:
        base = now_ms if now_ms is not None else _now_ms()
        role_absolute = base + role_ttl
    return _min_defined(parent_expires, role_absolute, caller_expires)


# =============================================================================
# Path helpers — peer-relative form + decomposition
# =============================================================================


def _peer_relative(path: str, local_peer_id: str) -> str:
    """Strip leading peer-id prefix to yield a peer-relative path.

    Accepts entity://peer/..., /peer/..., peer/..., and already-relative
    forms. The result begins at the path component immediately after the
    peer-id segment (e.g. `system/role/...`).
    """
    if path.startswith("entity://"):
        path = path[len("entity://"):]
    if path.startswith("/"):
        path = path[1:]
    if path.startswith(f"{local_peer_id}/"):
        path = path[len(local_peer_id) + 1:]
    return path


def role_definition_path(context: str, role_name: str) -> str:
    return f"{ROLE_PREFIX}{context}/{role_name}"


def role_assignment_path(
    context: str, peer_id_hex: str, role_name: str,
) -> str:
    """`{peer_id_hex}` is lowercase hex of `system/hash` of the assignee's
    `system/identity` entity (per v1.6 SI-1)."""
    return (
        f"{ROLE_PREFIX}{context}/{_ASSIGNMENT_SEG}/{peer_id_hex}/{role_name}"
    )


def role_exclusion_path(context: str, peer_id_hex: str) -> str:
    return f"{ROLE_PREFIX}{context}/{_EXCLUDED_SEG}/{peer_id_hex}"


def role_derived_token_path(
    context: str, peer_id_hex: str, token_hash: bytes,
) -> str:
    return (
        f"{ROLE_DERIVED_PREFIX}{context}/{peer_id_hex}/{token_hash.hex()}"
    )


def role_derived_token_link_path(
    context: str, peer_id_hex: str, role_name: str,
) -> str:
    """Linkage entity location per SI-5: sibling subtree (NOT nested under
    the entity-bearing assignment path).

    Stored at: `system/role/{context}/derived-tokens/{peer_id_hex}/{role_name}`.

    The entity at this path is of type `system/role/derived-token-link`
    (see SI-5 §2.4) and references the role-derived cap's content hash
    plus its issuance timestamp (the latter for tie-breaking when
    re-derive overlap leaves multiple linkage entities, per §6.5 SI-22).
    """
    return (
        f"{ROLE_PREFIX}{context}/{_DERIVED_TOKENS_SEG}"
        f"/{peer_id_hex}/{role_name}"
    )


def parse_role_definition_path(
    path: str, local_peer_id: str,
) -> tuple[str, str] | None:
    """Decompose a role-definition resource path.

    Returns (context, role_name) or None when malformed. Rejects paths
    that include the reserved `/assignment/`, `/excluded/`, or
    `/derived-tokens/` subtrees, or whose final segment uses a reserved
    role name (R10 + SI-5).
    """
    rel = _peer_relative(path, local_peer_id)
    if not rel.startswith(ROLE_PREFIX):
        return None
    rest = rel[len(ROLE_PREFIX):]
    if not rest:
        return None
    # Bail out if the path references the assignment / excluded /
    # derived-tokens subtree (decomposed by their dedicated parsers).
    if (
        f"/{_ASSIGNMENT_SEG}/" in rest
        or f"/{_EXCLUDED_SEG}/" in rest
        or f"/{_DERIVED_TOKENS_SEG}/" in rest
    ):
        return None
    last_slash = rest.rfind("/")
    if last_slash <= 0:
        return None
    context = rest[:last_slash]
    role_name = rest[last_slash + 1:]
    if not context or not role_name:
        return None
    if role_name in RESERVED_ROLE_NAMES:
        return None
    return (context, role_name)


def parse_assignment_path(
    path: str, local_peer_id: str,
) -> tuple[str, str, str] | None:
    """Decompose `system/role/{context}/assignment/{peer_id_hex}/{role_name}`.

    Returns (context, peer_id_hex, role_name) or None when malformed.
    `peer_id_hex` is lowercase hex of `system/hash` of the assignee's
    `system/identity` entity (per v1.6 SI-1).
    """
    rel = _peer_relative(path, local_peer_id)
    if not rel.startswith(ROLE_PREFIX):
        return None
    rest = rel[len(ROLE_PREFIX):]
    marker = f"/{_ASSIGNMENT_SEG}/"
    idx = rest.find(marker)
    if idx <= 0:
        return None
    context = rest[:idx]
    after = rest[idx + len(marker):]
    parts = after.split("/", 1)
    if len(parts) != 2:
        return None
    peer_id_hex, role_name = parts[0], parts[1]
    if not context or not peer_id_hex or not role_name:
        return None
    # role_name segment must not contain further slashes — rejects
    # nested-subpath forms so direct-as-resource use can't accidentally
    # point at something other than an assignment entity.
    if "/" in role_name:
        return None
    return (context, peer_id_hex, role_name)


def parse_assignment_peer_path(
    path: str, local_peer_id: str,
) -> tuple[str, str] | None:
    """Decompose `system/role/{context}/assignment/{peer_id_hex}` (no
    trailing role segment).

    Returns (context, peer_id_hex) or None when malformed. This is the
    per-peer (all-roles) form the unassign op supports per §4.4 — callers
    SHOULD try `parse_assignment_path` first (specific role) and fall
    back to this.

    Rejects the role-bearing form `.../{peer_id_hex}/{role_name}` so the
    two parsers carve up the path space cleanly.
    """
    rel = _peer_relative(path, local_peer_id)
    if not rel.startswith(ROLE_PREFIX):
        return None
    rest = rel[len(ROLE_PREFIX):]
    marker = f"/{_ASSIGNMENT_SEG}/"
    idx = rest.find(marker)
    if idx <= 0:
        return None
    context = rest[:idx]
    after = rest[idx + len(marker):]
    if not context or not after:
        return None
    # Reject the role-bearing form — that's parse_assignment_path's job.
    if "/" in after:
        return None
    return (context, after)


def parse_exclusion_path(
    path: str, local_peer_id: str,
) -> tuple[str, str] | None:
    """Decompose `system/role/{context}/excluded/{peer_id_hex}`.

    Returns (context, peer_id_hex) or None when malformed.
    """
    rel = _peer_relative(path, local_peer_id)
    if not rel.startswith(ROLE_PREFIX):
        return None
    rest = rel[len(ROLE_PREFIX):]
    marker = f"/{_EXCLUDED_SEG}/"
    idx = rest.find(marker)
    if idx <= 0:
        return None
    context = rest[:idx]
    peer_id_hex = rest[idx + len(marker):]
    if not context or not peer_id_hex:
        return None
    if "/" in peer_id_hex:
        return None
    return (context, peer_id_hex)


# =============================================================================
# Template resolution — §5.2
# =============================================================================


def resolve_templates(
    grant_entry: dict[str, Any],
    variables: dict[str, str],
) -> dict[str, Any]:
    """Substitute `{context}` / `{peer_id}` in handler & resource scopes.

    Pure textual substitution (§5.2). The role spec resolves templates in
    handler and resource path values; constraints, allowances, operations,
    and peer scopes are left unchanged. Returns a new dict; the input is
    not mutated.
    """
    out = copy.deepcopy(grant_entry)
    for dim in ("handlers", "resources"):
        scope = out.get(dim)
        if not isinstance(scope, dict):
            continue
        for side in ("include", "exclude"):
            patterns = scope.get(side)
            if not isinstance(patterns, list):
                continue
            for i, pat in enumerate(patterns):
                if not isinstance(pat, str):
                    continue
                for var_name, var_value in variables.items():
                    pat = pat.replace("{" + var_name + "}", var_value)
                patterns[i] = pat
    return out


# =============================================================================
# Capability extraction (handles both wrapped and unwrapped shapes)
# =============================================================================


def _capability_grants(capability: Any) -> list[dict[str, Any]]:
    """Extract the grants list from a capability entity or capability data.

    Accepts either `{type, data: {grants: [...]}}` or a bare
    `{grants: [...]}` form (the latter is what HandlerContext.caller_capability
    stores).
    """
    if not isinstance(capability, dict):
        return []
    if "data" in capability and isinstance(capability["data"], dict):
        grants = capability["data"].get("grants")
    else:
        grants = capability.get("grants")
    return grants if isinstance(grants, list) else []


# =============================================================================
# Layer-2 exclusion check — §6.2
# =============================================================================


def is_excluded(
    context: str, peer_id_hex: str, ctx: HandlerContext,
) -> bool:
    """True iff an exclusion entity exists at the context's exclusion path.

    Single tree read per check. Shared across `assign` (R7 layer 2) and
    `exclude` (R7 layer 1) sweep flows. `peer_id_hex` is hex of the peer's
    `system/identity` content_hash (per v1.6 SI-1).
    """
    return ctx.emit_pathway.entity_tree.get(
        role_exclusion_path(context, peer_id_hex)
    ) is not None


# =============================================================================
# Layer-1 exclusion sweep — §6.1, §6.4.1
# =============================================================================


def _sweep_role_derived_paths(
    pathway: EmitPathway,
    context: str,
    peer_id_hex: str,
    *,
    emit_ctx: EmitContext,
) -> list[bytes]:
    """Delete all role-derived tokens for (context, peer_id_hex).

    Pure-pathway form: takes an EmitPathway and an EmitContext directly,
    so the same helper can be reused from a HandlerContext-bearing op
    AND from extension code that has no HandlerContext (fleet-wide sweep,
    startup-time recovery).

    Returns the list of revoked token hashes (the previous bindings).
    Used by `exclude` (layer-1 sweep, §6.1), `unassign` (IA12 §6.4.1
    selective form falls back to this when the linkage entity is
    missing), and the RoleExtension fleet-wide sweep (§6.5 IA8).
    """
    tree = pathway.entity_tree
    prefix = f"{ROLE_DERIVED_PREFIX}{context}/{peer_id_hex}/"
    full_prefix = tree.normalize_uri(prefix)
    revoked: list[bytes] = []
    for full_uri in list(tree.list_prefix(prefix)):
        if not full_uri.startswith(full_prefix):
            continue
        # Skip signature side-files (revoked alongside their cap below).
        if full_uri.endswith("/signature"):
            continue
        prev = tree.get(full_uri)
        if prev is not None:
            revoked.append(prev)
        pathway.delete(full_uri, emit_ctx)
        # Unbind the cap's signature at the V7 §3.5 invariant pointer
        # path (signer = local/minting peer, target = the cap hash
        # `prev`). The legacy `{full_uri}/signature` sibling is gone.
        if prev is not None:
            sig_uri = invariant_signature_path(tree.local_peer_id, prev)
            if tree.get(sig_uri) is not None:
                pathway.delete(sig_uri, emit_ctx)
    return revoked


def _sweep_role_derived_tokens(
    ctx: HandlerContext,
    context: str,
    peer_id_hex: str,
    operation: str,
) -> list[bytes]:
    """HandlerContext wrapper for the pathway-only sweep helper."""
    return _sweep_role_derived_paths(
        ctx.emit_pathway,
        context,
        peer_id_hex,
        emit_ctx=EmitContext.from_handler_grant(ctx, operation),
    )


def _revoke_token_at_role_derived_path(
    pathway: EmitPathway,
    context: str,
    peer_id_hex: str,
    token_hash: bytes,
    *,
    emit_ctx: EmitContext,
) -> bool:
    """Revoke a single token by hash. Returns True if the binding was
    found and removed, False otherwise.

    Used by selective `unassign` (via the linkage entity per SI-5) and
    by `re-derive` to revoke T_old after T_new has been issued.
    """
    storage_path = role_derived_token_path(context, peer_id_hex, token_hash)
    if pathway.entity_tree.get(storage_path) is None:
        return False
    pathway.delete(storage_path, emit_ctx)
    # The role-derived cap's signature now lives at the V7 §3.5 invariant
    # pointer path (signer = the minting/local peer, target = the cap
    # hash), not the removed `{storage_path}/signature` sibling. Unbind it
    # there so revocation does not leak the signature.
    sig_path = invariant_signature_path(
        pathway.entity_tree.local_peer_id, token_hash,
    )
    if pathway.entity_tree.get(sig_path) is not None:
        pathway.delete(sig_path, emit_ctx)
    return True


def _rollback_role_derived_cap(
    pathway: EmitPathway,
    *,
    context: str,
    peer_id_hex: str,
    token_hash: bytes,
    role_name: str | None,
    assignment_path: str | None,
    emit_ctx: EmitContext,
) -> None:
    """PR-2 (v2.0 §6.6): roll back a freshly-issued role-derived cap when
    a concurrent `:exclude` lands during an `:assign` / `:re-derive`
    per-assignee leg / `:delegate` target — the canonical SEC-2 fix.

    Removes the cap and its signature unconditionally. The linkage
    entity is removed only when this flow wrote one (assign/re-derive
    over the assignee's own role-derived path); the delegation flow
    passes `role_name=None` because it doesn't write a linkage entity
    for the delegate. The assignment entity is removed only on the
    `:assign` path, which owns it.
    """
    _revoke_token_at_role_derived_path(
        pathway, context, peer_id_hex, token_hash, emit_ctx=emit_ctx,
    )
    if role_name is not None:
        link_path = role_derived_token_link_path(context, peer_id_hex, role_name)
        if pathway.entity_tree.get(link_path) is not None:
            pathway.delete(link_path, emit_ctx)
    if assignment_path is not None and pathway.entity_tree.get(assignment_path) is not None:
        pathway.delete(assignment_path, emit_ctx)


# =============================================================================
# Token issuance — §5.1
# =============================================================================


def _issue_role_derived_token(
    ctx: HandlerContext,
    context: str,
    assignee_peer_id_hex: str,
    derived_grants: list[dict[str, Any]],
    *,
    parent_hash: bytes | None,
    expires_at: int | None,
    operation: str,
) -> bytes:
    """HandlerContext wrapper around `_issue_role_derived_token_pathway`.

    Per SI-1 + SI-8 (v1.6): the storage-path peer segment AND the cap's
    `grantee` field both encode the same value — the `system/hash` of
    the assignee's `system/identity` entity. The path holds it as
    lowercase hex; the cap holds it as raw bytes (`bytes.fromhex(...)`).
    No identity lookup, no PeerID-to-hash resolution: the path segment
    IS the hash.
    """
    if ctx.keypair is None:
        raise RuntimeError(
            "role handler requires keypair access to mint role-derived caps",
        )
    return _issue_role_derived_token_pathway(
        ctx.emit_pathway,
        ctx.keypair,
        context=context,
        assignee_peer_id_hex=assignee_peer_id_hex,
        derived_grants=derived_grants,
        parent_hash=parent_hash,
        expires_at=expires_at,
        emit_ctx=EmitContext.from_handler_grant(ctx, operation),
    )


# =============================================================================
# Re-derive cascade — §5.5 IA9
# =============================================================================


def _list_assignments_for_role(
    pathway: EmitPathway,
    context: str,
    role_name: str,
    local_peer_id: str,
) -> list[tuple[str, str]]:
    """Walk `system/role/{context}/assignment/*` and return the list of
    (full_assignment_uri, assignee_peer_id_hex) pairs whose trailing
    role-name segment matches `role_name`.

    Signature side-files are filtered out so callers don't
    double-process them.
    """
    tree = pathway.entity_tree
    prefix = f"{ROLE_PREFIX}{context}/{_ASSIGNMENT_SEG}/"
    out: list[tuple[str, str]] = []
    for full_uri in list(tree.list_prefix(prefix)):
        if full_uri.endswith("/signature"):
            continue
        decomposed = parse_assignment_path(full_uri, local_peer_id)
        if decomposed is None:
            continue
        ctx_seen, assignee_peer_id_hex, role_seen = decomposed
        if ctx_seen != context or role_seen != role_name:
            continue
        out.append((full_uri, assignee_peer_id_hex))
    return out


def _re_derive_role_internal(
    pathway: EmitPathway,
    keypair: Keypair | None,
    *,
    context: str,
    role_name: str,
    parent_hash: bytes | None,
    caller_grants: list[dict[str, Any]],
    local_peer_id_for_attenuation: str,
    operation: str,
    parent_cap_expires_at: int | None = None,
    caller_expires_at: int | None = None,
) -> dict[str, Any]:
    """Per-assignee ordered re-derive (issue-first).

    For every assignment `system/role/{context}/assignment/{peer_id_hex}/{role_name}`:

    1. Skip if the assignee has an exclusion entity in this context
       (R7 layer 2).
    2. Resolve the role's grants with templates substituted for
       (context, peer_id_hex).
    3. **Per-assignee RL2 (per v1.6 SI-15)** — `caller_grants` MUST cover
       the resolved grants for THIS assignee. With template substitution
       per assignee the resolved grants vary; an undercovered assignee
       is added to `skipped_grantees` and the cascade continues.
       Skip-and-continue is preferred over abort because abort would
       leave earlier issuance + revocation pairs half-applied.
    4. Mint a new role-derived cap (T_new) at the spec-pinned R4
       storage path.
    5. Write the linkage entity at `derived-tokens/{peer_id_hex}/{role}`
       referencing T_new.
    6. Revoke T_old at the role-derived path (delete the binding;
       V7 §5.1 standard mechanism). Skip if T_old == T_new (cap content
       unchanged).

    Per IA9 the issue MUST happen before the revoke. Per-entity tree
    atomicity makes each leg recoverable; no transactional bundle is
    required. Concurrent operational keys MUST NOT be serialized — this
    helper does not take any cross-assignee lock.

    Delivery mechanism: tree-sync (T_new lands at the role-derived
    storage path; assignees discover via standard sync of that subtree,
    or via subscription on
    `system/capability/grants/role-derived/{context}/{peer_id_hex}/*`).
    Per IA9 the delivery mechanism MUST be named — that statement IS
    the naming.

    Returns a dict with `re_derived_count`, `revoked_token_hashes`,
    `new_token_hashes`, and (per SI-15) `skipped_grantees`.
    """
    empty = {
        "re_derived_count": 0,
        "revoked_token_hashes": [],
        "new_token_hashes": [],
        "skipped_grantees": [],
    }
    role_def_path = role_definition_path(context, role_name)
    role_def_hash = pathway.entity_tree.get(role_def_path)
    role_def = (
        pathway.content_store.get(role_def_hash)
        if role_def_hash is not None else None
    )
    if role_def is None or role_def.type != ROLE_TYPE:
        return empty
    role_grants = role_def.data.get("grants") or []
    if not isinstance(role_grants, list) or not role_grants:
        return empty

    if keypair is None:
        # Without a keypair we cannot sign new caps. Treat as a
        # no-op cascade rather than failing the surrounding op.
        return empty

    # v1.7 §5.3: compute the effective expires_at once for the cascade.
    # Role TTL becomes absolute against `now()` at cascade entry; using
    # a single base time across all assignees keeps the cascade
    # deterministic and avoids drift across the (typically tight) loop.
    role_ttl = _role_metadata_ttl(role_def)
    cascade_now = _now_ms()
    effective_expires = _effective_expires_at(
        parent_expires=parent_cap_expires_at,
        role_ttl=role_ttl,
        caller_expires=caller_expires_at,
        now_ms=cascade_now,
    )

    # Build the caller-cap shape once (with caller_expires_at folded in)
    # for is_attenuated; constructed via _as_capability_dict to handle
    # both wrapped and bare forms.
    from entity_core.capability.delegation import is_attenuated
    caller_cap_for_check = _as_capability_dict(
        {"grants": caller_grants},
        expires_at=caller_expires_at,
    )

    local_peer_id = keypair.peer_id
    new_tokens: list[bytes] = []
    revoked: list[bytes] = []
    skipped_grantees: list[bytes] = []
    re_derived_count = 0

    emit_ctx_handler = EmitContext.handler(
        author=local_peer_id,
        capability=None,
        handler_pattern=ROLE_HANDLER_PATTERN,
        operation=operation,
    )

    for assignment_uri, assignee_peer_id_hex in _list_assignments_for_role(
        pathway, context, role_name, local_peer_id,
    ):
        # Layer-2 exclusion check (R7) — excluded peers don't receive
        # re-derived caps even if their assignment entity still exists.
        if pathway.entity_tree.get(
            role_exclusion_path(context, assignee_peer_id_hex),
        ) is not None:
            continue

        derived_grants = [
            resolve_templates(
                g, {"context": context, "peer_id": assignee_peer_id_hex},
            )
            for g in role_grants
        ]

        # Per-assignee RL2 (SI-15) using v1.7 §4.3 step 5 hypothetical-cap
        # form: synthesize a cap with derived_grants + effective expiry
        # and check is_attenuated against the caller's cap. Templates
        # may make the resolved grants exceed the caller's authority for
        # this specific assignee — skip-and-continue, recording the
        # assignee in `skipped_grantees`.
        hypothetical = {"data": {"grants": derived_grants}}
        if effective_expires is not None:
            hypothetical["data"]["expires_at"] = effective_expires
        rl2_result = is_attenuated(
            hypothetical, caller_cap_for_check, local_peer_id_for_attenuation,
        )
        if not rl2_result.valid:
            try:
                skipped_grantees.append(bytes.fromhex(assignee_peer_id_hex))
            except ValueError:
                # Malformed hex in the path — skip but don't add to the
                # skipped_grantees list (no canonical bytes for it).
                pass
            continue

        # PR-1 (v2.0 §5.1): role-derived caps are root caps (parent: null,
        # granter: local peer's identity content_hash) — symmetric with the
        # startup-time L0 path (§4.5). The cascade's `parent_hash` arg is
        # retained for callers but is no longer threaded into the cap;
        # provenance lives in the linkage entity (§2.4 SI-5).
        new_hash = _issue_role_derived_token_pathway(
            pathway,
            keypair,
            context=context,
            assignee_peer_id_hex=assignee_peer_id_hex,
            derived_grants=derived_grants,
            parent_hash=None,
            expires_at=effective_expires,
            emit_ctx=emit_ctx_handler,
        )
        new_tokens.append(new_hash)

        # Read the existing linkage entity (if any) BEFORE overwriting.
        old_link = _read_derived_token_link(
            pathway,
            context=context,
            peer_id_hex=assignee_peer_id_hex,
            role_name=role_name,
        )

        # Write the new linkage to T_new BEFORE revoking T_old so any
        # reader sees a live pointer to a valid cap throughout.
        _write_derived_token_link(
            pathway,
            context=context,
            peer_id_hex=assignee_peer_id_hex,
            role_name=role_name,
            token_hash=new_hash,
            issued_at=_now_ms(),
            emit_ctx=emit_ctx_handler,
        )

        if old_link is not None:
            old_hash, _old_issued = old_link
            if old_hash != new_hash:
                if _revoke_token_at_role_derived_path(
                    pathway,
                    context,
                    assignee_peer_id_hex,
                    old_hash,
                    emit_ctx=emit_ctx_handler,
                ):
                    revoked.append(old_hash)

        # PR-2 (v2.0 §6.6 SEC-2): post-issue exclusion re-check on the
        # per-assignee leg. If a concurrent `:exclude(assignee)` landed
        # while the cap was being persisted, roll back T_new (and T_old
        # has already been revoked just above). Treat this as a skipped
        # grantee for accounting consistency with mid-cascade RL2 fail.
        if pathway.entity_tree.get(
            role_exclusion_path(context, assignee_peer_id_hex),
        ) is not None:
            _rollback_role_derived_cap(
                pathway,
                context=context,
                peer_id_hex=assignee_peer_id_hex,
                token_hash=new_hash,
                role_name=role_name,
                assignment_path=None,
                emit_ctx=emit_ctx_handler,
            )
            new_tokens.pop()
            try:
                skipped_grantees.append(bytes.fromhex(assignee_peer_id_hex))
            except ValueError:
                pass
            continue

        re_derived_count += 1

    return {
        "re_derived_count": re_derived_count,
        "revoked_token_hashes": revoked,
        "new_token_hashes": new_tokens,
        "skipped_grantees": skipped_grantees,
    }


def _issue_role_derived_token_pathway(
    pathway: EmitPathway,
    keypair: Keypair,
    *,
    context: str,
    assignee_peer_id_hex: str,
    derived_grants: list[dict[str, Any]],
    parent_hash: bytes | None,
    expires_at: int | None,
    emit_ctx: EmitContext,
) -> bytes:
    """Pure-pathway version of `_issue_role_derived_token`.

    Per v1.6 SI-8: the cap's `grantee` is `bytes.fromhex(assignee_peer_id_hex)`
    — the same `system/hash` that the storage-path segment encodes in
    hex. No resolver hook, no PeerID-to-hash conversion; the handler
    decodes from the path.
    """
    granter_identity = create_identity_entity(keypair)
    granter_hash = granter_identity.compute_hash()
    grantee_hash = bytes.fromhex(assignee_peer_id_hex)

    cap_data: dict[str, Any] = {
        "grants": derived_grants,
        "granter": granter_hash,
        "grantee": grantee_hash,
        "created_at": _now_ms(),
    }
    if parent_hash is not None:
        cap_data["parent"] = parent_hash
    if expires_at is not None:
        cap_data["expires_at"] = expires_at

    cap_entity = Entity(type="system/capability/token", data=cap_data)
    cap_hash = cap_entity.compute_hash()
    signature_entity = create_signature_entity(
        keypair, cap_hash, granter_hash,
    )

    storage_path = role_derived_token_path(
        context, assignee_peer_id_hex, cap_hash,
    )

    pathway.content_store.put(granter_identity)
    pathway.emit(storage_path, cap_entity, emit_ctx)
    # V7 §3.5 (v7.44, normative) + PROPOSAL Amendment 5/7: a role-derived
    # cap is a plain V7 root cap (ROLE PR-1) that can be the root of a
    # cross-peer continuation chain (§4.3), so its signature MUST be
    # discoverable at the invariant pointer path — the sole canonical
    # location (EXTENSION-ROLE pins no signature path; it inherits V7
    # §3.5). The legacy `{storage_path}/signature` sibling is removed
    # outright (Amendment 7: no production reader, clean break, no
    # dual-write per the project no-backward-compat policy).
    pathway.emit(
        invariant_signature_path(keypair.peer_id, cap_hash),
        signature_entity,
        emit_ctx,
    )
    return cap_hash


def _write_derived_token_link(
    pathway: EmitPathway,
    *,
    context: str,
    peer_id_hex: str,
    role_name: str,
    token_hash: bytes,
    issued_at: int,
    emit_ctx: EmitContext,
) -> None:
    """Persist a `system/role/derived-token-link` linkage entity (per
    SI-5 §2.4) at the sibling `derived-tokens/` subtree.

    One linkage entity per (context, peer, role); `re-derive` rewrites
    the entity to point at the new cap; `unassign` deletes it.
    """
    link = Entity(
        type=ROLE_DERIVED_TOKEN_LINK_TYPE,
        data={
            "token_hash": token_hash,
            "issued_at": issued_at,
        },
    )
    pathway.emit(
        role_derived_token_link_path(context, peer_id_hex, role_name),
        link,
        emit_ctx,
    )


def _read_derived_token_link(
    pathway: EmitPathway,
    *,
    context: str,
    peer_id_hex: str,
    role_name: str,
) -> tuple[bytes, int] | None:
    """Read a linkage entity. Returns (token_hash, issued_at) or None."""
    path = role_derived_token_link_path(context, peer_id_hex, role_name)
    h = pathway.entity_tree.get(path)
    if h is None:
        return None
    entity = pathway.content_store.get(h)
    if entity is None or entity.type != ROLE_DERIVED_TOKEN_LINK_TYPE:
        return None
    token_hash = entity.data.get("token_hash")
    issued_at = entity.data.get("issued_at")
    if not isinstance(token_hash, bytes) or not isinstance(issued_at, int):
        return None
    return (token_hash, issued_at)


# =============================================================================
# RL2 — caller authority covers derived grants
# =============================================================================


def _as_capability_dict(
    cap: Any, expires_at: int | None = None,
) -> dict[str, Any]:
    """Coerce a capability value to the `{data: {grants, expires_at}}`
    shape that `is_attenuated` expects. Accepts either the wrapped
    `{type, data: {...}}` form or the bare `{grants, expires_at}` form
    (HandlerContext stores `caller_capability` in the bare form).

    `expires_at`, when provided, OVERRIDES whatever's in the cap — used
    by RL2 to construct the hypothetical cap with the v1.7 §5.3
    effective expiry.
    """
    if not isinstance(cap, dict):
        return {"data": {} if expires_at is None else {"expires_at": expires_at}}
    if "data" in cap and isinstance(cap["data"], dict):
        data = dict(cap["data"])
    else:
        data = dict(cap)
    if expires_at is not None:
        data["expires_at"] = expires_at
    return {"data": data}


def _check_rl2(
    ctx: HandlerContext,
    derived_grants: list[dict[str, Any]],
    *,
    role_name: str,
    expires_at: int | None = None,
) -> dict[str, Any] | None:
    """Returns an error response if RL2 fails, else None.

    Per v1.7 §4.3 step 5: construct a hypothetical capability with the
    `derived_grants` and the v1.7 §5.3 effective expiry, then check
    `is_attenuated(hypothetical, caller_capability)`. This folds the
    expiration bound into RL2 so V7 §5.6 chain validation can't reject
    the cap at use-time after RL2 grant-coverage passed at issue-time
    ("RL2 OK at issue, chain-invalid at use" — closed by SI-29).

    Fail-closed per IA10 — no partial token minting.
    """
    from entity_core.capability.delegation import is_attenuated

    hypothetical = {
        "data": {"grants": derived_grants},
    }
    if expires_at is not None:
        hypothetical["data"]["expires_at"] = expires_at

    caller_cap = _as_capability_dict(ctx.caller_capability)

    result = is_attenuated(hypothetical, caller_cap, ctx.local_peer_id)
    if not result.valid:
        return _error(
            403, "assigner_authority_insufficient",
            f"Caller capability does not cover role-derived grant for "
            f"{role_name!r} (RL2: {result.error or 'attenuation failed'})",
        )
    return None


# =============================================================================
# Operation: define (IA11)
# =============================================================================


async def _handle_define(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Write a role definition through the handler (IA11 default).

    RL2 at definition-write time: the proposed grant set MUST be covered
    by the caller's capability. Direct `tree:put` to the role-definition
    path is not enforced here (kernel-level rejection per spec §1.3
    is a separate piece of plumbing); this op is the spec-canonical
    write path.

    Triggers a `re-derive` cascade (§5.5 IA9) AFTER the new definition
    is persisted: every existing assignment to this (context, role_name)
    receives a freshly-issued role-derived token before its prior token
    is revoked.
    """
    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/role:define requires a resource target (the role "
            "definition path).",
        )
    decomposed = parse_role_definition_path(target_path, ctx.local_peer_id)
    if decomposed is None:
        return _error(
            400, "malformed_resource",
            "expected system/role/{context}/{role_name}, with role_name "
            f"not in {sorted(RESERVED_ROLE_NAMES)}",
        )
    context, role_name = decomposed

    data = _params_data(params)
    grants = data.get("grants")
    if not isinstance(grants, list) or not grants:
        return _error(
            400, "invalid_params",
            "grants must be a non-empty list of grant entries",
        )
    # Each grant entry must be a dict — we don't enforce full schema here
    # since downstream cap minting will fail loudly on malformed entries.
    for g in grants:
        if not isinstance(g, dict):
            return _error(
                400, "invalid_params",
                "each grant entry must be a map (system/capability/grant-entry)",
            )

    # RL2 at definition-write time: caller's authority must cover every
    # grant entry that any future assignee would receive. Templates resolve
    # at assign time, but for the coverage check we use the literal grant
    # entries — pattern matching treats `{context}`/`{peer_id}` as opaque
    # substrings. Conservative; future tightening could resolve against a
    # synthetic "wildcard" expansion.
    #
    # v1.7 §5.3: the hypothetical cap's expires_at is bounded by the
    # caller (parent and role.ttl both apply at the future assign call,
    # not at define time). Roles that declare `metadata.ttl` get that
    # bound folded in at assign-time per assignee.
    err = _check_rl2(
        ctx, grants,
        role_name=role_name,
        expires_at=_caller_cap_expires(ctx),
    )
    if err is not None:
        return err

    role_data: dict[str, Any] = {
        "name": role_name,
        "grants": grants,
    }
    metadata = data.get("metadata")
    if metadata is not None:
        role_data["metadata"] = metadata

    role_entity = Entity(type=ROLE_TYPE, data=role_data)
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_DEFINE)
    ctx.emit_pathway.emit(target_path, role_entity, emit_ctx)

    # Re-derive cascade per IA11 (§5.5). Synchronous, in-handler — the
    # RoleExtension's mutation observer detects the same write and
    # short-circuits when it sees `handler_pattern == ROLE_HANDLER_PATTERN`
    # in the change context to avoid double-cascading.
    cascade = _re_derive_role_internal(
        ctx.emit_pathway,
        ctx.keypair,
        context=context,
        role_name=role_name,
        parent_hash=None,  # PR-1 v2.0: role-derived caps are root
        parent_cap_expires_at=_parent_cap_expires(ctx),
        caller_grants=_capability_grants(ctx.caller_capability),
        caller_expires_at=_caller_cap_expires(ctx),
        local_peer_id_for_attenuation=ctx.local_peer_id,
        operation=_OP_DEFINE,
    )

    return _ok(
        "system/role/define-result",
        {
            "role_path": target_path,
            "re_derived_count": cascade["re_derived_count"],
        },
    )


# =============================================================================
# Operation: assign (RL1, RL2, R7 layer 2)
# =============================================================================


async def _handle_assign(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/role:assign requires a resource target (the assignment path).",
        )
    decomposed = parse_assignment_path(target_path, ctx.local_peer_id)
    if decomposed is None:
        return _error(
            400, "malformed_resource",
            "expected system/role/{context}/assignment/{peer_id_hex}/{role_name}",
        )
    context, assignee_peer_id_hex, role_name_from_path = decomposed

    # SEC-18 / V7 v7.39 PR-3 (defense-in-depth, fail-fast at issuance):
    # reject zero-hash assignee at the role layer. Zero-hash never
    # resolves to a system/peer entity (no keypair hashes to zero), so
    # the minted cap would fail chain-walk anyway with
    # `unresolvable_grantee 401`. Failing fast here surfaces the error
    # to the assigner instead of leaving a dud cap bound.
    if _is_zero_hex_hash(assignee_peer_id_hex):
        return _error(
            400, "invalid_assign_request",
            "assignee peer_id_hex MUST NOT be a zero hash (SEC-18)",
        )

    data = _params_data(params)
    role_name = data.get("role")
    if not isinstance(role_name, str) or not role_name:
        return _error(
            400, "invalid_assign_request",
            "role is required (must match the trailing path segment)",
        )
    # The path's trailing role-name segment determines storage; the params
    # `role` selector MUST agree (no surprises in which definition gets read).
    if role_name != role_name_from_path:
        return _error(
            400, "invalid_request",
            "params.role must match the trailing role_name segment of the "
            "assignment resource path",
        )

    # Step 3: resolve role definition
    role_def_path = role_definition_path(context, role_name)
    role_def_hash = ctx.emit_pathway.entity_tree.get(role_def_path)
    role_def = (
        ctx.emit_pathway.content_store.get(role_def_hash)
        if role_def_hash is not None else None
    )
    if role_def is None or role_def.type != ROLE_TYPE:
        return _error(
            404, "role_not_found",
            f"No role definition at {role_def_path}",
        )

    # Step 4: template resolution (§5.2). Templates substitute
    # `{peer_id}` to `peer_id_hex` per v1.6 SI-1 — the same form used
    # in path segments.
    role_grants = role_def.data.get("grants") or []
    if not isinstance(role_grants, list) or not role_grants:
        return _error(
            500, "invalid_role_definition",
            "role definition has no grants",
        )
    derived_grants = [
        resolve_templates(
            g, {"context": context, "peer_id": assignee_peer_id_hex},
        )
        for g in role_grants
    ]

    # Step 4b: R7 layer 2 — block new derivation for excluded peers
    if is_excluded(context, assignee_peer_id_hex, ctx):
        return _error(
            403, "assignee_excluded",
            "Cannot assign role to a peer in the context's exclusion subtree",
        )

    # Step 4c: v1.7 §5.3 — compute the cap's effective `expires_at` as
    # MIN_DEFINED(parent.expires_at, now+role.ttl, caller.expires_at).
    # This is used both for the RL2 hypothetical (so V7 §5.6 strict
    # nil-vs-finite is checked at issue-time) AND for the issued cap
    # itself (so the minted cap doesn't outlive its sources).
    effective_expires = _effective_expires_at(
        parent_expires=_parent_cap_expires(ctx),
        role_ttl=_role_metadata_ttl(role_def),
        caller_expires=_caller_cap_expires(ctx),
    )

    # Step 5: RL2 — hypothetical-cap form per v1.7 §4.3 step 5.
    err = _check_rl2(
        ctx, derived_grants,
        role_name=role_name,
        expires_at=effective_expires,
    )
    if err is not None:
        return err

    # Step 6: persist the assignment
    author_hash = getattr(ctx, "remote_identity_hash", None)
    if author_hash is None:
        # Fall back to the local peer's identity hash when the request was
        # locally originated (no remote author bound).
        if ctx.keypair is not None:
            author_hash = create_identity_entity(ctx.keypair).compute_hash()
        else:
            author_hash = b""
    assignment_data: dict[str, Any] = {
        "role": role_name,
        "assigned_by": author_hash,
        "assigned_at": _now_ms(),
    }
    metadata = data.get("metadata")
    if metadata is not None:
        assignment_data["metadata"] = metadata
    assignment_entity = Entity(
        type=ROLE_ASSIGNMENT_TYPE, data=assignment_data,
    )
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_ASSIGN)
    ctx.emit_pathway.emit(target_path, assignment_entity, emit_ctx)

    # Step 7: derive and persist a capability token bundling the resolved
    # grants. Per v1.6 SI-8 the cap's `grantee` is bytes.fromhex of the
    # assignee's `peer_id_hex` — the same hash the path encodes.
    # PR-1 (v2.0 §5.1): role-derived caps are root caps. parent: null;
    # granter is local peer's identity content_hash. Chain validation
    # terminates at the role-derived cap, so use-time validation no
    # longer requires the handler grant to cover the role's grants.
    derived_token_hash = _issue_role_derived_token(
        ctx,
        context=context,
        assignee_peer_id_hex=assignee_peer_id_hex,
        derived_grants=derived_grants,
        parent_hash=None,
        expires_at=effective_expires,
        operation=_OP_ASSIGN,
    )

    # Step 8: linkage entity (per SI-5 §2.4) at the sibling
    # `derived-tokens/` subtree. Maps this specific (context, peer, role)
    # assignment to the freshly-issued token so unassign and re-derive
    # can target it precisely without disturbing other roles the same
    # peer holds.
    _write_derived_token_link(
        ctx.emit_pathway,
        context=context,
        peer_id_hex=assignee_peer_id_hex,
        role_name=role_name,
        token_hash=derived_token_hash,
        issued_at=_now_ms(),
        emit_ctx=emit_ctx,
    )

    # Step 9 (PR-2 v2.0 §6.6 SEC-2): post-issue exclusion re-check.
    # The `is_excluded` pre-check at step 4b and the cap `tree:put` at
    # step 7 form a TOCTOU window where a concurrent `:exclude` can land
    # an exclusion entity AND its layer-1 sweep before this cap was
    # bound. Re-check after persistence and roll back if the assignee
    # is now excluded — preserves §6.1 layer-2 atomicity from the
    # caller's perspective.
    if is_excluded(context, assignee_peer_id_hex, ctx):
        _rollback_role_derived_cap(
            ctx.emit_pathway,
            context=context,
            peer_id_hex=assignee_peer_id_hex,
            token_hash=derived_token_hash,
            role_name=role_name,
            assignment_path=target_path,
            emit_ctx=emit_ctx,
        )
        return _error(
            403, "assignee_excluded",
            "exclusion landed during :assign — rolled back (SEC-2)",
        )

    return _ok(
        "system/role/assign-result",
        {
            "assignment_path": target_path,
            "derived_tokens": [derived_token_hash],
        },
    )


# =============================================================================
# Operation: unassign (IA12)
# =============================================================================


def _unassign_one_role(
    pathway: EmitPathway,
    *,
    context: str,
    peer_id_hex: str,
    role_name: str,
    assignment_path: str,
    emit_ctx: EmitContext,
) -> list[bytes]:
    """Remove ONE (context, peer, role) assignment + its linkage entity
    + its single role-derived cap. Returns the list of revoked token
    hashes (0 or 1 entry).

    Used by both the specific-role unassign branch (parses to one
    role_name) and the all-roles branch (iterates over each role found
    under the peer's assignment subtree, per §4.4).
    """
    if pathway.entity_tree.get(assignment_path) is not None:
        pathway.delete(assignment_path, emit_ctx)

    revoked: list[bytes] = []
    link = _read_derived_token_link(
        pathway,
        context=context,
        peer_id_hex=peer_id_hex,
        role_name=role_name,
    )
    if link is not None:
        token_hash, _issued_at = link
        if _revoke_token_at_role_derived_path(
            pathway,
            context,
            peer_id_hex,
            token_hash,
            emit_ctx=emit_ctx,
        ):
            revoked.append(token_hash)
        pathway.delete(
            role_derived_token_link_path(context, peer_id_hex, role_name),
            emit_ctx,
        )
    return revoked


async def _handle_unassign(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """IA12 token-revocation flow (§6.4.1).

    Per spec §4.4 the resource path supports two forms:
      - `system/role/{context}/assignment/{peer_id_hex}/{role_name}` —
        revoke ONE specific role for the peer.
      - `system/role/{context}/assignment/{peer_id_hex}` (trailing role
        segment omitted) — revoke ALL roles the peer holds in that
        context.

    For each role removed, the IA12 flow runs:
      1) Remove the assignment binding.
      2) Read the SI-5 sibling-subtree linkage entity to locate the
         specific role-derived cap (multi-role-aware, R6).
      3) Revoke that cap by deleting its role-derived storage binding.
    The broad `(context, peer)` sweep is intentionally NOT used for
    unassign — it would catch other roles' tokens. The all-roles form
    iterates the per-peer subtree and runs the per-role flow once per
    role found.
    """
    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/role:unassign requires a resource target.",
        )

    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_UNASSIGN)

    # (a) Specific-role form first.
    specific = parse_assignment_path(target_path, ctx.local_peer_id)
    if specific is not None:
        context, peer_id_hex, role_name = specific
        revoked = _unassign_one_role(
            ctx.emit_pathway,
            context=context,
            peer_id_hex=peer_id_hex,
            role_name=role_name,
            assignment_path=target_path,
            emit_ctx=emit_ctx,
        )
        return _ok(
            "system/role/unassign-result",
            {
                "assignment_path": target_path,
                "revoked_token_hashes": revoked,
            },
        )

    # (b) All-roles-for-peer form (§4.4).
    per_peer = parse_assignment_peer_path(target_path, ctx.local_peer_id)
    if per_peer is None:
        return _error(
            400, "malformed_resource",
            "expected system/role/{context}/assignment/{peer_id_hex}/{role_name}"
            " or system/role/{context}/assignment/{peer_id_hex}",
        )
    context, peer_id_hex = per_peer

    # Walk every role-bearing assignment under the peer's subtree.
    # `parse_assignment_path` filters out signature side-files and any
    # nested-form path that doesn't match the assignment shape.
    revoked: list[bytes] = []
    prefix = f"{ROLE_PREFIX}{context}/{_ASSIGNMENT_SEG}/{peer_id_hex}/"
    full_prefix = ctx.emit_pathway.entity_tree.normalize_uri(prefix)
    for full_uri in list(ctx.emit_pathway.entity_tree.list_prefix(prefix)):
        if not full_uri.startswith(full_prefix):
            continue
        if full_uri.endswith("/signature"):
            continue
        decomposed = parse_assignment_path(full_uri, ctx.local_peer_id)
        if decomposed is None:
            continue
        ctx_seen, peer_seen, role_seen = decomposed
        if ctx_seen != context or peer_seen != peer_id_hex:
            continue
        revoked.extend(_unassign_one_role(
            ctx.emit_pathway,
            context=context,
            peer_id_hex=peer_id_hex,
            role_name=role_seen,
            assignment_path=full_uri,
            emit_ctx=emit_ctx,
        ))

    # `assignment_path` echoes the resource as received (per SI-27 echo
    # rule) — for the all-roles form that's the per-peer path.
    return _ok(
        "system/role/unassign-result",
        {
            "assignment_path": target_path,
            "revoked_token_hashes": revoked,
        },
    )


# =============================================================================
# Operation: exclude / unexclude (R7 layers 1 + 2)
# =============================================================================


async def _handle_exclude(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/role:exclude requires a resource target.",
        )
    decomposed = parse_exclusion_path(target_path, ctx.local_peer_id)
    if decomposed is None:
        return _error(
            400, "malformed_resource",
            "expected system/role/{context}/excluded/{peer_id_hex}",
        )
    context, peer_id_hex = decomposed

    data = _params_data(params)
    author_hash = getattr(ctx, "remote_identity_hash", None)
    if author_hash is None:
        if ctx.keypair is not None:
            author_hash = create_identity_entity(ctx.keypair).compute_hash()
        else:
            author_hash = b""

    # Per v1.6 SI-3, the exclusion entity does NOT carry a `peer_id`
    # body field — the path segment is canonical. (v1.5 had a redundant
    # `peer_id: system/hash` field; removed in v1.6.)
    exclusion_data: dict[str, Any] = {
        "excluded_by": author_hash,
        "excluded_at": _now_ms(),
    }
    reason = data.get("reason") if isinstance(data, dict) else None
    if isinstance(reason, str):
        exclusion_data["reason"] = reason

    exclusion_entity = Entity(type=ROLE_EXCLUSION_TYPE, data=exclusion_data)
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_EXCLUDE)
    ctx.emit_pathway.emit(target_path, exclusion_entity, emit_ctx)

    # Layer 1 broad sweep (per v1.6 SI-7) — delete every cap bound at
    # the role-derived subtree on this peer regardless of which fleet
    # peer originally issued. The exclusion entity is the trigger; the
    # local sweep is the local enforcement.
    revoked = _sweep_role_derived_tokens(
        ctx, context, peer_id_hex, _OP_EXCLUDE,
    )

    return _ok(
        "system/role/exclude-result",
        {
            "exclusion_path": target_path,
            "revoked_token_hashes": revoked,
        },
    )


async def _handle_unexclude(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/role:unexclude requires a resource target.",
        )
    decomposed = parse_exclusion_path(target_path, ctx.local_peer_id)
    if decomposed is None:
        return _error(
            400, "malformed_resource",
            "expected system/role/{context}/excluded/{peer_id_hex}",
        )
    found = ctx.emit_pathway.entity_tree.get(target_path) is not None
    if found:
        emit_ctx = EmitContext.from_handler_grant(ctx, _OP_UNEXCLUDE)
        ctx.emit_pathway.delete(target_path, emit_ctx)
    # Per SI-9 pattern parity, return shape matches
    # `system/role/unexclude-result`. `found` is not carried over;
    # `exclusion_path` echoes the resource.
    return _ok(
        "system/role/unexclude-result",
        {"exclusion_path": target_path},
    )


# =============================================================================
# Operation: re-derive (§5.5 IA9)
# =============================================================================


async def _handle_re_derive(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Re-issue role-derived tokens for all assignments of (context,
    role_name) per IA9. Caller authorizes against the role-definition
    path being re-derived (RL2 against the role's current grants).

    Resource is the role-definition path: `system/role/{context}/{role_name}`.
    `params.role`, when present, MUST agree with the trailing role-name
    segment.
    """
    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/role:re-derive requires a resource target (the "
            "role-definition path).",
        )
    decomposed = parse_role_definition_path(target_path, ctx.local_peer_id)
    if decomposed is None:
        return _error(
            400, "malformed_resource",
            "expected system/role/{context}/{role_name}",
        )
    context, role_name = decomposed

    data = _params_data(params)
    role_param = data.get("role")
    if role_param is not None and role_param != role_name:
        return _error(
            400, "invalid_request",
            "params.role must match the trailing role_name segment of "
            "the role-definition resource path",
        )

    role_def_hash = ctx.emit_pathway.entity_tree.get(target_path)
    role_def = (
        ctx.emit_pathway.content_store.get(role_def_hash)
        if role_def_hash is not None else None
    )
    if role_def is None or role_def.type != ROLE_TYPE:
        return _error(
            404, "role_not_found",
            f"No role definition at {target_path}",
        )

    # Per v1.7 SI-15 (role v1.7 cross-impl handoff): NO
    # top-level RL2 against the role's literal (often-templated) grants.
    # That would abort the whole cascade with 403 the moment a templated
    # role grant doesn't pattern-match the caller's per-peer authority
    # (e.g. role: `users/{peer_id}/*` vs caller: `users/<bob>/*` — the
    # template is treated as a literal string at this layer). The
    # per-assignee RL2 inside `_re_derive_role_internal` is the
    # authoritative check; it resolves templates per assignee and
    # skip-and-continues, reporting the failed grantees in
    # `skipped_grantees`. Aborting cascade-wide would leave earlier
    # ordered-write pairs half-applied (some assignees with no T_old
    # AND no T_new) — a security regression.
    cascade = _re_derive_role_internal(
        ctx.emit_pathway,
        ctx.keypair,
        context=context,
        role_name=role_name,
        parent_hash=None,  # PR-1 v2.0: role-derived caps are root
        parent_cap_expires_at=_parent_cap_expires(ctx),
        caller_grants=_capability_grants(ctx.caller_capability),
        caller_expires_at=_caller_cap_expires(ctx),
        local_peer_id_for_attenuation=ctx.local_peer_id,
        operation=_OP_RE_DERIVE,
    )
    return _ok(
        "system/role/re-derive-result",
        {
            "re_derived_count": cascade["re_derived_count"],
            "revoked_token_hashes": cascade["revoked_token_hashes"],
            "new_token_hashes": cascade["new_token_hashes"],
            "skipped_grantees": cascade["skipped_grantees"],
        },
    )


# =============================================================================
# Operation: delegate — member-to-member (§5.6 IA22)
# =============================================================================


async def _handle_delegate(
    ctx: HandlerContext, params: dict[str, Any],
) -> dict[str, Any]:
    """Issue a delegation cap from a delegator (B) to a delegate (C).

    Per IA22 + v1.6 cleanup:
    - Delegator is identified from `ctx.execute.data.author` (the local
      peer in this implementation, via `ctx.local_peer_id`). The
      delegator's `peer_id_hex` segment in the resource path MUST equal
      `hex(local_peer_identity_hash)`. (SI-21: dropped explicit
      `delegator` request field — author is authoritative.)
    - The path segment is hex of the delegator's `system/identity`
      content_hash (per SI-1).
    - Delegator MUST hold the named role in the context (assignment
      exists at the resource path).
    - **Locality invariant (SI-19):** `:delegate` MUST be invoked on the
      delegator's own runtime peer; the request is rejected with
      **400 `delegator_must_be_local_peer`** when the resource path's
      delegator segment doesn't match the local peer (precondition
      error — request is malformed for the deployment's locality
      model, NOT an authorization deny).
    - **Scope literal-only (SI-20):** the `scope` parameter MUST be
      literal — no template variables.
    - **RL2 attenuation against the DELEGATOR'S authority** (NOT the
      operational key's): scope MUST be covered by the delegator's role
      grants resolved with `peer_id = delegator_peer_id_hex`.
    - **Delegate must not be excluded** from the context (R7 layer 2).
    - **Parent selection (SI-22):** read the delegator's linkage entity
      at `derived-tokens/{delegator_peer_id_hex}/{role_name}` (per SI-5)
      to get the delegator's role-derived cap hash. (Tie-break by
      `issued_at` desc when multiple linkage entities exist — rare
      under grace=0.)
    - Cap rooted at delegator's runtime peer (granter = local peer's
      identity hash); persisted at the role-derived path so layer-1
      sweep, unassign revocation, and re-derive cascade all reach it.

    Resource: `system/role/{context}/assignment/{delegator_peer_id_hex}/{role_name}`.
    """
    # SI-19 locality invariant per EXTENSION-ROLE §5.6.0: `ctx.local_peer_id
    # == ctx.execute.data.author`. The path-based check below (resource
    # path's `delegator_peer_id_hex` == `hex(local_identity_content_hash)`)
    # is the spec-conformant enforcement: the path encodes the delegator,
    # the local peer must own that identity, and the handler signs the
    # issued cap with the local keypair by construction. We do NOT gate on
    # `ctx.remote_peer_id != ctx.local_peer_id` — the wire-transport peer
    # may legitimately differ from the EXECUTE author (e.g., the EXECUTE is
    # signed by the target peer's keypair but transmitted over an existing
    # admin connection; Rust + Go both accept this, surfaced by Go's
    # `acme_14_1_delegate_under_controller_cap` cross-impl fixture).
    target_path = _resource_target(ctx)
    if target_path is None:
        return _error(
            400, "path_required",
            "system/role:delegate requires a resource target (the "
            "delegator's assignment path).",
        )
    decomposed = parse_assignment_path(target_path, ctx.local_peer_id)
    if decomposed is None:
        return _error(
            400, "malformed_resource",
            "expected system/role/{context}/assignment/{delegator_peer_id_hex}/{role_name}",
        )
    context, delegator_peer_id_hex, role_name = decomposed

    data = _params_data(params)
    delegate_raw = data.get("delegate")
    role_param = data.get("role")
    context_param = data.get("context")
    scope = data.get("scope")
    expires_at = data.get("expires_at")

    # Accept the canonical wire form (33-byte system/hash byte string —
    # algorithm + digest) per V7 / EXTENSION-ATTESTATION; fall back to a
    # hex string for backward compat / human-friendly tooling. Both
    # normalize to lowercase hex for path construction.
    delegate_peer_id_hex = _normalize_peer_id_hex(delegate_raw)
    if delegate_peer_id_hex is None:
        return _error(
            400, "invalid_request",
            "delegate is required (system/hash byte string of the "
            "delegate's identity content_hash, or its hex equivalent)",
        )
    # SEC-18 / V7 v7.39 PR-3: same fail-fast rationale as `:assign` —
    # a zero-hash delegate would chain-walk-reject with
    # `unresolvable_grantee 401`; fail at mint time so the delegation
    # cap never binds.
    if _is_zero_hex_hash(delegate_peer_id_hex):
        return _error(
            400, "invalid_request",
            "delegate MUST NOT be a zero hash (SEC-18)",
        )
    if context_param is not None and context_param != context:
        return _error(
            400, "invalid_request",
            "params.context must match the assignment path's context segment",
        )
    if role_param is not None and role_param != role_name:
        return _error(
            400, "invalid_request",
            "params.role must match the assignment path's role_name segment",
        )
    if not isinstance(scope, list) or not scope:
        return _error(
            400, "invalid_request",
            "scope is required (non-empty list of grant entries)",
        )
    for g in scope:
        if not isinstance(g, dict):
            return _error(
                400, "invalid_request",
                "each scope entry must be a grant-entry map",
            )
    # SI-20: scope MUST be literal — no template variables.
    if _scope_contains_templates(scope):
        return _error(
            400, "scope_must_be_literal",
            "scope MUST NOT contain template variables ({context}/{peer_id}); "
            "only role-definition grants undergo template resolution per §5.6",
        )
    if expires_at is not None and not isinstance(expires_at, int):
        return _error(
            400, "invalid_request",
            "expires_at must be a uint (ms since epoch) when provided",
        )

    # Defense-in-depth: the path's delegator segment MUST match the local
    # peer's identity hash, since the handler signs the issued cap with
    # the local keypair. If a local in-process caller submits a path
    # naming someone else as delegator, reject with the same subcode.
    if ctx.keypair is None:
        return _error(
            500, "missing_keypair",
            "delegate requires keypair access to sign the delegation cap",
        )
    local_identity_hash_hex = (
        create_identity_entity(ctx.keypair).compute_hash().hex()
    )
    if delegator_peer_id_hex != local_identity_hash_hex:
        return _error(
            400, "delegator_must_be_local_peer",
            "system/role:delegate MUST be invoked on the delegator's own "
            "runtime peer (the handler signs with the local keypair). The "
            "resource path's delegator segment does not match the local "
            "peer's identity hash.",
        )

    # 1) Verify B holds the role.
    if ctx.emit_pathway.entity_tree.get(target_path) is None:
        return _error(
            404, "assignment_not_found",
            f"delegator does not hold role {role_name!r} in context "
            f"{context!r}",
        )

    # 2) Parent selection per SI-22: read linkage entity at the sibling
    #    `derived-tokens/{delegator_peer_id_hex}/{role_name}` subtree.
    parent_link = _read_derived_token_link(
        ctx.emit_pathway,
        context=context,
        peer_id_hex=delegator_peer_id_hex,
        role_name=role_name,
    )
    if parent_link is None:
        return _error(
            409, "delegator_no_derived_cap",
            "delegator's role-derived cap not found "
            "(an :assign or :re-derive may be required to mint it first)",
        )
    parent_cap_hash, _parent_issued_at = parent_link

    # 3) Read role definition + resolve B's authority.
    role_def_path = role_definition_path(context, role_name)
    role_def_hash = ctx.emit_pathway.entity_tree.get(role_def_path)
    role_def = (
        ctx.emit_pathway.content_store.get(role_def_hash)
        if role_def_hash is not None else None
    )
    if role_def is None or role_def.type != ROLE_TYPE:
        return _error(
            404, "role_not_found",
            f"role definition missing at {role_def_path}",
        )
    delegator_grants = [
        resolve_templates(
            g, {"context": context, "peer_id": delegator_peer_id_hex},
        )
        for g in (role_def.data.get("grants") or [])
    ]

    # 4) Layer-2 exclusion check on the delegate.
    if is_excluded(context, delegate_peer_id_hex, ctx):
        return _error(
            403, "delegate_excluded",
            "delegate is in the context's exclusion subtree",
        )

    # 5a) v1.7 §5.3: compute the effective expires_at for the delegation
    #     cap. Parent here is the delegator's role-derived cap (NOT the
    #     handler grant) — read its `expires_at` from the content store.
    #     Caller-supplied `expires_at` is folded in as another bound.
    parent_cap_entity = ctx.emit_pathway.content_store.get(parent_cap_hash)
    parent_cap_expires_for_delegate = (
        parent_cap_entity.data.get("expires_at")
        if parent_cap_entity is not None and isinstance(parent_cap_entity.data, dict)
        else None
    )
    effective_expires = _effective_expires_at(
        parent_expires=parent_cap_expires_for_delegate,
        role_ttl=_role_metadata_ttl(role_def),
        caller_expires=_caller_cap_expires(ctx),
    )
    if expires_at is not None:
        # Caller-requested upper bound is also folded in (a delegator
        # MAY attenuate further).
        effective_expires = _min_defined(effective_expires, expires_at)

    # 5b) RL2 attenuation against the DELEGATOR'S authority (per IA22),
    #     hypothetical-cap form per v1.7 §4.3 step 5. Build a synthetic
    #     "delegator cap" with the resolved role grants + delegator's
    #     own role-derived cap's expires_at (carrying the chain bound
    #     forward), then check is_attenuated(hypothetical_delegation,
    #     delegator_role_cap). Scope is literal (already enforced
    #     above); no template substitution before the coverage check.
    from entity_core.capability.delegation import is_attenuated
    delegator_role_cap_for_check = _as_capability_dict(
        {"grants": delegator_grants},
        expires_at=parent_cap_expires_for_delegate,
    )
    hypothetical_delegation = {
        "data": {"grants": scope},
    }
    if effective_expires is not None:
        hypothetical_delegation["data"]["expires_at"] = effective_expires
    rl2_result = is_attenuated(
        hypothetical_delegation,
        delegator_role_cap_for_check,
        ctx.local_peer_id,
    )
    if not rl2_result.valid:
        return _error(
            403, "delegation_authority_insufficient",
            f"scope is not an attenuation of the delegator's role grants "
            f"({rl2_result.error or 'attenuation failed'})",
        )

    # 6) Mint the delegation cap. Per SI-20, scope is literal — issue
    #    the cap with `scope` directly (no template substitution; the
    #    delegator chose the literal grants they want C to receive).
    delegation_token_hash = _issue_role_derived_token(
        ctx,
        context=context,
        assignee_peer_id_hex=delegate_peer_id_hex,
        derived_grants=scope,
        parent_hash=parent_cap_hash,
        expires_at=effective_expires,
        operation=_OP_DELEGATE,
    )

    # 7) PR-2 (v2.0 §6.6 SEC-2): post-issue exclusion re-check on the
    # delegate (target peer C). If a concurrent `:exclude(C)` landed
    # while the delegation cap was being persisted, roll back the
    # delegation cap and return 403. Same shape as `:assign` / cascade.
    if is_excluded(context, delegate_peer_id_hex, ctx):
        _rollback_role_derived_cap(
            ctx.emit_pathway,
            context=context,
            peer_id_hex=delegate_peer_id_hex,
            token_hash=delegation_token_hash,
            role_name=None,  # delegate flow writes no linkage entity
            assignment_path=None,
            emit_ctx=EmitContext.from_handler_grant(ctx, _OP_DELEGATE),
        )
        return _error(
            403, "delegate_excluded",
            "exclusion landed during :delegate — rolled back (SEC-2)",
        )

    return _ok(
        "system/role/delegate-result",
        {
            "delegation_token_hash": delegation_token_hash,
        },
    )


def _scope_contains_templates(scope: list[dict[str, Any]]) -> bool:
    """SI-20 helper: True iff any string in the scope's
    handler / resource patterns contains a template variable.

    Detects `{context}`, `{peer_id}`, and any other `{...}` substring
    so future template additions don't quietly bypass the check.
    """
    import re
    template_re = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
    for grant in scope:
        if not isinstance(grant, dict):
            continue
        for dim in ("handlers", "resources"):
            sc = grant.get(dim)
            if not isinstance(sc, dict):
                continue
            for side in ("include", "exclude"):
                patterns = sc.get(side) or []
                for pat in patterns:
                    if isinstance(pat, str) and template_re.search(pat):
                        return True
    return False


# =============================================================================
# Startup-time L0 helper — §4.5 IA13 (renamed from "bootstrap" per SI-28)
# =============================================================================


def startup_time_role_derived_token(
    pathway: EmitPathway,
    keypair: Keypair,
    *,
    context: str,
    role_def: Entity,
    assignee_peer_id_hex: str,
    expires_at: int | None = None,
) -> bytes:
    """Mint a root role-derived cap before the role handler is registered.

    Per §4.5 IA13 + v1.6 SI-28 rename: this is **startup-time L0
    access**, not "bootstrap". Startup-time-derived tokens are root caps
    — `parent` is None and `granter` is the local peer's identity. RL2
    does not apply (no caller capability exists yet). The R7 layer-2
    exclusion check DOES apply — startup-time L0 can NOT mint a cap for
    an excluded peer.

    Implementation contract:

      * Call BEFORE `peer.handlers.register(ROLE_HANDLER_PATTERN, ...)`.
        After registration, this function raises `RuntimeError` to
        enforce the L0 boundary (per v1.6 SI-12 conformance test
        vector). After registration, dispatch through `system/role:assign`
        is the only supported derivation path. The SDK MAY re-enter L0
        via a deliberate recovery ceremony (e.g., peer-owner key
        rotation), but doing so is out of scope for this helper.
      * The role definition entity is passed in directly (not read from
        the tree). Callers using a tree-stored definition should
        `tree.get` first.
      * Templates resolve with `{context}` and
        `{peer_id: assignee_peer_id_hex}` (v1.6 SI-1).
      * Per SI-1 + SI-8, `assignee_peer_id_hex` is lowercase hex of
        `system/hash` of the assignee's `system/identity` entity.
        The path segment AND the cap's `grantee` field both encode this
        same value.
      * The minted cap lands at the spec-pinned R4 storage path.

    Returns the new token's content hash. Raises:
    - `RuntimeError` if called after the role handler is registered.
    - `PermissionError` when the assignee is excluded from the context.
    - `ValueError` when the role definition is malformed.
    """
    # SI-12: linguistic-only L0 boundary, with a runtime guard. The
    # presence of `system/handler/system/role` in the tree means the
    # role handler has been registered (per V7 manifest decomposition).
    handler_marker = pathway.entity_tree.get(
        f"system/handler/{ROLE_HANDLER_PATTERN}",
    )
    if handler_marker is not None:
        raise RuntimeError(
            "startup_time_role_derived_token() was called AFTER the role "
            "handler was registered. The L0 derivation path is closed "
            "post-registration; use `system/role:assign` via dispatched "
            "EXECUTE instead. (Per EXTENSION-ROLE.md v1.6 §4.5 IA13.)",
        )

    excl_path = role_exclusion_path(context, assignee_peer_id_hex)
    if pathway.entity_tree.get(excl_path) is not None:
        raise PermissionError(
            f"startup_time_role_derived_token: peer "
            f"{assignee_peer_id_hex!r} is excluded from context "
            f"{context!r}",
        )

    if role_def.type != ROLE_TYPE:
        raise ValueError(
            f"role_def.type must be {ROLE_TYPE!r}, got {role_def.type!r}",
        )
    role_grants = role_def.data.get("grants") or []
    if not isinstance(role_grants, list) or not role_grants:
        raise ValueError("role_def has no grants")

    derived_grants = [
        resolve_templates(
            g, {"context": context, "peer_id": assignee_peer_id_hex},
        )
        for g in role_grants
    ]

    return _issue_role_derived_token_pathway(
        pathway,
        keypair,
        context=context,
        assignee_peer_id_hex=assignee_peer_id_hex,
        derived_grants=derived_grants,
        parent_hash=None,
        expires_at=expires_at,
        emit_ctx=EmitContext.bootstrap(),
    )


# =============================================================================
# RoleExtension — fleet-wide reactive sweep (§6.5 IA8) + IA11 option (b)
# =============================================================================


class _RoleExclusionWatcher:
    """InternalHook: fleet-wide reactive sweep on tree-sync of an exclusion
    entity (§6.5 IA8).

    When a `system/role/{context}/excluded/{peer_id}` binding lands on
    this peer (regardless of where it originated — local handler write
    OR tree-sync from another peer), sweep this peer's local
    `system/capability/grants/role-derived/{context}/{peer_id}/...`
    subtree so any role-derived caps this peer holds for the excluded
    peer are deleted.

    The hook's reach is local-only: it sweeps THIS peer's role-derived
    subtree, never another peer's. The exclusion entity is the trigger;
    the sync layer is what got it here.
    """

    def __init__(self, ext: RoleExtension) -> None:
        self._ext = ext

    def on_change_sync(self, event: ChangeEvent) -> int | None:
        if event.kind != ChangeKind.CREATED and event.kind != ChangeKind.UPDATED:
            return None
        entity = event.entity
        if entity is None or entity.type != ROLE_EXCLUSION_TYPE:
            return None
        # Local `system/role:exclude` already swept synchronously inside
        # the handler. The fleet-wide hook is the bridge for exclusion
        # entities arriving via tree-sync from another peer (or any
        # write originating outside the role handler), so we skip when
        # the change context attributes the write to the role handler
        # itself. Without this guard the hook would fire INSIDE the
        # handler's own emit(), beat the handler to the sweep, and
        # leave the handler's return value reporting an empty
        # `revoked_tokens` list.
        if event.context.handler_pattern == ROLE_HANDLER_PATTERN:
            return None
        local_peer_id = self._ext._local_peer_id
        decomposed = parse_exclusion_path(event.uri, local_peer_id)
        if decomposed is None:
            return None
        context, peer_id = decomposed
        emit_ctx = EmitContext.handler(
            author=local_peer_id,
            handler_pattern=ROLE_HANDLER_PATTERN,
            operation=_OP_FLEET_SWEEP,
        )
        _sweep_role_derived_paths(
            self._ext._pathway,
            context,
            peer_id,
            emit_ctx=emit_ctx,
        )
        return None


class _RoleDefinitionWatcher:
    """InternalHook: IA11 option (b) — when a role-definition entity is
    written by a path other than `system/role:define` (e.g. direct
    `tree:put` or `tree-sync`), trigger a `re-derive` cascade.

    Detection rule: fire only when the change context's
    `handler_pattern != ROLE_HANDLER_PATTERN`. This prevents a
    double-cascade when the role handler itself wrote the definition
    (the `:define` op already cascaded synchronously inside the
    handler).
    """

    def __init__(self, ext: RoleExtension) -> None:
        self._ext = ext

    def on_change_sync(self, event: ChangeEvent) -> int | None:
        if event.kind != ChangeKind.CREATED and event.kind != ChangeKind.UPDATED:
            return None
        entity = event.entity
        if entity is None or entity.type != ROLE_TYPE:
            return None
        # Avoid double-cascade when our own `:define` op authored this
        # write.
        ctx = event.context
        if ctx.handler_pattern == ROLE_HANDLER_PATTERN:
            return None
        local_peer_id = self._ext._local_peer_id
        decomposed = parse_role_definition_path(event.uri, local_peer_id)
        if decomposed is None:
            return None
        context, role_name = decomposed
        # IA11 option (b) cascade: the watcher fires for direct tree:put
        # arrivals (bypassing :define). We don't have a caller capability
        # at the sync-hook layer — the writer already passed V7's tree:put
        # capability check, so we treat this cascade as wildcard-authorized
        # within the role extension. Per-assignee RL2 (SI-15) does not
        # apply here in the same way as `:define` / `:re-derive`; the
        # watcher is OPTIONAL defense-in-depth for misconfigured
        # deployments (per v1.6 §1.3 capability-discipline framing).
        wildcard_grants = [
            {
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }
        ]
        _re_derive_role_internal(
            self._ext._pathway,
            self._ext._keypair,
            context=context,
            role_name=role_name,
            parent_hash=None,
            parent_cap_expires_at=None,
            caller_grants=wildcard_grants,
            caller_expires_at=None,
            local_peer_id_for_attenuation=local_peer_id,
            operation=_OP_RE_DERIVE,
        )
        return None


class RoleExtension(Extension):
    """Extension that wires the role machinery to the emit pathway.

    Two responsibilities (per EXTENSION-ROLE.md):

    1. Fleet-wide reactive sweep on exclusion entities (§6.5 IA8) —
       when an exclusion entity for `system/role/{context}/excluded/
       {peer_id}` arrives via tree-sync (or local write), this peer
       sweeps its own role-derived subtree for that (context, peer)
       so caps it holds locally are deleted.

    2. IA11 option (b) re-derive cascade on role-definition mutation
       outside the role handler — when a `system/role` entity is
       written by direct `tree:put` (or arrives via tree-sync), trigger
       a `re-derive` cascade for that role. The `system/role:define`
       op cascades synchronously on its own; the hook's discriminator
       (change context's `handler_pattern`) avoids double-cascading.

    Usage:
        peer = (PeerBuilder()
            .with_keypair(kp)
            .with_role_handler()
            .with_role_extension()
            .build())

    `with_role_extension()` is auto-installed by `with_all_handlers()`.
    """

    def __init__(self) -> None:
        self._pathway: EmitPathway | None = None
        self._keypair: Keypair | None = None
        self._local_peer_id: str = ""
        self._exclusion_watcher: _RoleExclusionWatcher | None = None
        self._definition_watcher: _RoleDefinitionWatcher | None = None

    def initialize(self, ctx: ExtensionContext) -> None:
        if ctx.emit_pathway is None:
            return
        self._pathway = ctx.emit_pathway
        self._keypair = ctx.keypair
        self._local_peer_id = ctx.peer_id
        self._exclusion_watcher = _RoleExclusionWatcher(self)
        self._definition_watcher = _RoleDefinitionWatcher(self)
        ctx.emit_pathway._add_internal_hook(
            self._exclusion_watcher,
            name="role/exclusion-sweep",
        )
        ctx.emit_pathway._add_internal_hook(
            self._definition_watcher,
            name="role/definition-cascade",
        )

    def shutdown(self) -> None:
        if self._pathway is None:
            return
        if self._exclusion_watcher is not None:
            self._pathway._remove_internal_hook(self._exclusion_watcher)
        if self._definition_watcher is not None:
            self._pathway._remove_internal_hook(self._definition_watcher)


# =============================================================================
# Dispatcher
# =============================================================================


async def role_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """Dispatch `system/role:*` operations per EXTENSION-ROLE.md v1.5."""
    if operation == _OP_DEFINE:
        return await _handle_define(ctx, params)
    if operation == _OP_ASSIGN:
        return await _handle_assign(ctx, params)
    if operation == _OP_UNASSIGN:
        return await _handle_unassign(ctx, params)
    if operation == _OP_EXCLUDE:
        return await _handle_exclude(ctx, params)
    if operation == _OP_UNEXCLUDE:
        return await _handle_unexclude(ctx, params)
    if operation == _OP_RE_DERIVE:
        return await _handle_re_derive(ctx, params)
    if operation == _OP_DELEGATE:
        return await _handle_delegate(ctx, params)
    return _error(
        501, "unsupported_operation",
        f"role handler does not support {operation!r}",
    )


__all__ = [
    "ROLE_TYPE",
    "ROLE_ASSIGNMENT_TYPE",
    "ROLE_EXCLUSION_TYPE",
    "ROLE_DERIVED_TOKEN_LINK_TYPE",
    "ROLE_HANDLER_PATTERN",
    "ROLE_PREFIX",
    "ROLE_DERIVED_PREFIX",
    "RESERVED_ROLE_NAMES",
    "INITIAL_GRANT_POLICY_PATH",
    "INITIAL_GRANT_POLICY_TYPE",
    "INITIAL_GRANT_MODE_ANONYMOUS_DENY",
    "INITIAL_GRANT_MODE_ANONYMOUS_ALLOW",
    "INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION",
    "INITIAL_GRANT_MODES",
    "role_handler",
    "role_definition_path",
    "role_assignment_path",
    "role_exclusion_path",
    "role_derived_token_path",
    "role_derived_token_link_path",
    "parse_role_definition_path",
    "parse_assignment_path",
    "parse_assignment_peer_path",
    "parse_exclusion_path",
    "resolve_templates",
    "is_excluded",
    "RoleExtension",
    "startup_time_role_derived_token",
]
