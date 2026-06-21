"""EXTENSION-ROLE §4.7 — initial-grant policy resolver.

Wires the connect handler's grant resolver to the role extension. At
AUTHENTICATE time the resolver reads the singleton policy entity at
`system/role/initial-grant-policy` and dispatches on the `unknown_peer`
mode:

- `anonymous-deny`           — return None; the connect handler falls
                               through to its static grant configuration.
- `anonymous-allow`          — issue grants from
                               `system/role/{default_context}/{default_role}`
                               on every connection.
- `recognize-on-attestation` — issue those grants only to peers whose
                               agent-cert chain terminates at the local
                               peer-config's `trusts_quorum`. Falls back
                               per `identity_required` (true → deny;
                               false → allow).

Layer-2 exclusion (§6.1) fires before mode dispatch: an excluded peer
gets None regardless of mode.

The resolver signature `(peer_id, identity_hash) -> list[Grant] | None`
matches the widened Go hook (`core/protocol/connect.go`); both arguments
are needed because the role-extension tree state is keyed by the
connecting peer's `system/peer` content hash while session state is
keyed by Base58 peer-id.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from entity_core.capability.token import Grant
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.bounds import Bounds
from entity_core.storage.emit import EmitPathway

from entity_handlers.attestation import (
    DEFAULT_MAX_DEPTH,
    find_attestations_by,
    find_attestations_targeting,
    is_attestation_live,
)
from entity_handlers.identity import (
    FUNCTION_AGENT,
    FUNCTION_CONTROLLER,
    KIND_IDENTITY_CERT,
    PEER_CONFIG_PATH,
)
from entity_handlers.role import (
    INITIAL_GRANT_MODE_ANONYMOUS_ALLOW,
    INITIAL_GRANT_MODE_ANONYMOUS_DENY,
    INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
    INITIAL_GRANT_POLICY_PATH,
    is_excluded,
    role_definition_path,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


# A grant resolver consulted at AUTHENTICATE time. Returning None means
# "no opinion — fall through to the connect handler's static grant
# configuration." Returning [] means "deny all" (but the connect handler
# may still issue an empty cap; callers SHOULD only return [] when they
# really mean to issue an empty cap, and otherwise return None).
GrantResolver = Callable[[str, "bytes | None"], "list[Grant] | None"]


@dataclass(frozen=True)
class InitialGrantPolicy:
    """Decoded `system/role/initial-grant-policy` entity."""

    unknown_peer: str
    default_role: str = ""
    default_context: str = ""
    identity_required: bool = False


# ---------------------------------------------------------------------------
# Policy entity reader
# ---------------------------------------------------------------------------


def read_initial_grant_policy(
    pathway: EmitPathway,
) -> InitialGrantPolicy | None:
    """Load the singleton policy entity at
    `system/role/initial-grant-policy`. Returns None when unbound or when
    the entity is malformed. The resolver treats both cases as
    "anonymous-deny" (the spec-pinned default per §4.7)."""
    h = pathway.entity_tree.get(INITIAL_GRANT_POLICY_PATH)
    if h is None:
        return None
    entity = pathway.content_store.get(h)
    if entity is None:
        return None
    data = entity.data if isinstance(entity.data, dict) else None
    if not data:
        return None
    mode = data.get("unknown_peer")
    if not isinstance(mode, str) or not mode:
        return None
    return InitialGrantPolicy(
        unknown_peer=mode,
        default_role=data.get("default_role", "") or "",
        default_context=data.get("default_context", "") or "",
        identity_required=bool(data.get("identity_required", False)),
    )


# ---------------------------------------------------------------------------
# HandlerContext stub (for re-using attestation helpers outside dispatch)
# ---------------------------------------------------------------------------


def _stub_handler_context(
    pathway: EmitPathway, local_peer_id: str,
) -> HandlerContext:
    """Construct a minimal HandlerContext rooted at `pathway`. Used to
    feed the attestation-extension lookup helpers, which take a
    HandlerContext but only read `ctx.emit_pathway`."""
    return HandlerContext(
        local_peer_id=local_peer_id,
        remote_peer_id="",
        handler_grant={},
        caller_capability={},
        emit_pathway=pathway,
        bounds=Bounds(),
    )


# ---------------------------------------------------------------------------
# Recognize-on-attestation predicate
# ---------------------------------------------------------------------------


def _now_ms() -> int:
    return int(time.time() * 1000)


def _read_trusted_quorum(pathway: EmitPathway) -> bytes | None:
    """Read `peer-config.trusts_quorum`. Returns None when peer-config is
    unbound (recognition impossible)."""
    h = pathway.entity_tree.get(PEER_CONFIG_PATH)
    if h is None:
        return None
    entity = pathway.content_store.get(h)
    if entity is None:
        return None
    data = entity.data if isinstance(entity.data, dict) else None
    if not data:
        return None
    raw = data.get("trusts_quorum")
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, dict):
        algorithm = raw.get("algorithm")
        digest = raw.get("digest")
        if isinstance(algorithm, int) and isinstance(digest, bytes):
            return bytes([algorithm]) + digest
    return None


def _props(att: Any) -> dict[str, Any]:
    data = getattr(att, "data", None) or {}
    props = data.get("properties") if isinstance(data, dict) else None
    return props if isinstance(props, dict) else {}


def _is_identity_cert_with_function(att: Any, function_name: str) -> bool:
    props = _props(att)
    return (
        props.get("kind") == KIND_IDENTITY_CERT
        and props.get("function") == function_name
    )


def _hash_field(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        algorithm = value.get("algorithm")
        digest = value.get("digest")
        if isinstance(algorithm, int) and isinstance(digest, bytes):
            return bytes([algorithm]) + digest
    return None


def recognize_identity_cert(
    pathway: EmitPathway,
    connecting_peer_hash: bytes,
    *,
    local_peer_id: str = "",
    as_of_ms: int | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> tuple[bool, "bytes | None"]:
    """Walk the agent-cert chain from `connecting_peer_hash` and decide
    whether it terminates at a controller cert under the local peer's
    trusted quorum.

    Returns `(recognized, controller_cert_hash)` — controller_cert_hash
    is the live controller cert at the recognition root, or None when
    the chain doesn't terminate at the trusted quorum.

    Per the handoff doc §5: an agent-cert's `attesting` field points to
    the controller's `system/peer` content_hash (the peer being attested
    FOR), NOT the controller-cert entity hash. So we walk by
    "find certs targeting this peer-hash" recursively.
    """
    trusted_quorum = _read_trusted_quorum(pathway)
    if trusted_quorum is None:
        # Peer-config unbound — recognition impossible.
        return False, None

    ctx = _stub_handler_context(pathway, local_peer_id)
    now = as_of_ms if as_of_ms is not None else _now_ms()

    def _live(att: Any) -> bool:
        return is_attestation_live(att, ctx, as_of=now)

    # Step 1: find live agent-certs targeting the connecting peer's hash.
    agent_certs = find_attestations_targeting(
        connecting_peer_hash,
        lambda a, _c: _is_identity_cert_with_function(a, FUNCTION_AGENT)
        and _live(a),
        ctx,
    )
    if not agent_certs:
        return False, None

    # Step 2: each agent-cert's `attesting` is the controller peer-hash.
    # Walk to a controller cert under the trusted quorum.
    for cert in agent_certs:
        controller_peer_hash = _hash_field(cert.data.get("attesting"))
        if controller_peer_hash is None:
            continue
        recognized, root = _walk_to_trusted_controller(
            controller_peer_hash, trusted_quorum, ctx, _live, depth=max_depth,
            visited=frozenset(),
        )
        if recognized:
            return True, root
    return False, None


def _walk_to_trusted_controller(
    candidate_peer_hash: bytes,
    trusted_quorum: bytes,
    ctx: HandlerContext,
    live: Callable[[Any], bool],
    *,
    depth: int,
    visited: frozenset[bytes],
) -> tuple[bool, "bytes | None"]:
    """Recurse over controller certs targeting `candidate_peer_hash`.

    Returns the live controller cert whose `attesting` is the trusted
    quorum (recognition root). When the cert's `attesting` is a
    sub-controller peer-hash instead, recurse via that peer-hash to
    look for the trusted quorum further up the chain. Bounded by
    `depth`; cycles are blocked by `visited`."""
    if depth <= 0 or candidate_peer_hash in visited:
        return False, None
    visited = visited | {candidate_peer_hash}

    controller_certs = find_attestations_targeting(
        candidate_peer_hash,
        lambda a, _c: _is_identity_cert_with_function(a, FUNCTION_CONTROLLER)
        and live(a),
        ctx,
    )
    for cert in controller_certs:
        attesting = _hash_field(cert.data.get("attesting"))
        if attesting is None:
            continue
        if attesting == trusted_quorum:
            return True, cert.compute_hash()
        # Sub-controller: walk via attesting (parent controller peer-hash).
        recognized, root = _walk_to_trusted_controller(
            attesting, trusted_quorum, ctx, live,
            depth=depth - 1, visited=visited,
        )
        if recognized:
            return True, root
    return False, None


# ---------------------------------------------------------------------------
# Mode dispatch
# ---------------------------------------------------------------------------


def _read_role_grants(
    pathway: EmitPathway,
    context: str,
    role_name: str,
) -> "list[Grant] | None":
    """Read the role definition at
    `system/role/{context}/{role_name}` and return its `grants` field as
    Grant objects. Returns None when the role definition is unbound or
    its grants field is missing — fail-closed; the caller SHOULD NOT
    issue an empty cap as a fallback."""
    if not context or not role_name:
        return None
    path = role_definition_path(context, role_name)
    h = pathway.entity_tree.get(path)
    if h is None:
        return None
    entity = pathway.content_store.get(h)
    if entity is None:
        return None
    data = entity.data if isinstance(entity.data, dict) else None
    if not data:
        return None
    raw_grants = data.get("grants")
    if not isinstance(raw_grants, list) or not raw_grants:
        return None
    out: list[Grant] = []
    for g in raw_grants:
        if isinstance(g, dict):
            out.append(Grant.from_dict(g))
    return out or None


class PolicyGrantResolver:
    """Connect-handler grant resolver that consults the policy entity at
    `system/role/initial-grant-policy` and dispatches on `unknown_peer`.

    Construct after peer build (the resolver needs the peer's
    EmitPathway). Install via `peer.set_grant_resolver(...)`. Compose
    with peer-id-keyed static resolvers via `chain_grant_resolvers`.
    """

    def __init__(
        self,
        pathway: EmitPathway,
        *,
        local_peer_id: str = "",
        max_chain_depth: int = DEFAULT_MAX_DEPTH,
    ) -> None:
        self._pathway = pathway
        self._local_peer_id = local_peer_id
        self._max_chain_depth = max_chain_depth

    def __call__(
        self,
        peer_id: str,
        identity_hash: bytes | None,
    ) -> list[Grant] | None:
        policy = read_initial_grant_policy(self._pathway)
        if policy is None:
            # Default per §4.7 — anonymous-deny: no opinion, let the
            # static fallback fire.
            return None

        # Layer-2 exclusion (§6.1) — fires before mode dispatch.
        if (
            identity_hash is not None
            and policy.default_context
            and is_excluded(
                policy.default_context,
                identity_hash.hex(),
                _stub_handler_context(self._pathway, self._local_peer_id),
            )
        ):
            logger.debug(
                "[role-policy] peer %s excluded in context %s",
                peer_id[:8] if peer_id else "?",
                policy.default_context,
            )
            return None

        mode = policy.unknown_peer

        if mode == INITIAL_GRANT_MODE_ANONYMOUS_DENY:
            return None

        if mode == INITIAL_GRANT_MODE_ANONYMOUS_ALLOW:
            return _read_role_grants(
                self._pathway, policy.default_context, policy.default_role,
            )

        if mode == INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION:
            recognized = False
            if identity_hash is not None:
                recognized, _ = recognize_identity_cert(
                    self._pathway,
                    identity_hash,
                    local_peer_id=self._local_peer_id,
                    max_depth=self._max_chain_depth,
                )
            if recognized:
                return _read_role_grants(
                    self._pathway,
                    policy.default_context,
                    policy.default_role,
                )
            if policy.identity_required:
                return None
            return _read_role_grants(
                self._pathway, policy.default_context, policy.default_role,
            )

        # Unknown mode → fail closed.
        logger.warning("[role-policy] unknown mode %r — failing closed", mode)
        return None


# ---------------------------------------------------------------------------
# Resolver chaining
# ---------------------------------------------------------------------------


def chain_grant_resolvers(*resolvers: GrantResolver | None) -> GrantResolver:
    """Compose grant resolvers in priority order. The first resolver to
    return a non-None result wins. None entries are skipped (so callers
    can pass an Optional static resolver alongside the policy resolver)."""
    chain = [r for r in resolvers if r is not None]

    def composed(
        peer_id: str, identity_hash: bytes | None,
    ) -> list[Grant] | None:
        for r in chain:
            result = r(peer_id, identity_hash)
            if result is not None:
                return result
        return None

    return composed


__all__ = [
    "GrantResolver",
    "InitialGrantPolicy",
    "PolicyGrantResolver",
    "chain_grant_resolvers",
    "read_initial_grant_policy",
    "recognize_identity_cert",
]
