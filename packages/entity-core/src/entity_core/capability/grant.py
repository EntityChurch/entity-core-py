"""Capability grant creation and management.

This module provides utilities for creating capability tokens and grants.

V4 Changes:
- granter and grantee are bytes (Hash), not strings
- Signatures sign hash bytes, not strings

V6.0 Changes:
- handlers, resources, operations are now CapabilityScope objects
- Each scope has include/exclude arrays
- Added peers field for peer scope
"""

from __future__ import annotations

import time
from typing import Any

from entity_core.capability.token import (
    CapabilityScope,
    CapabilityToken,
    Grant,
    grantee_is_zero,
)
from entity_core.crypto.identity import Keypair
from entity_core.protocol.auth import create_identity_entity, create_signature_entity
from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import Hash


def create_capability_token(
    granter_keypair: Keypair,
    grantee_identity: Entity,
    grants: list[Grant],
    expires_in_ms: int | None = None,
    *,
    algorithm: int | None = None,
) -> tuple[Entity, Entity, Entity]:
    """Create a capability token with supporting entities.

    V4: granter and grantee are bytes (Hash) in data.

    Args:
        granter_keypair: The granter's keypair (for signing).
        grantee_identity: The grantee's identity entity. Its ``content_hash``
            is honored verbatim when carried from the wire (§1.8) — the
            grantee reference is the connecting peer's *authored* identity
            hash, never recomputed here.
        grants: List of permission grants.
        expires_in_ms: Optional expiration time from now in milliseconds.
        algorithm: V7 v7.69 §4.5a active content_hash_format. The cap entity,
            the granter identity, and the cap signature are all authored under
            it (the cap chain is format-self-consistent, §5.5 freeze). ``None``
            → process-global default.

    Returns:
        Tuple of (capability_entity, granter_identity, signature_entity).
    """
    # Create granter identity (authored under the active format)
    granter_identity = create_identity_entity(granter_keypair, algorithm=algorithm)
    granter_hash = granter_identity.compute_hash()
    # §1.8: if grantee_identity carries a wire content_hash, compute_hash
    # returns it verbatim (the connecting peer's authored form); otherwise it
    # is hashed under the entity's own hash_algorithm.
    grantee_hash = grantee_identity.compute_hash()

    # SEC-18 / V7 v7.39 PR-3: fail-fast at the generic mint chokepoint so a
    # zero-hash-grantee cap never gets signed or bound. Chain-walk would
    # reject it later (`unresolvable_grantee`), but a bound dud cap pollutes
    # the audit trail in the meantime. Mirrors CapabilityToken.validate_structure().
    if grantee_is_zero(grantee_hash):
        raise ValueError(
            "capability grantee MUST be a non-zero hash "
            "(SEC-18 / V7 v7.39 PR-3 — a zero-hash grantee never resolves "
            "to a system/identity entity)"
        )

    # V4: granter/grantee in data as bytes for content_hash security
    # V4 §3.6: created_at is required, optional fields are omitted (not null)
    now_ms = int(time.time() * 1000)
    cap_data: dict[str, Any] = {
        "grants": [g.to_dict() for g in grants],
        "granter": granter_hash,  # V4: bytes
        "grantee": grantee_hash,  # V4: bytes
        "created_at": now_ms,
    }
    # V4: Optional fields are omitted, not set to None
    if expires_in_ms:
        cap_data["expires_at"] = now_ms + expires_in_ms
    # Note: delegation_caveats is also optional, omitted when empty

    # Create capability entity to compute hash
    cap_for_signing = Entity(
        type="system/capability/token",
        data=cap_data,
        hash_algorithm=algorithm,
    )
    cap_hash = cap_for_signing.compute_hash()

    # V4: Sign the hash bytes (not string)
    # V4: signer is granter_hash (identity hash), not peer_id
    signature_entity = create_signature_entity(
        granter_keypair, cap_hash, granter_hash, algorithm=algorithm,
    )

    # V4: No refs - granter/grantee in data, signature found via target-matching
    capability_entity = Entity(
        type="system/capability/token",
        data=cap_data,
        hash_algorithm=algorithm,
    )

    return capability_entity, granter_identity, signature_entity


def create_full_access_grant() -> list[Grant]:
    """Create grants for full access to everything.

    Uses wildcard for operations per ENTITY-CORE-PROTOCOL-V7 §5.3. Per V7
    §1.4 / §5.4 strict cap-resource canonicalization, bare `*` resolves to
    `/{granter_peer_id}/*` (local-namespace only). To grant cross-namespace
    authority — required for V7 invariant signature pointers like
    `/{ephemeral_peer}/system/signature/{hex}` — the cap MUST also include
    `/*/*` in resources and `peers=["*"]` for the cross-peer dimension.
    Cross-impl: matches Rust's Round-2 R-5 / Go's open-access-cap shape.

    Includes a query-specific grant with explicit constraints (tree scope,
    wildcard type_scope) per PROPOSAL-CAPABILITY-GRANT-ALLOWANCES (v7.14)
    so the query constraint pathway is exercised even in open-access mode.

    Returns:
        List of grants allowing all operations on all resources.
    """
    query_grant = Grant.create(
        handlers=["system/query"],
        resources=["*", "/*/*"],
        operations=["find", "count"],
        peers=["*"],
        constraints={"type_scope": {"include": ["*"]}},
        allowances={"scope": "content_store"},
    )
    general_grant = Grant.create(
        handlers=["*"],
        resources=["*", "/*/*"],
        operations=["*"],
        peers=["*"],
    )
    return [query_grant, general_grant]


def create_owner_grant(peer_id: str) -> list[Grant]:
    """The peer-owner seed grant — full authority over the peer's OWN
    namespace ``/{peer_id}/*`` (V7 §6.9a peer-authority-bootstrap, F27).

    This is the principal-level owner capability the §6.9a bootstrap
    materializes at L0 for the key-holder. Unlike ``create_full_access_grant``
    it does NOT carry the cross-namespace ``/*/*`` + ``peers=["*"]`` axes —
    the owner cap is authority over the local namespace only; cross-peer
    authority is a separate, explicitly-granted axis. ``"*"`` is included
    alongside the explicit ``/{peer_id}/*`` so the entry is self-documenting
    in the tree (A5 inspectability) while staying byte-stable under the
    §5.4 canonicalization that resolves bare ``*`` to ``/{granter}/*``.

    Args:
        peer_id: The local peer's Base58 PeerID (the namespace being owned).

    Returns:
        A single-grant list granting all handlers/operations over the
        peer's own namespace.
    """
    return [
        Grant.create(
            handlers=["*"],
            resources=["*", f"/{peer_id}/*"],
            operations=["*"],
        ),
    ]


def create_read_only_grant(resource_patterns: list[str], handler_patterns: list[str] | None = None) -> list[Grant]:
    """Create read-only grants for specific resources.

    Args:
        resource_patterns: URI patterns to grant read access to.
        handler_patterns: Handler patterns to authorize. Defaults to ["system/tree"].

    Returns:
        List of grants allowing get operations via tree handler.
    """
    if handler_patterns is None:
        handler_patterns = ["system/tree"]
    return [
        Grant.create(
            handlers=handler_patterns,
            resources=resource_patterns,
            operations=["get"],
        ),
    ]


def create_connect_grants() -> list[Grant]:
    """Create limited connect grants for initial capability.

    Connect capability grants limited access for type/handler discovery
    and capability negotiation per ENTITY-CORE-PROTOCOL-V7 §5.7.

    Returns:
        List of grants for connect scope.
    """
    return [
        # Tree handler for type/handler discovery (V7.7 singular namespaces)
        Grant.create(
            handlers=["system/tree"],
            resources=["system/type/*", "system/handler/*"],
            operations=["get"],
        ),
        # Capability handler for negotiation
        Grant.create(
            handlers=["system/capability"],
            resources=[],
            operations=["request"],
        ),
    ]
