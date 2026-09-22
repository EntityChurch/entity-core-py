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

#: `expires_at` is a `primitive/uint` and every other implementation decodes it
#: as a 64-bit unsigned integer. Python's arbitrary-precision ints mean the
#: overflow other stacks must guard against simply does not occur here — it
#: succeeds and encodes as a CBOR bignum instead.
_UINT64_MAX = (1 << 64) - 1


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
        algorithm: V7 v7.69 §4.5a active content_hash_format. The cap entity
            and the cap signature are authored under it (the cap chain is
            format-self-consistent, §5.5 freeze). The granter *identity* is
            not: §4.5a item 1a floor-pins ``system/peer`` unconditionally, and
            it is the named exception the chain's self-consistency reads
            around. ``None`` → process-global default.

    Returns:
        Tuple of (capability_entity, granter_identity, signature_entity).
    """
    # Create granter identity (floor-pinned, §4.5a item 1a)
    granter_identity = create_identity_entity(granter_keypair)
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
    # V4: Optional fields are omitted, not set to None.
    #
    # This is the **kernel's** mint path — `entity_handlers/capability.py` has
    # its own (`_mint_token`), so one entity type has two independent minting
    # implementations and a guard on one of them is a guard on half the repo.
    # `entity-core-go`'s CAP-6 probe reached the handler path; this one it
    # never saw, and every future caller of `create_capability_token` arrives
    # here.
    #
    # Two rules, both from §5.6 (see `_bounded_expiry` in the handler for the
    # full reasoning):
    #   * an unrepresentable `now + ttl` is **absent** — never wrapped, never
    #     saturated, and never carried at Python's arbitrary precision, which
    #     cbor2 would encode as a bignum no uint64 peer can decode;
    #   * `0` means **expires now**, not *never expires*. The previous
    #     truthiness test folded a zero ttl into the absent case, which is the
    #     dangerous direction: it hands back an immortal token for the request
    #     that asked for the shortest possible life.
    if expires_in_ms is not None:
        expiry = now_ms + expires_in_ms
        if expiry < 0:
            # Underflow is not symmetric with overflow: "absent" here would
            # mean never-expires. Clamp to already-expired instead.
            cap_data["expires_at"] = 0
        elif expiry <= _UINT64_MAX:
            cap_data["expires_at"] = expiry
        # else: unrepresentable -> omitted, per §5.6.
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


def create_default_handler_self_grant() -> list[Grant]:
    """The §6.2 default per-handler self-grant — what a handler declaring
    neither ``requested_scope`` nor ``internal_scope`` receives.

    Pinned normatively at protocol 0.8.2.3, and the two dimensions pull in
    opposite directions on purpose (§6.3):

    - ``resources`` spans namespaces (``/*/*``) because a peer's store is one
      local address space keyed by peer id (§1.4). ``/{them}/…`` names a
      **local** region holding that peer's cached or mirrored data, so writing
      there is a local write, not a remote reach. A proposal to narrow this to
      ``/{local}/*`` was **withdrawn** at 0.8.2.3 — it closes no hole and
      breaks the common follow-mirror write.
    - ``peers`` is **omitted**, which §5.2 Dimension 4 defaults to
      ``{include: [local_peer_id]}`` **and still checks**. The whole network
      bound is carried here. The spec calls ``peers: ["*"]`` — what this repo
      shipped, via :func:`create_full_access_grant` — *"specifically wrong …
      the one direction that must not be widened"*: it authorizes sub-dispatch
      at *foreign peers'* handlers under a grant nobody minted for that
      purpose.

    **This is a ceiling, not merely a default.** For a handler that declares
    nothing, this grant IS its §5.2 Dimension 3 ceiling on the in-process
    sub-dispatch path — so the silent case is not the harmless case when the
    silent value is a ceiling. That is why it is its own function rather than
    a shared open-access one: :func:`create_full_access_grant` is still the
    right shape for the two surfaces that genuinely reach across peers (the
    debug-mode grants handed to connecting peers, and the extension execute
    pathway that delivers notifications to remote subscribers), and folding
    three authorities into one helper is how the wrong one gets widened.

    Cohort: `entity-core-go` `defaultHandlerSelfGrant` has always omitted
    ``peers`` and routed the divergence as spec-issue ``2026-08-23-a``; it was
    ruled in that shape, so this is convergence on a ruling, not on a peer.

    Returns:
        The single-entry default scope, as a list (the grant array shape).
    """
    return [Grant.create(
        handlers=["*"],
        operations=["*"],
        # The whole LOCAL store, including the foreign-namespace regions it
        # holds. `peers` is deliberately not passed — see above.
        resources=["/*/*"],
    )]


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


def mint_deliver_token(
    inbox_owner_keypair: Keypair,
    delivering_engine_identity: Entity,
    inbox_uri: str,
    inbox_operation: str = "receive",
    ttl_ms: int | None = None,
) -> tuple[Entity, Entity, Entity]:
    """Mint an `EXTENSION-SUBSCRIPTION` §1.2 **subscription deliver_token**.

    This is the row-2 capability of §1.2's three-slot table — *"future async
    dispatch from the subscription engine to the subscriber's inbox"* — and it
    is a different object from the two rows either side of it. Getting the
    slot wrong is the failure §1.2 opens by naming: *"confusing them is a
    common source of design and review confusion."*

    .. rubric:: The two properties, together (arch's Subscription Phase 1)

    1. **A-rooted** — issued by *"the authority of the peer that owns the
       target inbox"* (§1.2). Here that is ``inbox_owner_keypair``: for A
       subscribing to B's data, **A** signs, because A is authorizing B's
       engine to reach A's inbox. A B-rooted token is B authorizing itself.
    2. **`grantee` = the delivering engine** — ``delivering_engine_identity``,
       i.e. **B**, the peer whose subscription engine will originate the
       delivery. §1.2's §7 pseudocode states the pair outright: *"the deliver
       token (granter = subscriber, grantee = server)."*

    **A self-grant (granter == grantee == the subscriber) satisfies neither
    half in substance** and is the shape that quietly does nothing: §1.4's
    outbound gate relaxes Dimension 4 only for a credential whose leaf
    ``grantee`` is the peer about to spend it, so a token granted back to the
    subscriber relaxes **nothing** for B's engine. It looks like authority and
    is inert — which is why it is refused here rather than left to fail
    silently at delivery time, two peers and one async hop away from the mint.

    .. rubric:: Phase 1 mints; it does not gate

    Nothing in this repo *presents* this token on the outbound delivery path
    yet — that is Phase 2, and per arch's sequencing no seat presents before
    all three mint. See ``docs/SPEC-AMBIGUITIES.md`` SA-PY-46 for the measured
    consequence of landing the gating half early.

    Args:
        inbox_owner_keypair: The subscriber's keypair (A) — the peer that owns
            the target inbox. This is the **root** of the token's authority.
        delivering_engine_identity: The identity entity of the peer whose
            subscription engine will deliver (B). Becomes the ``grantee``.
        inbox_uri: The inbox URI to authorize, e.g.
            ``entity://{A}/system/inbox/{name}``.
        inbox_operation: The operation to authorize (``receive``).
        ttl_ms: Optional time-to-live in milliseconds.

    Returns:
        ``(capability_entity, granter_identity, signature_entity)`` — the
        three entities the subscribe request must carry in ``included``.

    Raises:
        ValueError: if the grantee is the inbox owner itself (the inert
            self-grant above).
    """
    from entity_core.capability.token import DelegationCaveats
    from entity_core.utils.path import extract_handler_path

    owner_identity = create_identity_entity(inbox_owner_keypair)
    if owner_identity.compute_hash() == delivering_engine_identity.compute_hash():
        raise ValueError(
            "a subscription deliver_token granted back to the inbox owner is "
            "a self-grant and relaxes nothing: §1.4 relaxes Dimension 4 only "
            "for a credential whose leaf grantee is the peer spending it, so "
            "the delivering engine gets no authority from this token. "
            "EXTENSION-SUBSCRIPTION §1.2: granter = subscriber, "
            "grantee = server"
        )

    resource_path = extract_handler_path(inbox_uri)
    grants = [
        Grant.create(
            handlers=["system/inbox/*"],
            resources=[resource_path],
            operations=[inbox_operation],
        ),
    ]

    capability_entity, granter_identity, _signature_entity = (
        create_capability_token(
            inbox_owner_keypair,
            delivering_engine_identity,
            grants,
            expires_in_ms=ttl_ms,
        )
    )

    # A deliver_token is spent by one named engine at one named inbox; there
    # is no onward party for it to be delegated to, so the caveat is part of
    # the shape rather than a hardening option.
    cap_data = capability_entity.data.copy()
    cap_data["delegation_caveats"] = DelegationCaveats(no_delegation=True).to_dict()
    capability_entity = Entity(type="system/capability/token", data=cap_data)

    granter_hash = granter_identity.compute_hash()
    signature_entity = create_signature_entity(
        inbox_owner_keypair, capability_entity.compute_hash(), granter_hash,
    )
    return capability_entity, granter_identity, signature_entity
