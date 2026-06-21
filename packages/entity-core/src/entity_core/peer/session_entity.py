"""Per-peer session entity (PROPOSAL-TRANSPORT-FAMILY R6, §9 shape).

The handshake-cap state for a remote peer is held as a tree entity at
``system/peer/session/{remote_peer_id_hex}`` — the durable per-peer AUTH
record. It answers exactly one question for §10 dispatch: *"do I already
hold a valid capability to talk to this peer, or must I re-handshake?"*

Per V7 v7.64 §1.4 (positional encoding rule), the path segment is the
lowercase hex of the remote peer's ``system/peer`` entity content_hash
(33 bytes; 66 hex chars starting with ``00`` for ECFv1-SHA-256). The
remote's Base58 ``peer_id`` survives as the ``remote_peer_id`` body
field (typed ``system/peer-id``).

It is NOT the liveness / reachability / lifecycle record (those live on
``system/peer/status``, ``system/connection``, and
``system/peer/transport/*`` per the 4-entity boundary §7.1 #3). Fields
that are really liveness or lifecycle do NOT belong here.

Schema (§9.3 minimal — arch ruling, commit ``523cdc5``):

    system/peer/session/{remote_peer_id_hex} := {
        remote_peer_id,
        remote_identity_hash,                  # 33-byte system/hash
        remote_public_key?,                    # optional denorm (§9.2 R6-g)
        held_capability:    {hash, chain},     # cap remote granted me
        minted_capability?: {hash, chain},     # cap I issued remote — R3a
        granted_at,                            # uint ms = last handshake
        expires_at?,                           # uint ms, validity window
    }

DROPPED vs the §7.2 strawman: ``last_active`` (§9.1 R6-b — liveness, not
auth) and ``status`` (§9.1 R6-c — lifecycle is ``system/peer/status``'s
job; validity is derivable from ``expires_at``).

Held vs minted is the **bidirectional** lens (§9.1 R6-a Option A):

- ``held_capability``: the cap *remote* granted me. The dialer (grantee)
  writes it after a successful handshake. Dispatch reads it to
  authenticate outbound EXECUTE.
- ``minted_capability``: the cap *I* minted for remote. The granter
  writes it after issuing the connect cap. Used as the R3a idempotency
  anchor (re-mint avoidance) and the revocation anchor. In a
  bidirectional A↔B pair, A's ``minted_capability`` for B *is the same
  cap entity* as B's ``held_capability`` from A — one cap, recorded from
  both ends.

``minted_capability`` is NOT a back-delivery cap (§7.1 #2 + §9.1 R6-a
reconciliation). Back-direction auth remains ``deliver_token``,
unchanged.

No self-session (§9.1 R6-f): a peer never writes
``system/peer/session/{local_peer_id_hex}``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from entity_core.protocol.entity import Entity
from entity_core.primitives import Uint
from entity_core.storage.emit import EmitContext, EmitPathway

if TYPE_CHECKING:
    from entity_core.storage.content_store import ContentStore
    from entity_core.storage.entity_tree import EntityTree


SESSION_PATH_PREFIX = "system/peer/session"

#: Safety margin (ms) so we don't reuse an about-to-expire cap.
EXPIRY_SAFETY_MARGIN_MS = 1_000


def session_path(remote_identity_hash: bytes) -> str:
    """Return the tree path for a remote peer's session entity.

    Per V7 v7.64 §1.4 the path key is lowercase hex of the remote peer's
    ``system/peer`` content_hash (33 bytes / 66 hex chars). The caller
    holds those bytes — typically as ``Session.remote_identity_hash`` or
    the result of ``_identity_hash_from_authenticate_params``.
    """
    return f"{SESSION_PATH_PREFIX}/{remote_identity_hash.hex()}"


def read_session(
    content_store: "ContentStore",
    entity_tree: "EntityTree",
    remote_identity_hash: bytes,
) -> Entity | None:
    """Read the ``system/peer/session/{remote_peer_id_hex}`` entity, if present."""
    uri = entity_tree.normalize_uri(session_path(remote_identity_hash))
    h = entity_tree.get(uri)
    if h is None:
        return None
    return content_store.get(h)


def _resolve_cap_pointer(
    content_store: "ContentStore",
    session: Entity,
    field_name: str,
) -> tuple[Entity, list[Entity], Entity] | None:
    """Resolve a ``held_capability`` / ``minted_capability`` pointer into
    ``(capability_entity, chain_entities, session_entity)`` or ``None``.

    Returns ``None`` when the field is absent, the cap is expired (within
    the safety margin), the cap entity is missing from the content store,
    or any chain entity is missing.
    """
    expires_at = session.data.get("expires_at")
    if expires_at is not None:
        now_ms = int(time.time() * 1000)
        if expires_at <= now_ms + EXPIRY_SAFETY_MARGIN_MS:
            return None

    cap_field = session.data.get(field_name) or {}
    cap_hash = cap_field.get("hash")
    if cap_hash is None:
        return None

    capability_entity = content_store.get(cap_hash)
    if capability_entity is None:
        return None

    chain_hashes = cap_field.get("chain", []) or []
    chain_entities: list[Entity] = []
    for h in chain_hashes:
        e = content_store.get(h)
        if e is None:
            return None
        chain_entities.append(e)

    return capability_entity, chain_entities, session


def read_minted_capability(
    content_store: "ContentStore",
    entity_tree: "EntityTree",
    remote_identity_hash: bytes,
) -> tuple[Entity, list[Entity], Entity] | None:
    """Granter-side R3a lookup: the cap I previously minted for the
    peer whose ``system/peer`` content_hash is ``remote_identity_hash``.

    Returns ``(capability_entity, chain_entities, session_entity)`` or
    ``None``. The granter reuses this cap on a repeat handshake instead
    of emitting a fresh ``created_at: now()`` triple per dial.
    """
    session = read_session(content_store, entity_tree, remote_identity_hash)
    if session is None:
        return None
    return _resolve_cap_pointer(content_store, session, "minted_capability")


def read_held_capability(
    content_store: "ContentStore",
    entity_tree: "EntityTree",
    remote_identity_hash: bytes,
) -> tuple[Entity, list[Entity], Entity] | None:
    """Grantee-side lookup: the cap the peer whose ``system/peer``
    content_hash is ``remote_identity_hash`` granted me.

    Returns ``(capability_entity, chain_entities, session_entity)`` or
    ``None``. §10 dispatch will read this to authenticate outbound EXECUTE
    without re-handshaking.
    """
    session = read_session(content_store, entity_tree, remote_identity_hash)
    if session is None:
        return None
    return _resolve_cap_pointer(content_store, session, "held_capability")


def write_session(
    emit_pathway: EmitPathway,
    content_store: "ContentStore",
    entity_tree: "EntityTree",
    *,
    remote_peer_id: str,
    remote_identity_hash: bytes,
    held_capability: tuple[Entity, list[Entity]] | None = None,
    minted_capability: tuple[Entity, list[Entity]] | None = None,
    remote_public_key: bytes | None = None,
    granted_at: int | None = None,
    expires_at: int | None = None,
    ctx: EmitContext | None = None,
) -> bytes:
    """Persist (or update in place) the session entity at
    ``system/peer/session/{remote_peer_id_hex}`` (V7 v7.64 §1.4 — hex of
    ``remote_identity_hash``).

    Pass ``held_capability`` from the dialer (grantee) side and
    ``minted_capability`` from the granter side. Each is a tuple of
    ``(leaf_cap_entity, parent_chain_entities)`` where:

    - ``leaf_cap_entity`` is the capability token entity being presented
      (the cap at chain[0]); also becomes ``capability.hash``.
    - ``parent_chain_entities`` is the list of *parent* cap entities
      walking from ``leaf.parent`` up to root (root cap LAST). For a
      self-rooted cap (no parent), pass ``[]``.

    Per §9.1 R6-d the wire chain is hash pointers ``[leaf, parent1, ...,
    root]`` ordered leaf→root, length ≥ 1. The chain field carries the
    CAP DELEGATION chain only — supporting entities (granter identity,
    cap signature, grantee identity) are NOT included. Granter identity
    is reachable via ``cap.data.granter``; the cap signature is
    deterministic (ed25519) and re-derivable at reuse time.

    Bidirectional model: if a session entity already exists for this
    peer, the OTHER field is preserved as-is. So a granter mints + writes
    ``minted_capability``, and a separate grantee handshake writes
    ``held_capability`` onto the SAME entity without overwriting the
    granter's record (§9.1 R6-a Option A).

    Grants-change rule (§9.1 R6-e): the caller decides; this function
    overwrites the named field in place. One entity per peer, mutable.
    """
    now_ms = int(time.time() * 1000)

    # Source granted_at / expires_at from whichever cap was just supplied,
    # preferring the explicit caller value when set.
    cap_for_meta = None
    if held_capability is not None:
        cap_for_meta = held_capability[0]
    elif minted_capability is not None:
        cap_for_meta = minted_capability[0]

    if granted_at is None:
        if cap_for_meta is not None:
            cap_created = cap_for_meta.data.get("created_at")
            granted_at = int(cap_created) if cap_created is not None else now_ms
        else:
            granted_at = now_ms
    if expires_at is None and cap_for_meta is not None:
        cap_expires = cap_for_meta.data.get("expires_at")
        expires_at = int(cap_expires) if cap_expires is not None else None

    # Persist cap (leaf) + each parent cap to the content store so the
    # chain hashes are resolvable later. The chain in the session entity
    # is purely the leaf→root cap delegation chain (R6-d).
    def _persist(cap_pair: tuple[Entity, list[Entity]]) -> dict:
        leaf, parents = cap_pair
        leaf_hash = content_store.put(leaf)
        chain_hashes = [leaf_hash]
        for parent_cap in parents:
            chain_hashes.append(content_store.put(parent_cap))
        return {"hash": leaf_hash, "chain": chain_hashes}

    held_field = _persist(held_capability) if held_capability is not None else None
    minted_field = _persist(minted_capability) if minted_capability is not None else None

    # Preserve fields from any pre-existing session entity (bidirectional
    # writes update one side without touching the other).
    existing = read_session(content_store, entity_tree, remote_identity_hash)

    data: dict = {
        "remote_peer_id": remote_peer_id,
        "remote_identity_hash": remote_identity_hash,
        "granted_at": Uint(int(granted_at)),
    }
    if expires_at is not None:
        data["expires_at"] = Uint(int(expires_at))
    if remote_public_key is not None:
        data["remote_public_key"] = remote_public_key
    elif existing is not None and "remote_public_key" in existing.data:
        data["remote_public_key"] = existing.data["remote_public_key"]

    if held_field is not None:
        data["held_capability"] = held_field
    elif existing is not None and "held_capability" in existing.data:
        data["held_capability"] = existing.data["held_capability"]

    if minted_field is not None:
        data["minted_capability"] = minted_field
    elif existing is not None and "minted_capability" in existing.data:
        data["minted_capability"] = existing.data["minted_capability"]

    # `held_capability` is the canonical dispatch-readable field. If the
    # caller wrote only `minted_capability` and no prior held exists, the
    # entity is still well-formed: dispatch will simply skip it (no held
    # cap to reuse) and re-handshake.

    entity = Entity(type="system/peer/session", data=data)
    if ctx is None:
        ctx = EmitContext.bootstrap()
    result = emit_pathway.emit(session_path(remote_identity_hash), entity, ctx)
    return result.hash if result.hash is not None else entity.compute_hash()
