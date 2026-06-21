"""Type definitions for all core protocol types.

Each type is derived from a dataclass using reflection and emitted
in V6.0 field-based format. This ensures a single source of truth -
changing the dataclass automatically updates the type definition.

V6.0: Types use `fields` dict instead of CDDL `schema` strings.
Field format: {"field_name": {"type_ref": "...", "optional": true, ...}}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from entity_core.capability.token import CapabilityToken
from entity_core.protocol.entity import Entity
from entity_core.protocol.messages import (
    Execute,
    ExecuteResponse,
)
from entity_core.primitives import Uint, TreePath, TypeName, PeerId, WireBytes
from entity_core.types.schema import dataclass_to_fields
from entity_core.types.field_spec import FieldSpec
from entity_core.utils.ecf import Hash


# =============================================================================
# Supporting Type Dataclasses
# These types don't have dataclasses elsewhere, so we define them here.
# =============================================================================


@dataclass
class SystemType:
    """Meta-type: defines the structure of type definitions themselves.

    V6.0 spec: system/type entities have:
    - name: The type name being defined
    - fields: Field definitions dict (V6.0 format)
    - extends: Optional parent type name
    - layout: Optional field ordering for binary encoding
    - type_params: Optional generic type parameters
    - type_args: Optional concrete type bindings for generics

    Note: constraints moved to EXTENSION-TYPE.md (open type extension)
    """

    TYPE_NAME = "system/type"

    name: TypeName
    fields: dict[str, Any] | None = None  # V6.0 field definitions
    extends: TypeName | None = None
    layout: list[str] | None = None
    type_params: list[str] | None = None
    type_args: dict[str, TypeName] | None = None


@dataclass
class ConnectHello:
    """Connect hello params carried in EXECUTE.

    - peer_id: Base58-encoded peer identifier
    - nonce: Raw bytes (base64 encoded in Python)
    - protocols: Supported protocol versions
    - timestamp: Milliseconds since Unix epoch
    - hash_formats: Optional supported hash formats
    - key_types: Optional supported key types
    - compression: Optional supported compression algorithms
    - encryption: Optional supported encryption algorithms
    """

    TYPE_NAME = "system/protocol/connect/hello"

    peer_id: PeerId
    nonce: WireBytes
    protocols: list[str]
    timestamp: Uint
    hash_formats: list[str] | None = None
    key_types: list[str] | None = None
    compression: list[str] | None = None
    encryption: list[str] | None = None


@dataclass
class ConnectAuthenticate:
    """Connect authenticate params carried in EXECUTE.

    - peer_id: Base58-encoded peer identifier
    - public_key: Raw bytes (base64 encoded in Python)
    - key_type: Key algorithm (e.g., "ed25519")
    - nonce: Other peer's nonce (echoed back, base64 encoded in Python)
    """

    TYPE_NAME = "system/protocol/connect/authenticate"

    peer_id: PeerId
    public_key: WireBytes
    key_type: str
    nonce: WireBytes


@dataclass
class Peer:
    """Peer entity (V7 §1.5 — peer-keypair entity).

    Renamed from `Identity` per V7 PR-1 (system/identity → system/peer).
    The entity holds the peer's public key; the bare type name disambiguates
    against EXTENSION-IDENTITY's `system/identity/...` namespace.

    Fields:
    - peer_id: Base58-encoded peer identifier
    - public_key: Ed25519 public key bytes (base64 encoded in Python)
    - key_type: Key algorithm (e.g., "ed25519")
    """

    TYPE_NAME = "system/peer"

    peer_id: PeerId
    public_key: WireBytes
    key_type: str


@dataclass
class Signature:
    """Cryptographic signature entity.

    Per spec section 6.2:
    - target: Content hash of signed entity (system/hash)
    - algorithm: Signature algorithm (e.g., "ed25519")
    - signature: Signature bytes (base64 encoded in Python)
    - signer: Hash of signer's identity entity (system/hash)
    """

    TYPE_NAME = "system/signature"

    target: Hash
    algorithm: str
    signature: WireBytes
    signer: Hash


@dataclass
class TreeListingEntry:
    """Entry in a tree listing.

    Per spec section 8.2.1:
    - hash: Content hash if entity exists at path (nullable)
    - has_children: True if path has children (subtree)
    """

    TYPE_NAME = "system/tree/listing-entry"

    hash: Hash | None
    has_children: bool


@dataclass
class TreeListing:
    """Directory listing response.

    Per spec section 8.2.1 + V7 §3.9 (v7.57):
    - path: The prefix path being listed
    - entries: Map of name -> {hash, has_children}
    - count: Number of entries (always non-negative)
    - next_page: optional content hash of the next listing page
      (EXTENSION-NETWORK §6.5.3.1 static-HTTP pagination); absent on
      the last/only page.
    """

    TYPE_NAME = "system/tree/listing"

    path: TreePath
    entries: dict[str, TreeListingEntry]
    count: Uint
    offset: Uint = Uint(0)
    next_page: bytes | None = None


# =============================================================================
# Tree Extension Types (per EXTENSION-TREE.md v3.0)
# =============================================================================


@dataclass
class TreeSnapshot:
    """Snapshot of tree state (EXTENSION-TREE.md §3).

    A snapshot captures tree state as a content-addressable entity.
    Same bindings MUST produce the same snapshot on any peer.

    - prefix: Subtree prefix ("" = full tree). Non-empty must end with /
    - bindings: Map of relative_path -> content_hash
    """

    TYPE_NAME = "system/tree/snapshot"

    prefix: str
    bindings: dict[str, Hash]


@dataclass
class TreeSnapshotRequest:
    """Request params for snapshot operation (EXTENSION-TREE.md §3.2).

    - prefix: Subtree prefix ("" = full tree). Default: ""
    - tree_id: Target tree ID. Default: default tree
    """

    TYPE_NAME = "system/tree/snapshot-request"

    prefix: str | None = None
    tree_id: str | None = None


@dataclass
class TreeDiffChange:
    """Single changed entry in a diff (EXTENSION-TREE.md §4.1).

    - base_hash: Hash in the base snapshot
    - target_hash: Hash in the target snapshot
    """

    TYPE_NAME = "system/tree/diff/change"

    base_hash: Hash
    target_hash: Hash


@dataclass
class TreeDiff:
    """Diff between two snapshots (EXTENSION-TREE.md §4.1).

    - base: Content hash of base snapshot
    - target: Content hash of target snapshot
    - added: Paths in target but not in base
    - removed: Paths in base but not in target
    - changed: Paths with different hashes
    - unchanged: Count of paths with identical hashes
    """

    TYPE_NAME = "system/tree/diff"

    base: Hash
    target: Hash
    added: dict[str, Hash]
    removed: dict[str, Hash]
    changed: dict[str, TreeDiffChange]
    unchanged: Uint


@dataclass
class TreeDiffRequest:
    """Request params for diff operation (EXTENSION-TREE.md §4.2).

    - base: Content hash of base snapshot
    - target: Content hash of target snapshot
    """

    TYPE_NAME = "system/tree/diff-request"

    base: Hash
    target: Hash


@dataclass
class TreeMergeConflict:
    """Single conflict in a merge result (EXTENSION-TREE.md §5.1).

    - existing_hash: Hash already at target path
    - incoming_hash: Hash from source snapshot
    - resolution: "kept-existing" | "used-incoming" | "unresolved"
    """

    TYPE_NAME = "system/tree/merge-result/conflict"

    existing_hash: Hash
    incoming_hash: Hash
    resolution: str


@dataclass
class TreeMergeResult:
    """Result of merge operation (EXTENSION-TREE.md §5.1).

    - applied: Number of paths written
    - skipped: Number of paths not written
    - conflicts: Map of path -> conflict details
    - strategy: Strategy used for merge
    """

    TYPE_NAME = "system/tree/merge-result"

    applied: Uint
    skipped: Uint
    conflicts: dict[str, TreeMergeConflict]
    strategy: str


@dataclass
class TreeMergeRequest:
    """Request params for merge operation (EXTENSION-TREE.md §5.2).

    - source: Content hash of source snapshot
    - target_tree: Tree to merge into. Default: default tree
    - strategy: "no-overwrite" | "source-wins" | "target-wins". Default: "no-overwrite"
    - source_prefix: Prefix to match in reconstructed full paths
    - target_prefix: Replacement prefix in target tree
    - dry_run: If true, don't write, just compute result. Default: false
    """

    TYPE_NAME = "system/tree/merge-request"

    source: Hash
    target_tree: str | None = None
    strategy: str | None = None
    source_prefix: str | None = None
    target_prefix: str | None = None
    dry_run: bool | None = None


@dataclass
class TreeExtractRequest:
    """Request params for extract operation (EXTENSION-TREE.md §6.1).

    - prefix: Subtree prefix. Non-empty must end with /
    - tree_id: Source tree ID. Default: default tree
    - paths: Specific relative paths to include. Default: all paths under prefix
    """

    TYPE_NAME = "system/tree/extract-request"

    prefix: str
    tree_id: str | None = None
    paths: list[str] | None = None


@dataclass
class TreeConfig:
    """Configuration for a non-default tree (EXTENSION-TREE.md §7.1).

    - tree_id: Unique identifier for this tree
    - root_structure: "peer-namespaced" | "relaxed"
    - purpose: "staging" | "translation" | "sub-peer" | "view" | custom
    - ephemeral: If true, not persisted across restarts
    - source: Source tree_id for view trees
    - capability: Capability hash defining view filter (required when source present)
    """

    TYPE_NAME = "system/tree/config"

    tree_id: str
    root_structure: str
    purpose: str | None = None
    ephemeral: bool | None = None
    source: str | None = None
    capability: Hash | None = None


@dataclass
class CapabilityScope:
    """Typed scope for grant dimensions per TYPE-SYSTEM spec §9.8.

    The include array lists patterns that match; the optional exclude
    array carves out exceptions.

    Note: On wire, this maps to either path-scope or id-scope depending on usage.
    """

    include: list[str]
    exclude: list[str] | None = None


@dataclass
class CapabilityGrantEntry:
    """A single grant rule within a capability token.

    Per TYPE-SYSTEM spec §9.9 - system/capability/grant-entry.
    V6.0: handlers, resources, operations are now CapabilityScope objects.

    - handlers: Handler scope - which handlers can be called
    - resources: Data path scope - which paths can be accessed
    - operations: Operation scope - which operations are authorized
    - peers: Peer scope - which peers the grant applies to (optional)
    - constraints: Domain-specific narrowing fields (optional, map_of)
    - allowances: Domain-specific expanding fields (optional, map_of)

    V7.14: constraints changed to map_of, added allowances field.
    """

    TYPE_NAME = "system/capability/grant-entry"

    handlers: CapabilityScope
    resources: CapabilityScope
    operations: CapabilityScope
    peers: CapabilityScope | None = None
    constraints: dict[str, Any] | None = None
    allowances: dict[str, Any] | None = None


@dataclass
class CapabilityRequest:
    """Params type for the capabilities handler request operation.

    Per TYPE-SYSTEM spec §9.12 - system/capability/request.
    """

    TYPE_NAME = "system/capability/request"

    grants: list[CapabilityGrantEntry]
    ttl_ms: int | None = None


@dataclass
class CapabilityRevocation:
    """Params type for the capabilities handler revoke operation.

    Per TYPE-SYSTEM spec §9.13 - system/capability/revocation.
    """

    TYPE_NAME = "system/capability/revocation"

    token: bytes  # system/hash
    reason: str | None = None


@dataclass
class CapabilityDelegationCaveats:
    """Restrictions on further delegation of a capability.

    Per TYPE-SYSTEM spec §9.9 - system/capability/delegation-caveats.
    - no_delegation: If true, capability cannot be delegated
    - max_delegation_depth: Maximum chain depth from this capability
    - max_delegation_ttl: Maximum lifetime (ms) for delegated capabilities
    """

    TYPE_NAME = "system/capability/delegation-caveats"

    no_delegation: bool | None = None
    max_delegation_depth: Uint | None = None
    max_delegation_ttl: Uint | None = None


@dataclass
class CapabilityGrant:
    """Result type for capability delivery.

    Per TYPE-SYSTEM spec §9.7 - system/capability/grant.
    The token field references the capability token entity.
    """

    TYPE_NAME = "system/capability/grant"

    token: bytes  # system/hash referencing the capability token


@dataclass
class Handler:
    """Handler dispatch target entity.

    Per PROPOSAL-HANDLER-NORMALIZATION N2 - system/handler.
    - interface: Tree path of the system/handler/interface entity
    - max_scope: Maximum tree access for this handler
    - internal_scope: Handler's internal needs
    - expression_path: Compute expression path (optional)
    """

    TYPE_NAME = "system/handler"

    interface: TreePath
    max_scope: list[Any] | None = None
    internal_scope: list[Any] | None = None
    expression_path: TreePath | None = None


# =============================================================================
# Type Entity Generator Helper
# =============================================================================


def type_from_dataclass(cls: type, type_name: str, extends: str | None = None) -> Entity:
    """Generate a system/type entity from a dataclass using reflection.

    This is the primary way to define types - the dataclass IS the source of truth.
    The type definition is derived from the dataclass fields using dataclass_to_fields.

    Args:
        cls: The dataclass to generate a type from.
        type_name: The type name (e.g., "system/peer").
        extends: Optional parent type name.

    Returns:
        Entity with type="system/type" containing the type definition.
    """
    fields = dataclass_to_fields(cls)
    data: dict[str, Any] = {"name": type_name, "fields": fields}
    if extends:
        data["extends"] = extends
    return Entity(type="system/type", data=data)


# =============================================================================
# Type Entity Generators
# Types are generated from dataclasses where possible.
# Some meta-types require manual definition (e.g., system/type/field-spec).
# =============================================================================


def type_system_type() -> Entity:
    """V6.0 type definition for system/type (self-describing meta-type).

    Per TYPE-SYSTEM spec §4.1. The meta-type is manually defined since it describes itself.
    Note: constraints field moved to EXTENSION-TYPE.md (open type extension).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type",
            "fields": {
                "name": {"type_ref": "system/type/name"},
                "extends": {"type_ref": "system/type/name", "optional": True},
                "fields": {"map_of": {"type_ref": "system/type/field-spec"}, "optional": True},
                "layout": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
                "type_params": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
                "type_args": {"map_of": {"type_ref": "system/type/name"}, "optional": True},
            },
        },
    )


def type_entity() -> Entity:
    """The abstract structural root.

    Per PROPOSAL-TYPE-NAMESPACE-CONVENTIONS / TYPE-SYSTEM §3.1.1:
    bare `entity` is the structural root that every type specializes.
    `content_hash` is *derived* from this structural shape per
    ENTITY-CBOR-ENCODING §4.2 — not declared as a field.

    Distinct from `core/entity` (§8.1), which is the materialized form
    {type, data, content_hash} used as a `type_ref` marker for "this
    slot holds a real, identity-bearing entity, not raw CBOR".
    """
    return Entity(
        type="system/type",
        data={
            "name": "entity",
            "fields": {
                "type": {"type_ref": "primitive/string"},
                "data": {"type_ref": "primitive/any"},
            },
        },
    )


def type_core_entity() -> Entity:
    """The materialized form of an entity.

    Per PROPOSAL-TYPE-NAMESPACE-CONVENTIONS / TYPE-SYSTEM §8.1:
    {type, data, content_hash} — the form an entity takes once a
    content hash has been resolved into a slot. Used as a `type_ref`
    marker in field specs to require a materialized entity rather than
    raw CBOR. Lives in `core/*` alongside `core/envelope`, the other
    transmission/materialization shape.
    """
    return Entity(
        type="system/type",
        data={
            "name": "core/entity",
            "fields": {
                "type": {"type_ref": "primitive/string"},
                "data": {"type_ref": "primitive/any"},
                "content_hash": {"type_ref": "system/hash"},
            },
        },
    )


def type_core_envelope() -> Entity:
    """Core envelope structure - bundles root entity with included entities.

    Per TYPE-SYSTEM spec §8.3.
    """
    return Entity(
        type="system/type",
        data={
            "name": "core/envelope",
            "fields": {
                "root": {"type_ref": "core/entity"},
                "included": {
                    "map_of": {"type_ref": "core/entity"},
                    "key_type": "system/hash",
                    "optional": True,
                },
            },
        },
    )


def type_system_envelope() -> Entity:
    """General entity bundle.

    Per V7 §3.1.1. Used by extract, ingest, and handler responses
    that package entities. Structurally identical to system/protocol/envelope
    but without protocol-level implications.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/envelope",
            "extends": "core/envelope",
        },
    )


def type_system_protocol_envelope() -> Entity:
    """Protocol envelope - extends core/envelope for protocol messages.

    Per TYPE-SYSTEM spec §9.1. Constraints (type_pattern for root) moved to EXTENSION-TYPE.md.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/protocol/envelope",
            "extends": "core/envelope",
        },
    )


def type_system_protocol_error() -> Entity:
    """Protocol error entity - used in EXECUTE_RESPONSE result for errors.

    Per TYPE-SYSTEM spec §9.6.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/protocol/error",
            "fields": {
                "code": {"type_ref": "primitive/string"},
                "message": {"type_ref": "primitive/string", "optional": True},
                # EXTENSION-CONTINUATION v1.18 §3.10.4 — receiver-side
                # rejected-marker hash mirrored into the 403 response so the
                # sender can bind a paired lost-marker. Additive optional.
                "rejected_marker": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_protocol_connect_hello() -> Entity:
    """Type for connect hello message - generated from ConnectHello dataclass."""
    return type_from_dataclass(ConnectHello, "system/protocol/connect/hello")


def type_system_protocol_connect_authenticate() -> Entity:
    """Type for connect authenticate message - generated from ConnectAuthenticate dataclass."""
    return type_from_dataclass(ConnectAuthenticate, "system/protocol/connect/authenticate")


def type_system_protocol_resource_target() -> Entity:
    """Type for resource target specification.

    Enables dispatch-level resource authorization.
    Per TYPE-SYSTEM spec §9.4.1.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/protocol/resource-target",
            "fields": {
                "targets": {"array_of": {"type_ref": "system/tree/path"}},
                "exclude": {"array_of": {"type_ref": "system/tree/path"}, "optional": True},
            },
        },
    )


def type_system_durability_request() -> Entity:
    """Type for the optional request-side durability marker.

    Per EXTENSION-DURABILITY v0.1 §2 (extracted from
    EXTENSION-INBOX §10.2). Extends system/protocol/execute; independent
    of deliver_to/deliver_token. ``level`` vocabulary is illustrative,
    not a frozen enum (§7). ``must_have`` defaults false: false =
    best-effort (take less, observably), true = required (refuse with
    412 if unmet, §5). The extension is EXPLORATORY · OPTIONAL · NOT
    ACTIVELY DEVELOPED; peers that don't install it are unaffected.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/durability-request",
            "fields": {
                "level": {"type_ref": "primitive/string"},
                "must_have": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_durability_result() -> Entity:
    """Type for the pinned response durability field.

    Per EXTENSION-DURABILITY v0.1 §5. Carried on EXECUTE_RESPONSE as the
    ``durability`` field. ``applied`` is durability physically in place
    at response time (never a promise); ``committed`` appears ONLY with
    status 202; ``max_available`` ONLY with status 412; ``handle`` is
    present when ``applied != none`` (200 with achieved strength) and
    on 202 (naming where the committed entry will land), absent
    otherwise (§5 / §8 MUSTs).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/durability-result",
            "fields": {
                "requested": {"type_ref": "primitive/string"},
                "applied": {"type_ref": "primitive/string"},
                "committed": {"type_ref": "primitive/string", "optional": True},
                "max_available": {"type_ref": "primitive/string", "optional": True},
                "handle": {"type_ref": "system/tree/path", "optional": True},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_durability_advertisement() -> Entity:
    """Type for the §3 discovery advertisement.

    Per EXTENSION-DURABILITY v0.1 §3 (MAY — loosened from SHOULD on
    extraction). Published at the well-known tree path
    ``system/durability`` so a sender can discover what the receiver
    supports via an ordinary tree:get. Absence does NOT change the
    response contract (§5); probe-via-request is the canonical fallback.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/durability-advertisement",
            "fields": {
                "levels": {"array_of": {"type_ref": "primitive/string"}},
                "max_self_determinable": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_protocol_execute() -> Entity:
    """Type for execute operation request.

    Per TYPE-SYSTEM spec §9.4 + EXTENSION-INBOX v5.6 (deliver_to,
    deliver_token) + EXTENSION-DURABILITY v0.1 §2 (durability_request —
    optional, additive; durability-unaware callers are unaffected).
    V7.8: callback/callback_token replaced by deliver_to/deliver_token.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/protocol/execute",
            "fields": {
                "request_id": {"type_ref": "primitive/string"},
                "uri": {"type_ref": "system/tree/path"},
                "operation": {"type_ref": "primitive/string"},
                "params": {"type_ref": "core/entity"},
                "bounds": {"type_ref": "system/bounds", "optional": True},
                "author": {"type_ref": "system/hash", "optional": True},
                "capability": {"type_ref": "system/hash", "optional": True},
                "resource": {"type_ref": "system/protocol/resource-target", "optional": True},
                "deliver_to": {"type_ref": "system/delivery-spec", "optional": True},
                "deliver_token": {"type_ref": "system/hash", "optional": True},
                "durability_request": {"type_ref": "system/durability-request", "optional": True},
            },
        },
    )


def type_system_protocol_execute_response() -> Entity:
    """Type for execute response.

    Per TYPE-SYSTEM spec §9.5 + EXTENSION-DURABILITY v0.1 §5 (durability
    — optional, additive; durability-unaware consumers are unaffected).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/protocol/execute/response",
            "fields": {
                "request_id": {"type_ref": "primitive/string"},
                "status": {"type_ref": "primitive/uint"},
                "result": {"type_ref": "core/entity"},
                "durability": {"type_ref": "system/durability-result", "optional": True},
            },
        },
    )


def type_system_capability_token() -> Entity:
    """Type for capability token granting permissions.

    Per TYPE-SYSTEM spec §9.10.

    V7.35 (PROPOSAL-MULTISIG-CORE-PRIMITIVE M1): `granter` is polymorphic via
    `union_of` — either `system/hash` (single-sig, today) or
    `system/capability/multi-granter` (K-of-N root caps; M3 enforces parent=null).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/token",
            "fields": {
                "grants": {"array_of": {"type_ref": "system/capability/grant-entry"}},
                "granter": {
                    "union_of": [
                        {"type_ref": "system/hash"},
                        {"type_ref": "system/capability/multi-granter"},
                    ],
                },
                "grantee": {"type_ref": "system/hash"},
                "parent": {"type_ref": "system/hash", "optional": True},
                "created_at": {"type_ref": "primitive/uint"},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
                "not_before": {"type_ref": "primitive/uint", "optional": True},
                "delegation_caveats": {"type_ref": "system/capability/delegation-caveats", "optional": True},
                "resource_limits": {"type_ref": "system/resource-limits", "optional": True},
            },
        },
    )


def type_system_capability_multi_granter() -> Entity:
    """V7.35 §3.2 (M2): K-of-N multi-granter helper type.

    Carried inline in `system/capability/token.granter` when the cap is
    multi-sig. On the wire it serializes as a CBOR map (major type 5);
    single-hash granters serialize as a CBOR byte string. Decoders branch
    on CBOR major type per PROPOSAL-MULTISIG-CORE-PRIMITIVE §5 / §M8.

    Constraints (enforced at chain-walk entry per M3):
    - len(signers) >= 2 (use single-sig form for N=1)
    - threshold in [2, len(signers)]
    - no duplicate signer hashes
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/multi-granter",
            "fields": {
                "signers": {"array_of": {"type_ref": "system/hash"}},
                "threshold": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_peer() -> Entity:
    """Type for the V7 peer-keypair entity (system/peer per V7 PR-1)."""
    return type_from_dataclass(Peer, "system/peer")


def type_system_signature() -> Entity:
    """Type for cryptographic signature - generated from Signature dataclass."""
    return type_from_dataclass(Signature, "system/signature")


def type_system_tree_listing_entry() -> Entity:
    """Type for a single entry in a tree listing.

    Per spec: hash uses system/hash (not primitive/bytes).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/listing-entry",
            "fields": {
                "hash": {"type_ref": "system/hash", "optional": True},
                "has_children": {"type_ref": "primitive/bool"},
            },
        },
    )


def type_system_tree_listing() -> Entity:
    """Type for tree listing response.

    Per spec V7 §3.9 (v7.57): `next_page` added for static-HTTP listing
    pagination — see EXTENSION-NETWORK §6.5.3.1 (v1.4 Amendment 5). The
    head listing object (`{path}{tree_listing_suffix}`) carries the hash
    of the next page; subsequent pages are content-addressed
    `system/tree/listing` entities fetched via `CONTENT_GET`. Additive +
    optional ⇒ backward-compatible (single-page listings omit it).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/listing",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "entries": {"map_of": {"type_ref": "system/tree/listing-entry"}},
                "count": {"type_ref": "primitive/uint"},
                "offset": {"type_ref": "primitive/uint"},
                "next_page": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_tree_get_request() -> Entity:
    """Type for tree get request params.

    Per IMPLEMENTATION-SPEC §3.6. In V7, path comes from EXECUTE.resource.targets[0],
    not from request params.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/get-request",
            "fields": {
                "tree_id": {"type_ref": "primitive/string", "optional": True},
                "mode": {"type_ref": "primitive/string", "optional": True},
                "limit": {"type_ref": "primitive/uint", "optional": True},
                "offset": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_tree_put_request() -> Entity:
    """Type for tree put request params.

    Per IMPLEMENTATION-SPEC §3.6. In V7, path comes from EXECUTE.resource.targets[0],
    not from request params.

    `expected_hash` (V7.22, ENTITY-CORE-PROTOCOL §3.9): when present, the put
    is a conditional write (CAS). The put MUST succeed only if the current
    binding hash matches. Mismatch or missing binding -> 409 hash_mismatch.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/put-request",
            "fields": {
                "entity": {"type_ref": "core/entity", "optional": True},
                "expected_hash": {"type_ref": "system/hash", "optional": True},
                "tree_id": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


# Tree Extension Types (EXTENSION-TREE.md v3.0)


def type_system_tree_snapshot() -> Entity:
    """Type for tree snapshot (EXTENSION-TREE.md §3.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/snapshot",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "bindings": {"map_of": {"type_ref": "system/hash"}},
            },
        },
    )


def type_system_tree_snapshot_request() -> Entity:
    """Type for snapshot operation request (EXTENSION-TREE.md §3.2)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/snapshot-request",
            "fields": {
                "prefix": {"type_ref": "system/tree/path", "optional": True},
                "tree_id": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_tree_diff_change() -> Entity:
    """Type for a single change entry in a diff (EXTENSION-TREE.md §4.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/diff/change",
            "fields": {
                "base_hash": {"type_ref": "system/hash"},
                "target_hash": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_tree_diff() -> Entity:
    """Type for tree diff result (EXTENSION-TREE.md §4.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/diff",
            "fields": {
                "base": {"type_ref": "system/hash"},
                "target": {"type_ref": "system/hash"},
                "added": {"map_of": {"type_ref": "system/hash"}},
                "removed": {"map_of": {"type_ref": "system/hash"}},
                "changed": {"map_of": {"type_ref": "system/tree/diff/change"}},
                "unchanged": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_tree_diff_request() -> Entity:
    """Type for diff operation request (EXTENSION-TREE.md §4.2)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/diff-request",
            "fields": {
                "base": {"type_ref": "system/hash"},
                "target": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_tree_merge_conflict() -> Entity:
    """Type for a single merge conflict (EXTENSION-TREE.md §5.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/merge-result/conflict",
            "fields": {
                "existing_hash": {"type_ref": "system/hash"},
                "incoming_hash": {"type_ref": "system/hash"},
                "resolution": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_tree_merge_result() -> Entity:
    """Type for merge operation result (EXTENSION-TREE.md §5.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/merge-result",
            "fields": {
                "applied": {"type_ref": "primitive/uint"},
                "skipped": {"type_ref": "primitive/uint"},
                "conflicts": {"map_of": {"type_ref": "system/tree/merge-result/conflict"}},
                "strategy": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_tree_merge_request() -> Entity:
    """Type for merge operation request (EXTENSION-TREE.md §5.2)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/merge-request",
            "fields": {
                "source": {"type_ref": "system/hash"},
                "target_tree": {"type_ref": "primitive/string", "optional": True},
                "strategy": {"type_ref": "primitive/string", "optional": True},
                "source_prefix": {"type_ref": "system/tree/path", "optional": True},
                "target_prefix": {"type_ref": "system/tree/path", "optional": True},
                "dry_run": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_tree_extract_request() -> Entity:
    """Type for extract operation request (EXTENSION-TREE.md §6.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/extract-request",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "tree_id": {"type_ref": "primitive/string", "optional": True},
                "paths": {"array_of": {"type_ref": "system/tree/path"}, "optional": True},
            },
        },
    )


def type_system_tree_config() -> Entity:
    """Type for non-default tree configuration (EXTENSION-TREE.md §7.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/config",
            "fields": {
                "tree_id": {"type_ref": "primitive/string"},
                "root_structure": {"type_ref": "primitive/string"},
                "purpose": {"type_ref": "primitive/string", "optional": True},
                "ephemeral": {"type_ref": "primitive/bool", "optional": True},
                "source": {"type_ref": "primitive/string", "optional": True},
                "capability": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_type_validate_request() -> Entity:
    """Type for `system/type:validate` request params.

    Per EXTENSION-TYPE v1.1 §8.3. The `type_path` field is optional;
    when absent the validator uses `entity.type`. The field is named
    `type_path` but typed as `system/type/name` per the spec — a name
    here resolves to a path via the chosen resolution strategy (§1.5).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/validate-request",
            "fields": {
                "entity": {"type_ref": "core/entity"},
                "type_path": {"type_ref": "system/type/name", "optional": True},
            },
        },
    )


def type_system_type_validate_result() -> Entity:
    """Type for `system/type:validate` result.

    Per EXTENSION-TYPE v1.1 §8.4. `valid` reports whether every
    evaluated check passed; `violations` carries failures with a `kind`
    discriminator (structural / constraint / unknown_constraint);
    `unevaluated_fields` reports open-type fields the validator
    detected but could not interpret.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/validate-result",
            "fields": {
                "valid": {"type_ref": "primitive/bool"},
                "violations": {
                    "array_of": {"type_ref": "system/type/violation"},
                    "optional": True,
                },
                "unevaluated_fields": {
                    "array_of": {"type_ref": "primitive/string"},
                    "optional": True,
                },
            },
        },
    )


def type_system_type_field_comparison() -> Entity:
    """`system/type/field-comparison` — per-field row in `compare-result.shared`.

    Per EXTENSION-TYPE v1.1 §8.1. ``type_match`` and
    ``constraint_match`` are independent — constraint differences
    don't impair structural compatibility per ENTITY-NATIVE-TYPE-SYSTEM
    §12.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/field-comparison",
            "fields": {
                "type_match": {"type_ref": "primitive/bool"},
                "constraint_match": {"type_ref": "primitive/bool"},
                "a_optional": {"type_ref": "primitive/bool"},
                "b_optional": {"type_ref": "primitive/bool"},
                "detail": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_type_field_incompatibility() -> Entity:
    """`system/type/field-incompatibility` — one shared name, two types.

    Per EXTENSION-TYPE v1.1 §8.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/field-incompatibility",
            "fields": {
                "field_name": {"type_ref": "primitive/string"},
                "a_type": {"type_ref": "system/type/name"},
                "b_type": {"type_ref": "system/type/name"},
                "reason": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_type_compare_request() -> Entity:
    """`system/type/compare-request` — input for `system/type:compare`.

    Per EXTENSION-TYPE v1.1 §7.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/compare-request",
            "fields": {
                "type_a": {"type_ref": "system/tree/path"},
                "type_b": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_type_compare_result() -> Entity:
    """`system/type/compare-result` — output of `system/type:compare`.

    Per EXTENSION-TYPE v1.1 §7.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/compare-result",
            "fields": {
                "type_a_path": {"type_ref": "system/tree/path"},
                "type_b_path": {"type_ref": "system/tree/path"},
                "shared": {"map_of": {"type_ref": "system/type/field-comparison"}},
                "only_a": {"array_of": {"type_ref": "primitive/string"}},
                "only_b": {"array_of": {"type_ref": "primitive/string"}},
                "incompatible": {
                    "array_of": {"type_ref": "system/type/field-incompatibility"},
                    "optional": True,
                },
            },
        },
    )


def _constraint(constraint_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Embed a field-spec constraint as a full entity envelope.

    A field-spec ``constraints`` entry fills a ``core/entity``-typed slot
    (EXTENSION-TYPE §2), which per ENTITY-NATIVE-TYPE-SYSTEM §1.2 takes the
    **entity-envelope** wire form — the embedded entity carries its own
    ``content_hash`` (``{type, data, content_hash}``), not the bare 2-key
    ``{type, data}`` record. Go encodes these as ``[]entity.Entity`` (each
    3-key); a bare map under-encodes and diverges by exactly the
    ``content_hash`` key — the V7.72 cohort's four "ECF byte mismatch, no
    structural difference" WARNs on the constraint-carrying type defs
    (compatible-request, compatibility-report, converge-request,
    reconcile-request). Routing every inline constraint through ``Entity``
    makes the embedded form byte-identical to a standalone entity.
    """
    return Entity(type=constraint_type, data=data).to_dict()


def type_system_type_compatible_request() -> Entity:
    """`system/type/compatible-request` — input for `system/type:compatible`.

    Per EXTENSION-TYPE v1.1 §7.3. ``direction`` is one of
    ``forward``, ``backward``, ``bidirectional``.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/compatible-request",
            "fields": {
                "type_a": {"type_ref": "system/tree/path"},
                "type_b": {"type_ref": "system/tree/path"},
                "direction": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        _constraint(
                            "system/type/constraint/one-of",
                            {"values": ["forward", "backward", "bidirectional"]},
                        )
                    ],
                },
            },
        },
    )


def type_system_type_compatibility_report() -> Entity:
    """`system/type/compatibility-report` — output of `system/type:compatible`.

    Per EXTENSION-TYPE v1.1 §7.3. ``level`` is one of the five values
    in the constraint.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/compatibility-report",
            "fields": {
                "type_a_path": {"type_ref": "system/tree/path"},
                "type_b_path": {"type_ref": "system/tree/path"},
                "direction": {"type_ref": "primitive/string"},
                "level": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        _constraint(
                            "system/type/constraint/one-of",
                            {
                                "values": [
                                    "fully_compatible",
                                    "forward_only",
                                    "backward_only",
                                    "partially_compatible",
                                    "incompatible",
                                ]
                            },
                        )
                    ],
                },
                "shared_fields": {"array_of": {"type_ref": "primitive/string"}},
                "incompatible_fields": {
                    "array_of": {"type_ref": "system/type/field-incompatibility"},
                    "optional": True,
                },
                "missing_required_a": {
                    "array_of": {"type_ref": "primitive/string"},
                    "optional": True,
                },
                "missing_required_b": {
                    "array_of": {"type_ref": "primitive/string"},
                    "optional": True,
                },
            },
        },
    )


def type_system_type_converge_request() -> Entity:
    """`system/type/converge-request` — input for `system/type:converge`.

    Per EXTENSION-TYPE v1.1 §7.4.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/converge-request",
            "fields": {
                "type_paths": {
                    "array_of": {"type_ref": "system/tree/path"},
                    "constraints": [
                        _constraint(
                            "system/type/constraint/min-count", {"min_count": 2}
                        )
                    ],
                },
            },
        },
    )


def type_system_type_adopt_request() -> Entity:
    """`system/type/adopt-request` — input for `system/type:adopt`.

    Per EXTENSION-TYPE v1.1 §7.5.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/adopt-request",
            "fields": {
                "source_path": {"type_ref": "system/tree/path"},
                "local_name": {"type_ref": "system/type/name", "optional": True},
            },
        },
    )


def type_system_type_reconcile_request() -> Entity:
    """`system/type/reconcile-request` — input for `system/type:reconcile`.

    Per EXTENSION-TYPE v1.1 §7.6. ``strategy`` is intersect / union /
    prefer.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/reconcile-request",
            "fields": {
                "type_paths": {
                    "array_of": {"type_ref": "system/tree/path"},
                    "constraints": [
                        _constraint(
                            "system/type/constraint/min-count", {"min_count": 2}
                        )
                    ],
                },
                "strategy": {
                    "type_ref": "primitive/string",
                    "constraints": [
                        _constraint(
                            "system/type/constraint/one-of",
                            {"values": ["intersect", "union", "prefer"]},
                        )
                    ],
                },
            },
        },
    )


def type_system_type_reconcile_result() -> Entity:
    """`system/type/reconcile-result` — output of `system/type:reconcile`.

    Per EXTENSION-TYPE v1.1 §7.6.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/reconcile-result",
            "fields": {
                "reconciled_type": {"type_ref": "core/entity"},
                "strategy_used": {"type_ref": "primitive/string"},
                "sources": {"array_of": {"type_ref": "system/tree/path"}},
                "fields_dropped": {
                    "array_of": {"type_ref": "primitive/string"},
                    "optional": True,
                },
                "fields_made_optional": {
                    "array_of": {"type_ref": "primitive/string"},
                    "optional": True,
                },
                "incompatibilities": {
                    "array_of": {"type_ref": "system/type/field-incompatibility"},
                    "optional": True,
                },
            },
        },
    )


def type_system_type_violation() -> Entity:
    """Type for an entry in `validate-result.violations`.

    Per EXTENSION-TYPE v1.1 §8.5. `kind` discriminates structural
    failure, constraint failure, and unknown-constraint (fail-closed)
    cases per the design principle in §1.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/violation",
            "fields": {
                "field": {"type_ref": "primitive/string"},
                "kind": {"type_ref": "primitive/string"},
                "constraint": {"type_ref": "system/type/name", "optional": True},
                "reason": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_handler() -> Entity:
    """Type for handler dispatch target.

    Per PROPOSAL-HANDLER-NORMALIZATION N2. Stored at the pattern path.
    References the interface entity by path; holds private configuration.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/handler",
            "fields": {
                "interface": {"type_ref": "system/tree/path"},
                "max_scope": {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": True},
                "internal_scope": {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": True},
                "expression_path": {"type_ref": "system/tree/path", "optional": True},
            },
        },
    )


def type_system_handler_manifest() -> Entity:
    """Type for handler registration input.

    Per PROPOSAL-HANDLER-NORMALIZATION N1: extends `system/handler/interface`
    with install-time fields (max_scope, internal_scope, expression_path).

    The interface fields (pattern, name, operations) are republished here
    as the manifest's own field list rather than relying on `extends`
    alone — cross-impl validators (Go, Rust) expect the full effective
    field shape on the type entity itself, with `extends` as additional
    metadata about the parent relationship.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/handler/manifest",
            "extends": "system/handler/interface",
            "fields": {
                "pattern": {"type_ref": "system/tree/path"},
                "name": {"type_ref": "primitive/string"},
                "operations": {"map_of": {"type_ref": "system/handler/operation-spec"}},
                "max_scope": {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": True},
                "internal_scope": {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": True},
                "expression_path": {"type_ref": "system/tree/path", "optional": True},
            },
        },
    )


def type_system_handler_operation_spec() -> Entity:
    """Type for handler operation specification.

    Per IMPLEMENTATION-SPEC §3.4 V7.7.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/handler/operation-spec",
            "fields": {
                "input_type": {"type_ref": "system/type/name", "optional": True},
                "output_type": {"type_ref": "system/type/name", "optional": True},
            },
        },
    )


def type_system_handler_interface() -> Entity:
    """Type for handler discovery (public interface without internal fields).

    Per IMPLEMENTATION-SPEC §3.4 V7.7. Stored at system/handler/{pattern}.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/handler/interface",
            "fields": {
                "pattern": {"type_ref": "system/tree/path"},
                "name": {"type_ref": "primitive/string"},
                "operations": {"map_of": {"type_ref": "system/handler/operation-spec"}},
            },
        },
    )


def type_system_handler_register_request() -> Entity:
    """Type for handler registration request.

    Per PROPOSAL-HANDLER-NORMALIZATION N4.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/handler/register-request",
            "fields": {
                "manifest": {"type_ref": "system/handler/manifest"},
                "types": {"map_of": {"type_ref": "system/type"}, "optional": True},
                "requested_scope": {"array_of": {"type_ref": "system/capability/grant-entry"}, "optional": True},
            },
        },
    )


def type_system_handler_register_result() -> Entity:
    """Type for handler registration result.

    Per IMPLEMENTATION-SPEC §3.4 V7.7.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/handler/register-result",
            "fields": {
                "pattern": {"type_ref": "system/tree/path"},
                "grant": {"type_ref": "system/capability/token"},
            },
        },
    )


def type_system_capability_path_scope() -> Entity:
    """V7.7 type for path-valued capability scope dimensions.

    Per IMPLEMENTATION-SPEC §3.3. Used for handlers and resources dimensions.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/path-scope",
            "fields": {
                "include": {"array_of": {"type_ref": "system/tree/path"}},
                "exclude": {"array_of": {"type_ref": "system/tree/path"}, "optional": True},
            },
        },
    )


def type_system_capability_id_scope() -> Entity:
    """V7.7 type for identifier-valued capability scope dimensions.

    Per IMPLEMENTATION-SPEC §3.3. Used for operations and peers dimensions.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/id-scope",
            "fields": {
                "include": {"array_of": {"type_ref": "primitive/string"}},
                "exclude": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
            },
        },
    )


def type_system_capability_grant_entry() -> Entity:
    """Type for a single grant rule within a capability.

    Per IMPLEMENTATION-SPEC §3.3 V7.7, updated V7.14:
    - handlers, resources use path-scope (tree paths)
    - operations, peers use id-scope (identifiers)
    - constraints: map_of for domain-specific narrowing (keys can't be dropped)
    - allowances: map_of for domain-specific expanding (keys can't be added)
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/grant-entry",
            "fields": {
                "handlers": {"type_ref": "system/capability/path-scope"},
                "resources": {"type_ref": "system/capability/path-scope"},
                "operations": {"type_ref": "system/capability/id-scope"},
                "peers": {"type_ref": "system/capability/id-scope", "optional": True},
                "constraints": {"map_of": {"type_ref": "primitive/any"}, "optional": True},
                "allowances": {"map_of": {"type_ref": "primitive/any"}, "optional": True},
            },
        },
    )


def type_system_capability_request() -> Entity:
    """Type for capability request params.

    Per TYPE-SYSTEM spec §9.12 - system/capability/request.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/request",
            "fields": {
                "grants": {"array_of": {"type_ref": "system/capability/grant-entry"}},
                "ttl_ms": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_capability_revocation() -> Entity:
    """Persisted revocation MARKER entity (V7 §3.6, v7.62).

    Stored at ``system/capability/revocations/{cap_hash_hex}``. The handler
    sets ``revoked_at`` from server wall-clock; caller-supplied values are
    ignored (cross-cutting timestamp convention, §6.2).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/revocation",
            "fields": {
                "token": {"type_ref": "system/hash"},
                "reason": {"type_ref": "primitive/string", "optional": True},
                "revoked_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_capability_revoke_request() -> Entity:
    """Input type for the capability handler ``revoke`` operation (v7.62 §3.6)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/revoke-request",
            "fields": {
                "token": {"type_ref": "system/hash"},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_capability_delegate_request() -> Entity:
    """Input type for the capability handler ``delegate`` operation (v7.62 §3.6).

    Delegate v1 is self-attenuation only: grantee = caller's authenticated
    identity. Third-party delegation deferred.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/delegate-request",
            "fields": {
                "parent": {"type_ref": "system/hash"},
                "grants": {
                    "array_of": {"type_ref": "system/capability/grant-entry"}
                },
                "ttl_ms": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_capability_policy_entry() -> Entity:
    """Persisted policy entry consulted by the capability handler (v7.62 §3.6).

    Stored at ``system/capability/policy/{peer_pattern}`` where
    ``peer_pattern`` is exactly one of: the canonical peer identity hash
    hex (V7 §3.5 invariant-pointer form, format byte included — width is
    format-relative per v7.70 §1.2: 66 hex for SHA-256, 98 for SHA-384) or
    the literal wildcard ``*``. Partial-prefix patterns are not valid.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/policy-entry",
            "fields": {
                "peer_pattern": {"type_ref": "primitive/string"},
                "grants": {
                    "array_of": {"type_ref": "system/capability/grant-entry"}
                },
                "ttl_ms": {"type_ref": "primitive/uint", "optional": True},
                "notes": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_capability_delegation_caveats() -> Entity:
    """Type for delegation restrictions on a capability.

    Per TYPE-SYSTEM spec §9.9.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/delegation-caveats",
            "fields": {
                "no_delegation": {"type_ref": "primitive/bool", "optional": True},
                "max_delegation_depth": {"type_ref": "primitive/uint", "optional": True},
                "max_delegation_ttl": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_capability_grant() -> Entity:
    """Type for capability delivery result.

    Per TYPE-SYSTEM spec §9.7. The token field references the capability token.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/capability/grant",
            "fields": {
                "token": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_bounds() -> Entity:
    """Type for request bounds.

    Per IMPLEMENTATION-SPEC §3.7 V7.7.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/bounds",
            "fields": {
                "ttl": {"type_ref": "primitive/uint", "optional": True},
                "budget": {"type_ref": "primitive/uint", "optional": True},
                "chain_id": {"type_ref": "primitive/string", "optional": True},
                "parent_chain_id": {"type_ref": "primitive/string", "optional": True},
                "cascade_depth": {"type_ref": "primitive/uint", "optional": True},
                "visited": {"array_of": {"type_ref": "system/tree/path"}, "optional": True},
            },
        },
    )


def type_system_callback_spec() -> Entity:
    """Type for callback specification.

    Per IMPLEMENTATION-SPEC §3.7 V7.7.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/callback-spec",
            "fields": {
                "uri": {"type_ref": "system/tree/path"},
                "operation": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_resource_limits() -> Entity:
    """Type for resource limits on capability tokens.

    Per TYPE-SYSTEM spec §10.7.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/resource-limits",
            "fields": {
                "max_budget": {"type_ref": "primitive/uint", "optional": True},
                "max_ttl": {"type_ref": "primitive/uint", "optional": True},
                "max_visited_length": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


# =============================================================================
# Inbox Extension Types (EXTENSION-INBOX v5.0 - V7.8)
# =============================================================================


def type_system_delivery_spec() -> Entity:
    """Type for delivery specification (v7.8 inbox).

    Per EXTENSION-INBOX v5.0 §2.1.
    Specifies where to deliver async results.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/delivery-spec",
            "fields": {
                "uri": {"type_ref": "system/tree/path"},
                "operation": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_protocol_inbox_delivery() -> Entity:
    """Type for inbox delivery (async result).

    Per EXTENSION-INBOX v5.0 §3.1.
    Delivers the result of a completed async operation.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/protocol/inbox/delivery",
            "fields": {
                "original_request_id": {"type_ref": "primitive/string"},
                "status": {"type_ref": "primitive/uint"},
                "result": {"type_ref": "core/entity"},
            },
        },
    )


def type_system_protocol_inbox_notification() -> Entity:
    """Type for inbox notification (subscription event).

    Per EXTENSION-INBOX v5.0 §3.2.
    Delivers a subscription notification for entity tree changes.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/protocol/inbox/notification",
            "fields": {
                "subscription_id": {"type_ref": "primitive/string"},
                "event": {"type_ref": "primitive/string"},
                "uri": {"type_ref": "system/tree/path"},
                "hash": {"type_ref": "system/hash", "optional": True},
                "previous_hash": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


# =============================================================================
# Continuation Extension Types (EXTENSION-CONTINUATION v1.9)
# =============================================================================


def type_system_continuation() -> Entity:
    """Type for forward continuation (single dispatch with transform).

    Per EXTENSION-CONTINUATION v1.2 §2.1.
    Forward continuations dispatch a single result to a target.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation",
            "fields": {
                "target": {"type_ref": "system/tree/path"},
                "operation": {"type_ref": "primitive/string"},
                "resource": {"type_ref": "system/protocol/resource-target", "optional": True},
                "params": {"type_ref": "primitive/any", "optional": True},
                "result_transform": {"type_ref": "system/continuation/transform", "optional": True},
                "result_field": {"type_ref": "primitive/string", "optional": True},
                # EXTENSION-CONTINUATION v1.16 §2.1 — Merge-mode assembly.
                # Mutually exclusive with result_field; additive, default false.
                "result_merge": {"type_ref": "primitive/bool", "optional": True},
                "on_error": {"type_ref": "system/delivery-spec", "optional": True},
                "deliver_to": {"type_ref": "system/delivery-spec", "optional": True},
                "remaining_executions": {"type_ref": "primitive/uint", "optional": True},
                "dispatch_capability": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_continuation_join() -> Entity:
    """Type for join continuation (fan-in from multiple sources).

    Per EXTENSION-CONTINUATION v1.2 §2.2.
    Join continuations accumulate results from multiple slots before dispatch.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/join",
            "fields": {
                "expected": {"array_of": {"type_ref": "primitive/string"}},
                "received": {"map_of": {"type_ref": "primitive/any"}, "optional": True},
                "target": {"type_ref": "system/tree/path"},
                "operation": {"type_ref": "primitive/string"},
                "resource": {"type_ref": "system/protocol/resource-target", "optional": True},
                "params": {"type_ref": "primitive/any", "optional": True},
                "result_field": {"type_ref": "primitive/string", "optional": True},
                "on_error": {"type_ref": "system/delivery-spec", "optional": True},
                "deliver_to": {"type_ref": "system/delivery-spec", "optional": True},
                "remaining_executions": {"type_ref": "primitive/uint", "optional": True},
                "dispatch_capability": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_continuation_suspended() -> Entity:
    """Type for suspended continuation state.

    Per EXTENSION-CONTINUATION v1.2 §2.4.
    Stores continuation state when execution is paused for external signal.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/suspended",
            "fields": {
                "target": {"type_ref": "system/tree/path"},
                "operation": {"type_ref": "primitive/string"},
                "resource": {"type_ref": "system/protocol/resource-target", "optional": True},
                "params": {"type_ref": "primitive/any", "optional": True},
                "reason": {"type_ref": "primitive/string"},
                "chain_id": {"type_ref": "primitive/string"},
                "original_author": {"type_ref": "system/hash"},
                "suspended_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_continuation_transform() -> Entity:
    """Type for structural transform specification.

    Per EXTENSION-CONTINUATION v1.9 §2.2. Specifies structural navigation
    on the result before dispatch. Pipeline: extract -> select ->
    transform_ops -> *_extract.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/transform",
            "fields": {
                "extract": {"type_ref": "primitive/string", "optional": True},
                "select": {"map_of": {"type_ref": "primitive/string"}, "optional": True},
                # v1.9 G1: ordered list of closed/total/pure/bounded field
                # ops applied after extract/select, before the *_extract
                # fields. Unknown op rejected at install (fail-closed).
                "transform_ops": {
                    "array_of": {"type_ref": "system/continuation/transform-op"},
                    "optional": True,
                },
                # Per EXTENSION-CONTINUATION §2.2: dotted paths into the
                # post-extract/post-select value that override the static
                # dispatch fields when present.
                "resource_extract": {"type_ref": "primitive/string", "optional": True},
                "target_extract": {"type_ref": "primitive/string", "optional": True},
                "operation_extract": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_continuation_transform_op() -> Entity:
    """Type for one bounded field operation within a transform's transform_ops.

    Per EXTENSION-CONTINUATION v1.9 §2.2 (G1). Op set: strip_prefix,
    prepend, append, join, replace_literal, split, slice. The op set is
    closed, total, pure, bounded, and statically analyzable; an
    unrecognized `op` MUST be rejected at install (fail-closed).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/transform-op",
            "fields": {
                "op": {"type_ref": "primitive/string"},
                "field": {"type_ref": "primitive/string", "optional": True},
                "into": {"type_ref": "primitive/string", "optional": True},
                "fields": {
                    "array_of": {"type_ref": "primitive/string"},
                    "optional": True,
                },
                "prefix": {"type_ref": "primitive/string", "optional": True},
                "literal": {"type_ref": "primitive/string", "optional": True},
                "from": {"type_ref": "primitive/string", "optional": True},
                "to": {"type_ref": "primitive/string", "optional": True},
                "sep": {"type_ref": "primitive/string", "optional": True},
                "range": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_continuation_advance_request() -> Entity:
    """Type for advance operation input.

    Per EXTENSION-CONTINUATION v1.2 §2.5.
    Input type for the continuation handler's advance operation.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/advance-request",
            "fields": {
                "result": {"type_ref": "primitive/any", "optional": True},
                "status": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_continuation_resume_request() -> Entity:
    """Type for resume operation input.

    Per EXTENSION-CONTINUATION v1.2 §2.6.
    Input type for the continuation handler's resume operation.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/resume-request",
            "fields": {
                "bounds": {"type_ref": "system/bounds", "optional": True},
                "resolution": {"type_ref": "primitive/any", "optional": True},
                "deliver_to": {"type_ref": "system/delivery-spec", "optional": True},
            },
        },
    )


def type_system_continuation_abandon_request() -> Entity:
    """Type for abandon operation input.

    Per EXTENSION-CONTINUATION v1.2 §2.6.
    Input type for the continuation handler's abandon operation.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/abandon-request",
            "fields": {},
        },
    )


def type_system_continuation_install_result() -> Entity:
    """Type for install operation result.

    Per EXTENSION-CONTINUATION v1.7 §2.7. Retained after the
    PROPOSAL-PATH-AS-RESOURCE-HYGIENE wrapper-elimination pass — echoes
    the install path and leaves room for future install metadata.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/continuation/install-result",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
            },
        },
    )


# =============================================================================
# Subscription Extension Types (EXTENSION-SUBSCRIPTION v3.2)
# =============================================================================


def type_system_subscription_limits() -> Entity:
    """Type for subscription resource limits.

    Per EXTENSION-SUBSCRIPTION v3.2 §4.1.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/subscription/limits",
            "fields": {
                "max_events": {"type_ref": "primitive/uint", "optional": True},
                "max_duration_ms": {"type_ref": "primitive/uint", "optional": True},
                "rate_limit": {"type_ref": "primitive/uint", "optional": True},
                "notification_budget": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_subscription() -> Entity:
    """Type for subscription entity stored at system/subscription/{id}.

    Per EXTENSION-SUBSCRIPTION v3.3 §2.1.
    V7.8: Renamed callback_* fields to deliver_*.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/subscription",
            "fields": {
                "subscription_id": {"type_ref": "primitive/string"},
                "pattern": {"type_ref": "system/tree/path"},
                "events": {"array_of": {"type_ref": "primitive/string"}},
                "deliver_uri": {"type_ref": "system/tree/path"},
                "deliver_operation": {"type_ref": "primitive/string"},
                "subscriber_identity": {"type_ref": "system/hash"},
                "deliver_token": {"type_ref": "system/hash"},
                "created_at": {"type_ref": "primitive/uint"},
                "limits": {"type_ref": "system/subscription/limits", "optional": True},
                # EXTENSION-SUBSCRIPTION v3.14 §2.1 — persisted from the
                # subscribe request; engine reads it at delivery. Default false.
                "include_payload": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_subscription_request() -> Entity:
    """Type for subscribe operation request.

    Per EXTENSION-SUBSCRIPTION v3.3 §2.3.
    V7.8: Renamed callback to deliver_to, callback_token to deliver_token.

    Per spec §2.3: "The subscription pattern comes from the EXECUTE's
    resource field (resource.targets), not from params." The handler's
    legacy `params.pattern` fallback is preserved for backward compat
    but is NOT in the published type def (would diverge cross-impl).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/subscription/request",
            "fields": {
                "events": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
                "deliver_to": {"type_ref": "system/delivery-spec"},
                "deliver_token": {"type_ref": "system/hash"},
                "limits": {"type_ref": "system/subscription/limits", "optional": True},
                # EXTENSION-SUBSCRIPTION v3.12 §2.3 — opt-in content delivery
                # (requires read-authz per v3.13). Additive, default false.
                "include_payload": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_subscription_cancel() -> Entity:
    """Type for unsubscribe operation request.

    Per EXTENSION-SUBSCRIPTION v3.2 §3.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/subscription/cancel",
            "fields": {
                "subscription_id": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_subscription_redirect() -> Entity:
    """Type for subscription redirect when at capacity.

    Per SUBSCRIPTION v3.5 §S2: subscribe redirect response.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/subscription/redirect",
            "fields": {
                "reason": {"type_ref": "primitive/string"},
                "prefix": {"type_ref": "system/tree/path"},
                "alternatives": {"array_of": {"type_ref": "system/hash"}, "optional": True},
                "capacity": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_subscription_result() -> Entity:
    """Type for subscribe operation result.

    Per EXTENSION-SUBSCRIPTION v3.2 §3.1.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/subscription/result",
            "fields": {
                "subscription_id": {"type_ref": "primitive/string"},
                "pattern": {"type_ref": "system/tree/path"},
                "events": {"array_of": {"type_ref": "primitive/string"}},
                "limits": {"type_ref": "system/subscription/limits", "optional": True},
            },
        },
    )


# =============================================================================
# Trie Node Type (EXTENSION-TREE v3.2)
# =============================================================================



def type_system_tree_snapshot_node() -> Entity:
    """Type for trie node entity (content-addressed snapshot node).

    Per EXTENSION-TREE v3.2 section 3.3.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/snapshot/node",
            "fields": {
                "entries": {"map_of": {"type_ref": "system/hash"}},
                "binding": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_tree_tracking_config() -> Entity:
    """Trie root tracking configuration.

    Per EXTENSION-TREE v3.8 §3.4.1a. Stored at
    `system/tree/tracking-config/{name}`. The structural summary consumer
    watches these configs and maintains incremental trie roots at
    `system/tree/root/{prefix}` for each enabled prefix.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/tracking-config",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "enabled": {"type_ref": "primitive/bool"},
            },
        },
    )


def type_system_tree_consumer_halt() -> Entity:
    """A consumer that halted the cascade.

    Per PROPOSAL-CASCADE-SEMANTICS §4.4. Each entry names the consumer
    and carries its error (a system/protocol/error with code + message).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/consumer-halt",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "error": {"type_ref": "system/protocol/error"},
            },
        },
    )


def type_system_tree_partial_result() -> Entity:
    """Cascade-halt response envelope.

    Per PROPOSAL-CASCADE-SEMANTICS §4.4. Returned as the result of a
    tree.put (or content_store.put) that produced a 207 status — binding
    landed but cascade incomplete. Consumer names identify who halted.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/partial-result",
            "fields": {
                "binding_committed": {"type_ref": "primitive/bool"},
                "consumers_completed": {"type_ref": "primitive/list", "type_args": ["primitive/string"]},
                "consumers_halted": {"type_ref": "primitive/list", "type_args": ["system/tree/consumer-halt"]},
                "consumers_skipped": {"type_ref": "primitive/list", "type_args": ["primitive/string"]},
                "nested_cascade_ids": {"type_ref": "primitive/list", "type_args": ["system/hash"], "optional": True},
                "cascade_depth": {"type_ref": "primitive/uint"},
            },
        },
    )


# =============================================================================
# Revision Extension Types (EXTENSION-REVISION v2.1)
# =============================================================================


def type_system_revision_entry() -> Entity:
    """Structural version entry: {root, parents} only.

    Per EXTENSION-REVISION v2.1 and PROPOSAL-STRUCTURAL-VERSION-ENTRIES v4.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/entry",
            "fields": {
                "root": {"type_ref": "system/hash"},
                "parents": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


def type_system_revision_conflict() -> Entity:
    """Conflict entity with version tracking and supersedes.

    Per EXTENSION-REVISION v2.1 section 2.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/conflict",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "base": {"type_ref": "system/hash", "optional": True},
                "local": {"type_ref": "system/hash", "optional": True},
                "remote": {"type_ref": "system/hash", "optional": True},
                "strategy": {"type_ref": "primitive/string"},
                "version_local": {"type_ref": "system/hash"},
                "version_remote": {"type_ref": "system/hash"},
                "supersedes": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_merge_config() -> Entity:
    """Merge strategy configuration per path pattern (§2.3).

    Per EXTENSION-REVISION v3.1 §2.3 Amendment 4 (deletion_resolution):
    optional field selecting the resolution strategy when exactly one
    side of a three-way merge is a `system/deletion-marker` binding.
    `lww` and `keep-both` MUST be rejected at config-write time
    (§4.4.18 v3.3); other values are validated by `validate_merge_config`.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/merge-config",
            "fields": {
                "pattern": {"type_ref": "system/tree/path", "optional": True},
                "strategy": {"type_ref": "primitive/string", "optional": True},
                "handler": {"type_ref": "system/tree/path", "optional": True},
                "deletion_resolution": {
                    "type_ref": "primitive/string", "optional": True,
                },
            },
        },
    )


def type_system_revision_merge_config_params() -> Entity:
    """`merge-config` op params (REVISION v3.3 §4.4.18)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/merge-config-params",
            "fields": {
                "scope": {"type_ref": "primitive/string"},     # "path" | "type"
                "name": {"type_ref": "primitive/string"},      # pattern or type name
                "action": {"type_ref": "primitive/string"},    # "set" | "delete"
                "config": {
                    "type_ref": "system/revision/merge-config",
                    "optional": True,
                },
                "expected_hash": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_merge_config_result() -> Entity:
    """`merge-config` op result (REVISION v3.3 §4.4.18).

    `status` is one of `"set"`, `"deleted"`, `"no_change"` — pinned
    cross-impl per the §4.4.18 conformance vectors.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/merge-config-result",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "hash": {"type_ref": "system/hash", "optional": True},
                "status": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_revision_merge_request() -> Entity:
    """Request sent to custom merge handlers (§5.3)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/merge-request",
            "fields": {
                "base": {"type_ref": "system/hash", "optional": True},
                "local": {"type_ref": "system/hash"},
                "remote": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_revision_merge_response() -> Entity:
    """Response from custom merge handlers (§5.3)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/merge-response",
            "fields": {
                "resolved": {"type_ref": "primitive/bool"},
                "entity": {"type_ref": "system/hash", "optional": True},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_revision_config() -> Entity:
    """Per-prefix versioning configuration."""
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/config",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "exclude": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
                "exclude_types": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
                "auto_version": {"type_ref": "primitive/bool", "optional": True},
                "merge_order": {"type_ref": "primitive/string", "optional": True},
                "oscillation_depth": {"type_ref": "primitive/uint", "optional": True},
                "checkout_under_auto_version": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_revision_status() -> Entity:
    """Version status."""
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/status",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "head": {"type_ref": "system/hash", "optional": True},
                "remotes": {"map_of": {"type_ref": "system/hash"}, "optional": True},
                "conflicts": {"type_ref": "primitive/uint"},
                "pending": {"type_ref": "primitive/uint"},
                "keep_both_paths": {"array_of": {"type_ref": "system/tree/path"}, "optional": True},
            },
        },
    )


def type_system_revision_commit_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/commit-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_revision_commit_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/commit-result",
            "fields": {
                "version": {"type_ref": "system/hash"},
                "root": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_revision_log_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/log-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "limit": {"type_ref": "primitive/uint", "optional": True},
                "since": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_log_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/log-result",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "versions": {"array_of": {"type_ref": "system/hash"}},
                "has_more": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_revision_merge_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/merge-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "remote_version": {"type_ref": "system/hash"},
                "strategy": {"type_ref": "primitive/string", "optional": True},
                "dry_run": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_revision_merge_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/merge-result",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "status": {"type_ref": "primitive/string"},
                "version": {"type_ref": "system/hash", "optional": True},
                "conflicts": {"array_of": {"type_ref": "system/tree/path"}, "optional": True},
                "dry_run": {"type_ref": "primitive/bool", "optional": True},
                "cascade_warnings": {"array_of": {"type_ref": "system/revision/cascade-warning"}, "optional": True},
            },
        },
    )


def type_system_revision_resolve_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/resolve-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "path": {"type_ref": "system/tree/path"},
                "resolved": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_resolve_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/resolve-result",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "resolved": {"type_ref": "system/hash", "optional": True},
                "remaining_conflicts": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_revision_fetch_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/fetch-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "remote_prefix": {"type_ref": "system/tree/path", "optional": True},
                # `remote` is consumed by `pull` (§4.4.8) to identify the peer
                # to pull from; `fetch` itself ignores it (the remote is
                # implicit in the EXECUTE target URI for plain fetch).
                "remote": {"type_ref": "primitive/string", "optional": True},
                "since": {"type_ref": "system/hash", "optional": True},
                "depth": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_revision_fetch_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/fetch-result",
            "fields": {
                "head": {"type_ref": "system/hash", "optional": True},
                "versions": {"array_of": {"type_ref": "system/hash"}},
                "has_more": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_revision_fetch_diff_params() -> Entity:
    # EXTENSION-REVISION v3.4 §4.4.19. `base` is the version hash the caller
    # already has (zero/omitted = full closure against the empty trie); the
    # target is implicit (the handler peer's current head), which keeps the
    # op single-dynamic-field and so chain-expressible.
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/fetch-diff-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "base": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_fetch_entities_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/fetch-entities-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "snapshot": {"type_ref": "system/hash"},
                "hashes": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


def type_system_revision_fetch_entities_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/fetch-entities-result",
            "fields": {
                "found": {"array_of": {"type_ref": "system/hash"}},
                "missing": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


def type_system_revision_push_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/push-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "remote": {"type_ref": "primitive/string"},
                "remote_prefix": {"type_ref": "system/tree/path", "optional": True},
                "force": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_revision_push_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/push-result",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "remote": {"type_ref": "primitive/string"},
                "status": {"type_ref": "primitive/string"},
                "pushed": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_revision_ancestor_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/ancestor-params",
            "fields": {
                "version_a": {"type_ref": "system/hash"},
                "version_b": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_revision_ancestor_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/ancestor-result",
            "fields": {
                "ancestor": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_status_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/status-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_revision_branch_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/branch-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "action": {"type_ref": "primitive/string"},
                "name": {"type_ref": "primitive/string", "optional": True},
                "from": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_branch_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/branch-result",
            "fields": {
                "status": {"type_ref": "primitive/string", "optional": True},
                "branch": {"type_ref": "primitive/string", "optional": True},
                "branches": {"map_of": {"type_ref": "system/hash"}, "optional": True},
                "active": {"type_ref": "primitive/string", "optional": True},
                "version": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_checkout_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/checkout-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "branch": {"type_ref": "primitive/string", "optional": True},
                "version": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_checkout_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/checkout-result",
            "fields": {
                "status": {"type_ref": "primitive/string"},
                "version": {"type_ref": "system/hash"},
                "branch": {"type_ref": "primitive/string", "optional": True},
                "cascade_warnings": {"array_of": {"type_ref": "system/revision/cascade-warning"}, "optional": True},
            },
        },
    )


def type_system_revision_tag_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/tag-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "action": {"type_ref": "primitive/string"},
                "name": {"type_ref": "primitive/string", "optional": True},
                "version": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_tag_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/tag-result",
            "fields": {
                "status": {"type_ref": "primitive/string", "optional": True},
                "tag": {"type_ref": "primitive/string", "optional": True},
                "tags": {"map_of": {"type_ref": "system/hash"}, "optional": True},
                "version": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_diff_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/diff-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "base": {"type_ref": "system/hash"},
                "target": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_revision_cherry_pick_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/cherry-pick-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "version": {"type_ref": "system/hash"},
                "parent": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_cherry_pick_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/cherry-pick-result",
            "fields": {
                "status": {"type_ref": "primitive/string"},
                "version": {"type_ref": "system/hash"},
                "source": {"type_ref": "system/hash"},
                "cascade_warnings": {"array_of": {"type_ref": "system/revision/cascade-warning"}, "optional": True},
            },
        },
    )


def type_system_revision_revert_params() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/revert-params",
            "fields": {
                "prefix": {"type_ref": "system/tree/path"},
                "version": {"type_ref": "system/hash"},
                "parent": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_revert_result() -> Entity:
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/revert-result",
            "fields": {
                "status": {"type_ref": "primitive/string"},
                "version": {"type_ref": "system/hash"},
                "reverted": {"type_ref": "system/hash"},
                "cascade_warnings": {"array_of": {"type_ref": "system/revision/cascade-warning"}, "optional": True},
            },
        },
    )


def type_system_revision_config_params() -> Entity:
    """Config operation input per PROPOSAL-REVISION-CONFIG-OPERATION §3.1."""
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/config-params",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "action": {"type_ref": "primitive/string"},
                "config": {"type_ref": "system/revision/config", "optional": True},
                "expected_hash": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_revision_config_result() -> Entity:
    """Config operation result per PROPOSAL-REVISION-CONFIG-OPERATION §3.1."""
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/config-result",
            "fields": {
                "config_path": {"type_ref": "system/tree/path"},
                "config_hash": {"type_ref": "system/hash", "optional": True},
                "previous_hash": {"type_ref": "system/hash", "optional": True},
                "tracking_config_path": {"type_ref": "system/tree/path", "optional": True},
                "tracking_config_action": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_revision_cascade_warning() -> Entity:
    """Cascade warning for merge/checkout/cherry-pick/revert results.

    Per PROPOSAL-REVISION-CONFIG-OPERATION §3.5 (R5).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/revision/cascade-warning",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "consumer_halted": {"type_ref": "primitive/string"},
                "error_code": {"type_ref": "primitive/string"},
            },
        },
    )


# =============================================================================
# Clock Extension Types (EXTENSION-CLOCK v1.0)
# =============================================================================


def type_system_clock_timestamp() -> Entity:
    """Wall-clock timestamp in milliseconds since Unix epoch.

    Per EXTENSION-CLOCK v1.0 §2.1.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/timestamp",
            "fields": {
                "ms": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_clock_logical() -> Entity:
    """Lamport-style logical clock counter.

    Per EXTENSION-CLOCK v1.0 §2.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/logical",
            "fields": {
                "counter": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_clock_vector() -> Entity:
    """Vector clock with peer-indexed counters.

    Per EXTENSION-CLOCK v1.0 §2.3.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/vector",
            "fields": {
                "entries": {"map_of": {"type_ref": "primitive/uint"}},
            },
        },
    )


def type_system_clock_hlc() -> Entity:
    """Hybrid Logical Clock combining physical time with logical counter.

    Per EXTENSION-CLOCK v1.0 §2.4.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/hlc",
            "fields": {
                "physical": {"type_ref": "primitive/uint"},
                "logical": {"type_ref": "primitive/uint"},
                "peer": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_clock_config() -> Entity:
    """Clock configuration for a peer.

    Per EXTENSION-CLOCK v1.0 §2.5.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/config",
            "fields": {
                "mode": {"type_ref": "primitive/string"},
                "wall_clock": {"type_ref": "primitive/bool", "optional": True},
                "tick_interval": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_clock_state() -> Entity:
    """Current clock state for a peer.

    Per EXTENSION-CLOCK v1.0 §2.6.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/state",
            "fields": {
                "mode": {"type_ref": "primitive/string"},
                "timestamp": {"type_ref": "system/clock/timestamp", "optional": True},
                "logical": {"type_ref": "system/clock/logical", "optional": True},
                "vector": {"type_ref": "system/clock/vector", "optional": True},
                "hlc": {"type_ref": "system/clock/hlc", "optional": True},
            },
        },
    )


def type_system_clock_compare_params() -> Entity:
    """Parameters for clock compare operation.

    Per EXTENSION-CLOCK v1.0 §2.7.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/compare-params",
            "fields": {
                "a": {"type_ref": "primitive/any"},
                "b": {"type_ref": "primitive/any"},
            },
        },
    )


def type_system_clock_compare_result() -> Entity:
    """Result from clock compare operation.

    Per EXTENSION-CLOCK v1.0 §2.7.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/compare-result",
            "fields": {
                "order": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_clock_tick() -> Entity:
    """Periodic tick event.

    Per EXTENSION-CLOCK v1.0 §2.8.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/clock/tick",
            "fields": {
                "sequence": {"type_ref": "primitive/uint"},
                "state": {"type_ref": "system/clock/state"},
            },
        },
    )


# =============================================================================
# Query Extension Types (EXTENSION-QUERY v1.0)
# =============================================================================


def type_system_query_expression() -> Entity:
    """Query expression type (§4.1).

    Declarative query over indexed entity set. All present filters are
    conjunctive (AND).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/query/expression",
            "fields": {
                "type_filter": {"type_ref": "primitive/string", "optional": True},
                "field_filters": {
                    "array_of": {"type_ref": "system/query/field-predicate"},
                    "optional": True,
                },
                "ref_filter": {"type_ref": "system/hash", "optional": True},
                "path_filter": {"type_ref": "system/tree/path", "optional": True},
                "path_prefix": {"type_ref": "system/tree/path", "optional": True},
                "limit": {"type_ref": "primitive/uint", "optional": True},
                "cursor": {"type_ref": "primitive/string", "optional": True},
                "order_by": {"type_ref": "primitive/string", "optional": True},
                "descending": {"type_ref": "primitive/bool", "optional": True},
                "include_entities": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_query_field_predicate() -> Entity:
    """Field predicate type (§4.2).

    A single field comparison within a query expression.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/query/field-predicate",
            "fields": {
                "field": {"type_ref": "primitive/string"},
                "operator": {"type_ref": "primitive/string"},
                "value": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_query_result() -> Entity:
    """Query result type (§4.3).

    Returned by the find operation with matches, pagination, and total count.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/query/result",
            "fields": {
                "matches": {"array_of": {"type_ref": "system/query/match"}},
                "total": {"type_ref": "primitive/uint"},
                "has_more": {"type_ref": "primitive/bool"},
                "cursor": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_query_match() -> Entity:
    """Query match type (§4.3).

    A single matched entity in a query result.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/query/match",
            "fields": {
                "path": {"type_ref": "system/tree/path", "optional": True},
                "hash": {"type_ref": "system/hash"},
                "type": {"type_ref": "system/type/name"},
            },
        },
    )


def type_system_query_constraints() -> Entity:
    """Query constraints type (§5.5.1, updated v1.1).

    Domain-specific narrowing fields for query grants.
    V1.1: scope moved to allowances.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/query/constraints",
            "fields": {
                "max_results": {"type_ref": "primitive/uint", "optional": True},
                "type_scope": {
                    "type_ref": "system/capability/id-scope",
                    "optional": True,
                },
            },
        },
    )


def type_system_query_allowances() -> Entity:
    """Query allowances type (EXTENSION-QUERY v1.1, PROPOSAL-CAPABILITY-GRANT-ALLOWANCES G4).

    Domain-specific expanding fields for query grants.
    Absent = most restricted (tree scope only).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/query/allowances",
            "fields": {
                "scope": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_query_index_config() -> Entity:
    """Query index configuration type (EXTENSION-QUERY §2.4).

    Configures which (type, field) pairs are indexed for field queries.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/query/index-config",
            "fields": {
                "type_name": {"type_ref": "system/type/name"},
                "fields": {"array_of": {"type_ref": "primitive/string"}},
            },
        },
    )


# =============================================================================
# History Extension Types (EXTENSION-HISTORY v1.2)
# =============================================================================


def type_system_history_transition() -> Entity:
    """History transition type (EXTENSION-HISTORY §2.1).

    Records a single change to a tree binding with full execution context.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/history/transition",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "event": {"type_ref": "primitive/string"},
                "hash": {"type_ref": "system/hash", "optional": True},
                "previous_hash": {"type_ref": "system/hash", "optional": True},
                "author": {"type_ref": "system/hash"},
                "capability": {"type_ref": "system/hash"},
                "handler": {"type_ref": "system/tree/path"},
                "operation": {"type_ref": "primitive/string"},
                "timestamp": {"type_ref": "primitive/uint"},
                "clock": {"type_ref": "system/clock/state", "optional": True},
                "chain_id": {"type_ref": "primitive/string", "optional": True},
                "parent_chain_id": {"type_ref": "primitive/string", "optional": True},
                "previous": {"type_ref": "system/hash", "optional": True},
                "caller_capability": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_history_config() -> Entity:
    """History configuration type (EXTENSION-HISTORY §2.2).

    Per-path-pattern configuration for history recording.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/history/config",
            "fields": {
                "pattern": {"type_ref": "system/tree/path"},
                "enabled": {"type_ref": "primitive/bool"},
                "events": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
                "max_depth": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_history_query_params() -> Entity:
    """History query parameters type (EXTENSION-HISTORY §2.3)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/history/query-params",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "limit": {"type_ref": "primitive/uint", "optional": True},
                "since": {"type_ref": "system/hash", "optional": True},
                "before": {"type_ref": "primitive/uint", "optional": True},
                "events": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
            },
        },
    )


def type_system_history_query_result() -> Entity:
    """History query result type (EXTENSION-HISTORY §2.4)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/history/query-result",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "head": {"type_ref": "system/hash", "optional": True},
                "transitions": {"array_of": {"type_ref": "system/history/transition"}},
                "has_more": {"type_ref": "primitive/bool"},
            },
        },
    )


def type_system_history_rollback_params() -> Entity:
    """History rollback parameters type (EXTENSION-HISTORY §4.3.2)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/history/rollback-params",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "target_hash": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_history_rollback_result() -> Entity:
    """History rollback result type (EXTENSION-HISTORY §4.3.2)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/history/rollback-result",
            "fields": {
                "path": {"type_ref": "system/tree/path"},
                "restored": {"type_ref": "system/hash"},
            },
        },
    )


# =============================================================================
# Identity Extension Types (per EXTENSION-IDENTITY v2.2)
#
# Three primary entity types (quorum, peer-config, attestation) plus the
# identity-binding helper. All relational kinds (certification, runtime,
# contact-face, contact-quorum, rotation-handoff, rotation-recovery,
# retirement, quorum-update) live under the unified attestation type
# discriminated by `kind`. Validated entity-level by verify_attestation
# (§3.6), NOT by V7 cap-chain machinery.
# =============================================================================


def type_system_identity_quorum() -> Entity:
    """Identity quorum (EXTENSION-IDENTITY v2.2 §3.1).

    Defines the K-of-N signing group holding identity authority.
    Structural entity; not itself signed. Authorization flows from
    constituents collectively K-of-N-signing other entities.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/quorum",
            "fields": {
                "signers": {"array_of": {"type_ref": "system/hash"}},
                "threshold": {"type_ref": "primitive/uint"},
                "signer_resolution": {"type_ref": "primitive/string", "optional": True},
                "name": {"type_ref": "primitive/string", "optional": True},
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_identity_attestation() -> Entity:
    """Unified identity attestation (EXTENSION-IDENTITY v2.2 §3.3).

    Every edge in the identity key graph is an attestation. The `kind`
    field discriminates the structural relationship (one of:
    certification, quorum-update, runtime, contact-face, contact-quorum,
    rotation-handoff, rotation-recovery, retirement). Per-kind invariants
    are enforced by validate_kind_structure (§4.10); signature topology
    is dispatched by verify_attestation (§3.6).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/attestation",
            "fields": {
                "kind": {"type_ref": "primitive/string"},
                "attesting": {"type_ref": "system/hash"},
                "attested": {"type_ref": "system/hash"},
                "properties": {"type_ref": "primitive/any", "optional": True},
                "supersedes": {"type_ref": "system/hash", "optional": True},
                "not_before": {"type_ref": "primitive/uint", "optional": True},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_identity_identity_binding() -> Entity:
    """Identity-binding helper (EXTENSION-IDENTITY v3.3 §3.4).

    Field-only inner type. Lives inside peer-config.bindings; never
    stored as an independent entity. Records this agent's role in one
    identity by referencing the handle cert (controller cert in 3-key
    default, identifier cert in 4-key advanced) and the agent cert.
    Both fields are content hashes of `system/attestation` entities.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/identity-binding",
            "fields": {
                "handle_cert": {"type_ref": "system/hash"},
                "agent_cert": {"type_ref": "system/hash"},
                "label": {"type_ref": "primitive/string", "optional": True},
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_identity_event() -> Entity:
    """Controller-events stream entity (EXTENSION-IDENTITY v3.5 §6.3 / V7 PI-5).

    Emitted by `:process_attestation` phase 3 (and PI-3 publish-MOVE
    recovery / PI-13 cascade partial-failure) when a phase-2 handler
    fails. Bound at:
        system/identity/events/{timestamp_ms}/{handler_id}/{att_hash}/{event_hash}

    Per Rev 3 PI-5 event_subkind distinguishes recovery_signal events
    (orphaned/inconsistent state requiring controller action; MUST NOT
    be pruned until cleared) from failure_observation events (consistent
    state; impl-defined retention). v2 emits these subkinds; v2.x may add
    `informational` for success-path observability.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/event",
            "fields": {
                "event_subkind": {"type_ref": "primitive/string"},
                "handler_id": {"type_ref": "primitive/string"},
                "attestation_hash": {"type_ref": "system/hash"},
                "attestation_kind": {"type_ref": "primitive/string"},
                "error_code": {"type_ref": "primitive/string"},
                "error_detail": {"type_ref": "primitive/string"},
                "timestamp_ms": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_identity_peer_config() -> Entity:
    """Peer configuration (EXTENSION-IDENTITY v3.3 §3.2).

    Per-agent local config. Records the trusted quorum (a `system/quorum`
    reference, per the substrate), the grants the controller holds on
    this peer (drives the local peer→controller cap), and which
    identities this peer participates in (one binding per identity).

    Per-agent, NOT per-machine: a host operating as multiple agents
    has one peer-config per agent; peer-configs MUST NOT share state
    across identities.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/peer-config",
            "fields": {
                "trusts_quorum": {"type_ref": "system/hash"},
                "controller_grants": {
                    "array_of": {"type_ref": "system/capability/grant-entry"}
                },
                "bindings": {
                    "array_of": {"type_ref": "system/identity/identity-binding"},
                    "optional": True,
                },
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


# -- Identity handler request/result types (§6.2 — §6.7) -------------------
# Wire-observable surface for cross-impl validation; field shapes match
# the Go reference impl (entity-core-go/core/types/identity.go).


def type_system_identity_configure_request() -> Entity:
    """configure request (EXTENSION-IDENTITY v3.3 §6).
    `controller_grants` describe what the top-level controller's key is
    authorized to do on this peer (per §3.2 sub-controller chain rule)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/configure-request",
            "fields": {
                "trusts_quorum": {"type_ref": "system/hash"},
                "controller_grants": {
                    "array_of": {"type_ref": "system/capability/grant-entry"}
                },
                "bindings": {
                    "array_of": {"type_ref": "system/identity/identity-binding"},
                    "optional": True,
                },
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_identity_configure_result() -> Entity:
    """configure result (EXTENSION-IDENTITY v3.3 §6). One cap per live
    top-level controller cert under the trusted quorum (multi-controller
    deployments produce multiple)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/configure-result",
            "fields": {
                "peer_config": {"type_ref": "system/hash"},
                "trusts_quorum": {"type_ref": "system/hash"},
                "issued_controller_caps": {
                    "array_of": {"type_ref": "system/hash"},
                },
            },
        },
    )


def type_system_identity_create_quorum_request() -> Entity:
    """create_quorum request (EXTENSION-IDENTITY v3.3 §6). Delegates to
    QUORUM:create. Fields mirror system/quorum/create-request."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/create-quorum-request",
            "fields": {
                "signers": {"array_of": {"type_ref": "system/hash"}},
                "threshold": {"type_ref": "primitive/uint"},
                "signer_resolution": {
                    "type_ref": "primitive/string", "optional": True,
                },
                "name": {"type_ref": "primitive/string", "optional": True},
                "metadata": {"type_ref": "primitive/any", "optional": True},
                "controller_grants": {
                    "array_of": {"type_ref": "system/capability/grant-entry"},
                    "optional": True,
                },
            },
        },
    )


def type_system_identity_create_attestation_request() -> Entity:
    """create_attestation request (EXTENSION-IDENTITY v3.3 §6).
    `attestation` is a `system/attestation` entity with identity
    properties (kind=identity-cert / lifecycle, function, mode).
    Signatures live in `envelope.included` per V7's signature
    target-matching pattern; identity §6.2 v3.3 ingests them at handler
    entry before validation runs."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/create-attestation-request",
            "fields": {
                "attestation": {"type_ref": "system/attestation"},
                "included": {
                    "array_of": {"type_ref": "primitive/any"},
                    "optional": True,
                },
            },
        },
    )


def type_system_identity_create_attestation_result() -> Entity:
    """create_attestation result (EXTENSION-IDENTITY v3.3 §6).
    `entity` is set when an `identity-cert` (function=agent) cert with
    `mode=embedded` is created (no tree write; entity returned for
    caller-side embedding into a cap envelope). Unset for all other
    kinds and modes."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/create-attestation-result",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "kind": {"type_ref": "primitive/string", "optional": True},
                "mode": {"type_ref": "primitive/string", "optional": True},
                "stored_at": {"type_ref": "system/tree/path", "optional": True},
                "entity": {"type_ref": "system/attestation", "optional": True},
            },
        },
    )


def type_system_identity_supersede_attestation_request() -> Entity:
    """supersede_attestation request (EXTENSION-IDENTITY v3.3 §6).
    `new_attestation.data.supersedes` references the live attestation it
    replaces; the handler validates the supersedes-chain key per kind."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/supersede-attestation-request",
            "fields": {
                "new_attestation": {"type_ref": "system/attestation"},
                "included": {
                    "array_of": {"type_ref": "primitive/any"},
                    "optional": True,
                },
            },
        },
    )


def type_system_identity_publish_attestation_request() -> Entity:
    """publish_attestation request (EXTENSION-IDENTITY v3.3 §6).
    Changes the publication mode/path of an existing identity-cert
    (function=agent) attestation. contact_id is required when
    new_mode == 'per-relationship'."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/publish-attestation-request",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "new_mode": {"type_ref": "primitive/string"},
                "contact_id": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


# =============================================================================
# v3.3 substrate-aligned identity result types (per the Go cross-impl
# report). Naming aligns with Go reference impl.
# =============================================================================


def type_system_identity_create_quorum_result() -> Entity:
    """create_quorum result (EXTENSION-IDENTITY v3.3 §6). Delegates to
    QUORUM:create; returns the quorum_id."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/create-quorum-result",
            "fields": {
                "quorum_id": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_identity_supersede_attestation_result() -> Entity:
    """supersede_attestation result (EXTENSION-IDENTITY v3.3 §6)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/supersede-attestation-result",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "kind": {"type_ref": "primitive/string"},
                "stored_at": {"type_ref": "system/tree/path", "optional": True},
            },
        },
    )


def type_system_identity_revoke_attestation_request() -> Entity:
    """revoke_attestation request (EXTENSION-IDENTITY v3.3 §6). Path
    comes from `ctx.resource_targets[0]`; params is empty per
    path-as-resource."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/revoke-attestation-request",
            "fields": {},
        },
    )


def type_system_identity_revoke_attestation_result() -> Entity:
    """revoke_attestation result (EXTENSION-IDENTITY v3.3 §6)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/revoke-attestation-result",
            "fields": {
                "kind": {"type_ref": "primitive/string", "optional": True},
                "removed_from": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_identity_publish_attestation_result() -> Entity:
    """publish_attestation result (EXTENSION-IDENTITY v3.3 §6)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/identity/publish-attestation-result",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "mode": {"type_ref": "primitive/string"},
                "stored_at": {"type_ref": "system/tree/path", "optional": True},
            },
        },
    )


# =============================================================================
# EXTENSION-ATTESTATION v1.1 substrate types
# Per Go cross-impl report: substrate primary entity + 4 op request/result
# types (8 total) needed for wire conformance.
# =============================================================================


def type_system_attestation() -> Entity:
    """`system/attestation` (EXTENSION-ATTESTATION v1.1 §3.1) — the edge
    type in the system's signed graph."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation",
            "fields": {
                "attesting": {"type_ref": "system/hash"},
                "attested": {"type_ref": "system/hash"},
                "properties": {"type_ref": "primitive/any"},
                "supersedes": {"type_ref": "system/hash", "optional": True},
                "not_before": {"type_ref": "primitive/uint", "optional": True},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_attestation_create_request() -> Entity:
    """`system/attestation:create` request (EXTENSION-ATTESTATION v1.1
    §6.1). Path-as-resource MUST per SI-7."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/create-request",
            "fields": {
                "attesting": {"type_ref": "system/hash"},
                "attested": {"type_ref": "system/hash"},
                "properties": {"type_ref": "primitive/any"},
                "supersedes": {"type_ref": "system/hash", "optional": True},
                "not_before": {"type_ref": "primitive/uint", "optional": True},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_attestation_create_result() -> Entity:
    """`system/attestation:create` result (EXTENSION-ATTESTATION v1.1 §6.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/create-result",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "stored_at": {"type_ref": "system/tree/path", "optional": True},
            },
        },
    )


def type_system_attestation_supersede_request() -> Entity:
    """`system/attestation:supersede` request (EXTENSION-ATTESTATION v1.1
    §6.2). previous_hash is the attestation being superseded; the
    handler copies attesting/attested from it."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/supersede-request",
            "fields": {
                "previous_hash": {"type_ref": "system/hash"},
                "properties": {"type_ref": "primitive/any"},
                "not_before": {"type_ref": "primitive/uint", "optional": True},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_attestation_supersede_result() -> Entity:
    """`system/attestation:supersede` result. Same shape as create-result."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/supersede-result",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "stored_at": {"type_ref": "system/tree/path", "optional": True},
            },
        },
    )


def type_system_attestation_revoke_request() -> Entity:
    """`system/attestation:revoke` request (EXTENSION-ATTESTATION v1.1
    §6.3). Wraps :create with `kind="revocation"`."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/revoke-request",
            "fields": {
                "target_hash": {"type_ref": "system/hash"},
                "attesting": {"type_ref": "system/hash"},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_attestation_revoke_result() -> Entity:
    """`system/attestation:revoke` result. Same shape as create-result."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/revoke-result",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "stored_at": {"type_ref": "system/tree/path", "optional": True},
            },
        },
    )


def type_system_attestation_verify_request() -> Entity:
    """`system/attestation:verify` request (EXTENSION-ATTESTATION v1.1
    §6.4). Optional as_of supports time-traveling validation."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/verify-request",
            "fields": {
                "attestation_hash": {"type_ref": "system/hash"},
                "as_of": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_attestation_verify_result() -> Entity:
    """`system/attestation:verify` result (EXTENSION-ATTESTATION v1.1 §6.4)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/attestation/verify-result",
            "fields": {
                "valid": {"type_ref": "primitive/bool"},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


# =============================================================================
# EXTENSION-QUORUM v1.1 substrate types
# Per Go cross-impl report: substrate primary entity + 4 op request/result
# types (8 total). Quorum self-events are system/attestation entities
# (per QUORUM §3.2 / §3.3); their request/result shapes are below.
# =============================================================================


def type_system_quorum() -> Entity:
    """`system/quorum` (EXTENSION-QUORUM v1.1 §3.1) — the K-of-N node
    entity. Stored at `system/quorum/{quorum_id_hex}`. Structural; not
    itself signed."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum",
            "fields": {
                "signers": {"array_of": {"type_ref": "system/hash"}},
                "threshold": {"type_ref": "primitive/uint"},
                "signer_resolution": {
                    "type_ref": "primitive/string", "optional": True,
                },
                "name": {"type_ref": "primitive/string", "optional": True},
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_quorum_create_request() -> Entity:
    """`system/quorum:create` request (EXTENSION-QUORUM v1.1 §6.1).
    Path-as-resource MUST per SI-7/SI-22."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/create-request",
            "fields": {
                "signers": {"array_of": {"type_ref": "system/hash"}},
                "threshold": {"type_ref": "primitive/uint"},
                "signer_resolution": {
                    "type_ref": "primitive/string", "optional": True,
                },
                "name": {"type_ref": "primitive/string", "optional": True},
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_quorum_create_result() -> Entity:
    """`system/quorum:create` result."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/create-result",
            "fields": {
                "quorum_id": {"type_ref": "system/hash"},
                "stored_at": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_quorum_update_request() -> Entity:
    """`system/quorum:update` request (EXTENSION-QUORUM v1.1 §6.2).
    Produces an unsigned `quorum-update` attestation; signature gathering
    (K-of-N from the current signer set) is the caller's responsibility."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/update-request",
            "fields": {
                "quorum_id": {"type_ref": "system/hash"},
                "new_signers": {"array_of": {"type_ref": "system/hash"}},
                "new_threshold": {"type_ref": "primitive/uint"},
                "supersedes": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_quorum_update_result() -> Entity:
    """`system/quorum:update` result."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/update-result",
            "fields": {
                "update_hash": {"type_ref": "system/hash"},
                "stored_at": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_quorum_publish_request() -> Entity:
    """`system/quorum:publish` request (EXTENSION-QUORUM v1.1 §6.3).
    Initial publish: signers/threshold MUST match current_signer_set;
    superseding publish carries the new (post-update) signers/threshold
    and is K-of-N signed by the PREVIOUS quorum (per §3.3)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/publish-request",
            "fields": {
                "quorum_id": {"type_ref": "system/hash"},
                "signers": {"array_of": {"type_ref": "system/hash"}},
                "threshold": {"type_ref": "primitive/uint"},
                "published_handle": {"type_ref": "system/hash", "optional": True},
                "properties": {"type_ref": "primitive/any", "optional": True},
                "supersedes": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_quorum_publish_result() -> Entity:
    """`system/quorum:publish` result."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/publish-result",
            "fields": {
                "publish_hash": {"type_ref": "system/hash"},
                "stored_at": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_quorum_verify_request() -> Entity:
    """`system/quorum:verify` request (EXTENSION-QUORUM v1.1 §6.4).
    K-of-N verification helper wrapping current_signer_set +
    verify_k_of_n_signatures."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/verify-request",
            "fields": {
                "entity_hash": {"type_ref": "system/hash"},
                "quorum_id": {"type_ref": "system/hash"},
                "as_of": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_quorum_verify_result() -> Entity:
    """`system/quorum:verify` result. `signed_by` is the set of
    constituents whose signatures verified."""
    return Entity(
        type="system/type",
        data={
            "name": "system/quorum/verify-result",
            "fields": {
                "valid": {"type_ref": "primitive/bool"},
                "signed_by": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


# =============================================================================
# EXTENSION-ROLE v1.6 types — entity types + 11 request/result types
# Per the EXTENSION-ROLE v1.6 cross-impl report: 15 types total. Encoding aligned to
# v1.6 SI-1/SI-2/SI-8 (peer references are `system/hash`, raw bytes on
# wire / lowercase hex in path segments).
# =============================================================================


def type_system_role() -> Entity:
    """`system/role` (EXTENSION-ROLE.md v1.6 §2.1) — named bundle of
    capability grant entries. Stored at
    `system/role/{context}/{role_name}`."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "grants": {
                    "array_of": {"type_ref": "system/capability/grant-entry"},
                },
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_role_assignment() -> Entity:
    """`system/role/assignment` (EXTENSION-ROLE.md v1.6 §2.2) — binds a
    peer identity to a role within a context. Stored at
    `system/role/{context}/assignment/{peer_id_hex}/{role_name}`."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/assignment",
            "fields": {
                "role": {"type_ref": "primitive/string"},
                "assigned_by": {"type_ref": "system/hash"},
                "assigned_at": {"type_ref": "primitive/uint"},
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_role_exclusion() -> Entity:
    """`system/role/exclusion` (EXTENSION-ROLE.md v1.6 §2.3) — denies a
    peer all role-derived access within a context. Stored at
    `system/role/{context}/excluded/{peer_id_hex}`. Per SI-3, no body
    `peer_id` field — the path segment is canonical."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/exclusion",
            "fields": {
                "excluded_by": {"type_ref": "system/hash"},
                "excluded_at": {"type_ref": "primitive/uint"},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_role_derived_token_link() -> Entity:
    """`system/role/derived-token-link` (EXTENSION-ROLE.md v1.6 §2.4 / SI-5)
    — sibling-subtree linkage entity mapping a (context, peer, role)
    assignment to its issued role-derived cap. Stored at
    `system/role/{context}/derived-tokens/{peer_id_hex}/{role_name}`."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/derived-token-link",
            "fields": {
                "token_hash": {"type_ref": "system/hash"},
                "issued_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_role_define_request() -> Entity:
    """`system/role:define` request (EXTENSION-ROLE.md v1.6 §4.2 / IA11).
    Caller authorizes against the role-definition path; RL2 fires at
    definition-write time."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/define-request",
            "fields": {
                "grants": {
                    "array_of": {"type_ref": "system/capability/grant-entry"},
                },
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_role_define_result() -> Entity:
    """`system/role:define` result. `re_derived_count` is the per-role
    cascade triggered by IA11 (zero when no assignments exist yet)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/define-result",
            "fields": {
                "role_path": {"type_ref": "system/tree/path"},
                "re_derived_count": {
                    "type_ref": "primitive/uint", "optional": True,
                },
            },
        },
    )


def type_system_role_assign_request() -> Entity:
    """`system/role:assign` request (EXTENSION-ROLE.md v1.6 §4.2 / RL1, RL2).
    Path-as-resource: assignment path comes from EXECUTE.resource. The
    `role` selector MUST match the trailing role-name segment per SI-25."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/assign-request",
            "fields": {
                "role": {"type_ref": "primitive/string"},
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_role_assign_result() -> Entity:
    """`system/role:assign` result. `derived_tokens` carries the hashes
    of caps minted for the assignee."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/assign-result",
            "fields": {
                "assignment_path": {"type_ref": "system/tree/path"},
                "derived_tokens": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
            },
        },
    )


def type_system_role_unassign_result() -> Entity:
    """`system/role:unassign` result (EXTENSION-ROLE.md v1.6 §6.4.1 / IA12).
    Per SI-9 pattern parity, given its own dedicated result type in v1.6
    (was `system/protocol/status` in v1.5)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/unassign-result",
            "fields": {
                "assignment_path": {"type_ref": "system/tree/path"},
                "revoked_token_hashes": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
            },
        },
    )


def type_system_role_exclude_result() -> Entity:
    """`system/role:exclude` result (EXTENSION-ROLE.md v1.6 §4.2 / SI-9).
    Layer-1 broad sweep (SI-7) returns the hashes of role-derived caps
    deleted from the local subtree."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/exclude-result",
            "fields": {
                "exclusion_path": {"type_ref": "system/tree/path"},
                "revoked_token_hashes": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
            },
        },
    )


def type_system_role_unexclude_result() -> Entity:
    """`system/role:unexclude` result (EXTENSION-ROLE.md v1.6 §4.2).
    Per SI-9 pattern parity, given its own dedicated result type in v1.6."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/unexclude-result",
            "fields": {
                "exclusion_path": {"type_ref": "system/tree/path"},
            },
        },
    )


def type_system_role_re_derive_request() -> Entity:
    """`system/role:re-derive` request (EXTENSION-ROLE.md v1.6 §5.5 / IA9).
    Resource is the role-definition path; `role` is a selector that MUST
    match the trailing path segment when present."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/re-derive-request",
            "fields": {
                "role": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_role_re_derive_result() -> Entity:
    """`system/role:re-derive` result (EXTENSION-ROLE.md v1.6 §5.5).
    Per SI-15, `skipped_grantees` carries the `system/hash` (raw bytes)
    of assignees that retained T_old due to mid-cascade RL2 failure
    (the cascade does NOT abort on partial failure)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/re-derive-result",
            "fields": {
                "re_derived_count": {"type_ref": "primitive/uint"},
                "revoked_token_hashes": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "new_token_hashes": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "skipped_grantees": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
            },
        },
    )


def type_system_role_delegate_request() -> Entity:
    """`system/role:delegate` request (EXTENSION-ROLE.md v1.6 §5.6 / IA22).
    Per SI-21 the `delegator` field is dropped — caller is implicit from
    `ctx.execute.data.author`. Per SI-4 `context`/`role` are
    `primitive/string` (matching `assign-request`). Per SI-20 `scope` is
    literal — no template variables."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/delegate-request",
            "fields": {
                "delegate": {"type_ref": "system/hash"},
                "context": {"type_ref": "primitive/string"},
                "role": {"type_ref": "primitive/string"},
                "scope": {
                    "array_of": {"type_ref": "system/capability/grant-entry"},
                },
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_role_delegate_result() -> Entity:
    """`system/role:delegate` result (EXTENSION-ROLE.md v1.6 §5.6).
    The delegation cap lands at the role-derived storage path so
    layer-1 sweep, unassign revocation, and re-derive cascade reach
    it."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/delegate-result",
            "fields": {
                "delegation_token_hash": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_role_initial_grant_policy() -> Entity:
    """`system/role/initial-grant-policy` (EXTENSION-ROLE §4.7) — singleton
    entity bound at `system/role/initial-grant-policy` that drives the
    connect-handler grant resolver. `unknown_peer` selects the mode
    (`anonymous-deny`, `anonymous-allow`, `recognize-on-attestation`);
    `default_role` + `default_context` identify the role definition whose
    grants are issued on the connection cap; `identity_required` (only
    consulted in recognize-on-attestation mode) selects deny vs. allow
    fallback when the recognition predicate fails."""
    return Entity(
        type="system/type",
        data={
            "name": "system/role/initial-grant-policy",
            "fields": {
                "unknown_peer": {"type_ref": "primitive/string"},
                "default_role": {
                    "type_ref": "primitive/string", "optional": True,
                },
                "default_context": {
                    "type_ref": "primitive/string", "optional": True,
                },
                "identity_required": {
                    "type_ref": "primitive/bool", "optional": True,
                },
            },
        },
    )


# =============================================================================
# Primitive Type Definitions
# V6.0: Primitives are name-only types (no fields)
# =============================================================================


def type_primitive_string() -> Entity:
    """V6.0 primitive type: string."""
    return Entity(type="system/type", data={"name": "primitive/string"})


def type_primitive_bytes() -> Entity:
    """V6.0 primitive type: bytes."""
    return Entity(type="system/type", data={"name": "primitive/bytes"})


def type_primitive_int() -> Entity:
    """V6.0 primitive type: int (signed integer)."""
    return Entity(type="system/type", data={"name": "primitive/int"})


def type_primitive_uint() -> Entity:
    """V6.0 primitive type: uint (unsigned integer)."""
    return Entity(type="system/type", data={"name": "primitive/uint"})


def type_primitive_bool() -> Entity:
    """V6.0 primitive type: bool."""
    return Entity(type="system/type", data={"name": "primitive/bool"})


def type_primitive_float() -> Entity:
    """V6.0 primitive type: float."""
    return Entity(type="system/type", data={"name": "primitive/float"})


def type_primitive_any() -> Entity:
    """V6.0 primitive type: any (accepts any value)."""
    return Entity(type="system/type", data={"name": "primitive/any"})


def type_primitive_null() -> Entity:
    """V6.0 primitive type: null (distinct from absent per spec §2.4)."""
    return Entity(type="system/type", data={"name": "primitive/null"})


def type_system_hash() -> Entity:
    """V6.0 type for system/hash (structured primitive with layout).

    Hash is a structured type that extends bytes with a specific layout:
    - format_code: 1-byte algorithm identifier
    - digest: Variable-length hash bytes

    Per TYPE-SYSTEM spec §4.5. Constraints moved to EXTENSION-TYPE.md.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/hash",
            "extends": "primitive/bytes",
            "fields": {
                "format_code": {
                    "type_ref": "primitive/uint",
                    "byte_size": 1,
                },
                "digest": {
                    "type_ref": "primitive/bytes",
                },
            },
            "layout": ["format_code", "digest"],
        },
    )


def type_system_tree_path() -> Entity:
    """V7.7 semantic type for tree paths.

    Per IMPLEMENTATION-SPEC §3.1 - one of the 14 bootstrap types.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/tree/path",
            "extends": "primitive/string",
        },
    )


def type_system_type_name() -> Entity:
    """V7.7 semantic type for type names.

    Per IMPLEMENTATION-SPEC §3.1 - one of the 14 bootstrap types.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/name",
            "extends": "primitive/string",
        },
    )


def type_system_peer_id() -> Entity:
    """V7 semantic type for peer identifiers (system/peer-id per PR-1).

    Per IMPLEMENTATION-SPEC §3.1 - one of the 14 bootstrap types. Renamed
    from `system/identity/peer-id` so the V7 peer namespace is structural.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer-id",
            "extends": "primitive/string",
        },
    )


def type_system_deletion_marker() -> Entity:
    """V7 ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §4.9 — canonical deletion marker.

    Zero-field entity used by EXTENSION-REVISION (and any future
    extension that needs an explicit deletion signal in a content-
    addressed structure) to record intentional path deletion in a
    version's trie. Registered as a core type alongside `system/hash`,
    `system/tree/path`, `system/type/name`, and `system/peer-id` — NOT
    owned by EXTENSION-REVISION; deletion semantics are generic.

    Canonical encoding (normative): the `data` field is the CBOR empty
    map (`0xa0`), per ECF's standard treatment of zero-field types — NOT
    a CBOR empty byte string (`0x40`) and NOT CBOR null (`0xf6`).
    Canonical hash:
    `ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6`.
    Verified at module import time below.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/deletion-marker",
            "fields": {},
        },
    )


def type_system_type_field_spec() -> Entity:
    """V6.0 meta-type for field specifications.

    Per TYPE-SYSTEM spec §4.2:
    Exactly one of: type_ref, array_of, map_of, union_of, type_param
    Modifiers: optional, default, key_type, type_args, byte_size
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/field-spec",
            "fields": {
                "type_ref": {"type_ref": "system/type/name", "optional": True},
                "optional": {"type_ref": "primitive/bool", "optional": True},
                "array_of": {"type_ref": "system/type/field-spec", "optional": True},
                "map_of": {"type_ref": "system/type/field-spec", "optional": True},
                "union_of": {"array_of": {"type_ref": "system/type/field-spec"}, "optional": True},
                "type_param": {"type_ref": "primitive/string", "optional": True},
                "type_args": {"map_of": {"type_ref": "system/type/name"}, "optional": True},
                "default": {"type_ref": "primitive/any", "optional": True},
                "key_type": {"type_ref": "system/type/name", "optional": True},
                "byte_size": {"type_ref": "primitive/uint", "optional": True},
                # EXTENSION-TYPE §2 / §1.2 — the open `constraints` field:
                # an ordered list of constraint entities ({type, data}) the
                # TYPE extension dispatches to constraint handlers. Core
                # §4.2 leaves it undeclared (open-type-preserved); declaring
                # it optional here (Python ships EXTENSION-TYPE) converges the
                # published field-spec type def cross-impl.
                "constraints": {"array_of": {"type_ref": "core/entity"}, "optional": True},
            },
        },
    )


# -----------------------------------------------------------------------------
# EXTENSION-CONTENT v3.5 — content type definitions (§2.1, §2.2, §2.4) +
# system content handler op envelopes (§6.2, §6.3).
#
# Wire-shape discipline per ENTITY-NATIVE-TYPE-SYSTEM §2.8: `array_of` over
# `system/hash` emits flat byte strings (system/hash is named-but-primitive),
# NOT envelope-wrapped {type, data}. The `chunks` list on a blob, the `found`
# / `missing` / `hashes` lists on the op envelopes — all flat.
# -----------------------------------------------------------------------------


def type_system_content_blob() -> Entity:
    """`system/content/blob` — the chunk-list manifest (§2.1).

    `total_size` is the raw byte count; `chunk_size` is the nominal target
    (exact for fixed-size, target for FastCDC); `chunking` identifies a
    complete deterministic configuration (0 = fixed-size, 1 = FastCDC/NC2,
    2..255 reserved, 256+ custom); `chunks` is the ordered list of chunk
    entity hashes — covered by the blob's own entity hash.

    The blob carries NO semantic metadata (content type, filename, etc.) —
    those belong on the referencing entity (§5.1) or, for the public /
    hash-addressable case, on a separately-published `system/content/descriptor`
    (§2.4 + §5.3). This preserves the dedup invariant: same content + same
    `(chunking, chunk_size)` → same blob entity hash, regardless of producer.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/content/blob",
            "fields": {
                "total_size": {"type_ref": "primitive/uint"},
                "chunk_size": {"type_ref": "primitive/uint"},
                "chunking": {"type_ref": "primitive/uint"},
                "chunks": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


def type_system_content_chunk() -> Entity:
    """`system/content/chunk` — a single chunk payload (§2.2).

    Carries raw binary bytes only. No sequence number, no parent ref, no
    metadata — two chunks with byte-equal payload produce the same entity
    hash, enabling cross-blob and cross-peer deduplication.

    Compression is forbidden at the chunk layer (§2.3) — wire compression
    and storage compression layer below the content-addressing boundary so
    chunk entity hashes remain stable across peers.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/content/chunk",
            "fields": {
                "payload": {"type_ref": "primitive/bytes"},
            },
        },
    )


def type_system_content_descriptor() -> Entity:
    """`system/content/descriptor` — consumption-format declaration (§2.4).

    A descriptor is a statement that "this blob can be consumed as X" —
    not an authoritative claim about what the blob is. The same blob may
    have multiple valid descriptors (a PDF blob as `application/pdf`,
    `text/plain`, `image/png`-thumbnail, …) published by one or many peers.

    Presence rule: at least one of `media_type` or `type_ref` MUST be
    present. Both MAY be present.

    Bound at `/{publisher}/system/content/descriptor/{B_hex}/{D_hex}` per
    the §5.3 invariant-pointer convention; consumers MUST verify
    `descriptor.data.content == B` before honoring (§5.3 MUST).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/content/descriptor",
            "fields": {
                "content": {"type_ref": "system/hash"},
                "media_type": {"type_ref": "primitive/string", "optional": True},
                "type_ref": {"type_ref": "system/hash", "optional": True},
                "name": {"type_ref": "primitive/string", "optional": True},
                "metadata": {"type_ref": "primitive/any", "optional": True},
            },
        },
    )


def type_system_content_get_request() -> Entity:
    """`system/content/get-request` — params for `system/content:get` (§6.2).

    Hashes are flat byte strings per §2.8 (system/hash is a named-but-primitive
    type). The op identifies its namespace via the EXECUTE's `resource` field;
    a `get` without `resource` MUST return `path_required` (§6.2, v3.5
    behavior change from v3.4).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/content/get-request",
            "fields": {
                "hashes": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


def type_system_content_content_response() -> Entity:
    """`system/content/content-response` — result of `system/content:get`
    and of any handler's `get-request` op (§6.2, §4.2).

    `found` lists hashes successfully resolved (their entities arrive in
    the envelope's `included` map); `missing` lists hashes not present.
    Implementations MAY move resolved-but-too-large entities to `missing`
    to fit the transport frame; receivers retry the missing set.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/content/content-response",
            "fields": {
                "found": {"array_of": {"type_ref": "system/hash"}},
                "missing": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


def type_system_content_ingest_request() -> Entity:
    """`system/content/ingest-request` — params for `system/content:ingest`
    (§6.3).

    Two input modes. Envelope mode (`envelope` set): stores root + all
    included entities; each included entry's content hash MUST be
    recomputed against its key. Entity mode (`entity` set): stores a
    single entity. Exactly one of `envelope` / `entity` MUST be present
    — ambiguous and missing inputs are 400 errors.

    The op identifies its namespace via the EXECUTE's `resource` field;
    an `ingest` without `resource` MUST return `path_required` (§6.3,
    v3.5 behavior change from v3.4). The hashes inside the payload are
    operation data; the namespace path is the cap-scope resource.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/content/ingest-request",
            "fields": {
                "envelope": {"type_ref": "system/envelope", "optional": True},
                "entity": {"type_ref": "core/entity", "optional": True},
            },
        },
    )


def type_system_content_ingest_result() -> Entity:
    """`system/content/ingest-result` — result of `system/content:ingest`
    (§6.3).

    `root_hash` is the content hash of the stored root (envelope mode) or
    the single entity (entity mode); `ingested_count` reports the number
    of entities written.

    In envelope mode with a non-null `envelope.root`, the result MUST
    include `root` — the original `envelope.root` entity inlined as a
    value (§11.1 MUST). This enables downstream chain steps to navigate
    into the wrapper's fields (e.g., `extract: "data.root.data.head"`)
    without dereferencing the content store. In entity mode the wrapper
    has no envelope-level root, so `root` is absent.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/content/ingest-result",
            "fields": {
                "root": {"type_ref": "core/entity", "optional": True},
                # F-CIMP-1 generalization: `root_hash` is
                # absent in bundle-only ingest results (no envelope.root).
                # Parallels `root` (optional per §11.1) — both fields refer
                # to the same anchor, and both are omitted together when
                # the envelope is included-only.
                "root_hash": {"type_ref": "system/hash", "optional": True},
                "ingested_count": {"type_ref": "primitive/uint"},
            },
        },
    )


# =============================================================================
# Storage-Substitute Extension Types
#   (EXTENSION-STORAGE-SUBSTITUTE-SOURCES + EXTENSION-STORAGE-SUBSTITUTE-HTTP)
# =============================================================================
#
# Renamed from CONTENT-SUBSTITUTE per RULINGS-STORAGE-SUBSTITUTE-CROSS-IMPL
# §3: the extension substitutes the whole storage layer (tree +
# content) via the two-prefix profile, not just content. Wire namespace stays
# `system/substitute/*` (already converged across all three impls).
#
# Read-path substrate for the CDN corridor v1. The chain consult is exposed
# as an SDK primitive — `consult_substitute_chain(ctx, hash, source_peer_id)`
# — invoked by dispatcher/SDK code that holds the claimed source peer locally
# (Ruling 4: source_peer_id is local context, NOT a wire field on
# `system/content:get-request`). v1.0 ships bare-hash + the `http` backend;
# manifest signature processing + freshness gate land all-at-once in v1.1
# (Ruling 5). Mechanism A throughout — no BRIDGE-HTTP, no `bridge-http-fetch`
# cap. See: PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-SOURCES.md,
# PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-HTTP.md.


def type_system_peer_transport_tcp() -> Entity:
    """`system/peer/transport/tcp` — TCP live transport profile (§6.5.2a).

    Per EXTENSION-NETWORK §6.5 (v1.4 Amendment 2) + PROPOSAL-EXTENSION-
    NETWORK-TRANSPORT-FAMILY §4.1. The default live transport for all
    three impls; published as a discoverable profile so peers can resolve
    each other's transport endpoint.

    Fields (all required per §6.5):
      - peer_id:         the peer this profile is for
      - transport_type:  the literal string "tcp"
      - endpoint:        {url: "tcp://host:port"} per D-14
      - supported_ops:   ["EXECUTE"] (D-13; live profiles advertise EXECUTE)
      - freshness:       "live" (connection-liveness model)
      - nonce_required:  true (live transports require nonce per V7)
      - cap_flow:        "both" (request and response carry capability)
      - advertised_at:   monotonic publication timestamp (ms since epoch)

    Path: this entity is stored at `system/peer/transport/{peer_id}` in
    the tree (one primary profile per peer in v1; multi-profile peers
    introduce a per-transport-type path segment as a forward extension).

    Migration: this entity REPLACES the legacy flat
    `{peer_id, address}` shape on the same path. Per
    `[[feedback_no_legacy_code]]`, the legacy shape is not accepted.
    Cohort-coordinated cutover per CROSS-IMPL-HANDOFF-TRANSPORT-FAMILY
    Chunk C.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer/transport/tcp",
            "fields": {
                # F1 (NETWORK errata bdfb545): the transport-profile peer_id
                # is the Base58 id string at the `{peer_id}` path segment —
                # the semantic `system/peer-id` type, not a content hash.
                # §6.5.1:720 `Hash` was a transcription typo. Was system/hash.
                "peer_id": {"type_ref": "system/peer-id"},
                "transport_type": {"type_ref": "primitive/string"},
                "endpoint": {
                    "fields": {
                        "url": {"type_ref": "primitive/string"},
                    },
                },
                "supported_ops": {"array_of": {"type_ref": "primitive/string"}},
                "freshness": {"type_ref": "primitive/string"},
                "nonce_required": {"type_ref": "primitive/bool"},
                "cap_flow": {"type_ref": "primitive/string"},
                "advertised_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_peer_transport_http() -> Entity:
    """`system/peer/transport/http` — live HTTP transport profile (§6.5.2c).

    Per EXTENSION-NETWORK §6.5 (v1.4 Amendment 2) + Chunk D (the browser
    linchpin). EXECUTE / EXECUTE-RESPONSE carried over HTTP POST: the
    POST body is a CBOR-encoded EXECUTE envelope, the response body is a
    CBOR-encoded EXECUTE-RESPONSE envelope. POST-only — nothing in the
    protocol is idempotent so there is no GET sub-mode. Half-duplex —
    connector-driven, no server-push in v1 (subscribe needs a duplex
    transport: `tcp`/`websocket`). A **wrapper, NOT BRIDGE-HTTP**: the
    bytes on the wire ARE entity envelopes (Mechanism A), not foreign
    content.

    Fields (all required per §6.5; identical shape to `tcp` per D4 —
    single shared `endpoint:{url}`):
      - peer_id:         the peer this profile is for
      - transport_type:  the literal string "http"
      - endpoint:        {url: "https://host/path"} per D-14 (or "http://"
                         for dev/cleartext)
      - supported_ops:   ["EXECUTE"] (D-13)
      - freshness:       "live"
      - nonce_required:  true
      - cap_flow:        "both"
      - advertised_at:   monotonic publication timestamp (ms since epoch)

    Path: this entity is stored at
    `system/peer/transport/{peer_id}/{profile-id}` (D1), parallel to the
    `tcp` profile. A peer MAY publish both a `tcp` and an `http` profile;
    the consumer selects per D1 (primary-first then lex) within each
    transport_type.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer/transport/http",
            "fields": {
                # F1 (NETWORK errata bdfb545): transport-profile peer_id is
                # the Base58 id string → system/peer-id. Was system/hash.
                "peer_id": {"type_ref": "system/peer-id"},
                "transport_type": {"type_ref": "primitive/string"},
                "endpoint": {
                    "fields": {
                        "url": {"type_ref": "primitive/string"},
                    },
                },
                "supported_ops": {"array_of": {"type_ref": "primitive/string"}},
                "freshness": {"type_ref": "primitive/string"},
                "nonce_required": {"type_ref": "primitive/bool"},
                "cap_flow": {"type_ref": "primitive/string"},
                "advertised_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_peer_transport_http_poll() -> Entity:
    """`system/peer/transport/http-poll` — serving-mode profile (Chunk E).

    Per EXTENSION-NETWORK §6.5.3 + the arch serving-mode content-scope
    ruling + cohort
    CHUNK-E-IMPL-PLAN §5 E.2. The poll route is the public-HTTP, GET-only,
    uncapability-gated cousin of `system/peer/transport/http`. It carries
    content-by-hash and tree-get requests for browsers, `curl`, CDN edges
    — non-protocol-speakers who can't present caps. Hash-knowledge IS the
    read authority (arch §1.1 Axis 1); the serving scope predicate is the
    lever (arch §1.2 Axis 2 — default content-namespace).

    Fields (per §6.5.3 + cross-impl matrix F3):
      - peer_id (system/peer-id — the Base58 id string, NETWORK errata
        bdfb545), transport_type ("http-poll"),
      - endpoint: the rich `system/substitute/endpoint` (prefix-based CDN
        shape: tree_url_prefix / content_url_prefix / content_layout /
        tree_leaf_suffix) — NOT the single-`{url}` shape the live `http`/`tcp`
        profiles carry. For a LIVE serving peer the prefixes point at its own
        GET routes (see `Peer._publish_http_poll_profile`).
      - supported_ops (CONTENT_GET + TREE_GET; MANIFEST_GET reserved when
        EXTENSION-MANIFEST §4 lands), nonce_required false,
      - freshness / cap_flow / advertised_at / poll_interval_ms? /
        signed_pointer? / priority? — all OPTIONAL (Go omitempty + Amdt 8).
        A live-serving peer emits freshness "live" / cap_flow "none"; the
        canonical value-set vs Go's static-CDN "static-immutable+signed-
        pointer" / "egress" is the open F3 question routed to arch.

    Path: `system/peer/transport/{peer_id}/{profile-id}` (D1) — e.g.
    `primary-http-poll`. A peer publishing both an `http` and an
    `http-poll` profile under distinct profile-ids is the standard
    Posture-1 (isolated port) deployment.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer/transport/http-poll",
            "fields": {
                # F1 (NETWORK errata bdfb545): transport-profile peer_id is
                # the Base58 id string → system/peer-id. Was system/hash.
                "peer_id": {"type_ref": "system/peer-id"},
                "transport_type": {"type_ref": "primitive/string"},
                # F3 (cross-impl matrix): §6.5.3 + Go model the
                # http-poll endpoint as the rich `system/substitute/endpoint`
                # (the prefix-based CDN shape: tree_url_prefix /
                # content_url_prefix / content_layout / tree_leaf_suffix) —
                # NOT the single-`{url}` shape the live `http`/`tcp` profiles
                # carry. Was an inline `{url}` copied from the `http` profile.
                "endpoint": {"type_ref": "system/substitute/endpoint"},
                "supported_ops": {"array_of": {"type_ref": "primitive/string"}},
                # freshness / cap_flow / advertised_at are optional per Go's
                # omitempty + Amendment 8 (informational, not selection keys);
                # poll_interval_ms / signed_pointer (static-CDN signalling) and
                # priority? (Amdt 8 Q1 DNS-SRV semantics) are OPTIONAL fields
                # Go's reference carries — added here so the §6.5.3 http-poll
                # type-def is byte-identical across impls (cross-impl matrix F3).
                "freshness": {"type_ref": "primitive/string", "optional": True},
                "nonce_required": {"type_ref": "primitive/bool"},
                "cap_flow": {"type_ref": "primitive/string", "optional": True},
                "poll_interval_ms": {"type_ref": "primitive/uint", "optional": True},
                "signed_pointer": {"type_ref": "primitive/string", "optional": True},
                "advertised_at": {"type_ref": "primitive/uint", "optional": True},
                "priority": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_peer_published_root() -> Entity:
    """`system/peer/published-root` — signed tree-root anchor (Phase P / C1).

    Per `PROPOSAL-PEER-MANIFEST-STATIC-HANDSHAKE.md` §4 (NORMATIVE-LOCKED).
    The mutable-claim anchor a static http-poll consumer
    verifies before walking the tree (§1.1 threat model — never trust raw
    host bytes). Signature carried out-of-band as a `system/signature`
    entity at the invariant pointer `system/signature/{hex(pr_hash)}`
    (V7 §5.2 / §989 refless target-matching — NOT a `refs:` block).

    `peer_id` is the **Base58 peer-id string** (`system/peer-id`), NOT a
    `system/hash`: §4 spells it `<hash>` but that notation predates the
    V7 §1.5 peer-id pin and the NETWORK errata bdfb545 (which moved
    transport-profile `peer_id` to Base58) + REGISTRY F-PY-REG-5. The
    Base58 form is also what lets the consumer derive the publisher pubkey
    locally for verification. Flagged to the cohort for Go P1 convergence.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer/published-root",
            "fields": {
                "peer_id": {"type_ref": "system/peer-id"},
                "root_hash": {"type_ref": "system/hash"},
                "seq": {"type_ref": "primitive/uint"},
                "published_at": {"type_ref": "primitive/uint"},
                "predecessor": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_peer_session() -> Entity:
    """`system/peer/session/{peer_id}` — per-peer authenticated session entity.

    Per PROPOSAL-TRANSPORT-FAMILY R6 §9.3 minimal schema (arch ruling,
    commit ``523cdc5``). Implements §6.1 literally — "sessions
    are identified by `peer_id` and persist in the entity tree … held
    capability tokens." The unifying frame for R3b (one cap per peer),
    reconnect-survives-disconnect, and inspectability.

    Path: `system/peer/session/{remote_peer_id}` (one session per remote
    peer; no self-session per §9.1 R6-f).

    Purpose (the principle that decides the schema — §9.0): the session
    entity is the **durable per-peer AUTH record**. It answers exactly
    one question for §10 dispatch — *"do I already hold a valid capability
    to talk to this peer, or must I re-handshake?"* It is NOT the
    liveness/reachability/lifecycle record (those live on
    `system/peer/status`, `system/connection`, and `system/peer/transport/*`
    per the 4-entity boundary §7.1 #3). Fields that are really liveness or
    lifecycle do NOT belong here — they would duplicate other entities.

    Fields (§9.3):
      - remote_peer_id:       base58 PeerId of the remote peer (also in path)
      - remote_identity_hash: 33-byte content hash of remote's `system/peer`
      - remote_public_key:    OPTIONAL denormalization (§9.2 R6-g). pubkey
                              isn't trivially derivable from peer_id (which
                              is a hash of it); 32 bytes for
                              inspectability / sig-verify-without-fetch is
                              cheap. Peers MAY omit and deref
                              `remote_identity_hash`.
      - held_capability:      {hash, chain} — the cap *remote* granted me;
                              dispatch reads this to authenticate outbound
                              (§9.1 R6-a). chain is array_of system/hash,
                              leaf→root, length ≥ 1 (§9.1 R6-d).
      - minted_capability:    OPTIONAL {hash, chain} — the cap *I* minted
                              for remote, R3a idempotency / revocation
                              anchor (granter-side). In a bidirectional
                              pair A↔B, A's `minted_capability` for B *is
                              the same cap* as B's `held_capability` from
                              A. NOT a back-delivery cap (§7.1 #2 + §9.1
                              R6-a reconciliation) — back-delivery auth is
                              still `deliver_token`.
      - granted_at:           epoch ms — last handshake timestamp.
      - expires_at:           OPTIONAL epoch ms — validity window. Absence
                              = no expiry (matches connection cap default).

    DROPPED from the §7.2 strawman:
      - `status` (§9.1 R6-c): lifecycle is `system/peer/status`'s job;
        cap validity is derivable from `expires_at`.
      - `last_active` (§9.1 R6-b): liveness, not auth. Duplicates
        `system/peer/status.last_seen` and forces a tree write per message
        (subscription/revision fan-out). "Last handshake" is `granted_at`.

    Grants-change rule (§9.1 R6-e): when configured grants change at
    runtime, mint fresh + overwrite the session entity in place. One
    entity per peer, mutable.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer/session",
            "fields": {
                "remote_peer_id": {"type_ref": "system/peer-id"},
                "remote_identity_hash": {"type_ref": "system/hash"},
                "remote_public_key": {"type_ref": "primitive/bytes", "optional": True},
                "held_capability": {
                    "fields": {
                        "hash": {"type_ref": "system/hash"},
                        "chain": {"array_of": {"type_ref": "system/hash"}},
                    },
                },
                "minted_capability": {
                    "optional": True,
                    "fields": {
                        "hash": {"type_ref": "system/hash"},
                        "chain": {"array_of": {"type_ref": "system/hash"}},
                    },
                },
                "granted_at": {"type_ref": "primitive/uint"},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_substitute_endpoint() -> Entity:
    """`system/substitute/endpoint` — the HTTP convention's endpoint shape.

    The concrete endpoint the `http` substitute convention (§7) expects.
    A `system/substitute/source.endpoint` is now OPAQUE (`primitive/any?`,
    arch ruling Q3) — for `substitute_type = "http"` it carries *this*
    shape, interpreted by the http handler. Also carried (concretely) by
    `system/substitute/snapshot-manifest.endpoint`. Mirrors the
    NETWORK §6.5.3 `http-poll` profile shape. `tree_leaf_suffix` defaults
    to ".bin" per Round-6 #1 — consumers MUST append the suffix literally
    when constructing tree-leaf URLs.

    `content_layout` values are an open enum (Round-6 #2 added
    "sharded-2-flat"; "sharded-2-2" is an alias for "sharded-2-4").
    Per arch ruling (Option α): `{hash_hex}` is the 66-char
    wire form (algorithm byte + digest, V7 §3.5); shard slices come
    from that same string. SHA-256 entities land in `/00/...` (the
    algorithm partition); SHA-384 would land in `/01/`, SHA-512 in
    `/02/` — free crypto-agility.
      - "flat":           {content_url_prefix}/{hash_hex}
      - "sharded-2-flat": {content_url_prefix}/{hash_hex[0:2]}/{hash_hex}
      - "sharded-2-4":    {content_url_prefix}/{hash_hex[0:2]}/{hash_hex[2:4]}/{hash_hex}
      - "sharded-2-2":    alias for "sharded-2-4"

    `content_url_prefix` is REQUIRED — arch ruling Q2,
    EXTENSION-SUBSTITUTE §2.2. The two-prefix model (`tree_url_prefix` +
    `content_url_prefix` as *separate* publisher commitments) exists
    precisely so content can be dedup'd cross-peer to a different host than
    the tree (scenario S4). A "derive from tree_url_prefix when absent"
    default silently defeats that case, so there is no default — the
    publisher MUST state it. (The prior `effective_content_url_prefix`
    derivation helper was removed with this ruling.)
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/substitute/endpoint",
            "fields": {
                "tree_url_prefix": {"type_ref": "primitive/string"},
                "content_url_prefix": {"type_ref": "primitive/string"},
                "content_layout": {"type_ref": "primitive/string"},
                "tree_leaf_suffix": {"type_ref": "primitive/string", "optional": True},
                # EXTENSION-NETWORK §6.5.3 Amendment 5 — listing suffix
                # (default ".list", MUST differ from tree_leaf_suffix) and the
                # singular signed-manifest prefix. Both optional/defaulted.
                "tree_listing_suffix": {"type_ref": "primitive/string", "optional": True},
                "manifest_url_prefix": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_substitute_source() -> Entity:
    """`system/substitute/source` — one entry in the substitute chain (§2.1).

    Stored at `system/substitute/sources/{source_hash}`. `refs.signature`
    MUST be signed by `source_peer_id` over the entry's content hash —
    unsigned entries are rejected at consultation time. `priority`
    ascending (lower = first).

    `priority` is `primitive/int` per PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-
    SOURCES §2.1 (`priority: int, ; ascending; lower number = consulted
    first`). This is the substitute-CHAIN priority and is distinct from the
    transport-PROFILE `priority?: uint` of EXTENSION-NETWORK Amendment 8 Q1
    (a different field on a different type). Was `primitive/uint` here —
    a spec divergence the cross-impl matrix (§2.1) surfaced.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/substitute/source",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "substitute_type": {"type_ref": "primitive/string"},
                "source_peer_id": {"type_ref": "system/hash"},
                # OPAQUE (`primitive/any?`) — arch ruling Q3,
                # EXTENSION-SUBSTITUTE §2.1. Each `substitute_type` carries a
                # structurally different endpoint shape, dispatched on
                # `substitute_type` (same pattern as REGISTRY's per-backend
                # `hints`). Pinning it to a single concrete type would
                # foreclose non-HTTP conventions. The HTTP convention's
                # concrete shape is `system/substitute/endpoint` (§2.2),
                # interpreted by the `http` handler.
                "endpoint": {"type_ref": "primitive/any", "optional": True},
                "fetch_template": {"type_ref": "primitive/string", "optional": True},
                "priority": {"type_ref": "primitive/int"},
                "enabled": {"type_ref": "primitive/bool"},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
                "supersedes": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_substitute_snapshot_manifest() -> Entity:
    """`system/substitute/snapshot-manifest` — storage-substitute snapshot.

    Renamed from `system/content/substitute/snapshot-manifest` per
    RULINGS-STORAGE-SUBSTITUTE-CROSS-IMPL §3.2 — the manifest
    is a tree-path index (path → hash) + content, so it's storage-level,
    not content-namespaced.

    Served at `{base_url}/manifest/current`. `seq` is monotonic per
    `source_peer_id`; consumers reject `seq < cached_seq` with
    `manifest_stale_seq` (STORAGE-SUBSTITUTE-HTTP §3-RES.4). `refs.signature`
    MUST be signed by `source_peer_id` for `path_index` trust (§3-RES.1) —
    without sig, bare-hash content fetch still works but `path_index` MUST
    NOT be used.

    **v1.0 conformance:** the manifest path is NOT on the v1.0 default
    fetch path (Ruling 5 — all three impls defer manifest processing to
    v1.1). The type is registered so authoring + verify utilities work,
    but the bare-hash fetch path is the v1.0 mechanism.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/substitute/snapshot-manifest",
            "fields": {
                "source_peer_id": {"type_ref": "system/hash"},
                "snapshot_at": {"type_ref": "primitive/uint"},
                "seq": {"type_ref": "primitive/uint"},
                "endpoint": {"type_ref": "system/substitute/endpoint"},
                "path_index": {"map_of": {"type_ref": "system/hash"}},
                "content_count": {"type_ref": "primitive/uint"},
                "root_hashes": {"array_of": {"type_ref": "system/hash"}},
                "predecessor": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_substitute_try_request() -> Entity:
    """`system/substitute/try-request` — params for `system/substitute/<type>:try`.

    Per RULINGS §2 Ruling 2 + spec STORAGE-SUBSTITUTE-SOURCES §2.3:
    handler signature is `try(entry: system/substitute/source, hash) → bytes`
    — `entry` is the **full** source entity dict, not its hash. The
    consumer already holds the hash; passing the source dict means the
    handler doesn't re-lookup.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/substitute/try-request",
            "fields": {
                # Per RULINGS §2 Ruling 2 + §2.3 (cross-impl matrix F2):
                # `entry` is the FULL `system/substitute/source`
                # entity, so pin it precisely rather than `primitive/any` —
                # lets the type checker validate the entry's own fields and
                # converges with Go (which loosened to core/entity; both
                # adopt the precise token per the ruling).
                "entry": {"type_ref": "system/substitute/source"},
                "hash": {"type_ref": "system/hash"},
            },
        },
    )


# Per RULINGS §2 Ruling 3: the `:try` op returns the raw fetched entity
# directly (or a not_found / error via the standard handler-result
# mechanism). NO `system/substitute/try-result` wrapper — the consumer
# already holds the hash it asked for, so `{entity, hash}` is redundant.
# The earlier wrapper type was unwrapped during the cross-impl
# re-align; do not re-introduce.


def type_system_type_constraint() -> Entity:
    """Umbrella meta-type for constraint entities.

    Carried by NATIVE-TYPE-SYSTEM as the abstract `{type, data}` shape
    of a constraint entity. Concrete constraint types own their own
    `data` schema and live under `system/type/constraint/{kind}` —
    see the 11 standard constraint types below (EXTENSION-TYPE v1.1
    §4) and any custom constraint types registered by user handlers
    (§2.2).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint",
            "fields": {
                "type_pattern": {"type_ref": "primitive/string", "optional": True},
                "one_of": {"array_of": {"type_ref": "primitive/string"}, "optional": True},
                "min": {"type_ref": "primitive/int", "optional": True},
                "max": {"type_ref": "primitive/int", "optional": True},
                "pattern": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


# -----------------------------------------------------------------------------
# EXTENSION-TYPE v1.1 — standard constraint entity types (§4)
#
# Each is its own `system/type` definition; the constraint handler at pattern
# `system/type/constraint/*` dispatches on the constraint entity's `type`
# field per §2.2. Per §1.1 owned-namespaces, EXTENSION-TYPE owns the
# `system/type/constraint/` prefix.
# -----------------------------------------------------------------------------


def type_system_type_constraint_min() -> Entity:
    """`system/type/constraint/min` — numeric lower bound (inclusive).

    Per EXTENSION-TYPE v1.1 §4.1. Applies to numeric primitives;
    NaN comparisons return false.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/min",
            "fields": {
                "min": {"type_ref": "primitive/float"},
            },
        },
    )


def type_system_type_constraint_max() -> Entity:
    """`system/type/constraint/max` — numeric upper bound (inclusive).

    Per EXTENSION-TYPE v1.1 §4.1.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/max",
            "fields": {
                "max": {"type_ref": "primitive/float"},
            },
        },
    )


def type_system_type_constraint_min_length() -> Entity:
    """`system/type/constraint/min-length` — min length for strings/bytes.

    Per EXTENSION-TYPE v1.1 §4.2. Codepoints for strings; bytes for
    `primitive/bytes`.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/min-length",
            "fields": {
                "min_length": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_type_constraint_max_length() -> Entity:
    """`system/type/constraint/max-length` — max length for strings/bytes.

    Per EXTENSION-TYPE v1.1 §4.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/max-length",
            "fields": {
                "max_length": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_type_constraint_min_count() -> Entity:
    """`system/type/constraint/min-count` — min element count for array/map.

    Per EXTENSION-TYPE v1.1 §4.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/min-count",
            "fields": {
                "min_count": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_type_constraint_max_count() -> Entity:
    """`system/type/constraint/max-count` — max element count for array/map.

    Per EXTENSION-TYPE v1.1 §4.2.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/max-count",
            "fields": {
                "max_count": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_type_constraint_pattern() -> Entity:
    """`system/type/constraint/pattern` — RE2 full-match on string values.

    Per EXTENSION-TYPE v1.1 §4.3. Implementations MUST use a
    linear-time regex engine (RE2 or equivalent); backtracking
    engines are not conformant.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/pattern",
            "fields": {
                "pattern": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_type_constraint_one_of() -> Entity:
    """`system/type/constraint/one-of` — enumeration of allowed values.

    Per EXTENSION-TYPE v1.1 §4.4. **ECF byte equality** — the
    load-bearing cross-impl interop gate per §5.5 normative.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/one-of",
            "fields": {
                "values": {"array_of": {"type_ref": "primitive/any"}},
            },
        },
    )


def type_system_type_constraint_not_one_of() -> Entity:
    """`system/type/constraint/not-one-of` — enumeration of disallowed values.

    Per EXTENSION-TYPE v1.1 §4.4. Uses the same ECF byte equality
    as `one_of`; the §5.5 normative requirement applies.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/not-one-of",
            "fields": {
                "values": {"array_of": {"type_ref": "primitive/any"}},
            },
        },
    )


def type_system_type_constraint_format() -> Entity:
    """`system/type/constraint/format` — named format validation on strings.

    Per EXTENSION-TYPE v1.1 §4.5. Implementations MUST recognize
    `uri`, `date-time`, `date`, `uuid`, `base58`, `re2`. Unknown
    format names fail closed.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/format",
            "fields": {
                "format": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_type_constraint_type_pattern() -> Entity:
    """`system/type/constraint/type-pattern` — typed-reference type glob.

    Per EXTENSION-TYPE v1.1 §4.6. Applies to `system/hash` and
    `system/tree/path` fields; validates the referenced entity's
    `type` field matches the glob pattern. Resolution failure
    SHOULD pass with a warning.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/type-pattern",
            "fields": {
                "pattern": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_type_constraint_validate_request() -> Entity:
    """`system/type/constraint/validate-request` — constraint handler input.

    Per EXTENSION-TYPE v1.1 §5.2. Sent to a constraint handler when
    the type handler's validate op dispatches a single constraint
    check; `constraint_type` is the dispatch path (matched against
    the handler pattern `system/type/constraint/*` for standard
    constraints).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/validate-request",
            "fields": {
                "value": {"type_ref": "primitive/any"},
                "constraint_type": {"type_ref": "system/type/name"},
                "constraint_data": {"type_ref": "primitive/any"},
            },
        },
    )


def type_system_type_constraint_validate_result() -> Entity:
    """`system/type/constraint/validate-result` — constraint handler output.

    Per EXTENSION-TYPE v1.1 §5.3. `reason` is absent when `valid`
    is true.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/type/constraint/validate-result",
            "fields": {
                "valid": {"type_ref": "primitive/bool"},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


# =============================================================================
# EXTENSION-REGISTRY v1.0 — registry substrate + local-name backend
# (name → (peer_id, transports, attestations, trust_anchor, ttl))
# =============================================================================


def type_system_registry_binding() -> Entity:
    """`system/registry/binding` — the binding entity (EXTENSION-REGISTRY §3).

    `target_peer_id` is a Base58 peer-id per V7 §1.5 (NOT a content-hash;
    §3 alignment pin / F-PY-REG-5). Bare-hash fields (`supersedes`,
    `issuer_attestation`) are bare `system/hash` (33 bytes), never wrapped
    (§3 conformance). Non-self-certifying / non-local-name bindings carry an
    `issuer_signature` `system/signature` entity by target-matching +
    invariant pointer `system/signature/{hex(binding_hash)}` — NOT a
    `refs:` block (V7 §5.2 / §989 refless contract).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/binding",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "kind": {"type_ref": "primitive/string"},
                "target_peer_id": {"type_ref": "system/peer-id"},
                "transports": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "issued_at": {"type_ref": "primitive/uint"},
                "ttl": {"type_ref": "primitive/uint", "optional": True},
                "supersedes": {"type_ref": "system/hash", "optional": True},
                "issuer_attestation": {"type_ref": "system/hash", "optional": True},
                "metadata": {
                    "map_of": {"type_ref": "primitive/any"}, "optional": True,
                },
            },
        },
    )


def type_system_registry_revocation() -> Entity:
    """`system/registry/revocation` — revocation entity (§3.1).

    `revokes` is a bare `system/hash` of the revoked binding. The
    authenticating signature is carried per the same target-matching +
    invariant-pointer contract as bindings.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/revocation",
            "fields": {
                "revokes": {"type_ref": "system/hash"},
                "revoked_at": {"type_ref": "primitive/uint"},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_registry_resolver_chain_entry() -> Entity:
    """`system/registry/resolver-chain-entry` — one backend in the chain (§4).

    `backend_id` is REQUIRED (arch ruling Q1): it is both the
    dispatch key and the trust anchor (which signer the receiver verifies
    bindings against), so an entry without one cannot be dispatched or
    trust-checked. For the local-name single-store case (§6.2) it defaults
    to the local peer's identity — filled at config-load time
    (`registry._load_resolver_config`), not left optional on the wire.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/resolver-chain-entry",
            "fields": {
                "backend_kind": {"type_ref": "primitive/string"},
                "backend_id": {"type_ref": "primitive/string"},
                "priority": {"type_ref": "primitive/uint"},
                "accepted_trust_anchors": {
                    "array_of": {"type_ref": "primitive/string"}, "optional": True,
                },
                "hints": {
                    "map_of": {"type_ref": "primitive/any"}, "optional": True,
                },
            },
        },
    )


def type_system_registry_pinned_binding() -> Entity:
    """`system/registry/pinned-entry` — a pin entry in resolver-config (§4).

    Wire name `pinned-entry` per the V8 cohort-canonical registry naming
    (Go `DispatchEntry`/`PinnedEntry` reflection; spec §4 path style). Field
    function kept as `..._pinned_binding` for stable import; wire name is
    what crosses the cohort boundary.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/pinned-entry",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "target_peer_id": {"type_ref": "system/peer-id"},
                "reason": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_registry_name_format_dispatch() -> Entity:
    """`system/registry/dispatch-entry` — meta-resolver routing (§4).

    Wire name `dispatch-entry` per the V8 cohort-canonical registry naming
    (Go `DispatchEntry`). The `resolver-config.name_format_dispatch` FIELD
    key keeps its snake spelling (data key, not a path); only the referenced
    element TYPE path is `dispatch-entry`.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/dispatch-entry",
            "fields": {
                "pattern": {"type_ref": "primitive/string"},
                "backend_kinds": {"array_of": {"type_ref": "primitive/string"}},
            },
        },
    )


def type_system_registry_resolver_config() -> Entity:
    """`system/registry/resolver-config` — deployment config (§4).

    Peer-local; not synced. Pinned bindings override everything;
    `name_format_dispatch` narrows the chain by name format (the primary
    privacy mechanism, §4.1 step 2); the chain is consulted in ascending
    `priority` order (lower = first), returning the first validated hit
    (§4.1.1).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/resolver-config",
            "fields": {
                "resolver_chain": {
                    "array_of": {"type_ref": "system/registry/resolver-chain-entry"},
                },
                "pinned_bindings": {
                    "array_of": {"type_ref": "system/registry/pinned-entry"},
                    "optional": True,
                },
                "name_format_dispatch": {
                    "array_of": {"type_ref": "system/registry/dispatch-entry"},
                    "optional": True,
                },
                "log_cache_hits": {"type_ref": "primitive/bool", "optional": True},
                "resolution_log_capacity": {
                    "type_ref": "primitive/uint", "optional": True,
                },
            },
        },
    )


def type_system_registry_local_name_config() -> Entity:
    """`system/registry/local-name-config` — local-name-store config (§6.4)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name-config",
            "fields": {
                "default_pinned": {"type_ref": "primitive/bool"},
                "allow_supersede": {"type_ref": "primitive/bool"},
                "case_normalization": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_registry_resolution_result() -> Entity:
    """`system/registry/resolution-result` — the ResolutionResult (§2.1).

    All durations / timestamps are ms-since-epoch (signed int64), aligned
    with V7 cap-expiry convention.

    `backend_id` stays OPTIONAL here (advertised): a `chain_exhausted`
    result has no answering backend, so the field is omitted in that case.
    This matches the Go-ref reflection shape (`cbor:"backend_id,omitempty"`
    → optional) — the Q1 REQUIRED ruling is the resolver-CHAIN-entry config
    field, where it is the dispatch key and always present.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/resolution-result",
            "fields": {
                "status": {"type_ref": "primitive/string"},
                "binding": {"type_ref": "system/hash", "optional": True},
                "peer_id": {"type_ref": "system/peer-id", "optional": True},
                "transports": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "attestations": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "trust_anchor": {"type_ref": "primitive/string", "optional": True},
                "ttl": {"type_ref": "primitive/uint", "optional": True},
                "neg_ttl": {"type_ref": "primitive/uint", "optional": True},
                "backend_id": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_registry_resolution_log() -> Entity:
    """`system/registry/resolution-log` — inspectability log entry (§11.2 SHOULD)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/resolution-log",
            "fields": {
                "seq": {"type_ref": "primitive/uint"},
                "name": {"type_ref": "primitive/string"},
                "backend_id": {"type_ref": "primitive/string", "optional": True},
                "status": {"type_ref": "primitive/string"},
                "reason": {"type_ref": "primitive/string", "optional": True},
                "binding": {"type_ref": "system/hash", "optional": True},
                "attempted_at": {"type_ref": "primitive/uint"},
                "is_fallback_reresolve": {"type_ref": "primitive/bool", "optional": True},
            },
        },
    )


def type_system_registry_local_name_entry() -> Entity:
    """`system/registry/local-name/list-entry` — one row in a `:list` result (§6.5)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name/list-entry",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "hash": {"type_ref": "system/hash"},
                "target_peer_id": {"type_ref": "system/peer-id"},
                "notes": {"type_ref": "primitive/string", "optional": True},
                "pinned": {"type_ref": "primitive/bool"},
            },
        },
    )


def type_system_registry_local_name_list_result() -> Entity:
    """`system/registry/local-name/list-result` — `:list` op output (§6.5)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name/list-result",
            "fields": {
                "entries": {
                    "array_of": {"type_ref": "system/registry/local-name/list-entry"},
                },
            },
        },
    )


def type_system_registry_local_name_list_request() -> Entity:
    """`system/registry/local-name/list-request` — `:list` op input (§6.5).

    Optional opaque `filter` map (backend-MAY-ignore), mirroring Go's
    `LocalNameListRequestData{Filter map[string]cbor.RawMessage}`.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name/list-request",
            "fields": {
                "filter": {
                    "map_of": {"type_ref": "primitive/any"}, "optional": True,
                },
            },
        },
    )


def type_system_registry_bind_result() -> Entity:
    """`system/registry/local-name/bind-result` — `:bind` / `:update-transports` output."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name/bind-result",
            "fields": {
                "binding_hash": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_registry_resolve_request() -> Entity:
    """`system/registry/resolve-request` — `:resolve` op input (§2.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/resolve-request",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "hints": {
                    "map_of": {"type_ref": "primitive/any"}, "optional": True,
                },
            },
        },
    )


def type_system_registry_invalidate_cache_request() -> Entity:
    """`system/registry/invalidate-cache-request` — `:invalidate-cache` (§2.1)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/invalidate-cache-request",
            "fields": {
                "name": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_registry_local_name_bind_request() -> Entity:
    """`system/registry/local-name/bind-request` — `:bind` op input (§6.5)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name/bind-request",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "target_peer_id": {"type_ref": "system/peer-id"},
                "transports": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "notes": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_registry_local_name_unbind_request() -> Entity:
    """`system/registry/local-name/unbind-request` — `:unbind` op input (§6.5)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name/unbind-request",
            "fields": {
                "name": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_registry_local_name_update_transports_request() -> Entity:
    """`system/registry/local-name/update-transports-request` (§6.5)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/local-name/update-transports-request",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "transports": {"array_of": {"type_ref": "system/hash"}},
            },
        },
    )


# -----------------------------------------------------------------------------
# EXTENSION-REGISTRY §6a.9 — peer-issued live registration
# (publisher self-registration: register-request + issuer-policy admission;
#  `open` / `allowlist` / `manual` modes. `domain-control` is DEFERRED — its
#  DNS-challenge format co-designs with the web-native backends, §6a.9.1.)
# -----------------------------------------------------------------------------


def type_system_registry_register_request() -> Entity:
    """`system/registry/register-request` — publisher self-registration (§6a.9).

    Carries a `system/signature` BY `target_peer_id` (target-matching +
    invariant pointer `system/signature/{hex(request_hash)}`, V7 §5.2) — this
    is ownership-proof layer-1, always required: it proves the requester holds
    the key it is binding the name to. `nonce` + `issued_at` are the anti-replay
    pair (§6a.9.1).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/register-request",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "target_peer_id": {"type_ref": "system/peer-id"},
                "transports": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "requested_ttl": {"type_ref": "primitive/uint", "optional": True},
                "nonce": {"type_ref": "primitive/bytes"},
                "issued_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_registry_issuer_policy() -> Entity:
    """`system/registry/issuer-policy` — a live registry's admission config (§6a.9.1).

    Registry-local (a knob, not a mandate — the substrate gates no name claims,
    §5). `mode` selects the layer-2 entitlement check: `open` (first-come),
    `allowlist` (only listed peer-ids), `manual` (queue for operator), or the
    DEFERRED `domain-control`. Its presence is what makes a registry *live*; a
    peer with no issuer-policy is curated/static and rejects `register-request`.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/issuer-policy",
            "fields": {
                "mode": {"type_ref": "primitive/string"},
                "allowlist": {
                    "array_of": {"type_ref": "system/peer-id"}, "optional": True,
                },
                "name_constraints": {"type_ref": "primitive/string", "optional": True},
                "default_ttl": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_registry_register_pending() -> Entity:
    """`system/registry/register-pending` — a queued request in `manual` mode (§6a.9)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/register-pending",
            "fields": {
                "name": {"type_ref": "primitive/string"},
                "target_peer_id": {"type_ref": "system/peer-id"},
                "transports": {
                    "array_of": {"type_ref": "system/hash"}, "optional": True,
                },
                "requested_ttl": {"type_ref": "primitive/uint", "optional": True},
                "queued_at": {"type_ref": "primitive/uint"},
                "status": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_registry_nonce_record() -> Entity:
    """`system/registry/nonce-record` — anti-replay marker (§6a.9.1).

    Stored at `system/registry/nonce/{requester}/{hex(nonce)}`; a seen
    (requester, nonce) pair within the `issued_at` window is rejected.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/nonce-record",
            "fields": {
                "requester": {"type_ref": "system/peer-id"},
                "issued_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_registry_register_result() -> Entity:
    """`system/registry/register-result` — `:register-request` / `:approve-request` output.

    `status` is `registered` (binding issued, `binding_hash` present),
    `pending_review` (manual-mode queue, `pending_hash` present), or a typed
    rejection delivered as `system/protocol/error` instead.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/register-result",
            "fields": {
                "status": {"type_ref": "primitive/string"},
                "binding_hash": {"type_ref": "system/hash", "optional": True},
                "pending_hash": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_registry_revoke_request() -> Entity:
    """`system/registry/revoke-request` — registrant/operator revocation (§6a.9)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/revoke-request",
            "fields": {
                "binding_hash": {"type_ref": "system/hash"},
                "reason": {"type_ref": "primitive/string", "optional": True},
                "nonce": {"type_ref": "primitive/bytes", "optional": True},
                "issued_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_registry_renew_request() -> Entity:
    """`system/registry/renew-request` — registrant/operator renewal (§6a.9; supersedes-chain)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/registry/renew-request",
            "fields": {
                "binding_hash": {"type_ref": "system/hash"},
                "ttl": {"type_ref": "primitive/uint", "optional": True},
                "nonce": {"type_ref": "primitive/bytes", "optional": True},
                "issued_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


# =============================================================================
# EXTENSION-DISCOVERY v1.0 entity types (§2.1, §2.2.1, §3)
#
# Cohort-canonical type-paths + field schemas mirror the Go reference
# (`core/types/discovery.go`); Base58 peer-id fields carry `system/peer-id`
# per V7 §1.5. These were previously served by the discovery handler but the
# TYPE DEFINITIONS were never advertised in the core registry (cohort
# release-green punch list F1).
# =============================================================================


def type_system_discovery_candidate() -> Entity:
    """`system/discovery/candidate` — an observed peer candidate (§2.1).

    `peer_id` is the Base58 peer-id, nullable until IDENTIFY completes.
    `endpoint_hint` is opaque/backend-specific; `identity_hint` / `supersedes`
    are bare `system/hash` (refless target-matching, V7 §975).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/discovery/candidate",
            "fields": {
                "peer_id": {"type_ref": "system/peer-id", "optional": True},
                "backend": {"type_ref": "primitive/string"},
                "observed_at": {"type_ref": "primitive/uint"},
                "endpoint_hint": {"type_ref": "primitive/any", "optional": True},
                "identity_hint": {"type_ref": "system/hash", "optional": True},
                "supersedes": {"type_ref": "system/hash", "optional": True},
            },
        },
    )


def type_system_discovery_decision() -> Entity:
    """`system/discovery/decision` — an admission decision on a candidate (§2.1).

    `candidate` / `grant` are bare `system/hash` (refless). `grant` is present
    only for grant-limited / grant-more outcomes.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/discovery/decision",
            "fields": {
                "candidate": {"type_ref": "system/hash"},
                "outcome": {"type_ref": "primitive/string"},
                "grant": {"type_ref": "system/hash", "optional": True},
                "decided_at": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_discovery_identity_claim() -> Entity:
    """`system/discovery/identity-claim` — claimed-identity proof shape (§2.2.1).

    `public_key_digest` is the raw V7 §1.5 digest bytes (NOT a `system/hash` —
    no format-code prefix). The triple {key_type, hash_type, public_key_digest}
    with peer_id reproduces the multikey-canonical form a verifier
    reconstructs at IDENTIFY-complete time.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/discovery/identity-claim",
            "fields": {
                "peer_id": {"type_ref": "system/peer-id"},
                "key_type": {"type_ref": "primitive/uint"},
                "hash_type": {"type_ref": "primitive/uint"},
                "public_key_digest": {"type_ref": "primitive/bytes"},
            },
        },
    )


def type_system_discovery_scan_result() -> Entity:
    """`system/discovery/scan-result` — flat `:scan` result (§3).

    Flat entity (NOT wrapped under system/protocol/status). `candidates` is a
    bare `system/hash` list; `code` carries `discovery_scan_overflow` when
    truncated (never a silent truncation, §8.4).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/discovery/scan-result",
            "fields": {
                "candidates": {"array_of": {"type_ref": "system/hash"}},
                "truncated": {"type_ref": "primitive/bool"},
                "code": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_discovery_scan_request() -> Entity:
    """`system/discovery/scan-request` — `:scan` op input (§3).

    `filter` is opaque + backend-MAY-ignore.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/discovery/scan-request",
            "fields": {
                "backend": {"type_ref": "primitive/string"},
                "filter": {
                    "map_of": {"type_ref": "primitive/any"}, "optional": True,
                },
            },
        },
    )


def type_system_discovery_announce_request() -> Entity:
    """`system/discovery/announce-request` — `:announce` op input (§3).

    `profile_ref` is the transport-profile path-segment per NETWORK §6.5.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/discovery/announce-request",
            "fields": {
                "backend": {"type_ref": "primitive/string"},
                "profile_ref": {"type_ref": "primitive/string"},
            },
        },
    )


def type_system_discovery_announce_stop_request() -> Entity:
    """`system/discovery/announce-stop-request` — `:announce-stop` op input (§3)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/discovery/announce-stop-request",
            "fields": {
                "backend": {"type_ref": "primitive/string"},
                "profile_ref": {"type_ref": "primitive/string"},
            },
        },
    )


# =============================================================================
# EXTENSION-RELAY v1.0 entity types (§3, §4.1, §4.2) + §3.5 inbox-relay
#
# Field schemas mirror the Go reference (`core/types/relay.go`). `envelope_inner`
# is a bare `system/hash` (refless target-matching, V7 §5.2); the inner-envelope
# entity rides in the V7 envelope `included` set. Base58 peer-id fields carry
# `system/peer-id`. Cohort release-green punch list F1.
# =============================================================================


def type_system_relay_forward_request() -> Entity:
    """`system/relay/forward-request` — Mode-F forward request (§3.1).

    `route` is the optional source-routed hop list (RELAY v1.1); `next_hop`
    is the single-hop shorthand. `ttl_hops` is the relay-transport hop budget.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/forward-request",
            "fields": {
                "destination": {"type_ref": "system/peer-id"},
                "route": {
                    "array_of": {"type_ref": "primitive/string"}, "optional": True,
                },
                "next_hop": {"type_ref": "system/peer-id", "optional": True},
                "ttl_hops": {"type_ref": "primitive/uint"},
                "envelope_inner": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_relay_store_entry() -> Entity:
    """`system/relay/store-entry` — Mode-S stored entry (§3.2).

    `put_by` is the Base58 placement-identity (verified == authenticated caller
    on :put); authorship is the inner envelope's V7 §5.2 signature, NOT put_by.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/store-entry",
            "fields": {
                "namespace": {"type_ref": "primitive/string"},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
                "put_by": {"type_ref": "system/peer-id"},
                "envelope_inner": {"type_ref": "system/hash"},
            },
        },
    )


def type_system_relay_advertise_limits() -> Entity:
    """`system/relay/advertise-limits` — the §4.1 advertise `limits` sub-map.

    All sub-fields optional; the `advertise` entity MUST carry `limits` but its
    members are the optional bits.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/advertise-limits",
            "fields": {
                "max_envelope_size": {"type_ref": "primitive/uint", "optional": True},
                "max_storage_bytes": {"type_ref": "primitive/uint", "optional": True},
                "forward_rate_limit": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_relay_advertise() -> Entity:
    """`system/relay/advertise` — relay capability advertisement (§4.1).

    Stored at `system/relay/advertise/{relay_peer_id}`; signed by the relay
    per V7 §5.2 (invariant-pointer signature, NO refs block). `endpoints` are
    opaque per-entry NETWORK §6.5 dial profiles.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/advertise",
            "fields": {
                "modes": {"array_of": {"type_ref": "primitive/string"}},
                "endpoints": {"array_of": {"type_ref": "primitive/any"}},
                "limits": {"type_ref": "system/relay/advertise-limits"},
                "caps_required": {"array_of": {"type_ref": "primitive/string"}},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_relay_forward_result() -> Entity:
    """`system/relay/forward-result` — flat `:forward` result (§4.2).

    `next_hop` set when forwarded; `stored_at` set when queued-fallback
    (§6.2.1 Mode-F → Mode-S rendezvous).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/forward-result",
            "fields": {
                "status": {"type_ref": "primitive/string"},
                "next_hop": {"type_ref": "system/peer-id", "optional": True},
                "stored_at": {"type_ref": "primitive/string", "optional": True},
            },
        },
    )


def type_system_relay_put_result() -> Entity:
    """`system/relay/put-result` — flat `:put` result (§4.2)."""
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/put-result",
            "fields": {
                "status": {"type_ref": "primitive/string"},
                "stored_at": {"type_ref": "primitive/string"},
                "entry_hash": {"type_ref": "system/hash"},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_relay_poll_request() -> Entity:
    """`system/relay/poll-request` — `:poll` op input (§4.2).

    `since` is an opaque relay-owned cursor (pass back verbatim); `limit`
    optional (relay applies a default on absence).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/poll-request",
            "fields": {
                "namespace": {"type_ref": "primitive/string"},
                "since": {"type_ref": "primitive/any", "optional": True},
                "limit": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_relay_poll_result() -> Entity:
    """`system/relay/poll-result` — flat `:poll` result (§4.2).

    `entries` are store-entry hashes (pointers, two-hop fetch). `cursor` is an
    opaque relay-owned token; empty `entries` is the canonical authorized-empty
    shape (NOT namespace_not_found).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/relay/poll-result",
            "fields": {
                "entries": {"array_of": {"type_ref": "system/hash"}},
                "cursor": {"type_ref": "primitive/any"},
                "has_more": {"type_ref": "primitive/bool"},
            },
        },
    )


def type_system_peer_inbox_relay_entry() -> Entity:
    """`system/peer/inbox-relay-entry` — one (relay, namespace, priority) row (§3.5).

    Lower `priority` preferred (MX convention). `relay` is a Base58 peer-id.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer/inbox-relay-entry",
            "fields": {
                "relay": {"type_ref": "system/peer-id"},
                "namespace": {"type_ref": "primitive/string"},
                "priority": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_peer_inbox_relay() -> Entity:
    """`system/peer/inbox-relay` — MX-equivalent inbox declaration (§3.5).

    A peer's signed declaration of WHERE its mail is stored when unreachable
    (the DNS-MX analog). Resolvers MUST try entries in ascending priority and
    MUST V7 §5.2 signature-verify against the resolved peer-id (fail-closed).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/peer/inbox-relay",
            "fields": {
                "relays": {
                    "array_of": {"type_ref": "system/peer/inbox-relay-entry"},
                },
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


# =============================================================================
# EXTENSION-ROUTE v1.0 entity type (§2) — storage-plane routing-table entry
#
# Field schema mirrors the Go reference (`core/types/route.go`). `via` is a
# Base58 peer-id. Cohort release-green punch list F1.
# =============================================================================


def type_system_route() -> Entity:
    """`system/route` — one routing-table entry (EXTENSION-ROUTE §2).

    `match` is the destination pattern; `action` the routing action; `via` the
    optional next-hop peer-id; `metric` for tie-breaking (lower preferred).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/route",
            "fields": {
                "match": {"type_ref": "primitive/string"},
                "action": {"type_ref": "primitive/string"},
                "via": {"type_ref": "system/peer-id", "optional": True},
                "metric": {"type_ref": "primitive/uint", "optional": True},
                "expires_at": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


# =============================================================================
# EXTENSION-ENCRYPTION v1.0 — base per-entity stateless encryption
# (self / peer / group modes; §4.1 pubkey, §5.1 encrypted, §9.2 backup,
#  §10.1 handoff, §11.1 revocation). Nested records (kdf_params, wrapped-key)
# are their own named types since a field spec carries exactly one of
# type_ref/array_of/map_of.
# =============================================================================


def type_system_note() -> Entity:
    """`system/note` — generic note entity; the ENC-KAT-INNER carrier (R3).

    Arch ruling R3 pins the §16 encryption KAT plaintext to the
    ECF of `system/note{body, created:0}` rather than a bare string. Registered
    so the KAT carrier resolves as a first-class type across the cohort.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/note",
            "fields": {
                "body": {"type_ref": "primitive/string"},
                "created": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_encryption_kdf_params() -> Entity:
    """`system/encryption/kdf-params` — Argon2id parameters (§6.1).

    Field names are normative (`memory_cost`/`time_cost`/`parallelism`, NOT
    `m`/`t`/`p`) for ECF byte-equality (F-GO-9). Bound into the self-mode AAD
    (F2-4) and the §9.2 backup AAD.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/encryption/kdf-params",
            "fields": {
                "argon2_version": {"type_ref": "primitive/uint"},
                "memory_cost": {"type_ref": "primitive/uint"},
                "time_cost": {"type_ref": "primitive/uint"},
                "parallelism": {"type_ref": "primitive/uint"},
                "output_len": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_encryption_pubkey() -> Entity:
    """`system/encryption-pubkey` — the inner pubkey entity (§4.1).

    content_hash is a pure function of these six fields and is the uniform
    `recipient_key` value bound at every tier (F-GO-1); cross-tier interop
    requires re-publishing the byte-identical authored entity, not re-minting
    (F2-3). `public_key` length is determined by `enc_key_type` (§3.1).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/encryption-pubkey",
            "fields": {
                "enc_key_type": {"type_ref": "primitive/uint"},
                "public_key": {"type_ref": "primitive/bytes"},
                "supported_aead_ids": {"array_of": {"type_ref": "primitive/uint"}},
                "supported_kdf_ids": {"array_of": {"type_ref": "primitive/uint"}},
                "created": {"type_ref": "primitive/uint"},
                "expires": {"type_ref": "primitive/uint", "optional": True},
            },
        },
    )


def type_system_encryption_wrapped_key() -> Entity:
    """`system/encryption/wrapped-key` — one per-member group wrap (§8.2).

    Structurally peer-mode hybrid encryption of the random `group_aead_key` to
    member `recipient_key` (the member's inner pubkey content_hash, F-GO-1). No
    per-wrap signature — the outer entity is signed once (F-GO-3 / F-GO-6).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/encryption/wrapped-key",
            "fields": {
                "recipient_key": {"type_ref": "system/hash"},
                "enc_key_type": {"type_ref": "primitive/uint"},
                "ephemeral_key": {"type_ref": "primitive/bytes"},
                "wrapped_aead_key": {"type_ref": "primitive/bytes"},
                "wrap_nonce": {"type_ref": "primitive/bytes"},
            },
        },
    )


def type_system_encrypted() -> Entity:
    """`system/encrypted` — the encrypted outer entity (§5.1 + §6/§7/§8).

    Common fields are required; per-mode fields are optional (self: `key_id`,
    `kdf_salt`, `kdf_params`; peer: `ephemeral_key`, `recipient_key`; group:
    `wrapped_keys`). Sender authentication is NOT a field here — it lives at the
    V7 invariant pointer `system/signature/{hex(content_hash)}` (F-GO-3).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/encrypted",
            "fields": {
                # Common (§5.1)
                "mode": {"type_ref": "primitive/string"},
                "enc_key_type": {"type_ref": "primitive/uint"},
                "aead_id": {"type_ref": "primitive/uint"},
                "kdf_id": {"type_ref": "primitive/uint"},
                "nonce": {"type_ref": "primitive/bytes"},
                "ciphertext": {"type_ref": "primitive/bytes"},
                # self (§6.1)
                "key_id": {"type_ref": "primitive/string", "optional": True},
                "kdf_salt": {"type_ref": "primitive/bytes", "optional": True},
                "kdf_params": {
                    "type_ref": "system/encryption/kdf-params", "optional": True,
                },
                # peer (§7.2)
                "ephemeral_key": {"type_ref": "primitive/bytes", "optional": True},
                "recipient_key": {"type_ref": "system/hash", "optional": True},
                # group (§8.2)
                "wrapped_keys": {
                    "array_of": {"type_ref": "system/encryption/wrapped-key"},
                    "optional": True,
                },
            },
        },
    )


def type_system_encryption_key_backup() -> Entity:
    """`system/encryption/key-backup` — Tier-2 passphrase-wrapped key (§9.2).

    Tier A/B path `system/encryption/key-backup/{pubkey_hash}`; the encrypted
    private-key bytes are wrapped under an Argon2id→HKDF KEK with the params +
    pubkey_ref bound into the backup AAD.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/encryption/key-backup",
            "fields": {
                "pubkey_ref": {"type_ref": "system/hash"},
                "kdf_salt": {"type_ref": "primitive/bytes"},
                "kdf_params": {"type_ref": "system/encryption/kdf-params"},
                "wrap_nonce": {"type_ref": "primitive/bytes"},
                "wrapped_key": {"type_ref": "primitive/bytes"},
            },
        },
    )


def type_system_encryption_handoff() -> Entity:
    """`system/encryption/handoff` — Tier-A rotation link (§10.1).

    Dual-signed (old + new pubkey holders) at the invariant pointer
    `system/signature/{hex(handoff_hash)}`; senders walk `previous`→`next`
    forward to the terminal (current) pubkey.
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/encryption/handoff",
            "fields": {
                "previous_pubkey": {"type_ref": "system/hash"},
                "next_pubkey": {"type_ref": "system/hash"},
                "created": {"type_ref": "primitive/uint"},
            },
        },
    )


def type_system_encryption_revocation() -> Entity:
    """`system/encryption/revocation` — Tier-A revocation (§11.1).

    Marks an encryption-pubkey no longer trusted; signed by the peer's V7
    keypair at the invariant pointer. Senders enumerate these before encrypting
    and reject a revoked pubkey (`encryption_key_revoked`).
    """
    return Entity(
        type="system/type",
        data={
            "name": "system/encryption/revocation",
            "fields": {
                "revokes": {"type_ref": "system/hash"},
                "reason": {"type_ref": "primitive/string", "optional": True},
                "created": {"type_ref": "primitive/uint"},
            },
        },
    )


# =============================================================================
# Type Registry
# =============================================================================

ALL_TYPE_DEFINITIONS = [
    # Primitive types (8 primitives, name only)
    type_primitive_string,
    type_primitive_bytes,
    type_primitive_int,
    type_primitive_uint,
    type_primitive_float,
    type_primitive_bool,
    type_primitive_null,
    type_primitive_any,
    # Bootstrap types (V7.7 - 14 total including semantic string types)
    type_system_hash,
    type_system_tree_path,
    type_system_type_name,
    type_system_peer_id,
    type_system_deletion_marker,
    type_system_type,
    type_system_type_field_spec,
    # Core entity types
    type_entity,
    type_core_entity,
    type_core_envelope,
    # Protocol types
    type_system_envelope,
    type_system_protocol_envelope,
    type_system_protocol_error,
    type_system_protocol_connect_hello,
    type_system_protocol_connect_authenticate,
    type_system_protocol_resource_target,
    type_system_protocol_execute,
    type_system_protocol_execute_response,
    # Capability types (V7.7 - path-scope and id-scope)
    type_system_capability_path_scope,
    type_system_capability_id_scope,
    type_system_capability_grant_entry,
    type_system_capability_delegation_caveats,
    type_system_capability_multi_granter,
    type_system_capability_token,
    type_system_capability_grant,
    type_system_capability_request,
    type_system_capability_revocation,
    type_system_capability_revoke_request,
    type_system_capability_delegate_request,
    type_system_capability_policy_entry,
    # Identity and signature
    type_system_peer,
    type_system_signature,
    # Tree types (IMPLEMENTATION-SPEC §3.6 V7.7)
    type_system_tree_listing_entry,
    type_system_tree_listing,
    type_system_tree_get_request,
    type_system_tree_put_request,
    # Tree Extension types (EXTENSION-TREE.md v3.0)
    type_system_tree_snapshot,
    type_system_tree_snapshot_request,
    type_system_tree_diff_change,
    type_system_tree_diff,
    type_system_tree_diff_request,
    type_system_tree_merge_conflict,
    type_system_tree_merge_result,
    type_system_tree_merge_request,
    type_system_tree_extract_request,
    type_system_tree_config,
    # Content extension types (EXTENSION-CONTENT v3.5)
    type_system_content_blob,
    type_system_content_chunk,
    type_system_content_descriptor,
    type_system_content_get_request,
    type_system_content_content_response,
    type_system_content_ingest_request,
    type_system_content_ingest_result,
    # Transport-family profiles (EXTENSION-NETWORK §6.5, v1.4 Amendment 2)
    type_system_peer_transport_tcp,
    type_system_peer_transport_http,
    type_system_peer_transport_http_poll,
    # Signed tree-root anchor (Phase P / C1 — PEER-MANIFEST-STATIC-HANDSHAKE §4)
    type_system_peer_published_root,
    # Per-peer authenticated session entity (PROPOSAL-TRANSPORT-FAMILY R6)
    type_system_peer_session,
    # Storage-substitute extension types (CDN corridor v1; renamed
    # from CONTENT-SUBSTITUTE per RULINGS §3 — substitutes
    # the whole storage layer (tree + content) via the two-prefix profile)
    type_system_substitute_endpoint,
    type_system_substitute_source,
    type_system_substitute_snapshot_manifest,
    type_system_substitute_try_request,
    # Type validation types (EXTENSION-TYPE v1.1 §8.3–§8.5)
    type_system_type_validate_request,
    type_system_type_validate_result,
    type_system_type_violation,
    # Type analysis op request/result (EXTENSION-TYPE v1.1 §7.2–§7.6, §8.1–§8.2)
    type_system_type_field_comparison,
    type_system_type_field_incompatibility,
    type_system_type_compare_request,
    type_system_type_compare_result,
    type_system_type_compatible_request,
    type_system_type_compatibility_report,
    type_system_type_converge_request,
    type_system_type_adopt_request,
    type_system_type_reconcile_request,
    type_system_type_reconcile_result,
    # Standard constraint types (EXTENSION-TYPE v1.1 §4)
    type_system_type_constraint_min,
    type_system_type_constraint_max,
    type_system_type_constraint_min_length,
    type_system_type_constraint_max_length,
    type_system_type_constraint_min_count,
    type_system_type_constraint_max_count,
    type_system_type_constraint_pattern,
    type_system_type_constraint_one_of,
    type_system_type_constraint_not_one_of,
    type_system_type_constraint_format,
    type_system_type_constraint_type_pattern,
    # Constraint handler dispatch envelopes (EXTENSION-TYPE v1.1 §5.2–§5.3)
    type_system_type_constraint_validate_request,
    type_system_type_constraint_validate_result,
    # Handler types (V7.7 singular namespace)
    type_system_handler,
    type_system_handler_manifest,
    type_system_handler_operation_spec,
    type_system_handler_interface,
    type_system_handler_register_request,
    type_system_handler_register_result,
    # Resource types
    type_system_bounds,
    type_system_callback_spec,
    type_system_resource_limits,
    # Inbox extension types (EXTENSION-INBOX v5.0 - V7.8)
    type_system_delivery_spec,
    type_system_protocol_inbox_delivery,
    type_system_protocol_inbox_notification,
    # Durability contract types (EXTENSION-DURABILITY v0.1 — exploratory,
    # optional, extracted from EXTENSION-INBOX §10; depends V7 v7.46+)
    type_system_durability_request,
    type_system_durability_result,
    type_system_durability_advertisement,
    # Continuation extension types (EXTENSION-CONTINUATION v1.9)
    type_system_continuation,
    type_system_continuation_join,
    type_system_continuation_suspended,
    type_system_continuation_transform,
    type_system_continuation_transform_op,
    type_system_continuation_advance_request,
    type_system_continuation_resume_request,
    type_system_continuation_abandon_request,
    type_system_continuation_install_result,
    # Subscription extension types (EXTENSION-SUBSCRIPTION v3.2)
    type_system_subscription,
    type_system_subscription_request,
    type_system_subscription_cancel,
    type_system_subscription_redirect,
    type_system_subscription_limits,
    type_system_subscription_result,
    # Trie node type (EXTENSION-TREE v3.2)
    type_system_tree_snapshot_node,
    # Trie root tracking config (EXTENSION-TREE v3.8 §3.4.1a)
    type_system_tree_tracking_config,
    type_system_tree_consumer_halt,
    type_system_tree_partial_result,
    # Revision extension types (EXTENSION-REVISION v2.1)
    type_system_revision_entry,
    type_system_revision_conflict,
    type_system_revision_merge_config,
    type_system_revision_merge_config_params,
    type_system_revision_merge_config_result,
    type_system_revision_merge_request,
    type_system_revision_merge_response,
    type_system_revision_config,
    type_system_revision_status,
    type_system_revision_commit_params,
    type_system_revision_commit_result,
    type_system_revision_log_params,
    type_system_revision_log_result,
    type_system_revision_merge_params,
    type_system_revision_merge_result,
    type_system_revision_resolve_params,
    type_system_revision_resolve_result,
    type_system_revision_fetch_params,
    type_system_revision_fetch_result,
    type_system_revision_fetch_entities_params,
    type_system_revision_fetch_entities_result,
    type_system_revision_fetch_diff_params,
    type_system_revision_push_params,
    type_system_revision_push_result,
    type_system_revision_ancestor_params,
    type_system_revision_ancestor_result,
    type_system_revision_status_params,
    type_system_revision_branch_params,
    type_system_revision_branch_result,
    type_system_revision_checkout_params,
    type_system_revision_checkout_result,
    type_system_revision_tag_params,
    type_system_revision_tag_result,
    type_system_revision_diff_params,
    type_system_revision_cherry_pick_params,
    type_system_revision_cherry_pick_result,
    type_system_revision_revert_params,
    type_system_revision_revert_result,
    type_system_revision_config_params,
    type_system_revision_config_result,
    type_system_revision_cascade_warning,
    # Clock extension types (EXTENSION-CLOCK v1.0)
    type_system_clock_timestamp,
    type_system_clock_logical,
    type_system_clock_vector,
    type_system_clock_hlc,
    type_system_clock_config,
    type_system_clock_state,
    type_system_clock_compare_params,
    type_system_clock_compare_result,
    type_system_clock_tick,
    # Query extension types (EXTENSION-QUERY v1.0)
    type_system_query_expression,
    type_system_query_field_predicate,
    type_system_query_result,
    type_system_query_match,
    type_system_query_constraints,
    type_system_query_allowances,
    type_system_query_index_config,
    # History extension types (EXTENSION-HISTORY v1.2)
    type_system_history_transition,
    type_system_history_config,
    type_system_history_query_params,
    type_system_history_query_result,
    type_system_history_rollback_params,
    type_system_history_rollback_result,
    # EXTENSION-ATTESTATION v1.1 substrate types (entity + 4 op req/res)
    type_system_attestation,
    type_system_attestation_create_request,
    type_system_attestation_create_result,
    type_system_attestation_supersede_request,
    type_system_attestation_supersede_result,
    type_system_attestation_revoke_request,
    type_system_attestation_revoke_result,
    type_system_attestation_verify_request,
    type_system_attestation_verify_result,
    # EXTENSION-QUORUM v1.1 substrate types (entity + 4 op req/res)
    type_system_quorum,
    type_system_quorum_create_request,
    type_system_quorum_create_result,
    type_system_quorum_update_request,
    type_system_quorum_update_result,
    type_system_quorum_publish_request,
    type_system_quorum_publish_result,
    type_system_quorum_verify_request,
    type_system_quorum_verify_result,
    # EXTENSION-IDENTITY v3.3 types (peer-config + identity-binding only;
    # quorum and attestation entity types live in the substrate above)
    type_system_identity_identity_binding,
    type_system_identity_event,
    type_system_identity_peer_config,
    type_system_identity_configure_request,
    type_system_identity_configure_result,
    type_system_identity_create_quorum_request,
    type_system_identity_create_quorum_result,
    type_system_identity_create_attestation_request,
    type_system_identity_create_attestation_result,
    type_system_identity_supersede_attestation_request,
    type_system_identity_supersede_attestation_result,
    type_system_identity_revoke_attestation_request,
    type_system_identity_revoke_attestation_result,
    type_system_identity_publish_attestation_request,
    type_system_identity_publish_attestation_result,
    # EXTENSION-ROLE v1.6 — entity types + 11 request/result types
    # (per CROSS-IMPL-ROLE-V1.6 + PROPOSAL-ROLE-V1.5-SPEC-FIXES)
    type_system_role,
    type_system_role_assignment,
    type_system_role_exclusion,
    type_system_role_derived_token_link,
    type_system_role_define_request,
    type_system_role_define_result,
    type_system_role_assign_request,
    type_system_role_assign_result,
    type_system_role_unassign_result,
    type_system_role_exclude_result,
    type_system_role_unexclude_result,
    type_system_role_re_derive_request,
    type_system_role_re_derive_result,
    type_system_role_delegate_request,
    type_system_role_delegate_result,
    type_system_role_initial_grant_policy,
    # EXTENSION-REGISTRY v1.0 — substrate + local-name backend
    type_system_registry_binding,
    type_system_registry_revocation,
    type_system_registry_resolver_chain_entry,
    type_system_registry_pinned_binding,
    type_system_registry_name_format_dispatch,
    type_system_registry_resolver_config,
    type_system_registry_local_name_config,
    type_system_registry_resolution_result,
    type_system_registry_resolution_log,
    type_system_registry_local_name_entry,
    type_system_registry_local_name_list_result,
    type_system_registry_bind_result,
    type_system_registry_resolve_request,
    type_system_registry_invalidate_cache_request,
    type_system_registry_local_name_bind_request,
    type_system_registry_local_name_unbind_request,
    type_system_registry_local_name_update_transports_request,
    type_system_registry_local_name_list_request,
    # EXTENSION-REGISTRY §6a.9 — peer-issued live registration
    type_system_registry_register_request,
    type_system_registry_issuer_policy,
    type_system_registry_register_pending,
    type_system_registry_nonce_record,
    type_system_registry_register_result,
    type_system_registry_revoke_request,
    type_system_registry_renew_request,
    # EXTENSION-DISCOVERY v1.0 — candidate/decision/identity + scan/announce ops
    type_system_discovery_candidate,
    type_system_discovery_decision,
    type_system_discovery_identity_claim,
    type_system_discovery_scan_result,
    type_system_discovery_scan_request,
    type_system_discovery_announce_request,
    type_system_discovery_announce_stop_request,
    # EXTENSION-RELAY v1.0 — forward/store/advertise + flat results + §3.5 inbox
    type_system_relay_forward_request,
    type_system_relay_store_entry,
    type_system_relay_advertise_limits,
    type_system_relay_advertise,
    type_system_relay_forward_result,
    type_system_relay_put_result,
    type_system_relay_poll_request,
    type_system_relay_poll_result,
    type_system_peer_inbox_relay_entry,
    type_system_peer_inbox_relay,
    # EXTENSION-ROUTE v1.0 — storage-plane routing-table entry
    type_system_route,
    # EXTENSION-ENCRYPTION v1.0 — base per-entity stateless encryption
    type_system_note,  # R3 ENC-KAT-INNER carrier
    type_system_encryption_kdf_params,
    type_system_encryption_pubkey,
    type_system_encryption_wrapped_key,
    type_system_encrypted,
    type_system_encryption_key_backup,
    type_system_encryption_handoff,
    type_system_encryption_revocation,
]


def get_all_type_entities() -> list[Entity]:
    """Return all built-in type entities.

    Returns:
        List of Entity objects, each defining a system/type.
    """
    return [fn() for fn in ALL_TYPE_DEFINITIONS]
