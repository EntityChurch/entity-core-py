"""Capability token structure.

A capability token grants permissions for operations on resources.
Tokens can contain multiple grants, each specifying:
- Resources (URI patterns)
- Operations (read, write, list, etc.)
- Optional exclusions and constraints

Caveats restrict how capabilities can be delegated:
- no_delegation: Cannot delegate further
- max_delegation_depth: Maximum chain depth from this capability
- max_delegation_ttl: Maximum lifetime for delegated capabilities

V4 Changes:
- granter, grantee, parent are bytes (Hash), not strings
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from entity_core.utils.ecf import Hash


@dataclass
class DelegationCaveats:
    """V4 §3.6: Delegation restrictions on a capability.

    A flat struct with optional fields - NOT an array of objects.

    Attributes:
        no_delegation: If true, cannot delegate further.
        max_delegation_depth: Maximum chain depth from this capability.
        max_delegation_ttl: Maximum lifetime (ms) for delegated capabilities.
    """

    no_delegation: bool | None = None
    max_delegation_depth: int | None = None
    max_delegation_ttl: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (V4 flat struct format)."""
        result: dict[str, Any] = {}
        if self.no_delegation is not None:
            result["no_delegation"] = self.no_delegation
        if self.max_delegation_depth is not None:
            result["max_delegation_depth"] = self.max_delegation_depth
        if self.max_delegation_ttl is not None:
            result["max_delegation_ttl"] = self.max_delegation_ttl
        return result

    def is_empty(self) -> bool:
        """Check if all fields are None."""
        return (
            self.no_delegation is None
            and self.max_delegation_depth is None
            and self.max_delegation_ttl is None
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> DelegationCaveats | None:
        """Create DelegationCaveats from dictionary."""
        if d is None:
            return None
        return cls(
            no_delegation=d.get("no_delegation"),
            max_delegation_depth=d.get("max_delegation_depth"),
            max_delegation_ttl=d.get("max_delegation_ttl"),
        )


@dataclass
class CapabilityScope:
    """Typed scope for grant dimensions per spec §9.8.

    The include array lists patterns that match; the optional exclude
    array carves out exceptions.

    Attributes:
        include: Patterns that authorize access.
        exclude: Patterns that carve out exceptions (optional).
    """

    include: list[str]
    exclude: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {"include": self.include}
        if self.exclude:
            result["exclude"] = self.exclude
        return result

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CapabilityScope:
        """Create CapabilityScope from an {include, exclude} dict."""
        return cls(
            include=d.get("include", []),
            exclude=d.get("exclude"),
        )

    @classmethod
    def from_patterns(cls, patterns: list[str], exclude: list[str] | None = None) -> CapabilityScope:
        """Create CapabilityScope from patterns (convenience constructor)."""
        return cls(include=patterns, exclude=exclude)


def get_scope(d: dict[str, Any], key: str) -> CapabilityScope:
    """Get a CapabilityScope field from a grant dict.

    Scoped format: each key maps to {include: [...], exclude: [...]}.

    Args:
        d: The grant dictionary.
        key: The field key (e.g., "handlers", "resources", "operations").

    Returns:
        CapabilityScope parsed from the field.
    """
    value = d.get(key)
    if isinstance(value, dict):
        return CapabilityScope.from_dict(value)
    return CapabilityScope(include=[])


@dataclass
class Grant:
    """A single grant rule within a capability per spec §9.9.

    V6.0 Changes:
    - handlers, resources, operations are now CapabilityScope objects
    - Each scope has include/exclude arrays
    - Added peers field for peer scope
    - Removed top-level exclude (now per-scope)

    Attributes:
        handlers: Handler scope - which handlers can be called.
        resources: Data path scope - which paths can be accessed.
        operations: Operation scope - which operations are authorized.
        peers: Peer scope - which peers the grant applies to (optional).
        constraints: Domain-specific narrowing fields (handler-interpreted).
            map_of: primitive/any. Keys can't be dropped during delegation.
        allowances: Domain-specific expanding fields (handler-interpreted).
            map_of: primitive/any. Keys can't be added during delegation.

    V7.14 Changes:
    - constraints type changed from primitive/any to map_of: primitive/any
    - Added allowances field (map_of: primitive/any, optional)
    - grant_subset now checks key retention/containment + byte equality
    """

    handlers: CapabilityScope
    resources: CapabilityScope
    operations: CapabilityScope
    peers: CapabilityScope | None = None
    constraints: dict[str, Any] | None = None
    allowances: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (V6.0/V7.14 format with scoped fields)."""
        result: dict[str, Any] = {
            "handlers": self.handlers.to_dict(),
            "resources": self.resources.to_dict(),
            "operations": self.operations.to_dict(),
        }
        if self.peers is not None:
            result["peers"] = self.peers.to_dict()
        if self.constraints is not None:
            result["constraints"] = self.constraints
        if self.allowances is not None:
            result["allowances"] = self.allowances
        return result

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Grant:
        """Create Grant from dictionary.

        Scoped format (V6.0/V7.14): each of handlers/resources/operations
        maps to {include: [...], exclude: [...]}.
        """
        return cls(
            handlers=get_scope(d, "handlers"),
            resources=get_scope(d, "resources"),
            operations=get_scope(d, "operations"),
            peers=get_scope(d, "peers") if "peers" in d else None,
            constraints=d.get("constraints"),
            allowances=d.get("allowances"),
        )

    @classmethod
    def create(
        cls,
        handlers: list[str],
        resources: list[str],
        operations: list[str],
        *,
        handler_exclude: list[str] | None = None,
        resource_exclude: list[str] | None = None,
        operation_exclude: list[str] | None = None,
        peers: list[str] | None = None,
        peer_exclude: list[str] | None = None,
        constraints: Any = None,
        allowances: dict[str, Any] | None = None,
    ) -> Grant:
        """Create a Grant with explicit scope patterns (convenience constructor).

        Args:
            handlers: Handler patterns to include.
            resources: Resource patterns to include.
            operations: Operations to include.
            handler_exclude: Handler patterns to exclude.
            resource_exclude: Resource patterns to exclude.
            operation_exclude: Operation patterns to exclude.
            peers: Peer patterns to include.
            peer_exclude: Peer patterns to exclude.
            constraints: Domain-specific constraints.
            allowances: Domain-specific allowances.

        Returns:
            A new Grant object.
        """
        return cls(
            handlers=CapabilityScope(include=handlers, exclude=handler_exclude),
            resources=CapabilityScope(include=resources, exclude=resource_exclude),
            operations=CapabilityScope(include=operations, exclude=operation_exclude),
            peers=CapabilityScope(include=peers, exclude=peer_exclude) if peers else None,
            constraints=constraints,
            allowances=allowances,
        )


@dataclass
class MultiGranter:
    """V7.35 §3.2: Multi-signature granter for K-of-N root capabilities.

    Carried inline in `CapabilityToken.granter` when the cap is multi-sig.
    On the wire it serializes as a CBOR map; single-hash granters serialize
    as a CBOR byte string. Decoders branch on CBOR major type (no tags) per
    PROPOSAL-MULTISIG-CORE-PRIMITIVE §5 / ENTITY-CBOR-ENCODING §11.

    Attributes:
        signers: Identity hashes of the K-of-N constituent peers.
        threshold: K — how many of `signers` must sign the cap (M2).
    """

    signers: list[Hash]
    threshold: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to entity-data form: {"signers": [bytes...], "threshold": int}.

        Map keys go through ECF deterministic CBOR ordering at encode time.
        """
        return {"signers": list(self.signers), "threshold": self.threshold}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MultiGranter:
        """Parse from entity-data dict; no validity checks here (see validate)."""
        signers = list(d.get("signers", []))
        threshold = int(d.get("threshold", 0))
        return cls(signers=signers, threshold=threshold)


# N ceiling per PROPOSAL §6 (M9). SHOULD-level; implementations MAY accept
# larger N. Reject above this by default for DoS resistance.
MULTI_GRANTER_N_CEILING: int = 32


def is_multi_granter(value: Any) -> bool:
    """True when `value` has the multi-granter wire shape.

    Used at decode and verifier sites to branch on granter polymorphism
    without instantiating MultiGranter. Accepts the dict form (post-CBOR
    decode) or a MultiGranter instance.
    """
    if isinstance(value, MultiGranter):
        return True
    if isinstance(value, dict):
        return "signers" in value and "threshold" in value
    return False


def get_multi_granter(value: Any) -> MultiGranter | None:
    """Extract a MultiGranter from a wire-form granter value, or None.

    Single-hash granters (bytes / str) return None.
    """
    if isinstance(value, MultiGranter):
        return value
    if isinstance(value, dict) and "signers" in value and "threshold" in value:
        return MultiGranter.from_dict(value)
    return None


def validate_multi_granter(
    value: Any,
    *,
    enforce_n_ceiling: bool = True,
) -> tuple[bool, str | None]:
    """Validate a multi-granter struct per PROPOSAL §3.3 (M3) + §6 (M9).

    Constraints:
    - shape: dict-like with `signers` (list) + `threshold` (int)
    - N >= 2 (use single-sig form for N=1)
    - K in [2, N] (K=0 invalid; K=1 invalid; K>N invalid)
    - no duplicate signer hashes (byte-equality)
    - N <= MULTI_GRANTER_N_CEILING (32) when enforce_n_ceiling

    Args:
        value: The granter value (dict from decode, or MultiGranter instance).
        enforce_n_ceiling: When True (default), reject N > 32.

    Returns:
        (True, None) when valid; (False, reason) otherwise.
    """
    multi = get_multi_granter(value)
    if multi is None:
        return False, "Granter is not a multi-granter struct"

    signers = multi.signers
    threshold = multi.threshold

    if not isinstance(signers, list):
        return False, "multi-granter signers must be a list"
    n = len(signers)
    if n < 2:
        return False, f"multi-granter N must be >= 2 (got {n})"
    if enforce_n_ceiling and n > MULTI_GRANTER_N_CEILING:
        return False, f"multi-granter N exceeds ceiling: {n} > {MULTI_GRANTER_N_CEILING}"

    if not isinstance(threshold, int) or isinstance(threshold, bool):
        return False, "multi-granter threshold must be an integer"
    if threshold < 2:
        return False, f"multi-granter threshold must be >= 2 (got {threshold})"
    if threshold > n:
        return False, f"multi-granter threshold exceeds N: {threshold} > {n}"

    # Duplicate detection on raw bytes (signers are identity hashes).
    seen: set[bytes] = set()
    for s in signers:
        if not isinstance(s, (bytes, bytearray)):
            return False, "multi-granter signers must be byte-string identity hashes"
        b = bytes(s)
        if b in seen:
            return False, "multi-granter has duplicate signers"
        seen.add(b)

    return True, None


def multi_sig_root_path(cap_hash: Hash) -> str:
    """Storage path for multi-sig root caps per PROPOSAL §9 (M12).

    Returns `system/capability/grants/multi-sig-root/{hex(cap_hash)}`.

    The hex form here is the encoded path-component of the bytes hash; the
    bytes value itself is the address. (Single-sig handler self-grants live
    at `system/capability/grants/{handler_pattern}` per V7 §6.8.)
    """
    return f"system/capability/grants/multi-sig-root/{cap_hash.hex()}"


def grantee_is_zero(grantee: Any) -> bool:
    """True iff `grantee` is absent, empty, or an all-zeros hash.

    Mirrors Go's `hash.Hash.IsZero()` (zero-value Hash == zero algorithm +
    all-zero digest), and also treats the absent/empty wire form (`b""`,
    `None`, `from_entity`'s `data.get("grantee", b"")` default) as zero.
    A zero-hash grantee never resolves to a real `system/identity` entity
    (no keypair hashes to zero), so a cap minted with one is unusable by
    construction. See SEC-18 / V7 v7.39 PR-3.
    """
    if not grantee:  # None / b"" / empty
        return True
    if isinstance(grantee, (bytes, bytearray)):
        return all(b == 0 for b in grantee)
    return False


@dataclass
class CapabilityToken:
    """Capability token granting permissions.

    V4: Refless architecture - granter, grantee, parent are bytes (Hash) in data only.
    Signature is found via target-matching, not refs.

    V7.35 §3.1 (M1): `granter` is polymorphic — single-sig caps carry a
    `Hash` (CBOR bstr); multi-sig root caps carry a `MultiGranter` struct
    (CBOR map). Multi-sig caps MUST have `parent: None` (M3 root-only).

    Attributes:
        grants: List of permission grants.
        granter: Hash bytes of granter identity entity, OR MultiGranter
            struct for K-of-N root caps.
        grantee: Hash bytes of grantee identity entity (single hash; M3).
        not_before: Unix timestamp (ms) when token becomes valid.
        expires_at: Unix timestamp (ms) when token expires.
        parent: Hash bytes of parent capability (for delegation chains).
            MUST be None when granter is a MultiGranter (M3).
        delegation_caveats: V4 flat struct for delegation restrictions.
        created_at: Unix timestamp (ms) when token was created.
    """

    grants: list[Grant]
    granter: Hash | MultiGranter  # V7.35 §3.1: polymorphic
    grantee: Hash  # V4: bytes (single hash; M3)
    not_before: int | None = None
    expires_at: int | None = None
    parent: Hash | None = None  # V4: bytes; None for multi-sig (M3)
    delegation_caveats: DelegationCaveats | None = None  # V4: flat struct, not array
    created_at: int | None = None

    TYPE = "system/capability/token"

    def to_entity(self) -> dict[str, Any]:
        """Convert to entity dictionary.

        V4: All references are bytes in data only. Signature is found via target-matching.
        V4 §3.6: delegation_caveats is a flat struct, not an array.
        V7.35 §3.1: granter serializes as CBOR bstr (single-sig) or CBOR map (multi-sig).
        """
        # M1: granter encodes inline as bytes or as the multi-granter dict;
        # cbor2 maps Python bytes -> bstr (major type 2) and dict -> map
        # (major type 5), giving the kinded discrimination M8 specifies.
        granter_value: Any
        if isinstance(self.granter, MultiGranter):
            granter_value = self.granter.to_dict()
        else:
            granter_value = self.granter

        data: dict[str, Any] = {
            "grants": [g.to_dict() for g in self.grants],
            "granter": granter_value,
            "grantee": self.grantee,  # V4: bytes
        }
        # V4: Include created_at (required per spec)
        if self.created_at is not None:
            data["created_at"] = self.created_at
        # Optional fields - only include if set
        if self.not_before is not None:
            data["not_before"] = self.not_before
        if self.expires_at is not None:
            data["expires_at"] = self.expires_at
        if self.parent:
            data["parent"] = self.parent  # V4: bytes
        # V4 §3.6: delegation_caveats is a flat struct, field name is "delegation_caveats"
        if self.delegation_caveats and not self.delegation_caveats.is_empty():
            data["delegation_caveats"] = self.delegation_caveats.to_dict()

        return {"type": self.TYPE, "data": data}

    @classmethod
    def from_entity(cls, entity: dict[str, Any]) -> CapabilityToken:
        """Create from entity dictionary.

        V4: All fields are in data. No refs field.
        V4 §3.6: delegation_caveats is a flat struct.
        V7.35 §3.1: granter parses as MultiGranter when shape matches; else Hash bytes.
        """
        data = entity["data"]

        # V4: Parse delegation_caveats as flat struct
        delegation_caveats = DelegationCaveats.from_dict(data.get("delegation_caveats"))

        granter_raw = data.get("granter", b"")
        granter: Hash | MultiGranter
        multi = get_multi_granter(granter_raw)
        granter = multi if multi is not None else granter_raw

        return cls(
            grants=[Grant.from_dict(g) for g in data.get("grants", [])],
            granter=granter,
            grantee=data.get("grantee", b""),  # V4: bytes
            not_before=data.get("not_before"),
            expires_at=data.get("expires_at"),
            parent=data.get("parent"),  # V4: bytes or None
            delegation_caveats=delegation_caveats,
            created_at=data.get("created_at"),
        )

    def validate_structure(self) -> None:
        """Validate mint-time structural invariants. Raises ValueError.

        SEC-18 / V7 v7.39 PR-3: reject a zero/absent `grantee` at issuance
        (defense-in-depth, fail-fast). Mirrors Go's
        `CapabilityTokenData.ValidateStructure()`. The chain-walk grantee
        resolution in delegation.py already rejects such caps at use time
        with `unresolvable_grantee`; failing here surfaces the error to the
        issuer instead of leaving a dud cap bound. Role-layer mint paths
        (role.py `:assign` / `:delegate`) carry their own protocol-level
        rejection; this guards the generic capability paths uniformly.
        """
        if grantee_is_zero(self.grantee):
            raise ValueError(
                "capability grantee MUST be a non-zero hash "
                "(SEC-18 / V7 v7.39 PR-3 — a zero-hash grantee never "
                "resolves to a system/identity entity)"
            )

    def has_caveat(self, caveat_name: str) -> bool:
        """Check if this token has a specific delegation caveat set."""
        if not self.delegation_caveats:
            return False
        if caveat_name == "no_delegation":
            return self.delegation_caveats.no_delegation is True
        elif caveat_name == "max_delegation_depth":
            return self.delegation_caveats.max_delegation_depth is not None
        elif caveat_name == "max_delegation_ttl":
            return self.delegation_caveats.max_delegation_ttl is not None
        return False

    def get_caveat_limit(self, caveat_name: str) -> int | None:
        """Get the limit for a specific caveat, or None if not present."""
        if not self.delegation_caveats:
            return None
        if caveat_name == "max_delegation_depth":
            return self.delegation_caveats.max_delegation_depth
        elif caveat_name == "max_delegation_ttl":
            return self.delegation_caveats.max_delegation_ttl
        return None

    @classmethod
    def create_full_access(
        cls,
        granter: Hash,
        grantee: Hash,
        expires_at: int | None = None,
    ) -> CapabilityToken:
        """Create a token granting full access.

        V4: Signature is found via target-matching, not stored in token.

        Args:
            granter: Hash bytes of granter identity.
            grantee: Hash bytes of grantee identity.
            expires_at: Optional expiration timestamp.

        Returns:
            A CapabilityToken with full access.
        """
        # Per V7 §1.4 / §5.4 strict cap-resource canonicalization: bare `*`
        # canonicalizes to `/{granter_peer_id}/*` (local-namespace only).
        # `/*/*` + `peers=["*"]` is required for cross-peer authority (e.g.,
        # writing V7 invariant signature pointers under other peers'
        # namespaces). Both forms are kept so backward-compat code that
        # constructs `*` paths still authorizes against the local namespace.
        return cls(
            grants=[
                Grant.create(
                    handlers=["*"],
                    resources=["*", "/*/*"],
                    operations=["*"],
                    peers=["*"],
                ),
            ],
            granter=granter,
            grantee=grantee,
            expires_at=expires_at,
        )
