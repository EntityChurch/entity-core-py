"""Entity structure and content addressing.

The Entity is the fundamental data unit in the Entity Core Protocol.
Each entity has a type and data, with optional URI.

V4 Changes:
- content_hash is bytes (algorithm byte + digest)
- refs field removed (V4 refless architecture)
- References are now embedded in data as system/hash values
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from entity_core.utils.ecf import (
    Hash,
    compute_ecf_hash,
    get_default_hash_algorithm,
    validate_hash,
)

# Top-level wire keys the Entity models explicitly; everything else is an
# unknown/forward-compat field preserved verbatim in `extra` (§1.8 #5).
_RESERVED_WIRE_KEYS = frozenset({"type", "data", "uri", "content_hash"})


@dataclass
class Entity:
    """The fundamental data unit in Entity Core.

    Attributes:
        type: What this entity IS (e.g., "file", "status").
        data: The JSON payload.
        uri: Optional location address.
        content_hash: The *validated* hash carried from the wire (§1.8).
            Set only for entities received over the wire (via
            ``from_wire_dict``, after the framing layer validated it);
            ``None`` for entities constructed locally. When set, it is
            trusted verbatim and MUST NOT be recomputed.
        extra: Unknown top-level fields preserved verbatim from the wire so
            they survive store + forward (§1.8 #5, forward-compat).

    Note: V4 uses refless architecture - references are embedded in data
    as system/hash values, not in a separate refs field.

    Entity fidelity (§1.8): a received entity is validated on receipt and
    then carried unchanged — its claimed hash and any unknown fields ride
    through store + forward without recompute or re-serialization. Do not
    mutate a received entity's ``data`` and then read ``compute_hash()`` —
    it intentionally returns the carried hash, not a fresh one.
    """

    type: str
    data: dict[str, Any]
    uri: str | None = None
    content_hash: Hash | None = field(default=None, compare=False)
    extra: dict[str, Any] = field(default_factory=dict, compare=False)
    # V7 v7.69 §4.5a — the content_hash_format to author this entity under.
    # ``None`` means "use the process-global default" (non-connection-bound
    # authoring). Connection-bound authoring sets this to the connection's
    # negotiated active format so a peer whose home default differs from the
    # negotiated value still authors uniformly on that connection. Ignored for
    # received entities (a carried ``content_hash`` is trusted verbatim, §1.8).
    hash_algorithm: int | None = field(default=None, compare=False)

    def compute_hash(self) -> Hash:
        """Return the content hash: algorithm byte + DIGEST(ECF({type, data})).

        Per §1.8: when a validated hash was carried from the wire
        (``content_hash`` is set), it is trusted and returned as-is — we
        MUST NOT recompute. Otherwise the hash is computed from
        ``{type, data}`` (uri and unknown fields are not part of the hash)
        under ``hash_algorithm`` (or the process-global default when unset).

        Returns:
            Hash as bytes (33 bytes for SHA-256, 49 for SHA-384).
        """
        if self.content_hash is not None:
            return self.content_hash
        algorithm = (
            self.hash_algorithm
            if self.hash_algorithm is not None
            else get_default_hash_algorithm()
        )
        hashable = {"type": self.type, "data": self.data}
        return compute_ecf_hash(hashable, algorithm)

    def to_dict(self, include_hash: bool = True) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Per I2 (ENTITY-CORE-PROTOCOL v7.11 §1.1): all entities carry
        content_hash. The default includes it. Pass include_hash=False
        only for internal representations that explicitly don't need it.

        For a received entity this reproduces the wire form: the carried
        hash and any preserved unknown top-level fields are re-emitted
        verbatim (§1.8 forward-original).

        Args:
            include_hash: Include content_hash field (default True per I2).

        Returns:
            Dictionary representation with content_hash included by default.
        """
        result: dict[str, Any] = {"type": self.type, "data": self.data}
        if include_hash:
            result["content_hash"] = self.compute_hash()
        if self.uri:
            result["uri"] = self.uri
        # Preserve unknown top-level fields verbatim (never clobber a
        # modeled key).
        for k, v in self.extra.items():
            result.setdefault(k, v)
        return result

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Entity:
        """Create Entity from a locally-constructed dictionary.

        Computes the hash on demand from ``{type, data}`` — use for
        entities authored locally. For entities received over the wire,
        use ``from_wire_dict`` so the validated hash is carried (§1.8).

        Args:
            d: Dictionary with type, data, and optional uri.

        Returns:
            An Entity instance.
        """
        return cls(
            type=d["type"],
            data=d["data"],
            uri=d.get("uri"),
        )

    @classmethod
    def from_wire_dict(cls, d: dict[str, Any]) -> tuple["Entity", Hash]:
        """Create an Entity from a wire dict, carrying the claimed hash (§1.8).

        This is the *trust* half of §1.8 that pairs with receipt validation
        (``framing.validate_entity_hash``): the hash has already been
        verified against ``{type, data}`` upstream, so we carry it verbatim
        rather than recompute, and we preserve any unknown top-level fields
        so the entity stays byte-faithful through store + forward.

        Args:
            d: Dictionary with type, data, content_hash, and optional uri.

        Returns:
            Tuple of (Entity, claimed_hash).

        Raises:
            ValueError: If content_hash is missing or structurally invalid.
        """
        if "content_hash" not in d:
            raise ValueError("Wire entity must have content_hash")

        # Parse content_hash from wire format (raw bytes: algorithm + digest)
        raw_hash = d["content_hash"]
        if not isinstance(raw_hash, bytes):
            raise ValueError(f"Invalid content_hash format: {type(raw_hash)}")
        validate_hash(raw_hash)

        extra = {k: v for k, v in d.items() if k not in _RESERVED_WIRE_KEYS}
        entity = cls(
            type=d["type"],
            data=d["data"],
            uri=d.get("uri"),
            content_hash=raw_hash,
            extra=extra,
        )
        return entity, raw_hash
