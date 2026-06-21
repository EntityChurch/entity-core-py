"""Message envelope with included entities.

The Envelope is the wire format for Entity Core messages.
It contains a root message (the main protocol message) and
an optional list of included entities that are referenced.

V4 Changes:
- content_hash is bytes (algorithm byte + digest)
- included map keys are bytes (the hash)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from entity_core.utils.ecf import Hash, hash_equals, normalize_hash

# Use shared normalize_hash from ecf module
_normalize_hash = normalize_hash


@dataclass
class Envelope:
    """Wire format envelope containing root message and included entities.

    Attributes:
        root: The main protocol message (HELLO, EXECUTE, etc.).
        included: Referenced entities (capabilities, identities, signatures).
    """

    root: dict[str, Any]
    included: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Per spec §4.5: included is a map keyed by hash bytes (33 bytes).

        Returns:
            Dictionary suitable for CBOR serialization.
        """
        result: dict[str, Any] = {"root": self.root}
        # Always include 'included' for wire compatibility
        if self.included:
            # Convert list to dict keyed by hash bytes for wire format
            # Per spec §4.5: hash on wire is bytes (algorithm byte + digest)
            included_dict: dict[bytes, dict[str, Any]] = {}
            for entity_dict in self.included:
                # Use existing content_hash if present (for received entities)
                # Only compute if missing (for entities we created)
                if "content_hash" in entity_dict:
                    entity_hash = entity_dict["content_hash"]
                    # Ensure it's bytes for the key
                    key = _normalize_hash(entity_hash)
                    if key is not None:
                        included_dict[key] = entity_dict
                else:
                    from entity_core.protocol.entity import Entity
                    entity = Entity.from_dict(entity_dict)
                    h = entity.compute_hash()
                    wire_entity = entity_dict.copy()
                    wire_entity["content_hash"] = h
                    included_dict[h] = wire_entity
            result["included"] = included_dict
        else:
            result["included"] = {}
        return result

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Envelope:
        """Create Envelope from dictionary.

        Per spec §3.1: included is a map keyed by system/hash.
        Keys are bytes in V4.

        Args:
            d: Dictionary with root and optional included.

        Returns:
            An Envelope instance.
        """
        included_raw = d.get("included", {})

        # Wire `included` is a map {hash: entity, ...}; internal repr is a list.
        if isinstance(included_raw, dict):
            included = list(included_raw.values())
        else:
            included = []

        return cls(
            root=d["root"],
            included=included,
        )

    def find_included(self, hash_ref: bytes | str | dict[str, Any]) -> dict[str, Any] | None:
        """Find an included entity by its hash.

        Uses the content_hash from the received entity - does NOT recompute.
        Entities should have been validated on receipt.

        Args:
            hash_ref: The hash to search for (bytes, string, or structured).

        Returns:
            The matching entity dict, or None if not found.
        """
        # Normalize the search key to bytes
        search_hash = _normalize_hash(hash_ref)
        if search_hash is None:
            return None

        for entity_dict in self.included:
            # Use the content_hash from the wire (validated on receipt)
            # Do NOT recompute - that could produce different results
            entity_hash = entity_dict.get("content_hash")
            if entity_hash is not None:
                entity_hash_normalized = _normalize_hash(entity_hash)
                if hash_equals(entity_hash_normalized, search_hash):
                    return entity_dict
        return None

    def find_signature_for_target(self, target_hash: bytes | str | dict[str, Any]) -> dict[str, Any] | None:
        """Find a signature entity that signs the given target.

        V4 target-matching: scan included entities for a signature
        whose data.target matches the target_hash.

        Args:
            target_hash: The target hash to find a signature for.

        Returns:
            The matching signature entity dict, or None if not found.
        """
        target_normalized = _normalize_hash(target_hash)
        if target_normalized is None:
            return None

        for entity_dict in self.included:
            # Check if this is a signature entity
            if entity_dict.get("type") == "system/signature":
                sig_data = entity_dict.get("data", {})
                sig_target = sig_data.get("target")
                if sig_target is not None:
                    sig_target_normalized = _normalize_hash(sig_target)
                    if hash_equals(sig_target_normalized, target_normalized):
                        return entity_dict
        return None

    def find_signature_by_signer(
        self,
        target_hash: bytes | str | dict[str, Any],
        signer_hash: bytes | str | dict[str, Any],
    ) -> dict[str, Any] | None:
        """Find a signature entity that signs the given target by a specific signer.

        PROPOSAL-MULTISIG-CORE-PRIMITIVE §4.0: multi-sig verification needs to
        locate signatures by *both* target and signer, since multiple
        constituents sign the same target. This is the by-signer variant of
        `find_signature_for_target`.

        Args:
            target_hash: The target hash to find a signature for.
            signer_hash: The identity hash of the required signer.

        Returns:
            The matching signature entity dict, or None if not found.
        """
        target_normalized = _normalize_hash(target_hash)
        signer_normalized = _normalize_hash(signer_hash)
        if target_normalized is None or signer_normalized is None:
            return None

        for entity_dict in self.included:
            if entity_dict.get("type") != "system/signature":
                continue
            sig_data = entity_dict.get("data", {})
            sig_target = sig_data.get("target")
            sig_signer = sig_data.get("signer")
            if sig_target is None or sig_signer is None:
                continue
            if not hash_equals(_normalize_hash(sig_target), target_normalized):
                continue
            if not hash_equals(_normalize_hash(sig_signer), signer_normalized):
                continue
            return entity_dict
        return None
