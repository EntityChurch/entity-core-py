"""Length-prefixed TCP framing.

The Entity Core Protocol uses length-prefixed frames over TCP:
  [4 bytes: length (big-endian)] [length bytes: CBOR payload]

Maximum message size is configurable but defaults to 16 MB.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import Any

from entity_core.protocol.envelope import Envelope
from entity_core.utils.ecf import (
    Hash,
    compute_ecf_hash,
    ecf_decode,
    ecf_encode,
    get_hash_algorithm,
    hash_equals,
    hash_to_display,
    validate_hash,
)

# Maximum message size (16 MB default)
MAX_MESSAGE_SIZE = 16 * 1024 * 1024

logger = logging.getLogger(__name__)


class FramingError(Exception):
    """Error during message framing/deframing."""

    pass


class HashValidationError(Exception):
    """Entity content_hash doesn't match computed hash."""

    pass


def _format_value_for_debug(value: Any, max_bytes: int = 64) -> str:
    """Format a value for debug logging, truncating large bytes."""
    if isinstance(value, bytes):
        if len(value) <= max_bytes:
            return f"bytes({len(value)}): {value.hex()}"
        return f"bytes({len(value)}): {value[:max_bytes].hex()}..."
    elif isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {_format_value_for_debug(v)}" for k, v in sorted(value.items())) + "}"
    elif isinstance(value, list):
        if len(value) <= 3:
            return "[" + ", ".join(_format_value_for_debug(v) for v in value) + "]"
        return f"[{len(value)} items]"
    elif isinstance(value, str):
        if len(value) <= 100:
            return repr(value)
        return repr(value[:100]) + "..."
    else:
        return repr(value)


def validate_entity_hash(entity: dict[str, Any]) -> Hash:
    """Validate that an entity's content_hash matches its content.

    Per spec section 1.3.1, implementations MUST:
    1. Compute the hash of the received {type, data}
    2. Compare against the claimed content_hash
    3. Reject the entity if they don't match

    Args:
        entity: The entity dict with type, data, and content_hash.

    Returns:
        The validated hash (bytes).

    Raises:
        HashValidationError: If content_hash doesn't match or is missing.
    """
    content_hash = entity.get("content_hash")
    if not content_hash:
        raise HashValidationError("Entity missing content_hash")

    # Parse claimed hash from wire format
    try:
        if not isinstance(content_hash, bytes):
            raise HashValidationError(f"Invalid content_hash type: {type(content_hash)}")
        validate_hash(content_hash)
        claimed = content_hash
    except ValueError as e:
        raise HashValidationError(f"Invalid hash format: {e}")

    # Compute hash from {type, data} only using ECF (CBOR canonical form).
    # V7 v7.69 §4.5a — recompute under the format the entity was authored
    # under (the self-describing leading byte of the claimed hash), NOT the
    # process-global default. A peer receiving a SHA-384-authored entity on a
    # connection whose active format is anything must still validate it; the
    # content_hash is self-describing, so validation reads its format code.
    hashable = {"type": entity.get("type"), "data": entity.get("data")}
    computed = compute_ecf_hash(hashable, get_hash_algorithm(claimed))

    # Compare hashes (V4: simple bytes comparison)
    if not hash_equals(claimed, computed):
        entity_type = entity.get("type", "unknown")
        entity_data = entity.get("data", {})

        # Log detailed debug info
        logger.error(
            "Hash mismatch for entity type=%s\n"
            "  Claimed: %s\n"
            "  Computed: %s\n"
            "  Data fields: %s\n"
            "  Data field types: %s",
            entity_type,
            hash_to_display(claimed),
            hash_to_display(computed),
            list(entity_data.keys()) if isinstance(entity_data, dict) else type(entity_data),
            {k: type(v).__name__ for k, v in entity_data.items()} if isinstance(entity_data, dict) else "N/A",
        )

        # Log each field value for debugging
        if isinstance(entity_data, dict):
            for key, value in sorted(entity_data.items()):
                logger.debug("  Field %s: %s", key, _format_value_for_debug(value))

        # Log the ECF bytes for comparison
        ecf_bytes = ecf_encode(hashable)
        logger.debug("  ECF bytes (%d): %s", len(ecf_bytes), ecf_bytes.hex())

        raise HashValidationError(
            f"Hash mismatch: claimed {hash_to_display(claimed)}, "
            f"computed {hash_to_display(computed)}"
        )

    return claimed


async def send_envelope(writer: asyncio.StreamWriter, envelope: Envelope) -> None:
    """Send a length-prefixed envelope over the wire.

    Args:
        writer: AsyncIO stream writer.
        envelope: The envelope to send.

    Raises:
        FramingError: If the message exceeds maximum size.
    """
    payload = ecf_encode(envelope.to_dict())

    if len(payload) > MAX_MESSAGE_SIZE:
        raise FramingError(f"Message too large: {len(payload)} bytes (max {MAX_MESSAGE_SIZE})")

    # Debug logging similar to Go/Rust peers
    if logger.isEnabledFor(logging.DEBUG):
        root = envelope.root
        root_type = root.get("type", "unknown") if isinstance(root, dict) else "unknown"
        root_hash = root.get("content_hash") if isinstance(root, dict) else None
        hash_display = hash_to_display(root_hash)[:16] + ".." if root_hash else "none"
        included_count = len(envelope.included) if envelope.included else 0
        logger.debug(
            "[wire] -> send root_type=%s content_hash=%s included_count=%d size=%d",
            root_type, hash_display, included_count, len(payload)
        )

    length = struct.pack(">I", len(payload))
    writer.write(length + payload)
    await writer.drain()


async def send_raw_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Send pre-encoded ECF bytes verbatim as one length-prefixed frame.

    Unlike :func:`send_envelope`, this performs NO decode/re-encode of the
    payload — it writes the exact bytes given. Used by the EXTENSION-RELAY
    §3.1.1 terminal hop (§9 / §10.4): the relay forwards the source's
    original inner-envelope bytes unchanged, so the destination verifies the
    source's signature + capability chain exactly as on a direct connection.

    Args:
        writer: AsyncIO stream writer.
        payload: The pre-encoded envelope bytes (ECF of ``{root, included}``).

    Raises:
        FramingError: If the payload is empty or exceeds maximum size.
    """
    if not payload:
        raise FramingError("Empty raw frame")
    if len(payload) > MAX_MESSAGE_SIZE:
        raise FramingError(
            f"Message too large: {len(payload)} bytes (max {MAX_MESSAGE_SIZE})"
        )
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()


async def recv_envelope(
    reader: asyncio.StreamReader,
    validate_hashes: bool = True,
) -> Envelope:
    """Receive a length-prefixed envelope from the wire.

    Args:
        reader: AsyncIO stream reader.
        validate_hashes: Whether to validate content_hash on all entities.

    Returns:
        The received Envelope.

    Raises:
        FramingError: If the message is malformed or too large.
        HashValidationError: If any entity's content_hash doesn't match.
        asyncio.IncompleteReadError: If connection closed during read.
    """
    length_bytes = await reader.readexactly(4)
    length = struct.unpack(">I", length_bytes)[0]

    if length > MAX_MESSAGE_SIZE:
        raise FramingError(f"Message too large: {length} bytes (max {MAX_MESSAGE_SIZE})")

    if length == 0:
        raise FramingError("Empty message")

    payload = await reader.readexactly(length)

    try:
        data = ecf_decode(payload)
    except Exception as e:
        logger.error("[wire] <- recv CBOR decode error: %s (payload %d bytes: %s...)",
                     e, len(payload), payload.hex()[:64])
        raise FramingError(f"Invalid CBOR payload: {e}") from e

    # Debug logging similar to Go/Rust peers
    if logger.isEnabledFor(logging.DEBUG):
        root = data.get("root", {})
        root_type = root.get("type", "unknown") if isinstance(root, dict) else "unknown"
        root_hash = root.get("content_hash") if isinstance(root, dict) else None
        hash_display = hash_to_display(root_hash)[:16] + ".." if root_hash else "none"
        included = data.get("included", {})
        included_count = len(included) if isinstance(included, (dict, list)) else 0
        logger.debug(
            "[wire] <- recv root_type=%s content_hash=%s included_count=%d size=%d",
            root_type, hash_display, included_count, len(payload)
        )

    # Validate all entity hashes before accepting
    if validate_hashes:
        # Validate root entity
        root = data.get("root", {})
        if root.get("content_hash"):  # Only validate if hash is present
            try:
                validate_entity_hash(root)
            except HashValidationError as e:
                logger.error("Hash validation failed for ROOT entity")
                raise

        # Validate all included entities
        included = data.get("included", {})
        if isinstance(included, dict):
            for entity_hash, entity in included.items():
                try:
                    validate_entity_hash(entity)
                except HashValidationError as e:
                    key_display = entity_hash.hex() if isinstance(entity_hash, bytes) else str(entity_hash)
                    logger.error("Hash validation failed for INCLUDED entity at key=%s", key_display[:16] + "...")
                    raise
        elif isinstance(included, list):
            for idx, entity in enumerate(included):
                if entity.get("content_hash"):
                    try:
                        validate_entity_hash(entity)
                    except HashValidationError as e:
                        logger.error("Hash validation failed for INCLUDED entity at index=%d", idx)
                        raise

    return Envelope.from_dict(data)


async def send_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    """Send a message as an envelope with no included entities.

    Convenience function for simple messages.

    Args:
        writer: AsyncIO stream writer.
        message: The message entity dict.
    """
    await send_envelope(writer, Envelope(root=message))


async def recv_message(reader: asyncio.StreamReader) -> dict[str, Any]:
    """Receive a message, returning just the root entity.

    Convenience function when included entities aren't needed.

    Args:
        reader: AsyncIO stream reader.

    Returns:
        The root message entity dict.
    """
    envelope = await recv_envelope(reader)
    return envelope.root
