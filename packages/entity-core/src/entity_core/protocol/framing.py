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
    UnsupportedContentHashFormatError,
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


def validate_entity_structure(value: Any) -> str | None:
    """Return why ``value`` does not decode as an entity, or ``None``.

    The *structural* half of receipt validation, and the half that MUST run
    **before** :func:`validate_entity_hash` — EXTENSION-TREE Appendix A (v4.4)
    splits a bad submission into two 400 rows and the split is only
    expressible if structure is decided first:

    * *does not decode* → ``invalid_request`` (§3.3's generic 400 default);
    * *decodes, but the claimed hash is not its hash* → ``hash_mismatch``.

    A malformed entity that also carries a hash satisfies both descriptions,
    so an implementation that validates the hash first answers
    ``hash_mismatch`` for a submission whose real defect is its shape.
    Both siblings order it structure-first for exactly this reason
    (`entity-core-go` ``core/tree/handler.go`` decode-then-``Validate``,
    `entity-core-rust` ``core/tree/src/lib.rs`` ``decode_entity_from_cbor``
    then ``entity.validate``).

    Python is the seat that needs this stated as a function. Go and Rust
    decode into a typed ``Entity``, so *"does not decode"* is a language
    event they get for free; ``cbor2`` hands back a native mapping, so every
    shape below reaches the handler intact and fails later — as a
    ``TypeError``/``KeyError`` on the far side of the hash check, i.e. as a
    client-triggerable ``500``.

    **Ruled at 0.8.2.11 / EXTENSION-TREE v4.5, and the predicate we routed as
    SA-PY-41 was the answer.** The corpus did not need a new sentence: §3.9
    types ``put-request.entity`` as ``core/entity``, and
    ``ENTITY-NATIVE-TYPE-SYSTEM`` §8.1 declares that type with three fields and
    no ``optional`` marker on any of them — so *"does not decode"* means *"is
    not a `core/entity`"*. Six homes carried the strong form; §2.8 — the only
    table in the corpus describing what is **on the wire** at a ``core/entity``
    slot, i.e. exactly this surface — carried ``content_hash?`` and was
    corrected in the same fold.

    ==============================  ======  ======  ==============================
    Shape                            go      rust    Refused here
    ==============================  ======  ======  ==============================
    not a map                        yes     yes     yes
    ``type`` absent                  yes     yes     yes
    ``type`` not a text string       yes     yes     yes
    ``data`` absent                  yes     yes     yes
    ``type`` empty string            yes     no      **yes** — ruled 0.8.2.11 §6.3
    ``data`` null / non-map          no      no      no
    ==============================  ======  ======  ==============================

    The empty-``type`` row was routed as SA-PY-41 row 7 rather than settled
    locally, and the ruling went go's way: §6.3 step 1 says **non-empty**
    text-string ``type``, derived from §2.7 (*"the name is the interop
    contract"*) plus 0.8.2.4's precedent that a present-but-empty ``protocols``
    is *"a malformed request"*. An empty interop contract is not a contract.

    ``data: null`` stays **accepted** — §6.3 step 1 says *any CBOR value*, and
    names null as a legal payload outright, because ``primitive/any`` is
    unconstrained. This function refuses a *missing* ``data``, never an empty
    one, and a seat that "tightens" it to falsiness partitions the cohort in
    the direction nothing measures.

    **``content_hash`` is not checked here** — see
    :func:`validate_carried_content_hash`. The two clauses are §6.3 step 1's
    two halves and both emit ``invalid_request`` at ``put``, but they are
    separate functions because the *shape* half also guards
    ``system/tree:merge``'s ``source_envelope`` members, which are ingested by
    a path the admission ladder does not govern. Folding the hash clause in
    here would have extended a ruled ``put`` rule to an unruled surface by
    accident of code reuse.

    Args:
        value: The candidate entity, as decoded off the wire.

    Returns:
        A human-readable reason, or ``None`` when the shape decodes.
    """
    if not isinstance(value, dict):
        return f"entity must be a map, got {type(value).__name__}"
    if "type" not in value:
        return "entity is missing 'type'"
    if not isinstance(value["type"], str):
        return (
            "entity 'type' must be a text string, got "
            f"{type(value['type']).__name__}"
        )
    if value["type"] == "":
        return "entity 'type' is empty"
    if "data" not in value:
        return "entity is missing 'data'"
    return None


def validate_carried_content_hash(entity: dict[str, Any]) -> tuple[str, str] | None:
    """§6.3 step 1's ``content_hash`` clause. Returns ``(code, reason)`` or ``None``.

    ``put`` is a **receipt** path (0.8.2.11 §6.3, §1.8 item 1): the submitter
    authors the entity, the peer validates what it received, and a peer
    **MUST NOT** author a submitted entity's ``content_hash`` on the
    submitter's behalf. The authoring step exists and belongs to the SDK —
    ``SDK-OPERATIONS`` §3.2's ``put(path, type, data) → hash`` cannot return a
    hash it did not compute.

    Two codes come out of this one clause, and the split is
    ``ENTITY-CORE-PROTOCOL`` §4.7 row 5 restated on EXTENSION-TREE Appendix A
    v4.5:

    * **absent, null, not a bstr, or mis-sized for its format code** — the
      value never was a ``system/hash``, so the entity is not a
      ``core/entity``: ``400 invalid_request`` (row 1).
    * **well-formed but naming a format code this peer does not support** —
      the value *is* a structurally valid hash and the peer simply cannot
      verify it: ``400 unsupported_content_hash_format`` (row 4). Not row 1,
      and the distinction is caller-actionable: row 1 says *fix your request*,
      row 4 says *this peer cannot speak your format*.

    The order below is :func:`entity_core.utils.ecf.validate_hash`'s own —
    format code first, then digest length — which is the only order that has an
    answer, since the expected length is a function of the format code.

    Args:
        entity: A value that has already passed :func:`validate_entity_structure`.

    Returns:
        ``(code, reason)`` for a refusal, or ``None`` when the carried hash is
        well-formed and verifiable here.
    """
    if entity.get("content_hash") is None:
        return (
            "invalid_request",
            "entity is missing 'content_hash' — `put` is a receipt path and "
            "the peer does not author one (0.8.2.11 §6.3; the SDK's "
            "construction step is SDK-OPERATIONS §3.2)",
        )
    claimed = entity["content_hash"]
    if not isinstance(claimed, bytes):
        return (
            "invalid_request",
            f"entity 'content_hash' must be a byte string, got {type(claimed).__name__}",
        )
    try:
        validate_hash(claimed)
    except UnsupportedContentHashFormatError as exc:
        return ("unsupported_content_hash_format", str(exc))
    except ValueError as exc:
        return ("invalid_request", f"entity 'content_hash' is not a hash: {exc}")
    return None


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

    This is **step 2** of ``put``'s admission ladder (0.8.2.11 §6.3) and it
    presupposes step 1: a caller that has an ``invalid_request`` row to answer
    runs :func:`validate_entity_structure` and
    :func:`validate_carried_content_hash` first, and only then arrives here
    with a value it knows is an entity carrying a parseable hash. The
    absent/unparseable arms below stay as a guard for the receipt sites that
    have no such ladder (``http_server``, ``http_client``), where a bad hash is
    a rejection and not a distinct wire row.

    Raises:
        HashValidationError: If content_hash doesn't match, is missing, or does
            not parse as a hash.
    """
    content_hash = entity.get("content_hash")
    if not content_hash:
        raise HashValidationError("Entity missing content_hash")

    try:
        if not isinstance(content_hash, bytes):
            raise HashValidationError(
                f"Invalid content_hash type: {type(content_hash)}"
            )
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
