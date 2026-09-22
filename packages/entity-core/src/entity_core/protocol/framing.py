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
    """Error during message framing/deframing.

    .. rubric:: A pre-admission refusal carries its own code AND its own
       stream disposition (§4.11, 0.8.2.25)

    §4.11 makes the coded frame an obligation of the **class** and the code an
    obligation of the **cause**, so this exception carries the pair rather
    than letting the serve loop re-derive it from the message text. Three
    causes reach this boundary and the corpus gives them three answers:

    * **oversize** (§4.10(a)) → **413** ``payload_too_large``
    * **un-parseable CBOR** (§4.7, §4.11) → **400** ``invalid_request``
    * **a truncated payload** (§4.7, §4.11) → **400** ``invalid_request``

    .. rubric:: ``stream_synchronized`` — the axis §4.11 does not name, and
       the one that decides whether arm (f) is satisfiable

    §4.11 says *"whether the peer closes the connection afterwards is its own
    choice"*, and §9's ``CORE-PREADMISSION-REFUSAL-1`` arm **(f)** requires
    that a pre-admission refusal on a **multiplexed** connection not cost an
    admitted in-flight request its response (§4.9(c)). Those two can only both
    hold where the refusal leaves the stream **synchronized** — i.e. where a
    whole length-prefixed frame was consumed and the next read starts on a
    frame boundary:

    * **un-parseable CBOR with a complete payload** — the frame was consumed
      whole, so the next boundary is known. The connection CAN survive, and
      arm (f) says it must. ``stream_synchronized = True``.
    * **a truncated payload** — the sender promised ``length`` bytes and sent
      fewer. There is no way to find the next boundary, so a peer that kept
      reading would interpret the *next* frame's bytes as the tail of this
      one. The close is forced, not chosen. ``stream_synchronized = False``.
    * **oversize** — detected at the length prefix with ``length`` bytes still
      in the socket. Draining them to resynchronize is exactly the unbounded
      read §4.10(a) exists to refuse, so the close is forced here too.
      ``stream_synchronized = False``.

    **This is routed (SA-PY-62).** §4.11 presents the class as uniform on the
    close and then asks arm (f) of the one arm — *"(a) a truncated /
    un-parseable CBOR frame"* — that spans both dispositions. The truncated
    half of arm (a) cannot satisfy arm (f) at any conformant peer.
    """

    #: HTTP-style status for the coded frame this refusal owes.
    status: int = 400
    #: §3.3 ``code`` naming the cause, so the caller's remedy is selectable.
    code: str = "invalid_request"
    #: Whether the next read starts on a frame boundary. See the rubric.
    stream_synchronized: bool = True


class PayloadTooLargeError(FramingError):
    """The declared frame length exceeds the configured maximum (§4.10(a)).

    **413** ``payload_too_large``, and the close is forced: the length prefix
    has been consumed and ``length`` bytes remain unread, so the stream cannot
    be resynchronized without performing the very read that was refused.

    *(0.8.2.25 — §4.10(a)'s emission was `SHOULD` + `MAY close` and is now a
    `[MUST]` governed by §4.11. This peer previously answered this arm with
    `400 invalid_request`, because the oversize check raised a bare
    ``FramingError`` and the serve loop had one code for every one of them.)*
    """

    status = 413
    code = "payload_too_large"
    stream_synchronized = False


class FrameTruncatedError(FramingError):
    """The sender declared ``length`` bytes and the stream ended early.

    **400** ``invalid_request`` (§4.7, §4.11), and the close is forced — see
    :class:`FramingError`'s ``stream_synchronized`` rubric.

    .. rubric:: This is NOT an ordinary disconnect, and conflating the two is
       how the coded frame went missing

    Both a truncated frame and a peer hanging up cleanly surface as
    ``asyncio.IncompleteReadError`` from ``readexactly``. They are different
    events with opposite obligations:

    * **nothing consumed at a frame boundary** — the peer closed between
      frames. No frame was ever offered, so there is nothing to refuse and
      §4.11 does not reach it. Silence is correct.
    * **a length prefix consumed, then a short payload** — the peer offered a
      frame and the frame is malformed. That is arm (a), and it owes
      ``400 invalid_request``.

    The serve loop caught ``IncompleteReadError`` first and logged *"peer hung
    up cleanly"* for both, so every truncated frame was answered with a **bare
    close** — the failure §4.11 names as indistinguishable from a network
    fault. Raising a distinct type is what lets the loop tell them apart.
    """

    status = 400
    code = "invalid_request"
    stream_synchronized = False


class HashValidationError(Exception):
    """Entity content_hash doesn't match computed hash.

    .. rubric:: ``request_id`` — the correlation N4 asks for (0.8.2.24)

    §5.2a: *"A peer that refuses at the decode boundary MUST emit the coded
    response correlated by ``request_id`` where the id is available, and
    otherwise MUST make a best-effort coded frame before closing."*

    The id is available **exactly when the root decoded and only an included
    entry is bad** — which is the shape of the §1.8 forgery this row exists
    for: the root is a valid EXECUTE and the attacker has mis-stamped an
    entity in ``included``. So the receive path records the id on the way past
    rather than making the serve loop re-parse a payload it has just been told
    not to trust.

    ``None`` means *no reliable id* (the root itself failed, or carried none),
    and the caller emits the best-effort frame with an empty id.
    """

    def __init__(self, message: str, *, request_id: str | None = None) -> None:
        super().__init__(message)
        self.request_id = request_id


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
        PayloadTooLargeError: Declared length over the maximum (413, §4.10(a)).
        FrameTruncatedError: A frame was offered and the stream ended early.
        FramingError: The payload is whole and does not decode (400).
        HashValidationError: If any entity's content_hash doesn't match.
        asyncio.IncompleteReadError: Clean EOF **at a frame boundary** — the
            peer hung up between frames. No frame was offered, so §4.11 does
            not reach it and the caller should treat it as an ordinary
            disconnect. Every *other* short read raises
            :class:`FrameTruncatedError` instead.
    """
    # §4.11 (0.8.2.25) — a clean EOF here is an ordinary disconnect and owes
    # nothing; a PARTIAL length prefix is a frame the sender began and did not
    # finish, which is arm (a) and owes a coded frame. `readexactly` reports
    # both as IncompleteReadError, so the discriminator is `e.partial`.
    try:
        length_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            raise
        raise FrameTruncatedError(
            f"length prefix truncated: got {len(e.partial)} of 4 bytes",
        ) from e
    length = struct.unpack(">I", length_bytes)[0]

    if length > MAX_MESSAGE_SIZE:
        # §4.10(a)/§4.11 — 413, not the generic 400. `length` bytes are still
        # in the socket and draining them is the read we are refusing, so
        # `stream_synchronized` is False and the caller closes.
        raise PayloadTooLargeError(
            f"Message too large: {length} bytes (max {MAX_MESSAGE_SIZE})",
        )

    if length == 0:
        raise FramingError("Empty message")

    # A short payload is a truncated FRAME, never a clean hangup: the sender
    # has already told us how many bytes to expect.
    try:
        payload = await reader.readexactly(length)
    except asyncio.IncompleteReadError as e:
        raise FrameTruncatedError(
            f"payload truncated: got {len(e.partial)} of {length} bytes",
        ) from e

    try:
        data = ecf_decode(payload)
    except Exception as e:
        logger.error("[wire] <- recv CBOR decode error: %s (payload %d bytes: %s...)",
                     e, len(payload), payload.hex()[:64])
        raise FramingError(f"Invalid CBOR payload: {e}") from e

    # §4.11 — "NEVER BECOMES AN ENVELOPE" IS WIDER THAN "DOES NOT DECODE".
    #
    # A payload can decode perfectly and still not be an envelope: `\xf6` is
    # a valid CBOR null, `\xff` decodes to a break marker, `42` is an integer.
    # None of them is a map, so none of them has a `root`.
    #
    # ⛔ This check was absent, and its absence was invisible because the
    # NEXT line is `data.get("root")` — so a non-map payload raised a bare
    # `AttributeError: 'BreakMarkerType' object has no attribute 'get'` out of
    # the framing layer. It still reached the serve loop's catch-all and still
    # produced a coded 400, which is why no row noticed; what it did not carry
    # was `stream_synchronized`, so the peer closed a connection it could have
    # kept — §9 arm (f) — and the refusal's code came from a fallback rather
    # than from the cause.
    #
    # It also means the pre-existing N4 row named
    # `test_undecodable_cbor_still_gets_a_coded_frame` was driving an
    # AttributeError on a payload that DOES decode, not un-parseable CBOR:
    # `b"\xff\xff\xff\xff not cbor"` is a break marker followed by bytes the
    # decoder never reaches. The standing law — *your fixture is not the
    # discriminating configuration* — with the decoder as the filter.
    if not isinstance(data, dict):
        raise FramingError(
            "frame decoded but is not an envelope map: "
            f"{type(data).__name__}",
        )

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
                # No correlation: the root is the thing that failed, so its
                # `request_id` is not a value this peer may rely on (§4.10(a)).
                raise HashValidationError(str(e), request_id=None) from e

        # §5.2a/N4 (0.8.2.24): the id to correlate a decode-boundary refusal
        # by. Read only after the ROOT has validated, so it is the id of a
        # frame whose envelope really is what it says it is — which is the
        # forgery shape: valid EXECUTE root, mis-stamped `included` entry.
        request_id = None
        if isinstance(root, dict):
            root_data = root.get("data")
            if isinstance(root_data, dict):
                candidate = root_data.get("request_id")
                if isinstance(candidate, str):
                    request_id = candidate

        # Validate all included entities
        included = data.get("included", {})
        if isinstance(included, dict):
            for entity_hash, entity in included.items():
                try:
                    validate_entity_hash(entity)
                except HashValidationError as e:
                    key_display = entity_hash.hex() if isinstance(entity_hash, bytes) else str(entity_hash)
                    logger.error("Hash validation failed for INCLUDED entity at key=%s", key_display[:16] + "...")
                    raise HashValidationError(
                        str(e), request_id=request_id,
                    ) from e
        elif isinstance(included, list):
            for idx, entity in enumerate(included):
                if entity.get("content_hash"):
                    try:
                        validate_entity_hash(entity)
                    except HashValidationError as e:
                        logger.error("Hash validation failed for INCLUDED entity at index=%d", idx)
                        raise HashValidationError(
                            str(e), request_id=request_id,
                        ) from e

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
