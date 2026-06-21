"""D-13 `supported_ops` closed-enum vocabulary.

Per `EXTENSION-NETWORK.md` §6.5 (v1.4 Amendment 2) + PROPOSAL-EXTENSION-
NETWORK-TRANSPORT-FAMILY §7 (D-13). A transport profile's `supported_ops`
field declares which operation classes the endpoint physically carries.

The four active values terminate at distinct verification anchors:

- ``EXECUTE``      — full EXECUTE/EXECUTE-RESPONSE; live duplex transports
                     (``tcp`` / ``websocket``) and the half-duplex ``http``
                     wrapper (POST only).
- ``TREE_GET``     — passive tree-binding lookup; anchor = hash-chain from
                     a signed root.
- ``CONTENT_GET``  — passive content-addressed byte lookup; anchor = hash.
- ``MANIFEST_GET`` — passive signed-root / pointer lookup; anchor =
                     signature on the publisher's `system/peer/published-root`.

``SUBSCRIBE`` is reserved (push-capability is currently implicit in
transport duplexity); surface it only when a future transport needs
field-level push discrimination. It MUST NOT appear in v1 advertisements.

Live profiles advertise ``[EXECUTE]``. ``http-poll`` advertises any
non-empty subset of ``{TREE_GET, CONTENT_GET, MANIFEST_GET}`` — partial
publishers (content-only mirror, manifest-only registry) advertise only
the values they actually serve.

**Descriptive, never a grant.** ``supported_ops`` says what the endpoint
can physically carry; it does NOT authorize anything. Authorization is
the V7 grant-model's job (see ``capability/checking.py``). Treating
``supported_ops`` membership as a permission is the precise bug the
cap-axis ruling (RULING-NAMED-CAPABILITY-MAPPING) names.
"""

from __future__ import annotations

from typing import Final, FrozenSet

EXECUTE: Final[str] = "EXECUTE"
TREE_GET: Final[str] = "TREE_GET"
CONTENT_GET: Final[str] = "CONTENT_GET"
MANIFEST_GET: Final[str] = "MANIFEST_GET"

#: Reserved per D-13 — NOT a valid v1 advertisement value.
SUBSCRIBE_RESERVED: Final[str] = "SUBSCRIBE"

#: The four advertisable values for v1 conformance.
ACTIVE_OPS: Final[FrozenSet[str]] = frozenset(
    {EXECUTE, TREE_GET, CONTENT_GET, MANIFEST_GET}
)

#: GET-class subset — http-poll advertises a non-empty subset of this.
GET_CLASS_OPS: Final[FrozenSet[str]] = frozenset(
    {TREE_GET, CONTENT_GET, MANIFEST_GET}
)

#: Full vocabulary (active + reserved). Use ACTIVE_OPS for emit-time
#: validation; this is for parser-side recognition (e.g., classifying a
#: peer that advertises SUBSCRIBE as forward-version).
KNOWN_OPS: Final[FrozenSet[str]] = ACTIVE_OPS | {SUBSCRIBE_RESERVED}


def is_active_op(op: str) -> bool:
    """True iff ``op`` is one of the four v1 advertisable values."""
    return op in ACTIVE_OPS


def is_known_op(op: str) -> bool:
    """True iff ``op`` is in the closed enum (active or reserved)."""
    return op in KNOWN_OPS


def validate_supported_ops(
    ops: list[str],
    *,
    allow_reserved: bool = False,
) -> None:
    """Validate a ``supported_ops`` list for emit-time conformance.

    Per D-13:
      - non-empty list
      - every value in the closed enum
      - ``SUBSCRIBE`` is reserved — rejected unless ``allow_reserved=True``
        (e.g., to parse a forward-compat peer advertisement)

    Raises:
        ValueError: list is empty, or contains an unknown / reserved value.
    """
    if not ops:
        raise ValueError("supported_ops: empty list (must advertise at least one)")
    permitted = KNOWN_OPS if allow_reserved else ACTIVE_OPS
    for op in ops:
        if op not in permitted:
            if not allow_reserved and op == SUBSCRIBE_RESERVED:
                raise ValueError(
                    f"supported_ops: SUBSCRIBE is reserved per D-13; "
                    f"not a valid v1 advertisement value"
                )
            raise ValueError(
                f"supported_ops: unknown value {op!r} "
                f"(D-13 closed enum: {sorted(ACTIVE_OPS)})"
            )


def validate_http_poll_ops(ops: list[str]) -> None:
    """Validate ``supported_ops`` for an ``http-poll`` transport profile.

    Per §6.5.3 + D-13: ``http-poll`` advertises a non-empty subset of
    ``{TREE_GET, CONTENT_GET, MANIFEST_GET}``. ``EXECUTE`` is not valid on
    ``http-poll`` (the endpoint is a passive store; no executing peer).

    Raises:
        ValueError: empty, contains ``EXECUTE``, or contains an unknown value.
    """
    validate_supported_ops(ops)
    bad = [op for op in ops if op not in GET_CLASS_OPS]
    if bad:
        raise ValueError(
            f"http-poll supported_ops: invalid value(s) {bad!r} "
            f"(must be a non-empty subset of {sorted(GET_CLASS_OPS)})"
        )


def validate_live_ops(ops: list[str]) -> None:
    """Validate ``supported_ops`` for a live profile (``tcp``/``websocket``/``http``).

    Live profiles advertise ``[EXECUTE]``. Partial-publisher subsets are
    a property of ``http-poll`` only.

    Raises:
        ValueError: anything other than exactly ``["EXECUTE"]``.
    """
    if ops != [EXECUTE]:
        raise ValueError(
            f"live transport supported_ops must be exactly ['EXECUTE'], got {ops!r}"
        )
