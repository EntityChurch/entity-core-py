"""EXTENSION-SIGNALING §4.5.1 — the `reflection_endpoints` wire form.

A node that serves §9.3 STUN reflection publishes its **own** listener(s) in
`advertise`'s top-level `reflection_endpoints`. This module holds the one rule
that field carries: the **RFC 7064 STUN URI form, pinned 2026-08-14**, identical
to `EXTENSION-REGISTRY` §3b.0 — the two fields describe the same kind of thing
and MUST NOT differ in shape.

The pinned form is **non-hierarchical**:

- the scheme is ``stun:`` (over UDP/TCP) or ``stuns:`` (over TLS);
- there is **no** ``//`` authority separator — ``stun://host:3478`` is invalid;
- a bare ``host:3478`` with no scheme is invalid;
- the host is required; the port is optional and, if present, is 1..65535.

Why the node validates at configuration time
--------------------------------------------

A browser hands each entry to ``RTCIceServer.urls`` **verbatim**, and a
malformed entry does **not** degrade to host-candidates-only — it *throws at
``RTCPeerConnection`` construction* and takes the establisher with it. So the
emitting node publishes the final form and runs no transform, and neither does
any consumer: every transform is a place two consumers guess differently (given
``1.2.3.4:3478`` one prepends ``stun:`` and one does not; given
``stun:1.2.3.4:3478`` a prepending consumer produces ``stun:stun:1.2.3.4:3478``).
That makes the form the **operator's** contract, which is why a bad value fails
at startup rather than being silently dropped or "fixed" on the way out.

Parity with Go, and where this is deliberately stricter
-------------------------------------------------------

Ported from Go's ``signaling.ValidateReflectionEndpoint``
(``ext/signaling/reflection.go``), including what it does *not* check: the host
is never checked for being a **resolvable name or a well-formed IP literal**.
The node emits verbatim and the consumer resolves, so a host validator here
would be a second place to disagree.

What the host *is* checked for is a stray colon, which Rust found and Go adopted
(2026-08-15-c): an unbracketed host containing one is either an unbracketed IPv6
literal (ambiguous host-vs-port) or a **doubled scheme** — ``stun:stun:host`` —
which §4.5.1 names as *the* failure mode the pinned form exists to foreclose,
being exactly what a prepending consumer produces when it runs twice. A config
that starts this node must not fail a sibling's, so the three validators agree
on that rejection.

One deliberate difference, and it only ever **rejects** what Go accepts (never
the reverse, so a config this accepts is always Go-valid): the port must be
ASCII digits. Go's ``strconv.Atoi`` accepts a leading ``+``; Python's ``int()``
would additionally accept surrounding whitespace and non-ASCII decimal digits,
which is a wider door than the wire form should have.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from entity_handlers.signaling.constants import SignalingError

#: The two RFC 7064 schemes, longest first so ``stuns:`` is not read as
#: ``stun:`` with a host of ``s:…``.
SCHEME_STUNS = "stuns:"
SCHEME_STUN = "stun:"

_PORT_DIGITS = re.compile(r"[0-9]+")

_PORT_MIN, _PORT_MAX = 1, 65535


class ReflectionEndpointError(SignalingError):
    """A configured reflection endpoint is not in the pinned §4.5.1 form."""


def validate_reflection_endpoint(uri: str) -> None:
    """Raise :class:`ReflectionEndpointError` unless ``uri`` is a well-formed
    RFC 7064 STUN URI in the §4.5.1 pinned form.

    Returns ``None`` on success — it is a check, not a normalizer. Nothing here
    ever rewrites the string: §4.5.1 publishes the operator's bytes unchanged.
    """
    if not isinstance(uri, str):
        raise ReflectionEndpointError(
            f"reflection endpoint must be a string, got {type(uri).__name__}"
        )

    if uri.startswith(SCHEME_STUNS):
        host = uri[len(SCHEME_STUNS):]
    elif uri.startswith(SCHEME_STUN):
        host = uri[len(SCHEME_STUN):]
    else:
        raise ReflectionEndpointError(
            f"reflection endpoint {uri!r}: must begin with the RFC 7064 scheme "
            f"{SCHEME_STUN!r} or {SCHEME_STUNS!r}"
        )

    if host.startswith("//"):
        raise ReflectionEndpointError(
            f"reflection endpoint {uri!r}: RFC 7064 STUN URIs are "
            "non-hierarchical — there is no '//' (§4.5.1)"
        )
    if not host:
        raise ReflectionEndpointError(
            f"reflection endpoint {uri!r}: host is required after the scheme"
        )

    port_str = _split_port(uri, host)
    if port_str is None:
        return
    if not _PORT_DIGITS.fullmatch(port_str):
        raise ReflectionEndpointError(
            f"reflection endpoint {uri!r}: port {port_str!r} must be an "
            f"integer in {_PORT_MIN}..{_PORT_MAX}"
        )
    port = int(port_str)
    if not _PORT_MIN <= port <= _PORT_MAX:
        raise ReflectionEndpointError(
            f"reflection endpoint {uri!r}: port {port_str!r} must be an "
            f"integer in {_PORT_MIN}..{_PORT_MAX}"
        )


def _split_port(uri: str, host: str) -> str | None:
    """The OPTIONAL trailing ``:port`` of ``host``, or ``None`` if it has none.

    An IPv6 literal carries its own colons, so it must be in bracket form
    (``[::1]`` / ``[::1]:3478``) — RFC 3986 host syntax as RFC 7064 inherits it.
    A bracketed literal is well-formed as long as the bracket closes; only the
    segment *after* the closing bracket is a port.
    """
    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            raise ReflectionEndpointError(
                f"reflection endpoint {uri!r}: unterminated IPv6 literal — "
                "missing ']'"
            )
        if end == 1:
            raise ReflectionEndpointError(
                f"reflection endpoint {uri!r}: empty IPv6 literal"
            )
        rest = host[end + 1:]
        if not rest:
            return None
        if rest[0] != ":":
            raise ReflectionEndpointError(
                f"reflection endpoint {uri!r}: unexpected {rest!r} after IPv6 "
                "literal"
            )
        return rest[1:]

    index = host.rfind(":")
    if index < 0:
        return None
    if index == 0:
        raise ReflectionEndpointError(
            f"reflection endpoint {uri!r}: host is required before the port"
        )
    host_part = host[:index]
    # An unbracketed host MUST NOT itself contain a colon. Two malformed shapes
    # reach here, both forbidden by the RFC 3986 host syntax RFC 7064 inherits
    # and both rejected by a browser's URL parser:
    #
    #   - an unbracketed IPv6 literal — `stun:2001:db8::1` — where host and
    #     port are ambiguous; it MUST be written `stun:[2001:db8::1]`;
    #   - a doubled scheme — `stun:stun:relay.example:3478` — which §4.5.1
    #     names as *the* failure mode the pinned form exists to foreclose,
    #     being what a prepending consumer produces when it runs twice.
    #
    # Refuse both. A config that starts this node must not fail a sibling's.
    if ":" in host_part:
        raise ReflectionEndpointError(
            f"reflection endpoint {uri!r}: host {host_part!r} contains a colon "
            f"— an IPv6 literal MUST be bracketed as [{host_part}], and a URI "
            f"carries exactly one scheme (§4.5.1 names the doubled 'stun:stun:' "
            f"prefix as the failure mode)"
        )
    return host[index + 1:]


def normalize_reflection_endpoints(
    uris: Iterable[str] | None,
) -> tuple[str, ...]:
    """Validate ``uris`` and return them as a tuple, **in order and unchanged**.

    Order and bytes are preserved because §4.5.1 publishes what the operator
    configured — no sorting, no case-folding, no default-port canonicalization,
    and no dedup. A consumer dedups across sources by *published bytes*
    (§3b.3), which only works if nobody normalizes first.

    ``None`` and an empty iterable both give ``()`` — the node serves no
    reflection, and the field is then **absent** from `advertise`, never null
    and never an empty array (§4.5.1, the `lobby_constant` precedent).
    """
    if uris is None:
        return ()
    if isinstance(uris, str):
        # A bare string is 99% of the time a caller meaning one endpoint, and
        # iterating it would silently validate single characters.
        raise ReflectionEndpointError(
            "reflection endpoints must be a sequence of strings, not a single "
            f"string — did you mean [{uris!r}]?"
        )
    endpoints = tuple(uris)
    for uri in endpoints:
        validate_reflection_endpoint(uri)
    return endpoints
