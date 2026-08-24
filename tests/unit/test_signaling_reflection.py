"""EXTENSION-SIGNALING §4.5.1 — the `reflection_endpoints` URI form.

The form is pinned (2026-08-14) rather than left to the consumer, and the
reason is the whole test: a browser hands each entry to `RTCIceServer.urls`
**verbatim**, and a malformed entry does not degrade to host-candidates-only —
it *throws at `RTCPeerConnection` construction* and takes the establisher with
it. So a bad value has to die at the node's configuration, which is the only
place an operator can still fix it.

The table mirrors Go's `TestValidateReflectionEndpoint`
(`ext/signaling/reflection.go`) case for case, because §4.5.1 and
`EXTENSION-REGISTRY` §3b.0 pin the identical form and a validator that differs
cross-impl is an operator publishing in good faith into one client's empty ICE
list.
"""

from __future__ import annotations

import pytest

from entity_handlers.signaling.reflection import (
    ReflectionEndpointError,
    normalize_reflection_endpoints,
    validate_reflection_endpoint,
)


class TestValidateReflectionEndpoint:
    @pytest.mark.parametrize(
        "uri",
        [
            "stun:stun.example.org",
            "stun:stun.example.org:3478",
            "stuns:stun.example.org",
            "stuns:stun.example.org:5349",
            "stun:1.2.3.4:3478",
            "stun:[2001:db8::1]",
            "stun:[2001:db8::1]:3478",
            "stuns:[::1]:5349",
            "stun:host:1",  # the port floor
            "stun:host:65535",  # the port ceiling
        ],
    )
    def test_accepts_the_pinned_rfc_7064_form(self, uri: str) -> None:
        validate_reflection_endpoint(uri)  # does not raise

    @pytest.mark.parametrize(
        ("uri", "because"),
        [
            ("stun://host:3478", "non-hierarchical — there is no //"),
            ("stuns://host", "non-hierarchical — there is no //"),
            ("host:3478", "a bare host:port has no scheme"),
            ("1.2.3.4", "a bare host has no scheme"),
            ("", "empty is not a URI"),
            ("stun:", "the host is required after the scheme"),
            ("stuns:", "the host is required after the scheme"),
            ("turn:host:3478", "TURN is EXTENSION-REGISTRY §3b's data_relay"),
            ("STUN:host", "the scheme is matched exactly, not case-folded"),
            ("stun::3478", "the host is required before the port"),
            ("stun:host:0", "port 0 is out of the 1..65535 range"),
            ("stun:host:65536", "port 65536 is out of the 1..65535 range"),
            ("stun:host:-1", "a negative port is not an unsigned port"),
            ("stun:host:http", "the port is digits, not a service name"),
            ("stun:host: 3478", "no whitespace tolerance in the port"),
            ("stun:[2001:db8::1", "unterminated IPv6 literal"),
            ("stun:[]", "empty IPv6 literal"),
            ("stun:[::1]x", "trailing junk after the IPv6 literal"),
            ("stun:2001:db8::1", "an IPv6 literal MUST be bracketed"),
            ("stun:stun:relay.example:3478", "doubled scheme — §4.5.1's named failure mode"),
            ("stuns:stuns:relay.example", "doubled scheme, tls spelling"),
        ],
    )
    def test_rejects_everything_off_the_pinned_form(
        self, uri: str, because: str
    ) -> None:
        with pytest.raises(ReflectionEndpointError):
            validate_reflection_endpoint(uri)

    def test_the_scheme_prefixes_do_not_shadow_each_other(self) -> None:
        """`stuns:` is matched before `stun:`, so it is never read as `stun:`
        with a host of `s:…` — which would have made `stuns:` silently mean a
        different endpoint rather than STUN-over-TLS at the same one."""
        validate_reflection_endpoint("stuns:example.org:5349")
        # The proof it took the stuns branch: the same string read as
        # `stun:` + `s:example.org:5349` would have a host of `s` and a port
        # of `example.org:5349`, which is not a valid port.


class TestNormalizeReflectionEndpoints:
    def test_absent_and_empty_both_give_the_no_reflection_state(self) -> None:
        """§4.5.1: absent and empty are the same thing, and both are valid.
        Both land on `()`, which the node emits as an ABSENT field."""
        assert normalize_reflection_endpoints(None) == ()
        assert normalize_reflection_endpoints([]) == ()
        assert normalize_reflection_endpoints(()) == ()

    def test_order_and_bytes_survive_unchanged(self) -> None:
        """No sorting, no case-folding, no default-port canonicalization, no
        dedup. §3b.3 dedups by *published bytes*, so a normalizer here would
        break the one thing that makes a cross-source merge well-defined."""
        given = [
            "stun:B.example.org:3478",
            "stun:a.example.org",
            "stun:B.example.org:3478",  # a duplicate is the operator's call
            "stuns:[2001:DB8::1]:5349",
        ]
        assert normalize_reflection_endpoints(given) == tuple(given)

    def test_one_bad_entry_refuses_the_whole_configuration(self) -> None:
        """Not "drop the bad one and publish the rest" — a silently shortened
        list is how an operator ends up believing they advertise a reflector
        they do not."""
        with pytest.raises(ReflectionEndpointError):
            normalize_reflection_endpoints(
                ["stun:good.example.org:3478", "stun://bad.example.org"],
            )

    def test_a_bare_string_is_refused_rather_than_iterated(self) -> None:
        """Iterating a `str` would validate single characters and "succeed" on
        the empty string, publishing nothing while the operator configured
        something."""
        with pytest.raises(ReflectionEndpointError):
            normalize_reflection_endpoints("stun:stun.example.org:3478")
