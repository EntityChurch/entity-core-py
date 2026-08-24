"""`entity-core start --reflection-endpoint` — EXTENSION-SIGNALING §4.5.1.

The flag name and spelling match Go's `entity-peer --reflection-endpoint`
deliberately: an operator bringing up a mixed cohort to reproduce a cross-impl
report should not have to remember which peer spells it differently.

The reachability assertions are the point. A flag that parses but never reaches
the builder is the failure mode the inventory-boundary discipline exists to
catch — it looks configured, advertises nothing, and the operator finds out from
a browser's empty ICE list.
"""

from __future__ import annotations

import pytest

from entity_cli.main import _reflection_endpoints_from_args, build_parser
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_handlers.signaling.constants import PATTERN
from entity_handlers.signaling.node import SignalingNodeExtension
from entity_handlers.signaling.reflection import ReflectionEndpointError

_LISTEN = ["start", "--listen", "127.0.0.1:9001"]


class TestFlagParsing:
    def test_absent_is_the_no_reflection_state(self):
        args = build_parser().parse_args(_LISTEN)
        assert args.reflection_endpoint is None
        assert _reflection_endpoints_from_args(args) == []

    def test_a_single_uri_parses(self):
        args = build_parser().parse_args(
            [*_LISTEN, "--reflection-endpoint", "stun:reflect.example.org:3478"],
        )
        assert _reflection_endpoints_from_args(args) == [
            "stun:reflect.example.org:3478",
        ]

    def test_comma_separated_uris_split_in_order(self):
        args = build_parser().parse_args([
            *_LISTEN,
            "--reflection-endpoint",
            "stun:a.example.org:3478,stuns:[2001:db8::1]:5349",
        ])
        # Order is preserved and the IPv6 literal's own colons survive the
        # split — the separator is the comma, never the colon.
        assert _reflection_endpoints_from_args(args) == [
            "stun:a.example.org:3478",
            "stuns:[2001:db8::1]:5349",
        ]

    def test_whitespace_and_empty_segments_are_dropped(self):
        """A trailing comma is a typo, not an endpoint of ""."""
        args = build_parser().parse_args([
            *_LISTEN, "--reflection-endpoint", "stun:a.example.org, ,stun:b.org:1,",
        ])
        assert _reflection_endpoints_from_args(args) == [
            "stun:a.example.org", "stun:b.org:1",
        ]

    def test_the_uri_itself_is_never_rewritten(self):
        """§4.5.1 publishes the operator's bytes verbatim — no case-folding, no
        default-port canonicalization. Splitting is all this does."""
        given = "stuns:MiXeD.Example.ORG:5349"
        args = build_parser().parse_args(
            [*_LISTEN, "--reflection-endpoint", given],
        )
        assert _reflection_endpoints_from_args(args) == [given]


class TestItReachesTheNode:
    """The flag is wired through to something that publishes it — the half a
    parse test cannot see."""

    def test_the_builder_accepts_them_and_the_node_publishes_them(self):
        parsed = _reflection_endpoints_from_args(
            build_parser().parse_args([
                *_LISTEN, "--reflection-endpoint",
                "stun:reflect.example.org:3478,stuns:[2001:db8::1]:5349",
            ]),
        )
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .with_signaling_node_handler(reflection_endpoints=parsed)
            .build()
        )
        assert any(h.pattern == PATTERN for h in peer.handlers.list_handlers())
        extension = next(
            e for e in peer._extensions if isinstance(e, SignalingNodeExtension)
        )
        # Byte-for-byte what the operator typed, in order.
        assert list(extension.node.reflection_endpoints) == parsed

    def test_a_malformed_uri_is_refused_before_the_peer_exists(self):
        """Startup is the last moment an operator can fix it; a browser's
        RTCPeerConnection throws rather than degrading (§4.5.1)."""
        parsed = _reflection_endpoints_from_args(
            build_parser().parse_args(
                [*_LISTEN, "--reflection-endpoint", "stun://reflect.example.org"],
            ),
        )
        with pytest.raises(ReflectionEndpointError):
            (
                PeerBuilder()
                .with_keypair(Keypair.generate())
                .with_default_handlers()
                .with_signaling_node_handler(reflection_endpoints=parsed)
                .build()
            )
