"""`entity-core start --keepalive-*` flag surface (EXTENSION-NETWORK §2.3).

Cross-impl aliases for the Go peer-manager's `--keepalive` triple, which
forwards to the peer binary as -keepalive-interval-ms / -keepalive-timeout-ms
/ -keepalive-max-missed. These let validate-peer's liveness harness compress
the §5.4 escalation from the ~100s spec-default envelope to seconds against a
Python peer.

Parser-level + mapping-level assertions (no peer boot): the wiring under test
is arg -> with_keepalive_config, which the builder + KeepaliveConfig already
cover end-to-end.
"""

from __future__ import annotations

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.peer.liveness import KeepaliveConfig

from entity_cli.main import _keepalive_config_from_args, build_parser


def test_start_parses_all_three_keepalive_flags():
    args = build_parser().parse_args([
        "start",
        "--keepalive-interval-ms", "1500",
        "--keepalive-timeout-ms", "800",
        "--keepalive-max-missed", "2",
    ])
    assert args.keepalive_interval_ms == 1500
    assert args.keepalive_timeout_ms == 800
    assert args.keepalive_max_missed == 2


def test_keepalive_flags_absent_default_to_none():
    args = build_parser().parse_args(["start", "--listen", "127.0.0.1:9001"])
    assert args.keepalive_interval_ms is None
    assert args.keepalive_timeout_ms is None
    assert args.keepalive_max_missed is None
    # No flag set -> leave the loop at §2.3 spec defaults.
    assert _keepalive_config_from_args(args) is None


def test_keepalive_partial_mapping_keeps_only_set_fields():
    args = build_parser().parse_args([
        "start", "--keepalive-interval-ms", "1500",
    ])
    assert _keepalive_config_from_args(args) == {"interval_ms": 1500}


def test_keepalive_full_triple_maps_to_kwargs():
    args = build_parser().parse_args([
        "start",
        "--keepalive-interval-ms", "1500",
        "--keepalive-timeout-ms", "800",
        "--keepalive-max-missed", "2",
    ])
    assert _keepalive_config_from_args(args) == {
        "interval_ms": 1500,
        "timeout_ms": 800,
        "max_missed": 2,
    }


def test_kwargs_apply_to_builder_keepalive_config():
    """The mapping feeds with_keepalive_config; a partial triple leaves the
    omitted field at its §2.3 spec default."""
    args = build_parser().parse_args([
        "start",
        "--keepalive-interval-ms", "1500",
        "--keepalive-timeout-ms", "800",
    ])
    kwargs = _keepalive_config_from_args(args)
    builder = (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_keepalive_config(**kwargs)
    )
    cfg = builder._state.keepalive_config
    assert cfg.interval_ms == 1500
    assert cfg.timeout_ms == 800
    # max_missed unset -> spec default preserved by the builder.
    assert cfg.max_missed == KeepaliveConfig().max_missed
