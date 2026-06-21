"""EXTENSION-DISCOVERY v1.0 — mDNS / DNS-SD §3.2 wire pins.

The §3.2 constants are the SILENT cross-impl-divergence class (Go and Rust
never see each other on the LAN if these differ, with no error to catch), so
they get explicit byte-level pins here. These exercise the wire assembly +
parsing without live multicast; the three-peer LAN convergence is D8.

FLAG (handoff open #1): TXT key ordering is insertion-order in zeroconf; the
order pinned here is the §3.2-documented order. Cross-check at D5 against
Go/Rust byte dumps.
"""

from __future__ import annotations

from entity_core.crypto.identity import Keypair

from entity_handlers.discovery import identity_hint_for_peer_id
from entity_handlers.discovery_mdns import (
    SERVICE_TYPE,
    TXT_VERSION,
    _observation_from_info,
    _txt_properties,
)


def test_service_type_pinned():
    # RFC 6763 §7 service-name convention; the cohort interop pin.
    assert SERVICE_TYPE == "_entity-core._udp.local."


def test_txt_must_present_keys_and_order():
    props = _txt_properties("PEERID", "profile-7", {})
    # MUST-present keys (§3.2), in documented order.
    assert list(props.keys()) == ["version", "peer_id_hint", "profile_ref"]
    assert props["version"] == TXT_VERSION == "1"
    assert props["peer_id_hint"] == "PEERID"
    assert props["profile_ref"] == "profile-7"


def test_txt_optional_keys_follow_must_present():
    props = _txt_properties(
        "PEERID", "profile-7",
        {"proto": "webrtc,tcp,http-poll", "display_name": "Alice"},
    )
    assert list(props.keys()) == [
        "version", "peer_id_hint", "profile_ref", "proto", "display_name",
    ]


def test_txt_omits_absent_optional_keys():
    props = _txt_properties("PEERID", "profile-7", {"display_name": "Alice"})
    assert "proto" not in props
    assert props["display_name"] == "Alice"


class _FakeInfo:
    """Minimal stand-in for zeroconf ServiceInfo (the fields the parser uses)."""

    def __init__(self, properties, port, addresses):
        self.properties = properties
        self.port = port
        self._addresses = addresses

    def parsed_addresses(self):
        return self._addresses


def test_observation_parses_txt_and_strips_service_suffix():
    kp = Keypair.generate()
    info = _FakeInfo(
        properties={
            b"version": b"1",
            b"peer_id_hint": kp.peer_id.encode(),
            b"profile_ref": b"prof-1",
            b"proto": b"tcp,http-poll",
            b"unknown_future_key": b"ignored",  # §3.2 forward-compat MUST ignore
        },
        port=9000,
        addresses=["192.168.1.5"],
    )
    name = f"alice.{SERVICE_TYPE}"
    obs = _observation_from_info(name, info)
    assert obs is not None
    # candidate_id is the DNS-SD instance label (suffix stripped)
    assert obs.candidate_id == "alice"
    assert obs.peer_id_hint == kp.peer_id
    assert obs.endpoint_hint["port"] == 9000
    assert obs.endpoint_hint["addresses"] == ["192.168.1.5"]
    assert obs.endpoint_hint["profile_ref"] == "prof-1"
    assert obs.endpoint_hint["proto"] == ["tcp", "http-poll"]
    # unknown TXT key ignored — does not appear anywhere structured
    assert "unknown_future_key" not in obs.endpoint_hint


def test_observation_peer_id_hint_enables_identity_hint():
    # A peer_id_hint in the TXT lets the substrate pin the identity-claim at
    # scan time (§2.2.1) — the hint is deterministic from the peer-id.
    kp = Keypair.generate()
    info = _FakeInfo(
        properties={b"peer_id_hint": kp.peer_id.encode(), b"profile_ref": b"p"},
        port=1, addresses=[],
    )
    obs = _observation_from_info(f"x.{SERVICE_TYPE}", info)
    assert obs.peer_id_hint == kp.peer_id
    assert identity_hint_for_peer_id(obs.peer_id_hint) == identity_hint_for_peer_id(kp.peer_id)
