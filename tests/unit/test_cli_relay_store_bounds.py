"""`entity-core start --relay-store-retention-ms / --relay-max-storage-bytes`.

The operator knobs for EXTENSION-RELAY §8 (v1.3). They exist for two readers
and both matter:

* an operator, who sets a bound; and
* **a cross-impl harness**, which arms a peer for the §8 wire rows by passing a
  flag *by name*. `entity-core-go`'s `relay_store_bounds` category reports
  could-not-look against a peer with no ceiling, so a peer whose knob is
  spelled differently — or wired to nothing — is indistinguishable from one
  that simply has no bound configured, forever, while looking conformant.
  These names match the Go peer's character for character on purpose.

So the rows here follow the flag all the way to the handler's own read, not
just to `args`: a parsed flag that never reaches `system/relay/config` is the
"unreachable surface" shape go's reachability suite exists to catch, and it
would pass any parser-level assertion.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder

from entity_cli.main import _configure_relay_store_bounds, build_parser
from entity_handlers.relay import (
    CONFIG_MAX_STORAGE_BYTES,
    CONFIG_STORE_RETENTION_MS,
    LIMIT_MAX_RETENTION_MS,
    RELAY_CONFIG_PATH,
)


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _config(peer) -> dict | None:
    h = peer.emit_pathway.entity_tree.get(
        peer.emit_pathway.entity_tree.normalize_uri(RELAY_CONFIG_PATH)
    )
    return None if h is None else peer.emit_pathway.content_store.get(h).data


def _start(*argv):
    return build_parser().parse_args(["start", *argv])


def test_both_flags_parse_under_the_cross_impl_names():
    args = _start(
        "--relay-store-retention-ms", "3600000",
        "--relay-max-storage-bytes", "1048576",
    )
    assert args.relay_store_retention_ms == 3_600_000
    assert args.relay_max_storage_bytes == 1_048_576


def test_absent_flags_write_no_config_at_all(peer):
    """An ordinary peer is untouched: no config entity, so the handler reads
    `{}` and §8 stays off. Writing a config with zeros would look identical
    from the flag's side and is not the same thing — `_config_bound` would
    still say "no bound", but the tree would carry an assertion the operator
    never made."""
    _configure_relay_store_bounds(peer, _start("--listen", "127.0.0.1:9001"))
    assert _config(peer) is None


def test_the_retention_flag_reaches_the_handlers_own_read(peer):
    _configure_relay_store_bounds(peer, _start("--relay-store-retention-ms", "3600000"))
    assert _config(peer)[CONFIG_STORE_RETENTION_MS] == 3_600_000


def test_the_storage_flag_reaches_the_handlers_own_read(peer):
    _configure_relay_store_bounds(peer, _start("--relay-max-storage-bytes", "4096"))
    assert _config(peer)[CONFIG_MAX_STORAGE_BYTES] == 4096


def test_a_negative_bound_is_refused_not_demoted_to_unbounded(peer):
    """A typo'd ceiling is a request for a ceiling. Handing back the unbounded
    behaviour at the one moment the operator believes they set a bound is the
    failure mode `--max-lifetime` already taught this CLI — and unlike the
    tree-side read, there is an operator present here to be told."""
    with pytest.raises(SystemExit) as exc:
        _configure_relay_store_bounds(peer, _start("--relay-store-retention-ms", "-1"))
    assert "must be >= 0" in str(exc.value)
    assert _config(peer) is None, "a refused flag still wrote a config entity"


def test_zero_is_a_real_value_meaning_no_bound(peer):
    """Distinct from negative: 0 is what the flag's help and the Go peer's
    flag both mean by "no bound", so an operator can pass it deliberately —
    e.g. to override a bound in a persisted config."""
    _configure_relay_store_bounds(peer, _start("--relay-store-retention-ms", "0"))
    assert _config(peer)[CONFIG_STORE_RETENTION_MS] == 0


def test_setting_one_bound_preserves_the_other_config_keys(peer):
    """`system/relay/config` also carries §9.5's `disable_default_fallback`.
    A start-up write that replaced the entity would silently turn an
    operator's MX-required posture off on the next restart — a security
    posture lost to an unrelated flag."""
    from entity_core.protocol.entity import Entity
    from entity_core.storage.emit import EmitContext

    peer.emit_pathway.emit(
        RELAY_CONFIG_PATH,
        Entity(
            type="system/relay/config", data={"disable_default_fallback": True}
        ),
        EmitContext.bootstrap(),
    )
    _configure_relay_store_bounds(peer, _start("--relay-store-retention-ms", "60000"))

    cfg = _config(peer)
    assert cfg[CONFIG_STORE_RETENTION_MS] == 60_000
    assert cfg["disable_default_fallback"] is True


def test_configuring_a_bound_publishes_the_4_1_advertise(peer):
    """§4.1's MUST-when-enforced is wired to the same act as the bound. An
    operator who sets a ceiling and never calls `:advertise` would otherwise
    enforce a bound no counterparty can read, which is the exact state §8.1
    names as the reason publication is a MUST."""
    _configure_relay_store_bounds(peer, _start("--relay-store-retention-ms", "3600000"))

    path = f"system/relay/advertise/{peer.keypair.peer_id}"
    adv_hash = peer.emit_pathway.entity_tree.get(path)
    assert adv_hash is not None, "a bounded relay published no advertise"
    adv = peer.emit_pathway.content_store.get(adv_hash)
    assert adv.data["limits"][LIMIT_MAX_RETENTION_MS] == 3_600_000
    assert peer.emit_pathway.entity_tree.get(
        f"system/signature/{adv_hash.hex()}"
    ) is not None, "the published advertise carries no §5.2 signature"


def test_an_unbounded_peer_publishes_nothing(peer):
    """The control. Publishing an empty advertise would assert a relay
    reachability this peer was never configured to offer."""
    _configure_relay_store_bounds(peer, _start("--listen", "127.0.0.1:9001"))
    assert peer.emit_pathway.entity_tree.get(
        f"system/relay/advertise/{peer.keypair.peer_id}"
    ) is None
