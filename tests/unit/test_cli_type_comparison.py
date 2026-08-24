"""Offline coverage for the CLI's `compare-types` comparison loop.

`compare_types_with_peer` had exactly one caller in tests — `tests/interop/
test_type_parity.py` — which needs a live Rust peer and is therefore skipped
in every ordinary run. So the function's comparison branch, which runs on
*every* successfully fetched type, was never executed offline, and a
`NameError` on its hash-equality line sat there unnoticed.

These tests stub the fetch instead of the peer, which puts the same loop under
the default suite. The stub is the whole point: the bug is in the code around
the network call, not in the network call.
"""

from __future__ import annotations

import importlib

import pytest

from entity_cli.main import TypeComparisonResult, compare_types_with_peer
from entity_core.protocol.entity import Entity

# `entity_cli.__init__` re-exports the `main` *function*, so `from entity_cli
# import main` binds the callable and not the module. Ask for the module.
cli_main = importlib.import_module("entity_cli.main")

TYPE_PATH = "primitive/string"


def _local_type(data: dict) -> Entity:
    return Entity(type="system/type", data=data)


@pytest.fixture
def stub_fetch(monkeypatch: pytest.MonkeyPatch):
    """Replace the network fetch; return a setter for the remote payload."""

    def _set(remote: dict | None) -> None:
        async def _fetch(conn: object, type_path: str) -> dict | None:
            return remote

        monkeypatch.setattr(cli_main, "fetch_remote_type", _fetch)

    return _set


async def test_matching_type_reports_a_match(stub_fetch) -> None:
    """The equal-hash branch must run without raising.

    Regression: this line compared `local_hash` against a bare `remote_hash`
    that was never bound — the value had just been assigned to
    `result.remote_hash`. Every comparison against a reachable peer raised
    `NameError`, so `entity-core compare-types` crashed on its first fetched
    type. Only interop covered it, and interop does not run without a peer.
    """
    data = {"kind": "primitive", "name": "string"}
    local = _local_type(data)

    stub_fetch(data)
    results = await compare_types_with_peer(None, [TYPE_PATH], {TYPE_PATH: local})

    assert len(results) == 1
    r = results[0]
    assert isinstance(r, TypeComparisonResult)
    assert r.match is True
    assert r.differences == []
    assert r.local_hash == local.compute_hash()
    assert r.remote_hash == r.local_hash


async def test_differing_type_reports_the_differences(stub_fetch) -> None:
    """The unequal-hash branch reports diffs rather than claiming a match."""
    local = _local_type({"name": "string", "constraints": {"max": 1}})

    stub_fetch({"name": "text", "constraints": {"max": 1}})
    results = await compare_types_with_peer(None, [TYPE_PATH], {TYPE_PATH: local})

    r = results[0]
    assert r.match is False
    assert r.local_hash != r.remote_hash
    assert any("name" in d for d in r.differences or [])


async def test_a_divergence_outside_the_known_keys_is_still_named(stub_fetch) -> None:
    """A hash mismatch must never come back with an empty reason list.

    `compare_type_data` gives tailored messages for five TYPE-SYSTEM keys.
    Anything else still changes the hash, so before this was closed the CLI
    printed MISMATCH and then nothing — the one output that tells a
    divergence hunter least. An unknown key is precisely the interesting case:
    it is what a peer added that we do not model yet.
    """
    local = _local_type({"name": "string"})

    stub_fetch({"name": "string", "vendor_ext": {"go": True}})
    (r,) = await compare_types_with_peer(None, [TYPE_PATH], {TYPE_PATH: local})

    assert r.match is False
    assert r.local_hash != r.remote_hash
    assert r.differences, "a hash mismatch must always carry a reason"
    assert any("vendor_ext" in d for d in r.differences)


async def test_missing_local_and_missing_remote_are_distinguished(stub_fetch) -> None:
    """Both absence paths short-circuit before the hash comparison."""
    stub_fetch({"kind": "primitive"})
    (missing_local,) = await compare_types_with_peer(None, [TYPE_PATH], {})
    assert missing_local.match is False
    assert missing_local.differences == ["Local missing type"]

    stub_fetch(None)
    (missing_remote,) = await compare_types_with_peer(
        None, [TYPE_PATH], {TYPE_PATH: _local_type({"kind": "primitive"})}
    )
    assert missing_remote.match is False
    assert missing_remote.differences == ["Remote missing type"]
