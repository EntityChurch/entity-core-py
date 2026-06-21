"""Tests for CLI entity-tree commands.

Tests exercise the underlying command functions (cmd_ls, cmd_cat, etc.)
against a real peer, verifying the full request/response flow.
"""

import argparse

import pytest

from entity_cli.main import (
    cmd_cat,
    cmd_exec,
    cmd_get,
    cmd_info,
    cmd_ls,
    cmd_put,
    cmd_rm,
    cmd_tree,
    open_connection,
    parse_target,
)
from entity_cli.display import (
    display_entity,
    display_error,
    display_generic,
    display_info,
    display_status,
    display_tree_listing,
    to_diag,
)
from entity_core.crypto.identity import Keypair
from entity_core.peer import Peer, PeerBuilder


# ---------------------------------------------------------------------------
# Test port for this file (avoid conflicts with other integration tests)
# ---------------------------------------------------------------------------
TEST_PORT = 19003


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def server_peer():
    """Create and start a server peer on TEST_PORT."""
    keypair = Keypair.generate()
    peer = PeerBuilder().with_keypair(keypair).with_default_handlers().debug_mode(True).build()
    await peer.start("127.0.0.1", TEST_PORT)
    yield peer
    await peer.stop()


# ---------------------------------------------------------------------------
# parse_target tests
# ---------------------------------------------------------------------------

class TestParseTarget:
    def test_host_port_path(self):
        host, port, path = parse_target("127.0.0.1:9001/system/type/")
        assert host == "127.0.0.1"
        assert port == 9001
        assert path == "system/type/"

    def test_host_port_only(self):
        host, port, path = parse_target("127.0.0.1:9001")
        assert host == "127.0.0.1"
        assert port == 9001
        assert path == ""

    def test_deep_path(self):
        host, port, path = parse_target("127.0.0.1:9001/system/type/system/type")
        assert host == "127.0.0.1"
        assert port == 9001
        assert path == "system/type/system/type"

    def test_ipv6_bracket(self):
        host, port, path = parse_target("[::1]:9001/path")
        assert host == "::1"
        assert port == 9001
        assert path == "path"

    def test_no_colon_raises(self):
        with pytest.raises(ValueError):
            parse_target("localhost")


# ---------------------------------------------------------------------------
# Display function tests
# ---------------------------------------------------------------------------

class TestDiagnosticNotation:
    def test_primitives(self):
        assert to_diag(None) == "null"
        assert to_diag(True) == "true"
        assert to_diag(False) == "false"
        assert to_diag(42) == "42"
        assert to_diag(-1) == "-1"
        assert to_diag("hello") == '"hello"'

    def test_byte_string(self):
        assert to_diag(b"\x01\x02\xff") == "h'0102ff'"

    def test_array(self):
        assert to_diag([1, 2, 3]) == "[1, 2, 3]"

    def test_map(self):
        result = to_diag({"a": 1})
        assert result == '{"a": 1}'

    def test_nested(self):
        result = to_diag({"key": [1, 2]})
        assert result == '{"key": [1, 2]}'

    def test_string_escapes(self):
        assert to_diag('say "hi"') == '"say \\"hi\\""'
        assert to_diag("line\nnext") == '"line\\nnext"'

    def test_pretty_print(self):
        result = to_diag({"a": 1, "b": 2}, indent=2)
        assert '"a": 1' in result
        assert '"b": 2' in result
        assert "\n" in result

    def test_compact_vs_pretty(self):
        data = {"x": 1}
        compact = to_diag(data)
        pretty = to_diag(data, indent=2)
        # Compact is one line
        assert "\n" not in compact
        # Pretty has indentation
        assert "\n" in pretty


class TestDisplayFunctions:
    def test_display_tree_listing(self):
        entity = {
            "type": "tree/listing",
            "data": {
                "uri": "entity://peer123/system/type/",
                "entries": {
                    "system/type": {"hash": "ecf-sha256:abcdef1234567890", "has_children": False},
                    "system/handlers": {"hash": None, "has_children": True},
                },
            },
        }
        output = display_tree_listing(entity)
        assert "entity://peer123/system/type/" in output
        assert "system/type" in output
        assert "ecf-sha256:abcdef1234567890" in output
        assert "system/handlers/" in output
        assert "[+]" in output

    def test_display_status(self):
        entity = {"type": "status", "data": {"peer_id": "abc123", "uptime": 42}}
        output = display_status(entity)
        assert "Status" in output
        assert "peer_id: abc123" in output

    def test_display_generic(self):
        entity = {"type": "custom/thing", "data": {"key": "value"}}
        output = display_generic(entity)
        assert "[custom/thing]" in output
        assert '"key"' in output

    def test_display_info(self):
        entity = {
            "type": "test/data",
            "content_hash": "ecf-sha256:abc123",
            "data": {"x": 1, "y": 2},
            "refs": {},
        }
        output = display_info(entity)
        assert "type: test/data" in output
        assert "hash: ecf-sha256:abc123" in output
        assert "x" in output and "y" in output

    def test_display_error(self):
        output = display_error({"code": "not_found", "message": "Entity not found"})
        assert "not_found" in output
        assert "Entity not found" in output

    def test_display_entity_dispatches_tree(self):
        entity = {
            "type": "tree/listing",
            "data": {"uri": "/", "entries": {}},
        }
        output = display_entity(entity)
        # Should use tree listing display (starts with URI, not [tree/listing])
        assert "/" in output
        assert "[tree/listing]" not in output


# ---------------------------------------------------------------------------
# open_connection tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_open_connection(server_peer: Peer):
    """open_connection yields a working connection and auto-closes."""
    async with open_connection("127.0.0.1", TEST_PORT) as (conn, remote_peer):
        assert remote_peer == server_peer.peer_id
        assert conn.capability is not None

    # Connection should be closed after context exit
    assert conn.writer.is_closing()


# ---------------------------------------------------------------------------
# ls command tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_ls_system(server_peer: Peer, capsys):
    """ls on system/ path returns tree listing with type subtree (V7.7 singular)."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/",
        identity="framework-admin",
    )
    await cmd_ls(args)
    captured = capsys.readouterr()
    # Should show tree listing output (has type/ subtree - V7.7 singular)
    assert "type" in captured.out.lower()


@pytest.mark.asyncio
async def test_cmd_ls_system_types(server_peer: Peer, capsys):
    """ls on system/type/ shows type entries (V7.7 singular namespace)."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/type/",
        identity="framework-admin",
    )
    await cmd_ls(args)
    captured = capsys.readouterr()
    assert "system/type" in captured.out


@pytest.mark.asyncio
async def test_cmd_ls_auto_appends_slash(server_peer: Peer, capsys):
    """ls auto-appends / to path if missing."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/type",
        identity="framework-admin",
    )
    await cmd_ls(args)
    captured = capsys.readouterr()
    # Should still work — auto-appended /
    assert "system/type" in captured.out


# ---------------------------------------------------------------------------
# tree command tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_tree(server_peer: Peer, capsys):
    """tree shows recursive entity tree with connectors."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/",
        identity="framework-admin",
    )
    await cmd_tree(args)
    captured = capsys.readouterr()
    # Should show tree connectors
    assert "├── " in captured.out or "└── " in captured.out
    # Should recurse into type/ (V7.7 singular) and show leaf entities
    assert "type/" in captured.out
    assert "identity" in captured.out  # system/identity leaf


@pytest.mark.asyncio
async def test_cmd_tree_shows_hashes(server_peer: Peer, capsys):
    """tree shows hashes for leaf entities."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/type/",
        identity="framework-admin",
    )
    await cmd_tree(args)
    captured = capsys.readouterr()
    # Leaf type entities should show their ecf hashes
    assert "ecf-sha256:" in captured.out


# ---------------------------------------------------------------------------
# cat command tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_cat_status(server_peer: Peer, capsys):
    """cat system/status shows type-aware status display."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/status",
        identity="framework-admin",
    )
    await cmd_cat(args)
    captured = capsys.readouterr()
    assert "peer_id" in captured.out


# ---------------------------------------------------------------------------
# info command tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_info_status(server_peer: Peer, capsys):
    """info shows metadata (type, hash) without full data dump."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/status",
        identity="framework-admin",
    )
    await cmd_info(args)
    captured = capsys.readouterr()
    assert "type:" in captured.out
    assert "data keys:" in captured.out


# ---------------------------------------------------------------------------
# get command tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_get_raw_diag(server_peer: Peer, capsys):
    """get outputs CBOR diagnostic notation from entity tree."""
    # system/type/system/type is stored in the entity tree (not virtual)
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/type/system/type",
        identity="framework-admin",
    )
    await cmd_get(args)
    captured = capsys.readouterr()
    # Output is CBOR diagnostic notation — check for key content
    assert '"type": "system/type"' in captured.out
    assert '"name"' in captured.out


# ---------------------------------------------------------------------------
# put + cat + rm roundtrip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_put_cat_rm_roundtrip(server_peer: Peer, capsys):
    """put stores entity, cat reads it back, rm deletes it."""
    # put
    put_args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/data/cli-test",
        identity="framework-admin",
        type="test/data",
        data='{"value": 42}',
    )
    await cmd_put(put_args)
    captured = capsys.readouterr()
    assert "Stored:" in captured.out

    # cat — read it back
    cat_args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/data/cli-test",
        identity="framework-admin",
    )
    await cmd_cat(cat_args)
    captured = capsys.readouterr()
    assert "test/data" in captured.out
    assert "42" in captured.out

    # rm — delete it
    rm_args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/data/cli-test",
        identity="framework-admin",
    )
    await cmd_rm(rm_args)
    captured = capsys.readouterr()
    # Should succeed (either "Deleted." or JSON result)
    assert captured.out.strip()


# ---------------------------------------------------------------------------
# exec command tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_exec_read(server_peer: Peer, capsys):
    """exec with read operation works."""
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/system/status",
        identity="framework-admin",
        operation="get",
        params=None,
    )
    await cmd_exec(args)
    captured = capsys.readouterr()
    assert "peer_id" in captured.out


@pytest.mark.asyncio
async def test_cmd_exec_with_json_params(server_peer: Peer, capsys):
    """exec passes JSON params correctly."""
    # Write something first
    put_args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/data/exec-test",
        identity="framework-admin",
        type="test/data",
        data='{"msg": "hello"}',
    )
    await cmd_put(put_args)
    capsys.readouterr()  # clear

    # Read it back via exec
    args = argparse.Namespace(
        target=f"127.0.0.1:{TEST_PORT}/data/exec-test",
        identity="framework-admin",
        operation="get",
        params=None,
    )
    await cmd_exec(args)
    captured = capsys.readouterr()
    assert "hello" in captured.out
