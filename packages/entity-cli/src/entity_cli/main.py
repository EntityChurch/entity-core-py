"""Command-line interface for entity-core.

Usage:
    entity-core start [--listen HOST:PORT] [--identity NAME]
    entity-core ls HOST:PORT/path/
    entity-core cat HOST:PORT/path
    entity-core info HOST:PORT/path
    entity-core get HOST:PORT/path
    entity-core put HOST:PORT/path --type TYPE --data JSON
    entity-core rm HOST:PORT/path
    entity-core exec HOST:PORT/path OPERATION [PARAMS]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from dataclasses import dataclass, asdict

from entity_cli.display import (
    display_entity,
    display_error,
    display_info,
    to_diag,
)
from entity_core.crypto.identity import Keypair
from entity_core.crypto.identity_file import load_identity, list_identities
from entity_core.peer.connection import Connection
from entity_core.peer import PeerBuilder
from entity_core.protocol.messages import ExecuteResponse
# Canonical TYPE-SYSTEM §3-§10 core type paths. Single source of truth lives in
# entity_core.types.canonical; re-imported here so the `compare-types` command
# and interop type-parity tests (`from entity_cli.main import CORE_TYPE_PATHS`)
# keep working unchanged.
from entity_core.types import CORE_TYPE_PATHS


# ---------------------------------------------------------------------------
# Type comparison utilities
# ---------------------------------------------------------------------------

@dataclass
class TypeComparisonResult:
    """Result of comparing a single type definition."""

    type_path: str
    match: bool
    local_hash: bytes | None = None
    remote_hash: bytes | None = None
    differences: list[str] | None = None


async def fetch_remote_type(conn: Connection, type_path: str) -> dict | None:
    """Fetch a type definition from remote peer via tree handler.

    Args:
        conn: Active connection to remote peer.
        type_path: Type path (e.g., "primitive/string").

    Returns:
        Type data dict if found, None if not found or error.
    """
    remote_peer_id = conn.session.remote_peer_id

    # Use tree handler with typed params entity
    response = await conn.execute(
        uri=f"entity://{remote_peer_id}/system/tree",
        operation="get",
        params={
            "type": "system/tree/get-request",
            "data": {"path": f"system/types/{type_path}"},
        },
    )

    if response.status == 200:
        result = response.result
        if isinstance(result, dict):
            return result.get("data")
    return None


def compare_type_data(local_data: dict, remote_data: dict) -> list[str]:
    """Compare two type definitions and return differences.

    Args:
        local_data: Local type's data dict.
        remote_data: Remote type's data dict.

    Returns:
        List of difference descriptions (empty if types match).
    """
    differences = []

    # Compare name
    if local_data.get("name") != remote_data.get("name"):
        differences.append(
            f"name: local={local_data.get('name')} remote={remote_data.get('name')}"
        )

    # Compare extends
    if local_data.get("extends") != remote_data.get("extends"):
        differences.append(
            f"extends: local={local_data.get('extends')} remote={remote_data.get('extends')}"
        )

    # Compare layout
    if local_data.get("layout") != remote_data.get("layout"):
        differences.append(
            f"layout: local={local_data.get('layout')} remote={remote_data.get('layout')}"
        )

    # Compare fields
    local_fields = local_data.get("fields", {})
    remote_fields = remote_data.get("fields", {})

    local_field_names = set(local_fields.keys()) if local_fields else set()
    remote_field_names = set(remote_fields.keys()) if remote_fields else set()

    if local_field_names != remote_field_names:
        only_local = local_field_names - remote_field_names
        only_remote = remote_field_names - local_field_names
        if only_local:
            differences.append(f"fields: local-only: {only_local}")
        if only_remote:
            differences.append(f"fields: remote-only: {only_remote}")

    # Compare common fields
    for field_name in local_field_names & remote_field_names:
        local_field = local_fields[field_name]
        remote_field = remote_fields[field_name]
        if local_field != remote_field:
            differences.append(
                f"fields.{field_name}: local={local_field} remote={remote_field}"
            )

    # Compare constraints
    local_constraints = local_data.get("constraints", {})
    remote_constraints = remote_data.get("constraints", {})
    if local_constraints != remote_constraints:
        differences.append(
            f"constraints: local={local_constraints} remote={remote_constraints}"
        )

    return differences


async def compare_types_with_peer(
    conn: Connection,
    type_paths: list[str],
    local_types: dict[str, Any],
) -> list[TypeComparisonResult]:
    """Compare local and remote type definitions.

    Args:
        conn: Active connection to remote peer.
        type_paths: List of type paths to compare.
        local_types: Dict mapping type name to Entity object.

    Returns:
        List of TypeComparisonResult for each type.
    """
    from entity_core.utils.ecf import compute_ecf_hash

    results = []

    for type_path in type_paths:
        result = TypeComparisonResult(type_path=type_path, match=False, differences=[])

        # Check local type exists
        if type_path not in local_types:
            result.differences = ["Local missing type"]
            results.append(result)
            continue

        # Fetch remote type
        remote_data = await fetch_remote_type(conn, type_path)
        if remote_data is None:
            result.differences = ["Remote missing type"]
            results.append(result)
            continue

        # Compute hashes
        local_entity = local_types[type_path]
        local_hash = local_entity.compute_hash()
        result.local_hash = local_hash

        remote_hashable = {"type": "system/type", "data": remote_data}
        remote_hash = compute_ecf_hash(remote_hashable)
        result.remote_hash = remote_hash

        # Compare
        if local_hash == remote_hash:
            result.match = True
            result.differences = []
        else:
            result.differences = compare_type_data(local_entity.data, remote_data)

        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Target parsing & connection helpers
# ---------------------------------------------------------------------------

def parse_target(target: str) -> tuple[str, int, str]:
    """Parse 'host:port/path' into (host, port, path).

    Examples:
        '127.0.0.1:9001/system/types/' -> ('127.0.0.1', 9001, 'system/types/')
        '127.0.0.1:9001'               -> ('127.0.0.1', 9001, '')
        '[::1]:9001/path'              -> ('::1', 9001, 'path')

    Args:
        target: Target string in host:port or host:port/path form.

    Returns:
        Tuple of (host, port, path).

    Raises:
        ValueError: If target format is invalid.
    """
    # Handle IPv6 addresses in brackets
    if target.startswith("["):
        bracket_end = target.index("]")
        host = target[1:bracket_end]
        rest = target[bracket_end + 1:]  # e.g. ':9001/path'
        if not rest.startswith(":"):
            raise ValueError(f"Invalid target format: {target}")
        rest = rest[1:]  # strip leading ':'
    else:
        # Find the first colon that separates host from port
        colon_idx = target.index(":")
        host = target[:colon_idx]
        rest = target[colon_idx + 1:]  # e.g. '9001/path'

    # Split rest into port and optional path
    slash_idx = rest.find("/")
    if slash_idx == -1:
        port_str = rest
        path = ""
    else:
        port_str = rest[:slash_idx]
        path = rest[slash_idx + 1:]  # strip leading '/'

    return host, int(port_str), path


def _load_keypair(identity_name: str) -> Keypair:
    """Load a keypair by identity name, or generate ephemeral.

    Args:
        identity_name: Name of identity in ~/.entity/identities/.

    Returns:
        A Keypair for authentication.
    """
    try:
        identity = load_identity(identity_name)
        return identity.keypair
    except FileNotFoundError:
        print(f"Identity '{identity_name}' not found, generating ephemeral keypair",
              file=sys.stderr)
        return Keypair.generate()


@asynccontextmanager
async def open_connection(
    host: str,
    port: int,
    identity: str = "framework-admin",
) -> AsyncIterator[tuple[Connection, str]]:
    """Connect to a peer, yield (conn, remote_peer_id), auto-close.

    Args:
        host: Remote host.
        port: Remote port.
        identity: Identity name for authentication.

    Yields:
        Tuple of (Connection, remote_peer_id).
    """
    keypair = _load_keypair(identity)
    conn = await Connection.connect(host, port, keypair)
    try:
        yield conn, conn.session.remote_peer_id
    finally:
        conn.close()
        await conn.wait_closed()


# ---------------------------------------------------------------------------
# Entity tree subcommands
# ---------------------------------------------------------------------------

async def cmd_ls(args: argparse.Namespace) -> None:
    """List entities at a path (tree listing)."""
    host, port, path = parse_target(args.target)
    # ls auto-appends / if missing
    if path and not path.endswith("/"):
        path += "/"

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        # Use tree handler with typed params entity
        response = await conn.execute(
            uri=f"entity://{remote_peer}/system/tree",
            operation="get",
            params={
                "type": "system/tree/get-request",
                "data": {"path": path},
            },
        )
        if response.status != 200:
            _print_error(response)
            sys.exit(1)

        result = response.result
        if isinstance(result, dict) and result.get("type") == "tree/listing":
            print(display_entity(result))
        else:
            # Not a listing — show whatever came back
            print(display_entity(result) if isinstance(result, dict) else result)


async def cmd_cat(args: argparse.Namespace) -> None:
    """Display entity content with type-aware formatting."""
    host, port, path = parse_target(args.target)
    # cat reads entity, so no trailing slash
    path = path.rstrip("/")

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        # Try tree handler first with typed params entity
        response = await conn.execute(
            uri=f"entity://{remote_peer}/system/tree",
            operation="get",
            params={
                "type": "system/tree/get-request",
                "data": {"path": path},
            },
        )
        # If tree handler returns 404, try direct path (for dynamic endpoints)
        if response.status == 404:
            response = await conn.execute(
                uri=f"entity://{remote_peer}/{path}",
                operation="get",
            )
        if response.status != 200:
            _print_error(response)
            sys.exit(1)

        result = response.result
        if isinstance(result, dict):
            print(display_entity(result))
        else:
            print(result)


async def cmd_info(args: argparse.Namespace) -> None:
    """Show entity metadata only (type, hash, refs)."""
    host, port, path = parse_target(args.target)

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        response = await conn.execute(
            uri=f"entity://{remote_peer}/{path}",
            operation="get",
        )
        if response.status != 200:
            _print_error(response)
            sys.exit(1)

        result = response.result
        if isinstance(result, dict):
            print(display_info(result))
        else:
            print(result)


async def cmd_get(args: argparse.Namespace) -> None:
    """Get raw entity in CBOR diagnostic notation (machine-readable)."""
    host, port, path = parse_target(args.target)

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        response = await conn.execute(
            uri=f"entity://{remote_peer}/{path}",
            operation="get",
        )
        if response.status != 200:
            _print_error(response)
            sys.exit(1)

        print(to_diag(response.result, indent=2))


async def cmd_put(args: argparse.Namespace) -> None:
    """Store an entity at a path."""
    host, port, path = parse_target(args.target)

    # Parse --data as JSON
    try:
        data = json.loads(args.data) if args.data else {}
    except json.JSONDecodeError as e:
        print(f"Invalid JSON for --data: {e}", file=sys.stderr)
        sys.exit(1)

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        response = await conn.execute(
            uri=f"entity://{remote_peer}/{path}",
            operation="write",
            params={
                "entity": {
                    "type": args.type,
                    "data": data,
                },
            },
        )
        if response.status != 200:
            _print_error(response)
            sys.exit(1)

        # Storage handler returns a flat {hash, uri}; after §3.4 wire
        # wrapping the payload lives at result_data.
        result = response.result_data
        if isinstance(result, dict) and "hash" in result:
            print(f"Stored: {result['hash']}")
        else:
            print(to_diag(response.result, indent=2))


async def cmd_registry_issue_binding(args: argparse.Namespace) -> None:
    """PROPOSAL-PEER-ISSUED §3.2 — curated operator tool.

    Sign a peer-issued binding with the registry key and publish the three
    artifacts into the running registry peer's tree: the binding body at the
    universal location, its signature at the invariant pointer, and the
    by-name index pointer. No protocol, no handler — operator discipline.
    """
    import time
    import unicodedata
    from entity_core.protocol.auth import create_identity_entity, create_signature_entity
    from entity_core.protocol.entity import Entity

    host, port, _ = parse_target(args.target)
    name = unicodedata.normalize("NFC", args.name)
    if "/" in name or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in name):
        print(f"Invalid name {args.name!r} (no '/' or control chars)", file=sys.stderr)
        sys.exit(1)

    transports = json.loads(args.transports) if args.transports else []
    keypair = _load_keypair(args.identity)

    binding = Entity(type="system/registry/binding", data={
        "name": name,
        "kind": "peer-issued",
        "target_peer_id": args.target_peer_id,
        "transports": transports,
        "issued_at": int(time.time() * 1000),
        "ttl": args.ttl,
    })
    bh = binding.compute_hash()
    sig = create_signature_entity(keypair, bh, create_identity_entity(keypair).compute_hash())

    artifacts = [
        (f"system/registry/binding/{bh.hex()}", binding),                 # universal location
        (f"system/signature/{bh.hex()}", sig),                            # invariant pointer (V7 §5.2)
        (f"system/registry/binding/by-name/{name}", binding),             # by-name index (§2.2)
    ]
    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        for path, entity in artifacts:
            resp = await conn.execute(
                uri=f"entity://{remote_peer}/{path}",
                operation="write",
                params={"entity": {"type": entity.type, "data": entity.data}},
            )
            if resp.status != 200:
                _print_error(resp)
                sys.exit(1)
    print(f"Issued peer-issued binding {name!r} → {args.target_peer_id}")
    print(f"  binding_hash: {bh.hex()}")
    print(f"  signed by registry: {keypair.peer_id}")


async def cmd_registry_set_policy(args: argparse.Namespace) -> None:
    """EXTENSION-REGISTRY §6a.9.1 — install the registry's issuer-policy.

    Writing a policy is what turns a curated/static registry *live*: it begins
    accepting `register-request`. `domain-control` is deferred (§6a.10) — use
    `open` / `allowlist` / `manual`.
    """
    host, port, _ = parse_target(args.target)
    if args.mode == "domain-control":
        print("domain-control mode is deferred (§6a.9.1) — use open/allowlist/manual",
              file=sys.stderr)
        sys.exit(1)
    data = {
        "mode": args.mode,
        "allowlist": json.loads(args.allowlist) if args.allowlist else None,
        "name_constraints": args.name_constraints,
        "default_ttl": args.default_ttl,
    }
    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        resp = await conn.execute(
            uri=f"entity://{remote_peer}/system/registry",
            operation="set-issuer-policy",
            params={"type": "system/registry/issuer-policy", "data": data},
        )
        if resp.status != 200:
            _print_error(resp)
            sys.exit(1)
    print(f"Issuer policy set on {remote_peer}: mode={args.mode}")


async def cmd_registry_register(args: argparse.Namespace) -> None:
    """EXTENSION-REGISTRY §6a.9 — publisher self-registration (`register-request`).

    Builds the request, signs it with the local identity (the layer-1
    ownership proof — the requester IS `target_peer_id`), and sends it with the
    signature + identity in `included`. The registry applies its issuer-policy
    and, on approval, signs + publishes the binding.
    """
    import os
    import time
    import unicodedata
    from entity_core.protocol.auth import create_identity_entity, create_signature_entity
    from entity_core.protocol.entity import Entity

    host, port, _ = parse_target(args.target)
    name = unicodedata.normalize("NFC", args.name)
    if "/" in name or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in name):
        print(f"Invalid name {args.name!r} (no '/' or control chars)", file=sys.stderr)
        sys.exit(1)

    keypair = _load_keypair(args.identity)
    transports = json.loads(args.transports) if args.transports else []
    request_data = {
        "name": name,
        "target_peer_id": keypair.peer_id,  # layer-1: requester proves it holds this key
        "transports": transports,
        "requested_ttl": args.ttl,
        "nonce": os.urandom(16),
        "issued_at": int(time.time() * 1000),
    }
    request = Entity(type="system/registry/register-request", data=request_data)
    rh = request.compute_hash()
    identity = create_identity_entity(keypair)
    sig = create_signature_entity(keypair, rh, identity.compute_hash())

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        resp = await conn.execute(
            uri=f"entity://{remote_peer}/system/registry",
            operation="register-request",
            params={"type": "system/registry/register-request", "data": request_data},
            included=[identity.to_dict(), sig.to_dict()],
        )
        if resp.status != 200:
            _print_error(resp)
            sys.exit(1)
        result = resp.result if isinstance(resp.result, dict) else {}
    status = (result.get("data") or {}).get("status") if "data" in result else result.get("status")
    print(f"register-request {name!r} → {keypair.peer_id}: {status or result}")


async def cmd_rm(args: argparse.Namespace) -> None:
    """Remove a tree entry."""
    host, port, path = parse_target(args.target)

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        response = await conn.execute(
            uri=f"entity://{remote_peer}/{path}",
            operation="delete",
        )
        if response.status != 200:
            _print_error(response)
            sys.exit(1)

        result = response.result
        if isinstance(result, dict):
            print(to_diag(result, indent=2))
        else:
            print(result if result else "Deleted.")


async def cmd_tree(args: argparse.Namespace) -> None:
    """Show the full entity tree from a path."""
    host, port, path = parse_target(args.target)
    if path and not path.endswith("/"):
        path += "/"

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        lines: list[str] = []
        root_label = f"entity://{remote_peer}/{path}" if path else f"entity://{remote_peer}/"
        lines.append(root_label)
        await _tree_walk(conn, remote_peer, path, lines, prefix="")
        print("\n".join(lines))


async def _tree_walk(
    conn: Connection,
    remote_peer: str,
    path: str,
    lines: list[str],
    prefix: str,
) -> None:
    """Recursively walk the entity tree and append formatted lines.

    Args:
        conn: Active connection.
        remote_peer: Remote peer ID.
        path: Current path (with trailing /).
        lines: Accumulator for output lines.
        prefix: Indentation prefix for this level (e.g. "│   ").
    """
    response = await conn.execute(
        uri=f"entity://{remote_peer}/{path}",
        operation="get",
    )
    if response.status != 200:
        return

    result = response.result
    if not isinstance(result, dict) or result.get("type") != "tree/listing":
        return

    entries = result.get("data", {}).get("entries", {})
    names = sorted(entries.keys())

    for i, name in enumerate(names):
        info = entries[name]
        is_last = (i == len(names) - 1)
        connector = "└── " if is_last else "├── "
        has_children = info.get("has_children", False)
        hash_val = info.get("hash")

        if has_children:
            display_name = name + "/"
            suffix = ""
        elif hash_val:
            display_name = name
            suffix = f"  {_truncate_hash(hash_val, 30)}"
        else:
            display_name = name
            suffix = ""

        lines.append(f"{prefix}{connector}{display_name}{suffix}")

        if has_children:
            child_prefix = prefix + ("    " if is_last else "│   ")
            child_path = path + name + "/"
            await _tree_walk(conn, remote_peer, child_path, lines, child_prefix)


def _truncate_hash(hash_val: str | dict | bytes, max_len: int) -> str:
    """Truncate a hash for inline tree display.

    Args:
        hash_val: Hash as string, bytes, or structured dict.
        max_len: Maximum length of displayed hash.

    Returns:
        Truncated hash string.
    """
    from entity_core.utils.ecf import hash_to_string

    # Convert to string based on type
    if isinstance(hash_val, bytes):
        hash_str = hash_to_string(hash_val)
    else:
        hash_str = hash_val

    if len(hash_str) <= max_len:
        return hash_str
    return hash_str[:max_len] + "..."


async def cmd_exec(args: argparse.Namespace) -> None:
    """Execute an arbitrary operation."""
    host, port, path = parse_target(args.target)

    # Parse optional params as JSON
    params: dict[str, Any] = {}
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON for params: {e}", file=sys.stderr)
            sys.exit(1)

    async with open_connection(host, port, args.identity) as (conn, remote_peer):
        response = await conn.execute(
            uri=f"entity://{remote_peer}/{path}",
            operation=args.operation,
            params=params if params else None,
        )
        if response.status != 200:
            _print_error(response)
            sys.exit(1)

        result = response.result
        if isinstance(result, dict):
            print(display_entity(result))
        else:
            print(result)


# ---------------------------------------------------------------------------
# Error display helper
# ---------------------------------------------------------------------------

def _print_error(response: ExecuteResponse) -> None:
    """Print an error response to stderr."""
    result = response.result
    if isinstance(result, dict) and ("code" in result or "message" in result):
        print(display_error(result), file=sys.stderr)
    else:
        print(f"Error (status {response.status}): {result}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Legacy print helper (used by connect command)
# ---------------------------------------------------------------------------

def _print_response(path: str, response: ExecuteResponse) -> None:
    """Pretty print an execute response (legacy connect command)."""
    print(f"\n--- {path} ---")
    print(f"Status: {response.status}")

    if response.status != 200:
        print(f"Error: {response.result}")
        return

    result = response.result
    if isinstance(result, dict):
        if result.get("type") == "tree/listing":
            data = result.get("data", {})
            print(f"Type: tree/listing")
            print(f"Path: {data.get('path')}")
            print(f"Count: {data.get('count')}")
            entries = data.get("entries", {})
            for name, info in sorted(entries.items()):
                hash_val = info.get("hash")
                children = info.get("has_children", False)
                hash_str = f"{hash_val[:30]}..." if hash_val else "(no entity)"
                suffix = " [+]" if children else ""
                print(f"  {name}: {hash_str}{suffix}")
        elif "type" in result:
            print(f"Type: {result.get('type')}")
            print(f"Data: {to_diag(result.get('data'), indent=2)}")
        else:
            print(to_diag(result, indent=2))
    else:
        print(result)


# ---------------------------------------------------------------------------
# Unchanged commands: start, connect, list-identities, compare-types
# ---------------------------------------------------------------------------

def cmd_list_identities() -> None:
    """List available identities."""
    identities = list_identities()
    if not identities:
        print("No identities found in ~/.entity/identities/")
        print("Create one with: entity-cli identity create <name>")
        return

    print("Available identities:")
    for name in identities:
        try:
            identity = load_identity(name)
            print(f"  {name}: {identity.peer_id_base58}")
        except Exception as e:
            print(f"  {name}: (error loading: {e})")


async def cmd_start(args: argparse.Namespace) -> None:
    """Start a peer and listen for connections."""
    host, port_str = args.listen.rsplit(":", 1)
    port = int(port_str)

    # V7 v7.69 §4.5 — set the process-global default content_hash_format from
    # --hash-type. This is the peer's home/preferred format (advertised in
    # hello, used for non-connection-bound startup state); per-connection
    # authoring threads the negotiated active format explicitly.
    hash_type = getattr(args, "hash_type", "sha256")
    if hash_type == "sha384":
        from entity_core.utils.ecf import ALG_ECFV1_SHA384, set_default_hash_algorithm
        set_default_hash_algorithm(ALG_ECFV1_SHA384)
        print("Default content_hash_format: ecfv1-sha384 (advertises sha384, sha256)")

    # Load identity. When the named identity is absent, mint an ephemeral
    # keypair of the requested --key-type. This is the path the cross-impl
    # validate-peer harness uses to spawn Python peers on different crypto
    # backends (v7.67 Phase 2) without pre-provisioning identity files.
    key_type = getattr(args, "key_type", "ed25519")
    try:
        identity = load_identity(args.identity)
        keypair = identity.keypair
        print(f"Loaded identity: {args.identity}")
        # Stored Ed25519 identities can't serve an ed448 backend.
        if key_type != keypair.key_type:
            print(
                f"Warning: identity '{args.identity}' is {keypair.key_type}, "
                f"but --key-type {key_type} was requested; using the stored "
                f"{keypair.key_type} keypair."
            )
    except FileNotFoundError:
        if key_type == "ed448":
            from entity_core.crypto.ed448 import Ed448Keypair
            keypair = Ed448Keypair.generate()
        else:
            keypair = Keypair.generate()
        print(
            f"Identity '{args.identity}' not found; minted ephemeral "
            f"{key_type} keypair ({keypair.peer_id[:20]}...)"
        )

    # Load admin peer IDs
    admin_peer_ids: set[str] = set()
    for admin_name in args.admin:
        try:
            admin_identity = load_identity(admin_name)
            admin_peer_ids.add(admin_identity.peer_id_base58)
            print(f"Admin: {admin_name} ({admin_identity.peer_id_base58[:20]}...)")
        except FileNotFoundError:
            print(f"Warning: Admin identity '{admin_name}' not found, skipping")

    # Use with_all_handlers() for a "standard peer" with full subscription support
    builder = PeerBuilder().with_keypair(keypair).with_all_handlers()
    if admin_peer_ids:
        builder.with_admin_peer_ids(admin_peer_ids)

    # GUIDE-CONFORMANCE §7a: opt-in conformance test handlers. OFF by
    # default; flipped on for a validate-peer run. Do NOT enable in
    # production — dispatch-outbound originates outbound EXECUTEs from
    # caller-supplied params.
    if getattr(args, "validate", False):
        builder.with_conformance_handlers()
        print("WARNING: --validate enables the GUIDE-CONFORMANCE §7a test "
              "handlers (system/validate/*). For conformance runs only — "
              "do NOT use in production.")

    # V7 §6.9a (F27) peer-authority-bootstrap. The owner cap defaults to
    # this peer's own identity; --operator names a distinct owner.
    operator_name = getattr(args, "operator", None)
    if operator_name:
        try:
            operator_identity = load_identity(operator_name)
            from entity_core.protocol.auth import create_identity_entity
            builder.with_owner_identity(
                create_identity_entity(operator_identity.keypair)
            )
            print(f"Operator (owner): {operator_name} "
                  f"({operator_identity.peer_id_base58[:20]}...)")
        except FileNotFoundError:
            print(f"Warning: operator identity '{operator_name}' not found, "
                  "defaulting owner to self")
    seed_policy_file = getattr(args, "seed_policy", None)
    if seed_policy_file:
        builder.with_seed_policy_from_file(seed_policy_file)
        print(f"Seed policy: {seed_policy_file}")

    # --open-access is the cross-impl-aligned name for the same
    # full-access-to-connecting-peers semantic as --debug. Either flag
    # enables it (peer-manager passes --open-access; humans may use either).
    # DEPRECATED (V7 §6.9a/§3.7) — retained one cycle; migrate to
    # --seed-policy with a real `default` entry.
    open_access = bool(args.debug) or bool(getattr(args, "open_access", False))
    if open_access:
        print("WARNING: --open-access/--debug is DEPRECATED (V7 §6.9a/§3.7, "
              "removed v7.75) — it is the degenerate seed policy "
              "`default -> *`. Migrate to --seed-policy with a real "
              "`default` entry.")
        builder.debug_mode(True)
    peer = builder.build()

    # Install the role extension's initial-grant policy resolver so the
    # AUTHENTICATE flow honors `system/role/initial-grant-policy`
    # (recognize-on-attestation et al. per EXTENSION-ROLE §4.7).
    # Always wired — the resolver returns None when no policy is bound,
    # and the priority order in `_get_grants_for_peer` is designed so
    # an explicit policy fires ahead of debug_mode (otherwise dev runs
    # with --debug couldn't exercise the policy at all).
    from entity_handlers import PolicyGrantResolver
    peer.set_grant_resolver(
        PolicyGrantResolver(
            peer.emit_pathway, local_peer_id=keypair.peer_id,
        )
    )

    # Configure local/files root mappings if --files flags provided
    if getattr(args, "files", None):
        from entity_handlers import LocalFilesExtension

        local_files_ext: LocalFilesExtension | None = None
        for ext in peer._extensions:
            if isinstance(ext, LocalFilesExtension):
                local_files_ext = ext
                break
        if local_files_ext is None:
            print("WARNING: --files set but no LocalFilesExtension installed; "
                  "use a builder that calls with_local_files_handler().")
        else:
            for spec in args.files:
                parts = spec.split(":", 2)
                if len(parts) != 3:
                    print(f"WARNING: --files spec {spec!r} not in "
                          "'name:/fs/path:tree/prefix/' form; skipping")
                    continue
                root_name, fs_path, tree_prefix = parts
                os.makedirs(fs_path, exist_ok=True)
                try:
                    local_files_ext.add_root(
                        root_name,
                        prefix=tree_prefix,
                        filesystem_root=fs_path,
                    )
                    print(
                        f"Files root '{root_name}': {fs_path} → {tree_prefix}"
                    )
                except ValueError as exc:
                    print(f"WARNING: --files {root_name} skipped: {exc}")

    # Store history configs if --history flags provided
    if args.history:
        from entity_core.protocol.entity import Entity
        from entity_core.storage.emit import EmitContext

        for i, pattern in enumerate(args.history):
            config_entity = Entity(
                type="system/history/config",
                data={"pattern": pattern, "enabled": True},
            )
            config_path = f"system/history/config/cli-{i}"
            config_uri = peer.emit_pathway.entity_tree.normalize_uri(config_path)
            peer.emit_pathway.emit(config_uri, config_entity, EmitContext.bootstrap())
            print(f"History: recording enabled for pattern '{pattern}'")

    print(f"Peer ID: {keypair.peer_id}")
    print(f"Listening on {host}:{port}")
    if open_access:
        print("WARNING: Open-access mode enabled - ALL peers get full access")
    elif admin_peer_ids:
        print(f"Admin peers: {len(admin_peer_ids)}")
    else:
        print("No admin peers configured (peers can connect but won't receive capabilities)")

    await peer.start(host, port)

    # Phase P / C1: publish a signed root over the current tree BEFORE the
    # serving scope is built, so a --serve-closure-root scope can cover the
    # published root's closure (and MANIFEST_GET serves a real signed root).
    if getattr(args, "publish_root", False):
        pr_entity = peer.publish_root()
        print(
            f"Published signed root: seq={pr_entity.data['seq']} "
            f"root_hash={pr_entity.data['root_hash'].hex()[:16]}…"
        )

    # Chunk D HTTP-live listener (per EXTENSION-NETWORK §6.5.2c + v1.4
    # Amendment 3). Binds alongside the TCP listener; both share the
    # same dispatcher. Self-publishes a system/peer/transport/http
    # profile (D1 SHOULD).
    http_addr = getattr(args, "http_addr", None)

    # Chunk E serving-mode flags (per CHUNK-E-IMPL-PLAN §3 + arch ruling
    # §1.2). Build the scope predicate from --serve-* flags. Validation
    # happens BEFORE starting any listener so configuration errors surface
    # immediately.
    poll_addr = getattr(args, "http_poll_addr", None)
    poll_mount_on_live = getattr(args, "http_poll_mount_on_live", False)
    poll_prefix = getattr(args, "http_poll_prefix", "/poll") or "/poll"
    serve_namespace = getattr(args, "serve_namespace", None)
    serve_closure_root = getattr(args, "serve_closure_root", None)
    serve_whole_store = getattr(args, "serve_scope_whole_store", False)

    serving_enabled = poll_addr is not None or poll_mount_on_live
    if poll_addr is not None and poll_mount_on_live:
        raise SystemExit(
            "--http-poll-addr and --http-poll-mount-on-live are mutually "
            "exclusive (pick Posture 1 isolated-port OR Posture 2 same-listener)"
        )
    scope_flags_set = sum([
        bool(serve_namespace),
        bool(serve_closure_root),
        bool(serve_whole_store),
    ])
    if serving_enabled and scope_flags_set != 1:
        raise SystemExit(
            "serving requires exactly one of --serve-namespace, "
            "--serve-closure-root, --serve-scope-whole-store"
        )
    if scope_flags_set > 0 and not serving_enabled:
        raise SystemExit(
            "--serve-* flags require --http-poll-addr or "
            "--http-poll-mount-on-live to be set"
        )

    scope_predicate = None
    scope_description = None
    if serving_enabled:
        from entity_core.peer.serving import (
            CapTokenScope,
            ClosureScope,
            WholeStoreScope,
        )
        if serve_namespace:
            # Amendment 5: `serve_scope` is a cap-token. `--serve-namespace`
            # synthesizes a published-set cap whose `resources` grant `get`
            # on `{NS}/*`. Same evaluator the live-EXECUTE surface uses;
            # one ACL machinery (no NamespaceScope second code path).
            scope_predicate = CapTokenScope.from_namespace(
                peer.entity_tree, serve_namespace, peer.peer_id,
            )
            scope_description = scope_predicate.describe()
        elif serve_closure_root:
            # Phase P / C2: serve the transitive closure of a signed root.
            # When --publish-root is set, default to the just-published root's
            # closure (the common case); otherwise parse the flag value as a
            # hex root hash. Amendment 10: closure-of-signed-root.
            from entity_core.peer.published_root import (
                closure_scope_for_published_root,
            )

            if serve_closure_root in ("", "published", "@published"):
                scope_predicate = closure_scope_for_published_root(
                    peer.entity_tree, peer.content_store,
                )
            else:
                scope_predicate = ClosureScope(
                    peer.entity_tree,
                    peer.content_store,
                    bytes.fromhex(serve_closure_root),
                )
            scope_description = scope_predicate.describe()
        elif serve_whole_store:
            scope_predicate = WholeStoreScope()
            scope_description = "whole-store"
            # Arch ruling §1.3 T2/T3: operator owns the consequence. Make
            # that obligation loud at startup so a leaked hash → cap-token
            # exposure isn't a surprise discovery later.
            print(
                "WARNING: --serve-scope-whole-store enabled; "
                "serving every hash in the content store. "
                "Operator is responsible for T2 (known-hash retrieval of "
                "unpublished content) and T3 (cap/signature harvesting) "
                "per arch ruling §1.3.",
                file=sys.stderr,
            )

    if http_addr:
        http_host, http_port_str = http_addr.rsplit(":", 1)
        http_port = int(http_port_str)
        http_path = getattr(args, "http_path", "/entity") or "/entity"
        http_base_url = getattr(args, "http_base_url", None)
        if http_base_url is None:
            http_base_url = f"http://{http_host}:{http_port}{http_path}"
        # Posture 2: mount poll routes on the same listener.
        live_poll_prefix = poll_prefix if poll_mount_on_live else None
        live_poll_base_url = None
        if poll_mount_on_live:
            live_poll_base_url = f"http://{http_host}:{http_port}{poll_prefix}"
        await peer.start_http(
            http_host, http_port,
            base_url=http_base_url,
            url_path=http_path,
            poll_prefix=live_poll_prefix,
            scope_predicate=scope_predicate if poll_mount_on_live else None,
            poll_base_url=live_poll_base_url,
        )
        print(f"HTTP listening on {http_host}:{http_port}{http_path}")
        print(f"HTTP profile advertised: {http_base_url}")
        if poll_mount_on_live:
            print(
                f"HTTP poll routes mounted on same listener under "
                f"{poll_prefix}/ (scope={scope_description})"
            )

    # Posture 1: isolated serving port.
    if poll_addr is not None:
        poll_host, poll_port_str = poll_addr.rsplit(":", 1)
        poll_port = int(poll_port_str)
        await peer.start_http_poll(
            poll_host, poll_port,
            scope_predicate=scope_predicate,
            poll_prefix="",
        )
        print(
            f"HTTP poll listening on {poll_host}:{poll_port} "
            f"(scope={scope_description}) — Posture 1 (isolated port)"
        )

    # EXTENSION-DISCOVERY v1.0 §3: advertise self on the LAN over mDNS so other
    # peers can discover this one (the same-network demo). profile_ref is the
    # transport profile-id to dial (NETWORK §6.5); the TCP listen addr/port are
    # carried in the §3.2 SRV/TXT record.
    if getattr(args, "discovery_announce", False):
        from entity_handlers.discovery import DiscoveryExtension

        disc_ext = next(
            (e for e in peer._extensions if isinstance(e, DiscoveryExtension)),
            None,
        )
        if disc_ext is None:
            print("WARNING: --discovery-announce set but no DiscoveryExtension "
                  "installed; use a builder that calls with_discovery_handler().")
        elif "mdns" not in disc_ext._backends:
            print("WARNING: --discovery-announce set but the mDNS backend is "
                  "unavailable (zeroconf import failed).")
        else:
            profile_ref = getattr(args, "discovery_profile", None) or "tcp"
            try:
                await disc_ext._backends["mdns"].announce(
                    profile_ref,
                    {
                        "peer_id_hint": keypair.peer_id,
                        "profile_ref": profile_ref,
                        "address": host if host not in ("0.0.0.0", "") else None,
                        "port": port,
                    },
                )
                print(f"mDNS: announcing on the LAN (profile_ref={profile_ref})")
            except Exception as exc:
                print(f"WARNING: mDNS announce failed: {exc}")

    print("Press Ctrl+C to stop")

    try:
        await peer.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        await peer.stop()


async def cmd_connect(args: argparse.Namespace) -> None:
    """Connect to a peer (legacy command)."""
    host, port_str = args.address.rsplit(":", 1)
    port = int(port_str)

    # Load identity
    try:
        identity = load_identity(args.identity)
        keypair = identity.keypair
        print(f"Using identity: {args.identity} ({keypair.peer_id[:20]}...)")
    except FileNotFoundError:
        print(f"Identity '{args.identity}' not found, generating ephemeral keypair")
        keypair = Keypair.generate()

    try:
        conn = await Connection.connect(host, port, keypair)
        print(f"Connected to {conn.session.remote_peer_id}")

        if conn.capability is None:
            print("Warning: No capability received from peer")

        remote_peer = conn.session.remote_peer_id

        if args.status:
            response = await conn.execute(
                uri=f"entity://{remote_peer}/system/status",
                operation="get",
            )
            _print_response("system/status", response)

        if args.get:
            path = args.get
            response = await conn.execute(
                uri=f"entity://{remote_peer}/{path}",
                operation="get",
            )
            _print_response(path, response)

        if args.read:
            path = args.read
            response = await conn.execute(
                uri=f"entity://{remote_peer}/{path}",
                operation="get",
            )
            _print_response(path, response)

        if args.execute:
            path, operation = args.execute
            response = await conn.execute(
                uri=f"entity://{remote_peer}/{path}",
                operation=operation,
            )
            _print_response(f"{path} ({operation})", response)

        conn.close()
        await conn.wait_closed()

    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)


async def cmd_compare_types(args: argparse.Namespace) -> None:
    """Compare type definitions with another peer."""
    from entity_core.types import get_all_type_entities
    from entity_core.utils.ecf import hash_to_display

    host, port_str = args.address.rsplit(":", 1)
    port = int(port_str)

    # Load identity
    try:
        identity = load_identity(args.identity)
        keypair = identity.keypair
    except FileNotFoundError:
        keypair = Keypair.generate()

    try:
        conn = await Connection.connect(host, port, keypair)
        remote_peer_id = conn.session.remote_peer_id

        print(f"Comparing types with peer: {remote_peer_id[:20]}...")
        print()

        # Get local types
        local_types = {e.data["name"]: e for e in get_all_type_entities()}

        # Compare using utility function
        results = await compare_types_with_peer(conn, CORE_TYPE_PATHS, local_types)

        conn.close()
        await conn.wait_closed()

        # Compute stats
        matches = [r for r in results if r.match]
        mismatches = [r for r in results if not r.match]

        # Output results
        if args.json:
            # Convert to JSON-serializable format
            json_results = []
            for r in results:
                jr = asdict(r)
                if jr["local_hash"]:
                    jr["local_hash"] = hash_to_display(jr["local_hash"])
                if jr["remote_hash"]:
                    jr["remote_hash"] = hash_to_display(jr["remote_hash"])
                json_results.append(jr)
            print(json.dumps(json_results, indent=2))
        else:
            print("=" * 80)
            print(f"TYPE COMPARISON: Python vs {remote_peer_id[:16]}...")
            print("=" * 80)
            print()

            for r in results:
                status = "[MATCH]" if r.match else "[DIFF] "
                print(f"{status} {r.type_path}")

                if args.verbose and not r.match:
                    if r.local_hash:
                        print(f"         Local:  {hash_to_display(r.local_hash)}")
                    if r.remote_hash:
                        print(f"         Remote: {hash_to_display(r.remote_hash)}")
                    for diff in r.differences or []:
                        print(f"         - {diff}")

            print()
            print("=" * 80)
            print(f"Summary: {len(matches)}/{len(results)} types match")
            if mismatches:
                print(f"         {len(mismatches)} types differ")
            print("=" * 80)

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# ---------------------------------------------------------------------------
# wire-conformance command
# ---------------------------------------------------------------------------

def cmd_wire_conformance(args: argparse.Namespace) -> None:
    """ECF wire-conformance harness (emit-canonical mode)."""
    from entity_core.conformance import emit_canonical, load_corpus
    from entity_core.conformance.emit import encode_emission

    if args.wc_command != "emit-canonical":
        print("usage: entity-core wire-conformance emit-canonical "
              "--input <path> --out <path>", file=sys.stderr)
        sys.exit(2)

    impl_version = args.impl_version
    if impl_version is None:
        import subprocess
        try:
            sha = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=os.path.dirname(os.path.abspath(__file__)),
                stderr=subprocess.DEVNULL,
            ).decode().strip()
            impl_version = f"git-{sha}"
        except (subprocess.CalledProcessError, FileNotFoundError):
            impl_version = "unknown"

    corpus = load_corpus(args.input)
    emission = emit_canonical(corpus, impl_version)
    encoded = encode_emission(emission)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "wb") as f:
        f.write(encoded)

    n_enc = len(emission["encode_results"])
    n_dec = len(emission["decode_results"])
    n_err = len(emission["errors"])
    print(
        f"emit-canonical: {n_enc} encode_results, {n_dec} decode_results, "
        f"{n_err} errors → {args.out} ({len(encoded)} bytes)"
    )
    if n_err:
        for vid, msg in emission["errors"].items():
            print(f"  error {vid}: {msg}")


# ---------------------------------------------------------------------------
# Argument parser & main
# ---------------------------------------------------------------------------

def _add_identity_arg(parser: argparse.ArgumentParser) -> None:
    """Add the common --identity/-i argument to a subparser."""
    parser.add_argument(
        "--identity", "-i",
        default="framework-admin",
        help="Identity name from ~/.entity/identities/ (default: 'framework-admin')",
    )


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="entity-core",
        description="Entity Core Protocol - Python Implementation",
    )
    parser.add_argument(
        "-v", "-d", "--debug",
        action="store_true",
        help="Enable debug logging (wire-level tracing)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # --- start command ---
    start_parser = subparsers.add_parser("start", help="Start a peer")
    start_parser.add_argument(
        "--listen",
        default="127.0.0.1:9001",
        help="Address to listen on (default: 127.0.0.1:9001)",
    )
    start_parser.add_argument(
        "--identity", "-i",
        default="default",
        help="Identity name from ~/.entity/identities/ (default: 'default')",
    )
    start_parser.add_argument(
        "--key-type",
        dest="key_type",
        choices=["ed25519", "ed448"],
        default="ed25519",
        help="Crypto backend for the peer's keypair (default: ed25519). "
             "Cross-impl alias for Go peer-manager's --key-type flag — lets "
             "validate-peer exercise different crypto backends against a "
             "Python peer (v7.67 Phase 2 cross-key matrix). When the named "
             "--identity is not found, an ephemeral keypair of this type is "
             "minted.",
    )
    start_parser.add_argument(
        "--hash-type",
        dest="hash_type",
        choices=["sha256", "sha384"],
        default="sha256",
        help="Default content_hash_format the peer authors non-connection-"
             "bound state under (default: sha256). V7 v7.69 §4.5: this sets "
             "the peer's home/preferred hash format and its advertised "
             "hash_formats; per-connection traffic is authored under the "
             "negotiated active format. Cross-impl alias for the Go peer's "
             "--hash-type flag — lets validate-peer exercise multi-hash "
             "negotiation against a Python peer.",
    )
    start_parser.add_argument(
        "--admin", "-a",
        action="append",
        default=[],
        help="Identity name(s) to grant admin access (can be repeated). "
             "Example: -a framework-admin -a other-admin",
    )
    start_parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode: grant full access to ALL connecting peers (insecure, for testing only)",
    )
    start_parser.add_argument(
        "--open-access",
        dest="open_access",
        action="store_true",
        help="DEPRECATED (V7 §6.9a/§3.7, removed v7.75): the degenerate "
             "seed policy `default -> *`. Cross-impl alias for --debug; "
             "grants full access to all connecting peers. Migrate to "
             "--seed-policy with a real `default` entry.",
    )
    start_parser.add_argument(
        "--validate",
        action="store_true",
        help="GUIDE-CONFORMANCE §7a: enable the conformance test handlers "
             "(system/validate/echo + system/validate/dispatch-outbound) for "
             "a validate-peer run. OFF by default. Conformance runs only — "
             "NOT for production (dispatch-outbound originates outbound "
             "EXECUTEs from caller params).",
    )
    start_parser.add_argument(
        "--operator",
        metavar="IDENTITY",
        default=None,
        help="V7 §6.9a (F27): identity name that holds the principal-level "
             "owner capability over this peer's namespace. Defaults to the "
             "peer's own identity (--identity). Use for the multi-key model "
             "where a distinct operator administers the peer.",
    )
    start_parser.add_argument(
        "--seed-policy",
        metavar="FILE",
        dest="seed_policy",
        default=None,
        help="V7 §6.9a (F27): JSON file declaring the startup seed policy "
             "(per-identity grants + a `default` entry). Desugars to the "
             "builder's with_seed_policy. The replacement for --open-access.",
    )
    start_parser.add_argument(
        "--history",
        metavar="PATTERN",
        action="append",
        default=[],
        help="Enable history recording for paths matching PATTERN. "
             "Can be repeated. Use '/*/*' for all paths on all peers, "
             "or 'docs/*' for the local peer's docs subtree. "
             "Example: --history '/*/*' or --history 'project/*'",
    )
    start_parser.add_argument(
        "--files",
        metavar="NAME:FS_PATH:TREE_PREFIX",
        action="append",
        default=[],
        help="Configure a local/files root mapping. Repeatable. "
             "Format: 'name:/fs/path:tree/prefix/'. "
             "Cross-impl alias for Go peer-manager's --files flag — "
             "lets validate-peer's local_files category run against a "
             "Python peer with a writable test root. "
             "Example: --files 'test:/tmp/files:local/files/test/'",
    )
    # --- EXTENSION-DISCOVERY v1.0 flags (cross-impl-aligned) ---
    start_parser.add_argument(
        "--discovery-announce",
        dest="discovery_announce",
        action="store_true",
        help="Advertise this peer on the LAN over mDNS (EXTENSION-DISCOVERY "
             "§3.2 DNS-SD) so other peers can discover it. Cross-impl-aligned "
             "with Go/Rust's --discovery-announce. Needs a multicast-permitting "
             "network (the same-network demo / D8 convergence run).",
    )
    start_parser.add_argument(
        "--discovery-profile",
        dest="discovery_profile",
        default=None,
        metavar="PROFILE_ID",
        help="Transport profile-id advertised in the mDNS TXT record's "
             "profile_ref (NETWORK §6.5) — the profile a discoverer dials. "
             "Defaults to 'tcp'.",
    )
    # --- Chunk D HTTP-live transport flags (cross-impl-aligned with Go) ---
    # Per EXTENSION-NETWORK §6.5.2c + v1.4 Amendment 3 (body framing ruled:
    # HTTP carries bare ECF envelopes; Content-Length frames
    # the body; no 4-byte length prefix). Mirrors Go's `-http-addr`,
    # `-http-path` flag names so validate-peer harnesses can spawn Python
    # peers with the same flag shape as Go.
    start_parser.add_argument(
        "--http-addr",
        dest="http_addr",
        default=None,
        metavar="HOST:PORT",
        help="HTTP-live listener address (Chunk D). When set, binds an "
             "HTTP server alongside the TCP listener and self-publishes "
             "a system/peer/transport/http profile. Cross-impl-aligned "
             "with Go's `-http-addr` flag. Example: --http-addr 127.0.0.1:9101",
    )
    start_parser.add_argument(
        "--http-path",
        dest="http_path",
        default="/entity",
        metavar="PATH",
        help="HTTP path the live listener accepts POSTs at. Default '/entity' "
             "(cohort convention, matches Go's `-http-path` default). The "
             "Python server accepts POSTs to any path; this flag controls "
             "what gets written into the self-published profile URL.",
    )
    start_parser.add_argument(
        "--http-base-url",
        dest="http_base_url",
        default=None,
        metavar="URL",
        help="Public URL prefix to advertise in the self-published HTTP "
             "profile. When None (default), derives http://{http-addr}/{http-path}. "
             "Set to a TLS-fronted external URL for production "
             "(e.g., https://api.example.com/entity).",
    )
    # --- Chunk E serving-mode flags (per CHUNK-E-IMPL-PLAN §3 + the arch
    # serving-mode content-scope ruling). Mirrors Go's
    # `-http-poll-addr` / `-http-poll-mount-on-live` / `-http-poll-prefix` /
    # `-serve-namespace` / `-serve-closure-root` / `-serve-scope-whole-store`
    # flag names with the Python --double-dash dialect (per Chunk D
    # precedent: cohort tolerates flag-naming dialect divergence; semantics
    # match). ---
    start_parser.add_argument(
        "--http-poll-addr",
        dest="http_poll_addr",
        default=None,
        metavar="HOST:PORT",
        help="Bind a separate Chunk E serving listener (Posture 1 — "
             "isolated port, RECOMMENDED). Mutually exclusive with "
             "--http-poll-mount-on-live. Routes: GET /content/<hex(H)>, "
             "GET /tree/<absolute-path>. Example: --http-poll-addr 127.0.0.1:9201",
    )
    start_parser.add_argument(
        "--http-poll-mount-on-live",
        dest="http_poll_mount_on_live",
        action="store_true",
        help="Mount Chunk E serving routes on the live --http-addr listener "
             "(Posture 2 — same-port). Path prefix per --http-poll-prefix. "
             "Mutually exclusive with --http-poll-addr.",
    )
    start_parser.add_argument(
        "--http-poll-prefix",
        dest="http_poll_prefix",
        default="/poll",
        metavar="PATH",
        help="Path prefix for poll routes when mounted on the live listener "
             "(Posture 2). Default '/poll' (cohort default). Ignored "
             "without --http-poll-mount-on-live.",
    )
    start_parser.add_argument(
        "--serve-namespace",
        dest="serve_namespace",
        default=None,
        metavar="NAMESPACE",
        help="Content-namespace scope mode (RECOMMENDED, ship-first per "
             "arch ruling §1.2 #1). Serve hash H iff bound at "
             "NAMESPACE/<hex(H)> in the tree. Example: "
             "--serve-namespace system/content/public",
    )
    start_parser.add_argument(
        "--serve-closure-root",
        dest="serve_closure_root",
        default=None,
        metavar="PATH",
        help="Subtree-closure scope mode (E.3.1 follow-on per arch §1.2 "
             "#2). Serve hash H iff reachable from PATH closure. Pending "
             "cross-impl manifest tree-half closure-bundle convergence.",
    )
    start_parser.add_argument(
        "--serve-scope-whole-store",
        dest="serve_scope_whole_store",
        action="store_true",
        help="DEBUG opt-in: serve any hash in the local content store, "
             "regardless of namespace. Operator owns T2/T3 consequence per "
             "arch ruling §1.3 (caps/signatures reachable if their hashes "
             "leak). Logs a startup warning. NOT recommended for production.",
    )
    start_parser.add_argument(
        "--publish-root",
        dest="publish_root",
        action="store_true",
        help="Phase P / C1: mint + bind a signed system/peer/published-root "
             "over the current tree at startup (served by MANIFEST_GET; the "
             "§1.1 signed-root anchor for http-poll consumers). Pair with "
             "--http-poll-addr + a --serve-* scope so the root + its closure "
             "are fetchable. Amendment 10: with whole-store the closure is "
             "covered trivially.",
    )

    # --- ls command ---
    ls_parser = subparsers.add_parser("ls", help="List entities at a path")
    ls_parser.add_argument("target", help="Target: host:port/path/")
    _add_identity_arg(ls_parser)

    # --- tree command ---
    tree_parser = subparsers.add_parser("tree", help="Show full entity tree")
    tree_parser.add_argument("target", help="Target: host:port or host:port/path/")
    _add_identity_arg(tree_parser)

    # --- cat command ---
    cat_parser = subparsers.add_parser("cat", help="Display entity content (type-aware)")
    cat_parser.add_argument("target", help="Target: host:port/path")
    _add_identity_arg(cat_parser)

    # --- info command ---
    info_parser = subparsers.add_parser("info", help="Show entity metadata (type, hash, refs)")
    info_parser.add_argument("target", help="Target: host:port/path")
    _add_identity_arg(info_parser)

    # --- get command ---
    get_parser = subparsers.add_parser("get", help="Get raw entity (CBOR diagnostic notation)")
    get_parser.add_argument("target", help="Target: host:port/path")
    _add_identity_arg(get_parser)

    # --- put command ---
    put_parser = subparsers.add_parser("put", help="Store an entity at a path")
    put_parser.add_argument("target", help="Target: host:port/path")
    put_parser.add_argument("--type", "-t", required=True, help="Entity type (e.g. test/data)")
    put_parser.add_argument("--data", "-d", default="{}", help="Entity data as JSON (default: {})")
    _add_identity_arg(put_parser)

    # --- rm command ---
    rm_parser = subparsers.add_parser("rm", help="Remove a tree entry")
    rm_parser.add_argument("target", help="Target: host:port/path")
    _add_identity_arg(rm_parser)

    # --- registry-issue-binding command (curated operator tool, §3.2) ---
    rib_parser = subparsers.add_parser(
        "registry-issue-binding",
        help="Sign + publish a peer-issued registry binding (operator tool)",
    )
    rib_parser.add_argument("target", help="Registry peer: host:port")
    rib_parser.add_argument("name", help="The name to bind (e.g. billslab.com)")
    rib_parser.add_argument("target_peer_id", help="Base58 peer-id the name resolves to")
    rib_parser.add_argument("--transports", default=None,
                            help="Transports as a JSON array (default: [])")
    rib_parser.add_argument("--ttl", type=int, default=None,
                            help="TTL in ms (default: null = never expires)")
    _add_identity_arg(rib_parser)

    # --- registry-set-policy command (live registry admission, §6a.9.1) ---
    rsp_parser = subparsers.add_parser(
        "registry-set-policy",
        help="Install a live registry's issuer-policy (open/allowlist/manual)",
    )
    rsp_parser.add_argument("target", help="Registry peer: host:port")
    rsp_parser.add_argument("mode", choices=["open", "allowlist", "manual"],
                            help="Admission mode (domain-control is deferred)")
    rsp_parser.add_argument("--allowlist", default=None,
                            help="JSON array of peer-ids (allowlist mode)")
    rsp_parser.add_argument("--name-constraints", default=None,
                            help="Glob bounding issuable names (e.g. '*.lab')")
    rsp_parser.add_argument("--default-ttl", type=int, default=None,
                            help="Default binding TTL in ms (default: null)")
    _add_identity_arg(rsp_parser)

    # --- registry-register command (publisher self-registration, §6a.9) ---
    rreg_parser = subparsers.add_parser(
        "registry-register",
        help="Self-register a name at a live registry (proves you hold the peer-id)",
    )
    rreg_parser.add_argument("target", help="Registry peer: host:port")
    rreg_parser.add_argument("name", help="The name to register (e.g. billslab.com)")
    rreg_parser.add_argument("--transports", default=None,
                             help="Transports as a JSON array (default: [])")
    rreg_parser.add_argument("--ttl", type=int, default=None,
                             help="Requested TTL in ms (default: null)")
    _add_identity_arg(rreg_parser)

    # --- exec command ---
    exec_parser = subparsers.add_parser("exec", help="Execute an arbitrary operation")
    exec_parser.add_argument("target", help="Target: host:port/path")
    exec_parser.add_argument("operation", help="Operation to execute (e.g. read, list)")
    exec_parser.add_argument("params", nargs="?", default=None,
                             help="Operation params as JSON string")
    _add_identity_arg(exec_parser)

    # --- connect command (legacy, kept for backward compat) ---
    connect_parser = subparsers.add_parser("connect", help=argparse.SUPPRESS)
    connect_parser.add_argument("address", help="Address to connect to (host:port)")
    connect_parser.add_argument(
        "--identity", "-i",
        default="framework-admin",
        help="Identity name from ~/.entity/identities/ (default: 'framework-admin')",
    )
    connect_parser.add_argument("--status", action="store_true",
                                help="Request peer status after connecting")
    connect_parser.add_argument("--get", metavar="PATH",
                                help="GET a path (use trailing / for tree listing)")
    connect_parser.add_argument("--read", metavar="PATH",
                                help="Read an entity via handler")
    connect_parser.add_argument("--execute", nargs=2, metavar=("PATH", "OP"),
                                help="Execute arbitrary operation")

    # --- list-identities command ---
    subparsers.add_parser("list-identities", help="List available identities")

    # --- compare-types command ---
    compare_parser = subparsers.add_parser(
        "compare-types",
        help="Compare type schemas with another peer",
    )
    compare_parser.add_argument("address", help="Address to connect to (host:port)")
    compare_parser.add_argument(
        "--identity", "-i",
        default="framework-admin",
        help="Identity name (default: framework-admin)",
    )
    compare_parser.add_argument("--json", action="store_true", help="Output as JSON")
    compare_parser.add_argument("--verbose", "-V", action="store_true",
                                help="Show detailed schema differences")

    # --- wire-conformance command ---
    wc_parser = subparsers.add_parser(
        "wire-conformance",
        help="ECF wire-conformance harness (emit-canonical mode)",
    )
    wc_sub = wc_parser.add_subparsers(dest="wc_command")
    emit_parser = wc_sub.add_parser(
        "emit-canonical",
        help="Run the v1 corpus through Python's ECF encoder/validator",
    )
    emit_parser.add_argument(
        "--input", required=True,
        help="Path to conformance-vectors-v{N}.{cbor,diag}",
    )
    emit_parser.add_argument(
        "--out", required=True,
        help="Output path for canonical-ECF emission map",
    )
    emit_parser.add_argument(
        "--impl-version", default=None,
        help="Impl version string (default: 'git-<short-sha>')",
    )

    # --- Parse and dispatch ---
    args = parser.parse_args()

    # Configure logging
    if args.debug:
        log_level = logging.DEBUG
        log_format = "[%(levelname)s] %(name)s: %(message)s"
    else:
        log_level = logging.WARNING
        log_format = "%(message)s"
    logging.basicConfig(level=log_level, format=log_format)

    command_map = {
        "start": lambda: asyncio.run(cmd_start(args)),
        "ls": lambda: asyncio.run(cmd_ls(args)),
        "tree": lambda: asyncio.run(cmd_tree(args)),
        "cat": lambda: asyncio.run(cmd_cat(args)),
        "info": lambda: asyncio.run(cmd_info(args)),
        "get": lambda: asyncio.run(cmd_get(args)),
        "put": lambda: asyncio.run(cmd_put(args)),
        "rm": lambda: asyncio.run(cmd_rm(args)),
        "registry-issue-binding": lambda: asyncio.run(cmd_registry_issue_binding(args)),
        "registry-set-policy": lambda: asyncio.run(cmd_registry_set_policy(args)),
        "registry-register": lambda: asyncio.run(cmd_registry_register(args)),
        "exec": lambda: asyncio.run(cmd_exec(args)),
        "connect": lambda: asyncio.run(cmd_connect(args)),
        "list-identities": cmd_list_identities,
        "compare-types": lambda: asyncio.run(cmd_compare_types(args)),
        "wire-conformance": lambda: cmd_wire_conformance(args),
    }

    handler = command_map.get(args.command)
    if handler:
        handler()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
