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

**This module is the presentation tier and holds no protocol knowledge.** It
parses arguments, calls ``entity_sdk``, and formats what comes back. It
constructs no envelopes, issues no raw ``execute``, and builds no
``entity://`` URIs — a gate enforces all three
(``tests/unit/test_package_layering.py::test_presentation_constructs_no_protocol``).

That constraint is not tidiness. Every one of those things used to live here,
inlined at seventeen call sites, which is precisely why this repo had no L1 SDK
for as long as it did: the knowledge was real, and it was in the one package
nothing is allowed to depend on. If a command cannot be written without
reaching for the protocol, the missing piece is an ``entity-sdk`` affordance and
the gate says so at the moment it is worked around.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
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
from entity_sdk import (
    EntityClient,
    EntityError,
    IssuerPolicy,
    client_for_connection,
    content_hash,
    register,
    set_issuer_policy,
)
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
    """Fetch a type definition from a remote peer.

    Takes a ``Connection`` rather than a client because the interop type-parity
    tests call it directly with one; it wraps it and delegates.

    Args:
        conn: Active connection to remote peer.
        type_path: Type path (e.g., "primitive/string").

    Returns:
        Type data dict if found, None if not found or error.
    """
    client = client_for_connection(conn)
    try:
        entity = await client.get(f"system/types/{type_path}")
    except EntityError:
        return None
    return entity.get("data") if isinstance(entity, dict) else None


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

    # Everything else. The five keys above are the TYPE-SYSTEM ones worth a
    # tailored message; a key outside that set still changes the type's hash,
    # so leaving it unexamined makes `compare-types` report MISMATCH with an
    # empty reason list — the least useful output a divergence hunter can give.
    # Unknown keys are exactly what a cross-impl probe is looking for.
    known = {"name", "extends", "layout", "fields", "constraints"}
    for key in sorted((local_data.keys() | remote_data.keys()) - known):
        if local_data.get(key) != remote_data.get(key):
            differences.append(
                f"{key}: local={local_data.get(key)!r} remote={remote_data.get(key)!r}"
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

        result.remote_hash = content_hash("system/type", remote_data)

        # Compare
        if local_hash == result.remote_hash:
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

    Kept for callers that genuinely need the raw connection (``cmd_start``'s
    peer-to-peer wiring, the interop tests). Commands should use
    :func:`open_client` instead.
    """
    keypair = _load_keypair(identity)
    conn = await Connection.connect(host, port, keypair)
    try:
        yield conn, conn.session.remote_peer_id
    finally:
        conn.close()
        await conn.wait_closed()


@asynccontextmanager
async def open_client(
    host: str,
    port: int,
    identity: str = "framework-admin",
) -> AsyncIterator[EntityClient]:
    """Connect to a peer and yield a ready :class:`EntityClient`.

    Paths resolve against the **remote** peer's namespace, which is what a CLI
    argument like ``ls host:port/docs/`` means — *their* ``docs/``.
    """
    keypair = _load_keypair(identity)
    conn = await Connection.connect(host, port, keypair)
    try:
        yield client_for_connection(conn)
    finally:
        conn.close()
        await conn.wait_closed()


def _fail(exc: EntityError) -> None:
    """Report a dispatched-operation failure and exit non-zero.

    The SDK raises typed §12 exceptions carrying the status, the error code and
    the message. Rendering happens here; deciding what the status *means* — and
    which of them are failures at all, since 207 and 202 are not — happened in
    the SDK, once.
    """
    rendered = display_error({"code": exc.code or "error", "message": exc.message or ""})
    print(f"{rendered} (status {exc.status})", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Entity tree subcommands
# ---------------------------------------------------------------------------

async def _read_entity(client: EntityClient, path: str) -> Any:
    """Read the entity at ``path``, falling back to dispatch at the path.

    A tree read only sees **bound** paths. Plenty of useful reads are not
    bindings at all — ``system/status`` is computed by a handler on each
    request, so it has no tree entry and `get` returns ``None`` for it. In that
    case, dispatching *at the path* lets V7 §6.6 longest-prefix resolution find
    whichever handler serves it.

    Both routes were already in use before the SDK landed — `cat` did tree-then
    -path, while `info` and `get` went straight to path dispatch — which meant
    three commands with three slightly different notions of "read". One helper,
    used by all three, is the same behaviour without the drift.
    """
    entity = await client.get(path)
    if entity is not None:
        return entity
    return await client.execute(path, "get")


async def cmd_ls(args: argparse.Namespace) -> None:
    """List entities at a path (tree listing)."""
    host, port, path = parse_target(args.target)
    if path and not path.endswith("/"):
        path += "/"

    async with open_client(host, port, args.identity) as client:
        try:
            entries = await client.list(path)
        except EntityError as exc:
            _fail(exc)
            return

    print(f"{path or '/'}")
    if not entries:
        print("(empty)")
        return
    for entry in entries:
        name = entry.name + "/" if entry.has_children else entry.name
        suffix = f"  {_truncate_hash(entry.content_hash, 30)}" if entry.content_hash else ""
        print(f"{name}{suffix}")


async def cmd_cat(args: argparse.Namespace) -> None:
    """Display entity content with type-aware formatting."""
    host, port, path = parse_target(args.target)
    # cat reads an entity, so no trailing slash
    path = path.rstrip("/")

    async with open_client(host, port, args.identity) as client:
        try:
            entity = await _read_entity(client, path)
        except EntityError as exc:
            _fail(exc)
            return

    print(display_entity(entity) if isinstance(entity, dict) else entity)


async def cmd_info(args: argparse.Namespace) -> None:
    """Show entity metadata only (type, hash, refs)."""
    host, port, path = parse_target(args.target)

    async with open_client(host, port, args.identity) as client:
        try:
            entity = await _read_entity(client, path)
        except EntityError as exc:
            _fail(exc)
            return

    print(display_info(entity) if isinstance(entity, dict) else entity)


async def cmd_get(args: argparse.Namespace) -> None:
    """Get raw entity in CBOR diagnostic notation (machine-readable)."""
    host, port, path = parse_target(args.target)

    async with open_client(host, port, args.identity) as client:
        try:
            entity = await _read_entity(client, path)
        except EntityError as exc:
            _fail(exc)
            return

    print(to_diag(entity, indent=2))


async def cmd_put(args: argparse.Namespace) -> None:
    """Store an entity at a path."""
    host, port, path = parse_target(args.target)

    try:
        data = json.loads(args.data) if args.data else {}
    except json.JSONDecodeError as e:
        print(f"Invalid JSON for --data: {e}", file=sys.stderr)
        sys.exit(1)

    async with open_client(host, port, args.identity) as client:
        try:
            content_hash = await client.put(path, args.type, data)
        except EntityError as exc:
            _fail(exc)
            return

    print(f"Stored: {content_hash.hex()}")


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
    async with open_client(host, port, args.identity) as client:
        for path, entity in artifacts:
            try:
                await client.put(path, entity.type, entity.data)
            except EntityError as exc:
                _fail(exc)
                return

    print(f"Issued peer-issued binding {name!r} → {args.target_peer_id}")
    print(f"  binding_hash: {bh.hex()}")
    print(f"  signed by registry: {keypair.peer_id}")


async def cmd_registry_set_policy(args: argparse.Namespace) -> None:
    """EXTENSION-REGISTRY §6a.9.2 — install the registry's issuer-policy.

    Writing a policy is what turns a curated/static registry *live*: it begins
    accepting `register-request`. `domain-control` is deferred (§6a.9.1) — the
    registry rejects it with `400 unsupported_mode`, which we surface rather
    than pre-empt, so the ratified server-side rule is the one under test.
    """
    host, port, _ = parse_target(args.target)
    policy = IssuerPolicy(
        mode=args.mode,
        allowlist=json.loads(args.allowlist) if args.allowlist else None,
        name_constraints=args.name_constraints,
        default_ttl=args.default_ttl,
    )
    async with open_client(host, port, args.identity) as client:
        remote_peer = client.local_peer_id
        try:
            stored = await set_issuer_policy(client, policy)
        except EntityError as exc:
            _fail(exc)
            return

    print(f"Issuer policy set on {remote_peer}: mode={stored.mode}")


async def cmd_registry_register(args: argparse.Namespace) -> None:
    """EXTENSION-REGISTRY §6a.9 — publisher self-registration (`register-request`).

    Builds the request, signs it with the local identity (the layer-1
    ownership proof — the requester IS `target_peer_id`), and sends it with the
    signature + identity in `included`. The registry applies its issuer-policy
    and, on approval, signs + publishes the binding.
    """
    host, port, _ = parse_target(args.target)
    keypair = _load_keypair(args.identity)
    transports = json.loads(args.transports) if args.transports else []

    async with open_client(host, port, args.identity) as client:
        try:
            result = await register(
                client,
                keypair,
                args.name,
                transports=transports,
                requested_ttl=args.ttl,
            )
        except EntityError as exc:
            _fail(exc)
            return

    print(f"register-request {args.name!r} → {keypair.peer_id}: {result.status}")
    if result.bound and result.binding_hash:
        print(f"  binding_hash: {result.binding_hash.hex()}")
    elif result.pending and result.pending_hash:
        # 202 is accepted-pending, not a refusal — say so, and hand back the
        # poll handle rather than leaving the operator to guess at a next step.
        print(f"  queued for review; poll pending_hash: {result.pending_hash.hex()}")


async def cmd_rm(args: argparse.Namespace) -> None:
    """Remove a tree entry."""
    host, port, path = parse_target(args.target)

    async with open_client(host, port, args.identity) as client:
        try:
            await client.remove(path)
        except EntityError as exc:
            _fail(exc)
            return

    print("Deleted.")


async def cmd_tree(args: argparse.Namespace) -> None:
    """Show the full entity tree from a path."""
    host, port, path = parse_target(args.target)
    if path and not path.endswith("/"):
        path += "/"

    async with open_client(host, port, args.identity) as client:
        lines = [f"{client.local_peer_id}:/{path}"]
        try:
            await _tree_walk(client, path, lines, prefix="")
        except EntityError as exc:
            _fail(exc)
            return

    print("\n".join(lines))


async def _tree_walk(
    client: EntityClient,
    path: str,
    lines: list[str],
    prefix: str,
) -> None:
    """Recursively walk the entity tree and append formatted lines.

    One `list` per level — §3.3 `list` is single-level by conformance
    requirement, so the recursion is the caller's job and always was. The
    difference now is that the projection to `(name, path, hash, has_children)`
    happens once in the SDK instead of being re-derived from the raw listing
    map here.
    """
    entries = await client.list(path)

    for i, entry in enumerate(entries):
        is_last = i == len(entries) - 1
        connector = "└── " if is_last else "├── "

        if entry.has_children:
            display_name = entry.name + "/"
            suffix = ""
        elif entry.content_hash:
            display_name = entry.name
            suffix = f"  {_truncate_hash(entry.content_hash, 30)}"
        else:
            display_name = entry.name
            suffix = ""

        lines.append(f"{prefix}{connector}{display_name}{suffix}")

        if entry.has_children:
            child_prefix = prefix + ("    " if is_last else "│   ")
            await _tree_walk(client, path + entry.name + "/", lines, child_prefix)


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

    params: dict[str, Any] = {}
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON for params: {e}", file=sys.stderr)
            sys.exit(1)

    async with open_client(host, port, args.identity) as client:
        try:
            result = await client.execute(path, args.operation, params or None)
        except EntityError as exc:
            _fail(exc)
            return

    print(display_entity(result) if isinstance(result, dict) else result)


# ---------------------------------------------------------------------------
# Result display helper
# ---------------------------------------------------------------------------

def _print_result(label: str, result: Any) -> None:
    """Print a successful result under a label.

    There is no matching ``_print_error``: the SDK raises typed §12 exceptions
    rather than handing back a response for the caller to inspect, so the
    error path is :func:`_fail` and status interpretation is not this tier's
    job.
    """
    print(f"\n=== {label} ===")
    if isinstance(result, dict):
        print(display_entity(result))
    elif result is None:
        print("(no result)")
    else:
        print(result)


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


ENV_MAX_LIFETIME = "ENTITY_PEER_MAX_LIFETIME"


def _env_max_lifetime() -> float:
    """Read the ``$ENTITY_PEER_MAX_LIFETIME`` default for ``--max-lifetime``.

    This is the enforcement point for "a peer reaps itself": a dev box exports
    the variable once and no hand-started peer on it can outlive the shell that
    started it, whether or not whoever typed the command remembered the flag.

    A malformed value is a **hard error**, not a fallback to unlimited. Setting
    the variable is a statement that a bound is wanted; silently ignoring a typo
    would hand back the unbounded peer the variable exists to prevent, at the
    one moment nobody is looking for it.
    """
    raw = os.environ.get(ENV_MAX_LIFETIME)
    if raw is None or raw.strip() == "":
        return 0.0
    try:
        value = float(raw)
    except ValueError:
        raise SystemExit(
            f"Error: ${ENV_MAX_LIFETIME}={raw!r} is not a number. "
            "Set it to a positive number of seconds, or unset it."
        ) from None
    if value < 0:
        raise SystemExit(
            f"Error: ${ENV_MAX_LIFETIME}={raw!r} is negative. "
            "Use 0 for 'run until signalled'."
        )
    return value


def _configure_relay_store_bounds(peer, args: argparse.Namespace) -> None:
    """Apply `--relay-store-retention-ms` / `--relay-max-storage-bytes` to the
    relay's `system/relay/config`, and publish the §4.1 advertise that declares
    them.

    Both are no-ops when unset, so an ordinary peer is unchanged: no config
    entity is written and no advertise is published.

    A NEGATIVE bound is a hard refusal, not a silent demotion to "unbounded".
    A typo'd ceiling is a request for a ceiling, and handing back the unbounded
    behaviour at the one moment the operator believed they had set a bound is
    the failure mode `--max-lifetime` already taught this CLI. Zero is accepted
    and means "no bound" — that is what the flag's own help says and what the
    Go peer's flag means, so it is a value an operator can deliberately pass.

    The config entity is MERGED, not replaced: `system/relay/config` also
    carries `disable_default_fallback` (§9.5), and a start-up write that
    replaced the whole entity would silently turn an operator's MX-required
    posture off on the next restart.
    """
    from entity_core.protocol.entity import Entity
    from entity_core.storage.emit import EmitContext
    from entity_handlers.relay import (
        CONFIG_MAX_STORAGE_BYTES,
        CONFIG_STORE_RETENTION_MS,
        RELAY_CONFIG_PATH,
        publish_self_advertise,
    )

    retention = getattr(args, "relay_store_retention_ms", None)
    max_bytes = getattr(args, "relay_max_storage_bytes", None)
    if retention is None and max_bytes is None:
        return
    for flag, value in (
        ("--relay-store-retention-ms", retention),
        ("--relay-max-storage-bytes", max_bytes),
    ):
        if value is not None and value < 0:
            raise SystemExit(
                f"{flag} must be >= 0 (0 = no bound); got {value}. A negative "
                f"bound is refused rather than treated as unbounded — see "
                f"EXTENSION-RELAY §8."
            )

    config_uri = peer.emit_pathway.entity_tree.normalize_uri(RELAY_CONFIG_PATH)
    existing = peer.emit_pathway.entity_tree.get(config_uri)
    data = {}
    if existing is not None:
        current = peer.emit_pathway.content_store.get(existing)
        if current is not None and isinstance(current.data, dict):
            data = dict(current.data)
    if retention is not None:
        data[CONFIG_STORE_RETENTION_MS] = retention
    if max_bytes is not None:
        data[CONFIG_MAX_STORAGE_BYTES] = max_bytes
    peer.emit_pathway.emit(
        config_uri,
        Entity(type="system/relay/config", data=data),
        EmitContext.bootstrap(),
    )

    published = publish_self_advertise(
        peer.emit_pathway, peer.keypair, peer.keypair.peer_id, data
    )
    if retention:
        print(f"Relay: §8.1 retention ceiling {retention}ms (clamps, never refuses)")
    if max_bytes:
        print(f"Relay: §8.2 store bound {max_bytes} bytes (refuses, never evicts)")
    if published is not None:
        print(f"Relay: §4.1 advertise published at {published[0]}")


def _keepalive_config_from_args(args: argparse.Namespace) -> dict[str, int] | None:
    """Map the ``--keepalive-*`` start flags to ``with_keepalive_config`` kwargs.

    Returns a kwargs dict containing only the explicitly-set fields — each
    omitted field keeps its EXTENSION-NETWORK §2.3 spec default via the
    builder — or ``None`` when no keepalive flag was given (leave the loop
    at spec defaults).
    """
    mapping = {
        "interval_ms": getattr(args, "keepalive_interval_ms", None),
        "timeout_ms": getattr(args, "keepalive_timeout_ms", None),
        "max_missed": getattr(args, "keepalive_max_missed", None),
    }
    kwargs = {k: v for k, v in mapping.items() if v is not None}
    return kwargs or None


def _reflection_endpoints_from_args(args: argparse.Namespace) -> list[str]:
    """Split ``--reflection-endpoint``'s comma-separated value (§4.5.1).

    Returns ``[]`` when the flag is absent — the no-reflection state, which the
    node emits as an **absent** field rather than an empty array. Surrounding
    whitespace is stripped and empty segments dropped so a trailing comma is
    not a "" endpoint; the URI itself is never otherwise touched, because
    §4.5.1 publishes the operator's bytes verbatim and the node runs no
    transform. Validation is the node's (`normalize_reflection_endpoints`) —
    this only splits.
    """
    raw = getattr(args, "reflection_endpoint", None)
    if not raw:
        return []
    return [uri.strip() for uri in raw.split(",") if uri.strip()]


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

    # PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2: pin registries the §4 chain
    # will actually consult. Comma-separated `peer_id@endpoint`, matching
    # Go's entity-peer --peer-issued-registry.
    peer_issued = getattr(args, "peer_issued_registry", None)
    if peer_issued:
        for spec in peer_issued.split(","):
            spec = spec.strip()
            if not spec:
                continue
            registry_peer_id, sep, endpoint = spec.partition("@")
            if not sep or not registry_peer_id or not endpoint:
                print(f"Error: --peer-issued-registry expects peer_id@url, got {spec!r}")
                return 1
            builder.with_peer_issued_registry(registry_peer_id, endpoint)
            print(f"Peer-issued registry pinned: {registry_peer_id[:20]}... -> {endpoint}")

    # EXTENSION-SIGNALING §4/§5 rendezvous node. OFF by default — a peer is a
    # signaling CLIENT by default and only a deployed introducer serves (Go's
    # `-signaling-node` is off for the same reason). The caller's grant must
    # cover system/signaling:{offer,collect,advertise}, so pair it with
    # --open-access or a seed policy.
    reflection_endpoints = _reflection_endpoints_from_args(args)
    if reflection_endpoints and not getattr(args, "signaling_node", False):
        # §4.5.1 publishes these on the node's own `advertise`, so without the
        # node there is nowhere for them to go. Refuse rather than accept a
        # flag that would silently do nothing — same call as Go's entity-peer.
        print("Error: --reflection-endpoint requires --signaling-node "
              "(§4.5.1 publishes on the node's advertise)")
        return 1
    if getattr(args, "signaling_node", False):
        from entity_handlers.signaling.reflection import ReflectionEndpointError

        try:
            builder.with_signaling_node_handler(
                endpoint=getattr(args, "signaling_endpoint", "") or "",
                lobby_constant=getattr(args, "signaling_lobby", None),
                reflection_endpoints=reflection_endpoints or None,
            )
        except ReflectionEndpointError as exc:
            # Fail at startup, never publish it: a malformed URI does not
            # degrade at the consumer — it throws at RTCPeerConnection
            # construction and takes the establisher with it (§4.5.1).
            print(f"Error: --reflection-endpoint: {exc}")
            return 1
        print("Signaling: serving the §4/§5 rendezvous node "
              "(system/signaling offer/collect/advertise)")
        if reflection_endpoints:
            print("Signaling: advertising §9.3 reflection at "
                  + ", ".join(reflection_endpoints))

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

    # EXTENSION-NETWORK §2.3 keepalive override (validate-peer liveness
    # harness): apply only the explicitly-set --keepalive-* flags; omitted
    # fields keep their §2.3 spec defaults inside with_keepalive_config.
    keepalive_kwargs = _keepalive_config_from_args(args)
    if keepalive_kwargs is not None:
        builder.with_keepalive_config(**keepalive_kwargs)
        print(f"Keepalive override (EXTENSION-NETWORK §2.3): {keepalive_kwargs}")

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
                        publish_descriptors=bool(
                            getattr(args, "publish_descriptors", False)
                        ),
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

    # EXTENSION-RELAY §8 (v1.3) store bounds → system/relay/config, which is
    # where the handler reads every operator knob it has.
    _configure_relay_store_bounds(peer, args)

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
        # PROPOSAL-PEER-MANIFEST §4: "on every tree-root change", not once.
        # A peer that advertises a signed root and never republishes serves
        # a closure frozen at boot — every entity written afterwards is
        # permanently outside the served set, which for a static-origin
        # deployment is a publisher that can never publish anything.
        peer.enable_root_republish()

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

    max_lifetime = float(getattr(args, "max_lifetime", 0.0) or 0.0)
    if max_lifetime > 0:
        print(f"Max lifetime: {max_lifetime:g}s — the peer will stop itself")

    # SIGTERM is how every supervisor asks a peer to stop — `podman stop`,
    # systemd, a CI harness reaping its fixtures. The Dockerfile's ENTRYPOINT
    # makes this process **PID 1**, and the kernel does not apply a signal's
    # default disposition to PID 1: a SIGTERM with no *installed handler* is
    # discarded outright. So without this the peer ignores every stop request,
    # `podman stop` blocks for its full timeout and then SIGKILLs — which is a
    # shutdown that never runs `stop()`, never closes connections, and taught
    # everyone that reaping a peer means escalating to a kill.
    loop = asyncio.get_running_loop()
    stop_requested = asyncio.Event()
    signalled: list[str] = []
    installed: list[signal.Signals] = []
    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue

        def _request_stop(signame: str = name) -> None:
            if not stop_requested.is_set():
                signalled.append(signame)
                stop_requested.set()

        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):
            # Non-Unix, or not the main thread. The KeyboardInterrupt arm
            # below stays as the fallback for SIGINT.
            continue
        installed.append(sig)

    print("Press Ctrl+C to stop" + (" (SIGTERM honored)" if installed else ""))

    serve_task = asyncio.ensure_future(peer.serve_forever())
    stop_task = asyncio.ensure_future(stop_requested.wait())
    try:
        # Whichever comes first: the server ending, a stop signal, or the
        # lifetime bound. All three fall through to `stop()`, which is what
        # releases the listening socket.
        done, _ = await asyncio.wait(
            {serve_task, stop_task},
            timeout=max_lifetime if max_lifetime > 0 else None,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not done:
            print(f"\nMax lifetime {max_lifetime:g}s reached; shutting down...")
        elif stop_task in done:
            print(f"\nReceived {signalled[0] if signalled else 'stop'}; "
                  "shutting down...")
        elif serve_task in done and not serve_task.cancelled():
            # The server ended on its own. If it ended by RAISING, that
            # exception is the only account of why this peer stopped serving —
            # and `asyncio.wait` does not propagate it, it parks it on the task.
            # Re-raise so the process dies loudly with a traceback and a
            # non-zero status. Swallowing it here would turn a crash under load
            # into a silent exit 0, which reads downstream as an orderly
            # shutdown and leaves a conformance run reporting "connection
            # refused" with no cause anywhere.
            serve_exc = serve_task.exception()
            if serve_exc is not None:
                print(f"\nServer stopped with an error: {serve_exc!r}")
                raise serve_exc
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        for sig in installed:
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError):
                pass
        for task in (serve_task, stop_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(serve_task, stop_task, return_exceptions=True)
        await peer.stop()


async def cmd_connect(args: argparse.Namespace) -> None:
    """Connect to a peer (legacy command)."""
    host, port_str = args.address.rsplit(":", 1)
    port = int(port_str)

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

        client = client_for_connection(conn)

        probes: list[tuple[str, str, str]] = []
        if args.status:
            probes.append(("system/status", "system/status", "get"))
        if args.get:
            probes.append((args.get, args.get, "get"))
        if args.read:
            probes.append((args.read, args.read, "get"))
        if args.execute:
            path, operation = args.execute
            probes.append((f"{path} ({operation})", path, operation))

        for label, path, operation in probes:
            try:
                _print_result(label, await client.execute(path, operation))
            except EntityError as exc:
                print(f"\n=== {label} ===")
                print(
                    display_error(
                        {"code": exc.code or "error", "message": exc.message or ""}
                    ),
                    file=sys.stderr,
                )

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


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser (all subcommands).

    Extracted from ``main`` so the flag surface is testable without
    spawning a peer.
    """
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
        "--max-lifetime",
        dest="max_lifetime",
        type=float,
        default=_env_max_lifetime(),
        metavar="SECONDS",
        help="Stop the peer after SECONDS and exit cleanly (0 = run until "
             "signalled, the default). Defaults to $ENTITY_PEER_MAX_LIFETIME "
             "when set. A peer started for debugging MUST carry this: the "
             "shutdown path releases the listening port, so the peer reaps "
             "itself rather than depending on someone holding a PID.",
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
        "--peer-issued-registry",
        metavar="PEER_ID@URL",
        dest="peer_issued_registry",
        default=None,
        help="PROPOSAL-PEER-ISSUED-REGISTRY-BACKEND §2: pin one or more "
             "peer-issued registries (comma-separated `peer_id@tree_url_prefix`). "
             "Installs the trust root AND a §4 resolver-chain entry — registering "
             "a backend is not the same as consulting one, and a pin with no "
             "chain entry answers chain_exhausted having dialed nothing. Same "
             "flag name and spelling as Go's entity-peer --peer-issued-registry.",
    )
    start_parser.add_argument(
        "--signaling-node",
        action="store_true",
        dest="signaling_node",
        default=False,
        help="EXTENSION-SIGNALING §4/§5: serve the system/signaling rendezvous "
             "node (offer/collect/advertise) — the opaque per-key blob store "
             "for NAT introduction and the §7 punch. OFF by default (a peer is "
             "a signaling CLIENT by default; only a deployed introducer "
             "serves). The caller's grant must cover "
             "system/signaling:{offer,collect,advertise}, so pair it with "
             "--open-access or a seed policy. Same flag name and default as "
             "Go's entity-peer -signaling-node.",
    )
    start_parser.add_argument(
        "--signaling-endpoint",
        metavar="HOST:PORT",
        dest="signaling_endpoint",
        default=None,
        help="EXTENSION-SIGNALING §4.5: the endpoint this node advertises. "
             "Defaults to where the peer actually listens. §3.1.1 weights are "
             "computed over these bytes exactly as published, so a value here "
             "is never normalized.",
    )
    start_parser.add_argument(
        "--signaling-lobby",
        metavar="CONSTANT",
        dest="signaling_lobby",
        default=None,
        help="EXTENSION-SIGNALING §4.5: this deployment's `lobby` override, "
             "published in advertise. Omit to use `lobby:default` — it is a "
             "derivation input (§3.1 hashes it verbatim), so overriding it "
             "moves every peer's lobby bucket.",
    )
    start_parser.add_argument(
        "--reflection-endpoint",
        metavar="URI[,URI...]",
        dest="reflection_endpoint",
        default=None,
        help="EXTENSION-SIGNALING §4.5.1 (v1.1): comma-separated RFC 7064 STUN "
             "URI(s) (stun:host[:port] / stuns:host[:port], non-hierarchical — "
             "no //) for this node's OWN §9.3 reflection listener(s), published "
             "in advertise's top-level reflection_endpoints. Set ONLY if this "
             "deployment actually serves §9.3 reflection (co-located reflector "
             "per GUIDE-REFERENCE-DEPLOYMENT). Requires --signaling-node. Empty "
             "(default) advertises no reflection. Each URI is validated at "
             "startup and emitted verbatim — a browser hands them to "
             "RTCIceServer.urls as-is. Same flag name and spelling as Go's "
             "entity-peer --reflection-endpoint.",
    )
    start_parser.add_argument(
        "--seed-policy",
        metavar="FILE",
        dest="seed_policy",
        default=None,
        help="V7 §6.9a (F27): JSON file declaring the startup seed policy "
             "(per-identity grants + a `default` entry), in the keystone "
             "cross-peer canonical format "
             '{\"version\":1,\"entries\":[{\"grantee\",\"grants\"}]} — see '
             "protocol-generator/shared/seed-policy/. Desugars to the "
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
    start_parser.add_argument(
        "--publish-descriptors",
        dest="publish_descriptors",
        action="store_true",
        help="Arm DOMAIN-LOCAL-FILES v1.3 §10.5 V3 on every --files root: a "
             "file read writes system/content/descriptor/{hash} into the "
             "tree. Cross-impl alias for Go peer-manager's "
             "--publish-descriptors. Without it the V3 behavioural check "
             "reports 'not exercised' — a check quietly not running.",
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
    # --- EXTENSION-NETWORK §2.3 keepalive-override flags ---
    # Cross-impl aliases for the Go peer-manager's `--keepalive
    # interval,timeout,max_missed` triple, which forwards to the peer binary
    # as -keepalive-interval-ms / -keepalive-timeout-ms / -keepalive-max-missed
    # (Python --double-dash dialect per the Chunk D/E precedent). Compresses
    # the §5.4 liveness escalation from the ~100s spec-default envelope to
    # seconds so validate-peer's reconnect anchor is observable fast against a
    # Python peer. Keepalive itself is MUST (§12.1) and always runs; these only
    # tune parameters. Any omitted field keeps its §2.3 spec default.
    start_parser.add_argument(
        "--keepalive-interval-ms",
        dest="keepalive_interval_ms",
        type=int,
        default=None,
        metavar="MS",
        help="EXTENSION-NETWORK §2.3: keepalive ping interval in ms "
             "(spec default 30000). Cross-impl alias for the Go peer's "
             "-keepalive-interval-ms — lets validate-peer run the §5.4 "
             "escalation in seconds against a Python peer.",
    )
    start_parser.add_argument(
        "--keepalive-timeout-ms",
        dest="keepalive_timeout_ms",
        type=int,
        default=None,
        metavar="MS",
        help="EXTENSION-NETWORK §2.3: keepalive response timeout in ms "
             "(spec default 10000). Cross-impl alias for the Go peer's "
             "-keepalive-timeout-ms.",
    )
    start_parser.add_argument(
        "--keepalive-max-missed",
        dest="keepalive_max_missed",
        type=int,
        default=None,
        metavar="N",
        help="EXTENSION-NETWORK §2.3: consecutive missed keepalives before "
             "the suspect→disconnected demotion (spec default 3). Cross-impl "
             "alias for the Go peer's -keepalive-max-missed.",
    )

    # EXTENSION-RELAY §8 (v1.3) store bounds. Both default OFF — an
    # unconfigured relay behaves and encodes exactly as at v1.2. The names
    # match the Go peer's `--relay-store-retention-ms` /
    # `--relay-max-storage-bytes` character for character, because these are
    # the knobs a cross-impl harness uses to ARM a peer for the §8 wire rows:
    # peer-manager forwards a flag by name, and a peer whose knob is spelled
    # differently reports could-not-look forever while looking conformant.
    start_parser.add_argument(
        "--relay-store-retention-ms",
        dest="relay_store_retention_ms",
        type=int,
        default=None,
        metavar="MS",
        help="EXTENSION-RELAY §8.1 (v1.3): Mode-S store retention CEILING in "
             "ms (0/unset = no ceiling). A :put whose store-entry expires_at "
             "exceeds now+ceiling — or is null — is CLAMPED to the ceiling, "
             "never refused; the ceiling is published as "
             "limits.max_retention_ms in the relay's advertise (§4.1). "
             "Cross-impl alias for the Go peer's --relay-store-retention-ms.",
    )
    start_parser.add_argument(
        "--relay-max-storage-bytes",
        dest="relay_max_storage_bytes",
        type=int,
        default=None,
        metavar="BYTES",
        help="EXTENSION-RELAY §8.2 (v1.3): relay-wide Mode-S store bound in "
             "bytes (0/unset = unbounded). A :put that would exceed it is "
             "refused with storage_full/507 and NOTHING is evicted; published "
             "as limits.max_storage_bytes (§4.1). Cross-impl alias for the Go "
             "peer's --relay-max-storage-bytes.",
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

    return parser


def main() -> None:
    """Main entry point."""
    parser = build_parser()

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
