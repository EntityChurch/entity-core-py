"""Type-aware display for CLI output.

Renders entities in CBOR diagnostic notation (RFC 8949 §8) for human
consumption, dispatching on entity type for structured display.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# CBOR diagnostic notation formatter (RFC 8949 §8)
# ---------------------------------------------------------------------------

def to_diag(value: Any, indent: int | None = None) -> str:
    """Format a Python value as CBOR diagnostic notation.

    Handles the types produced by cbor2 decoding: str, int, float,
    bool, None, list, dict, bytes.  Maps use the CBOR key: value
    syntax (no quotes on keys that are simple identifiers, but we
    always quote string keys for unambiguity).

    Args:
        value: Python value to format.
        indent: Spaces per indent level for pretty-printing.
               None for compact single-line output.

    Returns:
        CBOR diagnostic notation string.
    """
    if indent is not None:
        return _diag_pretty(value, 0, indent)
    return _diag_compact(value)


def _diag_compact(value: Any) -> str:
    """Single-line CBOR diagnostic notation."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value:  # NaN
            return "NaN"
        if value == float("inf"):
            return "Infinity"
        if value == float("-inf"):
            return "-Infinity"
        return repr(value)
    if isinstance(value, str):
        return _diag_string(value)
    if isinstance(value, bytes):
        return f"h'{value.hex()}'"
    if isinstance(value, list):
        items = ", ".join(_diag_compact(v) for v in value)
        return f"[{items}]"
    if isinstance(value, dict):
        pairs = ", ".join(
            f"{_diag_compact(k)}: {_diag_compact(v)}"
            for k, v in value.items()
        )
        return "{" + pairs + "}"
    # Fallback for unknown types
    return repr(value)


def _diag_pretty(value: Any, level: int, indent: int) -> str:
    """Multi-line indented CBOR diagnostic notation."""
    pad = " " * (level * indent)
    inner_pad = " " * ((level + 1) * indent)

    if isinstance(value, dict) and value:
        lines = ["{"]
        items = list(value.items())
        for i, (k, v) in enumerate(items):
            sep = "," if i < len(items) - 1 else ""
            key_str = _diag_compact(k)
            val_str = _diag_pretty(v, level + 1, indent)
            # If val_str is multi-line, put it on same line as key
            # (the nested structure handles its own indentation)
            if "\n" in val_str:
                lines.append(f"{inner_pad}{key_str}: {val_str.lstrip()}{sep}")
            else:
                lines.append(f"{inner_pad}{key_str}: {val_str}{sep}")
        lines.append(f"{pad}" + "}")
        return "\n".join(lines)

    if isinstance(value, list) and value:
        # Short arrays on one line, long arrays get indented
        compact = _diag_compact(value)
        if len(compact) <= 72:
            return compact
        lines = ["["]
        for i, item in enumerate(value):
            sep = "," if i < len(value) - 1 else ""
            lines.append(f"{inner_pad}{_diag_pretty(item, level + 1, indent)}{sep}")
        lines.append(f"{pad}]")
        return "\n".join(lines)

    return _diag_compact(value)


def _diag_string(s: str) -> str:
    """Format a string in CBOR diagnostic notation with escapes."""
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{escaped}"'


# ---------------------------------------------------------------------------
# Entity display functions
# ---------------------------------------------------------------------------

def display_entity(entity: dict[str, Any]) -> str:
    """Render an entity for human consumption, dispatching by type.

    Args:
        entity: Entity dict with at least 'type' and 'data'.

    Returns:
        Formatted string for terminal output.
    """
    entity_type = entity.get("type", "")
    data = entity.get("data", {})

    if entity_type == "tree/listing":
        return display_tree_listing(entity)
    elif entity_type == "system/type":
        return display_type_schema(data)
    elif entity_type == "system/capability/token":
        return display_capability(data)
    elif entity_type == "system/peer":
        return display_identity(data)
    elif entity_type in ("status", "peer-info"):
        return display_status(entity)
    else:
        return display_generic(entity)


def display_tree_listing(entity: dict[str, Any]) -> str:
    """Render a tree/listing entity as ls-style output.

    Format:
        entity://PEER.../path/
          name                    ecf-sha256:a7b3...
          subdir/                 [+]
    """
    data = entity.get("data", {})
    uri = data.get("uri", data.get("path", ""))
    entries = data.get("entries", {})

    lines = [uri]

    for name in sorted(entries.keys()):
        info = entries[name]
        has_children = info.get("has_children", False)
        hash_val = info.get("hash")

        if has_children:
            display_name = name if name.endswith("/") else name + "/"
            hash_display = "[+]"
        else:
            display_name = name
            if hash_val:
                hash_display = _truncate_hash(hash_val, 30)
            else:
                hash_display = "(no entity)"

        lines.append(f"  {display_name:<32s} {hash_display}")

    return "\n".join(lines)


def display_type_schema(data: dict[str, Any]) -> str:
    """Render a system/type entity showing name and schema.

    Format:
        Type: system/protocol/execute
        Schema:
          required: [request_id, uri, operation, params]
          properties:
            request_id: {"type": "text"}
            ...
    """
    name = data.get("name", "(unnamed)")
    schema = data.get("schema", {})

    lines = [f"Type: {name}"]

    required = schema.get("required", [])
    if required:
        lines.append(f"  required: [{', '.join(required)}]")

    properties = schema.get("properties", {})
    if properties:
        lines.append("  properties:")
        for prop_name in sorted(properties.keys()):
            prop = properties[prop_name]
            lines.append(f"    {prop_name}: {to_diag(prop)}")

    return "\n".join(lines)


def display_capability(data: dict[str, Any]) -> str:
    """Render a capability token summary.

    Format:
        Capability Token
          granter: 12ABc...
          grantee: 34DEf...
          grants:
            - entity://*/data/* [read, write]
    """
    lines = ["Capability Token"]
    granter = data.get("granter", "")
    grantee = data.get("grantee", "")

    if granter:
        lines.append(f"  granter: {_truncate(granter, 24)}")
    if grantee:
        lines.append(f"  grantee: {_truncate(grantee, 24)}")

    grants = data.get("grants", [])
    if grants:
        lines.append("  grants:")
        for grant in grants:
            pattern = grant.get("pattern", "*")
            ops = grant.get("operations", ["*"])
            ops_str = ", ".join(ops)
            lines.append(f"    - {pattern} [{ops_str}]")

    caveats = data.get("caveats", {})
    if caveats:
        lines.append("  caveats:")
        for key, val in sorted(caveats.items()):
            lines.append(f"    {key}: {val}")

    return "\n".join(lines)


def display_identity(data: dict[str, Any]) -> str:
    """Render a system/identity entity.

    Format:
        Identity
          peer_id: 12ABcDEf...
          algorithm: Ed25519
    """
    lines = ["Identity"]
    peer_id = data.get("peer_id", "")
    if peer_id:
        lines.append(f"  peer_id: {peer_id}")
    algorithm = data.get("algorithm", "")
    if algorithm:
        lines.append(f"  algorithm: {algorithm}")
    public_key = data.get("public_key", "")
    if public_key:
        lines.append(f"  public_key: {_truncate(public_key, 24)}")
    return "\n".join(lines)


def display_status(entity: dict[str, Any]) -> str:
    """Render a status or peer-info entity.

    Format:
        Status
          peer_id: abc123
          protocols: ["entity-core/7.0"]
    """
    entity_type = entity.get("type", "")
    data = entity.get("data", {})

    if entity_type == "peer-info":
        lines = ["Peer Info"]
    else:
        lines = ["Status"]

    for key in sorted(data.keys()):
        val = data[key]
        if isinstance(val, (dict, list)):
            lines.append(f"  {key}: {to_diag(val)}")
        else:
            lines.append(f"  {key}: {val}")

    return "\n".join(lines)


def display_error(result: dict[str, Any]) -> str:
    """Render a V2 error response (code + message).

    Args:
        result: The result dict from an error ExecuteResponse.
    """
    code = result.get("code", "unknown")
    message = result.get("message", str(result))
    return f"Error [{code}]: {message}"


def display_info(entity: dict[str, Any]) -> str:
    """Render entity metadata only (type, hash) without data dump.

    Args:
        entity: Entity dict.

    Returns:
        Metadata-only display string.
    """
    lines = []
    entity_type = entity.get("type", "(unknown)")
    lines.append(f"type: {entity_type}")

    content_hash = entity.get("content_hash", "")
    if content_hash:
        lines.append(f"hash: {content_hash}")

    uri = entity.get("uri", "")
    if uri:
        lines.append(f"uri: {uri}")

    data = entity.get("data", {})
    if isinstance(data, dict):
        lines.append(f"data keys: [{', '.join(sorted(data.keys()))}]")

    return "\n".join(lines)


def display_generic(entity: dict[str, Any]) -> str:
    """Fallback display: type header + CBOR diagnostic data.

    Args:
        entity: Entity dict.

    Returns:
        Formatted string with type and indented data.
    """
    entity_type = entity.get("type", "(unknown)")
    data = entity.get("data", {})

    lines = [f"[{entity_type}]"]
    lines.append(to_diag(data, indent=2))
    return "\n".join(lines)


def _truncate_hash(hash_val: str, max_len: int) -> str:
    """Truncate a hash string for display."""
    if len(hash_val) <= max_len:
        return hash_val
    return hash_val[:max_len] + "..."


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string for display."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."
