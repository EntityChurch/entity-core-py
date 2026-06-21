"""Path utilities for the leading-slash absolute path convention.

Per PROPOSAL-PATH-ABSOLUTE-RELATIVE-CONVENTION:
- Absolute paths start with / followed by peer_id: /{peer_id}/rest
- Peer-relative paths have no leading /: system/tree
- Paths starting with ./ or ../ are reserved (rejected)
- Empty segments (consecutive //) are rejected at validation

Per EXTENSION-NETWORK §6.4 D9 (v1.4 Amendment 2,
PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS §D9):
``validate_absolute_path`` stays **strict** — the {X} slot MUST be a
valid peer-ID. Reserved-word recognition (``content`` / ``manifest``)
lives in a **separate URL-layer helper** (``http_poll_urls.py``) because
those reserved words are http-poll consumer-URL redirects, NOT tree-path
segments. The strict reject in the path validator is load-bearing for
§6.4's collision-safety argument.
"""

from __future__ import annotations

from entity_core.utils.identity import is_peer_id


def clean_path(path: str) -> str:
    """Normalize path separators per R8.

    - Collapse consecutive '/' into single '/'
    - Preserve single leading '/' (absolute marker)
    - Strip trailing '/' (unless path is just '/')
    - Reject paths starting with './' or '../'

    Does NOT handle entity:// scheme — callers must strip the scheme
    before calling this function.

    Args:
        path: The path to clean.

    Returns:
        Cleaned path.

    Raises:
        ValueError: If path starts with './' or '../'.
    """
    if not path:
        return path

    # Reject reserved directory-relative prefixes
    if path.startswith("./") or path.startswith("../"):
        raise ValueError(f"reserved: directory-relative paths: {path}")

    # Collapse consecutive slashes
    while "//" in path:
        path = path.replace("//", "/")

    # Strip trailing slash (but keep "/" itself)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
        # Restore leading / if it was stripped
        if not path:
            path = "/"

    return path


def extract_handler_path(uri_or_path: str) -> str:
    """Extract handler-relative path from a URI or absolute path.

    Strips the entity://peer_id/ or /peer_id/ prefix to get the bare
    handler-relative path (e.g., "system/tree").

    Used by handler dispatch and registry matching — handlers register
    at peer-relative patterns and match against bare paths.

    Args:
        uri_or_path: A URI (entity://peer/path), absolute path (/peer/path),
            or bare path (system/tree).

    Returns:
        The handler-relative path portion.
    """
    if uri_or_path.startswith("entity://"):
        parts = uri_or_path[len("entity://"):].split("/", 1)
        return parts[1] if len(parts) > 1 else ""

    if uri_or_path.startswith("/"):
        parts = uri_or_path[1:].split("/", 1)
        return parts[1] if len(parts) > 1 else ""

    return uri_or_path


def validate_absolute_path(path: str) -> str | None:
    """Validate that a path is a well-formed absolute path per R12.

    Called at protocol boundaries (dispatch, resource targets) after
    canonicalization. Defense-in-depth — catches malformed or malicious
    paths that survived canonicalization.

    NOT called on patterns — patterns may have wildcard segments (e.g.,
    /*/*) which are valid pattern syntax but not valid peer IDs.

    Checks:
    - Starts with /
    - No empty segments (//)
    - First segment after / is a valid peer_id (>= 46 chars, Base58)

    Per D9 (v1.4 Amendment 2): the {X} slot is peer-ID-only. The §6.4
    ``content`` / ``manifest`` reserved words are an **http-poll
    URL-layer** concept (consumer hits ``/{prefix}/{X}/...`` where {X}
    may be a peer-ID OR a reserved word). They are NOT tree paths and
    are NOT accepted here; that rejection is what makes peer-IDs and
    reserved words structurally collision-safe.

    Args:
        path: The canonicalized absolute path to validate.

    Returns:
        None if valid, or an error message string if invalid.
    """
    if not path.startswith("/"):
        return "not absolute: missing leading /"

    # Check for empty segments (// anywhere in the path)
    if "//" in path:
        return f"empty segment in path: {path}"

    # Extract and validate peer_id segment
    segments = path[1:].split("/")  # skip leading /
    if not segments or not segments[0]:
        return "missing peer_id segment"

    if not is_peer_id(segments[0]):
        return f"invalid peer_id segment: {segments[0][:20]}..."

    return None


def validate_path_chars(path: str) -> str | None:
    """Reject ASCII control characters in a path (V7 §1.4).

    Form-agnostic: scans the raw path string for NUL, the C0 control
    range (0x00–0x1F), and DEL (0x7F). Per V7 §1.4 paths MUST NOT
    contain control characters. Called at the tree-handler write
    boundary before any binding (v7.72 §9.5a CORE-TREE-PATH-FLEX-1).

    Returns None if clean, else an error message naming the offending
    byte and its offset.
    """
    for i, ch in enumerate(path):
        c = ord(ch)
        if c < 0x20 or c == 0x7F:
            return (
                f"control character 0x{c:02X} at offset {i} "
                "(V7 §1.4: paths MUST NOT contain control characters)"
            )
    return None


def invariant_signature_path(signer_peer_id: str, target_hash: bytes) -> str:
    """The V7 §3.5 invariant pointer path for a signature.

    `{signer_peer_id}/system/signature/{target_hash_hex}` — the single,
    peer-agnostic, V7-general constructable `(signer, target)`→signature
    location (v7.45 "Discovery locality" strategy (B)). This is the ONLY
    path the general chain machinery constructs and consults:
    `collect_chain_bundle` / the receiver's resolver / §2656 envelope
    ingest. A `system/capability/token` that can appear in an authority
    chain transported/re-verified away from its issuer MUST have its
    signature discoverable here (V7 §3.5, v7.44 normative); the extension
    that *locally mints* such a cap binds it here (it MAY additionally
    keep an extension-private copy only for its own bookkeeping).

    Single source so bind and resolve cannot drift (the prior inline
    copies in peer ingest / continuation chain-bundle / identity /
    role-derived minting all route through this).

    `target_hash` is the content hash bytes of the signed entity;
    hex is lowercase and includes the format-code prefix.
    """
    return f"{signer_peer_id}/system/signature/{target_hash.hex()}"
