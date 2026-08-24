"""URL construction per PROPOSAL-EXTENSION-CONTENT-SUBSTITUTE-CDN §3-RES.2
+ arch ruling (sharding hash — Option α), pinned by EXTENSION-NETWORK
§6.5.3 **hex strictness [MUST]**.

A `Hash` on-wire is `algorithm_byte || digest` (V7 §3.5). `{hash}` means
**one thing everywhere** — the full wire form, format-code byte
included. Shard layouts slice that same string; they do NOT re-split
into a digest-only view.

**The width is byte-implied and MUST NOT be treated as a constant**
(`SPECIFICATION-FORMAT` §8.4.5): 66 hex chars beginning `00` under
ECFv1-SHA-256, 98 beginning `01` under ECFv1-SHA-384, and so on. A
hardcoded-66 length gate *is* the bug — it was the corrected 2026-08-10
cohort defect that `400`'d a valid SHA-384 hash. Nothing in this module
computes a length; the width follows from the `Hash`'s own bytes, and
the serve side (`entity_core.peer.http_server`) validates it through
`validate_hash`, which reads the format byte and checks the digest width
that byte implies.

Per arch ruling (Option α adopted, β/γ rejected):
- §5 B made `{hash}` mean one thing — layouts must slice that, not
  re-split.
- `sharded-2-4` → `/{wire_hex[0:2]}/{wire_hex[2:4]}/{wire_hex}` =
  `/00/ad/00ada873…` for SHA-256 entities. `wire_hex[0:2]` is the
  **format-code byte = the algorithm partition** (free crypto-agility —
  SHA-384 entities land in `/01/`, SHA-512 in `/02/`); a digest-only hex
  would silently slice the first *digest* byte there and that property
  dies. `ad` is where SHA-256 actually shards. Leaf is the full wire
  hash.
- Matches workbench-go's shipped + validated layout (272 entities
  across 164 buckets, leaf `sha256sum == digest`).

`tree_leaf_suffix` defaults to `.bin` per Round-6 #1; consumers MUST
append the suffix literally (no URL rewriting at consume time).
"""

from __future__ import annotations

from entity_core.utils.ecf import Hash

DEFAULT_TREE_LEAF_SUFFIX = ".bin"

CONTENT_LAYOUTS = frozenset({"flat", "sharded-2-flat", "sharded-2-4", "sharded-2-2"})


def wire_hex(h: Hash) -> str:
    """Return the canonical wire-form hex of a Hash — format byte included.

    Per arch ruling (Option α) and EXTENSION-NETWORK §6.5.3's hex-strictness
    `[MUST]`: `{hash}` is uniformly the full wire form (format-code byte +
    digest, V7 §3.5), never the digest-only form. Shard slices are taken from
    this string.

    **The result's length is whatever the Hash's own bytes imply** — 66 chars
    for ECFv1-SHA-256, 98 for ECFv1-SHA-384. This function does not know, and
    must not learn, a constant.
    """
    return bytes(h).hex()


def build_content_url(
    content_url_prefix: str,
    content_layout: str,
    h: Hash,
) -> str:
    """Build a content URL for hash `h` per `content_layout` (§3-RES.2)
    + arch ruling (Option α).

    `{hash}` is uniformly the full wire-form hex (format-code byte + digest,
    NETWORK §6.5.3 `[MUST]`). Shard layouts slice from that string:
    - flat:           `{prefix}/{hash}`                         (full-wire leaf)
    - sharded-2-flat: `{prefix}/{hash[0:2]}/{hash}`             (format-byte shard)
    - sharded-2-4:    `{prefix}/{hash[0:2]}/{hash[2:4]}/{hash}` (format + first-digest-byte)
    - sharded-2-2:    alias for sharded-2-4

    For SHA-256 entities (format byte `0x00`) the first shard dir is
    always `/00/` — the algorithm partition. That's intentional (free
    crypto-agility): SHA-384 entities land in `/01/`, SHA-512 in
    `/02/`, with no per-deployment config needed. The leaf's length is
    byte-implied (66 / 98 / …), never asserted as a constant here.

    `content_url_prefix` is taken as-is; the publisher writes the literal
    URL prefix into their transport profile entity (no peer-id
    template-substitution at consume time, per §6.5.3).
    """
    if content_layout not in CONTENT_LAYOUTS:
        raise ValueError(
            f"Unsupported content_layout: {content_layout!r} "
            f"(must be one of {sorted(CONTENT_LAYOUTS)})"
        )
    hex_ = wire_hex(h)
    base = content_url_prefix.rstrip("/")
    if content_layout == "flat":
        return f"{base}/{hex_}"
    if content_layout == "sharded-2-flat":
        return f"{base}/{hex_[0:2]}/{hex_}"
    # sharded-2-4 / sharded-2-2 (alias)
    return f"{base}/{hex_[0:2]}/{hex_[2:4]}/{hex_}"


def build_tree_url(
    tree_url_prefix: str,
    tree_path: str,
    tree_leaf_suffix: str = DEFAULT_TREE_LEAF_SUFFIX,
) -> str:
    """Build a tree-leaf URL: `{prefix}/{tree_path}{suffix}` (NETWORK §6.5.3 step 5).

    The suffix is appended **literally** to the tree path. Default `.bin`;
    operator-overridable per Round-6 #1.
    """
    base = tree_url_prefix.rstrip("/")
    leaf = tree_path.lstrip("/")
    return f"{base}/{leaf}{tree_leaf_suffix}"
