"""URL construction per PROPOSAL-EXTENSION-CONTENT-SUBSTITUTE-CDN §3-RES.2
+ arch ruling (sharding hash — Option α).

A `Hash` on-wire is `algorithm_byte || digest` (V7 §3.5). `{hash}` means
**one thing everywhere** — the full 66-hex wire form. Shard layouts
slice that same string; they do NOT re-split into a digest-only view.

Per arch ruling (Option α adopted, β/γ rejected):
- §5 B made `{hash}` mean one thing — layouts must slice that, not
  re-split.
- `sharded-2-4` → `/{wire_hex[0:2]}/{wire_hex[2:4]}/{wire_hex}` =
  `/00/ad/00ada873…` for SHA-256 entities. `00` is the algorithm
  partition (free crypto-agility — SHA-384 entities land in `/01/`,
  SHA-512 in `/02/`). `ad` is where SHA-256 actually shards. Leaf is
  the full wire hash.
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
    """Return the canonical 66-char wire-form hex of a Hash.

    Per arch ruling (Option α): `{hash}` is uniformly the
    66-hex wire form (algorithm byte + digest, V7 §3.5). Shard slices
    are taken from this string."""
    return bytes(h).hex()


# Back-compat alias for any external callers still importing the old
# name; the old behavior (digest-only) is no longer the spec, so the
# alias returns the wire form. Removing in the next cleanup pass.
def digest_hex(h: Hash) -> str:
    """Deprecated alias for `wire_hex`. Returns the 66-char wire-form
    hex (algorithm byte + digest) per Option α. The old behavior
    (digest-only, 64 chars) was Option β, ruled against. Callers
    should migrate to `wire_hex`."""
    return wire_hex(h)


def build_content_url(
    content_url_prefix: str,
    content_layout: str,
    h: Hash,
) -> str:
    """Build a content URL for hash `h` per `content_layout` (§3-RES.2)
    + arch ruling (Option α).

    `{hash}` is uniformly the 66-hex wire form (algorithm byte + digest).
    Shard layouts slice from that string:
    - flat:           `{prefix}/{hash}`                        (66-char leaf)
    - sharded-2-flat: `{prefix}/{hash[0:2]}/{hash}`            (alg-byte shard)
    - sharded-2-4:    `{prefix}/{hash[0:2]}/{hash[2:4]}/{hash}` (alg + first-digest-byte)
    - sharded-2-2:    alias for sharded-2-4

    For SHA-256 entities (algorithm byte `0x00`) the first shard dir is
    always `/00/` — the algorithm partition. That's intentional (free
    crypto-agility): SHA-384 entities would land in `/01/`, SHA-512 in
    `/02/`, with no per-deployment config needed.

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
