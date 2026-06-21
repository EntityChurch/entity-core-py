#!/usr/bin/env python3
"""Generate EXTENSION-CONTENT v3.5 cross-impl conformance vectors.

Per §3.6.5 the spec names four vector surfaces:

1. **Gear table** — first 16 entries (§3.6.1 sanity check).
2. **Fixed-size chunking boundaries** — canonical inputs at standardized
   chunk sizes, byte-equal expected chunk hashes.
3. **FastCDC boundaries** — same canonical inputs at the §3.5 target
   sizes, with the edit-stability rider (1-byte insertion vector).
4. **ECF byte-equality** for blob and chunk entities at the canonical-
   encoding boundary.

Vectors emit to:

* ``content-vectors.json`` — machine-readable (cross-impl harness).
* ``content-vectors.md``   — human-readable (the discussion artifact).

Run from the repo root::

    uv run python docs/conformance/content-v3.5/generate_vectors.py

Cross-impl: Go and Rust generators (when they write them) MUST produce
the same JSON for the same canonical input definitions.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Ensure the workspace packages are importable when running this script
# directly from the conformance directory.
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "entity-core" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "entity-handlers" / "src"))

from entity_core.protocol.entity import Entity  # noqa: E402
from entity_core.utils.ecf import ecf_encode  # noqa: E402
from entity_handlers.content.chunking import (  # noqa: E402
    build_fastcdc,
    build_fixed_size,
)
from entity_handlers.content.fastcdc import GEAR_TABLE  # noqa: E402


# -----------------------------------------------------------------------------
# Canonical inputs — defined by content, not by random seed. Same byte
# stream on every impl. Cross-impl agreement is then a byte-for-byte
# property of the chunker.
# -----------------------------------------------------------------------------


def canonical_inputs() -> dict[str, bytes]:
    """The set of canonical byte streams cross-impl runs grade against.

    Each is a function of size + a deterministic pattern so any impl can
    construct the byte-identical input from the spec text.
    """
    return {
        # All zeros — degenerate but reveals min/max boundary behavior.
        "zeros_4mib": b"\x00" * (4 * 1024 * 1024),
        "zeros_512kib": b"\x00" * (512 * 1024),
        # Repeating byte pattern — every byte mod 256 in order.
        "ramp_4mib": bytes((i & 0xFF) for i in range(4 * 1024 * 1024)),
        # Deterministic pseudo-pattern via SHA-256 stream — high-entropy
        # but reproducible from the seed without language-specific PRNGs.
        # SHA-256 of "FastCDC-conformance" produces a 32-byte block;
        # we extend by hashing the previous block || block_index_byte.
        "sha256_stream_2mib": _sha256_stream(2 * 1024 * 1024),
    }


def _sha256_stream(n: int) -> bytes:
    """Generate ``n`` bytes deterministically via a SHA-256 chain.

    Spec-portable: any impl can produce the same bytes by hashing
    ``b"FastCDC-conformance"`` and chaining
    ``SHA-256(prev || byte(block_index))``.
    """
    out = bytearray()
    block_index = 0
    prev = b""
    seed = hashlib.sha256(b"FastCDC-conformance").digest()
    while len(out) < n:
        if not prev:
            block = seed
        else:
            block = hashlib.sha256(prev + bytes([block_index & 0xFF])).digest()
        out.extend(block)
        prev = block
        block_index += 1
    return bytes(out[:n])


# -----------------------------------------------------------------------------
# Surface 1: Gear table (first 16 entries)
# -----------------------------------------------------------------------------


def vec_gear_table_first_16() -> list[dict]:
    return [
        {
            "index": i,
            "preimage_hex": (b"FastCDC" + bytes([i])).hex(),
            "value_uint64": GEAR_TABLE[i],
            "value_hex_le8": GEAR_TABLE[i].to_bytes(8, byteorder="little").hex(),
        }
        for i in range(16)
    ]


# -----------------------------------------------------------------------------
# Surface 2: Fixed-size chunking boundaries
# -----------------------------------------------------------------------------


def vec_fixed_size() -> list[dict]:
    rows: list[dict] = []
    for name, data in canonical_inputs().items():
        for chunk_size in (64 * 1024, 4 * 1024 * 1024):
            if chunk_size > len(data) * 2:
                continue  # skip nonsense combinations
            result = build_fixed_size(data, chunk_size=chunk_size)
            rows.append(
                {
                    "input": name,
                    "input_size": len(data),
                    "chunk_size": chunk_size,
                    "blob_hash_hex": result.blob_hash.hex(),
                    "chunk_count": len(result.chunks),
                    "chunk_hashes_hex": [
                        h.hex() for h in result.blob.data["chunks"]
                    ],
                }
            )
    return rows


# -----------------------------------------------------------------------------
# Surface 3: FastCDC boundaries + edit-stability
# -----------------------------------------------------------------------------


def vec_fastcdc() -> list[dict]:
    rows: list[dict] = []
    inputs = canonical_inputs()
    for name, data in inputs.items():
        for target_size in (64 * 1024, 4 * 1024 * 1024):
            if target_size > len(data) * 2:
                continue
            result = build_fastcdc(data, target_size=target_size)
            rows.append(
                {
                    "input": name,
                    "input_size": len(data),
                    "target_size": target_size,
                    "blob_hash_hex": result.blob_hash.hex(),
                    "chunk_count": len(result.chunks),
                    "chunk_hashes_hex": [
                        h.hex() for h in result.blob.data["chunks"]
                    ],
                }
            )
    return rows


def vec_fastcdc_edit_stability() -> list[dict]:
    """The load-bearing vector: a 1-byte insertion at a known offset
    invalidates only the chunk containing the insertion (and a bounded
    re-sync window after); chunks before are byte-identical and the
    stream resyncs in the tail.

    Each row gives:
      * original_blob_hash — over the canonical pre-edit stream
      * edited_blob_hash   — over the post-edit stream
      * insertion_offset, insertion_byte — what changed
      * stable_prefix_chunks — count of leading chunks identical in both
      * resynced_tail_chunks — count of trailing chunks identical in both

    A conforming sibling impl produces the same numbers — both hashes,
    both counts. Different numbers means gear-table drift or mask-
    discipline divergence.
    """
    rows: list[dict] = []
    for name in ("sha256_stream_2mib",):
        original = canonical_inputs()[name]
        for insertion_offset in (100 * 1024,):
            insertion_byte = 0x5A
            edited = (
                original[:insertion_offset]
                + bytes([insertion_byte])
                + original[insertion_offset:]
            )
            target = 64 * 1024
            orig_result = build_fastcdc(original, target_size=target)
            edit_result = build_fastcdc(edited, target_size=target)

            orig_hashes = orig_result.blob.data["chunks"]
            edit_hashes = edit_result.blob.data["chunks"]

            # Stable prefix (chunks before the edit).
            stable = 0
            for o, e in zip(orig_hashes, edit_hashes):
                if o == e:
                    stable += 1
                else:
                    break
            # Resynced tail.
            resync = 0
            for k in range(1, min(len(orig_hashes), len(edit_hashes)) + 1):
                if orig_hashes[-k:] == edit_hashes[-k:]:
                    resync = k

            rows.append(
                {
                    "input": name,
                    "input_size": len(original),
                    "target_size": target,
                    "insertion_offset": insertion_offset,
                    "insertion_byte": insertion_byte,
                    "original_blob_hash_hex": orig_result.blob_hash.hex(),
                    "edited_blob_hash_hex": edit_result.blob_hash.hex(),
                    "original_chunk_count": len(orig_hashes),
                    "edited_chunk_count": len(edit_hashes),
                    "stable_prefix_chunks": stable,
                    "resynced_tail_chunks": resync,
                }
            )
    return rows


# -----------------------------------------------------------------------------
# Surface 4: ECF byte-equality for blob + chunk + descriptor entities
# -----------------------------------------------------------------------------


def vec_ecf_byte_equality() -> list[dict]:
    rows: list[dict] = []

    # A representative chunk
    chunk_payload = b"\x01\x02\x03\x04" * 32  # 128 bytes
    chunk = Entity(
        type="system/content/chunk",
        data={"payload": chunk_payload},
    )
    chunk_bytes = ecf_encode({"type": chunk.type, "data": chunk.data})
    rows.append(
        {
            "case": "chunk_128B",
            "entity_type": chunk.type,
            "ecf_bytes_hex": chunk_bytes.hex(),
            "entity_hash_hex": chunk.compute_hash().hex(),
        }
    )

    # A representative blob — 2 chunks, FastCDC, 4 MiB target.
    blob = Entity(
        type="system/content/blob",
        data={
            "total_size": 8 * 1024 * 1024,
            "chunk_size": 4 * 1024 * 1024,
            "chunking": 1,  # FastCDC/NC2
            "chunks": [
                bytes([0x00]) + bytes([0xA0] * 32),
                bytes([0x00]) + bytes([0xB1] * 32),
            ],
        },
    )
    blob_bytes = ecf_encode({"type": blob.type, "data": blob.data})
    rows.append(
        {
            "case": "blob_2chunks_4mib_fastcdc",
            "entity_type": blob.type,
            "ecf_bytes_hex": blob_bytes.hex(),
            "entity_hash_hex": blob.compute_hash().hex(),
        }
    )

    # A descriptor with media_type only — §2.4 minimal shape.
    descriptor = Entity(
        type="system/content/descriptor",
        data={
            "content": bytes([0x00]) + bytes([0x42] * 32),
            "media_type": "application/pdf",
        },
    )
    desc_bytes = ecf_encode({"type": descriptor.type, "data": descriptor.data})
    rows.append(
        {
            "case": "descriptor_media_type_only",
            "entity_type": descriptor.type,
            "ecf_bytes_hex": desc_bytes.hex(),
            "entity_hash_hex": descriptor.compute_hash().hex(),
        }
    )

    return rows


# -----------------------------------------------------------------------------
# Emit
# -----------------------------------------------------------------------------


def build_payload() -> dict:
    return {
        "spec": "EXTENSION-CONTENT.md v3.5",
        "generated_by": "entity-core-py",
        "vectors": {
            "gear_table_first_16": vec_gear_table_first_16(),
            "fixed_size_boundaries": vec_fixed_size(),
            "fastcdc_boundaries": vec_fastcdc(),
            "fastcdc_edit_stability": vec_fastcdc_edit_stability(),
            "ecf_byte_equality": vec_ecf_byte_equality(),
        },
    }


def render_markdown(payload: dict) -> str:
    lines = [
        "# EXTENSION-CONTENT v3.5 — cross-impl conformance vectors",
        "",
        "**Spec reference:** `EXTENSION-CONTENT.md` v3.5 §3.6.5",
        f"**Generator:** `{payload['generated_by']}` (regenerate via "
        "`docs/conformance/content-v3.5/generate_vectors.py`)",
        "",
        "These are the four conformance-vector surfaces named in §3.6.5. "
        "Sibling-impl regeneration MUST produce byte-identical values in "
        "every field. Mismatches indicate cross-impl divergence at the "
        "boundary the field grades (gear table → §3.6.1 derivation; "
        "boundary vectors → §3.6.3 algorithm; ECF byte equality → "
        "`ENTITY-CBOR-ENCODING.md` §4.2 + the §2.8 wire-shape pin).",
        "",
        "---",
        "",
    ]

    # Gear table
    lines.append("## Surface 1 — Gear table (first 16 entries, §3.6.1)")
    lines.append("")
    lines.append("| i | preimage (hex) | value_uint64 | first 8 bytes LE (hex) |")
    lines.append("|---|---|---|---|")
    for row in payload["vectors"]["gear_table_first_16"]:
        lines.append(
            f"| {row['index']} | `{row['preimage_hex']}` | "
            f"`{row['value_uint64']}` | `{row['value_hex_le8']}` |"
        )
    lines.append("")

    # Fixed-size
    lines.append("## Surface 2 — Fixed-size chunking boundaries (§3.2)")
    lines.append("")
    for row in payload["vectors"]["fixed_size_boundaries"]:
        lines.append(
            f"- **{row['input']}** ({row['input_size']} bytes) at "
            f"`chunk_size={row['chunk_size']}` → "
            f"`{row['chunk_count']}` chunks, "
            f"blob hash `{row['blob_hash_hex']}`."
        )
    lines.append("")

    # FastCDC
    lines.append("## Surface 3a — FastCDC chunking boundaries (§3.6)")
    lines.append("")
    for row in payload["vectors"]["fastcdc_boundaries"]:
        lines.append(
            f"- **{row['input']}** ({row['input_size']} bytes) at "
            f"`target_size={row['target_size']}` → "
            f"`{row['chunk_count']}` chunks, "
            f"blob hash `{row['blob_hash_hex']}`."
        )
    lines.append("")

    # Edit stability
    lines.append("## Surface 3b — FastCDC edit-stability (§3.6.5, load-bearing)")
    lines.append("")
    lines.append(
        "1-byte insertion at a known offset; sibling impls MUST produce "
        "the same edited-blob hash, the same chunk counts, and the same "
        "stable-prefix / resynced-tail measurements."
    )
    lines.append("")
    for row in payload["vectors"]["fastcdc_edit_stability"]:
        lines.append(
            f"- **{row['input']}** ({row['input_size']} bytes) @ "
            f"target={row['target_size']}, insertion at "
            f"offset={row['insertion_offset']} byte=`0x{row['insertion_byte']:02X}`:"
        )
        lines.append(
            f"  - original blob hash `{row['original_blob_hash_hex']}` "
            f"({row['original_chunk_count']} chunks)"
        )
        lines.append(
            f"  - edited blob hash `{row['edited_blob_hash_hex']}` "
            f"({row['edited_chunk_count']} chunks)"
        )
        lines.append(
            f"  - stable prefix chunks (identical leading run): "
            f"`{row['stable_prefix_chunks']}`"
        )
        lines.append(
            f"  - resynced tail chunks (identical trailing run): "
            f"`{row['resynced_tail_chunks']}`"
        )
    lines.append("")

    # ECF
    lines.append("## Surface 4 — ECF byte-equality for content entities (§2.1 / §2.2 / §2.4)")
    lines.append("")
    lines.append(
        "Same `{type, data}` → same canonical bytes → same entity hash. "
        "Cross-impl drift here would break content dedup silently — same "
        "class of risk that drove `ENTITY-CBOR-ENCODING.md` Appendix E."
    )
    lines.append("")
    lines.append("| case | type | entity hash (hex) | ECF bytes (hex, prefix) |")
    lines.append("|---|---|---|---|")
    for row in payload["vectors"]["ecf_byte_equality"]:
        bytes_preview = row["ecf_bytes_hex"][:80]
        if len(row["ecf_bytes_hex"]) > 80:
            bytes_preview += "…"
        lines.append(
            f"| `{row['case']}` | `{row['entity_type']}` | "
            f"`{row['entity_hash_hex']}` | `{bytes_preview}` |"
        )
    lines.append("")
    lines.append(
        "Full ECF bytes per case live in `content-vectors.json` "
        "(field `vectors.ecf_byte_equality[].ecf_bytes_hex`)."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    payload = build_payload()
    (out_dir / "content-vectors.json").write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n"
    )
    (out_dir / "content-vectors.md").write_text(render_markdown(payload))
    counts = {k: len(v) for k, v in payload["vectors"].items()}
    print("Wrote content-vectors.json and content-vectors.md")
    print(f"Vector counts: {counts}")


if __name__ == "__main__":
    main()
