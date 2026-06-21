"""Generate the canonical conformance-vector artifacts for
EXTENSION-TYPE v1.1 §5.5 (`one_of` ECF byte equality).

Produces two sibling files in this directory:

* ``one_of-ecf-vectors.cbor``  — normative CBOR-of-vectors per
  `PROPOSAL-WIRE-ENCODING-CONFORMANCE-VECTORS.md`. This is the
  machine-readable form Go's validate-peer (and Rust's
  equivalent) consume.
* ``one_of-ecf-vectors.diag`` — human-editable CBOR diagnostic
  notation source. The .cbor file is the canonical form; the
  .diag is the source-of-truth a human would edit.

Run from the repo root:

    uv run python docs/conformance/type-v1.1/generate_vectors.py
"""

from __future__ import annotations

import pathlib

from entity_core.utils.ecf import ecf_encode


# Each vector: (id, description, value, candidates, expected_valid).
# Mirrors `one_of-ecf-vectors.md` row-for-row.
VECTORS: list[tuple[str, str, object, list[object], bool]] = [
    ("v01", "string match",            "red",                                      ["red", "green", "blue"], True),
    ("v02", "string miss",             "yellow",                                   ["red", "green", "blue"], False),
    ("v03", "int match",               5,                                          [1, 2, 5],                True),
    ("v04", "int miss",                5,                                          [1, 2, 3],                False),
    ("v05", "int-vs-float divergence", 5.0,                                        [1, 2, 5],                False),
    ("v06", "nested map match",        {"kind": "color", "value": "red"},
        [
            {"kind": "color", "value": "blue"},
            {"kind": "color", "value": "red"},
            {"kind": "size", "value": "large"},
        ],
        True),
    ("v07", "array of strings",        ["a", "b"],                                  [["a"], ["a", "b"], ["c"]], True),
    ("v08", "bytes match",             b"hello",                                    [b"hello", b"world"],     True),
    ("v09", "bool match",              True,                                        [True],                   True),
    ("v10", "null match",              None,                                        [None, 1, 2],             True),
]


def main() -> None:
    here = pathlib.Path(__file__).parent

    # Build the normative CBOR-of-vectors structure.
    # Shape: array of {id, description, value, candidates, valid}.
    payload = [
        {
            "id": vid,
            "description": desc,
            "value": value,
            "candidates": cands,
            "valid": expected,
        }
        for vid, desc, value, cands, expected in VECTORS
    ]
    cbor_bytes = ecf_encode(payload)
    cbor_path = here / "one_of-ecf-vectors.cbor"
    cbor_path.write_bytes(cbor_bytes)

    # Build a .diag source file (CBOR diagnostic notation by hand).
    # Comments use #-prefix per RFC 8949 Appendix G.
    diag_lines: list[str] = []
    diag_lines.append("# EXTENSION-TYPE v1.1 §5.5 — `one_of` ECF byte-equality vectors.")
    diag_lines.append("# Companion to one_of-ecf-vectors.cbor (canonical form).")
    diag_lines.append("# See one_of-ecf-vectors.md for the human-readable table.")
    diag_lines.append("[")
    for vid, desc, value, cands, expected in VECTORS:
        diag_lines.append(f"  # {vid} — {desc}")
        diag_lines.append("  {")
        diag_lines.append(f'    "id": "{vid}",')
        diag_lines.append(f'    "description": "{desc}",')
        diag_lines.append(f'    "value": {_diag(value)},')
        diag_lines.append(f'    "candidates": [{", ".join(_diag(c) for c in cands)}],')
        diag_lines.append(f'    "valid": {"true" if expected else "false"}')
        diag_lines.append("  },")
    diag_lines.append("]")
    diag_path = here / "one_of-ecf-vectors.diag"
    diag_path.write_text("\n".join(diag_lines) + "\n")

    print(f"wrote {cbor_path} ({len(cbor_bytes)} bytes)")
    print(f"wrote {diag_path}")


def _diag(value: object) -> str:
    """Render a Python value as CBOR diagnostic notation."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, bytes):
        return f"h'{value.hex()}'"
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # The 5.0 vector is intentional — render as Python repr so the
        # reader sees it's a float, not an int.
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_diag(v) for v in value) + "]"
    if isinstance(value, dict):
        parts = [f'"{k}": {_diag(v)}' for k, v in value.items()]
        return "{" + ", ".join(parts) + "}"
    raise TypeError(f"unsupported value type for diag: {type(value)}")


if __name__ == "__main__":
    main()
