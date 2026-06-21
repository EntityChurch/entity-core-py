"""Anchor tests for the EXTENSION-CONTENT v3.5 conformance vectors.

The vectors live at ``tests/conformance/content-v3.5/`` and are
regenerated via ``tests/conformance/content-v3.5/generate_vectors.py``.
These tests grade two things:

1. The vector file exists and parses (the doc artifact is in tree).
2. The vector values match what the in-process generator produces
   *right now* — so accidental drift in chunker code without a vector
   regeneration is caught loudly.

The pattern mirrors ``tests/unit/test_type_v1_1_conformance_vectors.py``
for the §5.5 ``one_of`` vectors that closed TYPE Phase 1.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parents[1] / "conformance" / "content-v3.5"
VECTORS_JSON = VECTORS_DIR / "content-vectors.json"
GENERATOR = VECTORS_DIR / "generate_vectors.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "content_vectors_generator", GENERATOR
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stored() -> dict:
    return json.loads(VECTORS_JSON.read_text())


def _current() -> dict:
    return _load_generator().build_payload()


class TestVectorFileExists:
    def test_json_exists_and_parses(self):
        assert VECTORS_JSON.exists(), (
            "content-vectors.json missing — regenerate via "
            "tests/conformance/content-v3.5/generate_vectors.py"
        )
        data = _stored()
        assert data["spec"] == "EXTENSION-CONTENT.md v3.5"
        assert "vectors" in data

    def test_markdown_companion_present(self):
        md = VECTORS_DIR / "content-vectors.md"
        assert md.exists(), "content-vectors.md companion missing"


class TestVectorsAgreeWithGenerator:
    """If the chunker or ECF encoder drifts, the stored vectors stop
    matching what the generator produces in-process. Re-run the
    generator to update — the diff is the cross-impl-visible change.
    """

    def test_gear_table_first_16(self):
        assert _stored()["vectors"]["gear_table_first_16"] == _current()["vectors"]["gear_table_first_16"]

    def test_fixed_size_boundaries(self):
        assert _stored()["vectors"]["fixed_size_boundaries"] == _current()["vectors"]["fixed_size_boundaries"]

    def test_fastcdc_boundaries(self):
        assert _stored()["vectors"]["fastcdc_boundaries"] == _current()["vectors"]["fastcdc_boundaries"]

    def test_fastcdc_edit_stability(self):
        """The load-bearing surface. If this drifts, cross-impl
        convergence will fail on Go/Rust comparison; we want to know
        first.
        """
        assert _stored()["vectors"]["fastcdc_edit_stability"] == _current()["vectors"]["fastcdc_edit_stability"]

    def test_ecf_byte_equality(self):
        assert _stored()["vectors"]["ecf_byte_equality"] == _current()["vectors"]["ecf_byte_equality"]


class TestVectorInvariants:
    """Cross-checks on the vector content itself — these are properties
    every conforming impl's vectors MUST satisfy regardless of generator
    drift.
    """

    def test_gear_table_first_entry_matches_derivation(self):
        """§3.6.1 closed form must hold for the first row."""
        import hashlib

        row0 = _stored()["vectors"]["gear_table_first_16"][0]
        digest = hashlib.sha256(b"FastCDC" + b"\x00").digest()
        expected = int.from_bytes(digest[:8], byteorder="little", signed=False)
        assert row0["value_uint64"] == expected

    def test_edit_stability_stable_prefix_at_least_one(self):
        rows = _stored()["vectors"]["fastcdc_edit_stability"]
        assert rows, "edit-stability vector empty"
        for row in rows:
            # The insertion is at offset 100 KiB; the first chunk (at
            # least the leading min_size = 16 KiB on a 64 KiB target)
            # is before the edit. So stable prefix is >= 1.
            assert row["stable_prefix_chunks"] >= 1, (
                "edit-stability lost the leading chunk — gear table or "
                "mask discipline diverged"
            )

    def test_edit_stability_resyncs_in_tail(self):
        rows = _stored()["vectors"]["fastcdc_edit_stability"]
        for row in rows:
            assert row["resynced_tail_chunks"] >= 1, (
                "FastCDC failed to resync after a 1-byte insertion — "
                "this fails every cross-impl convergence run"
            )

    def test_blob_hashes_start_with_algorithm_byte_zero(self):
        """All blob hashes use ECFv1-SHA256 (algorithm byte 0x00)."""
        rows = _stored()["vectors"]["fixed_size_boundaries"]
        for row in rows:
            assert row["blob_hash_hex"].startswith("00"), (
                f"blob hash {row['blob_hash_hex']} not algorithm 0x00"
            )
