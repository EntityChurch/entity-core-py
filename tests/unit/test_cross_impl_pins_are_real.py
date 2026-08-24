"""The cross-impl fixture pins are measurements, not placeholders.

**This file exists because the row that should have caught it could not.**
`tests/integration/test_cross_impl_publish_fetch.py` is the headline
Go-publishes → Python-consumes byte-equality drive, and it `skipif`s cleanly
when the Go toolchain or the sibling checkout is absent — deliberately, so a
Python-only runner is not blocked. The consequence is the one `AGENTS.md`
names: *a gate that skips when its dependency is absent has never told you it
passes.* Its `PINNED_ROOT_HASH` shipped as the literal byte sequence
`0xc0..0xdf` — a stub nobody filled — and it had **never passed in visible
history** while reporting green on every host without Go.

So the placeholder check lives **here**, in `tests/unit/`, with no `skipif` on
anything: it needs no Go, no network, and no fixture. It reads the pins as data
and asks only whether they look like something a human typed to fill a hole.
That is the half of the check that can run everywhere, and running everywhere is
the entire point.

It does **not** verify the pins are *correct* — only the live drive can do that.
Two different jobs: this row catches a pin that was never measured; the
integration row catches a pin that was measured and has since drifted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DRIVER_PATH = _REPO_ROOT / "scripts" / "fetch_published_fixture.py"


def _load_driver():
    spec = importlib.util.spec_from_file_location(
        "fetch_published_fixture_pins", _DRIVER_PATH
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _looks_like_a_byte_ladder(raw: bytes) -> bool:
    """Are these bytes a consecutive ascending run, e.g. `0xc0 0xc1 0xc2 …`?

    This is what a hand-typed placeholder looks like, and it is what the
    original `PINNED_ROOT_HASH` was. A real digest has no such structure; the
    odds of SHA-256 producing 32 consecutive ascending bytes are nil.
    """
    return len(raw) > 3 and all(
        (b - a) % 256 == 1 for a, b in zip(raw, raw[1:])
    )


def _is_degenerate(raw: bytes) -> bool:
    """All-identical bytes — the other shape a stub takes (`00…`, `ff…`)."""
    return len(raw) > 3 and len(set(raw)) == 1


class TestPinsAreNotPlaceholders:
    """Every pinned hex constant is a measured value.

    Parametrized over the pins by *name*, so a pin added later is covered
    without anyone remembering to extend this file — the failure mode being
    guarded against is precisely "somebody stubbed a constant and moved on".
    """

    @pytest.fixture(scope="class")
    def driver(self):
        return _load_driver()

    def test_the_hex_pins_are_all_real_digests(self, driver):
        pins = {
            name: value
            for name, value in vars(driver).items()
            if name.startswith("PINNED_")
            and isinstance(value, str)
            and name.endswith("HASH")
        }
        assert pins, "no PINNED_*HASH constants found — did the driver move?"

        failures: list[str] = []
        for name, value in sorted(pins.items()):
            try:
                raw = bytes.fromhex(value)
            except ValueError:
                failures.append(f"{name}: not hex ({value!r})")
                continue
            if len(raw) != 32:
                failures.append(f"{name}: {len(raw)} bytes, expected a 32-byte digest")
            if _looks_like_a_byte_ladder(raw):
                failures.append(
                    f"{name}: consecutive ascending bytes ({value}) — this is a "
                    "hand-typed placeholder, not a measured digest. Run the "
                    "cross-impl drive on a host with the Go toolchain and pin "
                    "the signature-verified value it reports."
                )
            if _is_degenerate(raw):
                failures.append(f"{name}: all bytes identical ({value}) — a stub")
        assert not failures, "placeholder pins:\n  " + "\n  ".join(failures)

    def test_the_entry_content_hashes_are_real_digests(self, driver):
        """The per-path pins go through the same check as the root."""
        entries = driver.PINNED_ENTRIES
        assert entries, "PINNED_ENTRIES is empty"
        for entry in entries:
            raw = bytes.fromhex(entry.content_hash)
            assert len(raw) == 32, f"{entry.path}: not a 32-byte digest"
            assert not _looks_like_a_byte_ladder(raw), f"{entry.path}: placeholder"
            assert not _is_degenerate(raw), f"{entry.path}: placeholder"


class TestTheDetectorItself:
    """The detector has teeth — asserted, not assumed.

    A placeholder-detector that silently matches nothing is the same class of
    defect it is meant to catch, so the byte ladder that actually shipped is
    kept here as a positive control.
    """

    def test_it_flags_the_ladder_that_actually_shipped(self):
        shipped = bytes.fromhex(
            "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        )
        assert _looks_like_a_byte_ladder(shipped)

    def test_it_flags_degenerate_runs(self):
        assert _is_degenerate(b"\x00" * 32)
        assert _is_degenerate(b"\xff" * 32)

    def test_it_does_not_flag_a_real_digest(self):
        real = bytes.fromhex(
            "af1c9f6bb378ef614942e60864e3ba3f3e3ac4972c8c43580055fa2234cdd9ab"
        )
        assert not _looks_like_a_byte_ladder(real)
        assert not _is_degenerate(real)
