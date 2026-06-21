"""Cross-impl publish→fetch wire drive — Go publishes, Python consumes.

Builds and runs Go's ``cmd/publish-fixture`` deterministic http-poll origin,
then drives it with Python's ``HttpPollClient`` via the shared driver in
``scripts/fetch_published_fixture.py``, asserting the pinned contract from
the cross-impl publish-fetch fixture handoff.

This is the headline "publish to the web" interop proof — it converts Thread B's
per-impl self-PASS into an actual cross-process Go→Python byte-equality drive.
Arch ruled self-PASS sufficient for the v1 gate, so this is the
recommended interop leg, not a blocker; accordingly it **skips** cleanly when
the Go toolchain or the sibling ``entity-core-go`` checkout is absent (e.g. a
Python-only CI runner), rather than failing.

The driver itself (``scripts/fetch_published_fixture.py``) is the portable
artifact the cohort coordinator runs against any byte-compatible origin; this
test is the local "did interop" capture.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

# --- Locate the sibling Go repo + driver -------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GO_REPO = _REPO_ROOT.parent / "entity-core-go"
_FIXTURE_PKG = _GO_REPO / "cmd" / "publish-fixture"
_DRIVER_PATH = _REPO_ROOT / "scripts" / "fetch_published_fixture.py"

_go_bin = shutil.which("go")

pytestmark = pytest.mark.skipif(
    _go_bin is None or not _FIXTURE_PKG.is_dir() or not _DRIVER_PATH.is_file(),
    reason="cross-impl drive needs the Go toolchain + sibling entity-core-go checkout",
)


def _load_driver():
    """Import scripts/fetch_published_fixture.py as a module."""
    spec = importlib.util.spec_from_file_location("fetch_published_fixture", _DRIVER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so the deferred dataclass annotations (PEP 563) can
    # resolve cls.__module__ in sys.modules during exec_module.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_listening(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            if s.connect_ex((host, port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"publish-fixture did not start listening on {host}:{port}")


@pytest.fixture(scope="module")
def go_fixture_binary(tmp_path_factory) -> Path:
    """`go build` the publish-fixture into a temp dir (no writes to the Go repo)."""
    out = tmp_path_factory.mktemp("go-fixture") / "publish-fixture"
    build = subprocess.run(
        [_go_bin, "build", "-o", str(out), "./cmd/publish-fixture"],
        cwd=str(_GO_REPO),
        capture_output=True,
        text=True,
        timeout=300,
    )
    if build.returncode != 0:
        pytest.skip(f"go build publish-fixture failed:\n{build.stderr}")
    return out


@pytest.fixture
def running_fixture(go_fixture_binary):
    """Start the publisher on a free port; tear it down after the test."""
    port = _free_port()
    proc = subprocess.Popen(
        [str(go_fixture_binary), "-addr", f"127.0.0.1:{port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_listening("127.0.0.1", port)
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_go_publish_python_consume_byte_equality(running_fixture):
    """Go publishes the deterministic blog tree; Python consumes and verifies
    the signed manifest + per-leaf re-hash + byte-equality against the pinned
    contract. PASS == cross-impl interop, not just per-impl self-consistency."""
    driver = _load_driver()
    passes = asyncio.run(driver.drive(running_fixture))
    # Three vector groups: v1+v2 (manifest+sig), v3+v4 (leaves), v5 (bytes).
    assert len(passes) == 3, passes
    assert any("v1+v2" in p for p in passes)
    assert any("v5" in p for p in passes)


def test_driver_cli_exits_zero(running_fixture):
    """The portable CLI surface (what the cohort coordinator invokes) exits 0
    and prints ALL PASS against the live origin."""
    result = subprocess.run(
        [sys.executable, str(_DRIVER_PATH), "--url", running_fixture],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ},
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "ALL PASS" in result.stdout
