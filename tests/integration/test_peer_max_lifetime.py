"""`entity-core start --max-lifetime` — a debug peer that reaps itself.

Why this exists, and it is a process defect rather than a protocol one
(2026-08-22): `cmd_start` ended in a bare `await peer.serve_forever()`, so a
peer started by hand for debugging ran until something signalled it. The only
reaper was `kill`. When `kill` was withdrawn from agents on this host, the
workflow had no teardown at all and leaked listeners onto the fixed ports the
conformance harness binds — which is the *other* half of AGENTS.md's
"a validator failure on a fixed port is a leftover peer until proven
otherwise", arriving from the side that creates the leftover instead of the
side that trips over it.

**The property under test is that the port comes back**, not that the process
exited. A peer that dies without running `stop()` also exits; only the
shutdown path releases the listening socket, and the port is what the next run
collides with. So every row here asserts the socket, and
`TestMaxLifetime::test_the_teeth_control_*` pins that the exit is attributable
to the flag rather than to the peer falling over during startup — without it a
peer that crashed on boot would pass the headline row.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile

import pytest

# The peer stops itself this long after it begins serving. Kept small because
# the row's cost is wall-clock in the fast suite; large enough that the
# control below can distinguish "stopped by the flag" from "never came up".
LIFETIME_S = 1.0
# How long the control waits before asserting the unbounded peer is STILL up.
CONTROL_WAIT_S = LIFETIME_S + 1.5


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_for_port(host: str, port: int, *, timeout: float = 8.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        try:
            _, w = await asyncio.open_connection(host, port)
            w.close()
            await w.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise TimeoutError(f"port {host}:{port} did not open within {timeout}s")


async def _assert_port_released(host: str, port: int) -> None:
    """The socket is gone: nothing accepts, and the port rebinds."""
    with pytest.raises(OSError):
        _, w = await asyncio.open_connection(host, port)
        w.close()
        await w.wait_closed()

    # And it is actually reusable by the next run, which is the thing a
    # colliding harness needs. SO_REUSEADDR because the probe above may
    # leave the server side in TIME_WAIT.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))


async def _spawn_peer(
    tmp: str, port: int, *extra: str, env_overrides: dict[str, str] | None = None
) -> asyncio.subprocess.Process:
    env = os.environ.copy()
    env["HOME"] = tmp
    # Never inherit the host's own bound — each row states its own.
    env.pop("ENTITY_PEER_MAX_LIFETIME", None)
    if env_overrides:
        env.update(env_overrides)

    cmd = [
        sys.executable, "-m", "entity_cli.main",
        "start",
        "--listen", f"127.0.0.1:{port}",
        "-i", "max-lifetime-fixture",
        *extra,
    ]
    return await asyncio.create_subprocess_exec(
        *cmd, env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def _reap(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()


class TestMaxLifetime:
    """The flag, the env default, and the control that makes them attributable."""

    @pytest.mark.asyncio
    async def test_the_flag_stops_the_peer_and_releases_the_port(self):
        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            proc = await _spawn_peer(tmp, port, "--max-lifetime", str(LIFETIME_S))
            try:
                # It really served before it stopped — otherwise the exit
                # below says nothing about the lifetime path.
                await _wait_for_port("127.0.0.1", port)

                rc = await asyncio.wait_for(proc.wait(), timeout=LIFETIME_S + 8.0)
                assert rc == 0, f"expected a clean exit, got {rc}"

                await _assert_port_released("127.0.0.1", port)
            finally:
                await _reap(proc)

    @pytest.mark.asyncio
    async def test_the_teeth_control_without_the_flag_the_peer_keeps_serving(self):
        """Row 1's exit is the flag, not a peer that falls over on boot.

        Without this, a `start` that crashed during startup for an unrelated
        reason would satisfy "the process exited and the port is free" — the
        headline row would report the feature working while measuring a
        different failure entirely.
        """
        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            proc = await _spawn_peer(tmp, port)
            try:
                await _wait_for_port("127.0.0.1", port)
                await asyncio.sleep(CONTROL_WAIT_S)

                assert proc.returncode is None, (
                    "an unbounded peer exited on its own — the headline row's "
                    "exit is then not attributable to --max-lifetime"
                )
                # Still accepting: the port did NOT come back by itself.
                _, w = await asyncio.open_connection("127.0.0.1", port)
                w.close()
                await w.wait_closed()
            finally:
                await _reap(proc)

    @pytest.mark.asyncio
    async def test_the_env_var_bounds_a_peer_whose_command_line_forgot_to(self):
        """$ENTITY_PEER_MAX_LIFETIME is the enforcement point.

        The flag alone binds only the peers whose author remembered it, which
        is exactly the set that was never the problem.
        """
        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            proc = await _spawn_peer(
                tmp, port,
                env_overrides={"ENTITY_PEER_MAX_LIFETIME": str(LIFETIME_S)},
            )
            try:
                await _wait_for_port("127.0.0.1", port)
                rc = await asyncio.wait_for(proc.wait(), timeout=LIFETIME_S + 8.0)
                assert rc == 0, f"expected a clean exit, got {rc}"
                await _assert_port_released("127.0.0.1", port)
            finally:
                await _reap(proc)

    @pytest.mark.asyncio
    async def test_an_explicit_zero_overrides_the_env_var(self):
        """The bound is a default, not a ceiling — a long-lived peer stays sayable.

        The validator's own peers are started without a bound on purpose; an
        env var that could not be overridden would make this repo's release
        gate unrunnable on a box that exports it.
        """
        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            proc = await _spawn_peer(
                tmp, port, "--max-lifetime", "0",
                env_overrides={"ENTITY_PEER_MAX_LIFETIME": str(LIFETIME_S)},
            )
            try:
                await _wait_for_port("127.0.0.1", port)
                await asyncio.sleep(CONTROL_WAIT_S)
                assert proc.returncode is None, (
                    "an explicit --max-lifetime 0 was overridden by the env var"
                )
            finally:
                await _reap(proc)


class TestSigtermIsHonored:
    """SIGTERM stops the peer cleanly — the half that made `podman stop` hang.

    Found 2026-08-22 while reaping two leftover `entity-pm-*` containers: both
    logged *"StopSignal SIGTERM failed to stop container ... resorting to
    SIGKILL"*. The Dockerfile's `ENTRYPOINT ["entity-core"]` makes the peer
    **PID 1**, and the kernel does not apply a signal's default disposition to
    PID 1 — a SIGTERM with no *installed* handler is discarded, not fatal. So
    the peer ignored every supervisor stop request, every `podman stop` paid
    its full timeout and then SIGKILLed, and the lesson everyone drew was that
    reaping a peer means escalating to a kill.

    The assertion is a **clean** exit within a supervisor-plausible window, not
    just death: SIGKILL also produces a dead process and a freed port, so a row
    that only checked liveness would score the un-handled peer green.
    """

    @pytest.mark.asyncio
    async def test_sigterm_shuts_down_cleanly_and_releases_the_port(self):
        import signal as _signal

        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            proc = await _spawn_peer(tmp, port)
            try:
                await _wait_for_port("127.0.0.1", port)

                proc.send_signal(_signal.SIGTERM)
                # Well inside podman's default 10s stop timeout. Before the
                # handler existed this window expired every time.
                rc = await asyncio.wait_for(proc.wait(), timeout=5.0)

                assert rc == 0, (
                    f"SIGTERM should stop the peer cleanly, got exit {rc}. "
                    "A negative code means the signal killed it rather than "
                    "the shutdown path running."
                )
                await _assert_port_released("127.0.0.1", port)
            finally:
                await _reap(proc)

    @pytest.mark.asyncio
    async def test_sigint_still_shuts_down_cleanly(self):
        """Installing a SIGINT handler must not break Ctrl+C.

        The handler replaces the default KeyboardInterrupt delivery, so this
        is the row that catches "we made SIGTERM work and broke the way a
        human has always stopped a peer".
        """
        import signal as _signal

        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            proc = await _spawn_peer(tmp, port)
            try:
                await _wait_for_port("127.0.0.1", port)
                proc.send_signal(_signal.SIGINT)
                rc = await asyncio.wait_for(proc.wait(), timeout=5.0)
                assert rc == 0, f"SIGINT should stop the peer cleanly, got {rc}"
                await _assert_port_released("127.0.0.1", port)
            finally:
                await _reap(proc)


class TestAServerCrashIsLoud:
    """A server that ends by raising exits non-zero, with the traceback.

    Regression row for a flaw in the signal-handling change itself. Racing
    `serve_forever()` inside `asyncio.wait` means an exception no longer
    propagates — `wait` parks it on the task and returns normally, so the
    original draft fell through to `stop()` and exited **0**. A peer that
    crashed under load would have reported an orderly shutdown, and a
    conformance run would show "connection refused" with the cause nowhere.

    Found the same session, by a validator run in which the peer died mid
    sustained-load and left no account of itself.
    """

    @pytest.mark.asyncio
    async def test_a_serve_forever_that_raises_propagates_out_of_cmd_start(
        self, monkeypatch, tmp_path
    ):
        """Drives the real `cmd_start`, not a copy of its race.

        Re-implementing the `asyncio.wait` block in the test would measure the
        test's own copy — the same substitution `AGENTS.md` names as the reason
        3667 tests never noticed the unauthorized in-process dispatch. So this
        patches `Peer.serve_forever` to raise and calls `cmd_start` itself; the
        assertion is about the shipped function's behaviour.
        """
        import importlib

        from entity_core.peer.peer import Peer

        # `entity_cli.__init__` exports a `main` FUNCTION, which shadows the
        # `entity_cli.main` module under `import ... as`.
        cli = importlib.import_module("entity_cli.main")

        class _Boom(RuntimeError):
            pass

        async def _explode(self):
            raise _Boom("server fell over")

        stopped: list[bool] = []
        real_stop = Peer.stop

        async def _tracking_stop(self):
            stopped.append(True)
            await real_stop(self)

        monkeypatch.setattr(Peer, "serve_forever", _explode)
        monkeypatch.setattr(Peer, "stop", _tracking_stop)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("ENTITY_PEER_MAX_LIFETIME", raising=False)

        args = cli.build_parser().parse_args(
            ["start", "--listen", f"127.0.0.1:{_free_port()}", "-i", "crash-fixture"]
        )

        with pytest.raises(_Boom):
            await cli.cmd_start(args)

        assert stopped, "stop() must still run on the crash path"


class TestMalformedEnvFailsLoud:
    """A typo'd bound is refused, never silently demoted to unbounded.

    This is the fail-closed half: `$ENTITY_PEER_MAX_LIFETIME=1O` (letter O) is
    a request for a bound that did not parse. Falling back to "run forever"
    would hand back the unbounded peer the variable exists to prevent, at the
    one moment nobody is looking for it.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", ["abc", "1O", "-5"])
    async def test_it_refuses_to_start(self, bad: str):
        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            proc = await _spawn_peer(
                tmp, port, env_overrides={"ENTITY_PEER_MAX_LIFETIME": bad}
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=20.0
                )
                assert proc.returncode != 0, "a malformed bound started a peer"
                combined = (stdout + stderr).decode("utf-8", "replace")
                assert "ENTITY_PEER_MAX_LIFETIME" in combined, (
                    "the refusal must name the variable — an error that only "
                    f"refuses makes the reader re-derive it. Got: {combined!r}"
                )
            finally:
                await _reap(proc)
