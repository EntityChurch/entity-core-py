"""End-to-end smoke: `entity-core start --http-addr ...` boots an HTTP-live peer.

Spawns the CLI as a subprocess with the new Chunk D flags, waits for the
HTTP listener to bind, then drives a real connect handshake + system/status
round-trip against it from `HttpConnection`. Mirrors what validate-peer
will do across impls.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.http_client import HttpConnection


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _wait_for_port(host: str, port: int, *, timeout: float = 5.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            r, w = await asyncio.open_connection(host, port)
            w.close()
            await w.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise TimeoutError(f"port {host}:{port} did not open within {timeout}s")


def _write_identity(tmpdir: str, name: str) -> Keypair:
    """Materialize an identity at ~/.entity/identities/{name}{,.json} per
    the `load_identity` reader's expected layout (PEM-like private key
    + JSON metadata)."""
    import base64
    import json

    from cryptography.hazmat.primitives import serialization

    kp = Keypair.generate()
    base = os.path.join(tmpdir, ".entity", "identities")
    os.makedirs(base, exist_ok=True)

    private_bytes = kp.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = kp.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # PEM-like format the loader parses: 3 lines (header, payload, footer).
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        + base64.b64encode(private_bytes).decode("ascii")
        + "\n-----END PRIVATE KEY-----\n"
    )
    with open(os.path.join(base, name), "w") as f:
        f.write(pem)
    with open(os.path.join(base, f"{name}.json"), "w") as f:
        json.dump(
            {
                "peer_id": kp.peer_id,
                "public_key": base64.b64encode(public_bytes).decode("ascii"),
            },
            f,
        )
    return kp


@pytest.mark.asyncio
async def test_cli_http_addr_boots_listener_and_serves_status():
    """End-to-end: spawn CLI with --http-addr, dial via HttpConnection."""

    tcp_port = _free_port()
    http_port = _free_port()

    with tempfile.TemporaryDirectory() as tmp:
        _write_identity(tmp, "default")
        _write_identity(tmp, "admin")

        env = os.environ.copy()
        env["HOME"] = tmp

        cmd = [
            sys.executable, "-m", "entity_cli.main",
            "start",
            "--listen", f"127.0.0.1:{tcp_port}",
            "--http-addr", f"127.0.0.1:{http_port}",
            "--http-path", "/entity",
            "--open-access",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await _wait_for_port("127.0.0.1", http_port, timeout=8.0)

            client_kp = Keypair.generate()
            # Read the server peer's identity off the TCP handshake — the
            # CLI prints the peer id at start. Simpler: do an HTTP connect
            # without expected_peer_id and just confirm a 200 round-trip.
            conn = await HttpConnection.connect(
                f"http://127.0.0.1:{http_port}/entity",
                client_kp,
            )
            try:
                resp = await conn.execute(
                    "system/status", "get", params={"data": {}},
                )
                assert resp.status == 200, f"status={resp.status} result={resp.result}"
                data = resp.result.get("data", {}) if isinstance(resp.result, dict) else {}
                assert data.get("status") == "ok"
            finally:
                await conn.close()
        finally:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
