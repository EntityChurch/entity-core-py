#!/usr/bin/env python3
"""Cross-impl publish→fetch consumer driver (Python side).

Drives Python's ``HttpPollClient`` against the cohort's deterministic
publish-fixture (Go's ``cmd/publish-fixture`` or any byte-compatible origin)
and asserts the pinned contract from the cross-impl publish-fetch fixture
handoff.

This converts Thread B's per-impl self-PASS ("each impl is internally
consistent") into an actual cross-impl wire drive ("Go publishes, Python
consumes, byte-equality holds"). It is the headline-demo interop proof, not a
v1 gate (arch ruled self-PASS sufficient).

Usage::

    # Terminal 1 — Go publisher
    go build -o /tmp/publish-fixture ./cmd/publish-fixture
    /tmp/publish-fixture -addr 127.0.0.1:9301

    # Terminal 2 — Python consumer
    uv run python scripts/fetch_published_fixture.py --url http://127.0.0.1:9301

Exits 0 on PASS, non-zero with a diagnostic on the first failed vector.

Hash representation note: the fixture's pinned ``content_hash`` values are the
bare 32-byte ECFv1-SHA256 *digest* (Go's ``ecf-sha256:<hex>`` notation). Python
carries the full 33-byte wire hash (1-byte format code ``0x00`` ‖ digest). We
strip the leading format byte before comparing — same single source of truth,
two surface widths (cohort "`{hash}` is the 66-hex wire form, slice if needed").
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass

# Allow running both as a script (`python scripts/...`) and imported by tests.
try:
    from entity_core.peer.http_poll_client import HttpPollClient, HttpPollError
except ModuleNotFoundError:  # pragma: no cover - dev convenience
    import os

    sys.path.insert(
        0,
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "packages",
            "entity-core",
            "src",
        ),
    )
    from entity_core.peer.http_poll_client import HttpPollClient, HttpPollError


# --- The pinned contract (mirror of the fixture doc §1 table) ----------------
#
# Deterministic across every run/host: same seed → same peer-id, identity,
# signed manifest, leaf hashes, and content bytes. content_hash values are the
# 32-byte digest (no format-code prefix).

PINNED_PEER_ID = "2KHcFAKPfQLw2ug7exu2mYTYAzPSKrWX2CsYY1cBVbBYJt"
PINNED_KEY_TYPE = "ed25519"
PINNED_IDENTITY_HASH = (
    "356a7a81d4eaa197ad2d2a2fb131246a824e50665ea75dce0c1b11ddd0a10e38"
)
PINNED_ROOT_HASH = (
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
)


@dataclass(frozen=True)
class FixtureEntry:
    path: str
    entity_type: str
    content_hash: str  # 32-byte digest hex (no format prefix)
    data: dict[str, str]


PINNED_ENTRIES: list[FixtureEntry] = [
    FixtureEntry(
        "system/blog/post/entry-1",
        "test/blog/post/v1",
        "d20663fce170dc9c2fd970d765b11d1f077fac49a46e18532acc8305ffa7fc6a",
        {"title": "first", "body": "hello"},
    ),
    FixtureEntry(
        "system/blog/post/entry-2",
        "test/blog/post/v1",
        "e1f0e4d46fe870259f207e1427e47890e81d511055bc94babdaa349bb4ce1308",
        {"title": "second", "body": "world"},
    ),
    FixtureEntry(
        "system/blog/post/entry-3",
        "test/blog/post/v1",
        "5e53c3dd00cef1ff28e7063cce622ae8e77a80b2c9077010016b5e86479aa756",
        {"title": "third", "body": "fin"},
    ),
]


class DriveFailure(Exception):
    """A consumer-drive vector failed."""


def _digest_hex(wire_hash: bytes) -> str:
    """Strip the 1-byte ECF format code, return the 32-byte digest hex.

    Python carries the full 33-byte wire hash (``0x00`` ‖ SHA-256 digest);
    the fixture pins the bare digest. ``0x00`` = ECFv1-SHA256.
    """
    if len(wire_hash) == 33 and wire_hash[0] == 0x00:
        return wire_hash[1:].hex()
    # Already a bare digest, or a non-default format we still compare raw.
    return wire_hash.hex()


async def drive(url: str) -> list[str]:
    """Run the full publish→fetch consumer drive against ``url``.

    Returns a list of PASS lines (one per vector group). Raises
    ``DriveFailure`` on the first failed assertion.
    """
    client = HttpPollClient(url)
    passes: list[str] = []

    # v1+v2 — MANIFEST_GET → verify signature against the publisher's
    # peer-id-derived pubkey, and confirm the verified root is the one pinned.
    # Python's verify path is mandatory (no unverified fetch), so a returned
    # root is, by construction, a signature-verified root.
    pr, root_hash = await client.fetch_verified_root()
    if pr.type != "system/peer/published-root":
        raise DriveFailure(f"v1: manifest type {pr.type!r} != system/peer/published-root")
    if pr.data.get("peer_id") != PINNED_PEER_ID:
        raise DriveFailure(
            f"v2: verified peer_id {pr.data.get('peer_id')!r} != pinned {PINNED_PEER_ID!r}"
        )
    if _digest_hex(root_hash) != PINNED_ROOT_HASH:
        raise DriveFailure(
            f"v2: verified root_hash {_digest_hex(root_hash)} != pinned {PINNED_ROOT_HASH}"
        )
    passes.append(
        f"PASS  v1+v2: manifest served + signature verified (peer={PINNED_PEER_ID[:12]}…)"
    )

    # v3+v4 — for each path: TREE_GET pointer == pinned content_hash, then
    # CONTENT_GET (the client re-hashes the body and fails closed on mismatch).
    for entry in PINNED_ENTRIES:
        ptr = await client.tree_pointer(PINNED_PEER_ID, entry.path)
        if _digest_hex(ptr) != entry.content_hash:
            raise DriveFailure(
                f"v3 {entry.path}: pointer {_digest_hex(ptr)} != pinned {entry.content_hash}"
            )
        try:
            # content_get enforces 0x00‖SHA-256(body)==ptr before decoding and
            # raises on mismatch — a successful return IS the v4 re-hash proof
            # against Go's served bytes. The verified hash is `ptr` (content
            # addressing: the wire entity carries no content_hash field).
            ent = await client.content_get(ptr)
        except HttpPollError as exc:
            raise DriveFailure(f"v4 {entry.path}: content_get failed: {exc.code} {exc.message}")
        if ent.type != entry.entity_type:
            raise DriveFailure(
                f"v4 {entry.path}: type {ent.type!r} != pinned {entry.entity_type!r}"
            )
        # v5 — byte-equality of the data: ECF determinism means Python's
        # decoded dict equals the authored contract values exactly.
        if dict(ent.data) != entry.data:
            raise DriveFailure(
                f"v5 {entry.path}: data {dict(ent.data)!r} != pinned {entry.data!r}"
            )
    passes.append(
        f"PASS  v3+v4: resolved {len(PINNED_ENTRIES)} tree-leaf pointers + fetched + hash-verified"
    )
    passes.append(
        f"PASS  v5: byte-equality holds across {len(PINNED_ENTRIES)} entities"
    )
    return passes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True, help="publish-fixture origin URL")
    args = ap.parse_args()

    try:
        passes = asyncio.run(drive(args.url))
    except DriveFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - surface unexpected wire errors
        print(f"FAIL  unexpected: {exc!r}", file=sys.stderr)
        return 2

    for line in passes:
        print(line)
    print("ALL PASS (Go-publish → Python-consume, byte-equality verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
