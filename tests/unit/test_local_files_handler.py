"""Tests for DOMAIN-LOCAL-FILES v1.2 handler.

Covers the five §10.5 cross-impl gates + spec MUSTs:

1. **Type registration.** All eight ``local/files/*`` types installed
   at ``system/type/local/files/*`` after extension init (v1.2 §11).
2. **Handler manifest.** The four ``internal_scope`` grants are
   present and the five operations are declared (v1.2 §3.1).
3. **Read round-trip + inline-include boundary.**
   * `total_size ≤ MIN_CHUNK_SIZE` (64 KiB) → blob + all chunks in
     ``included``.
   * `total_size == MIN_CHUNK_SIZE + 1` → blob in ``included``;
     chunks NOT inlined.
   * Read of a non-existent path → 404 ``file_not_found``.
4. **Write round-trip.**
   * Bytes-mode write writes to disk + tree, sets ``written=true``,
     and round-trips through read.
   * Content-mode (dedup) write preserves the input blob hash.
   * Two-mode invariant: both / neither → 400 ``invalid_params``.
   * Write under a read-only root → 403 ``read_only_root``.
5. **Cross-handler blob-hash convergence (§10.5 gate 1).** A blob built
   via the shared content substrate matches what ``local/files:read``
   produces for the same bytes.
6. **Content-mode dedup preserves blob hash (§10.5 gate 5).**
7. **Path traversal rejection (§8.3).** ``..`` escapes → 403.
8. **Delete confirmation.**
9. **List + glob filters (include/exclude).**
10. **Edit-stability sanity spot check.** A 1-byte mid-file edit on a
    6 MiB body retains ≥75% chunk reuse (§10.5 gate 3 — covered by the
    cross-impl substrate test but spot-checked here so a Python-side
    regression surfaces locally).
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree

from entity_handlers import LOCAL_FILES_HANDLER_MANIFEST, LocalFilesExtension
from entity_handlers.content.chunking import (
    DEFAULT_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    build_fastcdc,
)
from entity_handlers.local_files import (
    LOCAL_FILES_HANDLER_PATTERN,
    LOCAL_FILES_TYPE_DEFS,
    TYPE_DELETED,
    TYPE_DIRECTORY,
    TYPE_FILE,
)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@dataclass
class _Env:
    keypair: Keypair
    pathway: EmitPathway
    extension: LocalFilesExtension
    handler_fn: object  # callable
    fs_root: str
    prefix: str


def _make_env(tmp_path: Path, *, prefix: str = "local/files/shared/") -> _Env:
    kp = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(kp.peer_id)
    pathway = EmitPathway(content_store, entity_tree)

    ext = LocalFilesExtension()
    ext_ctx = ExtensionContext(keypair=kp, emit_pathway=pathway)
    ext.initialize(ext_ctx)

    fs_root = str(tmp_path / "fs-root")
    os.makedirs(fs_root, exist_ok=True)
    ext.add_root(
        "shared",
        prefix=prefix,
        filesystem_root=fs_root,
    )
    return _Env(
        keypair=kp,
        pathway=pathway,
        extension=ext,
        handler_fn=ext.handler(),
        fs_root=fs_root,
        prefix=prefix,
    )


def _ctx(env: _Env, *, resource_targets: list[str] | None = None) -> HandlerContext:
    return HandlerContext(
        local_peer_id=env.keypair.peer_id,
        remote_peer_id=env.keypair.peer_id,
        handler_grant={},
        caller_capability={},
        emit_pathway=env.pathway,
        handler_pattern=LOCAL_FILES_HANDLER_PATTERN,
        resource_targets=resource_targets,
        keypair=env.keypair,
    )


def _run(coro):
    return asyncio.run(coro)


async def _exec(env: _Env, operation: str, *, target: str, params: dict | None = None) -> dict:
    ctx = _ctx(env, resource_targets=[target])
    params_payload = params if params is not None else {}
    return await env.handler_fn(target, operation, params_payload, ctx)


# -----------------------------------------------------------------------------
# 1. Type + manifest registration
# -----------------------------------------------------------------------------


def test_types_registered_in_tree(tmp_path):
    env = _make_env(tmp_path)
    tree = env.pathway.entity_tree
    for type_def in LOCAL_FILES_TYPE_DEFS:
        path = f"system/type/{type_def['name']}"
        h = tree.get(tree.normalize_uri(path))
        assert h is not None, f"type entity missing at {path}"
        entity = env.pathway.content_store.get(h)
        assert entity is not None
        assert entity.type == "system/type"
        assert entity.data["name"] == type_def["name"]


def test_handler_manifest_declares_four_operations_and_four_grants():
    """v1.3 L2: `watch` MUST be omitted from the manifest until the
    platform-native watcher is implemented; this impl exposes the four
    operations (`read`/`write`/`list`/`delete`) only.
    """
    data = LOCAL_FILES_HANDLER_MANIFEST.data
    assert data["pattern"] == "local/files"
    assert data["name"] == "local-files"
    for op in ("read", "write", "list", "delete"):
        assert op in data["operations"], f"manifest missing op {op}"
    assert "watch" not in data["operations"]
    assert data["operations"]["read"]["output_type"] == TYPE_FILE
    assert data["operations"]["write"]["input_type"] == "local/files/write-request"
    grants = data["internal_scope"]
    assert len(grants) == 4
    # Each grant declares its handlers/resources/operations triple
    handlers_seen = {g["handlers"]["include"][0] for g in grants}
    assert {"system/tree", "system/subscription", "system/content"} <= handlers_seen
    # The content-descriptor publish grant lives on system/tree
    descriptor_grants = [
        g
        for g in grants
        if g["resources"]["include"] == ["system/content/descriptor/*"]
    ]
    assert len(descriptor_grants) == 1
    assert descriptor_grants[0]["operations"]["include"] == ["put"]


# -----------------------------------------------------------------------------
# 2. Read — small file fits inline; above the boundary chunks excluded
# -----------------------------------------------------------------------------


def test_read_small_file_inlines_blob_and_chunks(tmp_path):
    env = _make_env(tmp_path)
    body = b"hello, validation\n"
    (Path(env.fs_root) / "readme.txt").write_bytes(body)

    resp = _run(_exec(env, "read", target=f"{env.prefix}readme.txt"))
    assert resp["status"] == 200
    # v1.2 §4.1 / cross-impl wire shape: result is the file entity
    # directly; bundle entities ride the outer wire envelope's
    # `included`, drained by peer.py from `envelope_included`.
    assert resp["result"]["type"] == TYPE_FILE
    root = resp["result"]
    assert root["data"]["size"] == len(body)
    blob_hash = root["data"]["content"]
    assert isinstance(blob_hash, (bytes, bytearray)) and len(blob_hash) > 0

    included = resp["envelope_included"]
    assert blob_hash in included, "blob entity MUST appear in included (CONTENT §5.2)"
    blob_dict = included[blob_hash]
    assert blob_dict["type"] == "system/content/blob"
    # Small file ⇒ all chunks inlined (CONTENT §4.3 + v1.2 §10.1 MUST)
    chunk_hashes = blob_dict["data"]["chunks"]
    assert chunk_hashes, "small blob should still have at least one chunk"
    for ch in chunk_hashes:
        assert ch in included, "small-file read MUST inline chunks (§10.1)"


def test_read_above_inline_threshold_excludes_chunks(tmp_path):
    env = _make_env(tmp_path)
    body = b"X" * (MIN_CHUNK_SIZE + 1)
    (Path(env.fs_root) / "big.bin").write_bytes(body)

    resp = _run(_exec(env, "read", target=f"{env.prefix}big.bin"))
    assert resp["status"] == 200
    blob_hash = resp["result"]["data"]["content"]
    included = resp["envelope_included"]
    assert blob_hash in included, "blob entity MUST still ride above threshold"
    blob_dict = included[blob_hash]
    # Above the boundary chunks MUST NOT be auto-included
    for ch in blob_dict["data"]["chunks"]:
        assert ch not in included, "chunks MUST be excluded above MIN_CHUNK_SIZE"


def test_inline_boundary_at_exactly_64_kib(tmp_path):
    env = _make_env(tmp_path)
    body = b"A" * MIN_CHUNK_SIZE
    (Path(env.fs_root) / "exact.bin").write_bytes(body)

    resp = _run(_exec(env, "read", target=f"{env.prefix}exact.bin"))
    blob_hash = resp["result"]["data"]["content"]
    included = resp["envelope_included"]
    blob = included[blob_hash]
    # At-the-boundary == MIN_CHUNK_SIZE inclusive → chunks inlined
    for ch in blob["data"]["chunks"]:
        assert ch in included, "at boundary (= MIN_CHUNK_SIZE) chunks MUST inline"


def test_read_missing_file_returns_404(tmp_path):
    env = _make_env(tmp_path)
    resp = _run(_exec(env, "read", target=f"{env.prefix}does-not-exist.txt"))
    assert resp["status"] == 404
    assert resp["result"]["data"]["code"] == "file_not_found"


def test_read_no_root_mapping_returns_404(tmp_path):
    env = _make_env(tmp_path)
    resp = _run(_exec(env, "read", target="local/files/unknown/x"))
    assert resp["status"] == 404
    assert resp["result"]["data"]["code"] == "no_root_mapping"


# -----------------------------------------------------------------------------
# 3. Write — bytes / content modes; two-mode invariant; written flag
# -----------------------------------------------------------------------------


def test_write_bytes_mode_round_trip(tmp_path):
    env = _make_env(tmp_path)
    body = b"a quick note\n"
    target = f"{env.prefix}note.txt"

    resp = _run(_exec(env, "write", target=target, params={"bytes": body}))
    assert resp["status"] == 200
    root = resp["result"]
    assert root["type"] == TYPE_FILE
    assert root["data"]["written"] is True
    blob_hash = root["data"]["content"]
    # On-disk bytes match
    assert (Path(env.fs_root) / "note.txt").read_bytes() == body

    # Read-back preserves the blob hash
    read_resp = _run(_exec(env, "read", target=target))
    read_blob = read_resp["result"]["data"]["content"]
    assert read_blob == blob_hash, "write → read round-trip preserves blob hash"


def test_write_content_mode_preserves_blob_hash(tmp_path):
    """§10.5 gate 5: write with content: <blob_hash> dedups without re-chunking."""
    env = _make_env(tmp_path)
    body = b"dedupe me\n"
    # Land the blob via a bytes-mode write
    first = _run(_exec(env, "write", target=f"{env.prefix}a.txt", params={"bytes": body}))
    blob_hash = first["result"]["data"]["content"]

    # Now write to a second path by content reference — no re-transmit.
    dedup = _run(
        _exec(env, "write", target=f"{env.prefix}b.txt", params={"content": blob_hash})
    )
    assert dedup["status"] == 200
    assert dedup["result"]["data"]["content"] == blob_hash
    # Disk side matches too
    assert (Path(env.fs_root) / "b.txt").read_bytes() == body


def test_write_both_modes_set_returns_400(tmp_path):
    env = _make_env(tmp_path)
    body = b"a"
    bogus_hash = b"\x00" + b"\x11" * 32
    resp = _run(
        _exec(
            env,
            "write",
            target=f"{env.prefix}x.txt",
            params={"bytes": body, "content": bogus_hash},
        )
    )
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "invalid_params"


def test_write_oversized_bytes_mode_returns_graceful_400(tmp_path):
    """V1 behavioral gate (v1.3 §10.5): a 20 MiB bytes-mode payload
    returns ``400 invalid_params`` — never a crash, panic, or hung
    connection. The protocol-level path for >16 MiB files is
    content-mode (the SDK wrapper routes between modes per §3.2 L1).
    """
    env = _make_env(tmp_path)
    oversized = b"X" * (20 * 1024 * 1024)
    resp = _run(
        _exec(
            env,
            "write",
            target=f"{env.prefix}huge.bin",
            params={"bytes": oversized},
        )
    )
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "invalid_params"
    assert "frame ceiling" in resp["result"]["data"]["message"]


def test_write_neither_mode_set_returns_400(tmp_path):
    env = _make_env(tmp_path)
    resp = _run(_exec(env, "write", target=f"{env.prefix}x.txt", params={}))
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "invalid_params"


def test_write_content_mode_missing_blob_returns_404(tmp_path):
    env = _make_env(tmp_path)
    bogus = b"\x00" + b"\xFE" * 32
    resp = _run(
        _exec(env, "write", target=f"{env.prefix}x.txt", params={"content": bogus})
    )
    assert resp["status"] == 404
    assert resp["result"]["data"]["code"] == "content_not_found"


def test_write_inline_include_above_boundary(tmp_path):
    """v1.2 §10.1 write-side MUST: chunks NOT inlined above MIN_CHUNK_SIZE."""
    env = _make_env(tmp_path)
    body = b"X" * (MIN_CHUNK_SIZE + 1)
    resp = _run(
        _exec(env, "write", target=f"{env.prefix}big.bin", params={"bytes": body})
    )
    blob_hash = resp["result"]["data"]["content"]
    included = resp["envelope_included"]
    assert blob_hash in included
    blob = included[blob_hash]
    for ch in blob["data"]["chunks"]:
        assert ch not in included, "write-side §10.1: no chunks above 64 KiB"


def test_write_inline_include_at_boundary(tmp_path):
    """v1.2 §10.1 write-side MUST: chunks INLINED at MIN_CHUNK_SIZE."""
    env = _make_env(tmp_path)
    body = b"W" * MIN_CHUNK_SIZE
    resp = _run(
        _exec(env, "write", target=f"{env.prefix}small.bin", params={"bytes": body})
    )
    blob_hash = resp["result"]["data"]["content"]
    included = resp["envelope_included"]
    blob = included[blob_hash]
    for ch in blob["data"]["chunks"]:
        assert ch in included, "write-side §10.1: chunks inlined at boundary"


def test_write_read_only_root_returns_403(tmp_path):
    env = _make_env(tmp_path)
    env.extension.roots["shared"].read_only = True
    resp = _run(
        _exec(env, "write", target=f"{env.prefix}x.txt", params={"bytes": b"x"})
    )
    assert resp["status"] == 403
    assert resp["result"]["data"]["code"] == "read_only_root"


def test_create_dirs_creates_parent(tmp_path):
    env = _make_env(tmp_path)
    target = f"{env.prefix}subdir/nested.txt"
    resp = _run(
        _exec(
            env,
            "write",
            target=target,
            params={"bytes": b"nested\n", "create_dirs": True},
        )
    )
    assert resp["status"] == 200
    assert (Path(env.fs_root) / "subdir" / "nested.txt").read_bytes() == b"nested\n"


# -----------------------------------------------------------------------------
# 4. Cross-handler blob-hash convergence (§10.5 gate 1)
# -----------------------------------------------------------------------------


def test_cross_handler_blob_hash_convergence(tmp_path):
    """Same bytes through the CONTENT substrate and through local/files:read
    must produce byte-identical blob hashes — the v1.2 load-bearing property.
    """
    env = _make_env(tmp_path)
    body = b"the same bytes go through both paths"
    (Path(env.fs_root) / "same.txt").write_bytes(body)

    expected = build_fastcdc(body, DEFAULT_CHUNK_SIZE).blob_hash
    resp = _run(_exec(env, "read", target=f"{env.prefix}same.txt"))
    actual = resp["result"]["data"]["content"]
    assert actual == expected, "cross-handler blob-hash convergence (§10.5 gate 1)"


# -----------------------------------------------------------------------------
# 5. Path traversal (§8.3)
# -----------------------------------------------------------------------------


def test_atomic_write_runs_directory_fsync(tmp_path):
    """F-3 spot check: ``atomic_write_file`` runs the full
    fsync(file)+rename+fsync(dir) recipe. We can't fault-inject a
    power loss in unit tests, but we can spy on the os.fsync call
    pattern and verify both the file-fd and the dir-fd are sync'd.
    """
    import unittest.mock as _mock

    from entity_handlers.local_files.operations import atomic_write_file

    target = str(tmp_path / "durable.bin")
    fsync_targets: list[int] = []
    real_fsync = os.fsync

    def _spy_fsync(fd: int) -> None:
        fsync_targets.append(fd)
        real_fsync(fd)

    with _mock.patch.object(os, "fsync", side_effect=_spy_fsync):
        atomic_write_file(target, b"durable\n")
    # Two fsyncs: one for the file-fd, one for the dir-fd. The actual
    # fd values aren't comparable across runs; the count is the
    # contract we're enforcing.
    assert len(fsync_targets) == 2, (
        f"atomic_write_file MUST fsync both the file and the parent "
        f"directory (PostgreSQL durable_rename pattern); got "
        f"{len(fsync_targets)} fsync calls"
    )
    assert Path(target).read_bytes() == b"durable\n"


def test_read_normalizes_nfc(tmp_path):
    """v1.3 §10.2 L8: filenames are NFC-normalized at the FS boundary.

    The literal "café" written in NFD form (e + COMBINING ACUTE) is
    stored on Linux ext4 as the NFD bytes. The handler reads the file,
    NFC-normalizes the path component, and binds the file entity with
    the NFC form ("café" as single composed character). This matches
    APFS/NTFS VFS-layer behavior and converges with cross-platform
    peers per UAX #15.
    """
    env = _make_env(tmp_path)
    nfc = "café"  # é U+00E9
    nfd = "café"  # e + COMBINING ACUTE ACCENT U+0301
    # Write the file with the NFD form to disk
    (Path(env.fs_root) / nfd).write_bytes(b"hello\n")
    # Read using the NFC form in the tree path — handler should find
    # the file (since APFS-style normalization-insensitive lookup
    # isn't available on ext4, we just exercise the read path with
    # the on-disk NFD name).
    resp = _run(_exec(env, "read", target=f"{env.prefix}{nfd}"))
    assert resp["status"] == 200, resp
    # The entity's path field MUST be NFC-normalized regardless of
    # what was on disk.
    returned_path = resp["result"]["data"]["path"]
    assert returned_path == nfc, (
        f"L8 SHOULD: relative_path must be NFC-normalized; got {returned_path!r}, "
        f"expected {nfc!r}"
    )


def test_read_rejects_non_utf8_filename(tmp_path):
    """v1.3 §10.2 L8: non-UTF-8 filenames (Linux surrogate-escape)
    SHOULD be rejected with ``invalid_filename`` — ECF wire encoding
    can't carry surrogate-escape strings.
    """
    env = _make_env(tmp_path)
    # Construct a filename with invalid UTF-8 bytes via the bytes API
    bad_name_bytes = b"bad\xff\xfename.bin"
    bad_path = os.path.join(env.fs_root.encode(), bad_name_bytes)
    with open(bad_path, "wb") as fp:
        fp.write(b"x")
    # The tree-path-side representation of that filename uses
    # surrogate-escape decoding (the default on POSIX); we pass it
    # through to the handler, which MUST reject before binding into
    # the tree.
    surrogate_name = bad_name_bytes.decode("utf-8", "surrogateescape")
    resp = _run(_exec(env, "read", target=f"{env.prefix}{surrogate_name}"))
    assert resp["status"] == 400
    assert resp["result"]["data"]["code"] == "invalid_filename"


def test_read_rejects_leaf_symlink(tmp_path):
    """F-4 defense: a leaf symlink at the read target raises ELOOP via
    ``O_NOFOLLOW`` and surfaces as ``path_traversal_rejected``.

    The pre-fix code resolved the parent dir via ``realpath`` then
    joined the basename — a symlink at the leaf would be followed by
    the subsequent ``open(fs_path, "rb")``, escaping the root. The
    ``_open_read_nofollow`` fix passes ``O_NOFOLLOW`` so the OS
    rejects the open with errno 40 before we read a byte.
    """
    env = _make_env(tmp_path)
    # Land an "outside" file the symlink would point to
    outside = tmp_path / "outside.secret"
    outside.write_bytes(b"sensitive\n")
    # Create a symlink at the leaf inside the mapped root
    inside_link = Path(env.fs_root) / "trapdoor.txt"
    os.symlink(outside, inside_link)

    resp = _run(_exec(env, "read", target=f"{env.prefix}trapdoor.txt"))
    assert resp["status"] == 403
    assert resp["result"]["data"]["code"] == "path_traversal_rejected"


def test_read_path_traversal_rejected(tmp_path):
    env = _make_env(tmp_path)
    # ../ escape: the canonical resolution lands outside the root,
    # which the spec §8.3 path-security check must reject.
    resp = _run(
        _exec(env, "read", target=f"{env.prefix}../escape.txt")
    )
    assert resp["status"] == 403
    assert resp["result"]["data"]["code"] == "path_traversal_rejected"


# -----------------------------------------------------------------------------
# 6. List + glob filters
# -----------------------------------------------------------------------------


def test_list_returns_directory_with_children(tmp_path):
    env = _make_env(tmp_path)
    (Path(env.fs_root) / "a.md").write_bytes(b"a")
    (Path(env.fs_root) / "b.md").write_bytes(b"b")
    (Path(env.fs_root) / "skip.tmp").write_bytes(b"x")
    os.makedirs(Path(env.fs_root) / "sub")

    resp = _run(_exec(env, "list", target=env.prefix))
    assert resp["status"] == 200
    assert resp["result"]["type"] == TYPE_DIRECTORY
    names = {c["name"] for c in resp["result"]["data"]["children"]}
    assert {"a.md", "b.md", "skip.tmp", "sub"} == names


def test_list_applies_exclude_glob(tmp_path):
    env = _make_env(tmp_path)
    env.extension.roots["shared"].exclude = ["*.tmp"]
    (Path(env.fs_root) / "a.txt").write_bytes(b"a")
    (Path(env.fs_root) / "junk.tmp").write_bytes(b"x")

    resp = _run(_exec(env, "list", target=env.prefix))
    names = {c["name"] for c in resp["result"]["data"]["children"]}
    assert names == {"a.txt"}, "*.tmp must be excluded by glob filter"


def test_list_include_is_files_only(tmp_path):
    """The include filter applies to files only — directories descend regardless.

    Per Amendment 1 / §2.5 admission rule: an include of ``*.md`` must
    still show subdirectories so the user can navigate into them.
    """
    env = _make_env(tmp_path)
    env.extension.roots["shared"].include = ["*.md"]
    (Path(env.fs_root) / "readme.md").write_bytes(b"#")
    (Path(env.fs_root) / "skip.txt").write_bytes(b"x")
    os.makedirs(Path(env.fs_root) / "docs")

    resp = _run(_exec(env, "list", target=env.prefix))
    names = {c["name"] for c in resp["result"]["data"]["children"]}
    # Subdirectory included; .txt excluded by positive filter
    assert names == {"readme.md", "docs"}


# -----------------------------------------------------------------------------
# 7. Delete
# -----------------------------------------------------------------------------


def test_delete_round_trip(tmp_path):
    env = _make_env(tmp_path)
    target = f"{env.prefix}gone.txt"
    _run(_exec(env, "write", target=target, params={"bytes": b"bye\n"}))

    resp = _run(_exec(env, "delete", target=target))
    assert resp["status"] == 200
    assert resp["result"]["type"] == TYPE_DELETED
    assert resp["result"]["data"]["existed"] is True
    assert not (Path(env.fs_root) / "gone.txt").exists()


def test_delete_missing_file_reports_not_existed(tmp_path):
    env = _make_env(tmp_path)
    resp = _run(_exec(env, "delete", target=f"{env.prefix}ghost.txt"))
    assert resp["status"] == 200
    assert resp["result"]["data"]["existed"] is False


# -----------------------------------------------------------------------------
# 8. Edit-stability spot check (§10.5 gate 3, conservative 75% floor)
# -----------------------------------------------------------------------------


def test_edit_stability_retains_most_chunks(tmp_path):
    env = _make_env(tmp_path)
    body = bytearray(6 * 1024 * 1024)
    for i in range(len(body)):
        body[i] = i % 251
    base_target = f"{env.prefix}edit-base.bin"
    edit_target = f"{env.prefix}edit-after.bin"

    _run(_exec(env, "write", target=base_target, params={"bytes": bytes(body)}))
    edited = bytearray(body)
    edited[len(edited) // 2] ^= 0xFF
    _run(
        _exec(env, "write", target=edit_target, params={"bytes": bytes(edited)})
    )

    # Compare blob chunk lists by re-running the substrate.
    base_chunks = build_fastcdc(bytes(body), DEFAULT_CHUNK_SIZE).blob.data["chunks"]
    edit_chunks = build_fastcdc(bytes(edited), DEFAULT_CHUNK_SIZE).blob.data["chunks"]
    base_set = {bytes(c) for c in base_chunks}
    reused = sum(1 for c in edit_chunks if bytes(c) in base_set)
    min_reuse = (len(edit_chunks) * 3) // 4
    assert reused >= min_reuse, (
        f"edit stability: reused {reused}/{len(edit_chunks)} chunks "
        f"(< {min_reuse} required by §10.5 gate 3)"
    )


# -----------------------------------------------------------------------------
# 9. Watch — config persistence (platform watcher is SHOULD, deferred)
# -----------------------------------------------------------------------------


def test_watch_returns_unknown_operation_when_not_implemented(tmp_path):
    """Per v1.3 §10.1 L2 MUST: a handler that exposes `watch` in its
    manifest MUST monitor the filesystem; a handler that doesn't
    implement the watcher MUST omit `watch` from the manifest and
    return ``unknown_operation`` to callers.

    Our impl is in the "omit + reject" state until the platform-native
    watcher (inotify/FSEvents/ReadDirectoryChangesW) lands. The
    deliberate visible signal here is the V2 behavioral gate's
    skip-with-WARN path.
    """
    env = _make_env(tmp_path)
    resp = _run(
        _exec(
            env,
            "watch",
            target="local/files",
            params={"root_name": "shared", "action": "start"},
        )
    )
    assert resp["status"] == 501
    assert resp["result"]["data"]["code"] == "unknown_operation"


def test_watch_not_in_manifest(tmp_path):
    """Manifest MUST NOT advertise watch while the watcher isn't wired
    (v1.3 L2). The manifest is the authoritative discovery surface;
    remote peers branch on it to decide whether to invoke the op.
    """
    from entity_handlers import LOCAL_FILES_HANDLER_MANIFEST
    ops = LOCAL_FILES_HANDLER_MANIFEST.data["operations"]
    assert "watch" not in ops, (
        "v1.3 §10.1 L2: watch MUST be omitted from the manifest until "
        "the platform-native watcher is implemented"
    )


# -----------------------------------------------------------------------------
# 10. Reverse-write — tree put under a root projects to disk
# -----------------------------------------------------------------------------


def test_reverse_write_uses_incoming_chunk_size_for_circuit_breaker(tmp_path):
    """Amendment 3 §5.5 normative MUST: the circuit-breaker recompute
    MUST use the incoming blob's ``chunk_size`` field, not the
    consumer's local DEFAULT_CHUNK_SIZE.

    Scenario (the cross-impl bug Rust surfaced): peer A
    chunks a file at 4 MiB; peer B receives the file entity + blob +
    chunks via sync. Peer B already has the bytes on disk (from a
    prior write at the same chunk_size). The circuit breaker MUST
    rechunk peer B's on-disk file at the *incoming* chunk_size (4
    MiB) — not at peer B's local DEFAULT_CHUNK_SIZE (which under
    CONTENT v3.6 will be 1 MiB). Using the wrong chunk_size produces
    a different blob hash, makes the circuit-breaker say "diverges,"
    and triggers a spurious rewrite + loop.

    We construct the scenario by:
    1. Build a blob via the substrate using a *non-default* chunk
       size (we use 256 KiB so the test is fast yet not the local
       default).
    2. Land the blob + chunks in the content store.
    3. Pre-write the same bytes to disk so the circuit-breaker check
       has a target to compare against.
    4. Emit the file-entity into the tree (simulates remote sync).
    5. Assert the FS file is NOT rewritten (mtime unchanged) — proves
       the circuit-breaker fired AND used incoming_chunk_size.
    """
    async def _drive():
        env = _make_env(tmp_path)
        body = b"chunk-size cross-peer scenario\n" * 5000  # ~150 KiB
        non_default = 256 * 1024  # 256 KiB, far from DEFAULT_CHUNK_SIZE
        assert non_default != DEFAULT_CHUNK_SIZE

        # Build the blob at the non-default size (simulates a remote
        # peer's choice) and land it in the content store
        result = build_fastcdc(body, target_size=non_default)
        store = env.pathway.content_store
        for chunk in result.chunks:
            store.put(chunk)
        store.put(result.blob)

        # Pre-write the same bytes to disk via the FS — bypass the
        # handler so we don't warm the stat-cache; the §5.5 fix is the
        # rechunk path's correctness, not the cache fast-path.
        target_path = Path(env.fs_root) / "shared.bin"
        target_path.write_bytes(body)
        pre_mtime_ns = target_path.stat().st_mtime_ns

        # Build a file entity referencing the blob; emit into the
        # tree. The reverse-write listener fires; the circuit-breaker
        # MUST rechunk at non_default (256 KiB), produce the same
        # hash as result.blob_hash, and skip the rewrite.
        file_entity = Entity(
            type=TYPE_FILE,
            data={
                "path": "shared.bin",
                "size": len(body),
                "content": result.blob_hash,
            },
        )
        from entity_core.storage.emit import EmitContext

        env.pathway.emit(
            f"{env.prefix}shared.bin",
            file_entity,
            EmitContext.bootstrap(),
        )
        # Wait for the async listener to process; reverse-write fires
        # via the loop's executor.
        for _ in range(100):
            await asyncio.sleep(0.01)
        post_mtime_ns = target_path.stat().st_mtime_ns

        assert post_mtime_ns == pre_mtime_ns, (
            "Amendment 3 §5.5 MUST: circuit-breaker MUST use incoming "
            "blob's chunk_size — pre-existing bytes on disk should NOT "
            "be rewritten when content matches. Pre-fix code used "
            "DEFAULT_CHUNK_SIZE → mismatched hash → spurious rewrite."
        )
        # Sanity: on-disk content unchanged
        assert target_path.read_bytes() == body

    _run(_drive())


def test_streaming_reverse_write_above_threshold(tmp_path, monkeypatch):
    """v1.3 §5.3 L4 SHOULD: reverse-write streams reassembly for blob
    sizes ≥ _STREAMING_THRESHOLD.

    We monkeypatch the threshold down so we don't have to allocate
    64 MiB in a unit test, then assert the streaming code path is
    chosen (via a spy on atomic_write_file_stream).
    """
    import unittest.mock as _mock

    from entity_handlers.content.chunking import build_fastcdc
    from entity_handlers.local_files import operations as _ops
    from entity_handlers.local_files import reverse as _reverse_mod

    # Lower threshold so a tiny payload is "large enough" to stream.
    monkeypatch.setattr(_reverse_mod, "_STREAMING_THRESHOLD", 1024)

    async def _drive():
        env = _make_env(tmp_path)
        body = b"big enough\n" * 200  # ~2 KiB > 1 KiB threshold
        from entity_core.storage.emit import EmitContext

        result = build_fastcdc(body, DEFAULT_CHUNK_SIZE)
        store = env.pathway.content_store
        for chunk in result.chunks:
            store.put(chunk)
        store.put(result.blob)

        stream_calls = []
        real_stream_write = _reverse_mod.atomic_write_file_stream

        def _spy(fs_path, blocks):
            stream_calls.append(fs_path)
            return real_stream_write(fs_path, blocks)

        with _mock.patch.object(
            _reverse_mod, "atomic_write_file_stream", side_effect=_spy
        ):
            file_entity = Entity(
                type=TYPE_FILE,
                data={
                    "path": "big.txt",
                    "size": len(body),
                    "content": result.blob_hash,
                },
            )
            env.pathway.emit(
                f"{env.prefix}big.txt", file_entity, EmitContext.bootstrap()
            )
            for _ in range(100):
                await asyncio.sleep(0.01)
                if (Path(env.fs_root) / "big.txt").exists():
                    break

        assert len(stream_calls) == 1, (
            "v1.3 §5.3 L4: blobs ≥ threshold MUST take the streaming path; "
            f"observed {len(stream_calls)} stream-write call(s)"
        )
        assert (Path(env.fs_root) / "big.txt").read_bytes() == body

    _run(_drive())


def test_stat_cache_skips_rechunk_on_match(tmp_path):
    """v1.3 §10.2 L7 fast path: when the stat-cache has a hit for the
    on-disk file and the cached hash equals the incoming blob hash,
    the reverse-write circuit breaker MUST NOT rechunk.

    We instrument ``build_fastcdc`` for the duration of the second
    emit; if the rechunk path is exercised the spy fires. The cache
    is warmed by an initial handler-side read.
    """
    async def _drive():
        env = _make_env(tmp_path)
        body = b"steady state\n"
        target = f"{env.prefix}stable.txt"

        # 1. Write through the handler so the file lands on disk + the
        #    cache is warmed (handle_write stores the cache entry).
        write_resp = await _exec(env, "write", target=target, params={"bytes": body})
        blob_hash = write_resp["result"]["data"]["content"]

        # Give the loop-back reverse-write a chance to fire and skip
        # via the recent-write tracker.
        await asyncio.sleep(0.05)

        # 2. Now simulate a remote sync delivery: emit the SAME file
        #    entity again. The cache says disk already matches; the
        #    rechunk path MUST NOT fire.
        import unittest.mock as _mock
        from entity_core.storage.emit import EmitContext

        from entity_handlers.local_files import reverse as _reverse_mod

        fastcdc_calls: list[int] = []
        real_build = _reverse_mod.build_fastcdc

        def _spy_build(data, target_size):
            fastcdc_calls.append(len(data))
            return real_build(data, target_size)

        with _mock.patch.object(_reverse_mod, "build_fastcdc", side_effect=_spy_build):
            file_entity = Entity(
                type=TYPE_FILE,
                data={
                    "path": "stable.txt",
                    "size": len(body),
                    "content": blob_hash,
                },
            )
            env.pathway.emit(target, file_entity, EmitContext.bootstrap())
            # Yield to let the async listener run
            for _ in range(50):
                await asyncio.sleep(0.01)

        assert fastcdc_calls == [], (
            "L7 stat-cache hit must skip the rechunk; "
            f"observed {len(fastcdc_calls)} rechunk(s) instead"
        )

    _run(_drive())


def test_reverse_write_rejects_path_traversal(tmp_path):
    """v1.3 §8.3 reverse-write coverage MUST: the reverse-write hook
    MUST apply the canonical path-resolution defenses, not bypass
    them via bare path-join. Go's L5 audit (commit ba21372) found Go
    had this bypass; Python is clean (both ``_reverse_write`` and
    ``_reverse_delete`` go through ``resolve_fs_path``). This test
    is the regression gate that confirms it stays clean.

    We construct a file entity with a tree path that escapes the root
    via ``../`` and assert the reverse-write hook rejects it (no disk
    write occurs outside the root).
    """
    async def _drive():
        env = _make_env(tmp_path)
        body = b"shouldn't escape\n"

        # Pre-land the blob
        result = build_fastcdc(body, DEFAULT_CHUNK_SIZE)
        store = env.pathway.content_store
        for chunk in result.chunks:
            store.put(chunk)
        store.put(result.blob)

        # Construct a tree path that, after stripping the prefix,
        # yields a relative_path with ``..`` segments. resolve_fs_path
        # MUST reject this; the reverse-write hook MUST honor that.
        # NOTE: tree-layer V7 §1.4 + CleanPath traversal rejection
        # would normally reject this upstream — we explicitly skip
        # that via direct EmitPathway.emit so the test exercises the
        # *local-files-layer* defense (the spec's "tree-layer
        # dependency" disclaimer warns this can change).
        escape_target = f"{env.prefix}../outside-root.txt"

        file_entity = Entity(
            type=TYPE_FILE,
            data={
                "path": "../outside-root.txt",
                "size": len(body),
                "content": result.blob_hash,
            },
        )
        from entity_core.storage.emit import EmitContext

        try:
            env.pathway.emit(
                escape_target, file_entity, EmitContext.bootstrap()
            )
        except Exception:
            # Upstream tree layer may reject the path before we get
            # to the local-files defense. That's an acceptable
            # outcome — defense-in-depth.
            return
        for _ in range(50):
            await asyncio.sleep(0.01)

        # Nothing should have been written outside the configured root.
        outside = tmp_path / "outside-root.txt"
        assert not outside.exists(), (
            "v1.3 §8.3 reverse-write coverage MUST: reverse-write hook "
            "must reject path-traversal via resolve_fs_path"
        )

    _run(_drive())


def test_reverse_delete_uses_resolver(tmp_path):
    """v1.3 §8.3 reverse-delete coverage MUST: reverse-delete also
    goes through resolve_fs_path (Python is clean — line 334 in
    reverse.py).

    Verifies via source inspection that the function calls
    resolve_fs_path before any os.remove. This is a static guard so a
    future refactor that bypasses the resolver fails CI.
    """
    import inspect

    from entity_handlers.local_files import reverse as _reverse_mod

    src = inspect.getsource(_reverse_mod._reverse_delete)
    assert "resolve_fs_path" in src, (
        "v1.3 §8.3 reverse-delete MUST go through resolve_fs_path; "
        "bare path-join bypasses both parent-traversal and leaf-symlink "
        "defenses (Go's L5 audit found this in their impl)"
    )


def test_reverse_write_projects_tree_to_disk(tmp_path):
    """A tree write under the configured prefix produces an actual file.

    Simulates the sync path: an external tree:put lands a file entity
    pointing at a content-store blob; the reverse-write listener
    reassembles the blob and atomically writes the disk file. The
    listener runs as a Phase-2 async subscription off the cascade
    (review F-1), so the test drives an event loop and yields until
    the executor-side FS work completes.
    """
    async def _drive():
        env = _make_env(tmp_path)
        body = b"propagated via tree\n"
        # Land the blob first so reverse-write can resolve it
        result = build_fastcdc(body, DEFAULT_CHUNK_SIZE)
        store = env.pathway.content_store
        for chunk in result.chunks:
            store.put(chunk)
        store.put(result.blob)

        # Build a file entity referencing that blob and emit it into the
        # tree under the mapped prefix (not via the handler — this
        # models an external sync delivery, not a local write).
        file_entity = Entity(
            type=TYPE_FILE,
            data={
                "path": "from-sync.txt",
                "size": len(body),
                "content": result.blob_hash,
            },
        )
        from entity_core.storage.emit import EmitContext

        env.pathway.emit(
            f"{env.prefix}from-sync.txt",
            file_entity,
            EmitContext.bootstrap(),
        )
        # The async listener fires via loop.create_task; the FS work
        # runs in a default-executor thread. Yield repeatedly until the
        # file appears or we time out (the rechunk on this tiny body
        # is < 1 ms, so this loop converges almost immediately).
        on_disk = Path(env.fs_root) / "from-sync.txt"
        import asyncio as _asyncio

        for _ in range(200):
            await _asyncio.sleep(0.01)
            if on_disk.exists():
                break
        assert on_disk.exists(), "reverse-write must project tree changes to disk"
        assert on_disk.read_bytes() == body

    _run(_drive())
