"""Tests for the ``system/content`` handler per EXTENSION-CONTENT v3.5 §6.

Three classes:

1. **path_required gate** (§6.2 / §6.3, behavior change from v3.4) —
   both ``get`` and ``ingest`` MUST return ``path_required`` without a
   resource target.

2. **get** (§6.2) — hash → entity resolution with ``found`` / ``missing``
   semantics; §4.3 small-content inline-include at the 64 KiB boundary
   (the load-bearing 65535 / 65536 / 65537 edge cases).

3. **ingest** (§6.3) — both modes (envelope, entity), exactly-one
   enforcement, hash-mismatch rejection per §6.3 hash validation, and
   the §11.1 MUST ``root`` pass-through in envelope mode.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.content import (
    CONTENT_HANDLER_PATTERN,
    build_fixed_size,
    content_handler,
    persist,
)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@dataclass
class Ctx:
    keypair: Keypair
    pathway: EmitPathway
    handler: HandlerContext

    @property
    def store(self) -> ContentStore:
        return self.pathway.content_store


def _make_ctx(*, resource_targets: list[str] | None = None) -> Ctx:
    kp = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(kp.peer_id)
    pathway = EmitPathway(content_store, entity_tree)
    handler = HandlerContext(
        local_peer_id=kp.peer_id,
        remote_peer_id=kp.peer_id,
        handler_grant={},
        caller_capability={},
        emit_pathway=pathway,
        handler_pattern=CONTENT_HANDLER_PATTERN,
        resource_targets=resource_targets,
        keypair=kp,
    )
    return Ctx(keypair=kp, pathway=pathway, handler=handler)


def _run(coro):
    return asyncio.run(coro)


# -----------------------------------------------------------------------------
# path_required gate (§6.2 / §6.3 — v3.5 behavior change)
# -----------------------------------------------------------------------------


class TestPathRequired:
    def test_get_without_resource_target_rejected(self):
        ctx = _make_ctx()  # no resource_targets
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": []}}, ctx.handler,
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "path_required"

    def test_ingest_without_resource_target_rejected(self):
        ctx = _make_ctx()  # no resource_targets
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"entity": {"type": "x", "data": {}}}},
                ctx.handler,
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "path_required"


# -----------------------------------------------------------------------------
# get (§6.2)
# -----------------------------------------------------------------------------


class TestGet:
    def test_returns_found_and_included(self):
        """v3.6 F4 wire shape: result is the content-response entity
        directly; entities ride in `envelope_included` (drained by
        peer.py to the outer wire envelope at send time). Match Go's
        shape on the entity-delivery channel.
        """
        ctx = _make_ctx(resource_targets=["system/content"])
        e1 = Entity(type="custom/thing", data={"x": 1})
        e2 = Entity(type="custom/thing", data={"x": 2})
        h1 = ctx.store.put(e1)
        h2 = ctx.store.put(e2)
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": [h1, h2]}}, ctx.handler,
            )
        )
        assert result["status"] == 200
        resp = result["result"]
        assert resp["type"] == "system/content/content-response"
        # Python's shape: found + missing are arrays of hashes (push-
        # back on §8.3's `found: uint64` — array is strictly more
        # informative than counter; consumers otherwise have to
        # set-difference against the request to recover the same info).
        assert set(resp["data"]["found"]) == {h1, h2}
        assert resp["data"]["missing"] == []
        included = result["envelope_included"]
        assert h1 in included
        assert h2 in included

    def test_unresolved_hashes_go_to_missing(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        fake = b"\x00" + b"\xff" * 32
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": [fake]}}, ctx.handler,
            )
        )
        assert result["status"] == 200
        resp = result["result"]
        assert resp["data"]["found"] == []
        assert resp["data"]["missing"] == [fake]
        assert result["envelope_included"] == {}

    def test_invalid_hashes_param_400s(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": "not-a-list"}}, ctx.handler,
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_params"


# -----------------------------------------------------------------------------
# §4.3 small-content inline-include — the 64 KiB boundary edges
# -----------------------------------------------------------------------------


class TestInlineInclude64KiB:
    """§4.3 + §10.1 pin: inline-include the chunks when the resolved
    blob's ``total_size`` is ``<= MIN_CHUNK_SIZE`` (65536). Above 65536
    the chunks are NOT inline-included; the caller follows up with a
    second EXECUTE.

    The three boundary tests guard the inclusive ``<=`` discipline.
    """

    @staticmethod
    def _persist_blob_of(ctx: Ctx, total_size: int):
        # Use fixed-size chunking with chunk_size = total_size so we get
        # exactly one chunk regardless of size — clean test isolation.
        data = b"X" * total_size
        result = build_fixed_size(data, chunk_size=max(1, total_size))
        persist(result, ctx.store)
        return result.blob_hash, [c.compute_hash() for c in result.chunks]

    def test_inline_at_below_threshold(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        blob_hash, chunk_hashes = self._persist_blob_of(ctx, 65535)
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": [blob_hash]}}, ctx.handler,
            )
        )
        included = result["envelope_included"]
        assert blob_hash in included
        for ch in chunk_hashes:
            assert ch in included, "chunk MUST be inline-included below 64 KiB"

    def test_inline_at_exact_threshold(self):
        """The pin is ``<=`` 65536 — equal-to-boundary STILL inlines."""
        ctx = _make_ctx(resource_targets=["system/content"])
        blob_hash, chunk_hashes = self._persist_blob_of(ctx, 65536)
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": [blob_hash]}}, ctx.handler,
            )
        )
        included = result["envelope_included"]
        for ch in chunk_hashes:
            assert ch in included

    def test_no_inline_above_threshold(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        blob_hash, chunk_hashes = self._persist_blob_of(ctx, 65537)
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "get",
                {"data": {"hashes": [blob_hash]}}, ctx.handler,
            )
        )
        included = result["envelope_included"]
        # Blob itself is included (it was requested); chunks are NOT.
        assert blob_hash in included
        for ch in chunk_hashes:
            assert ch not in included


# -----------------------------------------------------------------------------
# ingest (§6.3)
# -----------------------------------------------------------------------------


class TestIngest:
    def test_entity_mode_stores_and_returns_root_hash(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        e = Entity(type="custom/thing", data={"x": 42})
        expected = e.compute_hash()
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"entity": {"type": e.type, "data": e.data}}},
                ctx.handler,
            )
        )
        assert result["status"] == 200
        assert result["result"]["type"] == "system/content/ingest-result"
        body = result["result"]["data"]
        assert body["root_hash"] == expected
        assert body["ingested_count"] == 1
        # Entity mode: no `root` field per §6.3
        assert "root" not in body
        # And the entity is now in the store.
        assert ctx.store.get(expected) is not None

    def test_envelope_mode_returns_root_passthrough_MUST(self):
        """§11.1 MUST: envelope mode with non-null root MUST include the
        inlined `root`. This is the §6.3 chain-composition enabler.
        """
        ctx = _make_ctx(resource_targets=["system/content"])
        root = Entity(type="custom/wrapper", data={"head": b"\x00" + b"H" * 32})
        included_entity = Entity(type="custom/leaf", data={"value": 7})
        included_hash = included_entity.compute_hash()

        envelope = {
            "data": {
                "root": {"type": root.type, "data": root.data},
                "included": {
                    included_hash: {
                        "type": included_entity.type,
                        "data": included_entity.data,
                    }
                },
            }
        }
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"envelope": envelope}}, ctx.handler,
            )
        )
        assert result["status"] == 200
        body = result["result"]["data"]
        assert body["ingested_count"] == 2  # root + 1 included
        assert body["root_hash"] == root.compute_hash()
        # The MUST-pass-through:
        assert "root" in body
        assert body["root"]["type"] == "custom/wrapper"
        assert body["root"]["data"] == {"head": b"\x00" + b"H" * 32}
        # Both stored
        assert ctx.store.get(root.compute_hash()) is not None
        assert ctx.store.get(included_hash) is not None

    def test_envelope_mode_hash_mismatch_rejected(self):
        """§6.3: each included entry's content hash MUST be recomputed
        against its key; mismatch is a 400 ``hash_mismatch``.
        """
        ctx = _make_ctx(resource_targets=["system/content"])
        included_entity = Entity(type="custom/leaf", data={"value": 7})
        wrong_key = b"\x00" + b"Z" * 32  # not the entity's actual hash
        envelope = {
            "data": {
                "root": None,
                "included": {
                    wrong_key: {
                        "type": included_entity.type,
                        "data": included_entity.data,
                    }
                },
            }
        }
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"envelope": envelope}}, ctx.handler,
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "hash_mismatch"

    def test_envelope_mode_with_null_root_omits_root_field(self):
        """When ``envelope.root`` is null, ``root`` is absent from the
        result per the §6.3 / §11.1 phrasing (MUST is conditional on
        non-null root).
        """
        ctx = _make_ctx(resource_targets=["system/content"])
        envelope = {"data": {"root": None, "included": {}}}
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"envelope": envelope}}, ctx.handler,
            )
        )
        assert result["status"] == 200
        body = result["result"]["data"]
        assert "root" not in body
        assert body["ingested_count"] == 0

    def test_ambiguous_input_rejected(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {
                    "data": {
                        "envelope": {"data": {"root": None, "included": {}}},
                        "entity": {"type": "x", "data": {}},
                    }
                },
                ctx.handler,
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "ambiguous_input"

    def test_missing_input_rejected(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest", {"data": {}}, ctx.handler,
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "missing_input"

    def test_idempotency(self):
        """Content-addressed storage is inherently idempotent — re-
        ingesting the same entity is a no-op.
        """
        ctx = _make_ctx(resource_targets=["system/content"])
        e = Entity(type="custom/thing", data={"x": "stable"})
        params = {"data": {"entity": {"type": e.type, "data": e.data}}}

        r1 = _run(
            content_handler(CONTENT_HANDLER_PATTERN, "ingest", params, ctx.handler)
        )
        r2 = _run(
            content_handler(CONTENT_HANDLER_PATTERN, "ingest", params, ctx.handler)
        )
        assert r1["result"]["data"]["root_hash"] == r2["result"]["data"]["root_hash"]
        assert len(ctx.store) == 1


# -----------------------------------------------------------------------------
# Hash Tree Presence binding (CONTENT §6.4.2 MUST)
# -----------------------------------------------------------------------------


class TestHashTreePresence:
    """CONTENT §6.4.2 Hash Tree Presence MUST: every ingested entity
    gets a binding at `{namespace}/{hex(H)} → H` in the entity tree.

    Per the arch serving-mode content-scope ruling
    follow-up §2.3: this was the cohort-wide gap blocking namespace-
    scoped serving (`system/peer/transport/http-poll` content-get).
    Python landed it here; Rust+Go follow per ruling §4.
    """

    def test_entity_mode_writes_binding(self):
        namespace = "system/content/public"
        ctx = _make_ctx(resource_targets=[namespace])
        e = Entity(type="custom/thing", data={"x": 42})
        h = e.compute_hash()
        _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"entity": {"type": e.type, "data": e.data}}},
                ctx.handler,
            )
        )
        leaf = f"{namespace}/{h.hex()}"
        bound = ctx.pathway.entity_tree.get(leaf)
        assert bound == h, (
            f"missing §6.4.2 binding at {leaf!r}: got {bound!r}, expected {h.hex()!r}"
        )

    def test_envelope_mode_writes_binding_for_root_and_included(self):
        namespace = "system/content/public"
        ctx = _make_ctx(resource_targets=[namespace])
        root = Entity(type="custom/wrapper", data={"head": b"\x00" + b"H" * 32})
        leaf_entity = Entity(type="custom/leaf", data={"value": 7})
        root_h = root.compute_hash()
        leaf_h = leaf_entity.compute_hash()
        envelope = {
            "data": {
                "root": {"type": root.type, "data": root.data},
                "included": {
                    leaf_h: {"type": leaf_entity.type, "data": leaf_entity.data},
                },
            }
        }
        _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"envelope": envelope}}, ctx.handler,
            )
        )
        # Both root and included entry get bindings.
        for h in (root_h, leaf_h):
            leaf = f"{namespace}/{h.hex()}"
            assert ctx.pathway.entity_tree.get(leaf) == h, (
                f"missing §6.4.2 binding for {h.hex()} at {leaf!r}"
            )

    def test_binding_uses_caller_namespace_not_handler_prefix(self):
        """The binding sits under the *caller's resource target*, not the
        handler's `system/content` prefix. An operator publishing into
        `system/content/shared` gets bindings under `.../shared/...`,
        which is what NamespaceScope(namespace='system/content/shared')
        reads."""
        namespace = "system/content/shared"
        ctx = _make_ctx(resource_targets=[namespace])
        e = Entity(type="custom/thing", data={"label": "shared"})
        h = e.compute_hash()
        _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "ingest",
                {"data": {"entity": {"type": e.type, "data": e.data}}},
                ctx.handler,
            )
        )
        assert ctx.pathway.entity_tree.get(f"{namespace}/{h.hex()}") == h
        # NOT bound at the handler-prefix path.
        assert ctx.pathway.entity_tree.get(f"system/content/{h.hex()}") is None


# -----------------------------------------------------------------------------
# Unsupported operation
# -----------------------------------------------------------------------------


class TestUnsupportedOperation:
    def test_returns_501(self):
        ctx = _make_ctx(resource_targets=["system/content"])
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN, "vacuum", {"data": {}}, ctx.handler,
            )
        )
        assert result["status"] == 501
        assert result["result"]["data"]["code"] == "unsupported_operation"
