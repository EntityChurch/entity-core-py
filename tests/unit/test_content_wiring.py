"""Tests for CONTENT v3.5 manifest + PeerBuilder wiring.

Three things to grade for T5:

1. The content manifest is in ``ALL_HANDLER_MANIFESTS`` so it lands in
   the tree when the peer boots — peers running discovery see
   ``system/handler/system/content`` and learn the operation surface.

2. ``with_content_handler()`` registers the handler at the
   ``system/content`` prefix exactly once (idempotent if called twice).

3. ``with_all_handlers()`` chains content into the standard wiring.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.builder import PeerBuilder, _HandlerConfig
from entity_handlers import (
    ALL_HANDLER_MANIFESTS,
    CONTENT_HANDLER_MANIFEST,
    CONTENT_HANDLER_PATTERN,
    content_handler,
)


class TestManifestRegistration:
    def test_content_manifest_in_all(self):
        assert CONTENT_HANDLER_MANIFEST in ALL_HANDLER_MANIFESTS

    def test_manifest_shape(self):
        data = CONTENT_HANDLER_MANIFEST.data
        assert data["name"] == "content"
        # Per §4.9 + §6.1: the wire-advertised glob (not the bare prefix).
        assert data["pattern"] == "system/content/*"
        ops = data["operations"]
        assert "get" in ops
        assert "ingest" in ops
        assert ops["get"]["input_type"] == "system/content/get-request"
        assert ops["get"]["output_type"] == "system/content/content-response"
        assert ops["ingest"]["input_type"] == "system/content/ingest-request"
        assert ops["ingest"]["output_type"] == "system/content/ingest-result"


class TestBuilderWiring:
    def test_with_content_handler_registers_once(self):
        b = PeerBuilder().with_keypair(Keypair.generate())
        before = sum(
            1 for h in b._state.handlers if h.pattern == CONTENT_HANDLER_PATTERN
        )
        assert before == 0
        b.with_content_handler()
        configs = [
            h for h in b._state.handlers if h.pattern == CONTENT_HANDLER_PATTERN
        ]
        assert len(configs) == 1
        cfg = configs[0]
        assert cfg.handler is content_handler
        assert cfg.name == "content"
        # Priority between system (100) and revision (105) per design.
        assert 100 < cfg.priority < 105

    def test_with_content_handler_idempotent(self):
        b = PeerBuilder().with_keypair(Keypair.generate())
        b.with_content_handler().with_content_handler()
        configs = [
            h for h in b._state.handlers if h.pattern == CONTENT_HANDLER_PATTERN
        ]
        assert len(configs) == 1

    def test_with_all_handlers_includes_content(self):
        b = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
        )
        patterns = [h.pattern for h in b._state.handlers]
        assert CONTENT_HANDLER_PATTERN in patterns


class TestBuiltPeerHasContentManifestInTree:
    def test_built_peer_publishes_manifest(self):
        """After ``build()``, the manifest is in the entity tree at the
        well-known handler interface path so cross-peer discovery sees
        the content surface advertised.
        """
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .build()
        )
        # Path-of-record for discovery: system/handler/<pattern> per V7
        # §6.2. We check the bare path resolves to a stored entity.
        tree = peer.entity_tree
        full = tree.normalize_uri(f"system/handler/{CONTENT_HANDLER_PATTERN}")
        h = tree.get(full)
        assert h is not None, (
            f"content handler manifest missing from tree at {full}"
        )
