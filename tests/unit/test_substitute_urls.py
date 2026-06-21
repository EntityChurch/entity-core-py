"""content_url_prefix is a REQUIRED publisher commitment (no derivation).

Per arch ruling Q2 + EXTENSION-SUBSTITUTE §2.2: the
`system/substitute/endpoint.content_url_prefix` is REQUIRED. The earlier
`{tree_url_prefix}/content` derivation default was removed because it
silently defeats the dedup'd-content case (S4) the two-prefix model exists
for. These tests pin the URL-construction surface that remains.
"""

from __future__ import annotations

import pytest

from entity_core.utils.ecf import Hash
from entity_handlers.substitute import urls
from entity_handlers.substitute.urls import build_content_url, wire_hex


def _hash() -> Hash:
    # 0x00 (ECFv1-SHA256) + 32 bytes of 0xAB → a stable 66-hex wire form.
    return Hash(bytes([0x00]) + bytes([0xAB]) * 32)


class TestNoDerivationHelper:
    def test_effective_content_url_prefix_is_gone(self):
        # The derivation helper was removed with the Q2 ruling; importing it
        # must fail so nothing silently re-derives the prefix.
        assert not hasattr(urls, "effective_content_url_prefix")


class TestBuildContentUrl:
    def test_flat_layout(self):
        h = _hash()
        assert build_content_url("https://cdn.example.com/blobs", "flat", h) == (
            f"https://cdn.example.com/blobs/{wire_hex(h)}"
        )

    def test_sharded_2_flat_layout(self):
        h = _hash()
        hex_ = wire_hex(h)
        assert build_content_url("https://cdn.example.com", "sharded-2-flat", h) == (
            f"https://cdn.example.com/{hex_[0:2]}/{hex_}"
        )

    def test_sharded_2_4_layout(self):
        h = _hash()
        hex_ = wire_hex(h)
        assert build_content_url("https://cdn.example.com", "sharded-2-4", h) == (
            f"https://cdn.example.com/{hex_[0:2]}/{hex_[2:4]}/{hex_}"
        )

    def test_sharded_2_2_is_alias_for_2_4(self):
        h = _hash()
        assert build_content_url("https://x", "sharded-2-2", h) == (
            build_content_url("https://x", "sharded-2-4", h)
        )

    def test_trailing_slash_on_prefix_is_normalized(self):
        h = _hash()
        assert build_content_url("https://x/", "flat", h) == (
            f"https://x/{wire_hex(h)}"
        )

    def test_unknown_layout_raises(self):
        with pytest.raises(ValueError):
            build_content_url("https://x", "bogus-layout", _hash())
