"""content_url_prefix is a REQUIRED publisher commitment (no derivation).

Per arch ruling Q2 + EXTENSION-SUBSTITUTE §2.2: the
`system/substitute/endpoint.content_url_prefix` is REQUIRED. The earlier
`{tree_url_prefix}/content` derivation default was removed because it
silently defeats the dedup'd-content case (S4) the two-prefix model exists
for. These tests pin the URL-construction surface that remains.
"""

from __future__ import annotations

import pytest

from entity_core.utils.ecf import (
    ALG_ECFV1_SHA256,
    ALG_ECFV1_SHA384,
    DIGEST_SIZES,
    Hash,
)
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


class TestHexIsTheFullWireFormAndItsWidthIsByteImplied:
    """EXTENSION-NETWORK §6.5.3 hex strictness `[MUST]` — routed by core-go
    as `2026-08-21-a` (`-g`), ruled at arch `bded94c`.

    The content-hash hex on the `http-poll` / substitute content routes is
    **one convention**: the full wire form, format-code byte included. Its
    length is **implied by the leading format byte** and is never a constant
    (`SPECIFICATION-FORMAT` §8.4.5) — a hardcoded-66 gate is *itself* the bug
    (the corrected 2026-08-10 cohort defect that `400`'d a valid SHA-384 hash).

    The rows below are the mutation teeth, and they are deliberately NOT
    written as ``build_content_url(...) == f"...{wire_hex(h)}"`` — that shape
    is a tautology that passes against a digest-only builder, because both
    sides move together. Each row instead computes the expected width from
    ``DIGEST_SIZES[format_byte]``, so switching `wire_hex` to a digest-only
    form fails on **both** algorithms rather than on neither.
    """

    @pytest.mark.parametrize(
        ("format_byte", "expected_len"),
        [
            (ALG_ECFV1_SHA256, 66),  # 2 + 2*32
            (ALG_ECFV1_SHA384, 98),  # 2 + 2*48
        ],
        ids=["ecfv1-sha256", "ecfv1-sha384"],
    )
    def test_the_leaf_hex_length_is_what_the_format_byte_implies(
        self, format_byte: int, expected_len: int
    ):
        digest_len = DIGEST_SIZES[format_byte]
        h = Hash(bytes([format_byte]) + bytes([0xAB]) * digest_len)
        hex_ = wire_hex(h)

        # The width is derived, never asserted as a literal 66.
        assert len(hex_) == 2 + 2 * digest_len
        assert len(hex_) == expected_len
        # ...and it BEGINS with the format byte — the property a digest-only
        # hex silently destroys.
        assert hex_[0:2] == f"{format_byte:02x}"

        leaf = build_content_url("https://cdn.example.com/blobs", "flat", h)
        assert leaf == f"https://cdn.example.com/blobs/{hex_}"
        assert len(leaf.rsplit("/", 1)[1]) == 2 + 2 * digest_len

    @pytest.mark.parametrize(
        "format_byte", [ALG_ECFV1_SHA256, ALG_ECFV1_SHA384], ids=["sha256", "sha384"]
    )
    def test_the_first_shard_dir_is_the_algorithm_partition(self, format_byte: int):
        """`hex[0:2]` is the **format-code byte**, so the sharded layouts
        partition by algorithm for free. A digest-only hex would slice the
        first *digest* byte there instead and that property dies silently —
        the two algorithms would collide in the same shard tree."""
        h = Hash(bytes([format_byte]) + bytes([0xAB]) * DIGEST_SIZES[format_byte])
        url = build_content_url("https://x", "sharded-2-4", h)
        first_dir = url[len("https://x/"):].split("/")[0]
        assert first_dir == f"{format_byte:02x}"

    def test_two_algorithms_do_not_share_a_shard_directory(self):
        """The teeth for the row above, stated as the property it protects:
        the same digest bytes under two format codes must land in two
        different first-level shards. Under a digest-only hex they land in
        the same one, and one entity overwrites the other on a static CDN."""
        a = Hash(bytes([ALG_ECFV1_SHA256]) + bytes([0xAB]) * 32)
        b = Hash(bytes([ALG_ECFV1_SHA384]) + bytes([0xAB]) * 48)
        shard = lambda h: build_content_url("https://x", "sharded-2-flat", h).split("/")[3]  # noqa: E731
        assert shard(a) != shard(b)

    def test_the_module_hardcodes_no_hex_width(self):
        """The gate `AGENTS.md` asks for by name: *a hardcoded-66 length gate
        is the bug*. Reading the source is the only way to catch a constant
        that no current input exercises — every fixture we have is SHA-256,
        so a `== 66` gate would pass every other row in this file.

        Prose is excluded the same way the presentation-tier gate excludes
        `entity://` in docstrings: a gate that cannot tell a comment from a
        comparison is not a gate. Here the module explains the 66/98 widths
        in prose deliberately, so the check is on **code lines only**.
        """
        import inspect

        from entity_handlers.substitute import urls as urls_mod

        src = inspect.getsource(urls_mod)
        # Strip the module docstring and every comment/docstring line; what is
        # left is executable code.
        code_lines = []
        in_doc = False
        for raw in src.splitlines():
            line = raw.strip()
            if line.startswith('"""') or line.endswith('"""'):
                # Toggle on an opening/closing fence; a one-line docstring
                # opens and closes on the same line and is skipped either way.
                if line.startswith('"""') and line.endswith('"""') and len(line) > 5:
                    continue
                in_doc = not in_doc
                continue
            if in_doc or line.startswith("#"):
                continue
            code_lines.append(line)
        code = "\n".join(code_lines)
        for forbidden in ("66", "98", "64", "33", "49"):
            assert forbidden not in code, (
                f"substitute/urls.py code carries the literal {forbidden!r}; the "
                "hex width is byte-implied (NETWORK §6.5.3) and must never be "
                "spelled as a constant"
            )
