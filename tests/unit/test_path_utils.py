"""Tests for path utilities (leading-slash convention)."""

import pytest

from entity_core.utils.path import (
    clean_path,
    extract_handler_path,
    validate_absolute_path,
    validate_path_chars,
)


class TestValidatePathChars:
    """V7 §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1: reject control chars."""

    def test_clean_path_ok(self):
        assert validate_path_chars("app/notes/today") is None

    def test_empty_ok(self):
        assert validate_path_chars("") is None

    def test_nul_rejected(self):
        err = validate_path_chars("app/no\x00te")
        assert err is not None and "0x00" in err

    def test_c0_range_rejected(self):
        for c in (0x01, 0x09, 0x0A, 0x0D, 0x1F):
            assert validate_path_chars(f"app/{chr(c)}x") is not None

    def test_del_rejected(self):
        assert validate_path_chars("app/x\x7f") is not None

    def test_high_unicode_allowed(self):
        # Only ASCII control chars (<0x20, 0x7F) are rejected; printable
        # non-ASCII passes the char filter (peer-id/segment rules are separate).
        assert validate_path_chars("app/café/π") is None


class TestCleanPath:
    """Tests for clean_path()."""

    def test_collapse_double_slash(self):
        assert clean_path("/a//b/c") == "/a/b/c"

    def test_collapse_triple_slash(self):
        assert clean_path("/a///b") == "/a/b"

    def test_strip_trailing_slash(self):
        assert clean_path("/a/b/c/") == "/a/b/c"

    def test_no_change_needed(self):
        assert clean_path("/a/b/c") == "/a/b/c"

    def test_root_path_preserved(self):
        assert clean_path("/") == "/"

    def test_relative_path_no_leading_slash(self):
        assert clean_path("a/b") == "a/b"

    def test_relative_path_trailing_slash(self):
        assert clean_path("a/b/") == "a/b"

    def test_empty_string(self):
        assert clean_path("") == ""

    def test_reject_dot_slash(self):
        with pytest.raises(ValueError, match="reserved"):
            clean_path("./a")

    def test_reject_dot_dot_slash(self):
        with pytest.raises(ValueError, match="reserved"):
            clean_path("../a")

    def test_single_segment(self):
        assert clean_path("foo") == "foo"

    def test_absolute_single_segment(self):
        assert clean_path("/foo") == "/foo"

    def test_double_slash_at_start_collapses(self):
        assert clean_path("//foo/bar") == "/foo/bar"


class TestExtractHandlerPath:
    """Tests for extract_handler_path()."""

    def test_entity_uri(self):
        assert extract_handler_path("entity://peer123/system/tree") == "system/tree"

    def test_entity_uri_deep_path(self):
        assert extract_handler_path("entity://peer123/system/tree/sub") == "system/tree/sub"

    def test_entity_uri_no_path(self):
        assert extract_handler_path("entity://peer123") == ""

    def test_absolute_path(self):
        assert extract_handler_path("/peer123/system/tree") == "system/tree"

    def test_absolute_path_deep(self):
        assert extract_handler_path("/peer123/a/b/c") == "a/b/c"

    def test_absolute_path_no_rest(self):
        assert extract_handler_path("/peer123") == ""

    def test_bare_path_passthrough(self):
        assert extract_handler_path("system/tree") == "system/tree"

    def test_bare_single_segment(self):
        assert extract_handler_path("foo") == "foo"

    def test_empty_string(self):
        assert extract_handler_path("") == ""


class TestValidateAbsolutePath:
    """Tests for validate_absolute_path() — R12 defense-in-depth."""

    # Valid peer ID: 46 Base58 chars
    VALID_PEER = "2KcvGosJAZ8ssTzM1FqnnbvVYgdtJtLun9GmZ2Y3oGkZNY"

    def test_valid_absolute_path(self):
        assert validate_absolute_path(f"/{self.VALID_PEER}/system/tree") is None

    def test_valid_peer_only(self):
        """Just /{peer_id} with no rest is valid."""
        assert validate_absolute_path(f"/{self.VALID_PEER}") is None

    def test_valid_deep_path(self):
        assert validate_absolute_path(f"/{self.VALID_PEER}/a/b/c/d") is None

    def test_reject_no_leading_slash(self):
        result = validate_absolute_path(f"{self.VALID_PEER}/system/tree")
        assert result is not None
        assert "missing leading /" in result

    def test_reject_empty_segment(self):
        result = validate_absolute_path(f"/{self.VALID_PEER}/system//bad")
        assert result is not None
        assert "empty segment" in result

    def test_reject_invalid_peer_id_too_short(self):
        result = validate_absolute_path("/short/system/tree")
        assert result is not None
        assert "invalid peer_id" in result

    def test_reject_invalid_peer_id_bad_chars(self):
        """Peer IDs must be Base58 — no 0, O, I, l."""
        bad_peer = "0" * 46  # zeros are not in Base58
        result = validate_absolute_path(f"/{bad_peer}/system/tree")
        assert result is not None
        assert "invalid peer_id" in result

    def test_reject_empty_path(self):
        result = validate_absolute_path("/")
        assert result is not None
        assert "peer_id" in result

    def test_reject_slash_only_peer(self):
        result = validate_absolute_path("//system/tree")
        assert result is not None  # empty segment or invalid peer_id

    # §6.4 + D9: `validate_absolute_path` is STRICT — the {X} slot is
    # peer-ID-only. `content`/`manifest` reserved words are http-poll
    # URL-layer concepts (see entity_handlers.substitute.http_poll_urls),
    # NOT tree paths. The strict rejection here is what makes peer-IDs
    # and reserved words structurally collision-safe at their respective
    # layers.
    def test_rejects_content_reserved_word_as_tree_path(self):
        result = validate_absolute_path("/content/layout/abc123")
        assert result is not None
        assert "invalid peer_id" in result

    def test_rejects_manifest_reserved_word_as_tree_path(self):
        result = validate_absolute_path("/manifest")
        assert result is not None
        assert "invalid peer_id" in result

    def test_reserved_word_segments_only_collision_safe_at_url_layer(self):
        # Reserved words can never satisfy the peer-ID encoding rule, but
        # the path validator's job is to reject ANY non-peer-ID at {X}.
        # Reserved-word recognition lives in the URL-layer helper.
        for seg in ("content", "manifest"):
            assert validate_absolute_path(f"/{seg}/rest") is not None
