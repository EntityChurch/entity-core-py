"""D9 URL-layer helper tests — `content`/`manifest` reserved-word recognition.

Per EXTENSION-NETWORK §6.4 + D9 (v1.4 Amendment 2): http-poll consumer
URLs use a `{prefix}/{X}/{rest}` structure where `{X}` is a valid
peer-ID OR one of the reserved words. This helper lives separate from
``validate_absolute_path`` (which stays strict peer-ID-only) because the
reserved words are a URL-layer concept, not a tree-path concept.
"""

from __future__ import annotations

from entity_handlers.substitute.http_poll_urls import (
    RESERVED_X_SEGMENTS,
    classify_x_segment,
    is_valid_x_segment,
)


# Valid peer ID: 46 Base58 chars
VALID_PEER = "2KcvGosJAZ8ssTzM1FqnnbvVYgdtJtLun9GmZ2Y3oGkZNY"


class TestClassifyXSegment:
    def test_classifies_peer_id(self):
        assert classify_x_segment(VALID_PEER) == "peer_id"

    def test_classifies_content_reserved_word(self):
        assert classify_x_segment("content") == "content"

    def test_classifies_manifest_reserved_word(self):
        assert classify_x_segment("manifest") == "manifest"

    def test_rejects_unknown_segment(self):
        assert classify_x_segment("registry") is None
        assert classify_x_segment("foo") is None
        assert classify_x_segment("") is None

    def test_rejects_short_string(self):
        # A 45-char Base58 string is not a valid peer-ID (encoding requires >= 46).
        assert classify_x_segment("a" * 45) is None

    def test_case_sensitive_reserved_words(self):
        # Reserved words are lowercase ASCII; case variants don't match.
        assert classify_x_segment("Content") is None
        assert classify_x_segment("MANIFEST") is None

    def test_collision_safe_peer_id_and_reserved_word_disjoint(self):
        # A peer-ID encoding cannot produce "content" or "manifest"
        # (peer-IDs are >= 46 chars; reserved words are <= 8 chars). The
        # three classifications are mutually exclusive by construction.
        peer_kind = classify_x_segment(VALID_PEER)
        content_kind = classify_x_segment("content")
        manifest_kind = classify_x_segment("manifest")
        assert {peer_kind, content_kind, manifest_kind} == {
            "peer_id",
            "content",
            "manifest",
        }


class TestIsValidXSegment:
    def test_accepts_peer_id(self):
        assert is_valid_x_segment(VALID_PEER)

    def test_accepts_reserved_words(self):
        for seg in RESERVED_X_SEGMENTS:
            assert is_valid_x_segment(seg)

    def test_rejects_unknown(self):
        assert not is_valid_x_segment("not-a-peer")
        assert not is_valid_x_segment("")


class TestReservedXSegmentsConstant:
    def test_exactly_two_reserved_words(self):
        assert RESERVED_X_SEGMENTS == frozenset({"content", "manifest"})
