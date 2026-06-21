"""Chunk A1 — D-13 supported_ops vocabulary tests.

Per EXTENSION-NETWORK §6.5 (v1.4 Amendment 2) + PROPOSAL-EXTENSION-
NETWORK-TRANSPORT-FAMILY §7 (D-13). The four active values
(EXECUTE / TREE_GET / CONTENT_GET / MANIFEST_GET) are the v1
advertisement vocabulary; SUBSCRIBE is reserved (push-capability is
implicit in transport duplexity for v1).
"""

from __future__ import annotations

import pytest

from entity_core.protocol.transport_ops import (
    ACTIVE_OPS,
    CONTENT_GET,
    EXECUTE,
    GET_CLASS_OPS,
    KNOWN_OPS,
    MANIFEST_GET,
    SUBSCRIBE_RESERVED,
    TREE_GET,
    is_active_op,
    is_known_op,
    validate_http_poll_ops,
    validate_live_ops,
    validate_supported_ops,
)


class TestVocabulary:
    def test_active_ops_exact_set(self):
        assert ACTIVE_OPS == {EXECUTE, TREE_GET, CONTENT_GET, MANIFEST_GET}

    def test_get_class_excludes_execute(self):
        assert EXECUTE not in GET_CLASS_OPS
        assert GET_CLASS_OPS == {TREE_GET, CONTENT_GET, MANIFEST_GET}

    def test_known_ops_includes_reserved(self):
        assert SUBSCRIBE_RESERVED in KNOWN_OPS
        assert SUBSCRIBE_RESERVED not in ACTIVE_OPS

    def test_is_active_rejects_reserved(self):
        assert is_active_op(EXECUTE)
        assert not is_active_op(SUBSCRIBE_RESERVED)
        assert not is_active_op("HEAD")

    def test_is_known_accepts_reserved(self):
        assert is_known_op(SUBSCRIBE_RESERVED)
        assert not is_known_op("HEAD")


class TestValidateSupportedOps:
    def test_accepts_single_execute(self):
        validate_supported_ops([EXECUTE])

    def test_accepts_partial_publisher_subset(self):
        validate_supported_ops([CONTENT_GET])
        validate_supported_ops([TREE_GET, CONTENT_GET])
        validate_supported_ops(list(GET_CLASS_OPS))

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="empty list"):
            validate_supported_ops([])

    def test_rejects_unknown(self):
        with pytest.raises(ValueError, match="unknown value"):
            validate_supported_ops([EXECUTE, "HEAD"])

    def test_rejects_reserved_by_default(self):
        with pytest.raises(ValueError, match="reserved per D-13"):
            validate_supported_ops([EXECUTE, SUBSCRIBE_RESERVED])

    def test_allow_reserved_flag_accepts_subscribe(self):
        validate_supported_ops([EXECUTE, SUBSCRIBE_RESERVED], allow_reserved=True)


class TestValidateLiveOps:
    def test_accepts_execute_only(self):
        validate_live_ops([EXECUTE])

    def test_rejects_get_class(self):
        with pytest.raises(ValueError, match="must be exactly"):
            validate_live_ops([CONTENT_GET])

    def test_rejects_execute_plus_extras(self):
        with pytest.raises(ValueError, match="must be exactly"):
            validate_live_ops([EXECUTE, TREE_GET])

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must be exactly"):
            validate_live_ops([])


class TestValidateHttpPollOps:
    def test_accepts_full_publisher(self):
        validate_http_poll_ops([TREE_GET, CONTENT_GET, MANIFEST_GET])

    def test_accepts_content_only_mirror(self):
        validate_http_poll_ops([CONTENT_GET])

    def test_accepts_manifest_only_registry(self):
        validate_http_poll_ops([MANIFEST_GET])

    def test_rejects_execute(self):
        # http-poll is passive; EXECUTE means a live executing peer.
        with pytest.raises(ValueError, match="invalid value"):
            validate_http_poll_ops([EXECUTE])

    def test_rejects_execute_mixed_in(self):
        with pytest.raises(ValueError, match="invalid value"):
            validate_http_poll_ops([CONTENT_GET, EXECUTE])

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="empty list"):
            validate_http_poll_ops([])
