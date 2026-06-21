"""Wire-shape tests for EXECUTE / EXECUTE_RESPONSE per §3.4.

ENTITY-CORE-PROTOCOL-V7 §3.4 is normative: the ``params`` field of
EXECUTE and the ``result`` field of EXECUTE_RESPONSE are typed as
``entity`` — they MUST appear on the wire as materialized
``{type, data, content_hash}`` entities, not raw values. Go and Rust
both enforce this (the Go dispatcher returns 400 invalid_params when
params lacks a type field). Before this fix, Python emitted raw
payloads, which was masked in Python-to-Python flows and by Go's
lenient decoder, but failed cross-impl whenever a handler actually
needed structured params.

Tests cover:
- Outbound params/result are wrapped per §3.4 on the wire.
- Already-shaped entities are preserved (type kept, content_hash filled in).
- Raw payloads are wrapped as ``primitive/any``.
- Roundtrip through to_entity/from_entity preserves handler-visible data.
"""

from __future__ import annotations

from entity_core.protocol.bounds import Bounds
from entity_core.protocol.messages import (
    Execute,
    ExecuteResponse,
    compute_content_hash,
    unwrap_entity,
)
from entity_core.primitives import Uint


def _is_entity_shaped(value) -> bool:
    return (
        isinstance(value, dict)
        and "type" in value
        and "data" in value
        and "content_hash" in value
    )


class TestExecuteParamsWireShape:
    def test_raw_dict_is_wrapped_as_primitive_any(self):
        exec_ = Execute.create(uri="x", operation="get", params={"path": "data/x"})
        wire = exec_.to_entity()
        params = wire["data"]["params"]

        assert _is_entity_shaped(params)
        assert params["type"] == "primitive/any"
        assert params["data"] == {"path": "data/x"}
        assert params["content_hash"] == compute_content_hash(
            "primitive/any", {"path": "data/x"}
        )

    def test_already_entity_shaped_params_pass_through_type(self):
        """Callers that build entity-shaped params (e.g. connect hello
        passes a system/protocol/connect/hello entity) must keep their
        original type; we only fill in content_hash."""
        hello = {
            "type": "system/protocol/connect/hello",
            "data": {"peer_id": "p", "nonce": b"\x00" * 32},
        }
        exec_ = Execute.create(uri="x", operation="hello", params=hello)
        params = exec_.to_entity()["data"]["params"]

        assert params["type"] == "system/protocol/connect/hello"
        assert params["data"] == hello["data"]
        assert params["content_hash"] == compute_content_hash(
            hello["type"], hello["data"]
        )

    def test_preexisting_content_hash_is_preserved(self):
        data = {"peer_id": "p"}
        pre = {
            "type": "system/protocol/connect/hello",
            "data": data,
            "content_hash": b"\x00" + b"\xab" * 32,
        }
        exec_ = Execute.create(uri="x", operation="hello", params=pre)
        wire_params = exec_.to_entity()["data"]["params"]
        assert wire_params["content_hash"] == pre["content_hash"]

    def test_params_is_not_the_raw_dict_on_the_wire(self):
        """Regression: before the §3.4 fix Python emitted the raw dict
        directly, and Go/Rust rejected it with 400 invalid_params."""
        exec_ = Execute.create(uri="x", operation="get", params={"a": 1})
        wire_params = exec_.to_entity()["data"]["params"]
        # If this assert fails, the wrapper got removed — cross-impl
        # flows will break.
        assert wire_params != {"a": 1}
        assert _is_entity_shaped(wire_params)


class TestExecuteRoundtrip:
    def test_from_entity_keeps_envelope_for_handlers(self):
        """Handlers (especially connect-authenticate) need the envelope
        for signature target-matching; from_entity must preserve it."""
        original = Execute.create(
            uri="x", operation="get", params={"path": "data/x"}
        )
        wire = original.to_entity()
        parsed = Execute.from_entity(wire)
        assert _is_entity_shaped(parsed.params)

    def test_handler_shim_extracts_payload(self):
        """The idiomatic handler shim (``params.get("data", params)``)
        extracts the original raw payload from the wire envelope."""
        exec_ = Execute.create(uri="x", operation="get", params={"path": "y"})
        wire = exec_.to_entity()
        parsed = Execute.from_entity(wire)
        payload = parsed.params.get("data", parsed.params)
        assert payload == {"path": "y"}


class TestExecuteResponseWireShape:
    def test_entity_shaped_result_is_completed_not_replaced(self):
        result = {"type": "test/payload", "data": {"ok": True}}
        resp = ExecuteResponse(
            request_id="r", status=Uint(200), result=result
        )
        wire_result = resp.to_entity()["data"]["result"]
        assert wire_result["type"] == "test/payload"
        assert wire_result["data"] == {"ok": True}
        assert "content_hash" in wire_result

    def test_raw_result_is_wrapped_as_primitive_any(self):
        resp = ExecuteResponse(
            request_id="r", status=Uint(200), result={"hash": b"\x00" * 33}
        )
        wire_result = resp.to_entity()["data"]["result"]
        assert wire_result["type"] == "primitive/any"
        assert wire_result["data"] == {"hash": b"\x00" * 33}

    def test_result_data_property_unwraps_payload(self):
        resp = ExecuteResponse.from_entity(
            ExecuteResponse(
                request_id="r", status=Uint(200), result={"hash": b"abc"}
            ).to_entity()
        )
        # .result is still the envelope (per §3.4)
        assert _is_entity_shaped(resp.result)
        # .result_data is the payload for callers that don't care about
        # the envelope.
        assert resp.result_data == {"hash": b"abc"}


class TestUnwrapHelper:
    def test_unwrap_envelope_returns_data(self):
        env = {
            "type": "primitive/any",
            "data": {"k": "v"},
            "content_hash": b"\x00" * 33,
        }
        assert unwrap_entity(env) == {"k": "v"}

    def test_unwrap_non_envelope_returns_unchanged(self):
        # Missing content_hash -> not a full envelope; pass through.
        partial = {"type": "x", "data": {"k": "v"}}
        assert unwrap_entity(partial) is partial
        # Raw dict -> pass through.
        raw = {"path": "x"}
        assert unwrap_entity(raw) is raw
        # None -> None.
        assert unwrap_entity(None) is None


class TestErrorResultWireType:
    """V7 §3.3: error results MUST serialize as ``system/protocol/error``.

    Pins the single-serialization-point fix (to_entity) that materializes
    a bare error dict (status >= 400) as ``system/protocol/error`` rather
    than the generic ``primitive/any`` wrapper. The generic wrapper made
    strict cross-impl decoders read ``code=""`` (the v7.75 Go probe had to
    add a permissiveness fallback). The unwrapped ``data`` payload is
    byte-identical either way; only the wire ``type`` changes.
    """

    def test_bad_request_serializes_as_protocol_error(self):
        resp = ExecuteResponse.bad_request(
            request_id="r1", message="too deep", code="chain_depth_exceeded",
        )
        result = resp.to_entity()["data"]["result"]
        assert result["type"] == "system/protocol/error"
        assert result["data"]["code"] == "chain_depth_exceeded"
        assert result["data"]["message"] == "too deep"
        # Unwrapped payload is byte-identical to the in-memory bare dict.
        assert unwrap_entity(result) == {
            "code": "chain_depth_exceeded", "message": "too deep",
        }

    def test_all_error_helpers_use_protocol_error(self):
        for resp in (
            ExecuteResponse.not_found("r"),
            ExecuteResponse.forbidden("r"),
            ExecuteResponse.unauthorized("r"),
            ExecuteResponse.conflict("r"),
            ExecuteResponse.error("r", "boom"),
        ):
            result = resp.to_entity()["data"]["result"]
            assert result["type"] == "system/protocol/error", resp.status
            assert "code" in result["data"]

    def test_success_result_not_wrapped_as_error(self):
        # status < 400: a bare dict stays primitive/any, not protocol/error.
        resp = ExecuteResponse.success("r", {"ok": True})
        result = resp.to_entity()["data"]["result"]
        assert result["type"] == "primitive/any"

    def test_already_typed_error_left_untouched(self):
        # A handler's own typed error (or precondition_failed) is not
        # double-wrapped — its type is preserved.
        resp = ExecuteResponse(
            request_id="r",
            status=Uint(500),
            result={"type": "compute/error", "data": {"code": "x"}},
        )
        result = resp.to_entity()["data"]["result"]
        assert result["type"] == "compute/error"
