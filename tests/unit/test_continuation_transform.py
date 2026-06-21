"""Unit tests for the EXTENSION-CONTINUATION v1.9 transform pipeline.

Covers the pure helpers: extract -> select -> transform_ops navigation,
the bounded op set (G1), *_extract resolution, and the install-time
fail-closed validator.
"""

from entity_handlers.continuation import (
    KNOWN_TRANSFORM_OPS,
    _apply_transform,
    _apply_transform_ops,
    _navigate,
    _MISSING,
    _resolve_or_default,
    _resolve_or_default_resource,
    _validate_transform_ops,
)


class TestNavigate:
    def test_hit_and_miss(self):
        obj = {"a": {"b": {"c": 1}}}
        assert _navigate(obj, "a.b.c") == 1
        assert _navigate(obj, "a.b") == {"c": 1}
        assert _navigate(obj, "a.x") is _MISSING
        assert _navigate(obj, "") is obj

    def test_present_none_is_not_missing(self):
        assert _navigate({"a": None}, "a") is None  # found, value null


class TestApplyTransformPipeline:
    def test_none_and_string(self):
        assert _apply_transform({"x": 1}, None) == {"x": 1}
        assert _apply_transform({"data": {"v": 9}}, "data.v") == 9

    def test_string_miss_passes_original_through(self):
        original = {"data": {"v": 9}}
        assert _apply_transform(original, "data.nope") is original

    def test_extract_then_select_then_ops(self):
        result = {"data": {"items": {"name": "x", "kind": "file"}}}
        transform = {
            "extract": "data.items",
            "select": {"n": "name", "k": "kind"},
            "transform_ops": [
                {"op": "prepend", "field": "n", "literal": "doc-"},
            ],
        }
        assert _apply_transform(result, transform) == {"n": "doc-x", "k": "file"}

    def test_extract_miss_keeps_value(self):
        # best-effort: missed extract -> original value flows to select
        result = {"a": 1}
        out = _apply_transform(result, {"extract": "nope", "select": {"keep": "a"}})
        assert out == {"keep": 1}


class TestTransformOps:
    def test_strip_prefix_and_prepend_notification_rewrite(self):
        # The canonical cross-peer-notification -> local-path rewrite.
        value = {"path": "peer-b/data/shared/doc.txt"}
        ops = [
            {"op": "strip_prefix", "field": "path", "prefix": "peer-b/"},
            {"op": "prepend", "field": "path", "literal": "local/mirror/"},
        ]
        assert _apply_transform_ops(value, ops) == {
            "path": "local/mirror/data/shared/doc.txt"
        }

    def test_append_join_split_slice_replace(self):
        value = {"a": "x", "b": "y", "s": "a,b,c", "txt": "hello world"}
        assert _apply_transform_ops(value, [
            {"op": "append", "field": "a", "literal": "!"}])["a"] == "x!"
        assert _apply_transform_ops(value, [
            {"op": "join", "fields": ["a", "b"], "sep": "-", "into": "j"}])["j"] == "x-y"
        assert _apply_transform_ops(value, [
            {"op": "split", "field": "s", "sep": ",", "into": "arr"}])["arr"] == ["a", "b", "c"]
        assert _apply_transform_ops(value, [
            {"op": "slice", "field": "txt", "range": "0:5", "into": "head"}])["head"] == "hello"
        assert _apply_transform_ops(value, [
            {"op": "replace_literal", "field": "txt", "from": "world", "to": "there"}
        ])["txt"] == "hello there"

    def test_missing_field_is_total_noop(self):
        assert _apply_transform_ops({"a": 1}, [
            {"op": "prepend", "field": "absent", "literal": "z"}]) == {"a": 1}

    def test_non_map_value_all_noop(self):
        assert _apply_transform_ops("scalar", [
            {"op": "append", "field": "x", "literal": "y"}]) == "scalar"

    def test_unknown_op_raises(self):
        import pytest
        with pytest.raises(ValueError, match="unrecognized transform op"):
            _apply_transform_ops({"a": "1"}, [{"op": "regex_sub", "field": "a"}])

    def test_collect_keys_singular(self):
        # Singular: project one map's keys into an array at `into`.
        value = {"added": {"a/b": "h1", "c": "h2"}, "changed": {}}
        out = _apply_transform_ops(value, [
            {"op": "collect_keys", "field": "added", "into": "paths"},
        ])
        assert sorted(out["paths"]) == ["a/b", "c"]

    def test_collect_keys_plural_concatenates_in_list_order(self):
        # Plural: concatenate keys from each listed map in list order.
        # This is the canonical added ∪ changed shape for tree:extract.paths.
        value = {"added": {"x": 1}, "changed": {"y": 2}}
        out = _apply_transform_ops(value, [
            {"op": "collect_keys",
             "fields": ["added", "changed"], "into": "paths"},
        ])
        assert out["paths"] == ["x", "y"]

    def test_collect_keys_empty_map_yields_empty_array(self):
        out = _apply_transform_ops({"m": {}}, [
            {"op": "collect_keys", "field": "m", "into": "k"},
        ])
        assert out["k"] == []

    def test_collect_keys_missing_singular_is_noop(self):
        # Singular form, missing/non-map → no-op (don't write `into`).
        out = _apply_transform_ops({"a": 1}, [
            {"op": "collect_keys", "field": "absent", "into": "k"},
        ])
        assert "k" not in out
        # Non-map at the field is also no-op.
        out = _apply_transform_ops({"x": "scalar"}, [
            {"op": "collect_keys", "field": "x", "into": "k"},
        ])
        assert "k" not in out

    def test_collect_keys_plural_skips_missing_writes_empty(self):
        # Plural form: individually skip missing/non-map entries;
        # all-missing → empty array written.
        out = _apply_transform_ops({"a": {"k1": 1}, "b": "scalar"}, [
            {"op": "collect_keys",
             "fields": ["a", "b", "absent"], "into": "ks"},
        ])
        assert out["ks"] == ["k1"]
        out = _apply_transform_ops({}, [
            {"op": "collect_keys", "fields": ["x", "y"], "into": "ks"},
        ])
        assert out["ks"] == []

    def test_collect_keys_dotted_path_navigation(self):
        # `field`/`fields` follow the dotted-path rules from `extract`.
        value = {"diff": {"added": {"p/a": 1}, "changed": {"p/b": 2}}}
        out = _apply_transform_ops(value, [
            {"op": "collect_keys",
             "fields": ["diff.added", "diff.changed"], "into": "paths"},
        ])
        assert out["paths"] == ["p/a", "p/b"]

    def test_collect_keys_empty_into_silent_noop(self):
        # Empty `into` is a silent no-op per the best-effort rule.
        out = _apply_transform_ops({"m": {"k": 1}}, [
            {"op": "collect_keys", "field": "m", "into": ""},
        ])
        # `into=""` is treated as missing; nothing is written.
        assert out == {"m": {"k": 1}}


class TestValidateTransformOpsFailClosed:
    def test_all_known_ok(self):
        t = {"transform_ops": [{"op": op} for op in KNOWN_TRANSFORM_OPS]}
        assert _validate_transform_ops(t) is None

    def test_unknown_op_reported(self):
        # v1.10 §2.2 pin: unknown op rejected at install with the
        # `unknown_transform_op` code string; detail names the offender.
        result = _validate_transform_ops(
            {"transform_ops": [{"op": "strip_prefix"}, {"op": "eval"}]}
        )
        assert result is not None
        code, detail = result
        assert code == "unknown_transform_op"
        assert "eval" in detail

    def test_non_dict_or_no_ops_is_none(self):
        assert _validate_transform_ops("data.x") is None
        assert _validate_transform_ops({"extract": "a"}) is None

    def test_collect_keys_mutex_rejected(self):
        # v1.15 §2.2: a single `collect_keys` op MUST NOT carry both
        # `field` and `fields`. Pinned code `invalid_transform_args`.
        result = _validate_transform_ops(
            {"transform_ops": [
                {"op": "collect_keys", "field": "added",
                 "fields": ["added", "changed"], "into": "paths"},
            ]}
        )
        assert result is not None
        code, detail = result
        assert code == "invalid_transform_args"
        assert "mutually exclusive" in detail

    def test_collect_keys_singular_or_plural_ok(self):
        # Either form alone is admissible; neither form is also admissible
        # (silent no-op at apply).
        assert _validate_transform_ops(
            {"transform_ops": [{"op": "collect_keys", "field": "m", "into": "k"}]}
        ) is None
        assert _validate_transform_ops(
            {"transform_ops": [{"op": "collect_keys",
                                "fields": ["a", "b"], "into": "k"}]}
        ) is None
        assert _validate_transform_ops(
            {"transform_ops": [{"op": "collect_keys", "into": "k"}]}
        ) is None


class TestResolveOrDefault:
    def test_target_and_operation_extract_override(self):
        value = {"route": {"uri": "entity://b/system/tree", "op": "get"}}
        t = {"target_extract": "route.uri", "operation_extract": "route.op"}
        assert _resolve_or_default(value, t, "target_extract", "static") \
            == "entity://b/system/tree"
        assert _resolve_or_default(value, t, "operation_extract", "put") == "get"

    def test_fallback_when_absent_or_miss_or_null(self):
        assert _resolve_or_default({"a": 1}, None, "target_extract", "S") == "S"
        assert _resolve_or_default({"a": 1}, {}, "target_extract", "S") == "S"
        assert _resolve_or_default(
            {"a": 1}, {"target_extract": "nope"}, "target_extract", "S") == "S"
        assert _resolve_or_default(
            {"a": None}, {"target_extract": "a"}, "target_extract", "S") == "S"

    def test_resource_extract_wrapping(self):
        assert _resolve_or_default_resource(
            {"p": "x/y"}, {"resource_extract": "p"}, "resource_extract", None
        ) == {"targets": ["x/y"]}
        assert _resolve_or_default_resource(
            {"p": ["a", "b"]}, {"resource_extract": "p"}, "resource_extract", None
        ) == {"targets": ["a", "b"]}
        already = {"targets": ["z"]}
        assert _resolve_or_default_resource(
            {"p": already}, {"resource_extract": "p"}, "resource_extract", None
        ) == already
        assert _resolve_or_default_resource(
            {"p": 1}, {"resource_extract": "nope"}, "resource_extract", "DEF"
        ) == "DEF"


class TestDerefIncluded:
    """v1.17 §2.2 — deref_included resolves a hash field against the envelope's
    included map (pure: reads the request map, not the tree/store)."""

    def _ent(self, value):
        from entity_core.protocol.entity import Entity
        e = Entity(type="mirror/v", data={"value": value})
        return e.compute_hash(), e.to_dict()

    def test_replaces_hash_field_with_entity(self):
        h, ent = self._ent("hello")
        ops = [{"op": "deref_included", "field": "hash"}]
        out = _apply_transform_ops({"hash": h, "path": "m/x"}, ops, {h: ent})
        assert out["hash"] == ent
        assert out["path"] == "m/x"

    def test_into_target_leaves_source(self):
        h, ent = self._ent("v")
        ops = [{"op": "deref_included", "field": "hash", "into": "entity"}]
        out = _apply_transform_ops({"hash": h}, ops, {h: ent})
        assert out["entity"] == ent
        assert out["hash"] == h  # source untouched when `into` differs

    def test_noop_when_hash_absent_from_included(self):
        h, ent = self._ent("v")
        ops = [{"op": "deref_included", "field": "hash"}]
        out = _apply_transform_ops({"hash": h}, ops, {})  # empty map
        assert out == {"hash": h}  # best-effort no-op

    def test_noop_on_non_hash_value(self):
        ops = [{"op": "deref_included", "field": "hash"}]
        out = _apply_transform_ops({"hash": "not-a-hash"}, ops, {})
        assert out == {"hash": "not-a-hash"}

    def test_noop_on_missing_field(self):
        ops = [{"op": "deref_included", "field": "absent"}]
        out = _apply_transform_ops({"hash": b"\x00" * 33}, ops, {})
        assert out == {"hash": b"\x00" * 33}

    def test_in_known_ops_and_passes_install_validation(self):
        assert "deref_included" in KNOWN_TRANSFORM_OPS
        # Admissible op → install validator accepts it.
        assert _validate_transform_ops(
            {"transform_ops": [{"op": "deref_included", "field": "hash"}]}
        ) is None

    def test_pipeline_threads_included(self):
        h, ent = self._ent("threaded")
        out = _apply_transform(
            {"hash": h},
            {"transform_ops": [{"op": "deref_included", "field": "hash"}]},
            {h: ent},
        )
        assert out["hash"] == ent
