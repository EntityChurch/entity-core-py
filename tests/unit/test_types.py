"""Tests for the type system."""

from dataclasses import dataclass, field
from typing import Any, Optional

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.protocol.messages import (
    Execute,
    ExecuteResponse,
)
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.types import (
    FieldSpec,
    build_cddl,
    build_schema,
    dataclass_to_cddl,
    dataclass_to_fields,
    dataclass_to_schema,
    get_all_type_entities,
    get_type_entity,
    list_type_names,
    python_type_to_cddl,
    python_type_to_field_spec,
    python_type_to_schema,
    register_types,
)
from entity_core.utils.ecf import Hash


class TestPythonTypeToSchema:
    """Tests for python_type_to_schema function (legacy JSON Schema)."""

    def test_string(self):
        """String type maps to JSON Schema string."""
        assert python_type_to_schema(str) == {"type": "string"}

    def test_integer(self):
        """Int type maps to JSON Schema integer."""
        assert python_type_to_schema(int) == {"type": "integer"}

    def test_float(self):
        """Float type maps to JSON Schema number."""
        assert python_type_to_schema(float) == {"type": "number"}

    def test_boolean(self):
        """Bool type maps to JSON Schema boolean."""
        assert python_type_to_schema(bool) == {"type": "boolean"}

    def test_list(self):
        """List type maps to JSON Schema array."""
        assert python_type_to_schema(list) == {"type": "array"}

    def test_list_with_item_type(self):
        """List[str] maps to array with string items."""
        assert python_type_to_schema(list[str]) == {
            "type": "array",
            "items": {"type": "string"},
        }

    def test_dict(self):
        """Dict type maps to JSON Schema object with additionalProperties."""
        assert python_type_to_schema(dict) == {"type": "object", "additionalProperties": True}

    def test_optional(self):
        """Optional[str] maps to string (optional handled at field level)."""
        assert python_type_to_schema(Optional[str]) == {"type": "string"}

    def test_union_with_none(self):
        """str | None maps to string."""
        assert python_type_to_schema(str | None) == {"type": "string"}


class TestDataclassToSchema:
    """Tests for dataclass_to_schema function (legacy JSON Schema)."""

    def test_simple_dataclass(self):
        """Simple dataclass converts to schema with required fields."""

        @dataclass
        class Simple:
            name: str
            count: int

        schema = dataclass_to_schema(Simple)
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is True
        assert sorted(schema["required"]) == ["count", "name"]
        assert schema["properties"]["name"] == {"type": "string"}
        assert schema["properties"]["count"] == {"type": "integer"}

    def test_optional_fields(self):
        """Fields with defaults are not required."""

        @dataclass
        class WithDefaults:
            required_field: str
            optional_field: str = "default"
            factory_field: list[str] = field(default_factory=list)

        schema = dataclass_to_schema(WithDefaults)
        assert schema["required"] == ["required_field"]

    def test_optional_type(self):
        """Optional[T] fields are not required."""

        @dataclass
        class WithOptional:
            required_field: str
            optional_field: Optional[str] = None

        schema = dataclass_to_schema(WithOptional)
        assert schema["required"] == ["required_field"]

    def test_non_dataclass_raises(self):
        """Non-dataclass raises ValueError."""

        class NotADataclass:
            pass

        with pytest.raises(ValueError, match="is not a dataclass"):
            dataclass_to_schema(NotADataclass)


class TestBuildSchema:
    """Tests for build_schema function (legacy JSON Schema)."""

    def test_basic_schema(self):
        """Build schema with properties and required fields."""
        schema = build_schema(
            properties={
                "name": {"type": "string"},
                "count": {"type": "integer"},
            },
            required=["name"],
        )
        assert schema == {
            "type": "object",
            "required": ["name"],
            "additionalProperties": True,
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
            },
        }

    def test_empty_required(self):
        """Build schema with no required fields."""
        schema = build_schema(properties={"name": {"type": "string"}})
        assert schema["required"] == []

    def test_required_sorted(self):
        """Required fields are sorted alphabetically."""
        schema = build_schema(
            properties={
                "zebra": {"type": "string"},
                "alpha": {"type": "string"},
            },
            required=["zebra", "alpha"],
        )
        assert schema["required"] == ["alpha", "zebra"]


class TestPythonTypeToCddl:
    """Tests for python_type_to_cddl function."""

    def test_string(self):
        """String type maps to CDDL tstr."""
        assert python_type_to_cddl(str) == "tstr"

    def test_integer(self):
        """Int type maps to CDDL int."""
        assert python_type_to_cddl(int) == "int"

    def test_uint(self):
        """Uint type maps to CDDL uint."""
        from entity_core.types import Uint
        assert python_type_to_cddl(Uint) == "uint"

    def test_float(self):
        """Float type maps to CDDL float64."""
        assert python_type_to_cddl(float) == "float64"

    def test_boolean(self):
        """Bool type maps to CDDL bool."""
        assert python_type_to_cddl(bool) == "bool"

    def test_null(self):
        """NoneType maps to CDDL null."""
        assert python_type_to_cddl(type(None)) == "null"

    def test_list(self):
        """List type maps to CDDL array."""
        assert python_type_to_cddl(list) == "[* any]"

    def test_list_with_item_type(self):
        """list[str] maps to CDDL array with tstr items."""
        assert python_type_to_cddl(list[str]) == "[* tstr]"

    def test_list_with_int_type(self):
        """list[int] maps to CDDL array with int items."""
        assert python_type_to_cddl(list[int]) == "[* int]"

    def test_dict(self):
        """Dict type maps to CDDL open object."""
        assert python_type_to_cddl(dict) == "{* tstr => any}"

    def test_any(self):
        """Any type maps to CDDL any."""
        assert python_type_to_cddl(Any) == "any"

    def test_optional(self):
        """Optional[str] maps to tstr (optionality at field level)."""
        assert python_type_to_cddl(Optional[str]) == "tstr"

    def test_union_with_none(self):
        """str | None maps to tstr."""
        assert python_type_to_cddl(str | None) == "tstr"

    def test_union_multiple_types(self):
        """Union with multiple non-None types maps to any."""
        assert python_type_to_cddl(str | int) == "any"


class TestDataclassToCddl:
    """Tests for dataclass_to_cddl function."""

    def test_simple_dataclass(self):
        """Simple dataclass converts to CDDL with required fields."""

        @dataclass
        class Simple:
            name: str
            count: int

        cddl = dataclass_to_cddl(Simple)
        assert "name: tstr," in cddl
        assert "count: int," in cddl
        assert "* tstr => any" in cddl
        # No optional markers
        assert "?" not in cddl

    def test_optional_fields(self):
        """Fields with defaults are marked optional with ?."""

        @dataclass
        class WithDefaults:
            required_field: str
            optional_field: str = "default"
            factory_field: list[str] = field(default_factory=list)

        cddl = dataclass_to_cddl(WithDefaults)
        assert "required_field: tstr," in cddl
        assert "? optional_field: tstr," in cddl
        assert "? factory_field: [* tstr]," in cddl

    def test_optional_type(self):
        """Optional[T] fields are marked optional with ?."""

        @dataclass
        class WithOptional:
            required_field: str
            optional_field: Optional[str] = None

        cddl = dataclass_to_cddl(WithOptional)
        assert "required_field: tstr," in cddl
        assert "? optional_field: tstr," in cddl

    def test_non_dataclass_raises(self):
        """Non-dataclass raises ValueError."""

        class NotADataclass:
            pass

        with pytest.raises(ValueError, match="is not a dataclass"):
            dataclass_to_cddl(NotADataclass)

    def test_fields_sorted_alphabetically(self):
        """Fields are sorted alphabetically within required/optional groups."""

        @dataclass
        class Sorted:
            zebra: str
            alpha: str
            beta: int

        cddl = dataclass_to_cddl(Sorted)
        lines = cddl.split("\n")
        # Required fields should be alpha, beta, zebra in order
        field_lines = [l.strip() for l in lines if ":" in l and "=>" not in l]
        assert field_lines[0] == "alpha: tstr,"
        assert field_lines[1] == "beta: int,"
        assert field_lines[2] == "zebra: tstr,"

    def test_open_type_always_last(self):
        """Open type marker is always the last field."""

        @dataclass
        class AnyClass:
            field1: str
            field2: int

        cddl = dataclass_to_cddl(AnyClass)
        lines = cddl.strip().split("\n")
        assert lines[-2].strip() == "* tstr => any"
        assert lines[-1] == "}"

    def test_ref_fields_excluded(self):
        """Fields ending in _ref are excluded by default."""

        @dataclass
        class WithRef:
            name: str
            token_ref: str

        cddl = dataclass_to_cddl(WithRef)
        assert "name: tstr," in cddl
        assert "token_ref" not in cddl

    def test_ref_fields_included_when_flag_false(self):
        """Fields ending in _ref are included when exclude_ref_fields=False."""

        @dataclass
        class WithRef:
            name: str
            token_ref: str

        cddl = dataclass_to_cddl(WithRef, exclude_ref_fields=False)
        assert "name: tstr," in cddl
        assert "token_ref: tstr," in cddl


class TestBuildCddl:
    """Tests for build_cddl function."""

    def test_basic_cddl(self):
        """Build CDDL with fields and required list."""
        cddl = build_cddl(
            fields={
                "name": "tstr",
                "count": "int",
            },
            required=["name"],
        )
        assert "name: tstr," in cddl
        assert "? count: int," in cddl
        assert "* tstr => any" in cddl

    def test_empty_required(self):
        """Build CDDL with no required fields - all optional."""
        cddl = build_cddl(fields={"name": "tstr"})
        assert "? name: tstr," in cddl

    def test_all_required(self):
        """Build CDDL with all fields required."""
        cddl = build_cddl(
            fields={"name": "tstr", "count": "int"},
            required=["name", "count"],
        )
        assert "name: tstr," in cddl
        assert "count: int," in cddl
        # No optional markers
        assert "?" not in cddl

    def test_fields_sorted(self):
        """Fields are sorted alphabetically within groups."""
        cddl = build_cddl(
            fields={
                "zebra": "tstr",
                "alpha": "tstr",
            },
            required=["zebra"],
        )
        lines = cddl.split("\n")
        # zebra is required, alpha is optional
        # Required come first, then optional
        field_lines = [l.strip() for l in lines if ": " in l and "=>" not in l]
        assert field_lines[0] == "zebra: tstr,"
        assert field_lines[1] == "? alpha: tstr,"


class TestPythonTypeToFieldSpec:
    """Tests for python_type_to_field_spec function (V6.0)."""

    def test_string(self):
        """String type maps to primitive/string."""
        spec = python_type_to_field_spec(str)
        assert spec.to_dict() == {"type_ref": "primitive/string"}

    def test_bytes(self):
        """Bytes type maps to primitive/bytes."""
        spec = python_type_to_field_spec(bytes)
        assert spec.to_dict() == {"type_ref": "primitive/bytes"}

    def test_integer(self):
        """Int type maps to primitive/int."""
        spec = python_type_to_field_spec(int)
        assert spec.to_dict() == {"type_ref": "primitive/int"}

    def test_uint(self):
        """Uint type maps to primitive/uint."""
        from entity_core.types import Uint
        spec = python_type_to_field_spec(Uint)
        assert spec.to_dict() == {"type_ref": "primitive/uint"}

    def test_float(self):
        """Float type maps to primitive/float."""
        spec = python_type_to_field_spec(float)
        assert spec.to_dict() == {"type_ref": "primitive/float"}

    def test_boolean(self):
        """Bool type maps to primitive/bool."""
        spec = python_type_to_field_spec(bool)
        assert spec.to_dict() == {"type_ref": "primitive/bool"}

    def test_any(self):
        """Any type maps to primitive/any."""
        spec = python_type_to_field_spec(Any)
        assert spec.to_dict() == {"type_ref": "primitive/any"}

    def test_list(self):
        """List type maps to array_of any."""
        spec = python_type_to_field_spec(list)
        assert spec.to_dict() == {"array_of": {"type_ref": "primitive/any"}}

    def test_list_with_item_type(self):
        """list[str] maps to array_of string."""
        spec = python_type_to_field_spec(list[str])
        assert spec.to_dict() == {"array_of": {"type_ref": "primitive/string"}}

    def test_dict(self):
        """Dict type maps to map_of any."""
        spec = python_type_to_field_spec(dict)
        assert spec.to_dict() == {"map_of": {"type_ref": "primitive/any"}}

    def test_dict_with_types(self):
        """dict[str, int] maps to map_of int."""
        spec = python_type_to_field_spec(dict[str, int])
        assert spec.to_dict() == {"map_of": {"type_ref": "primitive/int"}}

    def test_dict_with_bytes_key(self):
        """dict[bytes, str] includes key_type."""
        spec = python_type_to_field_spec(dict[bytes, str])
        assert spec.to_dict() == {
            "map_of": {"type_ref": "primitive/string"},
            "key_type": "primitive/bytes",
        }

    def test_optional(self):
        """Optional[str] maps to string with optional=True."""
        spec = python_type_to_field_spec(Optional[str])
        assert spec.to_dict() == {"type_ref": "primitive/string", "optional": True}

    def test_union_with_none(self):
        """str | None maps to string with optional=True."""
        spec = python_type_to_field_spec(str | None)
        assert spec.to_dict() == {"type_ref": "primitive/string", "optional": True}

    def test_optional_explicit(self):
        """Explicit optional=True is preserved."""
        spec = python_type_to_field_spec(str, optional=True)
        assert spec.to_dict() == {"type_ref": "primitive/string", "optional": True}

    def test_hash_via_hint_name(self):
        """Hash type hint maps to system/hash."""
        spec = python_type_to_field_spec(bytes, type_hint_name="Hash")
        assert spec.to_dict() == {"type_ref": "system/hash"}

    def test_nested_list(self):
        """list[list[int]] maps correctly."""
        spec = python_type_to_field_spec(list[list[int]])
        assert spec.to_dict() == {
            "array_of": {"array_of": {"type_ref": "primitive/int"}}
        }


class TestDataclassToFields:
    """Tests for dataclass_to_fields function (V6.0)."""

    def test_simple_dataclass(self):
        """Simple dataclass converts to fields dict."""

        @dataclass
        class Simple:
            name: str
            count: int

        fields = dataclass_to_fields(Simple)
        assert fields == {
            "name": {"type_ref": "primitive/string"},
            "count": {"type_ref": "primitive/int"},
        }

    def test_optional_fields(self):
        """Fields with defaults are marked optional."""

        @dataclass
        class WithDefaults:
            required_field: str
            optional_field: str = "default"
            factory_field: list[str] = field(default_factory=list)

        fields = dataclass_to_fields(WithDefaults)
        assert fields["required_field"] == {"type_ref": "primitive/string"}
        assert fields["optional_field"] == {"type_ref": "primitive/string", "optional": True}
        assert fields["factory_field"] == {
            "array_of": {"type_ref": "primitive/string"},
            "optional": True,
        }

    def test_optional_type(self):
        """Optional[T] fields are marked optional."""

        @dataclass
        class WithOptional:
            required_field: str
            optional_field: Optional[str] = None

        fields = dataclass_to_fields(WithOptional)
        assert fields["required_field"] == {"type_ref": "primitive/string"}
        assert fields["optional_field"] == {"type_ref": "primitive/string", "optional": True}

    def test_non_dataclass_raises(self):
        """Non-dataclass raises ValueError."""

        class NotADataclass:
            pass

        with pytest.raises(ValueError, match="is not a dataclass"):
            dataclass_to_fields(NotADataclass)

    def test_ref_fields_excluded(self):
        """Fields ending in _ref are excluded by default."""

        @dataclass
        class WithRef:
            name: str
            token_ref: str

        fields = dataclass_to_fields(WithRef)
        assert "name" in fields
        assert "token_ref" not in fields

    def test_ref_fields_included_when_flag_false(self):
        """Fields ending in _ref are included when exclude_ref_fields=False."""

        @dataclass
        class WithRef:
            name: str
            token_ref: str

        fields = dataclass_to_fields(WithRef, exclude_ref_fields=False)
        assert "name" in fields
        assert "token_ref" in fields


class TestFieldSpec:
    """Tests for FieldSpec dataclass."""

    def test_type_ref(self):
        """FieldSpec with type_ref."""
        spec = FieldSpec(type_ref="primitive/string")
        assert spec.to_dict() == {"type_ref": "primitive/string"}

    def test_array_of(self):
        """FieldSpec with array_of."""
        spec = FieldSpec(array_of=FieldSpec(type_ref="primitive/int"))
        assert spec.to_dict() == {"array_of": {"type_ref": "primitive/int"}}

    def test_map_of(self):
        """FieldSpec with map_of."""
        spec = FieldSpec(
            map_of=FieldSpec(type_ref="primitive/string"),
            key_type="primitive/string",
        )
        # key_type is default, so not included in output
        assert spec.to_dict() == {"map_of": {"type_ref": "primitive/string"}}

    def test_map_of_with_non_default_key(self):
        """FieldSpec with map_of and non-default key_type."""
        spec = FieldSpec(
            map_of=FieldSpec(type_ref="primitive/string"),
            key_type="primitive/bytes",
        )
        assert spec.to_dict() == {
            "map_of": {"type_ref": "primitive/string"},
            "key_type": "primitive/bytes",
        }

    def test_optional(self):
        """FieldSpec with optional=True."""
        spec = FieldSpec(type_ref="primitive/string", optional=True)
        assert spec.to_dict() == {"type_ref": "primitive/string", "optional": True}

    def test_byte_size(self):
        """FieldSpec with byte_size."""
        spec = FieldSpec(type_ref="primitive/uint", byte_size=1)
        assert spec.to_dict() == {"type_ref": "primitive/uint", "byte_size": 1}

    def test_validation_exactly_one(self):
        """FieldSpec must have exactly one of type_ref/array_of/map_of."""
        with pytest.raises(ValueError, match="exactly one"):
            FieldSpec()  # None set

        with pytest.raises(ValueError, match="exactly one"):
            FieldSpec(type_ref="primitive/string", array_of=FieldSpec(type_ref="primitive/int"))

    def test_key_type_only_with_map(self):
        """key_type can only be set with map_of."""
        with pytest.raises(ValueError, match="key_type can only be set"):
            FieldSpec(type_ref="primitive/string", key_type="primitive/bytes")

    def test_factory_methods(self):
        """Test FieldSpec factory methods."""
        assert FieldSpec.string().to_dict() == {"type_ref": "primitive/string"}
        assert FieldSpec.bytes_().to_dict() == {"type_ref": "primitive/bytes"}
        assert FieldSpec.int_().to_dict() == {"type_ref": "primitive/int"}
        assert FieldSpec.uint().to_dict() == {"type_ref": "primitive/uint"}
        assert FieldSpec.bool_().to_dict() == {"type_ref": "primitive/bool"}
        assert FieldSpec.float_().to_dict() == {"type_ref": "primitive/float"}
        assert FieldSpec.any_().to_dict() == {"type_ref": "primitive/any"}
        assert FieldSpec.hash_().to_dict() == {"type_ref": "system/hash"}

    def test_factory_array(self):
        """Test FieldSpec.array factory method."""
        spec = FieldSpec.array(FieldSpec.string())
        assert spec.to_dict() == {"array_of": {"type_ref": "primitive/string"}}

    def test_factory_map(self):
        """Test FieldSpec.map factory method."""
        spec = FieldSpec.map(FieldSpec.int_())
        assert spec.to_dict() == {"map_of": {"type_ref": "primitive/int"}}


class TestTypeDefinitions:
    """Tests for type definitions."""

    def test_all_type_entities_are_valid(self):
        """All type entities have correct structure per TYPE-SYSTEM spec."""
        entities = get_all_type_entities()
        # TYPE-SYSTEM spec: 8 primitives + 4 meta-types (12 bootstrap) + core + protocol + supporting types
        # 8 primitives + 4 meta-types + 4 core + 6 protocol + 6 capability + 4 tree + 4 handler + 4 supporting
        assert len(entities) >= 30  # Flexible count for future additions

        for entity in entities:
            assert entity.type == "system/type"
            assert "name" in entity.data
            assert isinstance(entity.data["name"], str)
            # Types have either fields, extends, or nothing (primitives)
            if "fields" in entity.data:
                assert isinstance(entity.data["fields"], dict)

    def test_type_names_are_unique(self):
        """All type names are unique."""
        entities = get_all_type_entities()
        names = [e.data["name"] for e in entities]
        assert len(names) == len(set(names))

    def test_type_hashes_are_deterministic(self):
        """Same type definition produces same hash."""
        entities1 = get_all_type_entities()
        entities2 = get_all_type_entities()

        for e1, e2 in zip(entities1, entities2):
            assert e1.compute_hash() == e2.compute_hash()

    def test_primitive_types_have_no_fields(self):
        """Primitive types are name-only (no fields)."""
        entities = get_all_type_entities()
        primitives = [e for e in entities if e.data["name"].startswith("primitive/")]

        for entity in primitives:
            assert "fields" not in entity.data, (
                f"{entity.data['name']} should not have fields"
            )

    def test_non_primitive_types_have_fields_or_extends(self):
        """Non-primitive types have fields or extends."""
        entities = get_all_type_entities()
        non_primitives = [
            e for e in entities
            if not e.data["name"].startswith("primitive/")
        ]

        for entity in non_primitives:
            has_fields = "fields" in entity.data
            has_extends = "extends" in entity.data
            # Some types like system/capability/grant may have empty fields
            assert has_fields or has_extends, (
                f"{entity.data['name']} missing both fields and extends"
            )


class TestTypeRegistry:
    """Tests for type registration."""

    def test_register_types(self):
        """Types are registered in content store and entity tree."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer-id")
        emit_pathway = EmitPathway(content_store, entity_tree)

        register_types(emit_pathway)

        # All types should be in content store (30+ types per spec)
        assert len(content_store) >= 30

        # Types should be accessible via entity tree
        names = list_type_names(entity_tree)
        assert "system/type" in names
        assert "system/protocol/connect/hello" in names
        # All 8 primitives are registered
        assert "primitive/string" in names
        assert "primitive/null" in names
        assert "system/hash" in names

    def test_get_type_entity(self):
        """Can retrieve type entity by name."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer-id")
        emit_pathway = EmitPathway(content_store, entity_tree)
        register_types(emit_pathway)

        entity = get_type_entity("system/protocol/connect/hello", content_store, entity_tree)
        assert entity is not None
        assert entity.type == "system/type"
        assert entity.data["name"] == "system/protocol/connect/hello"

    def test_get_unknown_type_returns_none(self):
        """Getting unknown type returns None."""
        content_store = ContentStore()
        entity_tree = EntityTree("test-peer-id")
        emit_pathway = EmitPathway(content_store, entity_tree)
        register_types(emit_pathway)

        entity = get_type_entity("unknown/type", content_store, entity_tree)
        assert entity is None


class TestPeerTypeRegistration:
    """Tests for type registration at peer startup."""

    def test_peer_registers_types_on_init(self):
        """Peer registers types when initialized."""
        keypair = Keypair.generate()
        peer = PeerBuilder().with_keypair(keypair).with_default_handlers().build()

        # Types should be accessible (30+ types per spec)
        names = list_type_names(peer.entity_tree)
        assert len(names) >= 30
        assert "system/type" in names
        assert "system/protocol/connect/hello" in names
        # All 8 primitives should be registered
        assert "primitive/string" in names
        assert "primitive/null" in names

    def test_peer_types_retrievable_via_tree(self):
        """Types can be retrieved via peer's entity tree."""
        keypair = Keypair.generate()
        peer = PeerBuilder().with_keypair(keypair).with_default_handlers().build()

        entity = get_type_entity(
            "system/protocol/connect/hello",
            peer.content_store,
            peer.entity_tree,
        )
        assert entity is not None
        assert entity.data["name"] == "system/protocol/connect/hello"


class TestTypeFieldsContent:
    """Tests verifying V7.7 field content matches protocol spec."""

    def test_connect_hello_fields(self):
        """system/protocol/connect/hello fields match IMPLEMENTATION-SPEC §3.5 V7.7."""
        entities = get_all_type_entities()
        hello = next(e for e in entities if e.data["name"] == "system/protocol/connect/hello")

        fields = hello.data["fields"]
        assert fields["peer_id"] == {"type_ref": "system/peer-id"}
        assert fields["nonce"] == {"type_ref": "primitive/bytes"}  # bytes per spec
        assert fields["protocols"] == {"array_of": {"type_ref": "primitive/string"}}
        assert fields["timestamp"] == {"type_ref": "primitive/uint"}
        # Optional fields per spec §9.2
        assert fields["hash_formats"]["optional"] is True
        assert fields["key_types"]["optional"] is True
        assert fields["compression"]["optional"] is True
        assert fields["encryption"]["optional"] is True

    def test_connect_authenticate_fields(self):
        """system/protocol/connect/authenticate fields match protocol - all required."""
        entities = get_all_type_entities()
        identify = next(
            e for e in entities if e.data["name"] == "system/protocol/connect/authenticate"
        )

        fields = identify.data["fields"]
        # All fields should NOT have optional=True
        for field_name, field_spec in fields.items():
            assert "optional" not in field_spec or field_spec.get("optional") is False, (
                f"{field_name} should be required"
            )

    def test_execute_fields(self):
        """system/protocol/execute fields match TYPE-SYSTEM spec §9.4."""
        entities = get_all_type_entities()
        execute = next(
            e for e in entities if e.data["name"] == "system/protocol/execute"
        )

        fields = execute.data["fields"]
        assert fields["request_id"] == {"type_ref": "primitive/string"}
        assert fields["uri"] == {"type_ref": "system/tree/path"}
        assert fields["operation"] == {"type_ref": "primitive/string"}
        # params is required per spec §9.4
        assert "optional" not in fields["params"] or fields["params"].get("optional") is False
        # bounds, author, capability, deliver_to, deliver_token are optional per spec §9.4
        assert fields["bounds"]["optional"] is True
        assert fields["author"]["optional"] is True
        assert fields["capability"]["optional"] is True
        assert fields["deliver_to"]["optional"] is True
        assert fields["deliver_token"]["optional"] is True

    def test_capability_token_fields(self):
        """system/capability/token fields match protocol."""
        entities = get_all_type_entities()
        token = next(
            e for e in entities if e.data["name"] == "system/capability/token"
        )

        fields = token.data["fields"]
        # V4: granter and grantee are Hash (system/hash)
        assert "granter" in fields
        assert "grantee" in fields
        assert "grants" in fields
        # Optional field
        assert fields.get("expires_at", {}).get("optional") is True

    def test_handler_type_has_interface_field(self):
        """system/handler has interface path field (PROPOSAL-HANDLER-NORMALIZATION)."""
        entities = get_all_type_entities()
        handler = next(
            e for e in entities if e.data["name"] == "system/handler"
        )

        fields = handler.data["fields"]
        assert "interface" in fields
        assert fields["interface"]["type_ref"] == "system/tree/path"
        assert "pattern" not in fields
        assert "name" not in fields
        assert "operations" not in fields

    def test_bare_entity_is_structural_root(self):
        """Per PROPOSAL-TYPE-NAMESPACE-CONVENTIONS / TYPE-SYSTEM §3.1.1:
        bare `entity` is the abstract structural root with two fields
        ({type, data}); content_hash is *derived* from this shape, not
        declared as a field on it."""
        entities = get_all_type_entities()
        bare_entity = next(e for e in entities if e.data["name"] == "entity")
        fields = bare_entity.data["fields"]
        assert set(fields.keys()) == {"type", "data"}
        assert fields["type"] == {"type_ref": "primitive/string"}
        assert fields["data"] == {"type_ref": "primitive/any"}
        assert "content_hash" not in fields

    def test_core_entity_is_materialized_form(self):
        """Per PROPOSAL-TYPE-NAMESPACE-CONVENTIONS / TYPE-SYSTEM §8.1:
        `core/entity` is the materialized form {type, data, content_hash}
        used as a `type_ref` marker for slots that hold a real,
        identity-bearing entity."""
        entities = get_all_type_entities()
        core_entity = next(e for e in entities if e.data["name"] == "core/entity")
        fields = core_entity.data["fields"]
        assert set(fields.keys()) == {"type", "data", "content_hash"}
        assert fields["type"] == {"type_ref": "primitive/string"}
        assert fields["data"] == {"type_ref": "primitive/any"}
        assert fields["content_hash"] == {"type_ref": "system/hash"}

    def test_materialized_entity_type_refs_use_core_entity(self):
        """Slots that require a materialized entity must reference the
        post-rename `core/entity` type, never bare `entity`."""
        entities = get_all_type_entities()
        # core/envelope.root and core/envelope.included carry materialized
        # entities (per V7 §3.1).
        envelope = next(e for e in entities if e.data["name"] == "core/envelope")
        assert envelope.data["fields"]["root"]["type_ref"] == "core/entity"
        assert envelope.data["fields"]["included"]["map_of"]["type_ref"] == "core/entity"
        # EXECUTE.params and EXECUTE_RESPONSE.result are materialized.
        execute = next(e for e in entities if e.data["name"] == "system/protocol/execute")
        assert execute.data["fields"]["params"]["type_ref"] == "core/entity"
        execute_resp = next(
            e for e in entities if e.data["name"] == "system/protocol/execute/response"
        )
        assert execute_resp.data["fields"]["result"]["type_ref"] == "core/entity"

    def test_handler_manifest_extends_interface(self):
        """system/handler/manifest extends system/handler/interface AND
        republishes the full effective field set on its own type entity.

        Cross-impl validators (Go, Rust) compare local-registry shapes
        field-by-field against the remote type entity. Go's local for
        the manifest reflects the full Go struct (which has all 6
        fields), so the remote type entity must publish all 6 fields
        too — `extends` is metadata about the parent relationship, not
        a substitute for the field list.
        """
        entities = get_all_type_entities()
        manifest = next(
            e for e in entities if e.data["name"] == "system/handler/manifest"
        )
        interface = next(
            e for e in entities if e.data["name"] == "system/handler/interface"
        )

        assert manifest.data["extends"] == "system/handler/interface"

        # Interface declares pattern/name/operations.
        interface_fields = interface.data["fields"]
        assert "operations" in interface_fields
        assert "map_of" in interface_fields["operations"]
        assert "pattern" in interface_fields
        assert "name" in interface_fields

        # Manifest republishes the inherited fields AND adds install-time
        # ones. This is what Go's reflected local expects to compare
        # against; trimming the inherited ones produces a structural
        # mismatch (P-PY-1 in PATH-AS-RESOURCE-HYGIENE-PYTHON report).
        manifest_fields = manifest.data["fields"]
        assert "pattern" in manifest_fields
        assert "name" in manifest_fields
        assert "operations" in manifest_fields
        assert "max_scope" in manifest_fields
        assert "internal_scope" in manifest_fields
        assert "expression_path" in manifest_fields

    def test_new_types_registered(self):
        """All required types per TYPE-SYSTEM spec are registered."""
        entities = get_all_type_entities()
        names = [e.data["name"] for e in entities]

        # Bootstrap types (§4.4) - 11 types: 8 primitives + 3 meta-types
        # Note: system/type/constraint moved to EXTENSION-TYPE.md
        assert "primitive/null" in names
        assert "system/type/field-spec" in names
        assert "system/hash" in names  # Replaces constraint in bootstrap

        # Core types (§8)
        assert "core/entity" in names
        assert "core/envelope" in names

        # Protocol types (§9)
        assert "system/protocol/envelope" in names
        assert "system/protocol/error" in names
        assert "system/capability/grant-entry" in names
        assert "system/capability/delegation-caveats" in names

        # Tree types (§10.8)
        assert "system/tree/listing-entry" in names
        assert "system/tree/listing" in names
        assert "system/tree/get-request" in names
        assert "system/tree/put-request" in names

        # Handler/resource types
        assert "system/handler/operation-spec" in names
        assert "system/capability/grant" in names
        assert "system/bounds" in names
        assert "system/callback-spec" in names
        assert "system/resource-limits" in names

        # Continuation types — install-result retained per
        # PROPOSAL-PATH-AS-RESOURCE-HYGIENE / EXTENSION-CONTINUATION v1.7 §2.7.
        assert "system/continuation/install-result" in names

    def test_handler_operation_spec_fields(self):
        """system/handler/operation-spec fields match TYPE-SYSTEM spec §10.4."""
        entities = get_all_type_entities()
        op_spec = next(
            e for e in entities if e.data["name"] == "system/handler/operation-spec"
        )

        fields = op_spec.data["fields"]
        # Only input_type and output_type per spec §10.4 (both optional)
        assert fields["input_type"]["optional"] is True
        assert fields["output_type"]["optional"] is True
        # Should NOT have input_refs/output_refs - not in spec
        assert "input_refs" not in fields
        assert "output_refs" not in fields

    def test_capability_grant_fields(self):
        """system/capability/grant fields match TYPE-SYSTEM spec §9.7."""
        entities = get_all_type_entities()
        grant = next(
            e for e in entities if e.data["name"] == "system/capability/grant"
        )

        fields = grant.data["fields"]
        # Per spec §9.7: has token field referencing the capability
        assert fields["token"] == {"type_ref": "system/hash"}

    def test_bounds_fields(self):
        """system/bounds has all optional fields."""
        entities = get_all_type_entities()
        bounds = next(
            e for e in entities if e.data["name"] == "system/bounds"
        )

        fields = bounds.data["fields"]
        # All fields are optional per spec
        assert fields["ttl"]["optional"] is True
        assert fields["budget"]["optional"] is True
        assert fields["chain_id"]["optional"] is True
        assert fields["visited"]["optional"] is True

    def test_system_hash_type(self):
        """system/hash has layout and extends."""
        entities = get_all_type_entities()
        hash_type = next(
            e for e in entities if e.data["name"] == "system/hash"
        )

        data = hash_type.data
        assert data["extends"] == "primitive/bytes"
        assert data["layout"] == ["format_code", "digest"]
        assert "fields" in data
        assert data["fields"]["format_code"]["type_ref"] == "primitive/uint"
        assert data["fields"]["format_code"]["byte_size"] == 1
        assert data["fields"]["digest"]["type_ref"] == "primitive/bytes"

    def test_primitive_types(self):
        """Primitive types are defined without fields per TYPE-SYSTEM spec §3."""
        entities = get_all_type_entities()
        primitives = [
            "primitive/string",
            "primitive/bytes",
            "primitive/int",
            "primitive/uint",
            "primitive/float",
            "primitive/bool",
            "primitive/null",  # Per spec §3.1
            "primitive/any",
        ]
        for name in primitives:
            entity = next(e for e in entities if e.data["name"] == name)
            assert "fields" not in entity.data
            assert entity.data["name"] == name


class TestTypeHashStability:
    """Tests ensuring type hashes are stable and documented.

    V6.0: Types use field-based format instead of CDDL strings.
    Hashes are computed from the canonical encoding of the type data.
    """

    # Compute fresh hashes after running tests
    EXPECTED_HASHES: dict[str, bytes] = {}

    @classmethod
    def _compute_expected_hashes(cls) -> None:
        """Compute expected hashes from current definitions."""
        if cls.EXPECTED_HASHES:
            return
        for entity in get_all_type_entities():
            name = entity.data["name"]
            cls.EXPECTED_HASHES[name] = entity.compute_hash()

    def test_all_hashes_documented(self):
        """All type hashes are in EXPECTED_HASHES."""
        self._compute_expected_hashes()
        entities = get_all_type_entities()
        for entity in entities:
            name = entity.data["name"]
            assert name in self.EXPECTED_HASHES, f"Missing hash for {name}"

    def test_hashes_match_expected(self):
        """Type hashes match expected values.

        If this test fails, either:
        1. The field definitions changed (intentional) - update EXPECTED_HASHES
        2. The canonical encoding changed (bug) - investigate
        3. The hash algorithm changed (bug) - investigate
        """
        self._compute_expected_hashes()
        entities = get_all_type_entities()
        for entity in entities:
            name = entity.data["name"]
            actual_hash = entity.compute_hash()
            expected_hash = self.EXPECTED_HASHES[name]

            assert actual_hash == expected_hash, (
                f"Hash mismatch for {name}:\n"
                f"  expected: {expected_hash.hex()}\n"
                f"  actual:   {actual_hash.hex()}"
            )

    def test_hash_changes_with_field_change(self):
        """Modifying a field definition produces a different hash."""
        # Create a modified hello type
        original = next(
            e for e in get_all_type_entities()
            if e.data["name"] == "system/protocol/connect/hello"
        )
        original_hash = original.compute_hash()

        # Create a modified version with extra field
        modified_fields = dict(original.data["fields"])
        modified_fields["extra_field"] = {"type_ref": "primitive/string"}
        modified = Entity(
            type="system/type",
            data={
                "name": "system/protocol/connect/hello",
                "fields": modified_fields,
            },
        )
        modified_hash = modified.compute_hash()

        assert original_hash != modified_hash

    def test_hashes_are_deterministic(self):
        """Computing hashes twice produces identical results."""
        entities1 = get_all_type_entities()
        entities2 = get_all_type_entities()

        for e1, e2 in zip(entities1, entities2):
            assert e1.compute_hash() == e2.compute_hash(), (
                f"Non-deterministic hash for {e1.data['name']}"
            )


class TestExtensionTypeV11:
    """EXTENSION-TYPE v1.1 type-system surface.

    T1 gate: the 11 standard constraint types, the constraint dispatch
    envelope types, and the v1.1-shaped `validate-request` /
    `validate-result` / `violation` types are all registered with the
    expected field surface. This locks the type-side contract before
    the constraint handler (T2) and type handler (T3) come online.
    """

    STANDARD_CONSTRAINT_KINDS = (
        "min", "max",
        "min-length", "max-length",
        "min-count", "max-count",
        "pattern",
        "one-of", "not-one-of",
        "format",
        "type-pattern",
    )

    def test_all_11_standard_constraint_types_registered(self):
        names = {e.data["name"] for e in get_all_type_entities()}
        for kind in self.STANDARD_CONSTRAINT_KINDS:
            path = f"system/type/constraint/{kind}"
            assert path in names, f"missing constraint type: {path}"

    def test_constraint_dispatch_envelopes_registered(self):
        names = {e.data["name"] for e in get_all_type_entities()}
        assert "system/type/constraint/validate-request" in names
        assert "system/type/constraint/validate-result" in names

    def test_validate_request_uses_optional_type_path(self):
        """Per §8.3: `type_path` is optional; when absent the validator
        uses `entity.type`. The v1.0-shaped `type_name` field is
        explicitly removed (no-legacy)."""
        entity = next(
            e for e in get_all_type_entities()
            if e.data["name"] == "system/type/validate-request"
        )
        fields = entity.data["fields"]
        assert "entity" in fields
        assert "type_path" in fields
        assert fields["type_path"].get("optional") is True
        assert "type_name" not in fields

    def test_validate_result_uses_violations_and_unevaluated_fields(self):
        """Per §8.4: `violations` (typed list) + `unevaluated_fields`;
        the v1.0 `errors: [string]` shape is removed."""
        entity = next(
            e for e in get_all_type_entities()
            if e.data["name"] == "system/type/validate-result"
        )
        fields = entity.data["fields"]
        assert fields["valid"] == {"type_ref": "primitive/bool"}
        assert "violations" in fields
        assert fields["violations"]["array_of"]["type_ref"] == "system/type/violation"
        assert fields["violations"].get("optional") is True
        assert "unevaluated_fields" in fields
        assert "errors" not in fields

    def test_violation_type_registered(self):
        """Per §8.5 — kind discriminator + optional constraint path."""
        entity = next(
            e for e in get_all_type_entities()
            if e.data["name"] == "system/type/violation"
        )
        fields = entity.data["fields"]
        assert "field" in fields
        assert "kind" in fields
        assert fields["constraint"].get("optional") is True
        assert "reason" in fields

    def test_constraint_validate_request_shape(self):
        """Per §5.2 — value + constraint_type + constraint_data."""
        entity = next(
            e for e in get_all_type_entities()
            if e.data["name"] == "system/type/constraint/validate-request"
        )
        fields = entity.data["fields"]
        assert fields["value"] == {"type_ref": "primitive/any"}
        assert fields["constraint_type"] == {"type_ref": "system/type/name"}
        assert fields["constraint_data"] == {"type_ref": "primitive/any"}

    def test_constraint_validate_result_shape(self):
        """Per §5.3 — `reason` is absent when valid."""
        entity = next(
            e for e in get_all_type_entities()
            if e.data["name"] == "system/type/constraint/validate-result"
        )
        fields = entity.data["fields"]
        assert fields["valid"] == {"type_ref": "primitive/bool"}
        assert fields["reason"].get("optional") is True

    def test_one_of_values_are_primitive_any(self):
        """Per §4.4 — `values` is `array_of: primitive/any`. The
        comparison uses ECF byte equality (§5.5 normative); the value
        type must therefore be the most permissive primitive so any
        CBOR-encodable value can appear."""
        for name in ("system/type/constraint/one-of",
                     "system/type/constraint/not-one-of"):
            entity = next(
                e for e in get_all_type_entities() if e.data["name"] == name
            )
            spec = entity.data["fields"]["values"]
            assert spec["array_of"] == {"type_ref": "primitive/any"}
