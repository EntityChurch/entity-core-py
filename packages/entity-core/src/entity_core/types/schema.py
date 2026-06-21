"""Dataclass to CDDL, JSON Schema, and V6.0 field-spec conversion.

Converts Python dataclasses to type definitions for the type system.
Supports multiple output formats:
- CDDL (Concise Data Definition Language) - legacy format
- JSON Schema - legacy format
- V6.0 field-based format - current spec format

V6.0 field-spec type mapping:
- str -> {"type_ref": "primitive/string"}
- bytes -> {"type_ref": "primitive/bytes"}
- int -> {"type_ref": "primitive/int"}
- Uint -> {"type_ref": "primitive/uint"}
- float -> {"type_ref": "primitive/float"}
- bool -> {"type_ref": "primitive/bool"}
- Any -> {"type_ref": "primitive/any"}
- Hash (bytes) -> {"type_ref": "system/hash"}
- list[T] -> {"array_of": <T spec>}
- dict[K, V] -> {"map_of": <V spec>, "key_type": <K spec>}
- Optional[T] -> <T spec> + "optional": true

CDDL type mapping (ECF-CDDL canonical format, legacy):
- str -> tstr
- int -> int
- Uint -> uint
- float -> float64
- bool -> bool
- None -> null
- list -> [* any]
- list[T] -> [* T_cddl]
- dict -> {* tstr => any}
- Any -> any
- Optional[T] -> T_cddl (optionality via ? prefix at field level)
- Dataclass -> {field1: type1, ? opt_field: type2, * tstr => any}
"""

from __future__ import annotations

import dataclasses
import types
from typing import Any, Union, get_args, get_origin, get_type_hints

from entity_core.primitives import Uint, TreePath, TypeName, PeerId, WireBytes
from entity_core.types.field_spec import FieldSpec


# =============================================================================
# V6.0 Field-Spec Generation
# =============================================================================


def _is_union_type(py_type: type) -> bool:
    """Check if type is a Union (including types.UnionType from X | Y syntax)."""
    origin = get_origin(py_type)
    if origin is Union:
        return True
    # Python 3.10+ uses types.UnionType for X | Y syntax
    return isinstance(py_type, types.UnionType)


def _is_hash_type(py_type: type) -> bool:
    """Check if type is the Hash type alias (bytes from ecf.py)."""
    # Hash is defined as `Hash = bytes` in ecf.py
    # We check for the Hash annotation by looking at the module
    if py_type is bytes:
        # Could be either bytes or Hash - we'll treat as bytes
        # Caller needs to check type hints for "Hash" annotation
        return False
    return False


def _unwrap_optional(py_type: type) -> tuple[type, bool]:
    """Unwrap Optional[T] or T | None to (T, is_optional).

    Args:
        py_type: A Python type annotation.

    Returns:
        Tuple of (inner_type, is_optional).
    """
    if not _is_union_type(py_type):
        return py_type, False

    args = get_args(py_type)
    non_none_args = [arg for arg in args if arg is not type(None)]

    if len(non_none_args) == 1 and type(None) in args:
        # Optional[T] or T | None
        return non_none_args[0], True

    # Not a simple Optional - could be Union of multiple types
    return py_type, False


def python_type_to_field_spec(
    py_type: type,
    optional: bool = False,
    type_hint_name: str | None = None,
) -> FieldSpec:
    """Convert a Python type annotation to V6.0 FieldSpec.

    Args:
        py_type: A Python type annotation (str, int, list[T], Optional[T], etc.)
        optional: Whether this field is optional (from default value).
        type_hint_name: Original type hint name (e.g., "Hash") for alias detection.

    Returns:
        FieldSpec representing the type in V6.0 format.
    """
    # Handle Optional[T] / T | None - unwrap and set optional
    inner_type, is_optional_type = _unwrap_optional(py_type)
    if is_optional_type:
        return python_type_to_field_spec(
            inner_type,
            optional=True,
            type_hint_name=type_hint_name,
        )

    # Check if this is a Hash type alias (bytes used for hashes)
    # We detect Hash by checking the type_hint_name passed from caller
    if type_hint_name == "Hash" or (
        hasattr(py_type, "__name__") and py_type.__name__ == "Hash"
    ):
        return FieldSpec(type_ref="system/hash", optional=optional)

    # Handle None type
    if py_type is type(None):
        # null isn't a primitive in V6.0, treat as any
        return FieldSpec(type_ref="primitive/any", optional=True)

    # Handle basic types
    if py_type is str:
        return FieldSpec(type_ref="primitive/string", optional=optional)
    if py_type is bytes:
        return FieldSpec(type_ref="primitive/bytes", optional=optional)
    if py_type is int:
        return FieldSpec(type_ref="primitive/int", optional=optional)
    if py_type is float:
        return FieldSpec(type_ref="primitive/float", optional=optional)
    if py_type is bool:
        return FieldSpec(type_ref="primitive/bool", optional=optional)

    # Handle Any
    if py_type is Any:
        return FieldSpec(type_ref="primitive/any", optional=optional)

    # Handle bare list (no type parameters)
    if py_type is list:
        return FieldSpec(
            array_of=FieldSpec(type_ref="primitive/any"),
            optional=optional,
        )

    # Handle bare dict (no type parameters)
    if py_type is dict:
        return FieldSpec(
            map_of=FieldSpec(type_ref="primitive/any"),
            key_type="primitive/string",
            optional=optional,
        )

    # Handle NewType semantic types
    if hasattr(py_type, "__supertype__"):
        type_name = getattr(py_type, "__name__", "")
        if py_type.__supertype__ is int and type_name == "Uint":
            return FieldSpec(type_ref="primitive/uint", optional=optional)
        if py_type.__supertype__ is str:
            if type_name == "TreePath":
                return FieldSpec(type_ref="system/tree/path", optional=optional)
            if type_name == "TypeName":
                return FieldSpec(type_ref="system/type/name", optional=optional)
            if type_name == "PeerId":
                return FieldSpec(type_ref="system/peer-id", optional=optional)
            if type_name == "WireBytes":
                return FieldSpec(type_ref="primitive/bytes", optional=optional)

    # Handle dataclasses - use TYPE_NAME if available, otherwise fall back to any
    if dataclasses.is_dataclass(py_type) and isinstance(py_type, type):
        type_name = getattr(py_type, "TYPE_NAME", None)
        if type_name:
            return FieldSpec(type_ref=type_name, optional=optional)
        # No TYPE_NAME - fall back to any
        return FieldSpec(type_ref="primitive/any", optional=optional)

    # Get the origin for generic types (list, dict, Union, etc.)
    origin = get_origin(py_type)
    args = get_args(py_type)

    # Handle list/List types
    if origin is list:
        if args:
            item_spec = python_type_to_field_spec(args[0])
            return FieldSpec(array_of=item_spec, optional=optional)
        # Untyped list -> array of any
        return FieldSpec(
            array_of=FieldSpec(type_ref="primitive/any"),
            optional=optional,
        )

    # Handle dict/Dict types
    if origin is dict:
        if args and len(args) >= 2:
            # dict[K, V]
            key_type = args[0]
            value_type = args[1]
            value_spec = python_type_to_field_spec(value_type)

            # Determine key_type string
            if key_type is str:
                key_type_str = "primitive/string"
            elif key_type is bytes:
                key_type_str = "primitive/bytes"
            elif key_type is int:
                key_type_str = "primitive/int"
            else:
                key_type_str = "primitive/string"  # default

            return FieldSpec(
                map_of=value_spec,
                key_type=key_type_str,
                optional=optional,
            )
        # Untyped dict -> map of any
        return FieldSpec(
            map_of=FieldSpec(type_ref="primitive/any"),
            key_type="primitive/string",
            optional=optional,
        )

    # Handle Union with multiple non-None types as any
    if _is_union_type(py_type):
        return FieldSpec(type_ref="primitive/any", optional=optional)

    # Default to any for complex types
    return FieldSpec(type_ref="primitive/any", optional=optional)


def _get_type_hint_name(cls: type, field_name: str) -> str | None:
    """Get the original type hint name from annotations.

    This is used to detect type aliases like Hash = bytes.

    Args:
        cls: The dataclass type.
        field_name: The field name to look up.

    Returns:
        The annotation string if available, None otherwise.
    """
    annotations = getattr(cls, "__annotations__", {})
    hint = annotations.get(field_name)
    if isinstance(hint, str):
        return hint
    if hasattr(hint, "__name__"):
        return hint.__name__
    # For forward references or complex types
    if hasattr(hint, "__origin__"):
        return None
    return str(hint) if hint else None


def dataclass_to_fields(cls: type, exclude_ref_fields: bool = True) -> dict[str, dict[str, Any]]:
    """Convert a dataclass to V6.0 fields dict.

    Args:
        cls: A dataclass type to convert.
        exclude_ref_fields: If True, exclude fields ending in '_ref'.

    Returns:
        Dictionary mapping field names to V6.0 field specs.

    Raises:
        ValueError: If cls is not a dataclass.
    """
    if not dataclasses.is_dataclass(cls):
        raise ValueError(f"{cls} is not a dataclass")

    type_hints = get_type_hints(cls)
    fields: dict[str, dict[str, Any]] = {}

    for fld in dataclasses.fields(cls):
        # Skip ref fields by default
        if exclude_ref_fields and _is_ref_field(fld.name):
            continue

        # Get resolved type from type hints
        field_type = type_hints.get(fld.name, fld.type)

        # Get original annotation name for alias detection
        type_hint_name = _get_type_hint_name(cls, fld.name)

        # Determine if field is optional (has default or is Optional type)
        is_optional = (
            fld.default is not dataclasses.MISSING
            or fld.default_factory is not dataclasses.MISSING
        )
        # Also check if type is Optional (Union[T, None] or T | None)
        if _is_union_type(field_type):
            args = get_args(field_type)
            if type(None) in args:
                is_optional = True

        spec = python_type_to_field_spec(
            field_type,
            optional=is_optional,
            type_hint_name=type_hint_name,
        )
        fields[fld.name] = spec.to_dict()

    return fields


# =============================================================================
# Legacy JSON Schema Generation
# =============================================================================


def _is_ref_field(field_name: str) -> bool:
    """Check if a field is a reference field (excluded from data schema).

    Convention: fields ending in '_ref' are entity references that go in
    the refs section, not the data section.
    """
    return field_name.endswith("_ref")


def python_type_to_schema(py_type: type, exclude_ref_fields: bool = True) -> dict[str, Any]:
    """Convert a Python type annotation to JSON Schema.

    Args:
        py_type: A Python type (str, int, list[T], Optional[T], dataclass, etc.)
        exclude_ref_fields: If True, exclude fields ending in '_ref' for dataclasses.

    Returns:
        JSON Schema dictionary for the type.
    """
    # Handle None type
    if py_type is type(None):
        return {"type": "null"}

    # Handle basic types first (before checking generics)
    if py_type is str:
        return {"type": "string"}
    if py_type is int:
        return {"type": "integer"}
    if py_type is float:
        return {"type": "number"}
    if py_type is bool:
        return {"type": "boolean"}
    if py_type is list:
        return {"type": "array"}
    if py_type is dict:
        return {"type": "object", "additionalProperties": True}

    # Handle Any
    if py_type is Any:
        return {}

    # Handle dataclasses - recursively generate full schema
    if dataclasses.is_dataclass(py_type) and isinstance(py_type, type):
        return _dataclass_to_schema_internal(py_type, exclude_ref_fields)

    # Get the origin for generic types (list, dict, Union, etc.)
    origin = get_origin(py_type)
    args = get_args(py_type)

    # Handle Union types (including Optional[T] which is Union[T, None])
    # Also handles X | Y syntax from Python 3.10+
    if _is_union_type(py_type):
        # Filter out NoneType to get the actual types
        non_none_args = [arg for arg in args if arg is not type(None)]
        if len(non_none_args) == 1:
            # Optional[T] case - just return schema for T
            return python_type_to_schema(non_none_args[0], exclude_ref_fields)
        # Multiple types - not supported in our subset
        return {"type": "object", "additionalProperties": True}

    # Handle list/List types
    if origin is list:
        if args:
            return {"type": "array", "items": python_type_to_schema(args[0], exclude_ref_fields)}
        return {"type": "array"}

    # Handle dict/Dict types
    if origin is dict:
        return {"type": "object", "additionalProperties": True}

    # Default to object for complex types
    return {"type": "object", "additionalProperties": True}


def _dataclass_to_schema_internal(cls: type, exclude_ref_fields: bool = True) -> dict[str, Any]:
    """Internal helper to convert a dataclass to JSON Schema.

    This is used by python_type_to_schema for nested dataclasses.

    Args:
        cls: A dataclass type to convert.
        exclude_ref_fields: If True, exclude fields ending in '_ref'.

    Returns:
        JSON Schema dictionary representing the dataclass structure.
    """
    properties: dict[str, Any] = {}
    required: list[str] = []

    # Use get_type_hints to resolve string annotations (from __future__ import annotations)
    type_hints = get_type_hints(cls)

    for fld in dataclasses.fields(cls):
        # Skip ref fields - they go in refs, not data
        if exclude_ref_fields and _is_ref_field(fld.name):
            continue

        # Get resolved type from type hints
        field_type = type_hints.get(fld.name, fld.type)
        field_schema = python_type_to_schema(field_type, exclude_ref_fields)
        properties[fld.name] = field_schema

        # Determine if field is required
        # A field is optional if:
        # - It has a default value
        # - It has a default_factory
        # - Its type is Optional (Union with None)
        is_optional = (
            fld.default is not dataclasses.MISSING
            or fld.default_factory is not dataclasses.MISSING
        )

        # Also check if type is Optional (Union[T, None] or T | None)
        if _is_union_type(field_type):
            args = get_args(field_type)
            if type(None) in args:
                is_optional = True

        if not is_optional:
            required.append(fld.name)

    return {
        "type": "object",
        "required": sorted(required),
        "additionalProperties": True,
        "properties": properties,
    }


def dataclass_to_schema(cls: type, exclude_ref_fields: bool = True) -> dict[str, Any]:
    """Convert a dataclass to JSON Schema.

    Args:
        cls: A dataclass type to convert.
        exclude_ref_fields: If True, exclude fields ending in '_ref' (default True).
            These are entity references that go in refs, not data.

    Returns:
        JSON Schema dictionary representing the dataclass structure.

    Raises:
        ValueError: If cls is not a dataclass.
    """
    if not dataclasses.is_dataclass(cls):
        raise ValueError(f"{cls} is not a dataclass")

    return _dataclass_to_schema_internal(cls, exclude_ref_fields)


def build_schema(
    properties: dict[str, dict[str, Any]],
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Build a JSON Schema from explicit properties.

    This is the primary way to define type schemas - explicit property
    definitions rather than deriving from dataclasses.

    Args:
        properties: Dictionary mapping field names to their JSON Schema.
        required: List of required field names. If None, all properties are optional.

    Returns:
        JSON Schema dictionary with additionalProperties: true.
    """
    return {
        "type": "object",
        "required": sorted(required) if required else [],
        "additionalProperties": True,
        "properties": properties,
    }


# =============================================================================
# CDDL Type Generation
# =============================================================================


def python_type_to_cddl(py_type: type, exclude_ref_fields: bool = True) -> str:
    """Convert a Python type annotation to CDDL string.

    Args:
        py_type: A Python type (str, int, Uint, list[T], Optional[T], dataclass, etc.)
        exclude_ref_fields: If True, exclude fields ending in '_ref' for dataclasses.

    Returns:
        CDDL type string for the type.
    """
    # Handle None type
    if py_type is type(None):
        return "null"

    # Handle basic types first (before checking generics)
    if py_type is str:
        return "tstr"
    if py_type is int:
        return "int"
    if py_type is float:
        return "float64"
    if py_type is bool:
        return "bool"
    if py_type is list:
        return "[* any]"
    if py_type is dict:
        return "{* tstr => any}"

    # Handle Any
    if py_type is Any:
        return "any"

    # Handle Uint (NewType)
    if hasattr(py_type, "__supertype__") and py_type.__supertype__ is int:
        if getattr(py_type, "__name__", "") == "Uint":
            return "uint"

    # Handle dataclasses - recursively generate full CDDL
    if dataclasses.is_dataclass(py_type) and isinstance(py_type, type):
        return dataclass_to_cddl(py_type, exclude_ref_fields)

    # Get the origin for generic types (list, dict, Union, etc.)
    origin = get_origin(py_type)
    args = get_args(py_type)

    # Handle Union types (including Optional[T] which is Union[T, None])
    # Also handles X | Y syntax from Python 3.10+
    if _is_union_type(py_type):
        # Filter out NoneType to get the actual types
        non_none_args = [arg for arg in args if arg is not type(None)]
        if len(non_none_args) == 1:
            # Optional[T] case - just return CDDL for T
            return python_type_to_cddl(non_none_args[0], exclude_ref_fields)
        # Multiple non-None types - use any
        return "any"

    # Handle list/List types
    if origin is list:
        if args:
            return f"[* {python_type_to_cddl(args[0], exclude_ref_fields)}]"
        return "[* any]"

    # Handle dict/Dict types
    if origin is dict:
        return "{* tstr => any}"

    # Default to any for complex types
    return "any"


def dataclass_to_cddl(cls: type, exclude_ref_fields: bool = True) -> str:
    """Convert a dataclass to CDDL type definition string.

    Per spec Section 7.4, all Entity types are "open types" allowing
    additional properties via `* tstr => any`.

    Args:
        cls: A dataclass type to convert.
        exclude_ref_fields: If True, exclude fields ending in '_ref'.

    Returns:
        CDDL type definition string.

    Raises:
        ValueError: If cls is not a dataclass.
    """
    if not dataclasses.is_dataclass(cls):
        raise ValueError(f"{cls} is not a dataclass")

    type_hints = get_type_hints(cls)
    required_fields: list[tuple[str, str]] = []
    optional_fields: list[tuple[str, str]] = []

    for fld in dataclasses.fields(cls):
        # Skip ref fields - they go in refs, not data
        if exclude_ref_fields and _is_ref_field(fld.name):
            continue

        # Get resolved type from type hints
        field_type = type_hints.get(fld.name, fld.type)
        cddl_type = python_type_to_cddl(field_type, exclude_ref_fields)

        # Determine if field is required
        is_optional = (
            fld.default is not dataclasses.MISSING
            or fld.default_factory is not dataclasses.MISSING
        )

        # Also check if type is Optional (Union[T, None] or T | None)
        if _is_union_type(field_type):
            args = get_args(field_type)
            if type(None) in args:
                is_optional = True

        if is_optional:
            optional_fields.append((fld.name, cddl_type))
        else:
            required_fields.append((fld.name, cddl_type))

    # Sort alphabetically within each group
    required_fields.sort(key=lambda x: x[0])
    optional_fields.sort(key=lambda x: x[0])

    # Build CDDL string with canonical formatting
    lines = ["{"]
    for name, cddl_type in required_fields:
        lines.append(f"  {name}: {cddl_type},")
    for name, cddl_type in optional_fields:
        lines.append(f"  ? {name}: {cddl_type},")
    lines.append("  * tstr => any")
    lines.append("}")

    return "\n".join(lines)


def build_cddl(
    fields: dict[str, str],
    required: list[str] | None = None,
) -> str:
    """Build a CDDL type definition from explicit field types.

    Args:
        fields: Dictionary mapping field names to their CDDL type strings.
        required: List of required field names. If None, all fields are optional.

    Returns:
        CDDL type definition string with canonical formatting.
    """
    required = required or []

    required_fields = [(k, v) for k, v in sorted(fields.items()) if k in required]
    optional_fields = [(k, v) for k, v in sorted(fields.items()) if k not in required]

    lines = ["{"]
    for name, cddl_type in required_fields:
        lines.append(f"  {name}: {cddl_type},")
    for name, cddl_type in optional_fields:
        lines.append(f"  ? {name}: {cddl_type},")
    lines.append("  * tstr => any")
    lines.append("}")

    return "\n".join(lines)
