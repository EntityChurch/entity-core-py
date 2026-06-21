"""Type system for Entity Core Protocol.

This module provides V6.0 field-based type definitions for all core protocol types.
Types are content-addressed - same definition produces the same hash, enabling
cross-validation between implementations.

V6.0: Types use `fields` dict instead of CDDL `schema` strings.

Usage:
    from entity_core.types import register_types, get_type_entity

    # At peer startup
    register_types(emit_pathway)

    # To fetch a type definition
    type_entity = get_type_entity("system/protocol/hello", content_store, entity_tree)

    # Convert a dataclass to V6.0 fields
    from entity_core.types import dataclass_to_fields, FieldSpec
    fields = dataclass_to_fields(MyDataclass)
"""

from entity_core.primitives import Uint
from entity_core.types.canonical import CORE_TYPE_PATHS
from entity_core.types.definitions import get_all_type_entities
from entity_core.types.field_spec import FieldSpec
from entity_core.types.registry import get_type_entity, list_type_names, register_types
from entity_core.types.schema import (
    build_cddl,
    build_schema,
    dataclass_to_cddl,
    dataclass_to_fields,
    dataclass_to_schema,
    python_type_to_cddl,
    python_type_to_field_spec,
    python_type_to_schema,
)

__all__ = [
    # V6.0 field-based exports
    "FieldSpec",
    "dataclass_to_fields",
    "python_type_to_field_spec",
    # Primitives
    "Uint",
    # Canonical spec-pinned core type paths (TYPE-SYSTEM §3-§10)
    "CORE_TYPE_PATHS",
    # Registry
    "get_all_type_entities",
    "get_type_entity",
    "list_type_names",
    "register_types",
    # Legacy CDDL/JSON Schema exports (for backward compatibility)
    "build_cddl",
    "build_schema",
    "dataclass_to_cddl",
    "dataclass_to_schema",
    "python_type_to_cddl",
    "python_type_to_schema",
]
