"""V6.0 Field specification for type definitions.

Provides a type-safe way to define field specifications that convert
to the V6.0 wire format. Each field has exactly one of: type_ref, array_of, or map_of.

Field wire format per V6.0 spec:
- type_ref: Reference to a type (e.g., "primitive/string", "system/hash")
- array_of: Nested field spec for array items
- map_of: Nested field spec for map values
- key_type: Map key type (default: "primitive/string")
- optional: True if field can be omitted
- byte_size: Fixed byte size for binary types
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FieldSpec:
    """V6.0 field specification - exactly one of type_ref/array_of/map_of.

    This dataclass provides type-safe construction of field specs that
    serialize to the V6.0 wire format.

    Attributes:
        type_ref: Reference to a named type (e.g., "primitive/string").
        array_of: Nested FieldSpec for array item type.
        map_of: Nested FieldSpec for map value type.
        key_type: Map key type (default: "primitive/string", only for map_of).
        optional: True if the field is optional (can be omitted).
        byte_size: Fixed byte size (for binary types like format_code).
    """

    type_ref: str | None = None
    array_of: FieldSpec | None = None
    map_of: FieldSpec | None = None
    key_type: str | None = None
    optional: bool = False
    byte_size: int | None = None

    def __post_init__(self) -> None:
        """Validate that exactly one of type_ref/array_of/map_of is set."""
        set_count = sum([
            self.type_ref is not None,
            self.array_of is not None,
            self.map_of is not None,
        ])
        if set_count != 1:
            raise ValueError(
                "FieldSpec must have exactly one of: type_ref, array_of, map_of. "
                f"Got {set_count} set."
            )
        if self.key_type is not None and self.map_of is None:
            raise ValueError("key_type can only be set when map_of is set")

    def to_dict(self) -> dict[str, Any]:
        """Convert to V6.0 wire format, omitting unset optional fields.

        Returns:
            Dictionary in V6.0 field spec format.
        """
        result: dict[str, Any] = {}

        if self.type_ref is not None:
            result["type_ref"] = self.type_ref
        if self.array_of is not None:
            result["array_of"] = self.array_of.to_dict()
        if self.map_of is not None:
            result["map_of"] = self.map_of.to_dict()
            # Only include key_type if non-default
            if self.key_type is not None and self.key_type != "primitive/string":
                result["key_type"] = self.key_type
        if self.optional:
            result["optional"] = True
        if self.byte_size is not None:
            result["byte_size"] = self.byte_size

        return result

    @classmethod
    def string(cls, optional: bool = False) -> FieldSpec:
        """Create a string field spec."""
        return cls(type_ref="primitive/string", optional=optional)

    @classmethod
    def bytes_(cls, optional: bool = False, byte_size: int | None = None) -> FieldSpec:
        """Create a bytes field spec."""
        return cls(type_ref="primitive/bytes", optional=optional, byte_size=byte_size)

    @classmethod
    def int_(cls, optional: bool = False) -> FieldSpec:
        """Create an int field spec."""
        return cls(type_ref="primitive/int", optional=optional)

    @classmethod
    def uint(cls, optional: bool = False, byte_size: int | None = None) -> FieldSpec:
        """Create a uint field spec."""
        return cls(type_ref="primitive/uint", optional=optional, byte_size=byte_size)

    @classmethod
    def bool_(cls, optional: bool = False) -> FieldSpec:
        """Create a bool field spec."""
        return cls(type_ref="primitive/bool", optional=optional)

    @classmethod
    def float_(cls, optional: bool = False) -> FieldSpec:
        """Create a float field spec."""
        return cls(type_ref="primitive/float", optional=optional)

    @classmethod
    def any_(cls, optional: bool = False) -> FieldSpec:
        """Create an any field spec."""
        return cls(type_ref="primitive/any", optional=optional)

    @classmethod
    def hash_(cls, optional: bool = False) -> FieldSpec:
        """Create a system/hash field spec."""
        return cls(type_ref="system/hash", optional=optional)

    @classmethod
    def array(cls, item_spec: FieldSpec, optional: bool = False) -> FieldSpec:
        """Create an array field spec with the given item type."""
        return cls(array_of=item_spec, optional=optional)

    @classmethod
    def map(
        cls,
        value_spec: FieldSpec,
        key_type: str = "primitive/string",
        optional: bool = False,
    ) -> FieldSpec:
        """Create a map field spec with the given value type."""
        return cls(map_of=value_spec, key_type=key_type, optional=optional)

    @classmethod
    def type_reference(cls, type_name: str, optional: bool = False) -> FieldSpec:
        """Create a field spec referencing a named type."""
        return cls(type_ref=type_name, optional=optional)
