"""Primitive type definitions for Entity Core.

This module defines type aliases used across the codebase.
It has no dependencies on other entity_core modules to avoid circular imports.
"""

from typing import NewType

# Unsigned integer type for CDDL generation
# Use this for fields that should be uint in CDDL (timestamps, counts, status codes)
Uint = NewType("Uint", int)

# V7.7 Semantic string types
# These map to specific type_refs in the type system instead of primitive/string
TreePath = NewType("TreePath", str)  # system/tree/path
TypeName = NewType("TypeName", str)  # system/type/name
PeerId = NewType("PeerId", str)  # system/peer-id

# Wire format types
# WireBytes: str in Python (base64 encoded), but primitive/bytes on the wire
WireBytes = NewType("WireBytes", str)  # primitive/bytes
