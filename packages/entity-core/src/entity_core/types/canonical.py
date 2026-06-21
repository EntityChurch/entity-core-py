"""Canonical core type paths per the TYPE-SYSTEM spec (§3-§10).

Single source of truth for the spec-pinned set of core type identifiers.
This is an intentionally explicit, fixed list — NOT derived from
``get_all_type_entities()`` — because it is used for cross-implementation
type-parity validation. Deriving it from the live registry would let
implementation-specific extras leak in (or spec types silently drop out),
defeating the parity comparison.

Consumed by the CLI ``compare-types`` command and the interop type-parity
tests. Keep aligned with ENTITY-NATIVE-TYPE-SYSTEM.md §3-§10.
"""

from __future__ import annotations

# Core types per TYPE-SYSTEM spec §3-§10
CORE_TYPE_PATHS: list[str] = [
    # Primitives (§3) - 8 types
    "primitive/string",
    "primitive/bytes",
    "primitive/uint",
    "primitive/int",
    "primitive/float",
    "primitive/bool",
    "primitive/null",
    "primitive/any",
    # Meta-types (§4) - 4 types
    "system/hash",
    "system/type",
    "system/type/field-spec",
    "system/type/constraint",
    # Deletion marker (§4.9, v4.2.0) - zero-field core type used by
    # EXTENSION-REVISION (and future extensions) to record intentional
    # path deletion in a content-addressed structure. Registered as core
    # because deletion semantics are generic, not REVISION-owned.
    "system/deletion-marker",
    # Core types (§8) - 2 types
    "core/entity",
    "core/envelope",
    # Protocol types (§9) - 6 types
    "system/protocol/envelope",
    "system/protocol/connect/hello",
    "system/protocol/connect/authenticate",
    "system/protocol/execute",
    "system/protocol/execute/response",
    "system/protocol/error",
    # Capability types (§9) - 4 types
    "system/capability/grant-entry",
    "system/capability/delegation-caveats",
    "system/capability/grant",
    "system/capability/token",
    # Supporting types (§10) - 8 types
    "system/peer",
    "system/signature",
    "system/handler",
    "system/handler/manifest",
    "system/handler/operation-spec",
    "system/bounds",
    "system/callback-spec",
    "system/resource-limits",
    # Tree types (§10.8) - 4 types
    "system/tree/listing-entry",
    "system/tree/listing",
    "system/tree/get-request",
    "system/tree/put-request",
]

__all__ = ["CORE_TYPE_PATHS"]
