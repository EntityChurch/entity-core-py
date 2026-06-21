"""Capability system for authorization.

This module provides:
- CapabilityToken, Grant, CapabilityScope: Token structures
- matches_pattern, matches_scope: Permission checking
- check_handler_scope, check_path_permission: Two-level capability model
- is_attenuated: Delegation chain verification
- check_caveats: Caveat enforcement

V6.0 Changes:
- Added CapabilityScope with include/exclude arrays
- Grant now uses CapabilityScope for handlers, resources, operations
- Added matches_scope for scope-level pattern matching
"""

from entity_core.capability.token import CapabilityScope, CapabilityToken, Grant, get_scope
from entity_core.capability.checking import (
    matches_pattern,
    matches_scope,
    check_capability_refs,
    check_handler_scope,
    check_path_permission,
    find_matching_grant,
)
from entity_core.capability.delegation import (
    is_attenuated,
    grant_covered_by,
    scope_includes_subset,
    scope_exclude_inherited,
    check_caveats,
    validate_delegation,
    collect_authority_chain,
    check_creator_authority,
    DelegationResult,
    AttenuationResult,
    CaveatResult,
    ChainCollectResult,
    ChainCollectStatus,
    CreatorAuthorityResult,
)
from entity_core.capability.revocation import (
    DefaultRevocationContext,
    RevocationContext,
    capability_path_for,
    is_revoked,
)

__all__ = [
    # Token structures
    "CapabilityScope",
    "CapabilityToken",
    "Grant",
    "get_scope",
    # Permission checking
    "matches_pattern",
    "matches_scope",
    "check_capability_refs",
    # Two-level capability model
    "check_handler_scope",
    "check_path_permission",
    "find_matching_grant",
    # Delegation
    "is_attenuated",
    "grant_covered_by",
    "scope_includes_subset",
    "scope_exclude_inherited",
    "check_caveats",
    "validate_delegation",
    "collect_authority_chain",
    "check_creator_authority",
    "DelegationResult",
    "AttenuationResult",
    "CaveatResult",
    "ChainCollectResult",
    "ChainCollectStatus",
    "CreatorAuthorityResult",
    # Revocation (V7 §5.1 v7.62)
    "is_revoked",
    "capability_path_for",
    "DefaultRevocationContext",
    "RevocationContext",
]
