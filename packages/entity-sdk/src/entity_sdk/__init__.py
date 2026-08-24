"""entity-sdk — the L1 operations surface (`SDK-OPERATIONS` v0.8).

Tier 2 of five: ``entity-core → entity-handlers → entity-sdk → entity-app →
presentation``. This package depends on the **kernel only**. It reaches handlers
by dispatching to their pattern strings and never imports ``entity_handlers``,
so the tier boundary holds by construction rather than by discipline —
``tests/unit/test_package_layering.py`` is what says so out loud.

What lives here is the knowledge that used to be inlined at every call site: how
a tree operation is addressed, where the authorization-bearing path rides, what
the wire's listing map projects to, and which status means which exception. One
copy, typed, tested.

Start with :class:`EntityClient`. It composes over the ``Dispatcher`` Protocol
from ``entity_core.sdk``, so the same client serves local dispatch and cross-peer
dispatch — per `SDK-OPERATIONS` §2.7, the caller does not pick the level, the
peer id in the path does.
"""

from __future__ import annotations

from entity_sdk.client import (
    TREE_PATTERN,
    ZERO_HASH,
    EntityClient,
    Entry,
    content_hash,
)
from entity_sdk.connect import client_for_connection, connect
from entity_sdk.discovery import (
    HANDLER_PREFIX,
    TYPE_PREFIX,
    FieldInfo,
    HandlerInfo,
    OperationInfo,
    TypeInfo,
    discover_handlers,
    discover_types,
    dispatch_prefix,
)
from entity_sdk.events import (
    ChangeEvent,
    ChangeStream,
    TreeChangeEvent,
    TreeChangeStream,
    validate_watch_pattern,
)
from entity_sdk.store import LocalStore
from entity_sdk.subscription import (
    SUBSCRIPTION_PATTERN,
    WIRE_EVENTS,
    SubscriptionInfo,
    SubscriptionLimits,
    normalize_events,
    subscribe,
    unsubscribe,
)
from entity_sdk.errors import (
    AuthorizationError,
    BadRequest,
    ClientError,
    Conflict,
    EntityError,
    HandlerUndeclared,
    InternalError,
    NotFound,
    NotSupported,
    RateLimited,
    SystemFailure,
    error_for_status,
    raise_for_status,
)
from entity_sdk.paths import ResolvedPath, resolve
from entity_sdk.query import (
    OPERATORS,
    QUERY_PATTERN,
    FieldFilter,
    Match,
    QueryBuilder,
    QueryResult,
    normalize_operator,
    query,
)
from entity_sdk.revision import (
    CLEAN_MERGE_STATUSES,
    CONFLICT_MERGE_STATUSES,
    MERGE_STATUSES,
    REVISION_PATTERN,
    BranchListing,
    CheckoutResult,
    CherryPickResult,
    CommitResult,
    FetchEntitiesResult,
    FetchResult,
    LogPage,
    MergeResult,
    PushResult,
    ResolveResult,
    RevertResult,
    RevisionClient,
    RevisionStatus,
    TagListing,
    VersionDiff,
    find_ancestor,
    revision,
)
from entity_sdk.registry import (
    ISSUER_MODES,
    REGISTRY_PATTERN,
    IssuerPolicy,
    RegisterResult,
    RenewResult,
    RevokeResult,
    get_issuer_policy,
    normalize_registry_name,
    register,
    renew,
    revoke,
    set_issuer_policy,
)

__all__ = [
    # Client
    "EntityClient",
    "Entry",
    "TREE_PATTERN",
    "ZERO_HASH",
    "content_hash",
    # Change notification (§6)
    "ChangeEvent",
    "ChangeStream",
    "TreeChangeEvent",
    "TreeChangeStream",
    "validate_watch_pattern",
    # Level 0 surface (§6.5 — the naming carries the boundary)
    "LocalStore",
    # Connection (§7)
    "connect",
    "client_for_connection",
    # Discovery (§9)
    "discover_handlers",
    "discover_types",
    "dispatch_prefix",
    "HandlerInfo",
    "OperationInfo",
    "TypeInfo",
    "FieldInfo",
    "HANDLER_PREFIX",
    "TYPE_PREFIX",
    # Query (SDK-EXTENSION-OPERATIONS §6 — closes SDK-OPERATIONS §16.2 §5.1)
    "query",
    "QueryBuilder",
    "QueryResult",
    "Match",
    "FieldFilter",
    "normalize_operator",
    "OPERATORS",
    "QUERY_PATTERN",
    # Subscription (SDK-EXTENSION-OPERATIONS §3 — the cross-peer half of §6)
    "subscribe",
    "unsubscribe",
    "normalize_events",
    "SubscriptionInfo",
    "SubscriptionLimits",
    "SUBSCRIPTION_PATTERN",
    "WIRE_EVENTS",
    # Registry (EXTENSION-REGISTRY §6a.9 / §6a.9.2)
    "set_issuer_policy",
    "get_issuer_policy",
    "register",
    "renew",
    "revoke",
    "normalize_registry_name",
    "IssuerPolicy",
    "RegisterResult",
    "RenewResult",
    "RevokeResult",
    "ISSUER_MODES",
    "REGISTRY_PATTERN",
    # Revision (SDK-EXTENSION-OPERATIONS §4 / EXTENSION-REVISION §4)
    "revision",
    "find_ancestor",
    "RevisionClient",
    "RevisionStatus",
    "CommitResult",
    "LogPage",
    "MergeResult",
    "ResolveResult",
    "FetchResult",
    "FetchEntitiesResult",
    "CheckoutResult",
    "CherryPickResult",
    "RevertResult",
    "PushResult",
    "BranchListing",
    "TagListing",
    "VersionDiff",
    "MERGE_STATUSES",
    "CLEAN_MERGE_STATUSES",
    "CONFLICT_MERGE_STATUSES",
    "REVISION_PATTERN",
    # Paths
    "ResolvedPath",
    "resolve",
    # Errors
    "EntityError",
    "ClientError",
    "BadRequest",
    "NotFound",
    "Conflict",
    "AuthorizationError",
    "RateLimited",
    "SystemFailure",
    "InternalError",
    "NotSupported",
    "HandlerUndeclared",
    "error_for_status",
    "raise_for_status",
]
