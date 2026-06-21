"""Standard handlers for Entity Core Protocol V7.8.

This package provides optional handlers that can be registered with a peer:
- inbox_handler: Inbox delivery for async operations (v7.8, was callback_handler)
- tree_handler: Tree operations (get/put/list)
- revision_handler: Version control with content-addressed tries (EXTENSION-REVISION v2.1)
- subscription_handler: Subscription management (subscribe/unsubscribe)
- system_handler: System introspection
- storage_handler: Fallback CRUD operations
- manifest: Handler manifest utilities

Extensions:
- SubscriptionExtension: Manages subscription notifications
"""

from entity_handlers.tree import tree_handler, TREE_HANDLER_PATTERN
from entity_handlers.revision import revision_handler, REVISION_HANDLER_PATTERN
from entity_handlers.clock import (
    clock_handler,
    ClockExtension,
    CLOCK_HANDLER_PATTERN,
    system_clock_ms,
    advance_clock,
)
from entity_handlers.continuation import (
    continuation_handler,
    CONTINUATION_HANDLER_PATTERN,
)
from entity_handlers.inbox import (
    # V7.8 inbox handler
    inbox_handler,
    INBOX_HANDLER_PATTERN,
    create_inbox_token,
)
from entity_handlers.subscription import (
    subscription_handler,
    SUBSCRIPTION_HANDLER_PATTERN,
    SubscriptionExtension,
    SubscriptionEntity,
    SubscriptionLimits,
    SubscribeRequest,
    UnsubscribeRequest,
)
from entity_handlers.system import system_handler
from entity_handlers.storage import storage_handler
from entity_handlers.handlers import (
    handlers_handler,
    HANDLERS_HANDLER_PATTERN,
    HANDLERS_TYPE_DEFS,
)
from entity_handlers.capability import (
    capability_handler,
    CAPABILITY_HANDLER_PATTERN,
)
from entity_handlers.conformance import (
    EchoHandler,
    DispatchOutboundHandler,
    ECHO_HANDLER_PATTERN,
    DISPATCH_OUTBOUND_HANDLER_PATTERN,
)
from entity_handlers.query import (
    QueryExtension,
    QUERY_HANDLER_PATTERN,
    create_query_handler,
)
from entity_handlers.history import (
    HistoryExtension,
    HistoryConfig,
    HISTORY_HANDLER_PATTERN,
)
from entity_handlers.compute import (
    ComputeExtension,
    COMPUTE_HANDLER_PATTERN,
)
from entity_handlers.root_tracker import (
    RootTrackerExtension,
    TrackingConfig,
    TRACKING_CONFIG_TYPE,
    ROOT_BINDING_PREFIX,
)
from entity_handlers.attestation import (
    attestation_handler,
    ATTESTATION_HANDLER_PATTERN,
)
from entity_handlers.registry import (
    registry_handler,
    REGISTRY_HANDLER_PATTERN,
)
from entity_handlers.discovery import (
    DiscoveryExtension,
    DISCOVERY_HANDLER_PATTERN,
    DISCOVERY_CAPS,
)
from entity_handlers.relay import (
    relay_handler,
    RELAY_HANDLER_PATTERN,
    RELAY_CAPS,
    INBOX_RELAY_TYPE,
    make_inbox_relay,
    inbox_relay_storage_path,
)
from entity_handlers.route import (
    ROUTE_TYPE,
    ROUTE_PREFIX,
    ROUTE_ACTION_DELIVER,
    ROUTE_ACTION_FORWARD,
    ROUTE_MATCH_DEFAULT,
    CAPABILITY_ROUTE_CONFIGURE,
    make_route,
    route_storage_path,
    resolve_from_table,
)
from entity_handlers.quorum import (
    quorum_handler,
    QUORUM_HANDLER_PATTERN,
    QuorumExtension,
)
from entity_handlers.identity import (
    identity_handler,
    IDENTITY_HANDLER_PATTERN,
)
from entity_handlers.role import (
    role_handler,
    RoleExtension,
    startup_time_role_derived_token,
    INITIAL_GRANT_POLICY_PATH,
    INITIAL_GRANT_POLICY_TYPE,
    INITIAL_GRANT_MODE_ANONYMOUS_ALLOW,
    INITIAL_GRANT_MODE_ANONYMOUS_DENY,
    INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION,
    ROLE_HANDLER_PATTERN,
    ROLE_TYPE,
    ROLE_ASSIGNMENT_TYPE,
    ROLE_EXCLUSION_TYPE,
    ROLE_DERIVED_TOKEN_LINK_TYPE,
)
from entity_handlers.role_policy import (
    GrantResolver,
    InitialGrantPolicy,
    PolicyGrantResolver,
    chain_grant_resolvers,
    read_initial_grant_policy,
    recognize_identity_cert,
)
from entity_handlers.type_handler import (
    type_handler,
    TYPE_HANDLER_PATTERN,
)
from entity_handlers.type_constraint import (
    type_constraint_handler,
    TYPE_CONSTRAINT_HANDLER_PATTERN,
)
from entity_handlers.local_files import (
    LOCAL_FILES_HANDLER_PATTERN,
    LOCAL_FILES_TYPE_DEFS,
    LocalFilesExtension,
    add_root_mapping,
)
from entity_handlers.content import (
    CONTENT_HANDLER_PATTERN,
    content_handler,
    # algorithms / constants — re-exported so downstream code can build
    # and reassemble content without importing the subpackage directly
    build_blob,
    build_fastcdc,
    build_fixed_size,
    persist as persist_blob,
    reassemble_content,
    verify_content,
    DEFAULT_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    GET_BATCH_SIZE,
    CHUNKING_FIXED_SIZE,
    CHUNKING_FASTCDC_NC2,
)
from entity_handlers.substitute import (
    HTTP_HANDLER_PATTERN,
    http_substitute_handler,
    consult_substitute_chain,
    CHAIN_CONSULT_CAP,
    build_content_url,
    build_tree_url,
    CONTENT_LAYOUTS,
    DEFAULT_TREE_LEAF_SUFFIX,
    accept_manifest,
    verify_manifest_signature,
    ManifestFreshness,
    ManifestVerifyError,
)
from entity_handlers.manifest import (
    error_response,
    build_handler_manifest,
    SYSTEM_HANDLER_MANIFEST,
    STORAGE_HANDLER_MANIFEST,
    CONNECT_HANDLER_MANIFEST,
    TREE_HANDLER_MANIFEST,
    CONTINUATION_HANDLER_MANIFEST,
    INBOX_HANDLER_MANIFEST,
    SUBSCRIPTION_HANDLER_MANIFEST,
    REVISION_HANDLER_MANIFEST,
    CLOCK_HANDLER_MANIFEST,
    QUERY_HANDLER_MANIFEST,
    HISTORY_HANDLER_MANIFEST,
    COMPUTE_HANDLER_MANIFEST,
    HANDLERS_HANDLER_MANIFEST,
    CAPABILITY_HANDLER_MANIFEST,
    ATTESTATION_HANDLER_MANIFEST,
    QUORUM_HANDLER_MANIFEST,
    IDENTITY_HANDLER_MANIFEST,
    ROLE_HANDLER_MANIFEST,
    TYPE_HANDLER_MANIFEST,
    TYPE_CONSTRAINT_HANDLER_MANIFEST,
    CONTENT_HANDLER_MANIFEST,
    LOCAL_FILES_HANDLER_MANIFEST,
    REGISTRY_HANDLER_MANIFEST,
    DISCOVERY_HANDLER_MANIFEST,
    RELAY_HANDLER_MANIFEST,
    ALL_HANDLER_MANIFESTS,
)

__all__ = [
    # Tree handler
    "tree_handler",
    "TREE_HANDLER_PATTERN",
    # Revision handler (EXTENSION-REVISION v2.1)
    "revision_handler",
    "REVISION_HANDLER_PATTERN",
    # Clock handler (EXTENSION-CLOCK v1.0)
    "clock_handler",
    "CLOCK_HANDLER_PATTERN",
    "system_clock_ms",
    "advance_clock",
    # Continuation handler (v7.8)
    "continuation_handler",
    "CONTINUATION_HANDLER_PATTERN",
    # Inbox handler (v7.8)
    "inbox_handler",
    "INBOX_HANDLER_PATTERN",
    "create_inbox_token",
    # Subscription handler
    "subscription_handler",
    "SUBSCRIPTION_HANDLER_PATTERN",
    # Subscription types and extension
    "SubscriptionExtension",
    "SubscriptionEntity",
    "SubscriptionLimits",
    "SubscribeRequest",
    "UnsubscribeRequest",
    # System and storage handlers
    "system_handler",
    "storage_handler",
    # Handlers handler (V7 §6.2 — system/handler register/unregister)
    "handlers_handler",
    "HANDLERS_HANDLER_PATTERN",
    "HANDLERS_TYPE_DEFS",
    "HANDLERS_HANDLER_MANIFEST",
    # Capability handler (V7 §6.2 — system/capability request/delegate/revoke)
    "capability_handler",
    "CAPABILITY_HANDLER_PATTERN",
    "CAPABILITY_HANDLER_MANIFEST",
    # Conformance test handlers (GUIDE-CONFORMANCE §7a — opt-in only)
    "EchoHandler",
    "DispatchOutboundHandler",
    "ECHO_HANDLER_PATTERN",
    "DISPATCH_OUTBOUND_HANDLER_PATTERN",
    # Query handler (EXTENSION-QUERY v1.0)
    "QueryExtension",
    "QUERY_HANDLER_PATTERN",
    "create_query_handler",
    # History handler (EXTENSION-HISTORY v1.2)
    "HistoryExtension",
    "HistoryConfig",
    "HISTORY_HANDLER_PATTERN",
    "HISTORY_HANDLER_MANIFEST",
    # Compute handler (EXTENSION-COMPUTE v3.8)
    "ComputeExtension",
    "COMPUTE_HANDLER_PATTERN",
    "COMPUTE_HANDLER_MANIFEST",
    # Attestation substrate (EXTENSION-ATTESTATION v1.0)
    "attestation_handler",
    "ATTESTATION_HANDLER_PATTERN",
    "registry_handler",
    "REGISTRY_HANDLER_PATTERN",
    "REGISTRY_HANDLER_MANIFEST",
    "DiscoveryExtension",
    "DISCOVERY_HANDLER_PATTERN",
    "DISCOVERY_CAPS",
    "DISCOVERY_HANDLER_MANIFEST",
    "relay_handler",
    "RELAY_HANDLER_PATTERN",
    "RELAY_CAPS",
    "RELAY_HANDLER_MANIFEST",
    "INBOX_RELAY_TYPE",
    "make_inbox_relay",
    "inbox_relay_storage_path",
    "ROUTE_TYPE",
    "ROUTE_PREFIX",
    "ROUTE_ACTION_DELIVER",
    "ROUTE_ACTION_FORWARD",
    "ROUTE_MATCH_DEFAULT",
    "CAPABILITY_ROUTE_CONFIGURE",
    "make_route",
    "route_storage_path",
    "resolve_from_table",
    "ATTESTATION_HANDLER_MANIFEST",
    # Quorum substrate (EXTENSION-QUORUM v1.0)
    "quorum_handler",
    "QUORUM_HANDLER_PATTERN",
    "QUORUM_HANDLER_MANIFEST",
    "QuorumExtension",
    # Identity handler (EXTENSION-IDENTITY v3.2)
    "identity_handler",
    "IDENTITY_HANDLER_PATTERN",
    "IDENTITY_HANDLER_MANIFEST",
    # Role handler (EXTENSION-ROLE v1.6)
    "role_handler",
    "RoleExtension",
    "startup_time_role_derived_token",
    "INITIAL_GRANT_POLICY_PATH",
    "INITIAL_GRANT_POLICY_TYPE",
    "INITIAL_GRANT_MODE_ANONYMOUS_ALLOW",
    "INITIAL_GRANT_MODE_ANONYMOUS_DENY",
    "INITIAL_GRANT_MODE_RECOGNIZE_ON_ATTESTATION",
    "GrantResolver",
    "InitialGrantPolicy",
    "PolicyGrantResolver",
    "chain_grant_resolvers",
    "read_initial_grant_policy",
    "recognize_identity_cert",
    "ROLE_HANDLER_PATTERN",
    "ROLE_HANDLER_MANIFEST",
    "ROLE_TYPE",
    "ROLE_ASSIGNMENT_TYPE",
    "ROLE_EXCLUSION_TYPE",
    "ROLE_DERIVED_TOKEN_LINK_TYPE",
    # Root tracker (EXTENSION-TREE v3.8 §3.4)
    "RootTrackerExtension",
    "TrackingConfig",
    "TRACKING_CONFIG_TYPE",
    "ROOT_BINDING_PREFIX",
    # Type handler (EXTENSION-TYPE v1.1)
    "type_handler",
    "TYPE_HANDLER_PATTERN",
    "TYPE_HANDLER_MANIFEST",
    "type_constraint_handler",
    "TYPE_CONSTRAINT_HANDLER_PATTERN",
    "TYPE_CONSTRAINT_HANDLER_MANIFEST",
    # Content handler (EXTENSION-CONTENT v3.5)
    "content_handler",
    "CONTENT_HANDLER_PATTERN",
    "CONTENT_HANDLER_MANIFEST",
    "build_blob",
    "build_fastcdc",
    "build_fixed_size",
    "persist_blob",
    "reassemble_content",
    "verify_content",
    "DEFAULT_CHUNK_SIZE",
    "MIN_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "GET_BATCH_SIZE",
    "CHUNKING_FIXED_SIZE",
    "CHUNKING_FASTCDC_NC2",
    # Storage-substitute (CDN corridor v1; renamed from CONTENT-SUBSTITUTE
    # per the storage-substitute rulings)
    "HTTP_HANDLER_PATTERN",
    "http_substitute_handler",
    "consult_substitute_chain",
    "CHAIN_CONSULT_CAP",
    "build_content_url",
    "build_tree_url",
    "CONTENT_LAYOUTS",
    "DEFAULT_TREE_LEAF_SUFFIX",
    "accept_manifest",
    "verify_manifest_signature",
    "ManifestFreshness",
    "ManifestVerifyError",
    # Local files (DOMAIN-LOCAL-FILES v1.2)
    "LOCAL_FILES_HANDLER_PATTERN",
    "LOCAL_FILES_HANDLER_MANIFEST",
    "LOCAL_FILES_TYPE_DEFS",
    "LocalFilesExtension",
    "add_root_mapping",
    # Shared utilities
    "error_response",
    # Manifests
    "build_handler_manifest",
    "SYSTEM_HANDLER_MANIFEST",
    "STORAGE_HANDLER_MANIFEST",
    "CONNECT_HANDLER_MANIFEST",
    "TREE_HANDLER_MANIFEST",
    "CONTINUATION_HANDLER_MANIFEST",
    "INBOX_HANDLER_MANIFEST",
    "SUBSCRIPTION_HANDLER_MANIFEST",
    "REVISION_HANDLER_MANIFEST",
    "CLOCK_HANDLER_MANIFEST",
    "QUERY_HANDLER_MANIFEST",
    "ALL_HANDLER_MANIFESTS",
    # Registration
    "register_standard_handlers",
    "register_standard_handlers_with_subscriptions",
]


def register_standard_handlers(builder: "PeerBuilder") -> "PeerBuilder":
    """Register standard handlers on a peer builder.

    Args:
        builder: The PeerBuilder to configure.

    Returns:
        The builder for method chaining.
    """
    from entity_core.peer import PeerBuilder

    return (
        builder
        .with_handler(CONTINUATION_HANDLER_PATTERN, continuation_handler, priority=112, name="continuation")
        .with_handler(INBOX_HANDLER_PATTERN, inbox_handler, priority=110, name="inbox")
        .with_handler(SUBSCRIPTION_HANDLER_PATTERN, subscription_handler, priority=108, name="subscriptions")
        .with_handler(CLOCK_HANDLER_PATTERN, clock_handler, priority=107, name="clock")
        .with_handler(TREE_HANDLER_PATTERN, tree_handler, priority=106, name="tree")
        .with_handler(REVISION_HANDLER_PATTERN, revision_handler, priority=105, name="revision")
        .with_handler("system/*", system_handler, priority=100, name="system")
        .with_handler("*", storage_handler, priority=0, name="storage")
    )


def register_standard_handlers_with_subscriptions(builder: "PeerBuilder") -> "PeerBuilder":
    """Register standard handlers and subscription extension.

    Args:
        builder: The PeerBuilder to configure.

    Returns:
        The builder for method chaining.
    """
    return (
        register_standard_handlers(builder)
        .with_extension(SubscriptionExtension())
    )
