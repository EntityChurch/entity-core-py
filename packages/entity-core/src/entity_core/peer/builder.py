"""Fluent builder for peer construction.

PeerBuilder provides an opt-in API for configuring peers. Unlike the direct
Peer() constructor (now deprecated), PeerBuilder requires explicit registration
of handlers and other features.

Example:
    # Minimal peer (core only - just storage, no handlers)
    peer = PeerBuilder().with_keypair(keypair).build()

    # Full peer (like current Peer(keypair))
    peer = (PeerBuilder()
        .with_keypair(keypair)
        .with_default_handlers()
        .debug_mode(True)
        .build())

    # Custom handlers only
    peer = (PeerBuilder()
        .with_keypair(keypair)
        .with_handler("myapp/*", my_handler, priority=50, name="myapp")
        .build())

    # With extension
    peer = (PeerBuilder()
        .with_keypair(keypair)
        .with_default_handlers()
        .with_extension(SubscriptionExtension())
        .build())

Handler Protocols:
    Handlers implementing NamedHandler, TypeProvider, or ManifestProvider
    protocols are auto-detected:

    class MyHandler:
        @property
        def name(self) -> str:
            return "my-handler"

        def register_types(self, registry: TypeRegistry) -> None:
            registry.register(my_custom_type)

        def manifest(self) -> Entity:
            return Entity(type="system/handler/manifest", data={...})

    # Auto-detects name from NamedHandler protocol
    builder.with_handler("myapp/*", MyHandler())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from entity_core.capability.grant import Grant, create_full_access_grant
from entity_core.handlers.protocols import ManifestProvider, NamedHandler, TypeProvider
from entity_core.handlers.registry import Handler

if TYPE_CHECKING:
    from entity_core.crypto.identity import Keypair
    from entity_core.peer.extensions import Extension
    from entity_core.peer.peer import Peer
    from entity_core.protocol.durability import DurabilityPolicy
    from entity_core.protocol.entity import Entity


@dataclass
class _HandlerConfig:
    """Configuration for a handler to be registered."""

    pattern: str
    handler: Handler
    priority: int = 0
    name: str = ""
    max_scope: list[Grant] | None = None
    # Protocol implementations (auto-detected from handler)
    type_provider: TypeProvider | None = None
    manifest_provider: ManifestProvider | None = None


@dataclass
class _ExtensionConfig:
    """Configuration for an extension to be registered."""

    extension: Extension
    max_scope: list[Grant] | None = None


@dataclass
class _RemoteConfig:
    """Configuration for a remote peer.

    `transport` selects which profile-publisher runs at build time:
    "tcp" → `register_remote` (default profile-id ``primary``);
    "http" → `register_remote_http` (default profile-id ``primary-http``,
    distinct from `primary` so a peer can publish both without collision —
    G1 mitigation, Round-2 §7.3).
    """

    peer_id: str
    address: str
    public_key: bytes | None = None
    transport: str = "tcp"


@dataclass
class _BuilderState:
    """Internal state for PeerBuilder."""

    keypair: Keypair | None = None
    default_grants: list[Grant] | None = None
    admin_peer_ids: set[str] = field(default_factory=set)
    debug_mode: bool = False
    # V7 §6.9a peer-authority-bootstrap (F27). `owner_identity_hash` is the
    # content_hash of the identity that holds the principal-level owner cap
    # (None → this peer's own identity, axiom A1). `seed_policy` maps a
    # policy key (identity-hash hex, Base58 PeerID, or "default") → grants,
    # materialized at L0 alongside the owner entry.
    owner_identity_hash: bytes | None = None
    seed_policy: dict[str, list[Grant]] | None = None
    grant_resolver: (
        "Callable[[str, bytes | None], list[Grant] | None] | None"
    ) = None
    handlers: list[_HandlerConfig] = field(default_factory=list)
    extensions: list[_ExtensionConfig] = field(default_factory=list)
    remotes: list[_RemoteConfig] = field(default_factory=list)
    register_types: bool = True
    # EXTENSION-DURABILITY §4 / §8: the receiver's own durability policy.
    # None = auto-derive at build (no durable store unless an inbox
    # handler is installed, which provides the `stored` strength —
    # though §6 makes clear the inbox is one example of a durable store,
    # not the canonical store).
    durability_policy: "DurabilityPolicy | None" = None


class PeerBuilder:
    """Fluent builder for peer construction.

    Provides an opt-in API for configuring peers. All configuration methods
    return self for method chaining.

    Example:
        peer = (PeerBuilder()
            .with_keypair(keypair)
            .with_default_handlers()
            .build())
    """

    def __init__(self) -> None:
        """Initialize an empty builder."""
        self._state = _BuilderState()

    def with_keypair(self, keypair: Keypair) -> PeerBuilder:
        """Set the peer's cryptographic identity.

        Args:
            keypair: The keypair for this peer.

        Returns:
            Self for method chaining.
        """
        self._state.keypair = keypair
        return self

    def with_default_grants(self, grants: list[Grant]) -> PeerBuilder:
        """Set default grants for connecting peers.

        If not set, defaults to full access grants.

        Args:
            grants: List of grants to give connecting peers.

        Returns:
            Self for method chaining.
        """
        self._state.default_grants = grants
        return self

    def with_admin_peer_ids(self, peer_ids: set[str]) -> PeerBuilder:
        """Set peer IDs that get admin access.

        Args:
            peer_ids: Set of peer IDs with admin privileges.

        Returns:
            Self for method chaining.
        """
        self._state.admin_peer_ids = peer_ids
        return self

    def with_grant_resolver(
        self,
        resolver: "Callable[[str, bytes | None], list[Grant] | None]",
    ) -> PeerBuilder:
        """Install an AUTHENTICATE-time grant resolver.

        The resolver receives `(peer_id, identity_hash)` and returns a
        list of grants for the connection cap, or None to fall through
        to the static debug-mode/admin/connect-scope fallback. The
        identity hash is the connecting peer's `system/peer` content
        hash (the role extension keys tree state by this hash, not the
        Base58 peer-id).

        Most resolvers (e.g. `PolicyGrantResolver`) need access to the
        peer's EmitPathway and so are easier to wire post-build via
        `peer.set_grant_resolver(...)`.
        """
        self._state.grant_resolver = resolver
        return self

    def with_owner_identity(
        self, identity: "Entity | bytes",
    ) -> PeerBuilder:
        """Set the principal-level owner identity (V7 §6.9a, F27).

        The owner holds the self-signed root capability over this peer's
        namespace ``/{peer_id}/*``, materialized at L0 by the §6.9a
        bootstrap. Defaults to this peer's own identity (axiom A1 — the
        key-holder is owner by construction); call this only for the
        ``--operator <id>`` multi-key model where a distinct identity
        administers the peer.

        Args:
            identity: The owner's ``system/peer`` identity entity, or its
                content_hash bytes directly.

        Returns:
            Self for method chaining.
        """
        from entity_core.protocol.entity import Entity as _Entity

        if isinstance(identity, bytes):
            self._state.owner_identity_hash = identity
        elif isinstance(identity, _Entity):
            self._state.owner_identity_hash = identity.compute_hash()
        else:
            raise TypeError(
                "with_owner_identity expects a system/peer Entity or a "
                f"content_hash (bytes), got {type(identity).__name__}"
            )
        return self

    def with_seed_policy(
        self, policy: dict[str, list[Grant]],
    ) -> PeerBuilder:
        """Declare the startup seed policy (V7 §6.9a, F27 / SDK-OPERATIONS §3.6).

        The builder is the substrate supply mechanism for the seed policy;
        CLI flags / config files / env vars are ergonomic wrappers that
        desugar to this method (``with_seed_policy_from_file`` below).

        Each entry materializes a ``system/capability/policy-entry`` at L0,
        read back at §4.6 authenticate via the existing v7.62 §8 / v7.64
        dual-form policy path. The ``self``-owner entry is added
        automatically by the bootstrap and need not appear here; supply a
        ``"default"`` key for the §6.9a default entry, plus any named
        operator/admin/reader identities.

        Args:
            policy: Map of policy key → grants. Keys are the v7.64 dual-form
                addresses: an identity-content-hash hex (canonical), a
                Base58 PeerID (pre-contact affordance), or the literal
                ``"default"`` sentinel.

        Returns:
            Self for method chaining.
        """
        self._state.seed_policy = dict(policy)
        return self

    def with_seed_policy_from_file(self, path: str) -> PeerBuilder:
        """Load a seed policy from a JSON file (V7 §6.9a / SDK-OPERATIONS §3.6).

        Ergonomic CLI/config wrapper that desugars to ``with_seed_policy``.
        The cross-peer file format is keystone protocol-generator territory
        (``protocol-generator/shared/seed-policy/``); this is the provisional
        Python shape pending that ratification:

        ```json
        {
          "default": {"grants": [ <grant-entry>, ... ]},
          "<identity-hash-hex-or-base58>": {"grants": [ ... ]}
        }
        ```

        Each value is either a ``{"grants": [...]}`` object or a bare list
        of grant entries. Grant entries are the §3.6 ``CapabilityScope``
        shape (``handlers`` / ``resources`` / ``operations`` include/exclude).

        Args:
            path: Filesystem path to the JSON seed-policy file.

        Returns:
            Self for method chaining.
        """
        import json

        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise ValueError(
                f"seed-policy file {path!r} must be a JSON object mapping "
                "policy key → grants"
            )

        policy: dict[str, list[Grant]] = {}
        for key, value in raw.items():
            if isinstance(value, dict) and "grants" in value:
                grant_dicts = value["grants"]
            elif isinstance(value, list):
                grant_dicts = value
            else:
                raise ValueError(
                    f"seed-policy entry {key!r} must be a list of grants or "
                    "an object with a `grants` array"
                )
            policy[key] = [Grant.from_dict(g) for g in grant_dicts]

        return self.with_seed_policy(policy)

    def debug_mode(self, enabled: bool = True) -> PeerBuilder:
        """Enable debug mode (grants full access to all peers).

        DEPRECATED (V7 §6.9a / §3.7, F27): this is the degenerate seed
        policy ``default → *``. It is retained for one cycle (removed in
        v7.75); migrate to ``with_seed_policy({"default": [...]})`` (or
        ``with_owner_identity`` for the key-holder) which supplies a real,
        inspectable policy entry instead of a mode-fork. See axiom A2 —
        authority is a capability, never a mode.

        WARNING: This is insecure and should only be used for testing.

        Args:
            enabled: Whether to enable debug mode.

        Returns:
            Self for method chaining.
        """
        self._state.debug_mode = enabled
        return self

    def with_handler(
        self,
        pattern: str,
        handler: Handler | Any,
        priority: int = 0,
        name: str = "",
        max_scope: list[Grant] | None = None,
    ) -> PeerBuilder:
        """Register a handler at a path pattern.

        Handlers can be either async functions or objects implementing
        handler protocols (NamedHandler, TypeProvider, ManifestProvider).

        Protocol detection:
        - NamedHandler: Auto-detects name if not provided
        - TypeProvider: Registers types during peer initialization
        - ManifestProvider: Emits manifest to system/handlers/{name}

        Args:
            pattern: Path pattern (e.g., "system/*", "local/files/*", "*").
            handler: Async function or handler object with __call__.
            priority: Higher = checked first.
            name: Optional human-readable name (auto-detected from NamedHandler).
            max_scope: Optional list of grants defining max capabilities.
                If set, effective capability = intersection of request
                capability and max_scope.

        Returns:
            Self for method chaining.
        """
        # Auto-detect name from NamedHandler protocol
        if not name and isinstance(handler, NamedHandler):
            name = handler.name

        # Detect TypeProvider protocol
        type_provider: TypeProvider | None = None
        if isinstance(handler, TypeProvider):
            type_provider = handler

        # Detect ManifestProvider protocol
        manifest_provider: ManifestProvider | None = None
        if isinstance(handler, ManifestProvider):
            manifest_provider = handler

        self._state.handlers.append(
            _HandlerConfig(
                pattern=pattern,
                handler=handler,
                priority=priority,
                name=name,
                max_scope=max_scope,
                type_provider=type_provider,
                manifest_provider=manifest_provider,
            )
        )
        return self

    def with_default_handlers(self) -> PeerBuilder:
        """Register default system, tree, and storage handlers.

        This registers:
        - system/tree handler (priority=110) - V4 tree operations
        - system/handler handler (priority=111) - V7 §6.2 register/unregister
        - system/* handler (priority=100) - peer introspection
        - * handler (priority=0) - fallback storage operations

        Call this to get the same handlers as the deprecated Peer() constructor.

        For subscription support, also call:
        - with_inbox_handler() to receive async results
        - with_subscription_handler() to manage subscriptions
        - with_subscription_extension() to deliver notifications

        Or use with_all_handlers() for a full standard peer configuration.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import (
            tree_handler,
            TREE_HANDLER_PATTERN,
            system_handler,
            storage_handler,
        )

        self.with_handlers_handler()
        # The default connect grant advertises `system/capability:request`
        # (see capability/grant.py::create_connect_grants); installing the
        # handler here keeps the advertisement honest (Godot G1 → V7 §6.2
        # ruling: an advertised grant SHALL reference a
        # registered handler).
        self.with_capability_handler()

        # Only add if not already registered
        patterns = {h.pattern for h in self._state.handlers}
        if TREE_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=TREE_HANDLER_PATTERN,
                    handler=tree_handler,
                    priority=110,  # Higher than system/* to match first
                    name="tree",
                )
            )
        if "system/*" not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern="system/*",
                    handler=system_handler,
                    priority=100,
                    name="system",
                )
            )
        if "*" not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern="*",
                    handler=storage_handler,
                    priority=0,
                    name="storage",
                )
            )
        return self

    def with_handlers_handler(self) -> PeerBuilder:
        """Register the V7 §6.2 system/handler handlers handler.

        Provides the `register` and `unregister` operations that decompose
        manifests into interface + handler + grant entries in the tree
        (V7 §6.1, §6.2). One of the three bootstrap handlers per V7 §6.9.

        Idempotent — does nothing if already registered.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import handlers_handler, HANDLERS_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if HANDLERS_HANDLER_PATTERN in patterns:
            return self

        self._state.handlers.append(
            _HandlerConfig(
                pattern=HANDLERS_HANDLER_PATTERN,
                handler=handlers_handler,
                priority=111,  # Higher than system/* (100); spec-required bootstrap.
                name="handlers",
            )
        )
        return self

    def with_capability_handler(self) -> PeerBuilder:
        """Register the V7 §6.2 system/capability handler.

        Provides the `request`, `delegate`, and `revoke` operations:
        - request:  mint a peer-rooted token attenuated from caller's cap
        - delegate: mint a child token from a peer-issued parent
        - revoke:   write a revocation marker

        See the capability-handler ambiguity log
        (A1-A5) for the design decisions implementing this handler. Required
        to back the default connect grant for `system/capability:request`
        (otherwise the advertised grant 404s — the bug the Godot test caught
        on Rust).

        Idempotent — does nothing if already registered.
        """
        from entity_handlers import capability_handler, CAPABILITY_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if CAPABILITY_HANDLER_PATTERN in patterns:
            return self

        self._state.handlers.append(
            _HandlerConfig(
                pattern=CAPABILITY_HANDLER_PATTERN,
                handler=capability_handler,
                priority=111,  # spec-required, alongside handlers handler
                name="capability",
            )
        )
        return self

    def with_inbox_handler(self) -> PeerBuilder:
        """Register the inbox handler for async result delivery (v7.8).

        The inbox handler at system/inbox receives async results
        and subscription notifications. It's required for subscription
        support on this peer.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import inbox_handler, INBOX_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if INBOX_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=INBOX_HANDLER_PATTERN,
                    handler=inbox_handler,
                    priority=110,  # Higher priority than inbox
                    name="inbox",
                )
            )
        return self

    def with_durability_policy(
        self, policy: "DurabilityPolicy"
    ) -> PeerBuilder:
        """Set this peer's durability policy (EXTENSION-DURABILITY §4 / §8).

        The receiver's policy is implementation-defined and decided at
        acceptance from its own configuration — NOT a prediction of
        another peer's future state. When unset, the policy is
        auto-derived at build: no durable store unless an inbox handler
        is installed (which provides the ``stored`` self-determinable
        strength). Set this explicitly to advertise stronger strengths
        or to declare configured replication topologies.

        Returns:
            Self for method chaining.
        """
        self._state.durability_policy = policy
        return self

    def with_continuation_handler(self) -> PeerBuilder:
        """Register the continuation handler for execution chaining (v7.8).

        The continuation handler at system/continuation provides
        advance, resume, and abandon operations for execution chaining.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import continuation_handler, CONTINUATION_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if CONTINUATION_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=CONTINUATION_HANDLER_PATTERN,
                    handler=continuation_handler,
                    priority=112,  # Higher than inbox
                    name="continuation",
                )
            )
        return self

    def with_subscription_handler(self) -> PeerBuilder:
        """Register the subscription handler for subscription management.

        The subscription handler at system/subscription provides
        subscribe and unsubscribe operations. Clients use this to
        register for tree change notifications.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import subscription_handler, SUBSCRIPTION_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if SUBSCRIPTION_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=SUBSCRIPTION_HANDLER_PATTERN,
                    handler=subscription_handler,
                    priority=108,  # Between tree and inbox
                    name="subscriptions",
                )
            )
        return self

    def with_revision_handler(self) -> PeerBuilder:
        """Register the revision handler for version control (EXTENSION-REVISION v2.1).

        The revision handler at system/revision provides versioning with
        content-addressed tries and structural version entries.

        Operations: commit, log, status, merge, resolve, find-ancestor, diff,
        branch, checkout, tag, cherry-pick, revert, fetch, fetch-entities, push.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import revision_handler, REVISION_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if REVISION_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=REVISION_HANDLER_PATTERN,
                    handler=revision_handler,
                    priority=105,  # Between tree (106) and sync (104)
                    name="revision",
                )
            )
        return self

    def with_clock_handler(self) -> PeerBuilder:
        """Register the clock handler for system/clock operations.

        The clock handler provides unified timing (EXTENSION-CLOCK v1.0):
        - now: read current clock state
        - compare: compare two clock values
        - tick: subscribe to periodic clock events

        Supports wall-clock, logical, vector, and HLC modes.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import clock_handler, CLOCK_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if CLOCK_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=CLOCK_HANDLER_PATTERN,
                    handler=clock_handler,
                    priority=107,  # Between subscription (108) and tree (106)
                    name="clock",
                )
            )
        return self

    def with_clock_extension(self) -> PeerBuilder:
        """Register the clock extension for automatic advancement.

        Hooks into the emit pathway to advance the clock on every
        tree write (create/update). Per EXTENSION-CLOCK §4.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.clock import ClockExtension

        extension_types = {type(e.extension) for e in self._state.extensions}
        if ClockExtension not in extension_types:
            self._state.extensions.append(_ExtensionConfig(ClockExtension()))
        return self

    def with_query_handler(self) -> PeerBuilder:
        """Register the query handler and extension (EXTENSION-QUERY v1.0).

        The query handler at system/query provides secondary index queries:
        - find: evaluate query expression, return matching entities
        - count: return count of matching entities

        Also registers the QueryExtension which maintains type and reverse
        hash indexes via EmitPathway's InternalHook.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import QueryExtension, QUERY_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if QUERY_HANDLER_PATTERN not in patterns:
            query_ext = QueryExtension()
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=QUERY_HANDLER_PATTERN,
                    handler=query_ext.handler(),
                    priority=109,  # Between inbox (110) and subscription (108)
                    name="query",
                )
            )
            # Add the extension for index maintenance
            extension_types = {type(e.extension) for e in self._state.extensions}
            if QueryExtension not in extension_types:
                self._state.extensions.append(_ExtensionConfig(query_ext))
        return self

    def with_conformance_handlers(self) -> PeerBuilder:
        """Register the GUIDE-CONFORMANCE §7a test handlers (OPT-IN).

        Binds the two black-box conformance scaffolding handlers (§7a.1):

        * ``system/validate/echo``              — proves §6.13(a) dispatch
        * ``system/validate/dispatch-outbound`` — proves §6.13(b)/§6.11
          outbound-via-reentry

        These are conformance test fixtures, NOT core protocol and NOT an
        extension. They are OFF by default and intentionally **not** chained
        from :meth:`with_all_handlers`. Wire them only for a conformance run,
        typically from a host-level ``--validate`` flag. A peer without this
        opt-in 404s both patterns and the validator SKIPs honestly (§7a.4).

        Registering through :meth:`with_handler` auto-detects each handler's
        ``ManifestProvider`` so the manifest lands at
        ``system/handler/system/validate/{echo,dispatch-outbound}`` — the
        path the validator's presence probe tree-gets.

        SECURITY: ``dispatch-outbound`` originates outbound EXECUTEs from
        caller-supplied params. Do NOT enable in production.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import (
            EchoHandler,
            DispatchOutboundHandler,
            ECHO_HANDLER_PATTERN,
            DISPATCH_OUTBOUND_HANDLER_PATTERN,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if ECHO_HANDLER_PATTERN not in patterns:
            self.with_handler(
                ECHO_HANDLER_PATTERN, EchoHandler(),
                priority=111, name="validate/echo",
            )
        if DISPATCH_OUTBOUND_HANDLER_PATTERN not in patterns:
            self.with_handler(
                DISPATCH_OUTBOUND_HANDLER_PATTERN, DispatchOutboundHandler(),
                priority=111, name="validate/dispatch-outbound",
            )
        return self

    def with_type_handler(self) -> PeerBuilder:
        """Register EXTENSION-TYPE v1.1 handlers.

        Wires two handlers per spec §5.1 / §7.1:

        * ``system/type``                — validate + analysis ops
          (compare / compatible / converge / adopt / reconcile).
        * ``system/type/constraint/*``   — standard constraint
          dispatch surface for the 11 standard kinds (§4) plus
          fail-closed on unknown constraint types (§1.2).

        The constraint handler is registered at a higher priority
        (111) than the type handler (103) so that paths beginning
        with ``system/type/constraint/`` route to the constraint
        handler — the type handler's pattern ``system/type`` would
        otherwise prefix-match those paths too. See spec §2.2 /
        §5.4 for the dispatch model.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import (
            TYPE_CONSTRAINT_HANDLER_PATTERN,
            TYPE_HANDLER_PATTERN,
            type_constraint_handler,
            type_handler,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if TYPE_CONSTRAINT_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=TYPE_CONSTRAINT_HANDLER_PATTERN,
                    handler=type_constraint_handler,
                    priority=111,
                    name="type-constraints",
                )
            )
        if TYPE_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=TYPE_HANDLER_PATTERN,
                    handler=type_handler,
                    priority=103,
                    name="type",
                )
            )
        return self

    def with_local_files_handler(self) -> PeerBuilder:
        """Register the local files handler (DOMAIN-LOCAL-FILES v1.2).

        Binds ``local_files_handler`` at the prefix ``local/files`` and
        registers a :class:`LocalFilesExtension` to own root mappings,
        the recent-write tracker, the reverse-write subscription on the
        EmitPathway, and type registration for the eight domain types
        at ``system/type/local/files/*``.

        Configured root mappings are added at runtime via
        ``peer.extensions[...].add_root(...)`` — the builder method
        only installs the handler + extension; mapping configuration is
        a separate, post-build step (or rehydrated from existing
        ``local/files/root-config`` entities at peer build).

        Priority 101 — above ``system/*`` (100) and below
        ``system/content`` (102) so the literal-prefix dispatch lands
        before the generic ``*`` storage fallback. The pattern
        ``local/files`` is in the ``local/*`` namespace and won't
        contend with ``system/*`` resolution.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import (
            LOCAL_FILES_HANDLER_PATTERN,
            LocalFilesExtension,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if LOCAL_FILES_HANDLER_PATTERN not in patterns:
            ext = LocalFilesExtension()
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=LOCAL_FILES_HANDLER_PATTERN,
                    handler=ext.handler(),
                    priority=101,
                    name="local-files",
                )
            )
            extension_types = {type(e.extension) for e in self._state.extensions}
            if LocalFilesExtension not in extension_types:
                self._state.extensions.append(_ExtensionConfig(ext))
        return self

    def with_content_handler(self) -> PeerBuilder:
        """Register the system content handler (EXTENSION-CONTENT v3.5 §6).

        Binds the ``content_handler`` at the prefix ``system/content``;
        the manifest's ``pattern`` field advertises the spec glob
        ``system/content/*`` per the §4.9 (GUIDE-EXTENSION-DEVELOPMENT)
        registration convention. The dispatcher walks back from request
        paths to find this prefix; namespace subpaths (``system/content``,
        ``system/content/public``, ``system/content/shared``, …) all
        resolve here.

        Two ops install: ``get`` (hash → entity from the content store)
        and ``ingest`` (writes to the content store). Both v3.5-tightened
        with ``path_required`` when the EXECUTE lacks a resource field.

        Priority 102 — between system (100) and revision (105) — so the
        more specific prefix wins over the generic ``system/*`` fallback
        without contending with the storage-extension handlers.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import (
            CONTENT_HANDLER_PATTERN,
            content_handler,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if CONTENT_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=CONTENT_HANDLER_PATTERN,
                    handler=content_handler,
                    priority=102,
                    name="content",
                )
            )
        return self

    def with_history_handler(self) -> PeerBuilder:
        """Register the history handler and extension (EXTENSION-HISTORY v1.2).

        The history handler at system/history provides:
        - query: Retrieve transition history for a path
        - rollback: Restore a path to a previous state

        Also registers the HistoryExtension which records transitions
        via EmitPathway's InternalHook.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.history import HistoryExtension, HISTORY_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if HISTORY_HANDLER_PATTERN not in patterns:
            history_ext = HistoryExtension()
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=HISTORY_HANDLER_PATTERN,
                    handler=history_ext.handler(),
                    priority=104,  # Between revision (105) and system (100)
                    name="history",
                )
            )
            extension_types = {type(e.extension) for e in self._state.extensions}
            if HistoryExtension not in extension_types:
                self._state.extensions.append(_ExtensionConfig(history_ext))
        return self

    def with_entity_native_handler(
        self,
        pattern: str,
        expression_path: str,
        operations: dict[str, dict[str, Any]],
        *,
        name: str = "",
        priority: int = 0,
        internal_scope: list[Grant] | None = None,
    ) -> PeerBuilder:
        """Register an entity-native handler (V7 §6.6, EXTENSION-COMPUTE v3.9).

        The handler's body is the compute expression entity at
        `expression_path`. Each EXECUTE evaluates that expression with
        scope bindings `{operation, params, resource, caller_capability}`
        under the handler grant as the capability ceiling.

        Auto-registers the compute extension if not already present.

        Args:
            pattern: Path pattern the handler matches.
            expression_path: Tree path of the compute expression (the
                handler body). The expression entity must exist at this
                path before the first dispatch.
            operations: Map of operation name to operation spec — used to
                build the handler manifest and the handler interface
                published at `system/handler/{pattern}`.
            name: Optional human-readable name.
            priority: Higher = checked first in the in-memory dispatch
                index.
            internal_scope: Drives the handler grant created at
                `system/capability/grants/{pattern}`. If None, defaults to
                a full-access grant (most entity-native handlers should
                supply a tight scope).

        Returns:
            Self for method chaining.
        """
        from entity_handlers import ComputeExtension
        from entity_handlers.manifest import build_handler_manifest

        # Ensure compute extension is registered (entity-native dispatch
        # requires the evaluator).
        compute_ext: ComputeExtension | None = None
        for ext_config in self._state.extensions:
            if isinstance(ext_config.extension, ComputeExtension):
                compute_ext = ext_config.extension
                break
        if compute_ext is None:
            compute_ext = ComputeExtension()
            self._state.extensions.append(_ExtensionConfig(compute_ext))

        wrapper = compute_ext.make_entity_native_handler(expression_path)

        manifest = build_handler_manifest(
            name=name or pattern,
            pattern=pattern,
            operations=operations,
            expression_path=expression_path,
            internal_scope=(
                [g.to_dict() for g in internal_scope]
                if internal_scope is not None else None
            ),
        )

        class _EntityNativeManifestProvider:
            def manifest(self_inner) -> Any:  # noqa: N805
                return manifest

        self._state.handlers.append(
            _HandlerConfig(
                pattern=pattern,
                handler=wrapper,
                priority=priority,
                name=name,
                max_scope=internal_scope,
                manifest_provider=_EntityNativeManifestProvider(),
            )
        )
        return self

    def with_attestation_handler(self) -> PeerBuilder:
        """Register the attestation substrate handler (EXTENSION-ATTESTATION v1.1).

        The attestation handler at system/attestation provides the
        signed-graph substrate primitive: one entity type
        (system/attestation) plus four ops — :create, :supersede,
        :revoke, :verify. Identity, quorum, group, future VC /
        reputation / provenance / cluster / transaction / governance
        extensions all consume it.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.attestation import (
            ATTESTATION_HANDLER_PATTERN,
            attestation_handler,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if ATTESTATION_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=ATTESTATION_HANDLER_PATTERN,
                    handler=attestation_handler,
                    priority=113,  # Above continuation(112); below identity(111)? no — identity calls into substrate.
                    name="attestation",
                )
            )
        return self

    def with_registry_handler(self) -> PeerBuilder:
        """Register the registry handler (EXTENSION-REGISTRY v1.0).

        The registry handler at ``system/registry`` provides the name→peer
        resolution substrate (`:resolve` / `:invalidate-cache`) plus the v1
        local-name backend (`:bind` / `:unbind` / `:list` / `:update-transports`
        at ``system/registry/local-name``, caught by the same handler via
        prefix-subtree matching).

        The §5 capability surface (7 caps) is covered for the local peer by
        the §6.9a owner-cap full-self-access bootstrap (§5.2 floor) — no
        extra grant seeding is required.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.registry import (
            REGISTRY_HANDLER_PATTERN,
            registry_handler,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if REGISTRY_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=REGISTRY_HANDLER_PATTERN,
                    handler=registry_handler,
                    priority=117,  # Above role(115) — owns system/registry*;
                                   # wins over system/*(100) for these paths.
                    name="registry",
                )
            )
        return self

    def with_discovery_handler(self, *, enable_mdns: bool = True) -> PeerBuilder:
        """Register the discovery handler + DiscoveryExtension
        (EXTENSION-DISCOVERY v1.0).

        The discovery handler at ``system/discovery`` is the peer-finding
        substrate: ``:scan`` (hybrid snapshot + watchable candidate prefix,
        §3.0) / ``:announce`` / ``:announce-stop`` (§3) plus the ``:decide``
        decision-recording surface (§2.1). The v1 mDNS / DNS-SD backend (§3.2)
        is registered when ``enable_mdns`` is set (the default) and ``zeroconf``
        is importable.

        The §4 capability surface (``discovery-scan`` / ``discovery-announce``)
        is covered for the local peer by the §6.9a owner-cap full-self-access
        bootstrap (§4.1 floor) — no extra grant seeding is required.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.discovery import (
            DISCOVERY_HANDLER_PATTERN,
            DiscoveryExtension,
        )

        extension_types = {type(e.extension) for e in self._state.extensions}
        if DiscoveryExtension in extension_types:
            return self

        disc = DiscoveryExtension()
        if enable_mdns:
            try:
                from entity_handlers.discovery_mdns import MdnsBackend
                disc.register_backend(MdnsBackend())
            except Exception:  # zeroconf missing / import failure — substrate still works
                import logging
                logging.getLogger(__name__).warning(
                    "discovery: mDNS backend unavailable (zeroconf import failed); "
                    "substrate registered without it",
                    exc_info=True,
                )

        patterns = {h.pattern for h in self._state.handlers}
        if DISCOVERY_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=DISCOVERY_HANDLER_PATTERN,
                    handler=disc.handler(),
                    priority=116,  # owns system/discovery*; below registry(117),
                                   # above role(115); wins over system/*(100).
                    name="discovery",
                )
            )
        self._state.extensions.append(_ExtensionConfig(disc))
        return self

    def with_relay_handler(self) -> PeerBuilder:
        """Register the relay handler (EXTENSION-RELAY v1.0).

        The relay handler at ``system/relay`` carries opaque, signed,
        capability-bearing envelopes between endpoints (§1). v1 implements the
        floor (§10.1): **Mode F** (``:forward`` — ttl-bounded forwarding with
        intermediate/terminal-hop dispatch and Mode-S fallback for unreachable
        destinations) and **Mode S** (``:put`` / ``:poll`` — namespace-addressed
        store-and-poll with a relay-owned cursor) plus ``:advertise``.

        The §5.2 capability surface (relay-forward / relay-put / relay-poll /
        relay-advertise) is covered for the local peer by the §6.9a owner-cap
        full-self-access floor; the §5.5 self-poll default grant (each peer P
        may poll namespace = P) is seeded per requesting peer for cross-peer
        fallback retrieval.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.relay import (
            RELAY_HANDLER_PATTERN,
            relay_handler,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if RELAY_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=RELAY_HANDLER_PATTERN,
                    handler=relay_handler,
                    priority=114,  # owns system/relay*; below discovery(116)
                                   # /registry(117)/role(115); wins over system/*(100).
                    name="relay",
                )
            )
        return self

    def with_quorum_handler(self) -> PeerBuilder:
        """Register the quorum substrate handler + QuorumExtension
        (EXTENSION-QUORUM v1.1).

        The quorum handler at system/quorum provides the K-of-N node
        primitive: system/quorum entity type, four ops (:create,
        :update, :publish, :verify), the verify_k_of_n_signatures /
        current_signer_set / is_quorum_id validators, the pluggable
        signer-resolution hook (concrete built-in; identity-resolved
        registered by the identity handler at configure time), and the
        per-quorum signer-set cache with §4.2.1 invalidation.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.quorum import (
            QUORUM_HANDLER_PATTERN,
            QuorumExtension,
            quorum_handler,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if QUORUM_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=QUORUM_HANDLER_PATTERN,
                    handler=quorum_handler,
                    priority=114,
                    name="quorum",
                )
            )
        extension_types = {type(e.extension) for e in self._state.extensions}
        if QuorumExtension not in extension_types:
            self._state.extensions.append(_ExtensionConfig(QuorumExtension()))
        return self

    def with_identity_handler(self) -> PeerBuilder:
        """Register the identity handler (EXTENSION-IDENTITY v3.3).

        The identity handler at system/identity provides the convention
        layer over the attestation + quorum substrate primitives:
        - configure: bind peer-config to a trusted quorum + register
          identity-resolved resolver against EXTENSION-QUORUM; issue
          local peer→controller caps for live top-level controllers.
        - create_quorum: delegates to QUORUM:create + seeds peer-config.
        - create_attestation: wraps ATTESTATION:create with identity
          properties shape (kind=identity-cert + function + mode) and
          per-mode storage path resolution.
        - supersede_attestation / revoke_attestation: standard mutations.
        - publish_attestation: promote/demote agent certs across modes.
        - process_attestation: convergence point — validate via
          identity_verify_cert + apply state updates (cap issue/revoke;
          cache quorum-publish for compromise-recovery validation).

        Identity attestations are NEVER routed through V7's
        verify_capability_chain (three-parallel-mechanisms invariant).

        Identity depends on the attestation + quorum substrate. Calls
        to with_identity_handler() automatically install both.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import identity_handler, IDENTITY_HANDLER_PATTERN

        # Identity calls into both substrates; ensure they're installed.
        self.with_attestation_handler()
        self.with_quorum_handler()

        patterns = {h.pattern for h in self._state.handlers}
        if IDENTITY_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=IDENTITY_HANDLER_PATTERN,
                    handler=identity_handler,
                    priority=111,  # Above inbox(110); below continuation(112)
                    name="identity",
                )
            )
        return self

    def with_role_handler(self) -> PeerBuilder:
        """Register the role handler (EXTENSION-ROLE v1.5).

        The role handler at system/role provides named-grant-bundle
        management on top of the V7 capability system. Operations:
        define / assign / unassign / exclude / unexclude / re-derive /
        delegate.

        For the fleet-wide reactive sweep on tree-sync of exclusion
        entities (§6.5 IA8) AND IA11 option (b) re-derive cascade on
        out-of-handler role-definition mutation, also call
        `with_role_extension()`. `with_all_handlers()` chains both.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import role_handler, ROLE_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if ROLE_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=ROLE_HANDLER_PATTERN,
                    handler=role_handler,
                    priority=115,  # Above quorum(114) — role manages caps,
                                   # quorum is a substrate primitive.
                    name="role",
                )
            )
        return self

    def with_role_extension(self) -> PeerBuilder:
        """Register the role extension (EXTENSION-ROLE v1.5 — §6.5 IA8 +
        IA11 option (b)).

        Two responsibilities:

        1. Fleet-wide reactive sweep on tree-sync of exclusion entities
           — when `system/role/{context}/excluded/{peer_id}` lands here
           (locally OR via tree-sync), the role-derived caps this peer
           holds for that (context, peer) are deleted. Local-only reach;
           the exclusion entity is the trigger.

        2. IA11 option (b) re-derive cascade on out-of-handler
           role-definition mutation — when a `system/role` entity is
           written by direct `tree:put` (or arrives via tree-sync), the
           role's assignments are re-derived. The `system/role:define`
           op cascades synchronously on its own; the hook
           short-circuits when the change context attributes the write
           to the role handler itself, avoiding double-cascade.

        Idempotent.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import RoleExtension

        extension_types = {type(e.extension) for e in self._state.extensions}
        if RoleExtension not in extension_types:
            self._state.extensions.append(_ExtensionConfig(RoleExtension()))
        return self

    def with_compute_handler(self) -> PeerBuilder:
        """Register the compute handler and extension (EXTENSION-COMPUTE v3.5).

        The compute handler at system/compute/* provides:
        - eval: Evaluate a compute expression
        - install: Register a subgraph for reactive evaluation
        - uninstall: Remove a subgraph from reactive evaluation

        Also registers the ComputeExtension which maintains dependency
        indexes and triggers reactive re-evaluation via EmitPathway.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import ComputeExtension, COMPUTE_HANDLER_PATTERN

        patterns = {h.pattern for h in self._state.handlers}
        if COMPUTE_HANDLER_PATTERN not in patterns:
            compute_ext = ComputeExtension()
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=COMPUTE_HANDLER_PATTERN,
                    handler=compute_ext.handler(),
                    priority=103,
                    name="compute",
                )
            )
            extension_types = {type(e.extension) for e in self._state.extensions}
            if ComputeExtension not in extension_types:
                self._state.extensions.append(_ExtensionConfig(compute_ext))
        return self

    def with_root_tracker(self) -> PeerBuilder:
        """Register the trie root tracker extension (EXTENSION-TREE v3.8 §3.4).

        Watches `system/tree/tracking-config/*` for tracked prefixes and
        keeps `system/tree/root/{prefix}` in sync with the trie root for
        each enabled prefix. No handler operations — tracking configs are
        written via the standard tree `put` operation.

        Position 6 in SYSTEM-COMPOSITION emit ordering — registered after
        history (104) so summaries reflect settled derived state.

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.root_tracker import RootTrackerExtension

        extension_types = {type(e.extension) for e in self._state.extensions}
        if RootTrackerExtension not in extension_types:
            self._state.extensions.append(_ExtensionConfig(RootTrackerExtension()))
        return self

    def with_auto_version_extension(self) -> PeerBuilder:
        """Register the auto-version extension (position 7).

        Per-write auto-versioning per PROPOSAL-REVISION-AUTO-VERSION-FIX.
        For each tree write to a path under a tracked prefix (with
        `auto_version: true` revision config) and not matching the config's
        `exclude`, produces one `system/revision/entry` and advances
        `system/revision/head/{prefix}`.

        MUST be registered AFTER with_root_tracker() (position 6 produces
        the tracked root this extension reads) and BEFORE
        with_subscription_extension() (position 8 observes settled head).

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.auto_version import AutoVersionExtension

        extension_types = {type(e.extension) for e in self._state.extensions}
        if AutoVersionExtension not in extension_types:
            self._state.extensions.append(_ExtensionConfig(AutoVersionExtension()))
        return self

    def with_subscription_extension(self) -> PeerBuilder:
        """Add the subscription extension for notification delivery.

        The subscription extension monitors tree changes and delivers
        notifications to subscribed callbacks. This is required for
        a peer to actually send notifications (not just receive them).

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import SubscriptionExtension

        # Check if extension already added
        extension_types = {type(e.extension) for e in self._state.extensions}
        if SubscriptionExtension not in extension_types:
            self._state.extensions.append(_ExtensionConfig(SubscriptionExtension()))
        return self

    def with_substitute_handler(self) -> PeerBuilder:
        """Register the `http` storage-substitute handler (CDN corridor v1).

        Binds ``system/substitute/http`` at priority 101 — sibling slot
        to the content handler (102) since it's the per-type backend
        invoked by chain orchestrator dispatches via ``ctx.execute``.
        Other substitute backends (peer-to-peer, nix-cache, etc.)
        register at their own ``system/substitute/{type}`` patterns and
        compose freely.

        This is **Mechanism A** (inline HTTP GET + hash-verify); no
        BRIDGE-HTTP, no ``bridge-http-fetch`` cap on this path. See
        PROPOSAL-EXTENSION-STORAGE-SUBSTITUTE-HTTP.

        Per the storage-substitute cross-impl rulings: handler URI / `substitute_type` value
        renamed from `static-cdn` → `http` (the publisher's HTTP origin
        could be a bucket, nginx, or stdlib `http.server` — "CDN"
        under-named it).

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        from entity_handlers.substitute import (
            HTTP_HANDLER_PATTERN,
            http_substitute_handler,
        )

        patterns = {h.pattern for h in self._state.handlers}
        if HTTP_HANDLER_PATTERN not in patterns:
            self._state.handlers.append(
                _HandlerConfig(
                    pattern=HTTP_HANDLER_PATTERN,
                    handler=http_substitute_handler,
                    priority=101,
                    name="substitute-http",
                )
            )
        return self

    def with_all_handlers(self) -> PeerBuilder:
        """Register all standard handlers including v7.8 inbox and continuation.

        This is the "standard peer" configuration:
        - system/continuation handler (priority=112) - execution chaining
        - system/inbox handler (priority=110) - inbox delivery (v7.8)
        - system/subscription handler (priority=108) - subscription management
        - system/clock handler (priority=107) - clock operations (EXTENSION-CLOCK)
        - system/tree handler (priority=106) - tree operations
        - system/revision handler (priority=105) - version control (EXTENSION-REVISION v2.1)
        - system/* handler (priority=100) - peer introspection
        - * handler (priority=0) - fallback storage
        - SubscriptionExtension - notification delivery

        Requires the entity-handlers package to be installed.

        Returns:
            Self for method chaining.
        """
        return (
            self
            .with_default_handlers()
            .with_continuation_handler()
            .with_identity_handler()
            .with_role_handler()
            .with_role_extension()
            .with_inbox_handler()
            .with_query_handler()
            .with_subscription_handler()
            .with_clock_handler()
            .with_clock_extension()
            .with_revision_handler()
            .with_history_handler()
            .with_compute_handler()
            .with_type_handler()
            .with_content_handler()
            .with_substitute_handler()
            .with_local_files_handler()
            .with_registry_handler()
            .with_discovery_handler()
            .with_relay_handler()
            .with_root_tracker()
            .with_auto_version_extension()
            .with_subscription_extension()
        )

    def with_generic_storage(self, pattern: str) -> PeerBuilder:
        """Register generic storage handler at a specific pattern.

        Useful when you don't want the "*" fallback but need storage
        at a specific path.

        Requires the entity-handlers package to be installed.

        Args:
            pattern: Path pattern to register storage handler at.

        Returns:
            Self for method chaining.
        """
        from entity_handlers import storage_handler

        self._state.handlers.append(
            _HandlerConfig(
                pattern=pattern,
                handler=storage_handler,
                priority=0,
                name=f"storage({pattern})",
            )
        )
        return self

    def without_type_registration(self) -> PeerBuilder:
        """Disable automatic type registration.

        By default, built-in types are registered at system/types/*.
        Call this to skip type registration for a minimal peer.

        Returns:
            Self for method chaining.
        """
        self._state.register_types = False
        return self

    def with_extension(
        self,
        extension: Extension,
        max_scope: list[Grant] | None = None,
    ) -> PeerBuilder:
        """Add an extension to the peer.

        Extensions are initialized in order during build().

        Args:
            extension: The extension to add.
            max_scope: Optional list of grants defining max capabilities.
                If set, restricts what operations the extension can perform.

        Returns:
            Self for method chaining.
        """
        self._state.extensions.append(_ExtensionConfig(extension, max_scope))
        return self

    def with_remote_peer(
        self, peer_id: str, address: str, *,
        public_key: bytes | None = None,
    ) -> PeerBuilder:
        """Register a remote peer's TCP transport profile.

        The peer will be reachable via entity://{peer_id}/... URIs.
        Profile is stored at system/peer/transport/{peer_id_hex}/primary
        (V7 v7.64 §1.4 — hex of the remote peer's ``system/peer``
        content_hash). ``public_key`` is OPTIONAL for identity-multihash
        form PeerIDs (V7 v7.64 §1.5 ``hash_type = 0x00``) — derived
        locally from the Base58 PeerID; required only for SHA-256-form.
        """
        self._state.remotes.append(
            _RemoteConfig(
                peer_id=peer_id, address=address,
                public_key=public_key, transport="tcp",
            )
        )
        return self

    def with_remote_peer_http(
        self, peer_id: str, url: str, *,
        public_key: bytes | None = None,
    ) -> PeerBuilder:
        """Register a remote peer's HTTP transport profile.

        Profile is stored at system/peer/transport/{peer_id_hex}/primary-http
        — distinct from the TCP `primary` slot so both transports can be
        advertised for one peer without overwriting each other (G1).
        ``public_key`` is OPTIONAL for identity-multihash form PeerIDs;
        required for SHA-256-form (V7 v7.64 §1.5).
        """
        self._state.remotes.append(
            _RemoteConfig(
                peer_id=peer_id, address=url,
                public_key=public_key, transport="http",
            )
        )
        return self

    def build(self) -> Peer:
        """Build the configured peer.

        Raises:
            ValueError: If keypair is not set.

        Returns:
            Configured Peer instance.
        """
        if self._state.keypair is None:
            raise ValueError("Keypair is required. Call with_keypair() before build().")

        # Import here to avoid circular imports
        from entity_core.peer.peer import Peer

        return Peer._from_builder(self._state)
