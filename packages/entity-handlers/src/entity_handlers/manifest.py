"""Handler manifest definitions and shared handler utilities.

Per PROPOSAL-HANDLER-NORMALIZATION, manifests are registration inputs
(type system/handler/manifest). During registration they are decomposed
into system/handler/interface + system/handler entities.
"""

from __future__ import annotations

from typing import Any

from entity_core.protocol.entity import Entity

# error_response lives in _common (shared with the handler modules); re-exported
# here for the modules that import it from manifest.
from entity_handlers._common import error_response  # noqa: F401


def build_handler_manifest(
    name: str,
    pattern: str,
    operations: dict[str, dict[str, Any]],
    *,
    expression_path: str | None = None,
    internal_scope: list[Any] | None = None,
    max_scope: list[Any] | None = None,
) -> Entity:
    """Build a system/handler/manifest entity.

    Args:
        name: Handler name.
        pattern: URI pattern the handler matches.
        operations: Map of operation name to operation spec.
        expression_path: For entity-native handlers (V7 §6.6,
            EXTENSION-COMPUTE v3.9), the tree path of the compute expression
            evaluated on each EXECUTE. Absent for compiled handlers.
        internal_scope: Handler's declared internal access (drives the
            handler grant created at registration).
        max_scope: Handler's max scope ceiling.

    Returns:
        A system/handler/manifest entity (registration input).
    """
    data: dict[str, Any] = {
        "name": name,
        "pattern": pattern,
        "operations": operations,
    }
    if expression_path is not None:
        data["expression_path"] = expression_path
    if internal_scope is not None:
        data["internal_scope"] = internal_scope
    if max_scope is not None:
        data["max_scope"] = max_scope

    return Entity(type="system/handler/manifest", data=data)


# =============================================================================
# Built-in Handler Manifests
# =============================================================================

SYSTEM_HANDLER_MANIFEST = build_handler_manifest(
    name="system",
    pattern="system/*",
    operations={
        "get": {"output_type": "primitive/any"},
    },
)

STORAGE_HANDLER_MANIFEST = build_handler_manifest(
    name="storage",
    pattern="*",
    operations={
        "read": {"output_type": "primitive/any"},
        "write": {"input_type": "primitive/any", "output_type": "primitive/any"},
        "list": {"output_type": "primitive/any"},
        "delete": {"output_type": "primitive/any"},
    },
)

# NOTE: `connect` is NOT a registerable handler and intentionally has no
# function, no `with_connect_handler()` builder method, and no entry in the
# handler registry. The hello/authenticate exchange is served by the built-in
# bootstrap layer in entity-core (`entity_core/handlers/connect.py`, wired in
# the peer wire/connection path), so these operations never 404 despite the
# absence of a registry entry. This manifest exists ONLY so peers can discover
# the connect protocol's operation surface via the tree. Asserted by
# tests/integration/test_handler_registration.py — do not remove.
CONNECT_HANDLER_MANIFEST = build_handler_manifest(
    name="connect",
    pattern="system/protocol/connect",
    operations={
        "hello": {
            "input_type": "system/protocol/connect/hello",
            "output_type": "system/protocol/connect/hello",
        },
        "authenticate": {
            "input_type": "system/protocol/connect/authenticate",
            "output_type": "system/capability/grant",
        },
    },
)
TREE_HANDLER_MANIFEST = build_handler_manifest(
    name="tree",
    pattern="system/tree",
    operations={
        # Core operations (V7 §6.3)
        "get": {
            "input_type": "system/tree/get-request",
            "output_type": "primitive/any",
        },
        "put": {
            "input_type": "system/tree/put-request",
            "output_type": "system/tree/put-result",
        },
        # Extension operations (EXTENSION-TREE.md §9)
        "snapshot": {
            "input_type": "system/tree/snapshot-request",
            "output_type": "system/tree/snapshot",
        },
        "diff": {
            "input_type": "system/tree/diff-request",
            "output_type": "system/tree/diff",
        },
        "merge": {
            "input_type": "system/tree/merge-request",
            "output_type": "system/tree/merge-result",
        },
        "extract": {
            "input_type": "system/tree/extract-request",
            "output_type": "system/protocol/envelope",
        },
        "create": {
            "input_type": "system/tree/config",
            "output_type": "system/tree/config",
        },
        "destroy": {
            "input_type": "primitive/string",
            "output_type": "primitive/bool",
        },
    },
)

# V7.8 Continuation handler
CONTINUATION_HANDLER_MANIFEST = build_handler_manifest(
    name="continuation",
    pattern="system/continuation",
    operations={
        # Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-CONTINUATION-1: install
        # accepts a system/continuation or system/continuation/join entity
        # directly as params. The wrapper request type is eliminated.
        "install": {
            "input_type": "primitive/any",
            "output_type": "system/continuation/install-result",
        },
        "advance": {
            "input_type": "primitive/any",
            "output_type": "system/continuation/advance-result",
        },
        "resume": {
            "input_type": "primitive/any",
            "output_type": "system/continuation/advance-result",
        },
        "abandon": {
            "input_type": "primitive/any",
            "output_type": "system/continuation/abandon-result",
        },
    },
)

# V7.8 Inbox handler (replaces callback)
# Per EXTENSION-INBOX v5.9 (v5.6 surface; §10 extracted to
# EXTENSION-DURABILITY v0.1). The inbox handler exposes
# only `receive` (notify goes through receive). Durability concerns
# — lookup, advertisement — are handled by EXTENSION-DURABILITY at
# dispatch / bootstrap, not by inbox-handler operations.
INBOX_HANDLER_MANIFEST = build_handler_manifest(
    name="inbox",
    pattern="system/inbox",
    operations={
        "receive": {
            "input_type": "primitive/any",
            "output_type": "system/inbox/receive-result",
        },
    },
)

SUBSCRIPTION_HANDLER_MANIFEST = build_handler_manifest(
    name="subscriptions",
    pattern="system/subscription",
    operations={
        "subscribe": {
            "input_type": "system/subscription/request",
            "output_type": "system/subscription/result",
        },
        "unsubscribe": {
            "input_type": "system/subscription/cancel",
        },
    },
)

# Revision handler manifest (EXTENSION-REVISION v2.1)
REVISION_HANDLER_MANIFEST = build_handler_manifest(
    name="revision",
    pattern="system/revision",
    operations={
        # Core operations (MUST)
        "commit": {
            "input_type": "system/revision/commit-params",
            "output_type": "system/revision/commit-result",
        },
        "log": {
            "input_type": "system/revision/log-params",
            "output_type": "system/revision/log-result",
        },
        "status": {
            "input_type": "system/revision/status-params",
            "output_type": "system/revision/status",
        },
        "merge": {
            "input_type": "system/revision/merge-params",
            "output_type": "system/revision/merge-result",
        },
        "resolve": {
            "input_type": "system/revision/resolve-params",
            "output_type": "system/revision/resolve-result",
        },
        "find-ancestor": {
            "input_type": "system/revision/ancestor-params",
            "output_type": "system/revision/ancestor-result",
        },
        "diff": {
            "input_type": "system/revision/diff-params",
            "output_type": "system/tree/diff",
        },
        # Convenience operations (SHOULD)
        "branch": {
            "input_type": "system/revision/branch-params",
            "output_type": "system/revision/branch-result",
        },
        "checkout": {
            "input_type": "system/revision/checkout-params",
            "output_type": "system/revision/checkout-result",
        },
        "tag": {
            "input_type": "system/revision/tag-params",
            "output_type": "system/revision/tag-result",
        },
        "cherry-pick": {
            "input_type": "system/revision/cherry-pick-params",
            "output_type": "system/revision/cherry-pick-result",
        },
        "revert": {
            "input_type": "system/revision/revert-params",
            "output_type": "system/revision/revert-result",
        },
        # Transfer operations (SHOULD)
        "fetch": {
            "input_type": "system/revision/fetch-params",
            "output_type": "system/revision/fetch-result",
        },
        "fetch-entities": {
            "input_type": "system/revision/fetch-entities-params",
            "output_type": "system/revision/fetch-entities-result",
        },
        # Incremental content transport (REVISION v3.4 §4.4.19): bundle the
        # changed closure between a caller-supplied base version and this
        # peer's current head. Returns an envelope ingestible by tree:merge.
        "fetch-diff": {
            "input_type": "system/revision/fetch-diff-params",
            "output_type": "system/envelope",
        },
        # Cross-peer pull (REVISION §4.4.8): fetch + incremental
        # fetch-entities trie walk + local merge, in one op. Input reuses
        # fetch-params (the `remote` field names the peer to pull from).
        "pull": {
            "input_type": "system/revision/fetch-params",
            "output_type": "system/revision/merge-result",
        },
        "push": {
            "input_type": "system/revision/push-params",
            "output_type": "system/revision/push-result",
        },
        # Configuration (PROPOSAL-REVISION-CONFIG-OPERATION §3.1)
        "config": {
            "input_type": "system/revision/config-params",
            "output_type": "system/revision/config-result",
        },
        # Merge-config canonical write path (REVISION v3.3 §4.4.18, D1).
        "merge-config": {
            "input_type": "system/revision/merge-config-params",
            "output_type": "system/revision/merge-config-result",
        },
    },
)


# Clock handler manifest (EXTENSION-CLOCK v1.0)
CLOCK_HANDLER_MANIFEST = build_handler_manifest(
    name="clock",
    pattern="system/clock",
    operations={
        "now": {
            "output_type": "system/clock/state",
        },
        "compare": {
            "input_type": "system/clock/compare-params",
            "output_type": "system/clock/compare-result",
        },
        "tick": {
            "input_type": "system/subscription/request",
        },
    },
)


# Query handler manifest (EXTENSION-QUERY v1.0)
QUERY_HANDLER_MANIFEST = build_handler_manifest(
    name="query",
    pattern="system/query",
    operations={
        "find": {
            "input_type": "system/query/expression",
            "output_type": "system/query/result",
        },
        "count": {
            "input_type": "system/query/expression",
            "output_type": "primitive/uint",
        },
    },
)


# History handler manifest (EXTENSION-HISTORY v1.2)
HISTORY_HANDLER_MANIFEST = build_handler_manifest(
    name="history",
    pattern="system/history",
    operations={
        "query": {
            "input_type": "system/history/query-params",
            "output_type": "system/history/query-result",
        },
        "rollback": {
            "input_type": "system/history/rollback-params",
            "output_type": "system/history/rollback-result",
        },
    },
)


# Compute handler manifest (EXTENSION-COMPUTE v3.5)
COMPUTE_HANDLER_MANIFEST = build_handler_manifest(
    name="compute",
    pattern="system/compute",
    operations={
        "eval": {
            "input_type": "primitive/any",
            "output_type": "primitive/any",
        },
        "install": {
            "input_type": "system/compute/install-request",
            "output_type": "system/compute/install-result",
        },
        # Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-COMPUTE-3: subgraph path
        # comes from ctx.resource; uninstall-request wrapper is eliminated
        # and params is empty primitive/any.
        "uninstall": {
            "input_type": "primitive/any",
            "output_type": "system/protocol/status",
        },
    },
)


# Attestation substrate manifest (EXTENSION-ATTESTATION v1.1)
ATTESTATION_HANDLER_MANIFEST = build_handler_manifest(
    name="attestation",
    pattern="system/attestation",
    operations={
        "create": {
            "input_type": "system/attestation/create-request",
            "output_type": "system/attestation/create-result",
        },
        "supersede": {
            "input_type": "system/attestation/supersede-request",
            "output_type": "system/attestation/supersede-result",
        },
        "revoke": {
            "input_type": "system/attestation/revoke-request",
            "output_type": "system/attestation/revoke-result",
        },
        "verify": {
            "input_type": "system/attestation/verify-request",
            "output_type": "system/attestation/verify-result",
        },
    },
)


# Quorum substrate manifest (EXTENSION-QUORUM v1.1)
QUORUM_HANDLER_MANIFEST = build_handler_manifest(
    name="quorum",
    pattern="system/quorum",
    operations={
        "create": {
            "input_type": "system/quorum/create-request",
            "output_type": "system/quorum/create-result",
        },
        "update": {
            "input_type": "system/quorum/update-request",
            "output_type": "system/quorum/update-result",
        },
        "publish": {
            "input_type": "system/quorum/publish-request",
            "output_type": "system/quorum/publish-result",
        },
        "verify": {
            "input_type": "system/quorum/verify-request",
            "output_type": "system/quorum/verify-result",
        },
    },
)


# Role handler manifest (EXTENSION-ROLE v1.6 — all 7 ops)
# Per SI-9 pattern parity, unassign and unexclude have dedicated result
# types in v1.6 (were `system/protocol/status` in v1.5).
ROLE_HANDLER_MANIFEST = build_handler_manifest(
    name="role",
    pattern="system/role",
    operations={
        "define": {
            "input_type": "system/role/define-request",
            "output_type": "system/role/define-result",
        },
        "assign": {
            "input_type": "system/role/assign-request",
            "output_type": "system/role/assign-result",
        },
        # unassign / exclude / unexclude carry no params content beyond
        # the resource path (V7 §3.2 path-as-resource); inputs are
        # primitive/any.
        "unassign": {
            "input_type": "primitive/any",
            "output_type": "system/role/unassign-result",
        },
        "exclude": {
            "input_type": "primitive/any",
            "output_type": "system/role/exclude-result",
        },
        "unexclude": {
            "input_type": "primitive/any",
            "output_type": "system/role/unexclude-result",
        },
        "re-derive": {
            "input_type": "system/role/re-derive-request",
            "output_type": "system/role/re-derive-result",
        },
        "delegate": {
            "input_type": "system/role/delegate-request",
            "output_type": "system/role/delegate-result",
        },
    },
)


# Identity handler manifest (EXTENSION-IDENTITY v3.3)
IDENTITY_HANDLER_MANIFEST = build_handler_manifest(
    name="identity",
    pattern="system/identity",
    operations={
        "configure": {
            "input_type": "system/identity/configure-request",
            "output_type": "system/identity/configure-result",
        },
        "create_quorum": {
            "input_type": "system/identity/create-quorum-request",
            "output_type": "system/identity/create-quorum-result",
        },
        "create_attestation": {
            "input_type": "system/identity/create-attestation-request",
            "output_type": "system/identity/create-attestation-result",
        },
        "supersede_attestation": {
            "input_type": "system/identity/supersede-attestation-request",
            "output_type": "system/identity/supersede-attestation-result",
        },
        "revoke_attestation": {
            "input_type": "system/identity/revoke-attestation-request",
            "output_type": "system/identity/revoke-attestation-result",
        },
        "publish_attestation": {
            "input_type": "system/identity/publish-attestation-request",
            "output_type": "system/identity/publish-attestation-result",
        },
        "process_attestation": {
            "input_type": "primitive/any",
            "output_type": "system/protocol/status",
        },
    },
)


# Handlers handler (V7 §6.2 — system/handler lifecycle management)
HANDLERS_HANDLER_MANIFEST = build_handler_manifest(
    name="handlers",
    pattern="system/handler",
    operations={
        "register": {
            "input_type": "system/handler/register-request",
            "output_type": "system/handler/register-result",
        },
        # Per PROPOSAL-PATH-AS-RESOURCE-HYGIENE P-V7-2: pattern comes from
        # ctx.resource; unregister-request wrapper is eliminated and params
        # is empty primitive/any.
        "unregister": {
            "input_type": "primitive/any",
            "output_type": "system/protocol/status",
        },
    },
)


# Type handler manifests (EXTENSION-TYPE v1.1)
TYPE_HANDLER_MANIFEST = build_handler_manifest(
    name="type",
    pattern="system/type",
    operations={
        # MUST-implement (§12.1)
        "validate": {
            "input_type": "system/type/validate-request",
            "output_type": "system/type/validate-result",
        },
        # SHOULD-implement (§12.2)
        "compare": {
            "input_type": "system/type/compare-request",
            "output_type": "system/type/compare-result",
        },
        "compatible": {
            "input_type": "system/type/compatible-request",
            "output_type": "system/type/compatibility-report",
        },
        # MAY-implement (§12.3) — landed alongside SHOULD per the
        # Python sprint plan; the spec leaves the door open.
        "converge": {
            "input_type": "system/type/converge-request",
            "output_type": "system/type",
        },
        "adopt": {
            "input_type": "system/type/adopt-request",
            "output_type": "system/type",
        },
        "reconcile": {
            "input_type": "system/type/reconcile-request",
            "output_type": "system/type/reconcile-result",
        },
    },
)

TYPE_CONSTRAINT_HANDLER_MANIFEST = build_handler_manifest(
    name="type-constraints",
    pattern="system/type/constraint/*",
    operations={
        # The standard constraint handler dispatches on `constraint_type`
        # internally per §5.4; the wire-level op is uniform.
        "validate": {
            "input_type": "system/type/constraint/validate-request",
            "output_type": "system/type/constraint/validate-result",
        },
    },
)


# Local files handler manifest (DOMAIN-LOCAL-FILES v1.3 §3.1)
#
# `internal_scope` declares the four grants the handler relies on at
# dispatch time: tree get/put for binding file/directory entities,
# subscription subscribe/unsubscribe for the reverse-write hook,
# content ingest/get for blob+chunk persistence, and tree put on the
# system/content/descriptor namespace for the optional descriptor-
# publication path (gated per-root by RootConfigData.publish_descriptors).
#
# **Watch is intentionally NOT advertised** per v1.3 §10.1 L2 MUST:
# the platform-native filesystem-notification watcher (inotify /
# FSEvents / ReadDirectoryChangesW) is not yet wired in this impl, so
# advertising `watch` would publish a capability that returns success
# but doesn't propagate on-disk edits to the tree — a silent
# non-conformance the v1.3 amendment exists to prevent. Callers that
# attempt `watch` against this handler get `unknown_operation` — the
# deliberate visible signal the spec prescribes. Re-add once the
# inotify driver (and overflow recovery per §10.2 L9) lands.
LOCAL_FILES_HANDLER_MANIFEST = build_handler_manifest(
    name="local-files",
    pattern="local/files",
    operations={
        "read": {"output_type": "local/files/file"},
        "write": {
            "input_type": "local/files/write-request",
            "output_type": "local/files/file",
        },
        "list": {"output_type": "local/files/directory"},
        "delete": {"output_type": "local/files/deleted"},
    },
    internal_scope=[
        {
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["local/files/*"]},
            "operations": {"include": ["get", "put"]},
        },
        {
            "handlers": {"include": ["system/subscription"]},
            "resources": {"include": ["local/files/*"]},
            "operations": {"include": ["subscribe", "unsubscribe"]},
        },
        {
            "handlers": {"include": ["system/content"]},
            "resources": {"include": ["system/content"]},
            "operations": {"include": ["ingest", "get"]},
        },
        {
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["system/content/descriptor/*"]},
            "operations": {"include": ["put"]},
        },
    ],
)


# Content handler manifest (EXTENSION-CONTENT v3.5 §6.1)
CONTENT_HANDLER_MANIFEST = build_handler_manifest(
    name="content",
    # Per the §4.9 (GUIDE-EXTENSION-DEVELOPMENT) handler-registration
    # discipline: the manifest's `pattern` field carries the spec glob;
    # the dispatcher binds at the bare prefix (the handler is registered
    # at `system/content`). The glob advertises the namespace surface to
    # peers running tree discovery.
    pattern="system/content/*",
    operations={
        # MAY-implement (§11.3) but installed as part of `with_all_handlers`
        # for parity with the other standard handlers. Both ops require a
        # `resource` field per the v3.5 §6.2 / §6.3 path_required tightening.
        "get": {
            "input_type": "system/content/get-request",
            "output_type": "system/content/content-response",
        },
        "ingest": {
            "input_type": "system/content/ingest-request",
            "output_type": "system/content/ingest-result",
        },
    },
)


# Storage-substitute `http` handler manifest (CDN corridor v1 — Mechanism A:
# inline HTTP GET + hash-verify; NOT BRIDGE-HTTP). Renamed from
# `substitute-static-cdn` per the storage-substitute cross-impl rulings.
# Ruling 3 — `:try` returns the raw verified entity dict in `result`; no
# `system/substitute/try-result` wrapper. Output type is the carried
# entity's own type, declared here as `primitive/any` since the handler is
# type-agnostic over what bytes the URL serves.
CAPABILITY_HANDLER_MANIFEST = build_handler_manifest(
    name="capability",
    pattern="system/capability",
    operations={
        # V7 §6.2 (v7.62): request mints a token, validated as subset of BOTH
        # the caller's authenticated cap AND the matched policy entry.
        "request": {
            "input_type": "system/capability/request",
            "output_type": "system/capability/grant",
        },
        # V7 §6.2 (v7.62): delegate is self-attenuation only; parent is in
        # params.data.parent (system/hash), not the resource.
        "delegate": {
            "input_type": "system/capability/delegate-request",
            "output_type": "system/capability/grant",
        },
        # V7 §6.2 (v7.62): universal revoke — unbind tree (if known path)
        # AND write the marker at system/capability/revocations/{hex}.
        "revoke": {
            "input_type": "system/capability/revoke-request",
            "output_type": "system/protocol/status",
        },
        # V7 §6.2 (v7.62): configure writes a policy entry at
        # system/capability/policy/{peer_pattern}; consulted by request and §4.4.
        "configure": {
            "input_type": "system/capability/policy-entry",
            "output_type": "system/protocol/status",
        },
    },
)

SUBSTITUTE_HTTP_HANDLER_MANIFEST = build_handler_manifest(
    name="substitute-http",
    pattern="system/substitute/http",
    operations={
        "try": {
            "input_type": "system/substitute/try-request",
            "output_type": "primitive/any",
        },
    },
)


# All built-in handler manifests
REGISTRY_HANDLER_MANIFEST = build_handler_manifest(
    name="registry",
    pattern="system/registry",
    operations={
        # Substrate (§2.1)
        "resolve": {
            "input_type": "system/registry/resolve-request",
            "output_type": "system/registry/resolution-result",
        },
        "invalidate-cache": {
            "input_type": "system/registry/invalidate-cache-request",
        },
        # Petname backend (§6.5)
        "bind": {
            "input_type": "system/registry/local-name/bind-request",
            "output_type": "system/registry/local-name/bind-result",
        },
        "unbind": {
            "input_type": "system/registry/local-name/unbind-request",
        },
        "list": {
            "input_type": "system/registry/local-name/list-request",
            "output_type": "system/registry/local-name/list-result",
        },
        "update-transports": {
            "input_type": "system/registry/local-name/update-transports-request",
            "output_type": "system/registry/local-name/bind-result",
        },
        # Peer-issued live registration (§6a.9)
        "register-request": {
            "input_type": "system/registry/register-request",
            "output_type": "system/registry/register-result",
        },
        "revoke-request": {
            "input_type": "system/registry/revoke-request",
        },
        "renew-request": {
            "input_type": "system/registry/renew-request",
        },
        "approve-request": {
            "output_type": "system/registry/register-result",
        },
        "set-issuer-policy": {
            "input_type": "system/registry/issuer-policy",
        },
        "get-issuer-policy": {
            "output_type": "system/registry/issuer-policy",
        },
    },
)

DISCOVERY_HANDLER_MANIFEST = build_handler_manifest(
    name="discovery",
    pattern="system/discovery",
    operations={
        # §3 substrate ops
        "scan": {
            "input_type": "system/discovery/scan-request",
            "output_type": "system/discovery/scan-result",
        },
        "announce": {
            "input_type": "system/discovery/announce-request",
        },
        "announce-stop": {
            "input_type": "system/discovery/announce-stop-request",
        },
        # §2.1 decision-recording surface (explicit-decision-before-admission,
        # §8.1). Not in §3's normative op list — flagged for D5 reconciliation.
        "decide": {
            "input_type": "system/discovery/decision-request",
            "output_type": "system/discovery/decision-result",
        },
    },
)

RELAY_HANDLER_MANIFEST = build_handler_manifest(
    name="relay",
    pattern="system/relay",
    operations={
        # Mode F (§4.2)
        "forward": {
            "input_type": "system/relay/forward-request",
            "output_type": "system/relay/forward-result",
        },
        # Mode S (§4.2)
        "put": {
            "input_type": "system/relay/store-entry",
            "output_type": "system/relay/put-result",
        },
        "poll": {
            "input_type": "system/relay/poll-request",
            "output_type": "system/relay/poll-result",
        },
        # All modes (§4.1)
        "advertise": {
            "input_type": "system/relay/advertise",
            "output_type": "system/relay/advertise",
        },
    },
)

ALL_HANDLER_MANIFESTS = [
    SYSTEM_HANDLER_MANIFEST,
    STORAGE_HANDLER_MANIFEST,
    CONNECT_HANDLER_MANIFEST,  # bootstrap protocol — discovery metadata only (see def)
    TREE_HANDLER_MANIFEST,
    HANDLERS_HANDLER_MANIFEST,  # V7 §6.2 system/handler register/unregister
    CAPABILITY_HANDLER_MANIFEST,  # V7 §6.2 system/capability request/delegate/revoke
    CONTINUATION_HANDLER_MANIFEST,  # V7.8 continuation handler
    INBOX_HANDLER_MANIFEST,  # V7.8 inbox handler
    SUBSCRIPTION_HANDLER_MANIFEST,
    REVISION_HANDLER_MANIFEST,  # EXTENSION-REVISION v2.1
    CLOCK_HANDLER_MANIFEST,  # EXTENSION-CLOCK v1.0
    QUERY_HANDLER_MANIFEST,  # EXTENSION-QUERY v1.0
    HISTORY_HANDLER_MANIFEST,  # EXTENSION-HISTORY v1.2
    COMPUTE_HANDLER_MANIFEST,  # EXTENSION-COMPUTE v3.5
    ATTESTATION_HANDLER_MANIFEST,  # EXTENSION-ATTESTATION v1.1 (substrate)
    QUORUM_HANDLER_MANIFEST,  # EXTENSION-QUORUM v1.1 (substrate)
    IDENTITY_HANDLER_MANIFEST,  # EXTENSION-IDENTITY v3.3
    ROLE_HANDLER_MANIFEST,  # EXTENSION-ROLE v1.5 (phase-1 ops)
    TYPE_HANDLER_MANIFEST,  # EXTENSION-TYPE v1.1 (validate + analysis ops)
    TYPE_CONSTRAINT_HANDLER_MANIFEST,  # EXTENSION-TYPE v1.1 (standard constraint dispatch)
    CONTENT_HANDLER_MANIFEST,  # EXTENSION-CONTENT v3.5 (get + ingest)
    SUBSTITUTE_HTTP_HANDLER_MANIFEST,  # CDN corridor v1 (http:try)
    LOCAL_FILES_HANDLER_MANIFEST,  # DOMAIN-LOCAL-FILES v1.2 (read/write/list/delete/watch)
    REGISTRY_HANDLER_MANIFEST,  # EXTENSION-REGISTRY v1.0 (substrate + local-name backend)
    DISCOVERY_HANDLER_MANIFEST,  # EXTENSION-DISCOVERY v1.0 (substrate + mDNS backend)
    RELAY_HANDLER_MANIFEST,  # EXTENSION-RELAY v1.0 (Mode F forward + Mode S store-and-poll)
]
