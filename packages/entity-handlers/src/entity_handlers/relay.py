"""EXTENSION-RELAY v1.0 — Mode F (forward) + Mode S (store-and-poll) substrate.

A **relay** carries opaque, signed, capability-bearing envelopes between two
endpoints. The origin's capability chain passes through unchanged; the relay
is *transport, not authority* (`reviews/ANALYSIS-RELAY-CAPABILITY-CHAIN.md`).
A relay peer is just a peer running ``system/relay`` (§1) — no special role.

This module implements the v1 floor (§10.1): **Mode F** (forward, §3.1) and
**Mode S** (store-and-poll, §3.2), the ``:advertise`` surface (§4.1), the
per-mode capability model (§5), and the fail-closed error taxonomy (§4.3).
Mode A (aggregate) and Mode C (circuit) are deferred (§11.1 / §11.1a) — their
entity types are named for forward-compatibility only.

Cohort discipline pins (carried from REGISTRY / DISCOVERY landings):

- **peer_id is Base58** (V7 §1.5) everywhere — ``destination`` / ``next_hop`` /
  ``put_by`` / namespace addressing. Never a content-hash (§3.0). Routing keyed
  on the wrong representation silently fails to match — the cross-impl trap.
- **Refless, no ``refs:`` block** (§3.0). The spec writes ``refs: envelope_inner:
  <system/hash>`` but the Python codebase is uniformly refless: a hash reference
  embedded in an entity's ``data`` is a **raw 33-byte system/hash byte string**
  (same as DISCOVERY ``supersedes`` / ``candidate``; see storage/indexes.py
  "system/hash values are stored as raw bytes"). The carried inner envelope
  rides in the request envelope's ``included`` set, keyed by that hash.
  *** FLAG F-PY-RELAY-1 (cross-impl byte divergence): §3.0 also describes
  ``<system/hash>`` as the *wrapped* 2-key form ``ECF({type:"system/hash",
  data:H})``. Embedded-in-data we use raw bytes (refless norm). The store-entry
  hash is fetched cross-impl, so its ECF MUST be byte-identical — pinned in
  tests/integration/test_relay_conformance.py for the Go/Rust byte-diff round. ***
- **Signatures via V7 §5.2 target-matching** at the invariant pointer
  ``system/signature/{hex(content_hash)}`` — relay entities carry no
  ``refs: {signature}`` block (§3.0 / §4.1).
- **Timestamps** are integer ms since the Unix epoch.

Envelope opacity (§9): the relay decodes only the **relay envelope**
(forward-request / store-entry) to read its outer routing fields. The **inner
envelope** is held opaque, addressed by hash; routing decisions are based
solely on outer fields. The relay MUST NOT decode, re-encode, or inject into
the inner envelope (§10.4).
"""

from __future__ import annotations

import logging
from typing import Any

from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.utils.ecf import ecf_encode as _ecf_encode
from entity_handlers._common import (
    error_response as _error,
    now_ms as _now_ms,
    ok_response as _ok,
    params_data as _params_data,
)
from entity_handlers.route import resolve_from_table

logger = logging.getLogger(__name__)

# -- Patterns / paths -------------------------------------------------------

RELAY_HANDLER_PATTERN = "system/relay"

# §3 entity types (v1 = F + S; A/C named for forward-compat, §3.3/§3.4).
FORWARD_REQUEST_TYPE = "system/relay/forward-request"
STORE_ENTRY_TYPE = "system/relay/store-entry"
ADVERTISE_TYPE = "system/relay/advertise"
FORWARD_RESULT_TYPE = "system/relay/forward-result"
PUT_RESULT_TYPE = "system/relay/put-result"
POLL_REQUEST_TYPE = "system/relay/poll-request"
POLL_RESULT_TYPE = "system/relay/poll-result"
# Deferred (§11) — named only.
AGGREGATE_SUBSCRIPTION_TYPE = "system/relay/aggregate-subscription"
CIRCUIT_RESERVATION_TYPE = "system/relay/circuit-reservation"
CIRCUIT_DIAL_TYPE = "system/relay/circuit-dial"

# Mode S store subtree: system/relay/store/{namespace}/{hash} (§3.2).
STORE_PREFIX = "system/relay/store/"
# Advertise entity: system/relay/advertise/{relay_peer_id} (§4.1).
ADVERTISE_PREFIX = "system/relay/advertise/"

# §3.5 system/peer/inbox-relay — MX-equivalent declaration (cohort R6/R7 fold,
# arch faf3fa9). A peer publishes a SIGNED declaration of where its mail is
# stored when unreachable; resolves the §6.2.1 fallback target (closes v1.0 Q2).
INBOX_RELAY_TYPE = "system/peer/inbox-relay"
# Authored at the declaring peer's own tree; SERVED always-on by REGISTRY
# (primary holder) keyed by peer_id at this path.
INBOX_RELAY_PREFIX = "system/peer/inbox-relay/"
# Deployment knob (read from tree at this path): the "MX-required" posture
# (§9.5). When disable_default_fallback is set, the default-convention fallback
# is off and an undeclared/non-targeting destination yields no_inbox_relay/502.
RELAY_CONFIG_PATH = "system/relay/config"

# -- Capability surface (§5.2) ----------------------------------------------
# Named for discovery/inspectability; the local peer holds them via the §6.9a
# owner-cap full-self-access floor. The §5.5 self-poll default grant (each peer
# P may poll namespace = P) is seeded by :func:`make_self_poll_grant_scope` for
# cross-peer use; own-peer access is covered by the owner cap.
RELAY_CAPS = (
    "system/capability/relay-forward",
    "system/capability/relay-put",
    "system/capability/relay-poll",
    "system/capability/relay-advertise",
    # Mode A (deferred, §5.2):
    "system/capability/relay-subscribe",
)

# -- Operations (§4) --------------------------------------------------------

_OP_FORWARD = "forward"
_OP_PUT = "put"
_OP_POLL = "poll"
_OP_ADVERTISE = "advertise"

# -- Bounds -----------------------------------------------------------------
# Default poll page size when the caller passes no `limit` (§4.2). Relay-owned;
# operator-configurable. Conservative default per [[feedback_expose_knobs]].
DEFAULT_POLL_LIMIT = 256
# Default Mode-S fallback rendezvous: namespace = destination peer_id (§6.2.1).

# §8 store bounds (v1.3). Both are read from the `system/relay/config` entity
# and both default OFF, so an unconfigured relay encodes and behaves exactly as
# it did at v1.2.
#
# `relay_store_retention` is the spec's own configuration name (§8.1); the
# published form of the same number is `limits.max_retention_ms` (§4.1). They
# are deliberately different strings in the corpus — one is the knob, one is
# the advertised ceiling — and conflating them is how a relay ends up
# publishing a bound it does not enforce.
CONFIG_STORE_RETENTION_MS = "relay_store_retention"
CONFIG_MAX_STORAGE_BYTES = "max_storage_bytes"
LIMIT_MAX_RETENTION_MS = "max_retention_ms"
LIMIT_MAX_STORAGE_BYTES = "max_storage_bytes"


# ===========================================================================
# Entity constructors (§3) — Base58 peer_id, refless raw-bytes system/hash
# ===========================================================================


def make_forward_request(
    *,
    destination: str,
    envelope_inner: bytes,
    ttl_hops: int,
    next_hop: str | None = None,
    route: list[str] | None = None,
    expires_at: int | None = None,
) -> Entity:
    """Construct a ``system/relay/forward-request`` (§3.1).

    ``destination`` / ``next_hop`` are Base58 PeerIDs (§3.0). ``envelope_inner``
    is the bare ``system/hash`` (raw 33-byte form, refless) of the carried inner
    envelope, which rides in the request envelope's ``included`` set.
    ``next_hop`` is OMITTED when ``None`` (optional-field-absent convention).

    ``route`` (v1.1, §3.1) is the originator's **source route**: the remaining
    relay hops in order, ending at ``destination`` (the *first* relay — the
    EXECUTE target — is NOT in ``route``). It is OMITTED when ``None`` / empty
    (omitempty), so a v1.0 single-hop request encodes byte-identically. When
    ``route`` is present and non-empty, ``next_hop`` is advisory and MUST equal
    ``route[0]`` if both are set (§3.1.1). Precedence on receipt is **source
    route > next_hop > route table** (§3.1.1).

    ``expires_at`` (v1.3, §3.1 — D7) is the **originator's** deadline in ms
    since epoch, OMITTED when ``None`` so a v1.2 request encodes
    byte-identically. It exists for the same reason ``ttl_hops`` does: the
    inner envelope's ``bounds.ttl_absolute`` is unreachable to a relay under §9
    opacity, so on the §6.2.1 store fallback — where the relay constructs the
    ``store-entry`` itself — the only party who knows how long the message is
    worth holding would otherwise have no way to say so. *A bound whose
    enforcing party cannot read it is not a bound.* It governs the fallback
    entry's **storage lifetime** only, and has no effect on a live forward.
    """
    data: dict[str, Any] = {
        "destination": destination,
        "ttl_hops": ttl_hops,
        "envelope_inner": envelope_inner,
    }
    if next_hop is not None:
        data["next_hop"] = next_hop
    if route:  # omitempty: None/empty dropped → byte-identical to v1.0
        data["route"] = list(route)
    if expires_at is not None:  # omitempty → byte-identical to v1.2
        data["expires_at"] = expires_at
    return Entity(type=FORWARD_REQUEST_TYPE, data=data)


def make_store_entry(
    *,
    namespace: str,
    envelope_inner: bytes,
    put_by: str,
    expires_at: int | None = None,
) -> Entity:
    """Construct a ``system/relay/store-entry`` (§3.2).

    ``namespace`` is the receiver-poll path; ``put_by`` is the Base58 PeerID
    that *placed* the entry (placement-identity, NOT authorship — §3.2);
    ``envelope_inner`` is the bare ``system/hash`` of the carried inner
    envelope. ``expires_at`` is OMITTED when ``None``.
    """
    data: dict[str, Any] = {
        "namespace": namespace,
        "put_by": put_by,
        "envelope_inner": envelope_inner,
    }
    if expires_at is not None:
        data["expires_at"] = expires_at
    return Entity(type=STORE_ENTRY_TYPE, data=data)


def make_inbox_relay(
    *,
    relays: list[dict[str, Any]],
    expires_at: int | None = None,
) -> Entity:
    """Construct a ``system/peer/inbox-relay`` declaration (§3.5).

    ``relays`` is a priority-ordered set of entries, each
    ``{"relay": <peer_id>, "namespace": <path>, "priority": <u32>}`` — the
    MX-equivalent. Lower ``priority`` is preferred (backups higher). A resolver
    MUST try entries in ascending priority order. ``expires_at`` is OMITTED when
    ``None`` (omitempty; ``null`` = until superseded). Mirrors Go's
    ``InboxRelayData{Relays, ExpiresAt}`` / ``InboxRelayEntry{Relay, Namespace,
    Priority}`` byte shape.

    AUTHORED + SIGNED by the declaring peer per V7 §5.2 (signature at the
    invariant pointer; no ``refs:`` block). Stored at
    ``system/peer/inbox-relay/{peer_id}``.
    """
    entries = [
        {
            "relay": e["relay"],
            "namespace": e.get("namespace", ""),
            "priority": int(e.get("priority", 0)),
        }
        for e in relays
    ]
    data: dict[str, Any] = {"relays": entries}
    if expires_at:  # omitempty: 0 / None dropped (matches Go cbor omitempty)
        data["expires_at"] = expires_at
    return Entity(type=INBOX_RELAY_TYPE, data=data)


def inbox_relay_storage_path(peer_id: str) -> str:
    """Canonical storage path for a peer's inbox-relay declaration (§3.5):
    ``system/peer/inbox-relay/{peer_id}``."""
    return f"{INBOX_RELAY_PREFIX}{peer_id}"


def make_advertise(
    *,
    modes: list[str],
    endpoints: list[Any],
    caps_required: list[str],
    limits: dict[str, Any] | None = None,
    expires_at: int | None = None,
) -> Entity:
    """Construct a ``system/relay/advertise`` (§4.1).

    Published at ``system/relay/advertise/{relay_peer_id}`` and MUST be signed
    by ``relay_peer_id`` per V7 §5.2 (signature at the invariant pointer; no
    ``refs:`` block). ``modes`` is a subset of ``["F", "S"]`` in v1.
    """
    data: dict[str, Any] = {
        "modes": modes,
        "endpoints": endpoints,
        "limits": limits if limits is not None else {},
        "caps_required": caps_required,
    }
    if expires_at is not None:
        data["expires_at"] = expires_at
    return Entity(type=ADVERTISE_TYPE, data=data)


# ===========================================================================
# Namespace validation (§4.3 namespace_invalid)
# ===========================================================================


def _validate_namespace(namespace: Any) -> str | None:
    """Return the normalized namespace, or ``None`` if malformed (§4.3).

    A namespace is a path segment sequence: non-empty, NUL-free, no ``..``
    traversal. Leading/trailing slashes are stripped. Matches the v7.72 Class
    A1 path-NUL rejection discipline.
    """
    if not isinstance(namespace, str):
        return None
    ns = namespace.strip("/")
    if not ns or "\x00" in ns:
        return None
    if any(seg in ("", "..", ".") for seg in ns.split("/")):
        return None
    return ns


def _store_namespace_prefix(namespace: str) -> str:
    """Tree prefix for a namespace's entries: ``system/relay/store/{ns}/``."""
    return f"{STORE_PREFIX}{namespace}/"


# ===========================================================================
# §8 store bounds (v1.3) — the retention ceiling and the storage bound
# ===========================================================================


def _relay_config(ctx: HandlerContext) -> dict[str, Any]:
    """The operator's ``system/relay/config`` data, or ``{}``.

    One read for every knob this handler has. It replaced a per-knob reader
    because a second config field arriving with its own tree read is how two
    operations end up disagreeing about one entity.
    """
    cfg = _get_entity(
        ctx, ctx.emit_pathway.entity_tree.normalize_uri(RELAY_CONFIG_PATH)
    )
    if cfg is None or not isinstance(cfg.data, dict):
        return {}
    return cfg.data


def _config_bound(cfg: dict[str, Any], key: str) -> int:
    """A §8 bound from the config: a positive int, or 0 for "not enforced".

    Fails **open** deliberately, and only here: a malformed bound in the tree
    means the relay declares none, which is the v1.2 behaviour. The place a
    malformed bound is refused is the CLI that writes it (a typo'd ceiling is a
    request for a ceiling, and the operator is present to be told). By the time
    a value is in the tree there is no operator to tell, and refusing every
    `:put` because a config key is a string would take the relay down.
    """
    value = cfg.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return 0
    return value


def _clamp_expiry(now: int, expires_at: int | None, retention_ms: int) -> int | None:
    """The §8.1 retention ceiling. **One implementation, both store-write
    producers** — the direct ``:put`` (:func:`_handle_put`) and the §6.2.1
    Mode-F→Mode-S fallback (:func:`_fallback_store`).

    That is not tidiness. ``entity-core-go`` landed the ceiling on ``:put``
    alone and left its fallback path writing an unconditional null expiry —
    the second producer of the store shape inheriting none of the bound —
    and had to file the miss against itself (`0f9eb65`). A relay whose two
    write paths disagree about the bound does not have one.

    With no ceiling configured this is the **identity**: a null stays null
    ("hold until polled"), a set deadline survives verbatim. That is what lets
    the fallback path call it unconditionally. With a ceiling it clamps
    **down** only, so it can never EXTEND a deadline the originator set (§3.1
    MUST NOT) and can never turn a future expiry into an expired-on-arrival
    entry.

    §8.1 states the null arm rather than deriving it, because ``min(x,
    ceiling)`` has no arm for null — the same shape as REGISTRY §6a.9.1's ttl
    ceiling, where a guard that read as a type check silently narrowed the MUST
    to the values that already had a bound.
    """
    if retention_ms <= 0:
        return expires_at
    ceiling = now + retention_ms
    if expires_at is None or expires_at > ceiling:
        return ceiling
    return expires_at


def _entry_cost(store_entry: Entity, inner: Entity | None) -> int:
    """The §8.2 byte cost of one stored entry.

    **The metric is not defined by the spec** — §8.2's MUST turns on a byte
    count and neither §8.2 nor §4.1 says which bytes. `entity-core-go` routed
    that as spec-issue `2026-09-01-a` and documented its own choice; this is
    the same choice, deliberately, so that two peers under one eventual
    conformance vector count the same number: **the ECF bytes of the two
    entities the relay physically persists** — the store-entry's data and the
    opaque inner envelope's data — summed **relay-wide**.

    Matching go here is *not* convergence and is not evidence the metric is
    right; it is two seats declining to widen an unruled divergence while a
    ruling is pending. We concur with go's filing rather than filing a
    duplicate, and will move to whatever §8.2 is ruled to.

    ECF is deterministic (V7 §1.5), so the count is stable across peers and a
    hash-equal re-put costs exactly the same — which is what makes the §8.2
    dedup rule below expressible at all.
    """
    cost = len(_ecf_encode(store_entry.data))
    if inner is not None:
        cost += len(_ecf_encode(inner.data))
    return cost


def _live_stored_bytes(ctx: HandlerContext, now: int) -> int:
    """The relay-wide live byte total (§8.2).

    Relay-wide, not per-namespace: §8.2 says *"the relay's advertised
    max_storage_bytes"*, and a per-namespace reading would let a putter with
    two namespaces hold twice the advertised bound.

    Expired entries do not count. That is the §8.2 line that needs saying out
    loud: expiry freeing bytes is **not** eviction-to-make-room — the relay
    never removes a *live* entry to admit a new one, it only stops counting
    entries whose own deadline has passed, which §4.2 already makes invisible
    to a poller.

    Walks the store subtree, which is only reached when a bound is configured;
    an unbounded relay never pays for it.
    """
    total = 0
    for uri in ctx.emit_pathway.entity_tree.list_prefix(STORE_PREFIX):
        entry = _get_entity(ctx, uri)
        if entry is None or entry.type != STORE_ENTRY_TYPE:
            continue  # skips the `inner/` bindings, counted via their entry
        exp = entry.data.get("expires_at")
        if isinstance(exp, int) and exp <= now:
            continue
        inner_hash = entry.data.get("envelope_inner")
        inner = (
            ctx.emit_pathway.content_store.get(inner_hash)
            if isinstance(inner_hash, bytes)
            else None
        )
        total += _entry_cost(entry, inner)
    return total


# ===========================================================================
# Handler dispatch
# ===========================================================================


async def relay_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: HandlerContext,
) -> dict[str, Any]:
    """``system/relay`` handler — Mode F + Mode S (§4).

    Each op carries a relay-envelope request entity; the inner envelope stays
    opaque (§9). Per-op cap enforcement is the dispatcher's job (§5.2); this
    handler owns the operation semantics and the relay-owned error codes (§4.3).
    """
    if operation == _OP_PUT:
        return await _handle_put(params, ctx)
    if operation == _OP_POLL:
        return await _handle_poll(params, ctx)
    if operation == _OP_FORWARD:
        return await _handle_forward(params, ctx)
    if operation == _OP_ADVERTISE:
        return await _handle_advertise(params, ctx)
    return _error(
        501,
        "unsupported_operation",
        f"Relay handler does not support operation: {operation}",
    )


# ---------------------------------------------------------------------------
# Mode S — store-and-poll (§3.2 / §4.2)
# ---------------------------------------------------------------------------


def _authenticated_caller(ctx: HandlerContext) -> str:
    """The Base58 PeerID of the authenticated caller for this op.

    *** FLAG F-PY-RELAY-2: §3.2 says ``put_by`` MUST equal "the authenticated
    caller". Python uses the connection-authenticated session identity
    (``ctx.remote_peer_id``). For a direct ``:put`` this equals the
    inner-envelope author; they diverge only on cross-peer dispatch where the
    wire author (``ctx.author_identity_hash``) differs from the session peer.
    The relay cannot read the *inner* author (opacity, §9) — the relevant
    "caller" is the one that placed the entry over *this* connection, which is
    the session peer. Flagged for cohort confirm against Go's R3 plumbing. ***
    """
    return ctx.remote_peer_id


async def _handle_put(
    params: dict[str, Any], ctx: HandlerContext
) -> dict[str, Any]:
    """``system/relay:put`` (Mode S, §4.2). Request IS a store-entry (§3.2).

    Fail-closed (§4.3): on any error nothing is stored. Verifies
    ``put_by == authenticated caller`` (§3.2), namespace validity, and
    non-expired ``expires_at``.
    """
    data = _params_data(params)

    namespace = _validate_namespace(data.get("namespace"))
    if namespace is None:
        return _error(400, "namespace_invalid", "Malformed namespace path")

    put_by = data.get("put_by")
    if put_by != _authenticated_caller(ctx):
        return _error(
            400,
            "put_by_mismatch",
            "store-entry.put_by does not match the authenticated caller",
        )

    now = _now_ms()
    expires_at = data.get("expires_at")
    if isinstance(expires_at, int) and expires_at <= now:
        return _error(
            400, "expired_on_arrival", "expires_at is already past at put time"
        )

    envelope_inner = data.get("envelope_inner")
    if not isinstance(envelope_inner, bytes) or not envelope_inner:
        return _error(
            400,
            "namespace_invalid",
            "store-entry must carry an envelope_inner system/hash",
        )

    # §8.1 retention ceiling (v1.3): CLAMP a long or null expires_at, never
    # refuse. Refusing would convert an operator's capacity policy into a
    # delivery failure the sender cannot tell from an outage — so the ceiling
    # is invisible to a correct sender and fatal to none.
    #
    # Ordering: this runs BEFORE the store-entry is authored, so the clamped
    # deadline is what gets hashed, stored, polled, and echoed. Clamping after
    # would store one deadline and hash another. It runs AFTER the
    # expired_on_arrival check because that check is about what the caller
    # SENT; the clamp only ever lowers toward a future ceiling and can never
    # produce the expired value the check refuses.
    cfg = _relay_config(ctx)
    retention_ms = _config_bound(cfg, CONFIG_STORE_RETENTION_MS)
    max_storage_bytes = _config_bound(cfg, CONFIG_MAX_STORAGE_BYTES)
    stored_expires_at = _clamp_expiry(
        now, expires_at if isinstance(expires_at, int) else None, retention_ms
    )

    # Re-author the store-entry locally so its hash is canonical (the caller's
    # claimed content_hash, if any, is not trusted as the store key).
    store_entry = make_store_entry(
        namespace=namespace,
        envelope_inner=envelope_inner,
        put_by=put_by,
        expires_at=stored_expires_at,
    )
    entry_hash = store_entry.compute_hash()
    storage_path = f"{_store_namespace_prefix(namespace)}{entry_hash.hex()}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(storage_path)

    # §8.2 storage bound (v1.3): a put that would push the relay-wide live
    # total over the advertised `max_storage_bytes` is REFUSED — and the relay
    # MUST NOT evict an accepted entry to make room. Refuse-new rather than
    # evict-old is the same call EXTENSION-NETWORK §8.4 already made for the
    # sender-side pending queue: an accepted entry is a promise, and a store
    # that breaks old promises to keep new ones is worse than one that says no.
    #
    # Checked before ANY write, including the inner-envelope binding below —
    # §4.3 is fail-closed, so a refused put must leave nothing behind. Ordering
    # this after `_persist_included` would store the payload and refuse the
    # pointer, which is the worst of both.
    #
    # Dedup: a hash-equal re-put is already at this exact path (the path keys
    # on the entry hash), costs no new bytes, and MUST NOT be refused on a full
    # store — otherwise a retry, which is the one thing a sender does when it
    # is unsure, is the request a full relay rejects.
    if max_storage_bytes > 0 and ctx.emit_pathway.entity_tree.get(full_uri) is None:
        inner_entity = _included_entity(ctx, envelope_inner)
        cost = _entry_cost(store_entry, inner_entity)
        if _live_stored_bytes(ctx, now) + cost > max_storage_bytes:
            return _error(
                507,
                "storage_full",
                f"accepting {cost} bytes would exceed max_storage_bytes "
                f"{max_storage_bytes} (§8.2 — the relay refuses and does not evict)",
            )

    # Tree-bind the carried inner envelope (opaque, §9) under the namespace
    # subtree so a later poll+fetch resolves it via `tree:get` (§3.2 ruling).
    # It rides in the request envelope's `included`, keyed by envelope_inner.
    _persist_included(ctx, envelope_inner, namespace, _OP_PUT)

    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_PUT)
    ctx.emit_pathway.emit(full_uri, store_entry, emit_ctx)

    return _ok(
        PUT_RESULT_TYPE,
        {
            "status": "stored",
            "stored_at": storage_path,
            "entry_hash": entry_hash,
            # The STORED deadline, not the submitted one. This is the only
            # surface on which a clamp is observable to the sender, and it is
            # what the cross-impl §8.1 rows read.
            "expires_at": stored_expires_at,
        },
    )


async def _handle_poll(
    params: dict[str, Any], ctx: HandlerContext
) -> dict[str, Any]:
    """``system/relay:poll`` (Mode S, §4.2) — relay-owned cursor over the
    namespace subtree ``system/relay/store/{namespace}/*``.

    Empty namespace is NOT an error (§4.2): a namespace with no live entries
    returns ``{entries: [], has_more: false}`` at 200 — the steady state for a
    freshly-created fallback inbox. ``namespace_not_found`` is reserved for
    explicitly-provisioned deployments (not v1's open-namespace default).

    Returns store-entry **hashes** (pointers), not inline bytes (§4.2 two-hop
    pointer discipline). The receiver fetches each store-entry by hash, reads
    its ``envelope_inner`` ref, and fetches the inner envelope.

    Cursor: relay-owned, lexicographic over the stored tree paths (which key on
    the entry hash). ``since`` = the last path returned; entries with path >
    ``since`` are returned next. Stable and resumable.
    """
    data = _params_data(params)

    namespace = _validate_namespace(data.get("namespace"))
    if namespace is None:
        return _error(400, "namespace_invalid", "Malformed namespace path")

    since = data.get("since")
    limit = data.get("limit")
    if not isinstance(limit, int) or limit <= 0:
        limit = DEFAULT_POLL_LIMIT

    prefix = _store_namespace_prefix(namespace)
    full_prefix = ctx.emit_pathway.entity_tree.normalize_uri(prefix)
    all_uris = ctx.emit_pathway.entity_tree.list_prefix(prefix)  # sorted

    # Honor expiry lazily on read (GC §8 may also evict); skip expired entries.
    now = _now_ms()
    cursor_floor = since if isinstance(since, str) else ""
    entries: list[bytes] = []
    last_uri = cursor_floor
    has_more = False
    for uri in all_uris:
        if uri <= cursor_floor:
            continue
        entry = _get_entity(ctx, uri)
        if entry is None or entry.type != STORE_ENTRY_TYPE:
            continue
        exp = entry.data.get("expires_at")
        if isinstance(exp, int) and exp <= now:
            continue
        if len(entries) >= limit:
            has_more = True
            break
        entries.append(entry.compute_hash())
        last_uri = uri

    return _ok(
        POLL_RESULT_TYPE,
        {
            "entries": entries,
            "cursor": last_uri,
            "has_more": has_more,
        },
    )


async def _handle_advertise(
    params: dict[str, Any], ctx: HandlerContext
) -> dict[str, Any]:
    """``system/relay:advertise`` (§4.1) — publish this relay's advertise entity
    at ``system/relay/advertise/{relay_peer_id}``.

    The entity is authored locally and signed by the relay's own keypair via
    the §5.2 target-matching path (signature at the invariant pointer; no
    ``refs:`` block). Typically operator-only (``relay-advertise`` cap).
    """
    data = _params_data(params)

    modes = data.get("modes") or ["S"]
    endpoints = data.get("endpoints") or []
    caps_required = data.get("caps_required") or []
    limits = data.get("limits") if isinstance(data.get("limits"), dict) else {}
    expires_at = data.get("expires_at")

    storage_path, adv_hash = publish_advertise(
        emit_pathway=ctx.emit_pathway,
        keypair=getattr(ctx, "keypair", None),
        local_peer_id=ctx.local_peer_id,
        modes=list(modes),
        endpoints=list(endpoints),
        caps_required=list(caps_required),
        limits=_published_limits(_relay_config(ctx), limits),
        expires_at=expires_at if isinstance(expires_at, int) else None,
        emit_ctx=EmitContext.from_handler_grant(ctx, _OP_ADVERTISE),
    )

    return _ok(
        ADVERTISE_TYPE,
        {
            "published_at": storage_path,
            "advertise_hash": adv_hash,
            "modes": list(modes),
        },
    )


def publish_advertise(
    *,
    emit_pathway: Any,
    keypair: Any,
    local_peer_id: str,
    modes: list[str],
    endpoints: list[Any],
    caps_required: list[str],
    limits: dict[str, Any],
    expires_at: int | None = None,
    emit_ctx: EmitContext,
) -> tuple[str, bytes]:
    """Author, sign and bind a §4.1 advertise. Returns ``(path, hash)``.

    **One implementation, two callers**: the `:advertise` operation, and the
    peer-startup seam that publishes the §8 bounds when an operator configures
    them (there is no handler dispatch at startup, and §4.1's MUST binds the
    relay, not the operation that happened to publish). Two authoring paths
    would be two advertise shapes, and the shape is signed.

    Signature at the V7 §5.2 invariant pointer, bound BEFORE the advertise
    itself: a reader that can see the advertise can always resolve the
    signature that makes it trustworthy. The reverse order leaves a window in
    which the published ceiling is unverifiable, which is precisely the state a
    forger wants.
    """
    advertise = make_advertise(
        modes=modes,
        endpoints=endpoints,
        caps_required=caps_required,
        limits=limits,
        expires_at=expires_at,
    )
    adv_hash = advertise.compute_hash()

    if keypair is not None:
        from entity_core.protocol.auth import (
            create_identity_entity,
            create_signature_entity,
        )

        signer_hash = create_identity_entity(keypair).compute_hash()
        signature = create_signature_entity(keypair, adv_hash, signer_hash)
        emit_pathway.emit(
            f"system/signature/{adv_hash.hex()}", signature, emit_ctx
        )

    storage_path = f"{ADVERTISE_PREFIX}{local_peer_id}"
    full_uri = emit_pathway.entity_tree.normalize_uri(storage_path)
    bound_hash = emit_pathway.emit(full_uri, advertise, emit_ctx).hash
    return storage_path, bound_hash


def _published_limits(
    cfg: dict[str, Any], requested: dict[str, Any]
) -> dict[str, Any]:
    """The §4.1 ``limits`` block, with the §8 bounds this relay actually
    enforces written over whatever the caller asked for.

    §4.1 is `[MUST when present]`: a relay enforcing a §8 ceiling MUST publish
    it here. The enforced value is authoritative — an operator who passes a
    different `max_retention_ms` gets the real one, because the alternative is
    publishing a ceiling the relay does not honor, and the whole reason §8.1
    makes publication a MUST is that *"a ceiling that is enforced but
    unpublished configures behaviour no counterparty can observe before
    depending on it."* A published ceiling that is not the enforced one is
    worse than an absent one: it is observable and wrong.

    A bound that is not enforced is OMITTED rather than published as 0 —
    absent means *"this relay declares no ceiling"*, which §8.1 is careful to
    say does **not** mean unbounded. An unconfigured relay's advertise is
    therefore byte-identical to v1.2.
    """
    limits = dict(requested)
    for config_key, limit_key in (
        (CONFIG_STORE_RETENTION_MS, LIMIT_MAX_RETENTION_MS),
        (CONFIG_MAX_STORAGE_BYTES, LIMIT_MAX_STORAGE_BYTES),
    ):
        enforced = _config_bound(cfg, config_key)
        if enforced > 0:
            limits[limit_key] = enforced
    return limits


def publish_self_advertise(
    emit_pathway: Any, keypair: Any, local_peer_id: str, config: dict[str, Any]
) -> tuple[str, bytes] | None:
    """Publish this relay's own §4.1 advertise carrying its §8 bounds, or
    ``None`` when no bound is configured.

    The startup seam. §4.1 makes publication a MUST *when a ceiling is
    enforced*, and the `:advertise` operation cannot discharge it on its own:
    an operator who sets a bound and never calls `:advertise` would enforce a
    ceiling no counterparty can read, which is the exact state §8.1 names as
    the reason the MUST exists. So the bound and its publication are wired to
    the same act.

    An unbounded relay publishes nothing — there is no ceiling to declare, and
    §8.1 is explicit that an absent `max_retention_ms` does **not** mean
    unbounded. Publishing an empty advertise would assert reachability this
    relay has not been configured to offer.
    """
    limits = _published_limits(config, {})
    if not limits:
        return None
    return publish_advertise(
        emit_pathway=emit_pathway,
        keypair=keypair,
        local_peer_id=local_peer_id,
        # v1 serves Mode F (forward) + Mode S (store-poll) — §10.1's floor.
        modes=["F", "S"],
        endpoints=[],
        caps_required=["system/capability/relay-poll"],
        limits=limits,
        emit_ctx=EmitContext.bootstrap(),
    )


# ---------------------------------------------------------------------------
# Mode F — forward (§3.1 / §4.2)
# ---------------------------------------------------------------------------


async def _handle_forward(
    params: dict[str, Any], ctx: HandlerContext
) -> dict[str, Any]:
    """``system/relay:forward`` (Mode F, §4.2). Request IS a forward-request.

    The relay decrements ``ttl_hops`` and rejects at 0 on receipt (§3.1). It
    distinguishes the intermediate hop (forward the relay-typed request to the
    next relay) from the terminal hop (unwrap and dispatch the *bare inner
    envelope* to the destination — §3.1.1). If the destination has no live
    session, Mode F falls back to Mode S (§6.2.1), returning queued-fallback.
    """
    data = _params_data(params)

    destination = data.get("destination")
    if not isinstance(destination, str) or not destination:
        return _error(400, "namespace_invalid", "forward-request missing destination")

    ttl_hops = data.get("ttl_hops")
    if not isinstance(ttl_hops, int) or ttl_hops <= 0:
        # MUST reject fail-closed at 0 on receipt (§3.1). A missing/invalid
        # ttl is treated as exhausted (no implicit unbounded forwarding).
        return _error(400, "ttl_exhausted", "ttl_hops reached 0 on receipt")

    envelope_inner = data.get("envelope_inner")
    if not isinstance(envelope_inner, bytes) or not envelope_inner:
        return _error(400, "namespace_invalid", "forward-request missing envelope_inner")

    # D7 (§3.1, v1.3) — the originator's storage deadline, read off the OUTER
    # request because §9 forbids reading the inner envelope's bounds. It is
    # consumed only on the §6.2.1 fallback (both fallback sites below); a live
    # forward either succeeds or falls back within this one operation, so there
    # is nothing for it to bound on the forwarding path. Absent (v1.2 shape) is
    # None and reaches the ceiling's null arm.
    request_expires_at = data.get("expires_at")
    if not isinstance(request_expires_at, int) or isinstance(request_expires_at, bool):
        request_expires_at = None

    # §3.1.1 per-hop next-hop determination — three sources in precedence order
    # (source route > next_hop shorthand > route table). `route` (v1.1) is the
    # originator's source route; `remaining` is what the next relay receives
    # after we pop the head.
    next_hop = data.get("next_hop")
    route = data.get("route")
    next: str
    remaining: list[str]
    if isinstance(route, list) and route:
        # 1. Source route — the originator dictated the path. Cross-field
        #    invariant: if next_hop is also set it MUST equal route[0], else
        #    invalid_request/400 PRE-DISPATCH (before any forward; §3.1.1).
        next = route[0]
        remaining = list(route[1:])
        if next_hop is not None and next_hop != next:
            return _error(
                400,
                "invalid_request",
                f"next_hop ({next_hop}) MUST equal route[0] ({next}) when both are set (§3.1.1)",
            )
    elif next_hop is not None:
        # 2. next_hop shorthand — the degenerate single-hop / single-element
        #    route (v1.0 behavior).
        next = next_hop
        remaining = []
    else:
        # 3. Route table — both absent: consult the local system/route table
        #    per EXTENSION-ROUTE §3 (exact > `*` default, lowest metric,
        #    expiry-skip). No match → no_route/502 (§3.1.1; the §6.2.1 Mode-S
        #    fallback only fires after a terminal dispatch attempt fails).
        table_next, hit = resolve_from_table(ctx, destination)
        if not hit or table_next is None:
            return _error(
                502,
                "no_route",
                "no source route, no next_hop, and no matching system/route entry",
            )
        next = table_next
        remaining = []

    new_ttl = ttl_hops - 1

    # Terminal hop: the chosen next hop is the destination itself (§3.1.1).
    if next == destination:
        delivered = await _deliver_terminal(ctx, destination, envelope_inner)
        if delivered:
            return _ok(
                FORWARD_RESULT_TYPE,
                {"status": "forwarded", "next_hop": next, "stored_at": None},
            )
        # No live session → Mode-S fallback (§6.2.1). Resolve the destination's
        # system/peer/inbox-relay declaration (§3.5) to choose the store
        # namespace; absent one (or none targeting us), the default convention
        # is namespace = destination peer_id unless the MX-required posture
        # (disable_default_fallback) is set, in which case → no_inbox_relay/502
        # (fail-closed, never a silent drop — §9.5).
        namespace, code = _resolve_fallback_target(ctx, destination)
        if code is not None:
            return _error(
                502,
                code,
                "destination unreachable and no usable inbox-relay (§3.5/§6.2.1)",
            )
        # Store under the forwarder's relay-forward authority (§5.5) — the
        # caller needs no separate relay-put for the fallback.
        _fallback_store(ctx, namespace, envelope_inner, request_expires_at)
        # §4.2 (Rust R6 catch): forward-result.stored_at for queued-fallback is
        # the NAMESPACE (the destination polls it), NOT the full path+hash.
        return _ok(
            FORWARD_RESULT_TYPE,
            {"status": "queued-fallback", "next_hop": None, "stored_at": namespace},
        )

    # Intermediate hop: forward the (ttl-decremented) relay request to `next`
    # as a system/relay:forward EXECUTE. The next relay is another RELAY peer;
    # the inner envelope rides opaquely in `included` (§9). When the inbound
    # carried a source route we pop the head: route' = route[1:] and MUST set
    # next_hop' = route'[0] (or None when route' empty) so a downstream receiver
    # that reads next_hop first resolves correctly (§3.1.1 cross-impl trap).
    # Single-hop callers (next_hop only, no route) preserve the v1.0 shape:
    # `remaining` is empty, `route` drops via omitempty, and next_hop' is None
    # so the next relay chooses its own next hop.
    #
    # D7's `expires_at` travels with the request, unclamped. Two halves:
    #
    # It TRAVELS because the field is the originator's, and §3.1 grounds it as
    # *"the same move `ttl_hops` already makes"* — an outer copy of a bounding
    # concept, precisely because the inner one is unreachable. `ttl_hops` is
    # carried hop to hop; a deadline that is dropped at the first intermediate
    # relay leaves hop 2's §6.2.1 fallback storing with no bound at all, which
    # is `MUST NOT extend a deadline the originator set` reached by omission.
    # (`entity-core-go` rebuilds the relayed request without it — `ext/relay/
    # relay.go` `relayed := types.ForwardRequestData{...}`. Filed as SA-PY-30
    # and routed; we carry it because dropping it is the behaviour D7 exists to
    # stop, not because our reading outranks theirs.)
    #
    # It is UNCLAMPED because §8.1's ceiling bounds what THIS relay stores, not
    # what another relay may hold. Clamping here would silently impose our
    # operator's capacity policy on a peer we are only transiting through.
    next_hop_relayed = remaining[0] if remaining else None
    forward_req = make_forward_request(
        destination=destination,
        envelope_inner=envelope_inner,
        ttl_hops=new_ttl,
        next_hop=next_hop_relayed,
        route=remaining or None,
        expires_at=request_expires_at,
    )
    inner_entity = _included_entity(ctx, envelope_inner)
    included = (
        {envelope_inner: inner_entity.to_dict()} if inner_entity is not None else None
    )
    result = await ctx.execute(
        f"entity://{next}/{RELAY_HANDLER_PATTERN}",
        _OP_FORWARD,
        {"type": FORWARD_REQUEST_TYPE, "data": forward_req.data},
        resource_targets=[RELAY_HANDLER_PATTERN],
        included=included,
    )
    # §3.1.1 + §6.2.1: B reports its OWN hop decision — it forwarded to `next`.
    # Mirroring Go's PeerDispatcher.ForwardToNextHop, a *reachable* next that
    # responds — even with its own business error (e.g. it can't route onward
    # to `destination`) — is a successful forward at THIS hop (err==nil). Only a
    # genuine connectivity failure to `next` (unreachable / no dial) triggers
    # the §6.2.1 Mode-S fallback. The structural signal: a reachable next always
    # returns a response body (`result.result` is a dict), whereas a transport
    # failure surfaces as a bodyless 502 ("Remote execute failed" / no route to
    # peer) — the analog of Go's isUnreachable.
    next_reachable = result.ok or result.result is not None
    if next_reachable:
        return _ok(
            FORWARD_RESULT_TYPE,
            {"status": "forwarded", "next_hop": next, "stored_at": None},
        )

    # Unreachable intermediate `next` → §6.2.1 Mode-S fallback (srcr5), the same
    # codepath as the terminal-unreachable case. The fallback namespace is the
    # ultimate `destination` (NOT the unreachable hop): the destination polls
    # its own inbox. Honor the §3.5 inbox-relay declaration; absent a usable one
    # under the MX-required posture → no_inbox_relay/502 (never a silent drop).
    namespace, code = _resolve_fallback_target(ctx, destination)
    if code is not None:
        return _error(
            502,
            code,
            "next hop unreachable and no usable inbox-relay (§3.5/§6.2.1)",
        )
    _fallback_store(ctx, namespace, envelope_inner, request_expires_at)
    return _ok(
        FORWARD_RESULT_TYPE,
        {"status": "queued-fallback", "next_hop": None, "stored_at": namespace},
    )


async def _deliver_terminal(
    ctx: HandlerContext, destination: str, envelope_inner: bytes
) -> bool:
    """Terminal-hop delivery (§3.1.1): unwrap and dispatch the *bare inner
    envelope* to ``destination`` as a normal inbound EXECUTE — byte-identical
    to a direct connection (§9). The destination needs no RELAY extension to
    receive (required by §5.1: it verifies the inner signature + cap chain
    exactly as on a direct connection).

    Reuses the peer-level terminal-hop hookpoint (``ctx.relay_send``) when the
    handler context exposes it; that hookpoint reuses the *destination's*
    inbound ``_handle_execute`` entrypoint (the relay side only writes the raw
    frame / pushes the held session). Returns True on delivery to a live
    session, False when no live session exists (→ Mode-S fallback, §6.2.1).

    *** FLAG F-PY-RELAY-3 (cohort-gated seam, surfaced per the R7 handoff):
    the relay must forward the *original inner bytes* unchanged (§9 — decode +
    re-encode is not guaranteed byte-identical). The exact carriage — how a
    full inner ``{root, included}`` envelope becomes ONE content-addressed
    entity in the outer `included` — is the cross-impl wire decision pinned by
    Go's R1–R2 (RELAY R5 gate). Until that lands, this hookpoint is wired but
    the byte-fidelity contract is NOT yet locked; remote terminal-hop is the
    one seam not own-peer-closable. See the Python landing doc. ***
    """
    relay_send = getattr(ctx, "relay_send", None)
    if relay_send is None:
        return False
    inner_entity = _included_entity(ctx, envelope_inner)
    if inner_entity is None:
        return False
    try:
        return await relay_send(destination, inner_entity)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("relay terminal-hop delivery to %s failed: %s", destination[:16], e)
        return False


def _fallback_store(
    ctx: HandlerContext,
    namespace: str,
    envelope_inner: bytes,
    expires_at: int | None = None,
) -> str:
    """Mode-S fallback store (§6.2.1): place the entry at the resolved
    ``namespace`` under the forwarder's authority (§5.5). Returns the full
    store path. ``put_by`` = the relay itself — the relay placed it on the
    origin's behalf; authorship stays the inner-envelope signature (§3.2; the
    one case where ``put_by`` diverges from authorship by design).

    ``expires_at`` is the **originator's** deadline, carried on the outer
    ``forward-request`` (§3.1, D7) because the inner envelope's
    ``bounds.ttl_absolute`` is opaque to a relay under §9. This is the second
    producer of the store shape, and it goes through the same
    :func:`_clamp_expiry` as ``:put``: honored verbatim where the relay
    declares no ceiling, clamped down where it does, never extended.
    """
    _persist_included(ctx, envelope_inner, namespace, _OP_FORWARD)
    store_entry = make_store_entry(
        namespace=namespace,
        envelope_inner=envelope_inner,
        put_by=ctx.local_peer_id,  # placement-identity = the relay (§3.2)
        expires_at=_clamp_expiry(
            _now_ms(),
            expires_at,
            _config_bound(_relay_config(ctx), CONFIG_STORE_RETENTION_MS),
        ),
    )
    entry_hash = store_entry.compute_hash()
    storage_path = f"{_store_namespace_prefix(namespace)}{entry_hash.hex()}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(storage_path)
    emit_ctx = EmitContext.from_handler_grant(ctx, _OP_FORWARD)
    ctx.emit_pathway.emit(full_uri, store_entry, emit_ctx)
    return storage_path


# ---------------------------------------------------------------------------
# §3.5 inbox-relay fallback resolution (the MX-equivalent; cohort R6/R7 fold)
# ---------------------------------------------------------------------------


def _inbox_relay_declaration(ctx: HandlerContext, destination: str) -> dict | None:
    """Resolve the destination's ``system/peer/inbox-relay`` declaration data
    (§3.5), or ``None`` if undeclared **or not signed by the destination**.

    v1 Python resolves from the **local tree** (``system/peer/inbox-relay/
    {destination}``) — the relay-as-always-on-holder role (§3.1: a relay named
    in the declaration serves it). The cross-peer "fetch from REGISTRY" leg is
    still substrate, but the **forged-redirection defense (§3.5 + V7 §5.2, §7.1
    MUST)** is enforced here regardless of authority origin: the declaration is
    honored only if its invariant-pointer signature verifies against the
    destination's own key (``_verify_inbox_relay_signature``). A declaration
    that any peer wrote into the relay's tree without the destination's
    signature is rejected fail-closed → treated as no declaration → the
    §6.2.1 default convention takes over (never the attacker's namespace).
    """
    ent = _get_entity(
        ctx, ctx.emit_pathway.entity_tree.normalize_uri(inbox_relay_storage_path(destination))
    )
    if ent is None or ent.type != INBOX_RELAY_TYPE:
        return None
    if not _verify_inbox_relay_signature(ctx, destination, ent):
        return None
    return ent.data if isinstance(ent.data, dict) else None


def _verify_inbox_relay_signature(
    ctx: HandlerContext, destination: str, decl_ent: Entity
) -> bool:
    """§3.5 + V7 §5.2 forged-redirection defense (INBOX-RELAY-SIG-1).

    A declaration is honored only when its V7 §5.2 invariant-pointer signature
    (``system/signature/{hex(decl_hash)}``) verifies against the *destination
    peer's own* key. Fail-closed on every error: missing signature, wrong
    target, wrong signer, algorithm mismatch, or a failed cryptographic check
    all return ``False`` (→ the declaration is ignored, default convention
    applies). Mirrors Go ``peerwiring.TreeInboxRelayResolver.Resolve``.

    The destination's ``(public_key, key_type)`` is recovered from its
    identity-multihash peer_id (V7 §7.4). SHA-256-form peer_ids (where the
    pubkey is not self-resolving) fall closed in v1 — the same conservative
    posture as the Go reference until the REGISTRY-served identity leg lands.
    """
    from entity_core.crypto.identity import (
        KEY_TYPE_BYTE_TO_ENTITY_DATA,
        derive_peer_from_peer_id,
    )
    from entity_core.crypto.signing import verify_for_key_type
    from entity_core.protocol.auth import compute_peer_identity_hash

    # 1. Recover the destination's (pubkey, key_type) from its peer_id.
    derived = derive_peer_from_peer_id(destination)
    if derived is None:
        return False
    pubkey, kt_byte = derived
    kt_str = KEY_TYPE_BYTE_TO_ENTITY_DATA.get(kt_byte)
    if kt_str is None:
        return False

    # 2. Locate the §5.2 invariant-pointer signature for the declaration.
    decl_hash = decl_ent.compute_hash()
    sig_ent = _get_entity(
        ctx,
        ctx.emit_pathway.entity_tree.normalize_uri(
            f"system/signature/{decl_hash.hex()}"
        ),
    )
    if sig_ent is None or sig_ent.type != "system/signature":
        return False
    sd = sig_ent.data if isinstance(sig_ent.data, dict) else {}

    # 3. Signature MUST target this declaration.
    if sd.get("target") != decl_hash:
        return False

    # 4. Signer MUST be the destination's canonical identity hash. This is the
    #    forged-redirection fence: a declaration signed by a look-alike key has
    #    a different identity hash and is rejected here.
    dest_identity_hash = compute_peer_identity_hash(
        public_key=pubkey, key_type=kt_str
    )
    if sd.get("signer") != dest_identity_hash:
        return False

    # 5. Algorithm matches the destination's key_type; crypto verify against
    #    the declaration hash, fail-closed.
    if sd.get("algorithm") != kt_str:
        return False
    sig_bytes = sd.get("signature")
    if not isinstance(sig_bytes, bytes):
        return False
    try:
        return verify_for_key_type(kt_byte, pubkey, decl_hash, sig_bytes)
    except Exception:
        return False


def _disable_default_fallback(ctx: HandlerContext) -> bool:
    """The "MX-required" deployment posture (§9.5): when set, the
    default-convention fallback is OFF and an undeclared / non-targeting
    destination yields ``no_inbox_relay``. Read from the tree config entity at
    ``system/relay/config`` (default off — default-convention works)."""
    return bool(_relay_config(ctx).get("disable_default_fallback", False))


def _resolve_fallback_target(
    ctx: HandlerContext, destination: str
) -> tuple[str | None, str | None]:
    """§6.2.1 fallback resolution order (mirrors Go ``resolveFallbackTarget``):

    1. If the destination has an inbox-relay declaration and any entry targets
       **us** (this relay), use that entry's namespace (highest priority wins;
       empty namespace defaults to the destination peer_id).
    2. Otherwise, if default-fallback is enabled (default), use the §6.2.1
       default convention: namespace = destination peer_id on this relay.
    3. Otherwise (declared-but-not-us OR undeclared, AND default disabled),
       return ``no_inbox_relay`` — never a silent drop.

    Cross-relay store (a declared relay that is *not* us) requires a remote
    ``:put`` via the terminal-hop outbound seam and is v1-deferred (same as Go).

    Returns ``(namespace, None)`` on success or ``(None, "no_inbox_relay")``.
    """
    disable_default = _disable_default_fallback(ctx)
    decl = _inbox_relay_declaration(ctx, destination)
    if decl is not None:
        entries = sorted(
            (e for e in decl.get("relays", []) if isinstance(e, dict)),
            key=lambda e: e.get("priority", 0),
        )
        for e in entries:
            if e.get("relay") == ctx.local_peer_id:
                return (e.get("namespace") or destination), None
        # Declared, but no entry targets us — cross-relay store is v1-deferred.
        if disable_default:
            return None, "no_inbox_relay"
        return destination, None
    # No declaration.
    if disable_default:
        return None, "no_inbox_relay"
    return destination, None


# ===========================================================================
# Helpers
# ===========================================================================


def _get_entity(ctx: HandlerContext, path: str) -> Entity | None:
    """Resolve a tree path to its bound entity (or None)."""
    h = ctx.emit_pathway.entity_tree.get(path)
    if h is None:
        return None
    return ctx.emit_pathway.content_store.get(h)


def _included_entity(ctx: HandlerContext, h: bytes) -> Entity | None:
    """Resolve the inner-envelope entity carried in the request's `included`
    (by hash), falling back to the content store. Held opaque (§9) — never
    decoded as part of forward/store."""
    d = ctx.included.get(h) if ctx.included else None
    if isinstance(d, dict):
        try:
            return Entity.from_wire_dict(d)[0]
        except Exception:
            return Entity.from_dict(d)
    return ctx.emit_pathway.content_store.get(h)


def _persist_included(
    ctx: HandlerContext, h: bytes, namespace: str, op: str
) -> None:
    """Tree-bind the carried inner-envelope entity (opaque, §9) under the
    namespace subtree so a later poll+fetch resolves it with ``tree:get`` —
    NOT ``system/content`` (the relay receive-side fetch-surface ruling,
    folded into EXTENSION-RELAY §3.2/§4.2).

    The inner is bound at ``system/relay/store/{namespace}/inner/{inner_hash_hex}``,
    nested under the same namespace subtree as the store-entry, so a single
    namespace-scoped tree-read cap covers both fetches. ``emit`` stores the
    bytes in the content store keyed by hash (dedup preserved — two namespaces
    may point at the same inner hash, PRIMER invariant #1) and binds path→hash.
    No-op if the inner isn't carried; re-binding is idempotent (§emit no-op on
    same hash at same path)."""
    ent = _included_entity(ctx, h)
    if ent is None:
        return
    inner_path = f"{_store_namespace_prefix(namespace)}inner/{h.hex()}"
    full_uri = ctx.emit_pathway.entity_tree.normalize_uri(inner_path)
    emit_ctx = EmitContext.from_handler_grant(ctx, op)
    ctx.emit_pathway.emit(full_uri, ent, emit_ctx)


# ===========================================================================
# §5.5 self-poll default grant
# ===========================================================================


def make_self_poll_grant_scope(peer_id: str) -> dict[str, Any]:
    """The §5.5 self-poll default-grant scope: authorize requesting peer P to
    ``relay-poll`` at namespace = P's own peer_id (i.e. read the fallback inbox
    the relay holds *for that peer*). Mirrors DISCOVERY §4.1's
    default-grants-on-first-install posture.

    Returns a grant-scope dict (handlers/resources/operations) the relay seeds
    per requesting peer. It does NOT widen read access to any other namespace.
    """
    return {
        "handlers": [RELAY_HANDLER_PATTERN],
        "resources": [f"{_store_namespace_prefix(peer_id)}*"],
        "operations": [_OP_POLL],
    }
