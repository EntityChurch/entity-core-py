"""EXTENSION-DISCOVERY v1.0 — peer-finding substrate + mDNS backend.

DISCOVERY answers *"what peers are out there that I don't already know?"*
(find), the sibling of REGISTRY's *"given a name, where is this peer?"*
(lookup). Like NETWORK and REGISTRY it is a **substrate with pluggable
backends** (§1): it surfaces *candidate* peers and mediates the human
decision to admit them. Discovery never silently connects you to strangers —
it *finds* and *prompts*; the user *decides* (§2).

This module is the substrate. The concrete v1 backend (mDNS / DNS-SD per
§3.2) lives in :mod:`entity_handlers.discovery_mdns`, behind the
:class:`DiscoveryBackend` interface defined here.

Design notes (v1, implement-from-spec; fix-in-place per cohort dispatch):

- **Base58 peer_id everywhere** (§2.1, handoff discipline #1): a candidate's
  ``peer_id`` and an identity-claim's ``peer_id`` are Base58 PeerIDs per
  V7 §1.5 — never a content-hash. ``supersedes`` / ``candidate`` / ``grant``
  references are bare ``system/hash`` byte strings (§2.1, refless — handoff
  discipline #2; no ``refs:`` blocks).

- **Hybrid ``:scan``** (§3.0): returns an immediate snapshot (request/response
  form) AND starts/refreshes a *watchable browse session* that writes/removes
  candidate entities at ``system/discovery/candidate/{backend}/{id}`` as peers
  arrive and depart. Live consumers subscribe to the prefix and react. This is
  the substrate's reactive-default model — handlers pop entities into the tree;
  consumers subscribe and react.

- **Liveness reap** (§3.0.1): candidates under the watchable prefix are reaped
  by liveness, NOT wall-clock — mDNS goodbye (TTL=0) → immediate removal;
  ``now - last_seen > grace_window`` (default ``2 × last_TTL``) → aged out.
  ``last_seen`` is session-local (entities are immutable), kept in the
  extension's per-backend index.

- **Successor-candidate** (§2.2): a candidate's ``peer_id`` is ``null`` until
  IDENTIFY completes. We never mutate the observation record — on IDENTIFY
  completion a *successor* candidate is created with ``peer_id`` populated and
  ``supersedes: <candidate_0.content_hash>`` (the ATTESTATION supersedes-chain
  idiom). The IDENTIFY hook lives in the peer connection layer; this module
  provides the construction + identity_hint fail-closed check it calls.

- **identity_hint fail-closed** (§2.2.1): ``null`` → TOFU; non-null → the bare
  ``system/hash`` of an :data:`IDENTITY_CLAIM_TYPE` entity. Post-IDENTIFY the
  receiver reconstructs the claim from the actual peer-id and MUST fail closed
  if the constructed hint != the advertised hint.

- **Resource bounds** (§3.1): per-candidate payload bound → V7 §4.10(a)
  ``413 payload_too_large`` (the candidate is dropped, not emitted); per-scan
  candidate-count ceiling → ``truncated: true`` + ``code:
  "discovery_scan_overflow"`` (503) — NOT silent truncation.

- **2 caps** (§4): ``discovery-scan`` + ``discovery-announce``, default-granted
  to the local peer by the §6.9a owner-cap full-self-access bootstrap (§4.1).
  There is **no** "discovery grants access" cap — admission is the §2 user
  decision only (§8.4).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from entity_core.crypto.identity import decode_peer_id
from entity_core.peer.extensions import Extension, ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext
from entity_core.utils.ecf import ecf_encode
from entity_handlers._common import (
    error_response as _error,
    normalize_hash as _normalize_hash,
    now_ms as _now_ms,
    ok_response as _ok,
    params_data as _params_data,
)

if TYPE_CHECKING:
    from entity_core.handlers.context import HandlerContext

logger = logging.getLogger(__name__)

# -- Patterns / paths -------------------------------------------------------

DISCOVERY_HANDLER_PATTERN = "system/discovery"

CANDIDATE_TYPE = "system/discovery/candidate"
DECISION_TYPE = "system/discovery/decision"
IDENTITY_CLAIM_TYPE = "system/discovery/identity-claim"

# Watchable live surface: system/discovery/candidate/{backend}/{candidate_id}
CANDIDATE_PREFIX = "system/discovery/candidate/"
DECISION_PREFIX = "system/discovery/decision/"

# -- Capability surface (§4) ------------------------------------------------
# Named for discovery/inspectability; the local peer holds them via the §6.9a
# owner-cap full-self-access floor (§4.1). There is intentionally NO
# "discovery grants access" cap — admission is the §2 user decision only.
DISCOVERY_CAPS = (
    "system/capability/discovery-scan",
    "system/capability/discovery-announce",
)

# -- Operations -------------------------------------------------------------

_OP_SCAN = "scan"
_OP_ANNOUNCE = "announce"
_OP_ANNOUNCE_STOP = "announce-stop"
# `:decide` records a §2.1 decision entity (the explicit-decision-before-
# admission surface, §8.1). NOTE: §3's normative op list names only
# scan/announce/announce-stop; the decision-recording op is underspecified.
# Python exposes `:decide` as the validated surface pending Go's D3 reference —
# flagged for D5 reconciliation (handoff discipline #3, slug-divergence watch).
_OP_DECIDE = "decide"

_VALID_OUTCOMES = {"ignore", "track", "grant-limited", "grant-more"}
_GRANT_OUTCOMES = {"grant-limited", "grant-more"}

# -- Resource-bound defaults (§3.1) -----------------------------------------
# Per-scan candidate-count ceiling (§3.1; default informative 1024). Per-session
# ceiling on the watchable surface reuses the same bound. Operator-configurable.
DEFAULT_SCAN_CEILING = 1024
# Per-candidate payload bound (V7 §4.10(a) allocation-safety). mDNS records are
# tiny (a DNS packet caps ~9 KB); 64 KiB is a generous DISCOVERY-level ceiling.
# FLAG: §3.1 says "reuse the v7.75 cohort-converged code" but does not pin the
# per-candidate byte value — surfaced for D5 cross-check.
DEFAULT_MAX_CANDIDATE_PAYLOAD = 64 * 1024
# Default grace window multiplier for the §3.0.1 reap rule (2 × last_TTL).
DEFAULT_GRACE_MULTIPLIER = 2


# ===========================================================================
# Entity constructors (§2.1 / §2.2.1) — Base58 peer_id, refless bare hashes
# ===========================================================================


def make_candidate(
    *,
    backend: str,
    observed_at: int,
    endpoint_hint: Any,
    peer_id: str | None = None,
    identity_hint: bytes | None = None,
    supersedes: bytes | None = None,
) -> Entity:
    """Construct a ``system/discovery/candidate`` (§2.1).

    ``peer_id`` is a Base58 PeerID (V7 §1.5) or ``None`` until IDENTIFY
    completes (§2.2). ``identity_hint`` / ``supersedes`` are bare
    ``system/hash`` byte strings or ``None`` (refless, §2.1).

    Per REGISTRY/DISCOVERY ruling 6 (optional-field wire convention = **absent
    spec-wide**): a ``None`` optional is OMITTED from ``data`` — never emitted
    as a CBOR null (``0xf6``). Readers treat an absent key as null.
    """
    data: dict[str, Any] = {
        "backend": backend,
        "observed_at": observed_at,
        "endpoint_hint": endpoint_hint,
    }
    if peer_id is not None:
        data["peer_id"] = peer_id
    if identity_hint is not None:
        data["identity_hint"] = identity_hint
    if supersedes is not None:
        data["supersedes"] = supersedes
    return Entity(type=CANDIDATE_TYPE, data=data)


def make_decision(
    *,
    candidate: bytes,
    outcome: str,
    decided_at: int,
    grant: bytes | None = None,
) -> Entity:
    """Construct a ``system/discovery/decision`` (§2.1).

    ``candidate`` is the bare hash of the head of the candidate chain (§2.2);
    ``grant`` is the bare hash of a ``system/capability/grant`` entity per
    V7 §6.2 (refless target-matching), or ``None`` for ignore/track.

    Per ruling 6 (optional-field absent spec-wide): a ``None`` ``grant`` is
    OMITTED, not emitted as CBOR null.
    """
    data: dict[str, Any] = {
        "candidate": candidate,
        "outcome": outcome,
        "decided_at": decided_at,
    }
    if grant is not None:
        data["grant"] = grant
    return Entity(type=DECISION_TYPE, data=data)


def identity_claim_from_peer_id(peer_id: str) -> Entity:
    """Construct a ``system/discovery/identity-claim`` (§2.2.1) from a Base58
    PeerID by decoding its V7 §1.5 ``(key_type, hash_type, digest)`` framing.

    The claim's ``content_hash`` IS the ``identity_hint`` a candidate
    advertises. Post-IDENTIFY the receiver rebuilds this from the *actual*
    peer-id and compares (see :func:`verify_identity_hint`).
    """
    key_type, hash_type, digest = decode_peer_id(peer_id)
    return Entity(
        type=IDENTITY_CLAIM_TYPE,
        data={
            "peer_id": peer_id,
            "key_type": key_type,
            "hash_type": hash_type,
            "public_key_digest": digest,
        },
    )


def identity_hint_for_peer_id(peer_id: str) -> bytes:
    """The bare ``system/hash`` of the identity-claim for ``peer_id`` (§2.2.1)."""
    return identity_claim_from_peer_id(peer_id).compute_hash()


def verify_identity_hint(advertised: bytes | None, actual_peer_id: str) -> bool:
    """§2.2.1 admission check. ``advertised`` is the candidate's
    ``identity_hint`` (bare hash | ``None``); ``actual_peer_id`` is the
    IDENTIFY result.

    - ``advertised is None`` → TOFU; the §2 grant decision IS the trust anchor.
      Returns ``True`` (admission is at the user's discretion).
    - non-null → reconstruct the identity-claim from ``actual_peer_id`` and
      require byte-equality. **MUST fail closed** on mismatch (§8.4).
    """
    if advertised is None:
        return True
    try:
        constructed = identity_hint_for_peer_id(actual_peer_id)
    except Exception:
        return False
    return constructed == advertised


# ===========================================================================
# Backend interface (§1 pluggable substrate)
# ===========================================================================


@dataclass
class AdmitResult:
    """Outcome of :meth:`DiscoveryExtension.admit_identified` (§2.2 / §2.2.1).

    ``ok`` is False with ``reason="identity_hint_mismatch"`` when the §2.2.1
    fail-closed check rejects admission; ``successor`` is the bare hash of the
    created candidate_1 on success."""

    ok: bool
    reason: str | None
    successor: bytes | None


@dataclass
class CandidateObservation:
    """A raw backend observation, before the substrate wraps it as a candidate
    entity. Backends emit these; the substrate owns entity construction, tree
    writes, bounds, and reap (§3.0 / §3.1).

    ``candidate_id`` is the backend-stable key for the watchable tree slot
    (``system/discovery/candidate/{backend}/{candidate_id}``) — for mDNS, the
    DNS-SD instance name. ``ttl_ms`` drives the §3.0.1 grace window; ``None``
    for one-shot backends (QR) that never reap.
    """

    candidate_id: str
    endpoint_hint: Any
    peer_id_hint: str | None = None
    identity_hint: bytes | None = None
    ttl_ms: int | None = None
    observed_at: int | None = None


# Watchable-session callbacks the substrate hands a backend's browse session.
OnArrive = Callable[[CandidateObservation], None]
OnDepart = Callable[[str], None]  # candidate_id


class BrowseSession(ABC):
    """A live browse session started by :meth:`DiscoveryBackend.start_browse`.
    Streams arrival/departure events into the substrate until stopped."""

    @abstractmethod
    async def stop(self) -> None:
        """Tear down the session (release sockets, cancel listeners)."""
        ...


class AnnounceSession(ABC):
    """A live advertisement started by :meth:`DiscoveryBackend.announce`."""

    @abstractmethod
    async def stop(self) -> None:
        ...


class DiscoveryBackend(ABC):
    """Pluggable discovery backend (§1). v1 ships mDNS; QR / registry-assisted
    / gossip are additive (§6)."""

    name: str

    @abstractmethod
    async def scan(self, filter: Any) -> list[CandidateObservation]:
        """Immediate snapshot of currently-known candidates (§3.0 snapshot
        return). One-shot backends return their single observation here."""
        ...

    @abstractmethod
    async def start_browse(
        self, filter: Any, on_arrive: OnArrive, on_depart: OnDepart,
    ) -> BrowseSession:
        """Start (or the caller refreshes) a streaming browse session that
        invokes ``on_arrive`` / ``on_depart`` as peers come and go (§3.0
        watchable prefix)."""
        ...

    @abstractmethod
    async def announce(self, profile_ref: str, txt: dict[str, Any]) -> AnnounceSession:
        """Advertise self on the backend's medium (§3 ``:announce``)."""
        ...

    def set_local_peer_id(self, peer_id: str) -> None:
        """Optional hook: the substrate calls this at init with the local
        peer-id so backends can self-advertise without the caller threading it
        through every ``:announce``. Default no-op."""
        return None


# ===========================================================================
# Session-local state (§3.0.1 — last_seen is per-impl, not in the entity)
# ===========================================================================


@dataclass
class _CandidateState:
    """Per-candidate liveness record, session-local (§3.0.1)."""

    candidate_hash: bytes
    last_seen: int
    ttl_ms: int | None


@dataclass
class _BackendState:
    browse: BrowseSession | None = None
    # candidate_id -> liveness record (drives the §3.0.1 reap)
    live: dict[str, _CandidateState] = field(default_factory=dict)
    # profile_ref -> announce session
    announces: dict[str, AnnounceSession] = field(default_factory=dict)


# ===========================================================================
# DiscoveryExtension — owns backends, browse/announce sessions, reap state
# ===========================================================================


class DiscoveryExtension(Extension):
    """Wires the discovery substrate into a peer. Holds the backend registry,
    per-backend browse/announce session state, and the §3.0.1 liveness index.

    Usage::

        disc = DiscoveryExtension()
        disc.register_backend(MdnsBackend())
        builder.with_handler(DISCOVERY_HANDLER_PATTERN, disc.handler(),
                             priority=116, name="discovery")
        builder.with_extension(disc)
    """

    def __init__(
        self,
        *,
        scan_ceiling: int = DEFAULT_SCAN_CEILING,
        max_candidate_payload: int = DEFAULT_MAX_CANDIDATE_PAYLOAD,
        grace_multiplier: int = DEFAULT_GRACE_MULTIPLIER,
    ) -> None:
        self._emit_pathway: Any | None = None
        self._local_peer_id: str | None = None
        self._backends: dict[str, DiscoveryBackend] = {}
        self._state: dict[str, _BackendState] = {}
        self.scan_ceiling = scan_ceiling
        self.max_candidate_payload = max_candidate_payload
        self.grace_multiplier = grace_multiplier

    # -- registration -------------------------------------------------------

    def register_backend(self, backend: DiscoveryBackend) -> None:
        self._backends[backend.name] = backend
        self._state.setdefault(backend.name, _BackendState())

    def initialize(self, ctx: ExtensionContext) -> None:
        if ctx.emit_pathway is None:
            logger.warning("DiscoveryExtension: no emit_pathway; discovery disabled")
            return
        self._emit_pathway = ctx.emit_pathway
        self._local_peer_id = ctx.peer_id
        for backend in self._backends.values():
            try:
                backend.set_local_peer_id(ctx.peer_id)
            except Exception:
                logger.debug("discovery: set_local_peer_id failed on %s",
                             backend.name, exc_info=True)
        logger.info(
            "DiscoveryExtension initialized (backends=%s)",
            sorted(self._backends),
        )

    async def shutdown_async(self) -> None:
        """Stop all browse + announce sessions. (Sync ``shutdown`` cannot await;
        callers that have a loop should prefer this.)"""
        for st in self._state.values():
            if st.browse is not None:
                await st.browse.stop()
                st.browse = None
            for ann in st.announces.values():
                await ann.stop()
            st.announces.clear()

    def shutdown(self) -> None:
        # Best-effort: drop references. Async teardown is via shutdown_async().
        self._state.clear()

    # -- candidate emission / reap (§3.0) -----------------------------------

    def _candidate_uri(self, backend: str, candidate_id: str) -> str:
        return f"{CANDIDATE_PREFIX}{backend}/{candidate_id}"

    def _payload_ok(self, candidate: Entity) -> bool:
        """V7 §4.10(a) per-candidate payload bound (§3.1). Oversized records
        are rejected (dropped, not emitted) — a misbehaving LAN broadcaster
        cannot force an unbounded allocation."""
        try:
            size = len(ecf_encode(candidate.to_dict()))
        except Exception:
            return False
        if size > self.max_candidate_payload:
            logger.warning(
                "discovery: dropping oversized candidate (%d > %d bytes) "
                "— 413 payload_too_large (§3.1)",
                size, self.max_candidate_payload,
            )
            return False
        return True

    def _emit_candidate(
        self, backend: str, obs: CandidateObservation, *, at_ceiling: bool,
    ) -> bytes | None:
        """Build + write a candidate entity at the watchable slot, refresh its
        liveness record. Returns the candidate's bare hash, or ``None`` if it
        was dropped (oversized §3.1, or session at ceiling)."""
        observed_at = obs.observed_at if obs.observed_at is not None else _now_ms()
        identity_hint = obs.identity_hint
        if identity_hint is None and obs.peer_id_hint:
            # A peer_id_hint (mDNS TXT) lets us pin the identity-claim now.
            try:
                identity_hint = identity_hint_for_peer_id(obs.peer_id_hint)
            except Exception:
                identity_hint = None
        candidate = make_candidate(
            backend=backend,
            observed_at=observed_at,
            endpoint_hint=obs.endpoint_hint,
            peer_id=obs.peer_id_hint,
            identity_hint=identity_hint,
        )
        if not self._payload_ok(candidate):
            return None

        st = self._state.setdefault(backend, _BackendState())
        # §3.1: per-session-candidate ceiling on the watchable surface. A NEW
        # candidate at ceiling is NOT written (the drop is logged); a refresh
        # of an already-tracked candidate is always allowed.
        is_new = obs.candidate_id not in st.live
        if is_new and at_ceiling:
            logger.warning(
                "discovery: watchable session at ceiling (%d); dropping new "
                "candidate %r (§3.1)", self.scan_ceiling, obs.candidate_id,
            )
            return None

        chash = candidate.compute_hash()
        if self._emit_pathway is not None:
            uri = self._candidate_uri(backend, obs.candidate_id)
            self._emit_pathway.emit(uri, candidate, EmitContext.bootstrap())
        st.live[obs.candidate_id] = _CandidateState(
            candidate_hash=chash, last_seen=observed_at, ttl_ms=obs.ttl_ms,
        )
        return chash

    def _remove_candidate(self, backend: str, candidate_id: str) -> None:
        """§3.0.1(1) — immediate removal (mDNS goodbye). The candidate body
        remains in the content store (audit); only the live tree slot is
        removed, firing a DELETE change event to subscribers."""
        st = self._state.get(backend)
        if st is None or candidate_id not in st.live:
            return
        if self._emit_pathway is not None:
            self._emit_pathway.entity_tree.remove(
                self._candidate_uri(backend, candidate_id)
            )
        st.live.pop(candidate_id, None)

    def reap(self, backend: str, *, now: int | None = None) -> list[str]:
        """§3.0.1(2) — age out candidates whose ``now - last_seen >
        grace_window`` (``grace_window = grace_multiplier × last_TTL``).
        One-shot candidates (no TTL) are never aged out here (§3.0.1(4)).
        Returns the list of reaped candidate_ids."""
        st = self._state.get(backend)
        if st is None:
            return []
        now = now if now is not None else _now_ms()
        reaped: list[str] = []
        for cid, cs in list(st.live.items()):
            if cs.ttl_ms is None:
                continue  # one-shot; reaped only on explicit unbind / GC
            grace = self.grace_multiplier * cs.ttl_ms
            if now - cs.last_seen > grace:
                self._remove_candidate(backend, cid)
                reaped.append(cid)
        if reaped:
            logger.info("discovery: reaped %d stale candidate(s) on %s",
                        len(reaped), backend)
        return reaped

    # -- admission / successor-candidate (§2.2 / §2.2.1) --------------------

    def admit_identified(
        self, candidate_hash: bytes, actual_peer_id: str,
    ) -> AdmitResult:
        """The IDENTIFY-completion step (§2.2 / §2.2.1). Call this once IDENTIFY
        completes against the channel admitted for ``candidate_hash`` — i.e. at
        :meth:`entity_core.peer.connection.Connection.connect` completion, where
        the remote's actual ``peer_id`` is established.

        The hookpoint is impl-side (the handoff: "the hookpoint is impl-side;
        the wire shape is the spec"); orchestration (CLI / L5) invokes this. The
        convergence-critical output is the **successor candidate** entity shape.

        Behaviour:
        - resolve ``candidate_0`` by its bare hash;
        - §2.2.1 identity_hint check: if the candidate advertised a non-null
          ``identity_hint`` and the reconstructed hint for ``actual_peer_id``
          does not match, **fail closed** — NO successor, NO admission (§8.4);
        - otherwise create ``candidate_1``: a NEW entity (never mutate §8.4)
          with ``peer_id`` populated, ``supersedes: candidate_hash``, and the
          now-known ``identity_hint``. Update the live watchable slot to the
          successor when one exists; otherwise keep it addressable by hash.
        """
        if self._emit_pathway is None:
            return AdmitResult(ok=False, reason="not_initialized", successor=None)
        cand = self._emit_pathway.content_store.get(candidate_hash)
        if cand is None or cand.type != CANDIDATE_TYPE:
            return AdmitResult(ok=False, reason="candidate_not_found", successor=None)

        advertised = _normalize_hash(cand.data.get("identity_hint"))
        if not verify_identity_hint(advertised, actual_peer_id):
            logger.warning(
                "discovery: identity_hint mismatch admitting %s as %s — "
                "failing closed (§2.2.1 / §8.4)",
                candidate_hash.hex()[:12], actual_peer_id,
            )
            return AdmitResult(ok=False, reason="identity_hint_mismatch", successor=None)

        backend = cand.data.get("backend")
        successor = make_candidate(
            backend=backend,
            observed_at=_now_ms(),
            endpoint_hint=cand.data.get("endpoint_hint"),
            peer_id=actual_peer_id,
            identity_hint=identity_hint_for_peer_id(actual_peer_id),
            supersedes=candidate_hash,
        )
        shash = successor.compute_hash()

        # Update the live watchable slot to the identified successor when we can
        # locate it; entities are content-addressed so candidate_0 survives.
        st = self._state.get(backend) if isinstance(backend, str) else None
        cid = None
        old_ttl = None
        if st is not None:
            for k, cs in st.live.items():
                if cs.candidate_hash == candidate_hash:
                    cid, old_ttl = k, cs.ttl_ms
                    break
        if cid is not None and st is not None:
            self._emit_pathway.emit(
                self._candidate_uri(backend, cid), successor, EmitContext.bootstrap(),
            )
            st.live[cid] = _CandidateState(
                candidate_hash=shash,
                last_seen=successor.data["observed_at"],
                ttl_ms=old_ttl,
            )
        else:
            # No live slot (one-shot already reaped, or admit-by-hash) — keep
            # the successor addressable in the content store.
            self._emit_pathway.content_store.put(successor)
        return AdmitResult(ok=True, reason=None, successor=shash)

    # -- the handler --------------------------------------------------------

    def handler(self) -> Callable[..., Awaitable[dict[str, Any]]]:
        ext = self

        async def discovery_handler(
            path: str, operation: str, params: dict[str, Any], ctx: HandlerContext,
        ) -> dict[str, Any]:
            if operation == _OP_SCAN:
                return await ext._handle_scan(ctx, params)
            if operation == _OP_ANNOUNCE:
                return await ext._handle_announce(ctx, params)
            if operation == _OP_ANNOUNCE_STOP:
                return await ext._handle_announce_stop(ctx, params)
            if operation == _OP_DECIDE:
                return await ext._handle_decide(ctx, params)
            return _error(
                404, "unknown_operation",
                f"system/discovery has no operation {operation!r}",
            )

        return discovery_handler

    def _get_backend(self, name: Any) -> DiscoveryBackend | None:
        if not isinstance(name, str):
            return None
        return self._backends.get(name)

    async def _handle_scan(
        self, ctx: HandlerContext, params: dict[str, Any],
    ) -> dict[str, Any]:
        """§3 ``:scan(backend, filter?)`` — hybrid (§3.0): immediate snapshot
        return AND start/refresh of the watchable browse session."""
        data = _params_data(params)
        backend_name = data.get("backend")
        backend = self._get_backend(backend_name)
        if backend is None:
            return _error(
                400, "unknown_backend",
                f"no discovery backend {backend_name!r}",
            )
        filter_obj = data.get("filter")

        # 1. Snapshot.
        try:
            observations = await backend.scan(filter_obj)
        except Exception as exc:
            # §3.3: backends MUST NOT silently return zero on an unparseable
            # filter — surface as an error code, not an empty result.
            logger.warning("discovery: scan failed on %s: %s", backend_name, exc)
            return _error(503, "discovery_scan_failed", str(exc))

        st = self._state.setdefault(backend_name, _BackendState())
        candidates: list[bytes] = []
        truncated = False
        for obs in observations:
            at_ceiling = len(st.live) >= self.scan_ceiling
            chash = self._emit_candidate(backend_name, obs, at_ceiling=at_ceiling)
            if chash is None:
                # Dropped: oversized (§3.1) or session at ceiling.
                if at_ceiling and obs.candidate_id not in st.live:
                    truncated = True
                continue
            candidates.append(chash)
            if len(candidates) >= self.scan_ceiling:
                # Snapshot count ceiling reached; remaining are dropped (§3.1).
                if len(observations) > len(candidates):
                    truncated = True
                break

        # 2. Start / refresh the watchable browse session (§3.0).
        if st.browse is None:
            try:
                st.browse = await backend.start_browse(
                    filter_obj,
                    lambda o: self._on_browse_arrive(backend_name, o),
                    lambda cid: self._remove_candidate(backend_name, cid),
                )
            except Exception:
                logger.debug("discovery: start_browse failed on %s",
                             backend_name, exc_info=True)

        # Ruling 6 (optional-field absent spec-wide): `code` is null normally —
        # so it is OMITTED unless the per-scan ceiling was exceeded (§3.1).
        result: dict[str, Any] = {"candidates": candidates, "truncated": truncated}
        if truncated:
            result["code"] = "discovery_scan_overflow"
        status = 503 if truncated else 200
        return {
            "status": status,
            "result": {"type": "system/discovery/scan-result", "data": result},
        }

    def _on_browse_arrive(self, backend: str, obs: CandidateObservation) -> None:
        st = self._state.setdefault(backend, _BackendState())
        at_ceiling = (
            obs.candidate_id not in st.live and len(st.live) >= self.scan_ceiling
        )
        self._emit_candidate(backend, obs, at_ceiling=at_ceiling)

    async def _handle_announce(
        self, ctx: HandlerContext, params: dict[str, Any],
    ) -> dict[str, Any]:
        """§3 ``:announce(backend, profile_ref)`` — advertise self."""
        data = _params_data(params)
        backend_name = data.get("backend")
        backend = self._get_backend(backend_name)
        if backend is None:
            return _error(400, "unknown_backend",
                          f"no discovery backend {backend_name!r}")
        profile_ref = data.get("profile_ref")
        if not isinstance(profile_ref, str) or not profile_ref:
            return _error(400, "invalid_params", "announce requires a profile_ref")
        txt = data.get("txt") if isinstance(data.get("txt"), dict) else {}
        try:
            session = await backend.announce(profile_ref, txt)
        except Exception as exc:
            return _error(503, "discovery_announce_failed", str(exc))
        st = self._state.setdefault(backend_name, _BackendState())
        st.announces[profile_ref] = session
        return _ok("system/protocol/ack", {"announced": True})

    async def _handle_announce_stop(
        self, ctx: HandlerContext, params: dict[str, Any],
    ) -> dict[str, Any]:
        """§3 ``:announce-stop(backend, profile_ref)`` — end an announce."""
        data = _params_data(params)
        backend_name = data.get("backend")
        profile_ref = data.get("profile_ref")
        st = self._state.get(backend_name) if isinstance(backend_name, str) else None
        session = st.announces.pop(profile_ref, None) if st else None
        if session is not None:
            try:
                await session.stop()
            except Exception:
                logger.debug("discovery: announce-stop failed", exc_info=True)
        # Idempotent: stopping an absent announce is still ().
        return _ok("system/protocol/ack", {"stopped": session is not None})

    async def _handle_decide(
        self, ctx: HandlerContext, params: dict[str, Any],
    ) -> dict[str, Any]:
        """Record a §2.1 ``decision`` entity (the explicit-decision surface,
        §8.1). Discovery is the *initiator*, never the *authority* (§2): for
        grant outcomes the caller supplies the bare hash of a
        ``system/capability/grant`` minted by ordinary capability machinery —
        this op does not mint caps. Admission's identity_hint fail-closed check
        + successor-candidate happen at IDENTIFY completion (§2.2 / §2.2.1)."""
        data = _params_data(params)
        candidate = _normalize_hash(data.get("candidate"))
        outcome = data.get("outcome")
        if candidate is None:
            return _error(400, "invalid_params", "decide requires a candidate hash")
        if outcome not in _VALID_OUTCOMES:
            return _error(400, "invalid_outcome",
                          f"outcome must be one of {sorted(_VALID_OUTCOMES)}")
        grant = _normalize_hash(data.get("grant"))
        if outcome in _GRANT_OUTCOMES and grant is None:
            return _error(400, "grant_required",
                          f"outcome {outcome!r} requires a grant hash")
        if outcome not in _GRANT_OUTCOMES and grant is not None:
            return _error(400, "unexpected_grant",
                          f"outcome {outcome!r} must not carry a grant")

        decision = make_decision(
            candidate=candidate, outcome=outcome, grant=grant, decided_at=_now_ms(),
        )
        dhash = decision.compute_hash()
        if self._emit_pathway is not None:
            self._emit_pathway.emit(
                DECISION_PREFIX + dhash.hex(), decision,
                EmitContext.from_handler_grant(ctx, "decide"),
            )
        return _ok("system/discovery/decision-result",
                   {"decision": dhash, "outcome": outcome})
