"""EXTENSION-DISCOVERY v1.0 — mDNS / DNS-SD backend (§3 / §3.2).

The first and only v1 backend: zero-config multicast for finding peers on the
local network (the same-network demo). Built on ``zeroconf`` (the cohort's
named Python choice). The wire constants in §3.2 are pinned **normative** —
they are the SILENT cross-impl-divergence class (Go and Rust never see each
other on the LAN if these differ, with no error to catch), so they live here
as module constants and are surfaced for the D5 byte-equality cross-check.

§3.2 pins:
- DNS-SD service-type ``_entity-core._udp.local.`` (RFC 6763 §7).
- MUST-present TXT keys: ``version=1``, ``peer_id_hint=<Base58>``,
  ``profile_ref=<profile-id>``.
- OPTIONAL TXT keys: ``proto=<comma-list>``, ``display_name=<UTF-8>``.
- SRV record required (RFC 6763 §4.2) for port advertisement.
- Unknown TXT keys MUST be ignored (forward-compat).

mDNS is a discovery + signaling carrier only — NOT a trust surface (§3.3).
Trust is the IDENTIFY handshake over the resulting channel plus the user's
grant choice.

FLAG (handoff open #1): different mDNS libs may emit TXT keys in different
orders. zeroconf serializes ``properties`` in dict insertion order; we insert
in the §3.2-documented order (version, peer_id_hint, profile_ref, proto,
display_name). Verify against Go/Rust at D5 — if a lib re-sorts, route to arch.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

from entity_handlers.discovery import (
    AnnounceSession,
    BrowseSession,
    CandidateObservation,
    DiscoveryBackend,
    OnArrive,
    OnDepart,
)

logger = logging.getLogger(__name__)

# -- §3.2 wire pins (NORMATIVE — silent-divergence class) --------------------

SERVICE_TYPE = "_entity-core._udp.local."
TXT_VERSION = "1"  # DISCOVERY major version

# MUST-present + OPTIONAL TXT keys, in §3.2-documented order (insertion order
# drives zeroconf TXT serialization; see module FLAG).
_MUST_TXT_KEYS = ("version", "peer_id_hint", "profile_ref")
_OPTIONAL_TXT_KEYS = ("proto", "display_name")

# mDNS host-record default TTL (RFC 6762); drives the §3.0.1 grace window.
_HOST_TTL_S = 120
_OTHER_TTL_S = 4500


def _txt_str(value: Any) -> str | None:
    """Decode a zeroconf TXT value (bytes | str | None) to str."""
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return str(value)


def _txt_properties(peer_id_hint: str, profile_ref: str, txt: dict[str, Any]) -> dict[str, str]:
    """Assemble the §3.2 TXT record in documented key order.

    MUST-present keys first (version, peer_id_hint, profile_ref), then the
    OPTIONAL keys when supplied by the caller's ``txt`` (proto, display_name).
    Insertion order is the wire order zeroconf emits.
    """
    props: dict[str, str] = {
        "version": TXT_VERSION,
        "peer_id_hint": peer_id_hint,
        "profile_ref": profile_ref,
    }
    for k in _OPTIONAL_TXT_KEYS:
        v = txt.get(k)
        if v is not None:
            props[k] = str(v)
    return props


def _observation_from_info(name: str, info: Any) -> CandidateObservation | None:
    """Turn a resolved zeroconf ``ServiceInfo`` into a CandidateObservation.

    ``candidate_id`` is the DNS-SD instance label (the part before the service
    type) — the backend-stable key for the watchable tree slot. Unknown TXT
    keys are ignored (§3.2 forward-compat)."""
    props = info.properties or {}
    # zeroconf gives bytes keys/values.
    decoded = {
        _txt_str(k): _txt_str(v)
        for k, v in props.items()
        if _txt_str(k) is not None
    }
    peer_id_hint = decoded.get("peer_id_hint")
    profile_ref = decoded.get("profile_ref")

    addresses = []
    try:
        addresses = info.parsed_addresses()
    except Exception:
        addresses = []
    endpoint_hint: dict[str, Any] = {
        "addresses": addresses,
        "port": info.port,
        "profile_ref": profile_ref,
    }
    proto = decoded.get("proto")
    if proto:
        endpoint_hint["proto"] = proto.split(",")

    candidate_id = name
    if name.endswith("." + SERVICE_TYPE):
        candidate_id = name[: -(len(SERVICE_TYPE) + 1)]

    return CandidateObservation(
        candidate_id=candidate_id,
        endpoint_hint=endpoint_hint,
        peer_id_hint=peer_id_hint,
        ttl_ms=_HOST_TTL_S * 1000,
    )


class _MdnsBrowseSession(BrowseSession):
    def __init__(self, azc: Any, browser: Any) -> None:
        self._azc = azc
        self._browser = browser

    async def stop(self) -> None:
        try:
            await self._browser.async_cancel()
        except Exception:
            logger.debug("mdns: browser cancel failed", exc_info=True)


class _MdnsAnnounceSession(AnnounceSession):
    def __init__(self, azc: Any, info: Any) -> None:
        self._azc = azc
        self._info = info

    async def stop(self) -> None:
        try:
            await self._azc.async_unregister_service(self._info)
        except Exception:
            logger.debug("mdns: unregister failed", exc_info=True)


class MdnsBackend(DiscoveryBackend):
    """zeroconf-backed mDNS discovery backend (§3 / §3.2).

    Maintains one ``AsyncZeroconf`` instance and a lazily-started browser whose
    cache backs both the snapshot (``scan``) and the watchable session
    (``start_browse``)."""

    name = "mdns"

    def __init__(self, *, peer_id: str | None = None, resolve_timeout_ms: int = 3000) -> None:
        self._peer_id = peer_id
        self._resolve_timeout_ms = resolve_timeout_ms
        self._azc: Any | None = None
        # candidate_id -> last resolved CandidateObservation (snapshot cache).
        self._cache: dict[str, CandidateObservation] = {}
        self._browser: Any | None = None
        self._on_arrive: OnArrive | None = None
        self._on_depart: OnDepart | None = None

    def set_local_peer_id(self, peer_id: str) -> None:
        if not self._peer_id:
            self._peer_id = peer_id

    async def _ensure_zc(self) -> Any:
        if self._azc is None:
            from zeroconf.asyncio import AsyncZeroconf  # lazy: isolate C-ext
            self._azc = AsyncZeroconf()
        return self._azc

    def _handle_state_change(self, zeroconf: Any, service_type: str, name: str, state_change: Any) -> None:
        """zeroconf ServiceBrowser callback (sync). Schedules an async resolve
        for Added/Updated; fires on_depart for Removed."""
        from zeroconf import ServiceStateChange
        if state_change is ServiceStateChange.Removed:
            candidate_id = name
            if name.endswith("." + SERVICE_TYPE):
                candidate_id = name[: -(len(SERVICE_TYPE) + 1)]
            self._cache.pop(candidate_id, None)
            if self._on_depart is not None:
                self._on_depart(candidate_id)  # §3.0.1(1) goodbye → immediate
            return
        # Added / Updated → resolve out-of-band.
        asyncio.ensure_future(self._resolve_and_emit(service_type, name))

    async def _resolve_and_emit(self, service_type: str, name: str) -> None:
        from zeroconf.asyncio import AsyncServiceInfo
        azc = await self._ensure_zc()
        info = AsyncServiceInfo(service_type, name)
        try:
            ok = await info.async_request(azc.zeroconf, self._resolve_timeout_ms)
        except Exception:
            logger.debug("mdns: resolve failed for %s", name, exc_info=True)
            return
        if not ok:
            return
        obs = _observation_from_info(name, info)
        if obs is None:
            return
        self._cache[obs.candidate_id] = obs
        if self._on_arrive is not None:
            self._on_arrive(obs)

    async def scan(self, filter: Any) -> list[CandidateObservation]:
        """Snapshot of currently-known mDNS candidates. Starts a browser on
        first call so the cache is warm; returns the current cache contents."""
        await self._ensure_browser()
        return list(self._cache.values())

    async def _ensure_browser(self) -> None:
        if self._browser is not None:
            return
        from zeroconf.asyncio import AsyncServiceBrowser
        azc = await self._ensure_zc()
        self._browser = AsyncServiceBrowser(
            azc.zeroconf, SERVICE_TYPE, handlers=[self._handle_state_change],
        )

    async def start_browse(
        self, filter: Any, on_arrive: OnArrive, on_depart: OnDepart,
    ) -> BrowseSession:
        self._on_arrive = on_arrive
        self._on_depart = on_depart
        await self._ensure_browser()
        azc = await self._ensure_zc()
        return _MdnsBrowseSession(azc, self._browser)

    async def announce(self, profile_ref: str, txt: dict[str, Any]) -> AnnounceSession:
        """Advertise self on the LAN (§3 ``:announce``). Builds the §3.2
        ServiceInfo (service-type + TXT + SRV) and registers it."""
        from zeroconf import ServiceInfo
        peer_id = txt.get("peer_id_hint") or self._peer_id
        if not peer_id:
            raise ValueError("mdns announce requires a peer_id (peer_id_hint)")
        azc = await self._ensure_zc()

        instance = txt.get("instance") or peer_id
        service_name = f"{instance}.{SERVICE_TYPE}"
        port = int(txt.get("port", 0)) or 0
        properties = _txt_properties(str(peer_id), profile_ref, txt)

        addresses = []
        host = txt.get("address")
        if host:
            try:
                addresses = [socket.inet_aton(str(host))]
            except OSError:
                addresses = []

        info = ServiceInfo(
            SERVICE_TYPE,
            service_name,
            addresses=addresses or None,
            port=port,
            properties=properties,
            server=txt.get("server") or f"{instance}.local.",
            host_ttl=_HOST_TTL_S,
            other_ttl=_OTHER_TTL_S,
        )
        await azc.async_register_service(info)
        return _MdnsAnnounceSession(azc, info)

    async def close(self) -> None:
        if self._browser is not None:
            try:
                await self._browser.async_cancel()
            except Exception:
                logger.debug("mdns: browser close failed", exc_info=True)
            self._browser = None
        if self._azc is not None:
            try:
                await self._azc.async_close()
            except Exception:
                logger.debug("mdns: zeroconf close failed", exc_info=True)
            self._azc = None
