"""`system/substitute/http:try` handler — inline HTTP GET + hash-verify.

Renamed from `static-cdn` per the storage-substitute cross-impl
rulings §3.2: "it's HTTP, not 'CDN' — we don't know what's behind the
origin (could be a bucket, nginx, `python3 -m http.server`)." The
substitute_type value is `"http"`; the handler URI is
`system/substitute/http:try`.

This is **Mechanism A**: the consumer fetches `{content_url}` over HTTP,
decodes the body as a CBOR entity, recomputes its content hash, and
verifies it equals the requested hash. The content hash is the sole
trust anchor. No BRIDGE-HTTP handler invocation and no
`system/capability/bridge-http-fetch` cap on this path
(STORAGE-SUBSTITUTE-HTTP §1; NETWORK §6.5.3 step 4).

Response shape (Ruling 3): the handler returns the **raw fetched entity
dict** directly in `result`. No `{entity, hash}` wrapper — the chain
consumer already holds the hash it asked for, so the wrapper would be
redundant. `not_found` / transient errors flow through the standard
non-2xx handler-result mechanism.

Error semantics:
  - `cap_denied` (e.g., HTTPS-only policy rejects http://) → ABORT chain.
  - 5xx / network errors → ADVANCE (transient).
  - body hash mismatch → ADVANCE (discard bytes).
  - success → return verified entity to the chain orchestrator (raw shape).
"""

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from typing import Any, Protocol

import cbor2

from entity_core.protocol.entity import Entity
from entity_core.utils.ecf import Hash, compute_ecf_hash, hash_equals
from entity_handlers._common import error_response
from entity_handlers.substitute.urls import build_content_url

logger = logging.getLogger(__name__)

HTTP_HANDLER_PATTERN = "system/substitute/http"
HTTP_TRY_OP = "try"

# Default timeout: short enough that transients don't stall the chain.
DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0


class HttpSubstituteHandlerError(Exception):
    """Internal handler-side error category (not a wire error code)."""


class HttpFetcher(Protocol):
    """Pluggable fetch surface for testability.

    Implementations MUST raise `HttpSubstituteHandlerError` on policy
    denial (e.g., cleartext rejected), `urllib.error.HTTPError` for
    non-2xx (treated as transient → chain advances), or
    `urllib.error.URLError`/`OSError` for network errors (also
    transient).
    """

    def get(self, url: str, *, timeout: float) -> bytes: ...


class UrllibFetcher:
    """stdlib `urllib.request` fetcher — the production default.

    No connection pooling and no retries by design: the chain orchestrator
    handles retry semantics (advance on transient, abort on cap-denied).
    Keeps this surface tiny and stdlib-only (no `httpx`/`aiohttp` dep).
    """

    def __init__(self, *, allow_http: bool = False) -> None:
        # Defense-in-depth (HTTPS-only default per spec): reject http://
        # at consume time unless explicitly allowed. The primary gate is
        # the cap's `url_pattern`; this is a belt-and-suspenders check
        # that means a mis-issued cap can't pull cleartext bytes.
        self.allow_http = allow_http

    def get(self, url: str, *, timeout: float) -> bytes:
        if not self.allow_http and url.startswith("http://"):
            raise HttpSubstituteHandlerError(
                f"refusing cleartext http:// fetch (set allow_http=True to override): {url}"
            )
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()


def _verify_body_hash(body: bytes, expected: Hash) -> Entity:
    """Decode body as CBOR entity, recompute its content hash, verify.

    Raises:
        HttpSubstituteHandlerError on decode failure or hash mismatch
        (both chain-advancing errors, distinguished by message).
    """
    try:
        decoded = cbor2.loads(body)
    except Exception as exc:
        raise HttpSubstituteHandlerError(f"body is not valid CBOR: {exc}") from exc
    if not isinstance(decoded, dict):
        raise HttpSubstituteHandlerError(
            f"body decodes to {type(decoded).__name__}, expected entity dict"
        )

    type_ = decoded.get("type")
    data_ = decoded.get("data")
    if not isinstance(type_, str) or not isinstance(data_, dict):
        raise HttpSubstituteHandlerError("body missing type/data fields")
    hashable = {"type": type_, "data": data_}
    actual_hash = compute_ecf_hash(hashable)
    if not hash_equals(actual_hash, expected):
        raise HttpSubstituteHandlerError("body hash mismatch (chain advances)")

    # §1.8 fidelity: carry the validated hash on the Entity directly so
    # subsequent puts trust it instead of recomputing.
    return Entity(type=type_, data=data_, content_hash=actual_hash)


async def http_substitute_handler(
    path: str,
    operation: str,
    params: dict[str, Any],
    ctx: Any,
    *,
    fetcher: HttpFetcher | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Dispatch `system/substitute/http:try`.

    Params shape (`system/substitute/try-request` per Ruling 2):
        {"entry": <source-entry dict>, "hash": <Hash bytes>}

    Returns on success (Ruling 3 — raw entity, no wrapper):
        {"status": 200, "result": <decoded entity dict>,
         "envelope_included": {<hash>: <entity dict>}}

    Returns on transient / mismatch (chain ADVANCES):
        {"status": 404 or 502, "result": <error dict>}

    Returns on cap-denied (chain ABORTS):
        {"status": 403, "result": <error dict code=cap_denied>}
    """
    if operation != HTTP_TRY_OP:
        return error_response(
            501,
            "unsupported_operation",
            f"http substitute handler does not support operation: {operation}",
        )

    data = params.get("data") if isinstance(params, dict) and "data" in params else params
    if not isinstance(data, dict):
        return error_response(400, "invalid_params", "params must be a dict")
    entry = data.get("entry")
    expected_hash = data.get("hash")
    if not isinstance(entry, dict) or not isinstance(expected_hash, (bytes, bytearray)):
        return error_response(
            400,
            "invalid_params",
            "http:try requires `entry` (dict, full source) and `hash` (bytes)",
        )

    entry_data = entry.get("data") if "data" in entry else entry
    endpoint = entry_data.get("endpoint") if isinstance(entry_data, dict) else None
    if not isinstance(endpoint, dict):
        return error_response(
            400,
            "invalid_entry",
            "http substitute source MUST carry `endpoint`",
        )
    layout = endpoint.get("content_layout", "flat")
    # `content_url_prefix` is a REQUIRED publisher commitment (arch ruling
    # Q2; EXTENSION-SUBSTITUTE §2.2). No derivation default — the two-prefix
    # model exists so content can be dedup'd to a different host than the
    # tree, which a derive-from-tree_url_prefix default would defeat.
    content_prefix = endpoint.get("content_url_prefix")
    if not isinstance(content_prefix, str) or not content_prefix:
        return error_response(
            400,
            "invalid_entry",
            "endpoint MUST carry a non-empty `content_url_prefix`",
        )

    expected_hash_bytes = bytes(expected_hash)
    try:
        url = build_content_url(content_prefix, layout, expected_hash_bytes)
    except ValueError as exc:
        return error_response(400, "invalid_layout", str(exc))

    fetch = fetcher if fetcher is not None else UrllibFetcher()
    try:
        body = fetch.get(url, timeout=timeout)
    except HttpSubstituteHandlerError as exc:
        # Policy-denied (cleartext-rejected) → cap_denied → chain ABORTS.
        if "cleartext" in str(exc) or "cap" in str(exc):
            return error_response(403, "cap_denied", str(exc))
        # decode failure / hash mismatch / other handler-side problem →
        # chain ADVANCES.
        return error_response(404, "not_found", str(exc))
    except urllib.error.HTTPError as exc:
        return error_response(
            exc.code if 400 <= exc.code < 500 else 502,
            "http_error",
            f"http substitute fetch returned {exc.code}: {exc.reason}",
        )
    except (urllib.error.URLError, OSError) as exc:
        return error_response(
            502,
            "network_error",
            f"http substitute fetch failed: {exc}",
        )

    try:
        entity = _verify_body_hash(body, expected_hash_bytes)
    except HttpSubstituteHandlerError as exc:
        return error_response(404, "not_found", str(exc))

    entity_dict = entity.to_dict()
    return {
        "status": 200,
        "result": entity_dict,
        "envelope_included": {expected_hash_bytes: entity_dict},
    }
