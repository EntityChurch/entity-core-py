"""EXTENSION-STORAGE-SUBSTITUTE-SOURCES + -HTTP — read-path substrate.

Renamed from CONTENT-SUBSTITUTE per the storage-substitute cross-impl
rulings §3 — the extension substitutes the whole storage layer
(tree + content) via the two-prefix profile, not just content. The wire
namespace stays `system/substitute/*` (already converged across all
three impls).

On a local content miss, a consumer that knows the claimed source peer
consults an ordered chain of `system/substitute/source` entries;
per-type `:try` handlers dispatch the actual fetch. The `http` backend
does **inline HTTP GET + hash-verify** (Mechanism A) — no BRIDGE-HTTP,
no `bridge-http-fetch` cap on this path. Trust anchor: content hash.

Per Ruling 4, the chain helper is invoked by consumer-side code that
holds the source peer locally (Phase 2 dispatcher / SDK helpers); the
`system/content:get` handler does NOT auto-invoke the chain. Per
Ruling 5, manifest signature verify lives in `manifest.py` but is
gated off the v1.0 default path — manifest processing lands all-at-once
in v1.1.

Modules:

* :mod:`entity_handlers.substitute.urls` — URL construction per
  ``content_layout`` enum (flat / sharded-2-flat / sharded-2-4 /
  sharded-2-2) and ``tree_leaf_suffix`` append.
* :mod:`entity_handlers.substitute.manifest` — snapshot-manifest
  Ed25519 signature verify + monotonic ``seq`` freshness. **v1.1 only.**
* :mod:`entity_handlers.substitute.chain` — chain-consultation
  orchestrator: list + filter + sort + dispatch per-type with
  abort/advance/ingest semantics.
* :mod:`entity_handlers.substitute.http` — the
  ``system/substitute/http:try`` handler (inline ``http_get`` +
  hash-verify; raw-entity response shape per Ruling 3).
"""

from __future__ import annotations

from entity_handlers.substitute.chain import (
    CHAIN_CONSULT_CAP,
    consult_substitute_chain,
)
from entity_handlers.substitute.http import (
    DEFAULT_HTTP_TIMEOUT_SECONDS,
    HTTP_HANDLER_PATTERN,
    HTTP_TRY_OP,
    HttpFetcher,
    HttpSubstituteHandlerError,
    UrllibFetcher,
    http_substitute_handler,
)
from entity_handlers.substitute.manifest import (
    ManifestFreshness,
    ManifestVerifyError,
    accept_manifest,
    verify_manifest_signature,
)
from entity_handlers.substitute.urls import (
    CONTENT_LAYOUTS,
    DEFAULT_TREE_LEAF_SUFFIX,
    build_content_url,
    build_tree_url,
    digest_hex,
)

__all__ = [
    # chain orchestrator
    "CHAIN_CONSULT_CAP",
    "consult_substitute_chain",
    # manifest (v1.1 only)
    "ManifestFreshness",
    "ManifestVerifyError",
    "accept_manifest",
    "verify_manifest_signature",
    # http :try handler
    "DEFAULT_HTTP_TIMEOUT_SECONDS",
    "HTTP_HANDLER_PATTERN",
    "HTTP_TRY_OP",
    "HttpFetcher",
    "HttpSubstituteHandlerError",
    "UrllibFetcher",
    "http_substitute_handler",
    # url construction
    "CONTENT_LAYOUTS",
    "DEFAULT_TREE_LEAF_SUFFIX",
    "build_content_url",
    "build_tree_url",
    "digest_hex",
]
