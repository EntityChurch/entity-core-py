"""Tests for the storage-substitute extension (CDN corridor v1).

Updated against RULINGS-STORAGE-SUBSTITUTE-CROSS-IMPL:
  - Ruling 3: `:try` returns raw entity dict in `result` (no wrapper).
  - Ruling 4: `source_peer_id` is local context, NOT a wire field;
    `system/content:get` does NOT auto-invoke the chain.
  - Ruling 5: manifest verify lives in-tree but is NOT on the v1.0
    default path (tests retained as authoring-utility coverage).
  - §3.2 rename: handler is `system/substitute/http:try`;
    `substitute_type` value `"http"`.

Coverage:
  - URL construction per `content_layout` enum + `tree_leaf_suffix`.
  - Manifest signature verify + seq freshness (v1.1 path; in-tree).
  - HTTP `:try` handler: hash-verify, transient/mismatch/cap_denied,
    unwrapped result shape per Ruling 3.
  - Chain orchestrator: cap gate, source filtering, priority sort,
    abort/advance, success ingest. Invoked directly (no
    content:get wire-field hook per Ruling 4).
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any

import cbor2
import pytest

from entity_core.crypto.identity import HASH_TYPE_SHA256, Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import compute_ecf_hash, get_hash_digest
from entity_handlers.content import CONTENT_HANDLER_PATTERN, content_handler
from entity_handlers.substitute import (
    CHAIN_CONSULT_CAP,
    CONTENT_LAYOUTS,
    DEFAULT_TREE_LEAF_SUFFIX,
    HTTP_HANDLER_PATTERN,
    ManifestFreshness,
    ManifestVerifyError,
    accept_manifest,
    build_content_url,
    build_tree_url,
    consult_substitute_chain,
    http_substitute_handler,
    verify_manifest_signature,
)
from entity_handlers.substitute.chain import OperatorTrustPolicy


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


def _digest(b: bytes) -> bytes:
    """Wire-form Hash for raw bytes: 0x00 (ECFv1-SHA256) + SHA256."""
    return bytes([0x00]) + hashlib.sha256(b).digest()


def _entity_hash(entity_dict: dict[str, Any]) -> bytes:
    return compute_ecf_hash({"type": entity_dict["type"], "data": entity_dict["data"]})


@dataclass
class _FakeResult:
    """Mimics the dispatcher's ExecuteResult shape for chain tests.

    Top-level dataclass (not nested in test methods) so `@dataclass` is
    evaluated once at module import — avoids the mutable-default-error
    case that masks abort-vs-advance in the chain orchestrator.
    """

    status: int = 200
    result: Any = None
    error: str | None = None


@dataclass
class _CtxBundle:
    keypair: Keypair
    pathway: EmitPathway
    handler: HandlerContext


def _consult_grant(
    *,
    source_peer_id: bytes | None = None,
    substitute_types: list[str] | None = None,
    handlers: list[str] | None = None,
    operations: list[str] | None = None,
    resources: list[str] | None = None,
) -> dict[str, Any]:
    """Mint a cap-axis grant for the consult op (RULING §4 + D2 shape).

    Per RULING-NAMED-CAPABILITY-MAPPING §4 + Chunk-C §D2,
    `content-substitute-consult` maps to `(handler=system/substitute/sources,
    operation=consult, resource=target_namespace)`. Constraints
    (`source_peer_id`, `substitute_types`) gate per-publisher and per-type
    narrowing.
    """
    grant: dict[str, Any] = {
        "handlers": {"include": handlers or ["system/substitute/sources"]},
        "operations": {"include": operations or ["consult"]},
        "resources": {"include": resources or ["*"]},
    }
    constraints: dict[str, Any] = {}
    if source_peer_id is not None:
        constraints["source_peer_id"] = source_peer_id
    if substitute_types is not None:
        constraints["substitute_types"] = substitute_types
    if constraints:
        grant["constraints"] = constraints
    return grant


# Default target namespace for the consult-chain tests. D2 requires
# resource_targets be set on the ctx for any grant to match.
_DEFAULT_TARGET_NAMESPACE = "system/content"
_UNSET = object()  # sentinel distinguishing "not passed" from "explicit None"


def _make_ctx(
    *,
    resource_targets: list[str] | None | object = _UNSET,
    consult_cap: bool = False,
    grants: list[dict[str, Any]] | None = None,
    dispatcher=None,
) -> _CtxBundle:
    kp = Keypair.generate()
    store = ContentStore()
    tree = EntityTree(kp.peer_id)
    pathway = EmitPathway(store, tree)
    grant_list: list[Any] = list(grants) if grants is not None else []
    if consult_cap and grants is None:
        # Default: unconstrained consult grant (any publisher, any type, any namespace).
        grant_list.append(_consult_grant())
    # D2 — resource axis: tests that exercise the consult flow need a
    # target namespace on the ctx. Default to the standard content path
    # when consult_cap is in play OR explicit grants are provided
    # (typical for the conformance-test class). Explicit `resource_targets`
    # (including explicit None) always wins.
    if resource_targets is _UNSET:
        resource_targets = (
            [_DEFAULT_TARGET_NAMESPACE] if (consult_cap or grants is not None) else None
        )
    caller_cap = {"type": "system/capability/token", "data": {"grants": grant_list}}
    handler = HandlerContext(
        local_peer_id=kp.peer_id,
        remote_peer_id=kp.peer_id,
        handler_grant={"type": "system/capability/token", "data": {"grants": grant_list}},
        caller_capability=caller_cap,
        emit_pathway=pathway,
        handler_pattern=CONTENT_HANDLER_PATTERN,
        resource_targets=resource_targets,
        keypair=kp,
        _execute_dispatcher=dispatcher,
    )
    return _CtxBundle(keypair=kp, pathway=pathway, handler=handler)


def _run(coro):
    return asyncio.run(coro)


# -----------------------------------------------------------------------------
# URL construction (STORAGE-SUBSTITUTE-HTTP §3-RES.2)
# -----------------------------------------------------------------------------


class TestUrls:
    def test_layouts_complete(self):
        assert CONTENT_LAYOUTS == frozenset(
            {"flat", "sharded-2-flat", "sharded-2-4", "sharded-2-2"}
        )

    def test_default_tree_leaf_suffix(self):
        assert DEFAULT_TREE_LEAF_SUFFIX == ".bin"

    def test_flat_layout(self):
        """Option α (arch ruling): `{hash}` is uniformly the
        66-hex wire form. Leaf is the full wire hash, not digest-only."""
        h = _digest(b"hello")
        url = build_content_url("https://cdn.example/c", "flat", h)
        assert url == f"https://cdn.example/c/{h.hex()}"

    def test_sharded_2_flat_layout(self):
        """Option α: `sharded-2-flat` = `{prefix}/{wire_hex[0:2]}/{wire_hex}`.
        First shard dir is the algorithm byte (`00` for SHA-256), giving
        free crypto-agility — SHA-384 entities would land in `/01/`."""
        h = _digest(b"hello")
        hex_ = h.hex()  # 66-char wire form
        url = build_content_url("https://cdn.example/c", "sharded-2-flat", h)
        assert url == f"https://cdn.example/c/{hex_[0:2]}/{hex_}"
        # For SHA-256 (alg 0x00) the first shard is always `00`.
        assert hex_[0:2] == "00"

    def test_sharded_2_4_layout(self):
        """Option α: `sharded-2-4` = `{prefix}/{wire_hex[0:2]}/{wire_hex[2:4]}/{wire_hex}`.
        Matches workbench-go's validated layout (272 entities across 164
        buckets, leaf sha256sum == digest)."""
        h = _digest(b"hello")
        hex_ = h.hex()
        url = build_content_url("https://cdn.example/c", "sharded-2-4", h)
        assert url == f"https://cdn.example/c/{hex_[0:2]}/{hex_[2:4]}/{hex_}"
        # Algorithm partition + first-digest-byte partition.
        assert hex_[0:2] == "00"
        # First digest byte is where SHA-256 sharding actually happens.

    def test_sharded_2_4_workbench_go_example(self):
        """Verbatim cohort-validated example: hash `00ada873…` shards to
        `/00/ad/00ada873…` under sharded-2-4. Locks the Option α
        convention against any future digest-slicing regression."""
        digest_hex_str = "ada873" + "0" * 58  # 64-char hypothetical digest
        h = bytes([0x00]) + bytes.fromhex(digest_hex_str)
        url = build_content_url("https://cdn.example/c", "sharded-2-4", h)
        assert url == f"https://cdn.example/c/00/ad/{h.hex()}"

    def test_sharded_2_2_is_alias_for_sharded_2_4(self):
        h = _digest(b"hello")
        assert build_content_url(
            "https://cdn.example/c", "sharded-2-2", h
        ) == build_content_url("https://cdn.example/c", "sharded-2-4", h)

    def test_trailing_slash_stripped_from_prefix(self):
        h = _digest(b"hello")
        a = build_content_url("https://cdn.example/c/", "flat", h)
        b = build_content_url("https://cdn.example/c", "flat", h)
        assert a == b

    def test_unknown_layout_raises(self):
        with pytest.raises(ValueError, match="Unsupported content_layout"):
            build_content_url("https://cdn.example/c", "bogus", _digest(b"x"))

    def test_tree_url_appends_suffix_literally(self):
        """Round-6 #1: consumers MUST append the suffix literally; default `.bin`."""
        url = build_tree_url("https://cdn.example/tree", "alpha/beta")
        assert url == "https://cdn.example/tree/alpha/beta.bin"

    def test_tree_url_custom_suffix(self):
        url = build_tree_url(
            "https://cdn.example/tree", "alpha/beta", tree_leaf_suffix=".dat"
        )
        assert url == "https://cdn.example/tree/alpha/beta.dat"

    def test_tree_url_empty_suffix(self):
        url = build_tree_url(
            "https://cdn.example/tree", "alpha/beta", tree_leaf_suffix=""
        )
        assert url == "https://cdn.example/tree/alpha/beta"


# -----------------------------------------------------------------------------
# Manifest signature verify + freshness — v1.1 only (Ruling 5)
# -----------------------------------------------------------------------------


class TestManifest:
    """Manifest verify is NOT on the v1.0 default fetch path.

    These tests cover the authoring + verify utilities that publisher
    tooling and future v1.1 consumers depend on. The manifest type is
    `system/substitute/snapshot-manifest` per §3.2 rename.
    """

    def _make_manifest(self, peer_id_bytes: bytes, seq: int = 1) -> dict[str, Any]:
        return {
            "type": "system/substitute/snapshot-manifest",
            "data": {
                "source_peer_id": peer_id_bytes,
                "snapshot_at": 1700000000,
                "seq": seq,
                "endpoint": {
                    "tree_url_prefix": "https://cdn/tree",
                    "content_url_prefix": "https://cdn/content",
                    "content_layout": "sharded-2-flat",
                    "tree_leaf_suffix": ".bin",
                },
                "path_index": {},
                "content_count": 0,
                "root_hashes": [],
            },
        }

    def _sign(self, kp: Keypair, target_hash: bytes) -> dict[str, Any]:
        sig_bytes = kp.sign(target_hash)
        return {
            "type": "system/signature",
            "data": {"target": target_hash, "signature": sig_bytes},
        }

    def test_signature_verify_success(self):
        kp = Keypair.generate()
        m = self._make_manifest(_digest(b"peer-bytes"))
        m_hash = _entity_hash(m)
        sig = self._sign(kp, m_hash)
        verify_manifest_signature(m, sig, kp.public_key_bytes())

    def test_signature_verify_wrong_target(self):
        kp = Keypair.generate()
        m = self._make_manifest(_digest(b"peer-bytes"))
        sig = self._sign(kp, _digest(b"different"))
        with pytest.raises(ManifestVerifyError, match="different hash"):
            verify_manifest_signature(m, sig, kp.public_key_bytes())

    def test_signature_verify_wrong_key(self):
        kp_signer = Keypair.generate()
        kp_other = Keypair.generate()
        m = self._make_manifest(_digest(b"peer-bytes"))
        m_hash = _entity_hash(m)
        sig = self._sign(kp_signer, m_hash)
        with pytest.raises(ManifestVerifyError, match="Ed25519 verification failed"):
            verify_manifest_signature(m, sig, kp_other.public_key_bytes())

    def test_freshness_first_seen(self):
        cache: dict[bytes, int] = {}
        peer = _digest(b"p")
        m = self._make_manifest(peer, seq=5)
        verdict = accept_manifest(m["data"], cache)
        assert verdict is ManifestFreshness.FIRST_SEEN
        assert cache[peer] == 5

    def test_freshness_newer(self):
        peer = _digest(b"p")
        cache: dict[bytes, int] = {peer: 3}
        m = self._make_manifest(peer, seq=7)
        verdict = accept_manifest(m["data"], cache)
        assert verdict is ManifestFreshness.NEWER
        assert cache[peer] == 7

    def test_freshness_same_seq(self):
        peer = _digest(b"p")
        cache: dict[bytes, int] = {peer: 5}
        m = self._make_manifest(peer, seq=5)
        verdict = accept_manifest(m["data"], cache)
        assert verdict is ManifestFreshness.SAME_SEQ
        assert cache[peer] == 5

    def test_freshness_stale(self):
        peer = _digest(b"p")
        cache: dict[bytes, int] = {peer: 9}
        m = self._make_manifest(peer, seq=5)
        verdict = accept_manifest(m["data"], cache)
        assert verdict is ManifestFreshness.STALE
        # STALE does NOT touch the cache: the manifest is rejected.
        assert cache[peer] == 9


# -----------------------------------------------------------------------------
# HTTP `:try` handler — hash-verify, transient/mismatch/cap_denied
# Result shape per Ruling 3: raw verified entity dict in `result`.
# -----------------------------------------------------------------------------


class _FakeFetcher:
    def __init__(self, body: bytes | None = None, exc: Exception | None = None):
        self.body = body
        self.exc = exc
        self.url_seen: str | None = None

    def get(self, url: str, *, timeout: float) -> bytes:
        self.url_seen = url
        if self.exc is not None:
            raise self.exc
        assert self.body is not None
        return self.body


def _make_entry(layout: str = "flat", url_prefix: str = "https://cdn/c") -> dict[str, Any]:
    """`system/substitute/source` for the `http` backend (renamed from `static-cdn`)."""
    return {
        "type": "system/substitute/source",
        "data": {
            "name": "test-http",
            "substitute_type": "http",
            "source_peer_id": _digest(b"pub"),
            "endpoint": {
                "tree_url_prefix": "https://cdn/t",
                "content_url_prefix": url_prefix,
                "content_layout": layout,
                "tree_leaf_suffix": ".bin",
            },
            "priority": 0,
            "enabled": True,
        },
    }


class TestHttpSubstituteHandler:
    def test_success_returns_raw_entity_in_result(self):
        """Ruling 3: result is the raw verified entity dict, NOT a `{entity, hash}` wrapper."""
        ctx = _make_ctx()
        target = {"type": "custom/thing", "data": {"x": 1}}
        body = cbor2.dumps(target, canonical=True)
        h = _entity_hash(target)
        fetcher = _FakeFetcher(body=body)
        result = _run(
            http_substitute_handler(
                HTTP_HANDLER_PATTERN,
                "try",
                {"data": {"entry": _make_entry(), "hash": h}},
                ctx.handler,
                fetcher=fetcher,
            )
        )
        assert result["status"] == 200
        # No wrapper — result IS the entity dict.
        assert result["result"]["type"] == "custom/thing"
        assert result["result"]["data"] == {"x": 1}
        assert result["envelope_included"][h]["data"] == {"x": 1}
        # URL was built per `flat` layout
        assert fetcher.url_seen.endswith(get_hash_digest(h).hex())

    def test_handler_uri_renamed_to_http(self):
        """Sanity: pattern is `system/substitute/http`, not `static-cdn`."""
        assert HTTP_HANDLER_PATTERN == "system/substitute/http"

    def test_entry_substitute_type_is_http(self):
        """Sanity: the spec-pinned value is `"http"`, not `"static-cdn"`."""
        entry = _make_entry()
        assert entry["data"]["substitute_type"] == "http"

    def test_hash_mismatch_advances_chain(self):
        ctx = _make_ctx()
        body = cbor2.dumps({"type": "x", "data": {"x": 1}}, canonical=True)
        wrong_hash = _digest(b"definitely-not-this")
        result = _run(
            http_substitute_handler(
                HTTP_HANDLER_PATTERN,
                "try",
                {"data": {"entry": _make_entry(), "hash": wrong_hash}},
                ctx.handler,
                fetcher=_FakeFetcher(body=body),
            )
        )
        assert result["status"] == 404
        assert "mismatch" in result["result"]["data"]["message"]

    def test_network_error_advances(self):
        import urllib.error

        ctx = _make_ctx()
        result = _run(
            http_substitute_handler(
                HTTP_HANDLER_PATTERN,
                "try",
                {"data": {"entry": _make_entry(), "hash": _digest(b"x")}},
                ctx.handler,
                fetcher=_FakeFetcher(exc=urllib.error.URLError("connection refused")),
            )
        )
        assert result["status"] == 502
        assert result["result"]["data"]["code"] == "network_error"

    def test_http_error_5xx_advances(self):
        import urllib.error

        ctx = _make_ctx()
        result = _run(
            http_substitute_handler(
                HTTP_HANDLER_PATTERN,
                "try",
                {"data": {"entry": _make_entry(), "hash": _digest(b"x")}},
                ctx.handler,
                fetcher=_FakeFetcher(
                    exc=urllib.error.HTTPError(
                        "url", 503, "service unavailable", {}, None
                    )
                ),
            )
        )
        assert result["status"] == 502

    def test_invalid_layout_rejected(self):
        ctx = _make_ctx()
        bad_entry = _make_entry()
        bad_entry["data"]["endpoint"]["content_layout"] = "bogus"
        result = _run(
            http_substitute_handler(
                HTTP_HANDLER_PATTERN,
                "try",
                {"data": {"entry": bad_entry, "hash": _digest(b"x")}},
                ctx.handler,
                fetcher=_FakeFetcher(body=b""),
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_layout"

    def test_missing_endpoint_rejected(self):
        ctx = _make_ctx()
        bad = _make_entry()
        del bad["data"]["endpoint"]
        result = _run(
            http_substitute_handler(
                HTTP_HANDLER_PATTERN,
                "try",
                {"data": {"entry": bad, "hash": _digest(b"x")}},
                ctx.handler,
                fetcher=_FakeFetcher(body=b""),
            )
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_entry"


# -----------------------------------------------------------------------------
# Chain orchestrator — list/filter/sort + abort/advance + ingest.
# Invoked directly as an SDK primitive per Ruling 4 (no content:get hook).
# -----------------------------------------------------------------------------


def _put_source(pathway: EmitPathway, peer_id: str, source_data: dict[str, Any]) -> bytes:
    """Persist a substitute-source entity and bind it under sources/."""
    e = Entity(type="system/substitute/source", data=source_data)
    h = pathway.content_store.put(e)
    pathway.entity_tree.set(f"system/substitute/sources/{h.hex()}", h)
    return h


# D7 — default test trust policy: most legacy tests use synthetic fake
# publisher hashes (_digest(b"pub") etc.) that don't have real keypairs,
# so verifying their signatures is impossible. The tests use the
# OPERATOR-OVERRIDE path: they allowlist the fake publishers. New D7
# tests (TestD7SourceSignatureMust) exercise the real signed-path and
# the closed-default path.
_TEST_TRUST_POLICY = OperatorTrustPolicy(
    allow_unsigned_source_peer_ids=(
        _digest(b"pub"),
        _digest(b"other"),
        _digest(b"other-publisher"),
    )
)


async def _consult(ctx, missed_hash, *, claimed_source_peer_id, **kw):
    """Test wrapper around `consult_substitute_chain` that defaults to
    the override trust policy for synthetic fake publishers."""
    if "trust_policy" not in kw:
        kw["trust_policy"] = _TEST_TRUST_POLICY
    return await consult_substitute_chain(
        ctx, missed_hash, claimed_source_peer_id=claimed_source_peer_id, **kw
    )


def _http_source_data(*, peer: bytes, priority: int = 0, enabled: bool = True,
                      expires_at: int | None = None) -> dict[str, Any]:
    data = {
        "name": f"p{priority}",
        "substitute_type": "http",  # renamed from "static-cdn" per §3.2
        "source_peer_id": peer,
        "endpoint": {
            "tree_url_prefix": "https://x/t",
            "content_url_prefix": "https://x/c",
            "content_layout": "flat",
            "tree_leaf_suffix": ".bin",
        },
        "priority": priority,
        "enabled": enabled,
    }
    if expires_at is not None:
        data["expires_at"] = expires_at
    return data


class TestChainOrchestrator:
    def test_no_consult_cap_returns_empty(self):
        """Without CHAIN_CONSULT_CAP on caller chain, chain is not consulted."""
        ctx = _make_ctx(consult_cap=False)
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.entity is None
        assert outcome.attempted == 0
        assert outcome.aborted is False

    def test_no_claimed_source_peer_id_returns_empty(self):
        """Bare-hash query (no claimed_source_peer_id) skips consultation."""
        ctx = _make_ctx(consult_cap=True)
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=None,
            )
        )
        assert outcome.attempted == 0

    def test_disabled_source_filtered_out(self):
        ctx = _make_ctx(consult_cap=True)
        _put_source(
            ctx.pathway,
            ctx.keypair.peer_id,
            _http_source_data(peer=_digest(b"pub"), enabled=False),
        )
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0

    def test_wrong_peer_filtered_out(self):
        ctx = _make_ctx(consult_cap=True)
        _put_source(
            ctx.pathway,
            ctx.keypair.peer_id,
            _http_source_data(peer=_digest(b"other")),
        )
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0

    def test_priority_sort_ascending(self):
        """Lower priority value runs first."""
        dispatched: list[int] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            priority = params["entry"]["data"]["priority"]
            dispatched.append(priority)
            return _FakeResult(status=404, result={"data": {"code": "not_found"}})

        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        peer = _digest(b"pub")
        for prio in (5, 1, 3):
            _put_source(
                ctx.pathway,
                ctx.keypair.peer_id,
                _http_source_data(peer=peer, priority=prio),
            )
        _run(
            _consult(
                ctx.handler, _digest(b"target"), claimed_source_peer_id=peer
            )
        )
        assert dispatched == [1, 3, 5]

    def test_cap_denied_aborts_chain(self):
        """403 from `:try` ABORTS the chain — remaining sources not consulted."""
        dispatched: list[int] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            prio = params["entry"]["data"]["priority"]
            dispatched.append(prio)
            return _FakeResult(
                status=403,
                result={"data": {"code": "cap_denied", "message": "..."}},
            )

        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        peer = _digest(b"pub")
        for prio in (1, 2):
            _put_source(
                ctx.pathway,
                ctx.keypair.peer_id,
                _http_source_data(peer=peer, priority=prio),
            )
        outcome = _run(
            _consult(
                ctx.handler, _digest(b"target"), claimed_source_peer_id=peer
            )
        )
        assert dispatched == [1]  # second never tried
        assert outcome.aborted is True
        assert outcome.entity is None
        assert outcome.last_error == "cap_denied"

    def test_dispatch_uri_is_renamed_http_pattern(self):
        """Chain dispatches to `system/substitute/http`, not `static-cdn`."""
        seen_uris: list[str] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            seen_uris.append(uri)
            return _FakeResult(status=404, result={"data": {"code": "not_found"}})

        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        peer = _digest(b"pub")
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=peer))
        _run(
            _consult(
                ctx.handler, _digest(b"target"), claimed_source_peer_id=peer
            )
        )
        assert seen_uris == ["system/substitute/http"]

    def test_success_ingests_raw_entity(self):
        """Ruling 3: handler returns raw entity in `result`; orchestrator
        ingests it into the local content store under the verified hash."""
        target_entity = {"type": "custom/thing", "data": {"x": 42}}
        target_hash = _entity_hash(target_entity)

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            # Raw entity in result (no {entity, hash} wrapper).
            return _FakeResult(status=200, result=target_entity)

        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        peer = _digest(b"pub")
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=peer))
        outcome = _run(
            _consult(
                ctx.handler, target_hash, claimed_source_peer_id=peer
            )
        )
        assert outcome.entity is not None
        assert outcome.entity["type"] == "custom/thing"
        stored = ctx.pathway.content_store.get(target_hash)
        assert stored is not None
        assert stored.type == "custom/thing"

    def test_expired_source_filtered_out(self):
        ctx = _make_ctx(consult_cap=True)
        _put_source(
            ctx.pathway,
            ctx.keypair.peer_id,
            _http_source_data(peer=_digest(b"pub"), expires_at=1),
        )
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
                now_ms=1_000_000,
            )
        )
        assert outcome.attempted == 0


# -----------------------------------------------------------------------------
# Cap-axis ruling conformance (RULING-NAMED-CAPABILITY-MAPPING)
# Replaces the legacy string-presence check for `content-substitute-consult`
# with a real (handler, operation) grant check + constraint matching, and
# fails closed when no grant matches.
# -----------------------------------------------------------------------------


def _attempting_dispatcher(seen: list[dict[str, Any]]):
    """Record `(uri, entry)` for each dispatch and return a clean 404."""

    async def fake_dispatch(uri, op, params, *args, **kwargs):
        seen.append(
            {
                "uri": uri,
                "substitute_type": params["entry"]["data"].get("substitute_type"),
            }
        )
        return _FakeResult(status=404, result={"data": {"code": "not_found"}})

    return fake_dispatch


class TestCapAxisRulingConformance:
    """Fail-closed conformance per RULING §6 + per-cap mapping per §4."""

    def test_no_grant_at_all_denies_consultation(self):
        """Fail-closed: absent any grant → consultation denied."""
        seen: list[dict[str, Any]] = []
        ctx = _make_ctx(grants=[], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.entity is None
        assert outcome.attempted == 0
        assert seen == [], "no source should be dispatched without a matching grant"

    def test_grant_on_wrong_handler_denies(self):
        """RULING §4: only `(system/substitute/sources, consult)` matches.

        A grant on a different handler — even with op=consult — does NOT
        permit substitute consultation. ('Any token present' is not a match.)
        """
        seen: list[dict[str, Any]] = []
        wrong_handler_grant = _consult_grant(handlers=["system/tree"])
        ctx = _make_ctx(grants=[wrong_handler_grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_grant_on_wrong_operation_denies(self):
        """RULING §4: a grant on the right handler but wrong op does NOT permit."""
        seen: list[dict[str, Any]] = []
        wrong_op_grant = _consult_grant(operations=["read"])
        ctx = _make_ctx(grants=[wrong_op_grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_properly_scoped_grant_permits(self):
        """RULING §4: a grant on (system/substitute/sources, consult) permits."""
        seen: list[dict[str, Any]] = []
        ctx = _make_ctx(
            grants=[_consult_grant()], dispatcher=_attempting_dispatcher(seen)
        )
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        # Source attempted, dispatcher invoked.
        assert outcome.attempted == 1
        assert len(seen) == 1
        assert seen[0]["uri"] == "system/substitute/http"

    def test_source_peer_id_constraint_match_permits(self):
        """RULING §4: `source_peer_id` constraint, when byte-equal, permits."""
        seen: list[dict[str, Any]] = []
        peer = _digest(b"pub")
        grant = _consult_grant(source_peer_id=peer)
        ctx = _make_ctx(grants=[grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=peer))
        outcome = _run(
            _consult(
                ctx.handler, _digest(b"target"), claimed_source_peer_id=peer
            )
        )
        assert outcome.attempted == 1
        assert len(seen) == 1

    def test_source_peer_id_constraint_mismatch_denies(self):
        """RULING §4: a constraint scoped to a different publisher denies."""
        seen: list[dict[str, Any]] = []
        grant = _consult_grant(source_peer_id=_digest(b"other-publisher"))
        ctx = _make_ctx(grants=[grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_substitute_types_constraint_permits_listed_type(self):
        """RULING §4: `substitute_types` constraint permits the listed type."""
        seen: list[dict[str, Any]] = []
        grant = _consult_grant(substitute_types=["http"])
        ctx = _make_ctx(grants=[grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 1
        assert seen[0]["substitute_type"] == "http"

    def test_substitute_types_constraint_skips_unlisted_type(self):
        """RULING §4: per-entry skip when grant's substitute_types excludes the type."""
        seen: list[dict[str, Any]] = []
        # Grant restricts to "ipfs" only; the source on disk is "http" → skip.
        grant = _consult_grant(substitute_types=["ipfs"])
        ctx = _make_ctx(grants=[grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        # Source was iterated (attempted++) but the dispatcher never invoked
        # because no grant permitted "http".
        assert outcome.attempted == 1
        assert seen == []
        assert outcome.last_error == "substitute_type_not_permitted"

    def test_legacy_string_presence_shape_denies(self):
        """RULING §6: 'any token present' is NOT a grant match.

        A legacy grant carrying the cap *name* as a top-level `op` field —
        the permissive-forever shape — does NOT pass the cap-axis check.
        """
        seen: list[dict[str, Any]] = []
        legacy_grant = {"op": CHAIN_CONSULT_CAP, "resource": {"targets": ["*"]}}
        ctx = _make_ctx(grants=[legacy_grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_mal_typed_source_peer_id_constraint_fails_closed(self):
        """RULING §6: malformed constraints fail closed, not open."""
        seen: list[dict[str, Any]] = []
        # Constraint should be bytes; pass a string → grant rejected for safety.
        bad_grant = _consult_grant()
        bad_grant["constraints"] = {"source_peer_id": "not-bytes"}
        ctx = _make_ctx(grants=[bad_grant], dispatcher=_attempting_dispatcher(seen))
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    # D2 — resource axis specific tests.

    def test_d2_no_resource_targets_in_ctx_denies(self):
        """D2: without a target namespace on ctx, no grant matches.

        The consult cap is "for what the consumer is reading"; the
        resource axis pins which namespace. Empty/None resource_targets
        means we cannot establish the cap's scope → fail closed."""
        seen: list[dict[str, Any]] = []
        ctx = _make_ctx(
            grants=[_consult_grant()],
            dispatcher=_attempting_dispatcher(seen),
            resource_targets=None,  # explicit override of default
        )
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_d2_resource_axis_match_permits(self):
        """D2: grant's resources scope covers the ctx's resource_target."""
        seen: list[dict[str, Any]] = []
        # Grant scoped to system/content/blob/* — consumer reading into
        # system/content/blob/foo — match.
        grant = _consult_grant(resources=["system/content/blob/*"])
        ctx = _make_ctx(
            grants=[grant],
            dispatcher=_attempting_dispatcher(seen),
            resource_targets=["system/content/blob/foo"],
        )
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 1
        assert len(seen) == 1

    def test_d2_resource_axis_mismatch_denies(self):
        """D2: grant scoped to a different namespace than the consumer is
        reading into → no match, fail closed.

        This is the exact reason Python's prior constraints-only model
        was banned: a delegated consult grant on namespace X must NOT
        permit consultation when the consumer is reading into namespace Y."""
        seen: list[dict[str, Any]] = []
        # Grant scoped to namespace X; consumer reading into namespace Y.
        grant = _consult_grant(resources=["custom/namespace-X/*"])
        ctx = _make_ctx(
            grants=[grant],
            dispatcher=_attempting_dispatcher(seen),
            resource_targets=["custom/namespace-Y/some-resource"],
        )
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_d2_resource_axis_partial_coverage_denies(self):
        """D2: every target in resource_targets MUST be covered.

        A grant that covers SOME but not ALL targets does not match —
        delegated consult must apply uniformly to the consumer's read."""
        seen: list[dict[str, Any]] = []
        grant = _consult_grant(resources=["system/content/blob/*"])
        ctx = _make_ctx(
            grants=[grant],
            dispatcher=_attempting_dispatcher(seen),
            resource_targets=[
                "system/content/blob/covered",   # covered
                "system/other/uncovered",         # not covered
            ],
        )
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_d2_resource_exclude_denies(self):
        """D2: a grant's resources.exclude pattern denies the match for
        any covered target that falls under the exclusion."""
        seen: list[dict[str, Any]] = []
        grant = _consult_grant(resources=["system/content/*"])
        grant["resources"]["exclude"] = ["system/content/private/*"]
        ctx = _make_ctx(
            grants=[grant],
            dispatcher=_attempting_dispatcher(seen),
            resource_targets=["system/content/private/secret"],
        )
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_d2_wildcard_resources_covers_anything(self):
        """A grant with resources=['*'] covers any well-formed target."""
        seen: list[dict[str, Any]] = []
        ctx = _make_ctx(
            grants=[_consult_grant(resources=["*"])],
            dispatcher=_attempting_dispatcher(seen),
            resource_targets=["arbitrary/path/here"],
        )
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
            )
        )
        assert outcome.attempted == 1

    def test_expired_grant_denies(self):
        """Temporal bounds gate the cap-axis check too."""
        seen: list[dict[str, Any]] = []
        kp = Keypair.generate()
        store = ContentStore()
        tree = EntityTree(kp.peer_id)
        pathway = EmitPathway(store, tree)
        expired_cap_data = {
            "grants": [_consult_grant()],
            "expires_at": 1,  # expired in the distant past
        }
        caller_cap = {"type": "system/capability/token", "data": expired_cap_data}
        handler = HandlerContext(
            local_peer_id=kp.peer_id,
            remote_peer_id=kp.peer_id,
            handler_grant={"type": "system/capability/token", "data": expired_cap_data},
            caller_capability=caller_cap,
            emit_pathway=pathway,
            handler_pattern=CONTENT_HANDLER_PATTERN,
            resource_targets=None,
            keypair=kp,
            _execute_dispatcher=_attempting_dispatcher(seen),
        )
        _put_source(pathway, kp.peer_id, _http_source_data(peer=_digest(b"pub")))
        outcome = _run(
            _consult(
                handler,
                _digest(b"target"),
                claimed_source_peer_id=_digest(b"pub"),
                now_ms=1_000_000,
            )
        )
        assert outcome.attempted == 0
        assert seen == []


# -----------------------------------------------------------------------------
# D7 — source signature MUST on wire + operator-trust override knob.
# -----------------------------------------------------------------------------


def _publisher_peer_id_hash(publisher_kp: Keypair) -> bytes:
    """Return the publisher's `system/hash`-shape peer-id (algorithm byte
    + sha256 of pubkey). This matches the `source_peer_id` field type."""
    raw = publisher_kp.public_key.public_bytes_raw()
    return bytes([0x00]) + hashlib.sha256(raw).digest()


def _register_publisher_peer_entity(pathway: EmitPathway, publisher_kp: Keypair) -> None:
    """Write the publisher's ``system/peer/{peer_id}`` entity so D7's
    signature verify can look up the pubkey via the local tree.

    v7.65: dual-registration. The canonical (identity-form) path is the
    canonical storage form per §4; the SHA-256-form path is ALSO populated
    because D7's lookup (`_peer_id_string_from_hash`) reconstructs a
    SHA-256-form peer_id from `source_peer_id` (a `system/hash` of pubkey)
    and looks up that path. Dual-registration mirrors what §5 wire-acceptance
    canonicalization-on-storage would produce.
    """
    from entity_core.storage.emit import EmitContext
    from entity_core.crypto.identity import (
        HASH_TYPE_SHA256,
        KEY_TYPE_ED25519,
        _peer_id_from_bytes,
    )

    # v7.65 §2: system/peer data = (public_key, key_type) only
    peer_entity = Entity(
        type="system/peer",
        data={
            "public_key": publisher_kp.public_key.public_bytes_raw(),
            "key_type": "ed25519",
        },
    )
    pathway.emit(
        f"system/peer/{publisher_kp.peer_id}",
        peer_entity,
        EmitContext.bootstrap(),
    )
    # v7.66 §3 — public mint API is canonical-only; legacy-form
    # synthesis for the D7 dual-registration test uses the internal
    # corpus-authoring helper.
    sha_pid = _peer_id_from_bytes(
        publisher_kp.public_key.public_bytes_raw(),
        key_type=KEY_TYPE_ED25519,
        hash_type=HASH_TYPE_SHA256,
    )
    pathway.emit(
        f"system/peer/{sha_pid}",
        peer_entity,
        EmitContext.bootstrap(),
    )


def _put_signed_source(
    pathway: EmitPathway,
    publisher_kp: Keypair,
    source_data: dict,
) -> bytes:
    """Mint + sign + store a substitute-source entity (D7 signed path).

    The signature entity is bound at the V7 invariant signature path
    ``{publisher_peer_id}/system/signature/{source_hash_hex}`` (matches
    Python's refless model + `_verify_source_signature` discovery)."""
    from entity_core.protocol.auth import create_signature_entity

    from entity_core.crypto.identity import (
        HASH_TYPE_SHA256,
        KEY_TYPE_ED25519,
        _peer_id_from_bytes,
    )

    src = Entity(type="system/substitute/source", data=source_data)
    src_hash = src.compute_hash()
    sig_entity = create_signature_entity(publisher_kp, src_hash)
    sig_hash = pathway.content_store.put(sig_entity)
    # v7.65: bind at canonical (identity-form) path AND SHA-256-form path so
    # D7 lookup (which reconstructs SHA-256-form from source_peer_id hash)
    # finds it. Mirrors §5 carve-out's canonicalize-on-acceptance pattern.
    # v7.66 §3 — public mint API is canonical-only; corpus-side legacy-form
    # synthesis uses the internal helper.
    sha_pid = _peer_id_from_bytes(
        publisher_kp.public_key.public_bytes_raw(),
        key_type=KEY_TYPE_ED25519,
        hash_type=HASH_TYPE_SHA256,
    )
    for pid in (publisher_kp.peer_id, sha_pid):
        pathway.entity_tree.set(
            f"{pid}/system/signature/{src_hash.hex()}",
            sig_hash,
        )
    h = pathway.content_store.put(src)
    pathway.entity_tree.set(f"system/substitute/sources/{h.hex()}", h)
    return h


class TestD7SourceSignatureMust:
    """Per RULING/D7: source entries MUST be signed by source_peer_id on
    the wire; operator MAY locally override (default-closed, explicit)."""

    def test_signed_source_admitted_under_closed_policy(self):
        """The signed-path: real signature, no override needed."""
        seen: list[dict[str, Any]] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            seen.append({"uri": uri})
            return _FakeResult(status=200, result={"type": "x", "data": {}})

        publisher_kp = Keypair.generate()
        pub_hash = _publisher_peer_id_hash(publisher_kp)
        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        _register_publisher_peer_entity(ctx.pathway, publisher_kp)
        _put_signed_source(
            ctx.pathway,
            publisher_kp,
            _http_source_data(peer=pub_hash),
        )

        outcome = _run(
            consult_substitute_chain(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=pub_hash,
                # CLOSED policy — no override.
                trust_policy=OperatorTrustPolicy(),
            )
        )
        assert outcome.attempted == 1
        assert len(seen) == 1

    def test_unsigned_source_rejected_under_closed_policy(self):
        """Default-closed: an unsigned source is silently skipped."""
        seen: list[dict[str, Any]] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            seen.append({"uri": uri})
            return _FakeResult(status=200, result={"type": "x", "data": {}})

        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        pub_hash = _digest(b"unsigned-publisher")
        # Plain `_put_source` writes the entry without `refs.signature`.
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=pub_hash))

        outcome = _run(
            consult_substitute_chain(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=pub_hash,
                trust_policy=OperatorTrustPolicy(),
            )
        )
        assert outcome.attempted == 0
        assert seen == []

    def test_unsigned_source_admitted_under_operator_override(self):
        """Operator-trust override: explicit allowlist permits unsigned."""
        seen: list[dict[str, Any]] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            seen.append({"uri": uri})
            return _FakeResult(status=200, result={"type": "x", "data": {}})

        pub_hash = _digest(b"trusted-but-unsigned")
        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        _put_source(ctx.pathway, ctx.keypair.peer_id, _http_source_data(peer=pub_hash))

        outcome = _run(
            consult_substitute_chain(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=pub_hash,
                trust_policy=OperatorTrustPolicy(
                    allow_unsigned_source_peer_ids=(pub_hash,)
                ),
            )
        )
        assert outcome.attempted == 1
        assert len(seen) == 1

    def test_signature_by_wrong_key_rejected(self):
        """A signature created by a different keypair MUST NOT verify
        against the claimed source_peer_id's pubkey."""
        seen: list[dict[str, Any]] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            seen.append({"uri": uri})
            return _FakeResult(status=200, result={"type": "x", "data": {}})

        # Real publisher keypair P, but a different keypair WRONG signs.
        publisher_kp = Keypair.generate()
        wrong_kp = Keypair.generate()
        pub_hash = _publisher_peer_id_hash(publisher_kp)

        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        _register_publisher_peer_entity(ctx.pathway, publisher_kp)
        # Sign with the wrong key.
        _put_signed_source(ctx.pathway, wrong_kp, _http_source_data(peer=pub_hash))

        outcome = _run(
            consult_substitute_chain(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=pub_hash,
                trust_policy=OperatorTrustPolicy(),  # closed
            )
        )
        # Closed policy + bad sig → rejected.
        assert outcome.attempted == 0
        assert seen == []

    def test_signed_source_without_local_pubkey_lookup_fails_closed(self):
        """If publisher's system/peer entity is NOT in the local tree,
        we can't verify the signature → closed policy denies."""
        seen: list[dict[str, Any]] = []

        async def fake_dispatch(uri, op, params, *args, **kwargs):
            seen.append({"uri": uri})
            return _FakeResult(status=200, result={"type": "x", "data": {}})

        publisher_kp = Keypair.generate()
        pub_hash = _publisher_peer_id_hash(publisher_kp)
        ctx = _make_ctx(consult_cap=True, dispatcher=fake_dispatch)
        # NOTE: NOT registering system/peer/{peer_id} — pubkey unavailable.
        _put_signed_source(
            ctx.pathway, publisher_kp, _http_source_data(peer=pub_hash)
        )

        outcome = _run(
            consult_substitute_chain(
                ctx.handler,
                _digest(b"target"),
                claimed_source_peer_id=pub_hash,
                trust_policy=OperatorTrustPolicy(),  # closed
            )
        )
        assert outcome.attempted == 0
        assert seen == []


# -----------------------------------------------------------------------------
# Per Ruling 4, content:get has NO auto-invocation of the chain.
# The chain helper is for SDK / Phase-2-dispatcher use. Verify the
# wire shape of get-request is unchanged.
# -----------------------------------------------------------------------------


class TestContentGetWireShapeUnchanged:
    def test_get_request_does_not_accept_source_peer_id(self):
        """Ruling 4: `source_peer_id` is NOT a wire field on get-request.

        Passing it in params is ignored — the result is the bare miss
        response (no substitute meta, no chain attempt). This verifies the
        content handler does not introspect for it.
        """
        ctx = _make_ctx(
            resource_targets=["system/content"], consult_cap=True
        )
        target_hash = _digest(b"never-resolves")
        result = _run(
            content_handler(
                CONTENT_HANDLER_PATTERN,
                "get",
                {
                    "data": {
                        "hashes": [target_hash],
                        # Even with source_peer_id in params, content:get does
                        # NOT auto-invoke the chain (Ruling 4).
                        "source_peer_id": _digest(b"pub"),
                    }
                },
                ctx.handler,
            )
        )
        assert result["status"] == 200
        data = result["result"]["data"]
        assert target_hash in data["missing"]
        # No substitute meta — chain was not consulted.
        assert "substitute_chain_attempted" not in data
        assert "substitute_chain_length" not in data
        assert "substitute_chain_last_error" not in data
