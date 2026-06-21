"""Integration tests for subscription_handler subscribe operation.

Focuses on the SB1 chain-root check on `deliver_token` introduced by
PROPOSAL-COHERENT-CAPABILITY-AUTHORITY (EXTENSION-SUBSCRIPTION v3.10).
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_core.utils.ecf import ALG_ECFV1_SHA256

from entity_handlers.subscription import (
    SUBSCRIPTION_HANDLER_PATTERN,
    subscription_handler,
)


HASH_AUTHOR = bytes([ALG_ECFV1_SHA256]) + b"author" + b"\x00" * 26
HASH_OTHER = bytes([ALG_ECFV1_SHA256]) + b"other_" + b"\x00" * 26


def _make_token(
    *,
    granter: bytes,
    parent: bytes | None = None,
    deliver_uri: str,
    deliver_operation: str = "receive",
) -> Entity:
    """Build a deliver_token entity granting `deliver_operation` on `deliver_uri`."""
    data = {
        "granter": granter,
        "grantee": granter,
        "grants": [
            {
                "handlers": {"include": ["system/inbox"]},
                "resources": {"include": [deliver_uri]},
                "operations": {"include": [deliver_operation]},
            }
        ],
    }
    if parent is not None:
        data["parent"] = parent
    return Entity(type="system/capability/token", data=data)


def _make_ctx(
    *,
    content_store: ContentStore,
    emit_pathway: EmitPathway,
    author_hash: bytes | None,
    keypair: Keypair,
) -> HandlerContext:
    return HandlerContext(
        local_peer_id=keypair.peer_id,
        remote_peer_id="remote-peer-id",
        handler_grant={},
        # caller_capability: minimal grant covering the subscribe op so the
        # handler's caller_identity lookup succeeds. The SB1 check is
        # independent of caller_capability — it uses ctx.remote_identity_hash.
        caller_capability={"grantee": author_hash, "grants": []},
        emit_pathway=emit_pathway,
        remote_identity_hash=author_hash,
    )


def _build_pathway() -> tuple[ContentStore, EmitPathway, Keypair]:
    keypair = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(keypair.peer_id)
    emit_pathway = EmitPathway(content_store, entity_tree)
    return content_store, emit_pathway, keypair


def _subscribe_params(deliver_token_hash: bytes, *, deliver_uri: str) -> dict:
    return {
        "data": {
            "deliver_to": {"uri": deliver_uri, "operation": "receive"},
            "deliver_token": deliver_token_hash,
            "events": ["created"],
            "pattern": "data/*",
        },
    }


class TestSubscribeR1ChainRoot:
    """SB1 — R1 chain-root check on deliver_token in handle_subscribe."""

    @pytest.mark.asyncio
    async def test_self_rooted_token_accepted(self):
        """Author-rooted deliver_token: chain matches; subscribe succeeds."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"
        token = _make_token(granter=HASH_AUTHOR, deliver_uri=deliver_uri)
        token_hash = content_store.put(token)

        ctx = _make_ctx(
            content_store=content_store,
            emit_pathway=emit_pathway,
            author_hash=HASH_AUTHOR,
            keypair=keypair,
        )

        response = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN,
            "subscribe",
            _subscribe_params(token_hash, deliver_uri=deliver_uri),
            ctx,
        )

        assert response["status"] == 200, response

    @pytest.mark.asyncio
    async def test_foreign_rooted_token_rejected(self):
        """Token rooted at a different identity: 403 embedded_cap_unauthorized."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://other-peer/inbox"
        # Token granted by HASH_OTHER (not the subscribe author)
        token = _make_token(granter=HASH_OTHER, deliver_uri=deliver_uri)
        token_hash = content_store.put(token)

        ctx = _make_ctx(
            content_store=content_store,
            emit_pathway=emit_pathway,
            author_hash=HASH_AUTHOR,
            keypair=keypair,
        )

        response = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN,
            "subscribe",
            _subscribe_params(token_hash, deliver_uri=deliver_uri),
            ctx,
        )

        assert response["status"] == 403
        assert response["result"]["data"]["code"] == "embedded_cap_unauthorized"

    @pytest.mark.asyncio
    async def test_unreachable_chain_returns_404(self):
        """Token references a parent that's not in content store: 404 chain_unreachable."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"
        missing_parent_hash = bytes([ALG_ECFV1_SHA256]) + b"missin" + b"\x00" * 26
        # Granter HASH_OTHER + parent missing -> walker can't terminate.
        token = _make_token(
            granter=HASH_OTHER,
            parent=missing_parent_hash,
            deliver_uri=deliver_uri,
        )
        token_hash = content_store.put(token)

        ctx = _make_ctx(
            content_store=content_store,
            emit_pathway=emit_pathway,
            author_hash=HASH_AUTHOR,
            keypair=keypair,
        )

        response = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN,
            "subscribe",
            _subscribe_params(token_hash, deliver_uri=deliver_uri),
            ctx,
        )

        assert response["status"] == 404
        assert response["result"]["data"]["code"] == "chain_unreachable"

    @pytest.mark.asyncio
    async def test_unreachable_chain_supersedes_leaf_match(self):
        """Vector 4 analog for SB1: leaf granter matches subscriber, but
        parent unreachable. CHAIN_UNREACHABLE wins — without this, an
        attacker could claim leaf granter=self with fabricated parent and
        subscribe with arbitrary delivery scope."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"
        fabricated_parent = bytes([ALG_ECFV1_SHA256]) + b"fabric" + b"\x00" * 26
        # Leaf: granter=author (matches R1), parent unreachable.
        token = _make_token(
            granter=HASH_AUTHOR,
            parent=fabricated_parent,
            deliver_uri=deliver_uri,
        )
        token_hash = content_store.put(token)

        ctx = _make_ctx(
            content_store=content_store,
            emit_pathway=emit_pathway,
            author_hash=HASH_AUTHOR,
            keypair=keypair,
        )

        response = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN,
            "subscribe",
            _subscribe_params(token_hash, deliver_uri=deliver_uri),
            ctx,
        )
        assert response["status"] == 404
        assert response["result"]["data"]["code"] == "chain_unreachable"

    @pytest.mark.asyncio
    async def test_delegated_chain_terminates_at_author(self):
        """Two-link chain: leaf granter foreign, root granter is author. Accepted."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"

        # Root cap: granter=author, no parent.
        root = _make_token(granter=HASH_AUTHOR, deliver_uri=deliver_uri)
        root_hash = content_store.put(root)

        # Leaf cap: granter=other, parent=root.
        leaf = _make_token(
            granter=HASH_OTHER,
            parent=root_hash,
            deliver_uri=deliver_uri,
        )
        leaf_hash = content_store.put(leaf)

        ctx = _make_ctx(
            content_store=content_store,
            emit_pathway=emit_pathway,
            author_hash=HASH_AUTHOR,
            keypair=keypair,
        )

        response = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN,
            "subscribe",
            _subscribe_params(leaf_hash, deliver_uri=deliver_uri),
            ctx,
        )

        assert response["status"] == 200, response

    @pytest.mark.asyncio
    async def test_persistence_of_chain_after_success(self):
        """After SB1 passes, full authority chain remains in content store."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"

        root = _make_token(granter=HASH_AUTHOR, deliver_uri=deliver_uri)
        root_hash = content_store.put(root)
        leaf = _make_token(
            granter=HASH_OTHER,
            parent=root_hash,
            deliver_uri=deliver_uri,
        )
        leaf_hash = content_store.put(leaf)

        ctx = _make_ctx(
            content_store=content_store,
            emit_pathway=emit_pathway,
            author_hash=HASH_AUTHOR,
            keypair=keypair,
        )

        response = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN,
            "subscribe",
            _subscribe_params(leaf_hash, deliver_uri=deliver_uri),
            ctx,
        )
        assert response["status"] == 200

        # Both leaf and root should be resolvable from content store
        # (they were put there before the call, but persistence step is idempotent
        # and would have re-added them if missing).
        assert content_store.has(leaf_hash)
        assert content_store.has(root_hash)


class TestIncludePayloadReadAuth:
    """EXTENSION-SUBSCRIPTION §2.3 (v3.13/v3.14): include_payload requires
    tree:get read-authorization at subscribe time, and the option persists on
    the subscription entity for the engine to read at delivery (§4.2)."""

    def _ctx(self, emit_pathway, keypair, *, grant_get: bool) -> HandlerContext:
        grants = []
        if grant_get:
            grants = [{
                "handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]},
            }]
        return HandlerContext(
            local_peer_id=keypair.peer_id,
            remote_peer_id="remote-peer-id",
            handler_grant={},
            caller_capability={"grantee": HASH_AUTHOR, "grants": grants},
            emit_pathway=emit_pathway,
            remote_identity_hash=HASH_AUTHOR,
            handler_pattern=SUBSCRIPTION_HANDLER_PATTERN,
        )

    def _persisted_include_payload(self, emit_pathway, subscription_id: str) -> bool:
        path = f"system/subscription/{subscription_id}"
        h = emit_pathway.entity_tree.get(emit_pathway.entity_tree.normalize_uri(path))
        assert h is not None
        return bool(emit_pathway.content_store.get(h).data.get("include_payload", False))

    @pytest.mark.asyncio
    async def test_include_payload_without_get_rejected(self):
        """subscribe + include_payload but no tree:get → 403 payload_unauthorized."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"
        token_hash = content_store.put(_make_token(granter=HASH_AUTHOR, deliver_uri=deliver_uri))
        ctx = self._ctx(emit_pathway, keypair, grant_get=False)

        params = _subscribe_params(token_hash, deliver_uri=deliver_uri)
        params["data"]["include_payload"] = True
        resp = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN, "subscribe", params, ctx,
        )
        assert resp["status"] == 403, resp
        assert resp["result"]["data"]["code"] == "payload_unauthorized"

    @pytest.mark.asyncio
    async def test_include_payload_with_get_persists(self):
        """subscribe + include_payload with tree:get → 200, persisted on entity."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"
        token_hash = content_store.put(_make_token(granter=HASH_AUTHOR, deliver_uri=deliver_uri))
        ctx = self._ctx(emit_pathway, keypair, grant_get=True)

        params = _subscribe_params(token_hash, deliver_uri=deliver_uri)
        params["data"]["include_payload"] = True
        resp = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN, "subscribe", params, ctx,
        )
        assert resp["status"] == 200, resp
        sid = resp["result"]["data"]["subscription_id"]
        assert self._persisted_include_payload(emit_pathway, sid) is True

    @pytest.mark.asyncio
    async def test_default_no_payload_needs_no_read_auth(self):
        """Without include_payload, subscribe succeeds with no get grant; lean."""
        content_store, emit_pathway, keypair = _build_pathway()
        deliver_uri = "entity://author-peer/inbox"
        token_hash = content_store.put(_make_token(granter=HASH_AUTHOR, deliver_uri=deliver_uri))
        ctx = self._ctx(emit_pathway, keypair, grant_get=False)

        resp = await subscription_handler(
            SUBSCRIPTION_HANDLER_PATTERN, "subscribe",
            _subscribe_params(token_hash, deliver_uri=deliver_uri), ctx,
        )
        assert resp["status"] == 200, resp
        sid = resp["result"]["data"]["subscription_id"]
        assert self._persisted_include_payload(emit_pathway, sid) is False
