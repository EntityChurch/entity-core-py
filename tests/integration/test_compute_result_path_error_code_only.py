"""§7.2 `result_path` — a materialized `compute/error` is code-only `[MUST]`.

§2.4 names exactly two surfaces where an error materializes: the SA-9 `store`
builtin and this one, the reactive `result_path` write (including the
frozen-subgraph write, which goes to the same path). Its canonical content is
`{code}` alone — `message`, `at`, and `expression` are diagnostics that MUST NOT
enter the bytes V7 content-addresses.

**This half was not routed to us; it was found while landing the store ruling.**
Python wrote the *whole* in-flight error to `result_path`, message included, so
two conformant peers freezing on the same cause, or failing the same expression
in different words, wrote different entity hashes. That breaks AE-1
materialized-boundary equivalence, content dedup, cross-peer sync, and every
reactive consumer keyed on the result hash. `entity-core-go` fixed the same
crossing in its own tree (`ext/compute/engine.go`, the `evalErr` /
`freezeSubgraph` writes, both through `ToMaterializedEntity`) — the divergence
here was real and one-sided.

The gate is the written entity's **hash**, not its fields: an impl that keeps
`message` still answers `code` correctly at every other surface and diverges
only where the bytes are addressed.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.extensions import ExtensionContext
from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.compute import (
    ERR_DIVISION_BY_ZERO,
    ERR_INSTALLATION_GRANT_INVALID,
    ComputeExtension,
)

WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
    "allowances": {"content_store_access": True},
}

#: Loud prose, really in the stored bytes — so "only `code` survives" is a claim
#: this file can falsify rather than merely assert.
VALUE_FORM_ERROR = Entity(type="compute/error", data={
    "code": "stored_before_write",
    "message": "LOUD PROSE that MUST NOT reach the result_path bytes — §2.4",
    "at": "corpus/somewhere",
})


@pytest.fixture
def rig():
    keypair = Keypair.generate()
    content_store = ContentStore()
    entity_tree = EntityTree(keypair.peer_id)
    emit_pathway = EmitPathway(content_store, entity_tree)

    ext = ComputeExtension()
    ext.initialize(ExtensionContext(keypair=keypair, emit_pathway=emit_pathway))
    return ext, content_store, entity_tree, emit_pathway, keypair


def _handler_ctx(emit_pathway, peer_id, resource_targets=("app/expr",)):
    from unittest.mock import MagicMock

    ctx = MagicMock()
    ctx.emit_pathway = emit_pathway
    ctx.local_peer_id = peer_id
    ctx.caller_capability = WILDCARD_CAP
    ctx.caller_capability_granter_peer_id = None
    ctx.resource_targets = list(resource_targets)
    ctx.bounds = None
    ctx.remote_peer_id = peer_id
    return ctx


async def _install(ext, emit_pathway, peer_id):
    result = await ext.handler()(
        "system/compute/install", "install", {"data": {}},
        _handler_ctx(emit_pathway, peer_id),
    )
    assert result["status"] == 200, result
    return result["result"]["data"]


def _read(content_store, entity_tree, path: str) -> Entity | None:
    h = entity_tree.get(entity_tree.normalize_uri(path))
    return None if h is None else content_store.get(h)


def _prose_error(message: str) -> Entity:
    return Entity(type="compute/error", data={
        "code": "stored_before_write", "message": message, "at": "corpus/somewhere",
    })


@pytest.mark.asyncio
async def test_a_minted_error_materializes_code_only(rig):
    """`div(<dep>, 0)` — integer division by zero, the minted (dict)
    representation, carrying this impl's own "Division by zero" prose. The
    dependency is the *numerator* so that changing it drives a re-evaluation
    without changing the outcome."""
    ext, content_store, entity_tree, ep, keypair = rig

    ep.emit("app/data", Entity(type="compute/literal", data={"value": 1}))
    ep.emit("app/expr", Entity(type="compute/arithmetic", data={
        "op": "div",
        "left": content_store.put(
            Entity(type="compute/lookup/tree", data={"path": "app/data"}),
        ),
        "right": content_store.put(Entity(type="compute/literal", data={"value": 0})),
    }))

    data = await _install(ext, ep, keypair.peer_id)
    ep.emit("app/data", Entity(type="compute/literal", data={"value": 2}))

    written = _read(content_store, entity_tree, data["result_path"])
    assert written is not None, "the error must be written to result_path"
    assert written.type == "compute/error"
    assert set(written.data) == {"code"}, (
        f"§2.4: content is `code` alone, got {sorted(written.data)}"
    )
    assert written.data["code"] == ERR_DIVISION_BY_ZERO
    assert written.compute_hash() == Entity(
        type="compute/error", data={"code": ERR_DIVISION_BY_ZERO},
    ).compute_hash()


@pytest.mark.asyncio
async def test_a_value_form_error_materializes_code_only(rig):
    """The other representation: an SA-1 `compute/error` literal reached through
    a `lookup/tree`, which arrives at the crossing as an `Entity` rather than a
    minted dict. `is_error` is kind-based, so it must materialize identically —
    this is the form that has slipped through every other error test here."""
    ext, content_store, entity_tree, ep, keypair = rig

    ep.emit("app/data", VALUE_FORM_ERROR)
    ep.emit("app/expr", Entity(
        type="compute/lookup/tree", data={"path": "app/data"},
    ))

    data = await _install(ext, ep, keypair.peer_id)
    ep.emit("app/data", _prose_error("a second wording, same failure"))

    written = _read(content_store, entity_tree, data["result_path"])
    assert written is not None
    assert written.type == "compute/error"
    assert set(written.data) == {"code"}
    assert "LOUD PROSE" not in str(written.data)
    assert written.compute_hash() == Entity(
        type="compute/error", data={"code": "stored_before_write"},
    ).compute_hash()


@pytest.mark.asyncio
async def test_changing_only_the_prose_does_not_move_the_result_hash(rig):
    """The property §2.4 protects, observed where it bites: the *same* failure
    described in different words is one materialized entity.

    Read through §7.2's convergence check, which is what makes this more than a
    field assertion — a `result_path` carrying `message` re-writes on every
    reword, waking every reactive consumer keyed on the result hash for a change
    that is not a change.
    """
    ext, content_store, entity_tree, ep, keypair = rig

    ep.emit("app/data", _prose_error("one peer's words"))
    ep.emit("app/expr", Entity(
        type="compute/lookup/tree", data={"path": "app/data"},
    ))
    data = await _install(ext, ep, keypair.peer_id)
    result_path = entity_tree.normalize_uri(data["result_path"])

    ep.emit("app/data", _prose_error("another peer's words"))
    first = entity_tree.get(result_path)
    assert first is not None

    ep.emit("app/data", _prose_error("a third peer's, longer and quite different"))
    assert entity_tree.get(result_path) == first, (
        "message is unpinned prose (§9.1 pins codes, not strings); in the "
        "content hash it forks dedup and sync per-impl and defeats convergence"
    )


@pytest.mark.asyncio
async def test_a_frozen_subgraph_writes_code_only(rig):
    """The freeze write lands on the same `result_path` and is the same
    crossing. Its `at` was the expression URI — peer-local by construction, so
    it could never have been a pure function of the IR + inputs."""
    ext, content_store, entity_tree, ep, keypair = rig

    ep.emit("app/data", Entity(type="compute/literal", data={"value": 1}))
    ep.emit("app/expr", Entity(
        type="compute/lookup/tree", data={"path": "app/data"},
    ))
    data = await _install(ext, ep, keypair.peer_id)

    # Strip the installation grant — the next re-evaluation freezes the
    # subgraph and writes ERR_INSTALLATION_GRANT_INVALID to result_path.
    sg_path = entity_tree.normalize_uri(data["subgraph_path"])
    subgraph = content_store.get(entity_tree.get(sg_path))
    stripped = {k: v for k, v in subgraph.data.items() if k != "installation_grant"}
    ep.emit(sg_path, Entity(type="system/compute/subgraph", data=stripped))

    ep.emit("app/data", Entity(type="compute/literal", data={"value": 2}))

    written = _read(content_store, entity_tree, data["result_path"])
    assert written is not None, "the freeze must write its error"
    assert written.data == {"code": ERR_INSTALLATION_GRANT_INVALID}
    frozen = content_store.get(entity_tree.get(sg_path))
    assert frozen.data["status"] == "frozen"
