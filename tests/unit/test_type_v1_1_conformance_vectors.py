"""Conformance-vector check for EXTENSION-TYPE v1.1 §5.5.

Loads ``tests/conformance/type-v1.1/one_of-ecf-vectors.cbor`` and
runs every row through the standard constraint handler. The
constraint handler MUST return the expected ``valid`` on every row;
any divergence indicates either an encoder regression or a
constraint-handler regression — both block the cross-impl
convergence run with Go and Rust.

This is the Python-side enforcement of the cross-impl interop
gate. If this test fails, do not ship.
"""

from __future__ import annotations

import asyncio
import pathlib
from dataclasses import dataclass
from typing import Any

import cbor2
import pytest

from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.type_constraint import type_constraint_handler


VECTORS_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "conformance" / "type-v1.1" / "one_of-ecf-vectors.cbor"
)


@dataclass
class _Ctx:
    handler: HandlerContext


def _make_ctx() -> HandlerContext:
    kp = Keypair.generate()
    pathway = EmitPathway(ContentStore(), EntityTree(kp.peer_id))
    return HandlerContext(
        local_peer_id=kp.peer_id,
        remote_peer_id=kp.peer_id,
        handler_grant={},
        caller_capability={},
        emit_pathway=pathway,
        handler_pattern="system/type/constraint/*",
        keypair=kp,
    )


def _load_vectors() -> list[dict[str, Any]]:
    raw = VECTORS_PATH.read_bytes()
    payload = cbor2.loads(raw)
    assert isinstance(payload, list), "vector file root must be an array"
    assert payload, "vector file is empty"
    return payload


def test_vector_file_exists():
    assert VECTORS_PATH.exists(), (
        f"missing conformance-vector file at {VECTORS_PATH} — "
        f"regenerate via `uv run python tests/conformance/type-v1.1/generate_vectors.py`"
    )


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["id"])
def test_handler_agrees_with_vector(vector: dict[str, Any]):
    ctx = _make_ctx()
    params = {
        "data": {
            "value": vector["value"],
            "constraint_type": "system/type/constraint/one-of",
            "constraint_data": {"values": vector["candidates"]},
        }
    }
    response = asyncio.run(
        type_constraint_handler(
            "system/type/constraint/one-of", "validate", params, ctx,
        )
    )
    assert response["status"] == 200
    actual = response["result"]["data"]["valid"]
    expected = vector["valid"]
    assert actual is expected, (
        f"vector {vector['id']} ({vector['description']}): "
        f"expected valid={expected}, got {actual}"
    )


def test_embedded_constraints_are_entity_envelopes() -> None:
    """V7.72 cohort ECF-edge fix: inline field-spec constraints MUST embed as
    full entity envelopes ({type, data, content_hash}), NOT bare {type, data}.

    A field-spec ``constraints`` entry fills a ``core/entity``-typed slot, so
    per ENTITY-NATIVE-TYPE-SYSTEM §1.2 it takes the entity-envelope wire form
    carrying its own content_hash — matching Go's ``[]entity.Entity``. A bare
    2-key map under-encodes and diverges by exactly the content_hash key,
    which produced four "ECF byte mismatch, no structural difference" WARNs in
    the V7.72 core-profile cohort run against the Python peer. Pin the 3-key
    form (and that the content_hash is the real hash of {type, data}).
    """
    from entity_core.protocol.entity import Entity
    from entity_core.types.definitions import (
        type_system_type_compatibility_report,
        type_system_type_compatible_request,
        type_system_type_converge_request,
        type_system_type_reconcile_request,
    )

    builders = [
        type_system_type_compatible_request,
        type_system_type_compatibility_report,
        type_system_type_converge_request,
        type_system_type_reconcile_request,
    ]
    seen = 0
    for build in builders:
        ent = build()
        for fname, fspec in ent.data["fields"].items():
            for c in fspec.get("constraints", []):
                seen += 1
                assert set(c.keys()) == {"type", "data", "content_hash"}, (
                    f"{build.__name__}.{fname} constraint must be a 3-key "
                    f"entity envelope, got keys {sorted(c.keys())}"
                )
                # content_hash MUST be the genuine hash of {type, data}.
                expected = Entity(type=c["type"], data=c["data"]).compute_hash()
                assert c["content_hash"] == expected
    assert seen == 5, f"expected 5 inline constraints across the 4 defs, saw {seen}"
