"""EXTENSION-COMPUTE v3.23 §4.1 — a `compute/error` **literal** is an error.

Two distinct things meet in this file, and they were tangled in the cross-impl
report that surfaced them (`entity-core-go` 2026-08-15-d):

1. **The ruling.** `is_error(v)` is **kind-based, not outcome-based** `[MUST]`:
   true iff `kind_of(v)` is `compute/error`. A `compute/error` that evaluated
   *successfully* — a stored literal returned unchanged by SA-1 — is an error
   for every purpose in §4.1, so it **short-circuits** at every consumer
   (§7.2's "Error short-circuit normative" names construct and apply among
   them). Arch ruled (B) propagate, against the alternative reading that it
   embeds-and-materializes into the consuming expression. Python's evaluator
   was already on the ruled side; these lock it.

2. **The crash, which was independent of the ruling.** Python has *two*
   representations of a `compute/error`: `make_error` mints a **dict**, while a
   stored error literal resolves to an **`Entity` object** and is returned
   unchanged by the value-type rule. Every error-propagation test in
   `tests/test_compute.py` reaches the dict form (it triggers errors with
   unresolvable hashes), so the Entity form had no coverage at a boundary — and
   two of the three compute→non-compute crossings assumed dict. The `Entity`
   fell through to `_as_entity`, was wrapped as `primitive/any` with an Entity
   as its `data`, and killed the inbound handler task at the CBOR encoder:
   `CBOREncodeTypeError: cannot serialize type Entity`. The peer sent nothing
   back, so the caller saw an i/o timeout rather than a diagnostic.

   That is why the vector could not lock three-way: Go and Rust disagreed about
   the ruling, and Python answered neither because it never got as far as an
   answer.
"""

from __future__ import annotations

import asyncio

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.compute import (
    Budget,
    EvalContext,
    Scope,
    evaluate,
    is_error,
)

PEER_ID = "2KTestComputeErrorLiteralPeerIdaaaaaaaaaaaaaa"

WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
    # §4.2 tier 2: without this the evaluator resolves only out of the EXECUTE
    # envelope's `included` map, and a hash-referenced literal answers
    # not_found before it can be an error of the interesting kind.
    "allowances": {"content_store_access": True},
}

#: The stored error literal every case below is built around. It is a *value*:
#: it resolves cleanly, evaluates successfully, and is still an error.
ERROR_LITERAL = Entity(
    type="compute/error",
    data={"code": "corpus_materialized_error", "message": "vector error value"},
)


def _ctx(content_store: ContentStore | None = None) -> EvalContext:
    return EvalContext(
        content_store=content_store or ContentStore(),
        entity_tree=EntityTree(PEER_ID),
        local_peer_id=PEER_ID,
        capability=WILDCARD_CAP,
        included={},
        has_content_store_access=True,
    )


def _lit(value) -> Entity:
    return Entity(type="compute/literal", data={"value": value})


def _construct(entity_type: str, fields: dict[str, bytes]) -> Entity:
    return Entity(
        type="compute/construct",
        data={"entity_type": entity_type, "fields": fields},
    )


class TestTheRulingKindBasedIsError:
    """§4.1: kind-based, not outcome-based. The literal evaluated fine; it is
    still an error, and every consumer short-circuits to it."""

    def test_a_stored_error_literal_evaluates_to_itself_and_is_an_error(self):
        ctx = _ctx()
        target = ctx.content_store.get(ctx.content_store.put(ERROR_LITERAL))
        value = evaluate(target, Scope(), Budget(), ctx)
        assert is_error(value), (
            "SA-1 returns the literal unchanged and §4.1 calls it an error — "
            "this is the kind-based predicate, and an outcome-based one "
            "(did evaluation fail?) answers False here"
        )

    def test_construct_propagates_it_rather_than_embedding_it(self):
        """Arch ruling (B). Under the losing reading this returns an
        `app/user` entity whose `name` field holds a materialized error; under
        the ruled one the construct *is* the error."""
        ctx = _ctx()
        error_hash = ctx.content_store.put(ERROR_LITERAL)
        expr = _construct("app/user", {"name": error_hash})

        result = evaluate(expr, Scope(), Budget(), ctx)

        assert is_error(result)
        data = result.data if isinstance(result, Entity) else result["data"]
        assert data["code"] == "corpus_materialized_error", (
            "the propagated value must be the original error, not a fresh one"
        )

    def test_a_good_field_beside_it_does_not_survive(self):
        """Short-circuit, not collect-and-continue: the sibling field is
        irrelevant once an error is reached."""
        ctx = _ctx()
        expr = _construct("app/user", {
            "age": ctx.content_store.put(_lit(30)),
            "name": ctx.content_store.put(ERROR_LITERAL),
        })
        result = evaluate(expr, Scope(), Budget(), ctx)
        assert is_error(result)
        assert (result.type if isinstance(result, Entity) else result["type"]) == (
            "compute/error"
        )

    def test_nesting_does_not_launder_it(self):
        """An error one construct deep still reaches the top as an error —
        propagation composes, which is the property "embed" would break."""
        ctx = _ctx()
        inner = _construct("app/inner", {"bad": ctx.content_store.put(ERROR_LITERAL)})
        outer = _construct("app/outer", {"inner": ctx.content_store.put(inner)})
        result = evaluate(outer, Scope(), Budget(), ctx)
        assert is_error(result)


class TestTheCrashTheEntityFormReachesTheWire:
    """The defect that was independent of the ruling: an `Entity`-form
    compute/error reaching a compute→non-compute crossing.

    These assert the **shape** the crossing returns, because the shape is what
    the CBOR encoder chokes on. `to_dict()` form is required — an `Entity`
    object is not a dict, so `_as_entity` wraps it as `primitive/any` with an
    Entity payload and the encode dies with the task.
    """

    def _eval_over_handler(self, expr_entity: Entity):
        """Run `_handle_eval` against a peer holding the expression."""
        from entity_core.capability.grant import create_full_access_grant
        from entity_core.handlers.context import HandlerContext
        from entity_core.storage.emit import EmitPathway
        from entity_handlers.compute import _ComputeState, _handle_eval

        content_store = ContentStore()
        entity_tree = EntityTree(PEER_ID)
        emit_pathway = EmitPathway(content_store, entity_tree)

        expr_uri = entity_tree.normalize_uri("app/expr")
        entity_tree.set(expr_uri, content_store.put(expr_entity))
        # Seed the error literal into the store the handler evaluates in.
        content_store.put(ERROR_LITERAL)

        permissive = create_full_access_grant()

        async def _noop_dispatch(*a, **k):
            raise AssertionError("no outbound dispatch expected")

        handler_ctx = HandlerContext(
            local_peer_id=PEER_ID,
            remote_peer_id="remote",
            handler_grant=permissive,
            # The eval path reads capability constraints as a plain mapping
            # (`capability.get("constraints", ...)`), not as a Grant list.
            caller_capability=WILDCARD_CAP,
            emit_pathway=emit_pathway,
            _execute_dispatcher=_noop_dispatch,
            resource_targets=[expr_uri],
        )

        state = _ComputeState()
        state.emit_pathway = emit_pathway
        state.local_peer_id = PEER_ID
        return asyncio.run(
            _handle_eval({"data": {}}, handler_ctx, state),
        ), content_store

    def test_eval_returns_the_error_in_dict_form_not_as_an_entity_object(self):
        """The regression. Pre-fix this returned `{"result": <Entity ...>}` and
        the encoder killed the inbound handler task — the peer answered
        nothing, so the far side saw an i/o timeout with no diagnostic."""
        content_store = ContentStore()
        error_hash = content_store.put(ERROR_LITERAL)
        expr = _construct("app/user", {"name": error_hash})

        response, store = self._eval_over_handler(expr)

        assert response["status"] == 200, (
            "F10: an evaluated compute/error is a *value*; 200 with the error "
            "body, not a 4xx (those are dispatch failures)"
        )
        result = response["result"]
        assert not isinstance(result, Entity), (
            "an Entity object reaching the wire shim is the crash: _as_entity "
            "wraps a non-dict as primitive/any and cbor2 cannot encode it"
        )
        assert isinstance(result, dict)
        assert result["type"] == "compute/error"
        assert result["data"]["code"] == "corpus_materialized_error"

    def test_the_returned_shape_survives_the_wire_encoder(self):
        """The end of the failure chain, asserted directly: whatever `eval`
        returns must ECF-encode. This is the assertion that would have caught
        it without a live peer."""
        from entity_core.protocol.messages import _as_entity
        from entity_core.utils.ecf import ecf_encode

        content_store = ContentStore()
        expr = _construct("app/user", {"name": content_store.put(ERROR_LITERAL)})
        response, _ = self._eval_over_handler(expr)

        encoded = ecf_encode(_as_entity(response["result"]))
        assert b"corpus_materialized_error" in encoded, (
            "the error's code must survive to the wire — a primitive/any "
            "wrapper around an Entity object does not encode at all"
        )


class TestBothRepresentationsAgree:
    """Python mints errors as dicts (`make_error`) and resolves stored ones as
    `Entity`s. The two must be indistinguishable to every consumer — the split
    is exactly what left the Entity path uncovered."""

    @pytest.mark.parametrize("stored", [True, False])
    def test_construct_short_circuits_either_representation(self, stored: bool):
        from entity_handlers.compute import make_error

        ctx = _ctx()
        if stored:
            bad = ctx.content_store.put(ERROR_LITERAL)
        else:
            # An unresolvable hash makes the evaluator mint a dict error —
            # the form every pre-existing propagation test exercises.
            bad = b"\x00" * 33
        result = evaluate(
            _construct("app/user", {"name": bad}), Scope(), Budget(), ctx,
        )
        assert is_error(result)
        assert is_error(make_error("x", "y"))  # both forms answer the predicate
