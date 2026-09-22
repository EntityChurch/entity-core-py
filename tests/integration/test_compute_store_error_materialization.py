"""SA-9 `store(path, <a compute/error>)` **writes**, code-only `[MUST]`.

Ruled by arch on 2026-08-16 (`662e409`, routed as `ROUTING-2026-08-16-f`) after
`entity-core-go` filed it as a spec self-contradiction rather than fixing the
peers to match a 2-of-3 majority. `entity-core-go` was correct; this repo and
`entity-core-rust` changed. Two rules meet here and this file pins the boundary
between them:

1. **§2131 error short-circuit** — every expression that *consumes* a value
   MUST short-circuit on a `compute/error` "rather than attempting to read its
   fields". `store` is dispatched as a handler-mode `compute/apply`, so the rule
   appears to reach its `value`. **It does not.** An apply short-circuits on the
   operands it consumes — `resource`, `capability`, closure args bound to
   params. A builtin's **write payload** is not consumed: its fields are never
   read, they are *materialized*, so the hazard the rule guards against does not
   arise at a write site.

2. **§2.4 code-only materialization** — where an error IS written (the §7.2
   `result_path` and SA-9 `store`, the only two such surfaces), its canonical
   content is exactly `{code}`. `message`/`at`/`expression` are impl-private
   diagnostics; if any entered the bytes, two conformant peers writing the same
   error to the same path would produce different entity hashes — breaking AE-1
   materialized-boundary equivalence, content dedup, cross-peer sync, and any
   reactive consumer keyed on the result hash.

**Both representations, every case.** Python carries a `compute/error` two ways
— `make_error` mints a **dict**, an SA-1 literal resolves to an **`Entity`** —
and `is_error` is kind-based, so both must behave identically here. That split
is the one this repo already got bitten by at the wire crossing; the
parametrization is deliberate, not decoration.

**Read the entity that was WRITTEN, never the eval result.** An error result
reduces to error-kind and F10 re-wraps it with a fresh message on the way out,
so the eval result cannot observe §2.4 at all — which is exactly how a
three-way run reported LOCKED while go stored code-only and py stored the
message. Every assertion below reads back through the tree.
"""

from __future__ import annotations

import pytest

from entity_core.protocol.entity import Entity
from entity_core.storage.content_store import ContentStore
from entity_core.storage.emit import EmitPathway
from entity_core.storage.entity_tree import EntityTree
from entity_handlers.compute import (
    ERR_DIVISION_BY_ZERO,
    ERR_NOT_FOUND,
    ERR_TYPE_MISMATCH,
    Budget,
    EvalContext,
    Scope,
    evaluate,
    is_error,
)

PEER_ID = "2KTestStoreErrorMaterializationPeerIdaaaaaaa"

WILDCARD_CAP = {
    "grants": [{
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": ["*"]},
    }],
    "allowances": {"content_store_access": True},
}

#: The value-form error: it resolves cleanly, evaluates successfully under SA-1,
#: and is still an error. The prose is loud and really in the stored bytes — an
#: artifact carrying only a code could not tell a stripping impl from a leaking
#: one, which is the property this file has to be able to falsify.
VALUE_FORM_ERROR = Entity(
    type="compute/error",
    data={
        "code": "stored_before_write",
        "message": (
            "LOUD PROSE that MUST NOT survive the SA-9 store write — §2.4 code-only"
        ),
        "at": "corpus/somewhere",
    },
)

#: What §2.4 says the written entity is, for each representation.
EXPECTED_MINTED = Entity(type="compute/error", data={"code": ERR_DIVISION_BY_ZERO})
EXPECTED_VALUE_FORM = Entity(
    type="compute/error", data={"code": "stored_before_write"},
)


def _lit(value) -> Entity:
    return Entity(type="compute/literal", data={"value": value})


def _apply_store(path_hash: bytes, value_hash: bytes) -> Entity:
    return Entity(type="compute/apply", data={
        "path": "system/compute/builtins/store",
        "operation": "eval",
        "args": {"path": path_hash, "value": value_hash},
    })


class _Fixture:
    """A store-capable eval context, in either of the two wirings the builtin
    has: through a `system/tree:put` dispatch (what a peer runs) and through the
    direct-write fallback (a bare eval context with no dispatcher).

    Both are exercised for every case. A rule that holds on one path and not the
    other is the shape of bug this ruling is about.
    """

    def __init__(self, *, dispatched: bool) -> None:
        self.content_store = ContentStore()
        self.entity_tree = EntityTree(PEER_ID)
        self.emit_pathway = EmitPathway(self.content_store, self.entity_tree)
        #: What `system/tree:put` was handed, when dispatching.
        self.put_entity: dict | None = None

        self.ctx = EvalContext(
            content_store=self.content_store,
            entity_tree=self.entity_tree,
            local_peer_id=PEER_ID,
            capability=WILDCARD_CAP,
            emit_pathway=self.emit_pathway,
            included={},
            has_content_store_access=True,
            _execute_fn=self._dispatch if dispatched else None,
        )

    def _dispatch(self, path, operation, params, ctx, cap, targets, exclude):
        """Stand-in for `system/tree:put` — records the entity it was handed and
        performs the write, returning the handler's real put-result shape."""
        assert (path, operation) == ("system/tree", "put")
        self.put_entity = params["entity"]
        entity = Entity(type=self.put_entity["type"], data=self.put_entity["data"])
        emit_result = self.emit_pathway.emit(targets[0], entity)
        return {
            "type": "system/tree/put-result",
            "data": {"path": targets[0], "hash": emit_result.hash},
        }

    def put(self, entity: Entity) -> bytes:
        return self.content_store.put(entity)

    def minted_error_expr(self) -> bytes:
        """An expression that *evaluates* to a minted (dict) error — 1/0, the
        same shape the cross-impl corpus uses for the minted vector."""
        return self.put(Entity(type="compute/arithmetic", data={
            "op": "div",
            "left": self.put(_lit(1)),
            "right": self.put(_lit(0)),
        }))

    def value_form_error_expr(self) -> bytes:
        """A hash referencing the stored error literal. SA-1 returns it
        unchanged, so it arrives at the write site as an `Entity`."""
        return self.put(VALUE_FORM_ERROR)

    def eval(self, expr: Entity):
        return evaluate(expr, Scope(), Budget(), self.ctx)

    def read_back(self, path: str) -> Entity | None:
        h = self.entity_tree.get(self.entity_tree.normalize_uri(path))
        return None if h is None else self.content_store.get(h)


DISPATCH_MODES = pytest.mark.parametrize(
    "dispatched", [True, False], ids=["dispatched", "fallback"],
)
REPRESENTATIONS = pytest.mark.parametrize(
    "representation, expected",
    [("minted", EXPECTED_MINTED), ("value_form", EXPECTED_VALUE_FORM)],
)


def _error_value(fx: _Fixture, representation: str) -> bytes:
    return (
        fx.minted_error_expr() if representation == "minted"
        else fx.value_form_error_expr()
    )


class TestTheRulingTheWriteHappens:
    """The half `entity-core-py` had wrong: the write payload is outside the
    short-circuit, so the store runs instead of propagating."""

    @DISPATCH_MODES
    @REPRESENTATIONS
    def test_an_error_value_is_written_to_the_path(
        self, dispatched: bool, representation: str, expected: Entity,
    ):
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(
            fx.put(_lit("corpus/error/store")), _error_value(fx, representation),
        )

        fx.eval(expr)

        written = fx.read_back("corpus/error/store")
        assert written is not None, (
            "under the propagate reading the apply short-circuits and NOTHING is "
            "written — which is what this repo did before the ruling"
        )
        assert written.type == "compute/error"
        assert written.data == expected.data

    @DISPATCH_MODES
    @REPRESENTATIONS
    def test_the_store_succeeds_rather_than_evaluating_to_the_error(
        self, dispatched: bool, representation: str, expected: Entity,
    ):
        """"The store succeeds" is the other half of the ruling: `store`
        returns its write's result, not the error it wrote. Both wirings return
        the one `system/tree/put-result` shape — a per-path return would put the
        divergence straight back into the rule this file is about."""
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(
            fx.put(_lit("corpus/error/store")), _error_value(fx, representation),
        )

        result = fx.eval(expr)

        assert not is_error(result), (
            "a store that writes an error is not itself an error — a nested "
            "consumer of this apply must see a successful write"
        )
        assert result["type"] == "system/tree/put-result"


class TestSection24CodeOnly:
    """What is written, byte for byte. `message`/`at` MUST NOT be in it."""

    @DISPATCH_MODES
    @REPRESENTATIONS
    def test_the_written_entity_is_content_hashed_over_code_alone(
        self, dispatched: bool, representation: str, expected: Entity,
    ):
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(
            fx.put(_lit("corpus/error/store")), _error_value(fx, representation),
        )

        fx.eval(expr)

        written = fx.read_back("corpus/error/store")
        assert written.compute_hash() == expected.compute_hash(), (
            "the gate is the hash, not the fields: a peer that keeps `message` "
            "still answers `code` correctly and diverges only here"
        )
        assert set(written.data) == {"code"}

    @DISPATCH_MODES
    def test_the_value_forms_loud_prose_does_not_survive(self, dispatched: bool):
        """Falsifiable directly: the message is really in the stored literal's
        bytes, so a non-stripping impl carries it into the write."""
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(
            fx.put(_lit("corpus/error/store")), fx.value_form_error_expr(),
        )

        fx.eval(expr)

        written = fx.read_back("corpus/error/store")
        assert "message" not in written.data
        assert "at" not in written.data

    @DISPATCH_MODES
    def test_same_code_different_prose_writes_the_same_hash(self, dispatched: bool):
        """The reason §2.4 exists, stated as the property it protects: two peers
        blaming the same failure in different words converge on one entity."""
        hashes = set()
        for message in ("a peer that says one thing", "and a peer that says another"):
            fx = _Fixture(dispatched=dispatched)
            literal = Entity(type="compute/error", data={
                "code": "same_code", "message": message, "at": "wherever",
            })
            expr = _apply_store(fx.put(_lit("corpus/error/store")), fx.put(literal))
            fx.eval(expr)
            hashes.add(fx.read_back("corpus/error/store").compute_hash())

        assert len(hashes) == 1, (
            "message is unpinned prose (§9.1 pins codes, not strings) — if it "
            "reaches the content hash, dedup and sync fork per-impl"
        )


class TestTheBoundaryHoldsTheOtherWay:
    """The exemption is exactly one arg of exactly one builtin. Everything the
    short-circuit rule *does* cover still short-circuits — this is the half a
    too-broad fix would quietly break, and no existing test would have noticed.
    """

    @DISPATCH_MODES
    def test_an_error_path_still_short_circuits(self, dispatched: bool):
        """`path` is a *consumed* operand — it is read as a string — so an error
        there propagates and nothing is written anywhere."""
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(fx.minted_error_expr(), fx.put(_lit("some value")))

        result = fx.eval(expr)

        assert is_error(result)
        assert result["data"]["code"] == ERR_DIVISION_BY_ZERO, (
            "the propagated error must be the original, not a type_mismatch "
            "minted by store after reading a non-string path"
        )
        assert fx.put_entity is None, "no write may be attempted"

    @DISPATCH_MODES
    def test_an_unresolvable_value_hash_still_short_circuits(self, dispatched: bool):
        """A resolution failure is not an error *value* the caller asked to
        store — it never became one. Go propagates it at `resolveOrError`,
        before `Evaluate`; the exemption must sit on the same side of that line.
        """
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(fx.put(_lit("corpus/error/store")), b"\x00" * 33)

        result = fx.eval(expr)

        assert is_error(result)
        assert result["data"]["code"] == ERR_NOT_FOUND
        assert fx.read_back("corpus/error/store") is None

    @DISPATCH_MODES
    def test_a_non_store_builtins_error_arg_still_short_circuits(
        self, dispatched: bool,
    ):
        """The exemption is keyed on `store`, not on "the arg is called value".
        `map`'s collection is consumed, so it short-circuits as before."""
        fx = _Fixture(dispatched=dispatched)
        expr = Entity(type="compute/apply", data={
            "path": "system/compute/builtins/map",
            "operation": "eval",
            "args": {
                "collection": fx.minted_error_expr(),
                "fn": fx.put(Entity(type="compute/lambda", data={
                    "params": ["x"], "body": fx.put(_lit(1)),
                })),
            },
        })

        result = fx.eval(expr)

        assert is_error(result)
        assert result["data"]["code"] == ERR_DIVISION_BY_ZERO, (
            "a type_mismatch here would mean the error reached map's body as a "
            "collection — the exact field-reading the rule forbids"
        )

    @DISPATCH_MODES
    def test_a_non_error_store_is_unchanged(self, dispatched: bool):
        """The ordinary path, so the exemption cannot be read as loosening it."""
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(fx.put(_lit("corpus/ok")), fx.put(_lit(42)))

        result = fx.eval(expr)

        assert not is_error(result)
        written = fx.read_back("corpus/ok")
        assert written.type == "primitive/any"
        assert written.data == 42


class TestStoreStillRejectsWhatItAlwaysDid:
    """Guards that the exemption did not swallow store's own failures."""

    @DISPATCH_MODES
    def test_a_non_string_path_is_a_type_mismatch(self, dispatched: bool):
        fx = _Fixture(dispatched=dispatched)
        expr = _apply_store(fx.put(_lit(42)), fx.put(_lit("v")))

        result = fx.eval(expr)

        assert is_error(result)
        assert result["data"]["code"] == ERR_TYPE_MISMATCH


class TestTheDispatchedStoreReachesTheREALTreeHandler:
    """`store`'s dispatched arm, driven through `system/tree:put` itself.

    **Why this class exists, and it is a coverage finding rather than a rule.**
    Landing 0.8.2.11's `put` admission, the mutation that reverts *this
    builtin's* construction step — sending `{type, data}` again where the
    ruling requires all three `core/entity` fields — **reddened nothing across
    4289 tests**. Traced (A1): `_Fixture._dispatch` above is a stand-in that
    reads `params["entity"]["type"]` and `["data"]` and validates nothing, so
    the `dispatched` half of every row in this file is evidence about the
    builtin's *arguments* and about nothing on the far side of the seam.

    That is the standing law verbatim — *a test that substitutes the dispatcher
    cannot be evidence about the dispatcher; when the thing under test is the
    seam, the stub is the bug's hiding place* — with a **builtin's write
    payload** as the subject. The stub is right for the rows above, whose
    subject is what `store` materializes; it is the wrong instrument for
    whether the peer would accept it.

    `store` is the second `put` submitter in this repo and the one no SDK
    reaches, so nothing in `entity_sdk`'s coverage speaks for it either.
    """

    @pytest.fixture
    def peer(self):
        from entity_core.crypto.identity import Keypair
        from entity_core.peer import PeerBuilder

        from entity_core.capability.grant import Grant

        return (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"], resources=["*"],
            )])
            .build()
        )

    def _real_ctx(self, peer):
        """An EvalContext whose `_execute_fn` is the peer's own dispatcher.

        Built the way `compute.py` builds it for a live evaluation — through
        `_make_sync_dispatch` over a real `HandlerContext` — so the entity the
        builtin emits is admitted by the same `_handle_put` a wire caller hits.
        """
        from entity_core.handlers.context import HandlerContext
        from entity_handlers.compute import _make_sync_dispatch

        handler_ctx = HandlerContext(
            local_peer_id=peer.keypair.peer_id,
            remote_peer_id="test-remote",
            handler_grant=WILDCARD_CAP,
            caller_capability=WILDCARD_CAP,
            emit_pathway=peer.emit_pathway,
            _execute_dispatcher=peer._dispatch_local_execute,
        )
        return EvalContext(
            content_store=peer.emit_pathway.content_store,
            entity_tree=peer.emit_pathway.entity_tree,
            local_peer_id=peer.keypair.peer_id,
            capability=WILDCARD_CAP,
            caller_capability=WILDCARD_CAP,
            emit_pathway=peer.emit_pathway,
            included={},
            has_content_store_access=True,
            _execute_fn=_make_sync_dispatch(handler_ctx, WILDCARD_CAP),
        )

    def test_a_dispatched_store_is_accepted_by_the_real_put_admission(self, peer):
        """The row the stub could not carry.

        `put` is a receipt path since 0.8.2.11 §6.3 — it authors nothing — so a
        builtin that emits a two-key `{type, data}` is refused
        `400 invalid_request` and the write silently does not land. Reading the
        eval result is not enough: `store` returns the dispatch result, so the
        assertion is on the **binding**.
        """
        cs = peer.emit_pathway.content_store
        expr = _apply_store(cs.put(_lit("corpus/viadispatch")), cs.put(_lit(42)))

        result = evaluate(expr, Scope(), Budget(), self._real_ctx(peer))

        assert not is_error(result), (
            f"the dispatched store was refused by the real tree handler: "
            f"{result!r} — the builtin is a `put` SUBMITTER and must construct "
            f"the entity (0.8.2.11 §6.3), exactly as the SDK does"
        )
        tree = peer.emit_pathway.entity_tree
        bound = tree.get(tree.normalize_uri("corpus/viadispatch"))
        assert bound is not None, "a refused put binds nothing"
        assert cs.get(bound).data == 42

    def test_the_hash_bound_is_the_one_the_builtin_authored(self, peer):
        """Teeth: a 200 alone would also be satisfied by a peer that authored.

        The point of the ruling is *who* computes the hash, so the row has to
        assert the identity of the bound hash rather than the fact of a write.
        """
        cs = peer.emit_pathway.content_store
        expr = _apply_store(cs.put(_lit("corpus/authored")), cs.put(_lit(7)))

        evaluate(expr, Scope(), Budget(), self._real_ctx(peer))

        tree = peer.emit_pathway.entity_tree
        bound = tree.get(tree.normalize_uri("corpus/authored"))
        assert bound == Entity(type="primitive/any", data=7).compute_hash()
