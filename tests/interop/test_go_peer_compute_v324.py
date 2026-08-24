"""Two v3.24/v3.25 positions where this peer and `entity-core-go` disagree,
measured on the wire rather than argued from source.

**Why this file exists.** Building COMPUTE v3.24–v3.26 (`2026-08-21-a` `-f`) I
read two places where go's implementation departs from the spec text, and the
standing rule is that *"they read the spec differently" is the flattering
hypothesis* — a source reading is a claim about someone else's code and gets
the same evidence bar as a claim about our own. go's own compute corpus cannot
settle either one: cross-blessing 352 wire vectors go↔py comes back **LOCKED,
byte-identical**, because neither configuration is in the corpus. That is
exactly the *"two readings that agree everywhere your fixtures live"* shape —
so the configuration that distinguishes them has to be written down, and this
is it.

Both probes are **positive-control paired**: each asserts a divergent row AND
an adjacent row the two peers agree on, so a failure is attributable to the
position under test rather than to the harness, the grant, or the peer being
down. Without the control, a go peer that 500s on everything reads as
"confirms the divergence."

Run against a live go peer:

    cd ../entity-core-go && go run ./cmd/entity-peer -addr 127.0.0.1:19801 -open-access
    ENTITY_GO_PEER=127.0.0.1:19801 uv run pytest tests/interop/test_go_peer_compute_v324.py -v

**Opt-in by an explicit address, with NO default — deliberately, and the reason
is not convenience.** These rows assert a *sibling's* conformance, so leaving
them armed would make our own suite go red on a defect we do not own and cannot
fix, pinning our gate to core-go's release schedule. A defaulted port is worse
still: a go peer someone else left running turns an unrelated session's diff
red for a reason that has nothing to do with it.

That makes this a skip-on-absence gate, which `AGENTS.md` names as a thing that
"has never told you it passes" — so the obligation moves to naming **when it
runs**: on every cohort catch-up against core-go, and before replying to any
routed compute item. The measured result is recorded with its go commit in
`docs/status/ROUTING-2026-08-21-…`, not left implied by a green suite.

**A liveness probe that tests for a socket rather than for a peer converts a
foreign process into a false failure in your own diff** (the 2026-08-19
Selenium-on-9000 lesson), so the fixture completes a handshake and reads the
peer id before declaring the peer available.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer.connection import Connection
from entity_core.protocol.entity import Entity

#: `host:port` of a live `entity-core-go` peer. Unset ⇒ every row skips.
GO_PEER_ADDR = os.environ.get("ENTITY_GO_PEER", "")

TREE_PREFIX = "corpus/probe/v324"


# --- liveness ----------------------------------------------------------------

async def _handshake(keypair: Keypair) -> Connection | None:
    """Connect AND complete the handshake, or None.

    Testing for a listening socket is not testing for a peer: an unrelated
    container publishing this port makes the probe see a listener, skip the
    skip, and die mid-handshake with an `IncompleteReadError` that reads like a
    protocol regression in whatever you just changed.
    """
    if not GO_PEER_ADDR:
        return None
    host, _, port = GO_PEER_ADDR.partition(":")
    try:
        conn = await asyncio.wait_for(
            Connection.connect(
                host, int(port), keypair, wait_for_capability=True,
            ),
            timeout=5.0,
        )
    except Exception:
        return None
    if conn.session.remote_peer_id is None:
        conn.close()
        await conn.wait_closed()
        return None
    return conn


@pytest.fixture
def keypair() -> Keypair:
    return Keypair.generate()


@pytest.fixture
async def go_conn(keypair):
    conn = await _handshake(keypair)
    if conn is None:
        pytest.skip(
            "set ENTITY_GO_PEER=host:port to a live entity-core-go peer that "
            "completes a handshake (see this module's docstring); "
            f"current value: {GO_PEER_ADDR!r}"
        )
    try:
        yield conn
    finally:
        conn.close()
        await conn.wait_closed()


# --- expression building ------------------------------------------------------

class _Closure:
    """Collects the entities an expression references, keyed by content hash.

    Everything but the root rides in the envelope's `included` map (§4.2 tier
    1); the root has to live at a tree path because §3.2 resolves the
    expression from `EXECUTE.resource` and there is no request field carrying
    one inline. Same shape go's own corpus driver uses.
    """

    def __init__(self) -> None:
        self.by_hash: dict[bytes, Entity] = {}

    def add(self, entity: Entity) -> bytes:
        h = entity.compute_hash()
        self.by_hash[h] = entity
        return h

    def lit(self, value) -> bytes:
        return self.add(Entity(type="compute/literal", data={"value": value}))

    def error(self, code: str, message: str = "probe") -> bytes:
        return self.add(Entity(
            type="compute/error", data={"code": code, "message": message},
        ))

    def builtin(self, path: str, args: dict[str, bytes]) -> bytes:
        return self.add(Entity(type="compute/apply", data={
            "path": path, "operation": "eval", "args": args,
        }))

    def included(self, root_hash: bytes) -> list[dict]:
        """Wire form for the bundled entities — `content_hash` INCLUDED.

        §1.8 strict entity fidelity: the receiver validates the carried hash
        and then trusts it. Emitting `{type, data}` alone lets the encoder
        default the field to the zero hash, and the peer answers
        `400 invalid_entity … claimed ecf-sha256:0000…` — a hash-mismatch
        diagnostic that reads like a canonicalisation bug in the sender.
        """
        return [
            e.to_dict()
            for h, e in self.by_hash.items() if h != root_hash
        ]


async def _tree_put(conn: Connection, peer_id: str, path: str, entity: Entity) -> None:
    resp = await asyncio.wait_for(
        conn.execute(
            uri=f"entity://{peer_id}/system/tree",
            operation="put",
            params={"entity": entity.to_dict()},
            resource={"targets": [f"/{peer_id}/{path}"]},
        ),
        timeout=15.0,
    )
    assert 200 <= resp.status < 300, f"tree put {path} → {resp.status}: {resp.result}"


async def _eval(conn: Connection, closure: _Closure, root: bytes, name: str):
    """Store the root at a tree path, dispatch `system/compute:eval`, and
    return the peer's result entity (`{type, data}`).

    Driven through `Connection.execute` rather than raw `send`/`recv`: the
    connection runs a background reader, so a second coroutine calling `recv`
    races it and the failure surfaces as an asyncio `RuntimeError` that looks
    nothing like a protocol result.
    """
    peer_id = conn.session.remote_peer_id
    path = f"{TREE_PREFIX}/{name}"
    await _tree_put(conn, peer_id, path, closure.by_hash[root])

    resp = await asyncio.wait_for(
        conn.execute(
            uri=f"entity://{peer_id}/system/compute",
            operation="eval",
            resource={"targets": [f"/{peer_id}/{path}"]},
            included=closure.included(root),
        ),
        timeout=30.0,
    )
    assert resp.status == 200, f"{name}: eval status {resp.status}: {resp.result}"
    return resp.result


def _result_code(result) -> str | None:
    """The `code` of a `compute/error` result, or None if it is not one."""
    if isinstance(result, dict) and result.get("type") == "compute/error":
        return (result.get("data") or {}).get("code")
    return None


BUILTIN_ASSOC = "system/compute/builtins/assoc"
BUILTIN_CONCAT = "system/compute/builtins/concat"
BUILTIN_GROUP_BY = "system/compute/builtins/group-by"
BUILTIN_MAP = "system/compute/builtins/map"
BUILTIN_FILTER = "system/compute/builtins/filter"
BUILTIN_FOLD = "system/compute/builtins/fold"


def _result_array(result) -> list:
    """The peer's array answer, unwrapped from whatever envelope it arrived in.

    The eval result crosses the boundary materialized, so an array of CONTAINED
    entities arrives as an array of bare `system/hash` values — the *length* is
    what the containment rows assert, never the element type. Both peers wrap a
    non-error result in `compute/result{value, expression}`; a bare
    `primitive/any` and a naked list are accepted too rather than pinned,
    because the wrapper is not what these rows are about and a helper that
    over-specifies it turns an unrelated shape change into a false divergence.
    """
    if isinstance(result, dict):
        data = result.get("data")
        if isinstance(data, dict) and "value" in data:
            data = data["value"]
        assert isinstance(data, list), f"expected an array result, got {result!r}"
        return data
    assert isinstance(result, list), f"expected an array result, got {result!r}"
    return result


# --- the probes ---------------------------------------------------------------

@pytest.mark.asyncio
class TestAConsumedCollectionOperandThatIsAnError:
    """**The finding, and it is not the one I set out to measure.**

    §3.5's flow-through table makes a collection operand **consumed** — *"its
    length is read to copy"* — so §7.2's `[MUST]` short-circuits an
    error-as-value there to *its own code*. go answers `type_mismatch` at both
    sites below, substituting a verdict about the **shape** for one about the
    **value** and discarding the original code, so a caller cannot tell a
    poisoned collection from a malformed program.

    I came here with two separate claims read off go's source — one about
    `concat` and one about §8.2 arg ordering. Tracing the actual values
    (A1: *trace a value before you theorize*) collapsed them into **one defect
    with two call sites**, and made the second claim unmeasurable — see
    `TestArgEvaluationOrder` below. The reading was right about *there being*
    a divergence and wrong about *what it was*, which is the standing
    correction: **being right about the conclusion is not being right about
    the rule.**

    Sites, read at go `f14cc2c` and confirmed on the wire:
      - `builtinConcat` (`ext/compute/builtins_v324.go`) — the sub-collection
        loop reaches `sub, ok := c.([]interface{})` before any error test.
      - `resolveCollection` (`ext/compute/builtins.go`) — evaluates the
        `collection` arg with `Evaluate` rather than `evalOperand`, so the
        error is never tested for; used by BOTH `assoc` and `group-by`.

    The `index` arg is handled correctly (`evalControlArg` → `evalOperand`),
    which is what the controls establish: this is not "go has no error
    handling here", it is one helper on the wrong side of the line.
    """

    async def test_control_a_well_formed_concat_agrees(self, go_conn):
        """Positive control. If this row fails, every row below is measuring
        the harness, the grant, or a dead peer."""
        c = _Closure()
        root = c.builtin(BUILTIN_CONCAT, {"collections": c.lit([[1, 2], [3]])})
        result = await _eval(go_conn, c, root, "concat-control")
        assert _result_code(result) is None, f"control should not error: {result}"

    async def test_control_a_genuine_shape_error_is_type_mismatch(self, go_conn):
        """The discriminating control: a sub-collection that really is the
        wrong *shape* (an integer where an array belongs) IS `type_mismatch`
        under every reading. Without it, "go says type_mismatch" is equally
        consistent with go having no error handling in this position at all,
        and the finding would not be attributable."""
        c = _Closure()
        root = c.builtin(BUILTIN_CONCAT, {"collections": c.lit([[1, 2], 7])})
        result = await _eval(go_conn, c, root, "concat-shape-error")
        assert _result_code(result) == "type_mismatch"

    async def test_control_an_error_index_does_short_circuit(self, go_conn):
        """The second discriminating control, and the one that localizes the
        defect to a single helper: `assoc`'s `index` — also a consumed
        position — short-circuits correctly on go. So the divergence is not
        "consumed operands are unhandled"; it is `resolveCollection`
        specifically."""
        c = _Closure()
        root = c.builtin(BUILTIN_ASSOC, {
            "collection": c.lit([1, 2, 3]),
            "index": c.error("idx_error"),
            "value": c.lit(0),
        })
        result = await _eval(go_conn, c, root, "assoc-index-error-control")
        assert _result_code(result) == "idx_error"

    async def test_concat_sub_collection_that_is_an_error_short_circuits(self, go_conn):
        """Divergent row 1 — `builtinConcat`.

        The error is placed into the `collections` array by `assoc`: the
        production path, and the only one available, since a stored
        `compute/literal` round-trip degrades an error to a generic map and
        never reaches the contained path.

        **Expected to FAIL against go today.** Written as a plain assertion
        rather than `xfail` on purpose: this is a claim about go's *current*
        behaviour, so when go fixes it the row simply goes green, whereas an
        `xfail` would go XPASS and read as a new problem.
        """
        c = _Closure()
        collections = c.builtin(BUILTIN_ASSOC, {
            "collection": c.lit([[1, 2], [3]]),
            "index": c.lit(1),
            "value": c.error("sub_error"),
        })
        root = c.builtin(BUILTIN_CONCAT, {"collections": collections})
        result = await _eval(go_conn, c, root, "concat-error-subcollection")
        assert _result_code(result) == "sub_error", (
            "§3.5 makes each `collection` a CONSUMED position, so an error "
            f"there short-circuits to its own code; got {result!r}"
        )

    async def test_assoc_collection_that_is_an_error_short_circuits(self, go_conn):
        """Divergent row 2 — `resolveCollection`, reached through `assoc`.

        Only `collection` errors here, so nothing about evaluation ORDER is in
        play and the row measures the short-circuit alone. That separation is
        the whole reason this row exists rather than the two-erroring-args
        fixture I started with.
        """
        c = _Closure()
        root = c.builtin(BUILTIN_ASSOC, {
            "collection": c.error("coll_error"),
            "index": c.lit(0),
            "value": c.lit(0),
        })
        result = await _eval(go_conn, c, root, "assoc-error-collection")
        assert _result_code(result) == "coll_error", (
            "§7.2 short-circuits a consumed operand to its own code; go's "
            f"resolveCollection answers a shape verdict instead; got {result!r}"
        )

    async def test_group_by_collection_that_is_an_error_short_circuits(self, go_conn):
        """Divergent row 3 — the same helper reached through `group-by`,
        included because a fix applied only at `assoc`'s call site would leave
        this one open and the other two rows would not notice."""
        c = _Closure()
        ident = c.add(Entity(type="compute/lambda", data={
            "params": ["x"],
            "body": c.add(Entity(
                type="compute/lookup/scope", data={"name": "x"},
            )),
        }))
        root = c.builtin(BUILTIN_GROUP_BY, {
            "collection": c.error("coll_error"), "fn": ident,
        })
        result = await _eval(go_conn, c, root, "group-by-error-collection")
        assert _result_code(result) == "coll_error", (
            f"same defect as assoc, second call site; got {result!r}"
        )


@pytest.mark.asyncio
class TestArgEvaluationOrder:
    """§8.2: *"`compute/apply` arguments MUST be evaluated in ECF canonical map
    key order"* — keys sorted by encoded byte length, then lexicographically.
    For `assoc` that is `index` (5) · `value` (5) · `collection` (10).

    **CONFIRMED ON THE WIRE 2026-08-21 against go `9ad0110`:** go answers
    `coll_error`, py answers `idx_error`. Filed to core-go, not to arch — §8.2
    is a landed `[MUST]` read against one implementation, so it is theirs to
    check rather than arch's to rule.

    Read at `builtinAssoc` (go `f14cc2c`, unchanged at `9ad0110`): it resolves
    `collection` first and `index` second — positional order, which for this
    arg set is the reverse of canonical. The four v3.24 primitives resolve
    their own args instead of going through the generic path, so the divergence
    is specific to them.

    **How this row got here is the part worth keeping.** From 2026-08-21 to
    `ded9ea0` it was `skip`, not `xfail`, with its retirement condition written
    into the reason string: *"un-skip when `resolveCollection` short-circuits"*.
    The fixture that shows the ordering is "both args error, whose code comes
    back", and go answered `type_mismatch` from `resolveCollection` on exactly
    that fixture — so the other defect **masked** this one, and a row asserting
    `idx_error` would have gone red for a reason that is not this claim.

    go fixed `resolveCollection` (`ded9ea0`), the condition was discharged, and
    the row was armed and measured in the same session. An `xfail` would have
    flipped to **XPASS at `ded9ea0`** and been read as this claim confirming —
    which it is not; the claim was still false at that commit and is true now
    for a different reason. *A deferral without a retirement condition is an
    omission with better prose;* this one had one, and somebody discharged it.
    """

    async def test_the_first_canonical_arg_wins_when_two_would_error(self, go_conn):
        c = _Closure()
        root = c.builtin(BUILTIN_ASSOC, {
            "collection": c.error("coll_error"),
            "index": c.error("idx_error"),
            "value": c.lit(0),
        })
        result = await _eval(go_conn, c, root, "assoc-order-divergence")
        assert _result_code(result) == "idx_error", (
            "§8.2 MUSTs ECF canonical key order (index < value < collection); "
            f"got {result!r}"
        )


# --- C-8: the closure-result positions ---------------------------------------
#
# Added 2026-08-21, replying to `entity-core-go` 2026-08-21-c. go landed all of
# Corner 1 and asked rust/py to verify their own `filter`/`fold` rather than
# assuming. Verifying ours found something on theirs, which is why these rows
# point at a go peer: **arch ruled `fold`'s accumulator CONTAINED and go
# implemented it as a short-circuit**, reading arch's word "propagates" as
# "aborts". Read off `builtinFold` first, then measured here, because a source
# reading gives you the site and only a trace gives you the extent.

class _C8:
    """Expression builders the C-8 rows need on top of `_Closure`."""

    def __init__(self, c: "_Closure") -> None:
        self.c = c

    def scope(self, name: str) -> bytes:
        return self.c.add(Entity(
            type="compute/lookup/scope", data={"name": name},
        ))

    def lam(self, params: list[str], body: bytes) -> bytes:
        return self.c.add(Entity(
            type="compute/lambda", data={"params": params, "body": body},
        ))

    def div_by_zero(self) -> bytes:
        """A MINTED error — the evaluator produces it inside the closure."""
        return self.c.add(Entity(type="compute/arithmetic", data={
            "op": "div", "left": self.c.lit(1), "right": self.c.lit(0),
        }))

    def value_form_error(self, code: str) -> bytes:
        """A VALUE-FORM error — a lookup onto a stored `compute/error`, which
        SA-1 returns unchanged, so it never passed through a failure path."""
        return self.c.add(Entity(
            type="compute/lookup/hash", data={"hash": self.c.error(code)},
        ))

    def if_eq(self, name: str, n, then: bytes, els: bytes) -> bytes:
        cond = self.c.add(Entity(type="compute/compare", data={
            "op": "eq", "left": self.scope(name), "right": self.c.lit(n),
        }))
        return self.c.add(Entity(type="compute/if", data={
            "condition": cond, "then": then, "else": els,
        }))


@pytest.mark.asyncio
class TestC8ClosureResultPositions:
    """arch's C-8 ruling (`entity-system-architecture` `172589e`) measured
    against a live go peer at `9ad0110`, one position per row.

    The rule: **a position CONTAINS when the primitive places the value without
    reading it, and CONSUMES when it reads it to decide** — so `map`'s output
    element contains, `filter`'s predicate result short-circuits, and `fold`'s
    accumulator contains, which is why a closure that ignores its accumulator
    **recovers**.

    Rows are ordered agreement-first: `map` and `filter` are where the two peers
    now converge, and they are the controls that make the `fold` rows
    attributable. Without them a go peer that mishandled every closure result
    would read as "confirms the fold divergence".
    """

    async def test_control_map_contains_the_closure_result(self, go_conn):
        """go's own CV-8a shape. Both peers must answer a 2-element ARRAY, not
        one error — the length is the discriminator."""
        c = _Closure()
        b = _C8(c)
        root = c.builtin(BUILTIN_MAP, {
            "collection": c.lit([1, 2]),
            "fn": b.lam(["x"], b.div_by_zero()),
        })
        result = await _eval(go_conn, c, root, "c8-map-contains")
        assert _result_code(result) is None, (
            f"map short-circuited the closure result: {result!r}"
        )
        assert len(_result_array(result)) == 2

    async def test_control_filter_short_circuits_the_predicate_result(self, go_conn):
        """The consumed half. Containing it would coerce an error to a truth
        value and silently drop the element."""
        c = _Closure()
        b = _C8(c)
        root = c.builtin(BUILTIN_FILTER, {
            "collection": c.lit([1, 2]),
            "fn": b.lam(["x"], b.value_form_error("pred_error")),
        })
        result = await _eval(go_conn, c, root, "c8-filter-short-circuits")
        assert _result_code(result) == "pred_error"

    async def test_fold_recovers_when_the_closure_ignores_its_accumulator(
        self, go_conn,
    ):
        """**arch's CV-8d — the row go's CV-8c cannot see, and the divergence.**

        The closure errors on element 1 and answers `99` on element 2, ignoring
        `acc` entirely. Under the ruled containment the fold keeps going and
        returns `99`; under a short-circuit it stops at the first step and
        returns the error.

        arch names this position *"the one of the three with the widest blast
        radius if wrong: the only one where the alternative reading produces a
        different **value**, not merely a different cost."*

        **Expected to FAIL against go `9ad0110`.** `builtinFold` checks
        `computeErrorFromValue(acc)` after every `fn` step and returns it as a
        Go error. Plain assertion rather than `xfail`, for the same reason the
        class above gives: when go fixes it this row simply goes green.
        """
        c = _Closure()
        b = _C8(c)
        body = b.if_eq("el", 2, c.lit(99), b.value_form_error("acc_error"))
        root = c.builtin(BUILTIN_FOLD, {
            "collection": c.lit([1, 2]),
            "fn": b.lam(["acc", "el"], body),
            "initial": c.lit(0),
        })
        result = await _eval(go_conn, c, root, "c8-fold-recovers")
        assert _result_code(result) is None, (
            "the fold stopped at an accumulator it never reads — arch C-8 §2.3 "
            f"makes it a contained position, so a closure ignoring `acc` "
            f"recovers; got {result!r}"
        )

    async def test_fold_binds_an_error_initial_without_consuming_it(self, go_conn):
        """The arg-axis half of the same ruling: `initial` is bound into the
        closure, never read by `fold`, so it is contained.

        **Expected to FAIL against go `9ad0110`** — `builtinFold` moved
        `initial` onto `evalOperand` in `eea0a6e`, which short-circuits it.
        Separated from the row above because they are two different edits on
        go's side and a single row would not say which one to make.
        """
        c = _Closure()
        b = _C8(c)
        root = c.builtin(BUILTIN_FOLD, {
            "collection": c.lit([7]),
            "fn": b.lam(["acc", "el"], b.scope("el")),
            "initial": b.value_form_error("init_error"),
        })
        result = await _eval(go_conn, c, root, "c8-fold-initial-bound")
        assert _result_code(result) is None, (
            "an error `initial` short-circuited, so a closure that never reads "
            f"`acc` could not recover; got {result!r}"
        )

    async def test_a_value_form_limit_code_in_map(self, go_conn):
        """**The named divergence on the eval-limit carve-out, and it is a
        measurement of go's own stated design rather than of a bug.**

        go's `isEvalLimitCode` check sits on the MINTED arm of `builtinMap`
        only, so a closure returning a stored
        `compute/error{code: "budget_exhausted"}` is CONTAINED there. py reads
        the code through `error_data`, so both representations propagate. That
        is §2.4's provenance-independence applied to the carve-out, and it is
        the claim go is asked to concur with or refute (SA-PY-25).

        Written asserting **py's** behaviour so the row states our position and
        goes green when the cohort converges — not because go is presumed
        wrong. If arch rules the other way, this row is what has to change.
        """
        c = _Closure()
        b = _C8(c)
        root = c.builtin(BUILTIN_MAP, {
            "collection": c.lit([1, 2]),
            "fn": b.lam(["x"], b.value_form_error("budget_exhausted")),
        })
        result = await _eval(go_conn, c, root, "c8-map-value-form-limit")
        assert _result_code(result) == "budget_exhausted", (
            "a limit code propagates out of a contained position regardless of "
            f"how it was produced (§2.4); got {result!r}"
        )
