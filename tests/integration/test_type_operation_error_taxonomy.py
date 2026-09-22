"""`PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §2 and row 4, measured at this seat.

Arch routed §2 to us as the one thing that fold waits on
(`ROUTING-2026-09-03-a` §5.3, unchanged by `-c` §6.5), with the ask phrased as a
hypothetical: *"You have not built the TYPE handlers; the ask is whether §2
matches what you **would** build. If you do not intend to build them, say so and
it folds on rust's build alone."*

.. rubric:: The premise is wrong, and that is the first thing this file says

**We built all six.** `entity_handlers/type_handler.py` dispatches `validate`,
`compare`, `compatible`, `converge`, `adopt` and `reconcile` against
`EXTENSION-TYPE` v1.1 §7.1, registered at `system/type`. The proposal's §1
records *"`entity-core-go` and `entity-core-py` have not built these handlers,
searched at the commits above"* and §4 concludes *"rust has the only
implementation."*

That is the standing *a routed report's claims about our repo are hearsay* rule
with our **build state** as the subject — a seventh axis, after our
architecture, coverage, version, behaviour, filing record and a prescribed
remedy. It is also the flattering direction: a premise saying *you have nothing
to check* terminates in no work, exactly like the §8.3 instance where the
premise said *you already comply*. The check is the same one and it is one grep:
before answering a routed question about what you *would* build, grep for the
identifier.

So this file answers with a **measurement** rather than an intention, which is
what §4 says the fold actually needs (*"a derived failure set is a claim about
what these operations can fail on — the kind of claim that is checked in a
tree"*). It also means the fold has **two** independent builds, not one.

.. rubric:: What it found

* **§2 holds here, unprompted.** Every validation *outcome* is a `200` with
  `valid: false`; no typing verdict is a `400`. Third seat.
* **Row 4's `validate` arm — already implemented, derived independently.** An
  unresolvable type is a `200` with a `structural` violation on the `type`
  field, and the call site's comment says why: *"the spec is silent … reporting
  this as a structural violation is the §8.5 shape."* Arch adopted this arm from
  rust's build; it was reached here separately, which is corroboration and not
  an argument (L18).
* **Row 4's `compare` / `compatible` arm — we diverge, and worse than the row
  says.** An unresolvable type resolved to an **empty effective field set**
  rather than a lookup miss, so `compatible("no/such/a", "no/such/b")` answered
  `200` reporting the two nonexistent types **compatible**. That is a silent
  wrong answer under *either* reading of row 4, so it is fixed here rather than
  held for the fold: the ruling only decides whether the refusal is `404`, not
  whether inventing an empty type is allowed.
"""

from __future__ import annotations

from typing import Any

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_handlers.type_handler import TYPE_HANDLER_PATTERN, type_handler

VALIDATE_RESULT = "system/type/validate-result"


@pytest.fixture
def peer():
    return (
        PeerBuilder()
        .with_keypair(Keypair.generate())
        .with_all_handlers()
        .debug_mode(True)
        .build()
    )


def _ctx(peer):
    from entity_core.handlers.context import HandlerContext

    blanket = {
        "grants": [{
            "handlers": {"include": ["*"]},
            "resources": {"include": ["*"]},
            "operations": {"include": ["*"]},
        }]
    }
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=blanket,
        caller_capability=blanket,
        emit_pathway=peer.emit_pathway,
        _execute_dispatcher=peer._dispatch_local_execute,
    )


def _seed(peer, name: str) -> None:
    """Bind a minimal type definition at its `system/type/{name}` path."""
    from entity_core.protocol.entity import Entity
    from entity_core.storage.emit import EmitContext

    peer.emit_pathway.emit(
        f"system/type/{name}",
        Entity(
            type="system/type",
            data={
                "name": name,
                "fields": {"id": {"type_ref": "primitive/string"}},
            },
        ),
        EmitContext.bootstrap(),
    )


async def _call(peer, operation: str, data: dict[str, Any]) -> dict[str, Any]:
    return await type_handler(
        TYPE_HANDLER_PATTERN, operation, {"data": data}, _ctx(peer)
    )


class TestThePremiseThatWeHaveNotBuiltThem:
    """One row, and it is the cheap check the §8.3 instance cost us for skipping."""

    def test_all_six_operations_dispatch(self) -> None:
        """Asserted against the handler's own source, not against a memory.

        `EXTENSION-TYPE` v1.1 §7.1 names eight; §7.1's six are routed through
        this dispatcher (`converge`/`adopt`/`reconcile` are the §12.3 MAY set
        and are built anyway).
        """
        from pathlib import Path

        source = Path(type_handler.__code__.co_filename).read_text()
        for operation in (
            "validate", "compare", "compatible", "converge", "adopt", "reconcile",
        ):
            assert f'operation == "{operation}"' in source, (
                f"`{operation}` is not dispatched — if the handler was reduced, "
                "the proposal's premise became true and this file's answer to "
                "arch has to be re-stated as a hypothetical"
            )


class TestSection2TheOutcomeIsThePayloadNotAnError:
    """§2: *a type validation failure is a `200` with `valid: false`, not an
    error code* — the proposal's load-bearing sentence, and the one it says is
    cross-peer-observable on the primary success path if a seat gets it wrong.
    """

    @pytest.mark.asyncio
    async def test_a_failing_validation_is_200_valid_false(self, peer) -> None:
        result = await _call(
            peer,
            "validate",
            {"entity": {"type": "system/type", "data": {"name": "x"}},
             "type_path": "no/such/type"},
        )
        assert result["status"] == 200, (
            "§2: a peer that returns 400 for `valid: false` has made the "
            "operation useless to a caller doing schema exploration"
        )
        assert result["result"]["type"] == VALIDATE_RESULT
        assert result["result"]["data"]["valid"] is False

    @pytest.mark.asyncio
    async def test_a_structural_defect_of_the_REQUEST_is_still_a_400(
        self, peer
    ) -> None:
        """The other half of §2, and the one that keeps it a distinction.

        Error codes on these operations are reserved for *"structural defects
        of the request itself — the operation could not be performed at all."*
        A file that only asserted the 200 arm would pass a peer that answered
        200 to everything, including a request with no `entity` in it.
        """
        result = await _call(peer, "validate", {})
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_request"


class TestRow4TheDeclaredResultTypeCarriesTheOutcome:
    """Row 4's criterion, adopted from `entity-core-rust` and replacing arch's
    flat `404`: ***can the declared result type carry the outcome?***

    `validate-result` has a `violations` field that can express *"I could not
    resolve that type"*, so on `validate` that IS the analysis outcome.
    `compatibility-report` has nowhere to put it, so on `compare`/`compatible`
    it is a lookup miss and nothing else.
    """

    @pytest.mark.asyncio
    async def test_validate_expresses_the_miss_as_a_structural_violation(
        self, peer
    ) -> None:
        result = await _call(
            peer,
            "validate",
            {"entity": {"type": "no/such/type", "data": {}}},
        )
        assert result["status"] == 200
        data = result["result"]["data"]
        assert data["valid"] is False
        violations = data["violations"]
        assert [v["field"] for v in violations] == ["type"]
        assert violations[0]["kind"] == "structural"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", ["compare", "compatible"])
    async def test_an_unresolvable_type_is_404_not_an_empty_type(
        self, peer, operation
    ) -> None:
        """The divergence, and the reason it is fixed rather than held.

        Before this landed, an unresolvable path resolved to `{}` and flowed
        into the diff as *a type with no fields*. The status was the visible
        half; the invisible half is that `compatible` then reported two
        **nonexistent** types as compatible — `missing_required_*` are both
        empty, so nothing is incompatible. A caller doing schema exploration
        gets `compatible: true` for a typo.

        Row 4 decides whether the refusal is a `404`. It does not license
        inventing an empty type, so that half was never waiting on the fold.
        """
        result = await _call(
            peer, operation, {"type_a": "no/such/a", "type_b": "no/such/b"},
        )
        assert result["status"] == 404, (
            f"§8's `{operation}` result type has no field that can express an "
            f"unresolved type; got {result['status']}"
        )
        assert result["result"]["data"]["code"] == "type_not_found"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", ["compare", "compatible"])
    async def test_the_control_two_resolvable_types_still_answer_200(
        self, peer, operation
    ) -> None:
        """Teeth control: without it, `return 404` unconditionally passes."""
        result = await _call(
            peer,
            operation,
            {"type_a": "system/type", "type_b": "system/type"},
        )
        assert result["status"] == 200, (
            "the resolvable case must be unaffected, or the 404 rows above are "
            "measuring a handler that refuses everything"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", ["compare", "compatible"])
    async def test_a_resolvable_type_in_the_PREFIXED_form_still_answers_200(
        self, peer, operation
    ) -> None:
        """The form the probe writes, and the one my fixtures could not catch.

        `_normalize_type_lookup` accepts three spellings of the same type — a
        bare name (`app/user`), a peer-relative tree path
        (`system/type/app/user`) and an absolute one — and `op_compare` /
        `op_compatible` resolve **through** it. The first version of
        `_unresolvable` resolved the **raw** argument, so every prefixed form
        read as unresolvable and answered `404`. `entity-core-go`'s
        `type.op_compare_roundtrip` and `op_compatible_roundtrip` caught it.

        **Every fixture in the class above uses a bare name, which normalizes
        to itself** — including the control, which passes `system/type`. So the
        whole class was on the arm the conversion does not change, and could
        not fail. That is the standing *two readings that agree everywhere your
        fixtures live* shape with a **normalizer** as the thing being agreed
        about: a fixture is written by someone holding one representation, and
        the prefixed form is the one an outside caller reaches for.
        """
        _seed(peer, "roundtrip/probe")
        result = await _call(
            peer,
            operation,
            {
                "type_a": "system/type/roundtrip/probe",
                "type_b": "system/type/roundtrip/probe",
            },
        )
        assert result["status"] == 200, (
            "a resolvable type named in the `system/type/...` form must not "
            f"read as unresolvable; got {result['status']} "
            f"{result.get('result', {}).get('data', {}).get('code', '')!r}"
        )

    @pytest.mark.asyncio
    async def test_the_prefixed_form_of_an_ABSENT_type_is_still_404(
        self, peer
    ) -> None:
        """The other side of the normalizer, so the fix cannot over-correct.

        A fix that simply stopped checking would pass the row above. This one
        drives the prefixed form of a type that genuinely is not installed.
        """
        result = await _call(
            peer,
            "compare",
            {
                "type_a": "system/type/roundtrip/absent-3f9a",
                "type_b": "system/type/roundtrip/absent-3f9a",
            },
        )
        assert result["status"] == 404


# ---------------------------------------------------------------------------
# §6a.2 / §6a.3 — the three MAY operations, and the two rows go's gate cannot
# see. `entity-core-go` routed a ×3 alignment; walking the section found ×5.
# ---------------------------------------------------------------------------

#: Every operation whose declared `output_type` (§7.1) has no field that can
#: express *"a named type did not resolve"* — §6a.2's criterion, applied to the
#: manifest rather than to a preference. `validate` is the one exclusion and it
#: is asserted separately above, because `validate-result.violations` **can**
#: carry the outcome.
_LOOKUP_MISS_OPS = {
    # §6a.2 rows go's `op_*_missing_type_404` gate drives.
    "converge": {"type_paths": ["no/such/a", "no/such/b"]},
    "reconcile": {"type_paths": ["no/such/a", "no/such/b"], "strategy": "union"},
    "adopt": {"source_path": "no/such/a"},
    # Row 4's own pair. **Not in go's gate**, and the reason is structural:
    # their check is named for the three operations §6a.2 *added*, while
    # §6a.3's code change ("py's single `not_found` moves") lands on all five.
    "compare": {"type_a": "no/such/a", "type_b": "no/such/b"},
    "compatible": {"type_a": "no/such/a", "type_b": "no/such/b"},
}


class TestTheLookupMissIsOneRefusalAcrossFiveOperations:
    """`PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §6a.2 + §6a.3.

    .. rubric:: What the routed report could not say

    `entity-core-go`'s `2026-09-04` report measured this seat over the wire and
    was right about every row it drove: `converge` and `reconcile` answered
    `400 invalid_request` — a wrong status *class*, not a spelling — and
    `adopt` answered `404 not_found`. It routed a **×3** alignment because its
    gate is `op_{converge,adopt,reconcile}_missing_type_404`, named for the
    three operations §6a.2 added.

    **§6a.3's code change is not scoped to those three.** It reads *"py's
    single `not_found` moves"*, and that `not_found` is `compare`/`compatible`'s
    — the row-4 pair this seat had already fixed to the right *status* with the
    wrong *code*. So the divergence is **×5**, and the two rows outside it are
    invisible to a probe family named after the other three.

    That is the standing *when a sibling reports N rows of a table, walk every
    row* rule, with a **proposal section** as the table: the report's scope is
    the probes it seeds, the reader's impression is the section it cites, and
    nobody writes down the difference.

    .. rubric:: Why one helper and not five

    Before this, the same refusal was reached three ways — `compare`/
    `compatible` through a shared pre-check, `adopt` through
    `except ValueError -> 404 not_found`, and `converge`/`reconcile` through
    `except ValueError -> 400 invalid_request`, which conflated *"a type did
    not resolve"* with *"you sent fewer than two paths"* on one predicate. Five
    call sites, one spelling, is what stops them drifting again.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", sorted(_LOOKUP_MISS_OPS))
    async def test_an_unresolvable_type_is_404_type_not_found(
        self, peer, operation
    ) -> None:
        """The `(status, code)` pair, asserted as a pair.

        Mutating either half alone must fail this: `converge`/`reconcile` were
        wrong on the status, `adopt`/`compare`/`compatible` on the code, and a
        row asserting only one of them scores three of the five green.
        """
        result = await _call(peer, operation, _LOOKUP_MISS_OPS[operation])
        assert result["status"] == 404, (
            f"§6a.2: `{operation}`'s declared output_type has no field that "
            f"can express an unresolved type; got {result['status']}"
        )
        assert result["result"]["data"]["code"] == "type_not_found", (
            "§6a.3 adopts go's spelling: bare `not_found` is ambiguous with "
            "the entity-level 404 that 0.8.2.7's 404 row carves out"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", sorted(_LOOKUP_MISS_OPS))
    async def test_the_control_a_resolvable_type_still_answers_200(
        self, peer, operation
    ) -> None:
        """Teeth, and the same control go's gate runs before its assertion.

        Without it `return 404` unconditionally passes the class. go's check
        makes the reachability control explicit — a `200` here is what makes
        the row above attributable to the missing type rather than to an
        operation that refuses everything.
        """
        _seed(peer, "ctl/one")
        _seed(peer, "ctl/two")
        args = {
            "converge": {"type_paths": ["ctl/one", "ctl/two"]},
            "reconcile": {"type_paths": ["ctl/one", "ctl/two"], "strategy": "union"},
            "adopt": {"source_path": "ctl/one"},
            "compare": {"type_a": "ctl/one", "type_b": "ctl/two"},
            "compatible": {"type_a": "ctl/one", "type_b": "ctl/two"},
        }[operation]
        result = await _call(peer, operation, args)
        assert result["status"] == 200, (
            f"`{operation}` refused a resolvable pair with "
            f"{result['status']} "
            f"{result.get('result', {}).get('data', {}).get('code', '')!r}"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", sorted(_LOOKUP_MISS_OPS))
    async def test_the_PREFIXED_form_of_a_present_type_still_answers_200(
        self, peer, operation
    ) -> None:
        """The row the last fix cost us, written for the new gates up front.

        `_normalize_type_lookup` accepts a bare name, a peer-relative path and
        an absolute one; the operations resolve **through** it. The first
        version of `_unresolvable` resolved the raw argument, so every prefixed
        form read as unresolvable — caught by go's roundtrip probes, because a
        probe writes the prefixed form and a fixture author writes the short
        one. Three new call sites for that gate is three new chances to stand
        on the wrong side of the same conversion.
        """
        _seed(peer, "pfx/one")
        _seed(peer, "pfx/two")
        a, b = "system/type/pfx/one", "system/type/pfx/two"
        args = {
            "converge": {"type_paths": [a, b]},
            "reconcile": {"type_paths": [a, b], "strategy": "union"},
            "adopt": {"source_path": a},
            "compare": {"type_a": a, "type_b": b},
            "compatible": {"type_a": a, "type_b": b},
        }[operation]
        result = await _call(peer, operation, args)
        assert result["status"] == 200, (
            f"`{operation}` read a resolvable type named in the "
            f"`system/type/...` form as unresolvable; got {result['status']}"
        )

    @pytest.mark.asyncio
    async def test_a_partial_miss_still_refuses(self, peer) -> None:
        """One present, one absent — the arm a both-absent fixture cannot see.

        A gate that resolved only the *first* path passes every row above:
        both-absent rows fail on entry 0 and both-present rows have nothing to
        miss. Only a mixed pair distinguishes *all* from *any*.
        """
        _seed(peer, "partial/present")
        result = await _call(
            peer,
            "converge",
            {"type_paths": ["partial/present", "partial/absent-3f9a"]},
        )
        assert result["status"] == 404
        assert "partial/absent-3f9a" in result["result"]["data"]["message"]
        assert "partial/present" not in result["result"]["data"]["message"], (
            "the refusal names which lookup missed; listing the resolvable "
            "one back to the caller is the ambiguity `type_not_found` exists "
            "to remove"
        )


class TestAParamsDefectIsDecidedBeforeALookupMiss:
    """The ordering the new gate could have silently inverted.

    A request that is wrong in two dimensions at once has one right answer, and
    it is not *"whichever check was written first."* A `strategy` outside the
    enum is a structural defect of the request — the operation cannot be
    performed under it at all — while a missing type is a lookup miss on an
    otherwise well-formed request. `reconcile` validated `strategy` **inside**
    `op_reconcile`, i.e. after the point where the new `404` gate had to go, so
    landing the gate without hoisting it would have moved this row from `400`
    to `404` as a side effect nobody chose.

    No probe sends a request wrong in two dimensions, so nothing outside this
    file would have reported the change.
    """

    @pytest.mark.asyncio
    async def test_a_bad_strategy_AND_a_missing_type_is_the_400(
        self, peer
    ) -> None:
        result = await _call(
            peer,
            "reconcile",
            {"type_paths": ["no/such/a", "no/such/b"], "strategy": "nonsense"},
        )
        assert result["status"] == 400, (
            "a strategy outside the enum is decided before the lookup"
        )
        assert result["result"]["data"]["code"] == "invalid_request"

    @pytest.mark.asyncio
    async def test_a_bad_strategy_ALONE_is_still_the_400(self, peer) -> None:
        """Control: the hoist must not have changed the single-defect answer."""
        _seed(peer, "order/one")
        _seed(peer, "order/two")
        result = await _call(
            peer,
            "reconcile",
            {"type_paths": ["order/one", "order/two"], "strategy": "nonsense"},
        )
        assert result["status"] == 400
        assert result["result"]["data"]["code"] == "invalid_request"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", ["converge", "reconcile"])
    async def test_a_non_string_path_entry_is_a_400_about_the_entries(
        self, peer, operation
    ) -> None:
        """`[1, 2]` used to be filtered to `[]` and answered *"requires >= 2
        entries"* — a message describing a defect the request does not have,
        and the reason the length check inside the op stayed reachable behind
        a dispatcher guard that had already passed.
        """
        params: dict[str, Any] = {"type_paths": [1, 2]}
        if operation == "reconcile":
            params["strategy"] = "union"
        result = await _call(peer, operation, params)
        assert result["status"] == 400
        assert "must be strings" in result["result"]["data"]["message"]


class TestTheFiveOperationsShareOneSpelling:
    """Structural, and it is the row that survives a refactor.

    The behavioural rows above pass against a peer that hard-codes `404
    type_not_found` five times — which is the state this fix replaced, one
    spelling short. `_type_not_found` being the only producer is what stops the
    sixth operation inventing a seventh code, and a reviewer reading five
    correct-looking call sites cannot see that they share a source.
    """

    def test_no_bare_not_found_survives_in_the_type_handler(self) -> None:
        from pathlib import Path

        source = Path(type_handler.__code__.co_filename).read_text()
        assert '"not_found"' not in source, (
            "a second spelling of the lookup miss is how the five operations "
            "drifted apart; route it through `_type_not_found`"
        )

    def test_the_code_literal_has_exactly_one_producer(self) -> None:
        from pathlib import Path

        source = Path(type_handler.__code__.co_filename).read_text()
        assert source.count('"type_not_found"') == 1, (
            "the literal belongs to `_TYPE_NOT_FOUND` alone — a second "
            "occurrence means a call site re-rolled the refusal"
        )
