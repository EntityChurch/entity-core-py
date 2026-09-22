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
        assert result["result"]["data"]["code"] == "not_found"

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
