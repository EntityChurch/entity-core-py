"""0.8.2.17 — `path_required` is raised by the HANDLER, and the audit is
per-operation against each operation's own spec.

0.8.2.14 declared the code and said it was raised *"at dispatch, before the
handler runs"* for a *"directly-callable"* operation. **That reading is
withdrawn.** `directly-callable` occurred exactly once in the whole
specification — in the row that depended on it — citing §3.2, which does not
define it; §3.2 said the opposite; and `system/handler/operation-spec`
declares `input_type` and `output_type` and nothing else, so a dispatcher —
which holds the resolved manifest and nothing else — has **no field** against
which to decide whether an operation requires a `resource`.

So: the code stays core-declared (the *condition* is core's, since `resource`
is a §3.2 EXECUTE field), and the **raising site is the handler**, with each
operation's own specification saying whether it requires one. Operations for
which no resource is legitimate — `configure`, `create_quorum` — simply do not
carry the requirement.

.. rubric:: The census is by the row's INPUT, not by the token

This file exists because grepping for `path_required` answers *"where do we
already emit it"* and can never answer *"where should we."* The input §3.3
assigns to this code is **an operation whose own specification requires a
`resource`, invoked without one**, so the census starts from the specs that
state that requirement and asks what this peer answers.

That census found one defect that a token grep could not: `system/handler`'s
`register`/`unregister` answered `ambiguous_resource` for the **absent** case.
Absent and ambiguous are different inputs — *supply a resource* is not
*disambiguate the one you sent* — and §3.3 says selecting the remedy is what
the code is for. It read as conformant at every glance, because
`ambiguous_resource` is a real code and the site is a resource-count check
that happens to be written as `!= 1`.

.. rubric:: The set, and where each row's requirement is stated

======================================  ===========================  =========
operation                               requirement stated in        covered
======================================  ===========================  =========
`system/handler:register`               core §6.2                    here
`system/handler:unregister`             core §6.2                    here
`system/content:get`                    CONTENT §6.2                 here
`system/content:ingest`                 CONTENT §6.3                 here
`system/quorum:create/update/publish`   QUORUM §6 path-as-resource   here
`system/attestation:create`             ATTESTATION §6               here
`system/attestation:supersede/revoke`   ATTESTATION §6               here (*)
`system/continuation:install`           CONTINUATION P-CONTINUATION-1 here (+)
`system/compute:eval`                   COMPUTE §3.2                 here (+)
`system/compute:install`                COMPUTE §3.3                 here (+)
`system/compute:uninstall`              COMPUTE §3.4                 here (+)
======================================  ===========================  =========

(*) reached by delegation to `create`, which is where the check lives — see
`TestTheOrderIsNotStated` below, which is a finding rather than a pass.

(+) **added at 0.8.2.18, and the gap in the first census is the finding.**
This file was written to say *"the census is by the row's INPUT, not by the
token"* — and its own set stopped at **core and the two extensions the author
had open**. All four rows above derive their path from `resource.targets[0]`
in exactly the way `system/handler:register` does, all four collapsed the two
inputs into `len(targets) != 1 -> ambiguous_resource`, and all four were
invisible to a census that enumerated the specs it happened to be reading.

So the input-census beats a token grep and is still bounded by its **corpus
sweep**. The unit was right; the *scope* was the reading list. The check the
next census owes: enumerate from the handler registration list — the one
inventory a defect cannot edit — and ask of every operation *does this derive
a path from `resource.targets[0]`?*, rather than from the sections already
open. That is the same remedy the §3.3 slot census reached from the other
side, and it is the second time this repo has needed it.

.. rubric:: What is deliberately NOT in the set

`system/tree:get` / `:put` fall back to `params.data.path` when no `resource`
is present, and that is **left alone**. §6.3's examples all carry a resource,
but no sentence there requires one, and `CORE-TREE-PATH-FLEX-1` speaks of
*"caller-supplied paths"* — so requiring one would be inventing a wire
semantic, in the operation with the widest blast radius in the protocol.
Routed as a question (does §6.3 mean to require a resource?) rather than
answered locally. A row below pins today's behaviour so the answer arriving
is a visible change rather than a silent one.
"""

from __future__ import annotations

import pytest

from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder

# Operations whose own specification requires a `resource`, with the params
# that are otherwise valid — so the absent resource is the only fault, and the
# refusal attributes.
REQUIRES_RESOURCE = [
    ("system/handler", "register", {
        "manifest": {
            "name": "probe", "pattern": "local/probe",
            "operations": {"ping": {"input_type": "primitive/any"}},
        },
    }, "core §6.2"),
    ("system/handler", "unregister", {}, "core §6.2"),
    ("system/content", "get", {"hash": b"\x00" + b"\x11" * 32}, "CONTENT §6.2"),
    ("system/content", "ingest", {"entities": []}, "CONTENT §6.3"),
    # --- added 0.8.2.18, and the four rows the first census could not see ---
    ("system/continuation", "install", {}, "CONTINUATION P-CONTINUATION-1"),
    ("system/compute", "eval", {}, "COMPUTE §3.2"),
    ("system/compute", "install", {}, "COMPUTE §3.3"),
    ("system/compute", "uninstall", {}, "COMPUTE §3.4"),
    # --- added 2026-09-10: ROLE, the spec arch's 0.8.2.19 sweep named and
    #     this census never walked. See TestTheAmbiguousArm below. ---
    ("system/role", "define", {}, "ROLE §2.2"),
    ("system/role", "assign", {}, "ROLE §2.2"),
    ("system/role", "unassign", {}, "ROLE §2.2"),
    ("system/role", "exclude", {}, "ROLE §2.2"),
    ("system/role", "unexclude", {}, "ROLE §2.2"),
    ("system/role", "re-derive", {}, "ROLE §2.2"),
    ("system/role", "delegate", {}, "ROLE §2.2"),
    ("system/attestation", "create", {}, "ATTESTATION §6"),
]

#: Two well-formed resource targets. Which two does not matter — the fault
#: under test is the COUNT, and it is refused before any path is parsed.
TWO_TARGETS = ["system/probe/one", "system/probe/two"]


@pytest.fixture
def peer():
    return (
        PeerBuilder().with_keypair(Keypair.generate())
        .with_all_handlers().with_conformance_handlers().build()
    )


async def _dispatch(peer, handler, operation, data, resource_targets=None):
    return await peer._dispatch_local_execute(
        handler, operation, {"data": data},
        {"grants": [{
            "handlers": {"include": ["*"]},
            "operations": {"include": ["*"]},
            "resources": {"include": ["/*/*"]},
        }]},
        None, None, resource_targets=resource_targets,
    )


def _code(result) -> str:
    if isinstance(result.result, dict):
        return (result.result.get("data") or {}).get("code", "")
    return ""


class TestEveryOperationWhoseSpecRequiresOne:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "handler,operation,data,authority",
        REQUIRES_RESOURCE,
        ids=[f"{h}:{o}" for h, o, _d, _a in REQUIRES_RESOURCE],
    )
    async def test_answers_path_required_when_invoked_without_one(
        self, peer, handler, operation, data, authority,
    ):
        result = await _dispatch(peer, handler, operation, data)

        assert result.status == 400, (
            f"{handler}:{operation} without a resource -> {result.status} "
            f"({authority} requires one): {result.result}"
        )
        assert _code(result) == "path_required", (
            f"{handler}:{operation} without a resource answered "
            f"{_code(result)!r}. {authority} requires a resource, so this is "
            "§3.3's `path_required` input — and a code that names a different "
            "remedy sends the caller to fix the wrong thing"
        )


class TestTheAmbiguousArm:
    """§3.3's **other** input, which this file had never censused.

    The row is a pair — *"an operation that requires a resource answers ABSENT
    with `path_required` and MORE THAN ONE with `ambiguous_resource`"* — and
    every census above enumerated only the absent half. The class above is the
    set of operations that require a resource; **the same set owes both arms**,
    and that is not a new ruling, it is the second sentence of the row nobody
    read as a task.

    .. rubric:: How ten operations accepted an ambiguous request silently

    Nine of these sites shared one helper, `_common.resource_target`, which
    returns `targets[0]`. Absent was refused at each call site; more-than-one
    was **not refused anywhere** — a three-target request was served as if it
    named one, picking the first and discarding the rest without a word.

    That arm is invisible three ways over, which is why it survived two
    censuses of this exact row:

    1. **A token grep cannot see it.** Grepping `ambiguous_resource` finds the
       sites that already answer it. `role.py`, `quorum.py` and
       `attestation.py` contained **zero** occurrences — they read as having
       nothing to do with this code.
    2. **The absent-arm census cannot see it.** Every row above passes on a
       peer that has this defect, because they send zero targets.
    3. **No probe sends two.** Nobody supplies two resource targets by
       accident, so it is not reachable by fuzzing or by ordinary use — only
       by asking the question.

    The finding that reaches it is the one this file's own docstring already
    prescribed and did not perform: enumerate by the row's **input**, and the
    code's own `path_required` is the admission that the input applies.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "handler,operation,data,authority",
        REQUIRES_RESOURCE,
        ids=[f"{h}:{o}" for h, o, _d, _a in REQUIRES_RESOURCE],
    )
    async def test_answers_ambiguous_resource_when_given_more_than_one(
        self, peer, handler, operation, data, authority,
    ):
        result = await _dispatch(
            peer, handler, operation, data, resource_targets=TWO_TARGETS,
        )

        assert result.status == 400, (
            f"{handler}:{operation} with TWO resource targets -> "
            f"{result.status}. {authority} requires a resource, so §3.3's "
            "more-than-one input applies and the request is ambiguous: a "
            f"peer that serves it has silently picked one. {result.result}"
        )
        assert _code(result) == "ambiguous_resource", (
            f"{handler}:{operation} with two resource targets answered "
            f"{_code(result)!r}. `path_required` here would be the mirror of "
            "the 0.8.2.18 defect — *disambiguate the one you sent* is not "
            "*supply a resource*"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "handler,operation,data,authority",
        REQUIRES_RESOURCE,
        ids=[f"{h}:{o}" for h, o, _d, _a in REQUIRES_RESOURCE],
    )
    async def test_the_two_arms_do_not_collapse(
        self, peer, handler, operation, data, authority,
    ):
        """The control, and it is the whole point of the pair.

        A peer answering one code to both inputs satisfies neither arm's
        *spirit* while passing whichever arm you happen to check first. §3.3:
        *"a handler specification that collapses them into one code is
        non-conformant on the absent case."* Asserting both codes separately
        still permits a peer that answers `ambiguous_resource` to everything
        if only that row exists — so the codes are asserted **different**.
        """
        absent = await _dispatch(peer, handler, operation, data)
        ambiguous = await _dispatch(
            peer, handler, operation, data, resource_targets=TWO_TARGETS,
        )
        assert _code(absent) != _code(ambiguous), (
            f"{handler}:{operation} answers {_code(absent)!r} to both zero "
            "targets and two — one gate, not two. The two inputs have "
            "different remedies and §3.3 says selecting the remedy is what "
            "the code is for"
        )


class TestThePatternArm:
    """§3.3's **third** input, added at 0.8.2.20: *"A resource-requiring
    operation takes a CONCRETE path: where the effective list holds a single
    entry and that entry ``is_pattern``, the operation answers `400
    malformed_resource`."*

    .. rubric:: Why it is a third arm and not a variation of the second

    The first two arms are about **how many** targets there are; this one is
    about **what one target is**. A pattern passes every count check ever
    written for this row — it is exactly one entry — and then gets indexed and
    used as a path, so the operation acts at a literal path containing a `*`
    or, worse, at whatever a downstream normalizer makes of one.

    It is also the arm with no natural forcing function: 0.8.2.20 adds it to a
    row two prior censuses of this file walked and passed. There was no
    behaviour change to prompt a test, which is the *"a ruling you already
    satisfy produces no diff"* trap arriving one clause later — except here we
    did **not** already satisfy it, and the two existing arms are exactly what
    made it look like we did.

    .. rubric:: Measured: 7 of these 18 rows discriminate, and the prediction
       was 18

    Deleting the arm from ``_common.require_single_resource_target`` reddens
    **seven**: both `content` rows, all three `compute` rows,
    `continuation:install` and `attestation:create`. The other eleven —
    `system/handler`'s two verbs and all seven `role` operations — answer
    ``malformed_resource`` **anyway**, from their own downstream path-shape
    check (`register` requires the target to start `system/handler/`; a
    pattern does not), and so score a peer without the rule as conformant.

    They are kept and labelled rather than deleted: they are real conformance
    rows for those operations, and they are **not** evidence that the shared
    arm exists. The distinction matters because the eleven are the ones a
    later reader would cite — they are the operations §6.13 names by name.

    ``test_the_three_arms_do_not_collapse`` reddens on **none** of them, which
    is the same shape one level up: without the arm the pattern input still
    produces *some* third code (`404 not_found`, `400 invalid_params`), so
    three-distinct-codes is satisfied by a peer that has no pattern rule at
    all. It is a control against collapse, not a check on this arm.
    """

    #: One well-formed *pattern* target. The distinguishing property is not
    #: that it is malformed — it is structurally fine — but that it names a
    #: SET where the operation's own spec names an entity.
    PATTERN_TARGET = ["system/probe/*"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "handler,operation,data,authority",
        REQUIRES_RESOURCE,
        ids=[f"{h}:{o}" for h, o, _d, _a in REQUIRES_RESOURCE],
    )
    async def test_answers_malformed_resource_for_a_single_pattern_target(
        self, peer, handler, operation, data, authority,
    ):
        result = await _dispatch(
            peer, handler, operation, data, resource_targets=self.PATTERN_TARGET,
        )

        assert result.status == 400, (
            f"{handler}:{operation} with a single PATTERN target -> "
            f"{result.status}. {authority} requires *a* resource, and a "
            f"pattern is a set: {result.result}"
        )
        assert _code(result) == "malformed_resource", (
            f"{handler}:{operation} with a pattern target answered "
            f"{_code(result)!r}. §3.3 distinguishes this from `invalid_path` "
            "on purpose — the target is structurally valid and is simply not "
            "usable as *this* operation's subject, which is a different "
            "instruction to the caller"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "handler,operation,data,authority",
        REQUIRES_RESOURCE,
        ids=[f"{h}:{o}" for h, o, _d, _a in REQUIRES_RESOURCE],
    )
    async def test_the_three_arms_do_not_collapse(
        self, peer, handler, operation, data, authority,
    ):
        """The pair control, extended to the triple.

        Asserting each code separately still passes a peer that answers one
        code to all three inputs if the rows are read one at a time. Three
        inputs, three remedies — *supply a resource*, *disambiguate the one
        you sent*, *name an entity rather than a set* — and the code is what
        selects between them.
        """
        codes = {
            "absent": _code(await _dispatch(peer, handler, operation, data)),
            "ambiguous": _code(await _dispatch(
                peer, handler, operation, data, resource_targets=TWO_TARGETS,
            )),
            "pattern": _code(await _dispatch(
                peer, handler, operation, data,
                resource_targets=self.PATTERN_TARGET,
            )),
        }
        assert len(set(codes.values())) == 3, (
            f"{handler}:{operation} does not answer three distinct codes to "
            f"§3.3's three inputs: {codes}"
        )


class TestLocalFilesIsNotInTheSetAndThisIsWhy:
    """SA-PY-47 — the one resource-requiring surface the census reached and
    deliberately did not converge.

    `DOMAIN-LOCAL-FILES` v1.2 requires a resource at all four operations
    (`tree_path = ctx.resource.targets[0]`, §4.1-§4.4) and defines **no error
    table**, so under §3.3's escape clause the defaults ought to bind. Both
    `entity-core-py` and `entity-core-go` emit `400 invalid_resource` instead —
    a spelling in no §3.3 code set — and neither refuses the more-than-one
    case.

    **Matching go here is a choice, and it is recorded as one.** Converging
    unilaterally would refuse where a sibling accepts and manufacture a
    cross-impl divergence out of a corpus gap. This is two seats not making the
    surface worse while a ruling is pending — cohort-consistent, not
    conformant. The row pins today's answer so a later seat "finishing the
    census" has to change it on purpose.
    """

    def test_the_absent_arm_still_answers_the_undefined_spelling(self):
        import inspect

        from entity_handlers.local_files import operations

        src = inspect.getsource(operations)
        assert src.count('"invalid_resource"') == 4, (
            "the local/files resource-absent spelling moved. If SA-PY-47 has "
            "been ruled, update this row and sweep all four operations "
            "together; if it has not, a unilateral change here refuses where "
            "entity-core-go accepts"
        )
        assert "require_single_resource_target" not in src, (
            "local/files was migrated to the strict helper — that is the "
            "SA-PY-47 convergence, and it is only correct once the ruling "
            "says a domain spec with no error table inherits §3.3's defaults"
        )


class TestTheClassClosesAtOneSite:
    """The structural row: the more-than-one arm lives in ONE helper.

    Nine of the ten sites re-opened this defect independently because each
    inlined its own absent check and called a lenient shared getter for the
    value. Re-inlining `resource_target(ctx)` at a resource-requiring site
    silently restores the gap for that operation alone, and the behavioural
    rows above only catch it for operations already in `REQUIRES_RESOURCE` —
    i.e. not for the next one somebody adds.
    """

    def test_no_resource_requiring_handler_uses_the_lenient_getter(self):
        import inspect

        from entity_handlers import attestation, quorum, role

        for module in (role, quorum, attestation):
            src = inspect.getsource(module)
            # `require_single_resource_target` contains the substring, so
            # neutralize it before asking about the lenient one.
            probe = src.replace("require_single_resource_target", "OK")
            assert "resource_target(ctx)" not in probe, (
                f"{module.__name__} reads the resource target through the "
                "lenient getter, which returns targets[0] and never refuses "
                "an ambiguous request. Use require_single_resource_target — "
                "§3.3's more-than-one arm is not optional for an operation "
                "whose spec requires a resource"
            )

    def test_the_helper_answers_all_three_arms(self):
        """A helper that answered some arms would let every call site read as
        migrated while part of the row stayed unimplemented."""
        import inspect

        from entity_handlers._common import require_single_resource_target

        src = inspect.getsource(require_single_resource_target)
        assert "path_required" in src
        assert "ambiguous_resource" in src
        assert "malformed_resource" in src

    def test_no_resource_requiring_handler_keeps_a_PRIVATE_copy_of_the_row(self):
        """⭐ The row the two-arm era could not have written, and the one that
        the pattern arm turned red on its first run.

        `compute:eval`/`install`/`uninstall` and `continuation:install` each
        held their **own** copy of the absent/more-than-one check — correct on
        both arms, passing every behavioural row above, and therefore invisible
        to a class whose members are codes. When 0.8.2.20 added the third arm
        it reached the shared helper and **none of those four**.

        The reason all four kept a private copy is worth the row: their
        refusals carry a `compute/error` envelope rather than
        `system/protocol/error`, so *the shape of the answer* was the reason to
        re-derive *the rule*. The helper now takes the result type, which
        removes the reason. This asserts the copies are gone, module by
        module — a behavioural row cannot, because a private copy that happens
        to be correct today is indistinguishable from the shared one.
        """
        import inspect

        from entity_handlers import compute, continuation, handlers

        for module in (compute, continuation, handlers):
            src = inspect.getsource(module)
            assert "ERR_AMBIGUOUS_RESOURCE," not in src.replace(
                "ERR_AMBIGUOUS_RESOURCE = ", "",
            ), (
                f"{module.__name__} still emits the more-than-one arm itself; "
                "the row lives in `_common.require_single_resource_target` so "
                "that the next arm added to it reaches every site at once"
            )
            assert '"ambiguous_resource"' not in src, (
                f"{module.__name__} names the code directly — see above"
            )


class TestTheHandlerIsTheRaisingSite:
    """0.8.2.17's actual change: not *whether* the code exists but *where* it
    is raised. A dispatcher holds `{input_type, output_type}` and cannot
    decide this, so a peer that raises it at dispatch is reading a field that
    does not exist.
    """

    def test_the_dispatcher_raises_it_nowhere(self):
        import inspect

        from entity_core.peer.peer import Peer

        for fn in (Peer._dispatch_local_execute, Peer._resolve_for_dispatch):
            assert "path_required" not in inspect.getsource(fn), (
                f"{fn.__qualname__} raises `path_required` — the "
                "dispatch-level reading was withdrawn at 0.8.2.17 because no "
                "conformant implementation could execute it"
            )

    def test_operations_for_which_no_resource_is_legitimate_carry_nothing(
        self, peer,
    ):
        """`configure` and `create_quorum` are 0.8.2.17's own examples of
        operations that *"simply do not carry the requirement"*.

        This is the row that stops the fix from becoming *"require a resource
        everywhere"*, which would pass every row in the class above.
        """
        import inspect

        from entity_handlers import quorum

        src = inspect.getsource(quorum)
        assert "_require_path_matches" in src
        verify = inspect.getsource(quorum._handle_verify)
        assert "_require_path_matches" not in verify, (
            "`system/quorum:verify` is a read that targets no binding — "
            "requiring a resource there invents a requirement its spec does "
            "not state"
        )


class TestTheOrderIsNotStated:
    """A finding, not a pass.

    `attestation:supersede` and `:revoke` satisfy their §6 path-as-resource
    MUST by **delegating to `create`**, which is where the check lives. So the
    resource check runs *after* their own param validation and after a
    content-store lookup — and an input that is faulty in two ways answers the
    other fault.

    This is the same shape as EXTENSION-TREE Appendix A's two `put` rows: a
    table individually satisfiable and jointly ambiguous, whose discriminating
    input is the one no row-scoped author writes. Pinned at today's answer,
    with the ambiguity named, rather than reordered on our own authority —
    routing it is the fix, because the order is a missing sentence.
    """

    @pytest.mark.asyncio
    async def test_supersede_with_neither_a_resource_nor_a_previous_hash(
        self, peer,
    ):
        result = await _dispatch(peer, "system/attestation", "supersede", {})
        assert _code(result) == "invalid_params", (
            "the answer to a doubly-faulty supersede moved. That is not "
            "necessarily wrong — but it is unruled, so it should move "
            "deliberately and be routed, not drift"
        )

    @pytest.mark.asyncio
    async def test_but_a_well_formed_supersede_with_no_resource_is_path_required(
        self, peer,
    ):
        """The row that proves the delegation actually reaches the check —
        without it, the row above is equally consistent with `supersede`
        having no resource requirement at all."""
        from entity_core.protocol.entity import Entity

        prior = Entity(type="system/attestation", data={
            "attesting": b"\x00" + b"\x01" * 32,
            "attested": b"\x00" + b"\x02" * 32,
            "properties": {"kind": "assertion"},
        })
        peer.content_store.put(prior)

        result = await _dispatch(peer, "system/attestation", "supersede", {
            "previous_hash": prior.compute_hash(),
            "properties": {"kind": "assertion"},
        })
        assert _code(result) == "path_required", (
            f"supersede reached neither the check nor a resource: "
            f"{result.status} {result.result}"
        )


class TestTreeIsDeliberatelyOutOfTheSet:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("operation", ["get", "put"])
    async def test_tree_still_takes_its_path_from_params_when_no_resource(
        self, peer, operation,
    ):
        """Pinned so the answer arriving is a visible change.

        §6.3's examples all carry `resource: {targets: [...]}`, but no sentence
        there requires one, and `CORE-TREE-PATH-FLEX-1` speaks of
        *"caller-supplied paths"*. Adding `path_required` here would invent a
        wire semantic in the operation with the widest blast radius in the
        protocol — the trade SA-PY-24 already declined. Routed as a question.

        If §6.3 is later read as requiring a resource, this row fails and its
        message is where to look.
        """
        data = {"path": "app/probe"}
        if operation == "put":
            data["entity"] = {"type": "primitive/any", "data": 1}

        result = await _dispatch(peer, "system/tree", operation, data)

        assert _code(result) != "path_required", (
            "`system/tree` now requires a resource. If that is a ruling, "
            "good — add both tree ops to REQUIRES_RESOURCE above and delete "
            "this row. If it is a local decision, it is one this repo is not "
            "entitled to make."
        )
