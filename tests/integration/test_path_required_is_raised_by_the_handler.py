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
]


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
