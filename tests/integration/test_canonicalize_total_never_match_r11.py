"""R11 / G6 (0.8.2.20) — `canonicalize` is total, and every consumer of its
return domain is ruled.

`ENTITY-CORE-PROTOCOL` §5.4 replaces two ``error(...)`` returns *"that no
normative call site in this document could consume"* with a sentinel:
``canonicalize`` returns **a canonical path or** ``NEVER_MATCH``, never a
failure. Three consumers are then ruled, and all three exist here:

======================================  =====================================
consumer                                rule
======================================  =====================================
``matches_pattern`` (§5.4)              MUST return False for **either**
                                        operand
``validate_absolute_path`` (§5.4)       MUST error — by construction, and it
                                        is the designed destination for the
                                        diagnostic ``canonicalize`` no longer
                                        raises
storage / tree access                   MUST NOT store, key, or resolve it
======================================  =====================================

and **every ``validate_absolute_path`` call site MUST consume its return**
(G6) — *"a validator whose verdict is dropped enforces nothing."*

.. rubric:: Why this peer needed the change at all, having refused these
   inputs already

Before 0.8.2.20 a reserved (``./``, ``../``) or ambiguous (``*/``) string
passed through ``canonicalize`` unchanged, and the argument for that — in this
file's own history — was that a non-absolute string matches no canonical
``/{peer_id}/...`` target and is therefore fail-closed anyway. **The argument
is true of every input anyone named and is exactly what §5.4 now refuses to
rest on:** ``matches_pattern`` returns True for a bare ``"*"`` operand, one
recursion step through the ``/*/`` arm can produce one, and *"safety MUST NOT
rest on a value merely looking unmatchable."* The distinction is between *no
rule happens to match it* and *the matcher refuses it by name*, and only the
second survives someone adding a matcher arm.

That makes most rows here **behaviour-preserving on today's inputs and
mutation-sensitive on the mechanism** — which is stated rather than hidden:
``test_the_arm_is_first`` and ``test_a_peer_wildcard_grant_cannot_reach_a_
bogus_peer_target`` are the two that fail on a peer with the old shape.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import (
    NEVER_MATCH,
    canonicalize,
    check_resource_scope,
    effective_resource_targets,
    is_pattern,
    matches_pattern,
)
from entity_core.capability.token import Grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.utils.identity import is_peer_id
from entity_core.utils.path import validate_absolute_path

#: A syntactically valid peer id: 46 Base58 characters (the alphabet excludes
#: ``0 O I l``).
PEER = "2KTestCanonTotaRityPeerJdaaaaaaaaaaaaaaaaaaaaa"

#: 47 characters — legal per §5.4, which sets 46 as a **minimum** and says in
#: terms that a longer algorithm produces a longer id.
LONGER_PEER = PEER + "a"

RESERVED = ["./escape", "../escape", "*/anything"]


def _cap(include: list[str], exclude: list[str] | None = None) -> dict:
    grant: dict = {
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": include},
    }
    if exclude is not None:
        grant["resources"]["exclude"] = exclude
    return {"grants": [grant]}


class TestCanonicalizeIsTotal:
    """The return domain is a canonical path OR the sentinel — never an error,
    never the malformed input itself."""

    @pytest.mark.parametrize("path", RESERVED)
    def test_a_reserved_or_ambiguous_form_yields_the_sentinel(self, path):
        assert canonicalize(path, PEER) == NEVER_MATCH, (
            f"{path!r} is unrepresentable as a canonical path (§5.4). Passing "
            "it through unchanged leaves safety resting on 'nothing happens to "
            "match it', which is the property 0.8.2.20 withdrew"
        )

    @pytest.mark.parametrize("path", RESERVED)
    def test_it_does_not_raise(self, path):
        """§1.11 fail-closed / F5 — the `chain_malformed_resource_pattern`
        probe. A malformed pattern in a *grant* must produce a verdict, not an
        exception that drops the connection mid-check."""
        canonicalize(path, PEER)  # must not raise

    def test_ordinary_forms_are_untouched(self):
        assert canonicalize("app/data", PEER) == f"/{PEER}/app/data"
        assert canonicalize("*", PEER) == f"/{PEER}/*"
        assert canonicalize(f"/{PEER}/app", PEER) == f"/{PEER}/app"
        assert canonicalize(f"entity://{PEER}/app", PEER) == f"/{PEER}/app"


class TestTheThreeRuledConsumers:
    """§5.4 names three, and a total function that leaves any of them
    unruled has only moved the hazard."""

    def test_matches_pattern_refuses_the_sentinel_as_the_pattern(self):
        assert matches_pattern(NEVER_MATCH, f"/{PEER}/app/data") is False

    def test_matches_pattern_refuses_the_sentinel_as_the_path(self):
        assert matches_pattern(f"/{PEER}/*", NEVER_MATCH) is False

    def test_the_arm_is_first(self):
        """⭐ The discriminating row for arm ORDER.

        §5.4 states the sentinel arm **first** and says why: the arm below it
        returns True for a bare ``"*"`` operand. A peer that appends the
        sentinel check after the wildcard arm passes every other row in this
        class and answers **True** here — an unmatchable value matching
        everything, which is the inversion the sentinel exists to prevent.
        """
        assert matches_pattern("*", NEVER_MATCH) is False, (
            "the NEVER_MATCH arm must precede the bare-`*` arm"
        )

    def test_validate_absolute_path_errors_on_the_sentinel(self):
        """The designed destination for the diagnostic — unlike a matcher,
        this function's callers have an error channel."""
        assert validate_absolute_path(NEVER_MATCH) is not None

    def test_the_sentinel_is_unreachable_as_a_canonical_path(self):
        """Not prohibited — *unreachable*. `-` is outside the Base58 alphabet
        and the segment is far under 46 characters, so no peer can hold an id
        that produces it, and no path can canonicalize to it by accident."""
        assert is_peer_id(NEVER_MATCH.lstrip("/")) is False
        assert canonicalize("never-match", PEER) == f"/{PEER}/never-match"


class TestR11ThePeerWildcardPatternMatchesNothingAndDoesNotError:
    """§5.4: *"a `*/`-leading pattern in a grant now matches nothing rather
    than raising a diagnostic nobody receives."*"""

    def test_a_star_slash_grant_pattern_grants_nothing(self):
        granted = check_resource_scope(
            _cap(["*/files"]), handler_pattern="*", operation="get",
            resource_targets=[f"/{PEER}/files"], resource_exclude=None,
            local_peer_id=PEER,
        )
        assert granted is False

    def test_a_star_slash_grant_EXCLUDE_denies_EVERYTHING_and_does_not_raise(self):
        """⭐ The same string on the exclude side — and the answer is the
        OPPOSITE of the include side `[flipped 0.8.2.21]`.

        This row asserted ``True`` for one revision, with the reasoning in its
        own docstring: *"an unmatchable exclude carves out nothing, so the
        include still covers."* 0.8.2.21 withdraws that: **the sentinel's
        safety is directional.** Matches-nothing is fail-**closed** in an
        ``include`` (the row above — covers nothing, grants nothing) and
        fail-**OPEN** here, where carving out nothing leaves the grant
        *silently wider than its author wrote*.

        It is the sharpest illustration in this file of why 0.8.2.20's own
        argument was incomplete rather than wrong: the include row and this
        row take the **same string through the same matcher** and must answer
        differently, so no property of the *value* can decide it. Only the
        **position** can, which is why the rule is stated at the scope layer
        and ``matches_pattern`` stays uniform over its operands.

        The *"returns a verdict rather than raising"* half is unchanged and
        still load-bearing (§1.11 fail-closed / F5).
        """
        granted = check_resource_scope(
            _cap(["*"], exclude=["../escape"]), handler_pattern="*",
            operation="get", resource_targets=[f"/{PEER}/files"],
            resource_exclude=None, local_peer_id=PEER,
        )
        assert granted is False, (
            "an unmatchable exclude excludes EVERYTHING (§5.2, 0.8.2.21)"
        )

    def test_teeth_a_well_formed_grant_pattern_still_grants(self):
        assert check_resource_scope(
            _cap(["files/*"]), handler_pattern="*", operation="get",
            resource_targets=[f"/{PEER}/files/doc.txt"], resource_exclude=None,
            local_peer_id=PEER,
        ) is True


class TestG6AMalformedConcreteTargetFailsClosed:
    """§5.2: *"MUST consume the verdict and fail closed — this call previously
    discarded its return and enforced nothing."*"""

    @pytest.mark.parametrize("target", RESERVED)
    def test_a_reserved_target_is_refused(self, target):
        assert check_resource_scope(
            _cap(["*"]), handler_pattern="*", operation="get",
            resource_targets=[target], resource_exclude=None, local_peer_id=PEER,
        ) is False

    def test_a_peer_wildcard_grant_cannot_reach_a_bogus_peer_target(self):
        """⭐ The discriminating row for G6, and the one the sentinel alone
        does not cover.

        ``/short/x`` is absolute and star-free, so ``canonicalize`` returns it
        unchanged — it is **not** ``NEVER_MATCH`` — and its first segment is
        not a peer id. Against an ordinary ``/{peer}/*`` grant nothing matches
        it and the refusal is an accident of prefix comparison; against a
        **peer-wildcard** grant (``/*/*``) the matcher strips the first
        segment whatever it is, the remainder matches, and the target is
        covered by a grant for a peer that cannot exist.

        So this row separates *refused because no pattern matched* from
        *refused because the validator's verdict was consumed*, and it is the
        only configuration in this file that does. It is also where
        ``entity-core-go`` diverges: their ``validConcreteTarget`` checks the
        leading slash and the path characters and **not** the peer_id segment,
        which is the one clause that bites here (routed).
        """
        bogus = "/short/x"
        assert canonicalize(bogus, PEER) == bogus, (
            "precondition: this target is NOT the sentinel — if it were, the "
            "row would be measuring the matcher arm instead of G6"
        )
        assert matches_pattern("/*/*", bogus) is True, (
            "precondition: a peer-wildcard grant DOES match it, so a peer "
            "without the verdict-consumption rule authorizes it"
        )
        assert check_resource_scope(
            _cap(["/*/*"]), handler_pattern="*", operation="get",
            resource_targets=[bogus], resource_exclude=None, local_peer_id=PEER,
        ) is False

    def test_teeth_the_same_grant_still_covers_a_real_foreign_peer(self):
        """Control at one dimension's distance: same ``/*/*`` grant, same
        shape of target, a first segment that IS a peer id."""
        assert check_resource_scope(
            _cap(["/*/*"]), handler_pattern="*", operation="get",
            resource_targets=[f"/{LONGER_PEER}/x"], resource_exclude=None,
            local_peer_id=PEER,
        ) is True

    def test_a_pattern_target_is_exempt_from_the_validator(self):
        """§5.2 validates **concrete** targets only — a pattern target goes
        through pattern matching, not tree access, and `/{peer}/app/*` has no
        business being handed to a peer-id validator."""
        assert is_pattern(f"/{PEER}/app/*") is True
        assert check_resource_scope(
            _cap(["app/*"]), handler_pattern="*", operation="get",
            resource_targets=[f"/{PEER}/app/*"], resource_exclude=None,
            local_peer_id=PEER,
        ) is True


class TestTheSentinelSurvivesTheEffectiveSetReduction:
    """§5.2's ``effective_targets``: *"NEVER_MATCH is not skipped here — it
    cannot be covered by any exclude, so it stays in the list and is refused
    below."*"""

    def test_a_malformed_target_cannot_be_excluded_away(self):
        """Dropping it instead would convert a malformed target into an
        **absent** one — §3.3's ``path_required`` for a request whose defect
        is that its target is not a path."""
        survivors = effective_resource_targets(["../escape"], ["*"], PEER)
        assert survivors == ["../escape"]

    def test_an_ordinary_target_is_still_excluded_away(self):
        assert effective_resource_targets(["app/x"], ["*"], PEER) == []


class TestIsPeerIdIsAMinimumNotAnEquality:
    """§5.4: *"46 is the minimum — no supported algorithm produces fewer
    bytes"*, and *"future algorithms produce longer peer IDs."*"""

    def test_a_longer_peer_id_is_a_peer_id(self):
        assert is_peer_id(LONGER_PEER) is True, (
            "this predicate read `!= 46`. Equality and `< 46` agree on every "
            "peer this cohort has minted, which is why it survived"
        )

    def test_a_shorter_segment_is_not(self):
        assert is_peer_id(PEER[:-1]) is False

    def test_a_non_base58_segment_is_not(self):
        assert is_peer_id("l" * 46) is False  # `l` is outside the alphabet

    def test_the_consequence_a_longer_foreign_path_stays_absolute(self):
        """⭐ Why the equality form failed in the dangerous direction.

        ``extract_peer`` classifies a segment this predicate rejects as *not a
        peer*, so an absolute path naming a foreign peer would be read as a
        peer-relative **local** one — §1.4's address gate answering "local"
        for someone else's namespace. The visible half was a legitimate path
        being refused; this is the half worth the row.
        """
        from entity_core.capability.checking import extract_peer

        assert extract_peer(f"/{LONGER_PEER}/app/data", PEER) == LONGER_PEER


class TestTheThirdConsumerStorageAndTreeAccess:
    """§5.4's third ruled consumer: *"a path that canonicalizes to
    ``NEVER_MATCH`` MUST NOT be stored, used as a storage key, or resolved
    against the tree."*

    .. rubric:: Why the other two consumers do not already cover this

    A reserved path arriving in ``resource.targets`` is refused at the
    dispatch boundary by ``validate_absolute_path`` — that is the row above.
    But §3.2 sanctions taking the path from ``params`` instead (the tree
    handler's documented alternative, with the handler-level check carrying
    the authorization obligation), and **a params path never passes that
    validator at all**. What refused it before this rule was the *matcher*:
    the sentinel matches no grant pattern, so ``check_caller_permission``
    answered DENY and the caller got a **403**.

    That is a refusal, and it is the wrong one. The request is structurally
    unresolvable — a 403 tells a caller its authority is insufficient for a
    path that could not have been resolved under any authority, and (R-27
    clause 4) answers an authorization question the peer was never asked.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("op", ["get", "put"])
    @pytest.mark.parametrize("path", RESERVED)
    async def test_a_params_path_that_cannot_canonicalize_is_400(self, op, path):
        from entity_core.handlers.context import HandlerContext  # noqa: F401
        from entity_core.peer.connection import Connection

        server = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"], resources=["*"],
            )])
            .debug_mode(True)
            .build()
        )
        await server.start("127.0.0.1", 19098)
        try:
            conn = await Connection.connect("127.0.0.1", 19098, Keypair.generate())
            try:
                params: dict = {"path": path}
                if op == "put":
                    params["entity"] = {
                        "type": "probe/thing", "data": {"v": 1},
                    }
                result = await conn.execute(
                    f"entity://{server.peer_id}/system/tree", op,
                    {"type": f"system/tree/{op}-request", "data": params},
                )
            finally:
                conn.close()
                await conn.wait_closed()
        finally:
            await server.stop()

        assert result.status == 400, (
            f"tree:{op} with a params path of {path!r} answered "
            f"{result.status}. The path cannot be canonicalized, so it "
            f"cannot be a storage key or a tree lookup — and a 403 here "
            f"answers an authorization question about a path that does not "
            f"exist in any namespace: {result.result}"
        )
        assert result.result["data"].get("code") == "invalid_path"


class TestTheDesignedDestinationIsTheAdmissionBoundary:
    """§5.4: *"the diagnostic belongs at admission (§6.5), which has a caller
    to answer."* A matcher answers DENY; the wire answers 400."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("target", RESERVED)
    async def test_a_reserved_resource_target_is_refused_at_the_wire(self, target):
        from entity_core.peer.connection import Connection

        server = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"], resources=["*"],
            )])
            .debug_mode(True)
            .build()
        )
        await server.start("127.0.0.1", 19097)
        try:
            conn = await Connection.connect("127.0.0.1", 19097, Keypair.generate())
            try:
                result = await conn.execute(
                    f"entity://{server.peer_id}/system/tree", "get",
                    {"type": "system/tree/get-request", "data": {}},
                    resource={"targets": [target]},
                )
            finally:
                conn.close()
                await conn.wait_closed()
        finally:
            await server.stop()

        assert result.status == 400, (
            f"{target!r} canonicalizes to the sentinel, which fails "
            f"`validate_absolute_path` by construction — the admission "
            f"boundary is where that becomes a caller-visible diagnostic"
        )
        assert result.result["data"].get("code") == "invalid_path", (
            "§3.3 — `invalid_path` is 'structurally invalid anywhere', which "
            "is what a path that cannot be canonicalized is"
        )
