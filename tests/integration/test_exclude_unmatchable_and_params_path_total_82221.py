"""0.8.2.21 — the sentinel is safe in one direction and the exclude is the
other (`H1`), and path validation is a property of the BOUNDARY (`H3`).

Two conformance vectors land here, both wire-observable and both security
vectors:

==================================  ========================================
`CORE-EXCLUDE-UNMATCHABLE-1`        an unmatchable ``exclude`` excludes
                                    EVERYTHING, and a capability carrying
                                    one is INVALID at mint / delegate /
                                    chain-verify
`CORE-PARAMS-PATH-TOTAL-1`          a malformed path carried by ``params``
                                    is refused at the boundary that uses it
==================================  ========================================

.. rubric:: `H1` — why one value needs two opposite answers

0.8.2.20 ruled *"``matches_pattern`` MUST return false when either operand is
``NEVER_MATCH``"* and argued its safety **from the include side only**.
Matches-nothing is fail-**closed** in an ``include`` — covers nothing, so the
grant grants nothing — and fail-**OPEN** in an ``exclude``: it carves out
nothing, so **the grant is silently wider than its author wrote**, with no
error anywhere, because the sentinel is designed not to raise.

The worked case is a plausible spelling, not a contrived one: a granter
writing ``exclude: ["*/secret"]`` for *not `secret`, in any peer's namespace*
gets an exclusion that excludes nothing.

Because the same string through the same matcher must answer differently on
the two sides, **no property of the value can decide it** — only the position
can. So ``matches_pattern`` stays uniform over its operands (it is
transcribed into 46 languages) and the reading is chosen in every ``exclude``
loop, where the position is known.

.. rubric:: Measured here before the fix

All four arms of ``TestTheEvaluationLayer`` returned ALLOW, including the
headline vector. The **fourth** site is this peer's own finding and is not in
0.8.2.21's enumeration of three — see
:class:`TestTheFourthSiteArchDidNotEnumerate`.

.. rubric:: `H3` — a rule stated over channels gets an implementation that
   enumerates channels

§5.4's validation MUST already said *"all tree paths (dispatch, storage,
entity data path-reference fields)"* and §6.7 already named *"URI, resource
targets, params"* — and a pre-validator keyed to the **resource target alone**
was still what this tree had. Measured: ``validate_path_chars`` had exactly
ONE call site in the whole repo (``tree:put``), so

- ``tree:extract`` with ``paths: ["\\x01x"]`` answered **200**, and
- ``tree:merge`` with ``target_prefix: "\\x01x"`` **bound a control character
  as a tree key**.

Python fails soft where go aborted, so the same defect that was a remote DoS
there is silent corruption here — which is why the vector is written against
the **status**, not against the absence of a crash.
"""

from __future__ import annotations

import pytest

from entity_core.capability.checking import (
    NEVER_MATCH,
    check_path_permission,
    check_resource_scope,
    is_unmatchable_pattern,
    matches_scope,
    unmatchable_scope_pattern,
)
from entity_core.crypto.identity import Keypair
from entity_core.handlers.context import HandlerContext
from entity_core.peer import PeerBuilder
from entity_core.protocol.entity import Entity
from entity_core.storage.emit import EmitContext

#: 46 Base58 characters. The alphabet excludes ``0 O I l``, and the first
#: draft of this constant spelled *"Exclude"* — whose lowercase ``l`` is not a
#: Base58 character, so ``is_peer_id`` rejected it and **two unrelated rows
#: failed for a reason that had nothing to do with what they assert**. Pinned
#: by :func:`test_the_fixture_peer_id_is_one_a_peer_could_actually_hold`,
#: because a fixture peer id is a claim about the production write path and it
#: is the one claim in a test nobody re-checks.
PEER = "2KTestUnmatchabeExcPeerJdaaaaaaaaaaaaaaaaaaaaa"

#: The three forms ``canonicalize`` maps to the sentinel (§5.4). Reserved
#: directory-relative prefixes and the ambiguous bare peer wildcard.
UNMATCHABLE = ["*/secret", "../escape", "./escape"]

OPEN_GRANTS = [{"handlers": {"include": ["*"]},
                "resources": {"include": ["*"]},
                "operations": {"include": ["*"]}}]


def _cap(include: list[str], exclude: list[str] | None = None) -> dict:
    grant: dict = {
        "handlers": {"include": ["*"]},
        "operations": {"include": ["*"]},
        "resources": {"include": include},
    }
    if exclude is not None:
        grant["resources"]["exclude"] = exclude
    return {"grants": [grant]}


# ---------------------------------------------------------------------------
# H1 — the evaluation layer
# ---------------------------------------------------------------------------

class TestTheEvaluationLayer:
    """`CORE-EXCLUDE-UNMATCHABLE-1`, first arm: an unmatchable ``exclude``
    excludes EVERYTHING."""

    def test_the_headline_vector(self):
        """⭐ The vector as §9.1 writes it: ``resources: {include: ["/*/*"],
        exclude: ["*/secret"]}`` requesting ``/{peer}/secret`` MUST deny.

        A peer on the 0.8.2.20 rule **allows** it, because ``*/``-leading
        canonicalizes to ``NEVER_MATCH`` and an exclude that matches nothing
        carves out nothing. Measured ALLOW here before the fix.
        """
        assert check_resource_scope(
            _cap(["/*/*"], exclude=["*/secret"]),
            handler_pattern="*", operation="get",
            resource_targets=[f"/{PEER}/secret"], resource_exclude=None,
            local_peer_id=PEER,
        ) is False

    def test_the_discriminating_control_a_well_formed_exclude(self):
        """⭐ §9.1 names this arm and says why it is required: *"without that
        arm the row cannot tell a working exclusion from a peer that denies
        everything."*

        A peer that answers DENY to everything passes the headline row for a
        reason unrelated to the rule.
        """
        assert check_resource_scope(
            _cap(["/*/*"], exclude=["/*/secret"]),
            handler_pattern="*", operation="get",
            resource_targets=[f"/{PEER}/secret"], resource_exclude=None,
            local_peer_id=PEER,
        ) is False

    def test_teeth_an_unrelated_target_is_still_GRANTED(self):
        """The other half of the same control — the fix must not be
        "deny everything". This is the row that fails a peer which reads the
        new arm as an unconditional refusal."""
        assert check_resource_scope(
            _cap(["/*/*"], exclude=["/*/secret"]),
            handler_pattern="*", operation="get",
            resource_targets=[f"/{PEER}/public"], resource_exclude=None,
            local_peer_id=PEER,
        ) is True

    @pytest.mark.parametrize("bad", UNMATCHABLE)
    def test_matches_scope_the_widest_site(self, bad):
        """Site 1 — reached by **every dimension of every grant**, so it is
        the widest of the arms."""
        assert matches_scope({"include": ["*"], "exclude": [bad]},
                             f"/{PEER}/secret") is False

    def test_the_include_side_is_UNCHANGED(self):
        """The direction that was already fail-closed stays fail-closed, and
        for the *opposite* structural reason: an unmatchable include covers
        nothing, so the grant grants nothing.

        Kept as a row because the two sides taking the same string through the
        same matcher to opposite verdicts is the entire content of `H1`.
        """
        assert check_resource_scope(
            _cap(["*/files"]), handler_pattern="*", operation="get",
            resource_targets=[f"/{PEER}/files"], resource_exclude=None,
            local_peer_id=PEER,
        ) is False


class TestTheFourthSiteArchDidNotEnumerate:
    """0.8.2.21 enumerates THREE sites — ``matches_scope``'s exclude loop,
    ``check_resource_scope``'s concrete arm, and the pattern arm.

    ``check_path_permission`` (§6.3) is a **fourth**, and it is the one
    0.8.2.20 promoted *from defense-in-depth to the enforcement* for any
    subject derived after dispatch. Fixing only the dispatch-level sites
    leaves the fail-open live on exactly the path that carries the guarantee
    when the dispatch-level check has been made vacuous by caller input.

    Routed as **SA-PY-52**.
    """

    @pytest.mark.parametrize("bad", UNMATCHABLE)
    def test_the_handler_level_check_denies(self, bad):
        assert check_path_permission(
            _cap(["*"], exclude=[bad]), operation="get",
            path=f"/{PEER}/secret", local_peer_id=PEER, handler_pattern="system/tree",) is False

    def test_teeth_the_handler_level_check_still_grants(self):
        assert check_path_permission(
            _cap(["*"], exclude=[f"/{PEER}/secret"]), operation="get",
            path=f"/{PEER}/public", local_peer_id=PEER, handler_pattern="system/tree",) is True


class TestThePredicate:

    def test_the_fixture_peer_id_is_one_a_peer_could_actually_hold(self):
        """The fixture pinned against the production predicate.

        Every row in this file that names a concrete target depends on
        ``PEER`` being a peer id ``validate_absolute_path`` accepts — the `G6`
        arm refuses a target whose first segment is not one, so an invalid
        constant makes rows fail (or, worse, *pass*) for a reason unrelated to
        what they assert. It did: the first draft spelled *"Exclude"* and the
        lowercase ``l`` is outside Base58.
        """
        from entity_core.utils.identity import is_peer_id

        assert is_peer_id(PEER), f"{PEER!r} is not a peer id any peer could hold"
        assert len(PEER) >= 46

    def test_the_unmatchable_verdict_is_frame_independent(self):
        """``is_unmatchable_pattern`` takes no frame, and this is why that is
        exact rather than an approximation: ``canonicalize`` decides the
        sentinel on the ``./`` / ``../`` / ``*/`` **prefix alone** and never
        reads the peer id.

        A future edit that made the verdict frame-dependent would silently
        turn a total predicate into one answering for the wrong peer.
        """
        from entity_core.capability.checking import canonicalize

        other = "9" * 46
        for bad in UNMATCHABLE:
            assert canonicalize(bad, PEER) == NEVER_MATCH
            assert canonicalize(bad, other) == NEVER_MATCH
            assert is_unmatchable_pattern(bad) is True

    def test_ordinary_patterns_are_matchable(self):
        for good in ["*", "/*/*", "/*/secret", "files/*", f"/{PEER}/x"]:
            assert is_unmatchable_pattern(good) is False


# ---------------------------------------------------------------------------
# H1 — the authoring layer
# ---------------------------------------------------------------------------

class TestTheAuthoringLayer:
    """`CORE-EXCLUDE-UNMATCHABLE-1`, second arm: minting or delegating such a
    capability MUST be refused (``400 invalid_path``).

    §5.4: *"a grant is authored once and evaluated thousands of times, and the
    authoring step is the only moment the **granter** — the party the widening
    harms — can be told."* It is a MUST rather than a MAY because one
    conformant peer refusing the capability and another honouring a grant
    wider than written are **different authorization decisions on the same
    bytes**.
    """

    @pytest.mark.parametrize("bad", UNMATCHABLE)
    def test_an_unmatchable_exclude_is_refused(self, bad):
        assert unmatchable_scope_pattern(
            [{"resources": {"include": ["*"], "exclude": [bad]}}]
        ) == ("resources", "exclude", bad)

    @pytest.mark.parametrize("bad", UNMATCHABLE)
    def test_an_unmatchable_INCLUDE_is_also_refused(self, bad):
        """The MUST is written over *any* scope pattern, not only excludes.
        An unmatchable include is dead authority its author will debug later;
        the security argument is the exclude side, the rule is both."""
        assert unmatchable_scope_pattern(
            [{"resources": {"include": [bad]}}]
        ) == ("resources", "include", bad)

    def test_the_handlers_dimension_is_covered_too(self):
        """``handlers`` is path-scope and canonicalized, so it can carry the
        sentinel exactly as ``resources`` can. A check written only against
        ``resources`` — the dimension the worked example uses — passes every
        other row here."""
        assert unmatchable_scope_pattern(
            [{"handlers": {"include": ["*"], "exclude": ["*/admin"]}}]
        ) == ("handlers", "exclude", "*/admin")

    def test_a_well_formed_grant_is_admitted(self):
        assert unmatchable_scope_pattern(OPEN_GRANTS) is None
        assert unmatchable_scope_pattern(
            [{"resources": {"include": ["/*/*"], "exclude": ["/*/secret"]}}]
        ) is None

    def test_an_ancestor_grant_is_reached(self):
        """The walk is over every grant, not just the first — a capability
        with one clean grant and one carrying the sentinel is invalid."""
        assert unmatchable_scope_pattern(
            [{"resources": {"include": ["a/*"]}},
             {"resources": {"include": ["*"], "exclude": ["../escape"]}}]
        ) == ("resources", "exclude", "../escape")


class TestTheAuthoringRuleIsINSTALLED:
    """⭐ The rows above prove the **predicate**; these prove it is **wired**.

    A correct predicate nobody calls is the `G6` shape — *"a validator whose
    verdict is dropped enforces nothing"* — and the mutation run is what
    surfaced the gap: deleting the call from ``_handle_request`` reddened
    nothing in the first draft of this file, because every authoring row here
    tested ``unmatchable_scope_pattern`` directly.

    ``400 invalid_path``, per §5.4 at a §6.2 authoring surface.

    These reuse ``test_capability_handler``'s own ``_ctx``. The first draft
    hand-rolled one and both rows failed on the FIXTURE, not the rule:
    ``delegate`` is same-peer-only in v1 (a mismatched ``remote_peer_id``
    answers `501` before reaching any grant check) and ``request`` refuses
    with `403` unless the context carries a caller identity hash. A
    hand-rolled context is a claim about the shape production supplies.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("op", ["request", "delegate"])
    async def test_the_authoring_surface_refuses(self, peer, op):
        from entity_handlers.capability import (
            CAPABILITY_HANDLER_PATTERN,
            capability_handler,
        )
        from tests.integration.test_capability_handler import _ctx

        params = {"data": {"grants": [{
            "handlers": {"include": ["system/tree"]},
            "resources": {"include": ["*"], "exclude": ["*/secret"]},
            "operations": {"include": ["get"]},
        }]}}
        if op == "delegate":
            params["data"]["parent"] = b"\x00" * 33
        result = await capability_handler(
            CAPABILITY_HANDLER_PATTERN, op, params, _ctx(peer),
        )
        assert result["status"] == 400, (
            f"{op} accepted a grant whose exclude carves out nothing "
            f"(got {result['status']}) — the granter is the party this "
            "widening harms and authoring is the only moment they can be "
            "told (\u00a75.4)"
        )
        assert result["result"]["data"]["code"] == "invalid_path"

    @pytest.mark.asyncio
    async def test_the_refusal_precedes_the_parent_lookup(self, peer):
        """``delegate`` is refused on the GRANT, not by falling through to a
        bogus ``parent``. The row above passes a zero hash that resolves to no
        token, so without this control its `400` could be the parent check
        answering — a different code, but only by luck of ordering."""
        from entity_handlers.capability import (
            CAPABILITY_HANDLER_PATTERN,
            capability_handler,
        )
        from tests.integration.test_capability_handler import _ctx

        result = await capability_handler(
            CAPABILITY_HANDLER_PATTERN, "delegate",
            {"data": {"parent": b"\x00" * 33, "grants": [{
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["*"], "exclude": ["/*/secret"]},
                "operations": {"include": ["get"]},
            }]}},
            _ctx(peer),
        )
        assert result["result"]["data"]["code"] != "invalid_path", (
            "a well-formed grant must get past the unmatchable check and be "
            "refused for its parent instead"
        )

    @pytest.mark.asyncio
    async def test_teeth_a_well_formed_request_still_mints(self, peer):
        """Without this the rows above pass on a peer whose `request` is
        simply broken."""
        from entity_handlers.capability import (
            CAPABILITY_HANDLER_PATTERN,
            capability_handler,
        )
        from tests.integration.test_capability_handler import _ctx

        result = await capability_handler(
            CAPABILITY_HANDLER_PATTERN, "request",
            {"data": {"grants": [{
                "handlers": {"include": ["system/tree"]},
                "resources": {"include": ["*"], "exclude": ["/*/secret"]},
                "operations": {"include": ["get"]},
            }]}},
            _ctx(peer),
        )
        assert result["status"] == 200, repr(result)


class TestChainVerificationIsTheThirdMoment:
    """§5.4 names three moments — mint, delegate, **and chain verification**.

    This is the one that matters cross-impl, and it is why the rule is a
    `[MUST]` rather than a `[MAY]`: the other two bind only capabilities
    *this* peer authored. A capability minted by a **foreign** granter — a
    peer still on 0.8.2.20, or one that never implements the authoring half —
    arrives over the wire already signed, and chain verification is the only
    place it can be refused.

    Checked over **every link**, not just the leaf: an unmatchable ``exclude``
    on an ancestor hides a widening that every descendant inherits.
    """

    def _chain(self, grants):
        from entity_core.capability.token import CapabilityToken, Grant

        kp = Keypair.generate()
        from entity_core.protocol.auth import create_identity_entity

        ident = create_identity_entity(kp)
        ihash = ident.compute_hash()
        token = CapabilityToken(
            grants=grants, granter=ihash, grantee=ihash, created_at=1,
        )
        from entity_core.utils.ecf import compute_ecf_hash

        ent = token.to_entity()
        cap = dict(ent)
        cap["content_hash"] = compute_ecf_hash(
            {"type": ent["type"], "data": ent["data"]}
        )
        return kp, cap, {ihash: ident.to_dict()}

    @pytest.mark.parametrize("bad", UNMATCHABLE)
    def test_a_foreign_minted_capability_is_refused_at_verification(self, bad):
        from entity_core.capability.delegation import verify_capability_chain
        from entity_core.capability.token import Grant

        kp, cap, included = self._chain([
            Grant.create(handlers=["*"], resources=["*"], operations=["*"],
                         resource_exclude=[bad]),
        ])
        result = verify_capability_chain(
            cap, lambda h: included.get(h), lambda h: None, kp.peer_id,
        )
        assert not result.valid
        assert result.error_code == "invalid_path", result

    def test_teeth_a_well_formed_exclude_gets_PAST_this_check(self):
        """The control. This chain is refused for an unrelated reason (no
        signature), and what the row asserts is that the reason is **not**
        ours — without it, a check that refused every chain would score green
        on all three rows above."""
        from entity_core.capability.delegation import verify_capability_chain
        from entity_core.capability.token import Grant

        kp, cap, included = self._chain([
            Grant.create(handlers=["*"], resources=["*"], operations=["*"],
                         resource_exclude=[f"/{PEER}/secret"]),
        ])
        result = verify_capability_chain(
            cap, lambda h: included.get(h), lambda h: None, kp.peer_id,
        )
        assert result.error_code != "invalid_path", result


class TestTheIdScopeDimensionsAreNotCovered:
    """``operations`` and ``peers`` are **id-scope** — compared as literal
    identifiers, and §5.2 says in terms that *"an id dimension canonicalized
    is a conformance defect."* ``canonicalize`` is therefore never applied to
    them, and 0.8.2.21's MUST — written as ``canonicalize(pattern) ==
    NEVER_MATCH`` — cannot bind them.

    **An id-scope exclude can nonetheless match nothing** (``*/foo`` is a
    literal no operation name can equal), which is the same fail-open shape
    one dimension over and is **not ruled anywhere**.

    This row pins today's answer rather than settling it: inventing a refusal
    would refuse capabilities `entity-core-go` and `entity-core-rust` mint,
    manufacturing a cross-impl divergence out of a spec gap — the error this
    repo exists to find. Routed as **SA-PY-53**; this row flips when it rules.
    """

    def test_an_id_scope_pattern_is_not_refused_at_authoring(self):
        assert unmatchable_scope_pattern(
            [{"operations": {"include": ["*"], "exclude": ["*/foo"]}}]
        ) is None, (
            "SA-PY-53 is open: if this now refuses, the id-scope half was "
            "ruled and this row plus `_PATH_SCOPE_DIMENSIONS` move together"
        )


# ---------------------------------------------------------------------------
# H3 — CORE-PARAMS-PATH-TOTAL-1
# ---------------------------------------------------------------------------

OPEN = {"grants": OPEN_GRANTS}

#: Refusable shapes. ``\x01x`` is the vector §9.1 names; the reserved-prefix
#: forms are here because they were refused only BY ACCIDENT before the fix —
#: as `403 capability_denied`, the sentinel making them match no grant, which
#: is a refusal resting on the authorization check rather than the validator.
MALFORMED_PARAM_PATHS = ["\x01x", "../escape", "./escape", "*/anything"]


@pytest.fixture
def peer():
    return PeerBuilder().with_keypair(Keypair.generate()).with_all_handlers().build()


def _ctx(peer) -> HandlerContext:
    return HandlerContext(
        local_peer_id=peer.keypair.peer_id,
        remote_peer_id="test-remote",
        handler_grant=OPEN,
        caller_capability=OPEN,
        # §6.3 (0.8.2.23): REQUIRED and fail-closed. These rows drive
        # `system/tree`'s `extract` and `merge`, so that is the frame the
        # dispatcher would supply.
        handler_pattern="system/tree",
        emit_pathway=peer.emit_pathway,
    )


class TestParamsCarriedPathsAreValidatedAtTheBoundary:
    """*"Every path that reaches the location index, the content store, or the
    tree is validated at that boundary — whatever carried it."*

    §9.1: the row **cannot be a false pass** — *"a peer that pre-validates
    only the resource target answers 200 or dies; a peer that validates at the
    boundary answers 400."*
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", MALFORMED_PARAM_PATHS)
    async def test_extract_refuses_a_malformed_paths_entry(self, peer, bad):
        """``tree:extract``'s ``paths[]`` — an entry of a caller-supplied
        array, which no resource-target pre-validator ever sees."""
        peer.emit_pathway.emit("data/ok", Entity(type="t/d", data={"a": 1}),
                               EmitContext.bootstrap())
        tree = peer.handlers.find_handler("system/tree")
        r = await tree("system/tree", "extract",
                       {"data": {"prefix": "data/", "paths": [bad]}}, _ctx(peer))
        assert r["status"] == 400
        assert r["result"]["data"]["code"] == "invalid_path"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", MALFORMED_PARAM_PATHS)
    async def test_merge_refuses_a_malformed_target_prefix(self, peer, bad):
        """``tree:merge``'s ``target_prefix`` — a path the handler builds by
        **concatenation** from a caller-supplied params field, and a WRITE.
        Before the fix ``\\x01x`` bound a control character as a tree key."""
        peer.emit_pathway.emit("src/f1", Entity(type="t/d", data={"a": 1}),
                               EmitContext.bootstrap())
        tree = peer.handlers.find_handler("system/tree")
        ex = await tree("system/tree", "extract",
                        {"data": {"prefix": "src/"}}, _ctx(peer))
        assert ex["status"] == 200
        r = await tree("system/tree", "merge", {"data": {
            "source_envelope": ex["result"],
            "source_prefix": "src/",
            "target_prefix": bad,
        }}, _ctx(peer))
        assert r["status"] == 400
        assert r["result"]["data"]["code"] == "invalid_path"

    @pytest.mark.asyncio
    async def test_the_control_character_never_reaches_the_tree(self, peer):
        """The property, not the status. A peer could answer 400 and have
        already written — and in Python the write is the *whole* harm, since
        nothing aborts."""
        peer.emit_pathway.emit("src/f1", Entity(type="t/d", data={"a": 1}),
                               EmitContext.bootstrap())
        tree = peer.handlers.find_handler("system/tree")
        ex = await tree("system/tree", "extract",
                        {"data": {"prefix": "src/"}}, _ctx(peer))
        await tree("system/tree", "merge", {"data": {
            "source_envelope": ex["result"], "source_prefix": "src/",
            "target_prefix": "\x01x",
        }}, _ctx(peer))
        et = peer.emit_pathway.entity_tree
        bound = [u for u in et.list_prefix(et.normalize_uri("")) if "\x01" in u]
        assert bound == [], f"control character bound as a tree key: {bound!r}"

    @pytest.mark.asyncio
    async def test_teeth_a_well_formed_extract_and_merge_still_work(self, peer):
        """The control that keeps every row above attributable — without it a
        peer that refuses all of ``extract`` and ``merge`` scores green."""
        peer.emit_pathway.emit("src/f1", Entity(type="t/d", data={"a": 1}),
                               EmitContext.bootstrap())
        tree = peer.handlers.find_handler("system/tree")
        ex = await tree("system/tree", "extract",
                        {"data": {"prefix": "src/", "paths": ["f1"]}}, _ctx(peer))
        assert ex["status"] == 200
        r = await tree("system/tree", "merge", {"data": {
            "source_envelope": ex["result"], "source_prefix": "src/",
            "target_prefix": "dst/",
        }}, _ctx(peer))
        assert r["status"] == 200
        assert r["result"]["data"]["applied"] == 1

    @pytest.mark.asyncio
    async def test_the_unit_is_the_callers_ENTRY_not_the_joined_path(self, peer):
        """⭐ The row that separates a correct fix from a plausible one.

        Validating ``full_prefix + path`` instead of the entry lets a reserved
        form straight through: ``canonicalize``'s ``./`` / ``../`` / ``*/``
        test is **anchored at the start of the string**, so concatenation
        moves the reserved prefix into the interior where nothing looks for
        it. Measured — the first draft of this fix validated the joined path
        and ``paths: ["../escape"]`` still answered **200**.
        """
        from entity_handlers._common import unresolvable_tree_path

        joined = f"/{PEER}/data/" + "../escape"
        assert unresolvable_tree_path(joined, PEER) is None, (
            "the joined form is NOT refusable — which is exactly why the "
            "entry is the unit that must be validated"
        )
        assert unresolvable_tree_path("../escape", PEER) is not None
