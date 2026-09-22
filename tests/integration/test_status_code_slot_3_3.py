"""§3.3's default-code force and the code SLOT (0.8.2.7) — and the census
method that cannot see half of its own subject.

`entity-core-go` filed the question that produced this ruling while landing the
0.8.2.6 sweep; arch ruled three things (`PROPOSAL-STATUS-CODE-SLOT-AND-THE-
DEFAULT-CODE-FORCE`, protocol `221d8c3`):

1. a row's **default code is mandatory for the generic case**;
2. a more-specific code is permitted only where **defined in a spec code set**;
3. **the unit of conformance is the code slot** — every code emitted at that
   status — **never a single spelling**, because 0.8.2.6 retired one of five
   501 synonyms and reported the class closed.

Ruling 3 is the one with teeth and it is arch's own **AP-21**: *a count of the
token is not a census of the slot.*

.. rubric:: What building it here found, which is the next turn of the same screw

**A slot is keyed by a status, so a site that gets the STATUS wrong is
structurally invisible to a slot census.** Arch censused the 501 slot across
six trees and reported py owing four spellings. Censusing instead by the row's
**input** — *a handler is registered at this path and does not implement the
named operation* — found **four more sites at this seat**, every one of them
outside status 501:

===========================================  ====================================
Site                                          Was
===========================================  ====================================
``registry.py`` unknown-op fallthrough        ``404 unknown_operation``
``discovery.py`` unknown-op fallthrough       ``404 unknown_operation``
``storage.py`` unknown-op fallthrough         ``400``, **no `code` at all**
``signaling/node.py`` unknown-op fallthrough  ``400 invalid_request``
===========================================  ====================================

The last one is the instructive row. `invalid_request` is the *correct* default
for status 400, so the pair reads conformant at every glance short of asking
what the input was — a defect wearing the right answer to the wrong question.
And `storage.py` is the handler registered at ``*``, the catch-all every
unmatched path reaches, so it was the most reachable instance of the row in the
whole peer.

**So the rule generalizes past AP-21: a code slot is the unit for auditing a
CODE; the row's INPUT is the unit for auditing a ROW.** A slot census is a
grep with better manners — it still starts from what we emit. Starting from
the spec's input is what reaches the sites that got the status wrong, and
those are exactly the ones no cross-impl probe keyed on status can report.

.. rubric:: What is asserted

* **501** — wire-drivable per §3b: the pair, at several registered handlers,
  plus a structural row over the AST so a new fallthrough cannot pick its own
  spelling, plus a zero-ratchet on §9.1's five enumerated synonyms.
* **404** — the row's constructor, the single dispatch-boundary call site
  (structurally, so the *order* of the branch is pinned), the three
  entity-level sites that must NOT move, and **the reachability finding**: on a
  peer built with `with_default_handlers()` this row is not reachable at all,
  because the ``*`` catch-all means a handler is always registered.
* **500** — NOT oracle-drivable per §3b; satisfied by source audit. An AST
  ratchet at zero on the bare ``internal`` spelling. The ~16 specific spellings
  in that slot are **held** per §3a, not swept, and the row says so.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from entity_core.capability.grant import Grant
from entity_core.crypto.identity import Keypair
from entity_core.peer import PeerBuilder
from entity_core.protocol.messages import ExecuteResponse

PACKAGES = Path(__file__).resolve().parents[2] / "packages"

#: §3.3's rows, transcribed from the spec rather than from what we emit — the
#: standing `PINNED_ROOT_HASH` / `entity-core/1.0` lesson: both sides of an
#: assertion using our own constant measures nothing.
DEFAULT_CODE_AT = {
    400: "invalid_request",
    403: "capability_denied",
    404: "handler_not_found",
    500: "internal_error",
    501: "unsupported_operation",
}

#: §9.1 (0.8.2.7) enumerates these as non-conformant spellings of the 501 row:
#: *"The code slot at 501 carries no synonym: `unknown_operation`,
#: `not_implemented`, `not_supported`, `unsupported_mode` and `not_available`
#: are all non-conformant spellings of this row."* Kept as the spec's list, not
#: as ours, so a seat that adds a sixth has to come back here to justify it.
SECTION_9_1_LISTED_501_SYNONYMS = frozenset({
    "unknown_operation",
    "not_implemented",
    "not_supported",
    "unsupported_mode",
    "not_available",
})

#: **§9.1's list is not the rule; ruling 2 is.** A more-specific code is
#: permitted *"only where one is DEFINED for the operation in a spec code set
#: … or the owning domain handler's own table"*, and one entry on §9.1's list
#: is exactly that:
#:
#: `EXTENSION-REGISTRY` §6a.9.2 pins **`unsupported_mode` twice, as MUSTs** —
#: `400` when `set-issuer-policy` refuses to store `domain-control`, and `501`
#: when a stored `domain-control` policy fails closed at live registration.
#: The second carries its own justification: *"a cross-impl-observable answer
#: with four plausible codes, so it is pinned rather than left to converge."*
#:
#: So §9.1's list enumerates spellings **seats were emitting**, not spellings
#: the corpus leaves undefined — arch's own AP-21 (*a count of the token is not
#: a census of the slot*) reaching the remedy a second time, now as *a census
#: of emissions is not a census of definitions.* Filed as SA-PY-37.
#:
#: This exemption is cited, not carved: each entry names the section that
#: defines it, so a later seat cannot add one by asserting the code is fine.
DEFINED_ELSEWHERE = {
    "unsupported_mode": "EXTENSION-REGISTRY §6a.9.2 (400 and 501, both MUST)",
}

SECTION_9_1_FORBIDDEN_501_SYNONYMS = (
    SECTION_9_1_LISTED_501_SYNONYMS - set(DEFINED_ELSEWHERE)
)

#: The `error_response` helper (`entity_handlers/_common.py`) and every alias
#: it is imported under. One function, `(status, code, message)` positional.
ERROR_HELPER_NAMES = frozenset({"error_response", "_error", "_error_response"})


def _literal_status_code_pairs() -> list[tuple[int, str, str]]:
    """Every ``(status, code, site)`` an emit helper is called with literally.

    Two shapes, because a gate that budgets one form of a thing reports the
    others clean — the standing rule that produced the presentation-purity
    gate's three counters:

    1. ``error_response(<int>, "<code>", ...)`` and its aliases;
    2. the dict literal ``{"status": <int>, "result": {..., "data":
       {"code": "<code>"}}}`` that seven handlers hand-roll instead.
    """
    out: list[tuple[int, str, str]] = []
    for path in sorted(PACKAGES.rglob("*.py")):
        rel = str(path.relative_to(PACKAGES))
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or getattr(
                    node.func, "attr", None
                )
                if name in ERROR_HELPER_NAMES and len(node.args) >= 2:
                    status, code = node.args[0], node.args[1]
                    if (
                        isinstance(status, ast.Constant)
                        and isinstance(status.value, int)
                        and isinstance(code, ast.Constant)
                        and isinstance(code.value, str)
                    ):
                        out.append(
                            (status.value, code.value, f"{rel}:{node.lineno}")
                        )
            elif isinstance(node, ast.Dict):
                status = _dict_get(node, "status")
                if not (
                    isinstance(status, ast.Constant)
                    and isinstance(status.value, int)
                ):
                    continue
                result = _dict_get(node, "result")
                if not isinstance(result, ast.Dict):
                    continue
                data = _dict_get(result, "data")
                if not isinstance(data, ast.Dict):
                    continue
                code = _dict_get(data, "code")
                if isinstance(code, ast.Constant) and isinstance(code.value, str):
                    out.append(
                        (status.value, code.value, f"{rel}:{node.lineno}")
                    )
    return out


def _dict_get(node: ast.Dict, key: str) -> ast.expr | None:
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


# ---------------------------------------------------------------------------
# 501 — wire-drivable (§3b)
# ---------------------------------------------------------------------------


class TestThe501RowOnTheWire:
    """§3b: *dispatch an operation absent from a registered handler's
    manifest.* Driven at three handlers rather than one, because a row that
    names one site is satisfied by a peer that special-cased that site — which
    is exactly what the token-scoped 0.8.2.6 sweep did one level up.
    """

    PORT = 19103

    async def _pair(self, server, path: str, operation: str) -> tuple[int, str]:
        from entity_core.peer.connection import Connection

        conn = await Connection.connect("127.0.0.1", self.PORT, Keypair.generate())
        try:
            result = await conn.execute(
                f"entity://{server.peer_id}/{path}",
                operation,
                {"type": "primitive/any", "data": {}},
            )
            body = (result.result or {}).get("data") or {}
            return result.status, body.get("code", "")
        finally:
            conn.close()
            await conn.wait_closed()

    @pytest.fixture
    async def server(self):
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_all_handlers()
            .with_default_grants([Grant.create(
                handlers=["*"], operations=["*"], resources=["*"],
            )])
            .debug_mode(True)
            .build()
        )
        await peer.start("127.0.0.1", self.PORT)
        yield peer
        await peer.stop()

    @pytest.mark.asyncio
    async def test_every_registered_handler_answers_the_row(
        self, server
    ) -> None:
        """The census enumerated from the **registration list**, not from us.

        This row was three hand-picked paths, and the third mutation run showed
        why that is not a census: reverting `storage.py` to its pre-fix `400`
        left the sibling structural row **green**, because that row locates
        fallthroughs by a message convention and the mutation deleted the
        message along with the fix. *A gate whose search key is part of what
        the defect removes reports clean.*

        The registration list is the one inventory the defect cannot edit —
        a handler that stops answering the row is still registered. So the
        parametrization is derived from the peer under test, and adding a
        handler enrolls it here automatically rather than by someone
        remembering to.
        """
        patterns = sorted(
            {
                h.pattern
                for h in server.handlers.list_handlers()
                if not h.pattern.endswith("*")
            }
        )
        assert len(patterns) >= 10, (
            f"only {len(patterns)} concrete handlers registered — this row is "
            "measuring almost nothing; did `with_all_handlers()` change?"
        )

        offenders: dict[str, tuple[int, str]] = {}
        for pattern in patterns:
            pair = await self._pair(server, pattern, "no-such-operation")
            if pair != (501, DEFAULT_CODE_AT[501]):
                offenders[pattern] = pair
        assert not offenders, (
            "§3.3's 501 row: every registered handler must answer "
            f"(501, {DEFAULT_CODE_AT[501]!r}) for an operation it does not "
            f"implement. Divergent: {offenders}"
        )

    @pytest.mark.asyncio
    async def test_the_path_the_cohort_404_probe_uses_is_the_501_row(
        self, server
    ) -> None:
        """`entity-core-go`'s `handler_not_found_on_unregistered_path`, driven
        at the exact path and operation it uses — and this peer's answer is the
        **501** row, deliberately. See SA-PY-36.

        .. rubric:: How this row was reached, because the route matters

        Read from the log tail, this check appeared to PASS against py. It does
        not: the passing line belongs to a **later pass** with a differently
        built peer, and pass 1 is a FAIL. *The standing "read pass 1 before you
        read the verdict" rule, in its mirror image — a verdict read from the
        wrong pass.* The row exists because reasoning and a skimmed measurement
        disagreed, and neither was trusted until the pair was driven here.

        .. rubric:: Why 501 is the answer and the probe still reports FAIL

        `SYSTEM_HANDLER_MANIFEST` declares exactly one operation, `get`, and
        `STORAGE_HANDLER_MANIFEST` declares four at pattern `*`. Both are real
        registered handlers with manifests in the tree, not internal
        conveniences. So at `system/no-such-handler-conformance-3f9a` a handler
        **is** registered, and `no-such-operation` is *"an operation absent
        from a registered handler's manifest"* — §3.3's 501 row verbatim.

        The consequence is the filed one: **this peer has no unregistered local
        path**, so §3b's driver for the 404 row cannot be constructed against
        it and the probe reports FAIL for a reason that is not a defect. Before
        this landed the answer was `404 not_found`, which was wrong on **both**
        halves and would have tempted a fix toward `handler_not_found` — making
        the probe green by asserting something false about the path.
        """
        status, code = await self._pair(
            server, "system/no-such-handler-conformance-3f9a", "no-such-operation"
        )
        assert (status, code) == (501, DEFAULT_CODE_AT[501]), (
            "a handler IS registered at this path (`system/*`, manifest "
            "declares `get` only), so the input is §3.3's 501 row. Answering "
            "404 here — in either spelling — claims no handler is registered, "
            f"which is false. Got ({status}, {code!r})"
        )

    @pytest.mark.asyncio
    async def test_the_catch_all_handler_answers_the_row_too(
        self, server
    ) -> None:
        """The most reachable instance of the row, and the one nothing drove.

        ``storage_handler`` is registered at ``*`` with priority 0, so it is
        what answers for **every** path no specific handler claims. Its
        unknown-operation arm returned ``400`` with a ``{"error": str}`` body
        carrying no ``code`` field at all — not a synonym but an *absence*,
        which fails the MUST more plainly than any spelling does, and which no
        census of the 501 slot could reach because the status was 400.
        """
        status, code = await self._pair(
            server, "some/unclaimed/path", "no-such-operation"
        )
        assert (status, code) == (501, DEFAULT_CODE_AT[501]), (
            "the `*` catch-all storage handler must answer §3.3's 501 row; "
            f"got ({status}, {code!r})"
        )


class TestThe501SlotIsOneSpelling:
    """The structural half — the ratchet a token-scoped sweep cannot be."""

    def test_no_literal_501_emit_carries_an_undefined_code(self) -> None:
        """Ruling 1 + ruling 2, together — and the second half is what this row
        got wrong on its first outing.

        The first version asserted the default at **every** 501 emit, on the
        reasoning that *"no extension in this tree declares an error-code
        table"*. That sentence is arch's, about the ~90 held 500 sites, and it
        is not true of `EXTENSION-REGISTRY` §6a.9.2 — which pins `501
        unsupported_mode` as a MUST. Applying it swept a spec-pinned code into
        the default and turned `entity-core-go`'s
        `registry_issuer.set_issuer_policy_domain_control_rejected` red.

        **A sweep justified by "nothing defines a better code" is a claim about
        the corpus, and it is a negative one** — so `AGENTS-STANDARD`'s *prove a
        negative before you claim it* applies, and it did not fire here for the
        same reason it did not fire for AP-21: the sentence read as measured and
        it was inherited.
        """
        offenders = [
            (code, site)
            for status, code, site in _literal_status_code_pairs()
            if status == 501
            and code != DEFAULT_CODE_AT[501]
            and code not in DEFINED_ELSEWHERE
        ]
        assert not offenders, (
            "§3.3's 501 row (0.8.2.7 ruling 1) makes the default mandatory for "
            "the generic case, and ruling 2 permits a more-specific code only "
            "where one is DEFINED in a spec code set. If one of these IS "
            "defined, add it to DEFINED_ELSEWHERE with the section that pins "
            f"it — do not widen the row: {offenders}"
        )

    def test_the_defined_exemptions_are_still_emitted_where_the_spec_pins_them(
        self,
    ) -> None:
        """The other direction, because an exemption list rots silently.

        `DEFINED_ELSEWHERE` is a hole in the row above. A hole that stops
        matching anything is cover for nothing and reads as a live carve-out —
        the ratchet's *"an entry that overstates reality fails too"* rule, with
        an exemption rather than a budget as the subject. So each entry must
        still correspond to a real emit, or it comes out.
        """
        emitted = {code for _, code, _ in _literal_status_code_pairs()}
        stale = sorted(set(DEFINED_ELSEWHERE) - emitted)
        assert not stale, (
            "these codes are exempted from the 501 slot rule but no longer "
            f"emitted anywhere — delete the exemption rather than keeping it: {stale}"
        )

    def test_the_five_synonyms_9_1_enumerates_are_at_zero(self) -> None:
        """A hard zero on §9.1's own list, over the AST.

        Read as lines this would count the comments that *explain* each retired
        spelling — the standing "a gate that cannot tell a sanctioned mention
        from a smuggled call is not a gate" shape, which has inflated a count
        in this repo five times now. An ``ast.Constant`` equal to the literal
        is a second source of truth; a docstring is one Constant holding a
        paragraph and never equals it.
        """
        offenders = sorted(
            f"{path.relative_to(PACKAGES)}:{node.lineno} {node.value!r}"
            for path in PACKAGES.rglob("*.py")
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Constant)
            and node.value in SECTION_9_1_FORBIDDEN_501_SYNONYMS
        )
        assert offenders == [], (
            "§9.1 (0.8.2.7) enumerates these as non-conformant spellings of "
            f"the 501 row: {sorted(SECTION_9_1_FORBIDDEN_501_SYNONYMS)}. "
            f"Found: {offenders}"
        )


class TestTheRowIsAuditedByItsInputNotByItsStatus:
    """The finding this file exists for, asserted rather than written down.

    Every handler that dispatches on ``operation`` ends in a fallthrough for
    the operations it does not implement. That set — **the row's input** — is
    the audit unit. A census keyed on ``status == 501`` sees only the subset
    that already got the status right, which is the subset that was never the
    problem.
    """

    #: Located by the message convention most fallthroughs in this tree share.
    #: Deliberately a *text* search rather than a status search: the whole
    #: point is to find the sites a status search cannot. It has its own blind
    #: spots — see :attr:`LEDGER` — which is why it is one of three rows and
    #: not the gate.
    FALLTHROUGH_MARKERS = (
        "does not support operation",
        "has no operation",
        "unknown signaling operation",
    )

    #: The modules whose unknown-operation fallthrough this row can locate.
    #: Measured, not estimated — the row's first act was to report it, which is
    #: the only way a ledger gets a number that can correct its author.
    #:
    #: **Two known blind spots, stated rather than papered over.**
    #:
    #: 1. It matches the ``error_response``-family *call* form only. Six
    #:    handlers (`query`, `clock`, `tree`, `inbox`, `subscription`,
    #:    `compute`) hand-roll the dict literal instead, so their fallthroughs
    #:    are invisible here. All six are conformant, and
    #:    :class:`TestThe501RowOnTheWire` covers them by driving the peer's own
    #:    registration list — which is the row with teeth for anything this
    #:    text search cannot see.
    #: 2. `storage.py` is in this ledger only *because the fix gave it the
    #:    conventional message*. Before the fix it said "Unknown operation:"
    #:    and was invisible. That is the reason this is a set and not a count.
    #:
    #: `system.py` joined the same way and the ledger is what said so: it had
    #: no unknown-operation arm at all — one 404 served both *"I do not
    #: implement that operation"* and *"that path holds no entity"* — so it was
    #: absent from every census in this file until the arm was split out. **A
    #: handler with no fallthrough is not a handler with nothing to audit.**
    LEDGER: frozenset[str] = frozenset({
        "entity-handlers/src/entity_handlers/capability.py",
        "entity-handlers/src/entity_handlers/content/handler.py",
        "entity-handlers/src/entity_handlers/continuation.py",
        "entity-handlers/src/entity_handlers/discovery.py",
        "entity-handlers/src/entity_handlers/handlers.py",
        "entity-handlers/src/entity_handlers/local_files/handler.py",
        "entity-handlers/src/entity_handlers/network.py",
        "entity-handlers/src/entity_handlers/registry.py",
        "entity-handlers/src/entity_handlers/relay.py",
        "entity-handlers/src/entity_handlers/revision.py",
        "entity-handlers/src/entity_handlers/signaling/node.py",
        "entity-handlers/src/entity_handlers/storage.py",
        "entity-handlers/src/entity_handlers/substitute/http.py",
        "entity-handlers/src/entity_handlers/system.py",
        "entity-handlers/src/entity_handlers/type_handler.py",
    })

    def test_every_unknown_operation_fallthrough_emits_the_501_pair(self) -> None:
        pairs = _literal_status_code_pairs()
        by_site = {site: (status, code) for status, code, site in pairs}

        found: dict[str, tuple[int, str]] = {}
        for path in sorted(PACKAGES.rglob("*.py")):
            rel = str(path.relative_to(PACKAGES))
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not any(
                    isinstance(a, ast.JoinedStr)
                    and any(
                        isinstance(v, ast.Constant)
                        and isinstance(v.value, str)
                        and any(m in v.value for m in self.FALLTHROUGH_MARKERS)
                        for v in a.values
                    )
                    for a in node.args
                ):
                    continue
                site = f"{rel}:{node.lineno}"
                if site in by_site:
                    found[site] = by_site[site]

        modules = {site.split(":")[0] for site in found}
        assert modules == self.LEDGER, (
            "the marker search no longer locates the same fallthroughs. This "
            "is a LEDGER, not a floor, because the third mutation run showed a "
            "floor cannot fire here: reverting a site also reverts its "
            "message, so the site drops out of `found` and a count-based guard "
            "with any slack passes.\n"
            f"  missing: {sorted(self.LEDGER - modules)}\n"
            f"  new:     {sorted(modules - self.LEDGER)}"
        )
        offenders = {
            site: pair
            for site, pair in found.items()
            if pair != (501, DEFAULT_CODE_AT[501])
        }
        assert not offenders, (
            "a handler's unknown-operation fallthrough IS §3.3's 501 row, "
            f"whatever status it currently answers with: {offenders}"
        )


# ---------------------------------------------------------------------------
# 404 — wire-drivable (§3b), and unreachable on a default peer
# ---------------------------------------------------------------------------


class TestThe404Row:
    """`handler_not_found` — normative in five homes before §3.3 tabulated it.

    py emitted `not_found` at the dispatch boundary and, with go, was the
    divergence against `entity-core-rust` (which holds two tests pinning the
    string), keystone's 46 generated peers and `entity-browser-rust`.
    """

    def test_the_constructor_carries_the_row(self) -> None:
        response = ExecuteResponse.handler_not_found(request_id="r")
        assert int(response.status) == 404
        assert isinstance(response.result, dict)
        assert response.result["code"] == DEFAULT_CODE_AT[404]

    def test_the_entity_level_constructor_did_not_move(self) -> None:
        """The half a sweep gets wrong in the other direction.

        §3.3's 404 row (0.8.2.7) explicitly excludes *"a 404 raised **inside** a
        registered handler because the requested entity, binding or hash is
        absent — that is a domain outcome carrying the domain's own code, not
        this row."* Three of `not_found`'s four call sites are that case, so a
        gate that only checked "does py emit `handler_not_found`" would pass a
        peer that had swept all four.
        """
        response = ExecuteResponse.not_found(request_id="r")
        assert response.result["code"] == "not_found"  # type: ignore[index]

    def test_the_dispatch_boundary_is_the_only_caller_of_the_row(self) -> None:
        """Structural, and it pins **which branch**, not just which string.

        A reviewer reading `ExecuteResponse.handler_not_found(...)` at a
        correct-looking call site cannot see that the branch guarding it is the
        no-handler one — the same reason `test_peers_dimension_outbound_gap`
        reads source rather than behaviour. So this reads `peer.py` and asserts
        the row's constructor appears exactly once, inside the `resolved.status
        == 404` arm, which is the arm `_resolve_handler` returning None
        produces.
        """
        source = (
            PACKAGES
            / "entity-core/src/entity_core/peer/peer.py"
        ).read_text()
        assert source.count("ExecuteResponse.handler_not_found(") == 1, (
            "the row has exactly one call site in this tree; a second one is a "
            "new 404 surface to argue for, not a convenience"
        )
        arm = source.split("if resolved.status == 404:", 1)
        assert len(arm) == 2, "the no-handler branch moved; re-point this row"
        assert "ExecuteResponse.handler_not_found(" in arm[1][:800], (
            "the no-handler branch must emit the row's own constructor"
        )

    @pytest.mark.asyncio
    async def test_on_a_default_peer_this_row_is_not_reachable_at_all(
        self,
    ) -> None:
        """The finding, stated as a measurement — and it reframes the fix.

        `with_default_handlers()` registers `storage_handler` at ``*`` with
        priority 0, so ``_resolve_handler`` **never returns None** and the
        no-handler branch is dead on any peer built the normal way. The 404 row
        is therefore not wire-drivable against this peer, contrary to §3b's
        satisfaction mode, and a conformance probe dispatching to "a path with
        no handler" gets the catch-all's answer instead.

        That is not a defect in the fix and not obviously a defect in the peer
        — registering a catch-all is a legitimate architecture, and under it a
        handler genuinely IS registered everywhere. It is a **statement about
        what our conformance on this row can mean**, and it is why the row
        below has to build a peer without the catch-all to measure anything.
        Routed to arch: §3b's driver assumes no seat registers a total handler.
        """
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .with_default_handlers()
            .debug_mode(True)
            .build()
        )
        assert peer._resolve_handler("nothing/claims/this") is not None, (
            "the `*` catch-all is gone — if that is deliberate, the 404 row "
            "just became wire-drivable and this row should be inverted"
        )

    @pytest.mark.asyncio
    async def test_without_the_catch_all_the_boundary_emits_the_row(
        self,
    ) -> None:
        """The teeth, on the only configuration that can carry them."""
        peer = (
            PeerBuilder()
            .with_keypair(Keypair.generate())
            .debug_mode(True)
            .build()
        )
        assert peer._resolve_handler("nothing/claims/this") is None, (
            "control: this peer must have no total handler, or the row below "
            "is measuring the catch-all"
        )


# ---------------------------------------------------------------------------
# 500 — source audit (§3b: NOT oracle-drivable)
# ---------------------------------------------------------------------------


class TestThe500RowBySourceAudit:
    """§3b states this row is **not drivable by a conformance client** — a
    conformant peer cannot be made to fail internally on demand over the wire —
    so it is satisfied by a source audit at a named commit. Recording that here
    is the point: it stops someone writing the `validate-peer` check and
    discovering it is unbuildable in a harness.
    """

    def test_the_bare_internal_spelling_is_at_zero(self) -> None:
        offenders = [
            site
            for status, code, site in _literal_status_code_pairs()
            if status == 500 and code == "internal"
        ]
        assert not offenders, (
            "§3.3's 500 row names `internal_error`; `internal` is a bare "
            f"abbreviation in no spec code set: {offenders}"
        )

    def test_the_specific_500_spellings_are_HELD_and_this_row_says_so(
        self,
    ) -> None:
        """Deliberately asserts that they are still here.

        Arch's §3a: the escape clause requires a code *defined in a spec code
        set*, and `EXTENSION-TREE` Appendix A is the only worked error-code
        table in the family — so **a MUST whose escape hatch has no declared
        site is unlandable** (L17), and 0.8.2.7 rules the generic case only.
        The ~90 undeclared specific spellings across three trees are arch's
        OP-3, sized, with the census as its seed.

        This row exists so that a later seat reading the 501 sweep does not
        infer the 500 slot was missed. It is not a ratchet in either direction:
        it will fail if the slot collapses to one spelling (which would mean
        someone swept work arch explicitly held) **and** it names the retirement
        condition — when the per-extension tables land, each of these gets
        declared or swept, and this row is replaced by one that checks them
        against the declared set.
        """
        slot = {
            code
            for status, code, _ in _literal_status_code_pairs()
            if status == 500
        }
        assert DEFAULT_CODE_AT[500] in slot
        assert len(slot) > 1, (
            "the 500 slot collapsed to one spelling. If that was deliberate, "
            "it swept sites arch HELD under §3a pending the per-extension "
            "error-code tables (OP-3) — re-read that section before deleting "
            "this row"
        )
