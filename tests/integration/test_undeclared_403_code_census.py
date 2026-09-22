"""The **403** code slot at this seat, censused and ratcheted for the first time.

.. rubric:: Why there was no such file until now

This repo has censused §3.3's 501 slot (0.8.2.7), its 500 slot (0.8.2.8, and a
standing ledger beside this one), its 404 row and its 400 row — each because a
sibling's probe or an arch ruling named that status. **Nothing ever named 403**,
and a slot nobody names is a slot nobody walks: the census below was run by
asking §3.3's own question (*which codes does this peer emit at this status, and
does the corpus define them?*) rather than by following a report.

It found **thirteen** spellings the corpus defines nowhere, in eight handlers.
Twelve are ledgered here. The thirteenth was swept in the same commit and is
the reason the file exists:

    ``403 forbidden`` — ten sites in ``tree.py`` and ``revision.py``, every one
    of them carrying the message *"Capability doesn't grant {op} on {path}"*,
    which is **§5.2a's authz condition verbatim**. `EXTENSION-TREE` §8 and its
    Appendix A spell that answer ``capability_denied``; so does
    `EXTENSION-REVISION`'s. §3.3 (0.8.2.4) forbids minting a synonym for a row
    that has a code, and ``forbidden`` appears in the entire corpus three times,
    all of them prose.

**Two of those ten sites are `system/tree` `get` and `put`** — the most
dispatched refusals in the peer, and the handler-level path check `0.8.2.20`
§6.7 has just promoted from *"defense in depth"* to *the enforcement*. A
cross-impl debugger reading that refusal got a code in no table.

.. rubric:: What this file does NOT claim, stated because the shape invites it

The ``DEFINED`` side below is established by **grep presence in the two spec
corpora**, not by per-operation verification. `SA-PY-40`'s rule is that
*"defined in the corpus" is not the test; "defined for the operation" is* — so
an entry here means *some section names this token*, which is weaker than what
§3.3's escape clause (*defined in the owning domain handler's own table*) asks.
Walking those seventeen codes against their owning Appendix A tables is real
work and is **not done**; it is filed, not silently skipped.

The ``UNDEFINED_CEILING`` side is the opposite and is solid: a token absent from
both corpora is absent, and that is the direction a grep establishes reliably.

.. rubric:: Why the twelve are ledgered rather than swept

They are not synonyms. ``replay_detected``, ``token_expired``,
``registration_disabled`` and the rest name **conditions**, and §3.3's remedy
for a specific-but-undeclared code is a table row in the owning extension — the
disposition arch gave the ~16 held 500 spellings under §3a, not the sweep it
gave §9.1's five 501 synonyms. Inventing a per-token answer here is where
``bad_request`` came from. ``forbidden`` is swept because it is the other case:
its condition already has a code, in two tables, for this exact operation.
"""

from __future__ import annotations

import ast
import collections
import pathlib

PACKAGES = pathlib.Path(__file__).resolve().parents[2] / "packages"

#: Emit helpers whose first two positional arguments are ``(status, code)``.
ERROR_HELPER_NAMES = frozenset({
    "error_response", "_error_response", "_error", "_err",
    "make_error_response", "error",
})

#: Spellings the corpus names, each with where it was found. See the docstring:
#: this is **presence**, not per-operation verification, and the difference is
#: the filed gap rather than a hidden one.
DEFINED = {
    "capability_denied":
        "ENTITY-CORE-PROTOCOL §5.2a / §3.3 — the 403 row's declared default; "
        "EXTENSION-TREE Appendix A (`merge`) and EXTENSION-REVISION §8 spell "
        "the handler-level path refusal with it",
    "not_entitled": "EXTENSION-REGISTRY §4.3",
    "policy_rejected": "EXTENSION-REGISTRY",
    "scope_exceeds_authority": "GUIDE-CAPABILITIES / EXTENSION-CAPABILITY",
    "path_traversal_rejected": "DOMAIN-LOCAL-FILES",
    "read_only_root": "DOMAIN-LOCAL-FILES",
    "access_denied": "EXTENSION-HISTORY",
    "cap_denied": "EXTENSION-SUBSTITUTE, EXTENSION-CONTINUATION",
    "embedded_cap_unauthorized": "EXTENSION-COMPUTE",
    "content_store_requires_type_scope": "EXTENSION-QUERY",
    "type_not_authorized": "EXTENSION-QUERY",
    "assignee_excluded": "EXTENSION-ROLE",
    "assigner_authority_insufficient": "EXTENSION-ROLE",
    "controller_invalid": "EXTENSION-IDENTITY",
    "payload_unauthorized": "EXTENSION-SUBSCRIPTION",
    "deliver_token_insufficient": "EXTENSION-SUBSCRIPTION",
    "not_subscription_owner": "EXTENSION-SUBSCRIPTION",
}

#: Absent from BOTH spec corpora, searched 2026-09-11. Counts are a **ceiling**
#: and the ledger is monotone in both directions. ``note`` is the owing
#: extension — what the token needs is a row in its own Appendix A, not a
#: local decision here.
UNDEFINED_CEILING = {
    "no_identity": (5, "compute — the impure-op signer check"),
    "delegate_excluded": (2, "role"),
    "builtin_override_prohibited": (1, "handlers — §6.2 register"),
    "identity_verification_failed": (1, "identity"),
    "quorum_publish_validation_failed": (1, "identity"),
    "quorum_update_validation_failed": (1, "identity"),
    "stale_request": (1, "registry §6a.9"),
    "replay_detected": (1, "registry §6a.9"),
    "registration_disabled": (1, "registry"),
    "invalid_snapshot": (1, "revision — also a status smell, reads as a 400"),
    "delegation_authority_insufficient": (1, "role"),
    "token_expired": (1, "subscription"),
}

#: Swept 2026-09-11 and held at a hard zero. Unlike the ceiling above this is
#: not a backlog: the condition has a code, in the owning tables, for this
#: operation.
SWEPT_SYNONYMS_OF_THE_403_ROW = frozenset({"forbidden"})


def _dict_get(node: ast.Dict, key: str) -> ast.expr | None:
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def _emissions_at_403() -> list[tuple[str, int, str]]:
    """Every ``(site, line, code)`` emitted at 403, in **both** shapes.

    A gate that budgets one form of a thing reports the others clean — the
    standing law, and it bites here specifically: ``tree.py``'s two sites are
    hand-rolled dict literals, so a census scanning only helper calls (which is
    what the 500 ledger beside this file does, correctly for its own surface)
    would have found eight of the ten ``forbidden`` sites and **missed the two
    most-dispatched refusals in the peer**.
    """
    out: list[tuple[str, int, str]] = []
    for path in sorted(PACKAGES.glob("*/src/**/*.py")):
        rel = path.relative_to(PACKAGES).as_posix()
        for node in ast.walk(ast.parse(path.read_text())):
            code: str | None = None
            if isinstance(node, ast.Call) and len(node.args) >= 2:
                name = getattr(node.func, "id", None) or getattr(
                    node.func, "attr", None
                )
                status, code_arg = node.args[0], node.args[1]
                if (
                    name in ERROR_HELPER_NAMES
                    and isinstance(status, ast.Constant)
                    and status.value == 403
                    and isinstance(code_arg, ast.Constant)
                    and isinstance(code_arg.value, str)
                ):
                    code = code_arg.value
            elif isinstance(node, ast.Dict):
                status = _dict_get(node, "status")
                if isinstance(status, ast.Constant) and status.value == 403:
                    result = _dict_get(node, "result")
                    if isinstance(result, ast.Dict):
                        data = _dict_get(result, "data")
                        if isinstance(data, ast.Dict):
                            code_node = _dict_get(data, "code")
                            if isinstance(code_node, ast.Constant) and isinstance(
                                code_node.value, str
                            ):
                                code = code_node.value
            if code is not None:
                out.append((rel, node.lineno, code))
    return out


def _census() -> dict[str, int]:
    found: collections.Counter[str] = collections.Counter()
    for _, _, code in _emissions_at_403():
        found[code] += 1
    return dict(found)


class TestThe403SlotIsLedgeredAndMonotone:
    def test_no_403_spelling_exists_outside_the_ledger(self) -> None:
        unknown = sorted(set(_census()) - set(DEFINED) - set(UNDEFINED_CEILING))
        assert not unknown, (
            f"new 403 spelling(s) outside the ledger: {unknown}. Either the "
            "corpus defines it (add it to DEFINED naming where) or it is "
            "undeclared — and a new undeclared one does not go in the ceiling, "
            "which is a frozen backlog and not a place to put more"
        )

    def test_every_undefined_spelling_is_at_or_below_its_ceiling(self) -> None:
        census = _census()
        grew = {
            code: (census.get(code, 0), ceiling)
            for code, (ceiling, _) in UNDEFINED_CEILING.items()
            if census.get(code, 0) > ceiling
        }
        assert not grew, f"undefined 403 spellings grew (now, ceiling): {grew}"

    def test_no_ceiling_overstates_reality(self) -> None:
        """The direction an author's own estimate errs in.

        A ledger entry that survives the retirement of what it describes is
        permanent cover for a violation already fixed, and reads to the next
        seat as an open item.
        """
        census = _census()
        stale = {
            code: (census.get(code, 0), ceiling)
            for code, (ceiling, _) in UNDEFINED_CEILING.items()
            if census.get(code, 0) < ceiling
        }
        assert not stale, (
            f"ceiling is above reality (now, ceiling): {stale} — lower it in "
            "the commit that retires the sites, and say which way it moved"
        )

    def test_every_defined_exemption_is_still_emitted(self) -> None:
        census = _census()
        stale = sorted(c for c in DEFINED if census.get(c, 0) == 0)
        assert not stale, (
            "exempt from the row but no longer emitted — drop the entry rather "
            f"than leaving a carve-out with nothing under it: {stale}"
        )


class TestTheSweptSynonymIsAtZero:
    """`forbidden` — and the row is an AST constant scan, not a grep."""

    def test_the_synonym_is_not_emitted_anywhere(self) -> None:
        offenders = sorted(
            f"{site}:{line}"
            for site, line, code in _emissions_at_403()
            if code in SWEPT_SYNONYMS_OF_THE_403_ROW
        )
        assert offenders == [], (
            "§3.3 (0.8.2.4): a row that has a code MUST NOT be given a "
            "synonym. `forbidden` names §5.2a's authz condition, which "
            "EXTENSION-TREE and EXTENSION-REVISION both spell "
            f"`capability_denied`: {offenders}"
        )

    def test_the_condition_still_has_sites_so_the_zero_is_not_a_deletion(
        self,
    ) -> None:
        """Teeth. A hard zero is satisfied by deleting the refusals as well as
        by respelling them, and only one of those is the fix.

        `EXTENSION-TREE` Appendix A has no `get`/`put` 403 row of its own, so
        this asserts the count rather than the table: the ten sites are still
        ten refusals.
        """
        census = _census()
        assert census.get("capability_denied", 0) >= 10, (
            "the ten swept sites should still be refusing, now under the "
            f"declared code; found {census.get('capability_denied', 0)}"
        )


class TestTheCensusSeesBothEmissionShapes:
    """The blind spot the 500 ledger has and this one does not — asserted, so
    a later seat copying that file's extractor here is told why not to."""

    def test_a_hand_rolled_dict_literal_refusal_is_counted(self) -> None:
        sites = {
            site for site, _, code in _emissions_at_403()
            if code == "capability_denied"
        }
        assert any("tree.py" in s for s in sites), (
            "`tree.py`'s get/put refusals are dict literals, not helper "
            "calls — a call-only extractor scores this file clean while the "
            "two most-dispatched 403s in the peer carry whatever they like"
        )
