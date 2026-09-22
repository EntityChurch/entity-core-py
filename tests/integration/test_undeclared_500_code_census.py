"""The 500 code slot at this seat, censused and ratcheted — now against 0.8.2.8.

.. rubric:: Why this exists, and what the fold changed

`entity-core-go`'s item-D ledger censused go's 500 spellings, folded in rust's flag on one, and
routed two recommendations to arch: **bless** `storage_error` (a *"consistent, deliberate 14×
convention"*) and **keep** `backend_error`. Both were cohort-consistency arguments built on two
seats of three. Running the same census here split them — `backend_error` corroborated,
`storage_error` contradicted (×1 here, with the same failure spelled `io_error` ×7 in
`local_files`, the exact subsystem go spells `storage_error` ×4).

**0.8.2.8 ruled, and it ruled the split rather than either seat's count.** §3.3's 500 row now
reads:

    More-specific 500 codes where one applies (0.8.2.8): `io_error` — an operating-system I/O
    operation failed (`stat`, `read`, `write`, `mkdir`, `readdir`, `delete`); `storage_error` —
    a content-store or tree bind/read failed. The two are distinct conditions and are not
    interchangeable: a filesystem failure in a local-files handler is `io_error`, a store
    failure anywhere is `storage_error`.

**The discriminator is the CONDITION, not the handler.** That is the sentence that dissolved the
apparent go-vs-py divergence: go's four local-files `storage_error` sites are `TreeSet` binds and
py's seven local-files `io_error` sites are OS syscalls, so **the two seats were never
disagreeing — they were covering the two halves of one split, inside the same handler.** arch's
worklist item told go to move theirs to `io_error`; go verified against the landed line and
declined; this file is the same verification from the other side, and it agrees.

**What actually moved here was a site neither seat was looking at**: `identity.py`'s
`bind_failed` — an `emit()` tree bind wearing a minted name, which line 836 decides outright.

.. rubric:: What this file does NOT do

It still converges nothing on the eight spellings that remain undefined. §3.3's rule (*an
undefined 500 spelling is non-conformant*) is not in dispute; **which of the two remedies applies
to each token — a table row, or the default — is what the owning extensions still owe**, and
inventing an answer per token is where `bad_request` came from. OP-3 landed three tables this
fold and retired `backend_error` from this list by defining it; that is the mechanism working.

What it does is keep the census **reproducible and monotone**. Every entry may shrink and none
may grow, and an entry that *overstates* reality fails too.

.. rubric:: The ratchet did its job on this very fold

Landing 0.8.2.8 turned this file red three ways at once — `storage_error` grew (1→2),
`remote_empty` and `bind_failed` went to zero, and the tree-bind-family row fired to say the
routing packet's premise was stale. **A ledger that could not fail in the shrinking direction
would have carried the superseded claim into the next packet silently**, which is the whole
reason the staleness row exists.
"""

from __future__ import annotations

import ast
import collections
import pathlib

PACKAGES = pathlib.Path(__file__).resolve().parents[2] / "packages"

#: Spellings that are **defined**, each naming the section that defines it.
#: Per SA-PY-37 an exemption that does not name its pin is a carve-out a later seat can widen by
#: assertion.
DEFINED = {
    "internal_error":
        "ENTITY-CORE-PROTOCOL §3.3 — the 500 row's declared default code",
    "io_error":
        "ENTITY-CORE-PROTOCOL §3.3, 500 row (0.8.2.8) — an OS I/O operation failed; "
        "the six enumerated syscalls, pinned below",
    "storage_error":
        "ENTITY-CORE-PROTOCOL §3.3, 500 row (0.8.2.8) — a content-store or tree bind/read "
        "failed; 'a store failure anywhere'",
    "backend_error":
        "EXTENSION-DISCOVERY v1.2 Appendix A — defined this fold; the corroboration held",
    "config/config-write-failed":
        "EXTENSION-REVISION §4.4.17 — set-config's nested-cascade handling",
    "config/tracking-config-write-failed":
        "EXTENSION-REVISION §4.4.17 — same sentence",
}

#: §3.3's 500 row enumerates `io_error`'s conditions exhaustively. A seventh verb is not a
#: judgement call — it is outside the row, and the code falls back to `internal_error`.
ENUMERATED_OS_OPERATIONS = ("stat", "read", "write", "mkdir", "readdir", "delete")

#: Still undefined in both spec corpora, searched 2026-09-04 post-fold. Counts are a **ceiling**.
#: `note` is what the token is owed by the OWNING extension, not what we intend to do.
UNDEFINED_CEILING = {
    "invalid_version": (5, "revision; also a status smell — an invalid version argument "
                           "reads as a 400, so this is a status question before a code one"),
    "invalid_blob": (2, "content/sdk"),
    "cap_issue_failed": (1, "identity"),
    "dispatch_error": (1, "continuation; go converged its `dispatch_failed` sibling to "
                          "`internal_error`, which is the likely answer here too"),
    "invalid_role_definition": (1, "role; a status smell — reads as a 400"),
    "invalid_subscription": (1, "subscription; same status smell"),
    "missing_keypair": (1, "role"),
    "policy_invalid": (1, "registry; a status smell — reads as a 400"),
}


def _calls_at_500() -> list[tuple[str, int, str, ast.expr | None]]:
    """Every `(500, "<code>", <message>)` call in the shipped packages.

    The unit is the **call node**, not a source line: a multi-line refusal is one emission, and
    counting lines is what hid `invalid_blob` from the first census.
    """
    out: list[tuple[str, int, str, ast.expr | None]] = []
    for path in sorted(PACKAGES.glob("*/src/**/*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call) or len(node.args) < 2:
                continue
            status, code = node.args[0], node.args[1]
            if (
                isinstance(status, ast.Constant) and status.value == 500
                and isinstance(code, ast.Constant)
                and isinstance(code.value, str)
            ):
                msg = node.args[2] if len(node.args) > 2 else None
                rel = path.relative_to(PACKAGES).as_posix()
                out.append((rel, node.lineno, code.value, msg))
    return out


def _census() -> dict[str, int]:
    found: collections.Counter[str] = collections.Counter()
    for _, _, code, _ in _calls_at_500():
        found[code] += 1
    return dict(found)


def _leading_text(msg: ast.expr | None) -> str:
    """The literal head of a message argument, f-string or plain."""
    if isinstance(msg, ast.Constant) and isinstance(msg.value, str):
        return msg.value
    if isinstance(msg, ast.JoinedStr) and msg.values:
        head = msg.values[0]
        if isinstance(head, ast.Constant) and isinstance(head.value, str):
            return head.value
    return ""


class TestThe500SlotIsLedgeredAndMonotone:
    def test_no_500_spelling_exists_outside_the_ledger(self) -> None:
        unknown = sorted(set(_census()) - set(DEFINED) - set(UNDEFINED_CEILING))
        assert not unknown, (
            f"new undefined 500 spelling(s): {unknown}. §3.3 makes an undefined 500 code "
            "non-conformant; either it is defined (add it to DEFINED with the section that "
            "pins it) or it is `internal_error`. Do not add it to the ceiling — the ceiling "
            "is a frozen backlog, not a place to put new ones."
        )

    def test_every_undefined_spelling_is_at_or_below_its_ceiling(self) -> None:
        census = _census()
        grew = {
            code: (census.get(code, 0), ceiling)
            for code, (ceiling, _) in UNDEFINED_CEILING.items()
            if census.get(code, 0) > ceiling
        }
        assert not grew, f"undefined 500 spellings grew (now, ceiling): {grew}"

    def test_no_ceiling_overstates_reality(self) -> None:
        """The direction an author's own estimate errs in, and the one that fired on 0.8.2.8.

        A ledger that survives the retirement of what it describes becomes permanent cover for
        a violation already fixed, and reads to the next seat as an open item that still exists.
        """
        census = _census()
        stale = {
            code: (census.get(code, 0), ceiling)
            for code, (ceiling, _) in UNDEFINED_CEILING.items()
            if census.get(code, 0) < ceiling
        }
        assert not stale, (
            f"ceiling is above reality (now, ceiling): {stale} — lower it in the same commit "
            "that retires the sites, and say in the routing packet which way it moved"
        )

    def test_every_defined_exemption_names_its_pin_and_is_still_emitted(self) -> None:
        census = _census()
        for code, pin in DEFINED.items():
            assert "§" in pin or "Appendix" in pin, (
                f"`{code}` is exempt without naming the section that defines it — that is an "
                "assertion, not a pin"
            )
            assert census.get(code, 0) > 0, (
                f"`{code}` is exempt but no longer emitted; drop the entry rather than leaving "
                "a carve-out with nothing under it"
            )


class TestTheLine836SplitIsByConditionNotByHandler:
    """§3.3's 500 row (0.8.2.8), and the row that replaces the pre-fold finding.

    The old class here asserted that *the same failure has three spellings at this seat*, which
    was the finding routed to arch. It is resolved: line 836 split the two conditions and named
    the discriminator, `bind_failed` moved to `storage_error`, and what remains is a **rule to
    keep**, not a divergence to report.

    Keeping the class pointed at the resolved finding would have been the over-claiming-docstring
    failure — a test whose name says it is guarding something it has stopped guarding.
    """

    def test_every_io_error_names_one_of_the_six_enumerated_syscalls(self) -> None:
        """The enumeration is exhaustive, so a seventh verb is out of the row.

        This is the mechanical form of the question `entity-core-go` routed to arch — *are any
        of py's local-files `io_error`s tree binds rather than OS operations?* The answer is
        measured here rather than asserted in a packet, and it stays answered: all seven sites
        are `except OSError` arms naming their syscall, one per enumerated verb.
        """
        offenders = [
            (path, line, _leading_text(msg))
            for path, line, code, msg in _calls_at_500()
            if code == "io_error"
            and not _leading_text(msg).startswith(ENUMERATED_OS_OPERATIONS)
        ]
        assert not offenders, (
            f"`io_error` emitted for something outside §3.3's enumerated six "
            f"{ENUMERATED_OS_OPERATIONS}: {offenders}. If the failing operation is a tree bind "
            "or a content-store access it is `storage_error` — 'a store failure anywhere' — "
            "and if it is neither it is `internal_error`."
        )

    def test_the_storage_error_sites_are_store_or_tree_operations(self) -> None:
        """Ledgered by module, because *is this a store op* is not lexically checkable.

        A count alone would let a new `storage_error` land anywhere; naming the modules means a
        new one has to be argued for in this file.
        """
        expected = {
            # `emit()` on the publish-attestation move — a tree bind. Was `bind_failed`, a
            # minted spelling, until line 836 named the condition.
            "entity-handlers/src/entity_handlers/identity.py",
            # Installing the reconnect/resubscribe continuation graphs — tree puts.
            "entity-handlers/src/entity_handlers/network.py",
        }
        actual = {
            path for path, _, code, _ in _calls_at_500() if code == "storage_error"
        }
        assert actual == expected, (
            f"the `storage_error` site set moved: {actual ^ expected}. Every site must be a "
            "content-store or tree bind/read failure (§3.3, 0.8.2.8) — add the module here "
            "with the operation that failed, or use `internal_error`."
        )

    def test_the_two_conditions_do_not_collapse_into_one_handler_rule(self) -> None:
        """The finding itself, kept as a property rather than as prose.

        `local_files` emits `io_error` and **no** `storage_error`; the seat go compared us
        against emits `storage_error` there for its tree binds. Both are conformant, because the
        row splits on the CONDITION. A future seat "harmonising" local-files onto one code —
        in either direction — would be reading the row as a per-handler rule, which is the
        reading arch's own worklist item made and line 836 refutes.
        """
        local_files = [
            (code, line) for path, line, code, _ in _calls_at_500()
            if "local_files" in path
        ]
        codes = {code for code, _ in local_files}
        assert "io_error" in codes, "local-files lost its OS-syscall arm"
        assert "storage_error" not in codes, (
            "a `storage_error` appeared in local-files: that is correct ONLY if the failing "
            "operation is a tree bind or store access. If it is, add it to the ledger above "
            "with the operation named; if it is an OS syscall it is `io_error`."
        )
