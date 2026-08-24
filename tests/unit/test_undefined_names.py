"""F821 undefined-name, as a gate.

`make check` is red on ~660 ruff findings and the sweep is deliberately
deferred until the tiers land. That deferral is fine for cosmetics and wrong
for **F821**, which does not report style: it reports a name that is not bound.
Every hit is either a runtime `NameError` waiting for its branch to execute, or
an annotation naming a type that does not exist — a lie to mypy, which runs
`strict` here.

The sixteen findings that existed when this gate was written proved the point.
Fourteen were annotation-only (one of them, ``"Subscription"``, named a class
this repo has never had — the real name is ``SubscriptionEntity``). The other
two were live bugs, and both sat on branches the suite could not reach:

- ``entity_cli.main.compare_types_with_peer`` compared against an unbound
  ``remote_hash``, so ``entity-core compare-types`` raised on its first
  successfully fetched type. Its only coverage was ``tests/interop/``, which
  needs a live Rust peer and skips in an ordinary run.
- ``entity_core.capability.delegation._link_content_hash`` called an unimported
  ``Entity`` inside its own ``except Exception``, so the documented recompute
  fallback always returned ``None`` and CAP-FREEZE-1's cross-format check
  silently abstained on every link that omitted ``content_hash``.

Both are the same shape: an unexecuted branch, a broad ``except`` or a skipped
suite hiding it, and a static check that had already found it and was not being
read. So this rule gets separated from the deferred sweep and ratcheted at
**zero** — no ledger, because unlike the tier gates there is nothing left to
migrate. If a genuine forward reference ever needs to land, it belongs in a
``TYPE_CHECKING`` block, which is what makes it defined.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_no_undefined_names() -> None:
    """Ruff F821 must report nothing, repo-wide."""
    proc = subprocess.run(
        [
            sys.executable, "-m", "ruff", "check",
            "--select", "F821",
            "--output-format", "concise",
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
    )

    # An absent ruff must fail rather than skip. ruff is a declared dev
    # dependency; if it is missing the gate is not passing, it is not running,
    # and a skip would read as green.
    assert "No module named" not in proc.stderr, (
        f"ruff is not installed, so this gate did not run: {proc.stderr.strip()}"
    )

    findings = [ln for ln in proc.stdout.splitlines() if ": F821 " in ln]
    assert not findings, (
        "F821 undefined-name is ratcheted at zero — every hit is a NameError "
        "waiting to execute or a type annotation naming something that does "
        "not exist. Bind the name, or put a forward reference in a "
        "TYPE_CHECKING block:\n  " + "\n  ".join(findings)
    )
