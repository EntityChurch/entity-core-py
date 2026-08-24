"""The three tier boundaries, as gates.

`AGENTS.md` declares a strict dependency direction and, until this file, had no
enforcement point for it — which is the shape `AGENTS-STANDARD.md` names as
theater. The direction was already violated when these gates were written
(37 function-local imports of ``entity_handlers`` from inside ``entity-core``);
see ``docs/architecture/reviews/REVIEW-THE-SDK-AND-APPLICATION-TIER-GAP-2026-08-17.md``
§5.

The gates are written *before* the tier migration rather than after, so the
known violations enter as a dated, itemized ledger that can only shrink. A gate
added after a migration measures nothing.

Three gates, one per boundary the five-package split depends on:

1. :func:`test_no_upward_imports` — no package imports a package above it,
   **including function-local imports**. The deferred form is what the current
   violations use to dodge the import-time cycle, so a gate that only reads
   module-level imports would score this repo clean.
2. :func:`test_cross_package_imports_are_declared` — every cross-package import
   has a matching entry in the importing package's ``pyproject.toml``. This is
   the check for the latent ``ImportError``: ``entity-core`` imports
   ``entity_handlers`` and does not declare it, so
   ``PeerBuilder().with_all_handlers()`` on a standalone install raises.
3. :func:`test_presentation_constructs_no_envelopes` — the presentation tier
   builds no protocol envelopes. This is the load-bearing one: it makes an
   incomplete SDK fail with a filename instead of quietly growing another
   inline ``{"type": ..., "data": ...}``.

All three ledgers are **ratchets**: an entry may shrink or disappear, never
grow, and a ledger entry that no longer corresponds to a real violation is
itself a failure (:func:`test_no_stale_ledger_entries`) so the ledger cannot
become permanent cover.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES_DIR = REPO_ROOT / "packages"

# The tier order the five-package split enforces. Lower may not import higher.
# `entity_sdk` and `entity_app` are listed before they exist so the gates bind
# to them the moment their first file lands, rather than after.
TIER = {
    "entity_core": 0,
    "entity_handlers": 1,
    "entity_sdk": 2,
    "entity_app": 3,
    "entity_cli": 4,
}

# Distribution name per import package, for the declared-dependency gate.
DIST_NAME = {
    "entity_core": "entity-core",
    "entity_handlers": "entity-handlers",
    "entity_sdk": "entity-sdk",
    "entity_app": "entity-app",
    "entity_cli": "entity-cli",
}

# Packages that may not construct protocol envelopes — the presentation tier.
PRESENTATION_PACKAGES = {"entity_cli"}


# --------------------------------------------------------------------------
# Ledgers — dated, itemized, ratcheting. Each entry needs a justification and
# the step of the build order that retires it.
# --------------------------------------------------------------------------

# (importing package, imported package, path relative to the package root) -> count.
#
# 2026-08-17 — `PeerBuilder` is the composition root and reaches up into the
# layer it composes. All 37 are function-local; the deferral hides the cycle
# from Python but not from the packaging (see the declared-dependency ledger).
# Retired by build-order step 2: the standard-handler `with_*_handler()`
# convenience methods move down into `entity-handlers`, leaving `entity-core`
# with the generic `with_handler()` / `with_extension()` hooks and no knowledge
# of its own extensions' names.
UPWARD_IMPORT_LEDGER: dict[tuple[str, str, str], int] = {
    ("entity_core", "entity_handlers", "peer/builder.py"): 35,
    ("entity_core", "entity_handlers", "peer/peer.py"): 2,
}

# (importing package, imported package) — cross-package imports with no
# matching `dependencies` entry.
#
# 2026-08-17 — the other side of the same defect: `entity-core` cannot declare
# `entity-handlers` without making the cycle explicit in the metadata, so the
# dependency stays undeclared and `with_all_handlers()` is a latent
# `ImportError` on a standalone `entity-core` install. Retired by the same
# step 2 as the ledger above; the two entries retire together or neither does.
UNDECLARED_DEPENDENCY_LEDGER: set[tuple[str, str]] = {
    ("entity_core", "entity_handlers"),
}

# package -> {form of protocol leakage -> count}.
#
# 2026-08-17 — the CLI hand-assembled protocol at every call site because there
# was no L1 SDK to call; this was the measured cause of the SDK gap (review §4),
# not an incidental style problem.
#
# Protocol knowledge leaks into presentation in three distinct forms, and a
# gate that watches only one scores the other two clean. The first draft of
# this file budgeted envelope literals alone at a *guessed* 17 — the staleness
# gate immediately reported the real figure as 8, and measuring the other two
# forms found the 17 sitting in the dispatch calls. Hence three budgets:
#
#   envelope  — `{"type": ..., "data": ...}` dict literals: a hand-built payload
#   dispatch  — `.execute(uri=...)` calls: RAW protocol dispatch (see the
#               counter for why the `uri=` keyword is the discriminator)
#   uri       — `entity://...` string construction: addressing built by hand
#
# **The ledger is empty — all three forms are at 0 and enforced as such.**
# `budgets.get(form, 0)` below means an absent package is a hard zero, so
# deleting an entry is how a violation retires, not how it stops being watched.
#
# Build-order step 4 (the CLI rebuild) took `uri` and `dispatch` to 0. The last
# two envelopes were the typed params entities the registry commands handed to
# the execute primitive — `system/registry/issuer-policy` and
# `system/registry/register-request`. Using the dispatch primitive is
# sanctioned (§3.6-3.9); knowing the registry's request *type names* is
# extension knowledge sitting in a renderer. `entity_sdk.registry` (L3) owns
# those names now, and the staleness half of this ratchet is what reported the
# entry as spent the moment the CLI stopped building them.
#
# A new leak fails `test_presentation_constructs_no_protocol` and names the
# missing SDK affordance at the moment it is worked around. Re-adding an entry
# here is a deliberate act that has to be argued for, not a default.
PROTOCOL_LEAK_LEDGER: dict[str, dict[str, int]] = {}


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------


def _package_roots() -> dict[str, Path]:
    """Import-package name -> its source root (``packages/*/src/<name>``)."""
    roots: dict[str, Path] = {}
    for src in sorted(PACKAGES_DIR.glob("*/src/*")):
        if src.is_dir() and (src / "__init__.py").exists():
            roots[src.name] = src
    return roots


def _imports_in(path: Path) -> list[str]:
    """Every module imported by ``path``, at any nesting depth.

    Walks the whole AST rather than the module body, so function-local and
    ``TYPE_CHECKING`` imports are counted. Both express a real design-time
    dependency, and the function-local form is precisely what the current
    violations use.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # Relative imports (level > 0) are always intra-package.
            if node.level == 0 and node.module:
                modules.append(node.module)
    return modules


def _upward_violations() -> Counter[tuple[str, str, str]]:
    """(importer, imported, relpath) -> count, for imports of a higher tier."""
    found: Counter[tuple[str, str, str]] = Counter()
    for pkg, root in _package_roots().items():
        if pkg not in TIER:
            pytest.fail(
                f"package {pkg!r} has no TIER entry — a new package must "
                f"declare its tier in {__file__} before it can be imported"
            )
        for py_file in sorted(root.rglob("*.py")):
            rel = py_file.relative_to(root).as_posix()
            for module in _imports_in(py_file):
                top = module.split(".")[0]
                if top == pkg or top not in TIER:
                    continue
                if TIER[top] >= TIER[pkg]:
                    found[(pkg, top, rel)] += 1
    return found


def _declared_dependencies(pkg: str) -> set[str]:
    """Distribution names in ``pkg``'s ``[project] dependencies``."""
    pyproject = PACKAGES_DIR / DIST_NAME[pkg] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    declared: set[str] = set()
    for spec in data.get("project", {}).get("dependencies", []):
        # "entity-core>=0.8.0" -> "entity-core"
        name = spec.split(";")[0].strip()
        for sep in (">=", "<=", "==", "!=", "~=", ">", "<", "["):
            name = name.split(sep)[0]
        declared.add(name.strip())
    return declared


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """Ids of every ``Constant`` node that is a docstring.

    A docstring is the first statement of a module, class, or function when it
    is a bare string expression. Identity is by ``id()`` because ``ast`` nodes
    are neither hashable-by-value nor comparable.
    """
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if isinstance(first.value.value, str):
                found.add(id(first.value))
    return found


def _protocol_leak_counts(root: Path) -> dict[str, int]:
    """Count each form of protocol construction under ``root``.

    ``envelope``
        ``{"type": ..., "data": ...}`` dict literals. The envelope is the
        *pair*, not either key alone — a bare ``"type"`` key appears in plenty
        of ordinary dicts, so matching the pair keeps the gate specific to
        hand-assembled protocol payloads.
    ``dispatch``
        ``.execute(uri=...)`` calls — **raw** protocol dispatch issued by a
        renderer. The ``uri=`` keyword is the discriminator, and it is a precise
        one: it is the first named parameter of ``Connection.execute`` and
        ``Peer.execute``, and it is absent from ``EntityClient.execute``, whose
        target is positional and gets resolved through §2.5.

        Counting *every* ``.execute(`` would flag ``client.execute(...)``, which
        is a **sanctioned** surface rather than a leak — `SDK-OPERATIONS`
        §3.6-3.9 says outright that *"the SDK contract is the dispatch
        primitive, not the typed wrappers."* A gate that cannot tell the
        supported call from the smuggled one drives its own budget to a floor
        that correct code can never reach, and at that point the number stops
        meaning anything.
    ``uri``
        string literals containing ``entity://`` — addressing built by hand
        instead of taken from an SDK handle. Counts f-string parts too, which
        is the form the CLI actually uses. **Docstrings are excluded**: a
        docstring showing example output (``entity://PEER.../path/``) is
        documentation, not construction, and counting it would put a floor
        under the budget that no amount of correct refactoring could reach —
        leaving a permanently-nonzero number that a real leak could hide in.
    """
    counts = {"envelope": 0, "dispatch": 0, "uri": 0}
    for py_file in sorted(root.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), str(py_file))
        docstrings = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if id(node) in docstrings:
                continue
            if isinstance(node, ast.Dict):
                keys = {
                    k.value
                    for k in node.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
                if {"type", "data"} <= keys:
                    counts["envelope"] += 1
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and any(kw.arg == "uri" for kw in node.keywords)
            ):
                counts["dispatch"] += 1
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "entity://" in node.value:
                    counts["uri"] += 1
    return counts


# --------------------------------------------------------------------------
# Gate 1 — no upward imports
# --------------------------------------------------------------------------


def test_no_upward_imports() -> None:
    """No package imports a package at or above its own tier.

    Function-local and ``TYPE_CHECKING`` imports count: they are the form the
    known violations take.
    """
    found = _upward_violations()
    unledgered = {k: v for k, v in found.items() if k not in UPWARD_IMPORT_LEDGER}
    assert not unledgered, (
        "new upward import(s) across a tier boundary:\n"
        + "\n".join(
            f"  {imp} -> {tgt} ({n}x) in {rel}" for (imp, tgt, rel), n in sorted(unledgered.items())
        )
        + "\n\nThe dependency direction is entity-core -> entity-handlers -> "
        "entity-sdk -> entity-app -> presentation (AGENTS.md). Route the call "
        "downward, or add a dated ledger entry in this file with the build-order "
        "step that retires it."
    )


def test_upward_import_ledger_does_not_grow() -> None:
    """A ledgered violation may shrink, never grow."""
    found = _upward_violations()
    grew = {
        k: (UPWARD_IMPORT_LEDGER[k], found[k])
        for k in UPWARD_IMPORT_LEDGER
        if found[k] > UPWARD_IMPORT_LEDGER[k]
    }
    assert not grew, (
        "upward-import ledger grew — the boundary is meant to be a ratchet:\n"
        + "\n".join(f"  {k}: ledgered {was}, found {now}" for k, (was, now) in sorted(grew.items()))
    )


def test_no_stale_ledger_entries() -> None:
    """A ledger entry that overstates reality must be tightened or removed.

    Without this, the ledger becomes permanent cover: a violation gets fixed,
    the entry stays, and the gate silently re-permits the same import later.
    """
    found = _upward_violations()
    stale = {
        k: (UPWARD_IMPORT_LEDGER[k], found[k])
        for k in UPWARD_IMPORT_LEDGER
        if found[k] < UPWARD_IMPORT_LEDGER[k]
    }
    assert not stale, (
        "upward-import ledger is stale — tighten the count or drop the entry:\n"
        + "\n".join(f"  {k}: ledgered {was}, found {now}" for k, (was, now) in sorted(stale.items()))
    )


# --------------------------------------------------------------------------
# Gate 2 — cross-package imports are declared dependencies
# --------------------------------------------------------------------------


def test_cross_package_imports_are_declared() -> None:
    """Every cross-package import appears in the importer's ``dependencies``.

    An import that resolves in the workspace but is undeclared works in
    development and raises ``ImportError`` on a standalone install of that one
    package.
    """
    roots = _package_roots()
    missing: set[tuple[str, str]] = set()
    for pkg, root in roots.items():
        declared = _declared_dependencies(pkg)
        for py_file in sorted(root.rglob("*.py")):
            for module in _imports_in(py_file):
                top = module.split(".")[0]
                if top == pkg or top not in roots:
                    continue
                if DIST_NAME[top] not in declared:
                    missing.add((pkg, top))
    unledgered = missing - UNDECLARED_DEPENDENCY_LEDGER
    assert not unledgered, (
        "cross-package import with no declared dependency:\n"
        + "\n".join(
            f"  {imp} imports {tgt} but {DIST_NAME[imp]}/pyproject.toml "
            f"does not declare {DIST_NAME[tgt]}"
            for imp, tgt in sorted(unledgered)
        )
    )


def test_undeclared_dependency_ledger_is_not_stale() -> None:
    """A ledgered undeclared dependency that has been declared must be dropped."""
    roots = _package_roots()
    still_undeclared: set[tuple[str, str]] = set()
    for pkg, target in UNDECLARED_DEPENDENCY_LEDGER:
        if pkg not in roots or target not in roots:
            continue
        if DIST_NAME[target] not in _declared_dependencies(pkg):
            still_undeclared.add((pkg, target))
    resolved = UNDECLARED_DEPENDENCY_LEDGER - still_undeclared
    assert not resolved, (
        "undeclared-dependency ledger is stale — these are now declared, "
        f"drop the entries: {sorted(resolved)}"
    )


# --------------------------------------------------------------------------
# Gate 3 — the presentation tier constructs no protocol envelopes
# --------------------------------------------------------------------------


def test_presentation_constructs_no_protocol() -> None:
    """The presentation tier builds no envelopes, dispatch calls, or URIs.

    Protocol knowledge in the presentation tier is unreachable by every other
    consumer — which is exactly how this repo ended up with no L1 SDK (review
    §4). Each budget may only fall; all three go to 0 at build-order step 4.
    """
    roots = _package_roots()
    over: list[str] = []
    for pkg in sorted(PRESENTATION_PACKAGES & roots.keys()):
        counts = _protocol_leak_counts(roots[pkg])
        budgets = PROTOCOL_LEAK_LEDGER.get(pkg, {})
        for form, count in sorted(counts.items()):
            budget = budgets.get(form, 0)
            if count > budget:
                over.append(f"  {pkg}: {count} {form}, budget {budget}")
    assert not over, (
        "presentation tier constructs protocol:\n"
        + "\n".join(over)
        + "\n\nProtocol construction in a renderer names a missing entity-sdk "
        "affordance. Add the SDK call instead of inlining the protocol — that "
        "is the whole point of this gate (review §6.1 gate 3)."
    )


def test_protocol_leak_ledger_is_not_stale() -> None:
    """Each budget tracks reality downward, so the ratchet keeps biting."""
    roots = _package_roots()
    stale: list[str] = []
    for pkg, budgets in sorted(PROTOCOL_LEAK_LEDGER.items()):
        if pkg not in roots:
            continue
        counts = _protocol_leak_counts(roots[pkg])
        for form, budget in sorted(budgets.items()):
            if counts[form] < budget:
                stale.append(
                    f"  {pkg}.{form}: budget {budget}, actual {counts[form]} — lower the budget"
                )
    assert not stale, "protocol-leak budget is stale:\n" + "\n".join(stale)


# --------------------------------------------------------------------------
# The gates' own floor
# --------------------------------------------------------------------------


def test_gates_see_the_packages() -> None:
    """Guard against a path change silently reducing every gate to a no-op.

    Each gate above passes vacuously if `_package_roots()` returns nothing, so
    the discovery itself is asserted.
    """
    roots = _package_roots()
    assert {"entity_core", "entity_handlers", "entity_cli"} <= roots.keys(), (
        f"package discovery found {sorted(roots)} under {PACKAGES_DIR} — "
        "the layering gates cannot bind"
    )
    # Self-maintaining: every distribution on disk must be discovered, so a new
    # package cannot land unseen by the gates just because nobody listed it here.
    on_disk = {p.name for p in PACKAGES_DIR.iterdir() if (p / "pyproject.toml").exists()}
    discovered = {DIST_NAME[pkg] for pkg in roots}
    assert on_disk == discovered, (
        f"packages on disk {sorted(on_disk)} != discovered {sorted(discovered)} — "
        "a package whose source root the gates cannot find is a package the "
        "gates do not check"
    )


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is 3.11+")
def test_every_discovered_package_has_a_dist_name() -> None:
    """A new package must register in both maps before the gates can bind."""
    for pkg in _package_roots():
        assert pkg in DIST_NAME, f"{pkg!r} missing from DIST_NAME in {__file__}"
        assert (PACKAGES_DIR / DIST_NAME[pkg] / "pyproject.toml").exists(), (
            f"{pkg!r} maps to distribution {DIST_NAME[pkg]!r}, but "
            f"packages/{DIST_NAME[pkg]}/pyproject.toml does not exist"
        )
