"""The versioning convention, as a gate.

`AGENTS.md` §Versioning and `CHANGELOG.md`'s *"What the version numbers here
mean"* declare three things about this repo's version number, none of which had
an enforcement point before this file:

1. **All four workspace packages share one version and release together**, and
   their inter-package dependency floors move with them.
2. **`pyproject.toml` is the single source of truth.** ``entity_core.__version__``
   is *derived* from installed package metadata, not restated as a literal.
3. **`uv.lock` agrees with the manifests**, or the canonical container build
   fails at ``uv sync --frozen`` — which is a slow, confusing way to learn that
   someone bumped five files and forgot the sixth command.

Why this file exists at all: ``entity_core.__version__`` was a hand-maintained
literal that had drifted to ``0.1.0`` while every ``pyproject.toml`` said
``0.8.0``. Nothing caught it, because **nothing consumed it** — the classic shape
in this repo's charter, a value with a writer and no reader. The fix was to
remove the second representation rather than to correct it; these rows keep it
removed.

Note what is deliberately *not* asserted here: that the version equals the
protocol version. It does not, on purpose — see `AGENTS.md` §Versioning. Per
[ADR-0002] the spec level is carried out-of-band, so a gate tying the two
together would re-introduce exactly the conflation that ADR rejected.

**Mutation-verified at `9bff155`** — five mutations, each RED on exactly the
predicted row and green everywhere else, so no row here is riding on another's
coverage: a member package bumped out of lockstep; a dependency floor reverted
to `>=0.8.0`; ``__version__`` re-added as a literal at the *correct* value (the
row that proves the literal gate binds on shape, not on value); the same literal
at a *drifted* value (literal + mismatch, both); and a hand-edited stale
``uv.lock``.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES_DIR = REPO_ROOT / "packages"

# The workspace: the root manifest plus every member package. Distribution
# names, as they appear in `pyproject.toml` and in `uv.lock`.
ROOT_DIST = "entity-core-workspace"
MEMBER_DISTS = ("entity-core", "entity-handlers", "entity-sdk", "entity-cli")

# A version *claim* — a literal that asserts a release number. Deliberately not
# a bare "does this file mention a number" search: the prose in `__init__.py`
# names the versions that drifted, and a gate that cannot tell a mention from a
# claim is the same defect as counting `entity://` in docstrings.
_VERSION_LITERAL = re.compile(r"^\d+\.\d+")


def _declared_version(pyproject: Path) -> str:
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]


def _member_pyproject(dist: str) -> Path:
    return PACKAGES_DIR / dist / "pyproject.toml"


def test_every_workspace_package_declares_the_same_version() -> None:
    """One version across the workspace — they release together."""
    declared = {ROOT_DIST: _declared_version(REPO_ROOT / "pyproject.toml")}
    for dist in MEMBER_DISTS:
        declared[dist] = _declared_version(_member_pyproject(dist))

    assert len(set(declared.values())) == 1, (
        "the workspace packages have drifted apart in version. They share one "
        f"version line and release together (AGENTS.md §Versioning): {declared}"
    )


def test_inter_package_dependency_floors_track_the_shared_version() -> None:
    """A 0.9.0 CLI must not declare that a 0.8.0 core will do.

    A mixed installation is not a configuration this repo tests, so the floors
    are part of the bump rather than an afterthought.
    """
    shared = _declared_version(REPO_ROOT / "pyproject.toml")
    stale: dict[str, list[str]] = {}

    for dist in MEMBER_DISTS:
        data = tomllib.loads(_member_pyproject(dist).read_text(encoding="utf-8"))
        for dep in data["project"].get("dependencies", []):
            name = re.split(r"[<>=!~\[]", dep, maxsplit=1)[0].strip()
            if name not in MEMBER_DISTS:
                continue  # third-party floor; not ours to move
            if dep.strip() != f"{name}>={shared}":
                stale.setdefault(dist, []).append(dep)

    assert not stale, (
        f"intra-workspace dependency floors are not at the shared version {shared!r}. "
        f"Bumping the version means moving these too: {stale}"
    )


def test_entity_core_version_is_derived_and_not_a_second_literal() -> None:
    """``__version__`` must not restate the number `pyproject.toml` already holds.

    This is the row with teeth. It was a literal, it drifted to ``0.1.0``
    against a declared ``0.8.0``, and the whole suite stayed green because no
    other code read it. Re-adding a literal here re-opens that drift, so the
    gate is on the *shape* of the assignment rather than on its current value.
    """
    source = (
        PACKAGES_DIR / "entity-core" / "src" / "entity_core" / "__init__.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)

    claims: list[str] = []
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__version__" for t in targets):
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if _VERSION_LITERAL.match(value.value):
                claims.append(value.value)

    assert not claims, (
        "entity_core.__version__ is assigned a hardcoded version literal "
        f"{claims}. It must be derived from installed package metadata — "
        "pyproject.toml is the single source of truth, and a second copy of "
        "the number is what drifted to 0.1.0 last time."
    )


def test_entity_core_version_matches_the_declared_version() -> None:
    """The derived value actually resolves, and resolves to the declared number.

    Guards the failure mode the derivation introduces in place of the drift: an
    install where `importlib.metadata` cannot see the distribution silently
    yields the ``0+unknown`` fallback.
    """
    import entity_core

    expected = _declared_version(_member_pyproject("entity-core"))
    assert entity_core.__version__ == expected, (
        f"entity_core.__version__ is {entity_core.__version__!r}, expected "
        f"{expected!r} from packages/entity-core/pyproject.toml. "
        "'0+unknown' means the package is not installed in this environment."
    )


def test_uv_lock_agrees_with_the_manifests() -> None:
    """Catch a forgotten ``uv lock`` here, not 90 seconds into a container build.

    ``uv sync --frozen`` (both Dockerfile stages) refuses a lock that disagrees
    with the manifests, so a version bump without a re-lock takes down the
    canonical build with an error about the lockfile rather than about the bump.
    """
    locked = {
        pkg["name"]: pkg["version"]
        for pkg in tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))[
            "package"
        ]
    }
    shared = _declared_version(REPO_ROOT / "pyproject.toml")

    mismatched = {
        dist: locked.get(dist)
        for dist in (ROOT_DIST, *MEMBER_DISTS)
        if locked.get(dist) != shared
    }
    assert not mismatched, (
        f"uv.lock disagrees with the manifests (declared {shared!r}): {mismatched}. "
        "Re-run `uv lock` after a version bump."
    )
