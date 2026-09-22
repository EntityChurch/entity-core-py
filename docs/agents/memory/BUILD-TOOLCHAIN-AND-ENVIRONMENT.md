# Build, toolchain and environment

**When to open this:** Open this when the container build fails somewhere you do not recognise, when a lint class looks cosmetic, or before any bulk file operation.

The venv, the podman cache, ruff's non-cosmetic classes, and the shell hazards that have cost real work here.

> These entries were moved verbatim out of `AGENTS.md`. Each is a finding with a
> mechanism and, where one exists, a named enforcement point. An entry that could
> become a check should become one — and then it leaves this file.

---

- **The Bash tool's working directory persists between calls, and a relative `rm -rf` is where
  that becomes destructive.** *Candidate, 2026-08-22 — cost: the entire `docs/` tree, recovered
  from git in one command because it was committed.* A `cd docs/status` inside one call was still
  in effect two calls later; a cleanup line reading `ls -d docs && rm -rf docs`, written believing
  the shell was in a nested stray directory, executed at **repo root** and deleted every doc in
  the repo. Everything tracked came back with `git checkout -- docs`; the one uncommitted edit did
  not. Three standing consequences, and the first is the one with teeth:
  1. **Never `rm` a relative path.** The tool's own guidance says a compound `cd` can trip
     permissions — the sharper reason is that it silently changes what every later relative path
     means. Absolute paths only, and prefer `git mv` / `git rm` so the operation is reversible by
     the thing that already tracks it.
  2. **`git checkout -- <path>` is a real undo only for committed work** — the same trap as the
     mutation discipline's *"mutate a committed file"*, arriving from the cleanup side. Commit
     before any bulk file operation, not after.
  3. A directory existing is not evidence it is the one you meant. `ls -d docs` succeeded because
     `docs/` exists **everywhere** in this repo's subtree; the check confirmed the name, never the
     location. When a guard and the action share a relative path, the guard tests nothing.

- **The canonical build trusts a host cache it does not own, and a partially-reaped cache entry
  fails as a bug in an unrelated package.** *Candidate, 2026-08-30 — cost: `make build` red on this
  box, and a sibling seat reporting our repo as unbuildable.* `entity-core-go` could not measure a
  python peer at all and routed it as *"python's `uv.lock` / build backend needs fixing"*. **It was
  neither.** The identical `uv sync --frozen --no-dev --all-packages --no-editable` succeeds in a
  clean container with no cache mount — that control is what proves the manifests were never the
  problem. The failure is that buildah puts `--mount=type=cache` under **`/var/tmp`**, which Fedora
  reaps at 30 days (`q /var/tmp 1777 root root 30d`, `/usr/lib/tmpfiles.d/tmp.conf`), and the reap is
  **partial**: it removed `trove_classifiers/__init__.py` (43 577 bytes, still listed in the entry's
  own `RECORD`) while leaving the package directory, `py.typed` and the whole `dist-info` in place.
  uv re-uses the archive entry without validating it, and **an empty package directory imports
  cleanly as a PEP 420 namespace package** — so hatchling got a module with zero attributes and died
  on `AttributeError: module 'trove_classifiers' has no attribute 'classifiers'`, a message that
  names a third-party package and points nowhere near the cause. Measured: 99 of 1232 archive
  entries were damaged, every one on the far side of the 30-day line and every intact one inside it.
  **Two things to carry, and the second is the one with teeth:**
  1. **A dependency floats unless the lockfile contains it.** `uv.lock` has **zero** occurrences of
     `hatchling` or `trove-classifiers`: `--frozen` freezes *runtime* deps, while the build backend
     is resolved fresh in an isolated build env. The Dockerfile already documents this class getting
     us once (uv 0.9.30, hatchling's build venv missing `packaging`) and the fix then was to pin
     **uv** — which addressed that instance's proximate cause and left the floating surface open.
     Second instance, different package, same surface.
  2. **A shared cache is shared blast radius.** The mount was keyed only by target path, so every
     podman build by this user shared one cache and inherited one reaping. The mount now carries an
     explicit `id=entity-core-py-uv`, which is the fix that made `make build` green — *and it is
     isolation, not immunity: the new namespace is still under `/var/tmp` and will age out the same
     way.* **The durable check is the diagnostic one:** when a container build fails inside a package
     you do not depend on directly, re-run the same command in a clean container with **no cache
     mount** before believing anything about your manifests. That control costs one command and
     inverts the diagnosis.
  **And the routed claim about us was wrong in the flattering-to-nobody direction** — the standing
  *"a routed report's claims about our repo are hearsay"* rule, with our **build** as the subject
  rather than our architecture, coverage, version, or filing record. Their measurement (*the peer
  does not build here*) was correct and reproducible; their **attribution** was not, and it named a
  file that is fine.

- **F821 is not part of the deferred ruff sweep, and a broad `except` is where it hides.**
  *Ratified 2026-08-17 — bit us twice in one pass, in two different shapes.* `make check`
  is red on ~660 findings deliberately deferred, but F821 does not report style: it reports
  a name that is not bound. Two of the 16 were live bugs and **neither was reachable by the
  suite**: `compare_types_with_peer` compared against an unbound `remote_hash`, covered only
  by `tests/interop/` (skipped without a live Rust peer); `_link_content_hash` called an
  unimported `Entity` **inside its own `except Exception`**, so the documented recompute
  fallback returned `None` every time and CAP-FREEZE-1's cross-format check silently
  abstained. The second shape is the dangerous one — *a `NameError` swallowed by a broad
  `except` turns a security check into a no-op with no moment at which it looks wrong.*
  Enforcement point: `tests/unit/test_undefined_names.py`, ratcheted at **zero**, with a
  missing `ruff` failing rather than skipping so the gate cannot read green by not running.
  **Corollary for the other 645:** before dismissing a lint class as cosmetic, ask which of
  its findings would be *invisible at runtime* — that subset is not cosmetic.

- **A stale venv is a false green that only subprocess tests can see.** *2026-08-17.*
  All six package registrations for `entity-sdk` were correct in the files, but the local
  `.venv` had never installed it. `[tool.pytest.ini_options] pythonpath` makes a package
  importable **in-process**, so 3482 tests passed while the three tests that spawn the CLI
  via `python -m entity_cli.main` failed with `ModuleNotFoundError: entity_sdk`. Fix is
  `uv sync`; note `uv run` may refuse on the `.python-version` pin (3.12) when the venv is
  3.11 — `uv sync --python .venv/bin/python`, or invoke tools as `.venv/bin/python -m …`.
  **The general form:** a green in-process suite says nothing about packaging. The
  subprocess tests are the only ones that exercise it, so a failure there is a packaging
  claim, not a flake — check `ls .venv/lib/*/site-packages | grep entity` before theorising.
