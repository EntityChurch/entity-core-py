
# entity-core-py

Read **AGENTS-STANDARD.md** first. This file adds entity-core-py specifics.

## Overview

Python implementation of the Entity Core Protocol (V7; the wire identifier §8.4 pins is
**`entity-core/1.0`** — this line said `entity-core/7.0` until 2026-09-01 and that is where
the peer got it), built as a
clean-room peer for **interoperability testing against the Rust implementation** — it
validates that the spec is clear and complete enough to build compatible implementations.
The spec is upstream; this repo implements it.

## Versioning — ours, and it is NOT the protocol version

**This repo's release version is its own. The protocol version is a different number and
they are expected to disagree.** `entity-core` 0.9.0 implements Entity Core Protocol
0.8.2. Full reasoning: the *"What the version numbers here mean"* section at the top of
`CHANGELOG.md` — that section is the canonical statement and this is the pointer to it.

The short form:

- **Per [ADR-0002], the spec level an implementation targets is carried out-of-band**, never
  baked into the release number. That ADR rejected a 4-field `W.X.Y.Z` scheme precisely
  because one string cannot carry both *which spec level we target* and *our own release*
  without conflating them. Each changelog entry names its protocol level on a `Protocol:` line.
- At the `v0.8.0` Genesis release the two numbers coincided — the package version was simply
  set to the protocol version of the day. **That was a starting condition, not a scheme.**
  Reading it as one is how `0.8.2` nearly got stamped across this repo from outside.
- **All four workspace packages share one version and release together**, and the
  inter-package dependency floors move with them. A mixed installation is not a configuration
  we test.
- **`pyproject.toml` is the single source of truth.** `entity_core.__version__` is read from
  installed package metadata — it is not a second literal to maintain, because it was one and
  it silently drifted to `0.1.0`.
- **The number is not the contract; conformance is** ([ADR-0012]). Cite a measurement by its
  oracle commit, never by a release number — which is why a conformance emission pins
  `impl_version` to the git sha.

Bumping: 0.x SemVer — minor for added surface or a break, patch for fixes. Changing the number
means editing **five** `version =` lines (root + four packages) plus the dependency floors, and
then regenerating `uv.lock`, or the container build fails at `uv sync --frozen`.

## How we work here — tier **CORE**

This repo runs the entity-OS methodology at the **Core** tier — the framework is
`METHODOLOGY.md` (injected, identical everywhere; read it once). Conformance gates the wire
here. It does **not** catch process drift, stale build-state claims, unaccounted accumulation,
or a discipline quietly eaten by a competing legitimate pressure. Those need the ratchet.

What binds today:

- **Universal disciplines D1–D12** (`METHODOLOGY.md` §4) — apply as written; nothing to re-derive.
- **The review questions** (§6) — run on every diff.
- **The Audit Doctrine A0–A12** (§7.2) — open it for *"Y is broken"* or *"something feels
  wrong,"* including when the thing that feels wrong is our own process. **A1 is the prime:
  trace a value before you theorize.** The Foundation Audit Doctrine (§7.3) when opening a new
  surface to design against.
- **The ratchet** — every audit ends by syncing what it taught into this file, same session.
  **If it didn't land here, it didn't land.**
- **The promotion ladder** (§3) — bit us once → an anti-pattern entry; a second time in a
  different shape → a ratified discipline. Candidates are applied, not yet claimed to generalize.
  **A discipline with no enforcement point is theater** — name the grep, the lint rule, or the
  gate test.

**Owed:** a standing `DISCIPLINE-*` doc assembling this repo's own rules with an anti-pattern
catalog, each entry grounded by a source commit. The near-term native candidate is the encoding
class this stack forces — cbor2 float16 minimization is a known Rule-4 gap, and any
float-carrying entity type is a cross-impl hash divergence waiting to be filed as someone
else's bug.

## Setup / environment

- **Canonical build/test needs only `make` + `podman`** on the host — no host toolchain.
- **Local dev (optional):** Python **3.11+** and **`uv`** on the host. The Dockerfile pins
  Python **3.12** + uv.
- **uv workspace of 4 packages** (entity-core, entity-handlers, entity-sdk, entity-cli);
  `uv sync` installs all.
- `tests/interop/` runs against a **live Rust peer** — start one before running them
  (see Build & test).
- Identities live in `~/.entity/identities/<name>/`.

## Build & test

```bash
make build                                  # canonical (make + podman)
make test                                   # canonical full suite

uv sync                                     # local dev: install the workspace
uv run pytest                               # local dev: full suite
uv run pytest tests/unit/test_diagnostic.py # one file
uv run pytest -k delegation                 # one test by name
uv run pytest tests/interop/ -v             # interop suite (needs a live Rust peer)
```

Interop, against a running Rust peer:

```bash
# Terminal 1 — Rust peer:  cd ../entity-core && cargo run -p entity-cli -- peer start test-peer -l 127.0.0.1:9000
# Terminal 2 — Python peer: uv run entity-core start --listen 127.0.0.1:9001 -i my-identity
# Terminal 3 — tests:       uv run pytest tests/interop/ -v
```

Tests should be **fast and deterministic** (300+ tests, target <1s); prefer integration
tests over mocks for protocol code.

**Verify with pytest, not inline scripts.** Do **not** run `uv run python -c "..."` /
`python -c "..."`, and do not create throwaway verification scripts. The workflow is
edit → `uv run pytest` (scoped or full) → fix. If a fact is worth checking (a registry
entry, a type, a registered handler, a wire shape), it's worth a pytest assertion.

**Debugging cross-impl failures: observe before reading source.** When a cross-impl probe
fails, first run the same workload through `entity_core.diagnostic.DispatchTap`/`ContentTap`
and read the histogram — don't start by reading source. `DispatchTap.wrap(handler)` records
`(pattern, op, status, error_code, …)` per call (`tap.summary()` / `histogram()` /
`failures()`); `ContentTap(content_store)` records persisted entities by type. Module:
`packages/entity-core/src/entity_core/diagnostic/`; examples in `tests/unit/test_diagnostic.py`.

## Code style

- Python 3.11+; type hints on all public APIs.
- `dataclasses` for message types; `asyncio` for networking; the `cryptography` library
  for Ed25519.
- **ECF (Entity Canonical Form)** = deterministic CBOR per RFC 8949 §4.2
  (`cbor2.dumps(obj, canonical=True)`) for all wire encoding and hashing; **all field
  values preserved, no omissions**. See the upstream `ENTITY-CBOR-ENCODING.md` in the
  spec repo (`../entity-core-architecture/`).
- **No legacy / back-compat code.** This is a clean-room impl with no old peers to stay
  compatible with — as the spec lands, delete legacy / deprecated / dual-format paths
  (and tests that only assert them) rather than preserving them. Verify against
  IMPLEMENTATION-SPEC whether a path is current-spec before cutting; don't keep
  confirmed-legacy around "just in case."

## Project structure

uv workspace under `packages/`, with a strict dependency direction — **enforced**, see
"The tier gates" below. **Target shape is five packages**
(`entity-core → entity-handlers → entity-sdk → entity-app → presentation`), per
`docs/architecture/reviews/REVIEW-THE-SDK-AND-APPLICATION-TIER-GAP-2026-08-17.md`. Unlike
go/rust, this repo carries the SDK and application tiers **in-tree** rather than splitting
them out — which is only safe because the isolation is mechanical rather than stated.
`entity-sdk` and `entity-app` are already in the gate's tier map; they bind on their first
file. **Four packages exist today** — tiers `entity-core` (0) → `entity-handlers` (1) →
`entity-sdk` (2) → `entity-cli` (presentation); `entity-app` is still unbuilt:

- **entity-core** (minimal, stable) — `crypto/`, `protocol/`, `capability/`, `storage/`,
  `types/`, `utils/` (ECF), `peer/` (Peer, PeerBuilder, Connection), and `handlers/`
  (**registry + context + bootstrap ONLY**; bootstrap is MUST-per-spec, handles
  hello/identify).
- **entity-handlers** (standard, optional) — `tree.py`, `system.py`, `storage.py`,
  `query.py`, `manifest.py`.
- **entity-sdk** (L1 operations, `SDK-OPERATIONS` v0.8) — `client.py` (`EntityClient`:
  get/put/put_cas/list/remove/has/watch/unwatch + the `execute` primitive), `errors.py`
  (the §12 hierarchy), `paths.py` (§2.5 resolution), `events.py` (§6 change notification),
  `store.py` (the **Level 0** surface); **L3 extension wrappers** — `subscription.py`
  (§3, the cross-peer half of §6; `client.watch` remains the L1 emit-pathway surface),
  `query.py` (§6 + the fluent builder, reachable as `client.query()`; closes §16.2's
  `§5.1 query` SHOULD), and `registry.py` (
  `EXTENSION-REGISTRY` §6a.9/§6a.9.2 register/renew/revoke + issuer-policy; note registry
  appears in **neither** §14 nor §15 of `SDK-EXTENSION-OPERATIONS`, and the extension says
  why — *"this extension stops at the handler contract"* — so the method names are ours
  under the advisory tier while the wire is not), and `revision.py` (§4 /
  `EXTENSION-REVISION` §4 — all nineteen handler operations plus `find_ancestor`, bound to
  a prefix by `client.revision(prefix)`; the largest L3 surface, and the one where the SDK
  doc's drift stops being about names — see SA-PY-5/-6). **Depends on the kernel only** — it reaches
  handlers by dispatching to pattern strings and never imports `entity_handlers`, so the
  tier boundary holds by construction. **The §16.1 MUST list is COMPLETE** — the last row,
  §11.6 `register_handler`, is `handlers.py`: the four §11.6.1 paired writes in order, the
  collision check on **both** sides before any write, §11.6.2's handle (idempotent close,
  `async with`, and **no finalizer at all** — §11.6.2 forbids relying on GC, and a cleanup
  that only sometimes runs is worse than one that never does), §11.6.4 compensation with
  types exempt, and §12.5's four code strings as constants. **§11.6.9 service-owning
  handlers is deliberately unbuilt**: §16.1's MUST line does not name it, §11.6.9 says to
  prove the contract on a new extension first, and publishing its two type definitions with
  no producer would manufacture the type-census divergence §6a.9.3 warns about.
  **The dispatch index is not public surface** (§11.6 MUST NOT): `EntityClient` holds its
  peer privately, `HandlerRegistration` is the only way back out, and a test asserts the
  public names — because *"we didn't add an accessor"* is exactly what a later convenience
  method erases.
  - **Spec gaps found here go in `docs/SPEC-AMBIGUITIES.md`** and get routed upstream — not
    papered over at the call site. First entry: **SA-PY-1**, `SDK-OPERATIONS` §9's
    *"implemented as `list(...)`"* note contradicts §3.3's single-level-`list` MUST, because
    handler and type paths embed slash-bearing names. Following the note literally returns an
    **empty list**, which looks like a peer with no handlers rather than like a bug.
  - **The L0/L1 boundary is carried in the naming, by mandate.** §6.5: *"the naming MUST
    carry the boundary"*; §2.7 names two levels sharing one method name as the
    anti-pattern that hides it. So direct store access is only ever reachable as
    `client.store.…`, and `EntityClient` has no L0 method of its own. **L0 is local-only
    by construction, not by a policy check** — it needs an `EmitPathway`, which a client
    built over a `Connection` cannot produce, so `client.store` raises instead of
    degrading.
- **entity-cli** (presentation) — `main.py` (entry point), `display.py`. **Holds no
  protocol knowledge**: no envelope literals, no raw `.execute(uri=…)`, no hand-built
  `entity://`. Commands go through `entity_sdk`; `open_client()` is the entry point and
  `_fail()` renders a typed §12 exception. The raw `open_connection()` remains for the two
  callers that genuinely need a `Connection`.
- `tests/` — all tests together (`tests/unit/`, `tests/interop/`).

**Adding a package requires SIX registrations** — miss any and it builds locally but is
invisible to the container build, the type checker, or the gates:
1. `packages/{dist}/pyproject.toml` + `src/{import_name}/__init__.py`.
2. Root `pyproject.toml` → `[tool.uv.sources]`.
3. Root `pyproject.toml` → `[tool.pytest.ini_options] pythonpath`.
4. Root `pyproject.toml` → `[tool.mypy]` `mypy_path` **and** `packages`.
5. Root `pyproject.toml` → `[dependency-groups] dev` (this is the one the canonical
   `make test` container build needs; without it `uv sync` never builds the package and
   every import of it fails only *inside* the container).
6. `tests/unit/test_package_layering.py` → `TIER` **and** `DIST_NAME`.

**Adding a handler requires THREE things** — miss any and it appears registered but 404s
on operations:
1. Handler function in `entity-handlers`.
2. Manifest in `entity_handlers/manifest.py` → added to `ALL_HANDLER_MANIFESTS`.
3. Registration on the peer: a `with_X_handler()` method on `PeerBuilder` **and** that
   method called from `with_all_handlers()`.

Handlers needing persistent state (indexes, subscriptions) use an **Extension** (hooks
EmitPathway, initialized during `build()`); the handler is created via the extension so it
can reach the state.

### The tier gates — `tests/unit/test_package_layering.py`

The dependency direction above was **declared for months with no enforcement point and was
already violated** when the gates were written (2026-08-17): 37 imports of `entity_handlers`
from inside `entity-core`, all function-local, plus the matching undeclared dependency that
makes `with_all_handlers()` a latent `ImportError` on a standalone `entity-core` install.
Three gates now bind it:

1. **No upward imports** — *counting function-local and `TYPE_CHECKING` forms.* That detail
   **is** the gate: every existing violation is function-local, so a gate reading only
   module-level imports scores this repo clean.
2. **Cross-package imports are declared** in the importer's `pyproject.toml`.
3. **The presentation tier constructs no protocol** — no envelope literals, no raw
   `.execute(uri=…)`, no hand-built `entity://`. This is the load-bearing one. It exists
   because protocol knowledge inlined in `entity_cli/main.py` is *why* this repo had no L1
   SDK: the CLI was the SDK, written 17 times, in the one package nothing may depend on.
   **All three forms are at 0 and the ledger is empty** — `uri`/`dispatch` since the
   rebuild, `envelope` since `entity_sdk.registry` took the last two registry type names
   out of the renderer. An absent ledger entry is a **hard zero**, not an unwatched
   package, so re-adding one is a deliberate act to be argued for. **A gate must be able
   to tell a sanctioned call from a smuggled
   one** — counting every `.execute(` flagged `client.execute(...)`, which §3.6-3.9 names
   as *the* SDK contract, and a budget with a floor correct code cannot reach stops meaning
   anything. The `uri=` keyword is the discriminator. Same for docstrings: two `entity://`
   mentions in prose were inflating the count by two.

Every ledger entry is a **ratchet in both directions** — it may shrink, never grow, and an
entry that *overstates* reality fails too, so a ledger can never become permanent cover for
a violation already fixed. Each entry names the build-order step that retires it.

**Adding a package?** Register it in `TIER` and `DIST_NAME` first — an unregistered package
fails the gates rather than slipping past them.

## Boundaries — do NOT modify

- **`entity-core/handlers/` is registry + context + bootstrap ONLY** — keep it
  minimal/stable. Standard handlers belong in **entity-handlers**, not here.
- **The spec is upstream** (`../entity-core-architecture/.../IMPLEMENTATION-SPEC.md`,
  `ENTITY-CORE-PROTOCOL-V7.md`, `ENTITY-CBOR-ENCODING.md`, `EXTENSION-*.md`). This repo
  implements the spec; it does not define it. Hit a gap or ambiguity → log it and route
  upstream, don't paper over it locally.
- **Outside this repo: strictly read-only.** No git operations of any kind on sibling
  repos (`entity-core-architecture`, `entity-core-go`, …) — not even "safe" ones like
  `stash`/`pop`; no writes/edits/creates/deletes. Those trees hold other people's
  uncommitted work. Need newer state from a sibling? **Ask the user to pull it**; read
  the already-checked-out tree; never mutate it.

## Protocol / interop invariants agents get wrong

- **Strict entity fidelity (IMPLEMENTATION-SPEC §1.8) — the single biggest interop
  pitfall.** On receipt, validate the hash (compute from `{type, data}`, compare) and then
  **trust it: MUST NOT recompute**. **Store the original bytes** and **forward them as-is —
  MUST NOT re-serialize** when relaying. SHOULD preserve unknown fields. Recomputing or
  re-encoding silently breaks byte fidelity against the Rust peer.
- **Hash only `{type, data}`** — never `uri` or `content_hash`:
  `digest = SHA256(ECF({type, data}))`, format code `0x00` = ECFv1-SHA256 (flat
  `0x00‖digest`, 33 bytes). Use ECF (deterministic CBOR), never JSON, for hashing.
- **V7 dispatch authorization (defense-in-depth):** when `execute.resource` is present the
  dispatcher checks `grant.resources` **before** the handler runs. The tree handler's path
  comes from `resource.targets[0]`, **not** `params.data.path`.
- **Refless architecture:** entities have **no `refs` field**; references are
  `system/hash` values inside `data`. Signatures are **target-matched** — found by scanning
  `included` for a matching `data.target` (a capability's target is its `content_hash`).
- **A validator failure on a fixed port is a leftover peer until proven otherwise.**
  *2026-08-17.* `validate-complete.sh` binds **fixed** HTTP-poll ports (9451/9452), so a
  run that aborts leaves a peer holding them — one survived **seventeen minutes** into
  later runs here. It then presents as a peer defect wearing four different costumes: a
  refused dial (`tcp_connect`), a scoped peer that never comes up, and — the convincing
  one — a **content-fetch 404 under a stable root**, which reads exactly like the
  serving gap the vector's own message argues for, because the *stale* peer genuinely does
  not have the node. That message ("a node that will not fetch under a stable root is a
  serving gap, not a harness race") is right about its own peer and says nothing about
  *which* peer answered. **Before theorising, run `ss -ltnp | grep 945` and
  `podman ps | grep entity-pm`** — the question is not "is the root stable?" but "is this
  the peer I started?". Cost of skipping it here: a confidently-written handoff section
  diagnosing a race that did not exist.
  **Second instance, 2026-08-18, and the leftover was *our own previous run*.** A
  `validate-complete.sh` that exits non-zero mid-suite does **not** reap its peer container,
  so the next run's pass 2 dies on `[Errno 98] address already in use` at 9452 — and it
  presents as *"the namespace-scoped peer never comes up,"* which reads like the scoped
  configuration being broken rather than like a port. **So the discipline has a second half:
  after any validator run that did not exit 0, `podman stop entity-pm-*` before re-measuring.**
  The first run failed for a real reason (a genuine FAIL we then fixed); the failure it left
  behind was not related to that reason at all, which is exactly why the two get conflated.
  **Third instance, 2026-08-19, and the port was held by something that is not a peer at all.**
  `tests/interop/` dials a fixed `127.0.0.1:9000` and its `rust_peer_available` fixture skips on
  *"nothing is listening"* — so when an unrelated container publishes 9000 (here a Selenium
  `e2e-firefox` / `perf-chrome` from another project on the same host), the probe sees a
  listener, the suite does **not** skip, and `test_connect_to_rust_peer` dies mid-handshake with
  an `IncompleteReadError` that reads exactly like a protocol regression in whatever you just
  changed. **A liveness probe that tests for a socket rather than for a peer converts a foreign
  process into a false failure in your own diff.** Same first move as the other two: `ss -ltnp |
  grep 9000` before theorising, and check `podman ps` for a publisher — a container from an
  unrelated project counts. (Also: before running the validator, check `ps aux | grep
  validate-complete` — the fixed ports mean a **concurrent** run by another session collides
  with yours, and neither result is citable.)
  **And that pre-flight is a point-in-time sample, which is the half it does not say.**
  *2026-09-01:* the check was clean, and a `validate-complete.sh rust` from another session
  started **after** it and ran alongside. **The collision does not announce itself** — there is
  no port error and no message naming another run. The tell is the *count*: pass 1 reported
  `PARTIAL — 4 total ran` against an expected ~1616, i.e. the peer never came up and the run
  reported a shape, not a failure. **So the rule is: read pass 1's total before reading its
  verdict, and re-check `ps aux` when it is anomalous** — a two-order-of-magnitude shortfall is
  a harness fact, never a conformance result, and it is the one number that separates
  "collided" from "failed" without any log-reading at all.
  **Fourth instance, 2026-08-22, and the leftover was a peer *this session* started and could not
  stop.** `validate-complete.sh python` came back `1591 P · 6 F`, all six `peer_issued`, all six
  saying `bind: address already in use` on `127.0.0.1:9401` — which is where `-peer-issued-addr`
  binds its fixture registry by default, and where a debugging peer started an hour earlier was
  still listening. **The new part is the remedy, because the usual one is unavailable:** this box
  blocks agents from killing processes by policy, so *"stop the leftover"* is not a move an agent
  has. `validate-complete.sh` takes `PI_PORT` from the environment, so the run was **re-measured**
  at `PI_PORT=9411` (→ `0 F`) rather than attributed to the collision from the log message. That
  ordering is the discipline and it is the *"it's the environment" is the flattering hypothesis*
  rule applied to the case where the flattering hypothesis is **true**: the error string named the
  cause outright and it was *still* cheaper to re-measure than to publish an attribution. **Two
  standing consequences:** before starting any long-lived peer for debugging, pick a port outside
  the harness's fixed set (`9000`, `9401`, `9451`, `9452`), because you may not be able to take it
  back; and when a fixed-port collision is unavoidable, look for the **environment override in the
  harness** before you look for a process to end.
  **Fifth instance, 2026-08-22, from the *creating* side — and the four entries above are all
  written by the seat that tripped over a leftover, which is why none of them fixed it.**
  ***RATIFIED*** — the shapes are now five deep and the remedy was never "be more careful".
  Every entry above ends in a *detection* rule (`ss -ltnp` first, re-measure on a free port,
  check `podman ps`). None asks why a peer outlives the session that started it, because from
  the tripping side the leftover is someone else's artifact. Measured here: `cmd_start` ended in
  a bare `await peer.serve_forever()` and installed **no signal handlers at all**, so
  - a peer started by hand ran until something signalled it, and **an agent on this host cannot
    signal anything** — `kill` was withdrawn precisely because agents leaned on it. A workflow
    whose only teardown is a tool you do not have is a workflow with no teardown.
  - `ENTRYPOINT ["entity-core"]` makes the peer **PID 1**, where the kernel does *not* apply a
    signal's default disposition: a SIGTERM with **no installed handler is discarded, not
    fatal**. So `podman stop` paid its full timeout and SIGKILLed — every time, for months —
    and the lesson everyone drew was *"reaping a peer means escalating to a kill."* The two
    leftover `entity-pm-*` containers reaped this session both logged it verbatim.
  - the `except KeyboardInterrupt` arm that *looked* like the shutdown path **never ran**.
    KeyboardInterrupt is raised into the event loop, not into the coroutine's `try`, so it
    propagated past the handler; measured pre-fix exit status was `-2` (killed by SIGINT), not
    `0`. **A shutdown path that has only ever been exercised by Ctrl+C in a terminal has never
    been exercised at all** — nothing in 4000 tests asserted an exit *status*, only that the
    process was gone, and SIGKILL satisfies that too.
  **The rule: a process an agent cannot reap must reap itself.** Where a lifetime cannot be
  bounded by the thing that created it, bound it at the process — `--max-lifetime`, defaulted
  from `$ENTITY_PEER_MAX_LIFETIME`, because a *flag* binds only the peers whose author
  remembered it, which is exactly the set that was never the problem. A malformed value is a
  hard refusal: a typo'd bound is a request for a bound, and demoting it to "unbounded" hands
  back the leak at the one moment nobody is looking.
  **And the test has to assert the property, not the symptom** — *the port comes back*, and a
  **clean** exit status. A peer that dies without running `stop()` also exits and also frees its
  port; a liveness-only row scores the broken peer green, which is how this survived five
  entries' worth of attention. Enforcement point:
  `tests/integration/test_peer_max_lifetime.py` — the flag, the env default, the explicit-zero
  override, SIGTERM, SIGINT, and the malformed-env refusals, each mutation-verified RED on
  exactly the predicted rows (four mutations: race unarmed, env fail-open, env unwired, handlers
  uninstalled). The teeth control holds an *unbounded* peer up across the same window, so the
  headline row's exit is attributable to the flag rather than to a peer falling over on boot.

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

- **A rule that only makes sense against a stricter core is a rule you cannot test here — say
  so in the test rather than letting it read as covered.** *Candidate, 2026-08-18, building
  §11.6.* Two of §11.6's rules turned out to be unobservable in this peer, in opposite ways:
  - **The write ORDER** (tree first, dispatch index second) exists to close a window in which
    dispatch reaches a handler the tree does not declare. This peer cannot open that window —
    V7 §6.2 already makes the handler entity and its grant dispatch prerequisites, so an
    index-first implementation 403s rather than serves. Implemented as written anyway, because
    the rule is cross-impl and a peer that relaxes §6.2 later inherits the window silently.
  - **Close's ordering** has the same shape from the other side: removing the tree entries
    alone already stops dispatch, so the obvious *"dispatch stops after close"* test passes
    against an implementation that forgets to unregister the index. Found by **mutation** —
    the mutation was caught, but by a different test than the one whose docstring claimed to
    be the sharp one. That docstring was corrected rather than the test moved.
  **The check:** when a mutation is caught by a test you did not predict, the prediction is
  the finding. Write down which test actually discriminates and why the obvious one does not —
  an over-claiming docstring is how a later reader deletes the test that was doing the work.

- **Two readings that agree everywhere your fixtures live are one reading, until an oracle
  writes the configuration you would not.** *Candidate, 2026-08-18 — SA-PY-17, found by
  `entity-core-go`'s `registry.v15_dispatch_grammar` against a **3820-test-green** tree.*
  `EXTENSION-REGISTRY` §4.1 step 2's dispatch filter can be read as narrowing per **name**
  (eligible = union of the matching entries' kinds) or per **backend** (a kind named in no
  entry is always consulted). We implemented the second, which is what step 2's own clarifying
  sentence says. **The two readings give identical answers for every configuration in which the
  narrowed backend is in the resolver chain** — and that is every fixture this repo had, plus
  every one a person writes, because narrowing to a backend you do not have looks like a typo.
  The oracle narrows to `did-web`, which the peer does not implement, and only there do the
  readings separate.
  **The check when a spec sentence admits two readings:** do not ask which is more natural, ask
  **what configuration distinguishes them**, and write that configuration down. If you cannot
  name one, the ambiguity is not yet real. If you can, that configuration is the test — and it
  will not be one your existing fixtures resemble, because a fixture is written by someone who
  already holds one of the readings.
  **And the tiebreaker, which is the part that generalizes past this bug:** *a reading under
  which one of the spec's own MUSTs protects nothing is the wrong reading.* §4.1a's catch-all
  MUST forbids naming a name-transmitting backend in the catch-all row; under our reading a
  backend simply **left out of the list** was consulted for every name — a strictly larger
  disclosure, reached by not writing a row rather than by writing a bad one. That argument
  decided it, not the oracle's authority, and it is the argument to reach for first, because it
  is available from the text alone before any peer has an opinion.
  **Corrected within the session, and the correction is the sharper half.** §4.1 step 2 has
  **two** edge cases, not one, and the catch-all argument only reaches the first (*a kind named
  in no entry, when another entry matches*). The second (*a kind named by an entry, when no
  entry matches*) changed in the same commit and was never argued for — it rode along because
  one edit touched both. **An oracle failure that makes you change behaviour is a claim about
  the rows it names, not about the rows the same edit happens to touch: enumerate them and
  justify each.** We settled on excluding in both, which is the conjunction of go's and rust's
  exclusions rather than either seat's position — chosen because it is the only reading that
  satisfies both of step 2's clauses *and* keeps the MUST non-evadable, and because §4.1 step 4
  already says *"fail-closed; no silent fallback."*
  **And the oracle was withdrawn, for the mirror-image reason.** core-go pulled
  `v15_dispatch_grammar` (`8d2f5ad`) with the ratchet *"a wire check must not discriminate on
  an unruled or divergent semantic"* — it passed go-on-go and failed a conformant rust peer.
  **Our error was the mirror image: we let a wire check settle an unruled semantic for us.**
  The check was right that we had a defect and wrong about which rows. *A failing oracle is
  evidence that something is wrong, never evidence about what is right* — and the giveaway here
  was available at the time: the probe narrowed to a backend the peer does not have, i.e. the
  only configuration in which the readings differ, which is exactly the shape of a check
  measuring a semantic rather than a behaviour.
  **Fourth instance, 2026-08-19, filed as SA-PY-23 with the claim *"this one has no bug in
  it"* — and ~~that was the new part~~ that claim was wrong, which is the new part.** §4.1 step 2
  requires a rule *"whose pattern matches unscoped names"* and never
  defines *unscoped name* as a predicate. go and py derived **two sound classifiers** that agree
  on every one of §4.1a's shipped rows and disagree on `*.*`, `a.b`, `*.e*`. We concluded
  neither was wrong and the corpus owed a sentence, took **the conjunction — the strictly larger
  refusal set** — on the section's own cost asymmetry (a false positive is a visible edit with a
  documented override, a false negative is silent irreversible disclosure), and filed.
  **All of that procedure was right and the conclusion it reached was still an under-refusal**,
  because the divergence we enumerated was not the whole divergence.
  ***RULED 2026-08-20*** (§4.1b, v1.19): four conditions, and the third clause **both** seats
  carried — *a dotted literal suffix the star cannot reach into is narrow* — is refused outright.
  *"Any literal at all" is not the line*, because dotted **bare** names are ordinary local names
  under §6a, so `*.lab` handed every such name a user typed to a third party while reading as
  scoped. The line is *does the literal identify an authority or a naming system*, hence §4.1b.1's
  **enumerated** suffix list (`.eth`, and it grows only by spec revision `[MUST]`).
  **The correction, and it is the reusable half:** *when you take the conjunction of two readings,
  you have bounded the disagreement — you have not bounded the error.* Both seats can be wrong in
  the same direction, and a conjunction inherits that shared error silently, because the rows where
  the seats agree are exactly the rows nobody re-examines. **So the conjunction move needs a second
  step: enumerate the rows the two readings agree on and ask what would make *those* wrong** — here,
  *"is `.lab` an authority?"* was never asked by either seat, and one honest reading of the question
  answers it in one line. Enforcement point:
  `test_registry_name_privacy.py::TestUnscopedReach::test_the_rows_the_v1_19_ruling_moved` (the
  moved rows, in both directions, each naming which rule moved it) plus
  `::test_the_enumerated_suffix_list_is_exactly_what_the_spec_enumerates`, which fails on a seat
  that "helpfully" adds `.sol` — because the list growing is a privacy decision, not a config change.

- **Being right about the conclusion is not being right about the rule — and the conclusion is
  what stops anyone re-reading the rule.** ***RATIFIED 2026-08-20*** *— second instance in a
  different shape, and the shapes are mirror images.*
  - *First shape (SA-PY-21 Q1, 2026-08-19).* Our **conclusion** was right (kind-scoped) and our
    **argument** was wrong; arch recorded the argument as explicitly not the justification. Cost:
    the reviewing seat spent a real argument writing the refutation.
  - *Second shape (SA-PY-23, 2026-08-20).* Our **conclusion** was right on `*.*` and `*.e*` — we
    moved to the conservative side ahead of any grammar — and our **rule** was wrong. Cost: a live
    disclosure hole on `*.lab`, a row our rule reached and our conclusion never covered, sitting in
    a **3931-test-green** tree behind a classifier we had just audited and moved.
  - *Third shape (R-27 clause 4, 2026-08-20) — the corollary, and it is the one with teeth.* Our
    **code** was right (authorize-then-validate) and our **reason** was weaker than the real one. We
    ordered it on a *kinds* argument: an authz verdict and a policy verdict are different things.
    Arch's ruling gives an **information-disclosure** reason — §4.3's refusal is deliberately verbose
    (*"every violation, not the first"*), so validating first hands a **config-shaped disclosure to a
    caller with no authority to change anything**. Same lines of code, materially different weight.
    **Cost: none yet, and that is the point** — nothing was wrong, so nothing would have surfaced,
    and *our reason would not have survived a refactor.* Anyone hoisting the violation computation to
    the top of the function reads a tidiness comment, sees no security argument, and reorders.
  **Why the second shape is worse than the first and the third is the sneakiest:** a wrong argument
  behind a right conclusion is inert until someone reads it; a wrong *rule* behind a right conclusion
  **keeps deciding new cases**, and every one it decides inherits the error; a **weak reason** behind
  right code is inert *until someone refactors*, and then it fails silently in the direction the
  comment licensed. The tell is identical in all three and it is a feeling, not a finding: *we
  already looked at this and moved.* **A conclusion you changed recently is the least-audited code
  you own** — the move feels like the audit and is not one.
  **The two checks, both cheap:**
  1. After adopting a position, write down the *rule* you adopted as a sentence, and find one input
     it decides that your evidence never touched.
  2. **Write down the strongest reason you know, not the one that convinced you** — the comment is
     the artifact a future refactor consults, and a correct implementation held for a weak reason is
     one refactor from incorrect. Where the reason is a security property, say which property, and
     put the assertion on the thing the property is about: clause 4's row asserts the **response
     body carries no violation list**, not the status code, because a peer can answer `not_entitled`
     and leak the list anyway.

- **"It's the environment" is the flattering hypothesis for a flaky gate, and it needs the same
  evidence as any other.** *Candidate, 2026-08-20 — and I published the under-evidenced version
  first, which is why it is here.* `concurrency.t2_1_sustained_load` (go's oracle: C workers ×
  **10 000 `tree.get`s**, p50 of the last window vs the first, ceiling **4.0x**) FAILed a run, so I
  re-ran on a quiet host, it PASSed, and I reported *"host load, not this diff."* **One confirming
  re-run is not evidence for an attribution** — it is evidence that the check is not deterministic,
  which is a different claim. Three runs later the numbers are: `36.7s → PASS` · `44.0s → FAIL 4.1x`
  (first-window 39.05 ms, last 161.02 ms) · `56.6s → FAIL 4.2x` (39.11 ms, 164.22 ms). **The failing
  windows are near-identical**, the verdict tracks the wall time of the 10k run, and *pass 1b passes
  every time on the same tree.* So the honest statement is *"py sits at 4.0–4.2x against a 4.0x
  ceiling and crosses it about half the time,"* and **whether the slowness is host-side or peer-side
  is not established** — it could equally be a real sustained-load degradation worth fixing or a
  ceiling too tight for a peer at py's throughput.
  **Same law as *"they read the spec differently" is the flattering hypothesis***, one floor down,
  with a flaky gate as the subject instead of a sibling's code. The environment is the hypothesis
  that costs you nothing and closes the question, which is exactly why it needs the higher bar.
  **The check:** for a gate that flips, **record the measured numbers across runs, never the
  verdict** — a verdict re-run until green reads identical to one that was green, and the numbers
  are what tell the two apart. The half that *is* established gets stated separately and stays
  stated: t2_1 drives `tree.get` on a hot path, so a diff on the registry config path is provably
  not on it. **"Not my diff" and "not the peer" are two claims; the evidence for the first says
  nothing about the second.**

- **A ruling you already satisfy produces no diff, and no diff produces no test.** *Candidate,
  2026-08-20 — R-27.* All **four** of R-27's clauses were already true here on the day it landed, and
  the same was true at `entity-core-go`. That reads as the cheapest possible ruling to absorb and it
  is the most dangerous one: **the normal forcing function for a test is a behaviour change**, so a
  ruling that demands none leaves the surface exactly as untested as it was before it became
  normative. Two of ours were *correct by accident* in the literal sense — `pin-bindings` is
  non-dispatchable because it falls through to `404 unknown_operation`, which nothing prevents a
  later refactor from routing, and it sits textually beside the two operations that *are* routed.
  **The check when a ruling lands and you already comply:** treat "already matched" as a **finding
  about your coverage**, not as work avoided — enumerate the clauses, and for each ask *what mutation
  would break this, and does anything catch it?* Enforcement point:
  `TestSetResolverConfigPinDeltaRequiresPinCap`'s clause rows (dispatchability, ordering, the
  ordering's *reason*, the byte-identity field-drop), each mutation-verified RED on exactly the
  predicted row — because the prediction is the finding, and here it was right for the first time in
  four attempts across this file's history.

- **A detector is only mutation-verified on the peer you mutated — on every other seat it is an
  unarmed claim.** ***RATIFIED 2026-08-30*** *— the "a control-only fixture is not coverage" law with
  a **cross-impl oracle** as the subject, and the first instance where the blind gate was a
  **sibling's** and we were the seat it read as green.* `entity-core-go`'s
  `auto_version.burst_convergence_no_capture_loss` is the wire detector for the last-burst-write
  loss. It is impl-agnostic **by construction** — its oracle is REVISION §6.1 `status.pending`, a
  spec field — and go verified its teeth honestly, by reverting the go fix and watching it go RED.
  It then reported **py PASS** and **rust FAIL**. Measured here: **the check cannot see a capture
  loss on a py peer at all.** With auto-version capture stopped outright by mutation, py still
  reported **16/16 PASS**; with the `pending` fix below, the identical mutation FAILs at the 8s
  settle window. Six clean runs PASS either way, so nothing about the green was suspicious.
  **The mechanism, and it is the reusable half.** `pending` was computed under `if local_hash:` —
  a guard that reads as a null-check and is a **ruling on the absent case**, so 0 meant two opposite
  things: *fully captured* and *captured nothing*. The detector bursts at a **freshly generated
  random prefix**, so a peer that captures nothing for that prefix never mints a head, answers 0,
  and passes the check whose entire purpose is that loss. This is the same shape as the
  `min(binding.ttl, local_max)` entry — a binary operator with no arm for the absent case — arriving
  as an **oracle** rather than an authorization control, and our fixtures sat on the arm with an
  answer exactly as they did there: `TestStatus` covered *(empty tree, no head)* → 0 and
  *(entities, head)* → >0, and never *(entities, no head)*, which is the only combination the guard
  decides.
  **`entity-core-go` carries the identical guard** (`if !headVal.IsZero()`, `ext/revision/status.go`)
  — so this is a blind spot in the **shared** oracle, not a py-vs-go divergence, and go's own teeth
  check could not reveal it because the go bug leaves a head behind. **A verified-RED mutation on
  one implementation licenses a claim about that implementation and nothing else**; the oracle being
  a spec field makes the check *portable*, which is not the same as *armed*.
  **What this does NOT license, stated because it is the tempting over-read:** py's PASS still rules
  out the *partial* shape (head exists, a later write uncaptured) — that arm was armed all along.
  The unmeasured half was total capture failure. **And it reframes rust's FAIL rather than excusing
  it:** a peer can only FAIL this check by having a head *and* uncaptured paths, so rust's
  `pending=3` is not reachable by the blind path and their finding stands as measured.
  **The checks, in the order they are cheap:**
  1. **When a sibling's gate reports you green, mutate your own peer until it goes red before you
     accept the row.** One mutation, one rebuild. A cross-impl check is a claim about your peer that
     someone else armed against theirs.
  2. **When a check's oracle is a spec-defined count, ask what that count answers in the state where
     the subject is absent** — and if the answer collides with the healthy value, the check is blind
     in exactly the state it exists to detect.
  Enforcement point: `tests/unit/test_revision_status_pending_oracle.py` —
  `test_live_paths_with_no_head_are_uncaptured_but_pending_reports_zero` (the arm nothing drove),
  the empty-tree control that keeps it a count rather than a flag, and the head-arm teeth row.
  *The teeth row's first draft asserted `pending == 0` right after `commit` and was wrong (measured
  1: commit writes the head pointer into the live tree, which the new version does not contain) —
  recorded because `test_status_after_commit` had already skipped that count for the same reason,
  and the prediction being wrong is the finding.*

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

- **A gate that skips when its dependency is absent has never told you it passes.** *Candidate,
  2026-08-21 — found incidentally, and it had been red since the initial public release.*
  `tests/integration/test_cross_impl_publish_fetch.py` is the headline Go-publishes→Python-consumes
  byte-equality drive. It `skipif`s cleanly when the Go toolchain or the sibling checkout is absent
  — deliberately, so a Python-only runner is not blocked. On **this** host both are present, and it
  **fails**: `scripts/fetch_published_fixture.py`'s `PINNED_ROOT_HASH` is
  `c0c1c2c3…dcdddedf` — the literal byte sequence `0xc0..0xdf`, a **placeholder that was never filled
  in**, against a fixture that actually serves `af1c9f6b…`. Bisected to session start and to the
  squashed release commit; it has never passed in visible history.
  **The shape:** *skip-on-absence* + *a dependency almost no runner has* = a check that reports
  green by not running, forever, and whose first real execution is a surprise. `AGENTS-STANDARD`
  already says **a skip counts as a failure**; what this adds is that the rule has to be applied to
  the *conditional* skip, which is the one that looks principled. **The check:** for every
  `skipif` on an external dependency, ask *when did this last actually run?* — and if the answer is
  "unknown", run it once on a host that has the dependency before trusting anything it guards.
  **Was deliberately left unfixed at filing:** the correct pin is not derivable from either tree
  (neither hash appears in any `.md` in `entity-core-go`), and **updating a pin to whatever the code
  currently emits is how a pin stops meaning anything** — that would convert a loud placeholder into
  a silent tautology. Routed to core-go with the measured value instead.
  ***CLOSED at `c27b07b`.*** `PINNED_ROOT_HASH` is now `af1c9f6b…cdd9ab` and the row **passes on a
  host that has the Go toolchain and the sibling checkout** — re-measured 2026-08-30, 2 passed. The
  resolution is the part worth keeping: the pin was *not* set by copying what our code emits. go's
  own consumer (`cmd/fetch-published-fixture/main.go`) verifies the signature and then only
  **prints** the root, so there was no upstream table row to mirror and never will be — which is
  why the slot was stubbed in the first place. Ours is the stricter of the two checks and the only
  one that would notice Go's tree-root computation moving under a fixture whose content did not
  change, so the pin is load-bearing *here and nowhere else in the cohort*, and the call-site
  comment says so. **A pin with no upstream mirror is not thereby a tautology — it is a pin whose
  justification has to live at the call site**, and that is the distinction the original entry
  could not yet draw.

- **A ruling routed to you carries an assumed baseline, and the baseline is the claim to check
  first.** ***RATIFIED 2026-08-21*** *— second instance of "a routed report's claims about our repo
  are hearsay", and the first where the wrong claim was about our **version** rather than our
  architecture or our coverage.*
  **Fourth instance, 2026-09-09, and the assumed baseline was in a section written TO US, by ARCH,
  that says it is scoped by a diff.** `ROUTING-2026-09-09-i` is addressed to `entity-core-go` and
  carries *"For `entity-core-rust` and `entity-core-py` — relay this section"*, opening with
  **"Scoped by the diff, not by what you shipped."** That sentence reads as a guarantee of
  completeness and is one — **for go**, whose baseline was 0.8.2.14. This repo was on **0.8.2.11**,
  so `.12`/`.13`/`.14` were never in anyone's diff and were never routed here at all. `0.8.2.13`
  had live work in it: the `system/*` registration reservation is **withdrawn**, and this peer was
  still enforcing it with a hardcoded prefix match ahead of authorization. Nothing in the relay
  mentions it, correctly, because go had absorbed it a revision earlier.
  **Why this axis is worse than the sibling-relay shapes above.** A sibling's packet is obviously
  written from a sibling's seat, and *"a routed report's claims about our repo are hearsay"* is
  already the reflex. This one is **arch's**, it is addressed to us by name, and its scoping
  sentence is *about* completeness — so the one place you would look for the caveat is the place
  that reassures you. A relay's per-seat worklist is scoped by **the routing seat's** diff, and no
  amount of care in writing it can make it scoped by yours.
  **The check, and it is the same two seconds as every other instance:** before working a routed
  worklist, `grep` your own tree for the protocol level you last absorbed and diff it against the
  ruling's. Here `grep -o "0\.8\.2\.[0-9]\+" ... | sort -V | uniq -c` answered it — 36 hits at
  `.11`, none above — and reframed a four-item worklist into a six-item one. **Then state your
  corrected baseline in the reply**, because the relaying seat's board is tracking you against the
  version it assumed. Enforcement point: the version census is the first command of any
  catch-up pass, and `0.8.2.13`'s withdrawal is recorded at the site it was removed from
  (`entity_handlers/handlers.py`) as an argument against re-adding it — a withdrawn rule leaves no
  failing test behind, so the comment is the only thing that stops it coming back.
 `ROUTING-2026-08-21-a` routes COMPUTE **v3.26** with the sentence
  *"rust and py are not yet on v3.26."* True and useless: **this repo was on v3.23.** v3.24 and
  v3.25 were never routed here at all, so §3.5's three contained positions — `assoc`'s `value`,
  `concat`'s elements, `group-by`'s `members` — **did not exist to carve out.** The ruling's entire
  content is a carve-out at a site we did not have.
  **Why this shape is worse than the other two, and it is the reusable half:** a wrong claim about
  our *shape* or our *coverage* fails loudly the moment you look. A wrong claim about our *version*
  fails **silently and in the flattering direction** — the diff is small, it applies cleanly, the
  suite is green, and you have shipped a carve-out guarding nothing while reporting the ruling
  absorbed. Nothing in the routed report is wrong; it is written by a seat whose own baseline is
  three versions ahead, and *the delta it names is the delta from **its** last state.*
  **The check, and it is one command:** before implementing a routed ruling, grep your own tree for
  the identifiers the ruling's *premise* depends on — not the ones it introduces. Here
  `git log --all -S assoc -- packages/` is empty, which is a two-second answer and reframes the
  whole task. State the corrected baseline in the reply, because the sibling's board is tracking
  you against the version it assumed.
  **And the version gap is scope, not an excuse to narrow.** The deliverable for C-6 is *"py builds
  v3.26"*, which here means three versions; landing the carve-out alone would have been a green diff
  that unblocks nothing and reads as done. Enforcement point:
  `tests/integration/test_compute_v324_collection_primitives.py`, whose module docstring records the
  measured baseline and the search that established it.
  **Second instance, 2026-08-22, and the assumed premise was a claim about our *behaviour*, made by
  the *ruling itself*, in the flattering direction.** Arch's §8 eval-limit ruling opens by stating
  what each seat does: *"rust and py short-circuit `budget_exhausted` and `cascade_limit` and
  **contain** `depth_exceeded`."* §5.3 concludes *"your `depth_exceeded` containment stands. Nothing
  owed,"* and core-go relayed it as *"C-14 — you were right."* **py short-circuited all three** —
  `_EVAL_LIMIT_CODES` at `f09ae70` — and **our own SA-PY-25 says so in its second paragraph**, which
  is where the mis-read came from: the filing argued for a *code-based* discriminator against go's
  provenance-based one, arch read that as agreeing with rust's *criterion*, and the criterion and the
  code set are different things. So the ruling arbitrated against go on one row and shipped a
  premise that excused the seat with the same defect.
  **Why this direction is the dangerous one, and it is the reusable half.** The other three shapes of
  this law (our architecture, our coverage, our version) all fail *loudly the moment you look* — you
  go to do the work and the tree disagrees. A wrong premise saying **you already comply** produces
  **no task at all**. It is the *"a ruling you already satisfy produces no diff"* trap with the
  compliance itself fabricated: the normal forcing function is absent, the board reads closed at
  three seats, and the row sits green because nobody was assigned to look. Ours would have shipped
  into a release, and the two sibling reports would have been the evidence it was fine.
  **The check, and it costs one grep:** when a routed ruling states what your seat does, **grep for
  the identifier before reading the ruling's argument** — `_EVAL_LIMIT_CODES` here, two seconds, and
  the whole packet reframes. Do it *especially* when the sentence is complimentary, because that is
  the one branch of the read that terminates in no work. And when the premise came from your own
  filing, check what the filing actually claimed: **an SA is read by someone reconciling three seats,
  and a paragraph arguing about a *discriminator* will be summarized as a position on the *outcome*.**
  Enforcement point:
  `test_compute_v327_closure_result_positions.py::TestDepthExceededContains` — CV-9a, the value-form
  depth row, and the fold-recovery row, each mutation-verified RED against the shipped set, plus
  `test_the_premise_of_8_3_holds_at_this_peer_depth_is_restored_on_unwind`, which is the one that
  would have caught it **unaided**: it asserts the *property the ruling reasons from* (§5.1's `depth`
  restored on unwind) in our tree rather than the conclusion the ruling drew. **When a ruling derives
  your behaviour from a property of your implementation, assert the property.** That row's first
  draft was driven through `map` and failed under the carve-out mutation too — i.e. it was measuring
  containment a second time and not the premise; driven bare it is orthogonal, which is the only way
  it can tell the two failures apart. *A row that fails for two reasons is a row that has told you
  nothing about either.*
  ***RATIFIED 2026-09-01 — second instance, and the property was asserted by the ruling's own
  justification rather than assumed by its premise.*** Filed as SA-PY-29. §6.2 (0.8.2.3) pins the
  default per-handler self-grant with `peers` omitted and justifies the shape behaviourally: *"A
  default-scope handler consequently **cannot** dispatch at a foreign peer, which is the escalation
  that matters."* Asserted here, that is false on **both** paths — inbound, PD-1h now refuses before
  `check_permission`; in-process, `_dispatch_local_execute` returns at `_remote_execute` **before**
  `_resolve_for_dispatch`, and `target_peer` is computed *below* that return, so the only value that
  can reach the four-dimension check is the local peer. Measured: a handler holding exactly the ruled
  grant, sub-dispatching at a foreign uri, gets **502 "No live transport profile"** — it went looking
  for a *route*, i.e. it had already decided the dispatch was permitted. **The ruled shape is inert.**
  **Two things this adds to the law.** First, the tell moved: in the §8.3 instance the unasserted
  property sat in the ruling's *premise* (what it said we do), and the check was to grep for the
  identifier. Here it sits in the ruling's *justification* (why the shape is right), which nobody
  greps because it reads as motivation rather than as a claim. **A justification is a claim about
  your peer whenever it contains a verb your peer is the subject of** — `cannot`, `is still checked`,
  `defaults to and is enforced`. Second: **a ruling can absorb a filing and answer a different
  question than the one filed.** 0.8.2.3 absorbed `entity-core-go`'s `2026-08-23-a`, which asked
  *where does the check bind*, and ruled *what shape the grant has* — while resting that ruling on
  the check binding. Both seats' boards read the item closed. **When a ruling names your filing as
  absorbed, re-read what the filing asked, not what the ruling settled.**
  Enforcement point: `tests/integration/test_peers_dimension_outbound_gap.py` — rows that **fail
  when the enforcement point lands**, each carrying its retirement condition in the assertion
  message, including a structural row asserting `target_peer` is still read *after* the remote
  branch. That row is the one worth copying: the missing check is not a missing `if` but an argument
  that cannot be anything except the local peer, and **a reviewer reading a correct-looking call
  site cannot see that one of its arguments is a constant** — so the row reads the source and pins
  the *order*, not the behaviour.

- **A fix that moves a refusal earlier retires the seam an existing test was standing on — and the
  stale row keeps passing for one release if the statuses happen to differ.** *Candidate, 2026-09-01,
  found by running the full suite rather than the new file.* PD-1h moved the foreign-namespace
  refusal from §5.2 authorization (403) to §1.4 canonicalization (400).
  `test_authz_peers_dimension.py::TestOverARealConnection` had two rows driving that seam: the one
  asserting `foreign == 403` failed loudly, which is how the seam-move was found — but its sibling
  asserted `foreign != 403`, and **that row passed, silently, now measuring nothing at all**. A
  negative assertion survives the very change that empties it. The class is broader than this fix:
  **when a refusal changes layer, every test written against the old layer is either a loud failure
  or a passing row that has stopped discriminating, and only the first kind tells you.** So the move
  is: grep for the *old status* across the suite, not for the function you changed. Here the honest
  outcome was that the `peers` dimension is no longer wire-observable at all (core-go's PD-1d #2
  reached from the other side), so the rows were **re-pointed at the gate and relabelled** rather
  than deleted — a reader who finds the class gone has no way to learn the seam moved. The
  re-pointed wildcard row is now the load-bearing one: it drives a request the grant *permits*,
  which is the case a peer with only an authorization path gets wrong, and the case the old row
  could not express.

- **A clause that names a grep as its enforcement point is read as having one — run the grep before
  you believe it.** *Candidate, 2026-08-22, filed as SA-PY-27.* D8's §10.3 clause 3 states a
  grammar invariant (*every reference field is a scalar `system/hash`*, with `apply.args` and
  `let.bindings` the two enumerated exceptions) and names the grep that binds it. Writing that grep
  and running it against the shipping grammar found **both halves wrong**: `compute/construct.fields`
  is a third `{map_of: system/hash}` reference container, unenumerated and long-shipping; and
  `compute/let.bindings` is declared `{array_of: primitive/any}` — its `value: system/hash` lives in
  an untyped struct described only in the prose beneath — so **the grep cannot match the one shape
  the whole ruling exists because of.** The clause enumerates as an exception a row its own
  enforcement point would never have flagged, and that is what makes the blindness read as coverage.
  Same law as the presentation-purity gate two entries down (*enumerate the forms the thing you are
  forbidding can take*), with a **spec clause** as the gate and the declared `type_ref` as the wrong
  inventory unit. **The check:** when a ruling hands you an enforcement point, implement the
  behavioural rule so your conformance does not depend on the gate being right, then build the gate
  and let it correct its author. Ours did, twice, in one run. Enforcement point:
  `tests/integration/test_compute_d8_walk_completeness.py::TestEveryReferenceFieldIsAScalarHash`,
  whose exception list carries *why* each row is there and whose
  `test_the_clause_3_grep_cannot_see_let_bindings_at_all` pins the blind spot rather than working
  around it — so the thing actually protecting us stays legible: the recursive traversal, not the
  grep.

- **Two hand-rolled copies of one traversal are one defect with two consequences, and the measured
  one is not the worse one.** *Candidate, 2026-08-22 — the two-representations law with a
  **traversal** as the subject, found while fixing D8.* `_walk_deps` (reactive dependency
  registration) and `_audit_walk` (install-time static audit) each carried their own copy of the same
  four-case enumeration. Arch measured `_walk_deps` and named its failure: a reactive expression that
  evaluates once and is never woken. **`_audit_walk` has the same gap with a worse consequence** — a
  `compute/apply` nested past the enumerated shapes is never reached, so its install-time
  capability/resource check and the F5 structural error never run, and the subgraph installs clean.
  Nobody named that site, in any of the three seats' reports. **The check:** when a routed finding
  names a function, grep for the *concept* rather than the identifier — a traversal, a matcher, a
  validator — and fix the class. The second copy is always the one written for a narrower purpose
  before the rule existed. Enforcement point: `_referenced_entities`, the single traversal both
  walkers now call, plus
  `test_compute_d8_walk_completeness.py::TestTheAuditWalkerSharesTheTraversal`, whose F5 row is the
  one with teeth.

- **Trace the value before you route the reading — the divergence you can see is rarely the one you
  read.** ***RATIFIED 2026-08-21*** *— A1 applied to a **sibling's** code, and the third instance of
  the SA-PY-9 shape. The first two cost the reviewing seat an argument; this one would have cost them
  a fix in the wrong function.*
  Building v3.24 I read two departures in `entity-core-go`: `builtinConcat` answering `type_mismatch`
  for an error-valued sub-collection, and `builtinAssoc` resolving args positionally against §8.2's
  canonical-order `[MUST]`. Both readings were correct about the source. **Driven on the wire against
  a live go peer, they collapsed into one defect with three call sites and one unmeasurable claim:**
  `resolveCollection` (`ext/compute/builtins.go`) evaluates the `collection` arg with `Evaluate`
  where `evalOperand` is required, so a consumed operand that is an error-as-value gets a **shape**
  verdict instead of propagating — at `concat`, at `assoc`, **and** at `group-by`, the third of which
  neither reading predicted. And the ordering claim is **not separable on the wire at all**, because
  the collection defect answers first and masks it.
  **Three things to carry:**
  1. **A source reading gives you the site; only a trace gives you the extent.** Two of the three
     call sites came from running it, not from reading it. Had we filed the reading, go fixes
     `builtinConcat`, both other sites stay open, and the report reads as closed.
  2. **A blocked claim is `skip` with a written retirement condition, never `xfail`.** An `xfail`
     here flips to XPASS the day the *other* bug is fixed and gets read as this claim confirming —
     a false green manufactured by the harness. Same law as the deferral rule (a deferral without a
     retirement condition is an omission with better prose), with a *test* as the subject.
  3. **Point the probe at your own peer too, in the same run.** Six rows, three of which fail on go,
     **all six passing against py** is what makes the report a measurement rather than an assertion;
     without the py leg it is *"our reading of the spec disagrees with your code."*
  **What could not settle it, and this is the tell:** go's compute corpus cross-blesses **352/352
  byte-identical** go↔py. Neither configuration is in it — the *"two readings that agree everywhere
  your fixtures live"* law, arriving as a **corpus** that agrees everywhere. A locked cross-bless is
  evidence about the vectors it contains and nothing else, and it is the most convincing green there
  is. Enforcement point: `tests/interop/test_go_peer_compute_v324.py` — three divergence rows, three
  discriminating controls (including one that localizes the defect to a single helper by showing
  `index` handled correctly), and the skipped ordering row carrying its own un-skip condition.
  **It is opt-in via `ENTITY_GO_PEER=host:port` with no default, and that is a real weakness to state
  rather than a design flourish:** rows asserting a *sibling's* conformance must not put our gate on
  their release schedule, but the cost is a skip-on-absence check — the very thing the entry above
  says has never told you it passes. So the obligation moves from the suite to the calendar: **run it
  on every cohort catch-up against core-go and before replying to any routed compute item**, and
  record the result with the go commit attached (`docs/status/ROUTING-2026-08-21-…`), never as a green
  suite. The py-side half of each row *is* armed in the fast suite
  (`test_compute_v324_collection_primitives.py::TestV325FlowThrough`), so a regression on **our** side
  of the disagreement fails immediately; only the claim about theirs is on the calendar.

- **A one-word disposition column is where a two-reading word loses its second reading — open the
  ruling, not the packet that tabulates it.** *Candidate, 2026-08-21 — the "hearsay" law with the
  **ruling itself** as the subject, where the previous three instances had our code, our filing
  record, and our version.*
  Arch's C-8 (`172589e`) ruled `map`/`filter`/`fold`'s closure-result positions. `entity-core-go`
  relayed it as a three-row table with a disposition column: `map` *contain* · `filter`
  *short-circuit* · `fold` **propagate** — a faithful transcription of arch's own heading word. Arch's
  next sentence is what that word meant: *"`fold` binds it into the next closure invocation and never
  reads it, **so a closure that ignores its accumulator recovers**,"* and D2 puts *"`fold`'s final
  accumulator"* in the contained set of five. go implemented `propagate` as **abort**. Both readings
  are ordinary English for the word; only one survives the paragraph under it, and **the table is the
  artifact everyone downstream implements from.**
  **The compression happened three times and each step was individually reasonable**, which is why
  nothing looked wrong:
  1. *The ruling* used a word with two readings for the position it separately flagged as *"the
     widest blast radius if wrong — the only one where the alternative reading produces a different
     **value**, not merely a different cost."*
  2. *The report* rendered it as a table cell, dropping the sentence that disambiguated it.
  3. *The vector* was seeded at the **position** rather than at the **discriminator**: CV-8c is
     `fold(λacc x.E, 0, [1])`, one element with the closure *returning* the error — contain and
     short-circuit give the same answer, so it locks under either reading. Arch's own conformance
     table names CV-8**d** instead (*a closure that **ignores** its accumulator*), *"deliberately the
     shape where contain and short-circuit produce different values"* — and the report's vector set
     did not include it.
  **The proof is first-hand and it is the part to keep: the 358-vector corpus cross-blessed
  byte-identical go↔py at the same commits where the two peers answer differently on four measured
  rows.** Not "a corpus could miss this" — *this* corpus, LOCKED, on the day. The enclosing law
  (*two readings that agree everywhere your fixtures live are one reading*) is long ratified; what is
  new is that **the fixture set was authored by the seat that had just been told which shape
  discriminates**, and still landed the other one.
  **The three checks, in the order they are cheap:**
  1. **When a routed report tabulates a ruling, open the ruling and read the sentence each cell
     compresses.** One `git show` in the sibling's tree. The disposition column is exactly where a
     word like *propagate* / *pass through* / *flow* loses the half that decides behaviour.
  2. **When you seed a vector for a ruled position, write the configuration in which the two
     readings answer differently — and if you cannot, say the vector is a control.** A vector at the
     position is not a vector at the discriminator, and the corpus cannot tell you which one you
     seeded.
  3. **A carve-out added to fix an asymmetry goes at the join, not on one arm.** go closed the
     provenance asymmetry in `map` and then re-opened it three codes wide by putting
     `isEvalLimitCode` on the minted arm only — so a stored `compute/error{code:"budget_exhausted"}`
     is contained there and propagated here. Same defect, same function, same commit that fixed it.
  Enforcement points: `tests/integration/test_compute_v327_closure_result_positions.py`
  (`TestFoldContainsTheAccumulator` — the CV-8d row, plus the CV-8c shape kept and **labelled as the
  non-discriminator** so nobody reintroduces it as coverage) and
  `tests/interop/test_go_peer_compute_v324.py::TestC8ClosureResultPositions`, whose two agreeing
  controls are what make the two divergent rows attributable.
  *Second instance of the deferral rule's forward half, recorded because it is still rare:* the §8.2
  arg-order row carried a written retirement condition in its `skip` reason, go discharged it at
  `ded9ea0`, and the row was armed and measured the same session — `coll_error` vs `idx_error`,
  confirmed. An `xfail` would have flipped to XPASS at `ded9ea0` and read as the claim confirming,
  which it was not.

- **A control-only fixture at a call site is not coverage — and the spec's own example is
  usually the control.** ***RATIFIED 2026-08-19*** *— the "matcher gains a call site" law
  (SA-PY-12) arriving from the coverage side, and the second instance of a test set whose only
  row cannot discriminate the thing it names.* `name_constraints` (§6a.9.1) was pointed at
  §4's matcher in `c65bfe2` and the choice was filed as SA-PY-14 — **correctly**, and the
  ruling adopted it (v1.15). What did not land in the same commit was a row that could tell
  the two candidate matchers apart. The only `name_constraints` test in the repo used `*.lab`,
  which is the example the spec itself carries, and it is **grammar-identical under every
  candidate reading** — so a mutation of the call site to `fnmatch` left the suite green. Arch
  names that same example as the reason the divergence *survived upstream review*, which is
  the tell: **when a spec gives one example for a field, assume it was chosen to be readable,
  not to discriminate.**
  **The check:** after picking a semantics for an under-defined field, write the row that
  fails under the *other* reading, at the call site, in the same commit — and run the mutation
  rather than predicting it. Here the prediction was wrong twice in one pass and both
  corrections went into the docstrings: row 4 (`a[b`) discriminates a `path.Match`-family impl
  (which errors) and a later write-time validator, but **not** Python's `fnmatch`, which
  treats an unterminated `[` as a literal exactly as the ruled grammar does; and the
  "one matcher" identity test asserted two *other* functions' behaviour and never reached the
  admission site at all. Enforcement point:
  `test_registry_ttl_and_dispatch_grammar.py::TestNameConstraintsGrammar`, whose identity row
  reads the admission function's own source — and whose first draft failed on the call site's
  **comment** explaining that it used to be `fnmatch`, the same prose-inflates-a-code-gate
  shape as `entity://` in docstrings. A gate that cannot tell a sanctioned mention from a
  smuggled call is not a gate.

- **A sibling's summary of your board is a claim about your filings — check it the same way
  you check a claim about your code.** *Candidate, 2026-08-19.* `ROUTING-2026-08-19-c` §3
  reads *"Cohort board: closed. Every routed registry item is ruled."* **SA-PY-15 is a routed
  registry item and is unaddressed** — the resolver-side ceiling is still `[MUST when present]`
  with no declared site, and arch's tree carries **zero** occurrences of the identifier while
  citing SA-PY-14 and SA-PY-17 five times each. It was dropped in handling, not decided. The
  existing rule (*a routed report's claims about our repo are hearsay*) covers claims about our
  **code**; this is the same rule with our **filing record** as the subject, and it is the
  cheaper one to check — grep the other tree for the identifier. Cost of not checking: an open
  security-relevant gap gets closed on someone else's summary, and the next cohort member reads
  a board that says it is done.
  ***Vindicated and ruled the next day.*** SA-PY-15 was **ruled in our shape** at REGISTRY 1.16
  (`resolver_chain[].hints.max_ttl`, per chain entry, read at resolution) once the pushback
  reached arch inside core-go's cohort sweep, and the class became arch's **L17**. Two things to
  carry: the fix is structural, not diligence — arch now keeps `docs/COHORT-OPEN-ITEMS.md`, one
  reconciled ledger where *"closed"* means zero open on the **shared** view and only an owner's
  in-tree confirmation at a named commit closes a row; and **"ruled" is not "closed" for us
  either**, which is why the ceiling work below shipped with a test per row rather than a note
  saying we already did it.

- **A capability whose "operations" column is a bare tree-write is an unenforceable gate — and
  the missing operation shows up first as a check nobody can construct.** ***RATIFIED 2026-08-19,
  and the census it prescribes closed the whole table on 2026-08-20*** *— core-go ran step 2 over
  all seven §5 rows and found exactly the one row we had filed and no fourth, which is what turns a
  finding into a bounded class. Arch landed the invariant that keeps it closed:* **a new row is not
  landable without naming the operation the check runs at.**
  *Filed as a candidate 2026-08-19, implementing `EXTENSION-REGISTRY` §4.3.* We and core-go both routed *"read-at-resolution has no
  instrument"* as a **harness** gap. It was not: `system/capability/registry-configure` was
  declared as a bare tree-write against `system/registry/resolver-config`, so there was no
  operation for a client to drive, **no site for the write-time MUST to bind to**, and nowhere for
  an operator's override to live. A configuration surface with no defined write operation cannot
  be validated, cannot be rebound, and cannot be conformance-driven at all — three symptoms, one
  cause, and the ruling that fixed all three (§4.3's `set-resolver-config`/`get-resolver-config`)
  was invisible from any of them taken alone.
  **The checks:**
  1. **When a check cannot be constructed, ask which operation is missing before concluding the
     instrument is limited.** *"What would a conformance client call?"* is the question; *"the
     harness can't hold one process across a config rebind"* is the wrong answer to it.
  2. **Census the capability table.** A raw write cannot refuse selectively, cannot carry a
     qualifier, and cannot be told apart from any other write to the same entity — so a cap gating
     one is a name with no enforcement point. Running that census on the table arch had just
     edited found the **third instance in one table**: `registry-pin` still reads *"tree-edit
     `resolver-config.pinned_bindings`"*, and §4.3's new operation writes that field under a
     **different** capability. Filed as SA-PY-24 — a pin short-circuits §4.1 step 1, so the
     capability that got merged away is the one that outranks the control §4.3 exists to enforce.
  3. **A new operation is a new authorization surface: diff it against the capability table in the
     same commit**, field by field. The escalation here is not in the operation's own semantics —
     it is in which fields of a whole-entity write the gate was ever meant to cover.
  **SA-PY-24 ruled in our shape at v1.19 (§4.3's pin-delta `[MUST]`), and the deferral is the part
  that generalizes `[2026-08-20]`.** The filing pinned the gap as *behaviour* and **implemented no
  local fix** — inventing the delta check would have refused a client core-go accepted,
  manufacturing a cross-impl divergence out of a spec gap. That call held for exactly one day and
  the ruling arrived; the row that demonstrated the escalation (one peer, one config: a bare name
  is `chain_exhausted` and the pinned name resolves anyway) survived into the gate class unchanged,
  because it is *why the gate exists*, not *why the gate was missing*.
  **What the ruling did NOT settle is the sharper half: a ruled behaviour can still have an unruled
  encoding, and that alone can hold a conformance row off the wire.** §4.3 fixes *when* pin
  authority is required; §5 names `registry-pin` **descriptively** and fixes no way for a capability
  to *express* it. So each seat invents one (we and go both use an operation-axis discriminator,
  `pin-bindings`) — and `REG-DISPATCH-CONFIG-REFUSED-1` row 8 **cannot go on the wire**, because a
  shared harness minting one seat's encoding answers `403 not_entitled` to a **conformant** peer
  that checks another. That is a false red manufactured by the vector, the mirror of the
  deceptive-green trap, and it is the same law as *"a wire check must not discriminate on an unruled
  or divergent semantic"* with the **capability encoding** as the unruled thing.
  **And matching a sibling's encoding is not converging — say which it is.** We match core-go byte
  for byte here on purpose; that is two seats not making the vector worse while a ruling is pending,
  and recording it as convergence would manufacture exactly the *"cohort-consistent, not
  independent"* overclaim `AGENTS-STANDARD` forbids. Routed by go as spec-issue `2026-08-20-a`; we
  concur rather than filing a duplicate, and add nothing to the wire until it rules.
  ***RULED next day as R-27*** *(arch `08841d8`) — and the deferral is the half worth keeping.*
  **The forward half of a deferral rule actually executed**, which almost never gets recorded: the
  wire row was held for a **stated retirement condition** (*the discriminator is ruled AND every
  conformant impl agrees*), the condition was discharged, and go landed row 8 one cycle later
  (`2e8b9f8`) minting both caps in the ruled encoding. **A deferral without a retirement condition is
  just an omission with better prose** — this one had one, in writing, and it is why nobody had to
  re-litigate whether the row was ever coming.
  **Two corrections from the ruling, both about the reasoning and neither about the code.** Arch
  derives the operation axis from **V7** — a grant scopes on path-scope and id-scope only and the
  path axis is *explicitly non-portable*, so the operation name is the **sole portable
  discriminator**, true regardless of this entity's shape. Ours was narrower (*a resource split
  discriminates nothing **here***) and would not have generalized. And arch cites the three seats'
  independent agreement **last, labelled as corroboration** (L18), with the operative test written
  out: *if all three had chosen a resource path, would the argument change?* **That is the shape to
  copy when you are the one agreeing** — unanimous agreement on a wrong reason is the failure mode
  that looks most like validation.
  Enforcement point: `test_registry_name_privacy.py::TestSetResolverConfigPinDeltaRequiresPinCap` —
  eleven in-tree rows with teeth, including the **removal** row (§5 says *"add **or remove**"*, and a
  check written as *"does the submitted config carry pins"* passes every other row while letting the
  weaker grant delete the operator's pins) and the **unmodelled-key** row, which is the fail-open
  `entity-core-rust` found in `entity-core-go` (`f44ed4d`): a typed-struct decode drops a §4.2
  forward-compat key, so adding or stripping one reads as *"no change."* Python's native-mapping
  decode does not have it — **verified here rather than accepted from arch's summary of us**, which
  is the standing rule with our *code* as the subject instead of our filing record.

- **Winning the conclusion is not winning the argument, and the corpus records which one you
  sent.** *Candidate, 2026-08-19 — SA-PY-21 Q1.* We implemented chain-scoped, then routed the
  strongest argument we could find *against our own reading*: a broad row naming `did-web` with no
  such chain entry **arms silently** when an operator later adds the backend. Arch ruled
  kind-scoped — our conclusion — and **recorded our argument as explicitly not the justification**:
  the harm we described is closed under *either* reading, because the paragraph one line up binds
  the configuration **as a whole**, so adding that chain entry is itself a write the check
  evaluates. The ruling rests on monotonicity instead (a distribution cannot be held to a property
  that depends on what a downstream operator adds later).
  **The check when you argue a harm — including, especially, against yourself:** name the state in
  which the harm is reachable, then read the *rest of the section* for a rule that already refuses
  that state. A hole that another MUST already plugs is not evidence for anything, and it costs
  the reviewing seat a real argument to write the refutation. Being right about the answer makes
  this easier to miss, not harder: nobody re-reads the reasoning behind a conclusion that landed.

- **A binary operator with no arm for the absent case is a policy decision wearing a type
  guard.** ***RATIFIED 2026-08-19*** *— the validator-vs-consumer law's third shape, and the
  first where the untested arm was the one production always takes. Found by core-go's
  `v4c_ttl_resolver_ceiling` against a **3820-test-green** tree.* §6a.9.1's resolver ceiling is
  written `min(binding.ttl, local_max)`. A binding's `ttl` may be **null** — the sticky kinds
  (`local-name`, `pinned`) always are — and `min` has no answer for that, so the natural
  implementation guards it: `if isinstance(ttl, int)`. That guard reads as type hygiene and *is*
  a ruling: it applies the ceiling **only where a bound already exists**, leaving the unbounded
  case — the entire reason the control exists — uncovered. The control ends up pointed exactly
  backwards, and nothing looks wrong, because every row that *does* have a `ttl` behaves
  perfectly.
  **Why our own suite could not see it, and this is the sharper half:** every fixture in
  `TestResolverCeiling` hand-seeded a `local-name` binding **carrying an explicit `ttl`** — a
  shape `_handle_bind` has never minted (it writes `ttl: None`, sticky per §6.3). So the class
  exercised the arm `min` has an answer for and never the arm production produces, while reading
  as thorough: five rows, a hash-identity gate, an expiry-teeth row. Same law as the
  two-representations entries, with the **fixture** on the wrong side of it: *a hand-seeded
  entity is a claim about what the write path produces, and it is the one claim in a test nobody
  re-checks.*
  **The checks, in the order they are cheap:**
  1. When a spec rule is a binary operator over a field that can be absent, **the absent case is
     a ruling you are making** — write the arm explicitly and name it in the code, or you have
     silently narrowed a MUST. Grep for `isinstance(x, int)` guards standing where a spec
     sentence expected an answer.
  2. **Seed fixtures, then pin them against the production write path in the same class** —
     `test_the_bind_path_mints_the_sticky_shape` is the template: it asserts `bind` still mints
     the shape the other rows seed, so the class cannot drift into testing a shape no deployment
     reaches.
  3. **An oracle vector that reads the response says nothing about the verdict.** go's `v4c`
     reads the surfaced `ttl` off a *freshly bound* name, so an implementation that stamps
     `local_max` into the result and never feeds it to the expiry check **passes the vector and
     still honors a sticky binding forever**. The security property is the honoring. Owed to
     core-go, and covered here by
     `test_row_d_teeth_the_sticky_arm_bounds_honoring_and_not_just_the_number`.
  Enforcement point: `_effective_lifetime` in `entity_handlers/registry.py` — three arms, one
  function, **both** call sites (the expiry verdict and the surfaced `ttl`), because clamping
  one and not the other is the two-representations bug with an authorization decision on one
  side. Rows: `TestResolverCeiling` (all four `REG-TTL-RESOLVER-CEILING-1` rows + read-at-
  resolution + the sticky teeth).

- **A matcher inside a hash-determining function is wire contract — and the obvious tool in
  your language is the trap.** *2026-08-18, implementing the SA-PY-8 ruling.*
  `EXTENSION-REVISION` §2.4 filters versioned bindings through `glob_match`, names it, and
  never defines it. The filter decides trie membership and **the trie root is the version's
  identity**, so the matcher is part of the hash. The fork is language-shaped: Go's
  `path.Match` `*` does **not** cross `/`; Python's `fnmatch` `*` **does**. Reaching for the
  obvious tool in each language yields two filters, two roots for identical content, and **no
  error at the call site** — two DAGs that will not converge and nothing that looks wrong.
  **The check:** when a helper feeds a value that gets hashed, its semantics are wire, not
  style — write it out and pin it, don't call a stdlib whose rules you did not read. Filed as
  SA-PY-11, because picking a sibling's implementation as the spec is what we are otherwise
  not allowed to do. Enforcement point: `tests/unit/test_revision_exclude_glob.py`, which
  keeps `fnmatch` as an explicit **control row** so the wrong tool fails loudly later.
  ***RULED 2026-08-18*** *(arch `ROUTING-2026-08-18-i` §1) — and the interim fix we shipped
  was wrong in three separate ways, which is the part that generalizes.*
  §2.4 is now **four closed forms** — `*` · `<literal>/*` (§5.4 subtree, crosses `/`) ·
  `*<literal>` (byte suffix) · `<literal>` exact — plus §4.4.17 **V6**, which *rejects*
  anything else at config write. Three corrections to carry:
  - **A correct finding does not make its proposed remedy correct.** The report was upheld and
    produced the ruling; the fix we proposed (doublestar) was retracted cohort-wide a packet
    later. We had measured against Go's `path.Match` as the reference — *which has no `**` at
    all*, so it was never a valid control. **State the finding and the remedy as separate
    claims, and check the remedy's control as hard as the finding's.**
  - **"Match the sibling exactly" is a defensible interim and an indefensible reference.** Our
    port faithfully inherited both `path.Match`'s segment scoping (wrong — form 2 crosses `/`)
    and a `**` the corpus never reserved. Copying an unruled matcher copies its unruled parts.
  - **Rejecting beats defining when the surface is hash-determining.** A spec that *omits* a
    token and one that *rejects* it are indistinguishable until a config carries one, and
    "each impl does something reasonable" is exactly how two stdlibs got in. Write-time
    rejection is the mechanism: an unrepresentable config cannot be stored, so no two
    conformant peers can hold patterns they read differently. **When you pin a grammar, ask
    what refuses the patterns outside it** — a matcher with no validator is half a pin.
  **And landing it found the second matcher, which is the older law with a new subject.**
  `auto_version.py` carried its own exclude matcher for §6.1's emission gate, where `/*` was
  *segment-scoped* — so `tmp/*` suppressed the version for `tmp/x` and not for `tmp/a/b`,
  while the trie filter kept both out. One peer disagreeing with itself, and the divergent
  half was the one no test drove past depth 1. **A concept with two implementations in one
  process is the two-representations bug; the second one is usually the "intentionally
  narrow" helper written before the rule existed.** Same pass: `_exclude_covers` accepted
  `system/revision/` as covering a subtree, which under form 4 excludes one path and nothing
  beneath it — V2 would have passed a config whose reentrancy exclusion does not exclude.
  **A validator built on the old matcher is wrong the moment the matcher is ruled; grep every
  caller, not just the one the ruling names.** Third instance, one surface over, filed as
  SA-PY-12: the merge-config path matcher was `fnmatch`, non-conformant under both candidate
  readings of §2.3.
  ***SA-PY-12 RULED 2026-08-18 in our favour*** *(arch `86d6b20`, REVISION 3.12)* — merge-config
  `pattern` **is** the four forms, decided by §5.1's own worked example (*"all `.lock` files use
  `source-wins`"* is form 3, the one form §5.4 cannot express). Two things to carry:
  - **A matcher moved to a new field without its validator is half a pin, and we shipped that
    for a day.** SA-PY-12's fix put merge-config on `_glob_match` while V6 still bound
    `exclude`/`exclude_types` only, so an unevaluable pattern was **storable** and then fell
    silently to form 4 — the accept-then-mismatch shape V6 exists to prevent, one field from
    where V6 was put. §4.4.18 **V7** closes it (`7e56047`). *When a matcher gains a call site,
    the rejection rule gains it in the same commit.*
  - **How arch made the scoping error, recorded because the method is one we use.** The "and
    nowhere else" clause was scoped by a **census of `*`-bearing patterns**, and
    `glob_match(config.data.pattern, …)` carries no `*` — so *the field that most needed
    scoping was structurally invisible to the measurement that set the scope.* **When a rule is
    scoped by an inventory, the inventory's unit must be the thing the rule binds.** That is the
    gate lesson in this file's fourth two-representations entry, arriving from the spec side.
  - **A filing can produce a larger finding than the one filed.** Verifying our report, core-go
    found `pattern_specificity` called by §5.1 and defined **nowhere** in the corpus — all three
    seats had invented one, ours byte-identical to go's, rust's counting the `*`. The surface
    decides which config wins, hence the merged bytes, hence the version root. Landed here as a
    four-key total order (`7e56047`). **Route the ambiguity even when you have a working local
    answer; the value is in what the other seats find while checking it.**

- **When a new rule turns your whole suite red at once, read the fixtures before the rule.**
  *2026-08-18, implementing registry D11/D12.* §6a.9.2 D11 refuses a live issuer policy with
  `default_ttl: null`. Landing it failed **35 of 63** registry tests in one run — and the
  correct reading of that is not "the rule is too strict", it is *every helper in the suite
  had been arming the one policy shape the spec forbids.* The whole registry surface — layer-1
  proof, replay defense, the pending queue, live-wire registration — had only ever been
  exercised against a registry that could mint nothing but bindings §6a.3 rejects. Nothing
  looked wrong because **no test read the `ttl` a binding ended up with**: the field was
  carried, never asserted, so the invalid value rode through every green run.
  Same law as the two-representations entries below, inverted — there the tests covered one of
  two forms; here they covered *only* the invalid one. **The check when adding a validity rule:
  count how many existing tests construct the newly-invalid form. A large number is evidence
  about your fixtures, not about the rule** — and the interesting question is which assertions
  should have caught it (here: any that read the minted binding's lifetime).
  **Repeated the same day with `max_ttl` (v1.11): 14 tests armed the newly-invalid form.**
  Lower than 35 only because the D11 pass had already funnelled them through two helpers —
  which is the useful part. *The count is a measurement of your fixture centralization as much
  as of the rule*, so a second rule on the same entity is the cheap check that the first pass
  actually consolidated rather than patched call sites. And the refusal rows for D11 were given
  a **valid** `max_ttl` so their `400` stays attributable to `default_ttl`: when two rules gate
  one write, every rejection test must satisfy the rule it is not about.
  **A rule can also invalidate the test that proves a different rule.** `set_issuer_policy`'s
  replace-whole test demonstrated "absent means unset" by dropping `default_ttl` — the exact
  field D11 makes undroppable. The rule was unchanged; the field carrying its demonstration
  had to move. **When a MUST lands on a field, grep for tests using that field as an
  *example* rather than as their subject.** Enforcement points:
  `test_reg_set_issuer_policy_null_default_ttl_400` (D11, with the not-stored read-back) and
  `test_reg_null_ttl_stored_policy_fails_closed_403` (D12, seeded by direct tree write since
  D11 now refuses the storable path), each with a teeth control beside it.

- **"They read the spec differently" is the flattering hypothesis, and it needs the same
  evidence as any other.** *2026-08-18 — arch's SA-PY-9 ruling correcting us.* We routed the
  in-process resource gap to core-go as *"three implementations have silently split on the
  reading"* and asked arch to resolve an ambiguity. **§5.2 had no such axis**: its condition
  is `resource_target is not null` — a test on the **field**, not on the door. There was
  nothing to split on, and core-go's code computes `childResource`, installs it on the child
  context, and hands the check a literal that omits it *thirty lines earlier* — a **dropped
  field**, a materially stronger finding than the one we sent. **Before attributing a
  divergence to a reading, name the sentence that carries the axis.** If you cannot quote it,
  the disagreement is a defect in someone's code — possibly ours — and framing it as
  interpretation is a courtesy that costs the other seat an accurate report.

- **Mutate a *committed* file, or you will `git checkout` your own work.** *2026-08-18, cost:
  re-applying a finished change.* The mutation discipline (§5.2b.1 — a mutation nobody runs
  is a claim) says disable the fix and watch the test fail. The restore step is the trap:
  `git checkout -- <file>` restores **the last commit**, not the pre-mutation state, so
  mutating a file whose feature is still uncommitted deletes the feature along with the
  mutation. Commit the change first, then mutate, then restore — or keep the mutation in a
  patch you reverse by hand.

- **The validator measures your *working tree*, so don't edit it mid-run — and pin the
  oracle or the number is not citable.** *2026-08-18, both halves learned in one run.*
  `peer-manager` rebuilds the peer image from the working tree per pass (it logs
  `working tree dirty at <sha>`), so a run started before an edit and finishing after it
  reports passes measured against **two different trees** under one summary. Run 8 here
  straddled a `peer.py` change exactly that way and had to be thrown out and re-run from a
  committed tree. **Commit first, then measure.**
  Second half: `AGENTS-STANDARD` wants `N·0F @ <oracle-commit>`, and our own handoffs
  published `1594 · 0 F` with no go commit. The cost was concrete — when core-go's validator
  gained `subscriptions.events_vocabulary_filter` (`41ecf0b`) it was impossible to tell from
  our records whether the previous run had included it, so the only way to know was to run
  again. **A conformance number without its oracle commit is a number you will have to
  re-measure.**
- **Cross-impl reports lag — ground truth is a live run.** Go's `validate-peer` cross-impl
  reports live under `entity-core-go/docs/validation/reports/` (`CROSS-IMPL-*-PYTHON-*.md`,
  dated) and go stale: fixes land without a new report and runs can be flaky. Don't
  treat a dated report as current status — run the validator live against HEAD. `local_files`
  is a Go-only extension; Python failing it is an expected scope gap, not breakage.
- **A routed report's claims about *our* repo are hearsay — verify them here before acting.**
  **Ratified 2026-08-15** (twice in two shapes, one session apart). The claim to check is
  never the gap they found in themselves; it is the sentence about *us*.
  - *Wrong about our architecture.* The `reflection_endpoints` routing said "py serves both
    the wrapped and unwrapped surfaces — apply on each," so §2.2's both-surfaces MUST would
    bind twice. It does not: this repo serves **only the wrapped surface** — the §9.2
    raw-CBOR listener and §9.3 reflector are unbuilt (`create_datagram_endpoint` has zero
    hits; the only `advertise` handlers are `signaling/node.py` and the unrelated
    `relay.py`). Cost of believing it: a surface built against nothing, or a §2.2
    conformance claim on a listener we do not have.
  - *Wrong about our verification state.* The CONTINUATION v1.23 routing listed py's NETWORK
    §5.4.1 no-write-on-success as "unverified — no per-tick status write surfaced in a grep,
    but that is not proof of the negative." It has been proof-carrying since before that
    HEAD: `test_keepalive_no_cadence_writes` drives ≥2 real pong-driven freshness advances
    and asserts the status binding's content hash never moves. Cost of believing it: we
    "verify" something already locked, or worse, treat a green discipline as an open risk.
  - **The rule.** A sibling reads our tree from outside; it can be right about the gap and
    wrong about our shape or our coverage. Absence-of-a-grep-hit is their weakest evidence
    and it is usually what these claims rest on — so answer it with a named exhaustive
    search and a test run, the same standard AGENTS-STANDARD sets for claims we make about
    *them*. Then route the correction back: an uncorrected report is what the next cohort
    member reads.
  - **Sixth shape, 2026-09-01, and the wrong claim was about the *remedy* — the one axis where
    every previous instance's defence does not fire.** The five above are wrong about our
    architecture, our coverage, our version, our behaviour, or our filing record; all five fail
    the moment you look at the tree, because the tree disagrees. `entity-core-go`'s FM-1d relay
    was **right about everything it measured** — our defect (`400 bad_request`), our site
    (`handle_connect_authenticate`'s opening phase check, one frame above the nonce comparison),
    and a correction to a census that had us down as conformant. Then it prescribed the fix:
    *"set `code="invalid_nonce"` on that raise (it carries a 401), exactly as the
    unsupported-key-type call sites already do."* **The parenthetical is false here.** Our wire
    boundary called `ExecuteResponse.bad_request(…, code=…)`, which hardcodes `status=400`, so
    the relay applied verbatim yields **`400 invalid_nonce`** — a pair in no §4.7 row either, on
    the one surface whose entire defect was a pair in no §4.7 row. The cited precedent held
    because those rows *are* 400s, which is exactly why it read as the same shape.
    **Why this axis is the dangerous one:** a wrong claim about our code sends you to the tree,
    which corrects it. A wrong *remedy* sends you to an **edit**, and a one-line edit backed by
    a sibling's measurement is the least-audited change there is — it is short, it is authorized,
    the defect it names is real, and the diff looks complete. Nothing surfaces afterwards: the
    code assertion passes, and status alone cannot separate this from a post-hello nonce
    mismatch. **The check, and it is one read:** when a relay names the fix, open the function
    the fix lands in and confirm it does what the relay says it does — especially when the relay
    cites a precedent, because a precedent is a claim that two call sites are the same shape and
    that is a claim about *your* code, not theirs. And when a spec row is a `(status, code)`
    pair, mutate each half separately: a half-fix that satisfies the assertion you wrote is how
    a non-conformant peer ships wearing a green diff.
  - **And a relay's *strike* is a claim too.** The same packet struck an item as *"their standing
    change, which is the `2026-08-23-a` item"* — a spec-issue whose own file still reads
    `Status: open — measured divergence, routed. go is NOT converging by count.` It had been
    **ruled**, in go's shape, in the same protocol commit that produced the packet. Read as a
    standing divergence the correct answer is *refuse* (GUIDE-CONFORMANCE §4: one-differs → the
    spec arbitrates, two seats do not vote a third into line); read as a ruling it is ours to
    implement. **Same word, opposite obligations** — so resolve which it is from the spec text,
    never from the routing sentence, and grep the normative section for the field before
    deciding you owe nothing.
- **Two representations of one value is a bug that hides until the boundary — cover the
  form your own tests never mint.** `compute/error` is carried two ways here: `make_error`
  returns a **dict**, a stored error *literal* resolves to an **`Entity`**. Every
  evaluator-internal consumer goes through `is_error`, which handles both, so the split was
  invisible — right up to the compute→non-compute crossing, where two of three paths
  assumed dict, the `Entity` fell through `_as_entity` as `primitive/any`, and cbor2 killed
  the inbound handler task (`CBOREncodeTypeError: cannot serialize type Entity`). The peer
  then answered **nothing**, so the caller saw an i/o timeout — a serialization bug wearing
  a network bug's costume, and the worst shape a failure can take.
  **Why our suite missed it for so long:** every pre-existing error-propagation test
  triggers errors with *unresolvable hashes*, which mint the dict form. ~300 compute tests,
  100% on one of the two representations. **The check:** when a value has more than one
  in-flight representation, find the boundary functions (anything that returns to the wire,
  the tree, or the content store) and parametrize over *both* forms — the one your test
  helpers construct is not the one that breaks.
  **Third instance, 2026-08-16 — the same law twice more, so read the two refinements it
  forced** (arch's SA-9 `store` ruling, `662e409`):
  - *One value can have two boundaries wanting two answers.* The fourth crossing arrived
    and it did **not** want `error_to_wire`. §2.4 splits them: the **in-flight/dispatch**
    crossing (the F10 status-200 error-as-value) MAY carry `message`/`at`; a **written,
    content-addressed** crossing (§7.2 `result_path`, SA-9 `store`) is `{code}` **alone**,
    or two conformant peers writing the same error to the same path get different hashes.
    The enforcement point is the pair — **`error_to_wire` for the wire,
    `error_materialized` for a write** — and a fifth crossing picks by asking *do these
    bytes get hashed?*, never by copying whichever neighbour it found first.
  - *A predicate can fold two opposite things into one answer.* `resolve_or_error` returns
    the same `is_error` verdict for **resolution failed** and **resolved to a
    `compute/error` literal**. Every consumed operand short-circuits on both, so the fold
    was invisible — until `store`'s write payload, where they are opposites (a literal is
    a value the caller asked to store; a failure never became one). `entity-core-go` has no
    such hazard: there the two are different *types*. **When a helper answers a predicate
    for two causes, check whether any caller needs them apart before you exempt it.**
  **Fourth instance, 2026-08-17 — the law jumps from values to the gates that watch them.**
  Building the presentation-purity gate (`test_package_layering.py`), the first draft
  budgeted one form of protocol leakage: the `{"type", "data"}` envelope literal. But
  protocol leaks into a renderer **three** ways — hand-built payload, raw `.execute()`
  dispatch, hand-built `entity://` addressing — and the CLI does all three (8 / 17 / 21).
  A gate watching one form **reports the other two as clean**, which is worse than no gate:
  it converts an unmeasured risk into a false green. Same law, new subject — *one concern
  with several representations, coverage on one of them* — except the thing under-covered is
  now the **enforcement point**, so the failure is silent by construction.
  **The check when you write a gate:** enumerate the forms the thing you are forbidding can
  take, and budget each separately. If you can name a second form and your gate does not
  count it, the gate is not yet a gate.
  **And measure the budget, never guess it.** That same first draft asserted a budget of 17
  from *"one envelope per subcommand"* reasoning. The staleness half of the ratchet — an
  entry that overstates reality fails too — reported the real figure as **8** on the first
  run. **A ratchet must fail in both directions**: a too-loose budget is cover, and it is
  the direction an author's own estimate always errs. The gate's first act should be able to
  correct its author; this one's was.
  **Fifth instance, 2026-08-17 — a config field has two sites, and the tests all pile onto
  the validator.** `EXTENSION-REVISION` §2.4's `exclude` is *checked* at config write
  (§4.4.17 V1-V5, which refuses `auto_version: true` without the required patterns) and
  *used* at snapshot build (§4.4.1's `compute_versioned_bindings`). This repo implements
  the first and **not the second**: `_get_snapshot_bindings` never reads the config, so an
  exclude list is validated, stored, and applied to nothing — and a py peer's trie root for
  a configured prefix differs from go's, i.e. different version hashes for identical
  content. All ~87 revision tests exercise the validator; none drove the snapshot. **The
  check: for any field with a validator, find the consumer and test *there* — a validator
  proves the field was accepted, never that it acts.** Filed as SA-PY-8 (the auto-version
  half is a genuine spec question), pinned by
  `test_commit_does_not_yet_apply_config_excludes`, which fails when the fix lands.

- **`SDK-EXTENSION-OPERATIONS` has drifted from the extension specs it summarizes — check
  both before implementing a wrapper.** *Ratified 2026-08-17 — three instances in one
  session (SA-PY-2, -3, -4), across two unrelated extensions.* The SDK doc is *the document
  an SDK author reads*, and on every wrapper built this session it disagreed with the
  normative extension: §3's `events` vocabulary (`put`/`remove` vs the pinned
  `created`/`updated`/`deleted`), §3's `rate_limit` unit (per-second vs per-minute, 60×),
  and §6's whole query result shape plus an operator name (`entries`/`content_hash`/`neq`
  vs `matches`/`hash`/`not_eq`).
  **Triage by failure mode, because they are not equally dangerous.** SA-PY-4's items all
  fail *loudly* — a `KeyError`, a `400` — and cost one debugging session. **SA-PY-2 fails
  silently**: a subscription built from the SDK spec is created, returns an id, appears in
  the tree, and never fires for its entire lifetime. That is the one worth finding first,
  and the class to hunt for in every remaining extension: *a value compared by equality
  against a list the other document spells differently.*
  **The procedure:** open the extension's normative schema section **alongside**
  `SDK-EXTENSION-OPERATIONS` before writing the wrapper, and where they differ, implement
  the extension, absorb the difference at the SDK boundary, and file the SA. Never resolve
  a disagreement by picking the doc you happened to open. Enforcement point: an SA entry
  per divergence plus a test that drives the *engine's own* predicate with the SDK doc's
  spelling — `test_the_pre_ruling_spelling_would_have_matched_nothing` is the template,
  because it proves the contradiction against the implementation rather than arguing it
  from two texts.
  **Outcome, same day:** all three ruled in our favour at `SDK-EXTENSION-OPERATIONS` 0.8.1
  as SA-2 / SA-3 / SA-4, each recording the pre-ruling text inline. The proof-against-the-
  engine test is what made them decidable rather than arguable — write that test first.
  **Fourth extension, same day — and the drift is not only in names (SA-PY-5, SA-PY-6).**
  §4 vs `EXTENSION-REVISION` diverges in **seventeen** places: thirteen params/result rows
  and four rows about *which layer an operation lives in*. The second class is new and is
  worse, because following it means **building the wrong thing** rather than misspelling a
  field — §4 files `pull`/`push`/`diff`/`cherry-pick`/`revert`/`find-ancestor` as SDK
  workflows the extension makes handler operations, and tells you to write branches and
  tags as plain tree puts at **unhashed** paths (`system/revision/branches/{name}`) that
  the handler, which reads `system/revision/{H}/branches/{name}`, never looks at. The
  branch write returns 200 and reads back with `get`; every revision operation says the
  branch does not exist. Worse still, §4's client-side `checkout` recipe ("read trie,
  batch-write bindings") violates §4.4.4's version-transcription invariants — wrong diff
  baseline, and deletion markers bound into the live index. **So the check is not only
  "does this field have the same name?" but "is this even an SDK's job?"** — and the answer
  lives in the extension's §4.1 manifest and §4.2 core/convenience table, which is the
  first thing to open on any wrapper.

- **An absorption is a debt to the ruling, not a permanent feature — retire it when the
  spec lands.** *Candidate, 2026-08-17, and the first thing a ruling asks of us.* While an
  SA is open the SDK absorbs the divergence so callers see one behaviour. **The moment
  upstream rules, the compatibility path names a vocabulary no document defines**, and an
  SDK accepting a spelling nothing sanctions is manufacturing precisely the local
  divergence this repo exists to *find* in other people's stacks. `AGENTS.md`'s no-legacy
  rule is not a separate concern; this is what it is for. Retired at the SA-2/-3/-4
  rulings: the `put`/`remove` subscribe alias, the `neq` operator alias, and
  `QueryResult.entries` / `Match.content_hash`.
  **Two things the retirement has to get right, and both were nearly missed:**
  - *Check whether the retired spelling is still normative somewhere else.* `put`/`remove`
    are **not** dead — they are `ChangeEvent.event_type` in `SDK-OPERATIONS` §6.1, the L1
    `watch()` surface. So the caller passing `put` to `subscribe` is confusing **two real
    vocabularies at two levels**, not typing badly. Deleting the alias silently would turn
    a documented confusion into a bare "invalid". The 400 names the level each belongs to
    and gives the mapping.
  - *Say which ruling moved it.* A caller on a pre-ruling copy of the doc made a
    **documented** mistake. `neq` raises an error naming SA-4 and the new spelling, not
    "unknown operator". An error that only refuses makes the reader re-derive what the
    corpus already decided.

- **"The spec conflicts with itself" is the flattering hypothesis for a regression you just
  caused, and a real measurement will support it all the way to the filing.** ***RATIFIED
  2026-09-09*** *— the "'they read the spec differently' is the flattering hypothesis" law with a
  **conflict between two documents** as the subject instead of a sibling's code, and the first
  instance where the wrong diagnosis was written up, implemented, tested, committed, and
  withdrawn in one session.*
  Landing 0.8.2.17's outbound check took `convergence.rexec_delivered` FAIL against a
  **4359-green** tree. Traced to: §1.4 gives two authority arms (ambient / target-minted) and
  `EXTENSION-CONTINUATION` §4.2 case 3 authorizes a cross-peer advance with a capability
  *"authored by this host peer"* — **neither arm**. Filed as SA-PY-45, a **fold blocker**: PD-2 as
  written refuses every cross-peer continuation advance in the cohort. Implemented a named,
  retirement-conditioned hold on Dimension 4. All of it good procedure, and **the diagnosis was
  our own defect wearing a spec conflict's clothes.**
  **What refuted it: reading the sibling's FIXTURE, not either document.** `rexec_setup` mints
  `CreateChainedCapGrantedTo(b.CapEntity(), …, a.RemotePeerIdentityHash())` — the credential is
  `B (target) -> installer -> us`. Its **leaf** granter is the installer; its **root** is the
  target. §1.4's *"the capability's `granter` resolves to the target peer's identity"* read as the
  **leaf's** granter — the reading a careful implementer reaches first, and the one we shipped —
  refuses it. Read as the **chain's root** it is ordinary presented authority, there is no third
  case, and the hold had nothing to cover.
  **Where the wrong premise came from, and this is the part to carry: our own code comment.**
  `continuation.py` says the dispatch capability is *"authored by this host peer"*, paraphrasing
  §4.2 case 3. That sentence is true of one field and false as a description of the chain, and it
  was the entire evidence for a filing about the **corpus**. **A comment that paraphrases a spec
  is not evidence about the spec, and it is the last thing anyone re-reads** — it sits in the file
  you are already editing, in your own repo, written by someone who had read the section.
  **Why this branch is expensive in the same asymmetric way CE-1's was.** *"Two documents
  conflict"* terminates in a filing, a hold, a fold blocker and three seats' attention. *"We
  misread a sentence"* terminates in deleting six lines. The cheap branch has to be checked
  first, and *"I have a real measurement"* is not evidence for the expensive one — the measurement
  was real in both worlds.
  **The two checks, in order:**
  1. **When you are about to claim two documents conflict, drive the configuration the second one
     actually produces** — from the fixture or the sibling's constructor, never from its prose and
     never from your own paraphrase of its prose. One `grep` in the harness that failed.
  2. **Before filing a conflict, re-read your own sentence for a word that admits two readings**
     and ask which one your code took. Here it was `granter`: leaf or root. A one-word ambiguity
     in a ruling is indistinguishable from a gap in the corpus until you name it.
  **What survives:** the *measurement* (PD-2 breaks cross-peer continuation under the leaf
  reading) and the *ask* — §1.4 should say **"the chain's root granter"**, because go and rust
  will each reach this fork independently and the leaf reading is the one the sentence suggests.
  That is now SA-PY-42(c), a one-clause request rather than a fold blocker. Enforcement point:
  `test_outbound_sub_dispatch_authorization_pd2.py::TestThePresentedArm::
  test_a_capability_the_target_ROOTED_but_delegated_IS_presented_authority`, which asserted the
  **opposite** for one commit and carries the measured numbers (`1637 -> 1617`, convergence 30/30
  under the control) in its docstring.
  **And a corollary about holds, since one was built and removed here:** a hold is the right
  move when a ruling and a shipped behaviour genuinely collide, and it must be *named,
  single-dimension, retirement-conditioned, and paired with a teeth row proving the other
  dimensions still bind* — without that row a hold is indistinguishable from a bypass. But
  **build the hold last**, after the cheap branch is excluded, because a hold is a change to an
  authorization path and it made this defect *harder* to see: it explained why the check still
  failed as "the hold does not cover this shape" rather than "the reading is wrong".

- **A second dispatch path is a second boundary, and the in-process one is the untested
  half.** ***RATIFIED 2026-08-18*** *— third instance, and the first where the untested half
  was an* authorization *check rather than a lookup. Filed as a candidate 2026-08-17; the
  two-representations law again, subject = the pathway.*
  **The instance that ratified it.** §5.2 requires all four grant dimensions at dispatch and
  names the handler's own check *secondary*: "the dispatch-level `check_permission` handles
  the primary resource check." `handle_execute` ran it. `_dispatch_local_execute` accepted
  `resource_targets`, forwarded them into the child `HandlerContext`, and consulted
  `grant.resources` **nowhere** — so on a sub-dispatch the primary check was absent and the
  secondary one exists in **8 of the 70** non-`__init__` modules in `entity-handlers`.
  `system/handler:register` is the sharp end: §6.2 assigns the authorization of the install
  path to precisely that check and the handler performs none, so under a grant scoped to
  `app/*` a sub-dispatch reached it with pattern `pwn`. Fixed `00b2c05`.
  **`entity-core-go` has the same gap** (`makeLocalExecute`, `core/protocol/local.go`,
  `41ecf0b`: `CheckPermission(types.ExecuteData{Operation: operation}, …)` — a literal with
  `Resource` nil, while `childResource` is computed twelve lines later for the child
  context). rust unverified. So this is not a py quirk; it is the shape the *cohort* gets
  wrong, which is the argument for making it a standing rule rather than a fixed bug.
  **Why the suite was no help, and the part to carry:** every join/continuation test here
  drives a **stub** `_execute_dispatcher`. 3667 tests, and not one exercised real in-process
  authorization. *A test that substitutes the dispatcher cannot be evidence about the
  dispatcher* — when the thing under test is the seam, the stub is the bug's hiding place.
  **Second instance, 2026-09-09, at the same seam and in the opposite direction (SA-PY-45).**
  Landing PD-2's outbound check took `convergence.rexec_delivered` FAIL against a **4359-green**
  tree — a cross-peer continuation advance stopped being delivered. Same cause, one layer out:
  every continuation *cross-peer* test here also drives a stub, so the suite could not see a
  change to the real outbound path either. **The first instance was a missing check the stub hid;
  this one is an added check the stub hid.** A stub is not biased toward false green or false red
  — it is blind, and what it hides is whatever you just changed.
  **The consequence for scheduling, which is the actionable half:** a change to the dispatcher is
  a change **no local run can measure**, so the cohort validator is not a final gate for it, it
  is *the* measurement — run it before believing a dispatcher diff, not after. Here the two-peer
  check found a cohort-wide spec conflict that three green suites had no way to surface.
  Enforcement point: `tests/integration/test_authz_resource_dimension_in_process.py`,
  which drives a synthetic handler that performs **no** `check_caller_permission`, so the
  assertion is about the dispatcher's verdict and not a handler's, with in-scope controls on
  both seams and the wire rows in the same file.
  **And the fix's own fallout is the lesson's second half.** Running the check for the first
  time turned core-go's `join_target_received` PASS → WARN, deterministically. Traced (A1)
  from the peer's log — `[dispatch:internal] resource scope denied` — to a §5.5a granter-frame
  question nobody had an opinion on *because nobody was checking*. **Adding a check that
  should always have run is a behaviour change; budget for the second finding it exposes.**
  Filed SA-PY-9 (does §5.2 bind internal sub-dispatch) and SA-PY-10 (which peer frames a
  stored `dispatch_capability`).

- *(the candidate that became the rule above)* The registry handler found its §6a.9 layer-1 proof (the bundled `system/peer`
  + `system/signature`) by searching the tree and the content store. Both are populated on
  the **wire** path, where `_store_included_entities` persists `included` on receipt (V7
  §1.5). An **in-process dispatch has no receive step** — the bundle exists only as
  `ctx.included` (V7 §3.3 v7.51), which `capability.py`, `relay.py` and `identity.py`
  (SI-11) all read and registry alone did not. So a correctly signed request got
  **`401 signature_invalid`**: an authentication verdict handed to a caller who failed no
  authentication, which sends the reader hunting a key problem that does not exist.
  **Why nothing caught it:** every caller was the CLI reaching a peer over a connection.
  The defect surfaced on the *first in-process caller registry ever had* — an
  `EntityClient` composed over `HandlerContextDispatcher` — i.e. it was created by
  building the SDK tier, not found by it.
  **The check:** `EntityClient` composes over a `Dispatcher`, and there are two
  (`HandlerContextDispatcher` local, connection-backed remote). When wrapping a handler
  that reads *anything* off the envelope — `included`, bounds, author attribution — drive
  it on **both**, because "works over a connection" is not evidence about the local path
  and every existing test of that handler used the same one. Enforcement point:
  `tests/integration/test_sdk_registry.py::TestLayer1ProofReachesTheHandlerOnBothDispatchPaths`.
  And when reading a bundled entity, **validate the hash before trusting it** (§1.8): the
  map key is the sender's claim, so `_bundled` returns nothing unless the entity hashes to
  the key it arrived under.

- **A code SLOT is the unit for auditing a CODE; the row's INPUT is the unit for auditing a
  ROW — and a slot is keyed by a status, so it cannot see a site that got the status wrong.**
  ***RATIFIED 2026-09-03*** *— the "walk every row of a table when a sibling reports N" law
  with the **census method** as the subject, and the third turn of arch's own AP-21.*
  Arch ruled §3.3's default-code force (0.8.2.7) on the finding that *a count of the token is
  not a census of the slot*: 0.8.2.6 swept `unknown_operation` and reported the 501 class
  closed while `not_implemented` survived in all three trees. They then censused **by slot**
  — every code emitted at status 501 — across six trees and routed us four spellings.
  **Censusing instead by the row's INPUT** (*a handler is registered at this path and does not
  implement the named operation*) **found four more at this seat, every one outside status
  501**: two at `404 unknown_operation`, one at `400` with **no `code` field at all**, and one
  at `400 invalid_request`.
  **The last is the shape to remember, because it is invisible twice over.**
  `invalid_request` is the *correct* default for status 400, so the pair reads conformant at
  every glance short of asking what the input was. It carried a written argument for the 400 —
  `reflect` is the unwrapped listener's verb, so answering "not implemented" would imply a
  surface where it could be — which is an *intent* distinction, and §3.3's rows are defined by
  **inputs**. §6.2 says so outright and arch had ruled the identical distinction out at
  keystone's `pd` in the same packet. **And `storage.py`'s was the handler registered at `*`**,
  i.e. the most reachable refusal in the peer, answering with no code.
  **A slot census is a grep with better manners: it still starts from what you emit.** The
  spec's *input* is the only starting point that reaches a site whose status is wrong, and
  those are exactly the sites no cross-impl probe keyed on status can report.
  **Two corollaries earned building the gate, both from mutations that behaved unexpectedly:**
  1. **A gate whose search key is part of what the defect removes reports clean.** Reverting
     `storage.py` left the structural fallthrough row **green** — that row locates sites by a
     message convention, and the mutation deleted the message along with the fix, so the site
     dropped out of the population rather than failing. A count with any slack cannot fire for
     the same reason. Remedies: enumerate from the **registration list** (`handlers.
     list_handlers()`) — the one inventory a defect cannot edit, since a handler that stops
     answering the row is still registered — and make the marker guard a **ledger of modules**,
     not a floor.
  2. **A handler with no fallthrough is not a handler with nothing to audit.** `system.py`
     had *one* 404 serving both *"I do not implement that operation"* and *"that path holds no
     entity"*, so it was absent from every census in the file until the arm was split out. The
     ledger is what reported it joining.
  Enforcement point: `tests/integration/test_status_code_slot_3_3.py` — three complementary
  rows, each stating its own blind spot, plus the 404 row's reachability finding and the 500
  row's *deliberately assert-they-are-still-here* ratchet (arch **held** the ~16 specific 500
  spellings under §3a; a later reader of the 501 sweep must not infer the 500 slot was missed).
  Six mutations, six correct predictions after the two corrections above.

- **A sweep justified by "nothing defines a better code" is a NEGATIVE claim about the corpus,
  and your own tests will agree with you because you moved them.** ***RATIFIED 2026-09-03***
  *— SA-PY-37, and it is AP-21's own shape arriving inside AP-21's own remedy.* §9.1 (0.8.2.7)
  lists five *"non-conformant spellings"* of the 501 row. **`EXTENSION-REGISTRY` §6a.9.2 pins
  one of them, `unsupported_mode`, twice, both `[MUST]`** — and the second pins it *"because
  this is a cross-impl-observable answer with four plausible codes."* We swept both registry
  sites from the list; 0.8.2.7's own escape clause (*defined … in the owning domain handler's
  own table*) says §6a.9.2 wins.
  **Why the list is persuasive and wrong:** it enumerates spellings seats were **emitting** and
  reads as an enumeration of spellings the corpus leaves **undefined**. AP-21 is *a count of
  the token is not a census of the slot*; this is *a census of emissions is not a census of
  definitions*. Both are positive-sounding sentences whose truth condition is a negative, so
  `AGENTS-STANDARD`'s **prove a negative** rule never fires — the sentence reads as measured,
  and it cites five real spellings.
  **The unit suite could not catch it and the reason is the standing one.** We moved the
  assertions with the code — *our constant against our constant*, the exact configuration that
  hid `entity-core/7.0` and `bad_request`. **3854 green, and only a peer that does not share
  our constant could see it**: `entity-core-go`'s `registry_issuer.set_issuer_policy_domain_
  control_rejected`. **So: run the validator on a code sweep even when the unit suite is
  green** — a sweep is precisely the change whose tests move with it.
  **The checks, in the order they are cheap:** before retiring a spelling on a corpus-wide
  list, **grep the owning extension for it** — one command, and it reframes the task. And when
  a ruling hands you a list of forbidden values, treat the list as *evidence about
  implementations* and the ruling's escape clause as *the rule*; implement the rule.
  Enforcement point: the gate's `DEFINED_ELSEWHERE`, whose entries each **name the section that
  pins them** so a later seat cannot widen it by assertion, plus a row asserting each exemption
  is still emitted — an exemption that stops matching anything is cover for nothing while
  reading as a live carve-out.
  *Our own separate defect in the same pass, recorded because it is the funnier half: the 501
  site emitted `domain_control_unsupported` — a **fifth** spelling for the answer §6a.9.2
  pinned specifically because it had four plausible ones.*

- **A new gate on an argument that gets normalized is a gate on the wrong side of the
  conversion — and your fixtures are all on the arm where the conversion is a no-op.**
  ***RATIFIED 2026-09-03*** *— second instance of the §5.2 `target_peer` shape, and both were
  caught by a sibling's probe rather than by us.* Building row 4's refusal for
  `system/type:compare`, `_unresolvable` resolved the **raw** `type_a`/`type_b`, while
  `op_compare` resolves through `_normalize_type_lookup` — which accepts a bare name
  (`app/user`), a peer-relative path (`system/type/app/user`) and an absolute one. So every
  prefixed form read as unresolvable and answered `404` for a type that exists.
  **The two instances are the same defect in two languages of itself:** there, a new
  authorization check derived `target_peer` *inside* `_resolve_for_dispatch`, after
  `extract_handler_path` had stripped the peer segment. One parameter name, two
  representations, and the check standing before the conversion instead of after it.
  **And in both cases the local test passed because it handed the function a value production
  never gives it.** Here every fixture in the class used a bare name — *including the teeth
  control*, which passes `system/type` — so the whole class sat on the arm the normalizer does
  not change and could not fail. That is the *"two readings that agree everywhere your fixtures
  live"* law with a **normalizer** as the thing being agreed about, and the direction is not
  random: **a fixture author already holds one representation, and it is always the short one.**
  **The check:** when you add a gate to a function, find the conversions between the parameter
  and the value the *existing* logic reads, and write a row per representation — starting with
  the one you did not type. `git grep` the parameter name for a `_normalize`/`extract`/`canon`
  call on the path between the two. Enforcement point:
  `test_type_operation_error_taxonomy.py::test_a_resolvable_type_in_the_PREFIXED_form_still_answers_200`
  plus its absent-type mirror, so a fix that stops checking cannot pass the first.

- **Read pass 1 before you read the verdict — and a PASS read from the wrong pass is the same
  error wearing the opposite costume.** *Candidate, 2026-09-03.* The standing rule says a
  two-order-of-magnitude shortfall in pass 1's **total** is a harness fact, so read the count
  before the verdict. This is its mirror: `validate-complete.sh` runs seven passes against
  differently-built peers, `tail`ing the log showed
  `PASS connectivity.handler_not_found_on_unregistered_path`, and **pass 1 is a FAIL** — the
  passing line belonged to a later pass with a different peer configuration. I nearly published
  *"the cohort's 404 check passes against us"* on it, against a source read that said it could
  not. **`grep -n` the check name and look at the line numbers, never `tail`** — a multi-pass
  log has one line per pass per check and no two of them are claims about the same peer.
  *And the reasoning was right: the measurement that "disagreed" with it was never a
  measurement of the same thing.*

- **A routed report's claims about our repo are hearsay — seventh axis: our BUILD STATE, and it
  is the flattering direction.** *Candidate, 2026-09-03.*
  `PROPOSAL-TYPE-OPERATION-ERROR-TAXONOMY` §1 records *"`entity-core-go` and `entity-core-py`
  have not built these handlers, searched at the commits above"*, §4 concludes *"rust has the
  only implementation"*, and the relay asked us whether §2 matches what we **would** build.
  **We had built all six**, at `system/type`, against `EXTENSION-TYPE` v1.1 §7.1 — so the fold
  was sized on one build when it has two, and the ask was a hypothetical about a tree that
  already answers it.
  Same terminates-in-no-work direction as the §8.3 instance (*a premise saying you already
  comply*), one axis over: **a premise saying you have nothing to check produces no task at
  all.** Same one-grep check. And it changes what you can send back — an intention becomes a
  **measurement**, which is exactly what §4 says the fold needs (*"a derived failure set is a
  claim about what these operations can fail on — the kind of claim that is checked in a tree,
  not in a document"*).
  **What the measurement found:** §2 holds here unprompted (third seat); row 4's `validate` arm
  was already implemented and derived independently; row 4's `compare`/`compatible` arm
  diverged, and worse than the row says — an unresolvable type resolved to an **empty field
  set**, so `compatible("no/such/a","no/such/b")` reported two nonexistent types **compatible**.
  Fixed rather than held for the fold: the ruling decides whether the refusal is a `404`, and
  never licensed inventing an empty type. Enforcement point:
  `tests/integration/test_type_operation_error_taxonomy.py`, whose first class asserts the
  premise itself against the handler's source.

- **The control that makes a measurement attributable is also what stops it covering the
  neighbour.** *Candidate, 2026-09-03 — 0.8.2.6 Q1, and it is the row rust asked for on exactly
  this ground.* CE-1's rows target the responder's **own** namespace deliberately, so §1.4's
  address gate cannot be the refusing mechanism and the 401 attributes. go's probe carries the
  same precaution for the same reason. **Consequence: nothing in the cohort drove the foreign
  arm, and this peer answered `401 authentication_failed` for every pre-establishment address**
  — which is precisely the *"a peer that fixes CE-1 by relabelling its catch-all passes every
  own-namespace row and fails only this one"* shape, live in our tree one commit after landing
  CE-1. **When a test documents a control as protecting attribution, the case it excludes is
  owed a row of its own**, and the two must be asserted as *different* answers (ours is
  `test_the_foreign_arm_and_the_local_arm_do_not_collapse`) — a peer answering one code to both
  inputs has one gate, not two.
  **And the mutation run found the same asymmetry in the test file itself:** disarming the
  address gate reddened two rows; removing `uri=` from the **HTTP** call site reddened nothing,
  because the foreign rows were TCP-only. The refusal was shared and the *coverage* of it was
  not — the two-hand-rolled-copies shape reappearing on the test side one commit after the code
  side closed it, on the boundary no cohort probe dials.
  **Second half, and it is a correction of mine:** the other routed row —
  *"unauthenticated post-handshake `ping` must be served"* — is **not** a defect here, and the
  first draft of its test said it was. Driven against a **hello-only** socket it gets `409`,
  which looked wrong against the summary. The ruling's own argument is *"by the time the
  connection is established **both peers have authenticated** (§4.6)"*: the subject is a
  **frame-level** unsigned ping on a **fully established** connection, which we already serve.
  **Two senses of *unauthenticated*, and the one-line summary is true under both** — the
  standing *"open the ruling, not the packet that tabulates it"* rule, this time reaching a
  summary **arch wrote about its own ruling**. Both arms are pinned now, the half-open one with
  its reasoning and filed as SA-PY-35, because a later reader "completing" Q2 from the summary
  would serve a keepalive to a peer that has proved nothing.

- **When the spec assigns a row to SOURCE AUDIT, nothing will ever fail on it — so the census is
  the only detector, and it has to be scheduled rather than triggered.** *Candidate, 2026-09-04 —
  `remote_empty`, which shipped wrong from the day `pull` was written and was found by
  `entity-core-go` censusing 500 spellings, not by any probe.* §3.3's satisfaction mode (0.8.2.8)
  says the 500 row is **not drivable by a conformance client**: *"a conformant peer cannot be made
  to fail internally on demand over the wire, so this row is satisfied by a source audit of the
  implementation's emit sites at a named commit."* That is correct, and it has a consequence the
  paragraph does not state: **a status class excluded from wire testing is a status class in which
  a wrong answer is structurally undetectable.**
  **And the shape that made this one worse than a mis-spelled code.** The defect was not a wrong
  *code* at a real failure — it was a `500` on something that **is not a failure at all**. A
  remote with no versions is a normal outcome, so the wrong status was reachable by ordinary use
  and *still* invisible: no probe drives it (500 is exempt), no local test drove it (~90 revision
  tests and every one used a remote that had committed), and the emit site reads perfectly
  sensible in isolation. The census caught it because a census enumerates **emit sites** rather
  than failures, and an emit site on a success path is exactly what a failure-driven method
  cannot reach.
  **The check, and it is a calendar item rather than a rule:** for every row the corpus hands to
  source audit, put the census on the same schedule as the validator run — and census by **emit
  site**, then ask of each *"is the condition that reaches this line actually a failure?"*. That
  second question is the one that finds this class; *"is this code defined?"* would have passed
  `remote_empty` right up until the moment REVISION defined it as a 200.
  Enforcement point: `tests/integration/test_undeclared_500_code_census.py` (the standing census,
  monotone in both directions) plus
  `test_revision_extension.py::test_pull_from_an_empty_remote_is_200_remote_empty` and its
  unreachable-remote teeth control, because the substantive half of the ruling is that `502
  remote_fetch_failed` still means something different.

- **A fold answers some questions by OMISSION, and an omission from a table nobody had before is
  a ruling that arrives with nothing to prompt it.** *Candidate, 2026-09-04 — filed as SA-PY-40,
  found walking `EXTENSION-TYPE` v1.3 Appendix A after the fold rather than only the rows a
  sibling's gate drives.* This is the *"a ruling you already satisfy produces no diff"* law's
  sibling and it is worse in one specific way: there the normal forcing function (a behaviour
  change) is absent; here **there is no notification at all**, because the ruling is a row that
  is not present.
  **The mechanism.** A code minted where its extension had no error table is merely *undeclared*.
  The moment a table lands, §3.3's *"an undefined spelling is non-conformant"* binds it — so **a
  table landing retroactively converts every undeclared code in that handler's surface into a
  defect**, without touching a line of anyone's code. Measured: `entity-core-go` implemented three
  of the fold's four type-surface rulings in one clean cycle and reported the seat conformant and
  gate-green; the fourth (`decode_error` ×8 / `encode_error` ×3 / `invalid_entity` /
  `invalid_strategy` → the Appendix A defaults, which the proposal's §6a.4 had *already* routed as
  *"go aligns; nothing new is minted"*) had no row to implement **against**, so nothing surfaced
  it. Their own type gate drives neither a decode failure nor a bad strategy, which is the
  under-scoped-gate law they ratified in the same session, applied to the gate they wrote.
  **And the mirror was here**, disclosed in the same filing rather than after: py emits `400
  invalid_strategy` at two sites (`revision:merge`, `tree:merge`) whose owning tables define no
  such row — the code is real, it is just defined for a *different operation*. **"Defined in the
  corpus" is not the test; "defined for the operation" is**, and a grep that answers the first
  question reads like it answered the second.
  **The check:** when a table lands for a surface you implement — *especially* one you helped
  argue for — census that surface's whole code slot against the new table in the same session, in
  both directions. And do not route the sibling's half without walking your own first: the
  finding is the class, and the class is never one-sided.

- **A cross-impl probe that reads one field of a result says nothing about the others — and
  two implementations agreeing is not a majority verdict.** *Candidate, 2026-08-17 — found
  by building the `entity_sdk.revision` wrapper against §4.5.* `checkout` must answer
  `{status, target_version, head, branch?}`: `target_version` is what the caller asked for,
  `head` is where the prefix actually ended up, and under `auto_version: true` **they
  differ**, because applying the bindings mints versions and the head becomes a new
  descendant (§4.4.12). This peer answered a single `version` field. So did
  `entity-core-go`. Only `entity-core-rust` carried the spec pair — with `version` kept as
  a documented compat alias beside it. Two impls agreeing looked like the shape being
  right; it was two impls with the same gap.
  **Why every gate stayed green:** go's `validate-peer` checkout probe decodes the result
  and asserts `Status == "checked_out"`, full stop. A cross-impl run is only evidence about
  the fields it reads, and "cross-impl green" gets remembered as "the result shape is
  agreed". No local test asserted the shape either — 87 revision tests, none on this
  result.
  **The check:** when you wrap a handler, decode its result against the spec's result type
  **field by field**, and treat any field no test names as unverified regardless of how
  many peers pass. Where the spec gives two fields for what looks like one value, find the
  case that separates them and test *that* — here `auto_version: true`, which is the only
  configuration in which the old shape was observably lying. Enforcement:
  `tests/integration/test_sdk_revision.py::TestCheckout::test_under_auto_version_the_head_is_not_the_target`.
  Owed to core-go: the same field, and their probe cannot see it.
  ***RATIFIED 2026-09-01 — second instance, and the unit is a normative TABLE rather than a
  result's fields, which is what makes it worse.*** core-go's G-28 probe family measured us on
  §4.7 and reported two rows FAIL. Both reports were right. **Fixing them meant reading the
  table against the function, and four more rows were also wrong** — none of them probed:
  row 6's *mismatch* arm (FM-1 had fixed the same row's *pre-hello* arm three frames up and
  stopped), row 8's *second* named input, §4.6 step 2's *absent*-signature arm, and row 10,
  whose code we emitted for neither of its two inputs.
  **Why a table is the dangerous unit.** A result's fields are at least visible together in one
  decode. A §4.7 row is a `(failure, code, status)` triple whose *inputs* are scattered across a
  handler, and the probe family is named for the **table** — `connect_authenticate_*` reads as
  coverage of the connect-error contract. Three of ten rows were driven. **The report's scope is
  the probes it seeds; the reader's impression is the section it cites**, and nobody writes down
  the difference.
  **The check, and it is the cheap half of a relayed fix:** when a sibling reports N rows of a
  spec table failing, open the table and walk **every** row against your own code before fixing
  the N. It is the same read either way — you are already in the function — and the rows nobody
  drove are where a peer stays non-conformant *after* the cross-impl run goes green. Then say
  which rows they cannot reach, so their next probe family is not written to the same scope.
  Enforcement point: `tests/integration/test_connect_error_table_4_7.py`, which drives all four
  unprobed rows plus the two probed ones, each as a `(status, code)` pair, and carries
  `TestTheRowsDoNotCollapse` for §4.7's actual MUST (which is about the table, not any row).
  **Third instance, 2026-09-02, and the two new parts are *where* the unprobed arm lives and
  *why* a second walk of a row you already walked is not redundant.** core-go routed one row
  (`connect_ping_before_hello`: a pre-handshake `ping` answered `400 invalid_request` where
  0.8.2.4 pins `409 connection_sequence_error`). Walking row 10 *again* — the same row this
  entry's second instance had just walked — found the **mirror** defect: an unknown operation on
  an **established** connection answered `409 connection_already_established`. One predicate
  (*does the responder implement this operation*), two wire boundaries, classified by two
  hand-rolled comparisons that disagreed in opposite directions. The two-representations law with
  the **classifier** as the subject, and the fix is a set both call sites read
  (`IMPLEMENTED_CONNECT_OPERATIONS`) plus a structural row that fails a seat which re-rolls one.
  1. **A probe family's blind spot has a shape, and it is the seat the prober sits in.** A
     conformance probe dials in, so *every* state it can reach cheaply is a pre-handshake state;
     reaching the established side means completing a handshake first, which a probe author
     writes as **setup**, not as a state under test. So *"in any state"* clauses are
     systematically driven in one state, in every seat, and the arm nobody probes is not random —
     it is the far side of the setup. rust and go both happen to hold this arm correctly (checked
     first-hand, `connection.rs` `_ =>` and `execute.go`'s switch); **we were the only seat wrong,
     and no cross-impl run in the cohort could have said so.**
  2. **Walking a row once does not retire it — the *second* report on the same row is the cue to
     re-walk, not to patch.** The instance above walked row 10 and fixed both of its named inputs;
     this defect was live the whole time, in the same row, one state over. What changed was that
     0.8.2.4 re-cut the row on a *predicate* rather than on a list of inputs, and a predicate is
     what makes the unnamed cases enumerable. **When a ruling replaces a row's examples with a
     rule, re-derive every input from the rule** — the examples are what your last walk covered.
  Enforcement point: `TestTheSplitIsClassifiedByWhatWeImplement` in the same file — the routed
  row, its mid-handshake sibling, the established-state arm, row 9 as teeth (undriven on the wire
  until now), a control asserting we *serve* `ping` (the 409 is only conformant for a peer that
  does — go's probe carries that caveat in prose and nothing asserted it), and the structural row
  pinning both boundaries to one set. Four mutations, four correct predictions.
  **Fourth instance, 2026-09-06, and the unit shrinks again: the sibling reported ONE row, and a
  row is a PREDICATE while a probe is one member of it.** `entity-core-go` drove
  `EXTENSION-TREE` Appendix A's three `put` rows and reported py `3/4` — row 1 (*"the submitted
  entity does not decode"*) answered `500 internal_error`. Correct, reproducible, and their vector
  is `entity = 42`. Walking the **predicate** instead found **five** shapes reaching
  `Entity.from_dict`/`validate_entity_hash` intact, each answering a non-conformant pair.
  **The instructive one answered `200`.** A `type` of `42` is not a decode *failure* in Python at
  all — `cbor2` returns a native mapping, `compute_ecf_hash` encodes the integer, and the entity is
  **stored and bound under a type no typed peer can decode**. So the class had a member that was a
  success, and *nothing keyed on a status can reach it*: not go's relay (keyed on the 500), not our
  §3.3 slot census (keyed on the status), not a grep for a code (there is no code). Only driving
  the predicate's inputs finds it. **A defect class is bounded by its INPUTS; a success is a member
  of the class exactly as often as a wrong code is, and it is the member every status-keyed method
  is blind to.**
  **And the shape of the gap is language-shaped, which is why the cohort could not see it.** In go
  and rust *"does not decode"* is a language event — a typed decode — so the predicate is defined
  by their type system and never written down. Python has no such event, so this seat had to write
  the predicate as a function and found there was **nothing in the corpus to write it from**
  (filed, SA-PY-41). **When a spec row names a failure your siblings get for free from their type
  system, you are the only seat that has to state it — and the statement is a spec question, not
  an implementation detail.** The guard is deliberately the **intersection** of what go and rust
  refuse, so adopting it cannot make this seat the outlier on any shape; the two rows where the
  siblings disagree with *each other* are pinned at today's answer with the filing named in the
  assertion message rather than settled.
  Enforcement points: `tests/integration/test_tree_put_error_rows_appendix_a.py` (three mutations,
  three correct predictions) and `tests/interop/test_go_peer_tree_put_decode_predicate.py`, which
  **drives** the go column of SA-PY-41's table rather than reading it — 6/6 against a live peer at
  `69ec9e2`, including `EntityClient.put` itself raising a `400`, because *"our SDK cannot put to a
  go peer"* is a claim about a sibling and this repo does not route those on a source read. Same
  `ENTITY_GO_PEER=host:port` opt-in as the v324 probe, so the same **calendar** obligation applies:
  run it on every cohort catch-up and before replying to any routed tree item, and record the
  result with the go commit attached — never as a green suite.

- **The ORDER between two rows of one table is a rule no row states, and no per-row vector can
  reach it.** *Candidate, 2026-09-06 — found landing the row-1 fix above; reached independently by
  `entity-core-go` in their cycle 4, which is what makes it a shape rather than our bug.*
  `EXTENSION-TREE` Appendix A gives `put` two 400 rows: *does not decode* → `invalid_request`, and
  *the claimed hash is not its hash* → `hash_mismatch`. **An entity that is malformed AND carries a
  hash satisfies both descriptions**, so the table is individually satisfiable and jointly
  ambiguous. py validated the hash first and answered `hash_mismatch` for a submission whose defect
  was its shape — the caller told *"your hash is wrong"* when the fix is *"your entity is not an
  entity"*. go recorded the same thing about their own tree (*"`Validate` checks structure before
  hash — flipping wholesale to `hash_mismatch`, as the worklist prose read, would mis-code the
  structural case"*).
  **Why no vector catches it:** a vector is written per row, so it carries exactly the one fault its
  row names. go's row-1 vector (`42`) has no `content_hash` to disagree with, so a hash-first peer
  reaches the structural branch anyway and **passes**. The discriminating input is the one no
  row-scoped author writes, because it belongs to two rows at once.
  **The checks:** when a table gives one operation two rows over overlapping conditions, write the
  input that satisfies both and decide the order **explicitly** — then pin the order **structurally**,
  not behaviourally, because two correct-looking branches read fine in either sequence and a later
  seat hoisting one for tidiness reintroduces the defect at every overlapping input. And route the
  ordering: it is a missing sentence in the table, not a local choice
  (`TestTheOrderIsTheRow::test_the_source_orders_the_structural_check_before_the_hash`).

- **A DRAFT ruling is a thing to build, not a thing to wait on — the fold ratifies what the
  seats built.** ***RATIFIED 2026-09-04*** *— second instance, a different shape, a different
  seat, and the same source sentence, which is what makes it structural rather than a habit.*
  `entity-core-go` classified a whole board of items as *"prepare-then-land, gated on an arch
  spec-fold"*, traced the idea to `AGENTS-STANDARD`'s *"implement against the landed spec, not
  in-flight proposals"* — **the same line we cited when we held** — and had the operator strike
  it. Two seats, three days apart, reached the identical wrong posture from one sentence in the
  file that is injected into every repo. **A leak in the shared standard does not present as a
  shared mistake; it presents as two independent seats each being cautious**, and neither one
  can see the other's reasoning to notice the common cause.
  **The half that is still open here, and it is a real hazard rather than a footnote.** go fixed
  the sentence **in their working copy**. `AGENTS-STANDARD.md` opens with *"This file is
  identical in every entity-core repo… Do not edit it in your repo"* — so their copy and ours
  now differ, and **nothing anywhere checks that the identical-everywhere file is identical**.
  This repo's copy still reads *"implement against the landed spec, not in-flight proposals"*,
  which by that file's own precedence rule (*"this file wins on ecosystem conventions"*)
  outranks the entry you are reading. Our behaviour is right because this charter is what a
  session actually reads first; that is luck, not a mechanism. **Until the meta sync lands,
  treat this entry as the operative rule and expect the shared file to disagree with it** — and
  do not fix it here, because a second local edit to an injected file is how "identical" becomes
  unrecoverable rather than merely stale.
  *(Original entry, 2026-09-01 — the first instance:)* Arch ruled §4.7 row 10 in
  `PROPOSAL-CONNECT-SURFACE-RECONCILIATION` (FM-2), whose
  §7 reads *"No seat implements ahead of the fold."* We held on that sentence plus
  `AGENTS-STANDARD`'s *"implement against the landed spec, not in-flight proposals"*, and
  reported the resulting gate FAIL red. **go and rust had both already built it.** The cohort's
  actual working order is: **build the ruling, report what building it finds, let the fold
  ratify** — and the feedback from three seats building it is *the input the fold wants*. A seat
  that waits contributes nothing to the ruling and holds the cohort at two-of-three.
  **The distinction that survives, and it is the only one:** `AGENTS-STANDARD`'s rule is about
  *inventing* wire semantics — do not implement a proposal **nobody has ruled on**, and do not
  invent one yourself. It is not about a ruling arch has derived and written down. **Ruled-but-
  not-folded is not the same as unruled**, and treating them the same is what turned a one-line
  change into a routed disagreement.
  **What still justifies a hold** — narrowly: you find something *in the building* that
  contradicts the ruling. That is a finding, and it goes back with the evidence. *"The document
  says DRAFT"* is not a finding.
  **And it changes what the gate means.** A sibling's wire check on a ruled-but-unfolded
  semantic is not *"discriminating on an unruled semantic"* — the standing rule is about
  **unruled**, and we cited it at a row arch had ruled. The check was correct and our FAIL was
  ours.

- **A default argument is a wire decision with no call site to review it.** ***RATIFIED
  2026-09-02*** *— the `entity-core/7.0` law (a constant we chose, on a wire surface, that no
  local test can see) in a third shape, with an **error code** as the constant and a **default
  parameter** as its hiding place. Found by walking §3.3's code SET after core-go walked the
  §4.7 row set.* `ExecuteResponse.bad_request(..., code: str = "bad_request")` and
  `ConnectError(..., code: str = "bad_request")`. **`bad_request` is in no spec code set** —
  §3.3's 400 row declares *"Default `code` = `invalid_request`"* (landed at the 0.8.2.2 PD-1
  fold) and 0.8.2.4 adds *"MUST NOT mint a synonym"*; the string appears in the corpus once, at
  §5.1's M3 rule, as the thing you must **not** surface. Twelve kernel sites inherited it.
  **The mechanism, and it is the whole entry.** The *same peer* emits the correct
  `invalid_params` from ~80 handler-tier sites and the synonym from 12 kernel sites — and the
  difference is not care, it is that the handler sites **state** their code and the kernel sites
  **inherit** one. A default is invisible to exactly the review that reads call sites: every
  call site is correct-looking, because the wrong value is not written at any of them. Same
  family as *"a binary operator with no arm for the absent case is a policy decision wearing a
  type guard"*, one construct over — there the ruling hid in an `if`, here in an `=`.
  **Three things made it survive a suite that names it.** (1) Six test files *mention*
  `bad_request`; **none asserted our emission of it** — our constant on both sides, the version
  string's exact configuration. (2) The §4.7 table file's own docstring states the default
  accurately, **one session earlier**, while fixing the rows a probe named: *a probe family
  names rows, and nobody was assigned the default.* (3) It is a **code**, not a status, so every
  refusal still refused — nothing observable was ever wrong for a caller who did not read the
  code, which is every caller in our own tests.
  **The checks, in the order they are cheap:**
  1. **Grep your defaults for wire values.** Any `= "…"` in a constructor signature that reaches
     `result.data.code`, a type name, a format byte, or a protocol string is a spec value with
     no reviewer. Pin it against the **spec's declared literal**, never against what you emit.
  2. **When a sibling's report makes you re-read a spec section, read the paragraphs around the
     rows, not just the rows.** The sentence that produced this finding sits directly under the
     §4.7 table and is about the *code set*, not about any row — so a reader who arrives via a
     row-numbered relay scrolls past it. The row-walk rule (*walk every row when N are reported*)
     has a set-walk sibling: **walk the enumeration the rows draw from.**
  Enforcement point: `tests/integration/test_generic_400_code_is_invalid_request.py` — the wire
  pair for a codeless refusal, a spread row that fails a peer which special-cases one raise,
  both constructor defaults pinned against §3.3's text, and an **AST ratchet at zero** on the
  literal. *The gate corrected its author on its first run* (the standing "a gate's first act
  should be able to correct its author" shape, fourth instance): it found `peer.py`'s
  `getattr(e, "code", "bad_request")` — a fallback on an exception that always carries a code,
  invisible to the read that fixed the constructor — and one site that is **not** ours to fix,
  `EXTENSION-SIGNALING` §9.2's closed enum, which pins `bad_request` for the same class core
  §4.7 forbids a synonym for. Filed as SA-PY-33 rather than changed: core-go carries the
  identical string at the matching site, so it is the corpus disagreeing with itself.
  **And one place the value must NOT become the right code:** `connect_refusal` reports what the
  **remote** said, so filling an absent code with the plausible generic would fabricate a claim
  about a peer that made none. It carries `""`. *A default is a decision; the correct decision
  is not always the correct value.*
  **Second construct, next day (2026-09-02, CE-1), and it generalizes the rule past `=`.** The
  pre-establishment refusal answered **`403 capability_denied`** where §4.2/§5.2a pin `401
  authentication_failed`, at both of its call sites, and neither site named a status or a code:
  both read `ExecuteResponse.forbidden(request_id, message)`, a **named constructor that
  hardcodes the whole pair**. So the general form is not *"grep your default arguments"* — it is
  **any construct that supplies a wire value the call site does not write**: a default argument,
  a status-named constructor, a `getattr` fallback. All three have now bitten in eight days, and
  all three are invisible to the same review, because reviewing call sites is how you find wrong
  values and none of these has a wrong value *at a call site*.
  **Two things this shape adds that the `=` shape could not.** (1) The wrong value was **a real
  code from a real table** — `capability_denied` is §5.2a's authz default — so nothing looked
  minted, which is the cover `bad_request` never had. A code is only right *relative to an
  input*, and a helper named for a status cannot know the input. (2) It carried the **status**
  too, and the status is what encodes §5.2a's auth/authz class, so the same construct that hid a
  code hid a *classification*. **When a helper is named for a status (`forbidden`,
  `not_found`, `conflict`), every caller has silently agreed with its class** — grep those
  helpers' call sites and ask, at each, which spec sentence assigns that class.
  Enforcement point: `test_pre_establishment_execute_ce1.py::TestBothBoundariesShareOneRefusal`
  — but note what it pins, because it is the opposite of the ratchet above: the fix is a
  **shared** refusal (`_pre_establishment_refusal`) reached from both boundaries, i.e. one more
  construct supplying a value no call site writes. That is deliberate and it is the trade: a
  value stated in one place is reviewable, a value stated in zero places is not. What makes the
  difference is that the helper is named for the **input** rather than for the status, and that
  the structural row asserts both gates reach it.

- **"Unruled" is a claim about the corpus, and three peers disagreeing is evidence about three
  peers.** *Candidate, 2026-09-02 — CE-1. Cost: a routing packet, a proposal, and three seats'
  design attention on a question the spec answered two releases earlier.* `entity-core-go`
  measured the pre-establishment non-connect EXECUTE on all three live peers, found
  `403 connection_required` · `400 handshake_failed` · `403 capability_denied` — no two alike,
  none in any spec code set — and routed it by the divergence rule as *all-three-differ ⇒ spec
  ambiguity, tighten the spec*. Arch's first read agreed and argued a **401** lean on semantics.
  **§4.2's third pre-authorization bullet had ruled it at 0.8.1**, where F32 replaced that
  bullet's blanket 403 with the auth/authz discriminator, and §5.2a's table gives the code.
  **The mechanism, and it is why nobody was careless.** Every seat was reading **§4.7**, which
  declares itself the MUST-emit contract for that surface and had no row for this input. §4.2
  states the rule in the vocabulary of *pre-authorization*; the implementer is holding the
  vocabulary of *connection state*. **A rule stated in a vocabulary you are not searching in is
  indistinguishable from an absent rule** — and the missing cross-reference is exactly the
  SA-PY-32 defect (§4.5's `protocols` row, whose literal lived in §8.4) recurring one section
  over, which is the standing shape, not a coincidence.
  **Why divergence-by-measurement is the dangerous evidence:** it is the most convincing
  possible demonstration that a question is open, and it is **not evidence about the text at
  all**. It measures what implementers found, and every implementer read the same wrong section.
  This is *"two readings that agree everywhere your fixtures live"* inverted: there a shared
  corpus manufactured false agreement, here a shared **blind spot** manufactured false
  disagreement, and both are sustained by the cohort rather than caught by it.
  **And the two branches cost wildly different amounts, in the wrong direction.** *Unruled*
  terminates in a proposal, a routing packet and a design conversation — the expensive branch,
  and the one that feels careful and collaborative. *Ruled* terminates in a one-line fix. So the
  cheap check has to run first: **before accepting "unruled", grep the normative sections for
  the INPUT, not for the code.** Restate the input in the other vocabulary — *"an EXECUTE with
  no verified signer"* as well as *"a frame before the handshake"* — and search both. Two greps.
  **Two corollaries earned in the same pass:**
  1. **When you file a corpus conflict, name the section that governs your surface, not the
     section your constant transcribes.** SA-PY-33 filed §9.2-vs-§4.7 because §9.2 was the enum
     our constant copied; the ruling put the defect in **§4.3**, which is the section governing
     the surface we actually serve, and left §9.2 untouched. Same remedy, different sentence —
     and only one of the two tells the next person which line to grep.
  2. **A test that describes itself by reference to another surface makes no independent
     claim.** The HTTP pre-connect row asserted the old `403` under the docstring *"mirrors the
     TCP path's pre-connect reject"* — and what it mirrored was the TCP path's bug. It sat on
     the one boundary **no cohort probe reaches** (they all dial TCP), so it was the only thing
     that could ever have caught the divergence, and it was pinning the defect. The seam-move
     rule says grep the old status; this adds that a row asserting the defect and a row
     asserting the contract are textually identical, and the tell is a docstring that names a
     sibling instead of a spec sentence.
  Enforcement point: `tests/integration/test_pre_establishment_execute_ce1.py` — the ruled pair
  at both boundaries, an AST ratchet on the two codes 0.8.2.5 names non-conformant, and
  `test_the_two_states_now_agree_on_the_same_frame`, which is the row that states the defect:
  this peer already answered `401 authentication_failed` for the identical frame one state
  later, so it had been disagreeing with **itself** the whole time. *A cross-impl divergence
  that is also an internal one was never a spec question.*

- **A mutation that reddens NOTHING is a finding about the code, not a shortfall in the test —
  and the usual culprit is a defensive arm that already answers the same thing.** ***RATIFIED
  2026-09-09*** *— second instance in a different shape, and the two shapes want **opposite**
  remedies, which is the part the candidate could not yet say.*
  **Second shape, 2026-09-09, building PD-2's presented-authority arm.** Four verifications, four
  mutations. Two reddened the predicted row. **Two reddened nothing:** disabling the `granter`
  check and disabling the `grantee` check both left 15/15 green. Asking *what else answers this?*
  found, in each case, a **legitimately independent** second refusal rather than a dead arm:
  - the third-party-minted capability the granter row drove is *also* rejected by chain
    verification, whose root check runs in the target's frame;
  - the grantee row left the third party's identity out of the bundle, so `grantee` did not
    **resolve** — a weaker and different refusal than a *mismatched* grantee.
  **So the remedy was the fixture, not the code.** The configuration that isolates the granter
  check is a chain **rooted at the target** whose leaf was delegated on to a third party:
  chain-valid, leaf granter not the target, and nothing else refuses it. Both mutations now
  redden exactly one row.
  **The discriminator between the two remedies, which is what ratification adds:** ask whether
  the second path refuses **the same input for the same reason** or **a different input for a
  different reason**. Same-and-same (the `adopt` shape) is redundancy — delete the arm, because
  the next seat will delete the load-bearing one instead. Different-and-different (this shape) is
  defence in depth, and the finding is that **your fixture is not the discriminating
  configuration** — it is satisfying two refusals at once, so it can never tell you which one is
  doing the work. The tell is cheap: if you can describe an input that the *other* path accepts,
  the arm is live and the fixture is wrong.
  **And the non-discriminating rows are kept and labelled**, not deleted — a reader who finds
  four rows in a class counts four rows of coverage unless one of them says otherwise.
  *(Original candidate, 2026-09-04, landing the type-op alignment:)* The new `404 type_not_found` gate went onto five
  operations and each got a mutation. `converge`'s unarming reddened the two predicted rows;
  `adopt`'s reddened **nothing — 33/33 green with the gate deleted**. The reason is not a weak
  assertion: `op_adopt` raises `ValueError` for exactly one cause, the `except ValueError` arm
  routed it to the same `_type_not_found`, so **two independent paths produced one wire answer**
  and no single mutation could distinguish them.
  **Why the standing laws do not already cover it.** The mutation discipline says *a mutation
  nobody runs is a claim* — this one ran. The prediction rule says *when a mutation is caught by
  a test you did not predict, the prediction is the finding* — nothing caught it, which is the
  case that rule has no arm for, and the tempting reading is *"my row is too weak, strengthen
  it."* **That reading is wrong here and it is wrong in the expensive direction**: it sends you
  to write a sharper assertion for a gate that is not doing any work, and leaves the duplicate
  path in place, where the *next* seat deletes the arm that was actually load-bearing.
  **What it is a shape of:** the two-representations law with **control-flow paths** as the two
  representations. It is invisible to review for the ordinary reason — both paths are correct,
  and a reviewer checking that each produces the right code finds nothing wrong at either. It
  is invisible to the *mutation run* for the interesting reason: the run's whole method is
  single-point disablement, and redundancy is precisely what that method cannot see.
  **The check:** when a mutation fires on nothing, ask *what else answers this?* before touching
  the test. If the answer is a `try`/`except` or a fallback the new gate now precedes, the arm
  is dead by construction — delete it, and let the gate be the only path. Keep a fallback only
  where it answers a **different** status for a **different** cause, which is exactly why
  `converge`/`reconcile` keep theirs and why their mutation fires.
  Enforcement point: `_op_adopt_dispatch` has no `except` arm at all, with the measured 33/33
  green recorded at the call site so a later reader restoring it "for safety" is told what it
  costs; the row that now discriminates is
  `test_an_unresolvable_type_is_404_type_not_found[adopt]`, re-verified RED.

- **A cohort poll is ruling input, so a wrong answer moves a specification rather than failing a
  build — measure it, and then check whether your answer is a POSITION or an accident.**
  *Candidate, 2026-09-09 — F60/N-4, and both halves were wrong on the first pass.*
  `entity-core-go` polled the three seats: when a handler **is** registered, its operation **is**
  in the manifest, and **no body is bound to run**, what `code` do you emit? go spells it
  `no_handler_body`; the spec defines none; the question is whether an impl may mint one at all.
  **Half one — I answered from a source read and it was wrong.** The tree-walk resolver returns
  `None` when it can bind no implementation, which falls through to handler resolution, so: `404
  handler_not_found`. Measured: **`501 unsupported_operation`.** (The site's own log line says
  *"returning 501"* and returns `None`, so the comment was closer to the wire answer than my
  reading of the code was, for the wrong reason.)
  **Half two, and this is the part worth carrying.** The `501` is **not a decision about the
  bodyless handler**. Resolution falls through to the wildcard `*` handler a default peer
  registers, and *that* handler answers `501 unsupported_operation` because `ping` is not an
  operation **it** implements. Driven on a peer built without the `*` fallback, the identical
  input answers `404`. **So the code is a property of the deployment's handler table, not of the
  request** — and reporting it as py's answer, into a three-way comparison of spellings, would
  have contributed a number with no opinion behind it and let the ruling read it as one.
  **Why the standing laws do not cover this.** *"Verify with pytest, not inline scripts"* is about
  facts in our own tree; *"a routed report's claims about our repo are hearsay"* is about claims
  someone else makes. This is the inverse: **a claim WE make about ourselves, into someone else's
  ruling**, where the normal forcing function is absent in both directions — nothing fails if the
  answer is wrong, and nothing fails if the answer is meaningless.
  **The two checks, in order:**
  1. **Answer a poll with an assertion, not a paragraph.** A row that pins the measured pair is
     reproducible, survives a later refactor changing it, and costs one test.
  2. **Then ask whether a peer configured differently answers differently.** If yes, you have a
     coincidence of your handler table and you must say so — that fact is *more* useful to the
     ruling than the code is, because it says the row cannot be a conformance row until the
     code is pinned. Here it also supplied an argument *from the spec*: `501` asserts *this peer
     does not implement that operation* while the manifest in the tree says it does, and §6.6
     makes the tree the resolution surface — so a caller who reads then dispatches gets two
     contradicting answers. That is go's conclusion, reached from a different defect, which is
     worth more to arch than a third spelling.
  Enforcement point: `tests/integration/test_registered_handler_with_no_body.py` — the measured
  pair, and `test_the_answer_comes_from_the_wildcard_fallback_not_from_a_decision`, which builds
  a peer without the `*` handler and asserts the answer **changes**.

- **A filing posed as "which of these two readings" asserts that they are alternatives — check
  whether they are at different LAYERS before you make arch choose.** *Candidate, 2026-09-06 —
  SA-PY-41 ask 2, and the one ask of four that did not go either way we posed it.* We asked: is
  `put` a **wire-receipt** path (§1.8: validate the carried hash, never recompute) or an
  **authoring** path (§4.5a: the submitter chooses the format)? Both, and the corpus already said
  where: the peer's `system/tree:put` is receipt, the SDK's `put(path, type, data) → hash` is
  authoring, and they compose exactly — an SDK **cannot return a hash it did not compute**. The
  §4.5a half of the dichotomy was never an authoring *arm* at all; it governs which format an
  author uses and **presupposes** an author.
  **Why an either/or framing is worse than a bad answer:** it narrows the ruling's search space to
  the two branches you named, and both of ours were peer-side, so the whole SDK layer was outside
  the question. Arch went and looked anyway. Had it not, the ruling would have picked one of two
  wrong shapes and every seat would have implemented it.
  **The two checks, both cheap.** (1) When you cite two sections as opposed, **name the subject of
  each sentence** — ours were *a receiver* and *an author*, which is not a disagreement. (2) When
  an ambiguity is about **who does X**, enumerate the layers that could, including the ones above
  the wire: an SDK contract is normative here (`SDK-OPERATIONS`) and is the layer a peer-side
  reading structurally cannot see. *A dichotomy is a claim, and it is the claim in a filing that
  nobody checks, because the filing is framed as not knowing the answer.*

- **Two defects that cancel inside one tree are invisible to that tree's entire suite — and the
  pair you are most likely to own is a lenient RECEIVER plus a lax SENDER of the same field.**
  ***RATIFIED 2026-09-06*** *— the two-representations law with a **protocol layer boundary** as
  the thing represented twice, and the first instance where our own SDK and our own peer were the
  two halves. Filed as SA-PY-41, ruled the next day at 0.8.2.11 §6.3.*
  `EntityClient._put` sent `{"type", "data"}` — two of `core/entity`'s three required fields — and
  `system/tree:put` fell through to `Entity.from_dict` and minted the third. Each defect is the
  other's cover: the SDK's omission never surfaces because the peer supplies it, and the peer's
  authoring never surfaces because nothing local omits the field on purpose. **4289 tests, ~90
  driving `put`, and not one could fail** — a round-trip test asserts the value the caller gets
  back, and that value was right the whole time.
  **The tell is structural, not behavioural, and it is the reusable half.** A compensating pair
  needs *one tree containing both roles* of a wire contract. This repo carries the SDK and the peer
  in-tree (deliberately — see "Project structure"), so **every field on every request we both send
  and serve is a candidate**, and the isolation the tier gates give us is about *imports*, not about
  this. rust has the identical shape at the identical field and did not see it either; go, which
  had only the receiver defect, was the seat that could not help finding it.
  **The check, and there is only one that works:** for a field your own code both **emits** and
  **admits**, the discriminating test is one where the other end is *not yours*. A same-tree test
  cannot distinguish "we agree with the spec" from "we agree with ourselves" — the standing
  `entity-core/7.0` shape (*our constant against our constant*), now with a **required field's
  presence** as the constant. Enforcement points: `test_sdk_l1_operations.py::
  TestTheSDKConstructsTheEntity`, whose rows read the **request** rather than the result and whose
  last row drives the peer's refusal of the old shape so restoring either half alone fails; and
  `tests/interop/test_go_peer_tree_put_decode_predicate.py::test_our_own_sdk_can_now_put_to_a_go_peer`,
  which is the same assertion inverted at the boundary and is the only row in either repo that can
  see the SDK half at all.
  **Two corollaries earned landing it.**
  1. **A ruling that names two layers has a landing ORDER inside your seat, and getting it wrong
     breaks you rather than the cohort.** Sender-side construction first, receiver-side strictness
     second — the reverse leaves your own SDK talking to your own now-strict peer. Arch stated it;
     it is worth restating because *the receiver fix is the one that reads as "the conformance
     work"* and is therefore the one a seat reaches for first.
  2. **Fixing the receiver is not fixing the seat: census every SUBMITTER, including the ones no
     SDK reaches.** Ours were compute's `store` builtin (in-process, dispatches to `system/tree:put`
     with a hand-built dict) and `system/storage:write`'s wire callers. A grep for the *operation*
     finds them; a grep for the SDK method does not.
  *And the count is the fixture measurement, again: **10 of 4289** tests armed the newly-invalid
  form and one asserted it as the contract, docstring and all. A rule landing on a field you have
  never asserted turns your fixtures into the finding.*

- **A cohort-consistency argument is only as good as the census behind it — and the generated
  family is the one a ground-up seat forgets it is in a cohort with.** ***RATIFIED 2026-09-04***
  *— second instance, and the missing seat was a **ground-up** one, which retires the comforting
  reading that the first instance was about keystone being invisible.*
  `entity-core-go`'s item-D ledger routes two 500 tokens to arch as cohort-consistency
  arguments: **bless** `storage_error` (*"a consistent, deliberate 14× convention"* for a
  durable tree-bind failure) and **keep** `backend_error`. The census behind both polled go and
  rust. Running the identical census here **splits the two recommendations apart**:
  `backend_error` and `remote_empty` are corroborated — one site each, in the subsystems go
  names, reached independently — while `storage_error` is ×1 here, and the same failure is
  spelled `io_error` ×7 in `local_files`, *the exact subsystem go spells `storage_error` ×4*,
  plus `bind_failed` in `identity`. **The token is not a cohort convention; it is a go
  convention**, and go's own warning (*"do NOT converge 2 of 14 — that manufactures the
  divergence"*) is measuring the wrong scope: the cross-**seat** divergence already exists, and
  nothing reports it because no probe reads a 500 code.
  **The reusable half, and it is what makes this different from a duplicate of the first
  instance:** a census of *your own tree* answers *"is this consistent here"*, and a
  consistency argument is a claim that it is consistent **everywhere**. Those are different
  sentences and one grep separates them. So when you recommend a **bless** — the branch where
  the spec ratifies what implementations already do — the evidence has to come from the seats
  that would be ratified, and *"14 sites"* is a count of one seat however large it gets.
  **And say which branch the recommendation actually is.** Blessing `storage_error` is a
  **convergence instruction to this seat**, not the ratification of a shared practice. That is a
  perfectly good outcome; it is just the opposite of what the word *bless* implies, and the
  routing packet is where the difference has to be visible.
  Enforcement point: `tests/integration/test_undeclared_500_code_census.py` — a ledger of every
  undefined 500 spelling with its count, monotone in both directions, plus
  `TestTheTreeBindFamilyIsTheFindingGoCouldNotMake`, which fails if the family collapses so the
  packet's premise cannot go stale silently. *The gate corrected its author on its first run
  again (fourth instance): the `grep -E` census in the routing draft reported 36 sites and the
  AST walk found **40** — `invalid_blob` ×2 is split across lines. **A regex census of code
  emissions is a count of the token**, which is AP-21's own subject arriving inside the remedy
  for AP-21, exactly as SA-PY-37 did.*

  *(First instance, 2026-09-02 — SA-PY-31 ruled against the arm we shipped:)* §4.5 left the absent/empty `protocols` arm
  undefined; we picked reading 1 (unconstrained), **matching `entity-core-go` byte for byte**,
  and filed rather than settling — on the stated ground that *"a responder that refuses where
  its sibling accepts partitions the cohort, and inventing that out of a gap is the error this
  repo exists to find."* That reasoning is sound and the ruling went the other way, because
  **the cohort is not the ground-up seats**: keystone's generated `csharp` and `typescript`
  peers already **required** the field, so reading 1 would have made 46 peers non-conformant.
  We polled two of three families and called it the cohort.
  **And reading the third family first-hand — rather than through the relay that named it —
  found the second half.** The ruling's L16 cites those peers as *"already require the field
  and pass conformance."* Measured in `entity-core-keystone` (`ConnectHandler.cs:70`,
  `connect-handler.ts:80`, both `Ecf.require` → `EntityProtocolException(status=400)`):
  - **absent** → the exception is caught at the dispatcher's handler boundary and answered
    **`400 handler_error`** — a refusal, but not the ruled pair, and `handler_error` is in no
    §3.3 code set (their `request_error` / `internal_error` are the same class — SA-PY-33's
    shape at the conformance anchor).
  - **empty list** → passes `require`, fails the membership test, and answers **`400
    incompatible_protocol`** — **reading 3**, which 0.8.2.4 explicitly forecloses (*"row 1 is
    reserved for a non-empty set"*).
  So the peers the ruling cites as its evidence **do not implement the ruling**, on the arm the
  ruling names in its own sentence (*"no `protocols` field, **or an empty list**"*). The
  citation is right about the direction and wrong about the pair. **A ruling's justification is
  a claim about a peer, and it stays a claim when the peer is a third party's** — the standing
  law with the subject moved one seat over. Routed; `connect_absent_protocols` will FAIL against
  a keystone peer, and the tempting read of that FAIL is *"the check is wrong"*, because
  keystone is the conformance anchor.
  **Why the generated family is the one that gets dropped:** it has no `AGENTS.md`, files no
  SAs, routes nothing, and is invisible to the `git log`/`grep` sweep we run across
  `entity-core-{go,rust}` — the whole habit of *"read the source, not memory"* is pointed at the
  trees that talk back. It is nonetheless conformance-passing peers on the wire, and 46 of them.
  **This is the standing *"the conjunction of two readings bounds the disagreement, not the
  error"* law with a census as the subject** — both seats can be wrong in the same direction, and
  a cohort-consistency argument inherits that shared error *and dresses it as evidence*.
  **The check, and it is one grep in a tree we do not usually open:** before arguing "changing
  this partitions the cohort," grep `entity-core-keystone` for the field. If a generated peer
  already implements the arm you are declining to implement, your partition argument is
  backwards — **you are the partition.**
  **What this does NOT retract:** filing rather than inventing was still right, and our
  *argument* is what carried the ruling (arch adopted the remedy-selection reasoning verbatim).
  The defect was in the fallback, not the filing. Enforcement point:
  `test_connect_protocols_intersection_4_5.py::TestTheAbsentArmIsARuling`, whose retirement
  condition fired **as written** and which flipped rather than being deleted — the second
  recorded instance of a deferral's forward half executing, and the reason nobody had to
  re-litigate whether the arm was ever going to move.

- **A field with no consumer *anywhere in the cohort* is not a converged field — it is an
  unmeasured one, and the first seat to implement it creates the divergence rather than
  finding it.** ***RATIFIED 2026-09-01*** *— the validator-vs-consumer law (§2.4 `exclude`, the
  `peers` dimension, the resolver ceiling) with the missing consumer in **all three trees at
  once**, which is the shape none of those instances could warn about. Cost: py could not dial a
  go peer, measured, and the tree was `4138 P` green on both sides of the break.*
  `entity-core-go` implemented V7 §4.7 row 1 (§4.5's `protocols` *"Intersection, must be
  non-empty"*) and relayed it as *"both siblings owe the `handleHello` intersection check."*
  True, complete as a description of the work, and **applying it verbatim would have partitioned
  the cohort**: this peer advertised **`entity-core/7.0`** while §8.4, go and rust all say
  **`entity-core/1.0`**. Measured against a live go peer at `7262f17`, before touching anything:
  `400 incompatible_protocol · initiator=[entity-core/7.0] responder=[entity-core/1.0]`.
  **The mechanism, and it is the reusable half.** Every previous instance of this law had a field
  with a producer and no *local* consumer, so a cross-impl run could catch it — someone else read
  the field. Here **nobody** read it, in any tree, for the life of the project. Three peers
  carried it on every hello and agreed perfectly on the *behaviour* (ignore it) while disagreeing
  on the *value*. **A dead field cannot diverge observably**, so the 358-vector corpus, the 1616
  wire checks and three green suites were all evidence about a field none of them could see.
  The divergence was *created* by the first conformant implementation.
  **Why the direction of the check hides it, and this is what to carry past this bug.** Row 1 is
  a **responder** obligation, and a peer that implements it against the wrong constant still
  passes every responder-side check anyone will ever write — ours and the cohort's — because a
  probe dialing *you* offers *your* string back to you. **A negotiated value is only testable
  from the seat that does not choose it.** So the row that found this had to dial **out**, and
  the general form is: for any field whose value your peer *asserts*, the discriminating test is
  one where the other end asserts it instead.
  **Two things this does NOT license.** It is not an argument against go's relay — their
  measurement, their site and their fix were all correct for their peer, and the relay could not
  have contained a fact neither seat had. And it is not "check the constant" — it is *find the
  field's consumer in the cohort, and if there is none, the field's value has never been tested
  by anything.*
  **And it repeats the versioning conflation this file already refuses, one layer down.** The
  `7` was read off the specification's **title** (`ENTITY-CORE-PROTOCOL-V7`, cited as v7.69
  throughout) while §8.4 pins the wire identifier two thousand lines away. The top of this file
  spends a section on *"our release version is not the protocol version"*; the same mistake
  reached the wire because **a document's version and the identifier it pins are two numbers,
  and one of them is a string a peer compares byte for byte.** Filed as SA-PY-32 asking for the
  one cross-reference that would have prevented it: §4.5's row names §8.4's literal.
  Enforcement points: `test_connect_protocols_intersection_4_5.py` —
  `TestTheVersionStringItself::test_the_advertised_version_is_the_one_8_4_pins` (pinned to what
  **§8.4 declares**, not to what we emit, per the `PINNED_ROOT_HASH` lesson), the **AST-based**
  zero-ratchet against a second literal, and the `system/peer/info`-vs-hello row that compares the
  two surfaces a peer states its version on — they were separate literals, so each surface's suite
  asserted its own and neither could see the other. Seven mutations, seven correct predictions;
  the one that matters is that reverting the constant to `entity-core/7.0` turns **only** the
  version row red — every behavioural row passes, because both sides of a local test use the same
  constant. *That is the entry, restated as a measurement.*
  **Corollary, earned in the same pass: a rejection probe malformed in a second dimension is a
  harness defect that only surfaces when someone implements the rule it violates.** Landing the
  intersection turned go's `format_agility.agility_unknown_1` red — its hello encodes key_type
  `0xFD` *and* advertises `entity-core/v7`, a **third** spelling in no spec and no tree. This is
  the D11 rule (*"when two rules gate one write, every rejection test must satisfy the rule it is
  not about"*) with a **sibling's probe** as the subject. The right response was **not** to
  reorder our checks to suit it: tracing it (A1) found that §4.5 names hello *"the canonical
  earliest reject point for an unsupported `key_type`"* and we rejected only at `authenticate` —
  a real gap that `AGILITY-UNKNOWN-1` tolerated because it is satisfied *"at any handshake
  surface"*. **A vector written to accept any of several surfaces cannot tell you that you are on
  the wrong one**, so the gap read green until an earlier check took the surface away. Fix the
  spec's rule, not the probe's expectation — and keep the probe's own malformed frame as a test
  row, because the tidy frame your fixtures would have written cannot discriminate the ordering.

- **A new wire field has THREE homes and only two of them have a test that fails when you miss
  one.** *Candidate, 2026-09-01, building RELAY v1.3 — the two-representations law with the
  **declared type** as the representation nobody enumerated.* Adding `forward-request.
  expires_at` and `limits.max_retention_ms` touched the constructor (`make_*`), the handler
  that reads them, and `types/definitions.py`. The first two are exercised by every behavioural
  row you write *because you are writing them to test the behaviour*; the third is a separate
  file nothing in the feature's own test set imports. So the field shipped, worked, was
  mutation-verified — and was **undeclared**.
  **The only thing that saw it was a sibling's type census**, reporting `field "expires_at":
  optional locally, missing remotely`. Open-type-tolerable, hence a WARN rather than a FAIL, and
  still a real defect: a peer type-checking against our published `system/type` rejects a
  request *we ourselves send*. A WARN in a 446-row category is also the least-read line in the
  run.
  **The check:** after adding a wire field, grep `types/definitions.py` for it before you
  commit. And build the gate against the **constructors**, not against a field list — a
  hand-maintained list is the artifact that goes stale, and the constructor already knows every
  key it can emit. Enforcement point:
  `test_relay_store_bounds_v13.py::TestTheDeclaredTypesCarryTheNewFields`, which asserts
  `set(make_forward_request(...).data) - set(declared_fields)` is empty, so the *next* field is
  caught here rather than by whoever reads our types next. Mutation-verified.
  *And the mutation cost the work twice: it was run against an **uncommitted** type edit, so the
  `git checkout --` restore took the fix out with the mutation. The "mutate a committed file"
  rule below, hit in exactly the shape it describes — it is a rule about the restore step, and
  the restore step is the one you run on autopilot.*

- **Python's unbounded `int` turns a decode failure into a silent comparison — and a
  parsed-but-unread field is not a checked one.** *Two security defects, 2026-08-17, both
  found by running core-go's validator rather than by any test of ours.*
  - *CAP-6a ingest.* A received capability whose `expires_at` / `not_before` /
    `created_at` is a bignum or negative must be refused (`GUIDE-CAPABILITIES` §6.2). In Go
    and Rust the CBOR decode into `u64` fails and the token never reaches the bounds check.
    `cbor2` hands back an arbitrary-precision `int`, so `2**64 + 1000 < now` is a
    well-formed comparison that answers **False** — the token is not rejected, not
    truncated, just found to expire after the heat death of the universe. Four of the six
    field×shape variants were honored; the other two were refused **by accident**, as
    ordinary expiry verdicts, which is exactly how a narrower probe reports this clean.
    **Where a peer language fails closed by decoding, we have to fail closed by checking.**
    Enforcement: `capability/temporal.py` — one predicate, seven call sites, plus
    `tests/integration/test_capability_ingest_temporal_cap6a.py` (which carries the probe's
    *teeth control*: the same construction with a normal expiry MUST be honored, or a
    refusal is attributable to the re-sign rather than the field).
  - *The §5.2 `peers` dimension.* `system/capability/token` has parsed `peers` since V6.0
    and **nothing ever read it**. Two halves were missing: the target peer comes from
    `extract_peer(execute.uri)`, not `local_peer_id`; and an absent `peers` defaults to
    `{include:[local]}` **and is still checked**. Since every grant in this repo omits the
    field, every capability we issued authorized dispatch into *any* peer's namespace — a
    foreign-namespace privilege escalation. The whole suite passed before and after the
    fix, because nothing in it ever dispatched at a foreign URI.
  - *And the fix for the second one was itself wrong once, in the same shape.* The first
    version derived `target_peer` **inside** `_resolve_for_dispatch`, which runs after
    `extract_handler_path` has stripped the peer segment — it read `system/tree`, answered
    "local", and authorized every foreign dispatch exactly as before. The new test passed,
    because it handed that inner function a full URI **production never gives it**: one
    parameter name (`path`) carrying two representations at two call sites. Only re-running
    core-go's probe caught it. **When you add a check, verify the value it reads is the
    value at *that* point in the pipeline, not the one the caller had** — and prefer a
    required keyword argument to a derivation, so the next call site has to state what it
    means instead of silently inheriting a pass. The test seam has to be the one production
    uses: an in-process dispatch at a foreign URI never reaches local authorization at all
    (`_is_remote_uri` routes it), so that test could not have measured the thing it named.
  - **The rule both teach:** *a field the type system parses is not a field the
    authorization path checks.* For every dimension a capability can carry, name the line
    that reads it — and if the answer is "the dataclass", that dimension is unenforced.
    Same shape as the validator-vs-consumer lesson above (§2.4 `exclude`), one layer down:
    there the field had a validator and no consumer; here it had a *parser* and no
    consumer.

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

- **`EmitPathway.subscribe` accepts any pattern and silently matches nothing.** Its
  matcher (`_pattern_matches`, `storage/emit.py`) handles `*`, `prefix/*` and exact, and
  falls through to an **exact string compare** for everything else. So a reserved form
  like `docs/*/intro` registers without error and never fires, for the life of the
  process — a subscription to nothing, with no moment at which it looks wrong. **Audited
  2026-08-17: every in-tree caller subscribes `"*"`, so nothing is currently dead**, and
  the only caller-supplied pattern is the diagnostic tap's. `entity-sdk` converts the
  unsupported forms to a 400 at its boundary (`validate_watch_pattern`), which is the
  §6.1 status for invalid pattern syntax. **The peer's behaviour is pinned by a test**
  (`test_the_peer_really_does_accept_and_never_match`) rather than asserted in a comment,
  so if core ever starts rejecting or supporting the form, the SDK check gets revisited
  instead of quietly becoming wrong.
- **A spec `MAY` is cross-peer nondeterminism the SDK absorbs, not nondeterminism it
  forwards.** *Candidate, 2026-08-17 — bit us once, at the first operation we built.*
  `SDK-OPERATIONS` §3.4 lists 404 for `remove` and then says *"implementations MAY
  silently succeed."* Our tree handler silently succeeds; a conformant peer may 404. The
  first draft of `EntityClient.remove` exposed a `missing_ok` flag — which **forwards the
  coin flip to the caller**: identical caller code raises against one peer and not
  another, and the defect surfaces only on contact with a second implementation. That is
  precisely the class of bug this repo exists to *find* in other people's stacks, so
  shipping it in our own SDK would be an unusually poor trade. **The rule:** at a `MAY`,
  the SDK picks one branch, once, and documents which — every peer then looks the same
  from above. Where the caller genuinely needs the distinction, give them a separate
  operation that answers it directly (here: `has`), never a flag that means "tell me
  whichever thing this particular peer happens to do."
  **The enforcement point** is a test per absorbed `MAY` that drives *both* peer
  behaviours — one against the real peer, one against a stub returning the other answer —
  and asserts the SDK surfaces the same result. `test_sdk_l1_operations.py`
  `test_remove_is_idempotent` + `test_a_404_from_a_peer_that_reports_one_is_also_absorbed`
  are the pair. A single-sided test proves nothing here: our peer only ever produces one
  of the two answers, so the untested branch is the one that breaks on contact.

## Contributing

Default branch `master`; DCO sign-off required. See **AGENTS-STANDARD.md** for the full
contribution / branch / conformance flow.

**Commit finished work — don't ask first.** When a change is built and verified (scoped
tests green; `make test` and a live `validate-complete.sh` run for anything protocol-facing),
commit it with `git commit -s` on a non-default branch and report what you did. Choosing how
to split the work into commits is your call, not a question to route back: prefer themed
commits that each build and test on their own, and collapse an arc rather than ship an
intermediate commit that doesn't import. Say which way you split it and why. Leaving verified
work sitting in a dirty tree waiting for permission is the failure mode, not a safe default.

**Push it too — don't ask.** A fast-forward push of your own commits to a non-default
branch (`dev`) is authorized standing, not per-session. The cohort reads this repo off the
remote: go had to read py off disk to write a report because eighteen verified commits sat
unpushed waiting for a permission that was never going to be interesting. Unpushed verified
work is invisible work. Push it and say what you pushed.

Still ask before **opening a PR** or **tagging** — those announce something. And the golden
rules in AGENTS-STANDARD.md are unchanged and are what make the above safe: **never
force-push**, never rewrite shared history, never push to `master`, never touch a sibling
repo's git. A non-fast-forward is a stop-and-ask, always.
