@AGENTS-STANDARD.md

# entity-core-py

**`AGENTS-STANDARD.md` is imported above and is always loaded with this file** — it holds the
ecosystem-wide conventions and wins on those; this file wins on entity-core-py specifics.
`METHODOLOGY.md` sits beside them, carried but **not** loaded: open it by trigger (see *How we
work here*). `CLAUDE.md` is a shim to this file and nothing else.

**Our addressable name in cohort routing is `entity-core-py`** — the directory name. Packets
we send go in [`docs/outbox/`](docs/outbox/); see *Cohort routing* below.

## Overview

**entity-core-py is a clean-room Python peer for the Entity Core Protocol.** It is one of
three independent ground-up implementations (with `entity-core-go` and `entity-core-rust`),
and its job is **interoperability testing**: it exists to validate that the specification is
clear and complete enough that someone can build a compatible peer from the text alone. When
it cannot, that is a finding about the spec, not a local problem to paper over.

It implements the wire protocol end to end — content-addressed entities, ECF/CBOR encoding,
Ed25519 identity, capability delegation, and the handler/peer runtime — plus an SDK and a
CLI on top.

**The spec is upstream and this repo does not define it.** Hit a gap or an ambiguity → log it
in [`docs/SPEC-AMBIGUITIES.md`](docs/SPEC-AMBIGUITIES.md) and route it (below); do not settle
it locally.

### Where things are, on disk

The sibling repos are checked out beside this one. **Paths, because they are not guessable:**

| what | where |
|---|---|
| Core protocol + CBOR encoding + test vectors | `../entity-core-protocol/specs/` |
| `EXTENSION-*.md` (tree, revision, registry, compute, …) | `../entity-system-architecture/specs/extensions/` |
| `GUIDE-CONFORMANCE.md` and the other guides | `../entity-system-architecture/guides/` |
| The Go peer, and the cohort validator | `../entity-core-go/` — `scripts/validate-complete.sh` |
| The Rust peer | `../entity-core-rust/` — `cmd/entity-peer` |

**The wire protocol identifier is `entity-core/1.0`** (core spec §8.4). It is *not* the
document version and it is *not* our release version — this line read `entity-core/7.0` until
2026-09-01 and the peer advertised it on every hello. See
[`WIRE-ENCODING-AND-ENTITY-FIDELITY.md`](docs/agents/memory/WIRE-ENCODING-AND-ENTITY-FIDELITY.md).

## Versioning — ours, and it is NOT the protocol version

**This repo's release version is its own. The protocol version is a different number and
they are expected to disagree.** `entity-core` 0.9.0 implements Entity Core Protocol
0.8.2. Full reasoning: the *"What the version numbers here mean"* section at the top of
`CHANGELOG.md` — that section is the canonical statement and this is the pointer to it.

The operational facts:

- **Per [ADR-0002] the targeted spec level is carried out-of-band**, never in the release
  number — one string cannot carry both. Each changelog entry names its level on a
  `Protocol:` line. At `v0.8.0` the two coincided, which was a **starting condition, not a
  scheme**; reading it as one is how `0.8.2` nearly got stamped across this repo.
- **All four packages share one version and release together**, dependency floors included. A
  mixed installation is not a configuration we test.
- **`pyproject.toml` is the single source of truth.** `entity_core.__version__` reads
  installed package metadata — not a second literal, because it was one and it drifted
  to `0.1.0` unnoticed.
- **The number is not the contract; conformance is** ([ADR-0012]). Cite a measurement by its
  oracle commit, never by a release number — which is why a conformance emission pins
  `impl_version` to the git sha.

Bumping: 0.x SemVer — minor for added surface or a break, patch for fixes. Changing it means
editing **five** `version =` lines (root + four packages) plus the dependency floors, then
regenerating `uv.lock`, or the container build fails at `uv sync --frozen`.

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
- **The ratchet** — every audit ends by writing down what it taught, same session.
  **If it didn't land, it didn't land.** ⚠ **Where it lands is now a decision, not a
  default:** *would a newcomer need this before their first change?* → here. *Only when they
  hit the thing it describes?* → `docs/agents/memory/<TOPIC>.md`. **Adding to this file is the
  exception.** It grew to 309 KB — ten times its budget — because it was the only file whose
  name invited it, and everything in it was worth keeping.
- **An entry that could become a check SHOULD become one, and is then deleted from memory.**
  Memory is where a finding waits *while it is still only prose*; it is not where findings
  retire. Most entries there already name their enforcement point.
- **The promotion ladder** (§3) — bit us once → an anti-pattern entry; a second time in a
  different shape → a ratified discipline. Candidates are applied, not yet claimed to generalize.
  **A discipline with no enforcement point is theater** — name the grep, the lint rule, or the
  gate test.

**Owed:** the anti-pattern catalog now exists as `docs/agents/memory/` — nine topic files,
~100 entries, most naming an enforcement point. What is still owed is the **promotion pass**:
walking it entry by entry asking *could this be a check instead?* and deleting the ones that
become one. The near-term native candidate is the encoding
class this stack forces — cbor2 float16 minimization is a known Rule-4 gap, and any
float-carrying entity type is a cross-impl hash divergence waiting to be filed as someone
else's bug.

## Setup / environment

- **The canonical build and test need only `make` + `podman`** on the host. No Python, no
  toolchain. If you install nothing else, `make check` still works.
- **Local dev (optional, and much faster):** Python **3.12** and **`uv`**. The Dockerfile
  pins 3.12 too.
- **uv workspace of 4 packages** (`entity-core`, `entity-handlers`, `entity-sdk`,
  `entity-cli`) under `packages/`; `uv sync` installs all four.
- `tests/interop/` needs a **live peer from another implementation**; it skips cleanly
  without one. See *Interop* below.
- Identities live in `~/.entity/identities/<name>/` — outside the repo, shared between runs.

## Build & test

The canonical path. This is the one that gates a change:

```bash
make build     # build the runtime image
make test      # build the dev image, run the full suite in-container
make check     # lint + test — the green gate
make help      # every target
```

**Measured on a warm image, 2026-09-17: `4758 passed, 58 skipped in 120.96s`, 2m09s wall.**
A cold run adds the image build. 4,816 tests are collected; **the 58 skips are `tests/interop/`
with no sibling peer running** — that is the expected state for a plain `make test`, and it is
the one place a skip here is not a failure.

Local dev, once `uv sync` has run:

```bash
uv sync                                      # install the workspace
uv run pytest                                # full suite
uv run pytest tests/unit/test_diagnostic.py  # one file
uv run pytest -k delegation                  # one test by name
```

> ⚠ **`uv run` refuses if the host has no Python 3.12** — `.python-version` pins 3.12, and a
> 3.11 venv is a common state here. The message is *"No interpreter found for Python 3.12"*
> and it is not a repo problem. Either `uv python install 3.12`, or drive the venv directly:
> `.venv/bin/python -m pytest`. **`make test` is unaffected** — the container has 3.12.

**Run the bare full suite before committing anything that touches a shared predicate.**
`pytest tests/unit tests/integration` is *not* the full suite: `tests/` also holds
root-level modules (`tests/test_compute.py`, `tests/test_handlers_handler.py`, …) that a
directory-scoped run silently skips. Scope a run to a **file**, never to a directory with
siblings.

### Interop, against another implementation's peer

```bash
# Terminal 1 — Rust peer:   cd ../entity-core-rust && cargo run --bin entity-peer -- --listen 127.0.0.1:9000
# Terminal 2 — Python peer: uv run entity-core start --listen 127.0.0.1:9001 -i my-identity
# Terminal 3 — the tests:   uv run pytest tests/interop/ -v
```

⚠ **Before starting any peer, check the port is actually free** — `ss -ltnp | grep <port>`
*and* `grep -rn "<port>" tests/`. This has cost real sessions seven times. Read
[`PEERS-PORTS-AND-THE-VALIDATOR.md`](docs/agents/memory/PEERS-PORTS-AND-THE-VALIDATOR.md)
first; it is short and every line of it was paid for.

### Reading a green

- **The unit suite is not the gate for anything protocol-facing.** The real gate is the
  cohort validator, `../entity-core-go/scripts/validate-complete.sh python`, which drives
  this peer from an independent implementation. A local suite is our constants checked
  against our constants; several live defects here were invisible to it and visible to that.
- Cite a conformance number as `N·0F @ <oracle-commit>`, never as a bare percentage and
  never by our release version. **A skip counts as a failure.**

Tests should be **fast and deterministic**; prefer integration tests over mocks for protocol
code — a stub dispatcher cannot be evidence about the dispatcher.

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
  values preserved, no omissions**. Upstream:
  `../entity-core-protocol/specs/ENTITY-CBOR-ENCODING.md`.
- **No legacy / back-compat code.** This is a clean-room impl with no old peers to stay
  compatible with — as the spec lands, delete legacy / deprecated / dual-format paths
  (and tests that only assert them) rather than preserving them. Verify against
  the core protocol whether a path is current-spec before cutting; don't keep
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
- **The spec is upstream** — `../entity-core-protocol/specs/` and
  `../entity-system-architecture/specs/extensions/` (see the table in *Overview*). This repo
  implements the spec; it does not define it. Hit a gap or ambiguity → log it in
  `docs/SPEC-AMBIGUITIES.md` and route it upstream, don't paper over it locally.
- **Outside this repo: strictly read-only.** No git operations of any kind on sibling
  repos (`entity-core-protocol`, `entity-core-go`, `entity-core-rust`, …) — not even "safe"
  ones like `stash`/`pop`; no writes/edits/creates/deletes. Those trees hold other people's
  uncommitted work. Need newer state from a sibling? **Ask the operator to pull it**; read
  the already-checked-out tree; never mutate it.

## Where a new thing goes

| you are adding | put it in |
|---|---|
| a unit test | `tests/unit/` — one file per module under test |
| a test that drives a real peer over a socket | `tests/integration/` |
| a test that needs another implementation's live peer | `tests/interop/` — must skip cleanly without one |
| a conformance vector or emitter fixture | `tests/conformance/` |
| protocol kernel code | `packages/entity-core/` — see the tier rules in *Project structure* |
| a standard handler | `packages/entity-handlers/` — **and two more registrations**, see *Adding a handler* |
| an L1/L3 client operation | `packages/entity-sdk/` |
| anything the CLI renders | `packages/entity-cli/` — **no protocol knowledge**, the gate enforces it |
| a spec gap or ambiguity | `docs/SPEC-AMBIGUITIES.md` as the next `SA-PY-N`, then route it |
| a durable finding | `docs/agents/memory/<TOPIC>.md` — not `AGENTS.md`. See below |
| a dated snapshot or handoff | `docs/status/`, never the repo root |
| a packet for another repo's seat | `docs/outbox/` |

**A doc that should reach someone outside this project must be declared in
`CANONICAL-DOCS.toml`.** That file is a *keep-list*: undeclared prose is deleted from the
public tree at a release cut, not merely skipped.

## What is in flight

**[`docs/STATUS.md`](docs/STATUS.md) is the rolling log** — where the project is, what landed,
what is open. Read it before starting anything substantial; it is the one file that tells you
what you are about to collide with. Dated snapshots live in `docs/status/` and age out to
`docs/archive/status/`.

## Cohort routing — `docs/outbox/`

**Our addressable name is `entity-core-py`.**

Packets we send live in [`docs/outbox/`](docs/outbox/), one file, dated, under a title that
**states the finding** rather than labelling it. Acknowledged ones move to
`docs/archive/outbox/`. **`docs/outbox/` is never declared in `CANONICAL-DOCS.toml`** —
routing is internal and must not publish.

Every packet carries a header, and `To:`, `From:` and `Tip:` are required — **a packet whose
claim cannot be re-derived is an opinion**:

```markdown
**To:** `entity-core-go`, `entity-system-architecture`
**From:** `entity-core-py`
**cc:** `entity-core-rust`
**Re:** <full stem of what this answers — never an abbreviated form>
**Tip:** `dev` @ <sha>
```

**Receiving is a watermark, not a grep.** Each `docs/status/TRACKER-<counterpart>.md` carries
one line: *last read their outbox through `<date>`, at `<branch>` @ `<sha>`*. To check
inbound: **fetch their repo first**, list `docs/outbox/` for a filename dated after your
watermark, read the header, act or ignore, then move the line and record the tip you scanned
at. Going by file mtime instead of the filename date advances your watermark past packets you
never saw, and that miss is permanent.

**If you could not reach a counterpart's tree, write that in the tracker** — *could not look*
is not *nothing to see*, and an omitted row reads as clean. **Every packet addressed to us
gets a row, including ones we decline**: from the sender's side a refusal and a silence are
indistinguishable.

## What this repo has learned — `docs/agents/memory/`

**Everything this repo has found the hard way lives in [`docs/agents/memory/`](docs/agents/memory/INDEX.md), by topic.** Read [`INDEX.md`](docs/agents/memory/INDEX.md) first and open the row that matches what you are about to do — you are not expected to read all of it.

| open | before you |
|---|---|
| [`ROUTED-CLAIMS-ABOUT-US.md`](docs/agents/memory/ROUTED-CLAIMS-ABOUT-US.md) | act on a packet, ruling or fold that just arrived |
| [`FILING-AND-ARGUING-UPSTREAM.md`](docs/agents/memory/FILING-AND-ARGUING-UPSTREAM.md) | route a finding out, answer a cohort poll, or hold on a ruling |
| [`SPEC-READING-AND-CENSUS.md`](docs/agents/memory/SPEC-READING-AND-CENSUS.md) | implement a normative rule or walk an error table |
| [`TESTING-FIXTURES-AND-MUTATION.md`](docs/agents/memory/TESTING-FIXTURES-AND-MUTATION.md) | write a test, build a probe, or cite a result |
| [`AUTHORIZATION-AND-CAPABILITIES.md`](docs/agents/memory/AUTHORIZATION-AND-CAPABILITIES.md) | touch a grant, a scope matcher or a permission check |
| [`WIRE-ENCODING-AND-ENTITY-FIDELITY.md`](docs/agents/memory/WIRE-ENCODING-AND-ENTITY-FIDELITY.md) | touch ECF, hashing, the codec or a wire literal |
| [`SDK-HANDLERS-AND-DISPATCH.md`](docs/agents/memory/SDK-HANDLERS-AND-DISPATCH.md) | wrap a handler operation, or change the dispatcher |
| [`PEERS-PORTS-AND-THE-VALIDATOR.md`](docs/agents/memory/PEERS-PORTS-AND-THE-VALIDATOR.md) | start a peer, or cite a validator number |
| [`BUILD-TOOLCHAIN-AND-ENVIRONMENT.md`](docs/agents/memory/BUILD-TOOLCHAIN-AND-ENVIRONMENT.md) | debug the build or the tooling behaving oddly |

**These are live findings, not a changelog** — several are security defects that a green
suite did not see, and most name the test that now holds them. The rule that bounds the
directory: **an entry that could become a check should become one, and then it leaves.**

The four below stay here because you need them *before* your first change, not when you hit
them.

### The four that bite fastest

- **Strict entity fidelity (`ENTITY-CORE-PROTOCOL.md` §1.8) — the single biggest interop
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

> Getting any of these wrong breaks byte fidelity or authorization against the Rust and Go peers, silently. The instances that produced them are in [`WIRE-ENCODING-AND-ENTITY-FIDELITY.md`](docs/agents/memory/WIRE-ENCODING-AND-ENTITY-FIDELITY.md) and [`AUTHORIZATION-AND-CAPABILITIES.md`](docs/agents/memory/AUTHORIZATION-AND-CAPABILITIES.md).

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
