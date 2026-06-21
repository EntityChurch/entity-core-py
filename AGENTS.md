
# entity-core-py

Read **AGENTS-STANDARD.md** first. This file adds entity-core-py specifics.

## Overview

Python implementation of the Entity Core Protocol (`entity-core/7.0`), built as a
clean-room peer for **interoperability testing against the Rust implementation** — it
validates that the spec is clear and complete enough to build compatible implementations.
The spec is upstream; this repo implements it.

## Setup / environment

- **Canonical build/test needs only `make` + `podman`** on the host — no host toolchain.
- **Local dev (optional):** Python **3.11+** and **`uv`** on the host. The Dockerfile pins
  Python **3.12** + uv.
- **uv workspace of 3 packages** (entity-core, entity-handlers, entity-cli); `uv sync`
  installs all.
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

uv workspace, three packages under `packages/`, with a strict dependency direction
**entity-cli → entity-handlers → entity-core**:

- **entity-core** (minimal, stable) — `crypto/`, `protocol/`, `capability/`, `storage/`,
  `types/`, `utils/` (ECF), `peer/` (Peer, PeerBuilder, Connection), and `handlers/`
  (**registry + context + bootstrap ONLY**; bootstrap is MUST-per-spec, handles
  hello/identify).
- **entity-handlers** (standard, optional) — `tree.py`, `system.py`, `storage.py`,
  `query.py`, `manifest.py`.
- **entity-cli** (user app) — `main.py` (entry point), `display.py`.
- `tests/` — all tests together (`tests/unit/`, `tests/interop/`).

**Adding a handler requires THREE things** — miss any and it appears registered but 404s
on operations:
1. Handler function in `entity-handlers`.
2. Manifest in `entity_handlers/manifest.py` → added to `ALL_HANDLER_MANIFESTS`.
3. Registration on the peer: a `with_X_handler()` method on `PeerBuilder` **and** that
   method called from `with_all_handlers()`.

Handlers needing persistent state (indexes, subscriptions) use an **Extension** (hooks
EmitPathway, initialized during `build()`); the handler is created via the extension so it
can reach the state.

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
- **Cross-impl reports lag — ground truth is a live run.** Go's `validate-peer` cross-impl
  reports live under `entity-core-go/docs/validation/reports/` (`CROSS-IMPL-*-PYTHON-*.md`,
  dated) and go stale: fixes land without a new report and runs can be flaky. Don't
  treat a dated report as current status — run the validator live against HEAD. `local_files`
  is a Go-only extension; Python failing it is an expected scope gap, not breakage.

## Contributing

Default branch `master`; DCO sign-off required. See **AGENTS-STANDARD.md** for the full
contribution / branch / conformance flow.
