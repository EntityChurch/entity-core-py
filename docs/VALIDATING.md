# Validating a Peer Against the Spec

A practical guide to the peer validator: what it is, how to run it, and how to
read the results. Written to be shared across implementation teams (Python,
Rust, Go, workbench). Treat the validator as a **black-box development tool** —
something you run locally to confirm your changes still conform to the Entity
Core V7 spec, the same way you'd run a linter or a test suite.

> This is not a "Go thing." The validation suite happens to be hosted in the
> Go repo, but it talks to your peer **over the wire as a black box**. It
> validates any peer — Rust, Python, Go, or an arbitrary `host:port` — against
> the **spec**, not against Go. Go is just a convenient default reference peer.

---

## Mental model

The validator connects to a running peer and checks two things:

1. **Responder-side** — your peer *answers* incoming requests correctly
   (types, encoding, handler manifests, operation semantics).
2. **Origination-side ("A-role")** — your peer *dispatches outbound* EXECUTEs
   correctly, checked against a known-good **reference peer**. Single-peer-only
   validation misses every outbound-dispatch bug by design, so a full run needs
   a reference peer (the harness auto-starts a Go one unless you point it
   elsewhere).

Work is grouped into ~25 **categories** (connectivity, encoding, type_system,
handlers, tree_operations, subscriptions, continuations, revision, clock,
history, security, query, compute, identity, role, attestation, quorum,
origination, convergence, local_files, …). Each check carries a **spec
reference** (e.g. `TREE §6.2`). Each check is:

- **PASS** — conformant.
- **WARN** — minor/benign difference (optional field, version hash, a
  deliberate behavioral choice). Note it; not blocking.
- **FAIL** — a spec violation: required behavior missing or broken.

**The spec is the source of truth, not any implementation.** When a check
fails, read the `spec_ref` first. If Go (the default reference) is itself
wrong, the fix may be in Go and/or the check — not your peer.

---

## Prerequisites

- A checkout of `entity-core-go` (hosts the suite + `peer-manager`).
- A Go toolchain (to run the harness — you are not writing Go).
- Your own peer, buildable/runnable from its repo.

Sibling checkouts under one parent dir is the expected layout, e.g.:

```
entity-systems/
  entity-core-go/      # the validator harness lives here
  entity-core-py/
  entity-core-rust/
```

---

## Quick start

All commands run from the **`entity-core-go`** directory.

```bash
cd ../entity-core-go   # adjust to wherever your go checkout is
```

**1. Start your peer** (managed by peer-manager — it builds/runs from source):

```bash
# --type is one of: go | python | rust
# --history enables the history extension (without it, that category fails)
go run ./cmd/peer-manager start --name my-peer --type python --debug --history "*:1000"
```

It prints the address, e.g. `addr=127.0.0.1:38237`. (You can also point the
validator at any externally-started peer by address.)

**2. Run the validator** (auto-starts a Go reference peer for origination):

```bash
./scripts/validate-peers.sh my-peer
# or by address:
./scripts/validate-peers.sh 127.0.0.1:38237
```

**3. Read the summary** — a per-category table plus:

```
Summary: 915 total, 882 passed, 3 warned, 30 failed
Result: FAIL
```

**4. When you change code**, restart the peer so it picks up the change, then
re-validate (Python/Rust restart is instant; Go is rebuilt by peer-manager):

```bash
go run ./cmd/peer-manager stop my-peer          # note: positional name
go run ./cmd/peer-manager start --name my-peer --type python --debug --history "*:1000"
```

---

## Command cheat sheet

```bash
# Full validation (responder + origination), one peer
./scripts/validate-peers.sh my-peer

# Just one category (fast iteration on the thing you changed)
CATEGORY=tree_operations ./scripts/validate-peers.sh my-peer

# Save machine-readable JSON to docs/validation/reports/<peer>-validation-raw.json
SAVE=1 ./scripts/validate-peers.sh my-peer

# Responder-side only — quick smoke test, NOT a full validation
NO_REFERENCE=1 ./scripts/validate-peers.sh my-peer

# Use an already-running reference peer instead of auto-starting one
REFERENCE_ADDR=127.0.0.1:9002 ./scripts/validate-peers.sh my-peer

# Single category, direct, with full per-check JSON (good for triage)
go run ./cmd/validate-peer -addr 127.0.0.1:38237 \
    -identity framework-admin -category security -json

# peer-manager basics
go run ./cmd/peer-manager start --name X --type python --debug --history "*:1000"
go run ./cmd/peer-manager stop X            # positional, not --name
go run ./cmd/peer-manager addrs X           # print address
go run ./cmd/peer-manager logs X            # path to its log file
```

Always pass `-identity framework-admin` (directly or via the script's
default) — it carries admin grants covering all categories. Categories whose
grants aren't covered are **skipped**, not failed.

---

## Interpreting results

- **Restart before you trust a result.** A running peer holds your *old* code
  in memory until restarted. Re-validating without a restart tells you nothing.
- **Not every red is your bug.** Some categories cover **optional extensions**
  a given implementation hasn't built. Example: `local_files` is currently a
  Go-only optional extension; a Python/Rust peer "failing" all ~30
  `local_files` checks is one *unimplemented optional extension*, not 30
  broken things — a scope decision, not a regression. Know which categories
  are in scope for your peer.
- **WARN is usually fine.** e.g. a peer with a deeper/lighter evaluator may
  WARN on a depth-limit check — a deliberate behavioral choice, not a defect.
  Read the message and decide.
- **Group FAILs by root cause.** Common patterns:
  - all type hashes differ → type registration / ECF encoding issue
  - handler manifest 404 → handler not registered (or not implemented)
  - `403 forbidden` at dispatch → grants don't cover the handler/resource
  - `400 invalid_params` → params not entity-wrapped / missing resource targets
  - extract→merge roundtrip fails → envelope missing trie nodes

---

## Caveats worth knowing (learned the hard way)

- **Saved reports go stale fast.** A dated report in
  `docs/validation/reports/` reflects the code *at that moment*. Fixes land
  without new reports; runs can be flaky. **Always run the validator live
  against your current build** — never treat an old report as current status.
- **Some checks are timeout-based and can flake.** A lone FAIL on a
  delivery/timeout check (e.g. cross-peer result delivery) — especially one
  that blocks a cascade of dependent checks — re-run before believing it.
- **Rotate the reference periodically.** The default reference is Go, so Go
  bugs are invisible in origination checks (anything Go accepts "passes").
  Periodically run with Rust or Python as the reference
  (`REFERENCE_ADDR=...`); a check that passes against one reference but fails
  against another points at a bug in the reference that accepted it.

---

## The change → verify loop (for your own dev)

1. Make your change in your peer's repo.
2. Restart the managed peer (picks up the change).
3. `CATEGORY=<the area you touched> ./scripts/validate-peers.sh my-peer` —
   fast feedback.
4. Before calling it done: full `./scripts/validate-peers.sh my-peer` and
   confirm the summary is unchanged except for your intended deltas (no new
   FAILs in categories you didn't touch).
5. Run your own unit/integration suite too — the validator checks wire/spec
   conformance; it does not replace your in-repo tests.

---

## Going deeper

The authoritative, more detailed references live in the Go repo:

- `.claude/skills/validate-peers/SKILL.md` — full category table, options,
  reference-rotation and combinatorial procedures.
- `docs/architecture/guides/PEER-VALIDATION-WORKFLOW.md` — the spec-adoption
  vs. convergence workflows, how to classify divergences (spec ambiguity vs.
  spec-wrong vs. impl bug vs. impl gap), and worked case studies.

Spec text (the actual source of truth) lives in the
`entity-core-architecture` repo under
`docs/architecture/v7.0-core-revision/specs/`.
