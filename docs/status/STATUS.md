# entity-core-py — status

_Updated: 2026-06-30 · public: v0.8.0 (master)_

## Where it is

Python reference implementation of the Entity Core Protocol (`entity-core/7.0`).
It is built clean-room — directly from the specification, with no shared code with the
other implementations — so its real job is to prove the spec is clear and complete
enough to build a compatible peer from scratch, and to act as an interoperability peer
for the Rust and Go implementations.

The codebase is a `uv` workspace of three packages with a strict
`entity-cli → entity-handlers → entity-core` dependency direction:

- **entity-core** — the minimal, stable protocol library: `crypto/` (Ed25519/Ed448
  identity, signing, hashing), `protocol/` (Entity, Envelope, messages, framing),
  `capability/` (tokens, checking, delegation), `storage/` (ContentStore, EntityTree,
  EmitPathway), `types/` (definitions + registry), `utils/` (ECF encoding), `peer/`
  (Peer, PeerBuilder, Connection), and `handlers/` (**registry + context + bootstrap
  only**), plus `conformance/`, `diagnostic/`, and `sdk/`.
- **entity-handlers** — the standard, optional handlers: tree, system, storage, query,
  manifest, capability, role/role-policy, identity, attestation, quorum, subscription,
  inbox, continuation, history, revision, auto-version, compute, route, relay, discovery
  (incl. mDNS), registry (incl. peer-issued), type (handler/constraint/narrowing/
  analysis), and the `content/`, `encryption/`, `local_files/`, and `substitute/`
  sub-packages.
- **entity-cli** — the user-facing CLI (`entity-core start` / `connect` /
  `list-identities`).

Maturity: reasonably mature for a research preview. A broad suite — roughly 2,600+ test
functions across ~130 files (unit, integration, interop, and conformance directories) —
backs it, and `v0.8.0` ("Genesis") is cut as the initial public research-preview release,
with package versions aligned to `0.8.0` alongside the parallel Rust/Go cores. This is
**not a 1.0 API commitment.** The canonical build/test path needs only `make` + `podman`
on the host (a pinned `Dockerfile` carries the exact Python + `uv`); local dev uses
Python 3.11–3.13 and `uv`.

## Where we left off

No code or protocol changes since the `v0.8.0` "Genesis" research-preview cut — recent
work has been docs / standards hygiene only (the Code of Conduct was softened to open
with "be good to all"; this canonical status doc was added; a small standards-alignment
cleanup was applied). The implementation is at the Genesis line and stable; the next
substantive work is upstream-spec tracking and live cross-impl validation (below).

## Backlog

- Track the upstream spec as it lands and fold changes in. Per the **no-legacy policy**,
  delete legacy / deprecated / dual-format paths (and the tests that only assert them)
  once a path is confirmed not current-spec — verify against the spec before cutting,
  don't keep confirmed-legacy "just in case."
- Surface and route any spec gaps or ambiguities **upstream** rather than papering over
  them locally.
- The cross-impl peer validator's `local_files` profile is Go-scoped; Python not passing
  that profile is an **expected scope gap**, not a defect — keep it understood as such
  rather than chasing parity there.
- Open spec gaps / TODOs beyond the above: unknown / to confirm.

## Waiting on

- **The spec is upstream** (`entity-core-architecture`); this repo implements the landed
  spec and does not define it, so feature scope tracks what upstream lands.
- **Interop and cross-impl validation need a live reference peer.** `tests/interop/`
  requires a Rust peer started alongside, and the spec-conformance peer validator (see
  `docs/VALIDATING.md`) is an external, Go-hosted black-box harness that talks to a
  running peer over the wire — it is not runnable standalone from this repo. The
  authoritative cross-impl run is owned by the harness side at the release commit.

## Done recently

- **`v0.8.0` "Genesis" release** cut on `master`; the three published packages aligned to
  `0.8.0`; clone-fresh build verified (`make build` / `make test` green from a fresh
  clone with no sibling repos and no host toolchain beyond `make` + `podman`).
- **Build unified onto `make` + `podman` as the sole build door** — removed `mise` and
  the `docker-compose` alternate entrypoints; the `Makefile` drives raw `podman` over a
  pinned multistage `Dockerfile`, with podman resource caps added.
- **Conformance vectors moved out of `docs/`** into `tests/conformance/` so they survive
  the publish scrub (the content and type vector sets).
- **Multisig attenuation-across-depth vectors fixed** to spec-valid delegation chains —
  per-granter resource canonicalization correctly exposed that the stale tests granted a
  multi-sig root to a non-signer grantee; the implementation was right, the tests were
  wrong. Suite back to zero failures.
- **Encryption extension landed** — crypto substrate, three modes, a passphrase-wrapped
  (Argon2id) key-backup tier, and the associated entity type definitions. (The self-mode
  KATs run a memory-hard derivation and are marked `slow`.)
- **Registry extension** — a petname backend plus a peer-issued registry backend with
  live registration (register-request + issuer-policy) and a curated operator CLI.
- **Relay extension** — source-routing, raw-frame terminal-hop, and inbox-relay paths,
  exercised Python↔Go over a live wire.
- **Discovery extension** — substrate plus an mDNS backend and announce support.
- **Format agility / peer-id hardening** — Ed448 + SHA-384 support, content-hash-format
  negotiation, format-relative deletion markers and content paths, and identity loading
  that always re-derives the canonical peer id rather than trusting the file.
- **Standards check** against `AGENTS-STANDARD.md`: `AGENTS.md` / `CLAUDE.md` verified
  current (no drift).

## Next

1. Run the conformance + interop suites live against a current reference peer to confirm
   green at HEAD — cross-impl reports lag, so trust a live run, not a dated report.
2. Continue tracking upstream spec changes; fold landings in and prune confirmed-legacy
   paths as the spec settles.
