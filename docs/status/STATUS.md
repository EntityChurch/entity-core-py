# entity-core-py — status

_Updated: 2026-08-05 · public: v0.8.0 (master)_

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

**Symmetric origination authority + the namespace flag day (2026-08-05).** The
`EXTENSION-SIGNALING` §6.5 (b) reciprocal grant is built **both-sided and assembled** —
the S5 packet's gate #3 assignment for this repo. The dialer mints the acceptor's mirror
of the §6.6 cap on a rendezvous establishment (the grant an inbound dialer would actually
receive, advertisement-filtered — Q2/Q2a, not the flat §4.4 floor), and — the half that
fails silently — the **dialer now serves the reach-back**: an inbound EXECUTE on a
connection we dialed was previously dropped as an orphan response, so the acceptor's
authority was real and reached no handler. Both halves are pinned live, and the
reach-back vector was verified to fail (by timeout) when the serving branch is disabled.

The same pass ran the re-diff the signaling handoff promised for "the day the corpus
lands", and found this client was on the **pre-flag-day side of the `system/nat/*` →
`system/signaling/*` rename**: the derivation hashes the literal type string, so every
rendezvous key differed from go's and rust's and **the peers could not have met at any
key** since 2026-08-02. The stage-bisect payload, the 18 live node tests, and the pinned
go-agreement witness all passed throughout — the node is mode-blind and the witness
predated the rename. Fixed; both cross-impl witnesses re-derived live from
`entity-core-go` @ `94b6583`.
See `HANDOFF-2026-08-05-reciprocal-grant-and-namespace-flag-day-python.md` — §4 carries
two carriage findings routed to arch.

**Signaling client (2026-07-30).** The `signaling` **client** landed on `dev` —
§2.2 key derivation, §3.1.1 pool selection, the §3 coordination messages with §3.1 blob
framing and the §3.2 read rules, and the three wrapped-surface operations, in
`entity_handlers/signaling/`. Built against Rust's go/py build brief; the server role is
deliberately out of scope (§1.2 makes it optional). **86 same-impl tests plus 24 live**
against real Rust nodes. See `HANDOFF-2026-07-30-signaling-client-stage1-python.md`.

The admission blocker that handoff filed against Rust — the shipped
`entity-signaling-node` seeded no capability policy, so a foreign peer got `403` on every
signaling op — is **closed** (Rust `9714f13`: `--open` / `--grant`, closed by default).
The owner-keypair workaround is deleted and the live suite now runs **as an ordinary
stranger**, which puts the admission model itself under test. Also landed since: go's
byte-identical §2.2 keys and §3.1.1 selections pinned here as assertions, and
`tests/interop/signaling_meet.py` — Python's driveable half of the cross-process go↔py
meet, green with Python on both sides. *(Those pinned key/selection values were
pre-flag-day on both sides and were superseded on 2026-08-05 — see above.)*

Earlier on the `v0.8.0` "Genesis" research-preview line: NETWORK Amendment 12 rungs 1–2
(the reactive liveness floor: `system/peer/status` writes + §5 keepalive) landed on
`dev` — see `HANDOFF-2026-07-15-network-rungs-1-2-python.md` for the cohort convergence
input. Next substantive work is the cross-impl convergence pass once a second impl
completes the floor, plus running the conformance + interop suites live against a current
reference peer (below). *(This section predates the 2026-07-2x continuation
STANDING-MODEL work now on `dev`; those handoffs are the current record for it.)*

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
- **The live go↔py meet** is the one open piece of the signaling gate: Python's side is
  built (`tests/interop/signaling_meet.py`, driveable by any language), Go's validator
  currently spawns both of its peers in-process.
  `HANDOFF-2026-07-30-signaling-client-stage1-python.md` §6. It is newly *meaningful*:
  before the 2026-08-05 rename it could not have succeeded.
- **Re-run the signaling interop suite against a live Rust node** post-rename, before any
  three-way-green claim — the keys moved.
- **The §7 punch is unbuilt here** (S5 packet gate #5), and there is no WebRTC substrate.
  §6.5 (b) is wired to `Peer.establish_via_rendezvous`, so the punch calls one existing
  site when it lands.
- ~~**Waiting on arch:** the signaling corpus is still uncommitted upstream~~ — **closed
  2026-08-05.** The corpus is committed (`EXTENSION-SIGNALING.md`,
  `PROPOSAL-CONNECTION-NODE.md`); the promised re-diff ran and found the namespace flag
  day (above). Two carriage findings routed back in the 2026-08-05 handoff §4.
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

- **NETWORK Amendment 12 rungs 1–2 (the liveness floor)** — `system/peer/status` writes
  (`connected` both ends on establish; `suspect`/`transport-error` at the direct-dispatch
  seam with the behavioral no-clobber guard; `disconnected`/`keepalive-miss` from the new
  §5 keepalive loop), `system/connection` dialer-side transitions, the §5.1 ping op, and
  the six §3.13/NETWORK type registrations. Anchor vector reproduced (11 new integration
  tests). Surfaced + fixed two latent defects: dead-connection dispatch waiting out the
  full 60 s request timeout, and `Peer.stop()` deadlocking on Python 3.12+ while a remote
  held an open connection.
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

## Next

1. Run the conformance + interop suites live against a current reference peer to confirm
   green at HEAD — cross-impl reports lag, so trust a live run, not a dated report.
2. Continue tracking upstream spec changes; fold landings in and prune confirmed-legacy
   paths as the spec settles.
