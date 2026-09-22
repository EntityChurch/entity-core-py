# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## What the version numbers here mean

**The number below is this package set's own release version. It is NOT the protocol
version.** Each entry names the protocol level it targets on its own `Protocol:` line —
out-of-band, per [ADR-0002], which chose 3-field SemVer per implementation precisely
because a single string cannot carry both *which spec level an implementation targets*
and *the implementation's own release* without conflating two different things.

So: `entity-core` **0.10.0** implements Entity Core Protocol **0.8.2**. Those are two
numbers about two subjects, and they are expected to disagree. They will drift further —
a Python-side refactor bumps the left number and not the right one; a spec revision we
already satisfy bumps the right and not the left.

At the `v0.8.0` Genesis release the two numbers coincided, because the package version
was simply set to the protocol version of the day. That was a starting condition, not a
scheme, and reading it as one is what this section exists to prevent.

All four workspace packages — `entity-core`, `entity-handlers`, `entity-sdk`,
`entity-cli` — carry **one shared version** and release together. They are one tier-ordered
tree developed and tested as a unit; a mixed installation is not a configuration we test,
so the inter-package dependency floors move with each release.

**The version number is not the contract.** Conformance is ([ADR-0012]) — what this
implementation actually agrees with the Rust and Go peers about, measured, at a named
commit. A conformance emission pins `impl_version` to the git sha for exactly this reason.
Treat a number below as a label for a release, not as a promise about behaviour.

**This is a 0.x line and not a 1.0 API commitment.** Under SemVer 0.x we bump the minor
for added surface or a breaking change, and the patch for fixes.

## [Unreleased]

Nothing yet. Development lands on `dev`; `master` carries the last release.

## [0.10.0] — 2026-09-20

_Protocol: Entity Core Protocol 0.8.2 (wire identifier `entity-core/1.0`, V7 §8.4)._

A minor bump, and it **is breaking**: this release changes which peers can complete a
handshake with this one, and which requests an existing capability authorizes. Nothing was
removed, renamed or re-signatured in the Python API of the four packages, and the CLI's verbs
and flags are unchanged — the breakage is entirely on the wire and in authorization.

*Breaking* is measured here against what a peer on the other end of a socket observes (the
advertised protocol identifier, the handshake sequence, and the `(status, code)` pairs a
refusal carries), what a minted capability grants, and the public Python API of `entity-core`,
`entity-handlers`, `entity-sdk` and `entity-cli`. Internal module layout, docstrings and
console rendering are outside it.

### Changed in ways that can break an existing caller

- **The advertised protocol version is `entity-core/1.0`, per V7 §8.4 — and the `protocols`
  intersection is now enforced (§4.5 / §4.7 row 1). Together these change who can connect.**
  This peer had advertised `entity-core/7.0` since the Genesis release: the specification's
  *title* version rather than the wire identifier §8.4 pins. It survived because §4.5's
  *"Intersection, must be non-empty"* had no implementer in any implementation — every peer
  carried the field on every hello and none read it, so a dead field could not diverge
  observably. A hello whose non-empty `protocols` set is disjoint from ours is now refused
  `400 incompatible_protocol` rather than completing a handshake with a peer that speaks no
  version we support. **A 0.9.0 peer of ours, which advertises `entity-core/7.0`, is
  therefore refused by a 0.10.0 peer of ours.** An omitted or empty list stays unconstrained
  (SA-PY-31). The identifier is a single constant, with a test pinning it to §8.4 and a gate
  against a second literal.
  *Earlier entries in this file describe the protocol as `entity-core/7.0`; they are left
  as written, because they record what was shipped.*
- **Requests an existing grant did not actually authorize are now refused.** Five enforcement
  points that the `resources` dimension was supposed to bind, and did not — a caller upgrading
  should re-read what its capabilities say before assuming the same calls still succeed:
  - Eight of `EXTENSION-REVISION`'s nineteen handler operations — `log`, `status`, `diff`,
    `fetch`, `fetch-entities`, `branch`, `tag`, `push` — called no permission check at all,
    and took their prefix from the caller's own params rather than from `resource.targets[0]`.
    Four of them write.
  - §6.3's per-entry listing filter was absent on all three bulk readers, so a grant's
    `resources.exclude` carved nothing out of a listing, an `extract` or a `snapshot`. With
    `limit` set, pagination ran over the *unfiltered* set, which is worse than a no-op.
  - `check_resource_scope` and `check_path_permission` each had a concrete arm and no pattern
    arm, so re-spelling a target as a pattern stepped past an exclude — including, through
    `EXTENSION-SUBSCRIPTION` §2.3, subscribing with `include_payload` to a path the grant
    excludes, which pushes the body on every write for the life of the subscription.
  - An unmatchable `exclude` carved out nothing instead of everything. It now excludes
    everything at evaluation, and a capability carrying one is invalid at mint, at delegate
    and at chain verification (`400 invalid_path`).
  - `resource.targets` narrowed to the empty set is no longer indistinguishable from an
    absent `resource` (§3.3). A continuation whose stored resource was self-excluded used to
    advance as though it had named none — at `tree:snapshot`, the whole tree — and a
    cross-peer dispatch dropped the field where the in-process one refused. The same request
    now gets the same answer through either door.
- **An id-scope dimension is no longer canonicalized as a path, which widens some grants.**
  `operations: {include: ["*"], exclude: ["*/apply"]}` authorized *no* operation at all: the
  §5.4 path sentinel was applied to `operations`, `peers` and `type_scope`, denying the whole
  dimension on a property unrelated to what it excludes. Those grants now authorize what they
  say. Also withdrawn: the refusal of a contradicting `scope.type`, which obliged reading the
  field whose absence is the safety property.
- **An unallocated `key_type` is refused at `hello`**, which §4.5 names as the canonical
  earliest reject point. The peer previously refused only at `authenticate`, so a caller that
  read the refusal off the second step now sees it on the first.
- **V7 §4.7 row 10 is split into its two failures, in both connection states.** A second
  `hello` mid-handshake is a state conflict — `409 connection_sequence_error`, consistent
  with row 9's `connection_already_established`. An
  unknown connect operation is `400 invalid_request`: nothing is out of *order* when the
  operation name exists in no state. Applied to the operations this peer actually implements:
  a pre-handshake `ping` (§5.1 keepalive, which this peer serves) was `400 invalid_request`
  and is now `409 connection_sequence_error`; an unknown operation on an **established**
  connection was `409 connection_already_established` and is now `400 invalid_request`. Both
  boundaries classify from one set.
- **Pre-admission framing refusals carry the cause's own code (§4.11).** An oversize frame is
  `413 payload_too_large` where one `else` had given every framing error `400 invalid_request`
  — `payload_too_large` had zero occurrences in the tree. A truncated frame now gets a coded
  refusal instead of a bare close logged as a clean hangup. A payload that decodes to
  something other than a map is refused rather than raising out of the framing layer. Whether
  the stream survives the refusal is now a property of the cause rather than a blanket close.

### Fixed

- **A handshake refusal at the `hello` step now carries the remote's `(status, code)`.**
  Both the TCP and HTTP dialers read `peer_id`/`nonce` straight out of the hello response
  and reported *"Missing peer_id or nonce"* for what was actually a coded refusal, dropping
  the remote's answer. Four §4.7 rows refuse at hello, so this affected all of them. The
  `authenticate` step already did this correctly.

## [0.9.0] — 2026-08-23

_Protocol: Entity Core Protocol 0.8.2 (`entity-core/7.0`)._

The first release since `v0.8.0` (2026-06-21) — 180 commits. Still a **research
preview**: built clean-room from the specification, with no shared code with the Rust
and Go implementations, so its job is to prove the spec is complete enough to build a
compatible peer from scratch and to serve as an interop peer for the other two.

The minor bump is SemVer for **added surface**: the workspace gained a fourth package.

### Added

- **`entity-sdk` — a new package, the L1 operations surface.** `EntityClient`
  (get / put / put_cas / list / remove / has / watch / unwatch / `execute`), the §12
  error hierarchy, path resolution, change events, the Level-0 `store` surface, and the
  L3 extension wrappers (`subscription`, `query`, `registry`, `revision`, `handlers`).
  The §16.1 MUST list closes. Tier 2 by declaration as well as by convention — it depends
  on `entity-core` alone and reaches handlers by dispatching to pattern strings rather
  than importing them, so the tier boundary holds by construction.
- **Registry** — REGISTRY v1.19: §4.1b's classifier, §4.3's pin-delta and
  set/get-resolver-config, §6a.9.2/§6a.9.3 (pending-binding, the by-request pointer,
  deny), and peer-issued registration.
- **Compute** — the v3.24 collection primitives, v3.25's four corners, v3.26's
  contained-error form, the C-8 closure-result positions, and §7.1's recursive walk
  shared by both walkers.
- **Signaling** — §4.5.1 `reflection_endpoints`, published verbatim and absent when empty.
- **Revision / auto-version** — §5.3's handler sentinel (rejected at write, honoured at
  merge), and §2.4 excludes reaching the trie on both paths that emit a version.
- **`entity-core start --max-lifetime`** (defaulted from `$ENTITY_PEER_MAX_LIFETIME`) — a
  debug peer reaps itself.

### Fixed

- **Two capability fail-opens** — CAP-6a ingest and the §5.2 `peers` dimension on the
  dispatch path that never ran it.
- **The `system/*` handler reservation was never enforced** — registering at
  `system/tree` returned 200.
- **SIGTERM is honoured.** As PID 1 under `ENTRYPOINT ["entity-core"]` the kernel
  discards an unhandled SIGTERM, so the peer was discarding every stop request and
  `podman stop` paid its full timeout and SIGKILLed, every time. A `serve_forever()`
  crash is now re-raised rather than parked by `asyncio.wait` and silently exited 0.
- **The interop suite hung rather than failed** whenever a foreign container held the
  port — five hand-rolled socket probes replaced by one shared liveness probe that asks
  for a handshake and a remote peer id, bounded by a timeout.
- Numerous spec-conformance corrections across registry, revision, type, authz,
  discovery, substitute, inbox, continuation, history and liveness — each pinned to the
  spec row it answers. See the commit log.

### Changed

- `entity_core.__version__` is now read from installed package metadata instead of being
  a second hand-maintained literal. It had drifted to `0.1.0` while `pyproject.toml` said
  `0.8.0`, and nothing caught it because nothing consumed it. There is now one source of
  truth for the version, and it is `pyproject.toml`.
- `docs/status/STATUS.md` moved to `docs/STATUS.md` ([ADR-0031]); the published rolling
  log is unchanged apart from its path.

## [0.8.0] — 2026-06-21

_Protocol: Entity Core Protocol 0.8.0 (`entity-core/7.0`)._

- Initial public research-preview release. Tagged `v0.8.0` at `ecf0ee4`.
