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

So: `entity-core` **0.9.0** implements Entity Core Protocol **0.8.2**. Those are two
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

Development lands on `dev`; `master` carries the last release.

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
