# Entity Core Python

**A clean-room Python implementation of the Entity Core Protocol, built to test whether the
specification is good enough to build a peer from.**

## Overview

Entity Core is a peer-to-peer protocol built on content-addressed entities. This
implementation is one of **three independent, ground-up peers** — alongside a Go and a Rust
one — and its purpose is not merely to exist: it is written from the specification text
alone, so that **every place the text is unclear shows up as a bug here first**. When that
happens the gap is logged and routed upstream rather than patched over locally.

If you want to see the output of that, read
[`docs/SPEC-AMBIGUITIES.md`](docs/SPEC-AMBIGUITIES.md) — sixty-seven gaps and contradictions
found while implementing, each with what we did in the meantime and how it was ruled.

It implements the wire protocol end to end — content-addressed entities, ECF/CBOR encoding,
Ed25519 identity, capability delegation, the handler/peer runtime — plus an SDK and a CLI.

**Status: v0.9.0, a research preview.** 4,816 tests, cross-implementation converged. Not a
1.0 API commitment. The release version is deliberately *not* the protocol version — see the
top of [`CHANGELOG.md`](CHANGELOG.md) for why.

## Build and test

The canonical build needs only **`make` + `podman`** on the host — no Python,
no `uv`, no other toolchain. A pinned container image carries the exact Python
and `uv` versions, so a fresh clone builds identically anywhere:

```bash
make build      # build the runtime image (the entity-core CLI)
make test       # run the full test suite in the dev image
make lint       # run ruff in the dev image (read-only)
make check      # lint + test — the green gate
make help       # every target
```

**Measured on a warm image, 2026-09-17: `4758 passed, 58 skipped in 120.96s`** — about 2m09s
wall. A cold run adds the image build, a few minutes more. **The 58 skips are `tests/interop/`,
which need a peer from another implementation running**; that is the expected state and the
one place a skip here is not a failure.

This is the supported, reproducible path. `make test` is what a change has to keep green.

## Local development (optional)

Faster to iterate on, but it needs a toolchain. Install
[uv](https://docs.astral.sh/uv/) and **Python 3.12** — `.python-version` pins 3.12 and `uv`
will refuse to run without it:

```bash
# Install all workspace packages and dev dependencies (versions pinned by uv.lock)
uv sync

# Run the test suite
uv run pytest

# List available identities
uv run entity-core list-identities
```

> ⚠ **`No interpreter found for Python 3.12`** means exactly that and is not a repo problem.
> Either `uv python install 3.12`, or drive an existing venv directly with
> `.venv/bin/python -m pytest`. `make test` is unaffected — the container carries 3.12.

### What to watch out for

- **`uv sync` verifies SHA256 hashes** from `uv.lock` for every downloaded package. If hashes don't match, the install will fail — this is expected and is a supply chain safety check. Do not bypass it.
- **`uv.lock` must be committed.** It pins exact versions and SHA256 hashes for every dependency. Do not add it to `.gitignore`.
- **Identity files must exist before starting a peer.** The CLI reads Ed25519 keys from `~/.entity/identities/` (see [Identity Management](#identity-management) below). Running `entity-core start` without an identity will fail.
- **The workspace has internal dependencies.** The four packages sit in a strict tier order — `entity-core` (0) -> `entity-handlers` (1) -> `entity-sdk` (2) -> `entity-cli` (presentation) — and imports only ever point downward, enforced by `tests/unit/test_package_layering.py`. The declared edges are narrower than the tiers: `entity-sdk` depends on `entity-core` **alone** (it reaches handlers by dispatching to pattern strings, never by importing them), while `entity-cli` depends on all three. `uv sync` installs them all in editable mode. Do not install them individually with pip.

## Usage

The most common commands are below; the full command/flag reference (CLI +
`make` targets) is in [`docs/CLI.md`](docs/CLI.md).

```bash
# Start a peer (server mode)
uv run entity-core start --listen 127.0.0.1:9001 -i my-identity

# Connect to another peer (client mode)
uv run entity-core connect 127.0.0.1:9000 --status

# List available identities
uv run entity-core list-identities
```

### Start a Peer

```bash
entity-core start [--listen ADDRESS] [--identity NAME] [--admin NAME...] [--debug]

Options:
  --listen ADDRESS    Address to listen on (default: 127.0.0.1:9001)
  -i, --identity NAME Identity from ~/.entity/identities/ (default: 'default')
  -a, --admin NAME    Identity name(s) to grant admin access (can be repeated)
  --debug             Grant full access to ALL peers (insecure, for testing only)
```

| Mode | Behavior |
|------|----------|
| Default (no flags) | No capabilities granted — peers can connect but can't operate |
| `--admin NAME` | Only specified admin peers receive capabilities |
| `--debug` | ALL peers receive full capabilities (insecure, for testing) |

### Connect to a Peer

```bash
entity-core connect ADDRESS [--identity NAME] [--status]

Arguments:
  ADDRESS             Peer address as host:port

Options:
  -i, --identity NAME Identity to use (default: 'framework-admin')
  --status            Request peer status after connecting
```

## Identity Management

Identities are Ed25519 keypairs stored in `~/.entity/identities/`. Each identity has three files:

```
~/.entity/identities/
├── my-peer            # Private key (PEM-like: header, base64 seed, footer)
├── my-peer.json       # Metadata: {"peer_id": "...", "public_key": "..."}
└── my-peer.pub        # Public key (text format)
```

This file layout is shared with the Rust implementation for cross-peer compatibility. Identities created by either implementation work with both.

Identities are currently created using the Rust CLI:

```bash
# From the Rust implementation, checked out beside this repo
cd ../entity-core-rust
cargo run -p entity-cli -- identity create my-new-peer
```

The generated files in `~/.entity/identities/` are then usable by both implementations.

## Project Structure

This project is a uv workspace with four packages:

```
entity-core-py/
├── pyproject.toml              # Workspace root
├── Makefile                    # make + podman build/test entry points
├── Dockerfile                  # Pinned toolchain image (Python + uv)
├── uv.lock                     # Dependency lock file with SHA256 hashes
│
├── packages/
│   ├── entity-core/            # Core protocol library
│   │   └── src/entity_core/
│   │       ├── crypto/         # Ed25519 identity, signing, hashing
│   │       ├── protocol/       # Entity, Envelope, messages, framing
│   │       ├── capability/     # Token, checking, delegation
│   │       ├── storage/        # ContentStore, EntityTree, EmitPathway
│   │       ├── types/          # Type definitions, registry
│   │       ├── handlers/       # Registry, context, bootstrap
│   │       ├── peer/           # Peer, PeerBuilder, Connection
│   │       └── utils/          # ECF encoding
│   │
│   ├── entity-handlers/        # Standard handlers (tree, system, storage, query)
│   │   └── src/entity_handlers/
│   │
│   ├── entity-sdk/             # L1 operations + L3 extension wrappers
│   │   └── src/entity_sdk/     #   client, paths, events, store, query,
│   │                           #   subscription, registry, revision, handlers
│   │
│   └── entity-cli/             # CLI application (presentation tier)
│       └── src/entity_cli/
│
├── tests/
│   ├── unit/                   # Fast, deterministic unit tests
│   ├── integration/            # Protocol integration tests
│   └── interop/                # Cross-impl tests (need a live Go or Rust peer;
│                               #   they skip cleanly without one)
│
└── examples/                   # Standalone interop test scripts
```

## Dependencies

### Runtime (entity-core)

| Package | Purpose |
|---------|---------|
| `base58` | Base58 encoding for peer IDs |
| `cbor2` | CBOR encoding (ECF wire format) |
| `cryptography` | Ed25519 signing and key management |

### Dev only

`pytest`, `pytest-asyncio`, `mypy`, `ruff`, `jsonschema` — no runtime impact.

## Testing

The suite covers unit, integration, and interop scenarios. Run it in-container
with `make test`, or directly on the host with `uv`:

```bash
# Run all tests
uv run pytest

# Verbose output
uv run pytest -v

# Run a specific test file
uv run pytest tests/unit/test_capability.py

# Run interop tests (need a live sibling peer; see Cross-Implementation Testing)
uv run pytest tests/interop/
```

## Cross-Implementation Testing

The three implementations validate each other and the specification. To drive this peer
against the Rust one:

```bash
# Terminal 1: Start Rust peer
cd ../entity-core-rust
cargo run -p entity-cli -- peer start test-peer -l 127.0.0.1:9000

# Terminal 2: Start Python peer
uv run entity-core start --listen 127.0.0.1:9001

# Terminal 3: Run interop tests
uv run pytest tests/interop/ -v
```

## Protocol Overview

Entity Core Protocol v7 defines these core message types:

| Message | Purpose |
|---------|---------|
| `system/protocol/connect/hello` | Connection initiation, nonce exchange |
| `system/protocol/connect/authenticate` | Cryptographic identity proof |
| `system/capability/grant` | Authorization token exchange |
| `system/protocol/execute` | Universal operation request |
| `system/protocol/execute/response` | Operation result |
| `system/protocol/error` | Protocol-level error |

### Connection Flow

```
Client                              Server
  │                                   │
  ├──── HELLO ────────────────────────>│
  │<─────────────────────── HELLO ────┤
  ├──── AUTHENTICATE ─────────────────>│
  │<───────────────── AUTHENTICATE ───┤
  │<───────────── CAPABILITY_GRANT ───┤
  │                                   │
  ├──── EXECUTE ──────────────────────>│
  │<─────────────── EXECUTE_RESPONSE ──┤
```

## Working on this repo

| you want | read |
|---|---|
| to make a change, as a person or an agent | [`AGENTS.md`](AGENTS.md) — the orientation file, read first |
| what the project is doing right now | [`docs/STATUS.md`](docs/STATUS.md) |
| the CLI and `make` reference | [`docs/CLI.md`](docs/CLI.md) |
| how handlers, the registry and dispatch fit together | [`docs/HANDLER-ARCHITECTURE.md`](docs/HANDLER-ARCHITECTURE.md) |
| how this peer is validated against the others | [`docs/VALIDATING.md`](docs/VALIDATING.md) |
| where the spec is unclear, and how it was ruled | [`docs/SPEC-AMBIGUITIES.md`](docs/SPEC-AMBIGUITIES.md) |
| what we satisfy in-process rather than at the wire | [`docs/CONFORMANCE-EXCLUSIONS.md`](docs/CONFORMANCE-EXCLUSIONS.md) |
| everything this project learned the hard way | [`docs/agents/memory/INDEX.md`](docs/agents/memory/INDEX.md) |

**Two things not to touch**, because they are not this repo's to define:

- **The specification.** It lives upstream, in the sibling `entity-core-protocol` and
  `entity-system-architecture` repos. This repo implements it. A gap goes in
  `docs/SPEC-AMBIGUITIES.md` and is routed upstream — never settled locally.
- **`packages/entity-core/src/entity_core/handlers/`** is the registry, context and bootstrap
  only. Standard handlers belong in `entity-handlers`.

**The real gate for anything protocol-facing is not this repo's test suite** — it is the
cross-implementation validator, which drives this peer from an independent implementation. A
local suite checks our constants against our constants; several real defects here were
invisible to it and obvious to that. See [`docs/VALIDATING.md`](docs/VALIDATING.md).

## License

Licensed under the Apache License, Version 2.0 (Apache-2.0).

---

## Supporting the project

This project is developed in the open. If it's useful to you, the best support is
to use it, report issues, and contribute back — see
[CONTRIBUTING.md](CONTRIBUTING.md).

To support the work directly, see the project's funding page.
