# Entity Core Python

Python implementation of the Entity Core Protocol for interoperability testing with the Rust implementation.

## Overview

Entity Core is a distributed peer-to-peer protocol based on content-addressed entities. This Python implementation serves as both a reference implementation and a validation tool to ensure the protocol specification is clear and complete enough for interoperable implementations.

## Build and test

The canonical build needs only **`make` + `podman`** on the host — no Python,
no `uv`, no other toolchain. A pinned container image carries the exact Python
and `uv` versions, so a fresh clone builds identically anywhere:

```bash
make build      # build the runtime image (entity-core CLI)
make test       # run the full test suite in the dev image
make lint        # run ruff in the dev image
```

This is the supported, reproducible path; see [`CANONICAL-DOCS.toml`](CANONICAL-DOCS.toml)
and the `Makefile` for details.

## Local development (optional)

If you prefer to iterate directly on the host, install Python 3.11–3.13 and
[uv](https://docs.astral.sh/uv/), then:

```bash
# Install all workspace packages and dev dependencies (versions pinned by uv.lock)
uv sync

# Run the test suite
uv run pytest

# List available identities
uv run entity-core list-identities
```

### What to watch out for

- **`uv sync` verifies SHA256 hashes** from `uv.lock` for every downloaded package. If hashes don't match, the install will fail — this is expected and is a supply chain safety check. Do not bypass it.
- **`uv.lock` must be committed.** It pins exact versions and SHA256 hashes for every dependency. Do not add it to `.gitignore`.
- **Identity files must exist before starting a peer.** The CLI reads Ed25519 keys from `~/.entity/identities/` (see [Identity Management](#identity-management) below). Running `entity-core start` without an identity will fail.
- **The workspace has internal dependencies.** The three packages depend on each other (`entity-cli` -> `entity-handlers` -> `entity-core`), and `uv sync` installs them all in editable mode. Do not install them individually with pip.

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
# From the Rust entity-core repo
cargo run -p entity-cli -- identity create my-new-peer
```

The generated files in `~/.entity/identities/` are then usable by both implementations.

## Project Structure

This project is a uv workspace with three packages:

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
│   └── entity-cli/             # CLI application
│       └── src/entity_cli/
│
├── tests/
│   ├── unit/                   # Fast, deterministic unit tests
│   ├── integration/            # Protocol integration tests
│   └── interop/                # Cross-implementation tests (require Rust peer)
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

# Run interop tests (requires a Rust peer listening on 127.0.0.1:9000)
uv run pytest tests/interop/
```

## Cross-Implementation Testing

Both Python and Rust implementations validate each other and the protocol specification:

```bash
# Terminal 1: Start Rust peer
cd ../entity-core  # Rust implementation
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

## License

Licensed under the Apache License, Version 2.0 (Apache-2.0).

---

## Supporting the project

This project is developed in the open. If it's useful to you, the best support is
to use it, report issues, and contribute back — see
[CONTRIBUTING.md](CONTRIBUTING.md).

To support the work directly, see the project's funding page.
