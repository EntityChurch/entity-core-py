# Command-line tools

This repo ships two tool surfaces: the **`make` targets** (build/test, the
canonical entry points) and the **`entity-core` CLI** (run and talk to a peer).
Every command supports `--help`; this page is the map.

## `make` targets

The canonical build needs only `make` + `podman` on the host — no Python, no
`uv`, no other toolchain. A pinned container image (`Dockerfile`) carries the
exact Python and `uv` versions.

| Target | What it does |
|--------|--------------|
| `make build` (alias `make image`) | Build the runtime image (`entity-core` CLI as entrypoint). |
| `make test` | Build the dev image and run the full `pytest` suite in-container. |
| `make lint` | Build the dev image and run `ruff check .` in-container. |

```bash
make build      # produces localhost/entity-core-py:latest
make test
```

## `entity-core` CLI

The CLI is the package entry point (`entity-core ...`). In the container:
`podman run --rm localhost/entity-core-py <command> ...`. For host use, install
the package (`uv sync`) and run `uv run entity-core <command> ...`.

### Run a peer — `start`

```bash
entity-core start [--listen ADDR] [-i NAME] [--admin NAME ...] [--debug]
```

| Flag | Meaning |
|------|---------|
| `--listen ADDR` | Address to bind (default `127.0.0.1:9001`). |
| `-i, --identity NAME` | Identity from `~/.entity/identities/` (default `default`). |
| `-a, --admin NAME` | Grant admin access to the named identity (repeatable). |
| `--debug` | Grant full access to **all** connecting peers — insecure; testing only. |
| `--open-access` | Open-access posture (no per-peer grants required). |
| `--key-type {ed25519,ed448}` | Crypto backend for the peer keypair (default `ed25519`). |
| `--hash-type` | Default `content_hash_format` the peer authors with. |
| `--validate` | Enable the GUIDE-CONFORMANCE §7a conformance test handlers. |
| `--files DIR` | Serve a local directory via the local-files domain. |
| `--serve-namespace`, `--serve-closure-root`, `--serve-scope-whole-store`, `--publish-root` | Serving-mode scope selection (see GUIDE-SERVING-MODE). |
| `--http-addr`, `--http-path`, `--http-base-url`, `--http-poll-addr`, `--http-poll-prefix` | HTTP / HTTP-poll transport endpoints. |
| `--discovery-announce`, `--discovery-profile` | mDNS discovery announcement. |

No flags = peers can connect but receive no capabilities; `--admin` grants only
the named peers; `--debug` grants everyone (testing).

### Inspect the entity tree

All take a `target` path/URI argument and operate against the local peer.

| Command | What it does |
|---------|--------------|
| `ls TARGET` | List entities at a path. |
| `tree TARGET` | Show the full entity tree. |
| `cat TARGET` | Display entity content, type-aware. |
| `info TARGET` | Show entity metadata (type, hash, refs). |
| `get TARGET` | Get the raw entity as CBOR diagnostic notation. |
| `put TARGET -t TYPE -d DATA` | Store an entity at a path. |
| `rm TARGET` | Remove a tree entry. |

### Operations and connections

| Command | What it does |
|---------|--------------|
| `exec TARGET OPERATION [PARAMS]` | Execute an arbitrary operation against a path. |
| `connect ADDR [--status] [--get URI] [--execute ...]` | Connect to a remote peer (advanced/diagnostic). |
| `list-identities` | List identities available under `~/.entity/identities/`. |

### Registry curation (operator)

| Command | What it does |
|---------|--------------|
| `registry-issue-binding NAME TARGET_PEER_ID [--transports ...] [--ttl N]` | Issue a curated peer→endpoint binding. |
| `registry-set-policy TARGET {open,allowlist,manual} [--allowlist ...] [--name-constraints ...] [--default-ttl N]` | Set the registry issuer policy. |
| `registry-register NAME [--transports ...] [--ttl N]` | Submit a live registration request. |

### Conformance

| Command | What it does |
|---------|--------------|
| `compare-types ...` | Compare type definitions across peers. |
| `wire-conformance emit ...` | ECF wire-conformance harness (emit-canonical mode). |

## Peer validator

A separate cross-implementation conformance harness drives a running peer
against the spec. See [`VALIDATING.md`](VALIDATING.md) for what it checks and
how to run it.
