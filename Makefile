# Entity Core Python — make + podman build convention.
#
# Host needs ONLY `make` + `podman` (no host Python/uv). The multistage
# Dockerfile installs the locked uv workspace; the `dev` stage carries the
# test deps and runs pytest.
IMAGE := entity-core-py

# ============================================================================
# Podman resource caps — per-container ceilings so a build/run can't take the
# host down. Tune the COMMITTED defaults for THIS project; override per-machine
# WITHOUT editing this file via env vars or an untracked caps.local.mk.
#   Precedence (highest first):  env var  >  caps.local.mk  >  defaults below
#   CAP_SWAP == CAP_MEM  =>  zero swap: OOM-killed cleanly at the cap instead of
#   thrashing the host into a freeze.
#
# Sized for THIS project: the heaviest target is `make test` (a from-scratch
# dev image build + the full pytest suite). Measured peaks on podman 5.8 —
# build phase ≈ 1.3 GB (uv sync + bytecode compile), pytest run ≈ 175 MB.
# CAP_MEM 2g = measured peak + headroom; a smaller box that can't meet it
# fails cleanly at the cap instead of thrashing. Raise via caps.local.mk.
# ============================================================================
-include caps.local.mk          # untracked per-machine overrides (gitignored)

CAP_MEM           ?= 2g         # hard memory ceiling per container (peak ≈1.3g + headroom)
CAP_SWAP          ?= $(CAP_MEM) # keep == CAP_MEM (no swap); raise only deliberately
CAP_PIDS          ?= 2048       # max procs/threads (RUN only) — stops fork bombs
CAP_CPUS          ?= 4          # CPU cores at runtime (RUN only; fractional ok)
CAP_CGROUP_PARENT ?=            # optional host slice to nest under, e.g. dev-heavy.slice

_cap_cgp := $(if $(strip $(CAP_CGROUP_PARENT)),--cgroup-parent=$(CAP_CGROUP_PARENT),)

# podman BUILD accepts --memory/--memory-swap/--cgroup-parent (NOT --cpus/--pids-limit)
PODMAN_BUILD_CAPS := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) $(_cap_cgp)
# podman RUN accepts the full set
PODMAN_RUN_CAPS   := --memory=$(CAP_MEM) --memory-swap=$(CAP_SWAP) \
                     --pids-limit=$(CAP_PIDS) --cpus=$(CAP_CPUS) $(_cap_cgp)

.PHONY: help build image test lint fmt check clean

.DEFAULT_GOAL := help

# ADR-0019 Tier-1 verbs: help build test lint fmt check clean. Every recipe runs
# inside the multistage image (runtime or dev target); host needs only make + podman.
help:
	@echo "entity-core-py — make + podman (host needs only make + podman)"
	@echo
	@echo "  build    build the runtime image (the entity-core CLI; alias: image)"
	@echo "  test     build the dev image, then run pytest in-container"
	@echo "  lint     ruff check . in the dev image (read-only)"
	@echo "  fmt      ruff format . in the dev image (writes)"
	@echo "  check    lint + test (the green gate)"
	@echo "  clean    remove the runtime + dev images"

# Builds the runtime image: `uv sync --frozen --no-dev --all-packages` compiles
# the workspace into /opt/venv. `--target runtime` is REQUIRED — the Dockerfile's
# `dev` stage comes last, so an untargeted build would tag the dev image
# (ENTRYPOINT `uv run`) instead of the `entity-core` CLI. Green on a bare box.
build:
	podman build $(PODMAN_BUILD_CAPS) --target runtime -t $(IMAGE) .

# `image` alias keeps the older name working; `build` is the Tier-1 entry point.
image: build

# Dev image (workspace + dev deps + tests/), then run the suite in-container.
test:
	podman build $(PODMAN_BUILD_CAPS) --target dev -t $(IMAGE)-dev .
	podman run --rm $(PODMAN_RUN_CAPS) $(IMAGE)-dev pytest

lint:
	podman build $(PODMAN_BUILD_CAPS) --target dev -t $(IMAGE)-dev .
	podman run --rm $(PODMAN_RUN_CAPS) $(IMAGE)-dev ruff check .

# Tier-1 fmt = autoformat (writes). Mount the host tree at /src so ruff format's
# rewrites land on the working copy — without the bind mount it would format the
# source baked into the ephemeral dev image and `--rm` would discard the changes
# (same mount pattern as the go/rust siblings' fmt).
fmt:
	podman build $(PODMAN_BUILD_CAPS) --target dev -t $(IMAGE)-dev .
	podman run --rm $(PODMAN_RUN_CAPS) -v $(CURDIR):/src:Z -w /src $(IMAGE)-dev ruff format .

# Tier-1 check = the green gate (lint + test).
check: lint test

# Tier-1 clean = remove the build artifacts (the runtime + dev images).
clean:
	-podman rmi $(IMAGE) $(IMAGE)-dev
