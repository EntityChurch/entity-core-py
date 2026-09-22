# syntax=docker/dockerfile:1.7
ARG PYTHON_VERSION=3.12
# Pinned uv release, copied in below rather than floating on the
# astral-sh/uv:pythonX.Y-bookworm-slim tag (which tracks uv's latest release
# and drifted onto a uv 0.9.30 that fails `uv sync --frozen --no-editable`
# for this workspace — hatchling's build-isolation venv came up missing
# `packaging`, `ModuleNotFoundError: No module named 'packaging.version'` at
# entity-handlers' wheel build. uv 0.10.12 builds this workspace cleanly;
# pinning keeps the build reproducible instead of re-drifting on the next
# upstream uv release.
ARG UV_VERSION=0.10.12

# ---------- builder ----------
# Installs the workspace into /opt/venv. Used as the base for both runtime and dev.
# Same base image as the runtime stage (python:${PYTHON_VERSION}-slim-bookworm)
# so the venv built here and the interpreter it runs under at runtime match
# exactly — no ABI drift between a separate uv-vendor image and this one.
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder
ARG UV_VERSION
COPY --from=ghcr.io/astral-sh/uv:${UV_VERSION} /uv /uvx /usr/local/bin/

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Workspace manifests + sources. The root pyproject has no top-level deps —
# the workspace members are only referenced from the `dev` group, so without
# --all-packages the runtime sync would install nothing.
COPY pyproject.toml uv.lock README.md ./
COPY packages/ packages/

# --no-editable: install workspace packages as real wheels into the venv so
# the runtime stage doesn't need /app/packages on disk (uv's default is
# editable installs that .pth-link back to the source tree).
RUN --mount=type=cache,id=entity-core-py-uv,target=/root/.cache/uv \
    uv sync --frozen --no-dev --all-packages --no-editable

# ---------- runtime ----------
# Slim image with just the venv + entity-core CLI as the entrypoint.
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/entity

RUN groupadd --system --gid 1000 entity && \
    useradd  --system --uid 1000 --gid entity --home-dir /home/entity --shell /bin/bash entity && \
    mkdir -p /home/entity/.entity/identities && \
    chown -R entity:entity /home/entity

COPY --from=builder /opt/venv /opt/venv

USER entity
WORKDIR /home/entity

EXPOSE 9001
ENTRYPOINT ["entity-core"]
CMD ["--help"]

# ---------- dev ----------
# Same venv + dev deps + tests/, for running pytest, ruff, mypy in CI or locally.
FROM builder AS dev

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY tests/ tests/
# The wire-conformance corpus the suite reads at import time. Without it the
# dev image's pytest collection aborts (FileNotFoundError). The type-v1.1 and
# content-v3.5 corpora live under `tests/conformance/` and ride in with
# `tests/` above — they are NOT under `docs/`, despite what this comment used
# to claim.
COPY test-vectors/ test-vectors/
# `scripts/` is not tooling here: `tests/unit/test_cross_impl_pins_are_real.py`
# loads `scripts/fetch_published_fixture.py` as a module to read its pins, and
# that row carries no `skipif` on purpose — "it needs no Go, no network, and no
# fixture" is its whole argument. Omitting this COPY made it a hard collection
# ERROR in `make test` while `uv run pytest` on a host checkout stayed green,
# so the canonical entry point was red and the convenience one was not.
COPY scripts/ scripts/

RUN --mount=type=cache,id=entity-core-py-uv,target=/root/.cache/uv \
    uv sync --frozen

WORKDIR /app
ENTRYPOINT ["uv", "run"]
CMD ["pytest"]
