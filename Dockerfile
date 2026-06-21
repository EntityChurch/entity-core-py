# syntax=docker/dockerfile:1.7
ARG PYTHON_VERSION=3.12

# ---------- builder ----------
# Installs the workspace into /opt/venv. Used as the base for both runtime and dev.
FROM ghcr.io/astral-sh/uv:python${PYTHON_VERSION}-bookworm-slim AS builder

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
RUN --mount=type=cache,target=/root/.cache/uv \
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
# Conformance corpora + test vectors the suite reads at import time. Without
# these the dev image's pytest collection aborts (FileNotFoundError).
COPY docs/ docs/
COPY test-vectors/ test-vectors/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

WORKDIR /app
ENTRYPOINT ["uv", "run"]
CMD ["pytest"]
