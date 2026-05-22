# syntax=docker/dockerfile:1.7
#
# mcp-gateway — the generic, MCP-agnostic hub image.
#
# Builds ONLY the hub: a Python venv, tini, gosu, the per-identity UID range,
# and the entrypoint. No Node, no MCP servers baked in — bring your own MCPs via
# policy `command:` arrays (stdio), sibling containers (http), or container
# transport. Published to ghcr.io/nick-pape/mcp-gateway by
# .github/workflows/image.yml.
#
# A deployment that bakes in specific MCPs layers them on top with a thin
# `FROM ghcr.io/nick-pape/mcp-gateway` overlay (see the private ai-pape-house
# deployment for this homelab's Technitium/Vikunja overlay).
#
# Per-identity stdio children spawn as UIDs UID_BASE..UID_BASE+UID_COUNT-1 via
# gosu; those users are pre-created here so the hub never needs useradd at runtime.

# ============================================================================
# Hub Python package (uv-managed)
# ============================================================================
FROM python:3.13-slim AS hub-build

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

RUN pip install --no-cache-dir uv==0.11.9

WORKDIR /app

# Copy lockfile + project metadata first for cache friendliness.
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

# `--no-editable` -> portable venv; `--no-dev` excludes pytest/ruff/mypy;
# `--frozen` requires uv.lock to be in sync.
RUN uv sync --frozen --no-dev --no-editable


# ============================================================================
# Runtime — the generic hub image
# ============================================================================
FROM python:3.13-slim AS runtime

# tini reaps stdio children; gosu drops to the per-identity UIDs; curl is the
# healthcheck. No Node — the generic hub is MCP-agnostic.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gosu tini; \
    rm -rf /var/lib/apt/lists/*

# Pre-create the per-identity UID range (uid_base + per-MCP uid_offset in
# policy). Configurable so deployments aren't locked to 1001-1099.
ARG UID_BASE=1001
ARG UID_COUNT=99
RUN set -eux; \
    for i in $(seq "${UID_BASE}" "$((UID_BASE + UID_COUNT - 1))"); do \
        useradd -u "$i" -M -s /usr/sbin/nologin "mcp$i"; \
    done

# Hub Python venv — full /app/.venv copy from the hub-build stage.
COPY --from=hub-build /app/.venv /app/.venv

# Entrypoint
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_HUB_CONFIG=/etc/mcp-pape-house/policy.yaml \
    MCP_HUB_RUNTIME_DIR=/run/mcp-tokens

EXPOSE 8443

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "mcp_hub"]
