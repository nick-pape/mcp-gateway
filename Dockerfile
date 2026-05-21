# syntax=docker/dockerfile:1.7
#
# mcp-gateway — MCP gateway image
#
# Two publishable runtime targets from one build:
#
#   target=runtime          GENERIC hub image. Python + tini + gosu + the
#                           per-identity UID range + the hub venv. No Node,
#                           no baked MCPs. This is what CI publishes to
#                           ghcr.io/nick-pape/mcp-gateway. Bring your own MCPs
#                           via policy `command:` arrays (stdio) or sibling
#                           containers (http/container transport).
#
#   target=runtime-homelab  This homelab's deployment: FROM runtime, plus
#                           Node 22 + the Technitium and Vikunja MCPs baked
#                           in. This is the LAST/default stage, so an
#                           un-targeted `docker build` (and the current
#                           Portainer `build: {context: .}`) keeps producing
#                           exactly today's image. It will move out to a
#                           private deployment overlay (FROM the published
#                           generic image) in ai-pape-house — see GH #14/#15.
#
# Build stages:
#   1.  technitium-build  clone the fork + npm build           (homelab)
#   1b. vikunja-install   npm-install the upstream MCP tree     (homelab)
#   2.  hub-build         uv-resolve deps + install hub wheel   (generic)
#   3.  runtime           generic hub image                     (generic)
#   4.  runtime-homelab   runtime + Node + the baked MCPs       (homelab)
#
# Per-identity stdio children spawn as UIDs UID_BASE..UID_BASE+UID_COUNT-1
# via gosu; those users are pre-created in the runtime stage so the hub never
# needs useradd at runtime.

# ============================================================================
# Stage 1 — Technitium MCP (TypeScript -> dist/)   [homelab]
# ============================================================================
FROM node:22-alpine AS technitium-build

ARG TECHNITIUM_REPO=https://github.com/nick-pape/technitium-mcp-secure.git
ARG TECHNITIUM_REF=main

WORKDIR /src
RUN apk add --no-cache git
RUN git clone --depth 1 --branch ${TECHNITIUM_REF} ${TECHNITIUM_REPO} /src \
 && npm ci \
 && npm run build


# ============================================================================
# Stage 1b — Vikunja MCP (npm-installed binary tree)   [homelab]
# ============================================================================
FROM node:22-alpine AS vikunja-install

ARG VIKUNJA_MCP_VERSION=0.2.0

WORKDIR /pkg
RUN echo '{"dependencies":{"@democratize-technology/vikunja-mcp":"'${VIKUNJA_MCP_VERSION}'"}}' > package.json \
 && npm install --omit=dev --no-audit --no-fund


# ============================================================================
# Stage 2 — Hub Python package (uv-managed)   [generic]
# ============================================================================
FROM python:3.13-slim AS hub-build

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

RUN pip install --no-cache-dir uv==0.11.9

WORKDIR /app

# Copy lockfile + project metadata first for cache friendliness
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

# `--no-editable` -> portable venv; `--no-dev` excludes pytest/ruff/mypy;
# `--frozen` requires uv.lock to be in sync.
RUN uv sync --frozen --no-dev --no-editable


# ============================================================================
# Stage 3 — runtime  (GENERIC hub image -> GHCR)
# ============================================================================
FROM python:3.13-slim AS runtime

# tini reaps stdio children; gosu drops to the per-identity UIDs; curl is the
# healthcheck. No Node here — the generic hub is MCP-agnostic.
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

# Hub Python venv — full /app/.venv copy from hub-build stage.
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


# ============================================================================
# Stage 4 — runtime-homelab  (DEFAULT: runtime + Node + baked MCPs)  [homelab]
# ============================================================================
# Last stage, so an un-targeted build (and the current Portainer build) keeps
# producing today's image. Slated to move to a private deployment overlay in
# ai-pape-house that does `FROM ghcr.io/nick-pape/mcp-gateway:<tag>` (GH #14/#15).
FROM runtime AS runtime-homelab

# Node 22 runs the Technitium (and Vikunja proxy) MCPs.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends gnupg; \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/mcps/technitium /app/mcps/vikunja

# Technitium MCP build output.
COPY --from=technitium-build /src/dist /app/mcps/technitium/dist
COPY --from=technitium-build /src/node_modules /app/mcps/technitium/node_modules

# Vikunja MCP — npm tree + the run.sh/proxy.js tool-normalization wrapper.
# See vikunja/README.md.
COPY --from=vikunja-install /pkg/node_modules /app/mcps/vikunja/node_modules
COPY vikunja/run.sh vikunja/proxy.js /app/mcps/vikunja/
RUN chmod +x /app/mcps/vikunja/run.sh
