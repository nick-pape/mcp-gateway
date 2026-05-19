# syntax=docker/dockerfile:1.7
#
# mcp.pape.house — homelab MCP gateway
#
# Multi-stage build:
#   1. technitium-build: clone the user's fork + npm build
#   2. hub-build: uv-resolve deps + install hub package as a non-editable
#      wheel into a venv that we can COPY wholesale into runtime
#   3. runtime: python:3.13-slim + Node 22 + gosu, no caps in compose,
#      hub runs as root inside the container but cap_drop: [ALL] +
#      cap_add: [SETUID, SETGID] limits root to setuid (for spawning
#      stdio children as distinct UIDs)
#
# IMPORTANT: per-identity stdio children spawn as UIDs 1001-1099 via
# gosu. Those users are pre-created in the runtime stage so the hub
# never needs useradd at runtime.

# ============================================================================
# Stage 1 — Technitium MCP (TypeScript -> dist/)
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
# Stage 1b — Vikunja MCP (npm-installed binary tree)
# ============================================================================
# @democratize-technology/vikunja-mcp is npm-published; we install the
# exact version into a self-contained tree at /pkg, then COPY that tree
# into the runtime stage at /app/mcps/vikunja/. The package's
# `dist/index.js` is the stdio entrypoint; the per-identity child runs
# our run.sh wrapper which slurps the secret file and exec's it.
FROM node:22-alpine AS vikunja-install

ARG VIKUNJA_MCP_VERSION=0.2.0

WORKDIR /pkg
# Use `npm install --omit=dev` against a generated package.json so we
# get a deterministic node_modules tree, no devDependencies, and a real
# tree at /pkg/node_modules/@democratize-technology/vikunja-mcp/.
RUN echo '{"dependencies":{"@democratize-technology/vikunja-mcp":"'${VIKUNJA_MCP_VERSION}'"}}' > package.json \
 && npm install --omit=dev --no-audit --no-fund


# ============================================================================
# Stage 2 — Hub Python package (uv-managed)
# ============================================================================
FROM python:3.13-slim AS hub-build

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

# uv as the dependency manager; same one we use locally
RUN pip install --no-cache-dir uv==0.11.9

WORKDIR /app

# Copy lockfile + project metadata first for cache friendliness
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

# `--no-editable` produces a regular install (no .pth), so the resulting
# venv is portable to /app/.venv in the runtime stage.
# `--no-dev` excludes pytest/ruff/mypy.
# `--frozen` requires uv.lock to be in sync (errors otherwise).
RUN uv sync --frozen --no-dev --no-editable


# ============================================================================
# Stage 3 — Runtime
# ============================================================================
FROM python:3.13-slim AS runtime

# Tini reaps the stdio children Fanout spawns. gosu drops privileges to
# the per-identity UIDs the policy assigns. nodejs runs the Technitium
# (and any future Node-based) MCPs.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg gosu tini; \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*

# Pre-create UIDs 1001-1099 to match policy.example.yaml's uid_base
# range. Each identity in policy.yaml gets a UID in this range
# (uid_base + per-MCP uid_offset). The hub runs as root and uses
# `gosu <uid>` to spawn each child; cap_drop:[ALL]+cap_add:[SETUID,
# SETGID] in compose limits what root in this container can actually do.
RUN set -eux; \
    for i in $(seq 1001 1099); do \
        useradd -u "$i" -M -s /usr/sbin/nologin "mcp$i"; \
    done

# Hub Python venv — full /app/.venv copy from hub-build stage.
COPY --from=hub-build /app/.venv /app/.venv

# Technitium MCP build output. Future MCPs land at /app/mcps/<name>/...
RUN mkdir -p /app/mcps/technitium /app/mcps/vikunja
COPY --from=technitium-build /src/dist /app/mcps/technitium/dist
COPY --from=technitium-build /src/node_modules /app/mcps/technitium/node_modules

# Vikunja MCP — npm-installed tree from stage 1b. run.sh wraps the
# upstream binary to translate the hub's VIKUNJA_API_TOKEN_FILE
# convention into the upstream's VIKUNJA_API_TOKEN env. proxy.js sits
# between run.sh and the upstream stdio child, exploding composite
# subcommand tools into granular per-subcommand tools so the hub HITL
# policy can glob read-vs-write. See mcp.service.pape.house/vikunja/README.md.
COPY --from=vikunja-install /pkg/node_modules /app/mcps/vikunja/node_modules
COPY vikunja/run.sh vikunja/proxy.js /app/mcps/vikunja/
RUN chmod +x /app/mcps/vikunja/run.sh

# Entrypoint
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Runtime env
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCP_HUB_CONFIG=/etc/mcp-pape-house/policy.yaml \
    MCP_HUB_RUNTIME_DIR=/run/mcp-tokens

EXPOSE 8443

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["python", "-m", "mcp_hub"]
