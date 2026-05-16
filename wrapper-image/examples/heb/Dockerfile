# syntax=docker/dockerfile:1.7
#
# heb-mcp-wrapper — texas-grocery-mcp + Playwright + the wrapper-base.
#
# texas-grocery-mcp uses Playwright/Chromium for HEB.com browser auth
# (bot-detection-driven session refresh ~every 11 min). We base on the
# Microsoft Playwright Python image because Chromium + system deps are
# pre-installed there — saves us reinstalling them and keeps Chromium's
# version in lockstep with the playwright Python package.
#
# Build context is the wrapper-image/ directory. The base entrypoint.py
# is copied from there; the HEB-specific bootstrap.py runs first to
# persist orchestrator-injected HEB_EMAIL / HEB_PASSWORD into the MCP's
# credential store, then execs into the wrapper entrypoint.
#
# Build (from mcp.service.pape.house/wrapper-image/):
#   docker build -t mcp-pape-house/heb-mcp-wrapper:0.1 \
#                -f examples/heb/Dockerfile .
#
# At runtime the orchestrator injects:
#   HEB_EMAIL, HEB_PASSWORD       — bao-resolved per identity
#   HEB_DEFAULT_STORE             — store_id from policy.yaml env
#   OIDC_ISSUER, OIDC_DISCOVERY_URL, OIDC_AUDIENCE — for JWT validation
#   MCP_COMMAND="texas-grocery-mcp" — what entrypoint.py spawns
# Plus a per-identity Docker named volume mounted at
#   /home/appuser/.texas-grocery-mcp
# (auth.json + .credentials + .credentials.key persist across spawns).

FROM mcr.microsoft.com/playwright/python:v1.59.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Non-root user. The Playwright base image uses /ms-playwright as its
# browser-binary cache (root-owned and shared system-wide), but the HEB
# session state goes into the user's HOME so a per-identity volume mount
# at /home/appuser/.texas-grocery-mcp persists it independently.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 2001 appuser

# Install xvfb (virtual X server) — texas-grocery-mcp's
# session_refresh launches Chromium in headed mode for the
# saved-credentials login flow even when headless=True is passed.
# Wrapping the stdio child with xvfb-run gives Playwright a DISPLAY
# without rendering anything.
RUN apt-get update \
 && apt-get install -y --no-install-recommends xvfb \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Wrapper deps (matches mcp.service.pape.house/wrapper-image/requirements.txt)
RUN pip install --no-cache-dir \
        "fastapi>=0.115,<1.0" \
        "uvicorn[standard]>=0.32,<1.0" \
        "httpx>=0.28,<1.0" \
        "authlib>=1.3,<2.0"

# texas-grocery-mcp + browser extra. Pinned to nick-pape/main @ a4c0d33
# (our fork of mgwalkerjr95/texas-grocery-mcp). The fork adds:
#   - in-process self-heal for HEB's GraphQL persisted-query rotations
#     via passive Playwright page-load sweep (clients/hash_rediscover.py)
#   - ACTIVE mutation-hash discovery for SelectPickupFulfillment via a
#     two-click Playwright flow against heb.com (header "Change Store"
#     -> first store in popup -> mutation fires, network handler snags
#     the new hash). Unblocks store_change + cart_add when the
#     mutation hash rotates, without manual override.
# Both paths persist the override to
# /home/appuser/.texas-grocery-mcp/hash_overrides.json (volume-backed)
# so cold spawns load overrides from cache.
#
# First call after a rotation pays ~10-15s discovery; subsequent calls
# are fast. The fork ships with upstream's now-stale `cartEstimated` /
# `cartItemV2` defaults intentionally — the first heb_cart_* call IS
# the smoke test for the self-heal loop. If that ever regresses,
# revert this pin to `git+https://github.com/sleepgood/texas-grocery-mcp.git@6f797a8`
# (which has the post-rotation hashes baked in but no self-heal).
#
# Playwright Python is already in the base image; the [browser] extra
# pulls in the Python-side helpers.
RUN pip install --no-cache-dir \
    "texas-grocery-mcp[browser] @ git+https://github.com/nick-pape/texas-grocery-mcp.git@a4c0d33"

# The base entrypoint comes from wrapper-image/ (the build context).
COPY entrypoint.py /app/entrypoint.py
COPY examples/heb/bootstrap.py /app/bootstrap.py

# Pre-create the texas-grocery-mcp state dir with appuser ownership BEFORE
# the volume mount lands here. Docker's named-volume behavior is: when the
# target dir exists in the image, its ownership/permissions are copied into
# the freshly-created volume. Without this, the volume comes up as root:root
# and the appuser-running bootstrap can't write .credentials.key.
RUN mkdir -p /home/appuser/.texas-grocery-mcp \
 && chown -R appuser:appuser /app /home/appuser

USER appuser

EXPOSE 8080

# bootstrap.py persists the HEB creds, then execvp's into entrypoint.py.
# entrypoint.py spawns texas-grocery-mcp via $MCP_COMMAND.
ENTRYPOINT ["python", "/app/bootstrap.py"]
