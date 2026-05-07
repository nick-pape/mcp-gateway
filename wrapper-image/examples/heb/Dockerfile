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

FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Non-root user. The Playwright base image uses /ms-playwright as its
# browser-binary cache (root-owned and shared system-wide), but the HEB
# session state goes into the user's HOME so a per-identity volume mount
# at /home/appuser/.texas-grocery-mcp persists it independently.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 2001 appuser

WORKDIR /app

# Wrapper deps (matches mcp.service.pape.house/wrapper-image/requirements.txt)
RUN pip install --no-cache-dir \
        "fastapi>=0.115,<1.0" \
        "uvicorn[standard]>=0.32,<1.0" \
        "httpx>=0.28,<1.0" \
        "authlib>=1.3,<2.0"

# texas-grocery-mcp + browser extra. Playwright Python is already in the
# base image; the [browser] extra pulls in the Python-side helpers.
RUN pip install --no-cache-dir "texas-grocery-mcp[browser]"

# The base entrypoint comes from wrapper-image/ (the build context).
COPY entrypoint.py /app/entrypoint.py
COPY examples/heb/bootstrap.py /app/bootstrap.py

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

# bootstrap.py persists the HEB creds, then execvp's into entrypoint.py.
# entrypoint.py spawns texas-grocery-mcp via $MCP_COMMAND.
ENTRYPOINT ["python", "/app/bootstrap.py"]
