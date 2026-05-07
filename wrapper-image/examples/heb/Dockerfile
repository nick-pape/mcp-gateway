# syntax=docker/dockerfile:1.7
#
# heb-mcp-wrapper — texas-grocery-mcp (stdio) + Playwright + the wrapper base.
#
# texas-grocery-mcp uses Playwright/Chromium for HEB.com browser-auth
# (bot-detection-driven session refresh ~every 11 minutes), so we base on
# the Microsoft Playwright Python image rather than the slim wrapper base —
# this saves us reinstalling Chromium + system deps. The wrapper's
# entrypoint.py and requirements.txt are then copied in directly.
#
# Build:
#   docker build -t mcp.pape.house/heb-mcp-wrapper:0.1 -f examples/heb/Dockerfile ../..
#
# Or with the orchestrator's build context (whole wrapper-image dir as ctx):
#   docker build -t mcp.pape.house/heb-mcp-wrapper:0.1 ./examples/heb

FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Wrapper deps (matches requirements.txt in the parent dir)
RUN pip install --no-cache-dir \
    "fastapi>=0.115,<1.0" \
    "uvicorn[standard]>=0.32,<1.0" \
    "httpx>=0.28,<1.0" \
    "authlib>=1.3,<2.0"

# texas-grocery-mcp + browser deps. The [browser] extra pulls in playwright;
# Chromium itself is already provided by the base image.
RUN pip install --no-cache-dir "texas-grocery-mcp[browser]"

# Copy the wrapper entrypoint from the parent context. When building with
# the wrapper-image dir as context, this resolves to wrapper-image/entrypoint.py.
COPY entrypoint.py /app/entrypoint.py

EXPOSE 8080

# Default MCP_COMMAND for this image; orchestrator can still override via env.
ENV MCP_COMMAND="texas-grocery-mcp"

ENTRYPOINT ["python", "/app/entrypoint.py"]
