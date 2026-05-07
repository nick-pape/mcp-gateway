# syntax=docker/dockerfile:1.7
#
# mcp-wrapper-base — generic Authentik-fronted HTTPS-to-stdio bridge.
#
# Wraps a stdio MCP child with Streamable-HTTP transport and OIDC JWT
# validation. The orchestrator (mcp-hub's ContainerFanout) spawns one of
# these per (mcp × identity) on demand, injects per-spawn env (tokens,
# default-store IDs, etc.), and federates to the resulting :8080/mcp
# endpoint with the agent's JWT in the Authorization header.
#
# Per-MCP images derive from this and pip-install the actual stdio MCP,
# e.g.:
#
#   FROM mcp.pape.house/wrapper-base:0.1
#   RUN pip install --no-cache-dir texas-grocery-mcp[browser]
#   ENV MCP_COMMAND="texas-grocery-mcp"
#
# See README.md for the full env-var contract.

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.py .

EXPOSE 8080

# Healthcheck via /health (unauthenticated, returns 200 once the stdio
# child is alive). Uses the stdlib http.client to avoid pulling curl in.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3); sys.exit(0 if r.status==200 else 1)" \
    || exit 1

ENTRYPOINT ["python", "/app/entrypoint.py"]
