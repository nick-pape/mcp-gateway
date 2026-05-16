# syntax=docker/dockerfile:1.7
#
# email-mcp-proxy — the tool-name normalization layer between the hub
# and better-email-mcp. ~200 LoC fastapi + httpx forward proxy.
#
# Build context: this directory (mcp.service.pape.house/email-mcp-proxy/)
# Build:
#   docker build -t registry.pape.house/local/email-mcp-proxy:0.1 .
#   docker push registry.pape.house/local/email-mcp-proxy:0.1
#
# Runtime env (set in mcp.service.pape.house/docker-compose.yml):
#   EMAIL_MCP_URL          http://email-mcp:8080 (sibling container in same compose net)
#   LISTEN_PORT            8080 (internal; not exposed to host or Caddy)
#   SCHEMA_FILE            /app/tool-schemas.yaml (baked in by COPY below)
#   LOG_LEVEL              INFO
#
# This image does NOT need bao access — the hub-to-proxy auth uses the
# same `hub_bearer` value the hub fetches from bao via its
# bao_backed_bearer strategy. The proxy just forwards the inbound
# Authorization header through.

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tool-schemas.yaml proxy.py ./

EXPOSE 8080

# Same /health convention as wrapper-image. 200 once we can both reach
# email-mcp's well-known and load the schema file.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3); sys.exit(0 if r.status==200 else 1)" \
    || exit 1

ENTRYPOINT ["python", "/app/proxy.py"]
