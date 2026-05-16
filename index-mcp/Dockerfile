# index-mcp — FastMCP sidecar that exposes search() over the indexer's
# Qdrant collections. One tool today: `search(query, top_k, collection?)`.
# Embeds the query via LiteLLM/llama-swap, queries Qdrant, returns hits.

FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
RUN uv pip install --system --no-cache -r pyproject.toml

COPY src/ /app/src/

WORKDIR /app/src
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python", "server.py"]
