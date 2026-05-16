"""FastMCP search server. One tool today: `search(query, top_k, collection?)`.

Embeds the query via the same llama-swap endpoint the indexer uses
(qwen3-embed-0.6b-cpu, 1024-dim cosine), runs a Qdrant nearest-neighbour
search, and returns each hit with title + doc_url + text + score.

Federated through mcp.pape.house via the `index` MCP block in
mcp.service.pape.house/policy.yaml. Auth: none (hub→index internal-only
on the compose default network).
"""

from __future__ import annotations

import httpx
from fastmcp import FastMCP
from qdrant_client import QdrantClient

import settings


mcp = FastMCP(name="index-mcp")

# Long-lived clients
_qdrant = QdrantClient(
    url=settings.QDRANT_URL,
    api_key=settings.QDRANT_API_KEY,
    prefer_grpc=False,
)
_embed_client = httpx.AsyncClient(
    base_url=settings.EMBED_API_BASE,
    timeout=30.0,
)


async def _embed(text: str) -> list[float]:
    resp = await _embed_client.post(
        "/embeddings",
        json={
            "model": settings.EMBED_MODEL,
            "input": text,
            "encoding_format": "float",
        },
    )
    resp.raise_for_status()
    return resp.json()["data"][0]["embedding"]


@mcp.tool()
async def search(
    query: str,
    top_k: int = 10,
    collection: str | None = None,
) -> list[dict]:
    """Semantic search across the homelab index.

    Args:
        query: Free-text natural-language query.
        top_k: Max number of hits to return (default 10).
        collection: Qdrant collection name (default: `outline`). Other
            collections will land as we add more sources (email, paperless,
            code, etc.).

    Returns:
        List of hit dicts with `title`, `doc_url`, `text`, `score`,
        `chunk_start`, `chunk_end`, `doc_id`.
    """
    coll = collection or settings.DEFAULT_COLLECTION
    query_vec = await _embed(query)
    # qdrant-client>=1.16 deprecated `.search()` in favor of `.query_points()`.
    response = _qdrant.query_points(
        collection_name=coll,
        query=query_vec,
        limit=max(1, min(top_k, 50)),
        with_payload=True,
    )
    return [
        {
            "score": float(h.score),
            "title": h.payload.get("title"),
            "doc_url": h.payload.get("doc_url"),
            "text": h.payload.get("text"),
            "doc_id": h.payload.get("doc_id"),
            "chunk_start": h.payload.get("chunk_start"),
            "chunk_end": h.payload.get("chunk_end"),
            "updated_at": h.payload.get("updated_at"),
        }
        for h in response.points
    ]


if __name__ == "__main__":
    # stateless_http=True so the hub's stateless HttpFanout (no
    # Mcp-Session-Id round-trip) speaks to us cleanly. Same pattern as
    # mcp-searxng-enhanced. Without this the hub's tools/list call hits a
    # "Bad Request: Missing session ID" from FastMCP's default stateful
    # StreamableHTTPServerTransport.
    mcp.run(
        transport="http",
        host=settings.LISTEN_HOST,
        port=settings.LISTEN_PORT,
        stateless_http=True,
    )
