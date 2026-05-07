# mcp-wrapper-base

Generic Authentik-fronted HTTPS-to-stdio bridge for MCP servers. Wraps any
stdio MCP child with:

- Authentik OIDC validation on every request (issuer + audience + signature + expiry, JWKS-cached)
- Streamable-HTTP transport at `/mcp`
- `/health` + `/ready` endpoints (unauthenticated)
- Per-spawn env injection — secrets flow from bao via the orchestrator into the child's env, never to disk inside the container

This image is the runtime for **container-orchestrated stdio MCPs** under the homelab MCP gateway. The orchestrator (`ContainerFanout` in `mcp_hub`) spawns one of these per `(mcp × identity)` on demand and federates the agent's JWT to it.

## Building the base

```bash
docker build -t mcp.pape.house/wrapper-base:0.1 .
```

## Deriving a per-MCP image

```dockerfile
# examples/heb/Dockerfile
FROM mcp.pape.house/wrapper-base:0.1
RUN pip install --no-cache-dir texas-grocery-mcp[browser]
ENV MCP_COMMAND="texas-grocery-mcp"
```

That's it. The base handles JWT, transport, and lifecycle. The derived image just needs to install the stdio MCP and tell the wrapper how to spawn it.

## Env-var contract

The orchestrator injects all of these at container spawn time. Manual `docker run` only matters for testing the image in isolation.

| Var | Required | Default | Description |
|---|---|---|---|
| `MCP_COMMAND` | yes | — | shlex-parsed command for the stdio child (e.g. `texas-grocery-mcp`) |
| `OIDC_ISSUER` | yes | — | `iss` claim value to validate (e.g. `https://auth.pape.house/`) |
| `OIDC_DISCOVERY_URL` | yes | — | OIDC discovery base, the wrapper fetches `<url>/.well-known/openid-configuration` and uses its `jwks_uri` |
| `OIDC_AUDIENCE` | yes | — | `aud` claim value to validate (e.g. `mcp-interactive`) — typically the per-identity audience |
| `LISTEN_PORT` | no | `8080` | HTTP port |
| `LOG_LEVEL` | no | `INFO` | Python logging level |
| `JWT_CLOCK_SKEW_S` | no | `30` | Allowed clock skew on JWT validation |
| `JWKS_CACHE_TTL_S` | no | `600` | JWKS refresh interval |

Plus any env the spawned stdio child reads (e.g. `HEB_DEFAULT_STORE`, `TECHNITIUM_API_KEY`, etc.). The orchestrator resolves these from bao at spawn time per the `secrets_to_env:` mapping in `policy.yaml`.

## Endpoints

- `POST /mcp` — Streamable-HTTP MCP. JWT-required. Forwards JSON-RPC bodies to the spawned stdio child line-by-line. Returns the matching response. For notifications (no `id`), returns `202 Accepted` empty.
- `GET /health` — unauthenticated; 200 if the stdio child is alive, 503 otherwise.
- `GET /ready` — unauthenticated; 200 once the child is alive **and** JWKS has been fetched at least once.

## Manual smoke test

```bash
docker run --rm -p 8080:8080 \
  -e OIDC_ISSUER=https://auth.pape.house/ \
  -e OIDC_DISCOVERY_URL=https://auth.pape.house/application/o/mcp-fanout-svc/ \
  -e OIDC_AUDIENCE=mcp-interactive \
  -e MCP_COMMAND="texas-grocery-mcp" \
  mcp.pape.house/heb-mcp-wrapper:0.1
```

Then from a host with a valid Authentik JWT:

```bash
curl -sS -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Design notes

- **Single stdio child per container, async-locked.** The MCP spec doesn't require multiplexed responses, so serializing simplifies the wrapper. If a future MCP genuinely needs concurrent calls, swap the lock for an id-correlation table.
- **No on-disk token storage.** All secrets enter via env. If a wrapped MCP requires session state beyond a token (e.g. HEB's Playwright cookies), that's handled per-MCP — the base image stays stateless.
- **JWKS prefetch at startup** so the first real call doesn't pay discovery latency. JWKS refresh is single-flight via the cache lock; concurrent calls during a refresh wait on it.
- **Server-pushed notifications dropped on v0.** If the stdio child sends a JSON-RPC message that doesn't match our outstanding `id`, we log and discard. Adding bidirectional support is a follow-up.

## Follow-ups (deliberately deferred)

- `POST /admin/rotate {env_var, value}` to update a child's env in-process and re-exec. For HEB specifically, the in-band `session_save_credentials` tool covers this; for other MCPs, the orchestrator can just kill + respawn the container with a new env.
- Id-correlated multiplexing if any wrapped MCP grows concurrent-call requirements.
- SSE-shaped responses if any wrapped MCP emits them (none today).
