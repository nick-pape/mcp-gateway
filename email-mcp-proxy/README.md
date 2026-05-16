# email-mcp-proxy

Tool-name normalization layer between the homelab MCP hub
(`mcp.pape.house`) and `better-email-mcp` running in the same compose
stack. Runs as a sibling container; not externally exposed.

## Why this exists

`better-email-mcp` exposes **7 composite tools** where read-vs-write is
determined by an `action` argument:

```
messages.action ∈ {search, read, mark_read, mark_unread, flag, unflag, move, archive, trash}
send.action     ∈ {new, reply, forward}
config.action   ∈ {status, setup_start, setup_reset, setup_complete, set, cache_clear}
folders.action  ∈ {list}
attachments.action ∈ {list, download}
config__open_relay (single op)
help (takes tool_name arg)
```

The hub's HITL policy globs on **tool names**, so it can't distinguish
`messages.action=search` (safe) from `messages.action=trash` (destructive).
Either every search hits push-approve (annoying), or nothing does and
agents can mass-trash mail without confirmation (dangerous).

This proxy rewrites `tools/list` responses to expose **23 granular
tools** (`email-mcp_messages_search`, `email-mcp_messages_trash`,
`email-mcp_send_new`, …) that the hub can policy independently. On
`tools/call`, it translates the granular name back into the upstream's
composite `{name, action}` shape before forwarding.

## Architecture

```
hub container ──http+Bearer──> email-mcp-proxy ──http+Bearer──> email-mcp
                                  :8080 (internal)                  :8080 (internal)
```

The proxy:
- Lives in the `mcp-pape-house` docker-compose stack as a sibling
- Listens on `:8080` on the compose default network only (no host port
  mapping, no Caddy block — only the hub container reaches it)
- Forwards the inbound `Authorization` header verbatim. The hub uses
  `bao_backed_bearer` pointing at `secret/services/email-mcp` field
  `hub_bearer`; the proxy doesn't touch bao itself
- Preserves `Mcp-Session-Id` round-trip; handles SSE responses
- On any `tools/list` response: substitutes the 7-tool composite list
  with the 23-tool granular list from `tool-schemas.yaml`. Unknown
  upstream tools fall through with a logged warning (likely upstream
  added a new tool — surfaces as a CI schema-drift test failure too)
- On any `tools/call` request: if `params.name` matches `<base>_<action>`
  where `<base>` ∈ {messages, send, config, folders, attachments},
  rewrites to `{name: <base>, arguments: {action: <action>, ...}}`
  before forwarding. Pass-through for names that don't match (e.g.
  `config__open_relay`, `help` — single-op tools forwarded as-is)

## Drift detection

`tool-schemas.yaml` is **hand-authored**, not derived at runtime.
Upstream Jules-agent churn would silently break a runtime derivation;
hand-authored schemas + a CI drift test (compare `tool-schemas.yaml` to
the live `tools/list` from a real `n24q02m/better-email-mcp` container)
surfaces upstream changes as a test failure, not a silent prod misbehavior.

When the drift test fails after an upstream rebase:
1. Inspect the new upstream `tools/list` shape
2. Update `tool-schemas.yaml` to cover any new actions
3. Re-pin the email-mcp image digest in the parent compose
4. Re-deploy

## Env vars

| Var | Default | Description |
|---|---|---|
| `EMAIL_MCP_URL` | `http://email-mcp:8080` | sibling container in compose net |
| `LISTEN_PORT` | `8080` | internal port |
| `SCHEMA_FILE` | `/app/tool-schemas.yaml` | baked in by Dockerfile |
| `LOG_LEVEL` | `INFO` | python logging level |
| `REQUEST_TIMEOUT_S` | `30` | upstream forward timeout |

## Build + push

```bash
docker build -t registry.pape.house/local/email-mcp-proxy:0.1 .
docker push registry.pape.house/local/email-mcp-proxy:0.1
```

## Endpoints

- `POST /mcp` — forwards Streamable HTTP MCP requests to email-mcp.
  Handles JSON-RPC + SSE responses transparently.
- `GET /health` — 200 if `tool-schemas.yaml` loaded + email-mcp's
  `/.well-known/oauth-authorization-server` returns 200. 503 otherwise.

## What the proxy deliberately does NOT do

- **Bearer minting / refresh**: lives in the bootstrap script (annual
  manual run) + bao. Proxy is stateless w.r.t. credentials.
- **JWT validation**: relies on docker network isolation + email-mcp's
  own bearer check. Adding it here would just duplicate email-mcp's
  validation.
- **Per-identity routing**: there's exactly one Outlook account
  behind this proxy. The accounts-fallback fork in better-email-mcp
  means any sub on any bearer sees the same disk-loaded accounts.
- **Rate limiting / retries**: hub-side audit + HITL already gate
  this. Add later if real-world misuse warrants it.

## Out of scope

- Multi-tenant email accounts (the bearer is single-user; would need
  per-identity bao paths + the upstream multi-tenancy code path
  re-enabled)
- Caching `tools/list` responses (cheap upstream call, no benefit)
- Modifying `tools/call` results (tool output stays raw — agents read
  the upstream's `untrusted_email_content` markers as intended)
