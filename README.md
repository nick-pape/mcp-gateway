# mcp.pape.house

Homelab MCP (Model Context Protocol) gateway. Single docker container,
in-process Fanout module, Authentik OIDC auth, ntfy HITL push approvals,
bao-injected per-identity secrets.

See:

- [`architecture.md`](./architecture.md) — design contract
- [`landscape.md`](./landscape.md) — why we're building rather than adopting
- [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) — phased build plan

## Status

Phase 9 complete (Dockerfile + compose). End-to-end deploy in Phase 11.

## Quickstart (dev — Windows or Linux)

```bash
uv sync
uv run pytest -q
uv run ruff check src/
uv run mypy --strict src/
```

## Container build (local syntax check)

```bash
docker compose config           # validate compose schema
docker compose build            # full multi-stage build (~5 min cold)
```

The build pulls the Technitium MCP fork from
`https://github.com/nick-pape/technitium-mcp-secure` `main` by default;
override with `--build-arg TECHNITIUM_REF=<branch>`.

## First-time LXC deploy (Phase 11)

On a freshly-created Docker LXC (`mcp.service.pape.house`):

1. **Bind-mount config dir:**
   ```bash
   sudo mkdir -p /etc/mcp-pape-house
   sudo cp policy.example.yaml /etc/mcp-pape-house/policy.yaml
   sudo chown root:root /etc/mcp-pape-house/policy.yaml
   sudo chmod 0644 /etc/mcp-pape-house/policy.yaml
   ```
   Edit `/etc/mcp-pape-house/policy.yaml` to fill in the real
   Authentik issuer URL, audiences, and secret paths.

2. **Place secrets** (mode 0400 each):
   ```bash
   sudo install -m 0400 -o root -g root /dev/stdin /etc/mcp-pape-house/fanout_jwt < your-jwt
   sudo install -m 0400 -o root -g root /dev/stdin /etc/mcp-pape-house/ntfy_publish_token < your-token
   ```
   `fanout_jwt` is the Authentik machine token for the
   `mcp-fanout-svc` OAuth client (used by the hub to log in to bao).
   `ntfy_publish_token` is the ntfy bearer token for publishing to the
   `mcp-hitl-approvals` topic.

3. **bao bootstrap** — see `scripts/bootstrap-bao.sh` (Phase 10) which
   enables the JWT auth method, configures it against Authentik, and
   creates per-(mcp, identity) policies + roles.

4. **Caddy site block** — use the `caddy-add-block` skill for
   `mcp.pape.house → mcp.service.pape.house:8443` (forward_auth NOT
   needed; the hub validates JWTs itself).

5. **Deploy via Portainer** — Repository (Git) stack pointing at
   `mcp.service.pape.house/docker-compose.yml` on `main`.

6. **Smoke test the 10 verification steps** in
   [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) § Verification.

## Authentik setup (manual UI clicks)

Per identity that should reach the gateway, create one OAuth2/OpenID
Provider in Authentik:

- **Provider name:** `mcp-<identity>` (e.g. `mcp-ironclaw`)
- **Audiences:** `mcp-<identity>` (matches `audience_prefix` + suffix)
- **Subject mode:** depends on whether the consumer is a human (use
  username) or a service account (client credentials)
- Issue a token; for service accounts, save it on the LXC at
  `/etc/mcp-pape-house/clients/<identity>.token` (consumed by the
  agent process, not by the gateway)

For the hub itself (`mcp-fanout-svc`):
- Provider name: `mcp-fanout-svc`
- Audience: `mcp-fanout-svc`
- The token Authentik issues for this client is what goes into
  `/etc/mcp-pape-house/fanout_jwt` (used to log in to bao).
