# mcp-gateway

A multi-tenant **MCP (Model Context Protocol) gateway**: one process that sits in
front of many MCP servers and adds, per calling identity, the things individual
MCP servers don't: **authentication**, **per-tool authorization**,
**human-in-the-loop (HITL) approvals**, **audit logging**, and **per-identity
secret injection + process isolation**.

It's deliberately infrastructure-agnostic — secrets, inbound auth, HITL
approvals, and token refresh are all **pluggable** behind small interfaces, so
you can run it against your stack (Vault/OpenBao, Keycloak/Authentik/Auth0, ntfy/
Slack, …) or with zero external infrastructure.

> Status: pre-1.0. The core (`src/mcp_hub`, `src/mcp_fanout`) is stable; the
> public-readiness work is tracked in the [issues](https://github.com/nick-pape/mcp-gateway/issues).

## How it works

- **Fanout** — the hub registers every backend MCP's tools under a `<mcp>_`
  prefix and routes each call to a per-identity worker:
  - **stdio** — spawns the MCP as a child process, one per identity, each as a
    distinct UID (via `gosu`), with its secret injected as a `0400` file.
  - **http** — forwards to an HTTP MCP with a per-identity auth header.
  - **container** — spawns a wrapper container per identity on the Docker socket.
- **Middleware chain** — identity (JWT) → tool curation (per-identity allowlist)
  → HITL gate → audit.

See [`architecture.md`](./architecture.md) for the full design.

## Pluggable adapters

Each axis resolves an implementation by name from `policy.yaml`; third-party
adapters install side-by-side and are selected with a dotted path
(`name: my_pkg.MyClass`) — no fork required. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

| Axis | Built-ins | Entry-point group |
|---|---|---|
| Secrets | `env`, `file` (SOPS/age-friendly), `bao` (Vault/OpenBao) | `mcp_hub.secret_backends` |
| Approvals (HITL) | `auto`, `reject`, `ntfy` | `mcp_hub.approvers` |
| Token refresh | `authentik_client_credentials`, `file` sink | `mcp_hub.token_sources` / `token_sinks` |
| Inbound auth | OIDC JWT (any JWKS issuer), **static-token** (no IdP), **trusted-proxy** | `auth.mode` in `policy.yaml` |

**Zero-infra mode:** `auth: {mode: static_token}` + `secret_backend: {name: file}`
(or `env`) + `approver: {name: auto}` needs no IdP / Vault / ntfy — see
[`policy.example.minimal.yaml`](./policy.example.minimal.yaml) for a complete
no-infrastructure quickstart you can `docker compose up` and `curl`.

## Run it

The hub is published as a generic image: `ghcr.io/nick-pape/mcp-gateway`.

```bash
# 1. Put a policy.yaml in ./config (start from policy.example.minimal.yaml)
mkdir -p config && cp policy.example.minimal.yaml config/policy.yaml

# 2. Bring it up (see docker-compose.yml for the example service)
docker compose up -d
curl -fsS http://localhost:8443/health   # -> {"status":"ok"}
```

Config lives at `/etc/mcp-gateway/policy.yaml` by default (override with the
`MCP_HUB_CONFIG` env var). Backends that bake in specific MCP servers layer them
onto this base image with a thin `FROM ghcr.io/nick-pape/mcp-gateway` overlay.

## Configuration

- [`policy.example.minimal.yaml`](./policy.example.minimal.yaml) — smallest
  working config (no external infra).
- [`policy.example.yaml`](./policy.example.yaml) — full feature reference
  (OIDC auth, bao secrets, ntfy HITL, token refresh, per-identity allowlists).

## Development

Uses [uv](https://docs.astral.sh/uv/), Python 3.13.

```bash
uv sync
uv run pytest -m "not linux_only"   # full unit suite (linux_only needs gosu+root)
uv run ruff check .
uv run mypy
```

CI runs ruff + mypy `--strict` + pytest and builds/publishes the image.

## Security

This is an authenticating gateway for privileged tool calls — please report
vulnerabilities privately (see [`SECURITY.md`](./SECURITY.md)).

## License

[MIT](./LICENSE).
