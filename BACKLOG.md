# mcp.pape.house — backlog

Deferred items for v1.5+ surfaced during the Phase 11 deploy. Listed
here so they don't get lost. Not blocking; the gateway works
end-to-end without any of these.

## Architectural / feature

### MCP-client OAuth at the gateway
Currently agents must pre-mint JWTs via `client_credentials` against
Authentik (works for Claude Code, n8n, scripts, custom claws). Real MCP
clients like Copilot expect to **do the OAuth flow themselves** when
they register the MCP — they want to redirect to an authorization
endpoint and walk through user consent.

Design: the gateway exposes an `/oauth/authorize` + `/oauth/token`
proxy that delegates to Authentik. From the MCP client's perspective,
`mcp.pape.house` IS the OAuth provider; from Authentik's perspective,
the gateway is a confidential client doing on-behalf-of. The user
approves the connection in Authentik (real auth screen), and the MCP
client gets back a JWT scoped to that user's identity.

Benefits:
- Connect Copilot and have it OAuth into a service account or the
  user's own account
- Per-connection JWTs become user-scoped (not just service-scoped),
  so audit shows the human behind the call
- Standard MCP-spec OAuth flow; no custom client_credentials wiring

Probably ~150 LoC of additional middleware/routes plus an Authentik
client config that allows authz_code grant.

### JWT auto-refresh (v1.5)
Currently the fanout JWT on disk is a 15-min Authentik token (or 7d
once the user bumps validity). When it expires the hub's bao login
fails. Two options to fix:

- **In-process refresher** in the hub: background asyncio task hits
  Authentik client_credentials every N min and writes the JWT atomically
  to `/etc/mcp-pape-house/fanout_jwt`. Hub already has httpx and the
  client_secret would be added as a docker secret.
- **Long-lived JWT (7d–30d)** in Authentik: simpler, but the disk file
  becomes a long-lived bearer.

Recommend in-process refresher; it's clean and matches the threat
model goal of "no long-lived secrets at rest."

### Per-Technitium-user OIDC
Right now `claude-code-dev` calls Technitium with a shared admin token.
Upstream audit shows "the MCP made the change," not "ironclaw via
Claude Code made the change." Two paths:
- Multiple Technitium API users, each with a per-identity token in bao
- Technitium OIDC integration (newer Technitium supports it) → JWTs
  issued by Authentik flow through to upstream

Path 2 is the correct architectural move; defer until we have multiple
identities actively writing.

### Stack via Portainer GitOps
Currently deployed via `docker compose up -d` directly on CT 120.
Portainer sees it as "Unmanaged." Migrate to Repository (Git) stack so
updates flow from `git push`. See § "GitOps stack migration" below.

### Portainer OIDC for containers.mcp.pape.house
Mirror docker.pape.house's pattern. Authentik provider for
`portainer-mcp-containers`, Caddy block, configure Portainer OAuth via
its API.

## Security hardening

### bao LXC SSH separation
Root key (`/root/.vault-token`) is on the bao LXC's disk and reachable
by anyone with root SSH (which is anyone with the proxmox key). Lock
this down:
- Separate SSH key + password for the bao LXC, NOT shared with the
  general Proxmox key
- Or move the root token off-disk (encrypted with a passphrase prompt
  on bao service start)
- Or seal the root token in a smart-card / TPM

### Proxmox firewall for `*.service.pape.house:PORT`
Today, anyone on the LAN can hit `mcp.service.pape.house:8443` and
talk to the hub directly, bypassing Caddy's TLS + future Caddy-side
auth. Lock down via Proxmox datacenter firewall: only Caddy LXC IP
allowed to reach service-port IPs. Per-CT rules also possible.

### Static IP via pct
Documented bug: setting `var_net=dhcp` + Technitium reservation gives
the CT a dynamic-pool IP first; only after the lease expires (24h
default) does it migrate to the reservation. Workaround: `pct set
<id> -net0 ...,ip=172.16.1.X/22` to force static. Update create-ct
skill to do this automatically when add-service-ct is invoked.

## Operational polish

### LXC template for "Docker host with Portainer + OAuth"
Setting up a fresh Docker-in-LXC + Portainer + Authentik OIDC takes
~15 manual steps and three rounds of "oh right, that env var" (see
`TRUSTED_ORIGINS` memory). Worth scripting:
- Proxmox CT bring-up (already a skill: `add-service-ct`)
- Docker install (community script today; could be a baked template)
- Portainer recreate with the right env vars (`TRUSTED_ORIGINS`,
  optionally the `PORTAINER_OAUTH_*` family for fully-env-driven setup)
- Authentik provider+app create (mirroring this session's pattern)
- Caddy block for the public canonical name

Right output is a single skill `add-portainer-host <ct-id> <slug>`
that does all of the above. Out of scope for the current MCP work but
the pattern is now documented well enough across this repo + memory
to extract cleanly.

### Phase 12 — CT hostname cleanup workload
The original motivating task (set every CT's `/etc/hostname` to
`<name>.service` to prevent the shadow-DNS bug). Now possible to drive
through `https://mcp.pape.house` with a JWT. Defer until convenient.
