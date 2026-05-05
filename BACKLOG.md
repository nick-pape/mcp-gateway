# mcp.pape.house — backlog

Deferred items for v1.5+ surfaced during the Phase 11 deploy. Listed
here so they don't get lost. Not blocking; the gateway works
end-to-end without any of these.

## Architectural / feature

### HITL approval web UI
The phone notification has hard length limits and no room for full
context. Build a small web app at `https://mcp.pape.house/hitl/<request_id>`
that the ntfy notification deep-links to ("View details" action button
in addition to Approve/Reject). Shows what the hub already has but
doesn't surface today:

- Tool description from upstream MCP schema
- Args formatted as key/value (full, not hashed)
- Recent call history for this identity (last N calls + their outcomes)
- bao secret path that would be touched
- Request ID, identity, source IP, age of pending request
- Approve/Reject buttons that hit the same /hitl/ack route

Pure read of state the hub already holds; no new info channels. ~200
LoC of starlette + a single template. Auth via the same Authentik
OAuth flow (uses the human-OAuth backlog item — both depend on it).

### Per-identity ntfy topics
Today everyone subscribes to `mcp-hitl-approvals`. Two humans behind
separate identities means everyone gets every push. Add `topic_template`
to NtfyApprover config (`"mcp-hitl-{identity}"`); update ntfy ACL on
the publisher user from a specific topic to glob `mcp-hitl-*`. Each
human subscribes only to topics for identities they own.

### Richer HITL notification body
Current notification: `[claude-code-dev] technitium_dns_health_check?`
+ body `{}`. Have available but not piping through:
- Tool description from upstream MCP `tools/list` schema
- Args formatted as `key: value` lines (not raw JSON)
- Request ID for audit correlation
- Optional: severity/destructive-intent tagging based on tool name
  glob (delete/remove/reset → red, read → blue, etc.)

Pairs naturally with the per-identity topic change — both touch
NtfyApprover._publish.

### Required `justification` arg for push-approve tools
Every tool that resolves to push-approve for the calling identity
gets a *required* `justification` string parameter, enforced by
HITL middleware. Auto-approve callers don't need to pass it (so
headless agents stay simple); push-approve calls without
justification get `JUSTIFICATION_REQUIRED` immediately.

Implementation:
- Tool schema injection: any tool with push-approve in ANY identity's
  policy gets an OPTIONAL `justification` field added to its
  `inputSchema.properties` at registration time (so all callers can
  pass it without breaking schema validation).
- HITL middleware: before publishing to ntfy, check `args.get("justification")`
  is non-empty. Reject with `JUSTIFICATION_REQUIRED` if missing.
- The notification body + web UI surface the agent's justification
  prominently — that's the human's primary context for deciding.

Cheaper than MCP elicitation (no round-trip) and harder to skip than
voluntary `_meta` (schema-enforced for every push-approve caller).

### Two-tool elicitation pattern for HITL context (fallback)
If `justification` proves insufficient (e.g., LLM cargo-cults the
field with shallow reasons), fall back to: before publishing the
HITL request, the hub calls back to the agent via MCP "elicitation"
asking *"explain in more detail"*. Slow (extra round trip) but
breaks past trivial autocomplete-grade explanations. Defer until
the simpler pattern shows its limits.

### MCP-client OAuth at the gateway (human-driven flows)
Two distinct auth populations need different patterns, and the gateway
should serve both:

- **Service / autonomous agents** (Claude Code in headless runs, n8n,
  cron scripts, custom claws): pre-mint JWTs via Authentik
  `client_credentials` and present them as bearers. This is what works
  today; no change needed.

- **Humans driving MCP clients** (Claude Desktop, Copilot, Cursor, any
  IDE plugin that follows the MCP-spec OAuth flow): the client expects
  to do the OAuth dance itself when it registers the MCP. The user
  shouldn't have to know what a JWT is, let alone go pre-mint one. The
  flow they expect: point the client at `https://mcp.pape.house`,
  client discovers it needs auth, opens browser to Authentik, user
  logs in (with their normal SSO), client gets back a token scoped to
  that user's identity, tool calls work.

This second population is the missing piece today.

Design: the gateway exposes `/oauth/authorize` + `/oauth/token` +
`/.well-known/oauth-authorization-server` (the MCP-spec discovery
document) and proxies them to Authentik. From the MCP client's
perspective, `mcp.pape.house` IS the OAuth provider; from Authentik's
perspective, the gateway is a confidential client doing
on-behalf-of. The user sees the real Authentik consent screen.

Benefits beyond ergonomics:
- Per-connection JWTs are user-scoped (not just service-scoped), so
  audit shows the human behind every call
- Same identity model regardless of client (Claude Code, Copilot,
  custom): every tool call ties back to a user via Authentik
- Standard MCP-spec; future MCP clients work without per-client wiring

Probably ~150 LoC of additional middleware/routes plus an Authentik
client config that allows authz_code grant + PKCE.

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
