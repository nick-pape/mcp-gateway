# Architecture Directive — mcp-hub (provisionally "McpCommander")

Compact reference for everything load-bearing about this project's
architecture. If you only read one file in this repo, read this one.
For depth: `architecture.md`, `IMPLEMENTATION_PLAN.md`. For known
gaps: `KNOWN_LIMITATIONS.md`. For roadmap: `BACKLOG.md`.

---

## What it is, in one sentence

A multi-tenant MCP gateway that does **federated access, agent-on-behalf-of-human
to scoped configurable tools, with HITL first-class and pluggable
MCPs/HITL mechanisms**.

That sentence is the elevator pitch. Don't change it.

## What it isn't

- Not an identity provider (no internal user model — JWTs come from external IdP)
- Not an agent runtime (agents like IronClaw run elsewhere; we serve them)
- Not a secret store (we read secrets from bao; we don't store them)
- Not HA / clustered (one instance per deployment, deliberately)
- Not a GUI product (config is `policy.yaml`; we don't ship a web admin)

## Threat model

**Rogue agents under prompt injection**, NOT external network attackers.

Architectural principle: *agents can have god permissions (shell) OR
read untrusted input (unfettered web), but not both.* This project
implements the "scope down god permissions" half. The complementary
"sandbox the agent" half lives in IronClaw (WASM) / NemoClaw (kernel).

---

## Core architecture (one paragraph)

A FastMCP-based HTTP server validates inbound JWTs against an external
OIDC issuer (Authentik), extracts identity from the `aud` claim,
filters `tools/list` per-identity policy, gates `tools/call` via a
HITL middleware, and dispatches approved calls through an in-process
**Fanout** module that spawns one stdio child per (MCP × identity)
tuple under a distinct UID via `gosu`. Each child gets per-identity
credentials injected via a token file (mode 0400, owned by that UID).
Secrets come from OpenBao via JWT-OIDC token swap. HITL approvals
go through ntfy with required justification + receipts. The hub's
own auth-to-bao JWT is rotated by an in-process refresher every
~10 min.

## Layers (mental model)

```
Layer 1 (bootstrap, on disk)    Authentik OAuth client_secret
                                ↓ refresh every ~10min via refresher
Layer 1 (output, on disk)       Authentik JWT for hub identity
                                ↓ used to bao login
Layer 2 (ephemeral, in memory)  bao token (1h TTL)
                                ↓ reads upstream credentials
Layer 3 (long-lived in bao KV)  Upstream MCP API tokens
                                ↓ written per-identity to per-UID file
Layer 4 (per-fanout-child)      Token file mode 0400 owned by child UID
                                ↓ MCP child reads via configured env var
Layer 5 (upstream service)      Real API call with the token
```

**Layer 3 currently does NOT rotate.** Refresher framework supports
it via plugins; impls aren't written. See `KNOWN_LIMITATIONS.md` #2.

---

## Identity model

- JWT carries `aud` claim (issued by Authentik per-OAuth-provider).
- `audience_prefix` (default `mcp-`) is stripped to derive identity name.
  - JWT `aud: mcp-claude-code-dev` → identity `claude-code-dev`
  - JWT `aud: mcp-interactive` → identity `interactive`
  - **The identity name in `policy.yaml` must match the stripped form.**
    This is a real footgun; double-check when adding identities.
- Each identity has:
  - `aud`: the audience that maps to this identity
  - `uid_base`: distinct UID for `gosu` separation (1001+, +per-MCP offset)
  - `allowed_tools`: glob list filtering `tools/list`
  - `hitl`: defaults + per-tool overrides (`auto-approve` / `push-approve` / `reject`)
  - `secrets`: per-MCP `bao` paths

Identity types we support:
- **Service identities** (e.g., `claude-code-dev`, `mcp-fanout-svc`):
  authenticated via Authentik `client_credentials` grant. Defaults
  `auto-approve`, exceptions `push-approve` for destructive tools.
- **Interactive identities** (e.g., `interactive`): authenticated via
  Authentik `authorization_code` + PKCE. Defaults `push-approve`,
  exceptions `auto-approve` for pure reads + trivial cache ops.
- **Autonomous Claw identities** (e.g., `kitchen-claw`, `dns-claw`):
  `client_credentials` like service identities, but typically with
  more aggressive HITL gating (defaults `push-approve`).

## HITL model

`HITLMiddleware` runs per `tools/call`. For tools resolving to
`push-approve`:

1. Required `justification` arg (string). Schema-injected at tool
   registration; missing/empty → `JUSTIFICATION_REQUIRED` returned to
   agent.
2. Strip `justification` from args before forwarding upstream
   (handler in `server.py` pops it).
3. Build `ApprovalRequest`, call `Approver.request_approval(timeout_s)`.
4. Block until approve / reject / timeout.
5. After resolution, fire `Approver.publish_outcome(...)` as
   `asyncio.create_task` (fire-and-forget) for receipt notification.

`NtfyApprover` flow: bao login (mcp-hitl role) → store nonce + ack_token
in bao KV at `secret/data/hitl/pending/<nonce>` (5min TTL) → publish
to ntfy at `mcp-hitl-{identity}` topic with Approve/Reject buttons →
wait on `asyncio.Event` → `/hitl/ack` webhook decrypts ack, atomically
deletes bao entry, signals event → return result.

Receipts (post-resolution):
- `✓ Approved · <mcp_name> <tool>` — with result snippet + timing
- `⚠ Approved (errored)` — for upstream tool failures post-approval
- `✗ Rejected · ...` — with rejection wait time
- `⏱ Timed out · ...` — with original justification echoed back

Receipt notifications are **HITL-only** — auto-approve calls don't
publish anything (the auto-approve path doesn't even touch
`publish_outcome`).

---

## Plugin model

Three Protocols already plugin-ready via setuptools entry points:
- `TokenSource` — group `mcp_hub.token_sources`. Built-in:
  `authentik_client_credentials`.
- `TokenSink` — group `mcp_hub.token_sinks`. Built-in: `file`.
- Resolver also accepts dotted-path imports for in-repo plugins.

Two Protocols still hardcoded in `factory.py` (refactor pending for
OSS extraction):
- `SecretBackend` — concrete impls: `EnvSecretBackend`,
  `BaoSecretBackend`. Future entry-point group `mcp_hub.secret_backends`.
- `Approver` — concrete impls: `AutoApprover`, `RejectApprover`,
  `NtfyApprover`. Future entry-point group `mcp_hub.approvers`.

For OSS extraction, all four become entry-points; bao + ntfy specifics
move to separate `mcp-broker-secret-bao` and `mcp-broker-approver-ntfy`
packages. Core ships with the test/dev fakes only.

## Fanout pattern

`Fanout` (in `mcp_fanout/`) is the in-process multiplexer. One Fanout
per upstream MCP type. Each Fanout holds N stdio children — one per
identity that has access to that MCP. Each child runs as a distinct
UID via `gosu`, with its per-identity token file at mode 0400.

Eager-or-die at boot: any child that fails to spawn aborts hub
startup. (Recovery post-boot is a known gap — see
`KNOWN_LIMITATIONS.md` #4.)

Tool routing: at registration time the hub queries one child of
each Fanout for `tools/list`, prefixes each tool with the MCP name
(`technitium_dns_list_zones`), and registers with FastMCP. At
call time, the registered handler reads identity from context state
(set by `IdentityMiddleware`) and dispatches via `fanout.call(identity, request)`.

---

## OAuth flow at the gateway

- Hub serves `/.well-known/oauth-protected-resource` (RFC 9728)
  pointing at itself
- Hub serves `/.well-known/oauth-authorization-server` (RFC 8414)
  with Authentik's endpoints + `registration_endpoint` pointing at
  the hub
- Hub serves `POST /oauth/register` (RFC 7591) — currently a static
  shim returning the same `mcp-interactive` client_id for every
  caller (true DCR is a known gap, see #6)
- Issuer in metadata stays as Authentik's (`https://auth.pape.house/`),
  per RFC 8414 §3, so the JWT's `iss` claim matches the metadata's
  `issuer` field

The Authentik `mcp-interactive` provider:
- `client_type: public` (PKCE-only, no client_secret)
- `redirect_uris: regex http://localhost:[0-9]+/.*` (Claude Code's
  loopback callback pattern)
- `issuer_mode: global`
- `audience: mcp-interactive`

---

## Three Claw trigger types

For autonomous agents (Claws) running in front of the gateway:

| Trigger | Cadence | Use case |
|---|---|---|
| **Heartbeat** | Global fixed interval (env var, default 30 min) | Wake up, run `HEARTBEAT.md` checklist, alert if actionable |
| **Cron** | Per-routine cron expressions | "Every Wednesday 6pm, suggest meal plan" |
| **Reactive** | Event-driven / webhook triggered | User texts the ntfy topic, Claw responds |

The reactive trigger is what wires the bidirectional ntfy
conversation (see "Communication channel" below).

## Communication channel

Per-identity ntfy topic (`mcp-hitl-{identity}` for HITL,
`<claw-name>` for Claw conversations) carries:
- HITL prompts (gateway → operator)
- HITL receipts (gateway → operator)
- User → Claw messages (operator → ntfy → Claw subscriber)
- Claw → user updates (Claw → ntfy publish via channel module)

For IronClaw integration, write a `ironclaw-channel-ntfy` Rust crate
(WASM, target `wasm32-wasip2`) implementing the Guest trait
(`on_start`, `on_poll`, `on_respond`, `on_broadcast`). ~200-400 LoC.
This is an OSS contribution opportunity — no such crate exists today.

---

## Common gotchas

- **Identity = aud minus prefix.** Identity name in `policy.yaml`
  must match what's left after stripping `audience_prefix`.
- **Authentik bug #16621**: `access_token_validity` PATCHes silently
  no-op since 2025.6. Hub JWT must be refreshed every ~10 min.
- **bao role audiences are constant**, not per-identity. The hub
  authenticates to bao with the SAME `mcp-fanout-svc` JWT for all
  identities; bao roles bind audience `mcp-fanout-svc`, NOT the
  per-identity audience. Setting `bound_audiences:["mcp-<identity>"]`
  on a bao role will cause auth failures.
- **`bound_subject` on bao roles must be empty** (`""`). Authentik's
  JWT `sub` claim is a hashed user ID, not the literal client_id.
- **MCP children get cleaned-args**, not args-with-justification.
  Middleware reads justification but doesn't strip; the registered
  handler in `server.py` pops it before forwarding.
- **Single-file bind mounts can't be atomically replaced.** When
  binding a config dir into the container, bind the *directory*,
  not a single file. The refresher uses `os.replace` which fails
  on a bound file.
- **Portainer behind Caddy needs `TRUSTED_ORIGINS` env var.**
  Bare hostname only, no scheme.

## File map

```
src/mcp_hub/
├── __main__.py        Hub entrypoint; OAuth discovery routes
├── server.py          Hub class — middleware install, tool registration
├── auth.py            AuthentikJWTValidator — JWKS-cached signature verify
├── interfaces.py      SecretBackend, Approver, Token Protocols + ApprovalRequest, CallOutcome
├── policy.py          HubConfig pydantic model + Policy facade with accessors
├── factory.py         Config → backend instance dispatch
├── middleware.py      Identity, ToolCuration, HITL, Audit middlewares
├── audit.py           Structured JSONL audit log
├── errors.py          Stable ErrorCode taxonomy
├── bao_client.py      Hand-rolled bao HTTP client (~150 LoC)
├── secrets/           BaoSecretBackend, EnvSecretBackend
├── approvers/         AutoApprover, RejectApprover, NtfyApprover
└── refresher/         TokenSource/TokenSink Protocols, registry, orchestrator,
                       manager + builtins (Authentik client_credentials, file sink)

src/mcp_fanout/        In-process stdio multiplexer; future OSS package
├── fanout.py          Fanout + IdentityConfig
├── child.py           ChildProcess wrapper around asyncio subprocess
└── uid_alloc.py       gosu spawn helpers

policy.example.yaml    Canonical config example
docker-compose.yml     Single-container deploy
Dockerfile             Multi-stage build with upstream MCP build stages
scripts/               bao bootstrap, entrypoint
tests/                 pytest unit + fakes (no integration suite — see #13)
```

## Operational defaults

- Hub binds `0.0.0.0:8443` inside container; Caddy at
  `mcp.pape.house` reverse-proxies.
- HITL timeout: 300s (5 min) — set in `policy.yaml` under
  `approver.config.timeout_default_s`, plumbed via constructor to
  `HITLMiddleware`.
- bao HITL pending TTL: 5 min (`approver.config.ack_ttl_s`).
- Refresher cadence: `minutes=10` (default in policy.example.yaml).
- Fanout JWT expiry: 15 min (Authentik bug #16621 forces this; can't
  raise via per-provider PATCH).

## When in doubt

The user has explicitly said:
- Don't frame anything around job hunting (homelab is for fun)
- Don't broadly scan the filesystem; ask if you don't know a path
- Don't enumerate environment for credentials; ask
- Convention: public URLs are function-named (`secrets.pape.house`),
  CT hostnames are implementation-named (`bao.service.pape.house`)
- Caddy upstreams use service-tier FQDN, never raw IP
- Don't reflexively suggest mocking databases; integration tests > mocks
- bao + Authentik are the homelab-canonical secret + IdP layers; for
  OSS, abstract these via the existing Protocols, don't hardwire

## TL;DR for a future Claude session

1. Read this file + `BACKLOG.md` + `KNOWN_LIMITATIONS.md` (in that order)
2. Look at `policy.example.yaml` for the canonical config shape
3. Skim `src/mcp_hub/middleware.py` for the request lifecycle
4. Check `src/mcp_hub/refresher/` for the plugin model template
5. Don't suggest replacing bao or ntfy without checking memory for
   the user's preferences first
