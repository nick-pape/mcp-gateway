# Known Limitations

Honest accounting of architectural gaps, scale concerns, and OSS-readiness
TODOs. This document is the inverse of `BACKLOG.md` — that file lists
features we'd like to add; this file lists problems with what's already
shipped. They're related but they're different lists.

If you're evaluating this project for use: **read this file first.** The
defaults work for the homelab use case it was built for; if your
deployment differs, one of these will probably bite you.

---

## Architectural / adoption-blockers

### 1. Credential injection has exactly one shape

The `Fanout._spawn` flow writes a per-identity token file at a path the
upstream MCP reads via an env var (`secret_env_name` in `MCPConfig`).
That's *one* of many shapes upstream MCPs actually need:

- ✅ File path via env var (us; `technitium-mcp-secure`)
- ❌ Env var with the literal token value (`TOKEN=xxx ./mcp-server`)
- ❌ CLI flag (`--token=xxx` or `--api-key xxx`)
- ❌ Config file written at a known path in a specific format
  (JSON / YAML / TOML / INI)
- ❌ HTTP `Authorization: Bearer xxx` header injection (for the
  upcoming HTTP-transport upstream MCPs)
- ❌ "Upstream MCP does its own OAuth flow" — should NOT inject
  anything, and should NOT spawn the MCP under our identity at all

Today: shipping a new MCP federation almost always means either forking
the upstream MCP to accept our shape (the `technitium-mcp-secure`
pattern) or writing a wrapper script. Both are friction.

**Right shape:** a `TokenInjector` Protocol with the above as concrete
implementations, declared per-MCP in `policy.yaml`. ~5 implementations
covers ~80% of upstream MCPs. The remaining 20% can write a custom
injector or fork.

### 2. Layer 3 secrets never rotate

Three layers of credential lifetime:

| Layer | Example | Refresh |
|---|---|---|
| 1 (bootstrap, on disk) | Authentik OAuth `client_secret` for hub identity | Manual |
| 2 (ephemeral, memory) | bao token via JWT swap | Auto on bao TTL |
| 3 (long-lived, in bao KV) | Technitium API token | **Never** |

Layer 3 is the gap. The refresher framework exists (in `mcp_hub/refresher/`),
but only ships an `AuthentikClientCredentialsSource` and `FileSink`. To
refresh a Layer 3 secret like a Portainer self-rotated token, we'd need
a `BaoKVSink` and a `PortainerSelfRotateSource`. Mostly unwritten.

We're loud about "no long-lived ambient creds" while quietly relying on
sealed long-lived creds in bao. Honest: bao seal is a meaningful
mitigation, but rotation is the proper fix.

### 3. Stdio-only upstream MCPs

`Fanout` assumes spawn-and-pipe. The MCP transport spec defines stdio
*and* Streamable HTTP; many upstream MCPs ship HTTP-only (Home
Assistant's built-in MCP server, several vendor offerings).

Need: an `UpstreamTransport` abstraction with `StdioTransport` (today)
and `StreamableHTTPTransport` (TODO) implementations. The HTTP variant
also needs the `TokenInjector#header` shape (#1) for `Authorization`
header.

### 4. No upstream MCP failure recovery

Eager-or-die works at boot — any child that fails to spawn aborts the
whole hub start. Post-boot, if a child dies (OOM, network blip, upstream
MCP itself crashed, gosu segfault), the hub doesn't respawn it. The
tool keeps appearing in `tools/list`; calls fail at dispatch with
`BACKEND_CHILD_DEAD`.

Needs a supervision loop per child: on EOF or non-zero exit, attempt
respawn with bounded backoff; on persistent failure (N retries),
suspend the child + remove its tools from `tools/list` until manual
intervention.

### 5. Authentik-coupled in non-obvious places

The architecture pretends to be IdP-agnostic but bakes in Authentik
quirks:

- `issuer_mode=global` (Authentik's choice, not OIDC standard)
- The Authentik bug-#16621 workaround (refresh `client_credentials`
  JWTs every 10 min because `access_token_validity` PATCHes
  silently no-op since 2025.6)
- Per-app discovery URL pattern (`/application/o/<slug>/`)
- Authentik's specific PKCE redirect URI matching modes

`AuthentikJWTValidator` is the right Protocol shape but the only
concrete impl. Keycloak, Okta, Cognito each have their own oddities.
The second-IdP user will hit this immediately.

### 6. No real Dynamic Client Registration

Our `/oauth/register` endpoint is a static shim — every caller gets
the same `mcp-interactive` client_id. Sufficient for "Claude Code on
my laptop" but can't differentiate:

- Claude Code on dev laptop vs prod laptop
- Different MCP clients (Claude Code, Cursor, Copilot) all looking
  like one client to Authentik
- Clients that *should* be granted different scopes (read-only vs
  read-write personas of the same human)

Real DCR needs the Authentik DCR feature flag enabled + actual
per-client persistence on our side. ~1 day of work, currently
skipped because it wasn't needed for the homelab.

---

## Scale concerns

### 7. Fanout per-(MCP × identity) child spawn = N×M memory

With 1 MCP × 1 identity it's a non-issue. With 5 MCPs × 10 identities
it's 50 child processes — meaningful RAM, fork pressure, and PID-table
cost. Mitigations not yet built:

- Lazy spawn (only on first call from that identity, cache for some
  TTL after last call)
- Child pooling per MCP type with per-call identity injection
- In-process MCP support for trusted upstreams (skip the subprocess
  isolation)

### 8. No tools/list pagination

10 federated MCPs × ~100 tools each = 1000 tools returned in one
`tools/list` response. Some LLMs/clients tolerate this poorly (context
window cost, slower planning, schema-validation churn).

MCP spec supports pagination via `cursor` parameter. We don't
implement it on the gateway side. At ~50 tools today (Technitium only)
it's fine; at 200+ this will hurt.

### 9. JWT validation cost per call

Every `tools/call` re-validates the JWT signature against cached JWKS.
Cache makes the JWKS fetch ~free, but the RSA verification is still
~ms-scale per call. Sessions/cookies would skip the work after first
auth.

Not urgent for homelab traffic; would matter at API-scale loads.

---

## Operational / polish

### 10. No live policy reload

Any `policy.yaml` change requires container restart. That tears down
all fanout children, drops in-flight HITL approvals, and re-runs every
upstream MCP `initialize` handshake. Brief downtime is fine for
development but rough in production.

Cleaner: SIGHUP → diff old vs new policy → apply only the deltas
(new identities → spawn new children; removed identities → close
their children; HITL override changes → apply on next call). Most
changes are HITL overrides which need no spawn churn.

### 11. Receipts share topic with prompts

HITL prompt notifications and receipt notifications both publish to
`mcp-hitl-{identity}`. When watching the topic, the operator sees
interleaved "approve this?" and "✓ approved earlier" messages. Cleaner
options:

- Separate `mcp-hitl-{identity}-receipts` topic
- ntfy tags-based client-side filtering
- Update-in-place semantics (ntfy doesn't support natively today)

### 12. Per-call JWT mismatch surfaces no-oracle as silent

When the hub receives a JWT for an identity that exists in policy but
the requested tool isn't in `allowed_tools`, the response is
`POLICY_REJECTED` (correct). But when the JWT's `aud` strips to an
identity that DOESN'T exist in policy, `tools/list` returns an empty
list (also correct, no-oracle), and `tools/call` returns
`POLICY_REJECTED` for the same reason. Hard to distinguish "you're a
known identity with no tools allowed" from "you're an unknown identity"
— intentional security posture, but operationally confusing during
setup.

A diagnostic mode that logs distinct reasons (visible only in hub
logs, not in the response) would help debugging without compromising
the no-oracle property.

---

## Testing / quality gaps

### 13. No integration test suite

Unit tests are good (`tests/unit/test_*.py` covers protocols,
middleware, refresher, approver in isolation with fakes). End-to-end
tests don't exist — the full Authentik → bao → fanout → upstream MCP
chain is verified manually via curl + actual deploy.

CI runs unit tests; regressions in the integration boundary (e.g., a
bao client API change, an Authentik discovery doc field rename) won't
catch them. Manual smoke after each deploy is the current safety net.

### 14. Build-time `git clone` of upstream MCPs

The Dockerfile clones `technitium-mcp-secure` from GitHub at build
time, builds it from source, and bakes the binary into the image.
Fragile: if the upstream repo is renamed/deleted, builds break;
network at build time is required; no enforced version pinning.

Should at least pin to a commit SHA via `--build-arg`, ideally vendor
the upstream into the repo as a submodule, ideally-ideally pull
pre-built binaries from a release artifact.

---

## OSS-readiness

### 15. No README

Setup, configuration, deployment, and operating instructions don't
exist as a unified document. The codebase is well-commented and the
architecture docs (`architecture.md`, `landscape.md`,
`IMPLEMENTATION_PLAN.md`) are thorough — but they're insider docs, not
"someone landed here from a Hacker News link" docs.

Table-stakes for OSS launch.

### 16. policy.yaml schema versioning is informal

`version: 1` since day one despite adding fields like
`oidc_discovery_url`, `token_refresh:`, `topic_template`, the
`interactive` identity pattern. No clear "this field was added in
v1.2." Future schema migrations will be painful without a real
versioning story.

Either bump version on each breaking change (and document the
migration path) or commit to "additive-only forever" and document
which fields are required vs optional.

### 17. Documentation lives in scattered markdown files

`architecture.md`, `landscape.md`, `IMPLEMENTATION_PLAN.md`,
`BACKLOG.md`, `KNOWN_LIMITATIONS.md` (this file) are all good but
fragmented. A unified docs site (mkdocs / Docusaurus / hand-rolled
GitHub Pages) would help discoverability and let us link sections
between docs cleanly.

---

## What we're NOT going to fix (intentional limits)

These are calls we made on purpose, not gaps. Listing for clarity:

- **No multi-region / HA story.** Single hub, single bao, single
  Authentik. Acceptable for homelab; not a goal.
- **No built-in user model.** Identities come from external IdP via
  JWT validation. We will *not* add a Peta-style internal users
  table. The federated-IdP model is a deliberate differentiator.
- **No GUI admin console.** Configuration is `policy.yaml`. We will
  *not* add a web UI for editing it; that's a separate (optional)
  product.
- **No autoscaling / clustering.** One hub instance per deployment.
- **Python only, no Rust/Go rewrite.** The performance-sensitive
  parts are I/O-bound; Python's fine.

If any of these matter to you, you probably want a different tool.
