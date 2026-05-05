# MCP gateway landscape — May 2026 survey

> Sister doc: [`architecture.md`](./architecture.md) for the build proposal that came out of this survey.

## Spec we measured against

A focused MCP gateway for the homelab, decoupled from LiteLLM
(agents drive their own tool-use loops):

1. **OIDC/JWT ingress** validating Authentik-issued tokens
2. **Per-agent tool curation** — `list_tools` returns only allowed tools
   (disallowed tools are *invisible* to the LLM, not auto-rejected)
3. **HITL on `call_tool`** — per-tool policy with pluggable approver
   backends (ntfy push first)
4. **Federation** across multiple stdio MCP backends behind one endpoint
5. **Policy-as-code** — YAML/JSON in git, not admin-UI-only
6. **Self-hostable, OSS, single-developer-friendly**

## Candidates evaluated

### MetaMCP (`metatool-ai/metamcp`)
- ⭐ 2.3k · TypeScript / Next.js · Postgres · v2.4.22 (Dec 2025)
- ✅ OIDC tested with Auth0/Keycloak/Azure/Google/Okta — Authentik fits the
  pattern (env vars: `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
  `OIDC_DISCOVERY_URL`)
- ✅ Federation across stdio + SSE backends, namespace grouping
- ✅ Tool-level enable/disable inside a namespace, inline tool overrides
- ⚠️ Allowlists are **per-namespace**, not first-class per-API-key /
  per-identity — would need to model each agent as its own namespace, which
  fights the design
- ❌ No HITL of any kind
- ❌ Config lives in Postgres + admin UI; not version-controlled

### MCP Gateway & Registry (`agentic-community/mcp-gateway-registry`)
- ⭐ 631 · Python + React · MongoDB · v1.0.21 (active, 1082 commits)
- ✅ Generic OAuth 2.0 (Keycloak, Entra, Okta, Auth0, Cognito) — Authentik
  fits the same shape
- ✅ Database-driven fine-grained scopes (which servers, which tools, which
  agents per user/group)
- ✅ Federation + virtual server aggregation
- ✅ **Registration Gate**: calls an external endpoint to approve/deny
  registration *of new MCPs* — fail-closed
- ❌ The Registration Gate is for **admission of new MCPs**, not for
  per-tool-call HITL. There is no per-call equivalent.
- ❌ Admin-UI-only config (JSON import/export exists but isn't the source
  of truth)
- ❌ MongoDB dependency — heavy for a homelab

### IBM mcp-context-forge
- ⭐ Mature · Python · Postgres + Redis · v1.0.0 GA
- ✅ JWT auth, federation, structured logs, admin UI
- ✅ Plugin system with `tool_pre_invoke` and `tool_post_invoke` hooks —
  in principle a HITL plugin is buildable
- ⚠️ Plugin API is request/response interception (synchronous shape). HITL
  with push-and-wait may require either holding the request open for
  minutes (timeout risk) or implementing the async resume in the plugin
  itself with backing storage. Non-trivial.
- ❌ Heavy stack (Postgres + Redis + admin UI). For a single-MCP-cluster
  homelab, this is two extra services to keep alive.
- ❌ Pre-mortem (see SRE adversary review): Redis-backed HITL state can
  evaporate on LXC reboot if persistence isn't tuned, silently losing
  pending approvals.

### sparfenyuk/mcp-proxy
- ⭐ Active · Python · v0.11.0 (Jan 2026)
- ✅ Solid stdio↔SSE/Streamable HTTP bridge, named server hosting
  (`/servers/<name>/`)
- ✅ Auth: bearer headers, env vars, OAuth2 client credentials
- ❌ No tool curation, no HITL, no policy
- → A useful **building block** if we build (good shim/proxy primitive),
  not a complete gateway

### Preloop (commercial)
- ✅ Native push approvals (mobile / web / email) — exactly the HITL UX
  we want
- ✅ Per-policy rules (e.g., "allow payment < $50, require approval > $50")
- ✅ Self-hostable
- ❌ Commercial, no public source
- ❌ Single-tool proxy, not an aggregator
- → Validates the design pattern but unusable directly

### Peta (commercial)
- ✅ Native HITL via Slack/Teams ("Peta Desk")
- ✅ RBAC/ABAC
- ❌ Commercial, closed source
- → Same story as Preloop: validates pattern, unusable directly

### Kuadrant/mcp-gateway, Kong AI Gateway, Traefik Hub MCP Gateway
- All real, all featureful, all enterprise/k8s-flavored.
- Bringing any of them in would mean adopting their entire control plane
  (Gateway API CRDs, Kong's data model, Traefik Hub's commercial layer)
  for a homelab single-LXC use case. Disproportionate.

## Verdict: build, borrowing patterns

No single OSS tool hits all requirements without significant glue work.
The closest two each have a disqualifying gap:

- **MetaMCP**: no HITL at all
- **mcp-gateway-registry**: webhook approval is for registration, not
  per-call — and the whole config story is admin-UI-only, which the devex
  adversary review specifically called out as the worst experience over a
  2-year horizon

Building a focused gateway is the right call because:

1. **HITL on per-tool-call is the load-bearing feature.** Every OSS option
   either lacks it (MetaMCP, mcp-gateway-registry, mcp-context-forge in
   practice) or is commercial (Preloop, Peta).
2. The build is small (~400–700 LoC) when scoped to just the MCP gateway
   — no LiteLLM, no admin UI, no model proxy concerns.
3. Adversary review (ops + devex, both leaning A-custom over B-vendor) showed
   that the closest "buy" options trade one set of problems for another:
   Postgres-backed HITL state evaporating on Redis eviction, admin-UI
   config diverging from git, framework upgrades breaking Loki queries.
4. We can borrow concrete patterns from the OSS candidates rather than
   inventing.

## What we borrow

- **MetaMCP**: tool namespacing convention (e.g., `technitium_*`,
  `authentik_*` prefixes injected at proxy time)
- **mcp-gateway-registry**: external-webhook approval pattern, scoped down
  to per-tool-call (their pattern was for registration; same shape works
  for tool-call)
- **IBM context-forge**: `tool_pre_invoke` / `tool_post_invoke` hook shape
  as our middleware contract — this is the right interface even if we
  implement it ourselves
- **sparfenyuk/mcp-proxy**: validated stdio↔HTTP wrapping pattern.
  Not used directly in v1 (single-container in-process Fanout doesn't
  need network IPC), but the design space confirmation was useful.

## The multi-user secret problem

Surfaced late in design: the OSS MCP ecosystem was built for "Claude
Desktop, single user, env var at boot." 12 of 13 surveyed MCPs take
their credential from env at process start. Putting one behind a
multi-tenant gateway fights the design.

How others handle it:

- **Peta** sidesteps by writing their own vault-aware MCP servers
  (`dunialabs/mcp-servers`); does NOT have a documented retrofit for
  third-party env-var-at-boot MCPs
- **AgentGateway (Solo.io) enterprise tier** has a transparent wrapper
  that intercepts and injects per-call credentials — closest match to
  the problem we have, but commercial
- **Klavis (YC SaaS)** holds per-user OAuth refresh tokens, exposes
  per-user MCP endpoints — hosted only

**Our solution:** spawn one stdio child per (MCP × identity) tuple
inside a single in-process Fanout. Pre-resolves per-identity secrets
from bao at boot; routes incoming calls by identity tag. UID-per-child
isolation. See `architecture.md` for details. **The Fanout module is
worth packaging as standalone OSS** — it's a generic "multi-tenant
multiplexer for single-user stdio MCPs" that nothing else in the OSS
landscape provides.

## What we explicitly do NOT do

- **No admin UI in v1.** Policy is a YAML file in this repo; changes go
  through git PRs. Audit log is a flat JSONL stream to Loki.
- **No DB.** State is filesystem (policy YAML) + ephemeral memory
  (JWKS cache, in-flight approvals). HITL pending state is held in the
  request coroutine — when the gateway restarts, pending approvals are
  cancelled (clean failure, not silent loss).
- **No general "MCP store" / "agent registry" features.** Just
  authn + authz + curation + HITL + audit + federation.

## Re-evaluation triggers

Revisit the build-vs-buy decision if:

- MetaMCP adds first-class per-key allowlists AND a HITL hook
- mcp-context-forge ships a HITL plugin or pattern with proper async
  resume + persistence
- AgentGateway (Solo.io) open-sources their transparent-wrapper
  per-call credential injection from the enterprise tier
- Preloop/Peta open-source their HITL gate
- We hit ~10+ MCPs and find ourselves wanting an admin UI for
  registration churn
