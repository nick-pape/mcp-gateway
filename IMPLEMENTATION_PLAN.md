# Implementation plan — `mcp.pape.house`

> Companion to [`architecture.md`](./architecture.md) (the design) and
> [`landscape.md`](./landscape.md) (why we're building this).

## Refinements from plan-review pass (latest, supersede details below)

This original draft predates an adversary/Plan-agent review. The latest
plan with the refinements baked in lives in the session plan file (also
mirrored here). Deltas from this draft:

- **Phase 1.5 (Audit) added** — moved before Phase 2 so all later phases
  emit structured audit lines from day 1
- **Phase 6a (`BaoClient` primitive) added** — shared by Phase 6b
  (`BaoSecretBackend`) and Phase 7 (`NtfyApprover`); avoids duplicate
  bao-auth implementations
- **Library pins locked in**: `pyjwt>=2.10.1,<3` (CVE-2024-53861),
  `fastmcp` exact-version pin (Streamable HTTP wobbles in 2.x), `gosu`
  (not `su-exec`, better maintained), stdlib `json` (no `structlog`),
  hand-rolled bao client (no `hvac`)
- **Cuts from v1**: `FileSecretBackend` (`EnvSecretBackend` covers dev),
  `LogApprover` (`AutoApprover` + audit = same outcome),
  `bootstrap-authentik.sh` (5 min UI clicks; documented in README)
- **New required tests**:
  - Phase 2: cross-UID `/proc/<sibling>/environ` EACCES, `max_response_bytes`
  - Phase 3: `kid`-as-URL asserts ZERO outbound fetches; `iss=` validation; clock-drift startup probe
  - Phase 4: glob precedence rule explicit; tool-name → fanout collision detection at policy load
  - Phase 7: constant-time compare lock-in; replay-within-TTL atomic nonce-consumption; webhook always-200; per-identity rate limit (5-pending token bucket)
  - Phase 8: pending HITL evaporates on hub crash → `POLICY_HITL_TIMEOUT`
  - Phase 9: atomic bao-token-file write (`O_CREAT|O_EXCL|0o400` + `fchown` before write)
- **Hub binds to docker-network interface only**, not `0.0.0.0`
- **Threat-model items explicitly accepted** (not defended in v1): hub
  holds in-flight args/results in Python heap (heap-zeroing impractical);
  `cap_add: [SETUID, SETGID]` retained for hub lifetime; live token
  rotation requires restart; HITL flooding rate-limited per-identity not
  globally

The rest of this document remains as the comprehensive reference; phase
detail lines below are accurate except where the deltas above apply.

## Working agreement

- Build directly in this repo at `ai-pape-house/mcp.service.pape.house/`.
- When stable + battle-tested, migrate `src/mcp_fanout/` to its own
  public OSS repo (it's the genuinely-novel piece). The hub stays
  homelab-flavored.
- **Python 3.13 + FastMCP**, no Go, no TS. (User's call.)
- Two pluggable interfaces from day 1: `SecretBackend` and `Approver`.
  Both selected by config; production = `bao` + `ntfy`; tests = swappable
  fakes.
- Tests are first-class — every module has unit tests, hub has
  integration tests with fakes.

## Tech stack

| Concern | Choice | Why |
|---|---|---|
| MCP server framework | `fastmcp` (latest) | Best Python ergonomics; matches existing repos |
| HTTP transport | Streamable HTTP | Current MCP spec |
| JWT validation | `pyjwt` ≥2.10 | Stdlib-shape, simple, audit `kid` handling explicitly |
| HTTP client | `httpx` (async) | bao + ntfy + JWKS |
| Config | `pydantic` v2 + `pyyaml` | Schema-validated, typed |
| Logs / audit | `structlog` (or stdlib JSON) | JSONL stderr → Loki |
| Test runner | `pytest` + `pytest-asyncio` | Standard |
| Lint / typecheck | `ruff` + `mypy --strict` (on src/) | Fast feedback |
| Build | `uv` for dependency management | Matches the rest of the homelab |
| Container | Multi-stage Dockerfile | One image, all MCPs baked in |

## Repo layout

```
mcp.service.pape.house/
├── README.md
├── architecture.md                  (existing)
├── landscape.md                     (existing)
├── IMPLEMENTATION_PLAN.md           (this file)
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── uv.lock
├── policy.example.yaml
├── scripts/
│   ├── bootstrap-bao.sh             # idempotent role/policy creation
│   └── bootstrap-authentik.sh       # idempotent OAuth client creation
├── src/
│   ├── mcp_fanout/                  ← future OSS package
│   │   ├── __init__.py
│   │   ├── fanout.py                # Fanout class
│   │   ├── child.py                 # ChildProcess (stdio + JSON-RPC framing)
│   │   ├── uid_alloc.py             # UID allocation strategy
│   │   └── exceptions.py
│   └── mcp_hub/
│       ├── __init__.py
│       ├── __main__.py              # entrypoint
│       ├── server.py                # FastMCP server + middleware
│       ├── auth.py                  # AuthentikJWTValidator
│       ├── policy.py                # config + glob expansion + HITL lookup
│       ├── audit.py                 # JSONL emitter
│       ├── routing.py               # tool prefix → fanout
│       ├── interfaces.py            # SecretBackend, Approver Protocols
│       ├── factory.py               # config → backend instances
│       ├── secrets/
│       │   ├── __init__.py
│       │   ├── bao.py               # BaoSecretBackend (production)
│       │   ├── env.py               # EnvSecretBackend (testing)
│       │   └── file.py              # FileSecretBackend (dev)
│       └── approvers/
│           ├── __init__.py
│           ├── ntfy.py              # NtfyApprover (production)
│           ├── auto.py              # AutoApprover (testing — always approve)
│           ├── reject.py            # RejectApprover (testing — always reject)
│           └── log.py               # LogApprover (dev — log + auto-approve)
└── tests/
    ├── unit/
    │   ├── test_fanout.py
    │   ├── test_child.py
    │   ├── test_auth.py
    │   ├── test_policy.py
    │   ├── test_secrets_bao.py
    │   ├── test_secrets_env.py
    │   ├── test_approver_ntfy.py
    │   └── test_audit.py
    ├── integration/
    │   ├── conftest.py              # shared fixtures
    │   ├── test_hub_e2e.py          # hub + real fanout + fake auth/bao/ntfy
    │   └── test_fanout_real_stdio.py
    └── fakes/
        ├── echo_mcp.py              # minimal stdio MCP for tests
        ├── fake_bao.py
        ├── fake_authentik.py        # JWKS server + JWT issuer
        └── fake_ntfy.py             # publish + subscribe via in-memory queue
```

## Interface contracts

```python
# src/mcp_hub/interfaces.py

from typing import Protocol, runtime_checkable
from dataclasses import dataclass
from enum import StrEnum

@dataclass(frozen=True)
class SecretRef:
    path: str       # "secret/data/services/technitium/ironclaw"
    field: str      # "api_token"

@dataclass(frozen=True)
class ResolvedSecret:
    value: str
    ttl_s: int | None = None
    metadata: dict | None = None

class SecretResolutionError(Exception): ...

@runtime_checkable
class SecretBackend(Protocol):
    """Resolves secrets at boot per (mcp, identity)."""
    name: str

    async def resolve(self, ref: SecretRef) -> ResolvedSecret: ...
    async def close(self) -> None: ...


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    identity: str
    tool: str
    args: dict
    args_summary: str

class ApprovalResult(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"

@runtime_checkable
class Approver(Protocol):
    """Decides approval for HITL tool calls."""
    name: str

    async def request_approval(
        self, request: ApprovalRequest, timeout_s: float
    ) -> ApprovalResult: ...
    async def close(self) -> None: ...
```

Implementations are in `secrets/` and `approvers/`. Production wires
`BaoSecretBackend` + `NtfyApprover`; tests wire `EnvSecretBackend` +
`AutoApprover` (or `RejectApprover` to verify reject paths).

## Config shape

```yaml
# policy.example.yaml
version: 1

server:
  bind: "0.0.0.0:8443"
  hitl_webhook_path: "/hitl/ack"

auth:
  issuer: "https://auth.pape.house/application/o/mcp-pape-house/"
  jwks_uri: "https://auth.pape.house/application/o/mcp-pape-house/jwks/"
  audience_prefix: "mcp-"        # aud must start with this; suffix = identity
  algorithms: ["RS256"]
  clock_skew_s: 30

secret_backend:
  name: bao
  config:
    addr: "https://secrets.pape.house"
    role_jwt_path: "/run/secrets/fanout_jwt"
    role_template: "mcp-{mcp}-{identity}"

approver:
  name: ntfy
  config:
    server: "https://notify.service.pape.house"
    topic: "mcp-hitl-approvals"
    publish_token_path: "/run/secrets/ntfy_publish_token"
    timeout_default_s: 120

audit:
  sink: stderr
  hash_args_default: true

mcps:
  technitium:
    command: ["node", "/app/mcps/technitium/dist/index.js"]
    uid_offset: 10                # uid = identity.uid_base + uid_offset
    secret_env_name: "TECHNITIUM_TOKEN_FILE"
  paperless:
    command: ["python", "-m", "paperless_mcp"]
    uid_offset: 20
    secret_env_name: "PAPERLESS_TOKEN_FILE"

identities:
  ironclaw:
    aud: "mcp-ironclaw"
    uid_base: 1001
    allowed_tools: ["technitium_dns_*", "paperless_get_*"]
    hitl:
      defaults: auto-approve
      overrides:
        "technitium_dns_delete_record": push-approve
    secrets:
      technitium: { path: "secret/data/services/technitium/ironclaw", field: "api_token" }
      paperless:  { path: "secret/data/services/paperless/shared",    field: "api_token" }
```

## Phases

### Phase 0 — Project skeleton (½ day)

- `pyproject.toml` (uv-managed), Python 3.13
- Empty package skeletons for `mcp_fanout` and `mcp_hub`
- `pytest` config + `ruff` + `mypy --strict`
- Skeleton README

**Done when:** `uv sync && uv run pytest` runs zero tests cleanly,
`uv run mypy src/` passes on empty packages.

### Phase 1 — Interfaces + test fakes (½ day)

- `interfaces.py` with `SecretBackend` and `Approver` Protocols
- `secrets/env.py` (`EnvSecretBackend` — reads env vars matching ref path slug)
- `secrets/file.py` (`FileSecretBackend` — reads from a JSON file)
- `approvers/auto.py`, `approvers/reject.py`, `approvers/log.py`
- `tests/fakes/echo_mcp.py` — minimal stdio MCP that echoes input as a tool result
- Tests for each fake backend

**Done when:** all four fake backends have green tests and conform to
their respective Protocol via `isinstance(x, SecretBackend)` (runtime
checkable).

### Phase 2 — Fanout module (1–2 days)

- `mcp_fanout/child.py`:
  - `ChildProcess` class wrapping `asyncio.subprocess`
  - JSON-RPC framing over stdio (newline-delimited JSON)
  - in-flight request locking (one at a time per child)
  - liveness check + restart policy (restart NOT in v1; fail-stack)
  - `su-exec` to allocated UID (skipped if not root, with a clear log line)
- `mcp_fanout/uid_alloc.py`:
  - allocates `uid_base + offset` per (identity, mcp) tuple
- `mcp_fanout/fanout.py`:
  - `Fanout(mcp_name, command, identities, secret_backend, secret_env_name)`
  - `start_eager_or_die()` — async; spawns all children or raises
  - `call(identity, request) → response`
  - `close()` — cleanup all children
- `mcp_fanout/exceptions.py`:
  - `IdentityNotFound`, `BackendChildDead`, `ChildSpawnFailed`
- Tests:
  - Spawn echo MCP, send/receive JSON-RPC
  - Multiple identities → independent children
  - `IdentityNotFound` on unknown identity
  - Child crashes during call → `BackendChildDead`
  - Concurrent calls to same child → serialized via lock
  - Concurrent calls to different children → parallel
  - `start_eager_or_die` raises if any identity's secret resolution fails

**Done when:** `pytest tests/unit/test_fanout.py tests/unit/test_child.py`
fully green, including the real-stdio echo test.

### Phase 3 — JWT auth (1 day)

- `auth.py`:
  - `AuthentikJWTValidator(jwks_uri, audience_prefix, algorithms, clock_skew_s)`
  - JWKS cache: load on success, **serve stale on warm fetch failure**, propagate cold-start failure
  - explicit `algorithms=["RS256"]` (never None or library default)
  - `kid` resolved against cached JWKS dict only — **never** as a URL
  - returns `Identity(name, claims)` or raises `AuthFailed(code)` (with codes: `INVALID_SIGNATURE`, `BAD_AUDIENCE`, `EXPIRED`, `IDENTITY_UNKNOWN_KID`, etc.)
- `tests/fakes/fake_authentik.py`:
  - generates RSA keypair on startup
  - serves JWKS over HTTP
  - issues JWTs with configurable claims
- Tests:
  - Valid JWT with `aud: mcp-ironclaw` → identity `"ironclaw"`
  - Bad signature → `AuthFailed`
  - Wrong audience → `AuthFailed`
  - Expired → `AuthFailed`
  - `kid` not in JWKS → `AuthFailed` (no URL fetch attempted — verify via fake JWKS server logs)
  - Cold-fail JWKS → `AuthFailed` propagates with sentinel code
  - Warm cache + JWKS fetch failure → still validates, logs `jwks_serving_stale`

**Done when:** auth tests pass; will be manually verified against real
Authentik in Phase 11.

### Phase 4 — Policy loader (½ day)

- `policy.py`:
  - Pydantic models for HubConfig, IdentityPolicy, MCPConfig, etc.
  - `Policy.load(path) → Policy` (with schema errors mapped to readable messages)
  - `Policy.allowed_tools(identity, all_known_tools) → set[str]` (glob expansion)
  - `Policy.hitl_decision(identity, tool) → "auto" | "push" | "reject"`
- Tests for each operation, including weird globs (`technitium_*` vs `technitium_dns_*` precedence)

**Done when:** all policy tests green; `policy.example.yaml` loads cleanly.

### Phase 5 — Audit (½ day)

- `audit.py`:
  - `Audit(sink)` — writes JSONL to `sink` (default `sys.stderr`)
  - request_id generation (ULID or KSUID)
  - args_hash (SHA-256, hex-encoded)
  - schema-stable line shape (see architecture.md)
- Pluggable sink (`stderr` v1; `file` later)
- Tests verify line shape + hash determinism

**Done when:** audit tests pass; sample output looks right.

### Phase 6 — `BaoSecretBackend` (1 day)

- `secrets/bao.py`:
  - reads `role_jwt_path` once at construction
  - `resolve(ref)`: OIDC swap with `role={mcp}-{identity}` (templated by caller) → ephemeral bao token → KV read → return value, drop token
  - retries on transient 5xx with exponential backoff (max 3 tries)
  - all errors → `SecretResolutionError` with descriptive message
- `tests/fakes/fake_bao.py`:
  - in-memory KV store, simulates JWT auth method, role enforcement
- Tests:
  - Resolve happy path
  - Bad JWT → SecretResolutionError
  - Role doesn't allow that path → SecretResolutionError
  - Field doesn't exist in secret → SecretResolutionError
  - Transient 503 + retry → success on retry 2
- (Optional) integration test against real bao container — deferred

**Done when:** unit tests against `fake_bao` green.

### Phase 7 — `NtfyApprover` (1–2 days)

- `approvers/ntfy.py`:
  - `request_approval(req, timeout_s)`:
    - generate `nonce` + `ack_token` (`secrets.token_urlsafe(32)`)
    - PUT bao kv at `hitl/pending/{nonce}` with `ack_token` + req metadata, TTL 5min (uses the same `SecretBackend` instance? No — separate bao client, since this is read+write+delete, not just read. Add a `BaoTransientStore` helper used only by `NtfyApprover`.)
    - publish to fixed topic with action buttons posting back to webhook
    - await `asyncio.Event` set by webhook handler
    - on timeout / error → cleanup bao entry, return TIMEOUT/REJECTED
  - webhook handler `/hitl/ack` (registered by hub, calls into approver):
    - parse nonce + posted ack_token + decision
    - read bao `hitl/pending/{nonce}` → compare ack_token (constant-time)
    - on match: set `asyncio.Event` for that nonce, store decision
    - on mismatch / not-found: log + ignore (always 200 OK to avoid oracle)
- `tests/fakes/fake_ntfy.py`:
  - tracks publishes; lets test code "tap" an action to trigger the webhook
- Tests:
  - Approve flow → APPROVED
  - Reject flow → REJECTED
  - Timeout → TIMEOUT
  - Bogus ack_token in webhook → ignored, original request still pending
  - Replay old ack_token (after bao TTL expired) → ignored
  - Concurrent approvals don't interfere (per-nonce isolation)

**Done when:** ntfy tests pass; manual phone test deferred to Phase 11.

### Phase 8 — Hub server (composing) (1–2 days)

- `factory.py`:
  - given a `secret_backend.name`, return the right impl with its config
  - same for `approver.name`
- `routing.py`:
  - `route(tool_name) → mcp_name` (split on first `_`)
- `server.py`:
  - FastMCP app
  - middleware: auth (sets `request.state.identity`)
  - `list_tools` filter using policy + identity
  - `call_tool` handler:
    1. policy lookup
    2. HITL gate via approver
    3. fanout dispatch
    4. audit
  - HITL ack route (`/hitl/ack`)
- `__main__.py`:
  - load `policy.yaml` (path from env `MCP_HUB_CONFIG`)
  - instantiate backends via factory
  - instantiate Fanouts (eager spawn — fail fast)
  - start server
- `tests/integration/test_hub_e2e.py`:
  - real hub + fake_authentik + fake_bao + AutoApprover + echo MCP
  - end-to-end: list_tools → call_tool → response
  - HITL flow with RejectApprover → POLICY_HITL_REJECTED
  - Disallowed tool → POLICY_REJECTED
  - Unknown identity → IDENTITY_UNKNOWN

**Done when:** integration tests green; can run hub locally and curl through it.

### Phase 9 — Dockerfile + compose (1 day)

- Multi-stage Dockerfile:
  - Stage `technitium-build`: clone forked Technitium MCP, build
  - Stage `runtime`: Python 3.13 + Node + `su-exec`
  - COPY hub source, install via uv
  - COPY MCP build outputs into `/app/mcps/<name>/`
  - Pre-allocate UIDs 1001–1099 in image
  - `USER` set; `CAP_SETUID` granted via compose
- `docker-compose.yml`:
  - one service: `mcp-hub`
  - port 8443:8443
  - secrets: `fanout_jwt`, `ntfy_publish_token`
  - env: `MCP_HUB_CONFIG=/etc/mcp-hub/policy.yaml`
  - bind mount `/etc/mcp-hub/policy.yaml` (or bake into image; v1: bind mount for fast iteration)
  - `cap_add: [SETUID, SETGID]`
  - `cap_drop: [ALL]` (then re-add the two)
  - memory limits
  - healthcheck on `/health`
- Smoke: `docker compose up`, hit `/health`, curl JWT-protected endpoint

**Done when:** container starts cleanly with example policy + fake JWT (using `EnvSecretBackend` + `AutoApprover` for first smoke).

### Phase 10 — Bootstrap docs + scripts (½ day)

- `scripts/bootstrap-bao.sh`:
  - enables JWT auth method (idempotent)
  - configures it against Authentik issuer
  - creates per-(mcp, identity) policies + roles
  - writes initial secrets (prompts for values; doesn't put them in source)
- `scripts/bootstrap-authentik.sh`:
  - uses Authentik admin API to create per-identity OAuth2 providers
  - reads from a `identities.yaml` listing
  - outputs client_id / client_secret to stdout (one-time)
- README section: "First-time setup"

**Done when:** scripts run cleanly against the real bao + Authentik.

### Phase 11 — End-to-end with technitium MCP (1 day)

- Forked `technitium-mcp-secure` repo: add DHCP tool handlers (parallel
  workstream — can start as early as Phase 2)
- Per-identity Technitium service accounts created in Technitium UI
- Per-identity bao secrets populated
- Caddy block for `mcp.pape.house` → `mcp.service.pape.house:8443`
- Real Authentik OAuth2 provider for `mcp-claude-code-dev`
- Test from Claude Code:
  - device flow → JWT
  - register `mcp.pape.house` as remote MCP
  - `list_tools` → curated set
  - `call_tool: technitium_dhcp_list_reservations` → result
  - `call_tool: technitium_dns_delete_record` → ntfy push to phone → approve → result

**Done when:** full chain works end-to-end with real Authentik + bao + ntfy + Technitium.

### Phase 12 — Run the CT hostname cleanup (½ day)

The deferred homelab task that's been waiting since
`project_ct_hostname_cleanup.md` was created. First real workload through
the new gateway. Validates multi-call flows + audit trail.

**Done when:** all CTs report `<name>.service` as their OS hostname; no
stale `<bare>.pape.house` A records in Technitium zone.

---

## Phase parallelism

Strict deps:
- Phase 0 → 1 → 2 → 8 → 9 → 11 → 12

Parallel-safe after Phase 1:
- 3 (auth), 4 (policy), 5 (audit), 6 (bao), 7 (ntfy) can all proceed
  in parallel.

Parallel-safe with Phase 9:
- 10 (bootstrap scripts) and the technitium MCP DHCP fork.

## Total estimate

~10–13 working days, single-developer. Faster if Phases 3–7 actually
run in parallel (they have no dependency between them).

## Open questions

1. **`pyjwt` vs `python-jose`.** Lean: `pyjwt` ≥2.10. python-jose has
   had CVE history around algorithm confusion; pyjwt's API is narrower
   and easier to audit. Either way, write the test that fails if a JWT
   with `kid` pointing to a URL is fetched.
2. **FastMCP version.** Pin to a specific minor at start; bump
   deliberately. Verify Streamable HTTP transport works as documented.
3. **`/hitl/ack` webhook on the same port as MCP, or separate?** Lean:
   same port, different path. Reduces compose surface; Caddy already
   routes `mcp.pape.house` to the right host.
4. **Caddy → hub auth.** v1: trust LAN. v2: mTLS. Authentik JWT is the
   actual auth, Caddy is just TLS terminator.
5. **HITL ack signature.** Currently the ack_token is a shared secret
   stored in bao. Stronger option: hub signs the ack URL with a
   per-request HMAC; webhook verifies signature. Defer to v2 unless ntfy
   ack_token-in-body proves leaky.
6. **Add a `/health` endpoint.** Yes, plain HTTP, no auth, just for
   docker healthcheck. Add to Phase 8.

## What we are NOT doing in v1

(Cross-reference with `architecture.md` § "Out of scope".)

- Admin UI
- DB-backed state
- Live identity / MCP add-and-remove without restart
- Live token rotation (restart-only for v1)
- HA / multi-instance
- Per-tool args allowlist (e.g., "only internal email addresses")
- Tool argument schema rewriting

These are all real future work; none are blockers for v1.

## When to migrate `mcp_fanout` to its own public repo

Triggers:
- It's been used to wrap ≥3 different MCPs successfully
- Tests have stayed green across ≥1 month of homelab use
- We've hit ≥1 thing we'd want to upstream from another homelabber's
  use case (means the design generalizes)
- The fanout's API surface has stabilized for ≥2 weeks (no breaking
  changes in policy.yaml fanout config)

When migrating, the homelab repo imports it as a normal pip dep.
