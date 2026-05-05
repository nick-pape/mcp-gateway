# Architecture: `mcp.pape.house` — single-container hub with in-process fanout

> Sister doc: [`landscape.md`](./landscape.md) for the survey that led to
> "build" instead of adopt.

## Vision

A **single docker compose service** running an MCP gateway that:

1. Authenticates inbound calls via **Authentik OIDC JWT** (audience-per-identity)
2. **Curates `list_tools`** per identity (disallowed tools are *invisible*
   to the agent's LLM, never auto-rejected)
3. Applies per-tool **HITL policy** on `call_tool` (`auto-approve` /
   `push-approve` / `reject`)
4. **Multiplexes per-identity stdio MCP children** via the in-process
   `Fanout` module — one stdio process per (MCP × identity) tuple,
   each running as a distinct UID
5. **Audits** every request and tool call (JSONL → Loki)

LiteLLM is not in this picture. Agents drive their own tool-use loops
and reach the gateway directly.

## Component diagram

```mermaid
flowchart TB
    subgraph agents["Agents"]
        A1[ironclaw]
        A2[paperless-bot]
        A3[claude-code-dev]
    end

    AUTH[("Authentik<br/>auth.pape.house")]
    BAO[("bao<br/>secrets.pape.house")]
    NTFY[("ntfy<br/>notify.service.pape.house")]

    CADDY["Caddy<br/>caddy.service.pape.house"]

    subgraph mcp_lxc["mcp.service.pape.house LXC — single container"]
        HUB["Hub (FastMCP, Python, ~250 LoC)<br/>- JWT validate (aud → identity)<br/>- Policy: list_tools filter + HITL<br/>- Audit"]

        subgraph fanouts["In-process Fanout instances"]
            F1["Fanout(technitium)"]
            F2["Fanout(paperless)"]
            F3["Fanout(authentik)"]
        end

        subgraph stdio_children["Stdio children (su-exec'd to distinct UIDs)"]
            T1[(technitium<br/>UID 1001<br/>ironclaw)]
            T2[(technitium<br/>UID 1002<br/>paperless-bot)]
            T3[(technitium<br/>UID 1003<br/>claude-code-dev)]
            P1[(paperless<br/>UID 1011<br/>ironclaw)]
            P2[(paperless<br/>UID 1012<br/>paperless-bot)]
            AK1[(authentik<br/>UID 1021<br/>claude-code-dev)]
        end
    end

    A1 -->|JWT aud=mcp-ironclaw| CADDY
    A2 -->|JWT aud=mcp-paperless-bot| CADDY
    A3 -->|JWT aud=mcp-claude-code-dev| CADDY
    CADDY -->|Streamable HTTP| HUB

    HUB --> F1
    HUB --> F2
    HUB --> F3

    F1 -.->|stdio pipe| T1
    F1 -.->|stdio pipe| T2
    F1 -.->|stdio pipe| T3
    F2 -.->|stdio pipe| P1
    F2 -.->|stdio pipe| P2
    F3 -.->|stdio pipe| AK1

    HUB -.->|JWKS fetch + serve-stale-on-failure| AUTH
    HUB -->|push approval| NTFY
    NTFY -->|webhook ack| HUB

    F1 -.->|JWT swap (per identity at boot)| BAO
    F2 -.->|JWT swap (per identity at boot)| BAO
    F3 -.->|JWT swap (per identity at boot)| BAO
```

Containers: **1**. Stdio children: M × N (M MCP types × N identities).
All siblings, all in the same container, isolated by UID.

## End-to-end flow

1. **Agent → Caddy.** POST to `https://mcp.pape.house/mcp` with
   `Authorization: Bearer <Authentik-JWT>`. The JWT's `aud` claim is the
   agent's identity (`mcp-ironclaw`, `mcp-paperless-bot`, etc.).
2. **Caddy** terminates TLS, forwards to `mcp.service.pape.house:8443`.
3. **Hub auth middleware:** validates the JWT against pinned Authentik
   JWKS, extracts identity from `aud` claim. Attaches
   `request.state.identity` (e.g., `"ironclaw"`).
4. **`list_tools`:** hub returns only tools whose name matches the
   identity's `allowed_tools` glob list. The LLM never sees
   `authentik_*_delete` if `ironclaw` doesn't have it.
5. **`call_tool`:** hub middleware:
   - Look up policy: `auto-approve` / `push-approve` / `reject`
   - On `reject` → MCP error `POLICY_REJECTED`
   - On `push-approve` → ntfy push with bao-stored ack token; await
     webhook ack; on timeout → `POLICY_HITL_TIMEOUT`
   - On `auto-approve` → straight through
6. **Hub → Fanout:** call `fanout.call(identity, request)`. Hub picks
   the right `Fanout` instance by tool prefix
   (`technitium_*` → `Fanout(technitium)`).
7. **Fanout → stdio child:** writes JSON-RPC to that child's stdin,
   awaits response on its stdout. The child uses its bao-injected
   token-file (`/run/ironclaw-technitium-token`, mode 0400 owned by
   UID 1001) to call the upstream service API.
8. **Result** bubbles back through fanout → hub → agent. Audit line
   written at hub egress.

## Hub responsibilities

```python
# ~250 LoC of Python. Pseudocode shape:

from fastmcp import FastMCP
from .fanout import Fanout
from .auth import AuthentikJWTValidator
from .hitl import NtfyApprover

mcp = FastMCP("mcp.pape.house")
auth = AuthentikJWTValidator(jwks_uri=PINNED_JWKS_URI, audience_prefix="mcp-")
hitl = NtfyApprover(...)
policy = Policy.load("/etc/mcp-pape-house/policy.yaml")

# One Fanout per MCP type. Eager spawn at startup (per design choice 1).
fanouts = {
    "technitium": Fanout(
        mcp_name="technitium",
        command=["node", "/app/mcps/technitium/dist/index.js"],
        identities=policy.identity_secrets("technitium"),
    ),
    "paperless": Fanout(...),
    "authentik": Fanout(...),
}
for f in fanouts.values():
    f.start_eager_or_die()  # bao swap per identity, spawn all children;
                            # any failure → exit nonzero (per design choice 2)

@mcp.middleware
async def auth_middleware(request, call_next):
    jwt = strip_bearer(request.headers["Authorization"])
    claims = auth.validate(jwt)               # signature + aud + iss + exp
    request.state.identity = claims["aud"].removeprefix("mcp-")
    return await call_next(request)

@mcp.tool_call_handler
async def route(request, identity):
    tool = request.params.name
    if tool not in policy.allowed_tools(identity):
        return mcp_error("POLICY_REJECTED")
    decision = policy.hitl_decision(identity, tool)
    if decision == "reject":
        return mcp_error("POLICY_REJECTED")
    if decision == "push-approve":
        ok = await hitl.approve(identity=identity, tool=tool, args=request.params.args)
        if not ok:
            return mcp_error("POLICY_HITL_REJECTED")
    fanout = fanouts[mcp_prefix(tool)]
    return await fanout.call(identity, request)
```

## Fanout module (in-process)

The fanout is a Python class, not a separate process. It holds N stdio
child processes (one per identity), each as a distinct UID, and routes
incoming requests to the correct child.

```python
# ~200 LoC. Packaged separately as `mcp-fanout` so it's reusable
# without our hub. Hub imports it; standalone CLI also possible.

class Fanout:
    def __init__(self, mcp_name: str, command: list[str],
                 identities: dict[str, IdentityConfig]):
        # IdentityConfig holds: bao path, allocated UID, env-var name MCP expects
        self.mcp_name = mcp_name
        self.command = command
        self.identities = identities
        self.children: dict[str, ChildProcess] = {}

    async def start_eager_or_die(self):
        # Per design choice 2: any identity failure → exit nonzero,
        # whole stack restarts. Live token rotation handled later.
        for identity, cfg in self.identities.items():
            try:
                await self._spawn(identity, cfg)
            except Exception:
                logger.exception(f"failed to start {self.mcp_name}/{identity}")
                sys.exit(1)

    async def _spawn(self, identity: str, cfg: IdentityConfig):
        # 1. bao OIDC swap → ephemeral bao token bound to this fanout's role,
        #    scoped to read THIS identity's secret path
        bao_token = await bao_oidc_swap(
            role=f"mcp-{self.mcp_name}-{identity}",
            jwt=read("/run/secrets/fanout_jwt"),
        )
        # 2. read secret
        secret = await bao_kv_get(bao_token, cfg.secret_path, cfg.secret_field)
        # 3. write to per-UID tmpfs file mode 0400 owned by cfg.uid
        path = f"/run/{identity}-{self.mcp_name}-token"
        write_token_file(path, secret, owner_uid=cfg.uid, mode=0o400)
        # 4. spawn child via su-exec to cfg.uid; pass token-file path via env
        proc = await asyncio.create_subprocess_exec(
            "su-exec", f"{cfg.uid}:{cfg.uid}", *self.command,
            env={cfg.token_env_name: path},   # e.g., TECHNITIUM_TOKEN_FILE
            stdin=PIPE, stdout=PIPE, stderr=PIPE,
        )
        self.children[identity] = ChildProcess(proc, lock=asyncio.Lock())

    async def call(self, identity: str, request: dict) -> dict:
        child = self.children.get(identity)
        if child is None:
            raise IdentityNotFound(identity)
        async with child.lock:                  # one in-flight call per child
            child.proc.stdin.write(json.dumps(request).encode() + b"\n")
            await child.proc.stdin.drain()
            line = await child.proc.stdout.readline()
            return json.loads(line)
```

### Per-UID isolation: why and how

`/proc/<pid>/environ` shows the env that was passed to `exec()`. Even if
the MCP `unsetenv()`s after reading, the original environ persists in
/proc and is readable by any process running as the same UID.

In a single-container fanout where all children share UID 1000, a
compromised `paperless-bot` child can `cat /proc/<sibling-pid>/environ`
and read `ironclaw`'s Technitium token. The compromise vector is real
in this threat model: a poisoned tool result string with executable
content getting reflected through the MCP's parser.

Mitigations stacked:

1. **Each child runs as a distinct UID** allocated at hub startup
   (`1001`, `1002`, …). Linux blocks cross-UID `/proc/*/environ` reads.
2. **Secrets are passed via token-files**, not env vars. Even within the
   same UID, the env never had the secret (the env has a *path*; the
   secret is in a file mode 0400 owned by the child's UID).
3. **Forked MCPs sanitize their own outputs.** Defense in depth.

The hub container starts with `cap_add: [CAP_SETUID, CAP_SETGID]` and
no other capabilities. After spawning all children, the hub itself
continues running as a single unprivileged UID (it doesn't need
privileged operations after eager spawn).

## Image structure (multi-stage)

```dockerfile
# === Build stages: one per MCP, parallelizable ===
FROM node:22-alpine AS technitium-build
WORKDIR /src
RUN git clone --depth 1 --branch main \
    https://github.com/nick-pape/technitium-mcp-secure /src && \
    npm ci && npm run build

FROM python:3.13-slim AS paperless-build
WORKDIR /src
RUN pip install uv && \
    uv pip install --system paperless-mcp@git+https://github.com/.../paperless-mcp@vX.Y.Z

FROM golang:1.23-alpine AS portainer-build   # hypothetical Go MCP later
# ...

# === Runtime ===
FROM python:3.13-slim AS runtime
RUN apt-get update && apt-get install -y \
    nodejs su-exec ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Hub + fanout module
COPY hub/ /app/hub/
RUN pip install /app/hub  # installs `mcp-fanout` and the hub package

# MCP source from build stages
COPY --from=technitium-build /src/dist /app/mcps/technitium/dist
COPY --from=technitium-build /src/node_modules /app/mcps/technitium/node_modules
COPY --from=paperless-build /usr/local/lib/python3.13/site-packages /app/mcps/paperless/

# Pre-allocate UIDs that the fanout will spawn into
RUN for i in $(seq 1001 1099); do \
      adduser --disabled-password --uid $i --gecos "" --no-create-home mcp-$i || true; \
    done

# Hub runs as unprivileged UID 1000 with CAP_SETUID added at compose level
RUN adduser --disabled-password --uid 1000 --gecos "" hub
USER hub

ENTRYPOINT ["python", "-m", "hub"]
```

Adding a new MCP:

1. Add a new build stage to the Dockerfile (one git URL + build command)
2. Add a `COPY --from=...` line for the runtime stage
3. Add the MCP to `policy.yaml` (which identities, allowed tools, HITL)
4. Rebuild + redeploy

## Authentik configuration

One **OAuth2/OpenID Provider** per agent identity. Each issues JWTs
with a distinct audience claim:

| Authentik provider name | Audience | Used by |
|---|---|---|
| `mcp-ironclaw` | `mcp-ironclaw` | IronClaw autonomous agent |
| `mcp-paperless-bot` | `mcp-paperless-bot` | paperless processing bot |
| `mcp-claude-code-dev` | `mcp-claude-code-dev` | local Claude Code dev sessions |
| `mcp-fanout-svc` | `mcp-fanout-svc` | fanout itself, for bao swap |

The hub validates `aud == "mcp-<identity>"` and uses the suffix as the
identity name. No identity DB beyond the policy YAML.

Agents authenticate via:
- **Autonomous agents**: client_credentials grant, client_id+secret
  stored in their environment (their concern, not ours)
- **Claude Code dev**: device flow on first run, refresh token cached
- **n8n / scripts**: client_credentials with HTTP node

## bao configuration

### Per-identity-per-MCP roles

For each (MCP × identity) tuple, a JWT auth role bound to a narrow
policy that reads exactly one secret path:

```hcl
# bao policy: mcp-technitium-ironclaw
path "secret/data/services/technitium/ironclaw" {
  capabilities = ["read"]
}
```

```hcl
# bao role bound to fanout's JWT identity, allowed for one path per identity
{
  "role_type": "jwt",
  "user_claim": "sub",
  "bound_audiences": ["mcp-fanout-svc"],
  "bound_subject":   "mcp-fanout-svc",
  "policies":        ["mcp-technitium-ironclaw"],
  "ttl":             "1h",
  "max_ttl":         "1h"
}
```

The fanout container holds **one** long-lived JWT (the
`mcp-fanout-svc` identity). For each (MCP × identity) at boot, it
swaps that JWT at bao for an ephemeral bao token bound to that one
narrow path, reads the secret, drops the token. Container memory only.

The fanout's own JWT is mounted as a docker secret, mode 0400, owned
by UID 1000. The unprivileged hub user (1000) reads it once at startup;
children (1001+) never see it.

### Secret layout

```
secret/services/
  technitium/
    ironclaw         { api_token: "..." }
    paperless-bot    { api_token: "..." }
    claude-code-dev  { api_token: "..." }
  paperless/
    ironclaw         { api_token: "..." }
    paperless-bot    { api_token: "..." }
  authentik/
    claude-code-dev  { api_token: "..." }
```

Per-identity tokens give true upstream attribution: Technitium audit
log shows `ironclaw-svc` (the Technitium-side service account) made
the change, not "the gateway."

For services where one shared token is acceptable (or required, e.g.,
Paperless without per-user accounts), all identities point at the same
secret path: `secret/services/paperless/shared`.

## Tool curation + HITL: `policy.yaml`

```yaml
version: 1
identities:
  ironclaw:
    aud: "mcp-ironclaw"
    uid_base: 1001            # ironclaw's children get UIDs 1001, 1011, 1021...
    allowed_tools:
      - "technitium_dns_*"
      - "technitium_dhcp_list_*"
      - "paperless_get_*"
      - "paperless_search_*"
    hitl:
      defaults: auto-approve
      overrides:
        "technitium_dns_delete_record":   push-approve
        "technitium_dns_add_record":      push-approve
    secrets:
      technitium: { path: "secret/data/services/technitium/ironclaw", field: "api_token", env: "TECHNITIUM_TOKEN_FILE" }
      paperless:  { path: "secret/data/services/paperless/shared",    field: "api_token", env: "PAPERLESS_TOKEN_FILE" }

  paperless-bot:
    aud: "mcp-paperless-bot"
    uid_base: 1002
    allowed_tools: ["paperless_*"]
    hitl: { defaults: auto-approve }
    secrets:
      paperless: { path: "secret/data/services/paperless/shared", field: "api_token", env: "PAPERLESS_TOKEN_FILE" }

  claude-code-dev:
    aud: "mcp-claude-code-dev"
    uid_base: 1003
    allowed_tools: ["*"]
    hitl:
      defaults: auto-approve
      overrides:
        "technitium_dns_delete_record":   push-approve
        "technitium_dhcp_remove_*":       push-approve
        "authentik_*_create":             push-approve
        "authentik_*_delete":             push-approve
    secrets:
      technitium: { path: "secret/data/services/technitium/claude-code-dev", field: "api_token", env: "TECHNITIUM_TOKEN_FILE" }
      paperless:  { path: "secret/data/services/paperless/shared",          field: "api_token", env: "PAPERLESS_TOKEN_FILE" }
      authentik:  { path: "secret/data/services/authentik/claude-code-dev", field: "api_token", env: "AUTHENTIK_TOKEN_FILE" }
```

Hub watches `policy.yaml` and reloads on change for tool/HITL changes;
identity-set changes (add/remove identities, add/remove MCPs) require
restart (per design choice 2: simple eager v1).

## HITL via ntfy: fixed topic + bao-stored ack token

```python
async def push_approve(identity: str, tool: str, args: dict) -> bool:
    nonce = secrets.token_urlsafe(32)
    ack_token = secrets.token_urlsafe(48)

    # Store expected ack_token in bao with TTL
    await bao_kv_put(f"hitl/pending/{nonce}",
                     {"ack_token": ack_token, "tool": tool, "identity": identity},
                     ttl="300s")

    # Publish to FIXED ntfy topic. ntfy publish auth gates who can post here.
    await ntfy_publish(
        topic="mcp-hitl-approvals",
        title=f"[{identity}] {tool}?",
        message=render_args(args),
        actions=[
            {"action":"http","label":"Approve",
             "url":f"https://mcp.pape.house/hitl/ack?nonce={nonce}",
             "method":"POST",
             "body":json.dumps({"ack_token":ack_token,"decision":"approve"})},
            {"action":"http","label":"Reject",
             "url":f"https://mcp.pape.house/hitl/ack?nonce={nonce}",
             "method":"POST",
             "body":json.dumps({"ack_token":ack_token,"decision":"reject"})},
        ],
    )

    try:
        decision = await asyncio.wait_for(_pending[nonce].wait(), timeout=120)
        return decision == "approve"
    except asyncio.TimeoutError:
        return False
    finally:
        await bao_kv_delete(f"hitl/pending/{nonce}")
```

Properties:

- **Fixed topic** (`mcp-hitl-approvals`) — phone subscribes once, no
  wildcards needed (ntfy doesn't support them; multi-topic comma-list
  works but isn't necessary here)
- **ntfy publish auth** — only the hub can push to this topic; topic
  publish key stored in bao
- **Ack token validated against bao** — knowing the topic doesn't let
  an attacker self-approve; only the hub generates valid ack_tokens
- **Async webhook-driven** — no polling, no event-loop blocking
- **Fixed timeout** — explicit reject after 120s; pending state
  self-destructs via bao TTL even if hub crashes

## Security findings, addressed explicitly

| Finding | Mitigation |
|---|---|
| JWT `kid`-as-URL hijack | JWKS URI pinned at startup; `kid` resolved against cached JWKS only; explicit `algorithms=["RS256"]` |
| Cross-identity `/proc/environ` exfil | Each child runs as distinct UID; secrets via per-UID token-files (mode 0400), never env |
| Token in env via `/proc` | Same fix — env contains the *path*, not the secret |
| ntfy self-approval if topic guessable | Fixed topic + ntfy publish auth; the secret is the bao-stored ack_token, not the topic |
| JWKS cache cold-fail | Serve-stale-on-failure for warm cache; cold-start failure propagates (no fail-open) |
| Sync-blocking HITL polling | Fully async; webhook-driven, not polling; per-request timeout |
| Pending HITL evaporates on reboot | bao TTL on pending entries (5 min); restart returns clean `HITL_TIMEOUT` to in-flight callers |
| Hub OOM kills everything | Container memory limits + healthcheck + Portainer auto-restart; failure mode is "all-down" not "silent half-up" |

## Audit + observability

JSONL on stderr → Loki via Promtail.

```json
{
  "ts": "2026-05-05T17:23:01.234Z",
  "request_id": "01HXY...",
  "identity": "ironclaw",
  "method": "tools/call",
  "tool": "technitium_dhcp_set_reservation",
  "args_hash": "sha256:...",
  "decision": "auto-approve",
  "fanout": "technitium",
  "child_uid": 1001,
  "status": "ok",
  "duration_ms": 142,
  "hitl_duration_ms": 0
}
```

Args hashed by default; per-tool flag in policy unlocks full args
(debugging only).

Error code taxonomy:

- `POLICY_REJECTED` — tool not in identity's `allowed_tools`
- `POLICY_HITL_REJECTED` — operator rejected via ntfy
- `POLICY_HITL_TIMEOUT` — operator didn't respond in time
- `AUTH_FAILED` — JWT invalid / expired / wrong audience
- `IDENTITY_UNKNOWN` — JWT valid but `aud` not in policy.yaml
- `BACKEND_CHILD_DEAD` — fanout's stdio child crashed
- `INTERNAL_ERROR` — gateway bug; alert

## Build sequence

1. **Stand up `mcp.service.pape.house` LXC + Portainer** via `add-service-ct` skill
2. **bao setup**:
   - Enable JWT auth method against Authentik issuer
   - Per-MCP-per-identity policies (e.g., `mcp-technitium-ironclaw`)
   - Per-identity-per-MCP secrets at `secret/services/<mcp>/<identity>`
3. **Authentik setup**:
   - One OAuth2/OpenID Provider per identity (`mcp-ironclaw`, etc.)
   - One for the fanout itself (`mcp-fanout-svc`) — JWT mounted into container
4. **Forked Technitium MCP**: add DHCP tool handlers (parallel workstream)
5. **`mcp-fanout` Python module** (~200 LoC). Standalone tests with
   fake stdio MCP first.
6. **Hub** (~250 LoC): JWT validation + policy + HITL approver +
   import fanout. End-to-end test with a single fake MCP and 2
   identities.
7. **Multi-stage Dockerfile** with Technitium MCP first.
8. **Caddy block** for `mcp.pape.house` (TLS terminate; no mTLS in v1
   — Authentik JWT is the auth)
9. **End-to-end smoke**: Claude Code → Authentik device flow →
   `mcp.pape.house` → list_tools (curated) → call_tool (auto-approve) → result
10. **HITL smoke**: trigger a `push-approve` tool from Claude Code,
    receive ntfy push, approve, see result
11. **Run the CT hostname cleanup** through this path. First real use
    end-to-end validation.
12. **Add additional MCPs** (Authentik, Paperless, etc.) one stage at
    a time in the Dockerfile.

## Open design questions

1. **Live token rotation.** Per design choice 2: out of scope for v1
   — restart the stack to rotate. v2 candidate: fanout exposes an HTTP
   admin endpoint (auth via local socket / shared secret) to trigger
   per-(MCP, identity) child restart with fresh bao swap.
2. **Per-tool args allowlist.** E.g., `paperless_send_email` only to
   internal addresses. Out of scope for v1. Add as a hub middleware
   layer later.
3. **Audit args-when-non-sensitive.** v1: always hash. v2: per-tool
   override flag in policy.
4. **Single-instance HA.** Out of scope. If hub dies, restart via
   Portainer; agents see brief auth errors.
5. **Adding a new identity hot.** v1 requires restart. v2 candidate:
   fanout admin endpoint + signal-based child spawn.

## Out of scope (deliberately)

- Admin UI
- DB-backed state
- LiteLLM integration (agents reach LiteLLM independently if they want)
- A2A registry (separate concern)
- Tool argument schema rewriting / transformation
- HA / multi-instance
- Live identity / MCP add-and-remove without restart
