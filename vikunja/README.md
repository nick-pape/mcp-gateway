# vikunja MCP + proxy

Two-piece integration:

1. **Upstream**: [`@democratize-technology/vikunja-mcp`](https://github.com/democratize-technology/vikunja-mcp)
   (npm-published, TypeScript). Pinned in the hub `Dockerfile`'s
   `vikunja-install` stage by exact version (`0.2.0` at last bump —
   latest npm-published, even though the upstream master has bumped
   package.json to 0.2.2 without publishing).
2. **`proxy.js`** in this folder — a thin stdio-in-stdio Node proxy that
   sits between the hub and the upstream. It explodes upstream's
   ~10 composite tools (each driven by a `subcommand` or `action` enum)
   into ~70+ per-subcommand granular tools, so the hub's HITL policy
   can glob-match read-vs-write at tool-name granularity.

## Why proxy.js exists

Upstream groups everything into composite tools:

```
vikunja_tasks subcommand ∈ {create, get, update, delete, list, assign, comment,
                             bulk_create, bulk_update, bulk_delete, attach, ...}  (22 subcommands)
vikunja_projects subcommand ∈ {create, get, update, delete, list, archive,
                                create_share, get_tree, move, ...}  (16 subcommands)
vikunja_labels subcommand ∈ {list, get, create, update, delete}
vikunja_teams ...        (6 subcommands)
vikunja_templates ...    (6 subcommands)
vikunja_webhooks ...     (6 subcommands)
vikunja_auth ...         (4 subcommands)
vikunja_filters action ∈ {list, get, create, update, delete, build, validate}  (uses `action` not `subcommand`)
vikunja_batch_import     (single-op, no enum)
```

The hub's HITL policy globs on **tool names**, not call arguments, so
without exploding it can't tell `vikunja_tasks subcommand=list` (safe)
from `vikunja_tasks subcommand=delete` (destructive). The two choices
without a proxy are: every call buzzes phone (annoying), or nothing does
and agents can mass-delete (dangerous).

The proxy rewrites the composite surface into granular tools — same
problem and solution as [`email-mcp-proxy`](../email-mcp-proxy/) one
floor up the stack, just stdio-in-stdio instead of HTTP-in-HTTP because
the upstream is stdio.

## Architecture

```
hub stdio ──> /app/mcps/vikunja/run.sh ──> proxy.js ──stdio─> @democratize-technology/vikunja-mcp
                                            │
                                            ├ tools/list:  intercept upstream response,
                                            │              replace ~10 composite tools
                                            │              with ~70+ granular tools
                                            ├ tools/call:  look up granular name →
                                            │              (composite, subcommand|action),
                                            │              inject the enum arg, forward
                                            └ everything else: passthrough unchanged
```

The proxy is one process: spawned by `run.sh` (the per-identity
stdio child of the hub), spawns the upstream MCP as its own stdio child,
pipes stdio in/out with JSON-RPC line buffering.

### Runtime discovery, not hand-rolled schemas

`tool-schemas.json` and similar are intentionally **not** used here.
The proxy queries upstream's `tools/list` on the first hub call,
parses each composite's `subcommand` or `action` enum, and builds the
granular tool list dynamically. This means upstream drift — new
subcommand values, renamed enums — is picked up automatically on the
next hub restart with no maintenance required.

The trade-off vs `email-mcp-proxy`'s hand-authored
`tool-schemas.yaml`: we don't get a CI-test signal when upstream renames
a subcommand. If `vikunja_tasks subcommand: list` becomes
`vikunja_tasks subcommand: ls` in some future release, our policy.yaml's
`vikunja_*_list` glob silently stops matching → those calls fall through
to push-approve. Annoying but not unsafe. If this becomes painful, we
swap to a hand-authored schema with a drift test.

## Tool name mapping rules

For each upstream composite tool with a `subcommand` or `action` enum:

| Composite | Subcommand value | Granular tool name |
|---|---|---|
| `vikunja_tasks` | `list` | `vikunja_tasks_list` |
| `vikunja_tasks` | `bulk-create` | `vikunja_tasks_bulk_create` (hyphen→underscore) |
| `vikunja_projects` | `get-tree` | `vikunja_projects_get_tree` |
| `vikunja_filters` | `validate` (action) | `vikunja_filters_validate` |
| `vikunja_batch_import` | — (no enum) | `vikunja_batch_import` (passthrough) |

The `subcommand`/`action` field is removed from the granular schema
(it's injected server-side per granular tool). All other fields stay,
including any that were required on the composite but irrelevant to a
specific subcommand — that's an upstream design quirk
(e.g. `vikunja_filters` requires `parameters: {}` for every action,
including `list`).

## Auth model (unchanged)

Vikunja per-user **API tokens** (`tk_*`), minted in the Vikunja UI under
Settings → API Tokens (no CLI / API path to mint one as of v2.3.0).

Tokens live in bao at `secret/services/vikunja/{identity}` field
`api_token`. The hub writes the token value to a tmpfs file at
`/run/mcp-tokens/<uid>-vikunja` (mode 0400, chown'd to the per-identity
child UID) and sets `VIKUNJA_API_TOKEN_FILE` in the child's env.

`run.sh` slurps the file, exports `VIKUNJA_API_TOKEN`, then exec's
`proxy.js`. proxy.js inherits that env when spawning the upstream child.
Token never appears in process listings or `docker inspect` output.

## Updating

1. **Upstream version bump**: change `VIKUNJA_MCP_VERSION` in the
   `Dockerfile`'s `vikunja-install` stage. Commit + push. Portainer
   auto-rebuilds the hub image; the new npm-installed package replaces
   the old one. Granular tool list re-derives automatically on hub boot.
2. **Proxy logic changes** (rare): edit `proxy.js`, commit + push,
   rebuild. The proxy has no external state — restart is free.

## Operational expectations

- **Tool count visible to hub**: ~70+ (was 9 pre-proxy). Hub's
  `tools/list` cache size grows accordingly.
- **Latency added by proxy**: <1ms per call (JSON-RPC line parse + map
  lookup + line emit). Stays well under the per-call hub→upstream RTT
  which is dominated by the actual Vikunja API call.
- **Memory**: proxy.js holds the routing map (~70 entries) + pending
  request map (transient). <5 MB overhead vs upstream alone.

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| `tools/list` returns 9 composite tools | proxy.js not loaded (run.sh still exec'ing upstream directly) | check `/app/mcps/vikunja/run.sh` final exec line; rebuild |
| Granular call returns "tool not found" upstream | granular name not in routing map | check upstream actually has that subcommand; possible drift |
| Upstream child crash → proxy exits | upstream npm package broken | look at stderr (forwarded inherit); pin to known-good version |
| Hub fanout init timeout | proxy or upstream hung at startup | `docker exec mcp-hub` and inspect; usually a config issue |

## TODO

- [ ] CI drift test: spawn a real upstream container, request its
  `tools/list`, diff against a recorded snapshot. Fails CI on any
  upstream rename so we update policy.yaml glob patterns before deploy.
- [ ] Per-claw bootstrap script (`scripts/bin/bootstrap-claw-vikunja.sh`)
  — covered in the parent `vikunja.service.pape.house/README.md` TODO.
