# vikunja MCP

Upstream: [`@democratize-technology/vikunja-mcp`](https://github.com/democratize-technology/vikunja-mcp)
(npm-published, TypeScript). Pinned in the hub `Dockerfile`'s
`vikunja-install` stage by exact version (`0.2.0` at last bump — latest
npm-published, even though the upstream master has bumped package.json
to 0.2.2 without publishing).

## What it does

Surfaces ~10 subcommand-style tools (`vikunja_tasks`, `vikunja_projects`,
`vikunja_labels`, `vikunja_teams`, `vikunja_users`, `vikunja_webhooks`,
`vikunja_batch_import`, ...) talking to `https://tasks.pape.house/api/v1`.
Subcommands like `vikunja_tasks list`, `vikunja_tasks create`,
`vikunja_tasks bulk-update` mean a small surface for the hub but full
CRUD underneath.

## Auth model

Vikunja per-user **API tokens** (`tk_*`), minted in the Vikunja UI under
Settings → API Tokens (no CLI / API path to mint one as of v2.3.0). Each
hub identity gets its own Vikunja user + its own token. Single-user for
now — `interactive` identity only — with future per-claw expansion.

Tokens live in bao at `secret/services/vikunja/{identity}` field
`api_token`.

The hub writes the token value to a tmpfs file at
`/run/mcp-tokens/<uid>-vikunja` (mode 0400, chown'd to the per-identity
child UID) and sets `VIKUNJA_API_TOKEN_FILE` in the child's env.

`run.sh` in this folder is a tiny shell wrapper: cats the file, exports
`VIKUNJA_API_TOKEN`, exec's the upstream MCP binary. The wrapper is
needed because the upstream reads only `VIKUNJA_API_TOKEN` directly
(matches the `npx -y` install flow in the upstream README) — we use the
`_FILE` indirection so the secret never appears in process listings or
the docker inspect output.

## Drift detection

If upstream renames its tools, the hub's HITL globs in
[`policy.yaml`](../policy.yaml) (`vikunja_*list*`, `vikunja_*get*`,
`vikunja_*create*`, etc.) may stop matching. Easy detection: the hub
logs each tool's name on startup; grep for `vikunja_` after a redeploy
and confirm the expected subcommand surface is present.

## Updating

1. Bump the version pin in `mcp.service.pape.house/Dockerfile` (search
   for the `vikunja-install` stage).
2. Commit + push.
3. Portainer auto-rebuilds the hub image; the new MCP binary lands.
4. Verify the new tool surface in hub logs.

## Rebuild on demand

The MCP install is done in a build-cached stage, so changing
`policy.yaml` alone does NOT trigger a re-install. If you change the
pinned version OR any file in this folder, the hub rebuild grabs the
new binary.
