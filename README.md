# mcp.pape.house

Homelab MCP (Model Context Protocol) gateway. Single docker container,
in-process Fanout module, Authentik OIDC auth, ntfy HITL push approvals,
bao-injected per-identity secrets.

See:

- [`architecture.md`](./architecture.md) — design contract
- [`landscape.md`](./landscape.md) — why we're building rather than adopting
- [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) — phased build plan

## Status

In active development. Not yet deployed.

## Quickstart (dev)

```powershell
uv sync
uv run pytest -q
uv run ruff check src/
uv run mypy --strict src/
```

## First-time deploy (placeholder)

Follow `IMPLEMENTATION_PLAN.md` Phases 9–11. Bootstrap scripts at
`scripts/bootstrap-bao.sh`. Authentik OAuth2 provider setup is manual —
see this README's "Authentik setup" section once Phase 10 is done.
