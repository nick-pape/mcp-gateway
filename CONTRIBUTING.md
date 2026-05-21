# Contributing

Thanks for your interest in `mcp-gateway`. This is an MCP gateway/hub: it
authenticates callers, enforces per-identity tool policy + HITL approvals, and
fans out to MCP servers. The core (`src/mcp_hub`, `src/mcp_fanout`) is designed
to be infrastructure-agnostic — secrets, auth, approvals, and token refresh are
pluggable behind interfaces.

## Dev environment

The project uses [uv](https://docs.astral.sh/uv/) and targets Python 3.13.

```bash
uv sync                       # create the venv from uv.lock (incl. dev tools)
uv run pytest                 # run the test suite
uv run pytest -m "not linux_only and not integration"   # fast unit subset
uv run ruff check .           # lint
uv run ruff format .          # format
uv run mypy                   # type-check (strict on src/)
```

## Pull requests

- `main` is protected: changes land via PR, **squash-merged**. No direct pushes.
- Keep PRs focused; write a clear title (it becomes the squash commit subject).
- CI runs lint, type-check, tests, and a Docker image build — get it green.
- Don't commit secrets or live deployment config. The repo ships
  `policy.example.yaml`; real `policy.yaml` is gitignored.

## Writing a plugin (no fork required)

The hub discovers plugins via Python entry points — declare them in your own
package's `pyproject.toml` under the matching group and install side-by-side.
Resolution is entry-point first, then a dotted-path fallback
(`my_pkg.module:MyClass`); see `src/mcp_hub/refresher/registry.py`.

Current and planned groups:

| Group | Interface | Status |
|---|---|---|
| `mcp_hub.token_sources` | `TokenSource` (mint/rotate tokens) | available |
| `mcp_hub.token_sinks` | `TokenSink` (write rotated tokens) | available |
| `mcp_hub.secret_backends` | `SecretBackend` | planned (see #8) |
| `mcp_hub.approvers` | `Approver` | planned (see #11) |

Implement the Protocol from `src/mcp_hub/interfaces.py` (or
`refresher/protocols.py`), declare the entry point, and select it by name in
`policy.yaml`. Add unit tests using the fakes in `tests/fakes/`.

## Reporting security issues

See [SECURITY.md](./SECURITY.md) — please report privately, not via issues.
