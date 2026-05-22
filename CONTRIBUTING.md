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
  `policy.example.yaml`; real `policy.yaml` is gitignored. Secret scanning
  runs in CI and blocks merges (see below).

## Secret scanning

Secrets are caught by [gitleaks](https://github.com/gitleaks/gitleaks) at two
points, both using [`.gitleaks.toml`](./.gitleaks.toml):

- **CI** — `.github/workflows/secrets.yml` scans the full git history on every
  push and PR and fails the build on any finding.
- **Pre-commit (recommended)** — install the hook so staged changes are
  scanned before they leave your machine:

  ```bash
  pip install pre-commit && pre-commit install
  ```

Run it ad-hoc against the whole tree:

```bash
gitleaks detect --config .gitleaks.toml --redact          # native install
# or, no install needed:
docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --config /repo/.gitleaks.toml --redact
```

Beyond the upstream default ruleset, `.gitleaks.toml` adds a rule for opaque
high-entropy tokens behind a secret-ish prefix (e.g. a `private_<random>`
token embedded in a URL path) — the class that slips past naive scans.
A planted `secret_`/`token_`/`private_` value followed by a long random run
fails the gate; ordinary identifiers like `secret_backend` or `token_refresh`
do not.

This is defense-in-depth alongside GitHub's native secret scanning + push
protection, which we also enable once the repository is public.

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
| `mcp_hub.secret_backends` | `SecretBackend` | available (built-ins: `env`, `file`, `bao`) |
| `mcp_hub.approvers` | `Approver` | available (built-ins: `auto`, `reject`, `ntfy`) |

Implement the Protocol from `src/mcp_hub/interfaces.py` (or
`refresher/protocols.py`), declare the entry point, and select it by name in
`policy.yaml`. Add unit tests using the fakes in `tests/fakes/`.

## Reporting security issues

See [SECURITY.md](./SECURITY.md) — please report privately, not via issues.
