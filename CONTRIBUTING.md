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

Four of the hub's seams are pluggable via Python **entry points** — install a
package that declares one and the hub picks it up; no fork, no central registry.
Resolution is entry-point first, then a **dotted-path fallback**
(`my_pkg.module:MyClass`, handy for prototyping) — see
`src/mcp_hub/refresher/registry.py` and `src/mcp_hub/secrets/registry.py`.

| Entry-point group | Protocol (where) | Built-ins |
|---|---|---|
| `mcp_hub.secret_backends` | `SecretBackend` (`interfaces.py`) | `env`, `file`, `bao` |
| `mcp_hub.approvers` | `Approver` (`interfaces.py`) | `auto`, `reject`, `ntfy` |
| `mcp_hub.token_sources` | `TokenSource` (`refresher/protocols.py`) | `oidc_client_credentials` |
| `mcp_hub.token_sinks` | `TokenSink` (`refresher/protocols.py`) | `file` |

The loop is the same for all four: **implement the Protocol → declare the entry
point → `pip install` next to the hub → select it by name in `policy.yaml`**
(the `config:` block is passed to your `__init__` as kwargs). Add unit tests
with the fakes in `tests/fakes/`.

### Worked example — a token source

```python
# my_plugin/source.py
from datetime import UTC, datetime, timedelta
from mcp_hub.refresher.protocols import Token, TokenMintError

class MyTokenSource:
    name = "my_token_source"

    def __init__(self, *, endpoint: str) -> None:        # kwargs come from policy config
        self._endpoint = endpoint

    async def mint(self) -> Token:
        try:
            value = await fetch_token(self._endpoint)     # your logic
        except Exception as exc:
            raise TokenMintError(str(exc)) from exc        # transient=True by default; retried
        return Token(value=value, expires_at=datetime.now(UTC) + timedelta(minutes=15))

    async def close(self) -> None: ...
```

```toml
# my_plugin/pyproject.toml
[project.entry-points."mcp_hub.token_sources"]
my_token_source = "my_plugin.source:MyTokenSource"
```

```yaml
# policy.yaml — `config` keys are passed to __init__ as kwargs
token_refresh:
  fanout_jwt:
    source: { type: my_token_source, config: { endpoint: "https://..." } }
    sink:   { type: file, config: { path: /etc/mcp-gateway/fanout_jwt } }
    rotate_every: minutes=10
```

`pip install -e ./my_plugin` next to the hub and `type: my_token_source`
resolves. While prototyping, skip the entry point and use a dotted path:
`type: my_plugin.source:MyTokenSource`.

Secret backends (`SecretBackend.resolve/close`) and approvers
(`Approver.request_approval/publish_outcome/close`, plus the optional
`WebhookApprover.webhook_routes` for push callbacks) follow the same loop —
implement the Protocol from `interfaces.py`, declare the group's entry point.

## Reporting security issues

See [SECURITY.md](./SECURITY.md) — please report privately, not via issues.
