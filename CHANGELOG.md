# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased]

### Added
- Pluggable `SecretBackend` registry (`mcp_hub.secret_backends`) with built-in
  `env`, `file` (SOPS/age-friendly), and `bao` adapters; third-party adapters via
  entry points or dotted path.
- Pluggable `Approver` registry (`mcp_hub.approvers`) — `auto`/`reject`/`ntfy`
  built in; generic webhook-route capability so any push approver self-registers
  its callback.
- `TransientStore` for HITL pending state — `InMemoryTransientStore` (default,
  zero-infra) and `BaoTransientStore` (crash-safe); ntfy no longer requires Vault.
- Bao backend `auth.method: token` (static Vault token) alongside `jwt`.
- As-agent per-identity secret-store auth: an `IdentityPolicy.kind: autonomous`
  identity on a `secret_bearer` MCP with `as_agent: true` authenticates to the
  secret store with its *own* inbound JWT (closing the confused-deputy gap so
  the store audits the agent), via a new optional `jwt=` hook on the
  `SecretBackend.resolve()` Protocol. All-autonomous HTTP MCPs boot via a
  no-auth reachability probe.
- Non-OIDC inbound auth via `auth.mode`, behind a new `InboundAuthenticator`
  Protocol: `static_token` (opaque bearer tokens → identities from a file; **no
  IdP**) and `trusted_proxy` (trust a fronting proxy's identity header, gated by
  a constant-time shared-secret check). `oidc` stays the default — making a true
  no-IdP `docker compose up` possible. (`jwt_passthrough` / `as_agent` /
  container MCPs remain oidc-only, with clear config errors otherwise.)
- Generic OIDC validator: JWKS **auto-discovery** from
  `<issuer>/.well-known/openid-configuration` (supply only `issuer`), a
  configurable `identity_claim` (`sub`/`azp`/`client_id`/custom) alongside the
  audience-prefix model, and an optional exact `audience` check — validates
  against Keycloak / Auth0 / Zitadel / Authentik by config alone.
- Generic `oidc_client_credentials` token-refresh source (RFC 6749) — works with
  any OIDC IdP; `authentik_client_credentials` kept as a back-compat alias. Plus
  a CONTRIBUTING plugin-author guide (worked example) covering all four
  entry-point groups.
- Unified config templating: `{identity}` and `{mcp}` placeholders now work
  uniformly across secret paths, `path_template`, `secrets_to_env`,
  `audience_template`, and `role_template` (stdio `secrets.path` gains
  templating too).
- Container transport: `container_host` is now configurable per MCP in
  `policy.yaml` (was hardcoded `host.docker.internal`) for rootless / Podman /
  k8s; documented the Docker requirements and that stdio/http need no Docker.
  (The per-identity UID range was already a build ARG: `UID_BASE`/`UID_COUNT`.)
- GitHub Actions CI (ruff + mypy --strict + pytest) and a generic image build
  published to `ghcr.io/nick-pape/mcp-gateway`.
- gitleaks secret-scanning CI gate + pre-commit hook, with a custom rule for
  opaque URL-path tokens (`.gitleaks.toml`).
- `policy.example.minimal.yaml` + an example `docker-compose.yml`.
- LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md.

### Changed
- `identity.secrets` is now optional — http/container-only identities no longer
  need placeholder `secrets:` entries. (Schema stays `version: 1`; additive-only.)
- Renamed the distribution package `mcp-pape-house` → `mcp-gateway`.
- The HTTP auth strategy `bao_backed_bearer` is now `secret_bearer`
  (`bao_backed_bearer` kept as a back-compat alias).
- Renamed the inbound JWT validator `AuthentikJWTValidator` → `OidcJwtValidator`
  (it was always generic OIDC; the name was misleading). Internal class, no
  config impact.
- Generic image config-path defaults are now `/etc/mcp-gateway/` (override with
  `MCP_HUB_CONFIG`).
- The image is now MCP-agnostic — baked-in MCPs moved to deployment overlays.
- The OAuth discovery/DCR shim derives the upstream IdP base from the configured
  `auth.issuer` instead of a hardcoded URL (behavior-preserving for
  Authentik global-issuer mode).
- FastMCP server name and package docstrings are now `mcp-gateway`-branded;
  `policy.example.yaml` and `scripts/` use generic `example.com` hostnames.

### Fixed
- HTTP upstreams that use Streamable-HTTP sessions now work. `HttpFanout` reads
  the `Mcp-Session-Id` from the `initialize` reply and sends it on every later
  request, keeping one session per identity (the boot identity's from the boot
  handshake, the rest opened on first call). A 404 on a request that carried a
  session re-initializes once and retries; sessions are DELETEd on close.
  Previously every call after `initialize` failed with HTTP 400 "Server not
  initialized", which aborted hub startup. Stateless upstreams are unchanged.

### Documentation
- Rewrote `architecture.md` around the generic design: pluggable axes + the three
  transports (stdio/http/container) + three auth modes (oidc/static_token/
  trusted_proxy) as first-class, with Authentik/OpenBao/ntfy demoted to a worked
  example. Removed the stale baked-in-MCP multi-stage Dockerfile, `su-exec`,
  `AuthentikJWTValidator`, and "~250 LoC" references.
- Pruned `KNOWN_LIMITATIONS.md`: marked the stdio-only-transport (#3) and
  build-time `git clone` (#14) limitations resolved, rewrote the Authentik-coupling
  entry (#5), and updated the credential-injection (#1) and Layer-3 rotation (#2)
  entries to reflect the http/container transports and the generic refresher.
