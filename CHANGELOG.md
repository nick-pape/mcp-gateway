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
- GitHub Actions CI (ruff + mypy --strict + pytest) and a generic image build
  published to `ghcr.io/nick-pape/mcp-gateway`.
- `policy.example.minimal.yaml` + an example `docker-compose.yml`.
- LICENSE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md.

### Changed
- Renamed the distribution package `mcp-pape-house` → `mcp-gateway`.
- The HTTP auth strategy `bao_backed_bearer` is now `secret_bearer`
  (`bao_backed_bearer` kept as a back-compat alias).
- Generic image config-path defaults are now `/etc/mcp-gateway/` (override with
  `MCP_HUB_CONFIG`).
- The image is now MCP-agnostic — baked-in MCPs moved to deployment overlays.
- The OAuth discovery/DCR shim derives the upstream IdP base from the configured
  `auth.issuer` instead of a hardcoded URL (behavior-preserving for
  Authentik global-issuer mode).
- FastMCP server name and package docstrings are now `mcp-gateway`-branded;
  `policy.example.yaml` and `scripts/` use generic `example.com` hostnames.
