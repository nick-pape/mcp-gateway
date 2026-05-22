# Security Policy

`mcp-gateway` is an authenticating gateway that brokers privileged tool calls
across MCP servers. Treat security reports seriously and privately.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository
(<https://github.com/nick-pape/mcp-gateway/security/advisories/new>).

Please include:
- affected version / commit,
- a description and impact assessment,
- reproduction steps or a proof of concept,
- any suggested remediation.

You'll get an acknowledgement, and we'll coordinate a fix and disclosure
timeline with you. Please give us a reasonable window before any public
disclosure.

## Supported versions

Pre-1.0: only the latest `main` is supported. Once releases are tagged, this
table will list the supported version range.

## Inbound auth hardening

`auth.mode` selects how callers are authenticated; each has deployment
responsibilities:

- **`oidc`** (default): inbound OIDC JWTs validated against a pinned JWKS.
- **`static_token`**: opaque bearer tokens mapped to identities. Generate
  high-entropy tokens (`openssl rand -hex 32`), keep them in a `0400`,
  root-owned file referenced by `token_file` — **never inline in `policy.yaml`** —
  and rotate them like any credential.
- **`trusted_proxy`**: the hub trusts an `identity_header` injected by a fronting
  auth proxy. This is only safe because the proxy must also send a shared secret
  (`shared_secret_file`) in the `x-mcp-gateway-auth` header (constant-time
  compared). **Network-isolate the hub so only the proxy can reach it** —
  otherwise anyone who can reach the hub and learns the secret can assert any
  identity. Treat that secret as a high-value credential.

All modes fail closed: an unknown token, a missing/incorrect proxy secret, or an
unknown identity is rejected, never defaulted.

## Scope notes

- The hub validates inbound JWTs and enforces per-identity tool policy and
  human-in-the-loop approvals. Misconfiguration of the policy, secret backend,
  or identity provider can defeat these controls — report suspected
  *default-insecure* behavior, not deployment-specific misconfiguration.
- Secrets are referenced by backend path, never committed. If you find a
  committed credential, report it privately.
