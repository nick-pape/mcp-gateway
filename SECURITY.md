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

## Scope notes

- The hub validates inbound JWTs and enforces per-identity tool policy and
  human-in-the-loop approvals. Misconfiguration of the policy, secret backend,
  or identity provider can defeat these controls — report suspected
  *default-insecure* behavior, not deployment-specific misconfiguration.
- Secrets are referenced by backend path, never committed. If you find a
  committed credential, report it privately.
