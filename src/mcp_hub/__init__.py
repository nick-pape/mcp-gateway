"""mcp.pape.house — homelab MCP gateway.

Single-container hub with two pluggable interfaces (SecretBackend,
Approver), Authentik OIDC JWT validation, per-identity tool curation,
ntfy HITL push approvals, and federation across stdio MCP backends via
the `mcp_fanout` module.
"""
