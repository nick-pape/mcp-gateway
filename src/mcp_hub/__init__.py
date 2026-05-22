"""mcp-gateway — multi-tenant MCP gateway.

Single-container hub with pluggable interfaces (SecretBackend, Approver,
TransientStore, token sources/sinks), OIDC JWT validation, per-identity
tool curation, HITL push approvals, and federation across stdio + HTTP
MCP backends via the `mcp_fanout` module.
"""
