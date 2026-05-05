"""Multi-tenant stdio MCP multiplexer.

Spawns N stdio child processes per MCP type — one per identity — and
routes incoming JSON-RPC requests to the correct child by identity tag.
Designed for eventual standalone OSS publication; until then, lives
alongside the hub that imports it.
"""
