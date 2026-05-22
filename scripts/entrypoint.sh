#!/bin/sh
# Container entrypoint for mcp.pape.house.
#
# Pre-flight: bail loudly if required bind-mounts / secrets are missing.
# Then exec the CMD (default: python -m mcp_hub) so PID 1 stays sane
# and tini reaps zombies properly.
#
# The atomic-write-secret-file dance (O_CREAT|O_EXCL|0o400 + chown to
# the per-identity UID) lives INSIDE the hub's Fanout module — see
# mcp_fanout/fanout.py:_write_secret_file. The entrypoint doesn't read
# secrets; it just sanity-checks the deployment.

set -eu

POLICY_PATH="${MCP_HUB_CONFIG:-/etc/mcp-gateway/policy.yaml}"
RUNTIME_DIR="${MCP_HUB_RUNTIME_DIR:-/run/mcp-tokens}"
# fanout_jwt is now refresher-managed: written by the hub at startup
# (see mcp_hub.refresher) into the bind-mounted /etc/mcp-gateway/
# directory. We don't sanity-check its existence at entrypoint time
# anymore — the refresher creates it during the initial mint.
FANOUT_CLIENT_SECRET="/run/secrets/fanout_client_secret"
NTFY_PUBLISH_TOKEN="/run/secrets/ntfy_publish_token"

fatal() {
    echo "FATAL: $1" >&2
    exit 1
}

[ -f "$POLICY_PATH" ] || fatal "policy.yaml not mounted at $POLICY_PATH"

# Runtime dir for per-identity token files. compose mounts this as tmpfs
# so writes are RAM-only and disappear on container stop. Mode 0711 —
# root retains full access; per-identity children (UIDs 1001+) can
# *traverse* the dir to open their own file but cannot *list* it. The
# per-file mode 0400 owned by the child UID keeps siblings out.
# Mode 0700 would block traversal entirely and break the design.
mkdir -p "$RUNTIME_DIR"
chmod 0711 "$RUNTIME_DIR"

# Secrets are required for production backends. Tests / dev compose
# may use the env / auto backends and skip these — only fail if the
# referenced policy actually selects bao or ntfy.
if grep -q '^[[:space:]]*name:[[:space:]]*bao' "$POLICY_PATH" 2>/dev/null; then
    [ -f "$FANOUT_CLIENT_SECRET" ] || fatal "secret_backend=bao but no $FANOUT_CLIENT_SECRET mounted (token refresher needs it)"
fi
if grep -q '^[[:space:]]*name:[[:space:]]*ntfy' "$POLICY_PATH" 2>/dev/null; then
    [ -f "$NTFY_PUBLISH_TOKEN" ] || fatal "approver=ntfy but no $NTFY_PUBLISH_TOKEN mounted"
fi

exec "$@"
