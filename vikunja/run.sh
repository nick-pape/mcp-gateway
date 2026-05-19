#!/bin/sh
# Hub-side wrapper for @democratize-technology/vikunja-mcp.
#
# The hub injects per-identity secrets as FILE paths (convention shared
# with technitium-mcp-secure: env var name ends in _FILE, value is the
# path to a 0400-mode file on the tmpfs at /run/mcp-tokens/).
#
# vikunja-mcp upstream reads VIKUNJA_API_TOKEN directly from env. We
# slurp the file and re-export so the upstream binary works unchanged.
#
# secret_env_name in policy.yaml: VIKUNJA_API_TOKEN_FILE
# extra_env in policy.yaml:       VIKUNJA_URL: "https://tasks.pape.house/api/v1"

set -eu

if [ -z "${VIKUNJA_API_TOKEN_FILE:-}" ]; then
    echo "vikunja-mcp wrapper: VIKUNJA_API_TOKEN_FILE not set" >&2
    exit 1
fi
if [ ! -r "$VIKUNJA_API_TOKEN_FILE" ]; then
    echo "vikunja-mcp wrapper: cannot read $VIKUNJA_API_TOKEN_FILE" >&2
    exit 1
fi

VIKUNJA_API_TOKEN="$(cat "$VIKUNJA_API_TOKEN_FILE")"
export VIKUNJA_API_TOKEN

exec node /app/mcps/vikunja/node_modules/@democratize-technology/vikunja-mcp/dist/index.js "$@"
