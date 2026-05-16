#!/usr/bin/env bash
#
# Mint a 1-year hub bearer for better-email-mcp, store in bao.
#
# Two prerequisites the operator must satisfy before running this:
#  1. The forked email-mcp container must be running on CT 120 with
#     HOME=/home/node and the `email_mcp_state` volume mounted there. The
#     RSA signing keypair must already exist at
#     /home/node/.mcp-core/jwt-keys/better-email-mcp_{private,public}.pem
#     inside the container (auto-generated on first start).
#  2. At least one Outlook account must already be configured (encrypted
#     config at /home/node/.config/mcp/config.enc, Microsoft refresh
#     tokens at /home/node/.better-email-mcp/tokens.json). Fresh container
#     ⇒ walk the OAuth dance once via Claude Code's `/mcp` against the
#     `email-mcp` entry in `.mcp.json` to populate these.
#
# What this script does:
#  1. SSHes to Proxmox and `docker cp`s a tiny Node mint script into the
#     email-mcp container (must run from the package install dir so jose
#     resolves through the local node_modules)
#  2. `docker exec`s `node mint-jwt.mjs` to sign a 1-year RS256 JWT with
#     the persisted private key. Random sub — the accounts-fallback fork
#     in src/transports/http.ts means any sub falls back to currentAccounts
#  3. Verifies the JWT works by initializing an MCP session
#  4. Stores the JWT in bao at secret/services/email-mcp field hub_bearer
#     (alongside hub_bearer_exp for human reference)
#  5. Cleans up the in-container mint script
#
# Idempotent (each run = fresh sub, prior bearers stay valid until exp).
# Re-run annually for rotation. Re-run after restoring the email-mcp
# volume from backup to a different CT — the old bearer's signing key
# won't match the new install.
#
# Why bash + node-inside-container instead of Python:
#   - Python with PyJWT[crypto] needs cffi which is finicky on Windows
#     (can't import _cffi_backend through `uv pip install --target`).
#   - Node + jose is already inside the email-mcp container; no extra deps.
#
# Usage:
#   bash mcp.service.pape.house/scripts/bootstrap_email_mcp_hub_bearer.sh

set -euo pipefail

PROXMOX_HOST="${PROXMOX_HOST:-root@proxmox.service.pape.house}"
EMAIL_MCP_CT="${EMAIL_MCP_CT:-120}"
EMAIL_MCP_PUBLIC_URL="${EMAIL_MCP_PUBLIC_URL:-https://email.mcp.pape.house}"
BAO_CT="${BAO_CT:-119}"
BAO_PATH="${BAO_PATH:-secret/services/email-mcp}"
PACKAGE_INSTALL_DIR="/usr/local/lib/node_modules/@n24q02m/better-email-mcp"
TTL="365d"

say() { echo "==> $*"; }

# 1. Stage the mint script
say "1/5 staging mint script in email-mcp container"
TMP_MINT=$(mktemp --tmpdir mint-jwt-XXXXXX.mjs)
trap "rm -f $TMP_MINT" EXIT
cat > "$TMP_MINT" <<'NODE'
import * as jose from 'jose';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const pem = readFileSync('/home/node/.mcp-core/jwt-keys/better-email-mcp_private.pem', 'utf8');
const key = await jose.importPKCS8(pem, 'RS256');
const sub = randomUUID().replace(/-/g, '');
const jwt = await new jose.SignJWT({})
  .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
  .setIssuer('better-email-mcp')
  .setAudience('better-email-mcp')
  .setSubject(sub)
  .setIssuedAt()
  .setExpirationTime(process.env.MINT_TTL || '365d')
  .sign(key);
console.log(jwt);
NODE
scp -q "$TMP_MINT" "$PROXMOX_HOST:/tmp/mint-jwt.mjs"
ssh -q "$PROXMOX_HOST" "
  pct push $EMAIL_MCP_CT /tmp/mint-jwt.mjs /tmp/mint-jwt.mjs
  pct exec $EMAIL_MCP_CT -- docker cp /tmp/mint-jwt.mjs email-mcp:$PACKAGE_INSTALL_DIR/mint-jwt.mjs
  rm /tmp/mint-jwt.mjs
  pct exec $EMAIL_MCP_CT -- rm /tmp/mint-jwt.mjs
"

# 2. Mint
say "2/5 minting JWT inside email-mcp container"
BEARER=$(ssh -q "$PROXMOX_HOST" "pct exec $EMAIL_MCP_CT -- docker exec --workdir $PACKAGE_INSTALL_DIR -e MINT_TTL=$TTL email-mcp node mint-jwt.mjs" | tail -1)
[[ ${#BEARER} -gt 100 ]] || { echo "FATAL: mint output looks wrong (length=${#BEARER}): $BEARER" >&2; exit 1; }
echo "      bearer minted: ${#BEARER} chars"

# 3. Verify against live email-mcp
say "3/5 verifying bearer against $EMAIL_MCP_PUBLIC_URL/mcp"
HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$EMAIL_MCP_PUBLIC_URL/mcp" \
  -H "Authorization: Bearer $BEARER" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"bootstrap","version":"0.1"}}}')
if [[ "$HTTP_CODE" != "200" ]]; then
    echo "FATAL: initialize returned HTTP $HTTP_CODE (expected 200)" >&2
    exit 1
fi
echo "      OK — initialize accepted"

# 4. Decode exp for storage metadata
PAYLOAD_B64=$(echo -n "$BEARER" | cut -d. -f2)
# Pad to multiple of 4 for base64 decode
PADDED="${PAYLOAD_B64}$(printf '=%.0s' $(seq 1 $((4 - ${#PAYLOAD_B64} % 4))))"
EXP_TS=$(echo "$PADDED" | tr '_-' '/+' | base64 -d 2>/dev/null | python -c "import json,sys; print(json.load(sys.stdin)['exp'])")
EXP_ISO=$(python -c "from datetime import datetime, timezone; print(datetime.fromtimestamp($EXP_TS, tz=timezone.utc).isoformat())")
echo "      exp: $EXP_ISO"

# 5. Push to bao + cleanup mint script
say "4/5 PATCHing bao $BAO_PATH (fields hub_bearer + hub_bearer_exp)"
ssh -q "$PROXMOX_HOST" "pct exec $BAO_CT -- bash -lc \"bao kv patch $BAO_PATH hub_bearer='$BEARER' hub_bearer_exp='$EXP_ISO'\"" >/dev/null

say "5/5 cleaning up in-container mint script"
ssh -q "$PROXMOX_HOST" "pct exec $EMAIL_MCP_CT -- docker exec email-mcp rm $PACKAGE_INSTALL_DIR/mint-jwt.mjs" 2>/dev/null || true

echo
echo "DONE. bao $BAO_PATH.hub_bearer is a 1-year RS256 JWT."
echo "      exp: $EXP_ISO"
echo "      length: ${#BEARER} chars"
echo
echo "Re-run this script ~11 months from now for annual rotation."
