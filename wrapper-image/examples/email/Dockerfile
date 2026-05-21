# syntax=docker/dockerfile:1.7
#
# email-mcp-wrapper — @n24q02m/better-email-mcp + the wrapper-base.
#
# better-email-mcp is a Node 24 stdio MCP that wraps IMAPflow + nodemailer
# and exposes 5 composite tools (messages, folders, attachments, send,
# help). Multi-provider: Gmail, Yahoo, iCloud, Outlook, Zoho, ProtonMail.
# Outlook uses OAuth2 device-code flow under the hood; the rest use
# app-specific passwords. The MCP reads everything from one env var:
#
#   EMAIL_CREDENTIALS=user@example.com:app-password
#   EMAIL_CREDENTIALS=u1@host:pw1,u2@host:pw2:imap.custom.host    # multi-account
#
# Build (from wrapper-image/):
#   docker build -t registry.pape.house/local/email-mcp-wrapper:0.1 \
#                -f examples/email/Dockerfile .
#
# At runtime the orchestrator injects:
#   EMAIL_CREDENTIALS                                    bao-resolved per identity (or shared)
#   OIDC_ISSUER, OIDC_DISCOVERY_URL, OIDC_AUDIENCE       JWT validation in the wrapper
#   MCP_COMMAND="better-email-mcp"                        what the wrapper-base entrypoint spawns
#
# Unlike examples/heb/, there's no bootstrap.py — better-email-mcp reads
# EMAIL_CREDENTIALS directly from env, so the base wrapper entrypoint
# can spawn it without any credential bridging.

FROM registry.pape.house/local/wrapper-base:0.1

# Node 24 (>=24.14.0 per better-email-mcp's engines field). NodeSource
# distributes deb packages for the slim base's Debian release; the setup
# script auto-detects bookworm vs trixie.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && apt-get purge -y --auto-remove curl gnupg \
 && rm -rf /var/lib/apt/lists/*

# Pin the MCP package version so cold rebuilds are reproducible. Bump in
# lockstep when upstream cuts a release worth taking. `npm install -g`
# lands the `better-email-mcp` binary in /usr/bin/ which the wrapper
# entrypoint's $PATH already picks up.
RUN npm install -g @n24q02m/better-email-mcp@1.29.0 \
 && npm cache clean --force

ENV MCP_COMMAND="better-email-mcp"
