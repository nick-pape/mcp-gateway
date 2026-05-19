#!/usr/bin/env node
// vikunja-mcp-proxy: stdio-in-stdio MCP proxy that explodes the upstream
// @democratize-technology/vikunja-mcp's composite tools (each driven by a
// `subcommand` or `action` enum arg) into per-subcommand granular tools,
// so the hub's HITL policy can glob-match read-vs-write at tool-name
// granularity instead of being stuck at all-or-nothing per composite.
//
//   hub stdio ──> THIS PROXY ──stdio──> upstream vikunja-mcp child
//
// On tools/list: replaces upstream's ~10 composite tools with the
//   granular list (~70+ tools) built by enumerating each composite's
//   subcommand/action enum at runtime.
// On tools/call: looks up the granular name → (composite, arg), rewrites
//   request and forwards.
// Everything else passes through unchanged (initialize, ping,
//   notifications).
//
// Discovery is runtime, not hand-rolled. New subcommands added upstream
// surface here automatically on the next hub restart — no schema drift
// to chase.
//
// See mcp.service.pape.house/vikunja/README.md for the rationale.

const { spawn } = require('child_process');
const readline = require('readline');
const path = require('path');

const UPSTREAM_BIN = path.join(
    __dirname,
    'node_modules',
    '@democratize-technology',
    'vikunja-mcp',
    'dist',
    'index.js',
);

// ──────────────────────────────────────────────────────────────────────
// Upstream child management
// ──────────────────────────────────────────────────────────────────────

const upstream = spawn(process.execPath, [UPSTREAM_BIN], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: process.env,
});

upstream.on('exit', (code, signal) => {
    process.stderr.write(
        `vikunja-mcp-proxy: upstream exited code=${code} signal=${signal}\n`,
    );
    process.exit(code == null ? 1 : code);
});

upstream.on('error', (err) => {
    process.stderr.write(`vikunja-mcp-proxy: upstream spawn error: ${err.message}\n`);
    process.exit(2);
});

// Map: outgoing JSON-RPC id → { resolve, interceptor? }
const pending = new Map();
let nextProxyId = 1_000_000_000;  // namespace for proxy-internal probe IDs

const upstreamReader = readline.createInterface({
    input: upstream.stdout,
    terminal: false,
});

upstreamReader.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try {
        msg = JSON.parse(line);
    } catch (e) {
        process.stderr.write(
            `vikunja-mcp-proxy: bad upstream JSON (${e.message}): ${line.slice(0, 200)}\n`,
        );
        return;
    }

    // Response to a tracked request → resolve it (possibly intercepting).
    if (msg.id != null && pending.has(msg.id)) {
        const { resolve, interceptor } = pending.get(msg.id);
        pending.delete(msg.id);
        try {
            resolve(interceptor ? interceptor(msg) : msg);
        } catch (e) {
            process.stderr.write(
                `vikunja-mcp-proxy: interceptor error: ${e.message}\n`,
            );
            resolve(msg);
        }
        return;
    }

    // Unsolicited (notification or stray) → forward to hub as-is.
    process.stdout.write(JSON.stringify(msg) + '\n');
});

function sendToUpstream(msg, interceptor) {
    return new Promise((resolve) => {
        if (msg.id == null) {
            // Notification — fire-and-forget; no response expected.
            upstream.stdin.write(JSON.stringify(msg) + '\n');
            resolve(undefined);
            return;
        }
        pending.set(msg.id, { resolve, interceptor });
        upstream.stdin.write(JSON.stringify(msg) + '\n');
    });
}

// ──────────────────────────────────────────────────────────────────────
// Tool explosion + routing
// ──────────────────────────────────────────────────────────────────────

// Maps granular tool name → { composite, argName, argValue }.
// argName is 'subcommand', 'action', or null (single-op passthrough).
let routingMap = null;
let granularTools = null;

function explodeTools(compositeTools) {
    const granular = [];
    const map = new Map();

    for (const tool of compositeTools) {
        const schema = tool.inputSchema || { type: 'object' };
        const props = schema.properties || {};
        const required = schema.required || [];

        // Detect which arg field drives subcommand routing.
        let argName = null;
        let enumValues = null;
        if (props.subcommand && Array.isArray(props.subcommand.enum)) {
            argName = 'subcommand';
            enumValues = props.subcommand.enum;
        } else if (props.action && Array.isArray(props.action.enum)) {
            argName = 'action';
            enumValues = props.action.enum;
        }

        if (argName == null || !enumValues || enumValues.length === 0) {
            // Single-op tool — passthrough unchanged.
            granular.push(tool);
            map.set(tool.name, { composite: tool.name, argName: null, argValue: null });
            continue;
        }

        // Build a "cleaned" schema: drop the enum arg from properties
        // and required (the proxy injects it server-side per granular
        // tool, so callers don't need to set it).
        const cleanedProps = { ...props };
        delete cleanedProps[argName];
        const cleanedRequired = required.filter((r) => r !== argName);

        for (const val of enumValues) {
            const slug = String(val).replace(/-/g, '_');
            const granularName = `${tool.name}_${slug}`;
            const desc = tool.description
                ? `${tool.description} [${argName}=${val}]`
                : `${tool.name} ${argName}=${val}`;
            granular.push({
                name: granularName,
                description: desc,
                inputSchema: {
                    type: 'object',
                    ...schema,
                    properties: cleanedProps,
                    required: cleanedRequired,
                },
            });
            map.set(granularName, { composite: tool.name, argName, argValue: val });
        }
    }

    return { granular, map };
}

// ──────────────────────────────────────────────────────────────────────
// Hub stdin handler
// ──────────────────────────────────────────────────────────────────────

const hubReader = readline.createInterface({
    input: process.stdin,
    terminal: false,
});

hubReader.on('line', async (line) => {
    if (!line.trim()) return;
    let req;
    try {
        req = JSON.parse(line);
    } catch (e) {
        process.stderr.write(
            `vikunja-mcp-proxy: bad hub JSON (${e.message}): ${line.slice(0, 200)}\n`,
        );
        return;
    }

    try {
        // ── tools/list ── intercept response, return granular list ──
        if (req.method === 'tools/list') {
            const resp = await sendToUpstream(req, (msg) => {
                if (msg.result && Array.isArray(msg.result.tools)) {
                    const { granular, map } = explodeTools(msg.result.tools);
                    routingMap = map;
                    granularTools = granular;
                    msg.result.tools = granular;
                }
                return msg;
            });
            if (resp) process.stdout.write(JSON.stringify(resp) + '\n');
            return;
        }

        // ── tools/call ── rewrite name + inject subcommand/action ──
        if (req.method === 'tools/call') {
            // Build routing map lazily if hub somehow called tools/call
            // before tools/list (shouldn't happen but defensive).
            if (!routingMap) {
                const probe = {
                    jsonrpc: '2.0',
                    id: nextProxyId++,
                    method: 'tools/list',
                    params: {},
                };
                await sendToUpstream(probe, (msg) => {
                    if (msg.result && Array.isArray(msg.result.tools)) {
                        const { granular, map } = explodeTools(msg.result.tools);
                        routingMap = map;
                        granularTools = granular;
                    }
                    return msg;
                });
            }

            const callName = req.params && req.params.name;
            if (callName && routingMap && routingMap.has(callName)) {
                const route = routingMap.get(callName);
                const newReq = {
                    ...req,
                    params: {
                        ...req.params,
                        name: route.composite,
                        arguments: { ...(req.params.arguments || {}) },
                    },
                };
                if (route.argName) {
                    newReq.params.arguments[route.argName] = route.argValue;
                }
                const resp = await sendToUpstream(newReq);
                if (resp) process.stdout.write(JSON.stringify(resp) + '\n');
                return;
            }
            // Unknown granular name — let upstream error out naturally.
        }

        // ── everything else ── passthrough ──
        const resp = await sendToUpstream(req);
        if (req.id != null && resp) {
            process.stdout.write(JSON.stringify(resp) + '\n');
        }
    } catch (e) {
        process.stderr.write(
            `vikunja-mcp-proxy: error handling method=${req.method}: ${e.message}\n`,
        );
        if (req.id != null) {
            const errResp = {
                jsonrpc: '2.0',
                id: req.id,
                error: {
                    code: -32603,
                    message: `vikunja-mcp-proxy internal error: ${e.message}`,
                },
            };
            process.stdout.write(JSON.stringify(errResp) + '\n');
        }
    }
});

hubReader.on('close', () => {
    // Hub closed our stdin → shut down upstream gracefully.
    try {
        upstream.kill('SIGTERM');
    } catch (_) {
        // Best-effort.
    }
});
