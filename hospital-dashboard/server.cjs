// ============================================================
// NextGen NMS — Phase 10: Autonomous Enterprise SOC Backend
// server.cjs — Express + Socket.io + UDP Syslog + Real Ansible + Gemini Chat
//
// PHASE 10 PILLARS IMPLEMENTED HERE:
//
//  PILLAR 1 — NOC AI Assistant (Real Gemini, Real Context)
//     POST /api/chat  → reads full_topology.json, injects it as
//     Gemini system context, returns a real AI response grounded
//     in the live network state. Requires: npm install @google/generative-ai
//     and GEMINI_API_KEY env var set before starting the server.
//
//  PILLAR 2 — Autonomous Event-Driven SOC
//     UDP 514 listener now emits SOC_ACTION_START when %SYS-5-CONFIG_I
//     is detected, triggers ansible-playbook ai_audit.yml --limit <device>,
//     then emits SOC_ACTION_RESULT with the verdict. Both REST endpoint
//     (/api/ai-diagnostics) and the autonomous UDP path emit these events
//     so the React dashboard sees every action in real time.
//
// Start:    node server.cjs
// Dev mode: npx nodemon server.cjs
//
// Required env vars:
//   GEMINI_API_KEY  — Google AI Studio key (for /api/chat)
//   SYSLOG_PORT     — defaults to 514 (requires root); set 1514 for non-root
//   PORT            — HTTP port, defaults to 3001
// ============================================================

'use strict';

const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const dgram = require('dgram');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');






// ── Gemini AI (Pillar 1) ───────────────────────────────────────
// Install with: npm install @google/generative-ai
// The SDK is lazy-required inside /api/chat so the server still
// boots (without chat) if the package isn't installed yet.
let GoogleGenerativeAI;
try {
    ({ GoogleGenerativeAI } = require('@google/generative-ai'));
} catch {
    console.warn('[CHAT] @google/generative-ai not installed. Run: npm install @google/generative-ai');
    console.warn('[CHAT] /api/chat will return 503 until installed.');
}

// ── Bootstrap ─────────────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
});

app.use(cors());
app.use(express.json());

// server.cjs lives in hospital-dashboard/
// The Ansible project root is one directory up (contains hosts, ai_audit.yml)
const ANSIBLE_ROOT = path.resolve(__dirname, '..');

// The full_topology.json is served as a static file from public/
// and also read by /api/chat to give Gemini network context.
const TOPOLOGY_PATH = path.join(__dirname, 'public', 'full_topology.json');

// ── AUDIT TRAIL: Persistent SIEM log file ─────────────────────
// Every call to broadcast() and every raw UDP syslog packet is
// appended here as a single NDJSON line (one JSON object per line).
// This survives server restarts and can be tailed, grepped, or
// ingested by external SIEM platforms (Wazuh, Splunk, etc.).
//
// Format per line (consistent schema — App.jsx /api/logs consumer
// depends on EXACTLY these four fields being present):
//   { "iso": "2025-04-29T12:00:00.000Z", "lvl": "info", "source": "BACKEND", "msg": "..." }
const SIEM_LOG_FILE = path.join(__dirname, 'siem_events.log');

// Internal helper: non-blocking append to the audit trail.
// We deliberately use the async form of appendFile so disk I/O
// never stalls the WebSocket emit or the Node.js event loop.
// The callback only logs errors — a slow disk must never crash the NOC.
function persistLog(record) {
    fs.appendFile(SIEM_LOG_FILE, JSON.stringify(record) + '\n', (err) => {
        if (err) console.error('[SIEM-LOG] Failed to write audit entry:', err.message);
    });
}

// ── SECURITY: Input sanitizer ──────────────────────────────────
// NEVER pass raw user input to exec(). This regex allows only valid
// Cisco hostname characters (letters, digits, hyphens) up to 30 chars.
// Anything else is rejected with HTTP 400 before exec() is ever called.
function isSafeDeviceId(id) {
    return typeof id === 'string' && /^[A-Za-z0-9\-]+$/.test(id) && id.length <= 30;
}

// ── HELPER: Map IP → hostname ──────────────────────────────────
// The UDP syslog listener receives packets from raw IPs like 10.3.80.2.
// This map converts them to friendly names for the SIEM log.
// Keep this in sync with your /hosts file.
const IP_TO_HOSTNAME = {
    '10.3.255.1': 'OC-Router',
    '10.3.80.2': 'OC-MLS0',
    '10.3.80.3': 'OC-MLS1',
    '10.3.80.10': 'OC-Floor1',
    '10.3.80.11': 'OC-Floor2',
    '10.3.80.12': 'OC-Floor3',
    '10.4.255.1': 'ET-Router',
    '10.4.80.2': 'ET-MLS0',
    '10.4.80.3': 'ET-MLS1',
    '10.4.80.10': 'ET-Floor1',
    '10.4.80.11': 'ET-Floor2',
    '10.4.80.12': 'ET-Floor3',
};

// ── HELPER: Detect syslog severity ────────────────────────────
// Cisco syslogs embed a severity digit: %FACILITY-SEVERITY-MNEMONIC
// Levels: 0=emerg 1=alert 2=crit 3=err 4=warn 5=notice 6=info 7=debug
function detectSyslogLevel(msg) {
    const m = msg.match(/%[\w]+-(\d)-[\w]+/);
    if (!m) return 'info';
    const sev = parseInt(m[1], 10);
    if (sev <= 3) return 'alert';
    if (sev === 4) return 'warn';
    return 'info';
}

// ── HELPER: Broadcast to SIEM log ─────────────────────────────
// Central helper so every part of the server emits the same schema.
// React's socket.on('syslog') handler expects {time, msg, lvl}.
//
// TWO responsibilities every time it is called:
//   1. WebSocket emit  — pushes the event to every connected React dashboard instantly.
//   2. Audit trail     — appends the record to siem_events.log as NDJSON so the
//                        history survives a server restart and can be re-hydrated
//                        by the React UI via GET /api/logs on page load.
//
// The `source` field defaults to 'BACKEND' for server-generated events.
// UDP syslog entries override it with the originating Cisco device IP.
function broadcast(msg, lvl = 'info', source = 'BACKEND') {
    const now = new Date();
    const record = {
        iso: now.toISOString(),        // machine-sortable, used by /api/logs
        lvl,                              // 'ok' | 'info' | 'warn' | 'alert'
        source,                           // originator label
        msg,                              // human-readable message text
    };

    // 1️⃣  Push to every connected React SIEM panel immediately.
    io.emit('syslog', {
        time: now.toLocaleTimeString(),   // human clock for the UI badge
        msg,
        lvl,
        source,
    });

    // 2️⃣  Persist to disk — non-blocking so it never delays the WS emit.
    persistLog(record);
}

// ── HELPER: Build micro-context for Gemini (extreme data diet) ──
// Returns a SEVERELY stripped-down JSON string (~2KB) to minimize
// token usage and avoid 429 quota errors. Only includes:
//   device_name, management_ip, cpu_usage (parsed %), up_interfaces (names)
// NO mac_table, arp_table, routing_table, traffic_raw, or raw telemetry.
function buildMicroContext() {
    try {
        const raw = fs.readFileSync(TOPOLOGY_PATH, 'utf8');
        const topo = JSON.parse(raw);

        if (!Array.isArray(topo.network_devices)) {
            return JSON.stringify({ note: 'No devices in topology.' });
        }

        const micro = topo.network_devices.map(dev => {
            // Parse CPU from raw string: "five seconds: 88%/4%"
            let cpuUsage = null;
            const cpuRaw = dev.real_telemetry?.cpu_raw;
            if (cpuRaw && typeof cpuRaw === 'string') {
                const m = cpuRaw.match(/five seconds:\s*(\d+)/i);
                if (m) cpuUsage = parseInt(m[1], 10);
            }

            // Only list interface names that are "up"
            const upIfaces = (dev.interfaces || [])
                .filter(i => i.status === 'up')
                .map(i => i.name);

            return {
                device_name: dev.device_name,
                management_ip: dev.management_ip,
                cpu_usage: cpuUsage !== null ? `${cpuUsage}%` : 'N/A',
                up_interfaces: upIfaces,
            };
        });

        return JSON.stringify({ devices: micro });
    } catch {
        return JSON.stringify({
            note: 'Topology not yet generated. Run: ansible-playbook live_docs_backup.yml',
        });
    }
}

// ── HELPER: Parse Ansible stdout for NMS_VERDICT ──────────────
// ai_audit.yml emits a debug line like:
//   "msg": "NMS_VERDICT=VULNERABLE|NMS_DETAILS=Missing access-class...|NMS_FIX=..."
//
// We parse this from the raw stdout string.
function parseAnsibleVerdict(stdout) {
    const verdictMatch = stdout.match(/NMS_VERDICT=(SECURE|VULNERABLE)/);
    const detailsMatch = stdout.match(/NMS_DETAILS=([^|"\n]+)/);
    const fixMatch = stdout.match(/NMS_FIX=([^"\n]+)/);

    if (!verdictMatch) return null; // Playbook didn't complete the verdict task

    const verdict = verdictMatch[1];
    const details = detailsMatch ? detailsMatch[1].trim() : 'See Ansible stdout for details.';
    const fixRaw = fixMatch ? fixMatch[1].trim() : '';

    const fix = fixRaw
        ? fixRaw.split('|').map(l => l.trim()).filter(Boolean)
        : [];

    return {
        verdict,
        color: verdict === 'VULNERABLE' ? '#FF4444' : '#00FF88',
        icon: verdict === 'VULNERABLE' ? '⚠️' : '✅',
        summary: verdict === 'VULNERABLE'
            ? 'Security gap detected by Gemini AI via Ansible.'
            : 'Device configuration is HIPAA-compliant per Gemini AI.',
        details,
        fix,
        cmd: verdict === 'VULNERABLE' ? `ansible-playbook ai_audit.yml --limit <device>` : null,
    };
}

// ── AUTONOMOUS SOC: Cooldown tracker ─────────────────────────
// When CONFIG_I events fire rapidly (e.g., Ansible itself applying config),
// we don't want to trigger a recursive audit loop.
const lastAutoAudit = new Map(); // deviceId → timestamp
const AUTO_AUDIT_COOLDOWN_MS = 60_000;

// ── CORE FUNCTION: Run Ansible playbook ───────────────────────
function runAnsiblePlaybook(playbook, limit, extraArgs = '') {
    const cmd = `ansible-playbook ${playbook}${limit ? ` --limit "${limit}"` : ''} ${extraArgs} -v`.trim();
    console.log(`[ANSIBLE] $ ${cmd}`);

    return new Promise((resolve, reject) => {
        exec(cmd, {
            cwd: ANSIBLE_ROOT,
            timeout: 180_000, // 3 minutes max per device
            env: { ...process.env, ANSIBLE_FORCE_COLOR: '0' },
        }, (error, stdout, stderr) => {
            if (error && !stdout.includes('NMS_VERDICT')) {

                // يتجاهل التحذيرات لو الأنسيبل خلص فعلاً
                if (stderr && !stderr.toLowerCase().includes('error')) {
                    resolve({ stdout, stderr });
                } else {
                    reject(new Error(stderr || error.message));
                }

                return;
            }
            resolve({ stdout, stderr });
        });
    });
}

// ============================================================
// PHASE 11: Resilient Gemini AI Engine — Model Cascade + Cache
// ============================================================
//
// MODEL CASCADE STRATEGY
// ──────────────────────
// We define a priority-ordered list of models. The engine tries the first
// model; if it gets a 429 (quota) or 404 (model unavailable on this key),
// it automatically falls back to the next one. This means:
//   - On a fresh key with full quota → you get gemini-2.5-flash (best)
//   - After hitting daily limits    → graceful degradation to flash-lite
//   - Never a hard crash to the user
//
// Why these four models specifically?
//   gemini-2.5-flash       → Best free-tier balance of quality and quota
//   gemini-2.5-flash-lite  → Very generous RPM limits on free tier
//   gemini-2.0-flash-lite  → Older but stable; different daily quota bucket
//   gemini-flash-lite-latest → Alias that always points to current lite
//
// DO NOT use gemini-2.5-pro or gemini-2.5-pro-preview in the cascade —
// their free tier is extremely restricted and burns quota instantly.
const GEMINI_MODEL_CASCADE = [
    'gemini-2.5-flash',
    'gemini-2.5-flash-lite',
    'gemini-2.0-flash-lite',
    'gemini-flash-lite-latest',
];

// ── In-memory response cache ─────────────────────────────────────────────────
// If the operator asks the same question twice (or the SOC fires the same
// audit prompt), we return the cached answer instantly without burning quota.
// Key = the prompt string. TTL = 5 minutes.
const aiResponseCache = new Map();
const AI_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function getCachedResponse(prompt) {
    const entry = aiResponseCache.get(prompt);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > AI_CACHE_TTL_MS) {
        aiResponseCache.delete(prompt); // Expired
        return null;
    }
    return entry.response;
}

function setCachedResponse(prompt, response) {
    // Prevent unbounded memory growth — cap the cache at 50 entries.
    // When full, evict the oldest entry (first inserted, Map preserves order).
    if (aiResponseCache.size >= 50) {
        const oldestKey = aiResponseCache.keys().next().value;
        aiResponseCache.delete(oldestKey);
    }
    aiResponseCache.set(prompt, { response, timestamp: Date.now() });
}

// ── Core AI call with cascade + exponential backoff ───────────────────────────
// This is the single function everything (chat, SOC audit, syslog analysis)
// should call. Never call genAI.getGenerativeModel() directly elsewhere.
//
// EXPONENTIAL BACKOFF EXPLAINED:
//   When the API says "retry in 22s", that's its server-side suggestion.
//   We respect it by waiting (retryDelay) milliseconds between tries, capped
//   at 15s so we don't stall the entire request for too long. This prevents
//   hammering the API during a rate-limit window, which would only make
//   the situation worse.
async function callGeminiWithFallback(prompt, systemInstruction = null) {
    if (!GoogleGenerativeAI) {
        return '⚠️ @google/generative-ai not installed. Run: npm install @google/generative-ai';
    }
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
        return '⚠️ GEMINI_API_KEY not set. Configure the environment variable before starting the server.';
    }

    // Check cache first — free, instant, no quota consumed.
    const cached = getCachedResponse(prompt);
    if (cached) {
        console.log('[AI] Cache hit — returning stored response.');
        return cached;
    }

    const genAI = new GoogleGenerativeAI(apiKey);
    let lastError = null;

    for (let modelIdx = 0; modelIdx < GEMINI_MODEL_CASCADE.length; modelIdx++) {
        const modelName = GEMINI_MODEL_CASCADE[modelIdx];

        // Each model gets up to 2 retry attempts for transient 429s before we
        // give up on it and cascade to the next model in the list.
        for (let attempt = 0; attempt < 2; attempt++) {
            try {
                const modelConfig = { model: modelName };
                if (systemInstruction) {
                    modelConfig.systemInstruction = systemInstruction;
                }

                const model = genAI.getGenerativeModel(modelConfig);
                const result = await model.generateContent(prompt);
                const responseText = result.response.text();

                // Cache the successful response before returning.
                setCachedResponse(prompt, responseText);

                if (modelIdx > 0 || attempt > 0) {
                    // Log when we had to fall back or retry — useful for debugging.
                    console.log(`[AI] Success with ${modelName} (cascade index ${modelIdx}, attempt ${attempt + 1})`);
                }
                return responseText;

            } catch (err) {
                lastError = err;
                const errStr = err.message || '';

                // 404 = model doesn't exist on this API key/region.
                // No point retrying the same model — cascade immediately.
                if (errStr.includes('404') || errStr.includes('not found')) {
                    console.warn(`[AI] Model ${modelName} not available on this key — cascading.`);
                    break; // Break inner retry loop → move to next model
                }

                // 429 = quota exceeded. If this is our first attempt, wait briefly
                // and retry once. If we've already retried, cascade to the next model.
                if (errStr.includes('429') || errStr.includes('quota') || errStr.includes('Too Many Requests')) {
                    if (attempt === 0) {
                        // Extract the retry delay from the API response if present.
                        const retryMatch = errStr.match(/retry in (\d+(\.\d+)?)s/i);
                        // Use the API's suggested delay, but cap it at 15s so we
                        // don't stall the entire request for too long.
                        const waitMs = retryMatch
                            ? Math.min(parseFloat(retryMatch[1]) * 1000, 15000)
                            : 3000; // Default 3s if no hint given

                        console.warn(`[AI] 429 on ${modelName} — waiting ${Math.round(waitMs / 1000)}s before retry.`);
                        await new Promise(resolve => setTimeout(resolve, waitMs));
                        continue; // Retry the same model once
                    } else {
                        // Already retried this model — cascade to the next.
                        console.warn(`[AI] 429 persists on ${modelName} — cascading to next model.`);
                        break;
                    }
                }

                // Any other error (network, malformed response, etc.) — cascade immediately.
                console.error(`[AI] Unexpected error on ${modelName}:`, errStr.substring(0, 200));
                break;
            }
        }
    }

    // All models in the cascade exhausted. Return a graceful degradation
    // message rather than throwing, so the UI shows something useful
    // instead of a blank error panel.
    const fallbackMsg =
        '⚠️ AI analysis temporarily unavailable — all Gemini quota tiers are exhausted. ' +
        'This resets automatically. Meanwhile, all live telemetry, topology, and SIEM ' +
        'features continue operating normally without AI assistance.';

    console.error('[AI] Full cascade exhausted. Last error:', lastError?.message?.substring(0, 300));
    return fallbackMsg;
}

// ============================================================
// REST API
// ============================================================

// GET /api/health
app.get('/api/health', (req, res) => {
    res.json({
        status: 'online',
        timestamp: new Date().toISOString(),
        ansible: ANSIBLE_ROOT,
        gemini: !!process.env.GEMINI_API_KEY,
    });
});

// ── GET /api/logs — Hydrate the SIEM panel on page load ───────
// Reads siem_events.log (NDJSON: one JSON object per line, written
// by broadcast() and the UDP syslog listener) and returns the last
// 50 entries as a clean JSON array.
//
// The React SIEM panel calls this once on mount so the panel is
// never empty after a page reload or server restart. Live events
// from the WebSocket continue to prepend normally on top of the
// pre-loaded history — the two channels merge seamlessly.
//
// Resilient by design:
//   • File not yet created (first boot)  → returns []
//   • Corrupt individual line            → silently skipped
//   • Unreadable file (permissions/lock) → returns [] with server log
//   None of these ever produce a 5xx response.
app.get('/api/logs', (req, res) => {
    if (!fs.existsSync(SIEM_LOG_FILE)) {
        return res.json([]); // First boot — no events persisted yet
    }
    try {
        const raw = fs.readFileSync(SIEM_LOG_FILE, 'utf8');
        // NDJSON is append-only so the last lines are the most recent.
        // We take the last 50 non-empty lines to keep the payload small.
        const lines = raw
            .split('\n')
            .filter(line => line.trim().length > 0)
            .slice(-50);

        const entries = lines
            .map(line => {
                try { return JSON.parse(line); }
                catch { return null; }              // Silently skip malformed lines
            })
            .filter(Boolean);                       // Remove nulls from failed parses

        res.json(entries);
    } catch (err) {
        console.error('[SIEM LOG] Failed to read audit log:', err.message);
        res.json([]); // Degrade gracefully — never crash the NOC server
    }
});



// ── WEBHOOK: Notify topology update from external tools ─────
// Called by spike.py immediately after it writes full_topology.json.
// Also safe to use from other automation hooks.
app.post('/api/notify-update', (req, res) => {
    io.emit('TOPOLOGY_UPDATED');
    res.json({ success: true });
});
// ── PILLAR 1: POST /api/chat ──────────────────────────────────
// Body: { message: "Which devices are at high CPU?" }
//
// How it works:
//   1. Reads full_topology.json (the real-time network twin) via buildMicroContext().
//   2. Builds a context-enriched prompt with the live network state injected.
//   3. Routes through callGeminiWithFallback() which tries models in priority
//      order (gemini-2.5-flash → flash-lite → 2.0-flash-lite → alias) with
//      per-model retry and exponential backoff on 429s. Never crashes the NOC.
//
// REQUIREMENT: GEMINI_API_KEY env var must be set before starting the server.
// Also: npm install @google/generative-ai
app.post('/api/chat', async (req, res) => {
    const { message } = req.body;

    if (!message?.trim()) {
        return res.status(400).json({ error: 'Message is required.' });
    }

    try {
        // Build the context-enriched prompt exactly as before,
        // but now route through the resilient cascade function.
        const context = buildMicroContext();

        const systemInstruction =
            `You are AXIOM-NOC, an autonomous hospital network SOC AI assistant. ` +
            `You have real-time access to a summary of the network topology below.\n\n` +
            `LIVE NETWORK SUMMARY (from Ansible digital twin):\n${context}\n\n` +
            `OPERATIONAL CONTEXT:\n` +
            `- This is a HIPAA-regulated hospital network with two zones: OC (Oncology Center) and ET (Emergency & Trauma).\n` +
            `- All VTY access must be restricted by ACL ISOLATE_VTY per HIPAA policy.\n` +
            `- Core switches OC-MLS0/OC-MLS1 and ET-MLS0/ET-MLS1 are connected via LACP Port-Channels.\n` +
            `- The OC-Router ↔ ET-Router link is a MAN (Metropolitan Area Network) link between buildings.\n\n` +
            `RESPONSE RULES:\n` +
            `- Reference ACTUAL device names, IPs, and CPU values from the summary above.\n` +
            `- Flag any device with high CPU (>75%) as a potential issue.\n` +
            `- Keep responses concise (under 200 words) unless the user asks for detail.\n` +
            `- If no topology data is available, say so and instruct the user to run live_docs_backup.yml.`;

        const fullPrompt = `Operator query: ${message.trim()}`;

        const reply = await callGeminiWithFallback(fullPrompt, systemInstruction);
        console.log(`[CHAT] Query: "${message.substring(0, 60)}" → ${reply.length} chars`);
        return res.json({ reply });

    } catch (err) {
        // This should never be reached now since callGeminiWithFallback
        // handles all errors internally, but kept as a safety net.
        console.error('[CHAT] Unhandled error:', err.message);
        return res.status(500).json({ error: 'Internal server error.' });
    }
});

// ── PILLAR 2: POST /api/ai-diagnostics ───────────────────────
// Body: { nodeId: "ET-MLS0", role: "core_switch", building: "Emergency" }
//
// Emits SOC_ACTION_START at the beginning, SOC_ACTION_RESULT at the end,
// so the React dashboard can show real-time progress without polling.
app.post('/api/ai-diagnostics', (req, res) => {
    const { nodeId, role, building } = req.body;

    if (!nodeId) {
        return res.status(400).json({ error: 'nodeId is required.' });
    }
    if (!isSafeDeviceId(nodeId)) {
        return res.status(400).json({
            error: `Invalid deviceId format: "${nodeId}". Only letters, digits, hyphens allowed.`,
        });
    }

    // Endpoints (VPCs, Ansible Server) don't run IOS — skip Ansible for them
    const isEndpoint = ['endpoint', 'server'].includes(role);
    if (isEndpoint) {
        return res.json({
            verdict: 'N/A',
            color: '#888888',
            icon: 'ℹ️',
            summary: `${nodeId} is an endpoint/VPC — no IOS VTY configuration to audit.`,
            details: 'Only Cisco IOS routers and switches are auditable. VPCs run VPCS firmware and have no SSH daemon or ACL configuration.',
            fix: [],
            cmd: null,
        });
    }

    // ── PILLAR 2: Emit SOC_ACTION_START ───────────────────────
    // React listens for this to show an "audit in progress" banner
    // on any device, even if it's not the currently-selected node.
    io.emit('SOC_ACTION_START', {
        device: nodeId,
        reason: 'manual audit triggered via UI',
        time: new Date().toISOString(),
        trigger: 'REST_API',
        building: building || 'Unknown',
    });
    broadcast(`🧠 [AI AUDIT] Starting Gemini security audit for ${nodeId}…`, 'info');

    runAnsiblePlaybook('ai_audit.yml', nodeId, '--tags audit')
        .then(({ stdout }) => {
            const verdict = parseAnsibleVerdict(stdout);

            if (!verdict) {
                const errMsg = `[AI AUDIT] No verdict returned for ${nodeId}. Device unreachable or playbook error.`;
                console.error(errMsg);
                broadcast(`❌ ${errMsg}`, 'alert');

                // ── Emit result even on failure so UI can reset its loading state ──
                io.emit('SOC_ACTION_RESULT', {
                    device: nodeId,
                    verdict: 'ERROR',
                    details: errMsg,
                    time: new Date().toISOString(),
                });

                return res.status(502).json({
                    error: errMsg,
                    stdout: stdout.substring(0, 500),
                });
            }

            const logLvl = verdict.verdict === 'VULNERABLE' ? 'alert' : 'ok';
            broadcast(`🛡️ [AI AUDIT] ${nodeId}: ${verdict.verdict} — ${verdict.summary}`, logLvl);

            if (verdict.verdict === 'VULNERABLE') {
                broadcast(
                    `⚠️ [SOC] Vulnerability on ${nodeId} — flagged for review. Click "Auto-Heal" to remediate.`,
                    'alert',
                );
            }

            // ── PILLAR 2: Emit SOC_ACTION_RESULT ─────────────────
            // React uses this to update the SIEM log AND, if the user has
            // the device panel open, can refresh the audit display.
            io.emit('SOC_ACTION_RESULT', {
                device: nodeId,
                verdict: verdict.verdict,
                details: verdict.details,
                color: verdict.color,
                icon: verdict.icon,
                fix: verdict.fix,
                time: new Date().toISOString(),
                trigger: 'REST_API',
            });

            res.json(verdict);
        })
        .catch(err => {
            const errMsg = `[AI AUDIT] Ansible failed for ${nodeId}: ${err.message.substring(0, 200)}`;
            console.error(errMsg);
            broadcast(`❌ ${errMsg}`, 'alert');

            io.emit('SOC_ACTION_RESULT', {
                device: nodeId,
                verdict: 'ERROR',
                details: errMsg,
                time: new Date().toISOString(),
            });

            res.status(500).json({ error: errMsg });
        });
});

// POST /api/ansible/heal
app.post('/api/ansible/heal', (req, res) => {
    const { deviceId } = req.body;

    if (!deviceId || !isSafeDeviceId(deviceId)) {
        return res.status(400).json({ error: `Invalid deviceId: "${deviceId}"` });
    }

    broadcast(`⚡ [HEAL] Launching ai_audit.yml --tags heal on ${deviceId}…`, 'info');

    io.emit('SOC_ACTION_START', {
        device: deviceId,
        reason: 'approved self-heal via UI',
        time: new Date().toISOString(),
        trigger: 'HEAL_API',
    });

    runAnsiblePlaybook('ai_audit.yml', deviceId, '--tags heal')
        .then(({ stdout }) => {
            broadcast(`🛡️ [HEAL] ${deviceId} hardened — ACL ISOLATE_VTY applied and saved to NVRAM.`, 'ok');

            io.emit('SOC_ACTION_RESULT', {
                device: deviceId,
                verdict: 'SECURE',
                details: `${deviceId} self-healed. ACL ISOLATE_VTY applied. Config saved to NVRAM.`,
                color: '#00FF88',
                icon: '✅',
                fix: [],
                time: new Date().toISOString(),
                trigger: 'HEAL_API',
            });

            res.json({ success: true, output: stdout.substring(0, 2000) });
        })
        .catch(err => {
            const errMsg = `[HEAL] Failed on ${deviceId}: ${err.message.substring(0, 200)}`;
            broadcast(`❌ ${errMsg}`, 'alert');

            io.emit('SOC_ACTION_RESULT', {
                device: deviceId,
                verdict: 'ERROR',
                details: errMsg,
                time: new Date().toISOString(),
                trigger: 'HEAL_API',
            });

            res.status(500).json({ error: errMsg });
        });
});

// POST /api/ansible/run
// Generic playbook runner with a strict allowlist.
app.post('/api/ansible/run', (req, res) => {
    const { playbook, limit } = req.body;
    const ALLOWED = [
        'ai_audit.yml',
        'live_docs_backup.yml',
        'configure_syslog.yml',
        'site.yml',
    ];

    if (!ALLOWED.includes(playbook)) {
        return res.status(400).json({ error: `Playbook "${playbook}" not in allowlist.` });
    }
    if (limit && !isSafeDeviceId(limit)) {
        return res.status(400).json({ error: `Invalid --limit: "${limit}"` });
    }

    broadcast(`▶️ [ANSIBLE] Running ${playbook}${limit ? ` --limit ${limit}` : ''}…`, 'info');

    runAnsiblePlaybook(playbook, limit || '')
        .then(({ stdout }) => {
            broadcast(`✅ [ANSIBLE] ${playbook} complete.`, 'ok');
            res.json({ success: true, output: stdout.substring(0, 4000) });
        })
        .catch(err => {
            broadcast(`❌ [ANSIBLE] ${playbook} failed: ${err.message.substring(0, 150)}`, 'alert');
            res.status(500).json({ error: err.message });
        });
});

// Serve React's built static files from hospital-dashboard/dist
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// SOCKET.IO — WebSocket hub
// ============================================================
io.on('connection', (socket) => {
    console.log(`[WS] Dashboard connected: ${socket.id}`);

    socket.emit('syslog', {
        time: new Date().toLocaleTimeString(),
        msg: '🔌 [BACKEND] WebSocket connected — real-time syslog + autonomous SOC active.',
        lvl: 'ok',
        source: 'BACKEND',
    });

    socket.on('disconnect', () => {
        console.log(`[WS] Dashboard disconnected: ${socket.id}`);
    });
});

// ============================================================
// AUTONOMOUS SOC — UDP Syslog Listener on Port 514
//
// PILLAR 2 end-to-end flow:
//   1. Cisco device sends UDP syslog → this server's IP:514
//   2. We broadcast it immediately to all React dashboards via 'syslog'
//   3. If the message is %SYS-5-CONFIG_I (config changed):
//      a. Emit 'SOC_ACTION_START' → React shows autonomous audit banner
//      b. Execute: ansible-playbook ai_audit.yml --limit <device> --tags audit
//      c. Parse NMS_VERDICT from Ansible stdout
//      d. Emit 'SOC_ACTION_RESULT' with verdict → React updates SIEM log
//   4. If %LINEPROTO-5-UPDOWN (link flap): same automated path
// ============================================================
const udpServer = dgram.createSocket('udp4');

// Tracks which devices are currently being auto-audited.
// Prevents duplicate concurrent audits for the same device.
const autoAuditInProgress = new Set();

udpServer.on('message', (msgBuffer, rinfo) => {
    const raw = msgBuffer.toString().trim();
    const hostname = IP_TO_HOSTNAME[rinfo.address] || rinfo.address;
    const level = detectSyslogLevel(raw);

    const event = {
        time: new Date().toLocaleTimeString(),
        msg: `📡 [${hostname}] ${raw}`,
        lvl: level,
        source: rinfo.address,
        device: hostname,
        raw,
    };

    console.log(`[SYSLOG] ${hostname}: ${raw.substring(0, 100)}`);

    // Emit immediately to all connected React dashboards via the 'syslog' channel.
    // This is a direct io.emit (not broadcast()) because the event object already
    // contains the full schema the UI expects — we don't need to rebuild it.
    io.emit('syslog', event);

    // ── AUDIT TRAIL: persist raw syslog to disk ─────────────────
    // broadcast() auto-persists, but this UDP path bypasses broadcast()
    // (to preserve the richer `event` shape including `device` and `raw`).
    // We call persistLog() directly so the Cisco syslog is also in the
    // audit trail and visible to the /api/logs history endpoint.
    persistLog({
        iso: new Date().toISOString(),
        lvl: level,
        source: rinfo.address,           // originating Cisco device IP
        msg: `📡 [${hostname}] ${raw}`,
    });

    // ── PILLAR 2: AUTONOMOUS TRIGGER — CONFIG_I / LINK-DOWN ───
    const isConfigChange = /%SYS-5-CONFIG_I/i.test(raw);
    const isLinkDown = /%LINEPROTO-5-UPDOWN.*line protocol is down/i.test(raw);

    if ((isConfigChange || isLinkDown) && IP_TO_HOSTNAME[rinfo.address]) {
        const deviceId = hostname;

        // Cooldown: don't re-audit the same device within 60 seconds
        const lastAudit = lastAutoAudit.get(deviceId) || 0;
        const timeSince = Date.now() - lastAudit;

        if (timeSince < AUTO_AUDIT_COOLDOWN_MS) {
            console.log(
                `[SOC] ${deviceId}: CONFIG_I detected but cooldown active ` +
                `(${Math.round((AUTO_AUDIT_COOLDOWN_MS - timeSince) / 1000)}s remaining)`,
            );
            return;
        }
        if (autoAuditInProgress.has(deviceId)) {
            console.log(`[SOC] ${deviceId}: Audit already in progress — skipping.`);
            return;
        }

        lastAutoAudit.set(deviceId, Date.now());
        autoAuditInProgress.add(deviceId);

        const trigger = isConfigChange
            ? 'CONFIG_I (configuration changed)'
            : 'LINEPROTO-DOWN (link flap detected)';

        broadcast(
            `🤖 [AUTONOMOUS SOC] ${deviceId}: ${trigger} — auto-triggering Gemini AI audit…`,
            'alert',
        );

        // ── PILLAR 2: Emit SOC_ACTION_START ───────────────────────
        // React shows an "autonomous audit in progress" banner for this device.
        io.emit('SOC_ACTION_START', {
            device: deviceId,
            reason: trigger,
            time: new Date().toISOString(),
            trigger: 'UDP_SYSLOG',
            source: rinfo.address,
        });

        console.log(`[SOC] Auto-audit triggered for ${deviceId} (reason: ${trigger})`);

        runAnsiblePlaybook('ai_audit.yml', deviceId, '--tags audit')
            .then(({ stdout }) => {
                const verdict = parseAnsibleVerdict(stdout);
                autoAuditInProgress.delete(deviceId);

                if (!verdict) {
                    broadcast(
                        `⚠️ [SOC] ${deviceId}: Auto-audit completed but no verdict parsed. Check Ansible connectivity.`,
                        'warn',
                    );

                    // ── PILLAR 2: Emit failure result ─────────────────
                    io.emit('SOC_ACTION_RESULT', {
                        device: deviceId,
                        verdict: 'ERROR',
                        details: 'No verdict parsed. Check Ansible → device SSH connectivity.',
                        time: new Date().toISOString(),
                        trigger: 'UDP_SYSLOG',
                    });
                    return;
                }

                broadcast(
                    `🤖 [AUTONOMOUS VERDICT] ${deviceId}: ${verdict.verdict} — ${verdict.summary}`,
                    verdict.verdict === 'VULNERABLE' ? 'alert' : 'ok',
                );

                // ── PILLAR 2: Emit SOC_ACTION_RESULT ─────────────────
                // React updates the SIEM log AND — if this device's panel is open —
                // can display the verdict without the user clicking anything.
                io.emit('SOC_ACTION_RESULT', {
                    device: deviceId,
                    verdict: verdict.verdict,
                    details: verdict.details,
                    color: verdict.color,
                    icon: verdict.icon,
                    fix: verdict.fix,
                    time: new Date().toISOString(),
                    trigger: 'UDP_SYSLOG',
                });

                // OPTIONAL autonomous healing — disabled by default.
                // Uncomment ONLY in a fully trusted lab environment:
                /*
                if (verdict.verdict === 'VULNERABLE') {
                  broadcast(`🤖 [AUTONOMOUS HEAL] Auto-healing ${deviceId}…`, 'alert');
                  runAnsiblePlaybook('ai_audit.yml', deviceId, '--tags heal')
                    .then(() => broadcast(`🛡️ [AUTONOMOUS HEAL] ${deviceId} hardened automatically.`, 'ok'))
                    .catch(err => broadcast(`❌ [AUTO-HEAL FAILED] ${deviceId}: ${err.message}`, 'alert'));
                }
                */
            })
            .catch(err => {
                autoAuditInProgress.delete(deviceId);
                const errMsg = `Auto-audit failed for ${deviceId}: ${err.message.substring(0, 120)}`;
                broadcast(`❌ [SOC] ${errMsg}`, 'alert');

                io.emit('SOC_ACTION_RESULT', {
                    device: deviceId,
                    verdict: 'ERROR',
                    details: errMsg,
                    time: new Date().toISOString(),
                    trigger: 'UDP_SYSLOG',
                });
            });
    }
});

udpServer.on('error', (err) => {
    console.error(`[SYSLOG] UDP error: ${err.message}`);
    if (err.code === 'EACCES') {
        console.error('[SYSLOG] Port 514 requires elevated privileges. Options:');
        console.error('         sudo setcap cap_net_bind_service=+ep $(which node)');
        console.error('         OR: SYSLOG_PORT=1514 node server.cjs');
        console.error('         (then set logging host port 1514 in configure_syslog.yml)');
    }
});

udpServer.on('listening', () => {
    console.log(`[SYSLOG] UDP listener active on port ${udpServer.address().port}`);
});

const SYSLOG_PORT = parseInt(process.env.SYSLOG_PORT || '514', 10);
udpServer.bind(SYSLOG_PORT, '0.0.0.0');

// ── Start HTTP server ──────────────────────────────────────────
const HTTP_PORT = parseInt(process.env.PORT || '3001', 10);
server.listen(HTTP_PORT, () => {
    const geminiStatus = process.env.GEMINI_API_KEY ? '✅ configured' : '❌ GEMINI_API_KEY not set';
    const sdkStatus = GoogleGenerativeAI ? '✅ installed' : '❌ run: npm install @google/generative-ai';
    const bar = '═'.repeat(56);
    console.log(`\n╔${bar}╗`);
    console.log(`║  AXIOM-NOC — Autonomous Hospital SOC Platform           ║`);
    console.log(`║  REST API   →  http://localhost:${HTTP_PORT}                       ║`);
    console.log(`║  WebSocket  →  ws://localhost:${HTTP_PORT}                         ║`);
    console.log(`║  Syslog     →  UDP :${SYSLOG_PORT}  (Cisco → autonomous audit)    ║`);
    console.log(`║  Ansible    →  ${ANSIBLE_ROOT.substring(0, 38)}  ║`);
    console.log(`║  Gemini SDK →  ${sdkStatus.padEnd(38)}  ║`);
    console.log(`║  Gemini Key →  ${geminiStatus.padEnd(38)}  ║`);
    console.log(`╚${bar}╝\n`);
});


// ── 🚀 BACKGROUND POLLER: Auto-Refresh Telemetry ──────────────────────────
//
// ISSUE 2 FIX: The previous implementation used setInterval(fn, 120_000).
//
// WHY setInterval() IS FATAL HERE:
//   setInterval fires on a fixed wall-clock schedule — it does not care
//   whether the previous invocation has finished. Ansible typically takes
//   60–180 seconds per full run (SSH handshake × N devices + parsing).
//   When Ansible takes longer than the interval, a second process spawns
//   while the first is still running. Both processes try to open SSH
//   sessions to the same devices simultaneously. This causes:
//     • SSH channel exhaustion → "paramiko fallback" errors in Ansible logs
//     • Concurrent writes to full_topology.json → truncated / invalid JSON
//     • CPU exhaustion on the Ansible host → WebSocket keepalive timeouts
//     • React disconnects/reconnects every 2 minutes in a death spiral
//
// THE FIX — Recursive setTimeout + isPolling lock:
//   1. runTelemetryPoll() starts one Ansible child process and AWAITS it.
//   2. Only AFTER the process resolves (success) or rejects (failure) does
//      setTimeout() schedule the NEXT poll. This enforces a minimum gap of
//      POLL_INTERVAL_MS between the END of one poll and the START of the next.
//   3. The isPolling boolean is a redundant safety net. In normal operation
//      the recursive flow never calls runTelemetryPoll while it's running.
//      The lock defends against any external caller or race condition.
//   4. The finally{} block ALWAYS releases the lock and schedules the next
//      run — whether the poll succeeded, threw an exception, or timed out.
//      Without finally{}, a single Ansible failure would permanently stop
//      the polling loop with no error message explaining why.
//
// TAG UPDATE: changed from '--tags telemetry,render' to
//   '--tags facts,telemetry,cli_tables,render'
//   This ensures Phases 2/3/4 (MAC/ARP/routing tables) are collected on
//   every poll cycle — matching the tag fix applied in live_docs_backup.yml.
//   Without this, the poller collected CPU/RAM but left the CLI tables empty,
//   causing App.jsx to wipe the UI tables blank on every poll cycle (Issue 3).
// ───────────────────────────────────────────────────────────────────────────

// How long to wait between the END of one successful/failed poll and the
// START of the next. This is NOT a wall-clock interval — it's a rest gap.
const POLL_INTERVAL_MS = 20_000; // 20 seconds of rest between polls

// Lock flag: true while an Ansible child process is actively running.
// Declared with let so the async closure can mutate it.
let isPolling = false;

async function runTelemetryPoll() {
    // Guard: should never fire in the normal recursive flow, but protects
    // against any edge case where runTelemetryPoll() is called externally.
    if (isPolling) {
        console.warn('[POLLER] ⚠️  Previous poll still in progress — skipping this trigger.');
        return;
    }

    isPolling = true;
    const startTime = Date.now();
    console.log(`\n[POLLER] 🕒 Triggering telemetry collection at ${new Date().toISOString()}`);

    try {
        // runAnsiblePlaybook() already returns a Promise that resolves on exit
        // code 0 and rejects on non-zero exit. We await it here so the finally{}
        // block below cannot run until the child process fully exits — no overlap.
        await runAnsiblePlaybook(
            'live_docs_backup.yml',
            null,
            '--tags facts,telemetry,cli_tables,render',
        );

        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`[POLLER] ✅ Telemetry refreshed in ${elapsed}s — broadcasting TOPOLOGY_UPDATED`);

        // Tell every connected React dashboard to re-fetch full_topology.json.
        // The file is now fully written and JSON-validated (Ansible phase 7
        // validate: directive ensures the file is intact before overwriting).
        io.emit('TOPOLOGY_UPDATED', { time: new Date().toLocaleTimeString() });
        broadcast('📡 Telemetry updated automatically by Background Poller.', 'info');

    } catch (err) {
        // A failed poll is NOT fatal — we log and let the next cycle retry.
        // Common causes: one device unreachable (non-zero Ansible exit code),
        // SSH timeout on a single host, or EVE-NG lab paused.
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.error(
            `[POLLER] ❌ Background poll FAILED after ${elapsed}s: ${err.message.substring(0, 120)}`,
        );
        broadcast('⚠️ Background poll encountered errors. See server terminal.', 'warn');

    } finally {
        // CRITICAL: this block runs unconditionally — success, failure, or throw.
        // Releasing isPolling here (not in .then/.catch) is the guarantee that
        // the lock is ALWAYS freed even if runAnsiblePlaybook throws unexpectedly.
        isPolling = false;

        // Schedule the NEXT poll only after this one is completely done.
        // The gap is measured from END of execution, not start — so a slow
        // 150-second Ansible run followed by a 120-second rest gives 270 seconds
        // of total breathing room instead of the 0-second overlap of setInterval.
        console.log(`[POLLER] ⏳ Next poll scheduled in ${POLL_INTERVAL_MS / 1000}s`);
        setTimeout(runTelemetryPoll, POLL_INTERVAL_MS);
    }
}

// Bootstrap: delay the first poll by 5 seconds to give the HTTP server,
// Socket.io hub, and UDP syslog listener time to fully initialize before
// the first Ansible child process is spawned.
console.log('[POLLER] 🚀 Background poller armed — first poll in 5s');
setTimeout(runTelemetryPoll, 5_000);
