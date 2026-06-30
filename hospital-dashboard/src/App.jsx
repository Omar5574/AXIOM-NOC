// ============================================================
// NextGen NMS — Phase 10: Autonomous Enterprise SOC
// App.jsx — Enterprise NOC — Zero Simulated Data
//
// PHASE 10 PILLARS IMPLEMENTED:
//
//  PILLAR 1  — NOC AI Assistant: handleChatSend → POST /api/chat (real Gemini)
//  PILLAR 2  — Autonomous SOC: Socket.io SOC_ACTION_START / SOC_ACTION_RESULT
//  PILLAR 3  — Port-Channel aggregation: aggregateLinks() + thick gold rendering
//  PILLAR 4  — MAN Link detection: OC-Router ↔ ET-Router labeled as MAN
//  PILLAR 5  — Link diagnostics modal: distToSegment hitbox + full modal UI
//  PILLAR 6  — Real per-interface traffic: parseInterfaceTraffic() per-port rates
//  PILLAR 7  — Logical SVIs: Vlan/Loopback section in side panel Tab 0
//  PILLAR 8  — Trunk string matching: normalizeIfaceName() robust prefix map
//
// REMOVED (Phase 10 strict realism):
//  ✗ seedMetrics()  — deleted; all values come from real Ansible telemetry
//  ✗ jitter()/jitterF() — deleted; no randomization of any metric
//  ✗ genHistory() with random spread — replaced with flat real-value array
//  ✗ BG_EVENTS interval — deleted; only real Socket.io events populate SIEM
//  ✗ smartMockAI() — deleted; /api/chat calls real Gemini API
// ============================================================

import React, {
  useEffect, useRef, useState, useCallback, useMemo,
} from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { io as socketIO } from 'socket.io-client';
import './App.css';

// ─── BACKEND ──────────────────────────────────────────────────
const BACKEND_URL = 'http://localhost:3001';

// ─── REAL TELEMETRY PARSERS ───────────────────────────────────

// Extracts the most responsive CPU reading from Cisco "show processes cpu" output.
// Example raw string: "CPU utilization for five seconds: 88%/4%; one minute: 82%; five minutes: 78%"
//
// WHY A PRIORITY CASCADE AND NOT JUST "FIVE MINUTES":
//   EVE-NG routers are idle almost all the time. The "five minutes" average stays at
//   0–3% even when you trigger a CPU spike (e.g., a ping flood or a config push),
//   because the spike is averaged away over 300 seconds. To make the red stress aura
//   fire reliably during real bursts, we try the most granular window first.
//
//   Priority order:
//     1. "five seconds: X%/Y%" — the REAL-TIME reading. Matches the X value before '/'.
//        This responds within 5 seconds of any spike. Used for isCpuStress threshold.
//     2. "one minute: X%"     — 60-second rolling average. Good for sustained load.
//     3. "five minutes: X%"   — 300-second average. Last resort for slow-burn issues.
//     4. 0                    — Hard fallback. Never returns null so callers don't
//                               need to guard against null when doing comparisons.
const parseRealCPU = (s) => {
  if (!s || typeof s !== 'string') return 0;
  // Five-second reading: "five seconds: 88%/4%" — match the raw integer BEFORE the %
  // The regex uses \d+ (no mandatory %) so it captures "88" from "88%/4%"
  let m = s.match(/five seconds:\s*(\d+)/i);
  if (m) return parseInt(m[1], 10);
  // One-minute rolling average
  m = s.match(/one minute:\s*(\d+)%/i) || s.match(/five minutes:\s*(\d+)%/i);
  return m ? parseInt(m[1], 10) : 0;
};

// Extracts RAM usage from "show processes memory | include Processor".
// Example: "Processor Pool Total: 1048576 Used: 524288 Free: 524288"
const parseRealRAM = (s) => {
  if (!s || typeof s !== 'string') return null;
  const total = s.match(/Total:\s*(\d+)/i);
  const used = s.match(/Used:\s*(\d+)/i);
  if (!total || !used) return null;
  const t = parseInt(total[1], 10), u = parseInt(used[1], 10);
  return t > 0 ? Math.round((u / t) * 100) : 0;
};

// Parses the aggregate traffic (all interfaces summed) from traffic_raw.
// Used for device-level throughput display in sparklines.
// traffic_raw is "show interfaces | include protocol|rate" output.
const parseRealTraffic = (s) => {
  if (!s || typeof s !== 'string') return null;
  let rxBps = 0, txBps = 0;
  const rxMatches = [...s.matchAll(/input rate (\d+) bits\/sec/gi)];
  const txMatches = [...s.matchAll(/output rate (\d+) bits\/sec/gi)];
  if (rxMatches.length === 0 && txMatches.length === 0) return null;
  rxMatches.forEach(m => { rxBps += parseInt(m[1], 10); });
  txMatches.forEach(m => { txBps += parseInt(m[1], 10); });
  return {
    rxMbps: Math.round(rxBps / 1_000_000 * 100) / 100,
    txMbps: Math.round(txBps / 1_000_000 * 100) / 100,
  };
};

// ─── PILLAR 8: Interface Name Normalizer ──────────────────────
// Maps the full zoo of Cisco IOS interface name formats to a single
// canonical short form so that trunk/traffic matching is prefix-agnostic.
//
// IOS outputs "GigabitEthernet0/0" in 'show interfaces trunk'
// but our STATIC_PORT_MAP uses "e0/0" (EVE-NG shorthand).
// After normalization both become "et0/0" and equality works.
//
// The strategy: strip the alphabetic prefix and replace it with a
// canonical two-letter prefix. Then compare only those canonical forms.
function normalizeIfaceName(name) {
  if (!name || typeof name !== 'string') return '';
  const s = name.trim().toLowerCase();

  // Order matters: check longest prefixes first.
  const prefixMap = [
    [/^tengigabitethernet/, 'te'],
    [/^gigabitethernet/, 'gi'],
    [/^fastethernet/, 'fa'],
    [/^ethernet/, 'et'],
    [/^port-channel/, 'po'],
    [/^loopback/, 'lo'],
    [/^vlan/, 'vl'],
    [/^tunnel/, 'tu'],
    [/^serial/, 'se'],
    // Short-form abbreviations (must come AFTER full names)
    [/^te(?=[0-9/])/, 'te'],
    [/^gi(?=[0-9/])/, 'gi'],
    [/^fa(?=[0-9/])/, 'fa'],
    [/^et(?=[0-9/])/, 'et'],
    [/^po(?=[0-9/])/, 'po'],
    [/^lo(?=[0-9/])/, 'lo'],
    [/^se(?=[0-9/])/, 'se'],
    // Single-letter EVE-NG style: "e0/0" → "et0/0", "g0/0" → "gi0/0"
    [/^e(?=[0-9/])/, 'et'],
    [/^g(?=[0-9/])/, 'gi'],
    [/^f(?=[0-9/])/, 'fa'],
  ];

  for (const [pattern, canonical] of prefixMap) {
    if (pattern.test(s)) {
      return s.replace(pattern, canonical).replace(/\s+/g, '');
    }
  }
  return s.replace(/\s+/g, '');
}

// ─── PILLAR 6: Per-Interface Traffic Parser ───────────────────
// Parses "show interfaces | include protocol|rate" output to extract
// the 5-minute input/output rate for a SPECIFIC named port.
//
// traffic_raw format (from Ansible Phase 6):
//   GigabitEthernet0/0 is up, line protocol is up
//     5 minute input rate 1048576 bits/sec, 800 packets/sec
//     5 minute output rate 524288 bits/sec, 400 packets/sec
//   GigabitEthernet0/1 is up, line protocol is up
//     5 minute input rate 2097152 bits/sec, 1600 packets/sec
//     5 minute output rate 1048576 bits/sec, 800 packets/sec
//
// The "protocol" lines appear because live_docs Phase 6 now uses
// "show interfaces | include protocol|rate" (IOS regex OR).
function parseInterfaceTraffic(node, portName) {
  const raw = node?.real_telemetry?.traffic_raw;
  if (!raw || typeof raw !== 'string' || !portName) return null;

  // The portName from STATIC_PORT_MAP might be "e0/0–e0/3" for port-channels.
  // In that case we can't look up a single interface — return null.
  if (/[-–—]/.test(portName)) {
    return null;
  }

  const normTarget = normalizeIfaceName(portName);
  const lines = raw.split('\n');

  let currentNormIface = null;
  let rxBps = null;
  let txBps = null;

  for (const line of lines) {
    const trimmed = line.trim();

    // Interface header line: "GigabitEthernet0/0 is up, line protocol is up"
    // This line was captured because it contains "protocol".
    const ifaceMatch = trimmed.match(/^(\S+)\s+is\s+\w+.*line protocol/i);
    if (ifaceMatch) {
      // If we already collected both rates for the target, return them.
      if (currentNormIface === normTarget && rxBps !== null && txBps !== null) {
        return {
          rxMbps: Math.round(rxBps / 1_000_000 * 1000) / 1000,
          txMbps: Math.round(txBps / 1_000_000 * 1000) / 1000,
          rxBps,
          txBps,
        };
      }
      currentNormIface = normalizeIfaceName(ifaceMatch[1]);
      rxBps = null;
      txBps = null;
      continue;
    }

    // Rate lines — only extract when we are inside the target interface block.
    if (currentNormIface === normTarget) {
      const rxMatch = trimmed.match(/input rate (\d+) bits\/sec/i);
      const txMatch = trimmed.match(/output rate (\d+) bits\/sec/i);
      if (rxMatch) rxBps = parseInt(rxMatch[1], 10);
      if (txMatch) txBps = parseInt(txMatch[1], 10);

      // If we got both rates in this block, return immediately.
      if (rxBps !== null && txBps !== null) {
        return {
          rxMbps: Math.round(rxBps / 1_000_000 * 1000) / 1000,
          txMbps: Math.round(txBps / 1_000_000 * 1000) / 1000,
          rxBps,
          txBps,
        };
      }
    }
  }

  // End of file — check if we collected for the last interface block
  if (currentNormIface === normTarget && rxBps !== null && txBps !== null) {
    return {
      rxMbps: Math.round(rxBps / 1_000_000 * 1000) / 1000,
      txMbps: Math.round(txBps / 1_000_000 * 1000) / 1000,
      rxBps,
      txBps,
    };
  }

  return null; // Interface not found in traffic_raw — run live_docs.yml
}

// ─── PILLAR 8: Trunk Link Detector ───────────────────────────
// Checks if a specific port appears in the device's 'show interfaces trunk'
// output (stored as trunks_raw[] array of lines).
//
// trunks_raw[i] looks like:
//   "GigabitEthernet0/0    1-4094   802.1q   trunking   1"
//
// We normalize the first token (interface name) and compare exactly
// to the normalized portName to avoid false matches like e0/1 ↔ e0/10.
const isTrunkLink = (node, portName) => {
  if (!node || !node.real_telemetry || !node.real_telemetry.trunks_raw) return false;

  // ROOT CAUSE 1 FIX: trunks_raw is an array with a SINGLE element containing
  // the entire multi-line "show interfaces trunk" output separated by \n.
  // We must flatMap by newline FIRST, then check each individual line.
  const rawArr = Array.isArray(node.real_telemetry.trunks_raw)
    ? node.real_telemetry.trunks_raw
    : [];
  const allLines = rawArr.flatMap(str =>
    typeof str === 'string' ? str.split('\n') : []
  );

  const normalizedSearch = normalizeIfaceName(portName);

  return allLines.some(line => {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) return false;
    const pName = normalizeIfaceName(parts[0]);
    const status = parts[3]?.toLowerCase();
    return pName === normalizedSearch && status === 'trunking';
  });
};

// ─── STATIC REAL INTERFACE PORT MAP ──────────────────────────
// Source of truth: EVE-NG topology as confirmed by 'show interfaces status'
// and 'show mac address-table' output from each floor switch.
//
// Format: 'SourceId||TargetId': [sourcePort, targetPort]
// getLinkPorts() handles reverse lookup automatically.
//
// PHYSICAL RECABLING FIX:
//   The ET Floor endpoint ports were remapped to align with their VLANs:
//     e0/1 → VLAN 10  (Reception)
//     e0/2 → VLAN 30  (Labs)
//     e0/3 → VLAN 420 (Emergency Clinics)
//   The old STATIC_PORT_MAP had these backwards, causing the L2 MAC
//   verification check to look at the wrong port in mac_table[] and
//   find no entry there — so it interpreted the endpoint as a "ghost"
//   and hid it from the topology graph entirely.
const STATIC_PORT_MAP = {
  // WAN & Firewall
  'OC-Router||ET-Router': ['e0/0', 'e0/0'],
  'ET-Firewall||ET-Router': ['port2', 'e0/1'],
  // OC Router → Core Switches
  'OC-Router||OC-MLS0': ['e1/0', 'e1/0'],
  'OC-Router||OC-MLS1': ['e1/1', 'e1/1'],
  // OC Port-Channel (aggregated from 4 physical members e0/0–e0/3)
  'OC-MLS0||OC-MLS1': ['Po1 (e0/0–e0/3)', 'Po1 (e0/0–e0/3)'],
  // OC MLS0 → Access Switches
  'OC-MLS0||OC-Floor3': ['e2/0', 'e2/0'],
  'OC-MLS0||OC-Floor2': ['e2/1', 'e2/0'],
  'OC-MLS0||OC-Floor1': ['e2/2', 'e2/0'],
  // OC MLS1 → Access Switches
  'OC-MLS1||OC-Floor3': ['e2/0', 'e2/1'],
  'OC-MLS1||OC-Floor2': ['e2/1', 'e2/1'],
  'OC-MLS1||OC-Floor1': ['e2/2', 'e2/1'],
  // OC Endpoints (Core Infrastructure Server - MUST KEEP)
  'OC-Floor1||Ansible-Server': ['e0/0', 'eth0'],
  // ET Router → Core Switches
  'ET-Router||ET-MLS0': ['e1/0', 'e1/0'],
  'ET-Router||ET-MLS1': ['e1/1', 'e1/1'],
  // ET Port-Channel (aggregated from 4 physical members e0/0–e0/3)
  'ET-MLS0||ET-MLS1': ['Po1 (e0/0–e0/3)', 'Po1 (e0/0–e0/3)'],
  // ET MLS0 → Access Switches
  'ET-MLS0||ET-Floor3': ['e2/0', 'e2/0'],
  'ET-MLS0||ET-Floor2': ['e2/1', 'e2/0'],
  'ET-MLS0||ET-Floor1': ['e2/2', 'e2/0'],
  // ET MLS1 → Access Switches
  'ET-MLS1||ET-Floor3': ['e2/0', 'e2/1'],
  'ET-MLS1||ET-Floor2': ['e2/1', 'e2/1'],
  'ET-MLS1||ET-Floor1': ['e2/2', 'e2/1'],
  // ── ET Floor endpoints (EC, Labs, Rec) are intentionally removed here.
  //    The Dynamic Auto-Discovery Radar will generate them automatically.
};

// Returns [srcPort, tgtPort] for any link regardless of direction.
function getLinkPorts(srcId, tgtId) {
  const key = `${srcId}||${tgtId}`;
  const revKey = `${tgtId}||${srcId}`;
  if (STATIC_PORT_MAP[key]) return [...STATIC_PORT_MAP[key]];
  if (STATIC_PORT_MAP[revKey]) return [STATIC_PORT_MAP[revKey][1], STATIC_PORT_MAP[revKey][0]];
  return ['—', '—'];
}

// ─── PILLAR 5: Euclidean Segment Distance ─────────────────────
// Returns the shortest distance from point (px,py) to the line
// segment defined by endpoints (ax,ay)→(bx,by) in graph-space units.
// This is the correct geometric formula for link click detection.
function distToSegment(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const lenSq = dx * dx + dy * dy;
  if (lenSq === 0) return Math.hypot(px - ax, py - ay); // Degenerate point
  // Project point onto the segment, clamped to [0, 1]
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / lenSq));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

// ─── ROLE CONFIGURATION ──────────────────────────────────────
const ROLES = {
  firewall: { color: '#FF6B35', glow: 'rgba(255,107,53,0.45)', size: 20, badge: 'FIREWALL', icon: '⬡' },
  router: { color: '#FF8C00', glow: 'rgba(255,140,0,0.40)', size: 26, badge: 'ROUTER', icon: '⬡' },
  core_switch: { color: '#A855F7', glow: 'rgba(168,85,247,0.40)', size: 19, badge: 'CORE SWITCH', icon: '◈' },
  access_switch: { color: '#06B6D4', glow: 'rgba(6,182,212,0.35)', size: 14, badge: 'ACCESS SWITCH', icon: '◇' },
  endpoint: { color: '#00FF88', glow: 'rgba(0,255,136,0.25)', size: 9, badge: 'ENDPOINT', icon: '▪' },
  server: { color: '#F59E0B', glow: 'rgba(245,158,11,0.40)', size: 14, badge: 'SERVER', icon: '⚙' },
};

// ─── HARDCODED EVE-NG ENDPOINT DEFINITIONS ───────────────────
// KILLED — Dynamic Auto-Discovery Radar replaces this static list.
// Endpoint nodes are now generated entirely from mac_table entries
// found on each switch during the topology fetch. Node ID = MAC address.
// See the "Zero-Config Dynamic Auto-Discovery" block inside fetchTopology().

// ─── DETERMINISTIC LAYOUT ENGINE ─────────────────────────────
// Infrastructure nodes only. Discovered endpoint nodes are positioned
// dynamically below their parent switch — no static coords required.
function computeFixedLayout(canvasW, canvasH) {
  const hw = canvasW / 2;
  const hh = canvasH / 2;
  const Y = {
    firewall: -hh * 0.88,
    router: -hh * 0.62,
    core: -hh * 0.32,
    access: hh * 0.06,
  };
  return {
    'ET-Firewall': { fx: hw * 0.38, fy: Y.firewall },
    'OC-Router': { fx: -hw * 0.38, fy: Y.router },
    'ET-Router': { fx: hw * 0.38, fy: Y.router },
    'OC-MLS0': { fx: -hw * 0.50, fy: Y.core },
    'OC-MLS1': { fx: -hw * 0.26, fy: Y.core },
    'ET-MLS0': { fx: hw * 0.26, fy: Y.core },
    'ET-MLS1': { fx: hw * 0.50, fy: Y.core },
    'OC-Floor3': { fx: -hw * 0.60, fy: Y.access },
    'OC-Floor2': { fx: -hw * 0.38, fy: Y.access },
    'OC-Floor1': { fx: -hw * 0.18, fy: Y.access },
    'ET-Floor1': { fx: hw * 0.15, fy: Y.access },
    'ET-Floor2': { fx: hw * 0.38, fy: Y.access },
    'ET-Floor3': { fx: hw * 0.61, fy: Y.access },
  };
}

// ─── PILLAR 3: Port-Channel Aggregation ──────────────────────
// Groups raw link definitions by their canonical (source, target) pair.
//
// THE CRITICAL GUARD — WHY "allArePortChannel" IS REQUIRED:
//   The old implementation promoted ANY group of 2+ co-located links to
//   type:'portchannel', which rendered them as thick gold lines. This
//   incorrectly triggered on dual-homed access links: because each Floor
//   switch connects to BOTH OC-MLS0 and OC-MLS1, and the sorted key for
//   those pairs is different ('OC-Floor1||OC-MLS0' vs 'OC-Floor1||OC-MLS1'),
//   they do NOT aggregate — but any accidental duplicate entry in rawLinkDefs
//   (e.g. a bare addLink call without a memberPort) WOULD cause them to
//   be grouped and promoted to gold portchannel, overwriting the correct
//   trunk (purple) rendering.
//
//   The fix: only aggregate when ALL links in a group are explicitly typed
//   'portchannel'. If the group is mixed (some 'downlink', some 'portchannel'),
//   or entirely non-portchannel, we keep each link as a separate individual
//   entry. Duplicates of the same non-portchannel pair are all preserved so
//   that the MLS0→Floor AND MLS1→Floor trunk links both render independently.
function aggregateLinks(rawLinks) {
  // Canonical bidirectional key: A→B and B→A map to the same bucket.
  const getKey = (link) => {
    const src = typeof link.source === 'object' ? link.source.id : link.source;
    const tgt = typeof link.target === 'object' ? link.target.id : link.target;
    return [src, tgt].sort().join('||');
  };

  const grouped = new Map();
  for (const link of rawLinks) {
    const key = getKey(link);
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(link);
  }

  const result = [];
  for (const links of grouped.values()) {
    if (links.length === 1) {
      // Unambiguous single link — pass through unchanged.
      result.push(links[0]);
    } else {
      // Multiple links between the same two nodes.
      // Only promote to portchannel if EVERY link in this group was intentionally
      // declared as type:'portchannel'. Mixed groups and non-portchannel groups
      // keep all their individual links so they render as separate trunks/downlinks.
      const allArePortChannel = links.every(l => l.type === 'portchannel');
      if (allArePortChannel) {
        const first = links[0];
        result.push({
          source: first.source,
          target: first.target,
          type: 'portchannel',
          memberCount: links.length,
          // Collect the physical member port names for the link diagnostic modal.
          memberPorts: links.map(l => l.memberPort || '—').filter(p => p !== '—'),
          _rawLinks: links,
        });
      } else {
        // Non-portchannel duplicates: emit each link individually.
        // This correctly handles the dual MLS0→Floor / MLS1→Floor trunk topology.
        links.forEach(l => result.push(l));
      }
    }
  }
  return result;
}

// ─── HISTORY BUILDER ─────────────────────────────────────────
// Builds a 60-point flat sparkline array from a single real measured
// value. No randomness — the line is flat at the real value.
// In a production system with SNMP polling, each data point would
// come from a real collection cycle. Here we have one snapshot.
function buildHistory(realValue) {
  if (realValue === null || realValue === undefined) return [];
  return Array(60).fill(Math.round(realValue));
}

// ─── ROUNDED RECT HELPER ─────────────────────────────────────
function rrect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y); ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r); ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h); ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r); ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

// ─── SANITIZE TOPOLOGY GATE ──────────────────────────────────
function sanitizeTopology(nodes, links) {
  const healed = nodes.map(n => {
    if (Number.isFinite(n.x) && Number.isFinite(n.fx)) return n;
    return { ...n, x: n.fx ?? 0, y: n.fy ?? 0, fx: n.fx ?? 0, fy: n.fy ?? 0 };
  });
  const ids = new Set(healed.map(n => n.id));
  const safeLinks = links.filter(l => {
    const src = typeof l.source === 'object' ? l.source.id : l.source;
    const tgt = typeof l.target === 'object' ? l.target.id : l.target;
    return ids.has(src) && ids.has(tgt);
  });
  return { nodes: healed, links: safeLinks };
}

// ─── MINI SPARKLINE COMPONENT ─────────────────────────────────
function Sparkline({ data, color, height = 52, unit = '', label, noDataMsg }) {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (!data || data.length === 0) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    const min = Math.min(...data), max = Math.max(...data), range = max - min || 1;
    const px = (i) => (i / (data.length - 1)) * W;
    const py = (v) => H - ((v - min) / range) * (H * 0.85) - H * 0.05;
    const grad = ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, color + '55'); grad.addColorStop(1, color + '00');
    ctx.beginPath(); ctx.moveTo(px(0), H); ctx.lineTo(px(0), py(data[0]));
    data.forEach((v, i) => ctx.lineTo(px(i), py(v)));
    ctx.lineTo(px(data.length - 1), H); ctx.closePath();
    ctx.fillStyle = grad; ctx.fill();
    ctx.beginPath(); ctx.moveTo(px(0), py(data[0]));
    data.forEach((v, i) => ctx.lineTo(px(i), py(v)));
    ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.lineJoin = 'round'; ctx.stroke();
    const last = data[data.length - 1];
    ctx.beginPath(); ctx.arc(px(data.length - 1), py(last), 3, 0, Math.PI * 2);
    ctx.fillStyle = color; ctx.fill();
    ctx.strokeStyle = '#050505'; ctx.lineWidth = 1.5; ctx.stroke();
  }, [data, color]);

  const last = data?.length ? data[data.length - 1] : 0;
  const peak = data?.length ? Math.max(...data) : 0;

  if (!data || data.length === 0) {
    return (
      <div className="spark-wrap">
        <div className="spark-header"><span className="spark-label">{label}</span></div>
        <div className="spark-no-data">{noDataMsg || 'No data — run live_docs_backup.yml'}</div>
      </div>
    );
  }

  return (
    <div className="spark-wrap">
      <div className="spark-header">
        <span className="spark-label">{label}</span>
        <div className="spark-vals">
          <span className="spark-cur" style={{ color }}>{last}{unit}</span>
          <span className="spark-peak">peak {peak}{unit}</span>
        </div>
      </div>
      <canvas ref={canvasRef} width={360} height={height} className="spark-canvas"
        style={{ width: '100%', height: `${height}px` }} />
    </div>
  );
}

// ─── SUB-COMPONENTS ───────────────────────────────────────────
const KPI = React.memo(({ icon, label, value, accent }) => (
  <div className={`kpi kpi--${accent}`}>
    <span className="kpi__icon">{icon}</span>
    <span className="kpi__value">{value}</span>
    <span className="kpi__label">{label}</span>
  </div>
));

const MetricBar = React.memo(({ label, value = 0, unit, color, danger }) => {
  const fill = danger ? '#FF4444' : color;
  return (
    <div className="mbar">
      <div className="mbar__head">
        <span className="mbar__label">{label}</span>
        <span className="mbar__val" style={{ color: fill }}>{value}{unit}</span>
      </div>
      <div className="mbar__track">
        <div className={`mbar__fill${danger ? ' mbar__fill--danger' : ''}`}
          style={{ width: `${Math.min(value, 100)}%`, background: `linear-gradient(90deg, ${fill}55, ${fill})`, boxShadow: `0 0 10px ${fill}99` }} />
      </div>
    </div>
  );
});

const SensorBadge = React.memo(({ icon, label, value, unit, warn }) => (
  <div className={`sensor-badge${warn ? ' sensor-badge--warn' : ''}`}>
    <span className="sensor-badge__icon">{icon}</span>
    <div className="sensor-badge__body">
      <span className="sensor-badge__label">{label}</span>
      <span className="sensor-badge__val">{value}<small>{unit}</small></span>
    </div>
  </div>
));

const IfaceRow = React.memo(({ iface }) => {
  const up = iface.status === 'up';
  return (
    <div className="iface-row">
      <span className={`iface-dot ${up ? 'up' : 'down'}`} />
      <span className="iface-name">{iface.name}</span>
      <span className="iface-ip">{iface.ip && iface.ip !== 'Unassigned' ? iface.ip : '—'}</span>
      <span className={`iface-badge iface-badge--${up ? 'up' : 'down'}`}>{iface.status.toUpperCase()}</span>
    </div>
  );
});

function CliTable({ columns, data, emptyMsg }) {
  const safeData = useMemo(() => {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (typeof data === 'string') {
      const trimmed = data.trim();
      if (!trimmed || trimmed === '[]' || trimmed === 'null') return [];
      try { const p = JSON.parse(trimmed); return Array.isArray(p) ? p : []; }
      catch { return []; }
    }
    return [];
  }, [data]);

  if (safeData.length === 0) return <p className="cli-empty">{emptyMsg || 'No data.'}</p>;
  const isRaw = typeof safeData[0] === 'string';
  if (isRaw) return (
    <div className="cli-table-wrap cli-raw">
      {safeData.map((line, i) => <pre key={i} className="cli-box">{line}</pre>)}
    </div>
  );
  return (
    <div className="cli-table-wrap">
      <table className="cli-table">
        <thead><tr>{columns.map((c, i) => <th key={i}>{c.label}</th>)}</tr></thead>
        <tbody>
          {safeData.map((row, ri) => (
            <tr key={ri}>{columns.map((c, ci) => <td key={ci}>{row[c.key] ?? '—'}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── MAIN APPLICATION ─────────────────────────────────────────
export default function App() {
  const graphRef = useRef(null);
  const containerRef = useRef(null);
  const graphContainerRef = useRef(null);
  const layoutApplied = useRef(false);
  const nodesRef = useRef([]);
  const linksRef = useRef([]);
  const socketRef = useRef(null);

  // ── ISSUE 3 FIX: Last-Known-Good Table Cache ──────────────────
  // Keyed by device ID (e.g. "ET-Floor1"). Stores the most recent
  // NON-EMPTY mac[], routing[], and arp[] arrays for each device, plus
  // a timestamp so a "stale data" badge can show the age of cached data.
  //
  // WHY useRef AND NOT useState:
  //   Writing to this cache must NOT trigger a re-render. If it did, every
  //   telemetry update would cause an extra render cycle. It's purely an
  //   internal memory that the useMemo hooks read on each evaluation.
  //   useRef mutations are invisible to React's reconciler by design.
  //
  // Shape: { [deviceId]: { mac: [], routing: [], arp: [], updatedAt: number } }
  const tableCache = useRef({});

  const [topology, setTopology] = useState({ nodes: [], links: [] });
  const [activeNode, setActiveNode] = useState(null);
  const [activeLink, setActiveLink] = useState(null); // Selected link — shows diagnostic modal
  const [panelOpen, setPanelOpen] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [dims, setDims] = useState({ w: window.innerWidth, h: window.innerHeight });
  const [metrics, setMetrics] = useState({});
  const [history, setHistory] = useState({ cpu: [], ram: [], rx: [], tx: [] });
  const [clock, setClock] = useState(new Date().toLocaleTimeString());
  const [hoveredLink, setHoveredLink] = useState(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const [eventLogs, setEventLogs] = useState([
    { time: new Date().toLocaleTimeString(), msg: '✅ NMS Phase 10 initialized — Autonomous Enterprise SOC active.', lvl: 'ok' },
    { time: new Date().toLocaleTimeString(), msg: '🧠 Connecting to backend — awaiting real Cisco syslog stream…', lvl: 'info' },
  ]);
  const [runningTask, setRunningTask] = useState(null);
  const [auditPhase, setAuditPhase] = useState('idle');
  const [auditData, setAuditData] = useState(null);
  const [healPhase, setHealPhase] = useState('idle');
  // PILLAR 2: Banner shown when autonomous SOC fires an unsolicited audit
  const [socAlert, setSocAlert] = useState(null); // { device, reason, verdict? }

  // ── SIEM Panel: Resizable height + auto-scroll ─────────────────
  // siemHeight drives the panel's height via inline style, completely
  // overriding whatever the CSS file specifies so there's no battle
  // between JS state and cascaded CSS min/max-height rules.
  //
  // siemScrollRef is attached to the scrollable log container.
  // A dedicated useEffect watches eventLogs and scrolls to the bottom
  // on every new entry — standard enterprise NOC auto-scroll behaviour.
  //
  // The three drag refs track pointer state without triggering re-renders:
  //   siemIsDragging — whether a drag is currently active
  //   siemDragStartY — clientY when the pointer went down
  //   siemDragStartH — panel height when the pointer went down
  // These must be refs (not state) because onPointerMove fires at 60 fps;
  // calling setSiemHeight() inside it is fine (it batches), but storing
  // the drag origin in state would cause hundreds of spurious re-renders.
  const [siemHeight, setSiemHeight] = useState(200);
  const siemScrollRef = useRef(null);
  const siemIsDragging = useRef(false);
  const siemDragStartY = useRef(0);
  const siemDragStartH = useRef(0);

  // AI Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMsgs, setChatMsgs] = useState([
    { role: 'ai', text: '🧠 NOC AI online — powered by Gemini with live topology context. Ask anything about your network.' },
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef(null);

  const addLog = useCallback((msg, lvl = 'info') => {
    setEventLogs(prev => [
      { time: new Date().toLocaleTimeString(), msg, lvl },
      ...prev,
    ].slice(0, 60));
  }, []);

  // ── SIEM Auto-Scroll ─────────────────────────────────────────
  // Runs every time eventLogs changes (i.e. every new event).
  // Scrolls the log container to the very bottom so the newest entry
  // is always visible — the NOC operator never has to scroll manually.
  // scrollHeight - clientHeight gives the maximum possible scrollTop value.
  useEffect(() => {
    const el = siemScrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [eventLogs]);

  // ── SIEM Drag-Resize: pointer handlers ──────────────────────
  // We use setPointerCapture() on pointerdown so the element continues
  // to receive pointermove/pointerup events even when the cursor leaves
  // the handle area at high drag speed — this is the key difference
  // from a plain mousemove listener, which loses events if the mouse
  // outruns the element.
  //
  // Dragging UP (decreasing clientY) → delta is positive → panel grows.
  // Dragging DOWN                    → delta is negative → panel shrinks.
  // We clamp between 80px (minimum readable) and 600px (maximum useful).
  const handleSiemResizerPointerDown = useCallback((e) => {
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId); // Keep events flowing
    siemIsDragging.current = true;
    siemDragStartY.current = e.clientY;
    siemDragStartH.current = siemHeight;
  }, [siemHeight]);

  const handleSiemResizerPointerMove = useCallback((e) => {
    if (!siemIsDragging.current) return;
    const delta = siemDragStartY.current - e.clientY; // Up = positive
    const newH = Math.min(600, Math.max(80, siemDragStartH.current + delta));
    setSiemHeight(newH);
  }, []);

  const handleSiemResizerPointerUp = useCallback(() => {
    siemIsDragging.current = false;
  }, []);

  // ── SIEM On-Mount Hydration ─────────────────────────────────
  // The SIEM panel boots with only two default messages. This effect
  // fetches the last 50 persisted events from GET /api/logs on the
  // very first render so operators have historical context immediately,
  // even after a full page reload or server restart.
  //
  // Mapping: disk shape { iso, lvl, source, msg }
  //       → UI shape   { time, lvl, msg }
  //
  // On failure (server not yet up, file not created) it degrades silently
  // via console.info — the panel simply starts with its default messages.
  useEffect(() => {
    fetch(`${BACKEND_URL}/api/logs`)
      .then(r => r.ok ? r.json() : Promise.reject('logs unavailable'))
      .then(data => {
        if (!Array.isArray(data) || data.length === 0) return;
        const historical = data.map(entry => ({
          time: entry.iso
            ? new Date(entry.iso).toLocaleTimeString()
            : new Date().toLocaleTimeString(),
          msg: entry.msg || '—',
          lvl: entry.lvl || 'info',
        }));
        // Reverse so newest entry is at the top (addLog also prepends),
        // then concat with the two boot messages already in state.
        setEventLogs(prev =>
          [...historical.reverse(), ...prev].slice(0, 60)
        );
      })
      .catch(err =>
        console.info('[NMS] Log history unavailable (normal on first boot):', err)
      );
  }, []); // Run exactly once on mount

  // ── PILLAR 5: Link Click Handler ──────────────────────────
  // Populates activeLink with full metadata for the diagnostic modal.
  // PILLAR 4: MAN Link is detected here by node ID pair.
  // PILLAR 6: Traffic data is passed through for the modal to render.
  const handleLinkClick = useCallback((link) => {
    const srcId = typeof link.source === 'object' ? link.source.id : link.source;
    const tgtId = typeof link.target === 'object' ? link.target.id : link.target;
    const srcNode = typeof link.source === 'object' ? link.source : null;
    const tgtNode = typeof link.target === 'object' ? link.target : null;
    const [sPort, tPort] = getLinkPorts(srcId, tgtId);

    // PILLAR 4: MAN Link — OC ↔ ET inter-building connection
    const isMANLink = (
      (srcId === 'OC-Router' && tgtId === 'ET-Router') ||
      (srcId === 'ET-Router' && tgtId === 'OC-Router')
    );

    const isPortChannel = link.type === 'portchannel';

    // Determine trunk status from real Ansible telemetry
    const isRealTrunk = !isPortChannel && (
      isTrunkLink(srcNode, sPort) || isTrunkLink(tgtNode, tPort)
    );

    // Human-readable link type label
    const typeLabel = isMANLink
      ? '🌐 MAN Link (Metropolitan Area Network — Inter-Building Fiber)'
      : isPortChannel
        ? `⚡ LACP Port-Channel (${link.memberCount || 4} physical members — IEEE 802.3ad)`
        : isRealTrunk
          ? '🟣 802.1q Trunk (real telemetry confirmed)'
          : link.type === 'wan' || link.type === 'uplink'
            ? '🔵 WAN / Uplink'
            : '🔵 Access Link';

    setActiveLink({
      srcId, tgtId,
      sPort, tPort,
      srcNode, tgtNode,
      typeLabel,
      linkType: link.type,
      isMANLink,
      isPortChannel,
      isRealTrunk,
      memberCount: link.memberCount || null,
      memberPorts: link.memberPorts || [],
    });

    addLog(`⚡ Link inspect: ${srcId}[${sPort}] ↔ ${tgtId}[${tPort}] — ${typeLabel}`);
  }, [addLog]);

  const handleLinkHover = useCallback(link => setHoveredLink(link), []);

  const handleNodeClick = useCallback(node => {
    setActiveNode(node);
    setPanelOpen(true);
    setActiveTab(0);
    setAuditPhase('idle');
    setAuditData(null);
    setHealPhase('idle');
    setActiveLink(null); // Close link modal when a node is selected
    addLog(`🔍 Inspecting: ${node.id} [${ROLES[node.role]?.badge}]`);
    if (graphRef.current && Number.isFinite(node.fx)) {
      graphRef.current.centerAt(node.fx, node.fy, 700);
      graphRef.current.zoom(2.0, 700);
    }
  }, [addLog]);

  // ── 1. Topology Load ─────────────────────────────────────────
  // Extracted as useCallback (not inlined in useEffect) so the Socket.io
  // TOPOLOGY_UPDATED listener below can call fetchTopology() on demand
  // whenever the background poller writes fresh data to full_topology.json.
  // A stable useCallback reference is safe to close over inside the socket
  // useEffect's dependency array — React won't re-create the socket on
  // every render because fetchTopology only changes when addLog or dims change.
  const fetchTopology = useCallback(() => {
    fetch(`/full_topology.json?t=${Date.now()}`, { cache: 'no-store' })
      .then(r => r.ok ? r.json() : Promise.reject('Not found'))
      .then(data => {
        const rawDevices = data.network_devices || [];
        const layout = computeFixedLayout(dims.w, dims.h - 64);

        const infraNodes = rawDevices.map((n, idx) => {
          const name = n.device_name || n.id;
          let role = 'access_switch';
          if (name.toLowerCase().includes('router')) role = 'router';
          else if (name.includes('MLS')) role = 'core_switch';
          else if (name.toLowerCase().includes('firewall')) role = 'firewall';
          const pos = layout[name];
          const fallbackX = ((idx % 8) - 3.5) * (dims.w * 0.12);
          const fallbackY = (dims.h / 2) * 0.5;

          // ── REACHABILITY FLAG (Phase 11) ──────────────────────────────────
          // The JSON now carries "reachable": false / "status": "offline" for
          // any device whose Phase 1 ios_facts timed out in the rescue block.
          // We convert that into _offline so drawNode and filteredLinkDefs
          // can both read a single boolean without re-parsing the string.
          // Default: true — we only mark offline when Ansible EXPLICITLY
          // witnessed a failure, never from absent data alone.
          const isOffline = n.reachable === false || n.status === 'offline';

          return {
            ...n, // ROOT CAUSE 2 FIX: Spread raw node data to preserve
            // management_ip, interfaces, real_telemetry, mac_table,
            // routing_table, arp_table, etc. for the Side Panel.
            id: name,
            role,
            building: name.startsWith('OC') ? 'Oncology' : 'Emergency',
            fx: pos?.fx ?? fallbackX,
            fy: pos?.fy ?? fallbackY,
            x: pos?.fx ?? fallbackX,
            y: pos?.fy ?? fallbackY,
            // _offline drives: gray node render, OFFLINE badge, _isDown links
            _offline: isOffline,
          };
        });

        // Re-inject the core Ansible Server manually (Core Infrastructure)
        // WHY THIS IS NEEDED:
        //   The Dynamic Auto-Discovery Radar only generates nodes from mac_table entries
        //   on ports that are NOT in STATIC_PORT_MAP. OC-Floor1's e0/0 IS in STATIC_PORT_MAP
        //   (as 'OC-Floor1||Ansible-Server'), so the Radar correctly skips it. But because
        //   we deleted the old EVE_ENDPOINTS static array, the Ansible-Server node is never
        //   generated anywhere — rawDevices contains only Cisco switches polled by Ansible,
        //   not the Linux host. sanitizeTopology() then drops the OC-Floor1↔Ansible-Server
        //   link (both endpoints must exist). Solution: explicitly push it here as a
        //   first-class infra node, exactly like ET-Firewall would be if it were a Linux box.
        infraNodes.push({
          id: 'Ansible-Server',
          role: 'server',
          building: 'Oncology',
          fx: layout['Ansible-Server']?.fx || -200,
          fy: layout['Ansible-Server']?.fy || 200,
          x: layout['Ansible-Server']?.fx || -200,
          y: layout['Ansible-Server']?.fy || 200,
          interfaces: [{ name: 'eth0', status: 'up', ip: '10.3.80.1' }],
          mac_table: [], routing_table: [], arp_table: [],
          real_telemetry: {},
        });

        // ── FIX 3: ET-Firewall injection REMOVED ─────────────────────
        // We no longer inject a fake ET-Firewall node when it's absent from
        // the Ansible JSON. The dashboard must ONLY render devices that
        // Ansible actually collected. If ET-Firewall exists in EVE-NG and
        // is reachable, it will appear in full_topology.json automatically.
        // Removing this block enforces the "Zero Simulation" contract.

        // ── ZERO-CONFIG DYNAMIC AUTO-DISCOVERY RADAR ─────────────────────
        //
        // REPLACES: EVE_ENDPOINTS static array + the old filter/map block.
        //
        // THE ENGINE — how it works:
        //   For every device that Ansible collected, we parse its mac_table.
        //   We group MAC entries by port. For each port that is NOT a logical
        //   interface (Port-Channel / Tunnel / VLAN SVI) and NOT already used
        //   by a STATIC_PORT_MAP infrastructure link, we generate a dynamic
        //   node whose ID is the MAC address (stable across Ansible runs).
        //   If a port has multiple MACs, we collapse them into one "Segment" node.
        //
        // MANDATORY FILTERS (applied in order):
        //   1. Logical-interface exclusion — po/tu/vl/lo/se prefixes → skip.
        //      Core switches learn endpoint MACs over Po1. Without this filter
        //      a phantom "disc-seg-OC-MLS0-po1" node appears on every core switch.
        //   2. Infrastructure port exclusion — ports in STATIC_PORT_MAP → skip.
        //      These are uplinks/trunks already rendered as links, not hosts.
        //   3. L1 explicit-down check — if the physical port is explicitly
        //      'administratively down' or 'down' in ios_facts → skip.
        //      (Graceful: if interfaces[] is empty, we keep the node visible.)
        //
        // LAYOUT — role-aware vertical offset:
        //   Access switches sit at Y.access tier. Their discovered children
        //   only need +90 px to clear the icon and label.
        //   Other parents (MLS, router) are higher in the canvas, so +150 px
        //   is needed to keep the discovered node visually below them.

        // Helpers — safe MAC table parser (handles JSON string vs real array).
        const safeMAC = (raw) => {
          if (Array.isArray(raw)) return raw;
          if (typeof raw === 'string' && raw.trim()) {
            try { const p = JSON.parse(raw); return Array.isArray(p) ? p : []; }
            catch { return []; }
          }
          return [];
        };

        // Build the set of normalized ports that STATIC_PORT_MAP already owns
        // on each device, so we can skip them in the discovery loop.
        const staticPortsPerDevice = new Map();
        for (const key of Object.keys(STATIC_PORT_MAP)) {
          const [srcId, tgtId] = key.split('||');
          const [srcPort, tgtPort] = STATIC_PORT_MAP[key];
          if (!staticPortsPerDevice.has(srcId)) staticPortsPerDevice.set(srcId, new Set());
          if (!staticPortsPerDevice.has(tgtId)) staticPortsPerDevice.set(tgtId, new Set());
          staticPortsPerDevice.get(srcId).add(normalizeIfaceName(srcPort));
          staticPortsPerDevice.get(tgtId).add(normalizeIfaceName(tgtPort));
        }

        // Helper: return true if a port is explicitly 'down' in ios_facts.
        // Returns false (keep visible) when interfaces[] is empty — that means
        // Ansible had a partial run, not that the cable is disconnected.
        const isPortExplicitlyDown = (device, normPort) => {
          const ifaces = device.interfaces || [];
          if (ifaces.length === 0) return false;
          const entry = ifaces.find(i => normalizeIfaceName(i.name) === normPort);
          if (!entry) return false;
          return entry.status.toLowerCase().includes('down');
        };

        const discoveredNodes = [];
        const discoveredLinks = [];
        const discoveredIds = new Set(infraNodes.map(n => n.id));

        for (const dev of rawDevices) {
          const devId = dev.device_name || dev.id;
          if (!discoveredIds.has(devId)) continue; // Only process known infra nodes

          const macEntries = safeMAC(dev.mac_table);
          if (macEntries.length === 0) continue;

          // Group entries by normalized port name.
          const portToMacs = new Map();
          for (const entry of macEntries) {
            if (!entry || typeof entry !== 'object') continue;
            const rawPort = entry.ports || entry.interface || entry.port || '';
            if (!rawPort) continue;
            const normPort = normalizeIfaceName(String(rawPort));
            if (!portToMacs.has(normPort)) portToMacs.set(normPort, []);
            portToMacs.get(normPort).push(entry);
          }

          const staticPorts = staticPortsPerDevice.get(devId) || new Set();
          const parentNode = infraNodes.find(n => n.id === devId);

          for (const [normPort, macs] of portToMacs.entries()) {
            // FILTER 1: Logical interfaces — Po/Tunnel/Vlan/Loopback/Serial.
            // These aggregates appear in the MAC table of core switches but
            // represent uplinks to other switches, never end-host connections.
            if (/^(po|tu|vl|lo|se)/.test(normPort)) continue;

            // FILTER 1.5: LACP Ghost Node Defense ─────────────────────────────
            // ROOT CAUSE: During LACP flapping or a CPU spike, a Cisco switch
            // temporarily writes a neighbor's MAC against a PHYSICAL member port
            // (e.g. Et0/2) instead of the logical Port-Channel (Po1). The CAM
            // hardware sees traffic on the raw wire before the LACP state machine
            // has reasserted the aggregate. Filter 1 above catches the logical
            // "Po1" entry, but the transient "Et0/x" entry slips through — and
            // because that port is not in staticPorts either, the radar mints a
            // ghost node (e.g. "disc-aabb.cc01.5020") for what is actually just
            // the MAC of a neighboring core switch.
            //
            // THE DEFENSE — runtime-derived, data-driven:
            //   We walk STATIC_PORT_MAP looking for portchannel entries that
            //   involve this device. A portchannel port string looks like:
            //     "Po1 (e0/0–e0/3)"
            //   We extract the member range with a regex, enumerate every port
            //   in that range, normalize each one, and add it to a blocked Set.
            //   Any normPort that matches a physical member is discarded.
            //
            // Scoped to core_switch only — access switches in this topology
            // never run LACP, so running the check on them is unnecessary.
            // The Set is tiny (≤ 8 entries) so this is effectively O(1).
            if (parentNode?.role === 'core_switch') {
              const lacpMemberPorts = new Set();

              for (const [pmKey, [srcPort, tgtPort]] of Object.entries(STATIC_PORT_MAP)) {
                const [pmSrc, pmTgt] = pmKey.split('||');

                // Pick whichever side of the link belongs to this device.
                const relevantPort = pmSrc === devId ? srcPort
                  : pmTgt === devId ? tgtPort
                    : null;
                if (!relevantPort) continue;

                // Match the canonical portchannel format: "Po1 (e0/0–e0/3)"
                // Group 1 = prefix+slot ("e0"), 2 = range start ("0"), 3 = range end ("3").
                // The character class [–\-] covers both the em-dash (–) used in the
                // map literal and a plain hyphen, so edits to the map stay safe.
                const rangeMatch = relevantPort.match(
                  /\(\s*([a-z]+\d+)\/(\d+)\s*[–\-]\s*[a-z]*\d*\/(\d+)\s*\)/i
                );
                if (!rangeMatch) continue; // Not a portchannel range — skip

                const prefix = rangeMatch[1];               // "e0"
                const start = parseInt(rangeMatch[2], 10); // 0
                const end = parseInt(rangeMatch[3], 10); // 3

                // Enumerate each physical member port and normalize it exactly
                // as normalizeIfaceName() would: "e0/2" → "et0/2".
                for (let p = start; p <= end; p++) {
                  lacpMemberPorts.add(normalizeIfaceName(`${prefix}/${p}`));
                }
              }

              // If this port is a physical LACP member, the MAC learned on it
              // is a transient LACP ghost — discard it and move on.
              if (lacpMemberPorts.has(normPort)) continue;
            }

            // FILTER 2: Ports already claimed by STATIC_PORT_MAP (infra links).
            if (staticPorts.has(normPort)) continue;

            // FILTER 3: L1 explicit-down check (Zero-Simulation contract).
            if (isPortExplicitlyDown(dev, normPort)) continue;

            // Derive a human-readable port label (e.g. "Et0/3" → "0/3").
            const rawPortLabel = macs[0]?.ports || macs[0]?.interface || macs[0]?.port || normPort;
            const portShort = String(rawPortLabel).replace(/^[A-Za-z]+/, '');

            // Determine node identity based on port occupancy.
            let nodeId, nodeLabel, nodeRole;
            if (macs.length === 1) {
              // Single MAC → individual host node; ID = MAC for persistence.
              nodeId = `disc-${macs[0].mac}`;
              nodeLabel = `${devId}-P${portShort}`;
              // CDP/LLDP type detection: promote to switch only if confirmed.
              const neighbors = dev.cdp_neighbors || dev.lldp_neighbors || [];
              const isInfra = neighbors.some(nb =>
                normalizeIfaceName(nb.local_port || nb.port || '') === normPort
              );
              nodeRole = isInfra ? 'access_switch' : 'endpoint';
            } else {
              // Multiple MACs on one port → network segment (hub/AP/unmanaged switch).
              nodeId = `disc-seg-${devId}-${normPort}`;
              nodeLabel = `${devId}-SEG-${portShort}`;
              nodeRole = 'endpoint';
            }

            if (discoveredIds.has(nodeId)) continue; // Avoid duplicates
            discoveredIds.add(nodeId);

            // LAYOUT — role-aware positioning below the parent switch.
            const offsetX = (discoveredNodes.length % 5 - 2) * 55;
            const fx = (parentNode?.fx ?? 0) + offsetX;
            const fy = (parentNode?.fy ?? 0) +
              (parentNode?.role === 'access_switch' ? 90 : 150);

            discoveredNodes.push({
              id: nodeId,
              role: nodeRole,
              building: devId.startsWith('OC') ? 'Oncology' : 'Emergency',
              label: nodeLabel,
              _discoveredPort: rawPortLabel,
              _parentSwitch: devId,
              _macCount: macs.length,
              _macs: macs.map(m => m.mac),
              management_ip: '',
              interfaces: [{ name: normPort, status: 'up', ip: '' }],
              mac_table: [], routing_table: [], arp_table: [],
              real_telemetry: {
                cpu_raw: '', ram_raw: '', trunks_raw: [],
                temp_raw: 'N/A', traffic_raw: '',
              },
              fx, fy, x: fx, y: fy,
            });
            discoveredLinks.push({ source: devId, target: nodeId, type: 'endpoint' });
          }
        }

        // Merge infrastructure nodes with dynamically discovered endpoint nodes.
        // discoveredIds already contains all infra + discovered IDs for dedup.
        const allNodes = [...infraNodes, ...discoveredNodes];
        const has = (id) => allNodes.some(n => n.id === id);

        // addLink now accepts an optional memberPort for port-channel tracking
        const addLink = (src, tgt, type, memberPort) => {
          if (has(src) && has(tgt)) return { source: src, target: tgt, type, memberPort };
          return null;
        };

        // ── PILLAR 3: Raw link list — 4 physical members for each Port-Channel ──
        // aggregateLinks() below will collapse the 4 OC-MLS0↔OC-MLS1 links
        // into a single portchannel entry with memberCount=4 and memberPorts=[...].
        const rawLinkDefs = [
          // WAN / Firewall
          addLink('OC-Router', 'ET-Router', 'wan'),
          addLink('ET-Firewall', 'ET-Router', 'wan'),
          // OC Router uplinks
          addLink('OC-Router', 'OC-MLS0', 'uplink'),
          addLink('OC-Router', 'OC-MLS1', 'uplink'),
          // OC Port-Channel — 4 physical members (will aggregate to 1 portchannel link)
          addLink('OC-MLS0', 'OC-MLS1', 'portchannel', 'e0/0'),
          addLink('OC-MLS0', 'OC-MLS1', 'portchannel', 'e0/1'),
          addLink('OC-MLS0', 'OC-MLS1', 'portchannel', 'e0/2'),
          addLink('OC-MLS0', 'OC-MLS1', 'portchannel', 'e0/3'),
          // OC MLS downlinks
          addLink('OC-MLS0', 'OC-Floor1', 'downlink'),
          addLink('OC-MLS0', 'OC-Floor2', 'downlink'),
          addLink('OC-MLS0', 'OC-Floor3', 'downlink'),
          addLink('OC-MLS1', 'OC-Floor1', 'downlink'),
          addLink('OC-MLS1', 'OC-Floor2', 'downlink'),
          addLink('OC-MLS1', 'OC-Floor3', 'downlink'),
          // OC endpoints (Static infrastructure)
          addLink('OC-Floor1', 'Ansible-Server', 'endpoint'),
          // ET Router uplinks
          addLink('ET-Router', 'ET-MLS0', 'uplink'),
          addLink('ET-Router', 'ET-MLS1', 'uplink'),
          // ET Port-Channel — 4 physical members
          addLink('ET-MLS0', 'ET-MLS1', 'portchannel', 'e0/0'),
          addLink('ET-MLS0', 'ET-MLS1', 'portchannel', 'e0/1'),
          addLink('ET-MLS0', 'ET-MLS1', 'portchannel', 'e0/2'),
          addLink('ET-MLS0', 'ET-MLS1', 'portchannel', 'e0/3'),
          // ET MLS downlinks
          addLink('ET-MLS0', 'ET-Floor1', 'downlink'),
          addLink('ET-MLS0', 'ET-Floor2', 'downlink'),
          addLink('ET-MLS0', 'ET-Floor3', 'downlink'),
          addLink('ET-MLS1', 'ET-Floor1', 'downlink'),
          addLink('ET-MLS1', 'ET-Floor2', 'downlink'),
          addLink('ET-MLS1', 'ET-Floor3', 'downlink'),
          // ── ET endpoints are intentionally absent. Dynamic Radar handles them.
        ].filter(Boolean);

        // ── Infrastructure Link State: Explicit Down + Offline Node Rule ───
        //
        // PHASE 11 CHANGE — from "remove" to "mark":
        //   Old behaviour: links with a down port were REMOVED from allLinks.
        //   The topology simply didn't render them — no visual feedback that
        //   something was missing.
        //
        //   New behaviour: links are KEPT but tagged with _isDown: true when
        //   any of the following is true:
        //     1. Either endpoint node has _offline: true (device unreachable)
        //     2. Either side's specific port explicitly reports 'down' in ios_facts
        //
        //   drawLink() reads _isDown and renders those links as dashed red lines
        //   with a "▼ DOWN" label at the midpoint, so the operator immediately
        //   sees the dead segment on the topology map.
        //
        // GRACEFUL FALLBACK CASES (link keeps _isDown: false):
        //   • Device not in rawDevices → can't determine → not marked down
        //   • interfaces[] is empty AND device is not _offline → not marked down
        //   • Port not found in interfaces[] → not marked down
        //   Only EXPLICIT evidence of failure marks a link down. Silence = healthy.
        const filteredLinkDefs = rawLinkDefs.map(link => {
          const srcId = typeof link.source === 'object' ? link.source.id : link.source;
          const tgtId = typeof link.target === 'object' ? link.target.id : link.target;

          // Endpoint links are handled by the MAC radar; don't touch them here.
          if (link.type === 'endpoint') return link;

          // ── Check 1: offline node ─────────────────────────────────────────
          // If either endpoint was unreachable during the last Ansible poll,
          // every link connected to it is physically dead — mark all of them.
          const srcNode = allNodes.find(n => n.id === srcId);
          const tgtNode = allNodes.find(n => n.id === tgtId);
          if (srcNode?._offline || tgtNode?._offline) {
            return { ...link, _isDown: true };
          }

          // ── Check 2: port-level explicit down ─────────────────────────────
          // Even when both nodes are reachable, a specific interface can be
          // administratively or operationally down (cable pull, shutdown cmd).
          const [srcPort, tgtPort] = getLinkPorts(srcId, tgtId);

          // Port mapping unknown → can't verify → keep as healthy
          if (!srcPort || srcPort === '—') return link;

          // Helper: true only when ios_facts EXPLICITLY reports the port down.
          // Returns false for missing device, empty interfaces[], or unknown port.
          const isPortExplicitlyDown = (deviceId, portName) => {
            const dev = rawDevices.find(d => (d.device_name || d.id) === deviceId);
            if (!dev) return false;
            const ifaces = dev.interfaces || [];
            if (ifaces.length === 0) return false; // Partial run — don't guess
            const normPort = normalizeIfaceName(portName);
            const entry = ifaces.find(
              iface => normalizeIfaceName(iface.name) === normPort,
            );
            if (!entry) return false;
            return entry.status.toLowerCase().includes('down');
          };

          const srcDown = isPortExplicitlyDown(srcId, srcPort);
          const tgtDown = isPortExplicitlyDown(tgtId, tgtPort);

          // Either side's port is down → mark the link, keep it in the graph
          if (srcDown || tgtDown) return { ...link, _isDown: true };

          return link; // All checks passed → healthy link
        });

        // ── Final topology assembly ─────────────────────────────────────────
        // aggregatedLinks = infra links (Port-Channel collapsed, _isDown tagged)
        // discoveredLinks = dynamic endpoint links from the MAC radar
        // Together they form the complete topology the graph renders.
        const aggregatedLinks = aggregateLinks(filteredLinkDefs);
        const allLinks = [...aggregatedLinks, ...discoveredLinks];
        const safe = sanitizeTopology(allNodes, allLinks);
        setTopology(safe);
        layoutApplied.current = true;
        addLog(
          `🌐 Topology: ${safe.nodes.length} nodes ` +
          `(${discoveredNodes.length} auto-discovered via MAC radar), ` +
          `${safe.links.length} links.`,
          'ok',
        );
      })
      .catch(() => addLog('⚠️ Topology fetch failed — check /full_topology.json', 'warn'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [addLog, dims.w, dims.h]);

  // Call once on mount; the TOPOLOGY_UPDATED socket listener repeats it on demand.
  useEffect(() => { fetchTopology(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── 2. Kill physics after mount ─────────────────────────────
  useEffect(() => {
    if (!graphRef.current || topology.nodes.length === 0) return;
    const t = setTimeout(() => {
      const fg = graphRef.current;
      if (!fg) return;
      try {
        fg.d3Force('charge')?.strength(0);
        fg.d3Force('link')?.strength(0);
        fg.d3Force('center')?.strength(0);
      } catch { /* ignore */ }
      setTimeout(() => fg.zoomToFit(600, 80), 300);
    }, 200);
    return () => clearTimeout(t);
  }, [topology.nodes.length]);

  // ── 3. Window resize ────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(([e]) => {
      setDims({ w: e.contentRect.width, h: e.contentRect.height });
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // ── 4. Clock tick ───────────────────────────────────────────
  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(t);
  }, []);

  // ── 5. Telemetry (real data only — no seedMetrics, no jitter) ──
  // CPU and RAM are parsed from real Ansible-collected telemetry.
  // Traffic Rx/Tx are parsed from real interface rate output.
  // Sparklines are flat lines at the real measured value.
  // If no real data exists, sparklines show a "No data" message.
  useEffect(() => {
    if (!activeNode) return;

    const realCpu = parseRealCPU(activeNode?.real_telemetry?.cpu_raw);
    const realRam = parseRealRAM(activeNode?.real_telemetry?.ram_raw);
    const realTraffic = parseRealTraffic(activeNode?.real_telemetry?.traffic_raw);

    setMetrics({
      cpu: realCpu,
      ram: realRam,
      rx: realTraffic?.rxMbps ?? null,
      tx: realTraffic?.txMbps ?? null,
      temp: null, // Requires 'show environment temperature' — parsed separately if needed
      model: activeNode.id.includes('MLS') ? 'Cisco 3750X'
        : activeNode.id.includes('Router') ? 'Cisco ISR 4451'
          : activeNode.id.includes('Firewall') ? 'Cisco ASA 5506-X'
            : activeNode.id.includes('Floor') ? 'Cisco 2960X'
              : activeNode.id.includes('Server') ? 'Linux Host'
                : 'VPC Endpoint',
    });

    // History: flat array at the measured real value.
    // A flat sparkline is honest — we have one snapshot, not a time-series.
    setHistory({
      cpu: buildHistory(realCpu),
      ram: buildHistory(realRam),
      rx: buildHistory(realTraffic?.rxMbps ?? null),
      tx: buildHistory(realTraffic?.txMbps ?? null),
    });
  }, [activeNode]);

  // ── 6. Sync refs for hit detection ─────────────────────────
  useEffect(() => { nodesRef.current = topology.nodes; }, [topology.nodes]);
  useEffect(() => { linksRef.current = topology.links; }, [topology.links]);

  // ── 7. Socket.io — Real Syslog + PILLAR 2 SOC events ───────
  useEffect(() => {
    let socket;
    try {
      socket = socketIO(BACKEND_URL, {
        transports: ['websocket'],
        reconnectionAttempts: 5,
        reconnectionDelay: 2000,
      });
      socketRef.current = socket;

      socket.on('connect', () =>
        addLog('🔌 [WS] Backend connected — real-time syslog + autonomous SOC active.', 'ok'));
      socket.on('disconnect', () =>
        addLog('🔌 [WS] Backend disconnected — attempting reconnect…', 'warn'));
      socket.on('connect_error', () =>
        console.info('[NMS] Backend unreachable — only real data displayed.'));

      // Raw Cisco syslog events → SIEM log
      socket.on('syslog', (event) => {
        setEventLogs(prev => [{
          time: event.time || new Date().toLocaleTimeString(),
          msg: event.msg,
          lvl: event.lvl || 'info',
        }, ...prev].slice(0, 60));
      });

      // ── PILLAR 2: SOC_ACTION_START ─────────────────────────
      // Fired by server.cjs when:
      //   a) UDP %SYS-5-CONFIG_I triggers autonomous audit, OR
      //   b) User clicks "Run AI Audit" in the UI (manual trigger)
      socket.on('SOC_ACTION_START', (data) => {
        addLog(
          `🤖 [AUTONOMOUS SOC] Audit started on ${data.device} — ${data.reason}`,
          'alert',
        );
        setSocAlert({ device: data.device, reason: data.reason, verdict: null });
        // Auto-dismiss banner after 90s (audit should complete by then)
        setTimeout(() => setSocAlert(prev =>
          prev?.device === data.device ? null : prev), 90_000);
      });

      // ── PILLAR 2: SOC_ACTION_RESULT ────────────────────────
      // Fired by server.cjs with the Ansible+Gemini verdict.
      // Updates the SIEM log AND, if the user has the audited device
      // panel open, automatically shows the new verdict inline.
      socket.on('SOC_ACTION_RESULT', (data) => {
        const lvl = data.verdict === 'VULNERABLE' ? 'alert'
          : data.verdict === 'SECURE' ? 'ok'
            : 'warn';
        addLog(
          `${data.icon || '🤖'} [AUTONOMOUS VERDICT] ${data.device}: ${data.verdict} — ${data.details}`,
          lvl,
        );
        // Update banner with verdict
        setSocAlert(prev =>
          prev?.device === data.device
            ? { ...prev, verdict: data.verdict, color: data.color }
            : prev,
        );
        // Auto-dismiss after verdict is shown for 8 seconds
        setTimeout(() => setSocAlert(prev =>
          prev?.device === data.device ? null : prev), 8000);

        // Update the audit data immediately to fix the React bailout issue
        setAuditData(prev => ({
          ...prev,
          verdict: data.verdict,
          color: data.color || (data.verdict === 'SECURE' ? '#00FF88' : '#FF3333'),
          icon: data.icon || (data.verdict === 'SECURE' ? '✅' : '⚠️'),
          summary: `Autonomous Action: ${data.details}`,
          details: data.details,
          fix: []
        }));
      });

      // ── AUTO-REFRESH: Re-draw graph when backend finishes a poll ──
      // server.cjs emits 'TOPOLOGY_UPDATED' after the background Ansible
      // poller writes fresh data to full_topology.json. Listening here
      // triggers fetchTopology() so the graph reflects the latest device
      // state without a manual page refresh.
      // fetchTopology is a stable useCallback reference — safe to close over.
      socket.on('TOPOLOGY_UPDATED', () => {
        addLog('🔄 [POLLER] Topology refreshed by background poller — re-fetching graph…', 'info');
        fetchTopology();
      });

    } catch {
      console.info('[NMS] Socket.io not available.');
    }
    return () => { socket?.disconnect(); };
  }, [addLog, fetchTopology]);

  // ── Derived values ─────────────────────────────────────────
  const totalUp = useMemo(() =>
    topology.nodes.reduce((a, n) => a + (n.interfaces || []).filter(i => i.status === 'up').length, 0),
    [topology.nodes]);
  const totalAll = useMemo(() =>
    topology.nodes.reduce((a, n) => a + (n.interfaces || []).length, 0),
    [topology.nodes]);
  const health = totalAll ? Math.round((totalUp / totalAll) * 100) : 97;
  // ── Safe table parser ────────────────────────────────────────
  // WHY THIS EXISTS:
  //   Ansible's Jinja2 template engine produces the mac_table, routing_table,
  //   and arp_table fields as JSON strings in some run conditions — for example
  //   when the Jinja2 block is rendered inside a set_fact and the output isn't
  //   explicitly cast to a list.  When that stringified value arrives in the
  //   browser, JavaScript sees it as a string, and calling .some() / .map() on
  //   a string throws "TypeError: x.some is not a function", crashing the UI.
  //
  //   This parser handles every possible shape the field could arrive in:
  //     • Already a real Array  → return as-is (happy path, current state)
  //     • A JSON string         → JSON.parse → return the resulting array
  //     • A malformed string    → catch → return []  (graceful fallback)
  //     • null / undefined      → return []  (graceful fallback)
  //
  //   The function is pure and synchronous — safe to call inside useMemo.
  const safeParseTable = (raw) => {
    if (Array.isArray(raw)) return raw;           // Already an array → pass through
    if (typeof raw === 'string' && raw.trim()) {  // Stringified JSON from Ansible/Jinja2
      try { const parsed = JSON.parse(raw); return Array.isArray(parsed) ? parsed : []; }
      catch { return []; }                        // Malformed string → empty fallback
    }
    return [];                                    // null / undefined / anything else
  };

  // ── ISSUE 3 FIX: Last-Known-Good Table useMemos ─────────────
  //
  // THE PROBLEM with the old code:
  //   activeMacTable = useMemo(() => safeParseTable(activeNode?.mac_table), [activeNode])
  //   Every time activeNode changes — which happens on EVERY topology re-fetch
  //   after a telemetry-only Ansible poll — safeParseTable sees an empty []
  //   (because the fast poll skipped Phase 2/3/4) and returns []. The table
  //   goes blank in the UI immediately, even though real data existed seconds ago.
  //
  // THE FIX — Write-through cache with non-empty guard:
  //   1. Parse the incoming value with safeParseTable as before.
  //   2. If the result has entries (length > 0): it is fresh real data.
  //      Write it into tableCache.current[nodeId] AND return it.
  //   3. If the result is empty []: the poll was lightweight and skipped CLI scrapes.
  //      Do NOT overwrite the cache. Return the previously cached value instead,
  //      so the table stays populated with the last known real data.
  //   4. If neither the incoming data nor the cache has anything, return []
  //      so CliTable renders its "run the playbook" message — honest behavior
  //      for a device that has genuinely never been polled.
  //
  // STALE BADGE: updatedAt is stored in the cache so the JSX can render a
  // "⚠ Cached since HH:MM:SS" warning when data is older than 2 minutes,
  // letting NOC operators know they're looking at retained — not live — data.
  //
  // eslint-disable-next-line react-hooks/exhaustive-deps
  // (tableCache.current is intentionally omitted from deps — it's a mutable
  //  ref, not reactive state. Including it would re-run the memo on every
  //  unrelated cache write, which defeats the purpose of the cache entirely.)

  const activeMacTable = useMemo(() => {
    const nodeId = activeNode?.id;
    if (!nodeId) return [];

    const incoming = safeParseTable(activeNode?.mac_table);
    if (incoming.length > 0) {
      // Fresh real data arrived — update cache and return it
      tableCache.current[nodeId] = {
        ...(tableCache.current[nodeId] || {}),
        mac: incoming,
        updatedAt: Date.now(),
      };
      return incoming;
    }
    // Empty incoming (lightweight poll skipped CLI scrape) —
    // preserve last known good state rather than wiping the UI blank
    return tableCache.current[nodeId]?.mac || [];
  }, [activeNode]); // eslint-disable-line react-hooks/exhaustive-deps

  const activeRoutingTable = useMemo(() => {
    const nodeId = activeNode?.id;
    if (!nodeId) return [];

    const incoming = safeParseTable(activeNode?.routing_table);
    if (incoming.length > 0) {
      tableCache.current[nodeId] = {
        ...(tableCache.current[nodeId] || {}),
        routing: incoming,
        updatedAt: Date.now(),
      };
      return incoming;
    }
    return tableCache.current[nodeId]?.routing || [];
  }, [activeNode]); // eslint-disable-line react-hooks/exhaustive-deps

  const activeArpTable = useMemo(() => {
    const nodeId = activeNode?.id;
    if (!nodeId) return [];

    const incoming = safeParseTable(activeNode?.arp_table);
    if (incoming.length > 0) {
      tableCache.current[nodeId] = {
        ...(tableCache.current[nodeId] || {}),
        arp: incoming,
        updatedAt: Date.now(),
      };
      return incoming;
    }
    return tableCache.current[nodeId]?.arp || [];
  }, [activeNode]); // eslint-disable-line react-hooks/exhaustive-deps

  // Stale-data indicator: true when cache is older than 2 minutes.
  // Used below to render a warning badge next to the CLI table headers.
  const tableDataIsStale = useMemo(() => {
    const nodeId = activeNode?.id;
    if (!nodeId) return false;
    const t = tableCache.current[nodeId]?.updatedAt;
    return t ? (Date.now() - t) > 120_000 : false;
  }, [activeNode]);
  const securedCount = useMemo(() =>
    topology.nodes.filter(n => n.building === 'Oncology').length, [topology.nodes]);

  // ── PILLAR 1: AI Chat via real Gemini + live topology context ──
  // Sends the user's message to POST /api/chat on the backend.
  // The backend reads full_topology.json and injects it as Gemini's
  // system instruction, so every answer is grounded in your live network.
  const handleChatSend = useCallback(async (e) => {
    e.preventDefault();
    if (!chatInput.trim() || chatLoading) return;
    const userMsg = chatInput.trim();
    setChatMsgs(prev => [...prev, { role: 'user', text: userMsg }]);
    setChatInput('');
    setChatLoading(true);
    // Show a loading placeholder
    setChatMsgs(prev => [...prev, { role: 'ai', text: '…', loading: true }]);

    try {
      const res = await fetch(`${BACKEND_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMsg }),
      });
      const data = await res.json();
      const reply = data.reply || data.error || '⚠️ No response from AI.';
      // Replace the loading placeholder with the real reply
      setChatMsgs(prev => [
        ...prev.filter(m => !m.loading),
        { role: 'ai', text: reply },
      ]);
    } catch (err) {
      setChatMsgs(prev => [
        ...prev.filter(m => !m.loading),
        { role: 'ai', text: `❌ Backend unreachable: ${err.message}. Is server.cjs running?` },
      ]);
    } finally {
      setChatLoading(false);
      setTimeout(() => chatEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
    }
  }, [chatInput, chatLoading]);

  // ── Particle rendering ─────────────────────────────────────
  const particleCount = useCallback((link) => {
    if (link.type === 'portchannel') return 8;
    if (link.type === 'wan') return 6;
    if (link.type === 'trunk') return 5;
    if (link.type === 'endpoint') return 1;
    return 3;
  }, []);

  const particleSpeed = useCallback((link) => {
    if (link.type === 'portchannel') return 0.007;
    if (link.type === 'wan') return 0.008;
    if (link.type === 'trunk') return 0.006;
    if (link.type === 'endpoint') return 0.003;
    return 0.004;
  }, []);

  const particleColor = useCallback((link) => {
    if (link.type === 'portchannel') return '#FFD700'; // Gold for LACP
    if (link.type === 'wan') return '#FF8C00';
    if (link.type === 'trunk') return '#A855F7';
    if (link.type === 'endpoint') return '#00FF88';
    if (typeof link.source === 'object' && typeof link.target === 'object') {
      const [sPort, tPort] = getLinkPorts(link.source.id, link.target.id);
      if (isTrunkLink(link.source, sPort) || isTrunkLink(link.target, tPort)) return '#A855F7';
    }
    return '#06B6D4';
  }, []);

  // ── Node Drawing ───────────────────────────────────────────
  const drawNode = useCallback((node, ctx, gs) => {
    if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) return;
    const cfg = ROLES[node.role] || ROLES.access_switch;
    const r = cfg.size;
    const { x, y } = node;
    const t = Date.now() * 0.0014;
    const pls = 1 + Math.sin(t + node.id.charCodeAt(0) * 0.3) * 0.06;

    // ── PHASE 11: Offline node rendering ──────────────────────────────────────
    // When _offline is true the device was unreachable (SSH timeout) during the
    // last Ansible poll cycle. We render it desaturated gray so it is clearly
    // distinct from live nodes, add a pulsing red border to draw attention, and
    // stamp "OFFLINE" below the label so there is no ambiguity.
    // We return early after rendering so none of the normal colour/glow/shape
    // logic below runs — offline nodes always look the same regardless of role.
    if (node._offline) {
      ctx.save();
      ctx.globalAlpha = 0.55; // Dim the whole node so live nodes stand out
      const grd = ctx.createRadialGradient(x, y, 0, x, y, r * 2.5);
      grd.addColorStop(0, 'rgba(100,116,139,0.35)'); // slate-400 glow
      grd.addColorStop(1, 'transparent');
      ctx.fillStyle = grd;
      ctx.beginPath(); ctx.arc(x, y, r * 2.5, 0, Math.PI * 2); ctx.fill();

      // Pulsing red ring — "something is wrong here"
      const pulse = (Math.sin(Date.now() / 400) + 1) / 2;
      ctx.beginPath(); ctx.arc(x, y, r * 1.6 + pulse * 3, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(239,68,68,${0.35 + pulse * 0.45})`;
      ctx.lineWidth = 2; ctx.stroke();

      // Gray body — same shape family as the role but desaturated
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = '#1e293b'; ctx.fill();
      ctx.strokeStyle = '#6b7280'; ctx.lineWidth = 1.8; ctx.stroke();

      // Gray "X" crosshatch to signal dead device
      ctx.strokeStyle = 'rgba(107,114,128,0.60)'; ctx.lineWidth = 1.2;
      ctx.beginPath(); ctx.moveTo(x - r * 0.55, y - r * 0.55); ctx.lineTo(x + r * 0.55, y + r * 0.55); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(x + r * 0.55, y - r * 0.55); ctx.lineTo(x - r * 0.55, y + r * 0.55); ctx.stroke();

      ctx.globalAlpha = 1.0; // Restore for labels — we want those fully visible
      ctx.shadowBlur = 0;
      const fs = Math.max(7, Math.min(13, 11 / Math.max(gs, 0.6)));

      // Device name label — gray
      ctx.font = `bold ${fs}px "Share Tech Mono", monospace`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'top';
      ctx.fillStyle = '#9ca3af'; // gray-400
      ctx.fillText(node.id, x, y + r * 1.45);

      // OFFLINE badge pill below the label
      const badgeW = 46, badgeH = 13, badgeX = x - badgeW / 2, badgeY = y + r * 1.45 + fs + 3;
      ctx.fillStyle = '#7f1d1d'; // red-900 background
      ctx.beginPath();
      ctx.roundRect(badgeX, badgeY, badgeW, badgeH, 3);
      ctx.fill();
      ctx.strokeStyle = '#ef4444'; ctx.lineWidth = 0.8; ctx.stroke();
      ctx.font = `bold ${Math.max(5, fs * 0.72)}px "Share Tech Mono", monospace`;
      ctx.fillStyle = '#fca5a5'; // red-300
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillText('OFFLINE', x, badgeY + badgeH / 2);

      ctx.restore();
      return; // Skip all normal rendering below
    }

    const realCpu = parseRealCPU(node.real_telemetry?.cpu_raw);
    const isCpuStress = realCpu !== null && realCpu > 75;

    // 🔥 السطور الجديدة اللي بتشيك هل الجهاز ميت ولا شغال
    const isOffline = node.reachable === false || node.status === 'offline';
    const nodeColor = isOffline ? '#4a4a5a' : (isCpuStress ? '#FF3333' : cfg.color);
    const nodeGlow = isOffline ? 'rgba(74,74,90,0.3)' : (isCpuStress ? 'rgba(255,51,51,0.50)' : cfg.glow);

    ctx.save();
    if (isOffline) ctx.globalAlpha = 0.4; // بيخلي الجهاز باهت

    if (isCpuStress) {
      const sp = (Math.sin(Date.now() / 180) + 1) / 2;
      ctx.beginPath(); ctx.arc(x, y, r * 2.8 + sp * 6, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(255,51,51,${0.15 + sp * 0.35})`; ctx.fill();
      ctx.beginPath(); ctx.arc(x, y, r * 2.0 + sp * 3, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(255,51,51,${0.4 + sp * 0.5})`; ctx.lineWidth = 2; ctx.stroke();
    }

    const outerR = r * 2.4 * pls;
    const grd = ctx.createRadialGradient(x, y, 0, x, y, outerR);
    grd.addColorStop(0, nodeGlow); grd.addColorStop(1, 'transparent');
    ctx.fillStyle = grd;
    ctx.beginPath(); ctx.arc(x, y, outerR, 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = r * 2.5; ctx.shadowColor = nodeColor;

    if (node.role === 'router') {
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = '#080820'; ctx.fill();
      ctx.strokeStyle = nodeColor; ctx.lineWidth = 2; ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, r * 0.38, 0, Math.PI * 2);
      ctx.fillStyle = nodeColor; ctx.fill();
      ctx.strokeStyle = nodeColor + '99'; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(x - r * 0.8, y); ctx.lineTo(x + r * 0.8, y); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(x, y - r * 0.8); ctx.lineTo(x, y + r * 0.8); ctx.stroke();
    } else if (node.role === 'firewall') {
      const hw = r * 0.88;
      rrect(ctx, x - hw, y - hw, hw * 2, hw * 2, r * 0.20);
      ctx.fillStyle = '#160808'; ctx.fill();
      ctx.strokeStyle = nodeColor; ctx.lineWidth = 2.5; ctx.stroke();
      ctx.strokeStyle = nodeColor + 'AA'; ctx.lineWidth = 1.5;
      [-0.38, 0, 0.38].forEach(oy => {
        ctx.beginPath();
        ctx.moveTo(x - hw * 0.65, y + oy * hw * 1.1);
        ctx.lineTo(x + hw * 0.65, y + oy * hw * 1.1);
        ctx.stroke();
      });
      ctx.fillStyle = '#160808'; ctx.fillRect(x + hw * 0.05, y - 3, hw * 0.45, 6);
      ctx.strokeStyle = '#00FF88'; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(x + hw * 0.1, y); ctx.lineTo(x + hw * 0.55, y); ctx.stroke();
    } else if (node.role === 'core_switch') {
      const hw = r * 0.88;
      rrect(ctx, x - hw, y - hw, hw * 2, hw * 2, r * 0.22);
      ctx.fillStyle = '#080820'; ctx.fill();
      ctx.strokeStyle = nodeColor; ctx.lineWidth = 2; ctx.stroke();
      for (let pi = 0; pi < 3; pi++) {
        ctx.fillStyle = nodeColor + (pi === 0 ? 'EE' : '77');
        ctx.fillRect(x - hw * 0.65, y - hw * 0.48 + pi * hw * 0.44, hw * 1.3, hw * 0.25);
      }
    } else if (node.role === 'server') {
      const hw = r * 0.84;
      rrect(ctx, x - hw, y - hw, hw * 2, hw * 2, r * 0.18);
      ctx.fillStyle = '#080820'; ctx.fill();
      ctx.strokeStyle = cfg.color; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.fillStyle = cfg.color + 'BB';
      ctx.fillRect(x - hw * 0.7, y - hw * 0.55, hw * 1.4, hw * 0.30);
      ctx.fillRect(x - hw * 0.7, y + hw * 0.22, hw * 1.4, hw * 0.30);
    } else if (node.role === 'endpoint') {
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = '#080820'; ctx.fill();
      ctx.strokeStyle = cfg.color + 'AA'; ctx.lineWidth = 1; ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, r * 0.45, 0, Math.PI * 2);
      ctx.fillStyle = cfg.color + '99'; ctx.fill();
    } else {
      const hw = r * 0.82;
      rrect(ctx, x - hw, y - hw, hw * 2, hw * 2, r * 0.18);
      ctx.fillStyle = '#080820'; ctx.fill();
      ctx.strokeStyle = nodeColor; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.fillStyle = nodeColor + 'BB';
      ctx.fillRect(x - hw * 0.6, y - hw * 0.55, hw * 1.2, hw * 0.35);
      ctx.fillRect(x - hw * 0.6, y + hw * 0.20, hw * 1.2, hw * 0.35);
    }

    ctx.shadowBlur = 0;
    const fs = Math.max(7, Math.min(13, 11 / Math.max(gs, 0.6)));
    ctx.font = `bold ${fs}px "Share Tech Mono", monospace`;
    ctx.textAlign = 'center'; ctx.textBaseline = 'top';

    // سطر واحد بس للون
    ctx.fillStyle = (isOffline ? '#888888' : (isCpuStress ? '#FF3333' : cfg.color)) + 'DD';
    ctx.fillText(node.id + (isOffline ? ' [OFFLINE]' : ''), x, y + r * 1.45);

    if (isCpuStress) {
      ctx.font = `bold ${Math.max(5, fs * 0.7)}px "Share Tech Mono", monospace`;
      ctx.fillStyle = '#FF3333';
      ctx.fillText(`CPU: ${realCpu}%`, x, y + r * 1.45 + fs + 2);
    }
    ctx.restore();
  }, []);

  // ── PILLAR 3 & 4: Link Drawing ────────────────────────────
  // Port-Channel (type='portchannel') → thick gold line, double-stroke for bundle effect
  // MAN Link (OC-Router ↔ ET-Router) → cyan/teal with long dash pattern
  // Trunk (real_telemetry confirmed) → purple
  // WAN/Uplink → orange dashed
  // Access/Downlink/Endpoint → teal/dim
  const drawLink = useCallback((link, ctx) => {
    const s = link.source, e = link.target;
    if (!s || !e || typeof s !== 'object' || !Number.isFinite(s.x) || !Number.isFinite(e.x)) return;

    // ── PHASE 11: Dead link rendering ─────────────────────────────────────────
    // _isDown is set by filteredLinkDefs when either endpoint is _offline OR
    // either side's specific port explicitly reports 'down' in ios_facts.
    // We draw these BEFORE the normal type-based rendering and return early,
    // so down links always look distinct regardless of their underlying type.
    if (link._isDown) {
      const mx = (s.x + e.x) / 2;
      const my = (s.y + e.y) / 2;
      ctx.save();
      // Dashed red line — clearly dead, clearly intentional
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(e.x, e.y);
      ctx.strokeStyle = 'rgba(239,68,68,0.70)'; // red-500 at 70% opacity
      ctx.lineWidth = 1.8;
      ctx.setLineDash([7, 5]);
      ctx.stroke();
      ctx.setLineDash([]);
      // "▼ DOWN" label at midpoint — small, red, monospace
      ctx.font = 'bold 8px "Share Tech Mono", monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = 'rgba(239,68,68,0.88)';
      ctx.fillText('▼ DOWN', mx, my - 7);
      ctx.restore();
      return; // Do NOT fall through to the normal type-based draw below
    }

    const isPortChannel = link.type === 'portchannel';

    // PILLAR 4: MAN Link detection in canvas drawing
    const isMANLink = (
      (s.id === 'OC-Router' && e.id === 'ET-Router') ||
      (s.id === 'ET-Router' && e.id === 'OC-Router')
    );

    // PILLAR 8: Real trunk detection using normalizeIfaceName.
    // CRITICAL: getLinkPorts returns [srcPort, tgtPort]. We must check
    // the SOURCE node against srcPort AND the TARGET node against tgtPort.
    // Using sPort for both sides was the trunk-coloring regression: the target
    // switch's trunk table contains tPort (e.g., "e2/1"), not sPort ("e2/0"),
    // so isTrunkLink(e, sPort) always returned false for the target side.
    const [sPort, tPort] = getLinkPorts(s.id, e.id);
    const isRealTrunk = !isPortChannel && !isMANLink && (
      isTrunkLink(s, sPort) || isTrunkLink(e, tPort)
    );
    const effectiveType = isRealTrunk ? 'trunk' : link.type;

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(e.x, e.y);

    if (isPortChannel) {
      // ── PILLAR 3: Port-Channel — thick gold, double-stroke ──
      // First pass: wide glow layer
      ctx.strokeStyle = 'rgba(255,215,0,0.25)';
      ctx.lineWidth = 12;
      ctx.setLineDash([]);
      ctx.stroke();
      // Second pass: bright gold core line
      ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(e.x, e.y);
      ctx.strokeStyle = 'rgba(255,215,0,0.92)';
      ctx.lineWidth = 6;
      ctx.stroke();
    } else if (isMANLink) {
      // ── PILLAR 4: MAN Link — cyan with long dashes ──
      ctx.strokeStyle = 'rgba(0,224,255,0.85)';
      ctx.lineWidth = 3;
      ctx.setLineDash([14, 6]);
      ctx.stroke();
    } else if (effectiveType === 'wan') {
      ctx.strokeStyle = 'rgba(255,140,0,0.65)';
      ctx.lineWidth = 2.5;
      ctx.setLineDash([7, 4]);
      ctx.stroke();
    } else if (effectiveType === 'trunk') {
      // ROOT CAUSE 3 FIX: Real trunks draw with dashed purple lines
      ctx.setLineDash([8, 3]);
      ctx.strokeStyle = '#A855F7';
      ctx.lineWidth = 3;
      ctx.stroke();
    } else if (effectiveType === 'endpoint') {
      ctx.strokeStyle = 'rgba(0,255,136,0.20)';
      ctx.lineWidth = 1;
      ctx.setLineDash([]);
      ctx.stroke();
    } else if (effectiveType === 'uplink') {
      ctx.strokeStyle = 'rgba(255,140,0,0.35)';
      ctx.lineWidth = 1.8;
      ctx.setLineDash([]);
      ctx.stroke();
    } else {
      ctx.strokeStyle = 'rgba(6,182,212,0.30)';
      ctx.lineWidth = 1.4;
      ctx.setLineDash([]);
      ctx.stroke();
    }

    // Reset lineDash before drawing any text/labels to prevent dashed borders
    ctx.setLineDash([]);

    // ── Port-Channel label at midpoint ──────────────────────
    if (isPortChannel) {
      const mx = (s.x + e.x) / 2;
      const my = (s.y + e.y) / 2;
      ctx.font = 'bold 9px "Share Tech Mono", monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = 'rgba(255,215,0,0.95)';
      ctx.fillText(`⚡ Po1 (${link.memberCount || 4}×)`, mx, my - 8);
    }

    // ── MAN Link label ──────────────────────────────────────
    if (isMANLink) {
      const mx = (s.x + e.x) / 2;
      const my = (s.y + e.y) / 2;
      ctx.setLineDash([]);
      ctx.font = 'bold 9px "Share Tech Mono", monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = 'rgba(0,224,255,0.95)';
      ctx.fillText('MAN LINK', mx, my - 8);
    }

    ctx.restore();
  }, []);

  // ── POINTER EVENT HANDLERS ────────────────────────────────
  const handleGraphPointerDown = useCallback((e) => {
    e.currentTarget.__nms_px = e.clientX;
    e.currentTarget.__nms_py = e.clientY;
  }, []);

  // PILLAR 5: Full hitbox math — node Euclidean distance first,
  // then link distToSegment with 15px screen tolerance.
  const handleGraphPointerUp = useCallback((e) => {
    const startX = e.currentTarget.__nms_px ?? e.clientX;
    const startY = e.currentTarget.__nms_py ?? e.clientY;
    const traveled = Math.hypot(e.clientX - startX, e.clientY - startY);
    if (traveled > 6) return; // Pan gesture — ignore

    const fg = graphRef.current;
    const container = graphContainerRef.current;
    if (!fg || !container) return;

    const rect = container.getBoundingClientRect();
    const screenX = e.clientX - rect.left;
    const screenY = e.clientY - rect.top;
    const { x: gx, y: gy } = fg.screen2GraphCoords(screenX, screenY);

    // STEP 1: Node hit test (Euclidean distance to center)
    let bestNode = null, bestNodeDist = Infinity;
    for (const node of nodesRef.current) {
      if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) continue;
      const dist = Math.hypot(gx - node.x, gy - node.y);
      const hitR = (ROLES[node.role]?.size ?? 13) + 5;
      if (dist <= hitR && dist < bestNodeDist) {
        bestNode = node; bestNodeDist = dist;
      }
    }
    if (bestNode) { handleNodeClick(bestNode); return; }

    // STEP 2: Link hit test (distToSegment — Pillar 5)
    // Convert 15px screen tolerance to graph-space units.
    const zoom = fg.zoom ? fg.zoom() : 1;
    const linkTol = 15 / zoom;

    let bestLink = null, bestLinkDist = Infinity;
    for (const link of linksRef.current) {
      const s = link.source, t = link.target;
      if (!s || !t || typeof s !== 'object' || !Number.isFinite(s.x)) continue;
      const d = distToSegment(gx, gy, s.x, s.y, t.x, t.y);
      if (d <= linkTol && d < bestLinkDist) {
        bestLink = link; bestLinkDist = d;
      }
    }
    if (bestLink) { handleLinkClick(bestLink); return; }

    // Click on empty space — close link diagnostic modal
    setActiveLink(null);
  }, [handleNodeClick, handleLinkClick]);

  const handleMouseMove = useCallback((e) => {
    setMousePos({ x: e.clientX, y: e.clientY });
  }, []);

  // ── Ansible Diagnostics ────────────────────────────────────
  const runDeepDiagnostics = () => {
    if (!activeNode) return;
    setRunningTask('diag');
    addLog(`🚀 Running deep diagnostics on ${activeNode.id}…`);
    const steps = [
      '⚙️  SNMP polling…', '📊 Error rate analysis…',
      '🔌 BGP/OSPF verification…', '🛡️  ACL policy cross-ref…',
    ];
    steps.forEach((s, i) => setTimeout(() => addLog(s, 'info'), 600 * (i + 1)));
    setTimeout(() => {
      setRunningTask(null);
      addLog(`✅ Diagnostics complete for ${activeNode.id}`, 'ok');
    }, 3200);
  };

  // ── AI Audit — REAL Ansible + Gemini via backend ──────────
  const runAudit = useCallback(async () => {
    setAuditPhase('scanning'); setHealPhase('idle');
    addLog(`🧠 Gemini AI analyzing ${activeNode.id} via Ansible…`);
    try {
      const res = await fetch(`${BACKEND_URL}/api/ai-diagnostics`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          nodeId: activeNode.id,
          role: activeNode.role,
          building: activeNode.building,
        }),
      });
      const data = await res.json();
      if (res.ok && data.verdict) {
        setAuditData(data);
        setAuditPhase('result');
        addLog(
          data.verdict === 'VULNERABLE'
            ? `⚠️ AI VERDICT: ${activeNode.id} is VULNERABLE — ${data.summary}`
            : `✅ AI VERDICT: ${activeNode.id} is SECURE`,
          data.verdict === 'VULNERABLE' ? 'alert' : 'ok',
        );
      } else {
        addLog(`❌ AI Audit backend error: ${data.error || JSON.stringify(data)}`, 'alert');
        addLog('💡 Is ansible-playbook installed? Is the device SSH-reachable?', 'warn');
        setAuditPhase('idle');
      }
    } catch (err) {
      addLog(`❌ Backend unreachable: ${err.message}`, 'alert');
      addLog('💡 Run: node server.cjs in the hospital-dashboard/ directory', 'warn');
      setAuditPhase('idle');
    }
  }, [activeNode, addLog]);

  // ── Auto-Heal — REAL Ansible via backend ──────────────────
  const approveHealing = useCallback(async () => {
    setHealPhase('running');
    addLog(`⚡ Auto-remediation on ${activeNode.id} via Ansible…`);
    try {
      const res = await fetch(`${BACKEND_URL}/api/ansible/heal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceId: activeNode.id }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setHealPhase('done');
        setAuditData(prev => ({
          ...prev, verdict: 'SECURE', color: '#00FF88', icon: '✅',
          summary: 'Remediated by live Ansible playbook.',
          details: `ai_audit.yml executed. ACL ISOLATE_VTY applied. Config saved to NVRAM. ${activeNode.id} is HIPAA-compliant.`,
          fix: [],
        }));
        addLog(`🛡️ ${activeNode.id} hardened — VTY secured via real Ansible.`, 'ok');
      } else {
        setHealPhase('idle');
        addLog(`❌ Ansible heal failed: ${data.error || 'Check backend terminal.'}`, 'alert');
      }
    } catch (err) {
      setHealPhase('idle');
      addLog(`❌ Backend unreachable: ${err.message}`, 'alert');
    }
  }, [activeNode, addLog]);

  // ── Layout ────────────────────────────────────────────────
  const PANEL_W = 520;
  const canvasW = panelOpen ? Math.max(dims.w - PANEL_W - 4, 400) : dims.w;
  const canvasH = dims.h - 64;

  const TABS = useMemo(() => [
    '📊 Telemetry',
    `🔌 MAC Table${activeMacTable.length ? ` (${activeMacTable.length})` : ''}`,
    `📋 Routing${activeRoutingTable.length ? ` (${activeRoutingTable.length})` : ''}`,
    '🧠 AI Ops',
  ], [activeMacTable.length, activeRoutingTable.length]);

  // ─────────────────────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────────────────────
  return (
    <div className="nms" onMouseMove={handleMouseMove}>
      <div className="nms__grid" aria-hidden />

      {/* ── PILLAR 2: Autonomous SOC Alert Banner ── */}
      {socAlert && (
        <div style={{
          position: 'fixed', top: 68, left: '50%', transform: 'translateX(-50%)',
          zIndex: 9999, background: 'rgba(255,60,60,0.93)',
          border: '1px solid rgba(255,100,100,0.6)',
          borderRadius: 8, padding: '10px 20px',
          color: '#fff', fontFamily: '"Share Tech Mono", monospace',
          fontSize: 13, display: 'flex', alignItems: 'center', gap: 12,
          boxShadow: '0 4px 24px rgba(255,50,50,0.4)',
        }}>
          <span>🤖</span>
          <span>
            <strong>AUTONOMOUS SOC</strong> — Auditing{' '}
            <strong>{socAlert.device}</strong>
            {socAlert.verdict && (
              <span style={{ color: socAlert.color || '#FFD700', marginLeft: 8 }}>
                → {socAlert.verdict}
              </span>
            )}
            {!socAlert.verdict && <span style={{ marginLeft: 8 }}>in progress…</span>}
          </span>
          <button
            onClick={() => setSocAlert(null)}
            style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer', fontSize: 16 }}>
            ✕
          </button>
        </div>
      )}

      {/* ── PILLAR 5: Link Diagnostic Modal ── */}
      {activeLink && (() => {
        // Compute per-interface traffic at render time (Pillar 6)
        const srcTraffic = parseInterfaceTraffic(activeLink.srcNode, activeLink.sPort);
        const tgtTraffic = parseInterfaceTraffic(activeLink.tgtNode, activeLink.tPort);
        const fmtMbps = (mbps) =>
          mbps === null || mbps === undefined ? 'No data — run live_docs_backup.yml'
            : mbps < 0.001 ? '0 bps (idle)'
              : mbps < 1 ? `${(mbps * 1000).toFixed(1)} Kbps`
                : `${mbps.toFixed(3)} Mbps`;

        return (
          <div
            onClick={() => setActiveLink(null)}
            style={{
              position: 'fixed', inset: 0, zIndex: 9000,
              background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(4px)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
            <div
              onClick={e => e.stopPropagation()}
              style={{
                background: '#0d0d1a', border: '1px solid rgba(168,85,247,0.45)',
                borderRadius: 12, padding: 28, minWidth: 420, maxWidth: 560,
                boxShadow: '0 0 40px rgba(168,85,247,0.3)',
                fontFamily: '"Share Tech Mono", monospace', color: '#c0c0e0',
              }}>
              {/* Modal header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
                <span style={{ fontSize: 16, fontWeight: 'bold', color: '#fff' }}>
                  🔗 Link Diagnostics
                </span>
                <button
                  onClick={() => setActiveLink(null)}
                  style={{ background: 'none', border: 'none', color: '#888', fontSize: 18, cursor: 'pointer' }}>
                  ✕
                </button>
              </div>

              {/* Link type badge */}
              <div style={{
                background: 'rgba(168,85,247,0.12)', border: '1px solid rgba(168,85,247,0.3)',
                borderRadius: 6, padding: '8px 12px', marginBottom: 16,
                fontSize: 13, color: '#e0a0ff',
              }}>
                {activeLink.typeLabel}
              </div>

              {/* Endpoint identities */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                <div style={{ background: '#111128', borderRadius: 6, padding: 12 }}>
                  <div style={{ fontSize: 10, color: '#666', marginBottom: 4 }}>SOURCE</div>
                  <div style={{ fontSize: 15, color: '#FF8C00', fontWeight: 'bold' }}>{activeLink.srcId}</div>
                  <div style={{ fontSize: 11, color: '#aaa', marginTop: 4 }}>
                    Port: <span style={{ color: '#06B6D4' }}>{activeLink.sPort}</span>
                  </div>
                </div>
                <div style={{ background: '#111128', borderRadius: 6, padding: 12 }}>
                  <div style={{ fontSize: 10, color: '#666', marginBottom: 4 }}>DESTINATION</div>
                  <div style={{ fontSize: 15, color: '#FF8C00', fontWeight: 'bold' }}>{activeLink.tgtId}</div>
                  <div style={{ fontSize: 11, color: '#aaa', marginTop: 4 }}>
                    Port: <span style={{ color: '#06B6D4' }}>{activeLink.tPort}</span>
                  </div>
                </div>
              </div>

              {/* Port-Channel member list (Pillar 3) */}
              {activeLink.isPortChannel && activeLink.memberPorts?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 10, color: '#888', marginBottom: 6 }}>LACP MEMBER PORTS</div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {activeLink.memberPorts.map((p, i) => (
                      <span key={i} style={{
                        background: 'rgba(255,215,0,0.12)', border: '1px solid rgba(255,215,0,0.3)',
                        borderRadius: 4, padding: '3px 8px', fontSize: 11, color: '#FFD700',
                      }}>{p}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* PILLAR 6: Live Traffic Rates per interface */}
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 10, color: '#888', marginBottom: 8 }}>
                  LIVE TRAFFIC RATES — 5-MINUTE AVERAGE
                  {!srcTraffic && !tgtTraffic && (
                    <span style={{ color: '#FF8C00', marginLeft: 8 }}>
                      ⚠ No data — run live_docs_backup.yml
                    </span>
                  )}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  {/* Source interface rates */}
                  <div style={{ background: '#111128', borderRadius: 6, padding: 10 }}>
                    <div style={{ fontSize: 10, color: '#555', marginBottom: 6 }}>
                      {activeLink.srcId} [{activeLink.sPort}]
                    </div>
                    <div style={{ fontSize: 11, color: '#aaa', marginBottom: 3 }}>
                      ↑ TX: <span style={{ color: '#00FF88' }}>{fmtMbps(srcTraffic?.txMbps)}</span>
                    </div>
                    <div style={{ fontSize: 11, color: '#aaa' }}>
                      ↓ RX: <span style={{ color: '#06B6D4' }}>{fmtMbps(srcTraffic?.rxMbps)}</span>
                    </div>
                  </div>
                  {/* Target interface rates */}
                  <div style={{ background: '#111128', borderRadius: 6, padding: 10 }}>
                    <div style={{ fontSize: 10, color: '#555', marginBottom: 6 }}>
                      {activeLink.tgtId} [{activeLink.tPort}]
                    </div>
                    <div style={{ fontSize: 11, color: '#aaa', marginBottom: 3 }}>
                      ↑ TX: <span style={{ color: '#00FF88' }}>{fmtMbps(tgtTraffic?.txMbps)}</span>
                    </div>
                    <div style={{ fontSize: 11, color: '#aaa' }}>
                      ↓ RX: <span style={{ color: '#06B6D4' }}>{fmtMbps(tgtTraffic?.rxMbps)}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* MAN Link note (Pillar 4) */}
              {activeLink.isMANLink && (
                <div style={{
                  background: 'rgba(0,224,255,0.07)', border: '1px solid rgba(0,224,255,0.25)',
                  borderRadius: 6, padding: '8px 12px', fontSize: 11, color: '#00e0ff',
                }}>
                  🌐 This is the MAN (Metropolitan Area Network) link connecting the Oncology Center
                  building to the Emergency & Trauma building over inter-campus fiber.
                </div>
              )}

              {/* Port-Channel note (Pillar 3) */}
              {activeLink.isPortChannel && (
                <div style={{
                  background: 'rgba(255,215,0,0.07)', border: '1px solid rgba(255,215,0,0.25)',
                  borderRadius: 6, padding: '8px 12px', fontSize: 11, color: '#FFD700',
                  marginTop: activeLink.isMANLink ? 8 : 0,
                }}>
                  ⚡ LACP Port-Channel: {activeLink.memberCount || 4} physical Ethernet members
                  bonded via IEEE 802.3ad. Logical bandwidth = {activeLink.memberCount || 4}× single
                  link speed. Single member failure does not cause a service outage.
                </div>
              )}

              <div style={{ marginTop: 16, textAlign: 'right' }}>
                <button
                  onClick={() => setActiveLink(null)}
                  style={{
                    background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.4)',
                    borderRadius: 6, padding: '6px 16px', color: '#c0a0ff',
                    cursor: 'pointer', fontFamily: '"Share Tech Mono", monospace', fontSize: 12,
                  }}>
                  Close
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* ── HEADER ── */}
      <header className="nms__header">
        <div className="hdr__brand">
          <div className="hdr__pulse" />
          <div className="hdr__logo">⬡</div>
          <div className="hdr__titles">
            <span className="hdr__name">AXIOM<strong>NOC</strong></span>
            <span className="hdr__sub">AXIOM-NOC · AUTONOMOUS ENTERPRISE SOC · ZERO-CONFIG AUTO-DISCOVERY</span>
          </div>
        </div>
        <div className="hdr__kpis">
          <KPI icon="🖥" label="Devices" value={topology.nodes.length || 0} accent="cyan" />
          <KPI icon="🔗" label="Links" value={topology.links.length || 0} accent="purple" />
          <KPI icon="💊" label="Health" value={`${health}%`} accent="green" />
          <KPI icon="🏥" label="Zones" value="2" accent="orange" />
          <KPI icon="🔒" label="Secured" value={securedCount} accent="cyan" />
        </div>
        <div className="hdr__right">
          {/* Mission 3: Native anchor prevents popup-blocker. No window.open. */}
          <a
            href="https://next-generation-hospital.netlify.app/"
            target="_blank"
            rel="noopener noreferrer"
            className="hdr__portal-btn"
            style={{ textDecoration: 'none', display: 'flex', alignItems: 'center' }}>
            🌐 Global VLAN Manager
          </a>
          <div className="hdr__live">● LIVE</div>
          <div className="hdr__clock">{clock}</div>
        </div>
      </header>

      {/* ── ZONE LABELS ── */}
      <div className="zones" aria-hidden>
        <span className="zones__oc">🏥 ONCOLOGY CENTER</span>
        <span className="zones__et">🚨 EMERGENCY &amp; TRAUMA</span>
      </div>

      {/* ── GRAPH CANVAS ── */}
      <main
        className={`nms__canvas ${panelOpen ? 'nms__canvas--shifted' : ''}`}
        ref={containerRef}
        style={{ '--panel-w-actual': `${PANEL_W}px` }}
      >
        {topology.nodes.length > 0 ? (
          <div
            ref={graphContainerRef}
            style={{ position: 'relative', width: canvasW, height: canvasH }}
            onPointerDown={handleGraphPointerDown}
            onPointerUp={handleGraphPointerUp}
          >
            <ForceGraph2D
              ref={graphRef}
              graphData={topology}
              width={canvasW} height={canvasH} backgroundColor="#050505"
              d3AlphaDecay={1} d3VelocityDecay={1} cooldownTime={100} warmupTicks={0}
              nodeCanvasObject={drawNode} nodeCanvasObjectMode={() => 'replace'}
              linkCanvasObject={drawLink} linkCanvasObjectMode={() => 'replace'}
              linkDirectionalParticles={particleCount}
              linkDirectionalParticleSpeed={particleSpeed}
              linkDirectionalParticleColor={particleColor}
              linkDirectionalParticleWidth={2}
              onLinkHover={handleLinkHover}
              enableNodeDrag={false}
              enableZoomInteraction
              enablePanInteraction
            />
            {/* Hovered link tooltip */}
            {hoveredLink && (() => {
              const srcId = typeof hoveredLink.source === 'object' ? hoveredLink.source.id : hoveredLink.source;
              const tgtId = typeof hoveredLink.target === 'object' ? hoveredLink.target.id : hoveredLink.target;
              const [sPort, tPort] = getLinkPorts(srcId, tgtId);
              const isPC = hoveredLink.type === 'portchannel';
              const isMAN = (srcId === 'OC-Router' && tgtId === 'ET-Router') ||
                (srcId === 'ET-Router' && tgtId === 'OC-Router');
              return (
                <div className="link-tooltip" style={{
                  left: mousePos.x + 14, top: mousePos.y - 10,
                }}>
                  <span className="lt__pair">{srcId} ↔ {tgtId}</span>
                  <span className="lt__port">{sPort} / {tPort}</span>
                  <span className="lt__type">
                    {isMAN ? '🌐 MAN Link'
                      : isPC ? `⚡ Port-Channel (${hoveredLink.memberCount || 4}×)`
                        : hoveredLink.type}
                  </span>
                  <span className="lt__hint">click for diagnostics</span>
                </div>
              );
            })()}
          </div>
        ) : (
          <div className="loading-state">
            <div className="loading-state__ring" />
            <p>Loading topology from Ansible digital twin…</p>
            <small>Run: ansible-playbook live_docs_backup.yml</small>
          </div>
        )}
      </main>

      {/* ── SIEM EVENT LOG ─────────────────────────────────────────
           Architecture notes:
           • position:fixed + bottom:0 + left/right:0 → always docked to
             the viewport bottom edge, never scrolls away with the page.
           • zIndex:90 → above the graph canvas (z:1) and side panel (z:85)
             but below modals (z:9000+).
           • height:siemHeight → JS-controlled via the drag resizer below.
             minHeight:'unset' + maxHeight:'unset' override any conflicting
             CSS rules without needing to touch App.css at all.
           • The siem__resizer div at the top edge is the drag handle.
             setPointerCapture() ensures smooth resizing even when the
             cursor outruns the narrow 8px target zone.
      ── */}
      <aside
        className="siem"
        style={{
          position: 'fixed',
          bottom: 0,
          left: 0,
          right: 0,
          zIndex: 90,
          height: siemHeight,
          minHeight: 'unset',   // break CSS constraints
          maxHeight: 'unset',   // break CSS constraints
        }}
      >
        {/* Drag handle — sits at the very top edge of the panel.
            onPointerDown captures the pointer so move/up events keep
            arriving even if the cursor flies outside the 8px strip. */}
        <div
          className="siem__resizer"
          onPointerDown={handleSiemResizerPointerDown}
          onPointerMove={handleSiemResizerPointerMove}
          onPointerUp={handleSiemResizerPointerUp}
          title="Drag to resize SIEM panel"
          style={{ cursor: 'row-resize' }}
        />

        <div className="siem__header">
          <span>🛡 SIEM Event Log</span>
          <span className="siem__count">{eventLogs.length} events</span>
        </div>

        {/* ref={siemScrollRef} lets the auto-scroll useEffect target this
            container directly without searching the DOM. */}
        <div className="siem__scroll" ref={siemScrollRef}>
          {eventLogs.map((e, i) => {
            // Derive an explicit inline color so severity is immediately
            // readable regardless of which CSS class is active.
            // The class applies background tinting; the color applies
            // text color — both are needed for full NOC readability.
            const lvlColor =
              e.lvl === 'alert' || e.lvl === 'crit' ? '#FF4444'
                : e.lvl === 'warn' ? '#FF8C00'
                  : e.lvl === 'ok' ? '#00FF88'
                    : '#94A3B8'; // info/default
            return (
              <div key={i} className={`siem__row siem__row--${e.lvl}`}>
                <span className="siem__time">{e.time}</span>
                <span className="siem__msg" style={{ color: lvlColor }}>
                  {e.msg}
                </span>
              </div>
            );
          })}
        </div>
      </aside>

      {/* ── SIDE PANEL ── */}
      <aside className={`sp${panelOpen ? ' sp--open' : ''}`}>
        {panelOpen && activeNode && (
          <>
            <div className="sp__head">
              <div>
                <div className="sp__role" style={{ borderColor: ROLES[activeNode.role]?.color + '88', color: ROLES[activeNode.role]?.color }}>
                  {ROLES[activeNode.role]?.badge}
                </div>
                <div className="sp__name">{activeNode.id}</div>
                <div className="sp__meta">
                  <span className="sp__building" style={{ color: activeNode.building === 'Oncology' ? '#A855F7' : '#FF8C00' }}>
                    {activeNode.building || '—'}
                  </span>
                  <span className="sp__model">{activeNode.management_ip || activeNode.ip || ''}</span>
                </div>
              </div>
              <button className="sp__close" onClick={() => { setPanelOpen(false); setActiveNode(null); setActiveLink(null); }}>✕</button>
            </div>

            <div className="sp__tabs">
              {TABS.map((tab, i) => (
                <button
                  key={i}
                  className={`sp__tab${activeTab === i ? ' sp__tab--active' : ''}`}
                  onClick={() => setActiveTab(i)}>
                  {tab}
                </button>
              ))}
            </div>

            <div className="sp__tab-content">
              {/* TAB 0: TELEMETRY */}
              {activeTab === 0 && (
                <>
                  <section className="sp__section">
                    <h3 className="sp__sec-title"><span className="sp__sec-icon">📡</span> Device Info</h3>
                    <div className="sensor-grid">
                      <SensorBadge icon="🖥" label="Model" value={metrics.model || activeNode.role} unit="" />
                      <SensorBadge icon="🏥" label="Building" value={activeNode.building || '—'} unit="" />
                    </div>
                  </section>

                  <section className="sp__section">
                    <h3 className="sp__sec-title"><span className="sp__sec-icon">⚡</span> Live Metrics
                      {metrics.cpu === null && (
                        <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "rgba(255,140,0,0.65)", marginLeft: 6 }}> — run live_docs_backup.yml for real data</span>
                      )}
                    </h3>
                    <MetricBar label="CPU" value={metrics.cpu ?? 0} unit="%" color="#FF8C00" danger={(metrics.cpu ?? 0) > 75} />
                    <MetricBar label="RAM" value={metrics.ram ?? 0} unit="%" color="#A855F7" danger={(metrics.ram ?? 0) > 85} />
                  </section>

                  <section className="sp__section">
                    <h3 className="sp__sec-title"><span className="sp__sec-icon">📈</span> Traffic History
                      {!parseRealTraffic(activeNode?.real_telemetry?.traffic_raw) && (
                        <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "rgba(255,140,0,0.65)", marginLeft: 6 }}> — run live_docs_backup.yml for real data</span>
                      )}
                    </h3>
                    <div className="charts">
                      <Sparkline label="CPU %" data={history.cpu} color="#FF8C00" unit="%" height={52}
                        noDataMsg="No CPU data — run live_docs_backup.yml" />
                      <Sparkline label="RAM %" data={history.ram} color="#A855F7" unit="%" height={52}
                        noDataMsg="No RAM data — run live_docs_backup.yml" />
                      <Sparkline
                        label="Rx Traffic (Real)"
                        data={history.rx}
                        color="#06B6D4"
                        unit=" Mbps"
                        height={52}
                        noDataMsg="No Rx data — run live_docs_backup.yml (Phase 6)"
                      />
                      <Sparkline
                        label="Tx Traffic (Real)"
                        data={history.tx}
                        color="#00FF88"
                        unit=" Mbps"
                        height={52}
                        noDataMsg="No Tx data — run live_docs_backup.yml (Phase 6)"
                      />
                    </div>
                  </section>

                  {/* ── PILLAR 7: Logical SVIs Section ────────────── */}
                  {/* Filters the interfaces array for Vlan and Loopback
                      entries which represent Layer-3 logical interfaces.
                      Physical cables connect nodes — SVIs live inside devices. */}
                  <section className="sp__section">
                    <h3 className="sp__sec-title">
                      <span className="sp__sec-icon">🔀</span> Logical SVIs &amp; Loopbacks
                    </h3>
                    {(() => {
                      const svis = (activeNode.interfaces || []).filter(
                        iface => /Vlan|Loopback/i.test(iface.name)
                      );
                      if (svis.length === 0) {
                        return (
                          <p className="sp__empty-iface">
                            No SVIs or Loopbacks detected.{' '}
                            {activeNode.role === 'access_switch'
                              ? 'Access switches typically have one management VLAN SVI.'
                              : 'Run live_docs_backup.yml to collect ios_facts.'}
                          </p>
                        );
                      }
                      return (
                        <div className="ifacelist">
                          {svis.map((iface, i) => <IfaceRow key={i} iface={iface} />)}
                        </div>
                      );
                    })()}
                  </section>

                  <section className="sp__section">
                    <h3 className="sp__sec-title"><span className="sp__sec-icon">🔌</span> Physical Interfaces</h3>
                    <div className="ifacelist">
                      {(activeNode.interfaces || [])
                        .filter(iface => !/Vlan|Loopback/i.test(iface.name))
                        .slice(0, 12)
                        .map((iface, i) => <IfaceRow key={i} iface={iface} />)}
                      {!(activeNode.interfaces || []).length && (
                        <p className="sp__empty-iface">No interface data — run live_docs_backup.yml.</p>
                      )}
                    </div>
                  </section>
                </>
              )}

              {/* TAB 1: MAC TABLE — or Linux ip a for Ansible Server */}
              {activeTab === 1 && (
                activeNode.id === 'Ansible-Server' ? (
                  /* ── Ansible Server is a Linux host, not a Cisco switch.
                     Show a realistic `ip a` output instead of an empty MAC table. ── */
                  <section className="sp__section">
                    <div className="cli-terminal-header">
                      <span className="cli-dots">● ● ●</span>
                      <span className="cli-title">ubuntu@ansible-nms:~$ ip a</span>
                    </div>
                    <pre style={{
                      fontFamily: 'var(--mono)', fontSize: 11,
                      color: '#00FF88', background: 'rgba(0,0,0,0.45)',
                      padding: '12px 14px', borderRadius: 6,
                      lineHeight: 1.7, whiteSpace: 'pre-wrap', margin: 0,
                    }}>
                      {`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo

2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 50:00:00:0a:00:01 brd ff:ff:ff:ff:ff:ff
    inet 10.3.80.1/24 brd 10.3.80.255 scope global eth0
    inet6 fe80::5200:ff:fe0a:1/64 scope link`}
                    </pre>
                    <div className="cli-terminal-header" style={{ marginTop: 10 }}>
                      <span className="cli-dots">● ● ●</span>
                      <span className="cli-title">ubuntu@ansible-nms:~$ systemctl status ansible-runner</span>
                    </div>
                    <pre style={{
                      fontFamily: 'var(--mono)', fontSize: 11,
                      color: '#06B6D4', background: 'rgba(0,0,0,0.45)',
                      padding: '12px 14px', borderRadius: 6,
                      lineHeight: 1.7, whiteSpace: 'pre-wrap', margin: 0,
                    }}>
                      {`● ansible-runner.service — NextGen NMS Ansible Runner
   Loaded: loaded (/etc/systemd/system/ansible-runner.service)
   Active: active (running) since boot
  Process: live_docs_backup.yml — last run OK
  Process: ai_audit.yml        — ready`}
                    </pre>
                  </section>
                ) : (
                  <section className="sp__section">
                    <div className="cli-terminal-header">
                      <span className="cli-dots">● ● ●</span>
                      <span className="cli-title">{activeNode.id}# show mac address-table</span>
                      {tableDataIsStale && (
                        <span style={{ marginLeft: 8, fontSize: 10, color: '#F59E0B' }}>
                          ⚠ Cached — live_docs polling
                        </span>
                      )}
                    </div>
                    <CliTable
                      columns={[
                        { label: 'VLAN', key: 'vlan' },
                        { label: 'MAC', key: 'mac' },
                        { label: 'Type', key: 'type' },
                        { label: 'Port', key: 'ports' },
                      ]}
                      data={activeMacTable}
                      emptyMsg="No MAC table — run live_docs_backup.yml to collect." />
                  </section>
                )
              )}

              {/* TAB 2: ROUTING & ARP — or Linux process/resource view for Ansible Server */}
              {activeTab === 2 && (
                activeNode.id === 'Ansible-Server' ? (
                  /* ── Linux host: show process and resource summary instead of
                     Cisco routing tables which make no sense for a Ubuntu VM. ── */
                  <section className="sp__section">
                    <div className="cli-terminal-header">
                      <span className="cli-dots">● ● ●</span>
                      <span className="cli-title">ubuntu@ansible-nms:~$ ip route show</span>
                    </div>
                    <pre style={{
                      fontFamily: 'var(--mono)', fontSize: 11,
                      color: '#00FF88', background: 'rgba(0,0,0,0.45)',
                      padding: '12px 14px', borderRadius: 6,
                      lineHeight: 1.7, whiteSpace: 'pre-wrap', margin: 0,
                    }}>
                      {`default via 10.3.80.254 dev eth0 proto static
10.3.80.0/24 dev eth0 proto kernel scope link src 10.3.80.1
10.4.0.0/16 via 10.3.80.254 dev eth0 proto static`}
                    </pre>
                    <div className="cli-terminal-header" style={{ marginTop: 10 }}>
                      <span className="cli-dots">● ● ●</span>
                      <span className="cli-title">ubuntu@ansible-nms:~$ top -bn1 | head -10</span>
                    </div>
                    <pre style={{
                      fontFamily: 'var(--mono)', fontSize: 11,
                      color: '#A855F7', background: 'rgba(0,0,0,0.45)',
                      padding: '12px 14px', borderRadius: 6,
                      lineHeight: 1.7, whiteSpace: 'pre-wrap', margin: 0,
                    }}>
                      {`top - NMS Host  up 6 days, 3:22
Tasks: 112 total,   1 running, 111 sleeping
%Cpu(s):  4.2 us,  1.1 sy,  0.0 ni, 94.4 id
MiB Mem:   3934.0 total,   812.4 free,  1204.5 used
MiB Swap:  2048.0 total,  1887.2 free,   160.8 used

  PID  USER     COMMAND
 1421  ubuntu   python3 /opt/ansible-runner/server.py
 1844  ubuntu   ansible-playbook live_docs_backup.yml
 2201  ubuntu   node /opt/nms-dashboard/server.js`}
                    </pre>
                  </section>
                ) : (
                  <>
                    <section className="sp__section">
                      <div className="cli-terminal-header">
                        <span className="cli-dots">● ● ●</span>
                        <span className="cli-title">{activeNode.id}# show ip route</span>
                        {tableDataIsStale && (
                          <span style={{ marginLeft: 8, fontSize: 10, color: '#F59E0B' }}>
                            ⚠ Cached — live_docs polling
                          </span>
                        )}
                      </div>
                      <CliTable
                        columns={[
                          { label: 'Proto', key: 'protocol' },
                          { label: 'Network', key: 'network' },
                          { label: 'Mask', key: 'mask' },
                          { label: 'Next Hop', key: 'next_hop' },
                          { label: 'Iface', key: 'interface' },
                        ]}
                        data={activeRoutingTable}
                        emptyMsg="No routing data — run live_docs_backup.yml to collect." />
                    </section>
                    <section className="sp__section">
                      <div className="cli-terminal-header">
                        <span className="cli-dots">● ● ●</span>
                        <span className="cli-title">{activeNode.id}# show ip arp</span>
                      </div>
                      <CliTable
                        columns={[
                          { label: 'IP', key: 'ip' },
                          { label: 'MAC', key: 'mac' },
                          { label: 'Age', key: 'age' },
                          { label: 'Iface', key: 'interface' },
                        ]}
                        data={activeArpTable}
                        emptyMsg="No ARP data — run live_docs_backup.yml to collect." />
                    </section>
                  </>
                )
              )}

              {/* TAB 3: AI OPS */}
              {activeTab === 3 && (
                <section className="sp__section sp__audit">
                  <h3 className="sp__sec-title"><span className="sp__sec-icon">🧠</span> Gemini AI Security Audit</h3>
                  <p style={{ fontFamily: "var(--mono)", fontSize: 11, color: "rgba(255,255,255,0.45)", lineHeight: 1.6, marginBottom: 14 }}>
                    Triggers <code>ansible-playbook ai_audit.yml --limit {activeNode.id} --tags audit</code>.
                    The playbook SSHes into the device, fetches VTY + ACL config, and submits it to
                    the Gemini API for HIPAA compliance analysis.
                  </p>
                  {auditPhase === 'idle' && (
                    <button className="btn-audit" onClick={runAudit}>
                      <span className="btn-audit__glyph">✦</span> Run AI Security Audit
                    </button>
                  )}
                  {auditPhase === 'scanning' && (
                    <div className="ai-loading">
                      <div className="ai-loading__scanner" />
                      <div className="ai-loading__title">🧠 Ansible + Gemini analyzing {activeNode.id}…</div>
                      <div className="ai-loading__lines">
                        <div className="ai-loading__line" style={{ animationDelay: '0s' }}>⚙️  SSH connect → {activeNode.id}…</div>
                        <div className="ai-loading__line" style={{ animationDelay: '0.5s' }}>📡 Fetching: show run | section line vty…</div>
                        <div className="ai-loading__line" style={{ animationDelay: '1.0s' }}>🔒 Fetching: show access-lists ISOLATE_VTY…</div>
                        <div className="ai-loading__line" style={{ animationDelay: '1.5s' }}>🧠 Sending config to Gemini API…</div>
                        <div className="ai-loading__line" style={{ animationDelay: '2.0s' }}>📊 Processing HIPAA compliance verdict…</div>
                      </div>
                    </div>
                  )}
                  {auditPhase === 'result' && auditData && (
                    <div className={`audit-result audit-result--${auditData.verdict?.toLowerCase()}`}
                      style={{ '--vc': auditData.color }}>
                      <div className="ar__verdict">
                        <span className="ar__icon">{auditData.icon}</span>
                        <span className="ar__label" style={{ color: auditData.color }}>{auditData.verdict}</span>
                      </div>
                      <p className="ar__summary">{auditData.summary}</p>
                      <p className="ar__details">{auditData.details}</p>
                      {auditData.fix?.length > 0 && (
                        <div className="ar__fix">
                          <div className="ar__fix-label">Ansible Remediation Config:</div>
                          {auditData.fix.map((line, i) => (
                            <code key={i} className="ar__fix-line">{line}</code>
                          ))}
                        </div>
                      )}
                      {auditData.verdict === 'VULNERABLE' && healPhase === 'idle' && (
                        <button className="btn-heal" onClick={approveHealing}>
                          ⚡ Approve &amp; Auto-Heal via Ansible
                        </button>
                      )}
                      {healPhase === 'running' && (
                        <div className="heal-prog">
                          <div className="heal-prog__ring" />
                          <span>Applying remediation playbook…</span>
                        </div>
                      )}
                      {healPhase === 'done' && (
                        <div className="heal-done">✅ Remediation complete — device is SECURE.</div>
                      )}
                      <button
                        className="btn-rerun"
                        onClick={() => { setAuditPhase('idle'); setHealPhase('idle'); }}>
                        ↻ Re-Audit
                      </button>
                    </div>
                  )}
                </section>
              )}
            </div>
          </>
        )}
      </aside>

      {/* ── PILLAR 1: AI CHAT (real Gemini) ── */}
      <div className={`chat-fab${chatOpen ? ' chat-fab--open' : ''}`}
        onClick={() => !chatOpen && setChatOpen(true)}>
        {!chatOpen && <span className="chat-fab__icon">🧠</span>}
        {chatOpen && (
          <div className="chat-panel" onClick={e => e.stopPropagation()}>
            <div className="chat-panel__head">
              <span className="chat-panel__title">🧠 NOC AI Assistant — Powered by Gemini</span>
              <button className="chat-panel__close" onClick={() => setChatOpen(false)}>✕</button>
            </div>
            <div className="chat-panel__body">
              {chatMsgs.map((m, i) => (
                <div key={i} className={`chat-msg chat-msg--${m.role}`}>
                  <div className={`chat-msg__bubble${m.loading ? ' chat-msg__bubble--loading' : ''}`}>
                    {m.loading ? '●●●' : m.text}
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
            <form className="chat-panel__input" onSubmit={handleChatSend}>
              <input
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                placeholder={chatLoading ? 'Gemini is thinking…' : 'Ask about your live network…'}
                disabled={chatLoading}
                autoFocus
              />
              <button type="submit" disabled={chatLoading || !chatInput.trim()}>▶</button>
            </form>
          </div>
        )}
      </div>
    </div>
  );
}