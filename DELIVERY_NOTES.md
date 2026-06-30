# AXIOM-NOC — Delivery Package

**Packaged:** 2026-04-30 03:33:42 UTC
**Source:** mynext_gen_hospital v3

## Quick Start

### 1. Install Node.js dependencies
```bash
cd hospital-dashboard
npm install
```

### 2. Configure environment
Copy `.env.example` to `.env` and populate:
- `GEMINI_API_KEY` — your Google Gemini API key
- `BACKEND_PORT` — default 3001

### 3. Start the backend
```bash
node server.cjs
```

### 4. Start the frontend (dev mode)
```bash
npm run dev
```

### 5. Build for production
```bash
npm run build
```

### 6. Run the Ansible poller
```bash
ansible-playbook live_docs_backup.yml -i hosts
```

## Ansible Template Path
Jinja2 templates have been moved to Galaxy best-practice location:
`roles/cisco_base/templates/`

Both `master_topology.j2` and `topology_template.j2` now live there.
All playbooks have been patched to reference this path.

## What Was Excluded From This Package
- `node_modules/` — run `npm install` to restore
- `dist/` — run `npm run build` to restore
- `.git/` — version history not included in delivery
- All `fix*.cjs`, `fix*.js`, `rebuild_app.cjs`, `add_poller.cjs` dev scripts

## Architecture
- **Frontend:** React 18 + ForceGraph2D (Vite)
- **Backend:** Node.js + Express + Socket.io
- **Automation:** Ansible + Jinja2 (cisco_base role)
- **AI:** Google Gemini API (via /api/chat and ai_audit.yml)
- **Transport:** UDP Syslog (514) + WebSocket real-time
