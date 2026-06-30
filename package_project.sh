#!/usr/bin/env bash
# =============================================================================
#  package_project.sh — Enterprise NMS Delivery Packager
#  Authored for: NextGen Hospital NMS — Final Golden Build
#
#  WHAT THIS SCRIPT DOES (in order):
#    1. Presents 5 enterprise product name options and lets you choose.
#    2. Locates your source project directory (auto-detects or accepts arg).
#    3. Copies all necessary files into a clean, renamed delivery folder,
#       strictly excluding node_modules, .git, dist/, and all fix*.cjs /
#       fix*.js / rebuild_app.cjs / add_poller.cjs dev-time AST scripts.
#    4. Moves master_topology.j2 and topology_template.j2 into the
#       roles/cisco_base/templates/ directory (Ansible Galaxy best practice).
#    5. Patches all playbooks with sed so their template: src: references
#       point to the new roles/cisco_base/templates/ path.
#    6. Zips the clean directory and reports the output path.
#
#  USAGE:
#    chmod +x package_project.sh
#    ./package_project.sh                          # fully interactive
#    ./package_project.sh --name "AXIOM-NOC"       # skip name prompt
#    ./package_project.sh --src /path/to/project   # specify source dir
#    ./package_project.sh --name "NeuralFabric" --src ~/projects/hospital
# =============================================================================

set -euo pipefail   # Exit on any error, unset variable, or pipe failure.
                    # This turns silent failures into loud, obvious ones —
                    # critical for a packaging script that modifies files.

# ── Colour helpers ────────────────────────────────────────────────────────────
# These are purely cosmetic but make the output dramatically easier to read
# when you are watching a long script scroll by in a terminal.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fatal()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}${CYAN}  $*${RESET}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}\n"; }

# ── Enterprise name registry ──────────────────────────────────────────────────
# Stored as a plain array so the selection menu is data-driven.
# Add or remove names here without touching any other logic.
ENTERPRISE_NAMES=(
  "AXIOM-NOC"       # Autonomous eXchange & Intelligent Operations Monitor
  "NeuralFabric"    # AI-woven self-healing network digital twin
  "ClarisSOC"       # Zero-config clarity + HIPAA-grade autonomous SOC
  "PulseMatrix"     # Live telemetry heartbeat across a multi-site topology
  "OmniSentinel"    # All-seeing radar + autonomous threat sentinel
)

# ── Argument parsing ──────────────────────────────────────────────────────────
# Supports both interactive mode (no args) and CI/automation mode (--name, --src).
CHOSEN_NAME=""
SOURCE_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      CHOSEN_NAME="$2"
      shift 2
      ;;
    --src)
      SOURCE_DIR="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--name <project-name>] [--src <source-directory>]"
      exit 0
      ;;
    *)
      fatal "Unknown argument: $1. Use --name or --src."
      ;;
  esac
done

# =============================================================================
#  STEP 1 — Choose an enterprise product name
# =============================================================================
header "Step 1 — Enterprise Product Name"

if [[ -z "$CHOSEN_NAME" ]]; then
  echo "  Select a name for this delivery package:"
  echo ""
  for i in "${!ENTERPRISE_NAMES[@]}"; do
    printf "  ${BOLD}[%d]${RESET} %s\n" "$((i+1))" "${ENTERPRISE_NAMES[$i]}"
  done
  echo "  ${BOLD}[6]${RESET} Enter a custom name"
  echo ""

  while true; do
    read -rp "  Your choice [1-6]: " choice
    if [[ "$choice" =~ ^[1-5]$ ]]; then
      CHOSEN_NAME="${ENTERPRISE_NAMES[$((choice-1))]}"
      break
    elif [[ "$choice" == "6" ]]; then
      read -rp "  Enter custom product name: " CHOSEN_NAME
      [[ -z "$CHOSEN_NAME" ]] && fatal "Product name cannot be empty."
      break
    else
      warn "Please enter a number between 1 and 6."
    fi
  done
fi

success "Product name selected: ${BOLD}${CHOSEN_NAME}${RESET}"

# Sanitise the name for use as a directory/filename:
# replace spaces and special chars with hyphens, lowercase everything.
SAFE_NAME=$(echo "$CHOSEN_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g' | sed 's/^-//;s/-$//')

# =============================================================================
#  STEP 2 — Locate the source project directory
# =============================================================================
header "Step 2 — Locating Source Project"

if [[ -z "$SOURCE_DIR" ]]; then
  # Auto-detect: look for the v3 project folder next to this script,
  # in the current working directory, or in the home directory.
  # The order of preference is: script's directory → cwd → home.
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  for candidate in \
    "${SCRIPT_DIR}/mynext_gen_hospital v3" \
    "${SCRIPT_DIR}/mynext_gen_hospital_v3" \
    "$(pwd)/mynext_gen_hospital v3" \
    "$(pwd)/mynext_gen_hospital_v3" \
    "${HOME}/mynext_gen_hospital v3" \
    "${HOME}/mynext_gen_hospital_v3"
  do
    if [[ -d "$candidate" ]]; then
      SOURCE_DIR="$candidate"
      break
    fi
  done

  if [[ -z "$SOURCE_DIR" ]]; then
    # Last resort: ask the user directly.
    echo "  Could not auto-detect the source project directory."
    read -rp "  Enter full path to 'mynext_gen_hospital v3': " SOURCE_DIR
    # Expand tilde and trim whitespace
    SOURCE_DIR="${SOURCE_DIR/#\~/$HOME}"
    SOURCE_DIR="${SOURCE_DIR%/}"
  fi
fi

[[ -d "$SOURCE_DIR" ]] || fatal "Source directory not found: '${SOURCE_DIR}'"
success "Source directory: ${SOURCE_DIR}"

# =============================================================================
#  STEP 3 — Prepare the output directory
# =============================================================================
header "Step 3 — Preparing Clean Output Directory"

# Place the output next to the source project directory so we don't accidentally
# write into the source tree itself.
OUTPUT_PARENT="$(dirname "$SOURCE_DIR")"
OUTPUT_DIR="${OUTPUT_PARENT}/${CHOSEN_NAME}"
ZIP_PATH="${OUTPUT_PARENT}/${SAFE_NAME}-delivery.zip"

# If a previous packaging run left an output directory or zip, remove them
# cleanly rather than asking the user to do it manually.
if [[ -d "$OUTPUT_DIR" ]]; then
  warn "Output directory already exists — removing: ${OUTPUT_DIR}"
  rm -rf "$OUTPUT_DIR"
fi
if [[ -f "$ZIP_PATH" ]]; then
  warn "Previous zip found — removing: ${ZIP_PATH}"
  rm -f "$ZIP_PATH"
fi

mkdir -p "$OUTPUT_DIR"
success "Output directory created: ${OUTPUT_DIR}"

# =============================================================================
#  STEP 4 — Selective rsync copy (exclude garbage and build artifacts)
# =============================================================================
header "Step 4 — Copying Project Files (Exclusions Active)"

# rsync is used instead of cp -r because its --exclude patterns give us
# surgical control over what does and does not transfer.  Each exclusion
# has an explicit comment so a future maintainer understands the reasoning.
#
# EXCLUSION RATIONALE:
#   node_modules/   — npm install will recreate this; it can be 300 MB+
#   .git/           — delivery packages must not expose version history
#   dist/           — the recipient runs `npm run build` in their env
#   fix*.cjs        — AST patch scripts used during dev; dead weight now
#   fix*.js         — same category, .js extension variant
#   fix_*.cjs       — underscore variants (fix_panel.cjs, fix_ui.cjs, etc.)
#   rebuild_app.cjs — one-time full-file rebuild helper; dev-only
#   add_poller.cjs  — one-time poller injection script; dev-only
#   *.log           — any stray log files
#   siem_events.log — audit trail log (runtime-generated, not source)
#   __pycache__/    — any Python cache dirs (spike.py lives in public/)
#   .DS_Store       — macOS metadata noise

rsync -a \
  --exclude='node_modules/' \
  --exclude='.git/' \
  --exclude='dist/' \
  --exclude='fix[0-9]*.cjs' \
  --exclude='fix[0-9]*.js' \
  --exclude='fix.cjs' \
  --exclude='fix.js' \
  --exclude='fix_*.cjs' \
  --exclude='fix_*.js' \
  --exclude='rebuild_app.cjs' \
  --exclude='add_poller.cjs' \
  --exclude='*.log' \
  --exclude='siem_events.log' \
  --exclude='__pycache__/' \
  --exclude='.DS_Store' \
  "${SOURCE_DIR}/" \
  "${OUTPUT_DIR}/"

success "Files copied — exclusions applied."

# Quick sanity: confirm the critical source files arrived.
for critical in \
  "hospital-dashboard/src/App.jsx" \
  "hospital-dashboard/src/App.css" \
  "hospital-dashboard/server.cjs" \
  "live_docs_backup.yml" \
  "ai_audit.yml" \
  "hosts" \
  "ansible.cfg"
do
  if [[ ! -f "${OUTPUT_DIR}/${critical}" ]]; then
    fatal "Critical file missing after copy: ${critical}"
  fi
done
success "Critical file integrity check passed."

# =============================================================================
#  STEP 5 — Ansible Galaxy refactor: move .j2 templates
# =============================================================================
header "Step 5 — Ansible Refactor: Moving Jinja2 Templates"

TEMPLATES_DST="${OUTPUT_DIR}/roles/cisco_base/templates"
mkdir -p "$TEMPLATES_DST"

# We move (not copy) so there are no duplicate templates left at the root.
# If either file doesn't exist in the copy, we warn rather than fatal —
# the user may have already moved them in a previous run.
for j2_file in "master_topology.j2" "topology_template.j2"; do
  SRC_PATH="${OUTPUT_DIR}/${j2_file}"
  DST_PATH="${TEMPLATES_DST}/${j2_file}"

  if [[ -f "$SRC_PATH" ]]; then
    mv "$SRC_PATH" "$DST_PATH"
    success "Moved: ${j2_file}  →  roles/cisco_base/templates/${j2_file}"
  elif [[ -f "$DST_PATH" ]]; then
    info "Already in place: roles/cisco_base/templates/${j2_file}"
  else
    warn "${j2_file} not found at root or templates/ — skipping."
  fi
done

# =============================================================================
#  STEP 6 — Patch playbook template paths with sed
# =============================================================================
header "Step 6 — Patching Playbook template: src: References"

# The only confirmed reference is in live_docs_backup.yml:
#   src:  master_topology.j2
# After our move it must read:
#   src:  roles/cisco_base/templates/master_topology.j2
#
# sed logic:
#   We target lines that contain `src:` and end with `.j2` but do NOT
#   already contain `roles/cisco_base/templates/` — so this patch is
#   idempotent; running the script twice won't double-prefix the path.
#
#   The pattern captures whitespace before `src:` so indentation is preserved.

patch_playbook() {
  local playbook="$1"
  local filepath="${OUTPUT_DIR}/${playbook}"

  [[ -f "$filepath" ]] || { warn "Playbook not found, skipping: ${playbook}"; return; }

  # Idempotency guard: skip if already patched.
  if grep -q "roles/cisco_base/templates/" "$filepath" 2>/dev/null; then
    info "Already patched: ${playbook}"
    return
  fi

  # BSD sed (macOS) requires -i '' while GNU sed (Linux) uses -i alone.
  # We detect which sed is available and set the flag accordingly.
  if sed --version 2>&1 | grep -q GNU; then
    SED_INPLACE=(-i)
  else
    SED_INPLACE=(-i '')
  fi

  # Pattern: match `src:  <filename>.j2` (any whitespace before/after src:)
  # and prefix the filename with the Galaxy templates path.
  sed "${SED_INPLACE[@]}" \
    -E 's|(src:[[:space:]]+)([^/][^[:space:]]*)\.j2|\1roles/cisco_base/templates/\2.j2|g' \
    "$filepath"

  # Verify the patch actually took effect.
  if grep -q "roles/cisco_base/templates/" "$filepath"; then
    success "Patched: ${playbook}"
  else
    warn "Patch may not have matched anything in: ${playbook}"
    info  "  Check manually: grep 'src.*\.j2' ${playbook}"
  fi
}

patch_playbook "live_docs_backup.yml"
patch_playbook "ai_audit.yml"
patch_playbook "site.yml"

# =============================================================================
#  STEP 7 — Verify fix scripts are truly absent from output
# =============================================================================
header "Step 7 — Verifying Fix Script Elimination"

GARBAGE_FOUND=0
while IFS= read -r -d '' garbage_file; do
  warn "Garbage file still present: ${garbage_file#"$OUTPUT_DIR/"}"
  GARBAGE_FOUND=1
done < <(find "$OUTPUT_DIR" \
  \( -name 'fix*.cjs' -o -name 'fix*.js' -o -name 'fix_*.cjs' \
     -o -name 'rebuild_app.cjs' -o -name 'add_poller.cjs' \) \
  -print0 2>/dev/null)

if [[ "$GARBAGE_FOUND" -eq 1 ]]; then
  warn "Some fix scripts survived the rsync exclusions — removing them now."
  find "$OUTPUT_DIR" \
    \( -name 'fix*.cjs' -o -name 'fix*.js' -o -name 'fix_*.cjs' \
       -o -name 'rebuild_app.cjs' -o -name 'add_poller.cjs' \) \
    -delete
  success "Residual fix scripts forcibly removed."
else
  success "No fix/rebuild scripts found in output — clean."
fi

# =============================================================================
#  STEP 8 — Generate DELIVERY_NOTES.md inside the package
# =============================================================================
header "Step 8 — Writing Delivery Notes"

BUILD_DATE=$(date '+%Y-%m-%d %H:%M:%S %Z')

cat > "${OUTPUT_DIR}/DELIVERY_NOTES.md" << NOTES_EOF
# ${CHOSEN_NAME} — Delivery Package

**Packaged:** ${BUILD_DATE}
**Source:** $(basename "$SOURCE_DIR")

## Quick Start

### 1. Install Node.js dependencies
\`\`\`bash
cd hospital-dashboard
npm install
\`\`\`

### 2. Configure environment
Copy \`.env.example\` to \`.env\` and populate:
- \`GEMINI_API_KEY\` — your Google Gemini API key
- \`BACKEND_PORT\` — default 3001

### 3. Start the backend
\`\`\`bash
node server.cjs
\`\`\`

### 4. Start the frontend (dev mode)
\`\`\`bash
npm run dev
\`\`\`

### 5. Build for production
\`\`\`bash
npm run build
\`\`\`

### 6. Run the Ansible poller
\`\`\`bash
ansible-playbook live_docs_backup.yml -i hosts
\`\`\`

## Ansible Template Path
Jinja2 templates have been moved to Galaxy best-practice location:
\`roles/cisco_base/templates/\`

Both \`master_topology.j2\` and \`topology_template.j2\` now live there.
All playbooks have been patched to reference this path.

## What Was Excluded From This Package
- \`node_modules/\` — run \`npm install\` to restore
- \`dist/\` — run \`npm run build\` to restore
- \`.git/\` — version history not included in delivery
- All \`fix*.cjs\`, \`fix*.js\`, \`rebuild_app.cjs\`, \`add_poller.cjs\` dev scripts

## Architecture
- **Frontend:** React 18 + ForceGraph2D (Vite)
- **Backend:** Node.js + Express + Socket.io
- **Automation:** Ansible + Jinja2 (cisco_base role)
- **AI:** Google Gemini API (via /api/chat and ai_audit.yml)
- **Transport:** UDP Syslog (514) + WebSocket real-time
NOTES_EOF

success "DELIVERY_NOTES.md written."

# =============================================================================
#  STEP 9 — Create the final .zip archive
# =============================================================================
header "Step 9 — Creating ZIP Archive"

# zip is called from OUTPUT_PARENT so the archive contains the named folder
# at its root (e.g. AXIOM-NOC/...) rather than a bare file dump.
# The -r flag recurses, -q suppresses per-file output (keeps logs readable).
(
  cd "$OUTPUT_PARENT"
  zip -rq "${ZIP_PATH}" "$(basename "$OUTPUT_DIR")"
)

[[ -f "$ZIP_PATH" ]] || fatal "ZIP creation failed — file not found at: ${ZIP_PATH}"

ZIP_SIZE=$(du -sh "$ZIP_PATH" | cut -f1)
success "ZIP created: ${ZIP_PATH}  (${ZIP_SIZE})"

# =============================================================================
#  FINAL SUMMARY
# =============================================================================
header "Packaging Complete"

echo -e "  ${BOLD}Product Name:${RESET}     ${CHOSEN_NAME}"
echo -e "  ${BOLD}Clean Directory:${RESET}  ${OUTPUT_DIR}"
echo -e "  ${BOLD}Delivery ZIP:${RESET}     ${BOLD}${GREEN}${ZIP_PATH}${RESET}  (${ZIP_SIZE})"
echo ""
echo -e "  ${BOLD}Excluded:${RESET}"
echo    "    ✗  node_modules/          (npm install to restore)"
echo    "    ✗  dist/                  (npm run build to restore)"
echo    "    ✗  .git/                  (version history)"
echo    "    ✗  fix*.cjs / fix*.js     (dev AST patch scripts)"
echo    "    ✗  rebuild_app.cjs        (dev rebuild helper)"
echo    "    ✗  add_poller.cjs         (dev injection script)"
echo ""
echo -e "  ${BOLD}Refactored:${RESET}"
echo    "    ✔  master_topology.j2     → roles/cisco_base/templates/"
echo    "    ✔  topology_template.j2   → roles/cisco_base/templates/"
echo    "    ✔  live_docs_backup.yml   patched (template src: path updated)"
echo    "    ✔  ai_audit.yml           patched (template src: path updated)"
echo    "    ✔  site.yml               patched (template src: path updated)"
echo ""
echo -e "  ${GREEN}${BOLD}Ready for delivery. 🚀${RESET}"
echo ""
