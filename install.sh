#!/usr/bin/env bash
# ============================================================
# OPNSense Analyzer - One-Command Installer for Debian 13
# Everything lives under /srv/opnsense-analyzer/ — nothing scattered.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/opnsense-analyzer/main/install.sh | sudo bash
#   PORT=9090 curl -fsSL ... | sudo bash   # custom port
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

REPO_URL="https://github.com/YOUR_USERNAME/opnsense-analyzer"
INSTALL_DIR="/srv/opnsense-analyzer"
PORT="${PORT:-8080}"

# All host-side paths live under INSTALL_DIR
DATA_DIR="${INSTALL_DIR}/data"
LOGS_DIR="${DATA_DIR}/logs"

# Point Docker's build cache into our directory instead of /var/lib/docker
export DOCKER_BUILDKIT=1
export BUILDKIT_PROGRESS=plain

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[→]${NC} $1"; }

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   🛡  OPNSense Analyzer Installer${NC}"
echo -e "${BLUE}   Everything will live in: ${INSTALL_DIR}${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Check root ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "This script must be run as root. Try: sudo bash install.sh"
fi

# ── Detect OS ───────────────────────────────────────────────
if ! grep -qi "debian" /etc/os-release 2>/dev/null; then
  warn "This script is optimized for Debian. Proceeding anyway..."
fi

info "Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# ── Install Docker if not present ───────────────────────────
if ! command -v docker &>/dev/null; then
  info "Docker not found — installing..."
  apt-get install -y -qq ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  log "Docker installed"
else
  log "Docker already installed: $(docker --version)"
fi

# ── Move Docker data root into /srv if not already configured ──
# This is optional but keeps ALL docker data under /srv on a dedicated server.
# Uncomment the block below if you want Docker's full data root moved too.
# DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
# if ! grep -q '"data-root"' "$DOCKER_DAEMON_JSON" 2>/dev/null; then
#   info "Configuring Docker data-root to /srv/docker ..."
#   mkdir -p /srv/docker
#   echo '{ "data-root": "/srv/docker" }' > "$DOCKER_DAEMON_JSON"
#   systemctl restart docker
#   log "Docker data-root set to /srv/docker"
# fi

# ── Install git if not present ──────────────────────────────
if ! command -v git &>/dev/null; then
  apt-get install -y -qq git
  log "Git installed"
fi

# ── Create directory layout under /srv/opnsense-analyzer ────
info "Creating directory structure under ${INSTALL_DIR} ..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${LOGS_DIR}"
log "Directories created:
      ${INSTALL_DIR}/          ← source code + compose files
      ${LOGS_DIR}/    ← container log output"

# ── Clone / update repo into /srv/opnsense-analyzer ─────────
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  info "Updating existing installation..."
  git -C "${INSTALL_DIR}" pull --ff-only
  log "Repository updated"
else
  info "Cloning repository to ${INSTALL_DIR} ..."
  git clone "$REPO_URL" "${INSTALL_DIR}"
  log "Repository cloned"
fi

cd "${INSTALL_DIR}"

# ── Configure port ───────────────────────────────────────────
if [[ "$PORT" != "8080" ]]; then
  info "Configuring port $PORT..."
  sed -i "s/\"8080:8080\"/\"${PORT}:8080\"/" docker-compose.yml
  log "Port set to $PORT"
fi

# ── Build & start ────────────────────────────────────────────
info "Building Docker image (this may take a minute)..."
docker compose build --no-cache

info "Starting container..."
docker compose up -d

# ── Wait for health ──────────────────────────────────────────
info "Waiting for service to be healthy..."
MAX_WAIT=60
WAITED=0
until curl -sf "http://localhost:${PORT}/health" &>/dev/null; do
  sleep 2
  WAITED=$((WAITED+2))
  if [[ $WAITED -ge $MAX_WAIT ]]; then
    err "Service did not start in ${MAX_WAIT}s. Check: docker logs opnsense-analyzer"
  fi
done
log "Service is healthy"

# ── Systemd service for auto-start on boot ───────────────────
info "Registering systemd service..."
cat > /etc/systemd/system/opnsense-analyzer.service <<EOF
[Unit]
Description=OPNSense Analyzer
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable opnsense-analyzer
log "Systemd service enabled (auto-starts on boot)"

# ── UFW firewall rule — LAN only ─────────────────────────────
if command -v ufw &>/dev/null; then
  LOCAL_SUBNET=$(ip route | grep -v default | head -1 | awk '{print $1}' 2>/dev/null || echo "")
  if [[ -n "$LOCAL_SUBNET" ]]; then
    ufw allow from "$LOCAL_SUBNET" to any port "$PORT" comment "OPNSense Analyzer (LAN only)" 2>/dev/null || true
    warn "UFW: allowed ${LOCAL_SUBNET} → port ${PORT}"
    warn "SECURITY: Port ${PORT} must NOT be reachable from the internet."
  fi
fi

# ── Print layout summary ─────────────────────────────────────
LOCAL_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}   ✅  OPNSense Analyzer is running!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "   🌐 Local:    ${BLUE}http://localhost:${PORT}${NC}"
echo -e "   🌐 Network:  ${BLUE}http://${LOCAL_IP}:${PORT}${NC}"
echo ""
echo -e "   📁 All files are under: ${YELLOW}${INSTALL_DIR}/${NC}"
echo -e "      Source code:  ${INSTALL_DIR}/backend/  frontend/"
echo -e "      Logs:         ${LOGS_DIR}/"
echo -e "      Compose file: ${INSTALL_DIR}/docker-compose.yml"
echo ""
echo -e "   📋 Manage:"
echo -e "      Start:   ${YELLOW}systemctl start opnsense-analyzer${NC}"
echo -e "      Stop:    ${YELLOW}systemctl stop opnsense-analyzer${NC}"
echo -e "      Logs:    ${YELLOW}docker logs opnsense-analyzer${NC}"
echo -e "      Update:  ${YELLOW}cd ${INSTALL_DIR} && git pull && docker compose up -d --build${NC}"
echo -e "      Remove:  ${YELLOW}docker compose down --rmi all && rm -rf ${INSTALL_DIR}${NC}"
echo ""
echo -e "   ⚠️  ${RED}SECURITY REMINDER:${NC}"
echo -e "   Keep this service on your local network only."
echo -e "   OPNSense backups contain sensitive credentials."
echo ""
