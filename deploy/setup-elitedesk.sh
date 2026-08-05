#!/usr/bin/env bash
# ==============================================================================
# Outpost Phishing Intelligence Pipeline — HP EliteDesk 800 G4 Mini Setup Script
# Target OS: Arch Linux (i3 window manager, 24/7 server node)
# Directory: /opt/heapleap
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Color output helpers
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ------------------------------------------------------------------------------
# Root check
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  log_error "This script must be executed as root (or via sudo)."
  exit 1
fi

echo "=============================================================================="
echo "          Outpost Intelligence Pipeline — Arch Linux Setup                    "
echo "=============================================================================="

# ------------------------------------------------------------------------------
# SECTION 1: Package Management & System Dependencies
# ------------------------------------------------------------------------------
log_info "1/6 Installing system packages via pacman..."

if ! command -v pacman &>/dev/null; then
  log_error "pacman not found. This script is tailored for Arch Linux."
  exit 1
fi

# Refresh package databases
pacman -Sy --noconfirm

# Required official Arch Linux packages.
#
# podman rather than docker: the analyzer sandbox runs rootless under podman,
# so the 'outpost' user needs no membership of the 'docker' group. Membership
# of that group is equivalent to root on the host (you can bind-mount / into a
# privileged container), and it was previously granted for a sandbox that no
# code actually launched.
PACKAGES=(
  postgresql
  python
  python-pip
  podman
  git
  base-devel
  curl
  wget
)

# Optional / extra packages (e.g. cloudflared from official extra repo or AUR)
if pacman -Si cloudflared &>/dev/null; then
  PACKAGES+=(cloudflared)
else
  log_warn "cloudflared package not found in main repos. It can be installed via AUR (yay -S cloudflared)."
fi

pacman -S --needed --noconfirm "${PACKAGES[@]}"
log_ok "System packages installed successfully."

# ------------------------------------------------------------------------------
# Chromium renderer sandbox prerequisite
# ------------------------------------------------------------------------------
# The deep-triage pool navigates to live attacker infrastructure and executes
# its JavaScript. Chromium's own sandbox needs unprivileged user namespaces;
# without them it refuses to start, and the tempting "fix" is --no-sandbox,
# which removes the only thing standing between a renderer bug and code
# execution as 'outpost'. Enable the kernel feature instead.
log_info "Enabling unprivileged user namespaces (Chromium renderer sandbox)..."
echo 'kernel.unprivileged_userns_clone=1' > /etc/sysctl.d/99-userns.conf
sysctl -w kernel.unprivileged_userns_clone=1 >/dev/null 2>&1 || \
  log_warn "kernel.unprivileged_userns_clone not settable on this kernel (may already be default-on)."
log_ok "Unprivileged user namespaces enabled."

# ------------------------------------------------------------------------------
# SECTION 2: Create 'outpost' System User
# ------------------------------------------------------------------------------
log_info "2/6 Ensuring 'outpost' system user exists..."

if id "outpost" &>/dev/null; then
  log_ok "System user 'outpost' already exists."
else
  useradd -r -s /bin/bash -m -d /opt/heapleap outpost
  log_ok "Created system user 'outpost' with home directory /opt/heapleap."
fi

# NOTE: 'outpost' is deliberately NOT added to the 'docker' group.
#
# Docker group membership is root-equivalent — a member can bind-mount / into a
# privileged container and walk out with the host. It used to be granted here
# "so it can run sandbox containers", at a time when no code launched a
# container at all. The analyzer now runs under rootless podman, which needs no
# group membership and no daemon.
#
# If this box previously had the membership, remove it:
if id -nG outpost 2>/dev/null | grep -qw docker; then
  gpasswd -d outpost docker >/dev/null 2>&1 || true
  log_warn "Removed 'outpost' from the docker group (root-equivalent, no longer needed)."
fi

# Rootless podman needs subuid/subgid ranges for the user.
if ! grep -q '^outpost:' /etc/subuid 2>/dev/null; then
  usermod --add-subuids 200000-265535 --add-subgids 200000-265535 outpost
  log_ok "Allocated subuid/subgid ranges for rootless podman."
fi

# ------------------------------------------------------------------------------
# SECTION 3: PostgreSQL Database Setup
# ------------------------------------------------------------------------------
log_info "3/6 Setting up PostgreSQL database..."

PG_DATA_DIR="/var/lib/postgres/data"

if [ ! -d "$PG_DATA_DIR" ] || [ -z "$(ls -A "$PG_DATA_DIR" 2>/dev/null)" ]; then
  log_info "Initializing new PostgreSQL database cluster..."
  su - postgres -c "initdb -D '$PG_DATA_DIR' --locale=C.UTF-8"
  log_ok "Database cluster initialized."
else
  log_ok "PostgreSQL cluster already initialized at $PG_DATA_DIR."
fi

# Enable and start PostgreSQL service
systemctl enable --now postgresql.service
log_ok "postgresql.service is active."

# Idempotent DB user and database creation
log_info "Configuring PostgreSQL user 'outpost' and database 'outpost'..."

# Create database user 'outpost' if it doesn't exist.
#
# The password is GENERATED, not the literal string 'outpost'. It is written to
# /opt/heapleap/.pgpassword (mode 0600, owned by outpost) so the operator can
# paste it into PKINTEL_DB_URL. A guessable database password on a box that
# also holds the audit log and the work queue is not worth the convenience.
PGPASS_FILE="/opt/heapleap/.pgpassword"
USER_EXISTS=$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='outpost';\"" || true)
if [ "$USER_EXISTS" != "1" ]; then
  DB_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
  su - postgres -c "psql -c \"CREATE USER outpost WITH PASSWORD '${DB_PASSWORD}';\""
  mkdir -p /opt/heapleap
  umask 077
  printf '%s\n' "$DB_PASSWORD" > "$PGPASS_FILE"
  chmod 600 "$PGPASS_FILE"
  log_ok "PostgreSQL user 'outpost' created with a generated password."
  log_warn "Password written to ${PGPASS_FILE} (mode 0600). Put it in PKINTEL_DB_URL, then delete the file."
else
  log_ok "PostgreSQL user 'outpost' already exists (password left unchanged)."
fi

# Create database 'outpost' if it doesn't exist
DB_EXISTS=$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='outpost';\"" || true)
if [ "$DB_EXISTS" != "1" ]; then
  su - postgres -c "psql -c \"CREATE DATABASE outpost OWNER outpost;\""
  log_ok "PostgreSQL database 'outpost' created."
else
  log_ok "PostgreSQL database 'outpost' already exists."
fi

# Grant full privileges on database
su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE outpost TO outpost;\""
log_ok "PostgreSQL privileges granted."

# ------------------------------------------------------------------------------
# SECTION 4: Directory Structure & Permissions
# ------------------------------------------------------------------------------
log_info "4/6 Creating /opt/heapleap directory structure..."

mkdir -p /opt/heapleap/.storage/kits
mkdir -p /opt/heapleap/.storage/screenshots
mkdir -p /opt/heapleap/deploy
# outpost@.service declares these as ReadWritePaths. They are marked optional
# with a leading '-' so a missing one no longer prevents the unit from starting,
# but creating them is still the right thing to do.
mkdir -p /opt/heapleap/logs
mkdir -p /opt/heapleap/.cache

chown -R outpost:outpost /opt/heapleap

# NOT `chmod -R 755`. That made /opt/heapleap/.env — which holds the SMTP
# password, the indicator encryption key, the R2 secret and the DB DSN —
# readable by every local user and every process on the box.
chmod 750 /opt/heapleap
chmod 700 /opt/heapleap/.storage
[ -f /opt/heapleap/.env ] && chmod 600 /opt/heapleap/.env
for f in /opt/heapleap/.env.*; do
  [ -f "$f" ] && chmod 600 "$f"
done
log_ok "Directory structure created at /opt/heapleap (secrets mode 0600)."

# ------------------------------------------------------------------------------
# SECTION 5: Python Virtual Environment & Project Dependencies
# ------------------------------------------------------------------------------
log_info "5/6 Setting up Python 3.12 virtual environment..."

VENV_DIR="/opt/heapleap/venv"

if [ ! -d "$VENV_DIR" ]; then
  su - outpost -c "python3 -m venv '$VENV_DIR'"
  log_ok "Created virtual environment at $VENV_DIR."
else
  log_ok "Virtual environment already exists at $VENV_DIR."
fi

# Upgrade pip and base tools
su - outpost -c "'$VENV_DIR/bin/pip' install --upgrade pip setuptools wheel"

# Install project editable package if cloned
if [ -f "/opt/heapleap/pyproject.toml" ]; then
  log_info "Installing Outpost dependencies from /opt/heapleap/pyproject.toml..."
  su - outpost -c "cd /opt/heapleap && '$VENV_DIR/bin/pip' install -e '.[dev]'"
  log_ok "Outpost package installed into venv."
else
  log_warn "/opt/heapleap/pyproject.toml not found yet. Ensure code is cloned to /opt/heapleap before starting services."
fi

# ------------------------------------------------------------------------------
# SECTION 6: Hardened Analyzer Sandbox Image
# ------------------------------------------------------------------------------
# Built as the 'outpost' user under rootless podman, so the resulting image
# lives in that user's own store and the analyzer needs no daemon and no
# privileged group. The analyzer stage will refuse to run without this image.
log_info "6/6 Building the hardened analyzer sandbox image (rootless podman)..."

if [ -f "/opt/heapleap/analyzer_container/Dockerfile" ]; then
  su - outpost -c "podman build -t pkintel-analyzer:latest \
      -f /opt/heapleap/analyzer_container/Dockerfile /opt/heapleap" \
    && log_ok "Sandbox image 'pkintel-analyzer:latest' built." \
    || log_warn "Sandbox image build failed. The analyzer stage will not run until it succeeds."
else
  log_warn "analyzer_container/Dockerfile not found. Clone the repo first, then: make analyzer-image"
fi

# Ensure permissions after build steps (secrets keep their restrictive modes).
chown -R outpost:outpost /opt/heapleap
chmod 750 /opt/heapleap
[ -f /opt/heapleap/.env ] && chmod 600 /opt/heapleap/.env

# ------------------------------------------------------------------------------
# COMPLETION & NEXT STEPS
# ------------------------------------------------------------------------------
echo "=============================================================================="
echo -e "${GREEN}                 Setup Completed Successfully!                                ${NC}"
echo "=============================================================================="
echo "Next deployment steps to complete on EliteDesk:"
echo ""
echo "1. Clone / sync repository into /opt/heapleap:"
echo "   git clone <repo-url> /opt/heapleap"
echo "   chown -R outpost:outpost /opt/heapleap"
echo ""
echo "2. Set the DB password from ${PGPASS_FILE} into PKINTEL_DB_URL, then:"
echo "   shred -u ${PGPASS_FILE}"
echo ""
echo "3. Import the database dump exported from Neon (via export-neon-db.sh):"
echo "   psql 'postgresql://outpost:<password>@localhost:5432/outpost' \\"
echo "        -f /opt/heapleap/deploy/outpost_dump.sql"
echo ""
echo "4. Set up environment configuration:"
echo "   cp /opt/heapleap/deploy/.env.example /opt/heapleap/.env"
echo "   chown outpost:outpost /opt/heapleap/.env && chmod 600 /opt/heapleap/.env"
echo "   nano /opt/heapleap/.env   # DB URL, Sentry, SMTP, API keys"
echo ""
echo "   Generate the indicator encryption key (without it, full indicator"
echo "   values are NOT retained — the pipeline fails closed, by design):"
echo "     python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
echo "   -> PKINTEL_INDICATOR_ENC_KEY"
echo ""
echo "5. Run database migrations & seed feed sources:"
echo "   su - outpost -c '/opt/heapleap/venv/bin/pkintel db migrate'"
echo "   su - outpost -c '/opt/heapleap/venv/bin/pkintel db seed'"
echo ""
echo "6. Install systemd units and the per-stage drop-ins:"
echo "   cp /opt/heapleap/deploy/*.service /opt/heapleap/deploy/*.target /etc/systemd/system/"
echo "   for f in /opt/heapleap/deploy/stage-env/*.conf; do"
echo "     s=\$(basename \"\$f\" .conf)"
echo "     install -Dm644 \"\$f\" \"/etc/systemd/system/outpost@\${s}.service.d/override.conf\""
echo "   done"
echo "   systemctl daemon-reload"
echo "   systemd-analyze verify /etc/systemd/system/outpost@.service   # must be clean"
echo ""
echo "7. Start everything as ONE group:"
echo "   systemctl enable --now outpost.target"
echo ""
echo "   Do NOT also enable outpost-pipeline.service or outpost-ct.service."
echo "   They run the same stages as the outpost@* units; enabling both means"
echo "   every stage executes twice and every victim server sees double the"
echo "   requests. They are marked Conflicts= so systemd will refuse, but the"
echo "   correct action is to leave them disabled."
echo ""
echo "8. Verify:"
echo "   systemctl status outpost.target"
echo "   systemctl list-dependencies outpost.target"
echo "   curl -s localhost:8000/health | jq"
echo "   curl -s localhost:9101/metrics | head   # triage worker metrics"
echo "=============================================================================="
