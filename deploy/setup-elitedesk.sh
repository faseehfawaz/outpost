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

# Required official Arch Linux packages
PACKAGES=(
  postgresql
  python
  python-pip
  docker
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

# Enable & start Docker daemon
log_info "Enabling and starting docker.service..."
systemctl enable --now docker.service
log_ok "Docker daemon is active."

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

# Grant Docker group membership to outpost so it can run sandbox containers
usermod -aG docker outpost
log_ok "Added 'outpost' to the docker group."

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

# Create database user 'outpost' if it doesn't exist
USER_EXISTS=$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='outpost';\"" || true)
if [ "$USER_EXISTS" != "1" ]; then
  su - postgres -c "psql -c \"CREATE USER outpost WITH PASSWORD 'outpost';\""
  log_ok "PostgreSQL user 'outpost' created."
else
  log_ok "PostgreSQL user 'outpost' already exists."
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
mkdir -p /opt/heapleap/deploy

chown -R outpost:outpost /opt/heapleap
chmod -R 755 /opt/heapleap
log_ok "Directory structure created at /opt/heapleap with owner outpost:outpost."

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
# SECTION 6: Hardened Analyzer Docker Image Build
# ------------------------------------------------------------------------------
log_info "6/6 Checking Docker analyzer image build..."

if [ -f "/opt/heapleap/analyzer_container/Dockerfile" ]; then
  log_info "Building hardened sandbox image 'pkintel-analyzer:latest'..."
  docker build -t pkintel-analyzer:latest -f /opt/heapleap/analyzer_container/Dockerfile /opt/heapleap
  log_ok "Sandbox analyzer container image built successfully."
else
  log_warn "Analyzer Dockerfile not found at /opt/heapleap/analyzer_container/Dockerfile. Build manually after cloning."
fi

# Ensure permissions after build steps
chown -R outpost:outpost /opt/heapleap

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
echo "2. Import the database dump exported from Neon (via export-neon-db.sh):"
echo "   PGPASSWORD=outpost psql -h localhost -U outpost -d outpost -f /opt/heapleap/deploy/outpost_dump.sql"
echo ""
echo "3. Setup environment configuration:"
echo "   cp /opt/heapleap/deploy/.env.example /opt/heapleap/.env"
echo "   chown outpost:outpost /opt/heapleap/.env"
echo "   nano /opt/heapleap/.env  # edit Sentry, Datadog, API keys, SMTP, etc."
echo ""
echo "4. Run database migrations & seed feed sources:"
echo "   su - outpost -c '/opt/heapleap/venv/bin/pkintel db migrate'"
echo "   su - outpost -c '/opt/heapleap/venv/bin/pkintel db seed'"
echo ""
echo "5. Install and start systemd services:"
echo "   cp /opt/heapleap/deploy/*.service /etc/systemd/system/"
echo "   systemctl daemon-reload"
echo "   systemctl enable --now outpost-pipeline.service outpost-api.service outpost-ct.service"
echo ""
echo "6. Verify active status:"
echo "   systemctl status outpost-pipeline outpost-api outpost-ct"
echo "=============================================================================="
