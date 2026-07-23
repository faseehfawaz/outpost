#!/usr/bin/env bash
# ==============================================================================
# Outpost Database Exporter — Neon DB to EliteDesk Migration
# Run this script on MacBook to export current database to deploy/outpost_dump.sql
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

# Determine project directory structure
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/outpost_dump.sql"

echo "=============================================================================="
echo "          Outpost Neon Database Exporter (MacBook -> EliteDesk)              "
echo "=============================================================================="

# ------------------------------------------------------------------------------
# SECTION 1: Check Environment & Database URL
# ------------------------------------------------------------------------------
log_info "1/3 Resolving database connection string (PKINTEL_DB_URL)..."

if [ -z "${PKINTEL_DB_URL:-}" ]; then
  ENV_FILE="${PROJECT_ROOT}/.env"
  if [ -f "$ENV_FILE" ]; then
    log_info "Loading PKINTEL_DB_URL from $ENV_FILE..."
    # Extract PKINTEL_DB_URL ignoring comments and whitespace
    PKINTEL_DB_URL=$(grep -E '^PKINTEL_DB_URL=' "$ENV_FILE" | cut -d '=' -f 2- | tr -d '"' | tr -d "'" || true)
  fi
fi

if [ -z "${PKINTEL_DB_URL:-}" ]; then
  log_error "PKINTEL_DB_URL environment variable is not set and could not be found in ${PROJECT_ROOT}/.env."
  log_error "Usage: PKINTEL_DB_URL='postgresql://user:pass@host/dbname' ./deploy/export-neon-db.sh"
  exit 1
fi

log_ok "Database URL configured."

# Check for pg_dump utility
if ! command -v pg_dump &>/dev/null; then
  log_error "'pg_dump' utility not found. Please install PostgreSQL client tools (e.g. brew install postgresql@16)."
  exit 1
fi

# ------------------------------------------------------------------------------
# SECTION 2: Export Database Dump
# ------------------------------------------------------------------------------
log_info "2/3 Exporting database schema and data from Neon..."
log_info "Destination: $OUTPUT_FILE"

pg_dump \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  --dbname="$PKINTEL_DB_URL" \
  --file="$OUTPUT_FILE"

if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
  DUMP_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
  log_ok "Database successfully exported to $OUTPUT_FILE ($DUMP_SIZE)."
else
  log_error "Database dump failed or produced an empty file."
  exit 1
fi

# ------------------------------------------------------------------------------
# SECTION 3: Instructions for EliteDesk Transfer & Import
# ------------------------------------------------------------------------------
echo "=============================================================================="
echo -e "${GREEN}               Database Export Completed Successfully!                       ${NC}"
echo "=============================================================================="
echo "Follow these steps to transfer and import the dump onto the HP EliteDesk:"
echo ""
echo "1. Transfer dump file to EliteDesk:"
echo "   scp ${OUTPUT_FILE} outpost@<elitedesk-ip>:/opt/heapleap/deploy/outpost_dump.sql"
echo ""
echo "2. SSH into EliteDesk:"
echo "   ssh outpost@<elitedesk-ip>"
echo ""
echo "3. Import database dump into local PostgreSQL instance:"
echo "   PGPASSWORD=outpost psql -h localhost -U outpost -d outpost -f /opt/heapleap/deploy/outpost_dump.sql"
echo ""
echo "4. Verify tables & seed data on EliteDesk:"
echo "   PGPASSWORD=outpost psql -h localhost -U outpost -d outpost -c '\\dt'"
echo "=============================================================================="
