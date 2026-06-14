#!/usr/bin/env bash
# backup_firewall.sh — Archive the entire nft-firewall project folder.
#
# Creates:  ./backups/nft-firewall-YYYY-MM-DD_HHMMSS.tar.gz
# Usage:    bash backup_firewall.sh
#           bash backup_firewall.sh /path/to/custom/output/dir

set -euo pipefail

# Find project root relative to this script (scripts/backup_firewall.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE_DIR="${SOURCE_DIR:-${ROOT_DIR}}"
OUTPUT_DIR="${1:-${ROOT_DIR}/backups}"
TIMESTAMP="$(date +%Y-%m-%d_%H%M%S)"
ARCHIVE_NAME="nft-firewall-${TIMESTAMP}.tar.gz"
DEST="${OUTPUT_DIR}/${ARCHIVE_NAME}"

mkdir -p "${OUTPUT_DIR}"

echo "Backing up ${SOURCE_DIR} → ${DEST}"

tar -czf "${DEST}" \
    --exclude="${SOURCE_DIR}/.git" \
    --exclude="${SOURCE_DIR}/__pycache__" \
    --exclude="${SOURCE_DIR}/src/**/__pycache__" \
    --exclude="${SOURCE_DIR}/.backups" \
    --exclude="${SOURCE_DIR}/dist" \
    --exclude="${SOURCE_DIR}/state" \
    -C "$(dirname "${SOURCE_DIR}")" \
    "$(basename "${SOURCE_DIR}")"

SIZE="$(du -sh "${DEST}" | cut -f1)"
echo "Done. Archive: ${DEST} (${SIZE})"
