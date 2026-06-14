#!/usr/bin/env bash
set -euo pipefail

RULESET="${1:-}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/nft-firewall}"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/ruleset-before-$TS.nft"

if [ -z "$RULESET" ]; then
  echo "Usage: $0 /path/to/ruleset.nft" >&2
  exit 2
fi

if [ ! -f "$RULESET" ]; then
  echo "FAIL: ruleset not found: $RULESET" >&2
  exit 1
fi

sudo mkdir -p "$BACKUP_DIR"

echo "Backing up current nft ruleset to $BACKUP_FILE"
sudo nft list ruleset | sudo tee "$BACKUP_FILE" >/dev/null

echo "Checking new ruleset..."
sudo nft --check -f "$RULESET"

echo "Applying new ruleset..."
sudo nft -f "$RULESET"

echo "OK: ruleset applied."
echo "Backup: $BACKUP_FILE"
