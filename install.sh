#!/usr/bin/env bash
# Thin curl-friendly installer entrypoint.
# Downloads and runs setup.sh from the public repository.
set -euo pipefail

BRANCH="${NFT_FIREWALL_BRANCH:-main}"
SETUP_URL="${NFT_FIREWALL_SETUP_URL:-https://raw.githubusercontent.com/unknown0152/nft-firewall-public/${BRANCH}/setup.sh}"
LOG_DIR="${NFT_FIREWALL_INSTALL_LOG_DIR:-/var/log/nft-firewall}"
LOG_FILE="${NFT_FIREWALL_INSTALL_LOG:-}"

if ! command -v curl >/dev/null 2>&1; then
  echo "[FATAL] curl is required to fetch setup.sh" >&2
  exit 1
fi

if [[ -z "$LOG_FILE" ]]; then
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  if mkdir -p "$LOG_DIR" 2>/dev/null; then
    LOG_FILE="$LOG_DIR/install-$ts.log"
  else
    LOG_FILE="/tmp/nft-firewall-install-$ts.log"
  fi
else
  mkdir -p "$(dirname "$LOG_FILE")"
fi

touch "$LOG_FILE"
chmod 0600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[+] Install log: $LOG_FILE"

tmp="$(mktemp /tmp/nft-firewall-setup.XXXXXX.sh)"
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

echo "[+] Fetching nft-firewall setup script..."
echo "[+] URL: $SETUP_URL"
curl -fsSL "$SETUP_URL" -o "$tmp"
chmod +x "$tmp"

bash "$tmp" "$@"
