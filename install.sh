#!/usr/bin/env bash
# Thin curl-friendly installer entrypoint.
# Downloads and runs setup.sh from the public repository.
set -euo pipefail

BRANCH="${NFT_FIREWALL_BRANCH:-main}"
SETUP_URL="${NFT_FIREWALL_SETUP_URL:-https://raw.githubusercontent.com/unknown0152/nft-firewall-public/${BRANCH}/setup.sh}"

if ! command -v curl >/dev/null 2>&1; then
  echo "[FATAL] curl is required to fetch setup.sh" >&2
  exit 1
fi

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
