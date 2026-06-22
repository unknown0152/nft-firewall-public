#!/usr/bin/env bash
# Thin curl-friendly installer entrypoint.
# Clones the public repository once and runs setup.sh from that checkout.
set -euo pipefail

BRANCH="${NFT_FIREWALL_BRANCH:-main}"
REPO_URL="${NFT_FIREWALL_REPO_URL:-https://github.com/unknown0152/nft-firewall-public.git}"
REF="${NFT_FIREWALL_REF:-$BRANCH}"
LOG_DIR="${NFT_FIREWALL_INSTALL_LOG_DIR:-/var/log/nft-firewall}"
LOG_FILE="${NFT_FIREWALL_INSTALL_LOG:-}"

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

if [[ "${NFT_FIREWALL_DEBUG:-0}" == "1" ]]; then
  export PS4='+ ${0##*/}:${LINENO}: '
  set -x
fi

if ! command -v git >/dev/null 2>&1; then
  echo "[+] Installing git for repository checkout..."
  apt-get update -qq
  apt-get install -y git
fi

tmp="$(mktemp -d /tmp/nft-firewall-install.XXXXXX)"
git_err="$(mktemp /tmp/nft-firewall-git.XXXXXX.err)"
cleanup() {
  rm -rf "$tmp"
  rm -f "$git_err"
}
trap cleanup EXIT

echo "[+] Cloning nft-firewall installer..."
echo "[+] Repository: $REPO_URL"
echo "[+] Ref: $REF"
if ! git clone -q --depth 1 --branch "$REF" "$REPO_URL" "$tmp" 2>"$git_err"; then
  echo "[!] Shallow branch/tag clone failed; trying generic checkout..."
  cat "$git_err" >&2 || true
  rm -rf "$tmp"
  tmp="$(mktemp -d /tmp/nft-firewall-install.XXXXXX)"
  git clone -q "$REPO_URL" "$tmp"
  git -C "$tmp" fetch -q --depth 1 origin "$REF" || true
  git -C "$tmp" checkout -q "$REF" 2>/dev/null || git -C "$tmp" checkout -q FETCH_HEAD
fi

echo "[+] Checked out commit: $(git -C "$tmp" rev-parse --short HEAD)"

cd "$tmp"
NFT_FIREWALL_SOURCE_DIR="$tmp" bash ./setup.sh "$@"
