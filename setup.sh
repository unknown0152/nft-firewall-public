#!/usr/bin/env bash
# =============================================================================
# NFT Firewall + Cosmos Installer — Bootstrap
# =============================================================================
# This script is a lightweight loader that fetches the full installer logic
# from the repository to avoid truncation issues during 'curl | bash' piping.
# =============================================================================
set -euo pipefail

if [[ "${NFT_FIREWALL_DEBUG:-0}" == "1" ]]; then
    export PS4='+ ${0##*/}:${LINENO}: '
    set -x
fi

RUN_INTEGRATIONS=0
INSTALL_DOCKER=0
INSTALL_KEYBASE=0
KEYBASE_LOGIN=0
for arg in "$@"; do
    case "$arg" in
        --with-integrations|--with-cosmos-keybase)
            RUN_INTEGRATIONS=1
            ;;
        --with-docker)
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            ;;
        --with-keybase)
            RUN_INTEGRATIONS=1
            INSTALL_KEYBASE=1
            ;;
        --with-keybase-login)
            RUN_INTEGRATIONS=1
            INSTALL_KEYBASE=1
            KEYBASE_LOGIN=1
            ;;
        -h|--help)
            cat <<'USAGE'
Usage: sudo bash setup.sh [--with-integrations] [--with-docker] [--with-keybase] [--with-keybase-login]

Installs the core nft-firewall project. Optional Cosmos/Keybase hardening is
skipped by default and only runs when --with-integrations is supplied.

  --with-integrations  configure optional Cosmos/Keybase integration
  --with-docker        also install Docker Engine for Cosmos app management
  --with-keybase       also install the Keybase Linux package
  --with-keybase-login install Keybase and launch interactive login as the Keybase Linux user
USAGE
            exit 0
            ;;
        *)
            echo "[FATAL] Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

echo "[+] NFT Firewall Bootstrapper"

# 1. Install mandatory system packages if missing
echo "[+] Updating package cache and installing mandatory tools..."
apt-get update -qq
apt-get install -y git curl fuse3 unzip nftables wireguard wireguard-tools python3-pip python3-venv || {
    echo "[!] Some packages failed. Trying fallback names for Debian 13..."
    apt-get install -y git curl fuse3 unzip nftables wireguard wireguard-tools python3-pip python3-venv
}

# Ensure systemd sees new units immediately
systemctl daemon-reload

# Fix DNS symlink ONLY when /etc/resolv.conf is missing or a dangling symlink.
# A working file (systemd-resolved stub or custom static resolver) must be
# preserved — clobbering it can break DNS.
if [ -f /run/resolvconf/resolv.conf ] && ! [ -e /etc/resolv.conf ]; then
    ln -sf /run/resolvconf/resolv.conf /etc/resolv.conf
    echo "[+] Installed /etc/resolv.conf -> /run/resolvconf/resolv.conf (was missing)"
fi

# 2. Create temp workspace
INSTALL_TMP=$(mktemp -d /tmp/nft-firewall-install.XXXXXX)
echo "[+] Downloading full installer to $INSTALL_TMP..."

# 3. Clone repository
REPO_URL="${NFT_FIREWALL_REPO_URL:-https://github.com/unknown0152/nft-firewall-public.git}"
echo "[+] Using repository: $REPO_URL"
git clone -q "$REPO_URL" "$INSTALL_TMP"

# 4. Run the full installer logic
cd "$INSTALL_TMP"
chmod +x scripts/safe-nft-apply.sh # Ensure internal scripts are ready

# We run setup.py directly for the core firewall install
echo "[+] Running core installation..."
# Handle interactive TTY for the wizard. A core installer failure must stop the
# bootstrapper before any optional integrations are attempted.
if [[ -r /dev/tty ]]; then
    python3 setup.py install </dev/tty
else
    python3 setup.py install
fi

# 5. Run the Cosmos & Keybase hardening logic (modular script)
# We feed the current config to the hardening script
if [[ -f "/opt/nft-firewall/config/firewall.ini" ]]; then
    export FIREWALL_CONFIG="/opt/nft-firewall/config/firewall.ini"
fi

if [[ "$RUN_INTEGRATIONS" -eq 1 ]]; then
    echo "[+] Applying optional Cosmos/Keybase hardening and integrations..."
    export NFT_FIREWALL_INSTALL_DOCKER="$INSTALL_DOCKER"
    export NFT_FIREWALL_INSTALL_KEYBASE="$INSTALL_KEYBASE"
    export NFT_FIREWALL_KEYBASE_LOGIN="$KEYBASE_LOGIN"
    bash scripts/core-hardening.sh
else
    echo "[+] Skipping optional Cosmos/Keybase hardening."
    echo "    Re-run with --with-integrations when Docker/Cosmos/Keybase setup is intended."
fi

echo ""
echo "[OK] All-in-one installation complete."
echo "     Type 'fw' to open your control panel."
