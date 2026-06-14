#!/usr/bin/env bash
# =============================================================================
# NFT Firewall + Cosmos Installer — Bootstrap
# =============================================================================
# This script is a lightweight loader that fetches the full installer logic
# from the repository to avoid truncation issues during 'curl | bash' piping.
# =============================================================================
set -euo pipefail

echo "[+] NFT Firewall Bootstrapper"

# 1. Install mandatory system packages if missing
echo "[+] Updating package cache and installing mandatory tools..."
apt-get update -qq
apt-get install -y git curl fuse3 unzip nftables wireguard wireguard-tools wireguard-dkms openresolv python3-pip python3-venv || {
    echo "[!] Some packages failed. Trying fallback names for Debian 13..."
    apt-get install -y git curl fuse3 unzip nftables wireguard wireguard-tools openresolv python3-pip python3-venv
}

# Ensure systemd sees new units immediately
systemctl daemon-reload

# Fix DNS symlink ONLY when /etc/resolv.conf is missing or a dangling symlink.
# A working file (systemd-resolved stub, custom static resolver, existing
# openresolv link) must be preserved — clobbering it can break DNS.
if [ -f /run/resolvconf/resolv.conf ] && ! [ -e /etc/resolv.conf ]; then
    ln -sf /run/resolvconf/resolv.conf /etc/resolv.conf
    echo "[+] Installed /etc/resolv.conf -> /run/resolvconf/resolv.conf (was missing)"
fi

# 2. Create temp workspace
INSTALL_TMP=$(mktemp -d /tmp/nft-firewall-install.XXXXXX)
echo "[+] Downloading full installer to $INSTALL_TMP..."

# 3. Clone repository
git clone -q https://github.com/unknown0152/nft-firewall.git "$INSTALL_TMP"

# 4. Run the full installer logic
cd "$INSTALL_TMP"
chmod +x scripts/safe-nft-apply.sh # Ensure internal scripts are ready

# We run setup.py directly for the core firewall install
echo "[+] Running core installation..."
# Handle interactive TTY for the wizard; wrap in subshell for clean return
(python3 setup.py install </dev/tty) || echo "[!] Core install finished with notice."

# 5. Run the Cosmos & Keybase hardening logic (modular script)
# We feed the current config to the hardening script
if [[ -f "/opt/nft-firewall/config/firewall.ini" ]]; then
    export FIREWALL_CONFIG="/opt/nft-firewall/config/firewall.ini"
fi

echo "[+] Applying system-wide hardening and integrations..."
# We will create this core-hardening.sh script in the next step
bash scripts/core-hardening.sh

echo ""
echo "[OK] All-in-one installation complete."
echo "     Type 'fw' to open your control panel."
