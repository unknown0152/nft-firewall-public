#!/usr/bin/env bash
# =============================================================================
# scripts/core-hardening.sh — Secondary Installer Logic
# =============================================================================
# Handles Cosmos Cloud and Keybase installation/hardening.
# =============================================================================
set -euo pipefail

cosmos_installed() {
  # Require the systemd unit file specifically. The previous OR-with-start.sh
  # check produced false positives when /opt/cosmos held leftover binaries
  # from an earlier failed/partial install — the real installer was skipped
  # and no CosmosCloud.service ever got registered.
  [[ -s /etc/systemd/system/CosmosCloud.service ]]
}

echo "[+] Hardening Cosmos Cloud..."

if cosmos_installed; then
  echo "[+] Cosmos already installed — skipping full installer, applying security patches only"
else
  echo "[+] Downloading Cosmos installer..."
  COSMOS_INSTALLER="$(mktemp /tmp/cosmos-get.XXXXXX.sh)"
  # Check for curl again just in case
  if ! command -v curl >/dev/null 2>&1; then
      apt-get update -qq && apt-get install -y curl >/dev/null
  fi
  curl -sfL https://cosmos-cloud.io/get.sh -o "$COSMOS_INSTALLER"
  chmod +x "$COSMOS_INSTALLER"

  echo "[+] Patching Cosmos installer to skip iptables..."
  # We prepend the override to the script so it is defined before any calls
  sed -i '1a check_ports() { echo "[+] Skipping Cosmos iptables; nft-firewall active."; }' "$COSMOS_INSTALLER"
  
  echo "[+] Running Cosmos installer (NO_DOCKER=1)..."
  export NO_DOCKER=1
  bash "$COSMOS_INSTALLER"
  echo "[ok] Cosmos installer finished"
fi

# 1. Fix start.sh pathing
if [[ -f /opt/cosmos/start.sh ]]; then
  echo "[+] Fixing Cosmos start.sh pathing..."
  cat > /opt/cosmos/start.sh <<'EOF'
#!/bin/bash
cd /opt/cosmos
# The fix-cosmos-perms script handles base permissions; 
# launcher handles internal binary permissions.
./cosmos-launcher && ./cosmos
EOF
  chmod +x /opt/cosmos/start.sh
fi

# 2. Least-privilege user
id media >/dev/null 2>&1 || useradd -m -s /bin/bash media
if getent group docker >/dev/null 2>&1; then
  usermod -aG docker media || true
fi

# 3. Permissions wrapper
# Runs from the systemd ExecStartPre with the `+` prefix (i.e. as root) so it
# can create /var/lib/cosmos and reassign /opt/cosmos to the media user before
# the launcher tries to chmod its binaries.
cat > /usr/local/bin/fix-cosmos-perms <<'EOF'
#!/usr/bin/env bash
set -e
mkdir -p /var/lib/cosmos
# Ensure the top-level directories are owned by media so it can write inside them
chown media:media /opt/cosmos /var/lib/cosmos
chmod 755 /opt/cosmos /var/lib/cosmos
EOF
chmod +x /usr/local/bin/fix-cosmos-perms

# 4. Systemd overrides
# `ExecStartPre=+` runs the helper as root regardless of User=, which is
# required because chown/mkdir under /var/lib are root-only operations. The
# main ExecStart still drops to media:media via User=/Group=.
mkdir -p /etc/systemd/system/CosmosCloud.service.d
cat > /etc/systemd/system/CosmosCloud.service.d/override.conf <<'EOF'
[Service]
User=media
Group=media
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStartPre=+/usr/local/bin/fix-cosmos-perms
EOF

# 5. Docker configuration
echo "[+] Ensuring Docker firewall authority is disabled..."
mkdir -p /etc/docker
if [[ ! -f /etc/docker/daemon.json ]]; then
  echo '{"iptables": false, "ip6tables": false}' > /etc/docker/daemon.json
  systemctl restart docker || echo "[!] Docker restart failed (non-fatal)"
fi

# 6. NFTables activation
echo "[+] Activating nftables..."
systemctl enable --now nftables || echo "[!] nftables activation warning"
systemctl daemon-reload

if [[ -f /etc/systemd/system/CosmosCloud.service ]]; then
  echo "[+] Restarting CosmosCloud with new security profile..."
  systemctl restart CosmosCloud || echo "[!] CosmosCloud restart failed"
fi

# 7. Keybase Optional setup
echo "[+] Checking for Keybase ChatOps..."
if ! command -v keybase >/dev/null 2>&1; then
  # Try to read install choice if running interactively
  if [[ -t 0 ]]; then
      read -r -p "  Would you like to install Keybase for ChatOps? [y/N]: " install_kb
      if [[ "$install_kb" =~ ^[Yy]$ ]]; then
        echo "[+] Downloading Keybase..."
        curl -sfL https://prerelease.keybase.io/keybase_amd64.deb -o keybase_amd64.deb
        echo "[+] Installing Keybase..."
        apt-get update -qq && apt-get install -y ./keybase_amd64.deb >/dev/null
        rm keybase_amd64.deb
        echo "[!] Keybase installed. IMPORTANT: Run 'keybase login' after this script."
      fi
  fi
else
  echo "[ok] Keybase already present"
fi

# 8. Verification & Auto-Apply
echo ""
echo "[+] Finalizing verification..."
if [[ -f "/opt/nft-firewall/src/main.py" ]]; then
  PROF=$(grep "profile =" /opt/nft-firewall/config/firewall.ini | cut -d'=' -f2 | xargs || echo "cosmos-vpn-secure")
  echo "[+] Activating firewall rules for profile: $PROF..."
  
  # Run main.py directly to bypass wrapper restriction (bypass safe-mode for initial setup)
  if sudo PYTHONPATH=/opt/nft-firewall/src /usr/bin/python3 /opt/nft-firewall/src/main.py apply "$PROF"; then
      echo "[ok] Firewall rules applied successfully"
  else
      echo "[!] Firewall rules application failed"
  fi
  
  # Check status via wrapper
  fw doctor "$PROF" || echo "[!] Doctor check returned issues"
fi
