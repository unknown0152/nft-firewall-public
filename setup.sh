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
ENABLE_WEBUI=0
RUN_VALIDATE=1
RUN_SAFE_APPLY=0
PROFILE=""
MODE_SELECTED=0
ADVANCED_SELECTED=0
UPDATE_ONLY=0

while [[ "$#" -gt 0 ]]; do
    arg="$1"
    case "$arg" in
        --update|--upgrade)
            MODE_SELECTED=1
            UPDATE_ONLY=1
            RUN_INTEGRATIONS=0
            INSTALL_DOCKER=0
            INSTALL_KEYBASE=0
            KEYBASE_LOGIN=0
            ENABLE_WEBUI=0
            ;;
        --core)
            # Explicit core-only mode. This is also the default.
            MODE_SELECTED=1
            ;;
        --cosmos|--media|--media-server)
            MODE_SELECTED=1
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            ENABLE_WEBUI=1
            ;;
        --full)
            MODE_SELECTED=1
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            INSTALL_KEYBASE=1
            ENABLE_WEBUI=1
            ;;
        --full-login|--with-all)
            MODE_SELECTED=1
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            INSTALL_KEYBASE=1
            KEYBASE_LOGIN=1
            ENABLE_WEBUI=1
            ;;
        --with-integrations|--with-cosmos-keybase)
            ADVANCED_SELECTED=1
            RUN_INTEGRATIONS=1
            ;;
        --with-docker)
            ADVANCED_SELECTED=1
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            ;;
        --with-keybase)
            ADVANCED_SELECTED=1
            RUN_INTEGRATIONS=1
            INSTALL_KEYBASE=1
            ;;
        --with-keybase-login)
            ADVANCED_SELECTED=1
            RUN_INTEGRATIONS=1
            INSTALL_KEYBASE=1
            KEYBASE_LOGIN=1
            ;;
        --with-webui)
            ADVANCED_SELECTED=1
            ENABLE_WEBUI=1
            ;;
        --validate)
            RUN_VALIDATE=1
            ;;
        --no-validate)
            RUN_VALIDATE=0
            ;;
        --safe-apply|--apply)
            RUN_VALIDATE=1
            RUN_SAFE_APPLY=1
            ;;
        --profile)
            shift || {
                echo "[FATAL] --profile requires a value" >&2
                exit 2
            }
            PROFILE="$1"
            ;;
        --profile=*)
            PROFILE="${arg#--profile=}"
            ;;
        -h|--help)
            cat <<'USAGE'
Usage:
  sudo bash setup.sh [mode] [options]

Default behavior:
  With no mode flags and a TTY, this opens a guided installer.
  In non-interactive shells, it falls back to --core.

Simple modes:
  --update      update existing nft-firewall install; no config wizard
  --core        core firewall only (default)
  --cosmos      core + Cosmos/media hardening + Docker + web dashboard
  --media       alias for --cosmos
  --full        core + Cosmos/Docker/web dashboard + Keybase package
  --full-login  same as --full, then launch interactive Keybase login

Validation:
  --validate    run fw doctor + fw simulate after install (default)
  --no-validate skip post-install validation
  --safe-apply  after validation, run fw safe-apply interactively
  --profile X   profile used for validation/safe-apply (auto-detected by default)

Advanced compatibility flags:
  --with-integrations  configure optional Cosmos/Keybase integration
  --with-docker        also install Docker Engine for Cosmos app management
  --with-keybase       also install the Keybase Linux package
  --with-keybase-login install Keybase and launch interactive login as the Keybase Linux user
  --with-webui         enable local read-only dashboard on 127.0.0.1:8787

Examples:
  curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash -s -- --update
  curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash -s -- --cosmos
  curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash -s -- --full-login
USAGE
            exit 0
            ;;
        *)
            echo "[FATAL] Unknown option: $arg" >&2
            exit 2
            ;;
    esac
    shift
done

echo "[+] NFT Firewall Bootstrapper"

configure_mode() {
    local mode="$1"
    RUN_INTEGRATIONS=0
    INSTALL_DOCKER=0
    INSTALL_KEYBASE=0
    KEYBASE_LOGIN=0
    ENABLE_WEBUI=0

    case "$mode" in
        core)
            ;;
        cosmos)
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            ENABLE_WEBUI=1
            ;;
        full)
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            INSTALL_KEYBASE=1
            ENABLE_WEBUI=1
            ;;
        full-login)
            RUN_INTEGRATIONS=1
            INSTALL_DOCKER=1
            INSTALL_KEYBASE=1
            KEYBASE_LOGIN=1
            ENABLE_WEBUI=1
            ;;
    esac
}

guided_install_mode() {
    if [[ "$MODE_SELECTED" -ne 0 || "$ADVANCED_SELECTED" -ne 0 || ! -r /dev/tty ]]; then
        return 0
    fi

    echo ""
    if [[ -d /opt/nft-firewall && -f /opt/nft-firewall/config/firewall.ini ]]; then
        echo "Existing nft-firewall install detected."
        echo "  1) Update only (code, wrappers, units, restart, validate)"
        echo "  2) Re-run guided install"
        echo ""
        printf "Choose [1-2, default 1]: " > /dev/tty
        read -r existing_choice < /dev/tty || existing_choice=""
        existing_choice="${existing_choice:-1}"
        if [[ "$existing_choice" != "2" ]]; then
            UPDATE_ONLY=1
            RUN_INTEGRATIONS=0
            INSTALL_DOCKER=0
            INSTALL_KEYBASE=0
            KEYBASE_LOGIN=0
            ENABLE_WEBUI=0
            return
        fi
    fi

    echo "Choose install type:"
    echo "  1) Core firewall only"
    echo "  2) Cosmos/media server (Docker + dashboard)"
    echo "  3) Full server (Cosmos + Docker + dashboard + Keybase package)"
    echo "  4) Full server + interactive Keybase login"
    echo ""

    local choice=""
    while true; do
        printf "Install type [1-4, default 2]: " > /dev/tty
        read -r choice < /dev/tty || choice=""
        choice="${choice:-2}"
        case "$choice" in
            1) configure_mode core; break ;;
            2) configure_mode cosmos; break ;;
            3) configure_mode full; break ;;
            4) configure_mode full-login; break ;;
            *) echo "Please enter 1, 2, 3, or 4." > /dev/tty ;;
        esac
    done

    printf "Run safe-apply after validation? Type yes to enable [no]: " > /dev/tty
    read -r apply_choice < /dev/tty || apply_choice=""
    case "${apply_choice,,}" in
        yes|y)
            RUN_SAFE_APPLY=1
            RUN_VALIDATE=1
            ;;
    esac
}

guided_install_mode
echo "[+] Mode: update=$UPDATE_ONLY integrations=$RUN_INTEGRATIONS docker=$INSTALL_DOCKER keybase=$INSTALL_KEYBASE keybase_login=$KEYBASE_LOGIN webui=$ENABLE_WEBUI validate=$RUN_VALIDATE safe_apply=$RUN_SAFE_APPLY"

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
if [[ "$UPDATE_ONLY" -eq 1 ]]; then
    echo "[+] Running update-only installation..."
else
    echo "[+] Running core installation..."
fi
# Handle interactive TTY for the wizard. A core installer failure must stop the
# bootstrapper before any optional integrations are attempted.
if [[ "$UPDATE_ONLY" -eq 1 ]]; then
    python3 setup.py install
elif [[ -r /dev/tty ]]; then
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

if [[ "$ENABLE_WEBUI" -eq 1 ]]; then
    echo "[+] Enabling read-only local web dashboard..."
    systemctl daemon-reload
    systemctl enable --now nft-webui.service
    echo "    Local URL: http://127.0.0.1:8787"
    echo "    Put Cosmos Cloud in front of this local URL and require Cosmos login."
fi

detect_profile() {
    if [[ -n "$PROFILE" ]]; then
        printf '%s\n' "$PROFILE"
        return
    fi
    python3 - <<'PY'
import configparser
from pathlib import Path

cfg = configparser.ConfigParser()
for path in (Path("/opt/nft-firewall/config/firewall.ini"), Path("/etc/nft-firewall/firewall.ini")):
    if path.exists():
        cfg.read(path)
        break
print(cfg.get("install", "profile", fallback="cosmos-vpn-secure").strip() or "cosmos-vpn-secure")
PY
}

if [[ "$RUN_VALIDATE" -eq 1 ]] && command -v fw >/dev/null 2>&1; then
    PROF="$(detect_profile)"
    VALIDATION_OK=1
    echo ""
    echo "[+] Post-install validation for profile: $PROF"
    if fw doctor "$PROF"; then
        echo "[ok] fw doctor passed"
    else
        echo "[!] fw doctor reported issues; inspect output above before applying rules"
        VALIDATION_OK=0
    fi

    if fw simulate "$PROF"; then
        echo "[ok] fw simulate passed"
    else
        echo "[!] fw simulate failed; do not apply rules until fixed"
        VALIDATION_OK=0
    fi

    if [[ "$RUN_SAFE_APPLY" -eq 1 && "$VALIDATION_OK" -eq 1 ]]; then
        echo "[+] Running interactive safe-apply for profile: $PROF"
        fw safe-apply "$PROF"
    elif [[ "$RUN_SAFE_APPLY" -eq 1 ]]; then
        echo "[!] Skipping safe-apply because validation did not pass cleanly"
    else
        echo "[+] To apply rules interactively later: sudo fw safe-apply $PROF"
    fi
elif [[ "$RUN_VALIDATE" -eq 1 ]]; then
    echo "[!] fw command not found; skipping post-install validation"
fi

echo ""
echo "[OK] All-in-one installation complete."
echo "     Type 'fw' to open your control panel."
