#!/usr/bin/env bash
# =============================================================================
# scripts/uninstall.sh — NFT Firewall + Cosmos/Keybase Uninstaller
# =============================================================================
# Removes everything setup.py + core-hardening.sh installed, leaving the box
# in a state where the bootstrap one-liner can run fresh against it.
#
# Preserved (intentionally):
#   - System packages (nftables, wireguard, docker, keybase, etc.)
#   - /etc/wireguard/*.conf (your VPN keys live here)
#   - The user running sudo (n100, nuc, etc.)
#   - Keybase package and local account data unless --with-keybase is used
#
# Removed:
#   - /opt/nft-firewall, /opt/cosmos
#   - /var/lib/nft-firewall, /var/lib/cosmos, /var/log/nft-firewall
#   - /etc/nft-firewall, /etc/nft-watchdog.conf, /etc/sudoers.d/nft-firewall
#   - /etc/systemd/system/nft-*, /etc/systemd/system/CosmosCloud*
#   - /usr/local/bin/{fw,fix-cosmos-perms,nft-keybase-notify}
#   - /usr/local/lib/nft-firewall (sudo wrappers)
#   - Users: fw-admin, media, backup, deploy
#   - Live nftables ruleset (replaced with stock Debian default)
#
# Usage:
#   sudo bash uninstall.sh                       # interactive — prompts to confirm
#   sudo bash uninstall.sh --yes                 # scripted nft-firewall reinstall
#   sudo bash uninstall.sh --with-keybase        # also purge Keybase package/state
#   sudo bash uninstall.sh --keybase-only        # only purge Keybase package/state
# =============================================================================
set -uo pipefail   # -e intentionally omitted: keep going past missing pieces

# ── Safety: must be root, must not be one of the system users we delete ──────

if [[ $EUID -ne 0 ]]; then
    echo "[FATAL] Must run as root: sudo bash $0" >&2
    exit 1
fi

if [[ "${SUDO_USER:-root}" =~ ^(fw-admin|media|backup|deploy)$ ]]; then
    echo "[FATAL] Refusing to run as $SUDO_USER — that user is about to be deleted." >&2
    exit 1
fi

# ── Confirmation gate ────────────────────────────────────────────────────────

ASSUME_YES=0
REMOVE_KEYBASE=0
KEYBASE_ONLY=0
for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=1 ;;
        --with-keybase|--purge-keybase|--keybase)
            REMOVE_KEYBASE=1
            ;;
        --keybase-only)
            REMOVE_KEYBASE=1
            KEYBASE_ONLY=1
            ;;
        -h|--help)
            sed -n '2,36p' "$0"
            exit 0
            ;;
        *)
            echo "[FATAL] Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

detect_keybase_user() {
    if [[ -n "${NFT_FIREWALL_KEYBASE_USER:-}" ]]; then
        printf '%s\n' "$NFT_FIREWALL_KEYBASE_USER"
        return
    fi
    python3 - <<'PY' 2>/dev/null
import configparser
from pathlib import Path

for path in (
    Path("/opt/nft-firewall/config/firewall.ini"),
    Path("/etc/nft-firewall/firewall.ini"),
):
    if not path.exists():
        continue
    cfg = configparser.ConfigParser()
    cfg.read(path)
    user = cfg.get("keybase", "linux_user", fallback="").strip()
    if user:
        print(user)
        break
PY
}

remove_keybase() {
    echo ""
    echo "[keybase] Removing Keybase package and local state ..."
    local kb_user="${NFT_FIREWALL_KEYBASE_USER:-}"
    if [[ -z "$kb_user" ]]; then
        kb_user="$(detect_keybase_user || true)"
    fi

    if [[ -n "$kb_user" ]] && id "$kb_user" &>/dev/null; then
        local kb_uid kb_home
        kb_uid="$(id -u "$kb_user")"
        kb_home="$(getent passwd "$kb_user" | cut -d: -f6)"
        echo "  Keybase Linux user: $kb_user"
        if [[ -d "$kb_home/.config/keybase/kbfs" ]]; then
            fusermount3 -u "$kb_home/.config/keybase/kbfs" 2>/dev/null || \
                fusermount -u "$kb_home/.config/keybase/kbfs" 2>/dev/null || true
        fi
        pkill -u "$kb_user" -f 'keybase|kbfs' 2>/dev/null || true
        sleep 1
        rm -rf "$kb_home/.config/keybase"
        rm -rf "$kb_home/.cache/keybase"
        rm -rf "$kb_home/.local/share/keybase"
        rm -rf "/run/user/$kb_uid/keybase"
        rm -f  "/tmp/nft-firewall-keybase-run.log"
    else
        echo "  Keybase Linux user not detected; set NFT_FIREWALL_KEYBASE_USER=<user> if needed."
    fi

    rm -f /usr/local/bin/nft-keybase-notify
    rm -f /etc/sudoers.d/nft-firewall-keybase-fix

    if dpkg-query -W -f='${Status}' keybase 2>/dev/null | grep -q "install ok installed"; then
        apt-get purge -y keybase
    else
        echo "  Keybase package is not installed."
    fi
    rm -f /etc/apt/sources.list.d/keybase.list
}

if [[ $KEYBASE_ONLY -eq 1 ]]; then
    cat <<'KEYBASEONLYWARN'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Keybase-only UNINSTALLER

  This will purge the Keybase package and remove the configured user's
  local Keybase state under:
    ~/.config/keybase
    ~/.cache/keybase
    ~/.local/share/keybase

  PRESERVED:
    nft-firewall, Cosmos, WireGuard config, Docker, and nftables rules
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KEYBASEONLYWARN
else
    cat <<'WARN'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NFT Firewall + Cosmos UNINSTALLER

  This will remove ALL of the following:
    /opt/nft-firewall, /opt/cosmos
    /var/lib/nft-firewall, /var/lib/cosmos, /var/log/nft-firewall
    /etc/nft-firewall, /etc/nft-watchdog.conf, /etc/sudoers.d/nft-firewall
    /etc/systemd/system/nft-*  +  CosmosCloud*
    /usr/local/bin/fw, fix-cosmos-perms, nft-keybase-notify
    /usr/local/lib/nft-firewall
    System users: fw-admin, media, backup, deploy
    Live nftables ruleset (replaced with stock default)

  PRESERVED:
    /etc/wireguard/*.conf  (your VPN keys)
    System packages (nftables, wireguard, docker, keybase, ...)
    Your login user
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WARN
fi

if [[ $REMOVE_KEYBASE -eq 1 && $KEYBASE_ONLY -eq 0 ]]; then
    cat <<'KEYBASEWARN'
  EXTRA KEYBASE REMOVAL ENABLED:
    This also purges the Keybase package and removes the configured user's
    local Keybase state under ~/.config/keybase, ~/.cache/keybase, and
    ~/.local/share/keybase.

KEYBASEWARN
fi

if [[ $ASSUME_YES -ne 1 ]]; then
    expected="wipe"
    if [[ $REMOVE_KEYBASE -eq 1 ]]; then
        expected="wipe-keybase"
    fi
    read -r -p "Type '$expected' to proceed: " ans
    if [[ "$ans" != "$expected" ]]; then
        echo "Aborted."
        exit 1
    fi
fi

if [[ $KEYBASE_ONLY -eq 1 ]]; then
    remove_keybase
    echo ""
    echo "Keybase-only uninstall complete."
    exit 0
fi

# ── 1. Stop and disable services + timers ───────────────────────────────────

echo ""
echo "[1/6] Stopping services ..."
for svc in nft-watchdog nft-listener nft-knockd nft-ssh-alert nft-metrics \
           nft-daily-report nft-firewall-doctor nft-firewall-threatfeed \
           nft-threat-update CosmosCloud wg-quick@wg0; do
    systemctl stop    "$svc.service" 2>/dev/null
    systemctl stop    "$svc.timer"   2>/dev/null
    systemctl disable "$svc.service" 2>/dev/null
    systemctl disable "$svc.timer"   2>/dev/null
done

# ── 2. Remove systemd unit files and drop-ins ───────────────────────────────

echo "[2/6] Removing systemd unit files ..."
rm -f  /etc/systemd/system/nft-*.service
rm -f  /etc/systemd/system/nft-*.timer
rm -f  /etc/systemd/system/CosmosCloud.service
rm -rf /etc/systemd/system/CosmosCloud.service.d
systemctl daemon-reload
systemctl reset-failed 2>/dev/null

# ── 3. Reset nftables (live + persistent) ───────────────────────────────────

echo "[3/6] Flushing nftables and restoring stock default ..."
nft flush ruleset 2>/dev/null
cat > /etc/nftables.conf <<'NFTSTOCK'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input   { type filter hook input   priority 0; }
    chain forward { type filter hook forward priority 0; }
    chain output  { type filter hook output  priority 0; }
}
NFTSTOCK
chmod 0755 /etc/nftables.conf

# ── 4. Remove installed code/state/config ───────────────────────────────────

echo "[4/6] Removing installed files ..."
rm -rf /opt/nft-firewall
rm -rf /opt/cosmos
rm -rf /var/lib/nft-firewall
rm -rf /var/log/nft-firewall
rm -rf /etc/nft-firewall
rm -rf /var/lib/cosmos
rm -f  /etc/nft-watchdog.conf
rm -f  /etc/sudoers.d/nft-firewall
rm -f  /usr/local/bin/fw
rm -f  /usr/local/bin/fix-cosmos-perms
rm -f  /usr/local/bin/nft-keybase-notify
rm -f  /etc/sudoers.d/nft-firewall-keybase-fix
rm -rf /usr/local/lib/nft-firewall

if [[ $REMOVE_KEYBASE -eq 1 ]]; then
    remove_keybase
fi

# ── 5. Remove users created by setup ────────────────────────────────────────

echo "[5/6] Removing system users (fw-admin, media, backup, deploy) ..."
for u in fw-admin media backup deploy; do
    if id "$u" &>/dev/null; then
        pkill -u "$u" 2>/dev/null
    fi
done
sleep 1
for u in fw-admin media backup deploy; do
    if id "$u" &>/dev/null; then
        userdel -r "$u" 2>/dev/null
    fi
done
for g in fw-admin media; do
    if getent group "$g" &>/dev/null; then
        groupdel "$g" 2>/dev/null
    fi
done

# ── 6. Verification ─────────────────────────────────────────────────────────

echo "[6/6] Verifying clean state ..."
echo ""

LEFTOVERS=0

for d in /opt/nft-firewall /opt/cosmos /var/lib/nft-firewall /var/lib/cosmos \
         /var/log/nft-firewall /etc/nft-firewall /usr/local/lib/nft-firewall; do
    if [[ -e "$d" ]]; then
        echo "  WARN: leftover path: $d"
        (( LEFTOVERS++ ))
    fi
done

for f in /etc/sudoers.d/nft-firewall /etc/nft-watchdog.conf \
         /etc/sudoers.d/nft-firewall-keybase-fix \
         /usr/local/bin/fw /usr/local/bin/fix-cosmos-perms \
         /usr/local/bin/nft-keybase-notify; do
    if [[ -e "$f" ]]; then
        echo "  WARN: leftover file: $f"
        (( LEFTOVERS++ ))
    fi
done

for u in fw-admin media backup deploy; do
    if id "$u" &>/dev/null; then
        echo "  WARN: user still exists: $u"
        (( LEFTOVERS++ ))
    fi
done

leftover_units=()
for unit_path in /etc/systemd/system/nft-* /etc/systemd/system/CosmosCloud*; do
    [[ -e "$unit_path" ]] || continue
    leftover_units+=("${unit_path##*/}")
done
if ((${#leftover_units[@]} > 0)); then
    echo "  WARN: leftover unit files:"
    printf '    %s\n' "${leftover_units[@]}"
    (( LEFTOVERS++ ))
fi

echo ""
if (( LEFTOVERS == 0 )); then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Uninstall complete — system is clean."
    echo "  /etc/wireguard/ left untouched (your VPN keys are safe)."
    if [[ $REMOVE_KEYBASE -eq 0 ]]; then
        echo "  Keybase package/account data left untouched."
    else
        echo "  Keybase package/account data removed."
    fi
    echo ""
    echo "  Reinstall with the bootstrap one-liner:"
    echo "    curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 0
else
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Uninstall finished with $LEFTOVERS leftover(s) — see warnings above."
    echo "  Investigate manually before reinstalling."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 2
fi
