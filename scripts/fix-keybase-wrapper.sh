#!/bin/bash
set -euo pipefail

log() { printf '[+] %s\n' "$*"; }
ok()  { printf '[ok] %s\n' "$*"; }
warn(){ printf '[!] %s\n' "$*" >&2; }
die() { printf '[error] %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run as root"

command -v python3 >/dev/null || die "python3 is required"
command -v getent >/dev/null || die "getent is required"

detect_keybase_user() {
  python3 - <<'PY'
import configparser
from pathlib import Path

for path in (
    Path("/opt/nft-firewall/config/firewall.ini"),
    Path("/etc/nft-firewall/firewall.ini"),
    Path("/etc/nft-watchdog.conf"),
):
    cfg = configparser.ConfigParser()
    try:
        cfg.read(path)
    except Exception:
        continue
    user = cfg.get("keybase", "linux_user", fallback="").strip()
    if user:
        print(user)
        raise SystemExit(0)
PY
}

detect_keybase_user_from_home() {
  local found=()
  local home user
  for home in /home/* /root; do
    [[ -d "$home/.config/keybase" ]] || continue
    user="$(stat -c '%U' "$home" 2>/dev/null || true)"
    [[ -n "$user" && "$user" != UNKNOWN ]] || continue
    if [[ -S "$home/.config/keybase/keybased.sock" || -f "$home/.config/keybase/config.json" || -n "$(compgen -G "$home/.config/keybase/secretkeys.*.mpack" 2>/dev/null || true)" ]]; then
      found+=("$user")
    fi
  done

  if [[ "${#found[@]}" -eq 1 ]]; then
    printf '%s\n' "${found[0]}"
  fi
}

keybase_user="${NFT_FIREWALL_KEYBASE_USER:-}"
if [[ -z "$keybase_user" ]]; then
  keybase_user="$(detect_keybase_user || true)"
fi
if [[ -z "$keybase_user" ]]; then
  keybase_user="$(detect_keybase_user_from_home || true)"
fi

[[ -n "$keybase_user" ]] || die "could not detect Keybase Linux user; rerun with NFT_FIREWALL_KEYBASE_USER=<user>"
getent passwd "$keybase_user" >/dev/null || die "Keybase Linux user does not exist: $keybase_user"

system_user="${NFT_FIREWALL_SYSTEM_USER:-}"
if [[ -z "$system_user" ]]; then
  if getent passwd fw-admin >/dev/null; then
    system_user="fw-admin"
  elif getent passwd nft-firewall >/dev/null; then
    system_user="nft-firewall"
  fi
fi

log "Installing Keybase wrapper for linux_user=$keybase_user"

wrapper="/usr/local/bin/nft-keybase-notify"
tmp_wrapper="$(mktemp /tmp/nft-keybase-notify.XXXXXX)"
cat >"$tmp_wrapper" <<'WRAPPER'
#!/bin/bash
set -euo pipefail

default_kb_user="__NFT_DEFAULT_KB_USER__"

config_kb_user="$(/usr/bin/python3 - <<'PY' 2>/dev/null || true
import configparser
from pathlib import Path

for path in (
    Path("/opt/nft-firewall/config/firewall.ini"),
    Path("/etc/nft-firewall/firewall.ini"),
    Path("/etc/nft-watchdog.conf"),
):
    cfg = configparser.ConfigParser()
    try:
        cfg.read(path)
    except Exception:
        continue
    user = cfg.get("keybase", "linux_user", fallback="").strip()
    if user:
        print(user)
        break
PY
)"

detect_home_kb_user() {
  local found=()
  local home user
  for home in /home/* /root; do
    [[ -d "$home/.config/keybase" ]] || continue
    user="$(stat -c '%U' "$home" 2>/dev/null || true)"
    [[ -n "$user" && "$user" != UNKNOWN ]] || continue
    if [[ -S "$home/.config/keybase/keybased.sock" || -f "$home/.config/keybase/config.json" || -n "$(compgen -G "$home/.config/keybase/secretkeys.*.mpack" 2>/dev/null || true)" ]]; then
      found+=("$user")
    fi
  done
  if [[ "${#found[@]}" -eq 1 ]]; then
    printf '%s\n' "${found[0]}"
  fi
}

kb_user="${NFT_FIREWALL_KEYBASE_USER:-${config_kb_user:-$default_kb_user}}"
if [[ -z "$kb_user" ]]; then
  kb_user="$(detect_home_kb_user || true)"
fi

if [[ -z "$kb_user" ]]; then
  echo "Keybase linux_user is not configured" >&2
  exit 1
fi

if ! getent passwd "$kb_user" >/dev/null; then
  echo "Keybase linux_user does not exist: $kb_user" >&2
  exit 1
fi

runuser_bin="/usr/sbin/runuser"
if [[ ! -x "$runuser_bin" ]]; then
  runuser_bin="$(command -v runuser || true)"
fi
if [[ -z "$runuser_bin" ]]; then
  echo "runuser command not found" >&2
  exit 1
fi

kb_uid="$(id -u "$kb_user")"
kb_home="$(getent passwd "$kb_user" | cut -d: -f6)"

export HOME="$kb_home"
export USER="$kb_user"
export LOGNAME="$kb_user"
export SHELL="/bin/bash"
export XDG_RUNTIME_DIR="/run/user/$kb_uid"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$kb_uid/bus"
export PATH="/usr/local/bin:/usr/bin:/bin"

cd "$HOME" 2>/dev/null || true
exec "$runuser_bin" -u "$kb_user" -- env \
  HOME="$HOME" \
  USER="$USER" \
  LOGNAME="$LOGNAME" \
  SHELL="$SHELL" \
  XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
  DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
  PATH="$PATH" \
  /usr/bin/keybase "$@"
WRAPPER

python3 - "$tmp_wrapper" "$keybase_user" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
user = sys.argv[2]
path.write_text(path.read_text().replace("__NFT_DEFAULT_KB_USER__", user))
PY

install -m 0755 "$tmp_wrapper" "$wrapper"
rm -f "$tmp_wrapper"
ok "Installed $wrapper"

if [[ -n "$system_user" ]]; then
  log "Installing sudoers drop-in for $system_user"
  sudoers_tmp="$(mktemp /tmp/nft-firewall-keybase-fix.XXXXXX)"
  sudoers_file="/etc/sudoers.d/nft-firewall-keybase-fix"
  cat >"$sudoers_tmp" <<EOF
# nft-firewall one-off Keybase wrapper repair
Defaults:${system_user} !requiretty
${system_user} ALL=(root) NOPASSWD: /usr/local/bin/nft-keybase-notify
EOF
  visudo --check --file "$sudoers_tmp" >/dev/null
  install -m 0440 "$sudoers_tmp" "$sudoers_file"
  rm -f "$sudoers_tmp"
  ok "Installed $sudoers_file"
else
  warn "Could not detect fw-admin/nft-firewall system user; wrapper installed, sudoers unchanged"
fi

if ! command -v keybase >/dev/null; then
  warn "keybase command is not installed; install/login Keybase before testing notifications"
  exit 0
fi

log "Testing direct wrapper identity"
if "$wrapper" whoami; then
  ok "Wrapper can see the logged-in Keybase account"
else
  warn "Wrapper still cannot see a logged-in Keybase account"
  warn "Try: sudo -iu $keybase_user run_keybase -g && sudo -iu $keybase_user keybase login"
  exit 1
fi

if [[ -n "$system_user" ]] && command -v sudo >/dev/null; then
  log "Testing sudoers path as $system_user"
  if sudo -u "$system_user" sudo -n "$wrapper" whoami; then
    ok "fw-admin sudo path can invoke Keybase wrapper"
  else
    warn "sudoers path failed; inspect /etc/sudoers.d/nft-firewall-keybase-fix"
    exit 1
  fi
fi

ok "Repair complete. Now run: fw keybase-test"
