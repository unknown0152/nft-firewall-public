#!/usr/bin/env bash
# =============================================================================
# scripts/core-hardening.sh — Secondary Installer Logic
# =============================================================================
# Handles Cosmos Cloud and Keybase installation/hardening.
# =============================================================================
set -euo pipefail

if [[ "${NFT_FIREWALL_DEBUG:-0}" == "1" ]]; then
  export PS4='+ ${0##*/}:${LINENO}: '
  set -x
fi

MEDIA_USER="media"
MEDIA_HOME="/home/media"
COSMOS_CONFIG_DIR="/srv/cosmos/config"
COSMOS_CONFIG_FILE="$COSMOS_CONFIG_DIR/cosmos.config.json"
COSMOS_STORAGE_DIR="/srv/cosmos-storage"
APP_CONFIG_DIR="/srv/config"
MEDIA_LIBRARY_DIR="/srv/media"
BACKUP_DIR="/srv/backups"
DOCKER_DATA_DIR="/srv/docker"
CONTAINER_UIDS="${NFT_FIREWALL_CONTAINER_UIDS:-1000 1001}"
CONTAINER_GIDS="${NFT_FIREWALL_CONTAINER_GIDS:-1000 1001}"
INSTALL_DOCKER="${NFT_FIREWALL_INSTALL_DOCKER:-0}"
INSTALL_KEYBASE="${NFT_FIREWALL_INSTALL_KEYBASE:-0}"
KEYBASE_LOGIN="${NFT_FIREWALL_KEYBASE_LOGIN:-0}"
NFT_COSMOS_INSTALLER_FLAGS="${NFT_COSMOS_INSTALLER_FLAGS:-${COSMOS_INSTALLER_FLAGS:---no-docker --no-dep}}"
unset COSMOS_INSTALLER_FLAGS

ensure_dir() {
  local path="$1" owner="$2" mode="$3"
  mkdir -p "$path"
  chown "$owner" "$path"
  chmod "$mode" "$path"
}

ensure_package_command() {
  local command_name="$1" package_name="$2"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y "$package_name" >/dev/null
  fi
}

append_unique_id() {
  local var_name="$1" value="$2" existing
  [[ "$value" =~ ^[0-9]+$ ]] || return 0
  for existing in ${!var_name}; do
    [[ "$existing" == "$value" ]] && return 0
  done
  printf -v "$var_name" '%s %s' "${!var_name}" "$value"
}

add_user_spec_ids() {
  local user_spec="$1"
  [[ -n "$user_spec" ]] || return 0

  local uid="${user_spec%%:*}"
  local gid=""
  [[ "$user_spec" == *:* ]] && gid="${user_spec#*:}"

  append_unique_id CONTAINER_UIDS "$uid"
  append_unique_id CONTAINER_GIDS "$gid"
}

discover_container_permission_ids() {
  local path uid gid line

  while IFS= read -r path; do
    [[ -e "$path" ]] || continue
    uid="$(stat -c %u "$path" 2>/dev/null || true)"
    gid="$(stat -c %g "$path" 2>/dev/null || true)"
    append_unique_id CONTAINER_UIDS "$uid"
    append_unique_id CONTAINER_GIDS "$gid"
  done < <(find "$APP_CONFIG_DIR" "$MEDIA_LIBRARY_DIR" -mindepth 1 -maxdepth 2 -type d 2>/dev/null || true)

  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  local containers=()
  mapfile -t containers < <(docker ps -aq 2>/dev/null || true)
  [[ "${#containers[@]}" -gt 0 ]] || return 0

  while IFS= read -r line; do
    case "$line" in
      PUID=*) append_unique_id CONTAINER_UIDS "${line#PUID=}" ;;
      PGID=*) append_unique_id CONTAINER_GIDS "${line#PGID=}" ;;
    esac
  done < <(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${containers[@]}" 2>/dev/null || true)

  while IFS= read -r line; do
    add_user_spec_ids "$line"
  done < <(docker inspect --format '{{.Config.User}}' "${containers[@]}" 2>/dev/null || true)
}

discover_cosmos_bind_dirs() {
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  local containers=()
  mapfile -t containers < <(docker ps -aq 2>/dev/null || true)
  [[ "${#containers[@]}" -gt 0 ]] || return 0

  local source
  while IFS= read -r source; do
    case "$source" in
      "$APP_CONFIG_DIR"/*|"$MEDIA_LIBRARY_DIR"/*)
        mkdir -p "$source"
        ;;
    esac
  done < <(docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "${containers[@]}" 2>/dev/null || true)
}

apply_container_acl() {
  local path="$1"
  [[ -d "$path" ]] || return 0

  if ! command -v setfacl >/dev/null 2>&1; then
    echo "[+] Installing acl for container bind-mount permissions..."
    apt-get update -qq && apt-get install -y acl >/dev/null
  fi

  local acl_args=()
  local uid gid
  for uid in $CONTAINER_UIDS; do
    acl_args+=("-m" "u:${uid}:rwx" "-m" "d:u:${uid}:rwx")
  done
  for gid in $CONTAINER_GIDS; do
    acl_args+=("-m" "g:${gid}:rwx" "-m" "d:g:${gid}:rwx")
  done

  setfacl -R "${acl_args[@]}" "$path"
}

repair_media_stack_permissions() {
  echo "[+] Repairing media-stack bind-mount permissions..."

  local app_dirs=(
    "$APP_CONFIG_DIR/danish-intelligence"
    "$APP_CONFIG_DIR/prowlarr"
    "$APP_CONFIG_DIR/radarr"
    "$APP_CONFIG_DIR/sonarr"
    "$APP_CONFIG_DIR/radarr-2160p"
    "$APP_CONFIG_DIR/sonarr-2160p"
    "$APP_CONFIG_DIR/seerr"
    "$APP_CONFIG_DIR/altmount"
    "$APP_CONFIG_DIR/plex"
    "$APP_CONFIG_DIR/jellyfin"
  )

  local dir
  for dir in "${app_dirs[@]}"; do
    mkdir -p "$dir"
  done
  discover_cosmos_bind_dirs
  discover_container_permission_ids
  echo "[+] Container ACL users: $CONTAINER_UIDS"
  echo "[+] Container ACL groups: $CONTAINER_GIDS"

  chown -R "$MEDIA_USER:$MEDIA_USER" "$APP_CONFIG_DIR" "$MEDIA_LIBRARY_DIR"
  chmod -R u+rwX,g+rwX "$APP_CONFIG_DIR" "$MEDIA_LIBRARY_DIR"
  find "$APP_CONFIG_DIR" "$MEDIA_LIBRARY_DIR" -type d -exec chmod 2775 {} +

  apply_container_acl "$APP_CONFIG_DIR"
  apply_container_acl "$MEDIA_LIBRARY_DIR"

  chown "$MEDIA_USER:$MEDIA_USER" "$BACKUP_DIR"
  chmod 0750 "$BACKUP_DIR"
}

write_docker_daemon_json() {
  echo "[+] Ensuring Docker firewall authority is disabled..."
  mkdir -p /etc/docker
  DAEMON_JSON="$(python3 - /etc/docker/daemon.json <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    current = json.loads(path.read_text()) if path.exists() else {}
except json.JSONDecodeError as exc:
    raise SystemExit(f"invalid JSON in {path}: {exc}")

required = {
    "data-root": "/srv/docker",
    "iptables": False,
    "ip6tables": False,
    "log-driver": "json-file",
}
log_opts = dict(current.get("log-opts", {})) if isinstance(current.get("log-opts"), dict) else {}
log_opts.update({"max-size": "100m", "max-file": "5"})

merged = dict(current)
merged.update(required)
merged["log-opts"] = log_opts

print(json.dumps(merged, indent=2, sort_keys=True))
PY
)"

  if [[ ! -f /etc/docker/daemon.json ]] || [[ "$(cat /etc/docker/daemon.json)" != "$DAEMON_JSON" ]]; then
    if [[ -f /etc/docker/daemon.json ]]; then
      cp /etc/docker/daemon.json "/etc/docker/daemon.json.nft-firewall.bak.$(date +%Y%m%d%H%M%S)"
    fi
    printf '%s\n' "$DAEMON_JSON" > /etc/docker/daemon.json
    if systemctl list-unit-files docker.service >/dev/null 2>&1; then
      systemctl restart docker || echo "[!] Docker restart failed (non-fatal)"
    fi
  fi
}

install_docker_engine() {
  if [[ "$INSTALL_DOCKER" != "1" ]]; then
    return
  fi

  echo "[+] Installing Docker Engine for Cosmos app management..."
  ensure_dir "$DOCKER_DATA_DIR" root:root 0710
  write_docker_daemon_json

  ensure_package_command ca-certificates ca-certificates
  ensure_package_command curl curl
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -s /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  fi
  chmod a+r /etc/apt/keyrings/docker.asc

  # shellcheck disable=SC1091
  . /etc/os-release
  codename="${VERSION_CODENAME:-trixie}"
  arch="$(dpkg --print-architecture)"
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian %s stable\n' \
    "$arch" "$codename" > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

install_keybase_package() {
  if command -v keybase >/dev/null 2>&1; then
    echo "[ok] Keybase already present"
    return
  fi

  if [[ "$INSTALL_KEYBASE" != "1" ]]; then
    echo "[!] Keybase missing. Re-run with --with-keybase to install ChatOps support."
    return
  fi

  echo "[+] Installing Keybase Linux package..."
  tmp_dir="$(mktemp -d /tmp/keybase-install.XXXXXX)"
  trap 'rm -rf "$tmp_dir"' RETURN
  curl -fsSL https://prerelease.keybase.io/keybase_amd64.deb -o "$tmp_dir/keybase_amd64.deb"
  apt-get update -qq
  apt-get install -y "$tmp_dir/keybase_amd64.deb"
  rm -rf "$tmp_dir"
  trap - RETURN
  echo "[!] Keybase installed. Log in as the configured Linux user, not root."
  echo "    Example: sudo -iu <linux_user> run_keybase -g && sudo -iu <linux_user> keybase login"
}

detect_keybase_linux_user() {
  python3 - <<'PY'
import configparser
import os
import pwd
from pathlib import Path

cfg = configparser.ConfigParser()
cfg.read("/opt/nft-firewall/config/firewall.ini")
explicit = cfg.get("keybase", "linux_user", fallback="").strip()
if explicit:
    print(explicit)
    raise SystemExit

sudo_user = os.environ.get("SUDO_USER", "").strip()
if sudo_user and sudo_user != "root":
    print(sudo_user)
    raise SystemExit

for pw in pwd.getpwall():
    if pw.pw_uid >= 1000 and pw.pw_name != "nobody" and Path(pw.pw_dir).is_dir():
        print(pw.pw_name)
        raise SystemExit
PY
}

maybe_run_keybase_login() {
  if ! command -v keybase >/dev/null 2>&1; then
    return
  fi

  kb_user="$(detect_keybase_linux_user || true)"
  if [[ -z "$kb_user" ]] || ! id "$kb_user" >/dev/null 2>&1; then
    echo "[!] Keybase installed, but no usable Linux user was detected."
    echo "    Re-run setup.py --reconfigure and set [keybase] linux_user."
    return
  fi

  echo "[+] Keybase Linux user: $kb_user"
  whoami_out="$(sudo -iu "$kb_user" keybase whoami 2>/dev/null || true)"
  if [[ -n "$whoami_out" ]]; then
    echo "[ok] Keybase already logged in as $whoami_out"
    return
  fi

  echo "[+] Starting Keybase headless for $kb_user..."
  sudo -iu "$kb_user" sh -c 'run_keybase -g >/tmp/nft-firewall-keybase-run.log 2>&1' || true
  sleep 2
  whoami_out="$(sudo -iu "$kb_user" keybase whoami 2>/dev/null || true)"
  if [[ -n "$whoami_out" ]]; then
    echo "[ok] Keybase logged in as $whoami_out"
    return
  fi

  if [[ "$KEYBASE_LOGIN" == "1" && -r /dev/tty ]]; then
    echo "[+] Launching interactive Keybase login for $kb_user..."
    sudo -iu "$kb_user" sh -c 'keybase login </dev/tty'
    whoami_out="$(sudo -iu "$kb_user" keybase whoami 2>/dev/null || true)"
    if [[ -n "$whoami_out" ]]; then
      echo "[ok] Keybase logged in as $whoami_out"
      return
    fi
    echo "[!] Keybase login finished, but keybase whoami is still empty."
    return
  fi

  echo "[!] Keybase is installed but not logged in."
  echo "    Run:"
  echo "      sudo -iu $kb_user run_keybase -g"
  echo "      sudo -iu $kb_user keybase login"
  echo "    Then re-run setup.py --reconfigure if [keybase] was left blank."
}

keybase_config_ready() {
  python3 - <<'PY'
import configparser

cfg = configparser.ConfigParser()
cfg.read("/opt/nft-firewall/config/firewall.ini")
linux_user = cfg.get("keybase", "linux_user", fallback="").strip()
target_user = cfg.get("keybase", "target_user", fallback="").strip()
team = cfg.get("keybase", "team", fallback="").strip()
if linux_user and target_user and (team or target_user):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

enable_keybase_units_if_ready() {
  if ! command -v keybase >/dev/null 2>&1; then
    return
  fi
  if ! keybase_config_ready; then
    echo "[!] Keybase config incomplete; nft-listener and daily report timer not enabled."
    return
  fi

  kb_user="$(detect_keybase_linux_user || true)"
  if [[ -z "$kb_user" ]] || [[ -z "$(sudo -iu "$kb_user" keybase whoami 2>/dev/null || true)" ]]; then
    echo "[!] Keybase is not logged in; nft-listener and daily report timer not enabled."
    return
  fi

  echo "[+] Enabling Keybase-backed nft-firewall units..."
  systemctl daemon-reload
  systemctl enable nft-listener.service nft-daily-report.timer >/dev/null
  systemctl restart nft-listener.service || echo "[!] nft-listener restart failed"
  systemctl restart nft-daily-report.timer || echo "[!] nft-daily-report.timer restart failed"
}

cosmos_installed() {
  # Require the systemd unit file specifically. The previous OR-with-start.sh
  # check produced false positives when /opt/cosmos held leftover binaries
  # from an earlier failed/partial install — the real installer was skipped
  # and no CosmosCloud.service ever got registered.
  [[ -s /etc/systemd/system/CosmosCloud.service ]]
}

echo "[+] Hardening Cosmos Cloud..."

install_docker_engine

if cosmos_installed; then
  echo "[+] Cosmos already installed — skipping full installer, applying security patches only"
else
  echo "[+] Downloading Cosmos installer..."
  COSMOS_INSTALLER="$(mktemp /tmp/cosmos-get.XXXXXX.sh)"
  ensure_package_command curl curl
  ensure_package_command unzip unzip
  curl -sfL https://cosmos-cloud.io/get.sh -o "$COSMOS_INSTALLER"
  chmod +x "$COSMOS_INSTALLER"

  echo "[+] Patching Cosmos installer to skip iptables..."
  sed -i 's/^check_ports$/print_status "Skipping Cosmos iptables; nft-firewall controls firewall policy."/g' "$COSMOS_INSTALLER"
  
  echo "[+] Running Cosmos standalone installer ($NFT_COSMOS_INSTALLER_FLAGS)..."
  export COSMOS_CONFIG_FOLDER="$COSMOS_CONFIG_DIR/"
  export NO_DOCKER=1
  # shellcheck disable=SC2086
  bash "$COSMOS_INSTALLER" $NFT_COSMOS_INSTALLER_FLAGS
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

# 2. Least-privilege media/Cosmos user and /srv layout
if id "$MEDIA_USER" >/dev/null 2>&1; then
  usermod --shell /usr/sbin/nologin "$MEDIA_USER" || true
else
  useradd --create-home --home-dir "$MEDIA_HOME" --shell /usr/sbin/nologin "$MEDIA_USER"
fi
if getent group docker >/dev/null 2>&1; then
  usermod -aG docker "$MEDIA_USER" || true
  COSMOS_SUPPLEMENTARY_GROUPS="SupplementaryGroups=docker"
else
  echo "[!] Docker group missing. Re-run with --with-docker before using Cosmos to manage containers."
  COSMOS_SUPPLEMENTARY_GROUPS=""
fi

ensure_dir "/srv/cosmos" "$MEDIA_USER:$MEDIA_USER" 0750
ensure_dir "$COSMOS_CONFIG_DIR" "$MEDIA_USER:$MEDIA_USER" 0750
ensure_dir "$COSMOS_STORAGE_DIR" "$MEDIA_USER:$MEDIA_USER" 0750
ensure_dir "$APP_CONFIG_DIR" "$MEDIA_USER:$MEDIA_USER" 2775
ensure_dir "$MEDIA_LIBRARY_DIR" "$MEDIA_USER:$MEDIA_USER" 2775
ensure_dir "$BACKUP_DIR" "$MEDIA_USER:$MEDIA_USER" 0750
if getent group docker >/dev/null 2>&1; then
  ensure_dir "$DOCKER_DATA_DIR" root:docker 0710
else
  ensure_dir "$DOCKER_DATA_DIR" root:root 0710
fi
repair_media_stack_permissions

if [[ -f "$COSMOS_CONFIG_FILE" ]]; then
  python3 - "$COSMOS_CONFIG_FILE" "$COSMOS_STORAGE_DIR" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
default_data_path = sys.argv[2]
config = json.loads(path.read_text())
docker_config = config.setdefault("DockerConfig", {})
if docker_config.get("DefaultDataPath") != default_data_path:
    docker_config["DefaultDataPath"] = default_data_path
    path.write_text(json.dumps(config, indent=2))
PY
  chown "$MEDIA_USER:$MEDIA_USER" "$COSMOS_CONFIG_FILE"
else
  echo "[i] $COSMOS_CONFIG_FILE not found yet; Cosmos will create it on first startup."
  echo "    Re-run this integration after first setup to enforce DefaultDataPath=$COSMOS_STORAGE_DIR."
fi

# 3. Permissions wrapper
# Runs from the systemd ExecStartPre with the `+` prefix (i.e. as root) so it
# can keep /srv and /opt/cosmos ownership sane before
# the launcher tries to chmod its binaries.
cat > /usr/local/bin/fix-cosmos-perms <<'EOF'
#!/usr/bin/env bash
set -e
APP_CONFIG_DIR="/srv/config"
MEDIA_LIBRARY_DIR="/srv/media"
CONTAINER_UIDS="${NFT_FIREWALL_CONTAINER_UIDS:-1000 1001}"
CONTAINER_GIDS="${NFT_FIREWALL_CONTAINER_GIDS:-1000 1001}"

append_unique_id() {
  local var_name="$1" value="$2" existing
  [[ "$value" =~ ^[0-9]+$ ]] || return 0
  for existing in ${!var_name}; do
    [[ "$existing" == "$value" ]] && return 0
  done
  printf -v "$var_name" '%s %s' "${!var_name}" "$value"
}

add_user_spec_ids() {
  local user_spec="$1"
  [[ -n "$user_spec" ]] || return 0

  local uid="${user_spec%%:*}"
  local gid=""
  [[ "$user_spec" == *:* ]] && gid="${user_spec#*:}"

  append_unique_id CONTAINER_UIDS "$uid"
  append_unique_id CONTAINER_GIDS "$gid"
}

discover_container_permission_ids() {
  local path uid gid line

  while IFS= read -r path; do
    [[ -e "$path" ]] || continue
    uid="$(stat -c %u "$path" 2>/dev/null || true)"
    gid="$(stat -c %g "$path" 2>/dev/null || true)"
    append_unique_id CONTAINER_UIDS "$uid"
    append_unique_id CONTAINER_GIDS "$gid"
  done < <(find "$APP_CONFIG_DIR" "$MEDIA_LIBRARY_DIR" -mindepth 1 -maxdepth 2 -type d 2>/dev/null || true)

  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  local containers=()
  mapfile -t containers < <(docker ps -aq 2>/dev/null || true)
  [[ "${#containers[@]}" -gt 0 ]] || return 0

  while IFS= read -r line; do
    case "$line" in
      PUID=*) append_unique_id CONTAINER_UIDS "${line#PUID=}" ;;
      PGID=*) append_unique_id CONTAINER_GIDS "${line#PGID=}" ;;
    esac
  done < <(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${containers[@]}" 2>/dev/null || true)

  while IFS= read -r line; do
    add_user_spec_ids "$line"
  done < <(docker inspect --format '{{.Config.User}}' "${containers[@]}" 2>/dev/null || true)
}

discover_cosmos_bind_dirs() {
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  local containers=()
  mapfile -t containers < <(docker ps -aq 2>/dev/null || true)
  [[ "${#containers[@]}" -gt 0 ]] || return 0

  local source
  while IFS= read -r source; do
    case "$source" in
      "$APP_CONFIG_DIR"/*|"$MEDIA_LIBRARY_DIR"/*)
        mkdir -p "$source"
        ;;
    esac
  done < <(docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "${containers[@]}" 2>/dev/null || true)
}

apply_container_acl() {
  local path="$1"
  [[ -d "$path" ]] || return 0
  command -v setfacl >/dev/null 2>&1 || return 0

  local acl_args=()
  local uid gid
  for uid in $CONTAINER_UIDS; do
    acl_args+=("-m" "u:${uid}:rwx" "-m" "d:u:${uid}:rwx")
  done
  for gid in $CONTAINER_GIDS; do
    acl_args+=("-m" "g:${gid}:rwx" "-m" "d:g:${gid}:rwx")
  done

  setfacl -R "${acl_args[@]}" "$path"
}

mkdir -p /srv/cosmos/config /srv/cosmos-storage /srv/config /srv/media /srv/backups /srv/docker
chown media:media /srv/cosmos /srv/cosmos/config /srv/cosmos-storage /srv/config /srv/media /srv/backups
chown media:media /opt/cosmos
if getent group docker >/dev/null 2>&1; then
  chown root:docker /srv/docker
else
  chown root:root /srv/docker
fi
chmod 750 /srv/cosmos /srv/cosmos/config /srv/cosmos-storage /srv/backups
chmod 2775 /srv/config /srv/media
chmod 710 /srv/docker
chmod 755 /opt/cosmos
mkdir -p /srv/config/danish-intelligence /srv/config/prowlarr /srv/config/radarr /srv/config/sonarr /srv/config/radarr-2160p /srv/config/sonarr-2160p /srv/config/seerr /srv/config/altmount /srv/config/plex /srv/config/jellyfin
discover_cosmos_bind_dirs
discover_container_permission_ids
chown -R media:media /srv/config /srv/media
chmod -R u+rwX,g+rwX /srv/config /srv/media
find /srv/config /srv/media -type d -exec chmod 2775 {} +
apply_container_acl /srv/config
apply_container_acl /srv/media
EOF
chmod +x /usr/local/bin/fix-cosmos-perms

# 4. Systemd overrides
# `ExecStartPre=+` runs the helper as root regardless of User=, which is
# required because chown/mkdir under /var/lib are root-only operations. The
# main ExecStart still drops to media:media via User=/Group=.
mkdir -p /etc/systemd/system/CosmosCloud.service.d
cat > /etc/systemd/system/CosmosCloud.service.d/override.conf <<EOF
[Service]
User=media
Group=media
$COSMOS_SUPPLEMENTARY_GROUPS
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Environment=COSMOS_CONFIG_FOLDER=/srv/cosmos/config/
Environment=COSMOS_HTTP_PORT=80
Environment=COSMOS_HTTPS_PORT=443
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/srv/cosmos /srv/cosmos-storage /srv/config /srv/media /srv/backups /opt/cosmos
ReadOnlyPaths=/srv/docker
ExecStartPre=+/usr/local/bin/fix-cosmos-perms
EOF

# 5. Docker configuration
write_docker_daemon_json

# 6. NFTables activation
echo "[+] Activating nftables..."
systemctl enable --now nftables || echo "[!] nftables activation warning"
systemctl daemon-reload

if [[ -f /etc/systemd/system/CosmosCloud.service ]]; then
  echo "[+] Restarting CosmosCloud with new security profile..."
  systemctl restart CosmosCloud || echo "[!] CosmosCloud restart failed"
  if [[ -f "$COSMOS_CONFIG_FILE" ]]; then
    python3 - "$COSMOS_CONFIG_FILE" "$COSMOS_STORAGE_DIR" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
default_data_path = sys.argv[2]
config = json.loads(path.read_text())
docker_config = config.setdefault("DockerConfig", {})
if docker_config.get("DefaultDataPath") != default_data_path:
    docker_config["DefaultDataPath"] = default_data_path
    path.write_text(json.dumps(config, indent=2))
PY
    chown "$MEDIA_USER:$MEDIA_USER" "$COSMOS_CONFIG_FILE"
  fi
fi

# 7. Keybase Optional setup
echo "[+] Checking for Keybase ChatOps..."
install_keybase_package
maybe_run_keybase_login
enable_keybase_units_if_ready

# 8. Verification & Auto-Apply
echo ""
echo "[+] Finalizing verification..."
if [[ -f "/opt/nft-firewall/src/main.py" ]]; then
  PROF=$(grep "profile =" /opt/nft-firewall/config/firewall.ini | cut -d'=' -f2 | xargs || echo "cosmos-vpn-secure")
  echo "[+] Validating firewall rules for profile: $PROF..."

  if sudo PYTHONPATH=/opt/nft-firewall/src /usr/bin/python3 /opt/nft-firewall/src/main.py simulate "$PROF" >/dev/null; then
    echo "[+] Activating firewall rules for profile: $PROF..."
    # Run main.py directly to bypass wrapper restriction (bypass safe-mode for initial setup)
    if sudo PYTHONPATH=/opt/nft-firewall/src /usr/bin/python3 /opt/nft-firewall/src/main.py apply "$PROF"; then
      echo "[ok] Firewall rules applied successfully"
    else
      echo "[!] Firewall rules application failed"
    fi
  else
    echo "[!] Firewall rules validation failed; skipping automatic apply"
  fi
  
  # Check status via wrapper
  fw doctor "$PROF" || echo "[!] Doctor check returned issues"
fi
