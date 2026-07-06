#!/usr/bin/env python3
"""
setup.py — NFT Firewall System Installer.

Performs a privilege-separated installation of the nft-firewall suite under
a dedicated 'fw-admin' system account, completely isolated from personal
login accounts.

Usage
-----
    sudo python3 setup.py install    # full install or idempotent upgrade
    sudo python3 setup.py status     # show current installation state
    sudo python3 setup.py uninstall  # stop services and remove /opt/nft-firewall

The installer is idempotent: running 'install' twice is safe.

Security model
--------------
All daemons run as the 'fw-admin' system user (no login shell, no home
directory).  Privileged operations (nft, wg-quick, ip, conntrack, systemctl
for the VPN unit) are delegated through a minimal /etc/sudoers.d/nft-firewall
entry that grants exactly those commands — nothing more.  The personal user
account that owns Keybase is granted a single sudo permit so that fw-admin
can send chat notifications without holding the Keybase session itself.
"""

from __future__ import annotations

import argparse
import configparser
import grp
import ipaddress
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

# ── Layout ────────────────────────────────────────────────────────────────────

def _detect_admin_user() -> str:
    """Return the primary non-root user (SUDO_USER or first UID >= 1000)."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user

    for pw in pwd.getpwall():
        if pw.pw_uid >= 1000 and pw.pw_name != "nobody":
            return pw.pw_name
    return "admin"

SYSTEM_USER        = "fw-admin"
LEGACY_SYSTEM_USER = "nft-firewall"
ADMIN_USER         = _detect_admin_user()
MEDIA_USER         = "media"
BACKUP_USER        = "backup"
DEPLOY_USER        = "deploy"
INSTALL_DIR        = Path("/opt/nft-firewall")
LOG_DIR            = Path("/var/log/nft-firewall")
LIB_DIR            = Path("/var/lib/nft-firewall")
ETC_DIR            = Path("/etc/nft-firewall")
SYSTEM_HOME        = LIB_DIR
MEDIA_HOME         = Path("/home/media")
BACKUP_HOME        = Path("/home/backup")
DEPLOY_HOME        = Path("/home/deploy")
MEDIA_CONFIG_DIR   = Path("/srv/config")
COSMOS_CONFIG_DIR  = Path("/srv/cosmos/config")
COSMOS_STORAGE_DIR = Path("/srv/cosmos-storage")
COSMOS_COMPOSE_DIR = MEDIA_CONFIG_DIR / "cosmos"
SUDOERS_FILE       = Path("/etc/sudoers.d/nft-firewall")
SYSTEMD_DST        = Path("/etc/systemd/system")
SYSTEMD_SRC        = Path(__file__).resolve().parent / "systemd"
PYTHON_BIN         = "/usr/bin/python3"
FW_BIN             = Path("/usr/local/bin/fw")
WRAPPER_DIR        = Path("/usr/local/lib/nft-firewall")
KEYBASE_WRAPPER    = Path("/usr/local/bin/nft-keybase-notify")
FIREWALL_DIRS      = (INSTALL_DIR, LIB_DIR, LOG_DIR, ETC_DIR)

# Long-running daemons (restarted on every install)
ACTIVE_SERVICES = ["nft-watchdog", "nft-listener", "nft-ssh-alert"]
# Timer-driven units (enabled; systemd fires them on schedule)
TIMERS          = ["nft-daily-report"]


# ── Output helpers ────────────────────────────────────────────────────────────

def _ok(msg: str)   -> None: print(f"  \033[32m✓\033[0m  {msg}")
def _info(msg: str) -> None: print(f"  \033[34m→\033[0m  {msg}")
def _warn(msg: str) -> None: print(f"  \033[33m!\033[0m  {msg}", file=sys.stderr)

def _header(title: str) -> None:
    bar = "─" * max(4, 58 - len(title))
    print(f"\n\033[1m── {title} {bar}\033[0m")

def _die(msg: str) -> None:
    print(f"\n\033[31m[FATAL]\033[0m {msg}", file=sys.stderr)
    sys.exit(1)

def _run(cmd: List[str], check: bool = True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, **kw)


def _same_path(a: Path, b: Path) -> bool:
    """Return True when two paths refer to the same filesystem location."""
    try:
        return a.resolve() == b.resolve()
    except FileNotFoundError:
        return a.absolute() == b.absolute()


def _copytree_replace(src: Path, dst: Path, label: str) -> None:
    """Replace *dst* with a copy of *src*, unless source and destination match."""
    if _same_path(src, dst):
        _ok(f"{label} already in place at {dst} — skipping self-copy")
        return
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def _copy_file_replace(src: Path, dst: Path, label: str) -> None:
    """Copy *src* to *dst*, unless source and destination match."""
    if _same_path(src, dst):
        _ok(f"{label} already in place at {dst} — skipping self-copy")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _debug_log(msg: str) -> None:
    """Write a timestamped message to the debug log."""
    import datetime
    try:
        log_path = Path("/var/log/nft-firewall/debug.log")
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def _require_root() -> None:

    if os.geteuid() != 0:
        _die("Must run as root:  sudo python3 setup.py install")


REQUIRED_INSTALL_COMMANDS = (
    ("nft", "nftables"),
    ("systemctl", "systemd"),
    ("visudo", "sudo"),
    ("ip", "iproute2"),
    ("python3", "python3"),
)


def step0_0_validate_prerequisites() -> None:
    """Fail before persistent install side effects if required host tools are missing."""
    _header("Preflight — Installer prerequisites")

    missing = [
        (cmd, package)
        for cmd, package in REQUIRED_INSTALL_COMMANDS
        if shutil.which(cmd) is None
    ]
    if missing:
        lines = [
            "Missing required command(s):",
            *[f"  - {cmd}  (Debian package: {package})" for cmd, package in missing],
            "",
            "Install the missing package(s), then rerun:",
            "  sudo python3 setup.py install",
        ]
        _die("\n".join(lines))

    _ok("Required commands found: " + ", ".join(cmd for cmd, _ in REQUIRED_INSTALL_COMMANDS))


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def _ensure_group(name: str) -> None:
    if _group_exists(name):
        return
    r = _run(["groupadd", name], check=False)
    if r.returncode != 0:
        _die(f"groupadd {name} failed: {r.stderr.strip()}")
    _ok(f"Created group '{name}'")


def _user_in_group(user: str, group: str) -> bool:
    try:
        return user in grp.getgrnam(group).gr_mem
    except KeyError:
        return False


def _ensure_supplementary_group(user: str, group: str) -> None:
    if not _user_exists(user):
        _warn(f"User '{user}' not found — cannot add to group '{group}'")
        return
    _ensure_group(group)
    if _user_in_group(user, group):
        _ok(f"'{user}' is already in group '{group}'")
        return
    r = _run(["usermod", "--append", "--groups", group, user], check=False)
    if r.returncode != 0:
        _die(f"usermod -aG {group} {user} failed: {r.stderr.strip()}")
    _ok(f"Added '{user}' to group '{group}'")


def _user_has_processes(user: str) -> bool:
    r = _run(["pgrep", "-u", user], check=False)
    return r.returncode == 0


def _user_busy_message(stderr: str) -> bool:
    return "currently used by process" in stderr.lower()


def _remove_supplementary_group(user: str, group: str) -> None:
    if not _user_exists(user) or not _group_exists(group):
        return
    if not _user_in_group(user, group):
        return
    r = _run(["gpasswd", "--delete", user, group], check=False)
    if r.returncode == 0:
        _ok(f"Removed '{user}' from group '{group}'")
    else:
        _warn(f"Could not remove '{user}' from group '{group}': {r.stderr.strip()}")


def _ensure_user(name: str, *, system: bool, home: Optional[Path], shell: str) -> None:
    if _user_exists(name):
        pw = pwd.getpwnam(name)
        _ok(f"User '{name}' already exists (uid={pw.pw_uid}, shell={pw.pw_shell})")
        if home is not None and pw.pw_dir != str(home):
            if _user_has_processes(name):
                _info(f"'{name}' home is {pw.pw_dir}; leaving it unchanged while services are running")
            else:
                r = _run(["usermod", "--home", str(home), name], check=False)
                if r.returncode != 0:
                    detail = r.stderr.strip()
                    if _user_busy_message(detail):
                        _info(f"'{name}' home is {pw.pw_dir}; leaving it unchanged while services are running")
                    else:
                        _warn(f"Could not set home for '{name}' to {home}: {detail}")
                else:
                    _ok(f"Set '{name}' home to {home}")
        if shell and pw.pw_shell != shell:
            if _user_has_processes(name):
                _info(f"'{name}' shell is {pw.pw_shell}; leaving it unchanged while services are running")
            else:
                r = _run(["usermod", "--shell", shell, name], check=False)
                if r.returncode != 0:
                    detail = r.stderr.strip()
                    if _user_busy_message(detail):
                        _info(f"'{name}' shell is {pw.pw_shell}; leaving it unchanged while services are running")
                    else:
                        _warn(f"Could not set shell for '{name}' to {shell}: {detail}")
                else:
                    _ok(f"Set '{name}' shell to {shell}")
        return

    cmd = ["useradd", "--user-group", "--shell", shell]
    if system:
        cmd += ["--system", "--no-create-home"]
        if home is not None:
            cmd += ["--home-dir", str(home)]
    else:
        cmd += ["--create-home"]
        if home is not None:
            cmd += ["--home-dir", str(home)]
    cmd.append(name)

    _info(f"Creating user '{name}' ...")
    r = _run(cmd, check=False)
    if r.returncode != 0:
        _die(f"useradd {name} failed: {r.stderr.strip()}")
    _ok(f"Created user '{name}'")


def _migrate_legacy_system_user() -> None:
    """Rename a legacy nft-firewall runtime user to fw-admin when possible."""
    if not _user_exists(LEGACY_SYSTEM_USER):
        return
    if _user_exists(SYSTEM_USER):
        _warn(
            f"Legacy user '{LEGACY_SYSTEM_USER}' still exists; '{SYSTEM_USER}' is already present. "
            "It will not receive sudoers grants."
        )
        return

    _info(f"Migrating legacy runtime user '{LEGACY_SYSTEM_USER}' → '{SYSTEM_USER}' ...")
    r = _run(["usermod", "--login", SYSTEM_USER, LEGACY_SYSTEM_USER], check=False)
    if r.returncode != 0:
        _die(f"usermod --login {SYSTEM_USER} {LEGACY_SYSTEM_USER} failed: {r.stderr.strip()}")

    if _group_exists(LEGACY_SYSTEM_USER) and not _group_exists(SYSTEM_USER):
        r = _run(["groupmod", "--new-name", SYSTEM_USER, LEGACY_SYSTEM_USER], check=False)
        if r.returncode != 0:
            _die(f"groupmod --new-name {SYSTEM_USER} {LEGACY_SYSTEM_USER} failed: {r.stderr.strip()}")

    r = _run(["usermod", "--shell", "/bin/false", SYSTEM_USER], check=False)
    if r.returncode != 0:
        _warn(f"Could not reset shell for '{SYSTEM_USER}': {r.stderr.strip()}")
    _ok(f"Migrated '{LEGACY_SYSTEM_USER}' to '{SYSTEM_USER}'")


# ── Step 0: Interactive configuration wizard ──────────────────────────────────

_CONF_DIR  = Path(__file__).resolve().parent / "config"
_CONF_FILE = _CONF_DIR / "firewall.ini"


def _ask(label: str, default: str = "", hint: str = "") -> str:
    """Prompt for a value; pressing Enter accepts the default.

    Always reads from /dev/tty to support piped installation (curl | bash).
    """
    shown = default if default else hint
    suffix = f" \033[90m[{shown}]\033[0m" if shown else ""

    # Print the prompt manually since we are opening the tty
    print(f"  {label}{suffix}: ", end="", flush=True)

    try:
        with open("/dev/tty", "r") as tty:
            val = tty.readline().strip()
    except (KeyboardInterrupt, EOFError, OSError):
        # Fallback to standard input if /dev/tty is not available
        try:
            val = input().strip()
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(1)

    return val if val else default


def _ask_ports(label: str, default: str = "") -> str:
    """Prompt for a comma-separated list of ports; validate each entry."""
    while True:
        raw = _ask(label, default=default, hint=default or "leave blank to skip")
        if not raw:
            return ""
        parts = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
        bad = [p for p in parts if not (p.isdigit() and 1 <= int(p) <= 65535)]
        if bad:
            print(f"  \033[31m  Invalid port(s): {', '.join(bad)} — enter numbers 1-65535\033[0m")
            continue
        return ", ".join(parts)


def _detect_phy_if() -> str:
    """Heuristic: first non-loopback, non-virtual interface from `ip link`."""
    _skip = ("lo", "wg", "docker", "veth", "br-", "virbr", "tun", "tap", "dummy")
    r = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            name = parts[1].strip().split("@")[0]  # strip @ifname for veth
            if not any(name.startswith(p) for p in _skip):
                return name
    return ""


def _detect_vpn_if() -> str:
    """Return first wg* interface found in `ip link`, or first /etc/wireguard/*.conf stem."""
    r = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            name = parts[1].strip()
            if name.startswith("wg"):
                return name
    wg_dir = Path("/etc/wireguard")
    if wg_dir.exists():
        confs = sorted(wg_dir.glob("*.conf"))
        if confs:
            return confs[0].stem
    return "wg0"


def _detect_vpn_endpoint(vpn_if: str) -> Tuple[str, str]:
    """Parse ``Endpoint = host:port`` from /etc/wireguard/<iface>.conf."""
    conf = Path(f"/etc/wireguard/{vpn_if}.conf")
    if conf.exists():
        try:
            text = conf.read_text()
            m = re.search(r"^\s*Endpoint\s*=\s*([^:\s]+):(\d+)", text, re.MULTILINE)
            if m:
                return m.group(1), m.group(2)
        except PermissionError:
            pass
    return "", ""


def _detect_lan_net(phy_if: str) -> str:
    """Derive the LAN subnet from the physical interface's first IPv4 address."""
    if not phy_if:
        return ""
    r = subprocess.run(["ip", "-4", "addr", "show", phy_if], capture_output=True, text=True)
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", r.stdout)
    if m:
        try:
            return str(ipaddress.ip_interface(m.group(1)).network)
        except ValueError:
            pass
    return ""


def _detect_ssh_port() -> str:
    """Read the Port directive from /etc/ssh/sshd_config."""
    try:
        text = Path("/etc/ssh/sshd_config").read_text()
        m = re.search(r"^\s*Port\s+(\d+)", text, re.MULTILINE)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "22"


def _detect_keybase_linux_user() -> str:
    """Find a Linux user that has a Keybase config directory."""
    try:
        # Check primary admin user first
        admin_home = Path(f"/home/{ADMIN_USER}")
        if (admin_home / ".config" / "keybase").is_dir():
            return ADMIN_USER
            
        for home in sorted(Path("/home").iterdir()):
            if (home / ".config" / "keybase").is_dir():
                return home.name
    except Exception:
        pass
    return ""


def _write_firewall_ini(values: dict) -> None:
    """Write config/firewall.ini from a dict of section → {key: value}."""
    _CONF_DIR.mkdir(parents=True, exist_ok=True)
    cfg = configparser.ConfigParser()
    for section, kvs in values.items():
        cfg[section] = kvs
    with open(_CONF_FILE, "w") as fh:
        cfg.write(fh)


def step0_configure(reconfigure: bool = False) -> None:
    """Interactive wizard: detect defaults and ask the user to confirm/override.

    Writes ``config/firewall.ini``.  Skipped automatically on re-installs
    unless *reconfigure* is ``True``.
    """
    _header("Step 0 — Configure firewall.ini")

    if _CONF_FILE.exists() and not reconfigure:
        _ok(f"firewall.ini already exists — skipping  (use --reconfigure to redo)")
        return

    print("  Detected values are shown in \033[90m[brackets]\033[0m. "
          "Press Enter to accept, or type to override.\n")

    existing_cfg = configparser.ConfigParser()
    default_source = _CONF_FILE if _CONF_FILE.exists() else INSTALL_DIR / "config" / "firewall.ini"
    if default_source.exists():
        try:
            existing_cfg.read(str(default_source))
        except Exception:
            existing_cfg = configparser.ConfigParser()

    def _existing(section: str, option: str, default: str = "") -> str:
        return existing_cfg.get(section, option, fallback=default).strip()

    # ── Network ───────────────────────────────────────────────────────────────
    print("  \033[1mNetwork\033[0m")

    phy_if = _ask("Physical (WAN) interface",
                  default=_existing("network", "phy_if") or _detect_phy_if(),
                  hint="run `ip link show` to list interfaces")

    vpn_if = _ask("WireGuard interface",
                  default=_existing("network", "vpn_interface") or _detect_vpn_if())

    lan_net = _ask("LAN subnet (CIDR)",
                   default=_existing("network", "lan_net") or _detect_lan_net(phy_if),
                   hint="e.g. 192.168.1.0/24")

    detected_ip, detected_port = _detect_vpn_endpoint(vpn_if)
    vpn_ip   = _ask("VPN server IP / hostname",
                    default=_existing("network", "vpn_server_ip") or detected_ip)
    vpn_port = _ask("VPN server UDP port",
                    default=_existing("network", "vpn_server_port") or detected_port or "51820")

    ssh_port = _ask("SSH daemon port",
                    default=_existing("network", "ssh_port") or _detect_ssh_port())

    lan_full_access = _ask(
        "LAN full access (true/false)",
        default=_existing("network", "lan_full_access") or "false",
    ).lower()
    if lan_full_access not in {"true", "false", "yes", "no", "1", "0"}:
        _warn("LAN full access must be true/false — using false")
        lan_full_access = "false"
    lan_allow_ports = _ask_ports(
        "LAN allowed TCP ports when strict",
        default=_existing("network", "lan_allow_ports") or f"{ssh_port}, 32400",
    )
    lan_allow_udp_ports = _ask_ports(
        "LAN allowed UDP ports when strict",
        default=_existing("network", "lan_allow_udp_ports"),
    )

    # ── Open ports ────────────────────────────────────────────────────────────
    print()
    print("  \033[1mOpen ports on the VPN interface\033[0m")
    print("  (These are the ports reachable when connected to the VPN.)")

    extra_ports   = _ask_ports("Extra TCP ports (e.g. 8080, 443)",
                               default=_existing("network", "extra_ports"))
    torrent_port  = _ask_ports("BitTorrent port (TCP + UDP)",
                               default=_existing("network", "torrent_port"))
    # Validate torrent_port is a single port
    if torrent_port and "," in torrent_port:
        _warn("BitTorrent port must be a single port — using first value")
        torrent_port = torrent_port.split(",")[0].strip()

    # ── Keybase ───────────────────────────────────────────────────────────────
    print()
    print("  \033[1mKeybase ChatOps\033[0m")
    print("  (Leave blank to disable — you can add it to firewall.ini later.)")

    kb_linux_user  = _ask("Linux user running Keybase",
                          default=_existing("keybase", "linux_user") or _detect_keybase_linux_user())
    kb_team        = _ask("Keybase team name",    default=_existing("keybase", "team"))
    kb_channel     = _ask("Team channel",         default=_existing("keybase", "channel") or "general")
    kb_target_user = _ask("Your Keybase username  (REQUIRED — authorizes !commands)", default=_existing("keybase", "target_user"))

    # ── Firewall profile ──────────────────────────────────────────────────────
    print()
    print("  \033[1mFirewall profile\033[0m")
    firewall_profile = _ask("Firewall profile",
                            default=_existing("install", "profile") or "cosmos-vpn-secure",
                            hint="cosmos-vpn-secure")

    # ── Write ─────────────────────────────────────────────────────────────────
    print()

    network_section: dict = {
        "phy_if":          phy_if,
        "vpn_interface":   vpn_if,
        "lan_net":         lan_net,
        "vpn_server_ip":   vpn_ip,
        "vpn_server_port": vpn_port,
        "ssh_port":        ssh_port,
        "lan_full_access": lan_full_access,
    }
    if lan_allow_ports:
        network_section["lan_allow_ports"] = lan_allow_ports
    if lan_allow_udp_ports:
        network_section["lan_allow_udp_ports"] = lan_allow_udp_ports
    if extra_ports:
        network_section["extra_ports"] = extra_ports
    if torrent_port:
        network_section["torrent_port"] = torrent_port

    keybase_section: dict = {}
    keybase_enabled = any((kb_linux_user, kb_team, kb_target_user))
    if kb_linux_user:
        keybase_section["linux_user"] = kb_linux_user
    if kb_team:
        keybase_section["team"] = kb_team
    if keybase_enabled and kb_channel:
        keybase_section["channel"] = kb_channel
    if kb_target_user:
        keybase_section["target_user"] = kb_target_user

    sections: dict = {"network": network_section}
    if keybase_section:
        sections["keybase"] = keybase_section
    sections["install"] = {"profile": firewall_profile}

    _write_firewall_ini(sections)
    _ok(f"Written {_CONF_FILE}")

    # Summary
    print()
    print(f"    Interface  : {phy_if}  (VPN: {vpn_if})")
    print(f"    LAN        : {lan_net}")
    print(f"    VPN server : {vpn_ip}:{vpn_port}")
    print(f"    SSH port   : {ssh_port}")
    print(f"    LAN mode   : {'full access' if lan_full_access in {'true', 'yes', '1'} else 'strict'}")
    if lan_allow_ports:
        print(f"    LAN ports  : {lan_allow_ports}")
    if extra_ports:
        print(f"    Extra ports: {extra_ports}")
    if torrent_port:
        print(f"    Torrent    : {torrent_port}")
    if kb_team:
        print(f"    Keybase    : {kb_team}#{kb_channel}  (linux: {kb_linux_user})")


# ── Step 1: User model ────────────────────────────────────────────────────────

def step1_create_system_user() -> None:
    """Create and normalize the core nft-firewall runtime user."""
    _header("Step 1 — User Model")

    _migrate_legacy_system_user()
    _ensure_user(SYSTEM_USER, system=True, home=SYSTEM_HOME, shell="/bin/false")

    # 'adm' group membership lets fw-admin read /var/log/auth.log (ssh-alert)
    try:
        grp.getgrnam("adm")
        _ensure_supplementary_group(SYSTEM_USER, "adm")
    except KeyError:
        _warn("Group 'adm' not found — ssh-alert may not be able to read auth.log")

    _remove_supplementary_group(SYSTEM_USER, "docker")
    _ok(f"'{SYSTEM_USER}' is not granted Docker group access")


# ── Step 2: Install code ──────────────────────────────────────────────────────

def step2_install_code() -> None:
    """Sync src/ and config/ from the repo to /opt/nft-firewall/."""
    _header("Step 2 — Install Code to /opt/nft-firewall")

    project_root = Path(__file__).resolve().parent
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    src_dir = project_root / "src"
    if not src_dir.is_dir():
        _die(f"src/ not found at {src_dir} — run setup.py from the repository root")

    # src/ → /opt/nft-firewall/src/
    dst_src = INSTALL_DIR / "src"
    _info(f"Syncing {src_dir} → {dst_src}")
    _copytree_replace(src_dir, dst_src, "src/")
    _ok(f"Installed src/ ({sum(1 for _ in dst_src.rglob('*.py'))} Python files)")

    # config/ → /opt/nft-firewall/config/   (main.py resolves config relative to itself)
    cfg_dir = project_root / "config"
    if cfg_dir.is_dir():
        dst_cfg = INSTALL_DIR / "config"
        _copytree_replace(cfg_dir, dst_cfg, "config/")
        _ok(f"Installed config/ → {dst_cfg}")
    else:
        _warn("config/ directory not found — skipping (firewall.ini must be added manually)")

    # Make main.py executable
    main_py = INSTALL_DIR / "src" / "main.py"
    if main_py.exists():
        main_py.chmod(0o755)

    setup_src = project_root / "setup.py"
    if setup_src.exists():
        _copy_file_replace(setup_src, INSTALL_DIR / "setup.py", "setup.py")
        (INSTALL_DIR / "setup.py").chmod(0o755)

    fw_src = project_root / "scripts" / "fw"
    if fw_src.exists():
        _copy_file_replace(fw_src, FW_BIN, "fw wrapper")
        FW_BIN.chmod(0o755)
        _ok(f"Installed fw wrapper -> {FW_BIN}")

    # tests/ → /opt/nft-firewall/tests/
    tests_dir = project_root / "tests"
    if tests_dir.is_dir():
        dst_tests = INSTALL_DIR / "tests"
        _copytree_replace(tests_dir, dst_tests, "tests/")
        _ok(f"Installed tests/ → {dst_tests}")

    # scripts/ → /opt/nft-firewall/scripts/
    scripts_dir = project_root / "scripts"
    if scripts_dir.is_dir():
        dst_scripts = INSTALL_DIR / "scripts"
        _copytree_replace(scripts_dir, dst_scripts, "scripts/")
        _ok(f"Installed scripts/ → {dst_scripts}")

    # systemd templates and local check metadata are part of the installed
    # support tree because the bundled tests validate them in place.
    systemd_dir = project_root / "systemd"
    if systemd_dir.is_dir():
        dst_systemd = INSTALL_DIR / "systemd"
        _copytree_replace(systemd_dir, dst_systemd, "systemd/")
        _ok(f"Installed systemd/ → {dst_systemd}")

    for support_file in ("install.sh", "setup.sh", "pyproject.toml", "Makefile"):
        src = project_root / support_file
        if src.exists():
            _copy_file_replace(src, INSTALL_DIR / support_file, support_file)
            if support_file.endswith(".sh"):
                (INSTALL_DIR / support_file).chmod(0o755)
            _ok(f"Installed {support_file} → {INSTALL_DIR / support_file}")


def step2_5_nft_preflight(src_path: Optional[Path] = None) -> None:
    """Validate the generated ruleset with nft --check before touching systemd.

    Uses the just-installed src so we test exactly what was deployed.
    Exits with status 1 on any syntax error — stopping the install before
    any systemd units are created or enabled.
    """
    _header("Step 2.5 — Validate Ruleset Syntax (nft --check)")

    if not _CONF_FILE.exists():
        _warn("firewall.ini not found — skipping nft --check pre-flight")
        return

    # Load the just-installed (or provided) core.rules to generate a real ruleset
    import sys
    sys.path.insert(0, str(src_path or (INSTALL_DIR / "src")))

    try:
        from core.rules import RulesetConfig, generate_ruleset
    except ImportError as e:
        _die(f"Could not import core.rules from {src_path or (INSTALL_DIR / 'src')}: {e}")

    # Use a dummy profile for validation if firewall.ini exists
    from configparser import ConfigParser
    cp = ConfigParser()
    cp.read(_CONF_FILE)
    
    # Minimal config to trigger ruleset generation
    try:
        cfg = RulesetConfig(
            phy_if=cp.get("network", "phy_if", fallback="eth0"),
            vpn_interface=cp.get("network", "vpn_interface", fallback="wg0"),
            vpn_server_ip=cp.get("network", "vpn_server_ip", fallback="1.2.3.4"),
            vpn_server_port=cp.get("network", "vpn_server_port", fallback="51820"),
            lan_net=cp.get("network", "lan_net", fallback="192.168.1.0/24"),
            ssh_port=cp.getint("network", "ssh_port", fallback=22),
        )
        ruleset = generate_ruleset(cfg)
    except Exception as e:
        _die(f"Failed to generate ruleset for pre-flight: {e}")

    # Check syntax with nft --check
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf") as tmp:
        tmp.write(ruleset)
        tmp.flush()
        
        try:
            r = subprocess.run(["/usr/sbin/nft", "--check", "--file", tmp.name],
                              capture_output=True, text=True)
        except FileNotFoundError:
            _die("Missing /usr/sbin/nft. Install Debian package: nftables")
        if r.returncode != 0:
            print(f"\033[31m\033[1m  NFT Syntax Error Detected!\033[0m")
            print(r.stderr.strip())
            print()
            _die("Install aborted: Generated ruleset has syntax errors.")
        
    _ok("Ruleset syntax is valid (nft --check)")


# ── Step 3: Directories & ownership ──────────────────────────────────────────

def step3_scaffold_dirs() -> None:
    """Create runtime directories and apply firewall ownership.

    INSTALL_DIR holds code that fw-admin daemons execute via sudo wrappers.
    It must be root-owned so a compromised daemon cannot rewrite main.py and
    escalate to root on the next ``sudo /usr/local/bin/fw …`` invocation.
    Group is fw-admin so service accounts can still read the tree.

    Runtime dirs (LIB_DIR, LOG_DIR, ETC_DIR) stay fw-admin-owned because
    daemons must write state/logs there.
    """
    _header("Step 3 — Scaffold Directories & Ownership")

    for d in FIREWALL_DIRS:
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o755)
        _ok(f"Ensured {d} (755)")

    # Code: root-owned, fw-admin group (read-only for daemons)
    _run(["chown", "-R", f"root:{SYSTEM_USER}", str(INSTALL_DIR)])
    _run(["chmod", "-R", "u=rwX,g=rX,o=rX", str(INSTALL_DIR)])
    _ok(f"chown -R root:{SYSTEM_USER}  {INSTALL_DIR}  (code, read-only for fw-admin)")

    # Runtime/state: fw-admin-owned (daemons must write here)
    for d in (LIB_DIR, LOG_DIR, ETC_DIR):
        d.chmod(0o750)
        _run(["chown", "-R", f"{SYSTEM_USER}:{SYSTEM_USER}", str(d)])
        _ok(f"chown -R {SYSTEM_USER}:{SYSTEM_USER}  {d}")


# ── Step 4: Sudoers ───────────────────────────────────────────────────────────

def step4_install_sudoers() -> None:
    """Write a minimal /etc/sudoers.d/nft-firewall granting least-privilege access."""
    _header("Step 4 — Sudoers (Least-Privilege Grants)")

    keybase_user = _read_keybase_user()
    _install_sudo_wrappers()

    # Build the sudoers fragment
    fragment_lines = [
        "# nft-firewall — least-privilege grants for the fw-admin service account.",
        "# Generated by setup.py — re-run 'sudo python3 /opt/nft-firewall/setup.py install'",
        "# to regenerate after changes.",
        "",
        f"Defaults:{SYSTEM_USER} !requiretty",
        "",
        "# Firewall & VPN operations via argument-checking wrapper scripts.",
        f"{SYSTEM_USER} ALL=(root) NOPASSWD: \\",
        f"    {FW_BIN}, \\",
        f"    {WRAPPER_DIR}/fw-nft, \\",
        f"    {WRAPPER_DIR}/fw-wg, \\",
        f"    {WRAPPER_DIR}/fw-wg-quick, \\",
        f"    {WRAPPER_DIR}/fw-ip, \\",
        f"    {WRAPPER_DIR}/fw-conntrack, \\",
        f"    {WRAPPER_DIR}/fw-systemctl",
        "",
    ]

    if keybase_user:
        fragment_lines += [
            "# Keybase notifications — wrapper opens a login session for the Keybase account",
            f"{SYSTEM_USER} ALL=(root) NOPASSWD: {KEYBASE_WRAPPER}",
            "",
        ]
    else:
        fragment_lines += [
            "# Keybase linux_user not detected in firewall.ini — add manually if needed:",
            f"# {SYSTEM_USER} ALL=(root) NOPASSWD: {KEYBASE_WRAPPER}",
            "",
        ]

    content = "\n".join(fragment_lines)

    # Validate with visudo before touching the real file
    _info("Validating sudoers fragment with visudo ...")
    tmp = Path(tempfile.mktemp(suffix=".sudoers", dir="/tmp"))
    try:
        tmp.write_text(content)
        r = _run(["visudo", "--check", "--file", str(tmp)], check=False)
        if r.returncode != 0:
            _die(f"visudo rejected the sudoers fragment:\n{r.stderr.strip()}")
    finally:
        tmp.unlink(missing_ok=True)

    SUDOERS_FILE.write_text(content)
    SUDOERS_FILE.chmod(0o440)   # sudo requires 440 or 640
    _ok(f"Installed {SUDOERS_FILE}")
    if keybase_user:
        _ok(f"Keybase grant: {SYSTEM_USER} may run Keybase wrapper for '{keybase_user}'")
    else:
        _warn("Keybase user not configured — add to firewall.ini [keybase] linux_user")

    # Install the Keybase wrapper script used by the sudoers rule above.
    # The wrapper opens a login session for the configured Keybase account while
    # keeping sudoers pinned to an exact, fixed command path.
    _install_keybase_wrapper(keybase_user)


def _read_keybase_user() -> str:
    """Return [keybase] linux_user from firewall.ini, checking install dir first."""
    for ini_path in (
        INSTALL_DIR / "config" / "firewall.ini",
        Path(__file__).resolve().parent / "config" / "firewall.ini",
    ):
        try:
            cfg = configparser.ConfigParser()
            cfg.read(str(ini_path))
            u = cfg.get("keybase", "linux_user", fallback="").strip()
            if u:
                return u
        except Exception:
            pass
    return ""


def _install_keybase_wrapper(kb_user: str) -> None:
    """Write /usr/local/bin/nft-keybase-notify — the sudoers-safe Keybase wrapper.

    The wrapper is executed as root via a pinned sudoers rule, then opens the
    configured user's login context with sudo -iu. That matches the manual
    Keybase command operators already use (sudo -iu <user> keybase whoami) and
    avoids split sessions where the service appears logged out from automation.
    """
    wrapper = KEYBASE_WRAPPER

    if kb_user:
        try:
            pw      = pwd.getpwnam(kb_user)
            kb_home = pw.pw_dir
            kb_uid  = pw.pw_uid
        except KeyError:
            _warn(f"Cannot look up user '{kb_user}' — Keybase wrapper not installed")
            return
    else:
        # No Keybase user configured; install a stub that exits clearly
        kb_home = "/home/UNCONFIGURED"
        kb_uid  = 1000

    script = (
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "# Wrapper installed by nft-firewall setup.py\n"
        "# Allows fw-admin to invoke keybase through a root-owned, exact sudo rule.\n"
        f'default_kb_user="{kb_user or ""}"\n'
        'config_kb_user="$(/usr/bin/python3 - <<\'PY\' 2>/dev/null || true\n'
        'import configparser\n'
        'from pathlib import Path\n'
        'for path in (\n'
        '    Path("/opt/nft-firewall/config/firewall.ini"),\n'
        '    Path("/etc/nft-firewall/firewall.ini"),\n'
        '    Path("/etc/nft-watchdog.conf"),\n'
        '):\n'
        '    cfg = configparser.ConfigParser()\n'
        '    try:\n'
        '        cfg.read(path)\n'
        '    except Exception:\n'
        '        continue\n'
        '    user = cfg.get("keybase", "linux_user", fallback="").strip()\n'
        '    if user:\n'
        '        print(user)\n'
        '        break\n'
        'PY\n'
        ')"\n'
        'kb_user="${NFT_FIREWALL_KEYBASE_USER:-${config_kb_user:-$default_kb_user}}"\n'
        'if [[ -z "$kb_user" ]]; then\n'
        '  echo "Keybase linux_user is not configured" >&2\n'
        "  exit 1\n"
        "fi\n"
        'if ! getent passwd "$kb_user" >/dev/null; then\n'
        '  echo "Keybase linux_user does not exist: $kb_user" >&2\n'
        "  exit 1\n"
        "fi\n"
        'kb_uid="$(id -u "$kb_user")"\n'
        'kb_home="$(getent passwd "$kb_user" | cut -d: -f6)"\n'
        'export HOME="$kb_home"\n'
        'export USER="$kb_user"\n'
        'export LOGNAME="$kb_user"\n'
        'export SHELL="/bin/bash"\n'
        'export XDG_RUNTIME_DIR="$kb_home/.config"\n'
        'export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$kb_uid/bus"\n'
        'export PATH="/usr/local/bin:/usr/bin:/bin"\n'
        'cd "$HOME" 2>/dev/null || true\n'
        'sudo_bin="/usr/bin/sudo"\n'
        'if [[ ! -x "$sudo_bin" ]]; then\n'
        '  sudo_bin="$(command -v sudo || true)"\n'
        'fi\n'
        'if [[ -n "$sudo_bin" ]]; then\n'
        '  exec "$sudo_bin" -iu "$kb_user" -- /usr/bin/env XDG_RUNTIME_DIR="$kb_home/.config" /usr/bin/keybase "$@"\n'
        'fi\n'
        'runuser_bin="/usr/sbin/runuser"\n'
        'if [[ ! -x "$runuser_bin" ]]; then\n'
        '  runuser_bin="$(command -v runuser || true)"\n'
        'fi\n'
        'if [[ -z "$runuser_bin" ]]; then\n'
        '  echo "sudo/runuser command not found" >&2\n'
        '  exit 1\n'
        'fi\n'
        'exec "$runuser_bin" -u "$kb_user" -- env \\\n'
        '  HOME="$HOME" \\\n'
        '  USER="$USER" \\\n'
        '  LOGNAME="$LOGNAME" \\\n'
        '  SHELL="$SHELL" \\\n'
        '  XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \\\n'
        '  DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \\\n'
        '  PATH="$PATH" \\\n'
        '  /usr/bin/keybase "$@"\n'
    )

    wrapper.write_text(script)
    wrapper.chmod(0o755)
    _ok(f"Installed {wrapper}  (login user={kb_user or 'UNCONFIGURED'}, home={kb_home}, uid={kb_uid})")


def _keybase_failure_summary(detail: str, linux_user: str) -> str:
    normalized = detail.lower()
    if "login required" in normalized or "logged out" in normalized:
        return f"Keybase login is required for {linux_user}"
    if "failed to reach user-level systemd daemon" in normalized:
        return f"Keybase user session is not reachable for {linux_user}"
    if "keybased.sock" in normalized or "connect: no such file" in normalized:
        return f"Keybase service/socket is not running for {linux_user}"
    if "resource temporarily unavailable" in normalized:
        return f"Keybase local storage is temporarily locked for {linux_user}"
    return f"Keybase wrapper cannot access a logged-in session for {linux_user}"


def _dev_tty_available() -> bool:
    return os.access("/dev/tty", os.R_OK | os.W_OK)


def _ask_tty_yes_no(prompt: str, *, default: bool = False) -> bool:
    if not _dev_tty_available():
        return default
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            answer = tty.readline().strip().lower()
    except OSError:
        return default
    if not answer:
        return default
    return answer in {"y", "yes"}


def _keybase_direct_whoami(linux_user: str) -> str:
    result = subprocess.run(
        ["sudo", "-iu", linux_user, "keybase", "whoami"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _prepare_keybase_session(linux_user: str) -> None:
    """Start Keybase for linux_user and optionally launch interactive login."""
    _info(f"Starting Keybase service for {linux_user} if needed...")
    subprocess.run(
        [
            "sudo",
            "-iu",
            linux_user,
            "sh",
            "-c",
            "command -v run_keybase >/dev/null 2>&1 && run_keybase -g >/tmp/nft-firewall-keybase-run.log 2>&1 || true",
        ],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    time.sleep(2)
    if _keybase_direct_whoami(linux_user):
        return

    requested = os.environ.get("NFT_FIREWALL_KEYBASE_LOGIN") == "1"
    should_login = requested
    if not should_login:
        should_login = _ask_tty_yes_no(
            f"  Keybase is not logged in for {linux_user}. Launch interactive login now? Type yes to continue [no]: ",
            default=False,
        )
    if not should_login:
        return

    if not _dev_tty_available():
        _warn(f"Keybase login requested, but /dev/tty is not available for {linux_user}")
        return

    _info(f"Launching interactive Keybase login for {linux_user}...")
    subprocess.run(
        ["sudo", "-iu", linux_user, "sh", "-c", "keybase login </dev/tty"],
        check=False,
    )


def _read_install_config() -> configparser.ConfigParser:
    """Load the installed or local firewall.ini for installer decisions."""
    cfg = configparser.ConfigParser()
    for ini_path in (
        INSTALL_DIR / "config" / "firewall.ini",
        Path(__file__).resolve().parent / "config" / "firewall.ini",
    ):
        if ini_path.exists():
            cfg.read(str(ini_path))
            break
    return cfg


def _configured_vpn_interface(default: str = "wg0") -> str:
    """Return the configured WireGuard interface name for installer actions."""
    cfg = _read_install_config()
    vpn_if = cfg.get("network", "vpn_interface", fallback=default).strip() or default
    if not re.match(r"^[A-Za-z0-9_.:-]+$", vpn_if):
        _warn(f"Invalid vpn_interface {vpn_if!r}; falling back to {default}")
        return default
    return vpn_if


def _wireguard_runtime_ready() -> bool:
    """Return True when watchdog can reasonably start during install."""
    vpn_if = _configured_vpn_interface()
    wg_conf = Path(f"/etc/wireguard/{vpn_if}.conf")
    if not wg_conf.exists():
        _warn(f"Skipping nft-watchdog.service: {wg_conf} is missing")
        return False
    if shutil.which("wg-quick") is None:
        _warn("Skipping nft-watchdog.service: wg-quick is missing")
        return False
    return True


def _keybase_chatops_ready() -> bool:
    """Return True when Keybase-dependent services can start during install."""
    cfg = _read_install_config()
    linux_user = cfg.get("keybase", "linux_user", fallback="").strip()
    target_user = cfg.get("keybase", "target_user", fallback="").strip()
    team = cfg.get("keybase", "team", fallback="").strip()
    if not target_user or target_user == "your-keybase-username":
        _warn("Skipping Keybase services: keybase.target_user is not configured")
        return False
    if not team and not target_user:
        _warn("Skipping Keybase services: no Keybase team or target_user is configured")
        return False
    if not linux_user:
        _warn("Skipping Keybase services: keybase.linux_user is not configured")
        return False
    try:
        pwd.getpwnam(linux_user)
    except KeyError:
        _warn(f"Skipping Keybase services: keybase.linux_user does not exist: {linux_user}")
        return False
    if shutil.which("keybase") is None:
        _warn("Skipping Keybase services: keybase command is missing")
        return False
    wrapper = KEYBASE_WRAPPER
    if not wrapper.exists():
        _warn(f"Skipping Keybase services: {wrapper} is missing")
        return False

    try:
        _prepare_keybase_session(linux_user)
    except Exception as exc:
        if os.environ.get("NFT_FIREWALL_DEBUG") == "1":
            _warn(f"Could not prepare Keybase session for {linux_user}: {exc}")

    env = os.environ.copy()
    env["NFT_FIREWALL_KEYBASE_USER"] = linux_user
    result = subprocess.run(
        [str(wrapper), "whoami"],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
    )
    if result.returncode != 0 or not result.stdout.strip():
        detail = (result.stderr or result.stdout or "").strip()
        _warn(f"Skipping Keybase services: {_keybase_failure_summary(detail, linux_user)}")
        if detail and os.environ.get("NFT_FIREWALL_DEBUG") == "1":
            _warn(detail)
        _warn(f"Repair with: sudo -iu {linux_user} run_keybase -g && sudo -iu {linux_user} keybase login")
        return False
    _ok(f"Keybase wrapper logged in as {result.stdout.strip()}")
    return True


def _write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(0o755)


def _install_sudo_wrappers() -> None:
    """Install root wrapper scripts that validate privileged command arguments."""
    _write_executable(WRAPPER_DIR / "fw-nft", """#!/usr/bin/env bash
# Wrapper installed by nft-firewall setup.py
# Restricts privileged nftables operations to a strict allowlist.
set -euo pipefail

# 1. Deny shell injection tokens in ANY argument
for arg in "$@"; do
  if [[ "$arg" == *[';|&$()`><']* ]]; then
    echo "fw-nft: denied special characters in argument: $arg" >&2
    exit 126
  fi
done

case "${1:-}" in
  list)
    case "${2:-}" in
      ruleset) [ "$#" -eq 2 ] && exec /usr/sbin/nft list ruleset ;;
      set) [ "$#" -eq 5 ] && [ "${3:-}" = "ip" ] && [ "${4:-}" = "firewall" ] && case "${5:-}" in blocked_ips|trusted_ips|dk_ips|geowhitelist_ips) exec /usr/sbin/nft list set ip firewall "$5" ;; esac ;;
      chain) [ "$#" -eq 5 ] && [ "${3:-}" = "ip" ] && [ "${4:-}" = "firewall" ] && case "${5:-}" in input|output|forward) exec /usr/sbin/nft list chain ip firewall "$5" ;; esac ;;
      tables) [ "$#" -eq 3 ] && [ "${2:-}" = "tables" ] && [ "${3:-}" = "ip6" ] && exec /usr/sbin/nft list tables ip6 ;;
    esac
    ;;
  add|delete)
    if [ "$#" -eq 6 ] && [ "${2:-}" = "element" ] && [ "${3:-}" = "ip" ] && [ "${4:-}" = "firewall" ]; then
       case "${5:-}" in blocked_ips|trusted_ips|dk_ips|geowhitelist_ips) exec /usr/sbin/nft "$1" element ip firewall "$5" "$6" ;; esac
    fi
    if [ "$1" = "delete" ] && [ "$#" -eq 7 ] && [ "${2:-}" = "rule" ] && [ "${3:-}" = "ip" ] && [ "${4:-}" = "firewall" ] && [ "${5:-}" = "input" ] && [ "${6:-}" = "handle" ]; then
       exec /usr/sbin/nft delete rule ip firewall input handle "$7"
    fi
    ;;
  --check) [ "$#" -eq 3 ] && [ "${2:-}" = "--file" ] && exec /usr/sbin/nft --check --file "$3" ;;
  --file|-f) [ "$#" -eq 2 ] && [ "${2:-}" = "/etc/nftables.conf" ] && exec /usr/sbin/nft -f /etc/nftables.conf ;;

  --echo) [ "$#" -eq 8 ] && [ "${2:-}" = "--json" ] && [ "${3:-}" = "add" ] && [ "${4:-}" = "rule" ] && [ "${5:-}" = "ip" ] && [ "${6:-}" = "firewall" ] && [ "${7:-}" = "input" ] && exec /usr/sbin/nft --echo --json add rule ip firewall input "$8" ;;
esac
echo "fw-nft: denied arguments: $*" >&2
exit 126
""")
    _write_executable(WRAPPER_DIR / "fw-wg", """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  show) exec /usr/bin/wg "$@" ;;
  set) [ "${3:-}" = "peer" ] && [ "${5:-}" = "endpoint" ] && exec /usr/bin/wg "$@" ;;
esac
echo "fw-wg: denied arguments: $*" >&2
exit 126
""")
    _write_executable(WRAPPER_DIR / "fw-wg-quick", """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  up|down) exec /usr/bin/wg-quick "$@" ;;
esac
echo "fw-wg-quick: denied arguments: $*" >&2
exit 126
""")
    _write_executable(WRAPPER_DIR / "fw-ip", """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  link) case "${2:-}" in show|delete) exec /usr/bin/ip "$@" ;; esac ;;
  addr) [ "${2:-}" = "show" ] && exec /usr/bin/ip "$@" ;;
  -4) [ "${2:-}" = "addr" ] && [ "${3:-}" = "show" ] && exec /usr/bin/ip "$@" ;;
  -o) [ "${2:-}" = "link" ] && [ "${3:-}" = "show" ] && exec /usr/bin/ip "$@" ;;
esac
echo "fw-ip: denied arguments: $*" >&2
exit 126
""")
    _write_executable(WRAPPER_DIR / "fw-conntrack", """#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "-F" ] && exec /usr/sbin/conntrack "$@"
echo "fw-conntrack: denied arguments: $*" >&2
exit 126
""")
    _write_executable(WRAPPER_DIR / "fw-systemctl", """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  start)
    case "${2:-}" in
      wg-quick@*.service|wg-quick@*)
        unit="${2%.service}"
        iface="${unit#wg-quick@}"
        if /usr/bin/ip link show dev "$iface" >/dev/null 2>&1; then
          exit 0
        fi
        exec /usr/bin/systemctl "$@"
        ;;
    esac
    ;;
  stop|restart|reload)
    case "${2:-}" in wg-quick@*.service|wg-quick@*) exec /usr/bin/systemctl "$@" ;; esac
    ;;
esac
echo "fw-systemctl: denied arguments: $*" >&2
exit 126
""")
    _ok(f"Installed sudo wrapper scripts in {WRAPPER_DIR}")


# ── Step 5: Systemd unit files ────────────────────────────────────────────────

# Each tuple is (regex pattern, replacement) applied line-by-line.
# Replacements use named backreferences so the directive key is preserved.
_PATCHES: List[Tuple[str, str]] = [
    # User=<anything>  →  User=fw-admin
    (r"^(User=).*$",
     rf"\g<1>{SYSTEM_USER}"),

    # WorkingDirectory=<anything>  →  WorkingDirectory=/opt/nft-firewall
    (r"^(WorkingDirectory=).*$",
     rf"\g<1>{INSTALL_DIR}"),

    # ExecStart / ExecStartPost: replace whatever path precedes /src/main.py
    (r"^(Exec\w+=\S+\s+)\S+/src/main\.py",
     rf"\g<1>{INSTALL_DIR}/src/main.py"),

    # Environment=PYTHONPATH=<anything>  →  correct install path
    (r"^(Environment=PYTHONPATH=).*$",
     rf"\g<1>{INSTALL_DIR}/src"),
]


def _patch_unit(content: str) -> str:
    """Apply all layout patches to a systemd unit file, line by line."""
    vpn_if = _configured_vpn_interface()
    out_lines = []
    for line in content.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        for pattern, replacement in _PATCHES:
            stripped = re.sub(pattern, replacement, stripped)
        stripped = stripped.replace("wg-quick@wg0", f"wg-quick@{vpn_if}")
        out_lines.append(stripped + ("\n" if line.endswith("\n") else ""))
    return "".join(out_lines)


# Units that must keep User=root — none by default.  The firewall runtime
# model is fw-admin plus least-privilege sudo wrappers.
_ROOT_UNITS: set[str] = set()


def step5_deploy_services() -> None:
    """Patch and deploy all .service and .timer files from systemd/ to /etc/systemd/system/."""
    _header("Step 5 — Systemd Unit Files")

    if not SYSTEMD_SRC.is_dir():
        _die(
            f"systemd/ directory not found at {SYSTEMD_SRC}\n"
            "Run setup.py from the repository root."
        )

    unit_files = sorted(SYSTEMD_SRC.glob("*.service")) + sorted(SYSTEMD_SRC.glob("*.timer"))
    if not unit_files:
        _die(f"No .service or .timer files found in {SYSTEMD_SRC}")

    for src in unit_files:
        try:
            raw = src.read_text()
            if src.name in _ROOT_UNITS:
                # Apply all patches EXCEPT User= so User=root is preserved
                patched_lines = []
                for line in raw.splitlines(keepends=True):
                    stripped = line.rstrip("\n")
                    for pattern, replacement in _PATCHES:
                        if "User=" in pattern:
                            continue
                        stripped = re.sub(pattern, replacement, stripped)
                    patched_lines.append(stripped + ("\n" if line.endswith("\n") else ""))
                patched = "".join(patched_lines)
            else:
                patched = _patch_unit(raw)
            dst = SYSTEMD_DST / src.name
            dst.write_text(patched)
            dst.chmod(0o644)
            _ok(f"Deployed {src.name}  →  {dst}")
        except Exception as e:
            _warn(f"Failed to deploy {src.name}: {e} — skipping")
            _debug_log(f"Systemd deploy error ({src.name}): {e}")


# ── Step 6: Reload & restart ──────────────────────────────────────────────────

def step6_reload_and_restart() -> None:
    """Reload systemd and restart all nft-firewall units."""
    _header("Step 6 — Reload & Restart")

    r = _run(["systemctl", "daemon-reload"], check=False)
    if r.returncode != 0:
        _die(f"daemon-reload failed: {r.stderr.strip()}")
    _ok("systemctl daemon-reload")

    # Short delay to allow systemd to settle (essential for fresh user/unit recognition)
    time.sleep(2)

    keybase_ready = _keybase_chatops_ready()

    active_services: List[str] = []
    if _wireguard_runtime_ready():
        active_services.append("nft-watchdog")
    if keybase_ready:
        active_services.append("nft-listener")
    active_services.append("nft-ssh-alert")

    for svc in active_services:
        unit = f"{svc}.service"
        _run(["systemctl", "enable", unit], check=False)
        r = _run(["systemctl", "restart", unit], check=False)
        if r.returncode == 0:
            _ok(f"{unit} restarted")
        else:
            # Show the last 15 journal lines so the user can diagnose inline
            jctl = subprocess.run(
                ["journalctl", "-u", unit, "-n", "15", "--no-pager"],
                capture_output=True, text=True,
            )
            _warn(f"{unit} failed to restart:\n{jctl.stdout.strip()}")

    timers: List[str] = TIMERS if keybase_ready else []
    for tmr in timers:
        unit = f"{tmr}.timer"
        _run(["systemctl", "enable", unit], check=False)
        r = _run(["systemctl", "restart", unit], check=False)
        if r.returncode == 0:
            _ok(f"{unit} enabled")
        else:
            _warn(f"{unit} failed: {r.stderr.strip()}")


# ── Step 7: VPN Activation ────────────────────────────────────────────────────

def step7_activate_vpn() -> None:
    """If the configured WireGuard profile exists, enable and start it."""
    _header("Step 7 — VPN Activation")

    # Redundant reload to force systemd to see wg-quick template from newly installed package
    _run(["systemctl", "daemon-reload"], check=False)

    vpn_if = _configured_vpn_interface()
    wg_conf = Path(f"/etc/wireguard/{vpn_if}.conf")
    if not wg_conf.exists():
        _info(f"No {wg_conf} found — skipping auto-start")
        return

    # DNS Resolution Safety: If the config uses a hostname, resolve it now
    # while the network is still open.  Do not rewrite the operator's
    # WireGuard profile; keep the resolved IP only in firewall.ini.
    try:
        content = wg_conf.read_text()
        m = re.search(r"Endpoint\s*=\s*([^:\s]+)", content)
        if m:
            host = m.group(1)
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                _info(f"Resolving VPN hostname: {host} ...")
                import socket
                try:
                    ip = socket.gethostbyname(host)
                    _ok(f"Resolved to {ip}")
                    
                    # 1. Update firewall.ini
                    cp = configparser.ConfigParser()
                    cp.read(str(_CONF_FILE))
                    if cp.has_section("network"):
                        cp.set("network", "vpn_server_ip", ip)
                        with _CONF_FILE.open("w") as f:
                            cp.write(f)
                        _ok("Updated firewall.ini with resolved IP")

                except Exception as e:
                    _warn(f"Could not resolve {host}: {e}. VPN may fail to start.")
    except Exception:
        pass

    unit = f"wg-quick@{vpn_if}"
    _info(f"Found {wg_conf} — enabling {unit}.service ...")
    _run(["systemctl", "enable", unit], check=False)
    if _run(["ip", "link", "show", "dev", vpn_if], check=False).returncode == 0:
        _run(["systemctl", "reset-failed", unit], check=False)
        _ok(f"{vpn_if} already exists — leaving tunnel up and skipping {unit}.service start")
        return

    r = _run(["systemctl", "start", unit], check=False)
    if r.returncode == 0:
        _ok(f"{unit}.service started")
    else:
        _warn(f"Failed to start {unit}: {r.stderr.strip()}")


# ── Sub-commands ──────────────────────────────────────────────────────────────

def cmd_install(reconfigure: bool = False) -> None:
    step0_0_validate_prerequisites()
    step0_configure(reconfigure=reconfigure)
    step1_create_system_user()
    step2_install_code()
    step2_5_nft_preflight()
    step3_scaffold_dirs()
    step4_install_sudoers()
    step5_deploy_services()
    step6_reload_and_restart()
    step7_activate_vpn()

    print()
    print("\033[32m\033[1m  Install complete.\033[0m")
    print(f"    Code        : {INSTALL_DIR}")
    print(f"    Running as  : {SYSTEM_USER}")
    print(f"    Logs        : journalctl -u nft-watchdog -f")
    print(f"    Sudoers     : {SUDOERS_FILE}")
    print(f"    Apply rules : sudo fw doctor && sudo fw safe-apply <profile>")
    print()
    print("  User model:")
    print(f"    {ADMIN_USER:<8} human admin/dev user; copy and edit nft-firewall code as this user")
    print(f"    {SYSTEM_USER:<8} nft-firewall runtime/systemd user; no Docker group access")
    print()
    print("  Typical workflow:")
    print(f"    1. As {ADMIN_USER}: copy or git-clone this repo")
    print("    2. Install firewall: sudo python3 setup.py install")
    print("    3. Optional Cosmos/media setup: sudo bash setup.sh --with-integrations")


def cmd_status() -> None:
    _header("Installation Status")

    # User
    try:
        pw = pwd.getpwnam(SYSTEM_USER)
        _ok(f"User '{SYSTEM_USER}' — uid={pw.pw_uid}, shell={pw.pw_shell}")
        groups = [g.gr_name for g in grp.getgrall() if SYSTEM_USER in g.gr_mem]
        _ok(f"  Groups: {', '.join(groups) or '(none)'}")
    except KeyError:
        _warn(f"User '{SYSTEM_USER}' does not exist")

    # Directories
    for d in FIREWALL_DIRS:
        if d.exists():
            _ok(f"{d}")
        else:
            _warn(f"{d}  MISSING")
    # Sudoers
    if SUDOERS_FILE.exists():
        _ok(f"Sudoers: {SUDOERS_FILE}")
    else:
        _warn(f"Sudoers {SUDOERS_FILE}  MISSING")

    # Services
    print()
    all_units = (
        [f"{s}.service" for s in ACTIVE_SERVICES]
        + [f"{t}.timer" for t in TIMERS]
    )
    for unit in all_units:
        r = subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True
        )
        state = r.stdout.strip()
        if state == "active":
            _ok(f"{unit}: {state}")
        else:
            _warn(f"{unit}: {state}")


def cmd_uninstall() -> None:
    _header("Uninstall")

    # Flush live ruleset first — kernel default (no tables) is ACCEPT on all hooks.
    # Must happen before stopping the watchdog so the box stays reachable.
    _run(["/usr/sbin/nft", "flush", "ruleset"], check=False)
    _ok("nft flush ruleset — live rules cleared")

    all_units = (
        [f"{s}.service" for s in ACTIVE_SERVICES]
        + [f"{t}.timer" for t in TIMERS]
    )

    _info("Stopping and disabling units ...")
    for unit in all_units:
        _run(["systemctl", "stop",    unit], check=False)
        _run(["systemctl", "disable", unit], check=False)

    # Remove unit files from /etc/systemd/system/
    for unit in all_units:
        unit_file = SYSTEMD_DST / unit
        if unit_file.exists():
            unit_file.unlink()
            _ok(f"Removed {unit_file}")

    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)
        _ok(f"Removed {INSTALL_DIR}")

    if SUDOERS_FILE.exists():
        SUDOERS_FILE.unlink()
        _ok(f"Removed {SUDOERS_FILE}")

    # Remove the Keybase notify wrapper
    wrapper = Path("/usr/local/bin/nft-keybase-notify")
    if wrapper.exists():
        wrapper.unlink()
        _ok(f"Removed {wrapper}")

    _run(["systemctl", "daemon-reload"], check=False)
    _ok("systemctl daemon-reload")

    _info("Data directories and fw-admin user were preserved.")
    _info("To remove them completely, run:")
    _info(f"  sudo rm -rf {LOG_DIR} {LIB_DIR} {ETC_DIR}")
    _info(f"  sudo userdel {SYSTEM_USER}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    _require_root()
    parser = argparse.ArgumentParser(
        description="NFT Firewall System Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo python3 setup.py install               # install or upgrade\n"
            "  sudo python3 setup.py install --reconfigure # re-run config wizard\n"
            "  sudo python3 setup.py status                # check installation state\n"
            "  sudo python3 setup.py uninstall             # remove (preserves data dirs)\n"
        ),
    )
    parser.add_argument(
        "command",
        choices=["install", "status", "uninstall"],
    )
    parser.add_argument(
        "--reconfigure",
        action="store_true",
        help="re-run the configuration wizard even if firewall.ini already exists",
    )
    args = parser.parse_args()

    if args.command == "install":
        cmd_install(reconfigure=args.reconfigure)
    elif args.command == "status":
        cmd_status()
    elif args.command == "uninstall":
        cmd_uninstall()


if __name__ == "__main__":
    main()
