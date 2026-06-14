"""
src/integrations/docker.py — Docker daemon hardening and expose-registry management.

This module handles two concerns:

  1. Daemon hardening
     Enforce ``iptables: false``, ``ip6tables: false``, and ``userland-proxy: false``
     in ``/etc/docker/daemon.json``, preserving all existing keys.  A timestamped
     backup is written to ``state/`` before any change.

  2. Expose registry
     Read/write the JSON file that tracks which Docker container ports are forwarded
     through the host.  The registry is consumed by the nftables ruleset generator;
     this module never touches nftables directly.

Public API
----------
Daemon hardening::

    changed = harden_daemon()          # returns True if daemon.json was rewritten
    if changed:
        restart_docker()               # raises RuntimeError on failure

Expose registry::

    entries = load_registry()
    add_expose(8080, "172.17.0.2", 80)
    remove_expose(8080)
    entries = list_exposed()
"""

import ipaddress
import json
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from utils.validation import validate_ipv4_network, validate_port

# ── Paths & constants ─────────────────────────────────────────────────────────

DAEMON_JSON: Path = Path("/etc/docker/daemon.json")
EXPOSE_CONF: Path = Path("/etc/nftables-exposed-ports.json")

REQUIRED_DAEMON_KEYS: Dict[str, bool] = {
    "iptables"      : False,
    "ip6tables"     : False,
    "userland-proxy": False,
}

_PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent
_BACKUP_DIR:   Path = _PROJECT_ROOT / "state"


def firewall_policy_status(daemon_path: Path = DAEMON_JSON) -> tuple[str, str]:
    """Return doctor status for Docker firewall/NAT authority.

    Docker defaults to managing iptables when keys are absent.  nft-firewall
    requires both iptables and ip6tables to be explicitly false so Docker
    containers cannot publish public ports by themselves.
    """
    try:
        if not daemon_path.exists():
            return (
                "fail",
                f"{daemon_path} not found; Docker defaults may manage firewall rules",
            )
        data = json.loads(daemon_path.read_text())
    except PermissionError:
        return ("warn", f"cannot read {daemon_path}; run doctor as root to verify Docker firewall policy")
    except json.JSONDecodeError as exc:
        return ("warn", f"cannot parse {daemon_path}: {exc}")
    except OSError as exc:
        return ("warn", f"cannot read {daemon_path}: {exc}")

    iptables = data.get("iptables", True)
    ip6tables = data.get("ip6tables", True)
    if iptables is False and ip6tables is False:
        return ("ok", "Docker iptables=false and ip6tables=false")

    return (
        "fail",
        "Docker can manage firewall rules; set iptables=false and ip6tables=false "
        f"in {daemon_path} (current: iptables={iptables!r}, ip6tables={ip6tables!r})",
    )


# ── Daemon hardening ──────────────────────────────────────────────────────────

def harden_daemon(
    daemon_path: Path = DAEMON_JSON,
    backup_dir:  Path = _BACKUP_DIR,
    dry_run:     bool = False,
) -> bool:
    """Enforce the required Docker daemon settings in ``daemon.json``.

    Reads the existing ``daemon.json`` (if present), merges
    :data:`REQUIRED_DAEMON_KEYS` into it (preserving all other keys), and writes
    the result back.  Before overwriting, the original file is backed up to
    ``backup_dir`` with a timestamp.

    Parameters
    ----------
    daemon_path:
        Path to ``daemon.json``.  Defaults to ``/etc/docker/daemon.json``.
    backup_dir:
        Directory for pre-change backups.  Defaults to ``<project_root>/state/``.
    dry_run:
        When ``True``, print the would-be config and return ``True`` without
        writing anything.

    Returns
    -------
    bool
        ``True`` if ``daemon.json`` was written (or would be written in dry-run
        mode), ``False`` if all required keys were already correct.

    Raises
    ------
    OSError
        If the file cannot be written (e.g. permission denied).
    """
    existing: Dict = {}
    if daemon_path.exists():
        try:
            existing = json.loads(daemon_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"[docker] WARNING: daemon.json parse error ({exc}) — will overwrite")

    merged = {**existing, **REQUIRED_DAEMON_KEYS}

    # Nothing to do if all keys are already correct
    if all(existing.get(k) == v for k, v in REQUIRED_DAEMON_KEYS.items()):
        print("[docker] daemon.json already has required settings — no change needed")
        return False

    if dry_run:
        print(f"[docker] DRY RUN — would write {daemon_path}:")
        print(json.dumps(merged, indent=2))
        return True

    backup_dir.mkdir(parents=True, exist_ok=True)
    if daemon_path.exists():
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = backup_dir / f"daemon_json_{ts}.bak"
        bak.write_text(daemon_path.read_text())
        bak.chmod(0o600)
        print(f"[docker] Backed up daemon.json → {bak}")

    daemon_path.parent.mkdir(parents=True, exist_ok=True)
    daemon_path.write_text(json.dumps(merged, indent=2) + "\n")
    daemon_path.chmod(0o644)

    for key, val in REQUIRED_DAEMON_KEYS.items():
        print(f"[docker] Set {key}: {str(val).lower()}")

    return True


def restart_docker() -> None:
    """Stop and restart the Docker systemd service.

    Stops ``docker``, waits 2 seconds, starts it, then verifies it reached the
    ``active`` state.

    Raises
    ------
    RuntimeError
        If Docker fails to start or does not become active within the timeout.
    """
    print("[docker] Stopping Docker ...")
    subprocess.run(["systemctl", "stop", "docker"], check=False)
    time.sleep(2)

    print("[docker] Starting Docker ...")
    result = subprocess.run(
        ["systemctl", "start", "docker"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Docker failed to start: {result.stderr.strip()}")

    active = subprocess.run(
        ["systemctl", "is-active", "docker"],
        capture_output=True, text=True, timeout=60,
    )
    if active.stdout.strip() != "active":
        raise RuntimeError("Docker did not become active after restart")

    print("[docker] Docker restarted — iptables:false is now active")


# ── Expose registry ───────────────────────────────────────────────────────────

def load_registry(path: Path = EXPOSE_CONF) -> List[Dict]:
    """Load the expose registry from disk.

    Parameters
    ----------
    path:
        Path to the JSON registry file.  Defaults to
        ``/etc/nftables-exposed-ports.json``.

    Returns
    -------
    list[dict]
        List of expose entries, or ``[]`` if the file does not exist or cannot
        be parsed.
    """
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text())
    except Exception as exc:
        print(f"[docker] WARNING: could not read registry ({exc}) — returning empty list")
        return []
    if not isinstance(raw, list):
        print("[docker] WARNING: expose registry is not a list — returning empty list")
        return []

    entries: List[Dict] = []
    skipped = 0
    for item in raw:
        cleaned = _clean_registry_entry(item)
        if cleaned is None:
            skipped += 1
            continue
        entries.append(cleaned)
    if skipped:
        print(f"[docker] WARNING: ignored {skipped} malformed expose registry entries")
    return entries


def save_registry(entries: List[Dict], path: Path = EXPOSE_CONF) -> None:
    """Persist the expose registry to disk.

    Writes ``entries`` as pretty-printed JSON and sets permissions to ``0o600``
    (readable by root only).

    Parameters
    ----------
    entries:
        List of expose entry dicts to write.
    path:
        Destination path.  Defaults to ``/etc/nftables-exposed-ports.json``.
    """
    path.write_text(json.dumps(entries, indent=2) + "\n")
    path.chmod(0o600)


def add_expose(
    host_port:      int,
    container_ip:   str,
    container_port: int,
    proto:          str = "tcp",
    src:            Optional[str] = None,
    allowed_networks: Optional[Iterable[str]] = None,
    path:           Path = EXPOSE_CONF,
) -> None:
    """Add a container port forwarding entry to the expose registry.

    Validates the IP address, optional source network, and port range before
    writing.  Refuses to overwrite an existing ``host_port``/``proto`` pair —
    call :func:`remove_expose` first.

    Parameters
    ----------
    host_port:
        Port on the host to forward from (1–65535).
    container_ip:
        IP address of the destination container.
    container_port:
        Port inside the container to forward to (1–65535).
    proto:
        Protocol — ``"tcp"`` or ``"udp"``.  Defaults to ``"tcp"``.
    src:
        Optional source network restriction in CIDR notation (e.g.
        ``"192.168.1.0/24"``).  ``None`` means any source.
    path:
        Registry file path.  Defaults to ``/etc/nftables-exposed-ports.json``.

    Raises
    ------
    ValueError
        If any argument fails validation.
    """
    result = validate_ipv4_network(container_ip, allow_network=False)
    if not result.ok:
        raise ValueError(f"Invalid container IP: {container_ip!r}")
    container_ip = result.value

    if allowed_networks is not None:
        _validate_container_destination(container_ip, allowed_networks)

    if src is not None:
        src_result = validate_ipv4_network(src)
        if not src_result.ok:
            raise ValueError(f"Invalid src network: {src!r}")
        src = src_result.value

    proto = str(proto).lower()
    if proto not in {"tcp", "udp"}:
        raise ValueError(f"proto must be tcp or udp, got {proto!r}")

    host_port = validate_port(host_port, "host_port")
    container_port = validate_port(container_port, "container_port")

    entries = load_registry(path)
    for entry in entries:
        if entry["host_port"] == host_port and entry["proto"] == proto:
            raise ValueError(
                f"{host_port}/{proto} already exposed to "
                f"{entry['container_ip']}:{entry['container_port']} — "
                f"call remove_expose() first to change the target"
            )

    new_entry: Dict = {
        "host_port"     : host_port,
        "container_ip"  : container_ip,
        "container_port": container_port,
        "proto"         : proto,
    }
    if src is not None:
        new_entry["src"] = src

    entries.append(new_entry)
    save_registry(entries, path)

    src_str = f"src {src}" if src else "any source"
    print(f"[docker] Exposed: {host_port}/{proto} ({src_str}) → {container_ip}:{container_port}")
    print("[docker] Registry updated. Re-apply the ruleset to activate.")


def remove_expose(
    host_port: int,
    proto:     str  = "tcp",
    path:      Path = EXPOSE_CONF,
) -> None:
    """Remove a container port forwarding entry from the expose registry.

    Parameters
    ----------
    host_port:
        Host port of the entry to remove.
    proto:
        Protocol of the entry to remove.  Defaults to ``"tcp"``.
    path:
        Registry file path.  Defaults to ``/etc/nftables-exposed-ports.json``.
    """
    entries = load_registry(path)
    filtered = [
        e for e in entries
        if not (e["host_port"] == host_port and e["proto"] == proto)
    ]
    if len(filtered) == len(entries):
        print(f"[docker] WARNING: no entry found for {host_port}/{proto} — nothing removed")
        return

    save_registry(filtered, path)
    print(f"[docker] Removed {host_port}/{proto} from registry.")
    print("[docker] Registry updated. Re-apply the ruleset to activate.")


def list_exposed(path: Path = EXPOSE_CONF) -> List[Dict]:
    """Return all current expose registry entries.

    Parameters
    ----------
    path:
        Registry file path.  Defaults to ``/etc/nftables-exposed-ports.json``.

    Returns
    -------
    list[dict]
        Each dict contains at minimum: ``host_port``, ``container_ip``,
        ``container_port``, ``proto``.  An optional ``src`` key is present when
        a source restriction was set.
    """
    return load_registry(path)


def _clean_registry_entry(entry: object) -> Optional[Dict]:
    """Return a validated expose registry entry, or None for malformed input."""
    if not isinstance(entry, dict):
        return None
    try:
        host_port = validate_port(entry.get("host_port"), "host_port")
        container_port = validate_port(entry.get("container_port"), "container_port")
        proto = str(entry.get("proto", "tcp")).lower()
    except ValueError:
        return None
    if proto not in {"tcp", "udp"}:
        return None

    ip_result = validate_ipv4_network(str(entry.get("container_ip", "")), allow_network=False)
    if not ip_result.ok:
        return None

    cleaned: Dict = {
        "host_port": host_port,
        "container_ip": ip_result.value,
        "container_port": container_port,
        "proto": proto,
    }
    if entry.get("src") is not None:
        src_result = validate_ipv4_network(str(entry["src"]))
        if not src_result.ok:
            return None
        cleaned["src"] = src_result.value
    return cleaned


def _validate_container_destination(container_ip: str, allowed_networks: Iterable[str]) -> None:
    """Ensure *container_ip* is inside at least one validated Docker network."""
    addr = ipaddress.ip_address(container_ip)
    networks = []
    for raw in allowed_networks:
        result = validate_ipv4_network(str(raw))
        if not result.ok:
            continue
        networks.append(ipaddress.ip_network(result.value, strict=False))
    if not networks:
        raise ValueError("No valid Docker networks configured; refusing docker-expose")
    if not any(addr in net for net in networks):
        allowed = ", ".join(str(net) for net in networks)
        raise ValueError(
            f"container_ip {container_ip} is outside configured Docker networks: {allowed}"
        )


def detect_bridge_networks(default_supernet: str = "172.16.0.0/12") -> List[str]:
    """Return IPv4 CIDRs for Docker bridge networks, or a conservative fallback.

    This is read-only: it calls Docker CLI inspection commands when Docker is
    installed and reachable.  If Docker is absent, stopped, or not permitted for
    the current user, the configured supernet is returned so the firewall keeps
    the existing container killswitch coverage.
    """
    default_result = validate_ipv4_network(default_supernet) if default_supernet else None
    fallback = [default_result.value] if default_result and default_result.ok else []
    if shutil.which("docker") is None:
        return fallback

    try:
        ids = subprocess.run(
            ["docker", "network", "ls", "--filter", "driver=bridge", "--format", "{{.ID}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return fallback
    if ids.returncode != 0:
        return fallback

    network_ids = [line.strip() for line in ids.stdout.splitlines() if line.strip()]
    if not network_ids:
        return fallback

    try:
        inspected = subprocess.run(
            ["docker", "network", "inspect", *network_ids],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return fallback
    if inspected.returncode != 0:
        return fallback

    try:
        networks = json.loads(inspected.stdout)
    except json.JSONDecodeError:
        return fallback

    cidrs = set(fallback)
    for network in networks:
        ipam = network.get("IPAM", {}) if isinstance(network, dict) else {}
        for item in ipam.get("Config", []) or []:
            subnet = item.get("Subnet", "")
            if not subnet:
                continue
            try:
                parsed = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                continue
            if isinstance(parsed, ipaddress.IPv4Network):
                cidrs.add(str(parsed))

    return sorted(cidrs)
