"""
src/utils/formatter.py — Mobile-friendly vertical dashboard formatter.

Produces a compact, narrow status report suitable for reading on a phone.
No wide ASCII borders — every line fits in ~40 characters.

Public API
----------
    from utils.formatter import build_status_report

    print(build_status_report(cfg_path))
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

# ── Version banner ────────────────────────────────────────────────────────────

VERSION = "11.0"


# fw-admin sudoers does NOT permit raw /usr/bin/docker. Route privileged
# read-only docker calls through the fw-docker wrapper so the daemon can
# report state without requiring docker-group membership (which would imply
# effective root via container escape).
_FW_DOCKER_WRAPPER = Path("/usr/local/lib/nft-firewall/fw-docker")


def _docker_args(*args: str) -> List[str]:
    if _FW_DOCKER_WRAPPER.exists():
        return ["sudo", "-n", str(_FW_DOCKER_WRAPPER), *args]
    return ["docker", *args]

# Handshake age (seconds) beyond which VPN is considered stale
_HANDSHAKE_WARN  = 150   # 2.5 min — WireGuard re-keys every 2 min
_HANDSHAKE_DEAD  = 330   # 5.5 min — definitely lost

# ── Tiny helpers ──────────────────────────────────────────────────────────────

def _ok(cond: bool) -> str:
    return "🟢" if cond else "🔴"


def _fmt_age(seconds: Optional[float]) -> str:
    if seconds is None:
        return "🔴 no handshake"
    s = int(seconds)
    if s < 60:
        label = f"{s}s ago"
    elif s < 3600:
        label = f"{s // 60}m {s % 60}s ago"
    else:
        label = f"{s // 3600}h {(s % 3600) // 60}m ago"
    icon = _ok(s < _HANDSHAKE_DEAD)
    return f"{icon} {label}"


def _svc_status(name: str) -> str:
    """Return 🟢/🔴 + active/inactive for a systemd unit."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=5,
        )
        state = r.stdout.strip()
    except Exception:
        state = "unknown"
    return f"{_ok(state == 'active')} {state}"


def _docker_running() -> str:
    """Return count of running Docker containers, or error string."""
    try:
        r = subprocess.run(
            _docker_args("ps", "--format", "{{.Names}}"),
            capture_output=True, text=True, timeout=8,
        )
        if r.returncode != 0:
            err = r.stderr.strip().splitlines()[0] if r.stderr else f"exit {r.returncode}"
            # Shorten common permission error
            if "permission denied" in err.lower():
                return "🔴 logout required"
            return f"🔴 {err[:20]}"
        names = [l for l in r.stdout.splitlines() if l.strip()]
        n = len(names)
        return f"🟢 {n} running" if n else "🔴 none running"
    except FileNotFoundError:
        return "— not installed"
    except Exception as e:
        return f"🔴 {str(e)[:20]}"


def _exposed_ports(cfg_path: Optional[str] = None) -> str:
    """Return summary of exposed ports from both Docker registry and firewall.ini."""
    try:
        _root = Path(__file__).resolve().parent.parent.parent
        if str(_root / "src") not in sys.path:
            sys.path.insert(0, str(_root / "src"))
        from integrations.docker import list_exposed

        seen: set = set()
        parts: List[str] = []

        for port, proto, scope in _firewall_open_ports(cfg_path):
            key = (port, proto)
            if key not in seen:
                seen.add(key)
                parts.append(f"{port}/{proto}({scope})")

        for e in list_exposed():
            key = (e["host_port"], e["proto"])
            if key in seen:
                continue
            seen.add(key)
            src = e.get("src") or "any"
            tag = "(LAN)" if src not in ("any", "", None) else "(pub)"
            parts.append(f"{e['host_port']}/{e['proto']}{tag}")

        if not parts:
            return "none"
        n = len(parts)
        suffix = f" +{n - 3} more" if n > 3 else ""
        return ", ".join(parts[:3]) + suffix
    except Exception:
        return "—"


def _cpu_load() -> str:
    """Return the 1/5/15-minute load averages from /proc/loadavg."""
    try:
        parts = Path("/proc/loadavg").read_text().split()
        return f"{parts[0]}, {parts[1]}, {parts[2]}"
    except Exception:
        return "—"


def _ram_usage() -> str:
    """Return RAM usage as 'X.XGB / Y.YGB' from /proc/meminfo."""
    try:
        info: dict = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            info[k.strip()] = int(v.split()[0])   # kB
        total_kb = info["MemTotal"]
        avail_kb = info.get("MemAvailable", info.get("MemFree", 0))
        used_gb  = (total_kb - avail_kb) / 1_048_576
        total_gb = total_kb / 1_048_576
        return f"{used_gb:.1f}GB / {total_gb:.1f}GB"
    except Exception:
        return "—"


def _disk_space() -> str:
    """Return root filesystem usage as '/ is XX% full'."""
    try:
        import shutil
        u = shutil.disk_usage("/")
        pct = u.used / u.total * 100
        return f"/ is {pct:.0f}% full"
    except Exception:
        return "—"


def _parse_ports(raw: str) -> List[int]:
    """Parse a comma-separated port list without raising on malformed entries."""
    ports: List[int] = []
    for item in raw.split(","):
        port = item.strip()
        if port.isdigit():
            ports.append(int(port))
    return ports


def _firewall_open_ports(cfg_path: Optional[str] = None) -> List[Tuple[int, str, str]]:
    """Return (port, proto, scope) tuples from firewall.ini [network] section."""
    import configparser as _cp
    result: List[Tuple[int, str, str]] = []
    _root = Path(__file__).resolve().parent.parent.parent
    candidates: List[Path] = []
    if cfg_path:
        candidates.append(Path(cfg_path))
    candidates.extend([
        _root / "config" / "firewall.ini",
        Path("/opt/nft-firewall/config/firewall.ini"),
        Path("/etc/nft-watchdog.conf"),
    ])

    for ini in candidates:
        try:
            exists = ini.exists()
        except OSError:
            continue
        if exists:
            cfg = _cp.ConfigParser()
            cfg.read(str(ini))
            for port in _parse_ports(cfg.get("network", "extra_ports", fallback="")):
                result.append((port, "tcp", "VPN"))
            for port in _parse_ports(cfg.get("network", "lan_allow_ports", fallback="")):
                result.append((port, "tcp", "LAN"))
            for port in _parse_ports(cfg.get("network", "lan_allow_udp_ports", fallback="")):
                result.append((port, "udp", "LAN"))
            tp = cfg.get("network", "torrent_port", fallback="").strip()
            if tp.isdigit():
                result.append((int(tp), "tcp", "VPN"))
                result.append((int(tp), "udp", "VPN"))
            break
    return result


def _exposed_port_lines(cfg_path: Optional[str] = None) -> List[str]:
    """Return one line per exposed port, with scope-aware icons.

    Merges Docker registry entries with firewall.ini open ports.
    Deduplicates by (port, proto).
    """
    lines: List[str] = []
    seen: set = set()

    # Firewall.ini ports
    for port, proto, scope in _firewall_open_ports(cfg_path):
        key = (port, proto)
        if key not in seen:
            seen.add(key)
            icon = "🏠" if scope == "LAN" else "🛰️"
            lines.append(f"{icon} `{port}/{proto}`  {scope}")

    # Docker registry ports
    try:
        _root = Path(__file__).resolve().parent.parent.parent
        if str(_root / "src") not in sys.path:
            sys.path.insert(0, str(_root / "src"))
        from integrations.docker import list_exposed
        for e in list_exposed():
            key = (e["host_port"], e["proto"])
            if key in seen:
                continue
            seen.add(key)
            src = e.get("src") or "any"
            lan = src not in ("any", "", None)
            icon  = "🏠" if lan else "🌍"
            label = "LAN" if lan else "public"
            lines.append(f"{icon} `{e['host_port']}/{e['proto']}`  {label}")
    except Exception:
        pass

    return lines if lines else ["none"]


# ── Main builder ──────────────────────────────────────────────────────────────

def _blocked_geo_summary() -> str:
    """Return '<N> blocked — top: 🇨🇳 CN (8)' or 'none' if block list is empty.
    
    Uses pre-calculated geoblock state to stay instant even with 10k+ IPs.
    """
    try:
        from integrations.geoblock import list_blocked
        from utils.analytics import country_flag, read_blocked_ips
        
        # Get total count from live nft (very fast)
        n = len(read_blocked_ips())
        if n == 0:
            return "none blocked"
            
        # Get country breakdown from state (instant)
        stats = list_blocked()
        if not stats:
            return f"{n} blocked"
            
        # Find top blocked country from our state
        top_cc = max(stats, key=stats.get)
        top_count = stats[top_cc]
        
        return f"{n} blocked — top: {country_flag(top_cc)} {top_cc} ({top_count})"
    except Exception:
        return "—"


def _killswitch_packets() -> str:
    """Return formatted total packet drop count, or '—' if counters not active."""
    try:
        from utils.analytics import total_drop_packets
        total = total_drop_packets()
        return f"{total:,} packets denied"
    except Exception:
        return "—"


def _weekly_summary() -> str:
    """Return two-line weekly auto-block trend string."""
    try:
        from utils.analytics import weekly_ban_counts
        this_week, last_week = weekly_ban_counts()
        trend = "📈" if this_week > last_week else ("📉" if this_week < last_week else "➡️")
        return f"    {trend}  This week: *{this_week}*  Last week: {last_week}"
    except Exception:
        return "    —"


def build_status_report(cfg_path: Optional[str] = None,
                        weekly: bool = False) -> str:
    """Return the full vertical dashboard as a single string.

    Parameters
    ----------
    cfg_path:
        Path to the INI config file.  Passed through to
        :class:`~daemons.watchdog.NftWatchdog`.
    weekly:
        When ``True``, append a weekly auto-block summary section.
    """
    # ── Gather health data ────────────────────────────────────────────────────
    try:
        _root = Path(__file__).resolve().parent.parent.parent
        if str(_root / "src") not in sys.path:
            sys.path.insert(0, str(_root / "src"))
        from daemons.watchdog import NftWatchdog
        report = NftWatchdog(config_path=cfg_path).health()
    except Exception as exc:
        report = {
            "status"         : "DEGRADED",
            "reason"         : str(exc),
            "vpn_ip"         : None,
            "handshake_age_s": None,
            "markers"        : "unknown",
            "nft_integrity"  : False,
        }

    overall      = report.get("status", "DEGRADED")
    vpn_ip       = report.get("vpn_ip") or "none"
    handshake    = report.get("handshake_age_s")
    markers      = report.get("markers", "unknown")
    nft_ok       = bool(report.get("nft_integrity", False))
    reason       = report.get("reason", "")

    # ── Derived booleans ──────────────────────────────────────────────────────
    vpn_up        = vpn_ip != "none"
    ks_active     = markers == "ok"
    handshake_ok  = handshake is not None and handshake < _HANDSHAKE_DEAD

    overall_icon  = _ok(overall == "HEALTHY")

    # ── Timestamp ─────────────────────────────────────────────────────────────
    now = datetime.now().strftime("%a, %d %b · %H:%M")

    # ── Services ──────────────────────────────────────────────────────────────
    wd_ok = _svc_status('nft-watchdog').startswith("🟢")
    ls_ok = _svc_status('nft-listener').startswith("🟢")
    sa_ok = _svc_status('nft-ssh-alert').startswith("🟢")

    health_line = f"{overall_icon} *{overall}*"
    if overall != "HEALTHY" and reason:
        health_line += f"\n`{reason}`"

    # ── Assemble ──────────────────────────────────────────────────────────────
    lines = [
        f"☀️ *Good Morning — Firewall Brief*",
        f"`{now}`",
        f"",
        health_line,
        f"",
        f"🌐 *Network*",
        f"• VPN: {_ok(vpn_up)} `{vpn_ip}`",
        f"• Handshake: {_fmt_age(handshake)}",
        f"",
        f"🔒 *Security*",
        f"• Killswitch: {_ok(ks_active)} {'Active' if ks_active else 'MISSING'}",
        f"• NFT rules: {_ok(nft_ok)} {'Intact' if nft_ok else 'ERROR'}",
        f"• Block list: {_blocked_geo_summary()}",
        f"• Denied: {_killswitch_packets()}",
        f"",
        f"🐳 *Docker*",
        f"• Runtime: {_docker_running()}",
        f"• Exposed ports:",
        *[f"  {line}" for line in _exposed_port_lines(cfg_path)],
        f"",
        f"⚙️ *Daemons*",
        f"• {'🟢' if wd_ok else '🔴'} Watchdog",
        f"• {'🟢' if ls_ok else '🔴'} Listener",
        f"• {'🟢' if sa_ok else '🔴'} SSH Alert",
        f"",
        f"🖥️ *System*",
        f"• CPU: {_cpu_load()}",
        f"• RAM: {_ram_usage()}",
        f"• Disk: {_disk_space()}",
    ]

    if weekly:
        lines += [
            f"",
            f"📊 *Weekly Auto-Blocks*",
            _weekly_summary(),
        ]

    return "\n".join(lines)
