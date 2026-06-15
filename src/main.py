"""
src/main.py — NFT Firewall command-line interface.

Wires together all modular components:
  core.rules          — pure ruleset generation
  core.state          — apply / backup / restore / set modifiers
  core.profiles       — named firewall profiles
  integrations.docker — Docker daemon hardening + expose registry
  daemons.watchdog    — WireGuard health monitor
  daemons.listener    — Keybase ChatOps bot
  daemons.ssh_alert   — SSH intrusion alerter
  utils.keybase       — shared Keybase notifications

Usage
-----
    sudo python3 src/main.py apply cosmos-vpn-secure
    sudo python3 src/main.py simulate cosmos-vpn-secure
    sudo python3 src/main.py docker-expose 8080 172.17.0.2 80
    sudo python3 src/main.py watchdog status
    python3 src/main.py profiles

Run ``python3 src/main.py --help`` for the full command reference.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# ── Project root & config paths ───────────────────────────────────────────────

_PROJECT_ROOT  = Path(__file__).resolve().parent.parent
_LOCAL_CONF    = _PROJECT_ROOT / "config" / "firewall.ini"
_ETC_CONF      = Path("/etc/nft-firewall/firewall.ini")
_SYSTEM_CONF   = Path("/etc/nft-watchdog.conf")
_MARKERS_FILE  = Path("/var/lib/nft-firewall/watchdog-markers.json")
_NFT_CONF      = Path("/etc/nftables.conf")
_PORT_LABEL_SECTION = "port_labels"
_PORT_LABEL_PREFIX = {
    "extra_ports": "vpn_tcp",
    "lan_allow_ports": "lan_tcp",
    "lan_allow_udp_ports": "lan_udp",
}
_DEFAULT_PORT_LABELS = {
    ("extra_ports", 80): "HTTP / reverse proxy",
    ("extra_ports", 443): "HTTPS / reverse proxy",
    ("lan_allow_ports", 80): "HTTP from LAN",
    ("lan_allow_ports", 443): "HTTPS from LAN",
    ("lan_allow_ports", 58473): "SSH from LAN",
    ("lan_allow_ports", 32400): "Plex from LAN",
    ("lan_allow_ports", 8096): "Jellyfin from LAN",
    ("lan_allow_udp_ports", 7359): "Jellyfin discovery",
}


# ── Config helpers ────────────────────────────────────────────────────────────

def _config_candidates() -> List[Path]:
    """Return config paths in precedence order for this execution context."""
    if _PROJECT_ROOT == Path("/opt/nft-firewall"):
        return [_ETC_CONF, _LOCAL_CONF, _SYSTEM_CONF]
    return [_LOCAL_CONF, _ETC_CONF, _SYSTEM_CONF]


def _active_config_path() -> Optional[Path]:
    """Return the first readable config path candidate, if any."""
    for path in _config_candidates():
        try:
            if path.exists():
                return path
        except OSError:
            # Handle cases where user lacks permission to stat the path
            continue
    return None


def _config_path_for_daemon() -> str:
    """Return the active config path as a string for daemon/report helpers."""
    return str(_active_config_path() or _SYSTEM_CONF)


def _load_config() -> configparser.ConfigParser:
    """Load INI config from the active nft-firewall config path."""
    cfg = configparser.ConfigParser()
    path = _active_config_path()
    if path is None:
        return cfg
    try:
        cfg.read(str(path))
    except (configparser.Error, OSError) as exc:
        _die(f"Cannot read config {path}: {exc}")
    return cfg


def _build_ruleset_config(cfg: configparser.ConfigParser, profile_name: str):
    """Build a :class:`~core.rules.RulesetConfig` from INI config + profile.

    Reads the ``[network]`` section for topology values and overlays the
    named profile's policy flags.

    Parameters
    ----------
    cfg:
        Loaded :class:`configparser.ConfigParser`.
    profile_name:
        Name of a profile from :mod:`core.profiles`.

    Returns
    -------
    core.rules.RulesetConfig

    Raises
    ------
    KeyError
        If *profile_name* is unknown.
    SystemExit
        If ``phy_if`` is not set in the config (required field).
    """
    from core.profiles import get_profile
    from core.rules import RulesetConfig
    from core import state
    from integrations.docker import detect_bridge_networks

    profile = get_profile(profile_name)

    phy_if = cfg.get("network", "phy_if", fallback="").strip()
    if not phy_if:
        _die("'phy_if' must be set in [network] section of config — "
             "e.g. phy_if = eth0")

    extra_raw = cfg.get("network", "extra_ports", fallback="").strip()
    extra_ports: List[int] = (
        [_parse_int(p.strip(), "extra_ports") for p in extra_raw.split(",") if p.strip()]
        if extra_raw else []
    )

    torrent_raw = cfg.get("network", "torrent_port", fallback="").strip()
    torrent_port: Optional[int] = _parse_int(torrent_raw, "torrent_port") if torrent_raw else None

    from utils.validation import validate_port

    lan_full_access = cfg.getboolean("network", "lan_full_access", fallback=False)
    lan_allow_raw = cfg.get("network", "lan_allow_ports", fallback="").strip()
    lan_allow_ports: List[int] = []
    if lan_allow_raw:
        lan_allow_ports = [
            validate_port(p.strip(), "lan_allow_ports")
            for p in lan_allow_raw.replace(";", ",").split(",")
            if p.strip()
        ]

    lan_allow_udp_raw = cfg.get("network", "lan_allow_udp_ports", fallback="").strip()
    lan_allow_udp_ports: List[int] = []
    if lan_allow_udp_raw:
        lan_allow_udp_ports = [
            validate_port(p.strip(), "lan_allow_udp_ports")
            for p in lan_allow_udp_raw.replace(";", ",").split(",")
            if p.strip()
        ]

    cosmos_enabled = cfg.getboolean("cosmos", "enabled", fallback=profile.cosmos_enabled)
    cosmos_ports_raw = cfg.get("cosmos", "public_ports", fallback="").strip()
    cosmos_public_ports: List[int] = []
    if cosmos_enabled and cosmos_ports_raw:
        cosmos_public_ports = [
            validate_port(p.strip(), "cosmos.public_ports")
            for p in cosmos_ports_raw.replace(";", ",").split(",")
            if p.strip()
        ]

    container_supernet = cfg.get("network", "container_supernet", fallback="172.16.0.0/12")
    dynamic_sets = state.merge_live_sets_into_persistent()
    docker_networks = detect_bridge_networks(container_supernet)

    conf = RulesetConfig(
        phy_if             = phy_if,
        vpn_interface      = cfg.get("network", "vpn_interface",      fallback="wg0"),
        vpn_server_ip      = cfg.get("network", "vpn_server_ip",      fallback=""),
        vpn_server_port    = cfg.get("network", "vpn_server_port",    fallback=""),
        lan_net            = cfg.get("network", "lan_net",            fallback="192.168.1.0/24"),
        lan_full_access    = lan_full_access,
        lan_allow_ports    = lan_allow_ports,
        lan_allow_udp_ports = lan_allow_udp_ports,
        container_supernet = container_supernet,
        docker_networks    = docker_networks,
        ssh_port           = _parse_int(cfg.get("network", "ssh_port", fallback="22"), "ssh_port"),
        torrent_port       = torrent_port,
        extra_ports        = extra_ports,
        cosmos_tcp         = list(profile.cosmos_tcp),
        cosmos_udp         = list(profile.cosmos_udp),
        cosmos_public_ports = cosmos_public_ports,
        allow_plex_lan     = profile.allow_plex_lan,
        blocked_ips        = dynamic_sets.get(state.SET_BLOCKED, []),
        trusted_ips        = dynamic_sets.get(state.SET_TRUSTED, []),
        geowhitelist_ips   = dynamic_sets.get(state.SET_WHITELIST, []),
        dk_ips             = dynamic_sets.get(state.SET_DK, []),
    )

    # RUNTIME VALIDATION: Ensure interfaces actually exist when NOT in preflight/install mode
    if not os.environ.get("NFT_FIREWALL_NO_VALIDATE_IF"):
        from core.rules import validate_interface_exists
        validate_interface_exists(conf.phy_if)
        validate_interface_exists(conf.vpn_interface)

    return conf


def _write_watchdog_markers(ruleset_cfg) -> None:
    """Atomically write watchdog-markers.json after a successful apply.

    Uses write-to-tmp → fsync → os.replace so a power loss between steps
    never leaves a half-written or truncated JSON file on disk.
    """
    data = {
        "vpn_iface"  : ruleset_cfg.vpn_interface,
        "ip6_table"  : "killswitch",
        "main_table" : "firewall",
        "output_rule": 'comment "nft-killswitch-output"',
    }
    try:
        data["persisted_ruleset"] = {
            "path"      : str(_NFT_CONF),
            "sha256"    : hashlib.sha256(_NFT_CONF.read_bytes()).hexdigest(),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
    except OSError:
        # Backward-compatible: markers are still useful for live killswitch
        # checks even if the persisted file cannot be read during marker write.
        pass
    _MARKERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _MARKERS_FILE.with_suffix(".tmp")
    with tmp.open("w") as fh:
        fh.write(json.dumps(data, indent=2))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, _MARKERS_FILE)
    _MARKERS_FILE.chmod(0o644)


def _die(msg: str) -> None:
    print(f"[error] {msg}", file=sys.stderr)
    _debug_log(f"FATAL: {msg}")
    sys.exit(1)


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


def _parse_int(value: str, key: str) -> int:
    """Parse *value* as an integer, raising ValueError with a clear message on failure."""
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"Config key '{key}' has non-integer value: {value!r}")


def _split_config_list(raw: str) -> list[str]:
    """Split comma/semicolon-separated config lists without changing ConfigParser."""
    return [item.strip() for item in raw.replace(";", ",").split(",") if item.strip()]


def _validate_config_sanity(cfg: configparser.ConfigParser) -> list[tuple[str, str, str]]:
    """Return non-mutating config sanity issues as ``(status, key, detail)``.

    This is intentionally incremental: it validates values that are explicitly
    present in the INI file and leaves existing required-field behavior in
    ``_build_ruleset_config`` unchanged.
    """
    from utils.validation import parse_never_block, validate_ipv4_network, validate_port

    issues: list[tuple[str, str, str]] = []

    def add(status: str, key: str, detail: str) -> None:
        issues.append((status, key, detail))

    def option(section: str, key: str) -> str:
        return cfg.get(section, key, fallback="").strip()

    if cfg.has_section("network"):
        phy_if = option("network", "phy_if")
        vpn_if = option("network", "vpn_interface") or "wg0"
        if cfg.has_option("network", "phy_if") and not phy_if:
            add("fail", "network.phy_if", "must not be empty")
        if phy_if and vpn_if and phy_if == vpn_if:
            add("fail", "network.vpn_interface", "must differ from phy_if")

        for key in ("lan_net", "container_supernet"):
            raw = option("network", key)
            if raw:
                result = validate_ipv4_network(raw)
                if not result.ok:
                    add("fail", f"network.{key}", result.reason)

        vpn_ip = option("network", "vpn_server_ip")
        if vpn_ip:
            result = validate_ipv4_network(vpn_ip, allow_network=False)
            if not result.ok:
                add("fail", "network.vpn_server_ip", result.reason)

        for key in ("ssh_port", "torrent_port", "vpn_server_port"):
            raw = option("network", key)
            if raw:
                try:
                    validate_port(raw, f"network.{key}")
                except ValueError as exc:
                    add("fail", f"network.{key}", str(exc))

        for key in ("extra_ports", "lan_allow_ports", "lan_allow_udp_ports"):
            raw = option("network", key)
            for item in _split_config_list(raw):
                try:
                    validate_port(item, f"network.{key}")
                except ValueError as exc:
                    add("fail", f"network.{key}", str(exc))

        if cfg.has_option("network", "lan_full_access"):
            try:
                cfg.getboolean("network", "lan_full_access")
            except ValueError as exc:
                add("fail", "network.lan_full_access", str(exc))

    if cfg.has_section("cosmos"):
        if cfg.has_option("cosmos", "enabled"):
            try:
                cfg.getboolean("cosmos", "enabled")
            except ValueError as exc:
                add("fail", "cosmos.enabled", str(exc))
        for item in _split_config_list(option("cosmos", "public_ports")):
            try:
                validate_port(item, "cosmos.public_ports")
            except ValueError as exc:
                add("fail", "cosmos.public_ports", str(exc))

    for section, key in (
        ("watchdog", "check_interval"),
        ("watchdog", "recovery_wait"),
        ("watchdog", "recovery_retry_interval"),
        ("watchdog", "traffic_stall_timeout"),
        ("vpn", "handshake_timeout"),
        ("listener", "poll_interval"),
    ):
        raw = option(section, key)
        if raw:
            try:
                value = int(raw)
            except ValueError:
                add("fail", f"{section}.{key}", f"must be an integer, got {raw!r}")
                continue
            if value <= 0:
                add("fail", f"{section}.{key}", f"must be positive, got {value}")

    daily_hour = option("watchdog", "daily_summary_hour")
    if daily_hour:
        try:
            value = int(daily_hour)
        except ValueError:
            add("fail", "watchdog.daily_summary_hour", f"must be an integer, got {daily_hour!r}")
        else:
            if not -1 <= value <= 23:
                add("fail", "watchdog.daily_summary_hour", f"must be -1..23, got {value}")

    if cfg.has_section("threatfeed") and cfg.has_option("threatfeed", "enabled"):
        try:
            cfg.getboolean("threatfeed", "enabled")
        except ValueError as exc:
            add("fail", "threatfeed.enabled", str(exc))

    never_block = option("safety", "never_block")
    if never_block:
        try:
            parse_never_block(never_block)
        except ValueError as exc:
            add("warn", "safety.never_block", str(exc))

    return issues


def _read_port_list(cfg: configparser.ConfigParser, key: str) -> list[int]:
    """Read and validate one [network] port list from config."""
    from utils.validation import validate_port

    raw = cfg.get("network", key, fallback="").strip()
    ports = {validate_port(item, f"network.{key}") for item in _split_config_list(raw)}
    return sorted(ports)


def _write_config_atomic(path: Path, cfg: configparser.ConfigParser) -> None:
    """Write INI config atomically while preserving the existing file mode."""
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o640
    tmp = path.with_name(f".{path.name}.tmp")
    with tmp.open("w") as fh:
        cfg.write(fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _port_label_key(key: str, port: int | str) -> str:
    from utils.validation import validate_port

    prefix = _PORT_LABEL_PREFIX.get(key)
    if prefix is None:
        raise ValueError(f"unsupported port list: {key}")
    return f"{prefix}_{validate_port(port, 'port')}"


def _get_port_label(cfg: configparser.ConfigParser, key: str, port: int | str) -> str:
    from utils.validation import validate_port

    port_num = validate_port(port, "port")
    label_key = _port_label_key(key, port_num)
    configured = cfg.get(_PORT_LABEL_SECTION, label_key, fallback="").strip()
    if configured:
        return configured
    return _DEFAULT_PORT_LABELS.get((key, port_num), "")


def _set_port_label(cfg: configparser.ConfigParser, key: str, port: int | str, description: str) -> bool:
    """Set or clear a port description. Returns True when config changes."""
    label_key = _port_label_key(key, port)
    clean = " ".join((description or "").split())
    old = cfg.get(_PORT_LABEL_SECTION, label_key, fallback="").strip()

    if clean:
        if not cfg.has_section(_PORT_LABEL_SECTION):
            cfg.add_section(_PORT_LABEL_SECTION)
        if old == clean:
            return False
        cfg.set(_PORT_LABEL_SECTION, label_key, clean)
        return True

    if cfg.has_section(_PORT_LABEL_SECTION) and cfg.has_option(_PORT_LABEL_SECTION, label_key):
        cfg.remove_option(_PORT_LABEL_SECTION, label_key)
        if not list(cfg.items(_PORT_LABEL_SECTION)):
            cfg.remove_section(_PORT_LABEL_SECTION)
        return True

    return False


def _format_port_lines(cfg: configparser.ConfigParser, key: str) -> list[str]:
    """Return one display line per configured port with optional description."""
    lines: list[str] = []
    for port in _read_port_list(cfg, key):
        description = _get_port_label(cfg, key, port)
        suffix = f" — {description}" if description else ""
        lines.append(f"`{port}`{suffix}")
    return lines or ["none"]


def _change_config_port(
    path: Path,
    key: str,
    port: int | str,
    *,
    open_port: bool,
    description: str = "",
) -> tuple[bool, list[int]]:
    """Add or remove a port from one [network] config list.

    Returns ``(changed, new_ports)``.
    """
    from utils.validation import validate_port

    valid_keys = {"extra_ports", "lan_allow_ports", "lan_allow_udp_ports"}
    if key not in valid_keys:
        raise ValueError(f"unsupported port list: {key}")

    port = validate_port(port, "port")
    cfg = configparser.ConfigParser()
    if path.exists():
        cfg.read(str(path))
    if not cfg.has_section("network"):
        cfg.add_section("network")

    ports = set(_read_port_list(cfg, key))
    before = set(ports)
    if open_port:
        ports.add(port)
    else:
        ports.discard(port)

    changed = ports != before
    if open_port and description.strip():
        changed = _set_port_label(cfg, key, port, description) or changed
    if not open_port:
        changed = _set_port_label(cfg, key, port, "") or changed

    if changed:
        cfg.set("network", key, ", ".join(str(p) for p in sorted(ports)))
        _write_config_atomic(path, cfg)

    return changed, sorted(ports)


def _format_port_list(ports: list[int]) -> str:
    return ", ".join(str(p) for p in ports) if ports else "none"


def _port_change_notification(
    *,
    port: int | str,
    label: str,
    open_port: bool,
    profile: str,
    cfg_path: Path,
    key: str,
    description: str = "",
) -> tuple[str, str, str, str]:
    """Build a Keybase notification for a confirmed live port change."""
    from utils.validation import validate_port

    port_num = validate_port(port, "port")
    action = "Opened" if open_port else "Closed"
    title = f"{action} firewall access"
    tags = "ports,warning,shield" if open_port else "ports,shield"
    priority = "high" if open_port else "default"
    service = description or "not labeled"
    body_lines = [
        f"*{action}* `{port_num}` for *{label}*",
        "",
        f"Service: {service}",
        f"Profile: `{profile}`",
        f"Config: `network.{key}`",
        "",
        "✅ Safe apply confirmed",
        "Live rules and `/etc/nftables.conf` were updated.",
        f"`{cfg_path}`",
    ]
    body = "\n".join(body_lines)
    return title, body, tags, priority


def _notify_port_change(
    *,
    port: int | str,
    label: str,
    open_port: bool,
    profile: str,
    cfg_path: Path,
    key: str,
    description: str = "",
) -> bool:
    """Send a best-effort Keybase alert for a confirmed port change."""
    from utils.keybase import notify

    title, body, tags, priority = _port_change_notification(
        port=port,
        label=label,
        open_port=open_port,
        profile=profile,
        cfg_path=cfg_path,
        key=key,
        description=description,
    )
    return notify(title=title, body=body, tags=tags, priority=priority)


def _nftables_service_status() -> tuple[str, str]:
    """Return doctor status for nftables.service boot persistence."""
    import shutil
    import subprocess

    if shutil.which("systemctl") is None:
        return ("warn", "systemctl not found; cannot verify nftables.service enablement")
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", "nftables.service"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        return ("warn", f"cannot verify nftables.service enablement: {exc}")

    state = (result.stdout or result.stderr).strip() or f"rc={result.returncode}"
    if result.returncode == 0 and state in {"enabled", "enabled-runtime", "static"}:
        return ("ok", f"nftables.service is {state}")
    return ("fail", f"nftables.service is not enabled ({state})")


def _ruleset_has_broad_zero(ruleset: str) -> bool:
    """Return True if generated nft syntax contains the IPv4 default route."""
    return "0.0.0.0/0" in ruleset


def _physical_public_web_lines(ruleset: str, phy_if: str, lan_net: str = "") -> list[str]:
    """Return physical-interface rules that publicly expose TCP 80/443."""
    import re

    marker = f'iifname "{phy_if}"'
    matches: list[str] = []
    for line in ruleset.splitlines():
        stripped = line.strip()
        if marker not in stripped or "tcp dport" not in stripped:
            continue
        port_match = re.search(r"tcp dport\s+(\{[^}]+\}|\d+)", stripped)
        if not port_match:
            continue
        ports = {int(p) for p in re.findall(r"\d+", port_match.group(1))}
        if not ({80, 443} & ports):
            continue
        if " accept" not in stripped and " dnat " not in stripped:
            continue
        if lan_net and f"ip saddr {lan_net}" in stripped:
            continue
        if (
            "ip saddr @geowhitelist_ips" in stripped
            or "ip saddr @trusted_ips" in stripped
            or "ip saddr @dk_ips" in stripped
        ):
            continue
        matches.append(stripped)
    return matches


def _extract_chain_bodies(text: str) -> list[tuple[str, str]]:
    """Return ``[(chain_name, body), ...]`` from an nft ruleset string.

    Walks the text and uses brace-depth accounting so set literals inside a
    chain body (``tcp dport { 80, 443 }``) and set-definition blocks
    (``set blocked_ips { … elements = { … } }``) do not truncate the chain.
    A naive ``chain ... { (.*?) }`` regex stops at the first ``}`` and misses
    any rule that follows a nested ``{ … }`` — that is exactly the
    false-negative this parser fixes.
    """
    import re

    results: list[tuple[str, str]] = []
    pattern = re.compile(r'\bchain\s+(\w+)\s*\{', re.IGNORECASE)
    pos = 0
    while True:
        m = pattern.search(text, pos)
        if not m:
            break
        name = m.group(1)
        depth = 1
        i = m.end()  # position just after the opening '{'
        body_start = i
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth == 0 and i < len(text):
            results.append((name, text[body_start:i]))
            pos = i + 1
        else:
            # Unbalanced — bail to avoid an infinite loop on malformed input.
            break
    return results


def _check_live_rules_invariants(ruleset: str, phy_if: str, vpn_if: str, lan_net: str = "") -> list[str]:
    """Analyze a ruleset string for broad/unconditional accept rules.

    Returns a list of violation strings, or [] if clean.
    """
    import re
    violations = []

    # 1. Clean the ruleset (strip # comments) but PRESERVE newlines
    clean = re.sub(r'#.*$', '', ruleset, flags=re.MULTILINE)

    # 2. Isolate chains using a brace-depth-aware extractor (regex would
    #    truncate at the first '}' from any nested set literal).
    for chain_name_raw, body in _extract_chain_bodies(clean):
        chain_name = chain_name_raw.lower()

        # Split into individual rules. nft separates rules by newlines (or
        # semicolons within a single line). A rule may itself contain a
        # `{ a, b }` set literal — collapse those before splitting so the
        # set's commas don't get treated as rule separators.
        body_collapsed = re.sub(r'\{[^{}]*\}', lambda m: m.group(0).replace('\n', ' '), body)
        rules = [r.strip() for r in re.split(r'[;\n]', body_collapsed) if r.strip()]
        
        for rule in rules:
            if rule.startswith("type ") or rule.startswith("policy "):
                continue
                
            rule_lower = rule.lower()
            if "accept" in rule_lower:
                # --- OUTPUT Chain Invariants ---
                if chain_name == "output":
                    if rule_lower == "accept":
                        violations.append("output chain contains a standalone 'accept' rule")
                        continue
                        
                    # Accept must be restricted to safe paths
                    is_safe = (
                        f'oifname "{vpn_if}"' in rule_lower or
                        'oifname "lo"' in rule_lower or
                        'iifname "lo"' in rule_lower or
                        'meta mark 0x' in rule_lower or  # WireGuard bootstrap
                        # DHCP client rule: oifname phy_if udp sport 68 dport 67 accept
                        (f'oifname "{phy_if}"' in rule_lower and 'sport 68' in rule_lower and 'dport 67' in rule_lower) or
                        # LAN destination allow: oifname phy_if ip daddr lan_net accept
                        (lan_net and f'oifname "{phy_if}"' in rule_lower and f'ip daddr {lan_net}' in rule_lower) or
                        # Docker bridge-local destination: meta oifkind "bridge" ip daddr @docker_nets accept
                        ('meta oifkind "bridge"' in rule_lower and 'ip daddr @docker_nets' in rule_lower)
                    )
                    if not is_safe:
                        violations.append(f"output chain contains a potentially broad 'accept' rule: {rule}")

                # --- FORWARD Chain Invariants ---
                elif chain_name == "forward":
                    if "ip saddr @docker_nets" in rule_lower and f'oifname "{phy_if}"' in rule_lower:
                        if "ip daddr" not in rule_lower:
                            violations.append(f"forwarding allows @docker_nets to escape via {phy_if}: {rule}")

                # --- INPUT Chain Invariants ---
                elif chain_name == "input":
                    if f'iifname "{phy_if}"' in rule_lower:
                        if re.search(r'tcp\s+dport\s+({[^}]*?\b(80|443)\b[^}]*?}|(\b(80|443)\b))', rule_lower):
                            source_restricted = (
                                (lan_net and f"ip saddr {lan_net}" in rule_lower)
                                or "ip saddr @geowhitelist_ips" in rule_lower
                                or "ip saddr @trusted_ips" in rule_lower
                                or "ip saddr @dk_ips" in rule_lower
                            )
                            if source_restricted:
                                continue
                            violations.append(f"public port exposure on {phy_if}: {rule}")

    return violations


def _never_block_from_config(cfg: configparser.ConfigParser) -> List[str]:
    """Return configured never-block CIDRs, always including the LAN subnet."""
    from utils.validation import parse_never_block

    raw = cfg.get("safety", "never_block", fallback="")
    guards = parse_never_block(raw)
    lan_net = cfg.get("network", "lan_net", fallback="").strip()
    if lan_net:
        try:
            guards.extend(parse_never_block([lan_net]))
        except ValueError:
            pass
    return sorted(set(guards))


def _reapply_geoblocks() -> None:
    """Best-effort geoblock reapply after a full ruleset reload."""
    try:
        _gcfg = _load_config()
        _geo_countries = [c.strip() for c in
                          _gcfg.get("geoblock", "blocked_countries", fallback="").split()
                          if c.strip()]
        if _geo_countries:
            from integrations.geoblock import reblock_from_config
            reblock_from_config(_geo_countries)
    except Exception as _ge:
        print(f"[warn] geoblock reblock_from_config failed (non-fatal): {_ge}",
              file=sys.stderr)


# ── Command handlers ──────────────────────────────────────────────────────────

def _cmd_apply(args: argparse.Namespace) -> bool:
    """apply <profile> [--dry-run] [--safe]"""
    import select
    from core.rules import generate_ruleset
    from core import state
    from integrations.docker import load_registry

    cfg = _load_config()
    try:
        ruleset_cfg = _build_ruleset_config(cfg, args.profile)
    except (KeyError, ValueError) as exc:
        _die(str(exc))

    exposed = load_registry()
    ruleset = generate_ruleset(ruleset_cfg, exposed_ports=exposed)

    if args.dry_run:
        print(ruleset)
        return False

    # Always simulate before touching the live ruleset
    ok, err = state.simulate_apply(ruleset)
    if not ok:
        _die(f"Ruleset syntax error (nft --check):\n{err}")

    try:
        backup_path = state.backup_ruleset()
    except (OSError, RuntimeError) as exc:
        _die(f"Backup failed — aborting apply: {exc}")

    try:
        state.apply_ruleset(ruleset)
        state.save_conf(ruleset)
    except RuntimeError as exc:
        print(f"[error] Apply failed: {exc}", file=sys.stderr)
        print("[error] Attempting rollback ...", file=sys.stderr)
        if backup_path is not None:
            try:
                state.restore_ruleset(backup_path)
                print("[ok] Rollback succeeded.", file=sys.stderr)
            except RuntimeError as rb_exc:
                print(f"[error] Rollback also failed: {rb_exc}", file=sys.stderr)
        else:
            print("[error] No backup path available — manual intervention required.",
                  file=sys.stderr)
        sys.exit(1)

    if args.safe:
        print("\n--- ⚠️  SAFE MODE ---")
        print("  Type CONFIRM within 60s to keep these rules.")
        print("  No input → previous ruleset is restored.\n")
        try:
            ready, _, _ = select.select([sys.stdin], [], [], 60)
            confirmed = ready and sys.stdin.readline().strip() == "CONFIRM"
        except (EOFError, OSError, KeyboardInterrupt):
            confirmed = False

        if confirmed:
            print("[ok] CONFIRMED — new rules are now permanent.")
            _write_watchdog_markers(ruleset_cfg)
            _reapply_geoblocks()
            return True
        else:
            print("[warn] Not confirmed — rolling back ...", file=sys.stderr)
            if backup_path is not None:
                try:
                    state.restore_ruleset(backup_path)
                    print("[ok] Rollback complete.")
                    return False
                except RuntimeError as exc:
                    _die(f"Rollback failed: {exc}")
            else:
                _die("No backup path available — manual intervention required.")
    else:
        _write_watchdog_markers(ruleset_cfg)
        _reapply_geoblocks()
        return True


def _cmd_safe_apply(args: argparse.Namespace) -> bool:
    """safe-apply <profile> — apply with mandatory rollback confirmation."""
    args.safe = True
    args.dry_run = False
    return _cmd_apply(args)


def _cmd_simulate(args: argparse.Namespace) -> None:
    """simulate <profile> — validate syntax with nft --check, never apply."""
    from core.rules import generate_ruleset
    from core import state
    from integrations.docker import load_registry

    cfg = _load_config()
    try:
        ruleset_cfg = _build_ruleset_config(cfg, args.profile)
    except (KeyError, ValueError) as exc:
        _die(str(exc))

    exposed = load_registry()
    ruleset = generate_ruleset(ruleset_cfg, exposed_ports=exposed)

    ok, err = state.simulate_apply(ruleset)
    if ok:
        print(f"[ok] Ruleset for profile '{args.profile}' is valid (nft --check passed).")
    else:
        print(f"[error] Ruleset syntax error:\n{err}", file=sys.stderr)
        sys.exit(1)


def _cmd_backup(_args: argparse.Namespace) -> None:
    from core import state
    state.backup_ruleset()


def _cmd_restore(args: argparse.Namespace) -> None:
    from core import state
    backup = Path(args.file) if getattr(args, "file", None) else None
    try:
        state.restore_ruleset(backup)
    except RuntimeError as exc:
        _die(str(exc))


def _cmd_block(args: argparse.Namespace) -> None:
    from utils.validation import validate_block_target
    cfg = _load_config()
    result = validate_block_target(args.ip, never_block=_never_block_from_config(cfg))
    if not result.ok:
        _die(result.reason)
    from core.state import block_ip
    if block_ip(result.value, never_block=_never_block_from_config(cfg)):
        print(f"[ok] Blocked {result.value}")
    else:
        _die(f"Failed to block {result.value} — is the ruleset loaded?")


def _cmd_unblock(args: argparse.Namespace) -> None:
    from core.state import unblock_ip
    if unblock_ip(args.ip):
        print(f"[ok] Unblocked {args.ip}")
    else:
        _die(f"{args.ip} not found in blocked_ips set.")


def _cmd_threat_update(_args: argparse.Namespace) -> None:
    """threat-update — sync threat feed IPs into blocked_ips set."""
    from integrations.threatfeed import sync, _load_config as _tf_cfg
    url, max_entries, enabled = _tf_cfg()
    if not enabled:
        print("[threatfeed] disabled in config — skipping")
        return
    added, removed = sync(url=url, max_entries=max_entries)
    print(f"[threatfeed] sync complete: +{added} added, -{removed} removed")


def _cmd_metrics_update(_args: argparse.Namespace) -> None:
    """metrics-update — write Prometheus textfile metrics snapshot."""
    from utils.metrics import metrics_update
    cfg   = _load_config()
    iface = cfg.get("network", "vpn_interface", fallback="wg0")
    metrics_update(iface=iface)
    print("[metrics] metrics.prom updated")


def _cmd_geoblock(args: argparse.Namespace) -> None:
    """geoblock <CC...> — download and block all CIDRs for given country codes."""
    from integrations.geoblock import block_country
    for cc in args.country_codes:
        blocked, skipped = block_country(cc.upper())
        print(f"[geoblock] {cc.upper()}: +{blocked} CIDRs blocked, {skipped} skipped")


def _cmd_geoblock_test(_args: argparse.Namespace) -> None:
    """geoblock-test — validate that blocked countries are actually dropped."""
    from integrations.geoblock import geotest
    geotest()


def _cmd_geounblock(args: argparse.Namespace) -> None:
    """geounblock <CC> — remove all CIDRs blocked for a country."""
    from integrations.geoblock import unblock_country
    removed = unblock_country(args.country_code.upper())
    print(f"[geounblock] {args.country_code.upper()}: {removed} CIDRs removed")


def _cmd_geolist(_args: argparse.Namespace) -> None:
    """geolist — show blocked countries and CIDR counts."""
    from integrations.geoblock import list_blocked
    blocked = list_blocked()
    if not blocked:
        print("  No countries currently geo-blocked.")
    else:
        print(f"  {'Country':<10} {'CIDRs':>6}")
        print("  " + "─" * 17)
        for cc, count in sorted(blocked.items()):
            print(f"  {cc:<10} {count:>6}")


def _cmd_geoblock_status(_args: argparse.Namespace) -> None:
    """geoblock-status — technical details of the geoblock integration."""
    from integrations.geoblock import get_status
    import time

    s = get_status()
    print("  \033[1mGeo-Block Integration Status\033[0m")
    print("  " + "─" * 40)
    print(f"  State file   : {s['state_file']}")
    print(f"  Cache dir    : {s['cache_dir']}")
    print(f"  Blocked      : {len(s['blocked_countries'])} countries ({s['total_cidrs']} CIDRs)")
    print(f"  Cache count  : {s['cache_count']} files")

    age = s['newest_cache_age_seconds']
    if age is None:
        age_str = "never"
    elif age < 60:
        age_str = f"{int(age)}s ago"
    elif age < 3600:
        age_str = f"{int(age//60)}m ago"
    else:
        age_str = f"{int(age//3600)}h ago"
    print(f"  Newest cache : {age_str}")


def _cmd_set_stats(_args: argparse.Namespace) -> None:
    """set-stats — show element counts for dynamic nftables sets."""
    from core import state

    sets = {
        "Blocked IPs":     state.SET_BLOCKED,
        "Trusted IPs":     state.SET_TRUSTED,
        "Geo Whitelist":   state.SET_WHITELIST,
        "Knockd IPs":      state.SET_DK,
    }

    print(f"  {'Set Name':<15} {'Elements':>10}")
    print("  " + "─" * 26)

    for label, set_name in sets.items():
        # Using set_list with persistent_fallback=False gets live counts
        count = len(state.set_list(set_name, persistent_fallback=False))
        print(f"  {label:<15} {count:>10}")

    print()


def _cmd_knockd(args: argparse.Namespace) -> None:
    """knockd daemon — run the port-knock listener."""
    from daemons.knockd import PortKnockDaemon
    cfg_path = _config_path_for_daemon()
    if args.knockd_cmd == "daemon":
        PortKnockDaemon(config_path=cfg_path).run_daemon()
    else:
        _die(f"Unknown knockd subcommand: {args.knockd_cmd!r}")


def _cmd_allow(args: argparse.Namespace) -> None:
    from utils.validation import validate_trusted_target
    result = validate_trusted_target(args.ip)
    if not result.ok:
        _die(result.reason)
    from core.state import allow_ip
    if allow_ip(result.value):
        print(f"[ok] Trusted {result.value} (SSH override)")
    else:
        _die(f"Failed to add {result.value} — is the ruleset loaded?")


def _cmd_disallow(args: argparse.Namespace) -> None:
    from core.state import disallow_ip
    if disallow_ip(args.ip):
        print(f"[ok] Removed {args.ip} from trusted set.")
    else:
        _die(f"{args.ip} not found in trusted_ips set.")


def _cmd_ip_list(_args: argparse.Namespace) -> None:
    from core.state import set_list, SET_BLOCKED, SET_TRUSTED
    for label, set_name in [("Trusted IPs (SSH override)", SET_TRUSTED),
                             ("Blocked IPs",               SET_BLOCKED)]:
        entries = set_list(set_name)
        print(f"\n  {label}  ({set_name})")
        if entries:
            for e in entries:
                print(f"    • {e}")
        else:
            print("    (empty)")
    print()


def _cmd_docker_expose(args: argparse.Namespace) -> None:
    from integrations.docker import add_expose, detect_bridge_networks
    cfg = _load_config()
    container_supernet = cfg.get("network", "container_supernet", fallback="172.16.0.0/12")
    docker_networks = detect_bridge_networks(container_supernet)
    try:
        add_expose(
            host_port      = args.host_port,
            container_ip   = args.container_ip,
            container_port = args.container_port,
            proto          = args.proto,
            src            = getattr(args, "src", None),
            allowed_networks = docker_networks,
        )
    except ValueError as exc:
        _die(str(exc))


def _cmd_docker_unexpose(args: argparse.Namespace) -> None:
    from integrations.docker import remove_expose
    remove_expose(args.host_port, args.proto)


def _cmd_list_exposed(_args: argparse.Namespace) -> None:
    from integrations.docker import list_exposed
    entries = list_exposed()
    if not entries:
        print("  No ports currently exposed.")
        return
    print(f"\n  {'HOST PORT':<12} {'PROTO':<6} {'SRC RESTRICT':<20} {'CONTAINER DEST'}")
    print(f"  {'-'*11:<12} {'-'*5:<6} {'-'*19:<20} {'-'*25}")
    for e in entries:
        src = e.get("src", "any")
        print(f"  {e['host_port']:<12} {e['proto']:<6} {src:<20} "
              f"{e['container_ip']}:{e['container_port']}")
    print()


def _cmd_profiles(_args: argparse.Namespace) -> None:
    from core.profiles import list_profiles
    print("\n  Available firewall profiles:\n")
    for name, profile in sorted(list_profiles().items()):
        tcp  = ", ".join(map(str, profile.cosmos_tcp))  or "none"
        udp  = ", ".join(map(str, profile.cosmos_udp))  or "none"
        plex = "yes" if profile.allow_plex_lan else "no"
        print(f"  {name}")
        print(f"    {profile.description}")
        print(f"    cosmos_tcp={tcp}  cosmos_udp={udp}  plex_lan={plex}")
        print()


def _cmd_rules(args: argparse.Namespace) -> None:
    import subprocess
    import re
    try:
        result = subprocess.run(["nft", "list", "ruleset"],
                                capture_output=True, text=True)
    except OSError as exc:
        _die(f"Failed to run 'nft': {exc}")
    if result.returncode == 0:
        out = result.stdout
        if args.no_sets:
            # Strip large elements = { ... } blocks
            # We match 'elements = { ... }' non-greedily across multiple lines
            out = re.sub(r'elements\s*=\s*\{.*?\}', 'elements = { ... }', out, flags=re.DOTALL)
        print(out)
    else:
        _die(f"nft list ruleset failed: {result.stderr.strip()}")


def _cmd_doctor(args: argparse.Namespace) -> None:
    """doctor — non-mutating safety checks for config and generated ruleset."""
    from core.rules import generate_ruleset
    from core import state
    from integrations.docker import firewall_policy_status, load_registry

    nft_wrapper = Path("/usr/local/lib/nft-firewall/fw-nft")
    profile = getattr(args, "profile", None)
    cfg = _load_config()
    if not profile:
        profile = cfg.get("install", "profile", fallback="cosmos-vpn-secure")

    checks: list[tuple[str, str, str]] = []
    sanity_issues = _validate_config_sanity(cfg)
    if sanity_issues:
        sanity_status = "fail" if any(status == "fail" for status, _, _ in sanity_issues) else "warn"
        sanity_detail = "; ".join(
            f"{key}: {detail}" for _status, key, detail in sanity_issues
        )
        checks.append(("config sanity", sanity_status, sanity_detail))
    else:
        checks.append(("config sanity", "ok", "explicit config values parse cleanly"))

    try:
        ruleset_cfg = _build_ruleset_config(cfg, profile)
        checks.append(("config", "ok", f"profile={profile} phy_if={ruleset_cfg.phy_if} vpn={ruleset_cfg.vpn_interface}"))
    except (KeyError, ValueError, SystemExit) as exc:
        checks.append(("config", "fail", str(exc)))
        ruleset_cfg = None

    if ruleset_cfg is not None:
        exposed = load_registry()
        ruleset = generate_ruleset(ruleset_cfg, exposed_ports=exposed)
        docker_status, docker_detail = firewall_policy_status()
        checks.append(("docker firewall authority", docker_status, docker_detail))
        checks.append(("nftables.service", *_nftables_service_status()))
        broad_zero = _ruleset_has_broad_zero(ruleset)
        checks.append((
            "broad /0 generated rules",
            "fail" if broad_zero else "ok",
            "0.0.0.0/0 present in generated ruleset" if broad_zero else "no IPv4 /0 generated",
        ))
        public_phy = _physical_public_web_lines(
            ruleset,
            ruleset_cfg.phy_if,
            getattr(ruleset_cfg, "lan_net", ""),
        )
        checks.append((
            "physical public 80/443",
            "fail" if public_phy else "ok",
            "; ".join(public_phy) if public_phy else "no public web accept on physical interface",
        ))
        if os.geteuid() == 0:
            ok, err = state.simulate_apply(ruleset)
            checks.append(("nft --check", "ok" if ok else "fail",
                           "ruleset syntax valid" if ok else err))
        elif nft_wrapper.exists():
            ok, err = state.simulate_apply(ruleset, nft_cmd=["sudo", str(nft_wrapper)])
            if ok:
                checks.append(("nft --check", "ok", "ruleset syntax valid"))
            elif _nft_check_permission_error(err):
                checks.append((
                    "nft --check",
                    "warn",
                    "nft --check requires installed sudo wrapper; "
                    "run setup.py install or run doctor as root",
                ))
            else:
                checks.append(("nft --check", "fail", err))
        else:
            checks.append((
                "nft --check",
                "warn",
                "nft --check requires installed sudo wrapper; "
                "run setup.py install or run doctor as root",
            ))
        checks.append(("killswitch marker",
                       "ok" if 'oifname "' + ruleset_cfg.vpn_interface + '" accept' in ruleset else "fail",
                       "OUTPUT VPN accept present"))
        checks.append(("ipv6 blackout",
                       "ok" if "table ip6 killswitch" in ruleset and "priority -300" in ruleset else "fail",
                       "ip6 killswitch priority -300 present"))

        # LIVE RULES CHECK
        # Try raw `nft list ruleset` first (works as root). If that fails — the
        # systemd doctor unit runs as fw-admin without CAP_NET_ADMIN — fall back
        # to the privileged wrapper, which is whitelisted for `list ruleset` only.
        live_rules: Optional[str] = None
        live_error: Optional[str] = None
        candidates: list[list[str]] = [["nft", "list", "ruleset"]]
        if nft_wrapper.exists():
            candidates.append(["sudo", "-n", str(nft_wrapper), "list", "ruleset"])
        for cmd in candidates:
            try:
                live_result = subprocess.run(
                    cmd, capture_output=True, text=True, check=False
                )
            except (subprocess.SubprocessError, OSError) as exc:
                live_error = str(exc)
                continue
            if live_result.returncode == 0 and live_result.stdout.strip():
                live_rules = live_result.stdout
                break
            live_error = (live_result.stderr or live_result.stdout or "").strip() \
                or f"rc={live_result.returncode}"

        if live_rules is not None:
            live_violations = _check_live_rules_invariants(
                live_rules,
                ruleset_cfg.phy_if,
                ruleset_cfg.vpn_interface,
                getattr(ruleset_cfg, "lan_net", ""),
            )
            checks.append((
                "live rules invariants",
                "ok" if not live_violations else "fail",
                "intact" if not live_violations else "; ".join(live_violations),
            ))
        else:
            checks.append((
                "live rules invariants",
                "warn",
                f"could not fetch live ruleset: {live_error or 'no output'}",
            ))

    persisted = state.load_persistent_sets()
    total = sum(len(v) for v in persisted.values())
    checks.append(("dynamic sets", "ok", f"{total} persisted member(s) across {len(persisted)} set(s)"))

    failed = False
    for name, status, detail in checks:
        label = f"[{status}]"
        print(f"{label} {name}: {detail}")
        failed = failed or status == "fail"
    sys.exit(1 if failed else 0)


def _nft_check_permission_error(message: str) -> bool:
    """Return True when nft --check failed because it was not privileged."""
    lowered = (message or "").lower()
    needles = (
        "operation not permitted",
        "a password is required",
        "a terminal is required",
        "not in the sudoers",
        "may not run sudo",
        "permission denied",
    )
    return any(needle in lowered for needle in needles)


def _cmd_logs(_args: argparse.Namespace) -> None:
    """logs — Real-time color-coded stream of firewall and VPN events."""
    print("📋 Streaming Firewall & VPN Events (Ctrl+C to stop)...")
    print("-" * 50)
    
    # We use a combined journalctl command with color-coded markers
    cmd = (
        "journalctl -u nft-watchdog -u nft-ssh-alert -u wg-quick@wg0 -f --no-pager -o cat | "
        "sed --unbuffered "
        r"-e 's/.*\[INFO\].*/\x1b[32m&\x1b[0m/' "
        r"-e 's/.*\[WARN\].*/\x1b[33m&\x1b[0m/' "
        r"-e 's/.*\[ERROR\].*/\x1b[31m&\x1b[0m/' "
        r"-e 's/.*\[DEBUG\].*/\x1b[36m&\x1b[0m/' "
        r"-e 's/.*handshake.*/\x1b[35m&\x1b[0m/'"
    )
    try:
        os.system(cmd)
    except KeyboardInterrupt:
        print("\nStopped.")


def _cmd_debug(_args: argparse.Namespace) -> None:
    """debug — exhaustive technical dump for AI diagnostics."""
    print("=== NFT Firewall Technical Debug Dump ===")
    print(f"Time: {datetime.now().isoformat()}")
    print(f"Python: {sys.version}")
    
    print("\n-- OS Release --")
    os.system("cat /etc/os-release | grep PRETTY")
    
    print("\n-- Interfaces --")
    os.system("ip -br addr")
    
    print("\n-- WireGuard Status --")
    os.system("sudo wg show 2>&1")
    
    print("\n-- Systemd Units --")
    for svc in ["nft-watchdog", "nft-listener", "nft-ssh-alert", "wg-quick@wg0"]:
        os.system(f"systemctl status {svc} --no-pager -n 0 2>&1 | grep -E 'Active:|Loaded:'")

    print("\n-- Docker Info --")
    os.system("docker version --format 'Client: {{.Client.Version}} Server: {{.Server.Version}}' 2>&1")
    os.system("docker ps -a --format '{{.Names}} [{{.Status}}]' 2>&1")
    
    print("\n-- Groups --")
    os.system("groups")
    
    print("\n-- Recent Watchdog Logs --")
    os.system("journalctl -u nft-watchdog -n 10 --no-pager 2>&1")

    print("\n-- Recent NFT Denies --")
    os.system("dmesg | grep 'nft-in-drop' | tail -n 5")
    print("==========================================")


def _cmd_health(_args: argparse.Namespace) -> None:
    from daemons.watchdog import NftWatchdog
    cfg_path = _config_path_for_daemon()
    report   = NftWatchdog(config_path=cfg_path).health()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["status"] == "HEALTHY" else 1)


def _cmd_status(_args: argparse.Namespace) -> None:
    """status — mobile-friendly vertical dashboard."""
    from utils.formatter import build_status_report
    cfg_path = _config_path_for_daemon()
    print(build_status_report(cfg_path))


def _cmd_firewall_report(args: argparse.Namespace) -> None:
    """firewall-report — build status report and send it to Keybase."""
    from utils.formatter import build_status_report
    from utils.keybase import notify

    cfg_path = _config_path_for_daemon()
    report   = build_status_report(cfg_path, weekly=getattr(args, "weekly", False))
    print(report)

    ok = notify(
        title    = "Good Morning — NFT Firewall Daily Report",
        body     = report,
        tags     = "shield",
        priority = "default",
    )
    if not ok:
        _die("Report built but Keybase notification failed — check [keybase] config.")


def _cmd_maintenance(_args: argparse.Namespace) -> None:
    """maintenance — prune old state backups and rotated project log files."""
    import time as _time

    cutoff    = _time.time() - 30 * 86_400   # 30 days ago
    state_dir = _PROJECT_ROOT / "state"
    removed   = 0

    # ── State backups older than 30 days ──────────────────────────────────────
    if state_dir.exists():
        for f in sorted(state_dir.iterdir()):
            if f.suffix == ".conf" and f.name.startswith("nftables_"):
                try:
                    if f.stat().st_mtime < cutoff:
                        f.unlink()
                        removed += 1
                        print(f"[maintenance] Removed old backup: {f.name}")
                except OSError as exc:
                    print(f"[warn] Could not remove {f.name}: {exc}")

    # ── Rotated log files in project tree ─────────────────────────────────────
    for pattern in ("*.log.1", "*.log.2", "*.log.gz", "*.log.*.gz"):
        for f in _PROJECT_ROOT.rglob(pattern):
            # Never touch anything outside the project directory
            try:
                f.relative_to(_PROJECT_ROOT)
            except ValueError:
                continue
            try:
                f.unlink()
                removed += 1
                print(f"[maintenance] Removed rotated log: {f.relative_to(_PROJECT_ROOT)}")
            except OSError as exc:
                print(f"[warn] Could not remove {f.relative_to(_PROJECT_ROOT)}: {exc}")

    if removed:
        print(f"[maintenance] Done — removed {removed} file(s).")
    else:
        print("[maintenance] Nothing to clean.")


def _cmd_keybase_test(_args: argparse.Namespace) -> None:
    from utils.keybase import notify
    ok = notify(
        title    = "NFT Firewall — test notification",
        body     = "If you see this, Keybase notifications are working correctly.",
        tags     = "white_check_mark",
        priority = "default",
    )
    if ok:
        print("[ok] Test notification sent.")
    else:
        _die("Notification failed — check Keybase config.")


def _cmd_listener(args: argparse.Namespace) -> None:
    from daemons.listener import KeybaseListener
    cfg_path = _config_path_for_daemon()
    if args.listener_cmd == "daemon":
        KeybaseListener(config_path=cfg_path).run_daemon()
    else:
        _die(f"Unknown listener subcommand: {args.listener_cmd!r}")


def _cmd_ssh_alert(args: argparse.Namespace) -> None:
    from daemons.ssh_alert import SshAlertDaemon
    cfg_path = _config_path_for_daemon()
    if args.ssh_alert_cmd == "daemon":
        SshAlertDaemon(config_path=cfg_path).run_daemon()
    else:
        _die(f"Unknown ssh-alert subcommand: {args.ssh_alert_cmd!r}")


def _cmd_watchdog(args: argparse.Namespace) -> None:
    from daemons.watchdog import NftWatchdog
    cfg_path = _config_path_for_daemon()
    wd = NftWatchdog(config_path=cfg_path)

    if args.watchdog_cmd == "daemon":
        wd.run_daemon()
    elif args.watchdog_cmd == "status":
        wd.status()
    elif args.watchdog_cmd == "health":
        report = wd.health()
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["status"] == "HEALTHY" else 1)
    else:
        _die(f"Unknown watchdog subcommand: {args.watchdog_cmd!r}")


def _get_key() -> str:
    """Capture a single keypress without requiring Enter."""
    import sys, tty, termios
    try:
        with open("/dev/tty", "r") as tty_file:
            fd = tty_file.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = tty_file.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch
    except Exception:
        return sys.stdin.read(1)


def _cmd_menu(_args: argparse.Namespace) -> None:
    """Interactive TUI menu for MacOS-style ease of use."""
    import subprocess
    from daemons.watchdog import NftWatchdog
    
    _debug_log("Menu opened")
    while True:
        # Fetch status for header
        try:
            wd = NftWatchdog(config_path=_config_path_for_daemon())
            h = wd.health()
            status_str = f"🟢 \033[32mHEALTHY\033[0m" if h["status"] == "HEALTHY" else f"🔴 \033[31m{h['status']}\033[0m"
            vpn_ip = h.get("vpn_ip", "none")
            vpn_str = f"🟢 \033[32m{vpn_ip}\033[0m" if vpn_ip != "none" else "🔴 \033[31moffline\033[0m"
        except PermissionError:
            status_str = "🔒 \033[90mPermission Required\033[0m"
            vpn_str = "🔒 \033[90msudo needed\033[0m"
        except Exception as e:
            _debug_log(f"Header status error: {e}")
            status_str = "❓ \033[90munknown\033[0m"
            vpn_str = "❓ \033[90munknown\033[0m"

        load = os.getloadavg()[0] if hasattr(os, "getloadavg") else 0.0

        print("\033[2J\033[H", end="")
        print("  \033[1m🔥 NFT Firewall Control Panel\033[0m")
        print("  \033[90m──────────────────────────────────────────────────\033[0m")
        print(f"  Status: {status_str:<18} |  VPN: {vpn_str}")
        print(f"  Load:   \033[36m{load:.2f}\033[0m")
        print("  \033[90m──────────────────────────────────────────────────\033[0m")
        print()
        print("  \033[34m1.\033[0m  📊 View Full Status Dashboard")
        print("  \033[34m2.\033[0m  🔒 Apply / Update Firewall Rules")
        print("  \033[34m3.\033[0m  ⚕️  Run System Doctor (Diagnostics)")
        print()
        print("  \033[34m4.\033[0m  🚫 Block an IP Address")
        print("  \033[34m5.\033[0m  ✅ Unblock an IP Address")
        print("  \033[34m6.\033[0m  📋 View IP Lists (Blocked & Trusted)")
        print()
        print("  \033[34m7.\033[0m  📊 Live Firewall Logs (Activity)")
        print("  \033[34m8.\033[0m  🌍 Geo-Block Manager (by Country)")
        print("  \033[34m9.\033[0m  🔌 Port Manager (Open / Close)")
        print()
        print("  \033[34mr.\033[0m  🔄 Restart Watchdog")
        print("  \033[34m0.\033[0m  ❌ Exit")
        print()
        
        choice = _prompt_tty("  Select an option [0-9,r]: ")

        if choice == "1":
            _debug_log("Menu: View Status Dashboard")
            print("\033[2J\033[H", end="")
            from utils.formatter import build_status_report
            print(build_status_report(cfg_path=_config_path_for_daemon()))
            _wait_for_any_key()
        elif choice == "2":
            _debug_log("Menu: Apply rules")
            print("\033[2J\033[H  \033[1mAvailable profiles:\033[0m\n")
            _cmd_profiles(_args)
            prof = _prompt_tty("\n  Enter profile name (or 'q' to cancel) [cosmos-vpn-secure]: ")
            if not prof or prof.lower() == "q": continue
            _debug_log(f"Menu: Applying profile {prof}")
            apply_args = argparse.Namespace(profile=prof, safe=True)
            _cmd_apply(apply_args)
            _wait_for_any_key()
        elif choice == "3":
            _debug_log("Menu: Run Doctor")
            print("\033[2J\033[H", end="")
            doctor_args = argparse.Namespace(profile=None)
            _cmd_doctor(doctor_args)
            _wait_for_any_key()
        elif choice == "4":
            ip = _prompt_tty("\n  Enter IP/CIDR to block (or 'q' to cancel): ")
            if ip and ip.lower() != "q":
                _debug_log(f"Menu: Blocking IP {ip}")
                block_args = argparse.Namespace(ip=ip)
                _cmd_block(block_args)
                _wait_for_any_key()
        elif choice == "5":
            ip = _prompt_tty("\n  Enter IP/CIDR to unblock (or 'q' to cancel): ")
            if ip and ip.lower() != "q":
                _debug_log(f"Menu: Unblocking IP {ip}")
                unblock_args = argparse.Namespace(ip=ip)
                _cmd_unblock(unblock_args)
                _wait_for_any_key()
        elif choice == "6":
            _debug_log("Menu: View IP list")
            print("\033[2J\033[H", end="")
            _cmd_ip_list(_args)
            _wait_for_any_key()
        elif choice == "7":
            _debug_log("Menu: View live logs")
            _menu_live_logs()
        elif choice == "8":
            _debug_log("Menu: Geo-block manager")
            _menu_geoblock(_args)
        elif choice == "9":
            _debug_log("Menu: Port manager")
            _menu_port_manager()
        elif choice.lower() == "r":
            _debug_log("Menu: Restart watchdog")
            print("\n  \033[34m→\033[0m Restarting nft-watchdog...")
            subprocess.run(["sudo", "systemctl", "restart", "nft-watchdog"], capture_output=True)
            print("  \033[32m✓\033[0m Done.")
            _wait_for_any_key()
        elif choice in {"0", "q", "exit"}:
            _debug_log("Menu: Exit")
            print("\033[2J\033[H", end="")
            break


def _menu_port_manager() -> None:
    """Interactive config-backed port manager for the control panel."""
    options = {
        "1": ("extra_ports", "VPN TCP", True),
        "2": ("extra_ports", "VPN TCP", False),
        "3": ("lan_allow_ports", "LAN TCP", True),
        "4": ("lan_allow_ports", "LAN TCP", False),
        "5": ("lan_allow_udp_ports", "LAN UDP", True),
        "6": ("lan_allow_udp_ports", "LAN UDP", False),
    }

    while True:
        cfg_path = _active_config_path()
        if cfg_path is None:
            print("\033[2J\033[H", end="")
            print("  \033[1m🔌 Port Manager\033[0m\n")
            print("  \033[31mNo firewall config found.\033[0m")
            _wait_for_any_key()
            return

        cfg = _load_config()
        profile = cfg.get("install", "profile", fallback="cosmos-vpn-secure").strip() or "cosmos-vpn-secure"

        try:
            vpn_tcp = _read_port_list(cfg, "extra_ports")
            lan_tcp = _read_port_list(cfg, "lan_allow_ports")
            lan_udp = _read_port_list(cfg, "lan_allow_udp_ports")
        except ValueError as exc:
            print("\033[2J\033[H", end="")
            print("  \033[1m🔌 Port Manager\033[0m\n")
            print(f"  \033[31mConfig error:\033[0m {exc}")
            _wait_for_any_key()
            return

        print("\033[2J\033[H", end="")
        print("  \033[1m🔌 Port Manager\033[0m")
        print("  \033[90m──────────────────────────────────────────────────\033[0m")
        print(f"  Config:  \033[36m{cfg_path}\033[0m")
        print(f"  Profile: \033[36m{profile}\033[0m")
        print()
        print("  VPN TCP ports:")
        for line in _format_port_lines(cfg, "extra_ports"):
            print(f"    \033[36m{line}\033[0m")
        print("  LAN TCP ports:")
        for line in _format_port_lines(cfg, "lan_allow_ports"):
            print(f"    \033[36m{line}\033[0m")
        print("  LAN UDP ports:")
        for line in _format_port_lines(cfg, "lan_allow_udp_ports"):
            print(f"    \033[36m{line}\033[0m")
        print("  \033[90m──────────────────────────────────────────────────\033[0m")
        print()
        print("  \033[34m1.\033[0m  Open VPN TCP port")
        print("  \033[34m2.\033[0m  Close VPN TCP port")
        print("  \033[34m3.\033[0m  Open LAN TCP port")
        print("  \033[34m4.\033[0m  Close LAN TCP port")
        print("  \033[34m5.\033[0m  Open LAN UDP port")
        print("  \033[34m6.\033[0m  Close LAN UDP port")
        print()
        print("  \033[90mVPN TCP means reachable through wg0; LAN means restricted to your LAN CIDR.\033[0m")
        print("  \033[34m0.\033[0m  Back")
        print()

        choice = _prompt_tty("  Select an option [0-6]: ")
        if choice in {"0", "q", "exit"}:
            return
        if choice not in options:
            continue

        key, label, open_port = options[choice]
        action = "open" if open_port else "close"
        raw = _prompt_tty(f"\n  Port to {action} for {label} (or 'q' to cancel): ")
        if not raw or raw.lower() == "q":
            continue

        description = ""
        if open_port:
            description = _prompt_tty(
                "  Description / service name (optional, e.g. Jellyfin): "
            )

        try:
            changed, ports = _change_config_port(
                cfg_path,
                key,
                raw,
                open_port=open_port,
                description=description,
            )
        except ValueError as exc:
            print(f"\n  \033[31m✗\033[0m {exc}")
            _wait_for_any_key()
            continue

        if changed:
            print(f"\n  \033[32m✓\033[0m Updated {key}: {_format_port_list(ports)}")
            if open_port and description.strip():
                print(f"  \033[32m✓\033[0m Saved description: {description.strip()}")
        else:
            print(f"\n  \033[90mNo change; port was already {'present' if open_port else 'absent'}.\033[0m")

        apply_now = _prompt_tty(
            f"\n  Run safe-apply for profile '{profile}' now? Type 'yes' to continue [no]: "
        )
        if apply_now.lower() == "yes":
            print("\n  \033[33mSafe apply will roll back live rules unless you type CONFIRM.\033[0m")
            applied = _cmd_safe_apply(argparse.Namespace(profile=profile))
            if changed and applied:
                cfg_after = _load_config()
                saved_description = _get_port_label(cfg_after, key, raw)
                if _notify_port_change(
                    port=raw,
                    label=label,
                    open_port=open_port,
                    profile=profile,
                    cfg_path=cfg_path,
                    key=key,
                    description=saved_description,
                ):
                    print("  \033[32m✓\033[0m Keybase notification sent.")
                else:
                    print("  \033[33m!\033[0m Keybase notification failed; port change is still applied.")
        else:
            print("  \033[90mConfig changed only. Live rules are unchanged until safe-apply runs.\033[0m")
        _wait_for_any_key()


def _menu_live_logs() -> None:
    """Tails kernel logs for firewall drop events."""
    import os
    _debug_log("Live logs opened")
    print("\033[2J\033[H")
    print("  \033[1m📊 Live Firewall Activity\033[0m")
    print("  \033[90mWatching for dropped packets and VPN events...\033[0m")
    print("  \033[90m(Press Ctrl+C to return to menu)\033[0m\n")
    
    try:
        # Use os.system for a simple, robust tail + grep
        # This handles the TTY and colors much better for a live view
        os.system("sudo dmesg -w | grep --line-buffered -E 'nft-.*-drop|VPN'")
    except KeyboardInterrupt:
        _debug_log("Live logs interrupted by user")
        pass


def _menu_geoblock(args: argparse.Namespace) -> None:
    """Sub-menu for managing country blocks with Cosmos-style safety."""
    from integrations.geoblock import block_country, unblock_country
    _debug_log("Geoblock manager opened")
    while True:
        print("\033[2J\033[H")
        print("  \033[1m🌍 Geo-Block Manager\033[0m")
        print("  \033[90m──────────────────────────────────\033[0m")
        _cmd_geolist(args)
        print("\n  \033[34m1.\033[0m 🛡️  \033[1mBlock High-Risk Countries\033[0m (RU, CN, BR, IN, VN)")
        print("  \033[34m2.\033[0m 🚫 Block a Specific Country (e.g. RU)")
        print("  \033[34m3.\033[0m ✅ Unblock a Country")
        print("  \033[34m4.\033[0m 🔒 \033[1mActivate Lockdown Mode\033[0m (Only allow DK)")
        print("  \033[34m5.\033[0m 🔓 Disable Lockdown Mode")
        print("  \033[34m0.\033[0m ⬅️  Back to Main Menu")
        print()
        
        choice = _prompt_tty("  Select an option: ")
        if choice == "1":
            print("\n  \033[34m→\033[0m Protecting your current connection...")
            for cc in ["RU", "CN", "BR", "IN", "VN"]:
                _debug_log(f"Geoblock: Blocking high-risk {cc}")
                block_country(cc)
            _wait_for_any_key()
        elif choice == "2":
            cc_input = _prompt_tty("\n  Enter Country Code(s) (e.g. CN RU): ").upper()
            if cc_input and cc_input != "Q":
                for cc in cc_input.split():
                    _debug_log(f"Geoblock: Blocking country {cc}")
                    block_country(cc)
                _wait_for_any_key()
        elif choice == "3":
            cc = _prompt_tty("\n  Enter Country Code to unblock: ").upper()
            if cc and cc != "Q":
                _debug_log(f"Geoblock: Unblocking country {cc}")
                unblock_country(cc)
                _wait_for_any_key()
        elif choice == "4":
            cc = _prompt_tty("\n  Enter country to ONLY ALLOW (e.g. DK): ").upper()
            if cc and cc != "Q":
                _debug_log(f"Geoblock: Lockdown to {cc}")
                from integrations.geoblock import whitelist_country
                whitelist_country(cc)
                print("\n  \033[33m⚠️  IMPORTANT:\033[0m You must reload firewall for Lockdown to take full effect.")
                if _prompt_tty("  Reload now? [y/N]: ").lower() == 'y':
                    prof = _load_config().get("install", "profile", fallback="cosmos-vpn-secure")
                    subprocess.run(["sudo", "fw", "safe-apply", prof])
                _wait_for_any_key()
        elif choice == "5":
            _debug_log("Geoblock: Clearing whitelist")
            from integrations.geoblock import clear_geowhitelist
            clear_geowhitelist()
            print("\n  \033[33m⚠️  IMPORTANT:\033[0m Reloading firewall to restore normal access.")
            prof = _load_config().get("install", "profile", fallback="cosmos-vpn-secure")
            subprocess.run(["sudo", "fw", "safe-apply", prof])
            _wait_for_any_key()
        elif choice == "0" or choice.lower() == "q":
            _debug_log("Geoblock manager closed")
            break


def _prompt_tty(prompt: str) -> str:
    """Read a string from /dev/tty."""
    print(prompt, end="", flush=True)
    try:
        with open("/dev/tty", "r") as tty:
            return tty.readline().strip()
    except OSError:
        return input().strip()


def _wait_for_any_key() -> None:
    """Hold the screen until the user acknowledges."""
    print("\n  \033[90mPress any key to return to menu...\033[0m", end="", flush=True)
    _get_key()


# ── Parser construction ───────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog            = "nft-firewall",
        description     = "NFT Firewall & VPN Killswitch — modular edition",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog          = """
Quick-start workflow:
  1.  Edit config/firewall.ini  — set [network] phy_if, vpn_server_ip, etc.
  2.  fw doctor cosmos-vpn-secure
  3.  sudo fw safe-apply cosmos-vpn-secure
  4.  sudo python3 src/main.py backup
  5.  sudo python3 src/main.py watchdog daemon
        """.strip(),
    )

    sub = p.add_subparsers(dest="cmd", metavar="<command>")
    sub.required = True

    # ── Ruleset ───────────────────────────────────────────────────────────────
    ap = sub.add_parser("apply",     help="Generate and apply a firewall profile")
    ap.add_argument("profile",       help="Profile name (see 'profiles' command)")
    ap.add_argument("--dry-run",     action="store_true",
                    help="Print the generated ruleset without applying it")
    ap.add_argument("--safe",        action="store_true",
                    help="Auto-rollback unless you type CONFIRM within 60s")

    sp = sub.add_parser("simulate",  help="Validate a profile with nft --check (no apply, no root needed)")
    sp.add_argument("profile",       help="Profile name (see 'profiles' command)")

    sap = sub.add_parser("safe-apply", help="Apply with nft --check and timed rollback confirmation")
    sap.add_argument("profile",       help="Profile name (see 'profiles' command)")

    dp = sub.add_parser("doctor", help="Run non-mutating safety checks")
    dp.add_argument("profile", nargs="?", help="Profile name (default: [install] profile)")

    # ── State ─────────────────────────────────────────────────────────────────
    sub.add_parser("backup",         help="Snapshot the current live ruleset to state/")

    rp = sub.add_parser("restore",   help="Restore a ruleset from state/ (latest or specific file)")
    rp.add_argument("file", nargs="?", metavar="FILE",
                    help="Path to a specific backup file (default: most recent)")

    # ── IP sets ───────────────────────────────────────────────────────────────
    blk = sub.add_parser("block",    help="Block an IP/CIDR at runtime (no re-apply needed)")
    blk.add_argument("ip")

    ublk = sub.add_parser("unblock", help="Remove an IP/CIDR from the block list")
    ublk.add_argument("ip")

    alw = sub.add_parser("allow",    help="Add an IP to trusted set (SSH override from non-LAN)")
    alw.add_argument("ip")

    dalw = sub.add_parser("disallow", help="Remove an IP from the trusted set")
    dalw.add_argument("ip")

    sub.add_parser("ip-list",        help="List current blocked and trusted IPs")

    # ── Docker ────────────────────────────────────────────────────────────────
    ep = sub.add_parser("docker-expose",
                        help="Add a container port to the expose registry")
    ep.add_argument("host_port",      type=int,  help="Host-side port to forward from")
    ep.add_argument("container_ip",              help="Container IP address")
    ep.add_argument("container_port", type=int,  help="Port inside the container")
    ep.add_argument("proto", nargs="?", default="tcp", choices=["tcp", "udp"])
    ep.add_argument("--src", default=None, metavar="CIDR",
                    help="Restrict to a source network, e.g. 192.168.1.0/24")

    up = sub.add_parser("docker-unexpose",
                        help="Remove a container port from the expose registry")
    up.add_argument("host_port", type=int)
    up.add_argument("proto", nargs="?", default="tcp", choices=["tcp", "udp"])

    sub.add_parser("list-exposed",   help="Show currently exposed container ports")

    # ── Watchdog ──────────────────────────────────────────────────────────────
    wp     = sub.add_parser("watchdog", help="WireGuard health monitor")
    wp_sub = wp.add_subparsers(dest="watchdog_cmd", metavar="<subcommand>")
    wp_sub.required = True
    wp_sub.add_parser("daemon",  help="Run the watchdog daemon loop (systemd ExecStart)")
    wp_sub.add_parser("status",  help="One-shot human-readable status summary")
    wp_sub.add_parser("health",  help="One-shot JSON health report (exit 0=healthy, 1=degraded)")

    # ── Listener ──────────────────────────────────────────────────────────────
    lp     = sub.add_parser("listener", help="Keybase ChatOps bot")
    lp_sub = lp.add_subparsers(dest="listener_cmd", metavar="<subcommand>")
    lp_sub.required = True
    lp_sub.add_parser("daemon", help="Run the Keybase listener loop (systemd ExecStart)")

    # ── SSH alert ─────────────────────────────────────────────────────────────
    sa     = sub.add_parser("ssh-alert", help="SSH intrusion alerter")
    sa_sub = sa.add_subparsers(dest="ssh_alert_cmd", metavar="<subcommand>")
    sa_sub.required = True
    sa_sub.add_parser("daemon", help="Run the SSH alert daemon loop (systemd ExecStart)")

    # ── Knockd ────────────────────────────────────────────────────────────────
    kp     = sub.add_parser("knockd", help="Port-knock daemon for stealth SSH access")
    kp_sub = kp.add_subparsers(dest="knockd_cmd", metavar="<subcommand>")
    kp_sub.required = True
    kp_sub.add_parser("daemon", help="Run the port-knock daemon (systemd ExecStart)")

    # ── Info & notifications ──────────────────────────────────────────────────
    sub.add_parser("status",           help="Mobile-friendly vertical dashboard (all sections)")
    frp = sub.add_parser("firewall-report",  help="Build status report and send it to Keybase (for daily cron)")
    frp.add_argument("--weekly", action="store_true",
                     help="Include weekly auto-block summary section")
    sub.add_parser("profiles",         help="List available firewall profiles")
    rp = sub.add_parser("rules", help="Print the live nftables ruleset")
    rp.add_argument("--no-sets", action="store_true", help="Remove large elements = { ... } blocks from output")
    sub.add_parser("health",           help="JSON health report (exit 0=healthy, 1=degraded)")
    sub.add_parser("debug",            help="Technical debug dump for AI diagnostics")
    sub.add_parser("logs",             help="Real-time color-coded event stream")
    sub.add_parser("keybase-test",     help="Send a test Keybase notification")
    sub.add_parser("maintenance",      help="Prune state backups >30 days old and rotated log files")
    sub.add_parser("threat-update", help="Sync threat feed IPs into blocked_ips set (daily via timer)")
    sub.add_parser("metrics-update", help="Write Prometheus textfile to /var/lib/nft-firewall/metrics.prom")

    gp = sub.add_parser("geoblock",   help="Download and block all CIDRs for country codes (e.g. CN RU)")
    gp.add_argument("country_codes", nargs="+", metavar="CC")

    sub.add_parser("geoblock-test",   help="Verify that blocked countries are actually filtered")
    sub.add_parser("geoblock-status", help="Show blocked countries, CIDR counts, and cache info")

    gup = sub.add_parser("geounblock", help="Remove all CIDRs blocked for a country")
    gup.add_argument("country_code", metavar="CC")

    sub.add_parser("geolist", help="Show blocked countries and CIDR counts")
    sub.add_parser("set-stats", help="Show element counts for all dynamic nftables sets")
    sub.add_parser("menu",    help="Interactive TUI menu for easy management")

    return p


# ── Dispatch table ────────────────────────────────────────────────────────────

_HANDLERS = {
    "menu"            : _cmd_menu,
    "apply"           : _cmd_apply,
    "safe-apply"      : _cmd_safe_apply,
    "simulate"        : _cmd_simulate,
    "doctor"          : _cmd_doctor,
    "backup"          : _cmd_backup,
    "restore"         : _cmd_restore,
    "block"           : _cmd_block,
    "unblock"         : _cmd_unblock,
    "allow"           : _cmd_allow,
    "disallow"        : _cmd_disallow,
    "ip-list"         : _cmd_ip_list,
    "docker-expose"   : _cmd_docker_expose,
    "docker-unexpose" : _cmd_docker_unexpose,
    "list-exposed"    : _cmd_list_exposed,
    "watchdog"        : _cmd_watchdog,
    "listener"        : _cmd_listener,
    "ssh-alert"       : _cmd_ssh_alert,
    "knockd"          : _cmd_knockd,
    "status"          : _cmd_status,
    "firewall-report" : _cmd_firewall_report,
    "profiles"        : _cmd_profiles,
    "rules"           : _cmd_rules,
    "health"          : _cmd_health,
    "debug"           : _cmd_debug,
    "logs"            : _cmd_logs,
    "keybase-test"    : _cmd_keybase_test,
    "maintenance"     : _cmd_maintenance,
    "threat-update"   : _cmd_threat_update,
    "metrics-update"  : _cmd_metrics_update,
    "geoblock"        : _cmd_geoblock,
    "geoblock-test"   : _cmd_geoblock_test,
    "geoblock-status" : _cmd_geoblock_status,
    "geounblock"      : _cmd_geounblock,
    "geolist"         : _cmd_geolist,
    "set-stats"       : _cmd_set_stats,
}


def main() -> None:
    """Parse arguments and dispatch to the appropriate command handler."""
    parser  = _build_parser()
    args    = parser.parse_args()
    handler = _HANDLERS.get(args.cmd)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    handler(args)


if __name__ == "__main__":
    main()
