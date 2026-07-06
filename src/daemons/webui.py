"""Read-only local web dashboard for nft-firewall.

The dashboard intentionally binds to localhost by default. Put Cosmos Cloud in
front of it for TLS, public routing, and authentication.
"""

from __future__ import annotations

import configparser
import html
import json
import os
import re
import shutil
import subprocess
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from daemons.watchdog import NftWatchdog
from utils.formatter import build_status_report

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

_SAMPLE_LOCK = threading.Lock()
_LAST_CPU: tuple[float, int, int] | None = None
_LAST_NET: dict[str, tuple[float, int, int]] = {}


def _config_path() -> str:
    candidates = (
        Path("/opt/nft-firewall/config/firewall.ini"),
        Path(__file__).resolve().parent.parent.parent / "config" / "firewall.ini",
        Path("/etc/nft-watchdog.conf"),
    )
    for path in candidates:
        try:
            if path.exists():
                return str(path)
        except OSError:
            continue
    return str(candidates[-1])


def _load_config(config_path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    try:
        cfg.read(config_path)
    except Exception:
        pass
    return cfg


def _read_cpu_times() -> tuple[int, int] | None:
    try:
        fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()
        if fields[0] != "cpu":
            return None
        values = [int(v) for v in fields[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        return total, idle
    except Exception:
        return None


def _cpu_load() -> dict[str, Any]:
    load = {"one": None, "five": None, "fifteen": None}
    try:
        one, five, fifteen = Path("/proc/loadavg").read_text(encoding="utf-8").split()[:3]
        load = {"one": float(one), "five": float(five), "fifteen": float(fifteen)}
    except Exception:
        pass

    percent = None
    now = time.monotonic()
    sample = _read_cpu_times()
    global _LAST_CPU
    if sample:
        total, idle = sample
        with _SAMPLE_LOCK:
            previous = _LAST_CPU
            _LAST_CPU = (now, total, idle)
        if previous:
            _prev_ts, prev_total, prev_idle = previous
            delta_total = total - prev_total
            delta_idle = idle - prev_idle
            if delta_total > 0:
                percent = max(0.0, min(100.0, (1 - (delta_idle / delta_total)) * 100))

    cores = os.cpu_count() or 1
    return {
        "percent": round(percent, 1) if percent is not None else None,
        "load": load,
        "cores": cores,
        "load_ratio": round(min(float(load["one"] or 0) / cores, 1.0), 3),
    }


def _memory_usage() -> dict[str, Any]:
    try:
        info: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            info[key.strip()] = int(value.split()[0]) * 1024
        total = info["MemTotal"]
        available = info.get("MemAvailable", info.get("MemFree", 0))
        used = total - available
        return {
            "used": used,
            "total": total,
            "available": available,
            "percent": round((used / total) * 100, 1) if total else None,
        }
    except Exception:
        return {"used": None, "total": None, "available": None, "percent": None}


def _disk_usage(path: str = "/") -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        return {
            "path": path,
            "used": usage.used,
            "total": usage.total,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1) if usage.total else None,
        }
    except Exception:
        return {"path": path, "used": None, "total": None, "free": None, "percent": None}


def _read_network_bytes() -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    try:
        for line in Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]:
            iface, values = line.split(":", 1)
            parts = values.split()
            result[iface.strip()] = (int(parts[0]), int(parts[8]))
    except Exception:
        pass
    return result


def _network_usage(ifaces: list[str]) -> list[dict[str, Any]]:
    now = time.monotonic()
    current = _read_network_bytes()
    global _LAST_NET

    rows: list[dict[str, Any]] = []
    with _SAMPLE_LOCK:
        previous = dict(_LAST_NET)
        for iface, (rx, tx) in current.items():
            _LAST_NET[iface] = (now, rx, tx)

    selected = [iface for iface in ifaces if iface in current]
    if not selected:
        selected = [iface for iface in current if iface != "lo"][:4]

    for iface in selected:
        rx, tx = current[iface]
        rx_rate = None
        tx_rate = None
        if iface in previous:
            last_ts, last_rx, last_tx = previous[iface]
            elapsed = max(now - last_ts, 0.001)
            rx_rate = max(0.0, (rx - last_rx) / elapsed)
            tx_rate = max(0.0, (tx - last_tx) / elapsed)
        rows.append({
            "iface": iface,
            "rx": rx,
            "tx": tx,
            "rx_rate": round(rx_rate, 1) if rx_rate is not None else None,
            "tx_rate": round(tx_rate, 1) if tx_rate is not None else None,
        })
    return rows


def _service_states() -> list[dict[str, str]]:
    services = [
        "nft-webui.service",
        "nft-watchdog.service",
        "nft-listener.service",
        "nft-ssh-alert.service",
        "nftables.service",
        "wg-quick@wg0.service",
        "CosmosCloud.service",
        "docker.service",
    ]
    rows: list[dict[str, str]] = []
    for service in services:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            state = result.stdout.strip() or result.stderr.strip() or "unknown"
        except Exception:
            state = "unknown"
        rows.append({"name": service, "state": state})
    return rows


def _open_ports(cfg: configparser.ConfigParser) -> list[dict[str, Any]]:
    defaults = {
        ("extra_ports", 80): "HTTP / reverse proxy",
        ("extra_ports", 443): "HTTPS / reverse proxy",
        ("lan_allow_ports", 80): "HTTP from LAN",
        ("lan_allow_ports", 443): "HTTPS from LAN",
        ("lan_allow_ports", 58473): "SSH from LAN",
        ("lan_allow_ports", 32400): "Plex from LAN",
        ("lan_allow_ports", 8096): "Jellyfin from LAN",
        ("lan_allow_udp_ports", 7359): "Jellyfin discovery",
    }
    mapping = [
        ("extra_ports", "tcp", "VPN"),
        ("lan_allow_ports", "tcp", "LAN"),
        ("lan_allow_udp_ports", "udp", "LAN"),
    ]
    rows: list[dict[str, Any]] = []
    for key, proto, scope in mapping:
        raw = cfg.get("network", key, fallback="")
        for item in raw.replace(";", ",").split(","):
            item = item.strip()
            if not item.isdigit():
                continue
            port = int(item)
            label = cfg.get(
                "port_labels",
                f"{'vpn_tcp' if key == 'extra_ports' else 'lan_udp' if proto == 'udp' else 'lan_tcp'}_{port}",
                fallback=defaults.get((key, port), ""),
            )
            rows.append({"port": port, "proto": proto, "scope": scope, "label": label})
    torrent = cfg.get("network", "torrent_port", fallback="").strip()
    if torrent.isdigit():
        rows.append({"port": int(torrent), "proto": "tcp/udp", "scope": "VPN", "label": "BitTorrent"})
    return rows


_SETS_FILE = Path("/var/lib/nft-firewall/dynamic-sets.json")


def _threat_stats() -> dict[str, Any]:
    """Read-only threat posture snapshot.

    Set counts come from the persisted dynamic-sets state file (no privileges
    needed); drop counters and ban trends reuse the analytics helpers that the
    daily report already exercises.  Every lookup is best-effort — a missing
    data source hides its tile rather than failing the dashboard.
    """
    out: dict[str, Any] = {}
    try:
        sets = json.loads(_SETS_FILE.read_text())
        out["blocked"] = len(sets.get("blocked_ips", []))
        out["trusted"] = len(sets.get("trusted_ips", []))
        out["geo_allow"] = len(sets.get("geowhitelist_ips", []))
    except Exception:
        pass
    try:
        from utils.analytics import (
            country_flag,
            country_leaderboard,
            total_drop_packets,
            weekly_ban_counts,
        )
        out["drops"] = total_drop_packets()
        this_week, last_week = weekly_ban_counts()
        out["bans_week"], out["bans_last_week"] = this_week, last_week
        out["top_countries"] = [
            {"count": row[0], "cc": row[1], "flag": country_flag(row[1])}
            for row in country_leaderboard(4)
        ]
    except Exception:
        pass
    return out


# The page polls every 2 s; collecting shells out to the watchdog, systemctl,
# docker and nft, so serve a short-lived snapshot instead of re-collecting
# per request.
_DASH_CACHE: dict[str, Any] = {"t": 0.0, "data": None}
_DASH_TTL = 4.0
_DASH_LOCK = threading.Lock()


def cached_dashboard() -> dict[str, Any]:
    with _DASH_LOCK:
        now = time.time()
        if _DASH_CACHE["data"] is None or now - _DASH_CACHE["t"] > _DASH_TTL:
            _DASH_CACHE["data"] = collect_dashboard()
            _DASH_CACHE["t"] = now
        return _DASH_CACHE["data"]


def collect_dashboard(config_path: str | None = None) -> dict[str, Any]:
    """Collect read-only dashboard data."""
    cfg_path = config_path or _config_path()
    cfg = _load_config(cfg_path)
    health = NftWatchdog(config_path=cfg_path).health()
    report = build_status_report(cfg_path)
    phy_if = cfg.get("network", "phy_if", fallback="").strip()
    vpn_if = cfg.get("network", "vpn_interface", fallback="wg0").strip()
    ifaces = [iface for iface in (vpn_if, phy_if) if iface]
    return {
        "health": health,
        "report": report,
        "config_path": cfg_path,
        "collected_at": int(time.time()),
        "threat": _threat_stats(),
        "system": {
            "cpu": _cpu_load(),
            "memory": _memory_usage(),
            "disk": _disk_usage("/"),
            "network": _network_usage(ifaces),
            "services": _service_states(),
            "ports": _open_ports(cfg),
        },
    }


def _status_class(status: str) -> str:
    return "ok" if status.upper() == "HEALTHY" else "warn"


def _hide_ips(text: Any) -> str:
    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "hidden", str(text))



_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NFT Firewall — Command Deck</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>&#128737;</text></svg>">
  <style>
    :root {
      color-scheme: dark;
      --bg: #05070b;
      --card: rgba(17, 24, 34, 0.72);
      --card-solid: #10171f;
      --inset: rgba(8, 12, 17, 0.85);
      --line: rgba(148, 163, 184, 0.13);
      --line-2: rgba(148, 163, 184, 0.25);
      --text: #e8eef5;
      --soft: #aab6c4;
      --muted: #6d7a89;
      --ok: #34d399;
      --ok-dim: rgba(52, 211, 153, 0.12);
      --warn: #fbbf24;
      --warn-dim: rgba(251, 191, 36, 0.12);
      --bad: #f87171;
      --bad-dim: rgba(248, 113, 113, 0.12);
      --accent: #22d3ee;
      --accent-dim: rgba(34, 211, 238, 0.12);
      --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    html { scrollbar-color: #22303f var(--bg); }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
      background:
        radial-gradient(1100px 480px at 18% -12%, rgba(34, 211, 238, 0.09), transparent 62%),
        radial-gradient(900px 420px at 82% -10%, rgba(52, 211, 153, 0.08), transparent 60%),
        linear-gradient(rgba(148,163,184,0.028) 1px, transparent 1px),
        linear-gradient(90deg, rgba(148,163,184,0.028) 1px, transparent 1px),
        var(--bg);
      background-size: auto, auto, 44px 44px, 44px 44px, auto;
    }
    main { width: min(1720px, 100% - 28px); margin: 0 auto; padding: 14px 0 22px; }

    /* ── top bar ─────────────────────────────────────────────────────────── */
    .topbar {
      display: flex; align-items: center; gap: 16px;
      padding: 12px 18px; margin-bottom: 12px;
      background: var(--card); border: 1px solid var(--line); border-radius: 16px;
      backdrop-filter: blur(8px);
    }
    .sigil {
      width: 42px; height: 42px; flex: none; display: grid; place-items: center;
      font-size: 22px; border-radius: 12px;
      background: linear-gradient(140deg, rgba(34,211,238,0.16), rgba(52,211,153,0.16));
      border: 1px solid var(--line-2);
      box-shadow: 0 0 22px rgba(34, 211, 238, 0.12);
    }
    .brand { min-width: 0; }
    .brand h1 { margin: 0; font-size: 17px; letter-spacing: 3.5px; font-weight: 800; }
    .brand small { display: block; color: var(--muted); font-size: 11px; letter-spacing: 1.4px; text-transform: uppercase; margin-top: 1px; }
    .topline { margin-left: auto; display: flex; align-items: center; gap: 14px; min-width: 0; }
    .topline .reason { color: var(--soft); font-family: var(--mono); font-size: 12px; text-align: right; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .clock { color: var(--muted); font-family: var(--mono); font-size: 12px; white-space: nowrap; }
    .state {
      flex: none; display: inline-flex; align-items: center; gap: 9px;
      padding: 8px 16px; border-radius: 999px; font-weight: 800; letter-spacing: 1.6px; font-size: 13px;
    }
    .state .beacon { width: 9px; height: 9px; border-radius: 50%; }
    .state.ok { color: var(--ok); background: var(--ok-dim); border: 1px solid rgba(52,211,153,0.35); }
    .state.ok .beacon { background: var(--ok); box-shadow: 0 0 10px var(--ok); animation: pulse 2.4s ease-in-out infinite; }
    .state.warn { color: var(--warn); background: var(--warn-dim); border: 1px solid rgba(251,191,36,0.35); }
    .state.warn .beacon { background: var(--warn); box-shadow: 0 0 10px var(--warn); }
    @keyframes pulse { 50% { opacity: 0.45; } }

    /* ── KPI strip ───────────────────────────────────────────────────────── */
    .kpis {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px; margin-bottom: 12px;
    }
    .kpi {
      display: flex; flex-direction: column; gap: 5px;
      padding: 12px 14px; border-radius: 14px;
      background: var(--card); border: 1px solid var(--line);
      backdrop-filter: blur(8px);
      transition: border-color 0.25s;
    }
    .kpi:hover { border-color: var(--line-2); }
    .kpi label { color: var(--muted); font-size: 10.5px; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; }
    .kpi strong { font-family: var(--mono); font-size: 19px; font-weight: 700; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .kpi.ok strong { color: var(--ok); }
    .kpi.warn strong { color: var(--warn); }
    .kpi.bad strong { color: var(--bad); }
    .kpi.accent strong { color: var(--accent); }

    /* ── card grid ───────────────────────────────────────────────────────── */
    .deck { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 12px; }
    .card {
      background: var(--card); border: 1px solid var(--line); border-radius: 16px;
      padding: 16px 18px; backdrop-filter: blur(8px);
      transition: border-color 0.25s;
      min-width: 0;
    }
    .card:hover { border-color: var(--line-2); }
    .card > h2 {
      display: flex; align-items: center; gap: 9px;
      margin: 0 0 12px; font-size: 12px; font-weight: 800;
      letter-spacing: 1.6px; text-transform: uppercase; color: var(--soft);
    }
    .card > h2::before {
      content: ""; width: 8px; height: 8px; border-radius: 3px;
      background: linear-gradient(140deg, var(--accent), var(--ok));
    }
    .rows { display: flex; flex-direction: column; }
    .row {
      display: flex; align-items: center; justify-content: space-between; gap: 10px;
      padding: 8px 2px; border-bottom: 1px solid var(--line); font-size: 13px;
    }
    .row:last-child { border-bottom: none; }
    .row .k { color: var(--soft); }
    .row .v { display: inline-flex; align-items: center; gap: 8px; font-family: var(--mono); font-size: 12.5px; color: var(--text); }
    .dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
    .dot.ok { background: var(--ok); box-shadow: 0 0 8px rgba(52,211,153,0.55); }
    .dot.warn { background: var(--warn); box-shadow: 0 0 8px rgba(251,191,36,0.55); }
    .dot.bad { background: var(--bad); box-shadow: 0 0 8px rgba(248,113,113,0.55); }

    /* threat tiles */
    .tiles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; margin-bottom: 10px; }
    .tile { padding: 11px 13px; border-radius: 12px; background: var(--inset); border: 1px solid var(--line); }
    .tile label { display: block; color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }
    .tile strong { display: block; margin-top: 4px; font-family: var(--mono); font-size: 19px; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .tile.accent strong { color: var(--accent); }
    .tile.ok strong { color: var(--ok); }

    /* bars */
    .meter { margin-bottom: 12px; }
    .meter:last-child { margin-bottom: 0; }
    .meter .head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px; }
    .meter .head span { color: var(--soft); font-size: 12.5px; }
    .meter .head strong { font-family: var(--mono); font-size: 12px; color: var(--text); font-weight: 600; }
    .track { height: 7px; border-radius: 99px; background: var(--inset); border: 1px solid var(--line); overflow: hidden; }
    .fill { width: 0; height: 100%; border-radius: 99px; background: linear-gradient(90deg, var(--accent), var(--ok)); transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1); }
    .fill.hot { background: linear-gradient(90deg, var(--warn), var(--bad)); }

    /* service + port chips */
    .chips { display: flex; flex-wrap: wrap; gap: 7px; }
    .chip {
      display: inline-flex; align-items: center; gap: 7px;
      padding: 6px 11px; border-radius: 999px; font-size: 12px;
      background: var(--inset); border: 1px solid var(--line); color: var(--soft);
      font-family: var(--mono);
    }
    .chip .dot { width: 7px; height: 7px; }
    .portchip { flex-direction: column; align-items: flex-start; gap: 2px; border-radius: 12px; padding: 9px 12px; }
    .portchip .port { color: var(--accent); font-weight: 700; }
    .portchip .desc { color: var(--muted); font-size: 11px; font-family: system-ui, sans-serif; }
    .portchip .scope { color: var(--ok); font-size: 10px; letter-spacing: 1px; }

    footer {
      margin-top: 14px; display: flex; justify-content: space-between; gap: 10px;
      color: var(--muted); font-size: 11.5px; font-family: var(--mono);
    }

    /* ── adaptive scaling ────────────────────────────────────────────────── */
    @media (min-width: 1500px) { html { zoom: 1.08; } }
    @media (min-width: 1800px) { html { zoom: 1.18; } }
    @media (min-width: 1800px) and (min-height: 1150px) { html { zoom: 1.32; } }
    @media (min-width: 2300px) { html { zoom: 1.45; } }
    @media (min-width: 2300px) and (min-height: 1500px) { html { zoom: 1.65; } }
    @media (min-width: 3200px) { html { zoom: 1.95; } }
    @media (max-width: 760px) {
      main { width: min(1720px, 100% - 14px); padding-top: 8px; }
      .topbar { flex-wrap: wrap; gap: 10px; padding: 12px 14px; }
      .topline { margin-left: 0; width: 100%; justify-content: space-between; }
      .topline .reason { display: none; }
      .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
      .kpi { padding: 10px 12px; }
      .kpi strong { font-size: 16px; }
      .deck { grid-template-columns: 1fr; gap: 10px; }
      footer { flex-direction: column; align-items: center; }
    }
  </style>
</head>
<body>
  <main>
    <header class="topbar">
      <div class="sigil">&#128737;</div>
      <div class="brand">
        <h1>NFT FIREWALL</h1>
        <small>command deck &middot; read-only</small>
      </div>
      <div class="topline">
        <span class="reason" id="reason">__REASON__</span>
        <span class="clock" id="clock"></span>
        <span class="state __STATUS_CLASS__" id="stateBox"><i class="beacon"></i><span id="status">__STATUS__</span></span>
      </div>
    </header>

    <section class="kpis">
      <div class="kpi" id="kVpnBox"><label>VPN Tunnel</label><strong id="kVpn">&hellip;</strong></div>
      <div class="kpi" id="kHandshakeBox"><label>Handshake</label><strong id="kHandshake">&hellip;</strong></div>
      <div class="kpi" id="kKillswitchBox"><label>Killswitch</label><strong id="kKillswitch">&hellip;</strong></div>
      <div class="kpi" id="kRulesBox"><label>NFT Rules</label><strong id="kRules">&hellip;</strong></div>
      <div class="kpi accent"><label>Blocked IPs</label><strong id="kBlocked">&hellip;</strong></div>
      <div class="kpi accent"><label>Packets Denied</label><strong id="kDrops">&hellip;</strong></div>
    </section>

    <section class="deck">
      <section class="card">
        <h2>Security Posture</h2>
        <div class="rows">
          <div class="row"><span class="k">VPN tunnel</span><span class="v"><i class="dot ok" id="dVpn"></i><span id="rVpn">&hellip;</span></span></div>
          <div class="row"><span class="k">Handshake</span><span class="v"><i class="dot ok" id="dHandshake"></i><span id="rHandshake">&hellip;</span></span></div>
          <div class="row"><span class="k">Killswitch markers</span><span class="v"><i class="dot ok" id="dMarkers"></i><span id="rMarkers">&hellip;</span></span></div>
          <div class="row"><span class="k">Live ruleset</span><span class="v"><i class="dot ok" id="dRules"></i><span id="rRules">&hellip;</span></span></div>
          <div class="row"><span class="k">Persisted ruleset</span><span class="v"><i class="dot ok" id="dPersisted"></i><span id="rPersisted">&hellip;</span></span></div>
        </div>
      </section>

      <section class="card">
        <h2>Threat Overview</h2>
        <div class="tiles">
          <div class="tile"><label>Blocked IPs</label><strong id="tBlocked">--</strong></div>
          <div class="tile"><label>Trusted IPs</label><strong id="tTrusted">--</strong></div>
          <div class="tile accent"><label>Geo Allowlist</label><strong id="tGeo">--</strong></div>
          <div class="tile accent"><label>Packets Denied</label><strong id="tDrops">--</strong></div>
        </div>
        <div class="rows">
          <div class="row"><span class="k">Auto-bans this week</span><span class="v" id="tBansWeek">--</span></div>
          <div class="row"><span class="k">Auto-bans last week</span><span class="v" id="tBansLast">--</span></div>
        </div>
        <div class="rows" id="tCountries"></div>
      </section>

      <section class="card">
        <h2>Live System</h2>
        <div class="meter">
          <div class="head"><span>CPU</span><strong id="cpuText">&hellip;</strong></div>
          <div class="track"><div class="fill" id="cpuBar"></div></div>
        </div>
        <div class="meter">
          <div class="head"><span>Memory</span><strong id="memText">&hellip;</strong></div>
          <div class="track"><div class="fill" id="memBar"></div></div>
        </div>
        <div class="meter">
          <div class="head"><span>Disk /</span><strong id="diskText">&hellip;</strong></div>
          <div class="track"><div class="fill" id="diskBar"></div></div>
        </div>
      </section>

      <section class="card">
        <h2>Network Throughput</h2>
        <div class="rows" id="netRows"><div class="row"><span class="k">warming up</span><span class="v"></span></div></div>
      </section>

      <section class="card">
        <h2>Daemons</h2>
        <div class="chips" id="serviceChips"></div>
      </section>

      <section class="card">
        <h2>Exposed Ports Overview</h2>
        <div class="chips" id="portChips"></div>
      </section>
    </section>

    <footer>
      <span>nft-firewall &middot; localhost:8787 behind Cosmos SSO</span>
      <span>refreshed <span id="updated">&hellip;</span></span>
    </footer>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const redactIps = (v) => String(v || "").replace(/\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b/g, "hidden");
    const num = (v) => v === null || v === undefined ? "--"
      : Number(v) >= 100000
        ? new Intl.NumberFormat(undefined, {notation: "compact", maximumFractionDigits: 1}).format(Number(v))
        : Number(v).toLocaleString();
    const fmtBytes = (v) => {
      if (v === null || v === undefined) return "--";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let n = Number(v), i = 0;
      while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
      return `${n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[i]}`;
    };
    const fmtRate = (v) => v === null || v === undefined ? "&#8943;" : `${fmtBytes(v)}/s`;
    const setBar = (id, pct) => {
      const el = $(id);
      const p = Math.max(0, Math.min(100, Number(pct || 0)));
      el.style.width = `${p}%`;
      el.classList.toggle("hot", p >= 85);
    };
    const setDotRow = (dotId, rowId, ok, text) => {
      $(dotId).className = `dot ${ok ? "ok" : "bad"}`;
      $(rowId).textContent = text;
    };
    const setKpi = (boxId, valueId, ok, text) => {
      $(boxId).className = `kpi ${ok ? "ok" : "bad"}`;
      $(valueId).textContent = text;
    };
    const svcName = (n) => n.replace(".service", "").replace("wg-quick@", "wg:");
    const svcOk = (row) => row.state === "active" || (row.name === "docker.service" && row.state === "inactive");
    let lastData = 0;

    async function refresh() {
      const res = await fetch("/api/dashboard", {cache: "no-store"});
      const data = await res.json();
      const h = data.health || {};
      const s = data.system || {};
      const t = data.threat || {};
      lastData = Date.now();

      const healthy = (h.status || "").toUpperCase() === "HEALTHY";
      $("status").textContent = h.status || "UNKNOWN";
      $("stateBox").className = `state ${healthy ? "ok" : "warn"}`;
      $("reason").textContent = healthy
        ? `vpn up &middot; handshake ${h.handshake_age_s ?? "--"}s &middot; rules intact`.replaceAll("&middot;", "\u00b7")
        : redactIps(h.reason || "");

      const hsFresh = (h.handshake_age_s ?? 999) < 150;
      setKpi("kVpnBox", "kVpn", Boolean(h.vpn_ip), h.vpn_ip ? "ONLINE" : "DOWN");
      setKpi("kHandshakeBox", "kHandshake", hsFresh, h.handshake_age_s === null || h.handshake_age_s === undefined ? "--" : `${h.handshake_age_s}s`);
      setKpi("kKillswitchBox", "kKillswitch", h.markers === "ok", h.markers === "ok" ? "ARMED" : String(h.markers || "check").toUpperCase());
      setKpi("kRulesBox", "kRules", Boolean(h.nft_integrity), h.nft_integrity ? "INTACT" : "CHECK");
      $("kBlocked").textContent = num(t.blocked);
      $("kDrops").textContent = num(t.drops);

      setDotRow("dVpn", "rVpn", Boolean(h.vpn_ip), h.vpn_ip ? "connected" : "down");
      setDotRow("dHandshake", "rHandshake", hsFresh, h.handshake_age_s === null || h.handshake_age_s === undefined ? "unknown" : `${h.handshake_age_s}s ago`);
      setDotRow("dMarkers", "rMarkers", h.markers === "ok", h.markers === "ok" ? "armed" : String(h.markers || "check"));
      setDotRow("dRules", "rRules", Boolean(h.nft_integrity), h.nft_integrity ? "intact" : "check");
      setDotRow("dPersisted", "rPersisted", h.persisted_ruleset_integrity === "ok", String(h.persisted_ruleset_integrity || "unknown"));

      $("tBlocked").textContent = num(t.blocked);
      $("tTrusted").textContent = num(t.trusted);
      $("tGeo").textContent = num(t.geo_allow);
      $("tDrops").textContent = num(t.drops);
      $("tBansWeek").textContent = num(t.bans_week);
      $("tBansLast").textContent = num(t.bans_last_week);
      $("tCountries").innerHTML = (t.top_countries || []).map(row =>
        `<div class="row"><span class="k">${row.flag || ""} ${row.cc} attacks blocked</span><span class="v">${num(row.count)}</span></div>`
      ).join("") || `<div class="row"><span class="k">attacking countries</span><span class="v">none recorded</span></div>`;

      const cpu = s.cpu || {};
      const cpuPct = cpu.percent ?? ((cpu.load_ratio || 0) * 100);
      $("cpuText").textContent = cpu.percent === null || cpu.percent === undefined
        ? `load ${cpu.load?.one ?? "--"} / ${cpu.cores ?? "--"} cores`
        : `${cpu.percent.toFixed(1)}% \u00b7 ${cpu.cores ?? "--"} cores`;
      setBar("cpuBar", cpuPct);
      const mem = s.memory || {};
      $("memText").textContent = `${mem.percent ?? "--"}% \u00b7 ${fmtBytes(mem.used)} / ${fmtBytes(mem.total)}`;
      setBar("memBar", mem.percent);
      const disk = s.disk || {};
      $("diskText").textContent = `${disk.percent ?? "--"}% \u00b7 ${fmtBytes(disk.used)} / ${fmtBytes(disk.total)}`;
      setBar("diskBar", disk.percent);

      $("netRows").innerHTML = (s.network || []).map(row =>
        `<div class="row"><span class="v">${row.iface}</span><span class="v">&#8595; ${fmtRate(row.rx_rate)} &nbsp; &#8593; ${fmtRate(row.tx_rate)}</span></div>`
      ).join("") || `<div class="row"><span class="k">no interface data</span><span class="v"></span></div>`;

      $("serviceChips").innerHTML = (s.services || []).map(row =>
        `<span class="chip"><i class="dot ${svcOk(row) ? "ok" : "bad"}"></i>${svcName(row.name)}</span>`
      ).join("");

      $("portChips").innerHTML = (s.ports || []).map(row =>
        `<span class="chip portchip"><span><span class="port">${row.port}/${row.proto}</span> <span class="scope">${row.scope}</span></span><span class="desc">${row.label || "configured"}</span></span>`
      ).join("") || `<span class="chip">no configured ports</span>`;

      $("updated").textContent = "just now";
    }
    setInterval(() => {
      $("clock").textContent = new Date().toLocaleString(undefined, {weekday: "short", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit"});
      if (lastData) {
        const age = Math.round((Date.now() - lastData) / 1000);
        $("updated").textContent = age <= 2 ? "just now" : `${age}s ago`;
      }
    }, 1000);
    refresh().catch(console.error);
    setInterval(() => refresh().catch(console.error), 2000);
  </script>
</body>
</html>
"""


def render_dashboard(data: dict[str, Any]) -> str:
    """Render the read-only command-deck dashboard shell.

    All live values are filled client-side from /api/dashboard; the shell only
    interpolates initial status text (IP-redacted) so a no-JS request still
    reveals nothing sensitive.
    """
    health = data.get("health") or {}
    status = str(health.get("status", "UNKNOWN"))
    reason = _hide_ips(health.get("reason", ""))
    return (
        _PAGE_TEMPLATE
        .replace("__STATUS_CLASS__", _status_class(status))
        .replace("__STATUS__", html.escape(status))
        .replace("__REASON__", html.escape(reason))
    )


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "nft-firewall-webui/2"

    def _headers(self, status: HTTPStatus, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        route = urlparse(self.path).path
        try:
            data = cached_dashboard()
            if route in {"/", "/index.html"}:
                page = render_dashboard(data).encode("utf-8")
                self._headers(HTTPStatus.OK, "text/html; charset=utf-8")
                self.wfile.write(page)
                return
            if route == "/api/status":
                payload = json.dumps(data["health"], indent=2).encode("utf-8")
                self._headers(HTTPStatus.OK, "application/json; charset=utf-8")
                self.wfile.write(payload)
                return
            if route == "/api/dashboard":
                payload = json.dumps(data, indent=2).encode("utf-8")
                self._headers(HTTPStatus.OK, "application/json; charset=utf-8")
                self.wfile.write(payload)
                return
        except Exception as exc:  # pragma: no cover - defensive server boundary
            payload = json.dumps({"status": "ERROR", "reason": str(exc)}, indent=2).encode("utf-8")
            self._headers(HTTPStatus.INTERNAL_SERVER_ERROR, "application/json; charset=utf-8")
            self.wfile.write(payload)
            return

        self._headers(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8")
        self.wfile.write(b"not found\n")

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        route = urlparse(self.path).path
        if route in {"/", "/index.html"}:
            self._headers(HTTPStatus.OK, "text/html; charset=utf-8")
            return
        if route in {"/api/status", "/api/dashboard"}:
            self._headers(HTTPStatus.OK, "application/json; charset=utf-8")
            return
        self._headers(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._headers(HTTPStatus.METHOD_NOT_ALLOWED, "text/plain; charset=utf-8")
        self.wfile.write(b"read-only\n")

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[webui] {self.address_string()} {fmt % args}", flush=True)


def run(host: str | None = None, port: int | None = None) -> None:
    bind_host = host or os.environ.get("NFT_FIREWALL_WEBUI_HOST", DEFAULT_HOST)
    bind_port = port or int(os.environ.get("NFT_FIREWALL_WEBUI_PORT", str(DEFAULT_PORT)))
    httpd = ThreadingHTTPServer((bind_host, bind_port), DashboardHandler)
    print(f"[webui] listening on http://{bind_host}:{bind_port}", flush=True)
    httpd.serve_forever()
