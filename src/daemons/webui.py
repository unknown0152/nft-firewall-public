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


def _metric(label: str, value: Any, tone: str = "") -> str:
    return (
        f'<section class="metric {html.escape(tone)}">'
        f"<span>{html.escape(label)}</span>"
        f"<strong>{html.escape(str(value))}</strong>"
        "</section>"
    )


def _hide_ips(text: Any) -> str:
    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "hidden", str(text))


def _report_sections(report: str) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    title = "Report"
    lines: list[str] = []
    for raw in report.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("━━") or line.startswith("==="):
            continue
        if line.startswith(("🛡", "🌐", "🔐", "📦", "🧱", "💾", "🚦", "🧭")):
            if lines:
                sections.append((title, lines))
            title = line
            lines = []
        else:
            lines.append(line)
    if lines:
        sections.append((title, lines))
    return sections or [("Report", [report])]


def render_dashboard(data: dict[str, Any]) -> str:
    """Render a complete live dark-mode dashboard page."""
    health = data.get("health", {})
    status = str(health.get("status", "UNKNOWN"))
    reason = _hide_ips(health.get("reason", "No reason reported"))
    status_class = _status_class(status)

    handshake = health.get("handshake_age_s", "n/a")
    markers = health.get("markers", "n/a")
    nft_integrity = "intact" if health.get("nft_integrity") else "check"
    persisted = health.get("persisted_ruleset_integrity", "unknown")
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NFT Firewall Dashboard</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #080a0d;
      --bg-2: #0c1117;
      --panel: #111821;
      --panel-2: #151e29;
      --panel-3: #0d131a;
      --line: rgba(188, 202, 220, 0.14);
      --line-strong: rgba(188, 202, 220, 0.24);
      --text: #edf2f7;
      --soft: #b7c1ce;
      --muted: #7f8b9a;
      --green: #34d399;
      --green-glow: rgba(52, 211, 153, 0.22);
      --yellow: #fbbf24;
      --red: #fb7185;
      --cyan: #38bdf8;
      --violet: #a78bfa;
      --orange: #fb923c;
      --shadow: 0 18px 50px rgba(0, 0, 0, 0.28);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background:
        linear-gradient(180deg, #0b0f14 0%, var(--bg) 42%, #07080b 100%),
        var(--bg);
      color: var(--text);
      font: 14px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }}
    main {{ width: min(1360px, calc(100% - 28px)); margin: 0 auto; padding: 24px 0 36px; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: stretch;
      flex-wrap: wrap;
      gap: 14px;
      margin-bottom: 14px;
    }}
    h1 {{
      margin: 0;
      font-size: clamp(24px, 3vw, 34px);
      font-weight: 760;
      letter-spacing: 0;
    }}
    .masthead {{
      min-width: min(620px, 100%);
      flex: 1 1 auto;
      padding: 18px 20px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: linear-gradient(180deg, rgba(21, 30, 41, 0.92), rgba(12, 17, 23, 0.92));
      box-shadow: var(--shadow);
    }}
    .subtitle {{
      margin-top: 8px;
      color: var(--soft);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
    }}
    .status-card {{
      min-width: 260px;
      padding: 18px 20px;
      border: 1px solid var(--line);
      border-left: 4px solid var(--yellow);
      border-radius: 8px;
      background: var(--panel);
      text-align: right;
      box-shadow: var(--shadow);
    }}
    .status-card.ok {{ border-left-color: var(--green); }}
    .status-card.warn {{ border-left-color: var(--yellow); }}
    .eyebrow {{
      display: block;
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      font-weight: 600;
    }}
    .status-card strong {{ display: block; margin-top: 4px; font-size: 26px; }}
    .ok strong, .ok .value {{ color: var(--green); }}
    .warn strong, .warn .value {{ color: var(--yellow); }}
    .bad strong, .bad .value {{ color: var(--red); }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }}
    .metric {{
      min-height: 88px;
      padding: 14px;
      border-radius: 8px;
      background: var(--panel);
      border: 1px solid var(--line);
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 11px; font-weight: 700; text-transform: uppercase; }}
    .metric strong {{ display: block; margin-top: 10px; font-size: 19px; font-weight: 680; overflow-wrap: anywhere; }}
    .metric.ok strong {{ color: var(--green); }}
    .metric.warn strong {{ color: var(--yellow); }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      gap: 14px;
    }}
    .panel {{
      padding: 18px;
      border-radius: 8px;
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: 0 12px 34px rgba(0, 0, 0, 0.18);
      margin-bottom: 14px;
    }}
    .panel h2 {{
      margin: 0 0 16px;
      font-size: 16px;
      font-weight: 600;
      color: var(--text);
    }}
    .report-header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      padding-bottom: 14px;
      border-bottom: 1px solid var(--line);
      margin-bottom: 16px;
    }}
    .report-header h3 {{ margin: 0 0 4px; font-size: 18px; color: var(--text); }}
    .report-header p {{ margin: 0; color: var(--muted); font-size: 13px; }}
    .report-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }}
    .report-section {{
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-3);
    }}
    .report-section.wide {{ grid-column: 1 / -1; }}
    .report-section h4 {{
      margin: 0 0 12px;
      font-size: 14px;
      color: var(--soft);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .report-list {{ list-style: none; padding: 0; margin: 0; }}
    .report-list li {{
      padding: 8px 0;
      color: var(--text);
      font-size: 13px;
      display: flex;
      justify-content: space-between;
      gap: 16px;
      border-bottom: 1px solid rgba(188, 202, 220, 0.08);
    }}
    .port-list {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 10px;
    }}
    .port-list li {{
      display: grid;
      gap: 6px;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-2);
    }}
    .port-line {{ display: flex; justify-content: space-between; align-items: center; gap: 10px; }}
    .port-label {{ color: var(--soft); overflow-wrap: anywhere; }}
    .status-indicator {{ display: inline-flex; align-items: center; gap: 6px; }}
    .dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; }}
    .dot.green {{ background: var(--green); box-shadow: 0 0 8px var(--green-glow); }}
    .dot.red {{ background: var(--red); box-shadow: 0 0 8px rgba(239, 68, 68, 0.4); }}
    .dot.yellow {{ background: var(--yellow); box-shadow: 0 0 8px rgba(234, 179, 8, 0.35); }}
    .side {{ display: grid; gap: 0; align-content: start; }}
    .bars {{ display: grid; gap: 16px; }}
    .bar-row {{ display: grid; gap: 8px; }}
    .bar-head {{ display: flex; justify-content: space-between; font-size: 13px; color: var(--muted); gap: 12px; }}
    .bar-head strong {{ color: var(--text); font-weight: 500; }}
    .track {{
      height: 8px;
      background: rgba(0,0,0,0.34);
      border-radius: 99px;
      overflow: hidden;
      border: 1px solid var(--line);
    }}
    .fill {{
      height: 100%;
      background: linear-gradient(90deg, var(--cyan), var(--green));
      border-radius: 99px;
      transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 0 10px rgba(56, 189, 248, 0.24);
    }}
    table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
    th, td {{
      padding: 10px 4px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      font-size: 13px;
    }}
    th {{
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
    }}
    td:last-child, th:last-child {{ text-align: right; }}
    tbody tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover td {{ background: rgba(255,255,255,0.02); }}
    .pill {{ display: inline-flex; align-items: center; min-height: 22px; padding: 2px 8px; border-radius: 999px; background: var(--panel-3); color: var(--soft); font-size: 12px; font-weight: 700; }}
    .pill.ok {{ background: rgba(34,197,94,0.1); color: var(--green); border: 1px solid rgba(34,197,94,0.2); }}
    .pill.warn {{ background: rgba(234,179,8,0.1); color: var(--yellow); border: 1px solid rgba(234,179,8,0.2); }}
    .pill.bad {{ background: rgba(239,68,68,0.1); color: var(--red); border: 1px solid rgba(239,68,68,0.2); }}
    code {{
      font-family: ui-monospace, SFMono-Regular, monospace;
      background: rgba(0,0,0,0.34);
      padding: 2px 6px;
      border-radius: 4px;
      color: var(--cyan);
      font-size: 12px;
    }}
    footer {{ margin-top: 18px; text-align: right; color: var(--muted); font-size: 12px; }}
    @media (max-width: 1000px) {{
      .layout {{ grid-template-columns: 1fr; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .status-card {{ width: 100%; text-align: left; }}
    }}
    @media (max-width: 640px) {{
      main {{ width: min(100% - 20px, 1360px); padding-top: 10px; }}
      .metrics {{ grid-template-columns: 1fr; }}
      .report-header {{ display: block; }}
      .port-list {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="masthead">
        <h1>NFT Firewall</h1>
        <div class="subtitle" id="reason">{html.escape(reason)}</div>
      </div>
      <div class="status-card {status_class}">
        <span class="eyebrow">Firewall State</span>
        <strong id="status">{html.escape(status)}</strong>
      </div>
    </header>
    <section class="metrics">
      <section class="metric"><span>VPN IP</span><strong id="vpnIp">hidden</strong></section>
      <section class="metric"><span>Handshake</span><strong id="handshake">{html.escape(f"{handshake}s" if isinstance(handshake, int) else str(handshake))}</strong></section>
      <section class="metric {html.escape('ok' if markers == 'ok' else 'warn')}"><span>Markers</span><strong id="markers">{html.escape(str(markers))}</strong></section>
      <section class="metric {html.escape('ok' if nft_integrity == 'intact' else 'warn')}"><span>NFT Rules</span><strong id="nftRules">{html.escape(nft_integrity)}</strong></section>
      <section class="metric {html.escape('ok' if persisted == 'ok' else 'warn')}"><span>Persisted Rules</span><strong id="persistedRules">{html.escape(str(persisted))}</strong></section>
    </section>
    <section class="layout">
      <div class="main-content">
        <section class="panel">
          <div class="report-header">
            <div>
              <h3 id="briefTitle">Good Morning — Firewall Brief</h3>
              <p><span id="briefDate">loading</span></p>
            </div>
            <span class="pill {status_class}" id="briefStatus">{html.escape(status)}</span>
          </div>
          <div class="report-grid">
            <div class="report-section">
              <h4>Network & Security</h4>
              <ul class="report-list">
                <li><span>VPN</span> <span class="status-indicator"><i id="vpnDot" class="dot green"></i> <span id="vpnState">hidden</span></span></li>
                <li><span>Handshake</span> <span class="status-indicator"><i id="handshakeDot" class="dot green"></i> <span id="handshakeBrief">loading</span></span></li>
                <li><span>Killswitch</span> <span class="status-indicator"><i id="markerDot" class="dot green"></i> <span id="markerBrief">loading</span></span></li>
                <li><span>NFT Rules</span> <span class="status-indicator"><i id="nftDot" class="dot green"></i> <span id="nftBrief">loading</span></span></li>
                <li><span>Persisted Rules</span> <span class="status-indicator"><i id="persistedDot" class="dot green"></i> <span id="persistedBrief">loading</span></span></li>
              </ul>
            </div>
            <div class="report-section">
              <h4>Docker & Daemons</h4>
              <ul class="report-list" id="daemonBriefRows">
                <li><span>Services</span><span>loading</span></li>
              </ul>
            </div>
            <div class="report-section wide">
              <h4>Exposed Ports Overview</h4>
              <ul class="report-list port-list" id="briefPortRows">
                <li><span>loading</span><span></span></li>
              </ul>
            </div>
          </div>
        </section>
      </div>
      <aside class="side">
        <section class="panel">
          <h2>Live System</h2>
          <div class="bars">
            <div class="bar-row">
              <div class="bar-head"><span>CPU</span><strong id="cpuText">warming up</strong></div>
              <div class="track"><div class="fill" id="cpuBar"></div></div>
            </div>
            <div class="bar-row">
              <div class="bar-head"><span>Memory</span><strong id="memText">--</strong></div>
              <div class="track"><div class="fill" id="memBar"></div></div>
            </div>
            <div class="bar-row">
              <div class="bar-head"><span>Disk /</span><strong id="diskText">--</strong></div>
              <div class="track"><div class="fill" id="diskBar"></div></div>
            </div>
          </div>
        </section>
        <section class="panel">
          <h2>Network Throughput</h2>
          <table>
            <thead><tr><th>Interface</th><th>RX</th><th>TX</th></tr></thead>
            <tbody id="networkRows"><tr><td colspan="3">warming up</td></tr></tbody>
          </table>
        </section>
        <section class="panel">
          <h2>Core Services</h2>
          <table>
            <thead><tr><th>Service</th><th>State</th></tr></thead>
            <tbody id="serviceRows"></tbody>
          </table>
        </section>
      </aside>
    </section>
    <footer>Last refresh: <span id="updated">initial</span></footer>
  </main>
  <script>
    const redactIps = (value) => String(value || "").replace(/\\b(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}}\\b/g, "hidden");
    const fmtBytes = (value) => {{
      if (value === null || value === undefined) return "--";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let n = Number(value), i = 0;
      while (n >= 1024 && i < units.length - 1) {{ n /= 1024; i++; }}
      return `${{n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(1)}} ${{units[i]}}`;
    }};
    const fmtRate = (value) => value === null || value === undefined ? "warming" : `${{fmtBytes(value)}}/s`;
    const setBar = (id, pct) => {{
      const el = document.getElementById(id);
      el.style.width = `${{Math.max(0, Math.min(100, Number(pct || 0)))}}%`;
    }};
    const pillClass = (state) => state === "active" ? "ok" : (state === "inactive" || state === "unknown" ? "warn" : "bad");
    const dotClass = (ok) => `dot ${{ok ? "green" : "red"}}`;
    const serviceLabel = (name) => name.replace(".service", "");
    const serviceOk = (row) => row.state === "active" || (row.name === "docker.service" && row.state === "inactive");
    const briefName = (name) => {{
      const n = serviceLabel(name);
      if (n === "nft-watchdog") return "Watchdog";
      if (n === "nft-listener") return "Listener";
      if (n === "nft-ssh-alert") return "SSH Alert";
      if (n === "CosmosCloud") return "Cosmos";
      if (n === "docker") return "Docker";
      return n;
    }};
    async function refresh() {{
      const res = await fetch("/api/dashboard", {{cache: "no-store"}});
      const data = await res.json();
      const h = data.health || {{}};
      const s = data.system || {{}};
      document.getElementById("status").textContent = h.status || "UNKNOWN";
      document.getElementById("reason").textContent = redactIps(h.reason || "No reason reported");
      document.querySelector(".status-card").className = `status-card ${{(h.status || "").toUpperCase() === "HEALTHY" ? "ok" : "warn"}}`;
      document.getElementById("briefStatus").textContent = h.status || "UNKNOWN";
      document.getElementById("briefStatus").className = `pill ${{(h.status || "").toUpperCase() === "HEALTHY" ? "ok" : "warn"}}`;
      document.getElementById("briefDate").textContent = new Date().toLocaleString(undefined, {{weekday: "short", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"}});
      document.getElementById("vpnIp").textContent = "hidden";
      document.getElementById("handshake").textContent = h.handshake_age_s === null || h.handshake_age_s === undefined ? "--" : `${{h.handshake_age_s}}s`;
      document.getElementById("markers").textContent = h.markers || "--";
      document.getElementById("nftRules").textContent = h.nft_integrity ? "intact" : "check";
      document.getElementById("persistedRules").textContent = h.persisted_ruleset_integrity || "unknown";
      document.getElementById("vpnState").textContent = h.vpn_ip ? "hidden" : "unknown";
      document.getElementById("handshakeBrief").textContent = h.handshake_age_s === null || h.handshake_age_s === undefined ? "unknown" : `${{h.handshake_age_s}}s ago`;
      document.getElementById("markerBrief").textContent = h.markers === "ok" ? "Active" : (h.markers || "check");
      document.getElementById("nftBrief").textContent = h.nft_integrity ? "Intact" : "Check";
      document.getElementById("persistedBrief").textContent = h.persisted_ruleset_integrity || "unknown";
      document.getElementById("markerDot").className = dotClass(h.markers === "ok");
      document.getElementById("nftDot").className = dotClass(Boolean(h.nft_integrity));
      document.getElementById("persistedDot").className = dotClass(h.persisted_ruleset_integrity === "ok");

      const cpu = (s.cpu || {{}});
      const cpuPct = cpu.percent ?? ((cpu.load_ratio || 0) * 100);
      document.getElementById("cpuText").textContent = cpu.percent === null || cpu.percent === undefined
        ? `load ${{cpu.load?.one ?? "--"}} / ${{cpu.cores ?? "--"}} cores`
        : `${{cpu.percent.toFixed(1)}}%`;
      setBar("cpuBar", cpuPct);

      const mem = s.memory || {{}};
      document.getElementById("memText").textContent = `${{mem.percent ?? "--"}}%  ${{fmtBytes(mem.used)}} / ${{fmtBytes(mem.total)}}`;
      setBar("memBar", mem.percent);

      const disk = s.disk || {{}};
      document.getElementById("diskText").textContent = `${{disk.percent ?? "--"}}%  ${{fmtBytes(disk.used)}} / ${{fmtBytes(disk.total)}}`;
      setBar("diskBar", disk.percent);

      document.getElementById("networkRows").innerHTML = (s.network || []).map(row =>
        `<tr><td><code>${{row.iface}}</code></td><td>${{fmtRate(row.rx_rate)}}</td><td>${{fmtRate(row.tx_rate)}}</td></tr>`
      ).join("") || "<tr><td colspan=\\"3\\">No interface data</td></tr>";

      document.getElementById("briefPortRows").innerHTML = (s.ports || []).map(row =>
        `<li><div class="port-line"><code>${{row.port}}/${{row.proto}}</code><span class="pill">${{row.scope}}</span></div><span class="port-label">${{row.label || "configured"}}</span></li>`
      ).join("") || "<li><span>No configured ports</span><span></span></li>";

      document.getElementById("serviceRows").innerHTML = (s.services || []).map(row =>
        `<tr><td>${{serviceLabel(row.name)}}</td><td><span class="pill ${{pillClass(row.state)}}">${{row.state}}</span></td></tr>`
      ).join("");
      document.getElementById("daemonBriefRows").innerHTML = (s.services || [])
        .filter(row => ["nft-watchdog.service", "nft-listener.service", "nft-ssh-alert.service", "CosmosCloud.service", "docker.service"].includes(row.name))
        .map(row => `<li><span>${{briefName(row.name)}}</span><span class="status-indicator"><i class="${{dotClass(serviceOk(row))}}"></i> ${{row.state}}</span></li>`)
        .join("") || "<li><span>Services</span><span>unknown</span></li>";

      document.getElementById("updated").textContent = new Date().toLocaleTimeString();
    }}
    refresh().catch(console.error);
    setInterval(() => refresh().catch(console.error), 2000);
  </script>
</body>
</html>
"""


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
            "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        route = urlparse(self.path).path
        try:
            data = collect_dashboard()
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
