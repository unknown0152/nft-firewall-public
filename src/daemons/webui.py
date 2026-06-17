"""Read-only local web dashboard for nft-firewall.

The dashboard intentionally binds to localhost by default. Put Cosmos Cloud in
front of it for TLS, public routing, and authentication.
"""

from __future__ import annotations

import configparser
import html
import json
import os
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
    report = str(data.get("report", ""))
    status = str(health.get("status", "UNKNOWN"))
    reason = str(health.get("reason", "No reason reported"))
    status_class = _status_class(status)

    handshake = health.get("handshake_age_s", "n/a")
    vpn_ip = health.get("vpn_ip", "n/a")
    markers = health.get("markers", "n/a")
    nft_integrity = "intact" if health.get("nft_integrity") else "check"
    persisted = health.get("persisted_ruleset_integrity", "unknown")

    section_html = []
    for title, lines in _report_sections(report):
        rows = "\n".join(f"<li>{html.escape(line)}</li>" for line in lines)
        section_html.append(
            f'<section class="panel report-panel"><h2>{html.escape(title)}</h2><ul>{rows}</ul></section>'
        )

    body = "\n".join(section_html)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NFT Firewall Dashboard</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #080b10;
      --surface: #111820;
      --surface-2: #0e141b;
      --surface-3: #17212b;
      --text: #f3f7fb;
      --muted: #9aaabc;
      --soft: #c8d3df;
      --line: #253241;
      --green: #30d158;
      --yellow: #ffd60a;
      --red: #ff453a;
      --blue: #0a84ff;
      --cyan: #64d2ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, rgba(10,132,255,.18), transparent 360px),
        linear-gradient(180deg, #0b1017 0, var(--bg) 430px);
      color: var(--text);
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }}
    main {{ width: min(1280px, calc(100% - 28px)); margin: 0 auto; padding: 24px 0 36px; }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 18px;
      align-items: end;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--line);
    }}
    h1 {{ margin: 0; font-size: clamp(30px, 5vw, 58px); font-weight: 780; }}
    .subtitle {{ margin-top: 6px; color: var(--muted); max-width: 820px; }}
    .status-card {{
      min-width: 210px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(17,24,32,.88);
    }}
    .eyebrow {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .status-card strong {{ display: block; margin-top: 4px; font-size: 24px; }}
    .ok strong, .ok .value {{ color: var(--green); }}
    .warn strong, .warn .value {{ color: var(--yellow); }}
    .bad strong, .bad .value {{ color: var(--red); }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 10px;
      margin: 16px 0;
    }}
    .metric {{
      min-height: 88px;
      padding: 14px;
      border-radius: 8px;
      background: var(--surface);
      border: 1px solid var(--line);
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; }}
    .metric strong {{ display: block; margin-top: 8px; font-size: 18px; overflow-wrap: anywhere; }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(360px, .85fr);
      gap: 12px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .side {{ display: grid; gap: 12px; align-content: start; }}
    .panel {{
      padding: 16px;
      border-radius: 8px;
      background: rgba(14,20,27,.94);
      border: 1px solid var(--line);
    }}
    .panel h2 {{ margin: 0 0 12px; font-size: 16px; }}
    .bars {{ display: grid; gap: 12px; }}
    .bar-row {{ display: grid; gap: 6px; }}
    .bar-head {{ display: flex; align-items: baseline; justify-content: space-between; gap: 12px; color: var(--soft); }}
    .track {{ height: 10px; background: #202b38; border-radius: 99px; overflow: hidden; }}
    .fill {{ height: 100%; width: 0%; background: linear-gradient(90deg, var(--blue), var(--cyan)); transition: width .35s ease; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 8px 0; border-top: 1px solid rgba(255,255,255,.07); text-align: left; color: var(--soft); }}
    th {{ color: var(--muted); font-size: 12px; font-weight: 650; }}
    td:last-child, th:last-child {{ text-align: right; }}
    .pill {{ display: inline-flex; align-items: center; min-height: 22px; padding: 2px 8px; border-radius: 999px; background: var(--surface-3); color: var(--soft); }}
    .pill.ok {{ color: var(--green); }}
    .pill.warn {{ color: var(--yellow); }}
    .pill.bad {{ color: var(--red); }}
    ul {{ list-style: none; margin: 0; padding: 0; }}
    li {{ padding: 7px 0; border-top: 1px solid rgba(255,255,255,.06); color: var(--muted); }}
    li:first-child {{ border-top: 0; }}
    footer {{ margin-top: 16px; color: var(--muted); font-size: 12px; }}
    code {{ color: var(--cyan); }}
    @media (max-width: 1000px) {{
      header, .layout, .grid, .metrics {{ grid-template-columns: 1fr; }}
      .status-card {{ min-width: 0; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>NFT Firewall</h1>
        <div class="subtitle" id="reason">{html.escape(reason)}</div>
      </div>
      <div class="status-card {status_class}">
        <span class="eyebrow">Firewall State</span>
        <strong id="status">{html.escape(status)}</strong>
      </div>
    </header>
    <section class="metrics">
      {_metric("VPN IP", vpn_ip)}
      {_metric("Handshake", f"{handshake}s" if isinstance(handshake, int) else handshake)}
      {_metric("Markers", markers, "ok" if markers == "ok" else "warn")}
      {_metric("NFT Rules", nft_integrity, "ok" if nft_integrity == "intact" else "warn")}
      {_metric("Persisted Rules", persisted, "ok" if persisted == "ok" else "warn")}
    </section>
    <section class="layout">
      <div class="grid">{body}</div>
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
          <h2>Open Ports</h2>
          <table>
            <thead><tr><th>Port</th><th>Scope</th><th>Use</th></tr></thead>
            <tbody id="portRows"></tbody>
          </table>
        </section>
        <section class="panel">
          <h2>Services</h2>
          <table>
            <thead><tr><th>Service</th><th>State</th></tr></thead>
            <tbody id="serviceRows"></tbody>
          </table>
        </section>
      </aside>
    </section>
    <footer>Read-only local dashboard. Public access should stay behind Cosmos authentication. Last update: <span id="updated">initial</span></footer>
  </main>
  <script>
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
    async function refresh() {{
      const res = await fetch("/api/dashboard", {{cache: "no-store"}});
      const data = await res.json();
      const h = data.health || {{}};
      const s = data.system || {{}};
      document.getElementById("status").textContent = h.status || "UNKNOWN";
      document.getElementById("reason").textContent = h.reason || "No reason reported";
      document.querySelector(".status-card").className = `status-card ${{(h.status || "").toUpperCase() === "HEALTHY" ? "ok" : "warn"}}`;

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

      document.getElementById("portRows").innerHTML = (s.ports || []).map(row =>
        `<tr><td><code>${{row.port}}/${{row.proto}}</code></td><td>${{row.scope}}</td><td>${{row.label || "configured"}}</td></tr>`
      ).join("") || "<tr><td colspan=\\"3\\">No configured ports</td></tr>";

      document.getElementById("serviceRows").innerHTML = (s.services || []).map(row =>
        `<tr><td>${{row.name.replace(".service", "")}}</td><td><span class="pill ${{pillClass(row.state)}}">${{row.state}}</span></td></tr>`
      ).join("");

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
