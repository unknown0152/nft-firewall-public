"""Read-only local web dashboard for nft-firewall.

The dashboard intentionally binds to localhost by default. Put Cosmos Cloud in
front of it for TLS, public routing, and authentication.
"""

from __future__ import annotations

import html
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from daemons.watchdog import NftWatchdog
from utils.formatter import build_status_report

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


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


def collect_dashboard(config_path: str | None = None) -> dict[str, Any]:
    """Collect read-only dashboard data."""
    cfg_path = config_path or _config_path()
    health = NftWatchdog(config_path=cfg_path).health()
    report = build_status_report(cfg_path)
    return {
        "health": health,
        "report": report,
        "config_path": cfg_path,
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
    """Render a complete dark-mode dashboard page."""
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
            f"<section class=\"panel\"><h2>{html.escape(title)}</h2><ul>{rows}</ul></section>"
        )

    body = "\n".join(section_html)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="30">
  <title>NFT Firewall Dashboard</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b0f14;
      --surface: #141b24;
      --surface-2: #101720;
      --text: #edf2f7;
      --muted: #9fb0c3;
      --line: #263241;
      --green: #39d98a;
      --yellow: #ffd166;
      --red: #ff6b6b;
      --blue: #67b7ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background:
        linear-gradient(180deg, rgba(103, 183, 255, .08), transparent 360px),
        var(--bg);
      color: var(--text);
      font: 15px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }}
    main {{ width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 40px; }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 18px;
      align-items: end;
      padding-bottom: 18px;
      border-bottom: 1px solid var(--line);
    }}
    h1 {{ margin: 0; font-size: clamp(28px, 4vw, 46px); font-weight: 760; }}
    .subtitle {{ margin-top: 8px; color: var(--muted); max-width: 780px; }}
    .status {{
      min-width: 190px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
    }}
    .status span {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .status strong {{ display: block; margin-top: 4px; font-size: 22px; }}
    .status.ok strong {{ color: var(--green); }}
    .status.warn strong {{ color: var(--yellow); }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 10px;
      margin: 18px 0;
    }}
    .metric {{
      min-height: 84px;
      padding: 14px;
      border-radius: 8px;
      background: var(--surface);
      border: 1px solid var(--line);
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; }}
    .metric strong {{ display: block; margin-top: 8px; font-size: 18px; overflow-wrap: anywhere; }}
    .metric.ok strong {{ color: var(--green); }}
    .metric.warn strong {{ color: var(--yellow); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .panel {{
      padding: 16px;
      border-radius: 8px;
      background: var(--surface-2);
      border: 1px solid var(--line);
    }}
    .panel h2 {{ margin: 0 0 10px; font-size: 16px; }}
    ul {{ list-style: none; margin: 0; padding: 0; }}
    li {{ padding: 7px 0; border-top: 1px solid rgba(255,255,255,.06); color: var(--muted); }}
    li:first-child {{ border-top: 0; }}
    footer {{ margin-top: 18px; color: var(--muted); font-size: 12px; }}
    code {{ color: var(--blue); }}
    @media (max-width: 880px) {{
      header, .grid, .metrics {{ grid-template-columns: 1fr; }}
      .status {{ min-width: 0; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>NFT Firewall</h1>
        <div class="subtitle">{html.escape(reason)}</div>
      </div>
      <div class="status {status_class}">
        <span>Firewall State</span>
        <strong>{html.escape(status)}</strong>
      </div>
    </header>
    <section class="metrics">
      {_metric("VPN IP", vpn_ip)}
      {_metric("Handshake", f"{handshake}s" if isinstance(handshake, int) else handshake)}
      {_metric("Markers", markers, "ok" if markers == "ok" else "warn")}
      {_metric("NFT Rules", nft_integrity, "ok" if nft_integrity == "intact" else "warn")}
      {_metric("Persisted Rules", persisted, "ok" if persisted == "ok" else "warn")}
    </section>
    <section class="grid">
      {body}
    </section>
    <footer>Read-only local dashboard. Public access should stay behind Cosmos authentication.</footer>
  </main>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "nft-firewall-webui/1"

    def _headers(self, status: HTTPStatus, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'")
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
        except Exception as exc:  # pragma: no cover - defensive server boundary
            payload = json.dumps({"status": "ERROR", "reason": str(exc)}, indent=2).encode("utf-8")
            self._headers(HTTPStatus.INTERNAL_SERVER_ERROR, "application/json; charset=utf-8")
            self.wfile.write(payload)
            return

        self._headers(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8")
        self.wfile.write(b"not found\n")

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        route = urlparse(self.path).path
        self._headers(HTTPStatus.OK if route in {"/", "/index.html", "/api/status"} else HTTPStatus.NOT_FOUND, "text/plain")

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

