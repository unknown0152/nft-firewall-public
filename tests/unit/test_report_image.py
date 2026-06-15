"""Unit tests for PNG report rendering."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from utils.report_image import render_report_png


def test_render_report_png_creates_png_file(tmp_path):
    report = "\n".join([
        "☀️ *Good Morning — Firewall Brief*",
        "`Mon, 15 Jun · 08:00`",
        "",
        "🟢 *HEALTHY*",
        "",
        "🌐 *Network*",
        "• VPN: 🟢 `203.0.113.10`",
        "• Handshake: 🟢 42s ago",
    ])
    output = tmp_path / "report.png"

    result = render_report_png(report, output_path=output)

    assert result == output
    assert output.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert output.stat().st_size > 1000
    assert output.stat().st_mode & 0o044 == 0o044
