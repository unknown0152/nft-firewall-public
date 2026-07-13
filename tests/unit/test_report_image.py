"""Unit tests for PNG report rendering."""
import sys
import stat
from types import SimpleNamespace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from utils import report_image
from utils.report_image import render_report_png
import main


def _sample_report() -> str:
    return "\n".join([
        "☀️ *Good Morning — Firewall Brief*",
        "`Mon, 15 Jun · 08:00`",
        "",
        "🟢 *HEALTHY*",
        "",
        "🌐 *Network*",
        "• VPN: 🟢 `203.0.113.10`",
        "• Handshake: 🟢 42s ago",
        "",
        "🐳 *Docker*",
        "• Runtime: 🟢 2 running",
        "• Exposed ports:",
        "  🛰️ `443/tcp`  VPN — HTTPS",
    ])


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_render_report_png_creates_png_file(tmp_path, theme):
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
    output = tmp_path / f"report-{theme}.png"

    result = render_report_png(report, output_path=output, theme=theme)

    assert result == output
    assert output.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert output.stat().st_size > 1000
    assert output.stat().st_mode & 0o044 == 0o044


def test_render_report_png_rejects_unknown_theme(tmp_path):
    with pytest.raises(ValueError, match="Unsupported image report theme"):
        render_report_png(_sample_report(), output_path=tmp_path / "bad.png", theme="sepia")


def test_render_report_png_can_use_shared_runtime_directory(tmp_path):
    result = render_report_png(_sample_report(), temp_dir=tmp_path, output_mode=0o640)

    assert result.parent == tmp_path
    assert result.name.startswith("nft-firewall-report-")
    assert result.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert stat.S_IMODE(result.stat().st_mode) == 0o640


def test_direct_cli_rejects_image_without_managed_runtime(monkeypatch):
    monkeypatch.delenv("NFT_FIREWALL_REPORT_DIR", raising=False)
    monkeypatch.setattr(
        main,
        "_die",
        lambda message: (_ for _ in ()).throw(RuntimeError(message)),
    )

    with pytest.raises(RuntimeError, match="managed daily-report service"):
        main._cmd_firewall_report(
            SimpleNamespace(weekly=True, image=True, image_theme="dark")
        )


def test_spoofed_report_runtime_is_rejected_before_side_effects(monkeypatch):
    calls = []
    monkeypatch.setenv("NFT_FIREWALL_REPORT_DIR", "/tmp/spoofed-report-dir")
    monkeypatch.setattr(
        main,
        "_die",
        lambda message: (_ for _ in ()).throw(RuntimeError(message)),
    )
    monkeypatch.setattr(
        main,
        "_config_path_for_daemon",
        lambda: calls.append("config") or Path("/unused"),
    )

    with pytest.raises(RuntimeError, match="managed daily-report service"):
        main._cmd_firewall_report(
            SimpleNamespace(weekly=True, image=True, image_theme="dark")
        )

    assert calls == []


def test_port_rows_drop_redundant_scope_suffix():
    parsed = report_image._parse_report("\n".join([
        "🐳 *Docker*",
        "  🏠 `58473/tcp`  LAN — SSH from LAN",
        "  🛰️ `64279/tcp`  VPN — Torrent",
    ]))

    rows = report_image._port_rows(parsed)

    assert rows[0].scope == "LAN"
    assert rows[0].service == "SSH"
    assert rows[1].scope == "VPN"
    assert rows[1].service == "Torrent"


def test_system_stats_use_clean_disk_label():
    parsed = report_image._parse_report("\n".join([
        "🖥️ *System*",
        "• CPU: 0.20, 0.50, 0.90",
        "• RAM: 4.8GB / 62.5GB",
        "• Disk: / is 6% full",
    ]))

    stats = report_image._system_stats(parsed)

    assert stats.disk_percent == 6
    assert stats.disk_label == "Root used"
    assert stats.disk_ratio == pytest.approx(0.06)
