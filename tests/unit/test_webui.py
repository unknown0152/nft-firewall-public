import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from daemons.webui import render_dashboard


def test_webui_renders_read_only_dashboard():
    html = render_dashboard({
        "health": {
            "status": "HEALTHY",
            "reason": "UP 10.0.0.2 handshake 12s ago",
            "vpn_ip": "10.0.0.2",
            "handshake_age_s": 12,
            "markers": "ok",
            "nft_integrity": True,
            "persisted_ruleset_integrity": "ok",
        },
        "report": "🛡 NFT Firewall\nStatus: healthy\n🌐 VPN\nHandshake: fresh",
        "config_path": "/opt/nft-firewall/config/firewall.ini",
    })

    assert "NFT Firewall" in html
    assert "HEALTHY" in html
    assert "10.0.0.2" in html
    assert "<form" not in html
    assert "method=\"post\"" not in html.lower()


def test_webui_systemd_unit_is_localhost_only_and_fw_admin():
    unit = Path(__file__).resolve().parent.parent.parent / "systemd" / "nft-webui.service"
    text = unit.read_text()

    assert "User=fw-admin" in text
    assert "NFT_FIREWALL_WEBUI_HOST=127.0.0.1" in text
    assert "NFT_FIREWALL_WEBUI_PORT=8787" in text
    assert "ExecStart=/usr/bin/python3 /opt/nft-firewall/src/main.py webui daemon" in text
