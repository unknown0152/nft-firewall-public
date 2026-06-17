import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from daemons.webui import _network_usage, render_dashboard


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
        "system": {
            "cpu": {"percent": 12.3, "load": {"one": 0.4}, "cores": 4},
            "memory": {"used": 1024, "total": 2048, "percent": 50.0},
            "disk": {"used": 4096, "total": 8192, "percent": 50.0},
            "network": [{"iface": "wg0", "rx_rate": 1000.0, "tx_rate": 2000.0}],
            "services": [{"name": "nft-webui.service", "state": "active"}],
            "ports": [{"port": 443, "proto": "tcp", "scope": "VPN", "label": "HTTPS / reverse proxy"}],
        },
    })

    assert "NFT Firewall" in html
    assert "HEALTHY" in html
    assert "10.0.0.2" in html
    assert "/api/dashboard" in html
    assert "Network Throughput" in html
    assert "Open Ports" in html
    assert "Live System" in html
    assert "<form" not in html
    assert "method=\"post\"" not in html.lower()


def test_webui_systemd_unit_is_localhost_only_and_fw_admin():
    unit = Path(__file__).resolve().parent.parent.parent / "systemd" / "nft-webui.service"
    text = unit.read_text()

    assert "User=fw-admin" in text
    assert "NFT_FIREWALL_WEBUI_HOST=127.0.0.1" in text
    assert "NFT_FIREWALL_WEBUI_PORT=8787" in text
    assert "ExecStart=/usr/bin/python3 /opt/nft-firewall/src/main.py webui daemon" in text


def test_network_usage_returns_selected_interfaces_after_warmup(monkeypatch):
    import daemons.webui as webui

    samples = [
        {"wg0": (1000, 2000), "enp1s0": (3000, 4000)},
        {"wg0": (3000, 5000), "enp1s0": (5000, 9000)},
    ]
    times = iter([10.0, 12.0])

    monkeypatch.setattr(webui, "_LAST_NET", {})
    monkeypatch.setattr(webui, "_read_network_bytes", lambda: samples.pop(0))
    monkeypatch.setattr(webui.time, "monotonic", lambda: next(times))

    first = _network_usage(["wg0"])
    second = _network_usage(["wg0"])

    assert first[0]["iface"] == "wg0"
    assert first[0]["rx_rate"] is None
    assert second[0]["rx_rate"] == 1000.0
    assert second[0]["tx_rate"] == 1500.0
