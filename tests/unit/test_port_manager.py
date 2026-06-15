"""Unit tests for control-panel port manager helpers."""
import configparser
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

import main


def _write_config(path: Path, body: str) -> None:
    path.write_text(body.strip() + "\n")


def _read_config(path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    return cfg


def test_change_config_port_opens_sorted_unique_port(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(
        config,
        """
[network]
extra_ports = 443, 80
""",
    )

    changed, ports = main._change_config_port(config, "extra_ports", "8443", open_port=True)

    cfg = _read_config(config)
    assert changed is True
    assert ports == [80, 443, 8443]
    assert cfg.get("network", "extra_ports") == "80, 443, 8443"


def test_change_config_port_can_store_port_description(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(config, "[network]\nextra_ports = 80\n")

    changed, ports = main._change_config_port(
        config,
        "extra_ports",
        "8443",
        open_port=True,
        description="Test dashboard",
    )

    cfg = _read_config(config)
    assert changed is True
    assert ports == [80, 8443]
    assert cfg.get("port_labels", "vpn_tcp_8443") == "Test dashboard"


def test_change_config_port_removes_description_when_port_closes(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(
        config,
        """
[network]
lan_allow_ports = 8096

[port_labels]
lan_tcp_8096 = Jellyfin
""",
    )

    changed, ports = main._change_config_port(config, "lan_allow_ports", 8096, open_port=False)

    cfg = _read_config(config)
    assert changed is True
    assert ports == []
    assert not cfg.has_section("port_labels")


def test_format_port_lines_uses_configured_and_default_labels(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(
        config,
        """
[network]
lan_allow_ports = 58473, 9000

[port_labels]
lan_tcp_9000 = Test app
""",
    )
    cfg = _read_config(config)

    assert main._format_port_lines(cfg, "lan_allow_ports") == [
        "`9000` — Test app",
        "`58473` — SSH from LAN",
    ]


def test_change_config_port_closes_existing_port(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(
        config,
        """
[network]
lan_allow_ports = 80, 443, 8096
""",
    )

    changed, ports = main._change_config_port(config, "lan_allow_ports", 443, open_port=False)

    cfg = _read_config(config)
    assert changed is True
    assert ports == [80, 8096]
    assert cfg.get("network", "lan_allow_ports") == "80, 8096"


def test_change_config_port_reports_no_change_for_absent_close(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(
        config,
        """
[network]
lan_allow_udp_ports = 7359
""",
    )

    changed, ports = main._change_config_port(config, "lan_allow_udp_ports", 9999, open_port=False)

    assert changed is False
    assert ports == [7359]


def test_change_config_port_rejects_invalid_port(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(config, "[network]\nextra_ports = 80\n")

    with pytest.raises(ValueError, match="1-65535"):
        main._change_config_port(config, "extra_ports", "70000", open_port=True)


def test_change_config_port_rejects_unknown_config_key(tmp_path):
    config = tmp_path / "firewall.ini"
    _write_config(config, "[network]\nextra_ports = 80\n")

    with pytest.raises(ValueError, match="unsupported port list"):
        main._change_config_port(config, "ssh_port", "2222", open_port=True)


def test_port_change_notification_for_opened_port(tmp_path):
    title, body, tags, priority = main._port_change_notification(
        port="8443",
        label="VPN TCP",
        open_port=True,
        profile="cosmos-vpn-secure",
        cfg_path=tmp_path / "firewall.ini",
        key="extra_ports",
        description="Test dashboard",
    )

    assert title == "Firewall port opened"
    assert "OPENED: VPN TCP port 8443" in body
    assert "Description: Test dashboard" in body
    assert "Profile: cosmos-vpn-secure" in body
    assert "Config key: network.extra_ports" in body
    assert "safe-apply confirmed" in body
    assert tags == "warning,shield"
    assert priority == "high"


def test_port_change_notification_for_closed_port(tmp_path):
    title, body, tags, priority = main._port_change_notification(
        port=7359,
        label="LAN UDP",
        open_port=False,
        profile="cosmos-vpn-secure",
        cfg_path=tmp_path / "firewall.ini",
        key="lan_allow_udp_ports",
    )

    assert title == "Firewall port closed"
    assert "CLOSED: LAN UDP port 7359" in body
    assert "Config key: network.lan_allow_udp_ports" in body
    assert tags == "shield"
    assert priority == "default"
