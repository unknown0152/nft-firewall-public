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
