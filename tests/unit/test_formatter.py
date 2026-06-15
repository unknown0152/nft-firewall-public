"""
tests/unit/test_formatter.py — Unit tests for build_status_report()
from src/utils/formatter.py.

Tests verify that build_status_report() returns a non-empty string containing
expected sections (VPN, Security, Daemons) by mocking subprocess calls and
watchdog import dependencies.
"""
import sys
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / 'src'))


def _make_ini(tmp_path):
    """Create a minimal firewall.ini for testing."""
    ini = tmp_path / "firewall.ini"
    ini.write_text("[network]\nphy_if = eth0\nvpn_interface = wg0\n")
    return str(ini)


def test_returns_nonempty_string(tmp_path, monkeypatch):
    """build_status_report() returns a non-empty string."""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))
    from utils.formatter import build_status_report
    result = build_status_report(_make_ini(tmp_path))
    assert isinstance(result, str) and len(result) > 0


def test_contains_vpn_section(tmp_path, monkeypatch):
    """build_status_report() contains VPN section with 'VPN' or related keywords."""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))
    from utils.formatter import build_status_report
    result = build_status_report(_make_ini(tmp_path))
    # The formatter includes "Network" section with VPN status
    assert "Network" in result or "VPN" in result


def test_contains_security_section(tmp_path, monkeypatch):
    """build_status_report() contains Security section."""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))
    from utils.formatter import build_status_report
    result = build_status_report(_make_ini(tmp_path))
    assert "Security" in result or "Killswitch" in result


def test_contains_daemons_section(tmp_path, monkeypatch):
    """build_status_report() contains Daemons section."""
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))
    from utils.formatter import build_status_report
    result = build_status_report(_make_ini(tmp_path))
    assert "Daemons" in result or "Watchdog" in result


def test_report_uses_brief_header(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: MagicMock(returncode=0, stdout="", stderr=""))
    from utils.formatter import build_status_report
    result = build_status_report(_make_ini(tmp_path))
    assert "Good Morning — Firewall Brief" in result


def test_firewall_open_ports_report_vpn_and_lan_scopes(tmp_path):
    ini = tmp_path / "firewall.ini"
    ini.write_text(
        "[network]\n"
        "extra_ports = 80, 443\n"
        "lan_allow_ports = 58473, 8096\n"
        "lan_allow_udp_ports = 7359\n"
        "torrent_port = 64279\n"
    )

    from utils.formatter import _firewall_open_ports

    ports = _firewall_open_ports(str(ini))
    assert (80, "tcp", "VPN") in ports
    assert (443, "tcp", "VPN") in ports
    assert (58473, "tcp", "LAN") in ports
    assert (7359, "udp", "LAN") in ports
    assert (64279, "tcp", "VPN") in ports
    assert (64279, "udp", "VPN") in ports
