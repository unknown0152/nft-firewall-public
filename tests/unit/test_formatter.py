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
