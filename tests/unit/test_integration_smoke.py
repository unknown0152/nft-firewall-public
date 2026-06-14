"""
tests/unit/test_integration_smoke.py

Smoke tests that verify every V12 module imports cleanly and exposes
the expected public API. Catches import errors, missing functions, and
typos that would fail at runtime.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Ensure src/ is on the path
_SRC = Path(__file__).resolve().parent.parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def test_threatfeed_api() -> None:
    from integrations.threatfeed import sync, get_entry_count, _load_state, _save_state
    assert callable(sync)
    assert callable(get_entry_count)
    assert callable(_load_state)
    assert callable(_save_state)


def test_geoblock_api() -> None:
    from integrations.geoblock import (
        block_country, unblock_country, list_blocked,
        get_total_cidr_count, reblock_from_config,
    )
    assert callable(block_country)
    assert callable(unblock_country)
    assert callable(list_blocked)
    assert callable(get_total_cidr_count)
    assert callable(reblock_from_config)


def test_metrics_api() -> None:
    from utils.metrics import metrics_update
    assert callable(metrics_update)


def test_knockd_api() -> None:
    from daemons.knockd import PortKnockDaemon
    assert hasattr(PortKnockDaemon, "run_daemon")
    assert hasattr(PortKnockDaemon, "run_step")
    assert hasattr(PortKnockDaemon, "_add_rule")
    assert hasattr(PortKnockDaemon, "_remove_rule")
    assert hasattr(PortKnockDaemon, "_validate_vpn_iface")


def test_main_handlers_present() -> None:
    """All V12 CLI commands are registered in main._HANDLERS."""
    spec = importlib.util.spec_from_file_location("main", str(_SRC / "main.py"))
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    expected = {
        "threat-update",
        "geoblock",
        "geounblock",
        "geolist",
        "metrics-update",
        "knockd",
        "doctor",
        "safe-apply",
    }
    missing = expected - set(mod._HANDLERS.keys())
    assert not missing, f"Missing _HANDLERS keys: {missing}"
