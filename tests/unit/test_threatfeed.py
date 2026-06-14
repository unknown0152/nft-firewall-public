"""tests/unit/test_threatfeed.py — threatfeed sync persistence behaviour."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from integrations import threatfeed


def test_sync_persists_only_successfully_blocked_ips(monkeypatch, tmp_path):
    """If block_ip fails for a subset, those IPs must NOT be saved as blocked.

    Otherwise the next sync sees them in old_ips, computes them as already
    blocked, never retries, and the firewall stays out of sync with the feed.
    """
    state_file = tmp_path / "threatfeed-state.json"
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)

    fetched = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    monkeypatch.setattr(threatfeed, "_fetch_feed", lambda url: fetched)

    # Pretend block_ip succeeds for 1.1.1.1 and 3.3.3.3 but fails for 2.2.2.2.
    fake_state_module = type("S", (), {})()
    fake_state_module.block_ip = lambda ip, **_kw: ip != "2.2.2.2"
    fake_state_module.unblock_ip = lambda ip, **_kw: True
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    added, removed = threatfeed.sync()
    assert added == 2
    assert removed == 0

    persisted = threatfeed._load_state()
    assert "1.1.1.1" in persisted
    assert "3.3.3.3" in persisted
    assert "2.2.2.2" not in persisted, (
        "2.2.2.2 failed to block; persisting it as blocked causes drift on next sync"
    )


def test_sync_persists_only_successfully_unblocked_ips(monkeypatch, tmp_path):
    """If unblock_ip fails, the IP must remain in persisted state."""
    state_file = tmp_path / "threatfeed-state.json"
    state_file.write_text('{"ips": ["1.1.1.1", "2.2.2.2"]}')
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)

    monkeypatch.setattr(threatfeed, "_fetch_feed", lambda url: [])  # all gone

    fake_state_module = type("S", (), {})()
    fake_state_module.block_ip = lambda ip, **_kw: True
    # Only 1.1.1.1 unblocks successfully; 2.2.2.2 returns False
    fake_state_module.unblock_ip = lambda ip, **_kw: ip == "1.1.1.1"
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    added, removed = threatfeed.sync()
    assert added == 0
    assert removed == 1

    persisted = threatfeed._load_state()
    assert "1.1.1.1" not in persisted
    assert "2.2.2.2" in persisted, (
        "2.2.2.2 failed to unblock; dropping it from state causes drift"
    )
