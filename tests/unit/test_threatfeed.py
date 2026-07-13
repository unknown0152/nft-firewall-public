"""tests/unit/test_threatfeed.py — threatfeed sync persistence behaviour."""
import sys
import grp
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

    with pytest.raises(RuntimeError, match="1 mutation failed"):
        threatfeed.sync()

    persisted = threatfeed._load_state()
    assert "1.1.1.1" in persisted
    assert "3.3.3.3" in persisted
    assert "2.2.2.2" not in persisted, (
        "2.2.2.2 failed to block; persisting it as blocked causes drift on next sync"
    )


def test_sync_persists_only_successfully_unblocked_ips(monkeypatch, tmp_path):
    """If unblock_ip fails, the IP must remain in persisted state."""
    state_file = tmp_path / "threatfeed-state.json"
    state_file.write_text(
        '{"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]}'
    )
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)

    # One IP remains in the non-empty feed; one old IP must be removed.
    monkeypatch.setattr(
        threatfeed,
        "_fetch_feed",
        lambda url: ["1.1.1.1", "3.3.3.3", "4.4.4.4", "9.9.9.9"],
    )

    fake_state_module = type("S", (), {})()
    fake_state_module.block_ip = lambda ip, **_kw: True
    # Only 1.1.1.1 unblocks successfully; 2.2.2.2 returns False
    fake_state_module.unblock_ip = lambda ip, **_kw: ip == "1.1.1.1"
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    with pytest.raises(RuntimeError, match="1 mutation failed"):
        threatfeed.sync()

    persisted = threatfeed._load_state()
    assert "1.1.1.1" in persisted
    assert "2.2.2.2" in persisted, (
        "2.2.2.2 failed to unblock; dropping it from state causes drift"
    )
    assert "9.9.9.9" in persisted


@pytest.mark.parametrize("fetched", [None, []])
def test_sync_never_treats_failed_or_empty_feed_as_remove_everything(
    monkeypatch, tmp_path, fetched
):
    state_file = tmp_path / "threatfeed-state.json"
    state_file.write_text('{"ips": ["1.1.1.1"]}')
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)
    monkeypatch.setattr(threatfeed, "_fetch_feed", lambda url: fetched)

    calls: list[str] = []
    fake_state_module = type("S", (), {})()
    fake_state_module.block_ip = lambda ip, **_kw: calls.append(f"block:{ip}") or True
    fake_state_module.unblock_ip = lambda ip, **_kw: calls.append(f"unblock:{ip}") or True
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    with pytest.raises(RuntimeError, match="feed (fetch failed|was empty)"):
        threatfeed.sync()

    assert calls == []
    assert threatfeed._load_state() == {"1.1.1.1"}


def test_fetch_feed_returns_failure_sentinel_on_network_error(monkeypatch):
    def fail(*_a, **_kw):
        raise OSError("offline")

    monkeypatch.setattr(threatfeed.urllib.request, "urlopen", fail)

    assert threatfeed._fetch_feed("https://invalid.example") is None


def test_sync_rejects_implausibly_truncated_feed(monkeypatch, tmp_path):
    state_file = tmp_path / "threatfeed-state.json"
    state_file.write_text(
        '{"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]}'
    )
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)
    monkeypatch.setattr(threatfeed, "_fetch_feed", lambda _url: ["1.1.1.1"])
    calls = []
    fake_state_module = type("S", (), {})()
    fake_state_module.block_ip = lambda ip, **_kw: calls.append(("add", ip)) or True
    fake_state_module.unblock_ip = lambda ip, **_kw: calls.append(("del", ip)) or True
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    with pytest.raises(RuntimeError, match="implausibly truncated"):
        threatfeed.sync()

    assert calls == []


def test_sync_rejects_nonpositive_max_entries(monkeypatch):
    monkeypatch.setattr(threatfeed, "_fetch_feed", lambda _url: ["1.1.1.1"])

    with pytest.raises(ValueError, match="max_entries must be positive"):
        threatfeed.sync(max_entries=0)


def test_root_saved_state_remains_readable_by_daemon_group(monkeypatch, tmp_path):
    state_file = tmp_path / "threatfeed-state.json"
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)

    threatfeed._save_state({"1.1.1.1"})

    assert state_file.stat().st_gid == grp.getgrnam("fw-admin").gr_gid
    assert state_file.stat().st_mode & 0o640 == 0o640
    assert list(tmp_path.glob("threatfeed-state.json.*.tmp")) == []


def test_threatfeed_lock_refuses_symlinks(monkeypatch, tmp_path):
    state_file = tmp_path / "threatfeed-state.json"
    target = tmp_path / "sensitive"
    target.write_text("do not touch")
    state_file.with_name(state_file.name + ".lock").symlink_to(target)
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)

    with pytest.raises(OSError):
        threatfeed._load_state()

    assert target.read_text() == "do not touch"
