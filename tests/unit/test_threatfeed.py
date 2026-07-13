"""tests/unit/test_threatfeed.py — threatfeed sync persistence behaviour."""
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor
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


def test_sync_treats_ip_covered_by_existing_cidr_as_satisfied(monkeypatch, tmp_path):
    """A feed IP covered by a broader block is effective but not feed-owned.

    nftables interval sets reject an exact /32 that overlaps an existing CIDR.
    The feed must neither fail the whole sync nor claim ownership of that /32,
    because removing the broader block later must cause the feed to retry it.
    """
    state_file = tmp_path / "threatfeed-state.json"
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)
    monkeypatch.setattr(
        threatfeed,
        "_fetch_feed",
        lambda _url: ["47.1.2.3", "198.51.100.7"],
    )

    calls: list[str] = []
    fake_state_module = type("S", (), {})()
    fake_state_module.SET_BLOCKED = "blocked_ips"
    fake_state_module.set_list = lambda _name, **_kw: ["47.0.0.0/8"]
    fake_state_module.block_ip = lambda ip, **_kw: calls.append(ip) or True
    fake_state_module.unblock_ip = lambda _ip, **_kw: True
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    assert threatfeed.sync() == (1, 0)
    assert calls == ["198.51.100.7"]
    assert threatfeed._load_state() == {"198.51.100.7"}


def test_sync_does_not_trust_stale_persistent_cidr(monkeypatch, tmp_path):
    """Persistent coverage cannot suppress an add when live coverage is absent."""
    state_file = tmp_path / "threatfeed-state.json"
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)
    monkeypatch.setattr(threatfeed, "_fetch_feed", lambda _url: ["47.1.2.3"])

    calls: list[str] = []
    fake_state_module = type("S", (), {})()
    fake_state_module.SET_BLOCKED = "blocked_ips"
    fake_state_module.load_persistent_sets = lambda: {
        "blocked_ips": ["47.0.0.0/8"],
    }
    fake_state_module.set_list = lambda _name, **_kw: []
    fake_state_module.block_ip = lambda ip, **_kw: calls.append(ip) or True
    fake_state_module.unblock_ip = lambda _ip, **_kw: True
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    assert threatfeed.sync() == (1, 0)
    assert calls == ["47.1.2.3"]
    assert threatfeed._load_state() == {"47.1.2.3"}


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


def test_sync_allows_intentional_max_entries_reduction(monkeypatch, tmp_path):
    state_file = tmp_path / "threatfeed-state.json"
    state_file.write_text(
        '{"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]}'
    )
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)
    monkeypatch.setattr(
        threatfeed,
        "_fetch_feed",
        lambda _url: ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
    )
    fake_state_module = type("S", (), {})()
    fake_state_module.block_ip = lambda _ip, **_kw: True
    fake_state_module.unblock_ip = lambda _ip, **_kw: True
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    assert threatfeed.sync(max_entries=1) == (0, 3)
    assert threatfeed._load_state() == {"1.1.1.1"}


def test_state_reader_does_not_wait_for_feed_reconciliation(monkeypatch, tmp_path):
    state_file = tmp_path / "threatfeed-state.json"
    state_file.write_text('{"ips": ["1.1.1.1"]}')
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)
    fetch_started = threading.Event()
    release_fetch = threading.Event()

    def slow_fetch(_url):
        fetch_started.set()
        release_fetch.wait(timeout=2)
        return ["1.1.1.1"]

    monkeypatch.setattr(threatfeed, "_fetch_feed", slow_fetch)
    fake_state_module = type("S", (), {})()
    fake_state_module.block_ip = lambda _ip, **_kw: True
    fake_state_module.unblock_ip = lambda _ip, **_kw: True
    monkeypatch.setitem(sys.modules, "core.state", fake_state_module)

    with ThreadPoolExecutor(max_workers=2) as pool:
        sync_future = pool.submit(threatfeed.sync)
        assert fetch_started.wait(timeout=1)
        read_future = pool.submit(threatfeed.get_entry_count)
        try:
            assert read_future.result(timeout=0.25) == 1
        finally:
            release_fetch.set()
        assert sync_future.result(timeout=2) == (0, 0)


def test_sync_rejects_nonpositive_max_entries(monkeypatch):
    monkeypatch.setattr(threatfeed, "_fetch_feed", lambda _url: ["1.1.1.1"])

    with pytest.raises(ValueError, match="max_entries must be positive"):
        threatfeed.sync(max_entries=0)


def test_root_saved_state_remains_readable_by_daemon_group(monkeypatch, tmp_path):
    state_file = tmp_path / "threatfeed-state.json"
    monkeypatch.setattr(threatfeed, "_STATE_FILE", state_file)
    monkeypatch.setattr(
        threatfeed.grp,
        "getgrnam",
        lambda _name: type("Group", (), {"gr_gid": os.getgid()})(),
    )

    threatfeed._save_state({"1.1.1.1"})

    assert state_file.stat().st_gid == os.getgid()
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
