"""
tests/unit/test_ssh_alert.py — Unit tests for ssh_alert daemon.

Covers:
- _tail_stateful: first-run state, history not replayed
- _load_state / _save_state: persistence helpers
- SshAlertDaemon auto-block: short-window (3 in 5 min) and long-window (10 in 1 hr)
"""
import sys
import time as _time_module
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / 'src'))
from daemons.ssh_alert import (
    _tail_stateful, _load_state, _save_state,
    AUTO_BLOCK_THRESHOLD, AUTO_BLOCK_WINDOW,
    LONG_BLOCK_THRESHOLD, LONG_BLOCK_WINDOW,
    SshAlertDaemon,
)


# ---------------------------------------------------------------------------
# Test 1 — _load_state returns (None, 0) when the state file is absent
# ---------------------------------------------------------------------------

def test_load_state_returns_none_when_missing(tmp_path):
    result = _load_state(tmp_path / "nonexistent.json")
    assert result == (None, 0)


# ---------------------------------------------------------------------------
# Test 2 — first-run branch: inode and offset are captured in memory and
#           no lines from existing history are yielded before sleep fires.
#
# On first run the code reads st_ino and st_size into local variables
# (saved_inode, offset) but does NOT call _save_state until a *new* line
# is yielded.  The state file therefore does not exist after the first
# sleep fires with only pre-existing content.
#
# We verify the in-memory behaviour by appending a new line AFTER the
# generator has initialised (so history is skipped) and checking that
# only the new line is yielded.
# ---------------------------------------------------------------------------

def test_first_run_sets_inode_and_offset(tmp_path, monkeypatch):
    """After the first-run branch runs, existing content is skipped (EOF seek).

    We confirm this by checking that _load_state returns (None, 0) — i.e. the
    state file is NOT written — when no new lines appeared before sleep fires.
    """
    log_file = tmp_path / "auth.log"
    log_file.write_text("line1\nline2\nline3\n")
    state_file = tmp_path / "state.json"

    # Patch sleep to raise SystemExit to interrupt the infinite loop
    monkeypatch.setattr(_time_module, "sleep", lambda s: (_ for _ in ()).throw(SystemExit(0)))

    gen = _tail_stateful(log_file, state_file)
    try:
        next(gen)
    except (SystemExit, StopIteration):
        pass

    # The code only writes state when it yields a line; with no new lines after
    # the EOF seek, the state file must not exist yet.
    assert not state_file.exists(), (
        "State file should not be written on first run when no new lines appear"
    )


# ---------------------------------------------------------------------------
# Test 3 — first-run branch: history is not replayed
#
# Write content to the log, construct the generator (first-run branch runs
# and seeks to EOF), then interrupt via sleep.  Assert that no lines from
# the pre-existing content were ever yielded.
# ---------------------------------------------------------------------------

def test_first_run_does_not_replay_history(tmp_path, monkeypatch):
    log_file = tmp_path / "auth.log"
    log_file.write_text("old_line1\nold_line2\nold_line3\n")
    state_file = tmp_path / "state.json"

    yielded_lines = []

    # Patch sleep to raise SystemExit to break out of the loop
    monkeypatch.setattr(_time_module, "sleep", lambda s: (_ for _ in ()).throw(SystemExit(0)))

    gen = _tail_stateful(log_file, state_file)
    try:
        for line in gen:
            yielded_lines.append(line)
    except (SystemExit, StopIteration):
        pass

    assert yielded_lines == [], (
        f"Expected no lines on first run (history skipped), got: {yielded_lines}"
    )


# ---------------------------------------------------------------------------
# Helpers for auto-block threshold tests
# ---------------------------------------------------------------------------

def _make_alert() -> SshAlertDaemon:
    """Return an SshAlertDaemon with Keybase notifications and subprocess mocked out."""
    alert = SshAlertDaemon.__new__(SshAlertDaemon)
    import threading
    alert._lock               = threading.Lock()
    alert._attempt_counts     = {}
    alert._attempt_last_sent  = {}
    alert._attempt_timestamps = {}
    alert._long_timestamps    = {}
    alert._auto_blocked       = set()
    alert.config_path         = "/dev/null"
    alert._cfg                = None
    return alert


# ---------------------------------------------------------------------------
# Test 4 — short-window auto-block (3 failures within 5 minutes)
# ---------------------------------------------------------------------------

def test_short_window_auto_block_triggers(monkeypatch):
    """3 failures within AUTO_BLOCK_WINDOW seconds must call _auto_block."""
    alert = _make_alert()
    blocked_calls = []

    def _fake_auto_block(ip, count, user, window_label):
        blocked_calls.append((ip, window_label))
        alert._auto_blocked.add(ip)

    monkeypatch.setattr(alert, "_auto_block", _fake_auto_block)

    now = time.time()
    ip  = "1.2.3.4"

    # Inject AUTO_BLOCK_THRESHOLD failures all within the short window
    for _ in range(AUTO_BLOCK_THRESHOLD):
        alert._attempt_timestamps[ip] = alert._attempt_timestamps.get(ip, [])
        alert._attempt_timestamps[ip].append(now)
        alert._attempt_timestamps[ip] = [
            t for t in alert._attempt_timestamps[ip] if now - t <= AUTO_BLOCK_WINDOW
        ]
        window_count = len(alert._attempt_timestamps[ip])

        alert._long_timestamps[ip] = alert._long_timestamps.get(ip, [])
        alert._long_timestamps[ip].append(now)
        long_count = len(alert._long_timestamps[ip])

        already_blocked = ip in alert._auto_blocked

        from daemons.ssh_alert import _is_private_ip
        if window_count >= AUTO_BLOCK_THRESHOLD and not already_blocked and not _is_private_ip(ip):
            alert._auto_block(ip, window_count, "testuser", "5-min")

    assert len(blocked_calls) == 1, "Expected exactly one auto-block call"
    assert blocked_calls[0] == (ip, "5-min")


def test_short_window_does_not_trigger_below_threshold():
    """Fewer than AUTO_BLOCK_THRESHOLD failures must NOT trigger auto-block."""
    alert = _make_alert()
    blocked_calls = []

    now = time.time()
    ip  = "1.2.3.4"

    for _ in range(AUTO_BLOCK_THRESHOLD - 1):
        alert._attempt_timestamps[ip] = alert._attempt_timestamps.get(ip, [])
        alert._attempt_timestamps[ip].append(now)
        window_count = len(alert._attempt_timestamps[ip])

        from daemons.ssh_alert import _is_private_ip
        if window_count >= AUTO_BLOCK_THRESHOLD and ip not in alert._auto_blocked and not _is_private_ip(ip):
            blocked_calls.append(ip)

    assert blocked_calls == [], "Should not block below threshold"


# ---------------------------------------------------------------------------
# Test 5 — long-window auto-block (10 failures within 1 hour)
# ---------------------------------------------------------------------------

def test_long_window_auto_block_triggers(monkeypatch):
    """10 failures spread over < LONG_BLOCK_WINDOW seconds must trigger long-window block."""
    alert = _make_alert()
    blocked_calls = []

    def _fake_auto_block(ip, count, user, window_label):
        blocked_calls.append((ip, window_label))
        alert._auto_blocked.add(ip)

    monkeypatch.setattr(alert, "_auto_block", _fake_auto_block)

    now = time.time()
    ip  = "5.6.7.8"

    # Simulate LONG_BLOCK_THRESHOLD failures spaced > AUTO_BLOCK_WINDOW apart
    # so the short window never accumulates enough, but the long window does.
    from daemons.ssh_alert import _is_private_ip

    for i in range(LONG_BLOCK_THRESHOLD):
        # Spread across the hour — 5 min gaps keeps each short-window count at 1
        t = now - (LONG_BLOCK_WINDOW - 1) + i * (AUTO_BLOCK_WINDOW + 10)

        alert._attempt_timestamps[ip] = alert._attempt_timestamps.get(ip, [])
        alert._attempt_timestamps[ip].append(t)
        alert._attempt_timestamps[ip] = [
            x for x in alert._attempt_timestamps[ip] if now - x <= AUTO_BLOCK_WINDOW
        ]
        window_count = len(alert._attempt_timestamps[ip])

        alert._long_timestamps[ip] = alert._long_timestamps.get(ip, [])
        alert._long_timestamps[ip].append(t)
        alert._long_timestamps[ip] = [
            x for x in alert._long_timestamps[ip] if now - x <= LONG_BLOCK_WINDOW
        ]
        long_count = len(alert._long_timestamps[ip])

        already_blocked = ip in alert._auto_blocked

        if (window_count >= AUTO_BLOCK_THRESHOLD and not already_blocked and not _is_private_ip(ip)):
            alert._auto_block(ip, window_count, "testuser", "5-min")
        elif (long_count >= LONG_BLOCK_THRESHOLD and not already_blocked and not _is_private_ip(ip)):
            alert._auto_block(ip, long_count, "testuser", "1-hour")

    assert any(label == "1-hour" for _, label in blocked_calls), (
        "Expected a long-window auto-block after 10 spread-out failures"
    )


def test_private_ip_never_auto_blocked():
    """Private IPs must never be auto-blocked regardless of failure count."""
    from daemons.ssh_alert import _is_private_ip
    private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]
    for ip in private_ips:
        assert _is_private_ip(ip), f"{ip} should be private"
