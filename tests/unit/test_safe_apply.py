"""Transactional persistence tests for apply and safe-apply."""

from __future__ import annotations

import argparse
import sys
from contextlib import contextmanager
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

import main
from core import rules, state
from integrations import docker


def _arrange_apply(monkeypatch, *, stdin_ready: bool, stdin_text: str = "", save_error=None):
    events: list[str] = []
    ruleset_cfg = object()

    monkeypatch.setattr(main, "_load_config", lambda: object())
    monkeypatch.setattr(main, "_build_ruleset_config", lambda *_a: ruleset_cfg)
    monkeypatch.setattr(main, "_write_watchdog_markers", lambda _cfg: events.append("markers"))
    monkeypatch.setattr(main, "_reapply_geoblocks", lambda: events.append("geoblocks"))
    monkeypatch.setattr(rules, "generate_ruleset", lambda *_a, **_kw: "new rules\n")
    monkeypatch.setattr(docker, "load_registry", lambda: [])
    monkeypatch.setattr(state, "simulate_apply", lambda _rules: (True, ""))
    monkeypatch.setattr(state, "backup_ruleset", lambda: Path("/backup/known-good.conf"))
    monkeypatch.setattr(state, "apply_ruleset", lambda _rules: events.append("apply"))
    def save(_rules):
        events.append("save")
        if save_error is not None:
            raise save_error

    monkeypatch.setattr(state, "save_conf", save)
    monkeypatch.setattr(state, "restore_ruleset", lambda _path: events.append("restore"))
    guard = object()
    monkeypatch.setattr(
        state,
        "arm_rollback_guard",
        lambda _path, timeout=65: events.append("guard-arm") or guard,
        raising=False,
    )
    monkeypatch.setattr(
        state,
        "disarm_rollback_guard",
        lambda value: events.append("guard-disarm") if value is guard else None,
        raising=False,
    )

    @contextmanager
    def transaction_lock():
        events.append("lock-enter")
        try:
            yield
        finally:
            events.append("lock-exit")

    monkeypatch.setattr(state, "firewall_transaction_lock", transaction_lock)

    import select

    monkeypatch.setattr(select, "select", lambda *_a: ([sys.stdin], [], []) if stdin_ready else ([], [], []))
    monkeypatch.setattr(sys, "stdin", type("Input", (), {"readline": lambda self: stdin_text})())
    return events


def test_safe_apply_rejection_never_persists_candidate(monkeypatch):
    events = _arrange_apply(monkeypatch, stdin_ready=False)

    result = main._cmd_apply(argparse.Namespace(profile="test", dry_run=False, safe=True))

    assert result is False
    assert events == [
        "lock-enter", "guard-arm", "apply", "restore", "guard-disarm", "lock-exit"
    ]


def test_safe_apply_persists_only_after_explicit_confirmation(monkeypatch):
    events = _arrange_apply(monkeypatch, stdin_ready=True, stdin_text="CONFIRM\n")

    result = main._cmd_apply(argparse.Namespace(profile="test", dry_run=False, safe=True))

    assert result is True
    assert events == [
        "lock-enter", "guard-arm", "apply", "guard-disarm", "save",
        "markers", "geoblocks", "lock-exit"
    ]


def test_regular_apply_persists_immediately_after_live_apply(monkeypatch):
    events = _arrange_apply(monkeypatch, stdin_ready=False)

    result = main._cmd_apply(argparse.Namespace(profile="test", dry_run=False, safe=False))

    assert result is True
    assert events == [
        "lock-enter", "guard-arm", "apply", "save", "guard-disarm",
        "markers", "geoblocks", "lock-exit"
    ]


def test_persistence_failure_restores_known_good_live_rules(monkeypatch):
    import pytest

    events = _arrange_apply(
        monkeypatch,
        stdin_ready=True,
        stdin_text="CONFIRM\n",
        save_error=OSError("disk full"),
    )

    with pytest.raises(SystemExit):
        main._cmd_apply(argparse.Namespace(profile="test", dry_run=False, safe=True))

    assert events == [
        "lock-enter", "guard-arm", "apply", "guard-disarm", "save", "restore",
        "guard-disarm", "lock-exit"
    ]
