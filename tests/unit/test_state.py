import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from core import state


def _result(cmd, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)


def test_simulate_apply_uses_custom_nft_command_and_cleans_temp(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["tmp"] = cmd[-1]
        assert Path(cmd[-1]).read_text() == "flush ruleset\n"
        return _result(cmd)

    monkeypatch.setattr(state.subprocess, "run", fake_run)

    ok, err = state.simulate_apply("flush ruleset\n", nft_cmd=["sudo", "fw-nft"])

    assert (ok, err) == (True, "")
    assert captured["cmd"][:3] == ["sudo", "fw-nft", "--check"]
    assert not Path(captured["tmp"]).exists()


def test_simulate_apply_returns_error_text(monkeypatch):
    monkeypatch.setattr(
        state.subprocess,
        "run",
        lambda cmd, **kwargs: _result(cmd, returncode=1, stderr="bad syntax\n"),
    )

    assert state.simulate_apply("bad\n") == (False, "bad syntax")


def test_apply_ruleset_failure_raises_and_cleans_temp(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["tmp"] = cmd[-1]
        return _result(cmd, returncode=1, stderr="permission denied")

    monkeypatch.setattr(state.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="permission denied"):
        state.apply_ruleset("flush ruleset\n")
    assert not Path(captured["tmp"]).exists()


def test_save_conf_writes_world_readable_file(tmp_path):
    dest = tmp_path / "nftables.conf"

    state.save_conf("flush ruleset\n", path=dest)

    assert dest.read_text() == "flush ruleset\n"
    assert oct(dest.stat().st_mode & 0o777) == "0o644"


def test_load_and_save_persistent_sets_validate_and_normalize(tmp_path, capsys):
    path = tmp_path / "dynamic-sets.json"
    path.write_text(json.dumps({
        "blocked_ips": ["203.0.113.4", "0.0.0.0/0", ""],
        "trusted_ips": ["198.51.100.7"],
        "geowhitelist_ips": ["2.56.4.0/22"],
        "dk_ips": ["193.163.0.0/16"],
    }))

    loaded = state.load_persistent_sets(path)

    assert loaded["blocked_ips"] == ["203.0.113.4/32"]
    assert loaded["trusted_ips"] == ["198.51.100.7/32"]
    assert loaded["geowhitelist_ips"] == ["2.56.4.0/22"]
    assert loaded["dk_ips"] == ["193.163.0.0/16"]
    assert "ignored unsafe persisted blocked_ips member" in capsys.readouterr().out

    out = tmp_path / "saved.json"
    state.save_persistent_sets({"blocked_ips": ["203.0.113.4/32"]}, path=out)
    saved = json.loads(out.read_text())
    assert saved["blocked_ips"] == ["203.0.113.4/32"]
    assert saved["trusted_ips"] == []
    # Never world-accessible (owner rw, world none). The group-read bit may be
    # set so root-written state stays readable by the fw-admin daemon group.
    assert out.stat().st_mode & 0o606 == 0o600


def test_persist_set_member_adds_and_removes(monkeypatch):
    saved = {}
    monkeypatch.setattr(
        state,
        "load_persistent_sets",
        lambda: {name: [] for name in state._KNOWN_SETS},
    )
    monkeypatch.setattr(state, "save_persistent_sets", lambda sets: saved.update(sets))

    state.persist_set_member(state.SET_TRUSTED, "198.51.100.7/32", present=True)
    assert saved[state.SET_TRUSTED] == ["198.51.100.7/32"]

    monkeypatch.setattr(
        state,
        "load_persistent_sets",
        lambda: {**{name: [] for name in state._KNOWN_SETS}, state.SET_TRUSTED: ["198.51.100.7/32"]},
    )
    state.persist_set_member(state.SET_TRUSTED, "198.51.100.7/32", present=False)
    assert saved[state.SET_TRUSTED] == []


def test_audit_set_mutation_writes_jsonl(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDO_USER", "fw-admin")
    audit = tmp_path / "audit.jsonl"

    state._audit_set_mutation(
        "add",
        state.SET_BLOCKED,
        ["203.0.113.4/32"],
        path=audit,
    )

    record = json.loads(audit.read_text().strip())
    assert record["actor"] == "fw-admin"
    assert record["action"] == "add"
    assert record["set"] == state.SET_BLOCKED
    assert record["items"] == ["203.0.113.4/32"]
    assert record["count"] == 1
    assert isinstance(record["uid"], int)
    assert isinstance(record["euid"], int)
    assert "ts" in record
    assert oct(audit.stat().st_mode & 0o777) == "0o640"


def test_audit_set_mutation_failure_is_nonfatal(tmp_path, capsys):
    not_a_dir = tmp_path / "not-a-dir"
    not_a_dir.write_text("x")

    state._audit_set_mutation(
        "add",
        state.SET_BLOCKED,
        ["203.0.113.4/32"],
        path=not_a_dir / "audit.jsonl",
    )

    assert "audit log write failed" in capsys.readouterr().out


def test_merge_live_sets_into_persistent(monkeypatch):
    saved = {}
    monkeypatch.setattr(
        state,
        "load_persistent_sets",
        lambda: {**{name: [] for name in state._KNOWN_SETS}, state.SET_BLOCKED: ["203.0.113.1/32"]},
    )
    monkeypatch.setattr(
        state,
        "set_list",
        lambda name, persistent_fallback=False: ["203.0.113.2/32"] if name == state.SET_BLOCKED else [],
    )
    monkeypatch.setattr(state, "save_persistent_sets", lambda sets: saved.update(sets))

    merged = state.merge_live_sets_into_persistent()

    assert merged[state.SET_BLOCKED] == ["203.0.113.1/32", "203.0.113.2/32"]
    assert saved[state.SET_BLOCKED] == ["203.0.113.1/32", "203.0.113.2/32"]


def test_backup_and_restore_ruleset(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd == ["nft", "list", "ruleset"]:
            return _result(cmd, stdout="table ip firewall {}\n")
        return _result(cmd)

    monkeypatch.setattr(state.subprocess, "run", fake_run)

    backup = state.backup_ruleset(backup_dir=tmp_path)
    assert backup.read_text() == "table ip firewall {}\n"
    assert oct(backup.stat().st_mode & 0o777) == "0o600"

    state.restore_ruleset(backup_dir=tmp_path)
    assert calls[-1] == ["nft", "--file", str(backup)]


def test_backup_writes_placeholder_when_live_rules_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(
        state.subprocess,
        "run",
        lambda cmd, **kwargs: _result(cmd, returncode=1, stderr="no cap"),
    )

    backup = state.backup_ruleset(backup_dir=tmp_path)

    assert backup.read_text() == "# empty\nflush ruleset\n"


def test_restore_ruleset_errors(tmp_path, monkeypatch):
    with pytest.raises(RuntimeError, match="No backups found"):
        state.restore_ruleset(backup_dir=tmp_path)

    backup = tmp_path / "nftables_20260101_000000.conf"
    backup.write_text("flush ruleset\n")
    monkeypatch.setattr(
        state.subprocess,
        "run",
        lambda cmd, **kwargs: _result(cmd, returncode=1, stderr="restore failed"),
    )

    with pytest.raises(RuntimeError, match="restore failed"):
        state.restore_ruleset(backup)


def test_set_add_delete_and_list(monkeypatch):
    persisted = {name: [] for name in state._KNOWN_SETS}
    commands = []
    audits = []

    def fake_run(cmd, **kwargs):
        commands.append(list(cmd))
        if cmd[:4] == ["nft", "list", "set", "ip"]:
            return _result(cmd, stdout="set blocked_ips { elements = { 203.0.113.4, 198.51.100.0/24 } }")
        return _result(cmd)

    monkeypatch.setattr(state.subprocess, "run", fake_run)
    monkeypatch.setattr(state, "load_persistent_sets", lambda: {k: list(v) for k, v in persisted.items()})
    monkeypatch.setattr(state, "save_persistent_sets", lambda sets: persisted.update(sets))
    monkeypatch.setattr(
        state,
        "_audit_set_mutation",
        lambda action, set_name, ips: audits.append((action, set_name, list(ips))),
    )

    assert state.set_add_bulk(state.SET_BLOCKED, ["203.0.113.4/32"]) == 1
    assert persisted[state.SET_BLOCKED] == ["203.0.113.4/32"]
    assert state.set_del_bulk(state.SET_BLOCKED, ["203.0.113.4/32"]) == 1
    assert persisted[state.SET_BLOCKED] == []
    assert state.set_list(state.SET_BLOCKED) == ["203.0.113.4", "198.51.100.0/24"]
    assert any(cmd[0:2] == ["nft", "-f"] for cmd in commands)
    assert audits == [
        ("add", state.SET_BLOCKED, ["203.0.113.4/32"]),
        ("delete", state.SET_BLOCKED, ["203.0.113.4/32"]),
    ]


def test_set_bulk_failures_and_convenience_validation(monkeypatch):
    monkeypatch.setattr(
        state.subprocess,
        "run",
        lambda cmd, **kwargs: _result(cmd, returncode=1, stderr="nft failed"),
    )
    monkeypatch.setattr(state, "load_persistent_sets", lambda: {name: [] for name in state._KNOWN_SETS})

    assert state.set_add_bulk(state.SET_BLOCKED, []) == 0
    assert state.set_del_bulk(state.SET_BLOCKED, []) == 0
    assert state.set_add_bulk(state.SET_BLOCKED, ["203.0.113.4/32"]) == 0
    assert state.set_del_bulk(state.SET_BLOCKED, ["203.0.113.4/32"]) == 0
    assert state.set_list(state.SET_BLOCKED, persistent_fallback=True) == []
    assert state.block_ip("0.0.0.0/0") is False
    assert state.unblock_ip("not-an-ip") is False
    assert state.allow_ip("0.0.0.0/0") is False
    assert state.disallow_ip("not-an-ip") is False
