import json
import subprocess
import sys
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from core import state


@pytest.fixture(autouse=True)
def isolated_state_lock_namespace(monkeypatch, tmp_path):
    lock_dir = tmp_path / "state-locks"
    lock_dir.mkdir(mode=0o750)
    monkeypatch.setattr(state, "_LOCK_DIR", lock_dir)


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


def test_save_conf_failure_preserves_previous_complete_file(tmp_path, monkeypatch):
    dest = tmp_path / "nftables.conf"
    dest.write_text("known good\n")

    def fail_replace(*_args):
        raise OSError("disk failure")

    monkeypatch.setattr(state.os, "replace", fail_replace)

    with pytest.raises(OSError, match="disk failure"):
        state.save_conf("candidate\n", path=dest)

    assert dest.read_text() == "known good\n"
    assert list(tmp_path.glob("nftables.conf.*.tmp")) == []


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


def test_persistent_lock_uses_root_controlled_namespace(monkeypatch, tmp_path):
    lock_dir = tmp_path / "root-controlled-locks"
    lock_dir.mkdir(mode=0o750)
    monkeypatch.setattr(state, "_LOCK_DIR", lock_dir)

    state_path = tmp_path / "daemon-writable" / "dynamic-sets.json"
    state_path.parent.mkdir()
    with state._persistent_sets_lock(state_path):
        assert (lock_dir / "dynamic-sets.lock").exists()
        assert not state_path.with_name("dynamic-sets.json.lock").exists()


def test_persistent_lock_times_out_instead_of_blocking_forever(
    monkeypatch, tmp_path
):
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir(mode=0o750)
    monkeypatch.setattr(state, "_LOCK_DIR", lock_dir)
    monkeypatch.setattr(state, "_LOCK_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(
        state.fcntl,
        "flock",
        lambda *_args: (_ for _ in ()).throw(BlockingIOError()),
    )

    with pytest.raises(TimeoutError, match="Timed out acquiring firewall state lock"):
        with state._persistent_sets_lock(tmp_path / "state.json"):
            pass


def test_persist_set_member_adds_and_removes(monkeypatch):
    saved = {name: [] for name in state._KNOWN_SETS}

    def update(mutator, **_kwargs):
        mutator(saved)
        return saved

    monkeypatch.setattr(state, "_update_persistent_sets", update)

    state.persist_set_member(state.SET_TRUSTED, "198.51.100.7/32", present=True)
    assert saved[state.SET_TRUSTED] == ["198.51.100.7/32"]

    state.persist_set_member(state.SET_TRUSTED, "198.51.100.7/32", present=False)
    assert saved[state.SET_TRUSTED] == []


def test_persistent_set_transactions_do_not_lose_concurrent_updates(tmp_path):
    path = tmp_path / "dynamic-sets.json"
    state.save_persistent_sets({}, path=path)
    ips = [f"203.0.113.{n}/32" for n in range(1, 21)]

    def add_one(ip):
        def mutate(sets):
            members = set(sets[state.SET_BLOCKED])
            time.sleep(0.005)  # widen the read-modify-write race window
            members.add(ip)
            sets[state.SET_BLOCKED] = sorted(members)

        state._update_persistent_sets(mutate, path=path)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add_one, ips))

    assert state.load_persistent_sets(path)[state.SET_BLOCKED] == sorted(ips)


def test_persistent_state_lock_refuses_symlinks(tmp_path):
    path = tmp_path / "dynamic-sets.json"
    target = tmp_path / "sensitive"
    target.write_text("do not touch")
    (state._LOCK_DIR / "dynamic-sets.lock").symlink_to(target)

    with pytest.raises(OSError):
        state.load_persistent_sets(path)

    assert target.read_text() == "do not touch"


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


def test_audit_log_refuses_first_writer_symlink(tmp_path):
    target = tmp_path / "sensitive"
    target.write_text("unchanged")
    audit = tmp_path / "audit.jsonl"
    audit.symlink_to(target)

    state._audit_set_mutation(
        "add", state.SET_BLOCKED, ["203.0.113.9/32"], path=audit
    )

    assert target.read_text() == "unchanged"


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
    saved = {**{name: [] for name in state._KNOWN_SETS}, state.SET_BLOCKED: ["203.0.113.1/32"]}

    def update(mutator, **_kwargs):
        mutator(saved)
        return saved

    monkeypatch.setattr(state, "_update_persistent_sets", update)
    monkeypatch.setattr(
        state,
        "set_list",
        lambda name, persistent_fallback=False: ["203.0.113.2/32"] if name == state.SET_BLOCKED else [],
    )

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
    assert backup.read_text() == "flush ruleset\ntable ip firewall {}\n"
    assert oct(backup.stat().st_mode & 0o777) == "0o600"

    state.restore_ruleset(backup_dir=tmp_path)
    assert calls[-1] == ["nft", "--file", str(backup)]


def test_backup_fails_closed_when_live_rules_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(
        state.subprocess,
        "run",
        lambda cmd, **kwargs: _result(cmd, returncode=1, stderr="no cap"),
    )

    with pytest.raises(RuntimeError, match="Cannot snapshot live ruleset"):
        state.backup_ruleset(backup_dir=tmp_path)

    assert list(tmp_path.glob("nftables_*.conf")) == []


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


def test_rollback_guard_is_detached_and_disarm_removes_token(monkeypatch, tmp_path):
    lock_dir = tmp_path / "guard-locks"
    lock_dir.mkdir(mode=0o750)
    monkeypatch.setattr(state, "_LOCK_DIR", lock_dir)
    backup = tmp_path / "backup.conf"
    backup.write_text("flush ruleset\n")
    backup.chmod(0o600)
    seen = {}

    class Process:
        stopped = False
        pid = 4242

        def poll(self):
            return 0 if self.stopped else None

        def terminate(self):
            self.stopped = True

        def wait(self, timeout):
            return 0

    process = Process()
    monkeypatch.setattr(
        state.os,
        "killpg",
        lambda pid, _sig: setattr(process, "stopped", pid == process.pid),
    )

    def popen(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        return process

    monkeypatch.setattr(state.subprocess, "Popen", popen)

    with state._persistent_sets_lock(tmp_path / "state.json"):
        guard = state.arm_rollback_guard(backup, timeout=65)
        inherited_lock_fd = state._LOCK_LOCAL.fd

    assert guard.token.exists()
    assert seen["kwargs"]["start_new_session"] is True
    assert seen["kwargs"]["close_fds"] is True
    assert seen["kwargs"]["pass_fds"] == (inherited_lock_fd,)
    assert str(backup) in seen["cmd"]

    state.disarm_rollback_guard(guard)

    assert process.stopped
    assert not guard.token.exists()


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
    monkeypatch.setattr(
        state,
        "_load_persistent_sets_unlocked",
        lambda _path: {k: list(v) for k, v in persisted.items()},
    )
    monkeypatch.setattr(
        state,
        "_save_persistent_sets_unlocked",
        lambda sets, _path: persisted.update(sets),
    )
    monkeypatch.setattr(
        state,
        "_audit_set_mutation",
        lambda action, set_name, ips, **kw: audits.append((action, set_name, list(ips))),
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


def test_live_nft_mutation_and_persistence_share_one_lock(monkeypatch, tmp_path):
    state_file = tmp_path / "dynamic-sets.json"
    monkeypatch.setattr(state, "_SETS_STATE_FILE", state_file)
    active = False
    lock_entries = 0

    @contextmanager
    def lock(_path):
        nonlocal active, lock_entries
        assert not active, "persistent-state lock must not be nested"
        active = True
        lock_entries += 1
        try:
            yield
        finally:
            active = False

    def fake_run(cmd, **_kwargs):
        assert active, f"live mutation escaped state lock: {cmd}"
        return _result(cmd)

    monkeypatch.setattr(state, "_persistent_sets_lock", lock)
    monkeypatch.setattr(state.subprocess, "run", fake_run)
    monkeypatch.setattr(state, "_audit_set_mutation", lambda *_a, **_kw: None)

    assert state.set_add_bulk(state.SET_BLOCKED, ["203.0.113.8/32"]) == 1
    assert state.set_del_bulk(state.SET_BLOCKED, ["203.0.113.8/32"]) == 1
    assert lock_entries == 2


def test_set_flush_clears_live_and_persistent_state(monkeypatch, tmp_path):
    state_file = tmp_path / "dynamic-sets.json"
    monkeypatch.setattr(state, "_SETS_STATE_FILE", state_file)
    state.save_persistent_sets(
        {state.SET_WHITELIST: ["203.0.113.0/24"]}, path=state_file
    )
    calls = []
    monkeypatch.setattr(
        state.subprocess,
        "run",
        lambda cmd, **_kw: calls.append(cmd) or _result(cmd),
    )
    monkeypatch.setattr(state, "_audit_set_mutation", lambda *_a, **_kw: None)

    assert state.set_flush(state.SET_WHITELIST) is True
    assert calls == [
        ["nft", "list", "set", "ip", "firewall", state.SET_WHITELIST],
        ["nft", "flush", "set", "ip", "firewall", state.SET_WHITELIST],
    ]
    assert state.load_persistent_sets(state_file)[state.SET_WHITELIST] == []


@pytest.mark.parametrize(
    ("operation", "expected_forward", "expected_rollback"),
    [
        ("add", "add element", "delete element"),
        ("delete", "delete element", "add element"),
    ],
)
def test_bulk_mutation_rolls_back_live_state_when_persistence_fails(
    monkeypatch, tmp_path, operation, expected_forward, expected_rollback
):
    monkeypatch.setattr(state, "_SETS_STATE_FILE", tmp_path / "dynamic-sets.json")
    scripts = []

    def fake_run(cmd, **_kwargs):
        if cmd[:2] == ["nft", "-f"]:
            scripts.append(Path(cmd[2]).read_text())
        return _result(cmd)

    def fail_save(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(state.subprocess, "run", fake_run)
    monkeypatch.setattr(state, "_save_persistent_sets_unlocked", fail_save)

    fn = state.set_add_bulk if operation == "add" else state.set_del_bulk
    with pytest.raises(OSError, match="disk full"):
        fn(state.SET_BLOCKED, ["203.0.113.8/32"])

    assert expected_forward in scripts[0]
    assert expected_rollback in scripts[1]


def test_set_flush_restores_live_members_when_persistence_fails(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(state, "_SETS_STATE_FILE", tmp_path / "dynamic-sets.json")
    scripts = []
    monkeypatch.setattr(
        state,
        "_load_persistent_sets_unlocked",
        lambda _path: {
            **{name: [] for name in state._KNOWN_SETS},
            state.SET_WHITELIST: ["203.0.113.0/24"],
        },
    )

    def fake_run(cmd, **_kwargs):
        if cmd[:2] == ["nft", "-f"]:
            scripts.append(Path(cmd[2]).read_text())
        return _result(cmd)

    monkeypatch.setattr(state.subprocess, "run", fake_run)
    monkeypatch.setattr(
        state,
        "_save_persistent_sets_unlocked",
        lambda *_args: (_ for _ in ()).throw(OSError("disk full")),
    )

    with pytest.raises(OSError, match="disk full"):
        state.set_flush(state.SET_WHITELIST)

    assert scripts == [
        "add element ip firewall geowhitelist_ips { 203.0.113.0/24 }\n"
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


def test_trusted_access_list_parses_permanent_and_timed(monkeypatch):
    raw = (
        "table ip firewall {\n"
        "\tset trusted_ips {\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags interval,timeout\n"
        "\t\telements = { 198.51.100.9,\n"
        "\t\t\t     203.0.113.88 timeout 45m expires 44m59s40ms }\n"
        "\t}\n}\n"
    )
    monkeypatch.setattr(
        state.subprocess, "run",
        lambda cmd, **kw: _result(cmd, stdout=raw),
    )
    entries = state.trusted_access_list()
    by_ip = {e["ip"]: e for e in entries}
    assert by_ip["198.51.100.9"]["permanent"] is True
    assert by_ip["198.51.100.9"]["expires"] is None
    assert by_ip["203.0.113.88"]["permanent"] is False
    assert by_ip["203.0.113.88"]["expires"] == "44m59s"   # ms trimmed
