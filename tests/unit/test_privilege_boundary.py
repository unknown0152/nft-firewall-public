import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

import main


def test_clean_root_owned_paths_pass(tmp_path, monkeypatch):
    f = tmp_path / "code.py"
    f.write_text("x")
    f.chmod(0o644)
    # pretend the file is root-owned regardless of who runs the test
    real = os.lstat
    monkeypatch.setattr(main.os, "lstat", lambda p: _force_uid0(real(p)))
    violations, checked = main._scan_paths_for_escalation_risk([str(f)])
    assert violations == []
    assert checked == 1


def test_group_writable_file_is_flagged(tmp_path, monkeypatch):
    f = tmp_path / "code.py"
    f.write_text("x")
    f.chmod(0o664)   # group-writable — the escalation risk
    real = os.lstat
    monkeypatch.setattr(main.os, "lstat", lambda p: _force_uid0(real(p)))
    violations, _ = main._scan_paths_for_escalation_risk([str(f)])
    assert any("writable" in v for v in violations)


def test_non_root_owner_is_flagged(tmp_path, monkeypatch):
    f = tmp_path / "code.py"
    f.write_text("x")
    f.chmod(0o644)
    real = os.lstat
    monkeypatch.setattr(main.os, "lstat", lambda p: _force_uid(real(p), 999))
    violations, _ = main._scan_paths_for_escalation_risk([str(f)])
    assert any("not root" in v for v in violations)


def test_missing_paths_are_skipped():
    violations, checked = main._scan_paths_for_escalation_risk(["/no/such/path/xyz"])
    assert violations == []
    assert checked == 0


class _FakeStat:
    def __init__(self, st, uid):
        self.st_mode = st.st_mode
        self.st_uid = uid


def _force_uid0(st):
    return _FakeStat(st, 0)


def _force_uid(st, uid):
    return _FakeStat(st, uid)
