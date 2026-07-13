"""Permission and command-boundary tests for exported metrics."""

import os
import subprocess
import sys
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from utils import metrics


def test_handshake_metric_uses_privileged_read_wrapper(monkeypatch, tmp_path):
    wrapper = tmp_path / "fw-wg"
    wrapper.touch()
    calls = []
    monkeypatch.setattr(metrics, "_WG_WRAPPER", wrapper)

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, f"peer\t{int(time.time()) - 5}\n", "")

    monkeypatch.setattr(metrics.subprocess, "run", fake_run)

    assert 0 <= metrics._get_handshake_age("wg0") <= 10
    assert calls == [["sudo", "-n", str(wrapper), "show", "wg0", "latest-handshakes"]]


def test_metrics_export_is_group_readable(monkeypatch, tmp_path):
    target = tmp_path / "metrics.prom"
    monkeypatch.setattr(metrics, "_METRICS_FILE", target)
    monkeypatch.setattr(metrics, "_count_blocked_ips", lambda: 0)
    monkeypatch.setattr(metrics, "_count_drop_packets", lambda: 0)
    monkeypatch.setattr(metrics, "_get_handshake_age", lambda _iface: 1.0)
    monkeypatch.setattr(metrics, "_get_vpn_up", lambda _iface: 1)
    monkeypatch.setattr(metrics, "_count_threatfeed_entries", lambda: 0)
    monkeypatch.setattr(metrics, "_count_geo_cidrs", lambda: 0)
    monkeypatch.setattr(
        metrics.grp,
        "getgrnam",
        lambda _name: type("Group", (), {"gr_gid": os.getgid()})(),
    )

    metrics.metrics_update()

    assert target.exists()
    assert target.stat().st_mode & 0o777 == 0o640
    assert target.stat().st_gid == os.getgid()
