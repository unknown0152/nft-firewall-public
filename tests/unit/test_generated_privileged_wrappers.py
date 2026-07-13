"""Behavioral tests for the wrapper text emitted by setup.py."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


@pytest.fixture
def wrappers(tmp_path, monkeypatch):
    import setup

    emitted: dict[str, Path] = {}

    def write_safe_test_double(path: Path, content: str) -> None:
        # Exercise the generated shell policy without invoking host networking tools.
        for binary in (
            "/usr/sbin/nft",
            "/usr/bin/wg-quick",
            "/usr/bin/wg",
            "/usr/bin/ip",
            "/usr/sbin/conntrack",
            "/usr/bin/systemctl",
        ):
            content = content.replace(binary, "/bin/echo")
        dest = tmp_path / path.name
        dest.write_text(content)
        dest.chmod(0o755)
        emitted[path.name] = dest

    monkeypatch.setattr(setup, "_write_executable", write_safe_test_double)
    monkeypatch.setattr(setup, "_configured_vpn_interface", lambda: "wg0")
    monkeypatch.setattr(setup, "_ok", lambda *_a, **_kw: None)
    setup._install_sudo_wrappers()
    return emitted


def run_wrapper(wrappers: dict[str, Path], name: str, *args: str):
    return subprocess.run(
        ["bash", str(wrappers[name]), *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("fw-wg-quick", ("up", "/tmp/attacker/wg0.conf")),
        ("fw-wg-quick", ("up", "wg0", "extra")),
        ("fw-ip", ("link", "delete", "eth0")),
        ("fw-ip", ("link", "delete", "wg0", "extra")),
        ("fw-systemctl", ("restart", "wg-quick@wg0.service", "ssh.service")),
        ("fw-wg", ("show", "wg0", "latest-handshakes", "extra")),
        ("fw-conntrack", ("-F", "--any-extra-option")),
        (
            "fw-nft",
            ("--echo", "--json", "add", "rule", "ip", "firewall", "input", "accept"),
        ),
        (
            "fw-nft",
            ("add", "element", "ip", "firewall", "trusted_ips", "0.0.0.0/0"),
        ),
        (
            "fw-nft",
            ("delete", "rule", "ip", "firewall", "input", "handle", "not-a-number"),
        ),
        ("fw-nft", ("list", "ruleset", "extra")),
        ("fw-nft", ("list", "ruleset;id")),
        ("fw-nft", ("--check", "/tmp/rules.conf")),
    ],
)
def test_wrappers_reject_privilege_boundary_bypasses(wrappers, name, args):
    result = run_wrapper(wrappers, name, *args)
    assert result.returncode == 126, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("fw-wg-quick", ("up", "wg0")),
        ("fw-wg-quick", ("down", "wg0")),
        ("fw-ip", ("link", "show", "wg0")),
        ("fw-ip", ("link", "delete", "wg0")),
        ("fw-systemctl", ("restart", "wg-quick@wg0.service")),
        ("fw-wg", ("show", "wg0", "latest-handshakes")),
        ("fw-conntrack", ("-F",)),
        ("fw-nft", ("knock-add", "203.0.113.7")),
        ("fw-nft", ("delete", "rule", "ip", "firewall", "input", "handle", "42")),
        ("fw-nft", ("list", "ruleset")),
        ("fw-nft", ("--check", "--file", "/tmp/rules.conf")),
    ],
)
def test_wrappers_keep_exact_watchdog_and_knock_operations(wrappers, name, args):
    result = run_wrapper(wrappers, name, *args)
    assert result.returncode == 0, result.stdout + result.stderr
