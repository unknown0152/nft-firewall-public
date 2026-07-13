"""Behavioral tests for the wrapper text emitted by setup.py."""

from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


@pytest.fixture
def wrappers(tmp_path, monkeypatch):
    import setup

    emitted: dict[str, Path] = {}
    fake_nft = tmp_path / "fake-nft"
    fake_wg_quick = tmp_path / "fake-wg-quick"
    fake_stat = tmp_path / "fake-stat"
    wg_config = tmp_path / "wg0.conf"
    fake_nft.write_text(
        "#!/usr/bin/env bash\n"
        "if [ \"${1:-}\" = -a ] && [ \"${2:-}\" = list ]; then\n"
        "  echo 'ip saddr 203.0.113.7 comment \"nft-knockd\" # handle 42'\n"
        "  exit 0\n"
        "fi\n"
        "echo nft \"$@\"\n"
    )
    fake_nft.chmod(0o755)
    fake_stat.write_text(
        "#!/usr/bin/env bash\n"
        "target=$(readlink -f \"${@: -1}\")\n"
        "case \"$*\" in\n"
        "  *%F*) echo 'regular file' ;;\n"
        f"  *%U*) case \"$target\" in {tmp_path}/*) echo fw-admin ;; *) echo root ;; esac ;;\n"
        "esac\n"
    )
    fake_stat.chmod(0o755)
    fake_wg_quick.write_text(
        "#!/usr/bin/env bash\n"
        "if [ \"${1:-}\" = up ] && [ -f \"${2:-}\" ]; then cat \"$2\"; else echo wg-quick \"$@\"; fi\n"
    )
    fake_wg_quick.chmod(0o755)
    wg_config.write_text(
        "[Interface]\nPrivateKey = private\n"
        "[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "Endpoint = first.example:51820\n"
        "[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"
        "Endpoint = second.example:51821\n"
    )

    def write_safe_test_double(path: Path, content: str) -> None:
        # Exercise the generated shell policy without invoking host networking tools.
        content = content.replace("/usr/bin/wg-quick", str(fake_wg_quick))
        for binary in (
            "/usr/bin/wg",
            "/usr/bin/ip",
            "/usr/sbin/conntrack",
            "/usr/bin/systemctl",
            "/usr/local/bin/fw",
        ):
            content = content.replace(binary, "/bin/echo")
        content = content.replace("/usr/sbin/nft", str(fake_nft))
        content = content.replace("/usr/bin/stat", str(fake_stat))
        content = content.replace(
            'config="/etc/wireguard/${vpn_if}.conf"', f'config="{wg_config}"'
        )
        content = content.replace(
            "/run/nft-wg-recover.XXXXXX", str(tmp_path / "nft-wg-recover.XXXXXX")
        )
        content = content.replace(
            "/usr/local/lib/nft-firewall/fw-wg-recover", "/bin/echo"
        )
        content = content.replace(
            "/usr/local/lib/nft-firewall/fw-wg-inspect", "/bin/echo"
        )
        dest = tmp_path / path.name
        dest.write_text(content)
        dest.chmod(0o755)
        emitted[path.name] = dest

    monkeypatch.setattr(setup, "_write_executable", write_safe_test_double)
    monkeypatch.setattr(setup, "_configured_vpn_interface", lambda: "wg0")
    monkeypatch.setattr(setup, "_configured_ssh_port", lambda: 2222)
    monkeypatch.setattr(setup, "_configured_knock_ssh_port", lambda: 3333, raising=False)
    monkeypatch.setattr(setup, "_ok", lambda *_a, **_kw: None)
    setup._install_sudo_wrappers()
    return emitted


def run_wrapper(
    wrappers: dict[str, Path], name: str, *args: str, env: dict[str, str] | None = None
):
    effective_env = {**os.environ, "SUDO_USER": "fw-admin"} if env is None else env
    return subprocess.run(
        ["bash", str(wrappers[name]), *args],
        capture_output=True,
        text=True,
        check=False,
        env=effective_env,
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
        ("fw-nft", ("--check", "--file", "/etc/shadow")),
        ("fw-nft", ("delete", "rule", "ip", "firewall", "input", "handle", "42")),
        ("fw-nft", ("knock-del", "99")),
        ("fw-action", ("safe-apply", "cosmos-vpn-secure")),
        ("fw-action", ("block", "0.0.0.0/0")),
        ("fw-action", ("status", "extra")),
        ("fw-threat-update", ("extra",)),
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
        ("fw-nft", ("knock-del", "42")),
        ("fw-nft", ("list", "ruleset")),
        ("fw-nft", ("--check-persisted",)),
        ("fw-wg-quick", ("recover", "wg0", "203.0.113.9")),
        ("fw-action", ("status",)),
        ("fw-action", ("block", "203.0.113.7")),
        ("fw-action", ("allow", "203.0.113.7", "30m")),
        ("fw-action", ("allow", "203.0.113.7", "1d12h")),
        ("fw-action", ("allow", "203.0.113.7", "48H")),
        ("fw-threat-update", ()),
    ],
)
def test_wrappers_keep_exact_watchdog_and_knock_operations(wrappers, name, args):
    result = run_wrapper(wrappers, name, *args)
    assert result.returncode == 0, result.stdout + result.stderr


def test_knock_wrapper_uses_effective_knock_port(wrappers):
    result = run_wrapper(wrappers, "fw-nft", "knock-add", "203.0.113.7")
    assert result.returncode == 0
    assert "dport 3333" in result.stdout


def test_nft_check_accepts_only_fw_admin_owned_regular_file(wrappers, tmp_path):
    check_file = tmp_path / "nft_check_rules.conf"
    check_file.write_text("table ip test {}\n")
    check_file.chmod(0o600)

    result = run_wrapper(wrappers, "fw-nft", "--check", "--file", str(check_file))

    assert result.returncode == 0, result.stdout + result.stderr


def test_nft_check_rejects_secondary_includes(wrappers, tmp_path):
    check_file = tmp_path / "nft_check_include.conf"
    check_file.write_text('include "/etc/shadow"\n')
    check_file.chmod(0o600)

    result = run_wrapper(wrappers, "fw-nft", "--check", "--file", str(check_file))

    assert result.returncode == 126, result.stdout + result.stderr


def test_nft_check_parses_root_owned_snapshot_not_mutable_source(wrappers):
    wrapper_text = wrappers["fw-nft"].read_text()
    check_branch = wrapper_text.split("--check)", 1)[1].split(
        "--check-persisted)", 1
    )[0]

    assert 'snapshot="$snapshot_dir/ruleset.conf"' in wrapper_text
    assert 'grep -Eq' in wrapper_text and '"$snapshot"' in wrapper_text
    assert '--file "$snapshot"' in wrapper_text
    assert '--file /proc/self/fd/3' not in check_branch


def test_read_only_webui_cannot_use_nft_mutation_modes(wrappers):
    env = {**os.environ, "SUDO_USER": "nft-webui"}

    denied = run_wrapper(
        wrappers, "fw-nft", "knock-add", "203.0.113.7", env=env
    )
    allowed = run_wrapper(wrappers, "fw-nft", "list", "ruleset", env=env)

    assert denied.returncode == 126
    assert allowed.returncode == 0


def test_metrics_can_read_nft_chains_but_cannot_mutate(wrappers):
    env = {**os.environ, "SUDO_USER": "nft-metrics"}

    allowed = run_wrapper(
        wrappers, "fw-nft", "list", "chain", "ip", "firewall", "input", env=env
    )
    denied = run_wrapper(
        wrappers, "fw-nft", "knock-add", "203.0.113.7", env=env
    )

    assert allowed.returncode == 0
    assert denied.returncode == 126


def test_ssh_alert_can_block_but_cannot_grant_trusted_access(wrappers):
    env = {**os.environ, "SUDO_USER": "nft-ssh-alert"}

    block = run_wrapper(wrappers, "fw-action", "block", "203.0.113.7", env=env)
    allow = run_wrapper(wrappers, "fw-action", "allow", "203.0.113.7", env=env)

    assert block.returncode == 0
    assert allow.returncode == 126


def test_read_only_service_cannot_repoint_wireguard_peer(wrappers):
    env = {**os.environ, "SUDO_USER": "nft-webui"}
    result = run_wrapper(
        wrappers, "fw-wg", "set", "wg0", "peer", "A" * 43 + "=",
        "endpoint", "203.0.113.9:51820", env=env,
    )
    assert result.returncode == 126


@pytest.mark.parametrize("caller", ["nft-webui", "nft-reporter"])
def test_dashboard_readers_can_inspect_but_not_delete_vpn_interface(
    wrappers, caller
):
    env = {**os.environ, "SUDO_USER": caller}

    link = run_wrapper(wrappers, "fw-ip", "link", "show", "wg0", env=env)
    addr = run_wrapper(wrappers, "fw-ip", "addr", "show", "wg0", env=env)
    delete = run_wrapper(wrappers, "fw-ip", "link", "delete", "wg0", env=env)

    assert link.returncode == 0
    assert addr.returncode == 0
    assert delete.returncode == 126


def test_wg_inspection_preserves_base64_padding(wrappers):
    result = run_wrapper(wrappers, "fw-wg-inspect", "wg0")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in result.stdout


def test_wg_recovery_only_rewrites_the_first_peer(wrappers):
    result = run_wrapper(wrappers, "fw-wg-recover", "wg0", "203.0.113.9")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Endpoint = 203.0.113.9:51820" in result.stdout
    assert "Endpoint = second.example:51821" in result.stdout
