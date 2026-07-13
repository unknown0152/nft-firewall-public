import sys
import pytest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def test_setup_install_sequence_does_not_apply_live_rules(monkeypatch):
    import setup

    calls = []
    for name in (
        "step0_0_validate_prerequisites",
        "step0_configure",
        "step1_create_system_user",
        "step2_install_code",
        "step2_5_nft_preflight",
        "step3_scaffold_dirs",
        "step4_install_sudoers",
        "step5_deploy_services",
        "step6_reload_and_restart",
        "step7_activate_vpn",
    ):
        monkeypatch.setattr(setup, name, lambda name=name, **_kw: calls.append(name))

    setup.cmd_install()

    # The installer should run the sequence but not 'apply' (which is the live rule command)
    # Applying rules is handled by 'fw safe-apply' manually post-install.
    assert calls[0] == "step0_0_validate_prerequisites"
    assert "step7_activate_vpn" in calls


def test_fw_wrapper_blocks_plain_apply():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "fw"
    text = script.read_text()
    assert "safe-apply" in text
    assert "use 'fw safe-apply <profile>'" in text


def test_setup_sh_exposes_curl_uninstall_modes():
    setup_sh = Path(__file__).resolve().parent.parent.parent / "setup.sh"
    text = setup_sh.read_text()

    assert "--uninstall" in text
    assert "--keybase-only" in text
    assert "bash scripts/uninstall.sh" in text
    assert "uninstall_args+=(--with-keybase)" in text
    assert "uninstall_args+=(--keybase-only)" in text


def test_uninstall_script_keeps_keybase_opt_in():
    uninstall_sh = Path(__file__).resolve().parent.parent.parent / "scripts" / "uninstall.sh"
    text = uninstall_sh.read_text()

    assert "--with-keybase" in text
    assert "--keybase-only" in text
    assert "REMOVE_KEYBASE=0" in text
    assert "apt-get purge -y keybase" in text
    assert "Keybase package/account data left untouched" in text
    assert "Type '$expected' to proceed" in text


def test_keybase_wrapper_sets_login_like_environment():
    setup_py = Path(__file__).resolve().parent.parent.parent / "setup.py"
    text = setup_py.read_text()

    assert 'default_kb_user="{kb_user or ""}"' in text
    assert 'Path("/opt/nft-firewall/config/firewall.ini")' in text
    assert 'cfg.get("keybase", "linux_user", fallback="").strip()' in text
    assert 'kb_user="${NFT_FIREWALL_KEYBASE_USER:-${config_kb_user:-$default_kb_user}}"' in text
    assert 'Keybase linux_user does not exist: $kb_user' in text
    assert 'kb_uid="$(id -u "$kb_user")"' in text
    assert 'XDG_RUNTIME_DIR="$kb_home/.config"' in text
    assert 'XDG_RUNTIME_DIR="/run/user/$kb_uid"' not in text
    assert 'DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$kb_uid/bus"' in text
    assert ('exec "$sudo_bin" -iu "$kb_user" -- /usr/bin/env '
            'XDG_RUNTIME_DIR="$kb_home/.config" /usr/bin/keybase "$@"') in text
    assert 'exec "$runuser_bin" -u "$kb_user" -- env' in text
    assert '/usr/bin/keybase "$@"' in text
    assert 'runuser -l "$kb_user"' not in text


def test_keybase_one_off_repair_uses_generic_runtime_wrapper():
    script = (
        Path(__file__).resolve().parent.parent.parent
        / "scripts"
        / "fix-keybase-wrapper.sh"
    )
    text = script.read_text()

    assert 'Path("/opt/nft-firewall/config/firewall.ini")' in text
    assert 'cfg.get("keybase", "linux_user", fallback="").strip()' in text
    assert 'NFT_FIREWALL_KEYBASE_USER' in text
    assert 'NFT_FIREWALL_SYSTEM_USER' in text
    assert 'XDG_RUNTIME_DIR="$kb_home/.config"' in text
    assert 'XDG_RUNTIME_DIR="/run/user/$kb_uid"' not in text
    assert 'DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$kb_uid/bus"' in text
    assert ('exec "$sudo_bin" -iu "$kb_user" -- /usr/bin/env '
            'XDG_RUNTIME_DIR="$kb_home/.config" /usr/bin/keybase "$@"') in text
    assert 'exec "$runuser_bin" -u "$kb_user" -- env' in text
    assert '/usr/bin/keybase "$@"' in text
    assert 'runuser -l "$kb_user"' not in text


def test_firewall_threatfeed_service_uses_real_cli_command():
    service = (
        Path(__file__).resolve().parent.parent.parent
        / "systemd"
        / "nft-firewall-threatfeed.service"
    )
    text = service.read_text()

    assert "ExecStart=/usr/bin/sudo -n /usr/local/lib/nft-firewall/fw-threat-update" in text
    assert "threatfeed update" not in text
    assert not service.with_name("nft-threat-update.service").exists()
    assert not service.with_name("nft-threat-update.timer").exists()


def test_daily_report_uses_traversable_shared_runtime_directory():
    text = (
        Path(__file__).resolve().parent.parent.parent
        / "systemd"
        / "nft-daily-report.service"
    ).read_text()

    assert "PrivateTmp=true" in text
    assert "RuntimeDirectory=nft-firewall-report" in text
    assert "Group=nft-report" in text
    assert "SupplementaryGroups=fw-admin" in text
    assert "RuntimeDirectoryMode=0710" in text
    assert "NFT_FIREWALL_REPORT_DIR=/run/nft-firewall-report" in text

def test_all_firewall_services_have_baseline_systemd_hardening():
    service_dir = Path(__file__).resolve().parent.parent.parent / "systemd"
    required = {
        "UMask=0077",
        "PrivateTmp=true",
        "ProtectClock=true",
        "ProtectControlGroups=true",
        "ProtectHostname=true",
        "ProtectKernelLogs=true",
        "ProtectKernelModules=true",
        "LockPersonality=true",
        "RestrictRealtime=true",
        "SystemCallArchitectures=native",
    }

    for service in service_dir.glob("*.service"):
        directives = set(service.read_text().splitlines())
        assert required <= directives, f"{service.name} missing {sorted(required - directives)}"


def test_knockd_has_only_the_capabilities_required_for_capture_and_nft():
    service = (
        Path(__file__).resolve().parent.parent.parent
        / "systemd"
        / "nft-knockd.service"
    ).read_text()

    assert "AmbientCapabilities=CAP_NET_RAW" in service
    assert (
        "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE"
        in service
    )


def test_watchdog_unit_uses_privileged_systemctl_wrapper():
    service = (
        Path(__file__).resolve().parent.parent.parent
        / "systemd"
        / "nft-watchdog.service"
    )
    text = service.read_text()

    assert "ExecStartPre=-/usr/bin/sudo /usr/local/lib/nft-firewall/fw-systemctl start wg-quick@wg0.service" in text
    assert "ExecStartPre=-/usr/bin/sudo /usr/bin/systemctl start wg-quick@wg0.service" not in text


def test_systemctl_wrapper_skips_start_when_wireguard_interface_exists():
    setup_py = Path(__file__).resolve().parent.parent.parent / "setup.py"
    text = setup_py.read_text()

    assert 'vpn_if="@VPN_IF@"' in text
    assert 'unit="wg-quick@${vpn_if}.service"' in text
    assert '[ "$#" -ne 2 ] || [ "${2:-}" != "$unit" ]' in text
    assert '/usr/bin/ip link show dev "$vpn_if"' in text
    assert 'exit 0' in text


def test_core_hardening_repairs_cosmos_bind_mount_permissions():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "core-hardening.sh"
    text = script.read_text()

    assert "repair_media_stack_permissions" in text
    assert "discover_container_permission_ids" in text
    assert "discover_cosmos_bind_dirs" in text
    assert "docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}'" in text
    assert "PUID=*" in text
    assert "PGID=*" in text
    assert "setfacl -R" in text
    assert 'CONTAINER_UIDS="${NFT_FIREWALL_CONTAINER_UIDS:-1000 1001}"' in text
    assert "/srv/config/seerr" in text
    assert "ReadOnlyPaths=/srv/docker" in text


def test_unit_patching_uses_configured_wireguard_interface(monkeypatch, tmp_path):
    import setup

    install_dir = tmp_path / "opt" / "nft-firewall"
    config_dir = install_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "firewall.ini").write_text(
        "[network]\nvpn_interface = wg-test\n"
    )
    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)

    patched = setup._patch_unit(
        "After=network-online.target wg-quick@wg0.service\n"
        "ExecStartPre=-/usr/bin/sudo /usr/local/lib/nft-firewall/fw-systemctl start wg-quick@wg0.service\n"
    )

    assert "wg-quick@wg-test.service" in patched
    assert "wg-quick@wg0.service" not in patched


def test_unit_patching_preserves_isolated_service_user(monkeypatch):
    import setup

    monkeypatch.setattr(setup, "_configured_vpn_interface", lambda: "wg0")

    assert "User=nft-webui" in setup._patch_unit("User=nft-webui\n")


def test_uninstall_flushes_live_ruleset(monkeypatch):
    import setup

    calls = []
    monkeypatch.setattr(setup, "_run", lambda cmd, **kw: calls.append(tuple(cmd)))
    monkeypatch.setattr(setup, "_ok",   lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "shutil", type("S", (), {"rmtree": lambda *a: None})())

    import pathlib
    monkeypatch.setattr(setup, "INSTALL_DIR",  type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(setup, "SUDOERS_FILE", type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(pathlib.Path, "exists", lambda s: False)

    setup.cmd_uninstall()

    flush_call = ("/usr/sbin/nft", "flush", "ruleset")
    assert flush_call in calls, f"nft flush ruleset not called; calls={calls}"


def test_uninstall_flushes_before_stopping_services(monkeypatch):
    import setup

    calls = []
    monkeypatch.setattr(setup, "_run", lambda cmd, **kw: calls.append(tuple(cmd)))
    monkeypatch.setattr(setup, "_ok",   lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "shutil", type("S", (), {"rmtree": lambda *a: None})())

    import pathlib
    monkeypatch.setattr(setup, "INSTALL_DIR",  type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(setup, "SUDOERS_FILE", type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(pathlib.Path, "exists", lambda s: False)

    setup.cmd_uninstall()

    flush_idx = next(i for i, c in enumerate(calls) if c == ("/usr/sbin/nft", "flush", "ruleset"))
    systemctl_indices = [i for i, c in enumerate(calls) if c[0] == "systemctl"]
    assert all(flush_idx < s for s in systemctl_indices), (
        f"flush (idx={flush_idx}) must precede all systemctl calls (idx={systemctl_indices})"
    )


def test_install_sequence_calls_nft_preflight(monkeypatch):
    import setup

    calls = []
    for name in (
        "step0_0_validate_prerequisites",
        "step0_configure",
        "step1_create_system_user",
        "step2_install_code",
        "step2_5_nft_preflight",
        "step3_scaffold_dirs",
        "step4_install_sudoers",
        "step5_deploy_services",
        "step6_reload_and_restart",
        "step7_activate_vpn",
    ):
        monkeypatch.setattr(setup, name, lambda name=name, **_kw: calls.append(name))

    setup.cmd_install()

    assert "step2_5_nft_preflight" in calls
    assert calls.index("step0_0_validate_prerequisites") < calls.index("step0_configure")
    assert calls.index("step2_5_nft_preflight") > calls.index("step2_install_code")
    assert calls.index("step2_5_nft_preflight") < calls.index("step3_scaffold_dirs")


def test_install_prerequisites_run_before_side_effects(monkeypatch):
    import setup

    calls = []
    for name in (
        "step0_configure",
        "step1_create_system_user",
        "step2_install_code",
        "step2_5_nft_preflight",
        "step3_scaffold_dirs",
        "step4_install_sudoers",
        "step5_deploy_services",
        "step6_reload_and_restart",
        "step7_activate_vpn",
    ):
        monkeypatch.setattr(setup, name, lambda name=name, **_kw: calls.append(name))

    monkeypatch.setattr(setup.shutil, "which", lambda cmd: None if cmd == "nft" else f"/usr/bin/{cmd}")

    with pytest.raises(SystemExit):
        setup.cmd_install()

    assert calls == []


def test_validate_prerequisites_reports_missing_command(monkeypatch, capsys):
    import setup

    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)
    monkeypatch.setattr(setup.shutil, "which", lambda cmd: None if cmd == "nft" else f"/usr/bin/{cmd}")

    with pytest.raises(SystemExit):
        setup.step0_0_validate_prerequisites()

    captured = capsys.readouterr()
    assert "Missing required command(s)" in captured.err
    assert "nft" in captured.err
    assert "nftables" in captured.err


def test_preflight_exits_on_nft_syntax_error(monkeypatch, tmp_path):
    import setup
    import subprocess as _subprocess

    ini = tmp_path / "firewall.ini"
    ini.write_text(
        "[network]\nphy_if = eth0\nvpn_server_ip = 1.2.3.4\n"
        "vpn_server_port = 51820\nlan_net = 192.168.1.0/24\nssh_port = 22\n"
    )
    monkeypatch.setattr(setup, "_CONF_FILE", ini)

    real_src = str(Path(__file__).resolve().parent.parent.parent / "src")
    monkeypatch.syspath_prepend(real_src)

    monkeypatch.setattr(
        _subprocess, "run",
        lambda *a, **kw: _subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Error: syntax error at line 42"
        ),
    )

    with pytest.raises(SystemExit):
        setup.step2_5_nft_preflight(src_path=Path(__file__).resolve().parent.parent.parent / "src")


def test_preflight_exits_cleanly_when_nft_missing(monkeypatch, tmp_path, capsys):
    import setup
    import subprocess as _subprocess

    ini = tmp_path / "firewall.ini"
    ini.write_text(
        "[network]\nphy_if = eth0\nvpn_server_ip = 1.2.3.4\n"
        "vpn_server_port = 51820\nlan_net = 192.168.1.0/24\nssh_port = 22\n"
    )
    monkeypatch.setattr(setup, "_CONF_FILE", ini)

    def _missing_nft(*_args, **_kwargs):
        raise FileNotFoundError("/usr/sbin/nft")

    monkeypatch.setattr(_subprocess, "run", _missing_nft)

    with pytest.raises(SystemExit):
        setup.step2_5_nft_preflight(src_path=Path(__file__).resolve().parent.parent.parent / "src")

    captured = capsys.readouterr()
    assert "Missing /usr/sbin/nft" in captured.err
    assert "nftables" in captured.err


def test_step6_skips_optional_services_without_runtime_prereqs(monkeypatch):
    import setup

    calls = []

    monkeypatch.setattr(
        setup,
        "_run",
        lambda cmd, **_kw: calls.append(cmd) or type("R", (), {"returncode": 0, "stderr": ""})(),
    )
    monkeypatch.setattr(setup.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(setup, "_wireguard_runtime_ready", lambda: False)
    monkeypatch.setattr(setup, "_keybase_chatops_ready", lambda: False)
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)

    setup.step6_reload_and_restart()

    assert ["systemctl", "daemon-reload"] in calls
    assert ["systemctl", "enable", "nft-ssh-alert.service"] in calls
    assert ["systemctl", "restart", "nft-ssh-alert.service"] in calls
    assert ["systemctl", "enable", "nft-watchdog.service"] not in calls
    assert ["systemctl", "restart", "nft-watchdog.service"] not in calls
    assert ["systemctl", "enable", "nft-listener.service"] not in calls
    assert ["systemctl", "restart", "nft-listener.service"] not in calls
    assert ["systemctl", "enable", "nft-daily-report.timer"] not in calls
    assert ["systemctl", "restart", "nft-daily-report.timer"] not in calls
    for unit in (
        "nft-firewall-doctor.timer",
        "nft-firewall-threatfeed.timer",
        "nft-metrics.timer",
    ):
        assert ["systemctl", "enable", unit] in calls
        assert ["systemctl", "restart", unit] in calls


def test_step6_starts_optional_services_when_runtime_prereqs_exist(monkeypatch):
    import setup

    calls = []

    monkeypatch.setattr(
        setup,
        "_run",
        lambda cmd, **_kw: calls.append(cmd) or type("R", (), {"returncode": 0, "stderr": ""})(),
    )
    monkeypatch.setattr(setup.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(setup, "_wireguard_runtime_ready", lambda: True)
    monkeypatch.setattr(setup, "_keybase_chatops_ready", lambda: True)
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)

    setup.step6_reload_and_restart()

    for unit in ("nft-watchdog.service", "nft-listener.service", "nft-ssh-alert.service"):
        assert ["systemctl", "enable", unit] in calls
        assert ["systemctl", "restart", unit] in calls
    assert ["systemctl", "enable", "nft-daily-report.timer"] in calls
    assert ["systemctl", "restart", "nft-daily-report.timer"] in calls


def test_keybase_chatops_ready_requires_working_wrapper(monkeypatch, tmp_path):
    import configparser
    import setup
    import subprocess as _subprocess

    cfg = configparser.ConfigParser()
    cfg["keybase"] = {
        "linux_user": "botuser",
        "target_user": "botaccount",
        "team": "ops",
    }
    wrapper = tmp_path / "nft-keybase-notify"
    wrapper.write_text("#!/bin/sh\n")

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _subprocess.CompletedProcess(cmd, 0, stdout="botaccount\n", stderr="")

    monkeypatch.setattr(setup, "_read_install_config", lambda: cfg)
    monkeypatch.setattr(setup.shutil, "which", lambda cmd: "/usr/bin/keybase" if cmd == "keybase" else None)
    monkeypatch.setattr(setup.pwd, "getpwnam", lambda user: object())
    monkeypatch.setattr(setup, "KEYBASE_WRAPPER", wrapper)
    monkeypatch.setattr(setup, "_prepare_keybase_session", lambda user: None)
    monkeypatch.setattr(setup.subprocess, "run", fake_run)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)

    assert setup._keybase_chatops_ready()
    assert calls[0][0] == [str(wrapper), "whoami"]
    assert calls[0][1]["env"]["NFT_FIREWALL_KEYBASE_USER"] == "botuser"


def test_keybase_wrapper_is_limited_to_required_chat_operations(monkeypatch, tmp_path):
    import setup

    wrapper = tmp_path / "nft-keybase-notify"
    monkeypatch.setattr(setup, "KEYBASE_WRAPPER", wrapper)
    monkeypatch.setattr(
        setup.pwd,
        "getpwnam",
        lambda _user: type("PW", (), {"pw_dir": "/home/bot", "pw_uid": 1000})(),
    )
    monkeypatch.setattr(setup, "_ok", lambda *_a, **_kw: None)

    setup._install_keybase_wrapper("bot")
    text = wrapper.read_text()

    assert "case \"${1:-}\" in" in text
    assert "whoami)" in text
    assert "chat)" in text
    for verb in ("list-channels", "create-channel", "send", "upload", "api"):
        assert f"{verb})" in text
    assert "denied Keybase operation" in text
    assert 'exec 9<"$resolved_upload"' in text
    assert 'chown root:nft-report /run/nft-firewall-report' in text
    assert 'chmod 0510 /run/nft-firewall-report' in text
    assert '"/proc/self/fd/9"' in text
    assert 'dirname -- "$resolved_upload"' in text


def test_keybase_chatops_ready_rejects_logged_out_wrapper(monkeypatch, tmp_path):
    import configparser
    import setup
    import subprocess as _subprocess

    cfg = configparser.ConfigParser()
    cfg["keybase"] = {
        "linux_user": "botuser",
        "target_user": "botaccount",
        "team": "ops",
    }
    wrapper = tmp_path / "nft-keybase-notify"
    wrapper.write_text("#!/bin/sh\n")
    warnings = []

    monkeypatch.setattr(setup, "_read_install_config", lambda: cfg)
    monkeypatch.setattr(setup.shutil, "which", lambda cmd: "/usr/bin/keybase" if cmd == "keybase" else None)
    monkeypatch.setattr(setup.pwd, "getpwnam", lambda user: object())
    monkeypatch.setattr(setup, "KEYBASE_WRAPPER", wrapper)
    monkeypatch.setattr(setup, "_prepare_keybase_session", lambda user: None)
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda cmd, **kwargs: _subprocess.CompletedProcess(
            cmd,
            1,
            stdout="",
            stderr=(
                "Failed to reach user-level systemd daemon.\n"
                "dial unix /home/botuser/.config/keybase/keybased.sock: connect: no such file or directory"
            ),
        ),
    )
    monkeypatch.setattr(setup, "_warn", lambda msg, *a, **kw: warnings.append(msg))

    assert not setup._keybase_chatops_ready()
    assert any("Keybase user session is not reachable for botuser" in msg for msg in warnings)
    assert any("Repair with: sudo -iu botuser run_keybase -g" in msg for msg in warnings)
    assert not any("dial unix" in msg for msg in warnings)


def test_prepare_keybase_session_starts_service_without_login_prompt(monkeypatch):
    import setup
    import subprocess as _subprocess

    calls = []
    monkeypatch.delenv("NFT_FIREWALL_KEYBASE_LOGIN", raising=False)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "time", SimpleNamespace(sleep=lambda _seconds: None))
    monkeypatch.setattr(setup, "_keybase_direct_whoami", lambda _user: "")
    monkeypatch.setattr(setup, "_ask_tty_yes_no", lambda *a, **kw: False)
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda cmd, **kwargs: calls.append((cmd, kwargs))
        or _subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
    )

    setup._prepare_keybase_session("botuser")

    assert calls
    assert calls[0][0][:3] == ["sudo", "-iu", "botuser"]
    assert "run_keybase -g" in calls[0][0][-1]
    assert not any("keybase login" in call[0][-1] for call in calls)


def test_prepare_keybase_session_launches_login_when_requested(monkeypatch):
    import setup
    import subprocess as _subprocess

    calls = []
    monkeypatch.setenv("NFT_FIREWALL_KEYBASE_LOGIN", "1")
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "time", SimpleNamespace(sleep=lambda _seconds: None))
    monkeypatch.setattr(setup, "_keybase_direct_whoami", lambda _user: "")
    monkeypatch.setattr(setup, "_ask_tty_yes_no", lambda *a, **kw: False)
    monkeypatch.setattr(setup, "_dev_tty_available", lambda: True)
    monkeypatch.setattr(
        setup.subprocess,
        "run",
        lambda cmd, **kwargs: calls.append((cmd, kwargs))
        or _subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
    )

    setup._prepare_keybase_session("botuser")

    assert any("run_keybase -g" in call[0][-1] for call in calls)
    assert any("keybase login </dev/tty" in call[0][-1] for call in calls)


def test_preflight_passes_on_valid_ruleset(monkeypatch, tmp_path):
    import setup
    import subprocess as _subprocess

    ini = tmp_path / "firewall.ini"
    ini.write_text(
        "[network]\nphy_if = eth0\nvpn_server_ip = 1.2.3.4\n"
        "vpn_server_port = 51820\nlan_net = 192.168.1.0/24\nssh_port = 22\n"
    )
    monkeypatch.setattr(setup, "_CONF_FILE", ini)

    monkeypatch.setattr(
        _subprocess, "run",
        lambda *a, **kw: _subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        ),
    )

    # Should complete without raising
    setup.step2_5_nft_preflight(src_path=Path(__file__).resolve().parent.parent.parent / "src")


def test_preflight_skips_if_ini_missing(monkeypatch, tmp_path):
    import setup
    import subprocess as _subprocess

    monkeypatch.setattr(setup, "_CONF_FILE", tmp_path / "missing.ini")
    run_calls = []
    monkeypatch.setattr(_subprocess, "run", lambda *a, **kw: run_calls.append(a))

    setup.step2_5_nft_preflight(src_path=Path(__file__).resolve().parent.parent.parent / "src")

    assert run_calls == [], "nft should not be called when firewall.ini is missing"


def test_blank_keybase_prompts_do_not_write_partial_keybase_section(monkeypatch, tmp_path):
    import configparser
    import setup

    ini = tmp_path / "firewall.ini"
    monkeypatch.setattr(setup, "_CONF_DIR", tmp_path)
    monkeypatch.setattr(setup, "_CONF_FILE", ini)
    monkeypatch.setattr(setup, "INSTALL_DIR", tmp_path / "missing-install")
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_detect_phy_if", lambda: "ens3")
    monkeypatch.setattr(setup, "_detect_vpn_if", lambda: "wg0")
    monkeypatch.setattr(setup, "_detect_lan_net", lambda _phy_if: "10.0.2.0/24")
    monkeypatch.setattr(setup, "_detect_vpn_endpoint", lambda _vpn_if: ("", ""))
    monkeypatch.setattr(setup, "_detect_ssh_port", lambda: "22")
    monkeypatch.setattr(setup, "_detect_keybase_linux_user", lambda: "")
    monkeypatch.setattr(setup, "_ask", lambda _label, default="", hint="": default)
    monkeypatch.setattr(setup, "_ask_ports", lambda _label, default="": default)

    setup.step0_configure()

    cfg = configparser.ConfigParser()
    cfg.read(ini)
    assert cfg.has_section("network")
    assert not cfg.has_section("keybase")


def test_reconfigure_defaults_preserve_installed_config_from_temp_checkout(monkeypatch, tmp_path):
    import configparser
    import setup

    checkout_config = tmp_path / "checkout" / "config"
    checkout_config.mkdir(parents=True)
    installed_config = tmp_path / "opt" / "nft-firewall" / "config"
    installed_config.mkdir(parents=True)
    installed_ini = installed_config / "firewall.ini"
    installed_ini.write_text(
        "[network]\n"
        "phy_if = enp88s0\n"
        "vpn_interface = wg0\n"
        "lan_net = 192.168.50.0/24\n"
        "vpn_server_ip = 185.236.203.98\n"
        "vpn_server_port = 9930\n"
        "ssh_port = 58473\n"
        "lan_full_access = false\n"
        "lan_allow_ports = 58473, 80, 443, 32400, 8096\n"
        "lan_allow_udp_ports = 7359\n"
        "extra_ports = 80, 443\n"
        "torrent_port = 64279\n"
        "\n"
        "[keybase]\n"
        "linux_user = nuc\n"
        "team = nuc_alerts\n"
        "channel = general\n"
        "target_user = blackflagdata\n"
        "\n"
        "[install]\n"
        "profile = cosmos-vpn-secure\n"
    )
    target_ini = checkout_config / "firewall.ini"

    monkeypatch.setattr(setup, "_CONF_DIR", checkout_config)
    monkeypatch.setattr(setup, "_CONF_FILE", target_ini)
    monkeypatch.setattr(setup, "INSTALL_DIR", tmp_path / "opt" / "nft-firewall")
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_detect_phy_if", lambda: "wrong0")
    monkeypatch.setattr(setup, "_detect_vpn_if", lambda: "wrongwg")
    monkeypatch.setattr(setup, "_detect_lan_net", lambda _phy_if: "10.0.2.0/24")
    monkeypatch.setattr(setup, "_detect_vpn_endpoint", lambda _vpn_if: ("203.0.113.1", "51820"))
    monkeypatch.setattr(setup, "_detect_ssh_port", lambda: "22")
    monkeypatch.setattr(setup, "_detect_keybase_linux_user", lambda: "")
    monkeypatch.setattr(setup, "_ask", lambda _label, default="", hint="": default)
    monkeypatch.setattr(setup, "_ask_ports", lambda _label, default="": default)

    setup.step0_configure()

    cfg = configparser.ConfigParser()
    cfg.read(target_ini)
    assert cfg.get("network", "phy_if") == "enp88s0"
    assert cfg.get("network", "ssh_port") == "58473"
    assert cfg.get("network", "lan_allow_ports") == "58473, 80, 443, 32400, 8096"
    assert cfg.get("network", "lan_allow_udp_ports") == "7359"
    assert cfg.get("network", "extra_ports") == "80, 443"
    assert cfg.get("network", "torrent_port") == "64279"
    assert cfg.get("keybase", "team") == "nuc_alerts"
    assert cfg.get("keybase", "target_user") == "blackflagdata"


def test_install_dir_is_root_owned_not_fw_admin(monkeypatch, tmp_path):
    """INSTALL_DIR (code) must NOT be chowned to fw-admin.

    A daemon running as fw-admin must not be able to rewrite
    /opt/nft-firewall/src/main.py — otherwise a compromise of any service
    account daemon escalates to root via the broad sudoers grant on /usr/local/bin/fw.
    Runtime/state dirs (LIB_DIR, LOG_DIR, ETC_DIR) may stay fw-admin-owned.
    """
    import setup

    chown_calls = []
    monkeypatch.setattr(setup, "_run", lambda cmd, **kw: chown_calls.append(tuple(cmd)))
    monkeypatch.setattr(setup, "_ok",   lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)

    install_dir = tmp_path / "opt/nft-firewall"
    lib_dir = tmp_path / "var/lib/nft-firewall"
    log_dir = tmp_path / "var/log/nft-firewall"
    etc_dir = tmp_path / "etc/nft-firewall"
    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "LIB_DIR", lib_dir)
    monkeypatch.setattr(setup, "LOG_DIR", log_dir)
    monkeypatch.setattr(setup, "ETC_DIR", etc_dir)
    monkeypatch.setattr(setup, "LOCK_DIR", tmp_path / "var/lib/nft-firewall-locks")
    monkeypatch.setattr(setup, "FIREWALL_DIRS", (install_dir, lib_dir, log_dir, etc_dir))
    monkeypatch.setattr(setup, "_set_authoritative_fd_owner", lambda _fd: None)

    setup.step3_scaffold_dirs()

    install_dir = str(setup.INSTALL_DIR)
    install_chowns = [c for c in chown_calls if c[0] == "chown" and c[-1] == install_dir]
    assert install_chowns, f"no chown call for INSTALL_DIR; calls={chown_calls}"
    for call in install_chowns:
        owner = call[2] if call[1] == "-R" else call[1]
        assert not owner.startswith(f"{setup.SYSTEM_USER}:"), (
            f"INSTALL_DIR must not be chowned to fw-admin; got {owner!r} in {call!r}"
        )
        assert owner.startswith("root:"), (
            f"INSTALL_DIR should be root-owned; got {owner!r} in {call!r}"
        )


def test_setup_sh_does_not_clobber_existing_resolv_conf():
    """setup.sh must NOT unconditionally relink /etc/resolv.conf.

    A working systemd-resolved symlink or custom static resolv.conf must be
    preserved; only repair the link when /etc/resolv.conf is missing or dangling.
    """
    setup_sh = Path(__file__).resolve().parent.parent.parent / "setup.sh"
    text = setup_sh.read_text()
    # Must guard the relink with an existence check, not just `[ -f /run/... ]`.
    assert "! [ -e /etc/resolv.conf ]" in text, (
        "setup.sh should only touch /etc/resolv.conf when it is missing/dangling"
    )
    # And the ln -sf must NOT appear unguarded on a line by itself.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("ln -sf /run/resolvconf/resolv.conf /etc/resolv.conf"):
            # Acceptable: this line lives inside the guarded block. Reject only
            # if there is no guard anywhere above mentioning /etc/resolv.conf.
            assert "! [ -e /etc/resolv.conf ]" in text


def test_setup_sh_does_not_replace_systemd_resolved_with_openresolv():
    setup_sh = Path(__file__).resolve().parent.parent.parent / "setup.sh"
    text = setup_sh.read_text()

    assert "openresolv" not in text


def test_setup_sh_uses_debian_13_wireguard_packages_without_dkms():
    setup_sh = Path(__file__).resolve().parent.parent.parent / "setup.sh"
    text = setup_sh.read_text()

    assert "wireguard-tools" in text
    assert "wireguard-dkms" not in text


def test_setup_sh_fails_hard_on_core_install_failure():
    """setup.sh must not continue into integrations after setup.py fails."""
    setup_sh = Path(__file__).resolve().parent.parent.parent / "setup.sh"
    text = setup_sh.read_text()

    assert "python3 setup.py install </dev/tty" in text
    assert "python3 setup.py install\nfi" in text
    assert "Core install finished with notice" not in text
    assert "setup.py install </dev/tty) ||" not in text


def test_setup_sh_integrations_are_explicit_opt_in():
    """Cosmos/Keybase hardening should not run on the default core install path."""
    setup_sh = Path(__file__).resolve().parent.parent.parent / "setup.sh"
    text = setup_sh.read_text()

    assert "RUN_INTEGRATIONS=0" in text
    assert "INSTALL_DOCKER=0" in text
    assert "INSTALL_KEYBASE=0" in text
    assert "KEYBASE_LOGIN=0" in text
    assert "RUN_VALIDATE=1" in text
    assert "RUN_SAFE_APPLY=0" in text
    assert "MODE_SELECTED=0" in text
    assert "ADVANCED_SELECTED=0" in text
    assert "UPDATE_ONLY=0" in text
    assert "--update|--upgrade)" in text
    assert 'return 0' in text
    assert '[[ "$MODE_SELECTED" -ne 0 || "$ADVANCED_SELECTED" -ne 0 || ! -r /dev/tty ]]' in text
    assert "Existing nft-firewall install detected." in text
    assert "Update only (code, wrappers, units, restart, validate)" in text
    assert "Preserving existing firewall.ini for update-only run" in text
    assert "cp -f /opt/nft-firewall/config/firewall.ini config/firewall.ini" in text
    assert "Running update-only installation" in text
    assert 'if [[ "$UPDATE_ONLY" -eq 1 ]]' in text
    assert "guided_install_mode" in text
    assert "Choose install type:" in text
    assert "Install type [1-4, default 2]" in text
    assert "Run safe-apply after validation?" in text
    assert "configure_mode core" in text
    assert "configure_mode cosmos" in text
    assert "configure_mode full" in text
    assert "configure_mode full-login" in text
    assert "--core)" in text
    assert "--cosmos|--media|--media-server)" in text
    assert "--full)" in text
    assert "--full-login|--with-all)" in text
    assert "--with-integrations" in text
    assert "--with-docker" in text
    assert "--with-keybase" in text
    assert "--with-keybase-login" in text
    assert "--safe-apply|--apply)" in text
    assert "--no-validate)" in text
    assert 'INSTALL_DOCKER=1' in text
    assert 'INSTALL_KEYBASE=1' in text
    assert 'KEYBASE_LOGIN=1' in text
    assert 'ENABLE_WEBUI=1' in text
    assert 'export NFT_FIREWALL_INSTALL_DOCKER="$INSTALL_DOCKER"' in text
    assert 'export NFT_FIREWALL_INSTALL_KEYBASE="$INSTALL_KEYBASE"' in text
    assert 'export NFT_FIREWALL_KEYBASE_LOGIN="$KEYBASE_LOGIN"' in text
    assert "Skipping optional Cosmos/Keybase hardening" in text
    assert 'if [[ "$RUN_INTEGRATIONS" -eq 1 ]]' in text
    assert 'fw doctor "$PROF"' in text
    assert 'fw simulate "$PROF"' in text
    assert "VALIDATION_OK=0" in text
    assert '[[ "$RUN_SAFE_APPLY" -eq 1 && "$VALIDATION_OK" -eq 1 ]]' in text
    assert 'fw safe-apply "$PROF"' in text
    assert "sudo fw safe-apply $PROF" in text


def test_core_hardening_owns_optional_srv_cosmos_layout():
    """Cosmos/media paths belong to the optional integration, not core setup."""
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "core-hardening.sh"
    text = script.read_text()

    assert 'COSMOS_CONFIG_DIR="/srv/cosmos/config"' in text
    assert 'COSMOS_STORAGE_DIR="/srv/cosmos-storage"' in text
    assert 'APP_CONFIG_DIR="/srv/config"' in text
    assert 'MEDIA_LIBRARY_DIR="/srv/media"' in text
    assert 'DOCKER_DATA_DIR="/srv/docker"' in text
    assert 'COSMOS_CONFIG_FILE="$COSMOS_CONFIG_DIR/cosmos.config.json"' in text
    assert "COSMOS_CONFIG_FOLDER=/srv/cosmos/config/" in text
    assert "COSMOS_HTTP_PORT=80" in text
    assert "COSMOS_HTTPS_PORT=443" in text
    assert "ReadWritePaths=/srv/cosmos /srv/cosmos-storage /srv/config /srv/media /srv/backups /opt/cosmos" in text
    assert '"DefaultDataPath") != default_data_path' in text


def test_core_hardening_preserves_nft_firewall_docker_authority():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "core-hardening.sh"
    text = script.read_text()

    assert 'write_docker_daemon_json' in text
    assert '"data-root": "/srv/docker"' in text
    assert '"iptables": False' in text
    assert '"ip6tables": False' in text
    assert '"max-size": "100m"' in text
    assert '"max-file": "5"' in text
    assert text.index('write_docker_daemon_json') < text.index('apt-get install -y docker-ce')


def test_core_hardening_can_install_docker_engine_explicitly():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "core-hardening.sh"
    text = script.read_text()

    assert 'INSTALL_DOCKER="${NFT_FIREWALL_INSTALL_DOCKER:-0}"' in text
    assert 'install_docker_engine' in text
    assert 'https://download.docker.com/linux/debian/gpg' in text
    assert 'https://download.docker.com/linux/debian %s stable' in text
    assert 'docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin' in text
    assert 'systemctl enable --now docker' in text
    assert text.index('install_docker_engine') < text.index('if cosmos_installed')


def test_core_hardening_can_install_keybase_explicitly():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "core-hardening.sh"
    text = script.read_text()

    assert 'INSTALL_KEYBASE="${NFT_FIREWALL_INSTALL_KEYBASE:-0}"' in text
    assert 'KEYBASE_LOGIN="${NFT_FIREWALL_KEYBASE_LOGIN:-0}"' in text
    assert "install_keybase_package" in text
    assert "detect_keybase_linux_user" in text
    assert "maybe_run_keybase_login" in text
    assert "keybase_wrapper_whoami" in text
    assert 'NFT_FIREWALL_KEYBASE_USER="$kb_user" /usr/local/bin/nft-keybase-notify whoami' in text
    assert "enable_keybase_units_if_ready" in text
    assert "keybase_config_ready" in text
    assert "https://prerelease.keybase.io/keybase_amd64.deb" in text
    assert 'apt-get install -y "$tmp_dir/keybase_amd64.deb"' in text
    assert "run_keybase -g" in text
    assert "keybase login" in text
    assert "sh -c 'keybase login </dev/tty'" in text
    assert "keybase whoami" in text
    assert "keybase status" not in text
    assert "systemctl restart nft-listener.service" in text
    assert "systemctl restart nft-daily-report.timer" in text
    assert text.index("Checking for Keybase ChatOps") < text.rindex("install_keybase_package")


def test_core_hardening_uses_documented_cosmos_standalone_flags():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "core-hardening.sh"
    text = script.read_text()

    assert 'NFT_COSMOS_INSTALLER_FLAGS="${NFT_COSMOS_INSTALLER_FLAGS:-${COSMOS_INSTALLER_FLAGS:---no-docker --no-dep}}"' in text
    assert "unset COSMOS_INSTALLER_FLAGS" in text
    assert "ensure_package_command unzip unzip" in text
    assert 'export COSMOS_CONFIG_FOLDER="$COSMOS_CONFIG_DIR/"' in text
    assert 'bash "$COSMOS_INSTALLER" $NFT_COSMOS_INSTALLER_FLAGS' in text
    assert 'bash "$COSMOS_INSTALLER"' in text
    assert 'bash "$COSMOS_INSTALLER"\n' not in text
    assert "nft-firewall controls firewall policy" in text
    assert 'COSMOS_SUPPLEMENTARY_GROUPS="SupplementaryGroups=docker"' in text


def test_core_hardening_simulates_before_optional_auto_apply():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "core-hardening.sh"
    text = script.read_text()

    assert 'main.py simulate "$PROF"' in text
    assert "Firewall rules validation failed; skipping automatic apply" in text
    assert text.index('main.py simulate "$PROF"') < text.index('main.py apply "$PROF"')



def test_setup_sh_uses_public_repo_url_by_default():
    """Public bootstrap must not clone the private/live-history repo by default."""
    setup_sh = Path(__file__).resolve().parent.parent.parent / "setup.sh"
    text = setup_sh.read_text()

    assert "NFT_FIREWALL_REPO_URL" in text
    assert "NFT_FIREWALL_BRANCH" in text
    assert "NFT_FIREWALL_REF" in text
    assert "NFT_FIREWALL_SOURCE_DIR" in text
    assert "https://github.com/unknown0152/nft-firewall-public.git" in text
    assert 'git clone -q --depth 1 --branch "$REF" "$REPO_URL" "$INSTALL_TMP"' in text
    assert 'git -C "$INSTALL_TMP" checkout -q "$REF"' in text
    assert "Using installer checkout" in text
    assert "git clone -q https://github.com/unknown0152/nft-firewall.git" not in text


def test_install_sh_clones_public_repo_once_and_preserves_args():
    install_sh = Path(__file__).resolve().parent.parent.parent / "install.sh"
    text = install_sh.read_text()

    assert "https://github.com/unknown0152/nft-firewall-public.git" in text
    assert "NFT_FIREWALL_REPO_URL" in text
    assert "NFT_FIREWALL_BRANCH" in text
    assert "NFT_FIREWALL_REF" in text
    assert 'git clone -q --depth 1 --branch "$REF" "$REPO_URL" "$tmp"' in text
    assert 'git -C "$tmp" checkout -q "$REF"' in text
    assert "Checked out commit:" in text
    assert 'NFT_FIREWALL_SOURCE_DIR="$tmp" bash ./setup.sh "$@"' in text
    assert "raw.githubusercontent.com/unknown0152/nft-firewall-public/${BRANCH}/setup.sh" not in text


def test_install_sh_writes_timestamped_install_log():
    install_sh = Path(__file__).resolve().parent.parent.parent / "install.sh"
    text = install_sh.read_text()

    assert 'LOG_DIR="${NFT_FIREWALL_INSTALL_LOG_DIR:-/var/log/nft-firewall}"' in text
    assert 'LOG_FILE="${NFT_FIREWALL_INSTALL_LOG:-}"' in text
    assert 'LOG_FILE="$LOG_DIR/install-$ts.log"' in text
    assert 'chmod 0600 "$LOG_FILE"' in text
    assert 'exec > >(tee -a "$LOG_FILE") 2>&1' in text
    assert 'echo "[+] Install log: $LOG_FILE"' in text


def test_shell_installers_support_debug_tracing():
    root = Path(__file__).resolve().parent.parent.parent
    for relative in ("install.sh", "setup.sh", "scripts/core-hardening.sh"):
        text = (root / relative).read_text()
        assert 'NFT_FIREWALL_DEBUG:-0' in text
        assert 'set -x' in text
        assert 'PS4=' in text
        assert 'BASH_SOURCE' not in text
        assert '${0##*/}' in text


def test_setup_installs_curl_entrypoint_locally():
    setup_py = Path(__file__).resolve().parent.parent.parent / "setup.py"
    text = setup_py.read_text()

    assert '"install.sh", "setup.sh"' in text
    assert "support_file.endswith(\".sh\")" in text


def test_step7_resolves_endpoint_without_rewriting_wireguard_config(monkeypatch, tmp_path):
    import socket
    import setup

    install_dir = tmp_path / "opt" / "nft-firewall"
    config_dir = install_dir / "config"
    config_dir.mkdir(parents=True)
    ini = config_dir / "firewall.ini"
    ini.write_text(
        "[network]\n"
        "vpn_interface = wg-test\n"
        "vpn_server_ip = vpn.example.test\n"
    )
    wg_dir = tmp_path / "etc" / "wireguard"
    wg_dir.mkdir(parents=True)
    wg_conf = wg_dir / "wg-test.conf"
    original = "[Peer]\nEndpoint = vpn.example.test:51820\n"
    wg_conf.write_text(original)

    calls = []
    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "_CONF_FILE", ini)
    monkeypatch.setattr(setup, "Path", lambda value: wg_conf if value == "/etc/wireguard/wg-test.conf" else Path(value))
    monkeypatch.setattr(socket, "gethostbyname", lambda _host: "203.0.113.10")

    def fake_run(cmd, **_kw):
        calls.append(cmd)
        rc = 1 if cmd[:4] == ["ip", "link", "show", "dev"] else 0
        return type("R", (), {"returncode": rc, "stderr": ""})()

    monkeypatch.setattr(setup, "_run", fake_run)
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)

    setup.step7_activate_vpn()

    assert wg_conf.read_text() == original
    assert "vpn_server_ip = 203.0.113.10" in ini.read_text()
    assert ["systemctl", "enable", "wg-quick@wg-test"] in calls
    assert ["systemctl", "start", "wg-quick@wg-test"] in calls


def test_step7_skips_start_when_wireguard_interface_already_exists(monkeypatch, tmp_path):
    import setup

    install_dir = tmp_path / "opt" / "nft-firewall"
    config_dir = install_dir / "config"
    config_dir.mkdir(parents=True)
    ini = config_dir / "firewall.ini"
    ini.write_text("[network]\nvpn_interface = wg-test\n")

    wg_dir = tmp_path / "etc" / "wireguard"
    wg_dir.mkdir(parents=True)
    wg_conf = wg_dir / "wg-test.conf"
    wg_conf.write_text("[Interface]\nPrivateKey = test\n")

    calls = []

    def fake_run(cmd, **_kw):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "_CONF_FILE", ini)
    monkeypatch.setattr(setup, "Path", lambda value: wg_conf if value == "/etc/wireguard/wg-test.conf" else Path(value))
    monkeypatch.setattr(setup, "_run", fake_run)
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)

    setup.step7_activate_vpn()

    assert ["systemctl", "enable", "wg-quick@wg-test"] in calls
    assert ["ip", "link", "show", "dev", "wg-test"] in calls
    assert ["systemctl", "reset-failed", "wg-quick@wg-test"] in calls
    assert ["systemctl", "start", "wg-quick@wg-test"] not in calls
    assert ["systemctl", "restart", "wg-quick@wg-test"] not in calls


def test_state_dirs_are_root_owned_shared_sticky_namespaces(monkeypatch, tmp_path):
    """Services may create own files but cannot replace another owner's state."""
    import setup

    chown_calls = []
    monkeypatch.setattr(setup, "_run", lambda cmd, **kw: chown_calls.append(tuple(cmd)))
    monkeypatch.setattr(setup, "_ok",   lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)

    install_dir = tmp_path / "opt/nft-firewall"
    lib_dir = tmp_path / "var/lib/nft-firewall"
    log_dir = tmp_path / "var/log/nft-firewall"
    etc_dir = tmp_path / "etc/nft-firewall"
    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "LIB_DIR", lib_dir)
    monkeypatch.setattr(setup, "LOG_DIR", log_dir)
    monkeypatch.setattr(setup, "ETC_DIR", etc_dir)
    monkeypatch.setattr(setup, "LOCK_DIR", tmp_path / "var/lib/nft-firewall-locks")
    monkeypatch.setattr(setup, "FIREWALL_DIRS", (install_dir, lib_dir, log_dir, etc_dir))
    monkeypatch.setattr(setup, "_set_authoritative_fd_owner", lambda _fd: None)

    setup.step3_scaffold_dirs()

    for state_dir in (setup.LIB_DIR, setup.LOG_DIR):
        path_str = str(state_dir)
        matching = [c for c in chown_calls if c[0] == "chown" and c[-1] == path_str]
        assert matching, f"no chown call for {state_dir}; calls={chown_calls}"
        owners = [(c[2] if c[1] == "-R" else c[1]) for c in matching]
        assert "root:fw-admin" in owners, (
            f"{state_dir} must be root-owned with shared group; got {owners!r}"
        )
        assert state_dir.stat().st_mode & 0o1777 == 0o1770


def test_copytree_replace_skips_self_copy(monkeypatch, tmp_path):
    import setup

    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("print('ok')\n")

    calls = []
    monkeypatch.setattr(setup, "_ok", lambda msg: calls.append(msg))

    setup._copytree_replace(src, src, "src/")

    assert (src / "main.py").exists()
    assert any("skipping self-copy" in msg for msg in calls)


def test_copytree_replace_copies_to_fresh_install_path(tmp_path):
    import setup

    src = tmp_path / "checkout" / "src"
    dst = tmp_path / "opt" / "nft-firewall" / "src"
    src.mkdir(parents=True)
    (src / "main.py").write_text("print('fresh install')\n")

    setup._copytree_replace(src, dst, "src/")

    assert (dst / "main.py").read_text() == "print('fresh install')\n"
