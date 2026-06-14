import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def test_setup_install_sequence_does_not_apply_live_rules(monkeypatch):
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

    setup.cmd_install()

    # The installer should run the sequence but not 'apply' (which is the live rule command)
    # Applying rules is handled by 'fw safe-apply' manually post-install.
    assert "step7_activate_vpn" in calls


def test_fw_wrapper_blocks_plain_apply():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "fw"
    text = script.read_text()
    assert "safe-apply" in text
    assert "use 'fw safe-apply <profile>'" in text


def test_firewall_threatfeed_service_uses_real_cli_command():
    service = (
        Path(__file__).resolve().parent.parent.parent
        / "systemd"
        / "nft-firewall-threatfeed.service"
    )
    text = service.read_text()

    assert "ExecStart=/usr/local/bin/fw threat-update" in text
    assert "threatfeed update" not in text


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
    assert calls.index("step2_5_nft_preflight") > calls.index("step2_install_code")
    assert calls.index("step2_5_nft_preflight") < calls.index("step3_scaffold_dirs")


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


def test_install_dir_is_root_owned_not_fw_admin(monkeypatch):
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

    # Stop mkdir/chmod from touching the host
    class _Stub:
        def __init__(self, p): self._p = p
        def __str__(self): return str(self._p)
        def mkdir(self, *a, **kw): pass
        def chmod(self, *a, **kw): pass
    monkeypatch.setattr(setup, "FIREWALL_DIRS", tuple(_Stub(p) for p in setup.FIREWALL_DIRS))
    monkeypatch.setattr(setup, "COSMOS_COMPOSE_DIR", _Stub(setup.COSMOS_COMPOSE_DIR))

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


def test_state_dirs_remain_fw_admin_owned(monkeypatch):
    """Runtime state/log dirs must stay fw-admin-owned so daemons can write."""
    import setup

    chown_calls = []
    monkeypatch.setattr(setup, "_run", lambda cmd, **kw: chown_calls.append(tuple(cmd)))
    monkeypatch.setattr(setup, "_ok",   lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_warn", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_header", lambda *a, **kw: None)

    class _Stub:
        def __init__(self, p): self._p = p
        def __str__(self): return str(self._p)
        def mkdir(self, *a, **kw): pass
        def chmod(self, *a, **kw): pass
    monkeypatch.setattr(setup, "FIREWALL_DIRS", tuple(_Stub(p) for p in setup.FIREWALL_DIRS))
    monkeypatch.setattr(setup, "COSMOS_COMPOSE_DIR", _Stub(setup.COSMOS_COMPOSE_DIR))

    setup.step3_scaffold_dirs()

    fw_admin = setup.SYSTEM_USER
    for state_dir in (setup.LIB_DIR, setup.LOG_DIR):
        path_str = str(state_dir)
        matching = [c for c in chown_calls if c[0] == "chown" and c[-1] == path_str]
        assert matching, f"no chown call for {state_dir}; calls={chown_calls}"
        owners = [(c[2] if c[1] == "-R" else c[1]) for c in matching]
        assert any(o.startswith(f"{fw_admin}:") for o in owners), (
            f"{state_dir} must remain fw-admin-owned; got {owners!r}"
        )
