import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def test_step1_normalizes_required_user_model(monkeypatch):
    import setup

    ensured_users = []
    ensured_groups = []
    added_groups = []
    removed_groups = []
    reconciled = []

    monkeypatch.setattr(setup, "_migrate_legacy_system_user", lambda: None)
    monkeypatch.setattr(
        setup,
        "_ensure_user",
        lambda name, *, system, home, shell: ensured_users.append((name, system, home, shell)),
    )
    monkeypatch.setattr(setup, "_ensure_group", lambda group: ensured_groups.append(group))
    monkeypatch.setattr(
        setup,
        "_ensure_supplementary_group",
        lambda user, group: added_groups.append((user, group)),
    )
    monkeypatch.setattr(
        setup,
        "_remove_supplementary_group",
        lambda user, group: removed_groups.append((user, group)),
    )
    monkeypatch.setattr(setup, "_user_exists", lambda user: user == "nuc")
    monkeypatch.setattr(setup, "_read_keybase_user", lambda: "nuc")
    monkeypatch.setattr(
        setup,
        "_reconcile_report_group",
        lambda user: reconciled.append(user),
    )
    monkeypatch.setattr(
        setup.grp,
        "getgrnam",
        lambda group: SimpleNamespace(gr_name=group, gr_mem=[]),
    )

    setup.step1_create_system_user()

    assert ("fw-admin", True, setup.SYSTEM_HOME, "/bin/false") in ensured_users
    for service_user in setup.SERVICE_USERS.values():
        assert (
            service_user,
            True,
            setup.SERVICE_HOME_ROOT / service_user,
            "/bin/false",
        ) in ensured_users
        assert (service_user, "fw-admin") in added_groups
    assert ("nft-ssh-alert", "adm") in added_groups
    assert reconciled == ["nuc"]
    assert ("fw-admin", "docker") in removed_groups
    assert not any(user == "media" for user, *_ in ensured_users)
    assert not any(user == "backup" for user, *_ in ensured_users)
    assert not any(user == "deploy" for user, *_ in ensured_users)
    assert "docker" not in ensured_groups


def test_report_group_reconciles_changed_keybase_user(monkeypatch, tmp_path):
    import setup

    installed = tmp_path / "installed" / "config"
    source = tmp_path / "source" / "config"
    installed.mkdir(parents=True)
    source.mkdir(parents=True)
    (installed / "firewall.ini").write_text(
        "[keybase]\nlinux_user = oldbot\n"
    )
    (source / "firewall.ini").write_text(
        "[keybase]\nlinux_user = newbot\n"
    )
    monkeypatch.setattr(setup, "INSTALL_DIR", installed.parent)
    monkeypatch.setattr(setup, "_CONF_FILE", source / "firewall.ini")

    assert setup._read_keybase_user() == "newbot"

    (source / "firewall.ini").write_text("[network]\nphy_if = eth0\n")
    assert setup._read_keybase_user() == ""
    (source / "firewall.ini").write_text(
        "[keybase]\nlinux_user = newbot\n"
    )

    calls = []
    members = ["fw-admin", "oldbot"]
    monkeypatch.setattr(setup, "_ensure_group", lambda _group: None)

    def run(cmd, **_kwargs):
        calls.append(cmd)
        members[:] = cmd[2].split(",")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(setup, "_run", run)
    monkeypatch.setattr(
        setup.grp,
        "getgrnam",
        lambda _group: SimpleNamespace(gr_mem=list(members)),
    )

    setup._reconcile_report_group("newbot")

    assert calls == [["gpasswd", "--members", "newbot,nft-reporter", "nft-report"]]
    assert members == ["newbot", "nft-reporter"]


def test_report_group_reconciliation_fails_closed(monkeypatch):
    import setup

    monkeypatch.setattr(setup, "_ensure_group", lambda _group: None)
    monkeypatch.setattr(
        setup,
        "_run",
        lambda _cmd, **_kw: SimpleNamespace(returncode=1, stderr="denied"),
    )

    with pytest.raises(SystemExit):
        setup._reconcile_report_group("newbot")


def test_scaffold_dirs_sets_firewall_and_media_ownership(monkeypatch, tmp_path):
    import setup

    install_dir = tmp_path / "opt" / "nft-firewall"
    lib_dir = tmp_path / "var" / "lib" / "nft-firewall"
    log_dir = tmp_path / "var" / "log" / "nft-firewall"
    etc_dir = tmp_path / "etc" / "nft-firewall"
    lock_dir = tmp_path / "var" / "lib" / "nft-firewall-locks"
    calls = []

    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "LIB_DIR", lib_dir)
    monkeypatch.setattr(setup, "LOG_DIR", log_dir)
    monkeypatch.setattr(setup, "ETC_DIR", etc_dir)
    monkeypatch.setattr(setup, "LOCK_DIR", lock_dir)
    monkeypatch.setattr(setup, "FIREWALL_DIRS", (install_dir, lib_dir, log_dir, etc_dir))
    monkeypatch.setattr(setup, "_run", lambda cmd, **_kw: calls.append(cmd))
    authoritative_fds = []
    monkeypatch.setattr(
        setup, "_set_authoritative_fd_owner", lambda fd: authoritative_fds.append(fd)
    )

    setup.step3_scaffold_dirs()

    for path in (install_dir, lib_dir, log_dir, etc_dir):
        assert path.exists()
    assert lock_dir.exists()
    assert lock_dir.stat().st_mode & 0o777 == 0o750
    assert (lock_dir / "dynamic-sets.lock").exists()
    assert ["chown", "root:fw-admin", str(lock_dir)] in calls
    assert ["chown", "root:fw-admin", str(lock_dir / "dynamic-sets.lock")] in calls
    for path in (lib_dir, log_dir):
        assert path.stat().st_mode & 0o777 == 0o770
        assert path.stat().st_mode & 0o1000
    assert etc_dir.stat().st_mode & 0o777 == 0o750
    # Code dir is root-owned (group fw-admin) so daemons cannot rewrite their own code.
    assert ["chown", "-R", "root:fw-admin", str(install_dir)] in calls
    # Runtime/state dirs stay fw-admin-owned so daemons can write logs and state.
    for path in (lib_dir, log_dir):
        assert ["chown", "-R", "root:fw-admin", str(path)] in calls
    assert ["chown", "-R", "root:fw-admin", str(etc_dir)] in calls
    assert len(authoritative_fds) == 4
    assert not any(call[:3] == ["chown", "-R", "media:media"] for call in calls)


def test_existing_users_are_normalized_to_expected_home_and_shell(monkeypatch):
    import setup

    calls = []
    monkeypatch.setattr(setup, "_user_exists", lambda _name: True)
    monkeypatch.setattr(
        setup.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=999, pw_dir="/home/fw-admin", pw_shell="/bin/sh"),
    )
    monkeypatch.setattr(
        setup,
        "_run",
        lambda cmd, **_kw: calls.append(cmd) or SimpleNamespace(returncode=0, stderr=""),
    )
    monkeypatch.setattr(setup, "_user_has_processes", lambda _name: False)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)

    setup._ensure_user("fw-admin", system=True, home=setup.SYSTEM_HOME, shell="/bin/false")

    assert ["usermod", "--home", str(setup.SYSTEM_HOME), "fw-admin"] in calls
    assert ["usermod", "--shell", "/bin/false", "fw-admin"] in calls


def test_existing_active_user_skips_home_and_shell_normalization(monkeypatch):
    import setup

    calls = []
    infos = []
    monkeypatch.setattr(setup, "_user_exists", lambda _name: True)
    monkeypatch.setattr(
        setup.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=999, pw_dir="/home/fw-admin", pw_shell="/bin/sh"),
    )
    monkeypatch.setattr(
        setup,
        "_run",
        lambda cmd, **_kw: calls.append(cmd) or SimpleNamespace(returncode=0, stderr=""),
    )
    monkeypatch.setattr(setup, "_user_has_processes", lambda _name: True)
    monkeypatch.setattr(setup, "_ok", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda msg, *a, **kw: infos.append(msg))

    setup._ensure_user("fw-admin", system=True, home=setup.SYSTEM_HOME, shell="/bin/false")

    assert not any(call[:1] == ["usermod"] for call in calls)
    assert any("home is /home/fw-admin" in msg for msg in infos)
    assert any("shell is /bin/sh" in msg for msg in infos)


def test_sudoers_uses_per_service_grants_not_shared_fw_admin(monkeypatch, tmp_path):
    import setup

    sudoers = tmp_path / "nft-firewall.sudoers"
    monkeypatch.setattr(setup, "SUDOERS_FILE", sudoers)
    monkeypatch.setattr(setup, "_read_keybase_user", lambda: "")
    monkeypatch.setattr(setup, "_install_sudo_wrappers", lambda: None)
    monkeypatch.setattr(setup, "_install_keybase_wrapper", lambda _user: None)
    monkeypatch.setattr(
        setup,
        "_run",
        lambda _cmd, **_kw: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    setup.step4_install_sudoers()
    content = sudoers.read_text()

    assert "fw-admin ALL=(root) NOPASSWD:" not in content
    assert "nft-firewall ALL=" not in content
    assert "nft-webui ALL=(root) NOPASSWD: /usr/local/lib/nft-firewall/fw-nft" in content
    assert "nft-listener ALL=(root) NOPASSWD: /usr/local/lib/nft-firewall/fw-action" in content
    assert "nft-threatfeed ALL=(root) NOPASSWD: /usr/local/lib/nft-firewall/fw-threat-update" in content
    assert "nft-metrics ALL=(root) NOPASSWD: /usr/local/lib/nft-firewall/fw-nft" in content
    assert "nft-webui ALL=(root) NOPASSWD: /usr/local/lib/nft-firewall/fw-action" not in content
    assert "    /usr/local/bin/fw," not in content
    assert "/opt/nft-firewall/src/main.py *" not in content


def test_systemd_templates_use_distinct_service_identities():
    systemd_dir = Path(__file__).resolve().parent.parent.parent / "systemd"
    expected = {
        "nft-watchdog.service": "nft-watchdog",
        "nft-listener.service": "nft-listener",
        "nft-ssh-alert.service": "nft-ssh-alert",
        "nft-webui.service": "nft-webui",
        "nft-metrics.service": "nft-metrics",
        "nft-daily-report.service": "nft-reporter",
        "nft-firewall-doctor.service": "nft-doctor",
        "nft-firewall-threatfeed.service": "nft-threatfeed",
        "nft-knockd.service": "nft-knockd",
    }

    for name, user in expected.items():
        text = (systemd_dir / name).read_text()
        assert f"User={user}" in text
        assert "User=fw-admin" not in text
        assert "User=root" not in text
        assert "User=nft-firewall" not in text
