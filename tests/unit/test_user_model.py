import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def test_step1_normalizes_required_user_model(monkeypatch):
    import setup

    ensured_users = []
    ensured_groups = []
    added_groups = []
    removed_groups = []

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
    monkeypatch.setattr(setup.grp, "getgrnam", lambda group: SimpleNamespace(gr_name=group))

    setup.step1_create_system_user()

    assert ("fw-admin", True, setup.SYSTEM_HOME, "/bin/false") in ensured_users
    assert ("fw-admin", "adm") in added_groups
    assert ("fw-admin", "docker") in removed_groups
    assert not any(user == "media" for user, *_ in ensured_users)
    assert not any(user == "backup" for user, *_ in ensured_users)
    assert not any(user == "deploy" for user, *_ in ensured_users)
    assert "docker" not in ensured_groups


def test_scaffold_dirs_sets_firewall_and_media_ownership(monkeypatch, tmp_path):
    import setup

    install_dir = tmp_path / "opt" / "nft-firewall"
    lib_dir = tmp_path / "var" / "lib" / "nft-firewall"
    log_dir = tmp_path / "var" / "log" / "nft-firewall"
    etc_dir = tmp_path / "etc" / "nft-firewall"
    calls = []

    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "LIB_DIR", lib_dir)
    monkeypatch.setattr(setup, "LOG_DIR", log_dir)
    monkeypatch.setattr(setup, "ETC_DIR", etc_dir)
    monkeypatch.setattr(setup, "FIREWALL_DIRS", (install_dir, lib_dir, log_dir, etc_dir))
    monkeypatch.setattr(setup, "_run", lambda cmd, **_kw: calls.append(cmd))

    setup.step3_scaffold_dirs()

    for path in (install_dir, lib_dir, log_dir, etc_dir):
        assert path.exists()
    for path in (lib_dir, log_dir, etc_dir):
        assert path.stat().st_mode & 0o777 == 0o750
    # Code dir is root-owned (group fw-admin) so daemons cannot rewrite their own code.
    assert ["chown", "-R", "root:fw-admin", str(install_dir)] in calls
    # Runtime/state dirs stay fw-admin-owned so daemons can write logs and state.
    for path in (lib_dir, log_dir, etc_dir):
        assert ["chown", "-R", "fw-admin:fw-admin", str(path)] in calls
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


def test_sudoers_uses_fw_admin_and_not_legacy_nft_firewall(monkeypatch, tmp_path):
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

    assert "fw-admin ALL=(root) NOPASSWD:" in content
    assert "nft-firewall ALL=" not in content
    assert "/usr/local/lib/nft-firewall/fw-nft" in content
    assert "/usr/local/lib/nft-firewall/fw-action" in content
    assert "/usr/local/lib/nft-firewall/fw-threat-update" in content
    assert "    /usr/local/bin/fw," not in content
    assert "/opt/nft-firewall/src/main.py *" not in content


def test_systemd_templates_run_as_fw_admin():
    systemd_dir = Path(__file__).resolve().parent.parent.parent / "systemd"
    service_files = sorted(systemd_dir.glob("nft-*.service"))

    assert service_files
    for service in service_files:
        text = service.read_text()
        assert "User=fw-admin" in text
        assert "User=root" not in text
        assert "User=nft-firewall" not in text
