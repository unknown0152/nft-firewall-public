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

    assert ("fw-admin", True, None, "/bin/false") in ensured_users
    assert ("media", False, Path("/home/media"), "/bin/bash") in ensured_users
    assert ("backup", False, Path("/home/backup"), "/bin/bash") in ensured_users
    assert ("deploy", False, Path("/home/deploy"), "/bin/bash") in ensured_users
    assert "docker" in ensured_groups
    assert ("fw-admin", "adm") in added_groups
    assert ("media", "docker") in added_groups
    assert ("nuc", "docker") in added_groups
    assert ("fw-admin", "docker") in removed_groups


def test_scaffold_dirs_sets_firewall_and_media_ownership(monkeypatch, tmp_path):
    import setup

    install_dir = tmp_path / "opt" / "nft-firewall"
    lib_dir = tmp_path / "var" / "lib" / "nft-firewall"
    log_dir = tmp_path / "var" / "log" / "nft-firewall"
    etc_dir = tmp_path / "etc" / "nft-firewall"
    media_compose = tmp_path / "home" / "media" / "compose"
    cosmos_compose = media_compose / "cosmos"
    calls = []

    monkeypatch.setattr(setup, "INSTALL_DIR", install_dir)
    monkeypatch.setattr(setup, "LIB_DIR", lib_dir)
    monkeypatch.setattr(setup, "LOG_DIR", log_dir)
    monkeypatch.setattr(setup, "ETC_DIR", etc_dir)
    monkeypatch.setattr(setup, "FIREWALL_DIRS", (install_dir, lib_dir, log_dir, etc_dir))
    monkeypatch.setattr(setup, "MEDIA_COMPOSE_DIR", media_compose)
    monkeypatch.setattr(setup, "COSMOS_COMPOSE_DIR", cosmos_compose)
    monkeypatch.setattr(setup, "_run", lambda cmd, **_kw: calls.append(cmd))

    setup.step3_scaffold_dirs()

    for path in (install_dir, lib_dir, log_dir, etc_dir, cosmos_compose):
        assert path.exists()
    # Code dir is root-owned (group fw-admin) so daemons cannot rewrite their own code.
    assert ["chown", "-R", "root:fw-admin", str(install_dir)] in calls
    # Runtime/state dirs stay fw-admin-owned so daemons can write logs and state.
    for path in (lib_dir, log_dir, etc_dir):
        assert ["chown", "-R", "fw-admin:fw-admin", str(path)] in calls
    assert ["chown", "-R", "media:media", str(media_compose)] in calls


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
