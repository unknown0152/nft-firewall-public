"""Unit tests for shared Keybase notification helpers."""
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

import pytest

from utils import keybase


@pytest.fixture(autouse=True)
def _reset_keybase_caches():
    """notify() caches positive whoami/channel checks — isolate tests."""
    keybase._ready_cache["expires"] = 0.0
    keybase._channels_ensured.clear()
    yield
    keybase._ready_cache["expires"] = 0.0
    keybase._channels_ensured.clear()


def test_channel_for_tags_uses_configured_default_channel():
    assert keybase._channel_for_tags("", "Daily report", "ops") == "ops"


def test_channel_for_tags_routes_ssh_to_ssh_channel():
    assert keybase._channel_for_tags("", "SSH Login", "general") == "ssh"


def test_channel_for_tags_routes_port_changes_to_ports_channel():
    assert keybase._channel_for_tags("ports,shield", "Opened firewall access", "general") == "ports"


def test_parse_list_channels_extracts_keybase_channel_names():
    output = """
Listing channels on nuc_alerts:

#general (created by: alice on: 2026-01-01)
#vpn-down (created by: bot on: 2026-01-02)
#ssh (created by: bot on: 2026-01-03)
"""

    assert keybase._parse_list_channels(output) == {"general", "vpn-down", "ssh"}


def test_ensure_team_channels_creates_missing_routed_channels(monkeypatch):
    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[-2:] == ["list-channels", "ops"]:
            return MagicMock(returncode=0, stdout="#general\n#vpn-down\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(keybase.subprocess, "run", fake_run)

    keybase._ensure_team_channels(["sudo", "/usr/local/bin/nft-keybase-notify"], "ops", "alerts")

    created = [cmd[-1] for cmd in calls if "create-channel" in cmd]
    assert created == ["vpn-up", "ssh", "ports", "alerts"]


def test_ensure_team_channels_does_not_raise_when_list_fails(monkeypatch):
    monkeypatch.setattr(
        keybase.subprocess,
        "run",
        lambda *_args, **_kwargs: MagicMock(returncode=1, stdout="", stderr="not allowed"),
    )

    keybase._ensure_team_channels(["keybase"], "ops", "general")


def test_format_message_uses_compact_status_layout():
    message = keybase._format_message(
        title="SSH Login",
        body="Accepted publickey for admin",
        tags="",
        priority="high",
        channel="ssh",
    )

    assert "🔐 **SSH Login**" in message
    assert "Accepted publickey for admin" in message
    assert "`nft-firewall` · `#ssh` · `HIGH` · `" in message


def test_upload_file_uses_team_channel_upload(monkeypatch, tmp_path):
    attachment = tmp_path / "report.png"
    attachment.write_bytes(b"\x89PNG\r\n\x1a\n")

    cfg = keybase.configparser.ConfigParser()
    cfg["keybase"] = {
        "team": "ops",
        "channel": "general",
        "linux_user": "botuser",
    }
    monkeypatch.setattr(keybase, "_load_config", lambda: cfg)
    monkeypatch.setattr(keybase, "_detect_linux_user", lambda _cfg: "botuser")
    monkeypatch.setattr(keybase.pwd, "getpwnam", lambda _user: object())
    monkeypatch.setattr(keybase, "_ensure_team_channels", lambda *_args, **_kwargs: None)

    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[-1] == "whoami":
            return MagicMock(returncode=0, stdout="botaccount\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(keybase.subprocess, "run", fake_run)

    assert keybase.upload_file(attachment, title="Daily Report", tags="shield")

    assert calls == [[
        "sudo",
        "/usr/local/bin/nft-keybase-notify",
        "whoami",
    ], [
        "sudo",
        "/usr/local/bin/nft-keybase-notify",
        "chat",
        "upload",
        "--channel",
        "general",
        "--title",
        "Daily Report",
        "ops",
        str(attachment),
    ]]


def test_notify_preflights_wrapper_before_channel_and_send(monkeypatch, capsys):
    cfg = keybase.configparser.ConfigParser()
    cfg["keybase"] = {
        "team": "ops",
        "channel": "general",
        "linux_user": "botuser",
        "target_user": "botaccount",
    }
    monkeypatch.setattr(keybase, "_load_config", lambda: cfg)
    monkeypatch.setattr(keybase, "_detect_linux_user", lambda _cfg: "botuser")
    monkeypatch.setattr(keybase.pwd, "getpwnam", lambda _user: object())

    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[-1] == "whoami":
            return MagicMock(returncode=1, stdout="", stderr="Login required")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(keybase.subprocess, "run", fake_run)

    assert not keybase.notify("NFT Firewall - test", "body")
    assert calls == [["sudo", "/usr/local/bin/nft-keybase-notify", "whoami"]]

    out = capsys.readouterr().out
    assert "wrapper cannot access a logged-in Keybase session" in out
    assert "sudo -iu botuser keybase login" in out


def test_notify_sends_after_wrapper_identity_check(monkeypatch):
    cfg = keybase.configparser.ConfigParser()
    cfg["keybase"] = {
        "team": "ops",
        "channel": "general",
        "linux_user": "botuser",
        "target_user": "botaccount",
    }
    monkeypatch.setattr(keybase, "_load_config", lambda: cfg)
    monkeypatch.setattr(keybase, "_detect_linux_user", lambda _cfg: "botuser")
    monkeypatch.setattr(keybase.pwd, "getpwnam", lambda _user: object())
    monkeypatch.setattr(keybase, "_ensure_team_channels", lambda *_args, **_kwargs: None)

    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        if cmd[-1] == "whoami":
            return MagicMock(returncode=0, stdout="botaccount\n", stderr="")
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(keybase.subprocess, "run", fake_run)

    assert keybase.notify("NFT Firewall - test", "body")
    assert calls[0] == ["sudo", "/usr/local/bin/nft-keybase-notify", "whoami"]
    assert calls[1][:5] == ["sudo", "/usr/local/bin/nft-keybase-notify", "chat", "send", "--channel"]
