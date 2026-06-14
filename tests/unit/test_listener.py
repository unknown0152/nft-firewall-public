"""
tests/unit/test_listener.py — Unit tests for the Keybase ChatOps listener.

Covers:
- validate_ip: /0 rejected, valid IPs accepted
- _CMD_WHITELIST: all expected verbs present
- _run_cli: non-whitelisted subcommands blocked, /0 blocked, argument count enforced
- _dispatch: !block calls _run_cli with correct args; bad IP rejected
- !help output: all documented commands mentioned
- !top: calls build_top_report from analytics
"""
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from daemons.listener import (
    validate_ip,
    parse_poll_interval,
    _CMD_WHITELIST,
    _KNOWN_SAFE_SUBCMDS,
    KeybaseListener,
)


# ── validate_ip ───────────────────────────────────────────────────────────────

class TestValidateIp:

    def test_valid_host(self):
        assert validate_ip("1.2.3.4")

    def test_valid_cidr(self):
        assert validate_ip("203.0.113.0/24")

    def test_slash_zero_rejected(self):
        """/0 must be rejected at the listener's first gate."""
        assert not validate_ip("0.0.0.0/0"), \
            "validate_ip must reject /0 (catastrophic block guard)"

    def test_ipv6_rejected(self):
        assert not validate_ip("::1")

    def test_junk_rejected(self):
        assert not validate_ip("not-an-ip")

    def test_empty_rejected(self):
        assert not validate_ip("")


class TestPollInterval:

    def test_parse_poll_interval_default_and_bounds(self):
        assert parse_poll_interval("15") == 15
        assert parse_poll_interval("1") == 5
        assert parse_poll_interval("999") == 300
        assert parse_poll_interval("not-int") == 5
        assert parse_poll_interval(None) == 5

    def test_load_cfg_reads_listener_poll_interval(self, tmp_path):
        conf = tmp_path / "firewall.ini"
        conf.write_text(
            "[keybase]\n"
            "target_user = alice\n"
            "linux_user = keybaseuser\n"
            "team = ops\n"
            "\n"
            "[watchdog]\n"
            "hostname = host1\n"
            "\n"
            "[listener]\n"
            "poll_interval = 30\n"
        )
        listener = KeybaseListener(config_path=str(conf))

        cfg = listener._load_cfg()

        assert cfg["authorized_user"] == "alice"
        assert cfg["linux_user"] == "keybaseuser"
        assert cfg["team"] == "ops"
        assert cfg["host"] == "host1"
        assert cfg["poll_interval"] == 30


# ── _CMD_WHITELIST completeness ───────────────────────────────────────────────

class TestCmdWhitelist:

    EXPECTED_VERBS = {"!block", "!unblock", "!allow", "!unallow", "!status", "!rules", "!ip-list"}

    def test_all_expected_verbs_present(self):
        for verb in self.EXPECTED_VERBS:
            assert verb in _CMD_WHITELIST, f"Missing verb in _CMD_WHITELIST: {verb}"

    def test_whitelist_subcmds_subset_of_known_safe(self):
        subcmds = {spec.cli_subcmd for spec in _CMD_WHITELIST.values()}
        assert subcmds <= _KNOWN_SAFE_SUBCMDS, (
            f"Subcmds not in _KNOWN_SAFE_SUBCMDS: {subcmds - _KNOWN_SAFE_SUBCMDS}"
        )

    def test_no_dangerous_subcmds_in_whitelist(self):
        dangerous = {"apply", "docker-expose", "docker-unexpose", "install", "root"}
        subcmds = {spec.cli_subcmd for spec in _CMD_WHITELIST.values()}
        overlap = subcmds & dangerous
        assert not overlap, f"Dangerous subcmds in whitelist: {overlap}"


# ── _run_cli security guards ──────────────────────────────────────────────────

def _make_listener() -> KeybaseListener:
    l = KeybaseListener.__new__(KeybaseListener)
    l.config_path = "/dev/null"
    l._processed  = set()
    return l


class TestRunCli:

    def test_non_whitelisted_subcommand_blocked(self, capsys):
        l = _make_listener()
        rc, out = l._run_cli("apply", "home")
        assert rc != 0
        captured = capsys.readouterr()
        assert "SECURITY" in captured.out or "not permitted" in out.lower()

    def test_too_many_arguments_blocked(self, capsys):
        l = _make_listener()
        rc, out = l._run_cli("block", "1.2.3.4", "extra")
        assert rc != 0
        captured = capsys.readouterr()
        assert "SECURITY" in captured.out or "Too many" in out

    def test_no_arguments_blocked(self, capsys):
        l = _make_listener()
        rc, out = l._run_cli()
        assert rc != 0

    def test_allowed_subcommand_reaches_subprocess(self, monkeypatch):
        l = _make_listener()
        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = "ok"
        fake_result.stderr = ""

        with patch("subprocess.run", return_value=fake_result) as mock_run, \
             patch("pathlib.Path.exists", return_value=False):
            rc, out = l._run_cli("ip-list")

        assert rc == 0
        assert mock_run.called


# ── _dispatch ─────────────────────────────────────────────────────────────────

def _make_cfg_dict(host="testhost"):
    return {
        "host": host,
        "channel": "general",
        "authorized": ["testuser"],
    }


class TestDispatch:

    def _listener_with_mock_cli(self, rc=0, output="ok"):
        l = _make_listener()
        l._run_cli   = MagicMock(return_value=(rc, output))
        l._send_reply = MagicMock()
        return l

    def test_block_valid_ip_calls_run_cli(self):
        l = self._listener_with_mock_cli()
        l._dispatch(_make_cfg_dict(), {"body": "!block 1.2.3.4", "sender": "testuser", "channel": "general"})
        l._run_cli.assert_called_once_with("block", "1.2.3.4")

    def test_block_slash_zero_rejected_before_run_cli(self, capsys):
        l = self._listener_with_mock_cli()
        l._dispatch(_make_cfg_dict(), {"body": "!block 0.0.0.0/0", "sender": "testuser", "channel": "general"})
        l._run_cli.assert_not_called()
        captured = capsys.readouterr()
        assert "SECURITY" in captured.out or "Invalid" in captured.out

    def test_unknown_verb_ignored(self, capsys):
        l = self._listener_with_mock_cli()
        l._dispatch(_make_cfg_dict(), {"body": "!apply home", "sender": "testuser", "channel": "general"})
        l._run_cli.assert_not_called()
        captured = capsys.readouterr()
        assert "SECURITY" in captured.out

    def test_unblock_calls_run_cli(self):
        l = self._listener_with_mock_cli()
        l._dispatch(_make_cfg_dict(), {"body": "!unblock 9.9.9.9", "sender": "testuser", "channel": "general"})
        l._run_cli.assert_called_once_with("unblock", "9.9.9.9")

    def test_status_calls_run_cli_no_arg(self):
        l = self._listener_with_mock_cli()
        l._dispatch(_make_cfg_dict(), {"body": "!status", "sender": "testuser", "channel": "general"})
        l._run_cli.assert_called_once_with("status")

    def test_status_with_trailing_arg_rejected(self, capsys):
        l = self._listener_with_mock_cli()
        l._dispatch(_make_cfg_dict(), {"body": "!status extra", "sender": "testuser", "channel": "general"})
        l._run_cli.assert_not_called()


# ── !help output ──────────────────────────────────────────────────────────────

class TestHelpOutput:

    def test_help_mentions_all_commands(self):
        l = _make_listener()
        replies = []
        l._send_reply = lambda cfg, ch, msg: replies.append(msg)

        l._dispatch(_make_cfg_dict(), {"body": "!help", "sender": "testuser", "channel": "general"})

        assert replies, "!help should send a reply"
        text = replies[0]
        for verb in ("!status", "!top", "!block", "!unblock", "!ip-list"):
            assert verb in text, f"!help output missing: {verb}"


# ── !top routes to analytics ──────────────────────────────────────────────────

class TestTopCommand:

    def test_top_calls_build_top_report(self):
        l = _make_listener()
        replies = []
        l._send_reply = lambda cfg, ch, msg: replies.append(msg)

        with patch("utils.analytics.build_top_report", return_value="🌍 Top report here") as mock_top:
            l._dispatch(_make_cfg_dict(), {"body": "!top", "sender": "testuser", "channel": "general"})

        assert replies, "!top should send a reply"
        assert "Top report" in replies[0] or mock_top.called
