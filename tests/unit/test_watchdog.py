"""
tests/unit/test_watchdog.py — Unit tests for NftWatchdog.

Covers:
- _vpn_is_healthy: interface missing / no IP / stale handshake / healthy
- _check_nftables_integrity: missing output_rule marker / missing ip6 table
- _attempt_recovery: stops at first successful level / escalates through all levels

All subprocess calls are patched out — no root, no WireGuard required.
"""
import configparser
import hashlib
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from daemons.watchdog import NftWatchdog


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_cfg(handshake_timeout: int = 180, interface: str = "wg0") -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg["vpn"] = {"interface": interface, "handshake_timeout": str(handshake_timeout)}
    cfg["watchdog"] = {"hostname": "testhost"}
    cfg["keybase"] = {"team": "", "target_user": "", "channel": "general", "linux_user": ""}
    return cfg


def _wd() -> NftWatchdog:
    wd = NftWatchdog(config_path="/dev/null")
    wd._cfg = _make_cfg()
    return wd


def test_watchdog_log_file_uses_runtime_log_dir():
    assert NftWatchdog.LOG_FILE == Path("/var/log/nft-firewall/watchdog.log")


def test_watchdog_uses_fixed_persisted_ruleset_check_operation():
    source = Path(__file__).resolve().parent.parent.parent / "src" / "daemons" / "watchdog.py"

    assert '["nft", "--check-persisted"]' in source.read_text()


def test_level3_uses_sanitized_config_inspection_and_fixed_recovery_operation(monkeypatch):
    wd = _wd()
    cfg = _make_cfg()
    cfg["vpn"]["config"] = "/etc/wireguard/wg0.conf"
    calls = []

    def fake_run(cmd, **_kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["wg", "config-endpoint"]:
            return True, "PublicKey = abcdef=\nEndpoint = vpn.example:51820", ""
        return True, "", ""

    monkeypatch.setattr(Path, "read_text", lambda _self: (_ for _ in ()).throw(PermissionError("denied")))
    monkeypatch.setattr(wd, "_run", fake_run)
    monkeypatch.setattr(
        "daemons.watchdog.socket.getaddrinfo",
        lambda *_a, **_kw: [(None, None, None, None, ("203.0.113.9", 0))],
    )
    monkeypatch.setattr("daemons.watchdog.time.sleep", lambda _seconds: None)

    assert wd._level3_dns_reresolve(cfg, "wg0") is True
    assert ["wg", "config-endpoint", "wg0"] in calls
    assert ["wg-quick", "recover", "wg0", "203.0.113.9"] in calls


# ── _vpn_is_healthy ───────────────────────────────────────────────────────────

class TestVpnIsHealthy:

    def test_interface_missing(self):
        wd = _wd()
        with patch.object(wd, "_run", return_value=(False, "", "link not found")):
            ok, reason = wd._vpn_is_healthy(_make_cfg())
        assert not ok
        assert "does not exist" in reason

    def test_no_ip_address(self):
        wd = _wd()
        def _run(cmd, **kw):
            if cmd[0] == "ip" and "show" in cmd:
                return True, "4: wg0: <POINTOPOINT,UP> ...", ""  # present but no inet line
            return True, "", ""
        with patch.object(wd, "_run", side_effect=_run):
            ok, reason = wd._vpn_is_healthy(_make_cfg())
        assert not ok
        assert "no IP" in reason

    def test_handshake_never_recorded(self):
        wd = _wd()
        def _run(cmd, **kw):
            if cmd[0] == "ip":
                return True, "inet 10.99.0.2/32", ""
            if cmd[0] == "wg":
                return True, "", ""   # empty output → no handshake
            return True, "", ""
        with patch.object(wd, "_run", side_effect=_run):
            ok, reason = wd._vpn_is_healthy(_make_cfg())
        assert not ok
        assert "no WireGuard handshake" in reason

    def test_stale_handshake_triggers_degraded(self):
        """A handshake older than handshake_timeout must cause DEGRADED."""
        wd = _wd()
        old_ts = int(time.time()) - 999          # 999 s > 180 s timeout

        def _run(cmd, **kw):
            if cmd[0] == "ip":
                return True, "inet 10.99.0.2/32", ""
            if cmd[0] == "wg" and "latest-handshakes" in cmd:
                return True, f"somepubkey\t{old_ts}", ""
            return True, "", ""

        with patch.object(wd, "_run", side_effect=_run):
            ok, reason = wd._vpn_is_healthy(_make_cfg(handshake_timeout=180))
        assert not ok
        assert "999s ago" in reason or "limit 180s" in reason

    def test_fresh_handshake_is_healthy(self):
        wd = _wd()
        fresh_ts = int(time.time()) - 30          # 30 s < 180 s timeout

        def _run(cmd, **kw):
            if cmd[0] == "ip":
                return True, "inet 10.99.0.2/32", ""
            if cmd[0] == "wg" and "latest-handshakes" in cmd:
                return True, f"somepubkey\t{fresh_ts}", ""
            return True, "", ""

        with patch.object(wd, "_run", side_effect=_run):
            ok, reason = wd._vpn_is_healthy(_make_cfg(handshake_timeout=180))
        assert ok
        assert "UP" in reason


# ── _check_nftables_integrity ─────────────────────────────────────────────────

class TestNftablesIntegrity:

    def _wd_with_markers(self, output_rule="nft-killswitch-output", ip6_table="fw6"):
        wd = _wd()
        wd._markers = {
            "vpn_iface": "wg0",
            "output_rule": output_rule,
            "ip6_table": ip6_table,
        }
        return wd

    def test_output_rule_marker_missing(self):
        wd = self._wd_with_markers()
        with patch.object(wd, "_run", return_value=(True, "# some other rules", "")):
            ok, reason = wd._check_nftables_integrity("wg0")
        assert not ok
        assert "output" in reason.lower() or "missing" in reason.lower()

    def test_ip6_table_missing(self):
        wd = self._wd_with_markers(output_rule="nft-killswitch-output", ip6_table="fw6")
        ruleset = "nft-killswitch-output\n# no ip6 table here"
        with patch.object(wd, "_run", return_value=(True, ruleset, "")):
            ok, reason = wd._check_nftables_integrity("wg0")
        assert not ok
        assert "fw6" in reason or "ip6" in reason.lower()

    def test_both_markers_present_is_ok(self):
        wd = self._wd_with_markers(output_rule="nft-killswitch-output", ip6_table="fw6")
        ruleset = "nft-killswitch-output\ntable ip6 fw6 {\n}"
        with patch.object(wd, "_run", return_value=(True, ruleset, "")):
            ok, _ = wd._check_nftables_integrity("wg0")
        assert ok

    def test_nft_command_failure_returns_false(self):
        wd = self._wd_with_markers()
        with patch.object(wd, "_run", return_value=(False, "", "permission denied")):
            ok, reason = wd._check_nftables_integrity("wg0")
        assert not ok

    def test_no_markers_loaded_fails_closed(self):
        wd = _wd()
        wd._markers = None
        ok, reason = wd._check_nftables_integrity("wg0")
        assert not ok
        assert "markers not loaded" in reason


# ── _check_persisted_ruleset_integrity ────────────────────────────────────────

class TestPersistedRulesetIntegrity:

    def test_missing_checksum_marker_is_untracked(self):
        wd = _wd()
        wd._markers = {"vpn_iface": "wg0"}

        ok, status, reason = wd._check_persisted_ruleset_integrity()

        assert ok
        assert status == "untracked"
        assert "checksum" in reason

    def test_matching_checksum_is_ok(self, tmp_path):
        conf = tmp_path / "nftables.conf"
        conf.write_text("flush ruleset\n")
        digest = hashlib.sha256(conf.read_bytes()).hexdigest()
        wd = _wd()
        wd.NFT_CONF = conf
        wd._markers = {
            "persisted_ruleset": {
                "path": str(conf),
                "sha256": digest,
            }
        }

        ok, status, reason = wd._check_persisted_ruleset_integrity()

        assert ok
        assert status == "ok"
        assert reason == "checksum matches"

    def test_checksum_mismatch_is_degraded(self, tmp_path):
        conf = tmp_path / "nftables.conf"
        conf.write_text("flush ruleset\n")
        wd = _wd()
        wd.NFT_CONF = conf
        wd._markers = {
            "persisted_ruleset": {
                "path": str(conf),
                "sha256": "0" * 64,
            }
        }

        ok, status, reason = wd._check_persisted_ruleset_integrity()

        assert not ok
        assert status == "mismatch"
        assert "checksum mismatch" in reason

    def test_missing_persisted_file_is_degraded(self, tmp_path):
        conf = tmp_path / "missing.conf"
        wd = _wd()
        wd.NFT_CONF = conf
        wd._markers = {
            "persisted_ruleset": {
                "path": str(conf),
                "sha256": "0" * 64,
            }
        }

        ok, status, reason = wd._check_persisted_ruleset_integrity()

        assert not ok
        assert status == "missing"
        assert "missing" in reason


# ── _attempt_recovery ─────────────────────────────────────────────────────────

class TestAttemptRecovery:

    def _wd_patched_recovery(self, level_results: list) -> NftWatchdog:
        """Return a watchdog whose recovery levels succeed/fail per level_results.

        level_results is a list of 4 bools: True = that level brings wg0 up.
        """
        wd = _wd()
        cfg = _make_cfg()

        # Patch each level method
        for i, succeeds in enumerate(level_results, start=1):
            setattr(wd, f"_level{i}_soft_restart" if i == 1 else
                        f"_level{i}_hard_restart" if i == 2 else
                        f"_level{i}_dns_reresolve" if i == 3 else
                        f"_level{i}_full_recreation",
                    MagicMock(return_value=succeeds))

        # Always report interface present after a level attempt
        wd._run = MagicMock(return_value=(True, "", ""))
        # _wait_for_handshake succeeds when the corresponding level succeeded
        wd._wait_for_handshake = MagicMock(return_value=(True, 10))
        wd._vpn_is_healthy = MagicMock(return_value=(True, "UP 10.0.0.1 handshake 10s ago"))
        return wd, cfg

    def test_stops_at_level1_when_it_succeeds(self):
        wd, cfg = self._wd_patched_recovery([True, True, True, True])
        success, level = wd._attempt_recovery(cfg, "wg0", recovery_wait=1)
        assert success
        assert level == 1
        wd._level1_soft_restart.assert_called_once()
        wd._level2_hard_restart.assert_not_called()

    def test_escalates_to_level2_when_level1_fails(self):
        wd, cfg = self._wd_patched_recovery([False, True, True, True])
        # Level 1 fails: _wait_for_handshake returns False the first time
        wd._wait_for_handshake = MagicMock(side_effect=[(False, None), (True, 10)])
        success, level = wd._attempt_recovery(cfg, "wg0", recovery_wait=1)
        assert success
        assert level >= 2
        wd._level1_soft_restart.assert_called_once()
        wd._level2_hard_restart.assert_called_once()

    def test_returns_false_when_all_levels_exhausted(self):
        wd, cfg = self._wd_patched_recovery([False, False, False, False])
        wd._wait_for_handshake = MagicMock(return_value=(False, None))
        success, level = wd._attempt_recovery(cfg, "wg0", recovery_wait=1)
        assert not success
        assert level == 0

    def test_skips_handshake_wait_when_interface_absent(self):
        """If the interface is not up after a level, skip the handshake poll."""
        wd, cfg = self._wd_patched_recovery([False, True, True, True])
        wait_mock = MagicMock(return_value=(True, 10))
        wd._wait_for_handshake = wait_mock
        # Level 1 leaves interface absent; level 2 brings it up
        wd._run = MagicMock(side_effect=[
            (False, "", ""),  # ip link show after level 1 — absent
            (True, "", ""),   # ip link show after level 2 — present
        ])
        wd._vpn_is_healthy = MagicMock(return_value=(True, "UP"))
        wd._attempt_recovery(cfg, "wg0", recovery_wait=1)
        # _wait_for_handshake should NOT have been called for level 1
        # (interface was absent), only for level 2
        assert wait_mock.call_count == 1


# ── _validate_conf_markers ────────────────────────────────────────────────────

class TestValidateConfMarkers:

    def _wd(self, output_rule="nft-killswitch-output", ip6_table="fw6"):
        wd = _wd()
        wd._markers = {"output_rule": output_rule, "ip6_table": ip6_table}
        return wd

    def test_empty_content_returns_false(self):
        wd = self._wd()
        assert not wd._validate_conf_markers("")

    def test_whitespace_only_returns_false(self):
        wd = self._wd()
        assert not wd._validate_conf_markers("   \n  ")

    def test_missing_ip6_killswitch_table_returns_true_if_others_exist(self):
        wd = self._wd()
        content = "nft-killswitch-output\npolicy drop\n"
        # Now returns True because we only need drop + comment
        assert wd._validate_conf_markers(content)

    def test_missing_policy_drop_returns_false(self):
        wd = self._wd()
        content = "table ip6 killswitch { }\nnft-killswitch-output\n"
        assert not wd._validate_conf_markers(content)

    def test_missing_output_rule_marker_returns_false(self):
        wd = self._wd()
        content = "table ip6 killswitch { }\npolicy drop\ntable ip6 fw6 { }\n"
        assert not wd._validate_conf_markers(content)

    def test_valid_content_returns_true(self):
        wd = self._wd()
        content = (
            "table ip6 killswitch {\n"
            "    chain output { type filter hook output priority filter; policy drop; }\n"
            "}\n"
            "nft-killswitch-output\n"
        )
        assert wd._validate_conf_markers(content)

    def test_no_markers_requires_only_structural_patterns(self):
        wd = _wd()
        wd._markers = None
        content = "table ip6 killswitch {\npolicy drop\n}\nnft-killswitch-output\n"
        assert wd._validate_conf_markers(content)
