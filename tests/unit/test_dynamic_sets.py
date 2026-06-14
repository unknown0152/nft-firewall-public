import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from core.rules import RulesetConfig, generate_ruleset


def test_generate_ruleset_preloads_persistent_dynamic_sets():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        blocked_ips=["203.0.113.4/32"],
        trusted_ips=["198.51.100.7/32"],
        dk_ips=["193.163.0.0/16"],
    )
    ruleset = generate_ruleset(cfg)

    assert "set blocked_ips" in ruleset
    assert "elements = { 203.0.113.4/32 }" in ruleset
    assert "elements = { 198.51.100.7/32 }" in ruleset
    assert "elements = { 193.163.0.0/16 }" in ruleset


def test_apply_ruleset_uses_named_temp_file(monkeypatch):
    import subprocess
    import core.state as state

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["file"] = cmd[-1] if cmd else ""
        class R:
            returncode = 0
            stdout = stderr = ""
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    state.apply_ruleset("flush ruleset\n")

    tmp_path = captured.get("file", "")
    assert tmp_path != "/tmp/_nft_apply.conf", "must not use the fixed /tmp path"
    assert "nft_apply_" in tmp_path
    assert not Path(tmp_path).exists(), "temp file must be cleaned up"
