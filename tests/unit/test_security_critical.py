"""
tests/unit/test_security_critical.py
"""
import os
import pytest
from core.rules import RulesetConfig, generate_ruleset, _check_invariants
from daemons.knockd import PortKnockDaemon

def test_ruleset_invariant_catches_alias_0_slash_0():
    cfg = RulesetConfig(phy_if="eth0", vpn_interface="wg0")
    ruleset = 'table ip firewall { chain input { ip saddr 0/0 accept comment "nft-killswitch-output" } } policy drop'
    with pytest.raises(ValueError, match="/0 network found"):
        _check_invariants(cfg, ruleset)

def test_ruleset_invariant_catches_multiline_exposure():
    cfg = RulesetConfig(phy_if="eth0", vpn_interface="wg0")
    ruleset = (
        'table ip firewall {\n'
        '  chain input {\n'
        '    iifname "eth0"\n'
        '    tcp dport 80\n'
        '    accept\n'
        '  }\n'
        '}\n'
        'comment "nft-killswitch-output"\n'
        'policy drop'
    )
    with pytest.raises(ValueError, match="Public port exposure detected on eth0"):
        _check_invariants(cfg, ruleset)

def test_knockd_rejects_physical_iface(tmp_path):
    conf = tmp_path / "firewall.ini"
    conf.write_text("[network]\nphy_if = eth0\nvpn_interface = eth0\n")
    daemon = PortKnockDaemon(str(conf))
    with pytest.raises(RuntimeError, match="matches physical interface"):
        daemon._add_rule("1.2.3.4")

def test_knockd_rejects_non_wg_iface(tmp_path):
    conf = tmp_path / "firewall.ini"
    conf.write_text("[network]\nphy_if = eth0\nvpn_interface = enp1s0\n")
    daemon = PortKnockDaemon(str(conf))
    with pytest.raises(RuntimeError, match="not a trusted tunnel type"):
        daemon._add_rule("1.2.3.4")


def test_knockd_rejects_malformed_source_ip_before_subprocess(tmp_path, monkeypatch):
    """knockd must validate the source IP before any subprocess call.

    A malformed ``ip`` argument like ``"1.2.3.4 accept"`` would be a single
    nft body token after the wrapper fix, but it would still inject extra
    tokens into the rule body and silently widen the rule. Validation must
    fail closed before subprocess.run is ever reached.
    """
    from daemons import knockd as knockd_mod

    conf = tmp_path / "firewall.ini"
    conf.write_text("[network]\nphy_if = eth0\nvpn_interface = wg0\nssh_port = 22\n")
    daemon = knockd_mod.PortKnockDaemon(str(conf))

    called = {"n": 0}
    monkeypatch.setattr(
        knockd_mod.subprocess, "run",
        lambda *a, **kw: called.__setitem__("n", called["n"] + 1),
    )

    for bad in ("1.2.3.4 accept", "1.2.3.4; rm -rf /", "not-an-ip", "1.2.3.4/24", ""):
        with pytest.raises((ValueError, RuntimeError)):
            daemon._add_rule(bad)
    assert called["n"] == 0, "subprocess.run must not be called for malformed IPs"


def test_knockd_accepts_well_formed_single_ip(tmp_path, monkeypatch):
    """The validator must still let through a single well-formed IPv4 host."""
    import json
    import subprocess
    from daemons import knockd as knockd_mod

    conf = tmp_path / "firewall.ini"
    conf.write_text("[network]\nphy_if = eth0\nvpn_interface = wg0\nssh_port = 22\n")
    fake_wrapper = tmp_path / "fw-nft"
    fake_wrapper.write_text("#!/bin/sh\n")
    fake_wrapper.chmod(0o755)
    daemon = knockd_mod.PortKnockDaemon(str(conf), wrapper_path=str(fake_wrapper))
    monkeypatch.setattr(knockd_mod.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        knockd_mod.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a[0], 0, json.dumps({"nftables": [{"rule": {"handle": "1"}}]}), "",
        ),
    )
    assert daemon._add_rule("203.0.113.5") == "1"


def test_output_chain_blocked_ips_drop_precedes_killswitch_accept():
    """`ip daddr @blocked_ips drop` and `ct state invalid drop` must fire BEFORE
    the broad `oifname "wg0" accept` (the killswitch marker), otherwise outbound
    traffic to blocked IPs and ct-invalid packets slip through unchecked because
    wg0 is the only egress.
    """
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="1.2.3.4",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
    )
    ruleset = generate_ruleset(cfg)

    output_start = ruleset.index("chain output {")
    output_end   = ruleset.index("\n    }", output_start)
    output_block = ruleset[output_start:output_end]

    blocked_idx  = output_block.index("ip daddr @blocked_ips drop")
    invalid_idx  = output_block.index("ct state invalid drop")
    marker_idx   = output_block.index('comment "nft-killswitch-output"')

    assert blocked_idx < marker_idx, (
        "blocked_ips drop must precede the killswitch accept marker"
    )
    assert invalid_idx < marker_idx, (
        "ct state invalid drop must precede the killswitch accept marker"
    )


def test_knockd_add_rule_matches_fw_nft_wrapper_echo_form(tmp_path, monkeypatch):
    """The fw-nft wrapper accepts only:
       --echo --json add rule ip firewall input <BODY>
    where ``<BODY>`` is a SINGLE argv token. knockd previously split BODY
    into many tokens, so the wrapper denied every call. The fix is to build
    BODY as one string so the wrapper's `[ "$#" -eq 8 ]` check passes.
    """
    import json
    import subprocess
    from daemons import knockd as knockd_mod

    conf = tmp_path / "firewall.ini"
    conf.write_text("[network]\nphy_if = eth0\nvpn_interface = wg0\nssh_port = 22\n")

    fake_wrapper = tmp_path / "fw-nft"
    fake_wrapper.write_text("#!/bin/sh\n")
    fake_wrapper.chmod(0o755)

    daemon = knockd_mod.PortKnockDaemon(str(conf), wrapper_path=str(fake_wrapper))

    # Force the non-root branch so we exercise the wrapper invocation
    monkeypatch.setattr(knockd_mod.os, "geteuid", lambda: 1000)

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return subprocess.CompletedProcess(
            cmd, 0,
            json.dumps({"nftables": [{"rule": {"handle": "42"}}]}),
            "",
        )

    monkeypatch.setattr(knockd_mod.subprocess, "run", fake_run)
    handle = daemon._add_rule("1.2.3.4")
    assert handle == "42"

    cmd = captured["cmd"]
    # ["sudo", "<wrapper>", "--echo", "--json", "add", "rule", "ip", "firewall", "input", "<BODY>"]
    assert cmd[0] == "sudo"
    assert cmd[1] == str(fake_wrapper)
    assert cmd[2:9] == ["--echo", "--json", "add", "rule", "ip", "firewall", "input"]
    assert len(cmd) == 10, f"wrapper requires exactly 8 trailing args; got {cmd[2:]}"
    body = cmd[9]
    assert 'iifname "wg0"' in body
    assert "ip saddr 1.2.3.4" in body
    assert "tcp dport 22 accept" in body


def test_output_chain_has_single_broad_wg_accept():
    """There must be exactly one broad `oifname "wg0" ... accept` in OUTPUT
    (the marker line). A duplicate is harmless functionally but wastes a hook
    slot and clutters reasoning about the chain."""
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="1.2.3.4",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
    )
    ruleset = generate_ruleset(cfg)
    output_start = ruleset.index("chain output {")
    output_end   = ruleset.index("\n    }", output_start)
    output_block = ruleset[output_start:output_end]

    broad = [
        line.strip() for line in output_block.splitlines()
        if line.strip().startswith('oifname "wg0"') and "accept" in line
        and "tcp dport" not in line and "udp dport" not in line
        and "ip daddr" not in line and "ip saddr" not in line
    ]
    assert len(broad) == 1, f"expected exactly one broad wg0 accept; got {broad}"


def test_geowhitelist_gates_only_explicit_tcp_services():
    """Country whitelist must never become a full physical-interface trust zone."""
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="1.2.3.4",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
        ssh_port=2222,
        extra_ports=[80, 443],
        lan_allow_ports=[80, 443, 8096, 2222],
        lan_allow_udp_ports=[7359],
        geowhitelist_ips=["2.56.4.0/22"],
    )

    ruleset = generate_ruleset(cfg)
    input_start = ruleset.index("chain input {")
    input_end = ruleset.index("\n    }", input_start)
    input_block = ruleset[input_start:input_end]

    assert "ip saddr @geowhitelist_ips accept" not in input_block
    assert (
        'iifname "eth0" ip saddr @geowhitelist_ips '
        "tcp dport { 80, 443, 2222 } accept"
    ) in input_block
    assert 'iifname "eth0" ip saddr != 192.168.1.0/24 drop' in input_block
    assert "ip saddr @geowhitelist_ips udp dport" not in input_block
    assert "ip saddr @geowhitelist_ips tcp dport 8096" not in input_block
