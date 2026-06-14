import configparser
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))


def _patch_doctor_common(monkeypatch, ruleset=None):
    import core.rules
    import core.state
    import integrations.docker
    import main
    import subprocess

    cfg = configparser.ConfigParser()
    cfg["install"] = {"profile": "cosmos-vpn-secure"}
    default_ruleset = ruleset or (
        'table ip6 killswitch { chain input { priority -300; } }\n'
        'table ip firewall { chain output { oifname "wg0" accept } }\n'
    )

    monkeypatch.setattr(main, "_load_config", lambda: cfg)
    monkeypatch.setattr(
        main,
        "_build_ruleset_config",
        lambda _cfg, _profile: types.SimpleNamespace(phy_if="eth0", vpn_interface="wg0"),
    )
    monkeypatch.setattr(integrations.docker, "load_registry", lambda: [])
    monkeypatch.setattr(
        integrations.docker,
        "firewall_policy_status",
        lambda: ("ok", "Docker iptables=false and ip6tables=false"),
    )
    monkeypatch.setattr(
        main,
        "_nftables_service_status",
        lambda: ("ok", "nftables.service is enabled"),
    )
    monkeypatch.setattr(
        core.rules,
        "generate_ruleset",
        lambda _cfg, exposed_ports=None: default_ruleset,
    )
    monkeypatch.setattr(core.state, "load_persistent_sets", lambda: {})

    def fake_run(cmd, **_kwargs):
        if cmd == ["nft", "list", "ruleset"] or cmd[-2:] == ["list", "ruleset"]:
            return subprocess.CompletedProcess(cmd, 0, default_ruleset, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return main, core.state


def test_config_sanity_accepts_current_shape():
    import main

    cfg = configparser.ConfigParser()
    cfg.read_string("""
[network]
phy_if = pub0
vpn_interface = wg0
vpn_server_ip = 198.51.100.10
vpn_server_port = 51820
ssh_port = 2222
lan_net = 192.168.100.0/24
container_supernet = 172.16.0.0/12
lan_full_access = false
lan_allow_ports = 2222, 80, 443
lan_allow_udp_ports = 7359

[cosmos]
enabled = true
public_ports = 80,443

[watchdog]
check_interval = 30
daily_summary_hour = 8

[listener]
poll_interval = 15
""")

    assert main._validate_config_sanity(cfg) == []


def test_config_sanity_reports_malformed_operator_values():
    import main

    cfg = configparser.ConfigParser()
    cfg.read_string("""
[network]
phy_if = wg0
vpn_interface = wg0
vpn_server_ip = 198.51.100.0/24
ssh_port = 70000
lan_net = 0.0.0.0/0
lan_full_access = maybe
lan_allow_ports = 80,bad

[cosmos]
enabled = not-bool
public_ports = 443,99999

[watchdog]
daily_summary_hour = 24

[listener]
poll_interval = 0
""")

    issues = main._validate_config_sanity(cfg)
    rendered = "; ".join(f"{key}: {detail}" for _status, key, detail in issues)

    assert any(status == "fail" for status, _key, _detail in issues)
    assert "network.vpn_interface: must differ from phy_if" in rendered
    assert "network.vpn_server_ip" in rendered
    assert "network.ssh_port" in rendered
    assert "network.lan_net" in rendered
    assert "network.lan_full_access" in rendered
    assert "cosmos.enabled" in rendered
    assert "watchdog.daily_summary_hour" in rendered
    assert "listener.poll_interval" in rendered


def test_doctor_fails_on_config_sanity_error(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)
    cfg = configparser.ConfigParser()
    cfg.read_string("""
[install]
profile = cosmos-vpn-secure

[network]
ssh_port = 70000
""")
    monkeypatch.setattr(main, "_load_config", lambda: cfg)
    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "[fail] config sanity:" in out
    assert "network.ssh_port" in out


def test_doctor_uses_installed_privileged_nft_wrapper(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)
    seen = {}

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    monkeypatch.setattr(
        main.Path,
        "exists",
        lambda self: str(self) == "/usr/local/lib/nft-firewall/fw-nft",
    )

    def fake_simulate(_ruleset, nft_cmd=None):
        seen["nft_cmd"] = nft_cmd
        return True, ""

    monkeypatch.setattr(state, "simulate_apply", fake_simulate)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    assert exc.value.code == 0
    assert seen["nft_cmd"] == ["sudo", "/usr/local/lib/nft-firewall/fw-nft"]
    assert "[ok] nft --check: ruleset syntax valid" in capsys.readouterr().out


def test_doctor_warns_when_privileged_nft_wrapper_missing(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    monkeypatch.setattr(main.Path, "exists", lambda _self: False)
    monkeypatch.setattr(
        state,
        "simulate_apply",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not run")),
    )

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "[warn] nft --check: nft --check requires installed sudo wrapper; run setup.py install or run doctor as root" in out


def test_doctor_warns_when_sudo_wrapper_permission_missing(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    monkeypatch.setattr(
        main.Path,
        "exists",
        lambda self: str(self) == "/usr/local/lib/nft-firewall/fw-nft",
    )
    monkeypatch.setattr(
        state,
        "simulate_apply",
        lambda _ruleset, nft_cmd=None: (False, "sudo: a password is required"),
    )

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "[warn] nft --check: nft --check requires installed sudo wrapper; run setup.py install or run doctor as root" in out


def test_doctor_fails_when_docker_iptables_enabled(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)

    import integrations.docker

    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))
    monkeypatch.setattr(
        integrations.docker,
        "firewall_policy_status",
        lambda: ("fail", "Docker can manage firewall rules"),
    )

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "[fail] docker firewall authority: Docker can manage firewall rules" in out


def test_doctor_detects_broad_zero_generated_rules(monkeypatch, capsys):
    ruleset = (
        'table ip6 killswitch { chain input { priority -300; } }\n'
        'table ip firewall { chain output { oifname "wg0" accept }\n'
        'chain input { iifname "eth0" ip saddr 0.0.0.0/0 accept } }\n'
    )
    main, state = _patch_doctor_common(monkeypatch, ruleset=ruleset)

    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "[fail] broad /0 generated rules" in out


def test_doctor_detects_public_web_on_physical(monkeypatch, capsys):
    ruleset = (
        'table ip6 killswitch { chain input { priority -300; } }\n'
        'table ip firewall { chain output { oifname "wg0" accept }\n'
        'chain input { iifname "eth0" tcp dport { 80, 443 } accept } }\n'
    )
    main, state = _patch_doctor_common(monkeypatch, ruleset=ruleset)

    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "[fail] physical public 80/443" in out


def test_doctor_detects_malicious_live_rules(monkeypatch, capsys):
    """Verify that doctor detects broad/unconditional accept rules in LIVE nftables."""
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    import subprocess

    def mock_run(cmd, **kwargs):
        class MockResult:
            returncode = 0
            stdout = ""
            stderr = ""
        
        res = MockResult()
        # Mocking 'nft list ruleset' specifically
        if cmd == ["nft", "list", "ruleset"]:
            res.stdout = (
                'table ip firewall {\n'
                '    chain output {\n'
                '        accept\n'  # Standalone accept — FAILURE 1
                '    }\n'
                '    chain forward {\n'
                '        ip saddr @docker_nets oifname "eth0" accept\n' # Docker escape — FAILURE 2
                '    }\n'
                '    chain input {\n'
                '        iifname "eth0" tcp dport 80 accept\n' # Public exposure — FAILURE 3
                '    }\n'
                '}\n'
            )
        return res

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "[fail] live rules invariants" in out
    assert "output chain contains a standalone 'accept' rule" in out
    assert "forwarding allows @docker_nets to escape via eth0" in out
    assert "public port exposure on eth0" in out


def test_doctor_allows_intended_forward_rules(monkeypatch, capsys):
    """Verify that doctor ALLOWS safe rules (hard-drop and LAN-restricted established)."""
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    import subprocess

    def mock_run(cmd, **kwargs):
        class MockResult:
            returncode = 0
            stdout = ""
            stderr = ""
        
        res = MockResult()
        if cmd == ["nft", "list", "ruleset"]:
            res.stdout = (
                'table ip firewall {\n'
                '    chain forward {\n'
                '        # SAFE: hard drop\n'
                '        ip saddr @docker_nets oifname "eth0" drop\n'
                '        # SAFE: restricted established\n'
                '        ip saddr @docker_nets oifname "eth0" ip daddr 192.168.1.0/24 ct state established,related accept\n'
                '    }\n'
                '    chain output {\n'
                '        oifname "wg0" accept comment "nft-killswitch-output"\n'
                '    }\n'
                '}\n'
            )
        return res

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "[ok] live rules invariants: intact" in out


def test_doctor_fails_on_malicious_forward_established(monkeypatch, capsys):
    """Verify that doctor FAILS on established rules that LACK daddr restriction."""
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    import subprocess

    def mock_run(cmd, **kwargs):
        class MockResult:
            returncode = 0
            stdout = 'table ip firewall {\n' \
                     '    chain forward {\n' \
                     '        ip saddr @docker_nets oifname "eth0" ct state established,related accept\n' \
                     '    }\n' \
                     '    chain output {\n' \
                     '        oifname "wg0" accept comment "nft-killswitch-output"\n' \
                     '    }\n' \
                     '}\n'
            stderr = ""
        return MockResult()

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "forwarding allows @docker_nets to escape via eth0" in out


def test_doctor_fails_on_standalone_output_accept(monkeypatch, capsys):
    """Verify that doctor FAILS when a bare 'accept' is added to output chain."""
    main, state = _patch_doctor_common(monkeypatch)
    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    import subprocess
    def mock_run(cmd, **kwargs):
        class MockResult:
            returncode = 0
            stdout = (
                'table ip firewall {\n'
                '    chain output {\n'
                '        type filter hook output priority filter; policy drop;\n'
                '        oifname "wg0" accept comment "nft-killswitch-output"\n'
                '        accept\n' # MALICIOUS BARE ACCEPT
                '    }\n'
                '}\n'
            )
            stderr = ""
        return MockResult()

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 1
    assert "output chain contains a standalone 'accept' rule" in out


def test_check_live_rules_handles_nested_brace_set_literal():
    """The chain parser must NOT stop at the first '}' from a port-set literal.

    Real `nft list ruleset` output places set literals like `tcp dport {80,443}`
    inside chain bodies. A regex with `chain ... { (.*?) }` truncates the body
    there and misses any malicious rule placed AFTER the set literal.
    """
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent.parent / "src"))
    from main import _check_live_rules_invariants

    ruleset = (
        'table ip firewall {\n'
        '    chain output {\n'
        '        type filter hook output priority filter; policy drop;\n'
        '        oifname "wg0" tcp dport { 80, 443 } accept\n'
        '        accept\n'  # bare accept hidden behind the set literal
        '    }\n'
        '}\n'
    )
    violations = _check_live_rules_invariants(ruleset, "eth0", "wg0")
    assert any("standalone 'accept'" in v for v in violations), (
        f"bare accept after a set literal must still be detected; got {violations!r}"
    )


def test_check_live_rules_handles_nested_set_definition_block():
    """Inline set definition blocks (`set foo { ... elements = { ... } }`) must
    not break the chain extractor either — they have multiple nested braces.
    """
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent.parent / "src"))
    from main import _check_live_rules_invariants

    ruleset = (
        'table ip firewall {\n'
        '    set blocked_ips {\n'
        '        type ipv4_addr\n'
        '        flags interval\n'
        '        elements = { 1.2.3.0/24, 8.8.8.0/24 }\n'
        '    }\n'
        '    chain output {\n'
        '        type filter hook output priority filter; policy drop;\n'
        '        oifname "wg0" counter accept comment "nft-killswitch-output"\n'
        '        ip daddr @blocked_ips drop\n'
        '        oifname "eth0" tcp dport { 80, 443 } accept\n'
        '        accept\n'  # malicious rule, placed after a set literal
        '    }\n'
        '}\n'
    )
    violations = _check_live_rules_invariants(ruleset, "eth0", "wg0")
    assert any("standalone 'accept'" in v for v in violations), (
        f"bare accept must still be detected with set definitions present; got {violations!r}"
    )


def test_check_live_rules_no_false_positive_on_clean_generated_ruleset(monkeypatch):
    """The new parser must not regress: a real generated ruleset must stay clean."""
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent.parent / "src"))
    from core.rules import RulesetConfig, generate_ruleset
    from main import _check_live_rules_invariants

    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="1.2.3.4",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
    )
    ruleset = generate_ruleset(cfg)
    violations = _check_live_rules_invariants(ruleset, "eth0", "wg0", "192.168.1.0/24")
    assert violations == [], f"clean generated ruleset flagged: {violations}"


def test_check_live_rules_allows_source_restricted_physical_web():
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent.parent / "src"))
    from main import _check_live_rules_invariants

    ruleset = (
        'table ip firewall {\n'
        '    chain input {\n'
        '        type filter hook input priority filter; policy drop;\n'
        '        iifname "eth0" ip saddr 192.168.1.0/24 tcp dport { 80, 443 } accept\n'
        '        iifname "eth0" ip saddr @geowhitelist_ips tcp dport { 80, 443 } accept\n'
        '        iifname "eth0" tcp dport 2222 drop\n'
        '    }\n'
        '}\n'
    )

    violations = _check_live_rules_invariants(ruleset, "eth0", "wg0", "192.168.1.0/24")
    assert violations == [], f"source-restricted physical web rules flagged: {violations}"


def test_check_live_rules_flags_unrestricted_physical_web():
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent.parent / "src"))
    from main import _check_live_rules_invariants

    ruleset = (
        'table ip firewall {\n'
        '    chain input {\n'
        '        type filter hook input priority filter; policy drop;\n'
        '        iifname "eth0" tcp dport { 80, 443 } accept\n'
        '    }\n'
        '}\n'
    )

    violations = _check_live_rules_invariants(ruleset, "eth0", "wg0", "192.168.1.0/24")
    assert any("public port exposure on eth0" in v for v in violations)


def test_doctor_uses_wrapper_for_live_ruleset_when_not_root(monkeypatch, capsys):
    """As fw-admin, raw `nft list ruleset` fails — doctor must fall back to the wrapper.

    Without this fallback, the live-rules invariant check is silently a no-op
    in the systemd-driven `nft-firewall-doctor.service` (which runs as fw-admin
    and has no CAP_NET_ADMIN). Then a malicious bare `accept` in the live
    OUTPUT chain would never be reported.
    """
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    # Pretend the privileged wrapper is installed
    monkeypatch.setattr(
        main.Path,
        "exists",
        lambda self: str(self) == "/usr/local/lib/nft-firewall/fw-nft",
    )
    monkeypatch.setattr(state, "simulate_apply", lambda *_a, **_kw: (True, ""))

    import subprocess

    seen = []

    def mock_run(cmd, **kwargs):
        seen.append(list(cmd))
        # Raw nft fails — fw-admin doesn't have CAP_NET_ADMIN
        if cmd == ["nft", "list", "ruleset"]:
            if kwargs.get("check"):
                raise subprocess.CalledProcessError(1, cmd, stderr="Operation not permitted")
            return subprocess.CompletedProcess(cmd, 1, "", "Operation not permitted")
        # Wrapper succeeds and returns a malicious ruleset
        if cmd[:1] == ["sudo"] and "fw-nft" in cmd[-3] and cmd[-2:] == ["list", "ruleset"]:
            return subprocess.CompletedProcess(
                cmd,
                0,
                'table ip firewall {\n'
                '    chain output {\n'
                '        accept\n'
                '    }\n'
                '}\n',
                "",
            )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    # The wrapper invocation must have been attempted
    wrapper_calls = [c for c in seen if c[:1] == ["sudo"] and "fw-nft" in str(c)]
    assert wrapper_calls, f"doctor did not fall back to wrapper; calls={seen}"
    # And the malicious rule it returned must be reported
    assert exc.value.code == 1
    assert "[fail] live rules invariants" in out
    assert "standalone 'accept'" in out


def test_doctor_warns_when_live_ruleset_unreadable(monkeypatch, capsys):
    """If both raw nft and the wrapper fail, doctor must warn — not silently pass."""
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    # Wrapper is NOT installed
    monkeypatch.setattr(main.Path, "exists", lambda self: False)
    monkeypatch.setattr(state, "simulate_apply", lambda *_a, **_kw: (True, ""))

    import subprocess

    def mock_run(cmd, **kwargs):
        if cmd == ["nft", "list", "ruleset"] and kwargs.get("check"):
            raise subprocess.CalledProcessError(1, cmd, stderr="Operation not permitted")
        return subprocess.CompletedProcess(cmd, 1, "", "Operation not permitted")

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert "[warn] live rules invariants" in out


def test_doctor_allows_wireguard_bootstrap_output_rule(monkeypatch, capsys):
    """Verify that doctor ALLOWS the legitimate WireGuard bootstrap rule in output."""
    main, state = _patch_doctor_common(monkeypatch)
    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    monkeypatch.setattr(state, "simulate_apply", lambda _ruleset: (True, ""))

    import subprocess
    def mock_run(cmd, **kwargs):
        class MockResult:
            returncode = 0
            stdout = (
                'table ip firewall {\n'
                '    chain output {\n'
                '        type filter hook output priority filter; policy drop;\n'
                '        # The actual bootstrap rule from core/rules.py\n'
                '        oifname "eth0" meta mark 0x0000ca6c ip daddr 1.2.3.4 udp dport 51820 accept\n'
                '        oifname "wg0" accept comment "nft-killswitch-output"\n'
                '    }\n'
                '}\n'
            )
            stderr = ""
        return MockResult()

    monkeypatch.setattr(subprocess, "run", mock_run)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "[ok] live rules invariants: intact" in out
