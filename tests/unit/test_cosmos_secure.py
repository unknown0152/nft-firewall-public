import configparser
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

import main
import core.state as state
import integrations.docker as docker
from core.profiles import get_profile
from core.rules import RulesetConfig, generate_ruleset


def _rules(public_ports=None):
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
        docker_networks=["172.18.0.0/16", "172.19.0.0/16"],
        cosmos_public_ports=public_ports or [],
    )
    return generate_ruleset(cfg)


def test_cosmos_secure_profile_does_not_open_cosmos_vpn_port():
    profile = get_profile("cosmos-secure")
    ruleset = _rules([80, 443])

    assert "4242" not in ruleset
    assert "udp dport 4242" not in ruleset


def test_cosmos_public_ports_are_configurable():
    ruleset = _rules([8080])

    assert 'iifname "wg0" ip saddr @trusted_ips tcp dport { 8080 } accept' in ruleset
    assert 'iifname "eth0" tcp dport { 8080 } accept' not in ruleset
    assert "tcp dport { 80, 443 }" not in ruleset


def test_docker_forwarding_is_limited_to_configured_public_ports():
    ruleset = _rules([80, 443])

    assert "set docker_nets" in ruleset
    assert "elements = { 172.18.0.0/15 }" in ruleset
    assert 'iifname "wg0" ip saddr @trusted_ips tcp dport { 80, 443 } ip daddr @docker_nets accept' in ruleset
    assert 'iifname "eth0" tcp dport { 80, 443 } ip daddr @docker_nets accept' not in ruleset
    assert 'meta iifkind "bridge" meta oifkind "bridge" accept' not in ruleset


def test_public_ports_only_allowed_on_wg0():
    ruleset = _rules([80, 443])

    assert 'iifname "wg0" ip saddr @trusted_ips tcp dport { 80, 443 } accept' in ruleset
    assert 'iifname "eth0" tcp dport { 80, 443 } accept' not in ruleset


def test_build_ruleset_config_reads_cosmos_public_ports_from_ini(monkeypatch):
    cfg = configparser.ConfigParser()
    cfg.read_string("""
[network]
phy_if = eth0
vpn_interface = wg0
vpn_server_ip = 198.51.100.10
vpn_server_port = 51820
lan_net = 192.168.1.0/24
lan_full_access = false
lan_allow_ports = 2222,32400

[cosmos]
enabled = true
public_ports = 80,443
""")
    monkeypatch.setattr(state, "merge_live_sets_into_persistent", lambda: {})
    monkeypatch.setattr(docker, "detect_bridge_networks", lambda _supernet: ["172.18.0.0/16"])
    # Mock interface existence validation for tests
    import core.rules
    monkeypatch.setattr(core.rules, "validate_interface_exists", lambda _iface: None)

    ruleset_cfg = main._build_ruleset_config(cfg, "cosmos-vpn-secure")
    ruleset = generate_ruleset(ruleset_cfg)

    assert ruleset_cfg.cosmos_public_ports == [80, 443]
    assert ruleset_cfg.lan_full_access is False
    assert ruleset_cfg.lan_allow_ports == [2222, 32400]
    assert 'iifname "wg0" ip saddr @trusted_ips tcp dport { 80, 443 } accept' in ruleset
    assert 'iifname "eth0" tcp dport { 80, 443 } accept' not in ruleset
    assert "4242" not in ruleset


def test_cosmos_public_ports_do_not_require_running_docker_containers(monkeypatch):
    cfg = configparser.ConfigParser()
    cfg.read_string("""
[network]
phy_if = pub0
vpn_interface = wg0
vpn_server_ip = 198.51.100.10
vpn_server_port = 51820
lan_net = 192.168.1.0/24

[cosmos]
enabled = true
public_ports = 80,443
""")
    monkeypatch.setattr(state, "merge_live_sets_into_persistent", lambda: {})
    monkeypatch.setattr(docker, "detect_bridge_networks", lambda _supernet: [])
    # Mock interface existence validation for tests
    import core.rules
    monkeypatch.setattr(core.rules, "validate_interface_exists", lambda _iface: None)

    ruleset_cfg = main._build_ruleset_config(cfg, "cosmos-vpn-secure")
    ruleset = generate_ruleset(ruleset_cfg, exposed_ports=[])

    assert ruleset_cfg.docker_networks == []
    assert ruleset_cfg.cosmos_public_ports == [80, 443]
    assert 'iifname "wg0" ip saddr @trusted_ips tcp dport { 80, 443 } accept' in ruleset
    assert 'iifname "pub0" tcp dport { 80, 443 } accept' not in ruleset
    assert "udp dport 4242" not in ruleset


def test_cosmos_public_input_accept_is_not_duplicated_by_extra_ports():
    cfg = RulesetConfig(
        phy_if="pub0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        extra_ports=[80, 443, 8443],
        cosmos_public_ports=[80, 443, 443],
    )
    ruleset = generate_ruleset(cfg)

    assert ruleset.count('iifname "wg0" ip saddr @trusted_ips tcp dport { 80, 443 } accept') == 1
    assert 'iifname "wg0" tcp dport { 8443 } accept' in ruleset
    assert 'iifname "pub0" tcp dport { 80, 443 } accept' not in ruleset
    assert "udp dport 4242" not in ruleset


def test_strict_lan_mode_does_not_allow_random_lan_port():
    cfg = RulesetConfig(
        phy_if="pub0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        lan_net="192.168.100.0/24",
        ssh_port=2222,
        lan_full_access=False,
        lan_allow_ports=[2222, 32400],
        cosmos_public_ports=[80, 443],
    )
    ruleset = generate_ruleset(cfg)

    assert 'iifname "pub0" ip saddr 192.168.100.0/24 accept' not in ruleset
    assert 'iifname "pub0" ip saddr 192.168.100.0/24 tcp dport 9999 accept' not in ruleset
    assert 'iifname "pub0" ip saddr 192.168.100.0/24 drop' in ruleset


def test_strict_lan_mode_allows_configured_lan_ports_and_preserves_cosmos():
    cfg = RulesetConfig(
        phy_if="pub0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        lan_net="192.168.100.0/24",
        ssh_port=2222,
        lan_full_access=False,
        lan_allow_ports=[2222, 32400],
        cosmos_public_ports=[80, 443],
    )
    ruleset = generate_ruleset(cfg)

    assert 'iifname "pub0" ip saddr 192.168.100.0/24 tcp dport 2222 accept' in ruleset
    assert 'iifname "pub0" ip saddr 192.168.100.0/24 tcp dport { 2222, 32400 } accept' in ruleset
    assert 'iifname "wg0" ip saddr @trusted_ips tcp dport { 80, 443 } accept' in ruleset
    assert 'iifname "pub0" tcp dport { 80, 443 } accept' not in ruleset
    assert "udp dport 4242" not in ruleset


def test_lan_full_access_preserves_legacy_trusted_lan_behavior():
    cfg = RulesetConfig(
        phy_if="pub0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        lan_net="192.168.100.0/24",
        lan_full_access=True,
    )
    ruleset = generate_ruleset(cfg)

    assert 'iifname "pub0" ip saddr 192.168.100.0/24 accept' in ruleset
    assert 'iifname "pub0" ip saddr 192.168.100.0/24 drop' not in ruleset


def test_installed_load_config_prefers_etc_nft_firewall(monkeypatch, tmp_path):
    local_conf = tmp_path / "opt-firewall.ini"
    etc_conf = tmp_path / "etc-nft-firewall.ini"
    legacy_conf = tmp_path / "nft-watchdog.conf"

    local_conf.write_text("[network]\nphy_if = eth0\n", encoding="utf-8")
    etc_conf.write_text(
        "[network]\nphy_if = pub0\n\n[cosmos]\nenabled = true\npublic_ports = 80,443\n",
        encoding="utf-8",
    )
    legacy_conf.write_text("[network]\nphy_if = legacy0\n", encoding="utf-8")

    monkeypatch.setattr(main, "_PROJECT_ROOT", Path("/opt/nft-firewall"))
    monkeypatch.setattr(main, "_LOCAL_CONF", local_conf)
    monkeypatch.setattr(main, "_ETC_CONF", etc_conf)
    monkeypatch.setattr(main, "_SYSTEM_CONF", legacy_conf)

    cfg = main._load_config()

    assert cfg.get("network", "phy_if") == "pub0"
    assert cfg.getboolean("cosmos", "enabled") is True
    assert cfg.get("cosmos", "public_ports") == "80,443"


def test_overlapping_docker_networks_are_collapsed_for_interval_set():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        docker_networks=["172.16.0.0/12", "172.17.0.0/16", "172.18.0.0/16"],
        cosmos_public_ports=[80, 443],
    )
    ruleset = generate_ruleset(cfg)

    assert "elements = { 172.16.0.0/12 }" in ruleset
    assert "172.17.0.0/16" not in ruleset
    assert "172.18.0.0/16" not in ruleset


def test_generated_interval_sets_are_collapsed():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        blocked_ips=["203.0.113.0/24", "203.0.113.7/32"],
        trusted_ips=["198.51.100.0/24", "198.51.100.4/32"],
        dk_ips=["193.163.0.0/16", "193.163.10.0/24"],
    )
    ruleset = generate_ruleset(cfg)

    assert "elements = { 203.0.113.0/24 }" in ruleset
    assert "203.0.113.7/32" not in ruleset
    assert "elements = { 198.51.100.0/24 }" in ruleset
    assert "198.51.100.4/32" not in ruleset
    assert "elements = { 193.163.0.0/16 }" in ruleset
    assert "193.163.10.0/24" not in ruleset


def test_random_published_container_port_is_not_allowed_without_config_port():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        docker_networks=["172.18.0.0/16"],
        cosmos_public_ports=[80, 443],
    )
    exposed = [{
        "host_port": 9999,
        "container_ip": "172.18.0.5",
        "container_port": 9999,
        "proto": "tcp",
    }]
    ruleset = generate_ruleset(cfg, exposed_ports=exposed)

    assert "tcp dport 9999 dnat" not in ruleset
    assert "tcp dport 9999 ip daddr 172.18.0.5 accept" not in ruleset
    assert 'iifname "eth0" tcp dport 9999 accept' not in ruleset


def test_published_container_port_is_allowed_when_listed_in_firewall_config():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        docker_networks=["172.18.0.0/16"],
        cosmos_public_ports=[8080],
    )
    exposed = [{
        "host_port": 8080,
        "container_ip": "172.18.0.5",
        "container_port": 80,
        "proto": "tcp",
    }]
    ruleset = generate_ruleset(cfg, exposed_ports=exposed)

    assert 'iifname "wg0" tcp dport 8080 dnat to 172.18.0.5:80' in ruleset
    assert 'iifname "eth0" tcp dport 8080 dnat to 172.18.0.5:80' not in ruleset
    assert 'iifname "wg0" tcp dport 80 ip daddr 172.18.0.5 accept' in ruleset
    assert 'iifname "eth0" tcp dport 80 ip daddr 172.18.0.5 accept' not in ruleset


def test_container_killswitch_remains_enforced_for_forwarding():
    ruleset = _rules([80, 443])

    assert 'ip saddr @docker_nets oifname "eth0" drop' in ruleset
    assert 'ip saddr @docker_nets oifname "wg0" accept' in ruleset
    assert '        oifname "wg0" accept  # container internet ONLY via VPN' not in ruleset


def test_ssh_rules_remain_protected():
    ruleset = _rules([80, 443])

    assert 'iifname "eth0" ip saddr 192.168.1.0/24 tcp dport 22 accept' in ruleset
    assert 'iifname "eth0" tcp dport 22 drop' in ruleset
    assert 'iifname "wg0" tcp dport 22 drop' in ruleset


def test_output_dhcp_is_restricted_to_sport_68():
    ruleset = _rules([80, 443])

    assert "udp sport 68 udp dport 67 accept" in ruleset
    assert "udp dport 67 accept" not in ruleset.replace("udp sport 68 udp dport 67 accept", "")


def test_container_to_phy_is_hard_dropped_for_all_states():
    ruleset = _rules([80, 443])

    assert 'ip saddr @docker_nets oifname "eth0" drop' in ruleset
    assert 'ip saddr @docker_nets oifname "eth0" ct state new drop' not in ruleset


def test_container_dnat_replies_to_lan_are_allowed():
    ruleset = _rules([80, 443])

    assert (
        'ip saddr @docker_nets oifname "eth0" ip daddr 192.168.1.0/24 '
        'ct state established,related accept'
    ) in ruleset
