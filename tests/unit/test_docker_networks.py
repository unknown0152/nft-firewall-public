import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from integrations.docker import add_expose, detect_bridge_networks, firewall_policy_status, load_registry


def test_detect_bridge_networks_reads_docker_bridge_subnets(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/docker" if name == "docker" else None)

    def fake_run(cmd, **_kwargs):
        if cmd[:3] == ["docker", "network", "ls"]:
            return MagicMock(returncode=0, stdout="abc\n")
        if cmd[:3] == ["docker", "network", "inspect"]:
            return MagicMock(
                returncode=0,
                stdout=json.dumps([
                    {"IPAM": {"Config": [{"Subnet": "172.30.0.0/16"}, {"Subnet": "fd00::/64"}]}}
                ]),
            )
        raise AssertionError(cmd)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert detect_bridge_networks("172.16.0.0/12") == ["172.16.0.0/12", "172.30.0.0/16"]


def test_detect_bridge_networks_falls_back_when_docker_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: None)

    assert detect_bridge_networks("172.16.0.0/12") == ["172.16.0.0/12"]


def test_firewall_policy_status_ok_when_docker_iptables_disabled(tmp_path):
    daemon = tmp_path / "daemon.json"
    daemon.write_text('{"iptables": false, "ip6tables": false}\n')

    status, detail = firewall_policy_status(daemon)

    assert status == "ok"
    assert "iptables=false" in detail


def test_firewall_policy_status_fails_when_docker_can_manage_rules(tmp_path):
    daemon = tmp_path / "daemon.json"
    daemon.write_text('{"iptables": true, "ip6tables": false}\n')

    status, detail = firewall_policy_status(daemon)

    assert status == "fail"
    assert "Docker can manage firewall rules" in detail


def test_firewall_policy_status_warns_when_daemon_json_missing(tmp_path):
    status, detail = firewall_policy_status(tmp_path / "missing.json")

    assert status == "fail"
    assert "Docker defaults may manage firewall rules" in detail


def test_docker_expose_rejects_destination_outside_docker_networks(tmp_path):
    registry = tmp_path / "exposed.json"

    try:
        add_expose(
            8080,
            "192.168.100.10",
            80,
            allowed_networks=["172.18.0.0/16"],
            path=registry,
        )
    except ValueError as exc:
        assert "outside configured Docker networks" in str(exc)
    else:
        raise AssertionError("docker-expose accepted a non-Docker destination")

    assert not registry.exists()


def test_load_registry_ignores_malformed_entries(tmp_path):
    registry = tmp_path / "exposed.json"
    registry.write_text(json.dumps([
        {"host_port": 80, "container_ip": "172.18.0.4", "container_port": 8080, "proto": "tcp"},
        {"host_port": 443, "container_ip": "not-an-ip", "container_port": 8443, "proto": "tcp"},
        {"host_port": 0, "container_ip": "172.18.0.5", "container_port": 8080, "proto": "tcp"},
        "not-a-dict",
    ]))

    assert load_registry(registry) == [{
        "host_port": 80,
        "container_ip": "172.18.0.4",
        "container_port": 8080,
        "proto": "tcp",
    }]
