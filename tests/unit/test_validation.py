import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from utils.validation import validate_block_target, validate_port, validate_trusted_target
from core.rules import RulesetConfig
from core.state import load_persistent_sets


def test_block_target_rejects_default_route():
    result = validate_block_target("0.0.0.0/0")
    assert not result.ok


def test_block_target_rejects_never_block_overlap():
    result = validate_block_target("203.0.113.10", never_block=["203.0.113.0/24"])
    assert not result.ok


def test_block_target_accepts_public_cidr():
    result = validate_block_target("198.51.100.0/24")
    assert result.ok
    assert result.value == "198.51.100.0/24"


def test_trusted_target_rejects_private_range():
    result = validate_trusted_target("192.168.1.50")
    assert not result.ok


def test_validate_port_bounds():
    assert validate_port("443") == 443


def test_ruleset_config_rejects_slash_zero_lan_net():
    import pytest

    with pytest.raises(ValueError, match="lan_net"):
        RulesetConfig(phy_if="eth0", lan_net="0.0.0.0/0")


def test_ruleset_config_rejects_slash_zero_container_supernet():
    import pytest

    with pytest.raises(ValueError, match="container_supernet"):
        RulesetConfig(phy_if="eth0", container_supernet="0.0.0.0/0")


def test_ruleset_config_rejects_slash_zero_docker_network():
    import pytest

    with pytest.raises(ValueError, match="docker_networks"):
        RulesetConfig(phy_if="eth0", docker_networks=["0.0.0.0/0"])


def test_ruleset_config_rejects_slash_zero_dynamic_sets():
    import pytest

    for field in ("blocked_ips", "trusted_ips", "dk_ips"):
        with pytest.raises(ValueError, match=field):
            RulesetConfig(phy_if="eth0", **{field: ["0.0.0.0/0"]})


def test_persisted_dynamic_sets_drop_slash_zero(tmp_path):
    state_file = tmp_path / "dynamic-sets.json"
    state_file.write_text(json.dumps({
        "blocked_ips": ["0.0.0.0/0", "203.0.113.5"],
        "trusted_ips": ["0.0.0.0/0", "198.51.100.7"],
        "dk_ips": ["0.0.0.0/0", "193.163.0.0/16"],
    }))

    loaded = load_persistent_sets(state_file)

    assert "0.0.0.0/0" not in loaded["blocked_ips"]
    assert "0.0.0.0/0" not in loaded["trusted_ips"]
    assert "0.0.0.0/0" not in loaded["dk_ips"]
    assert loaded["blocked_ips"] == ["203.0.113.5/32"]
    assert loaded["trusted_ips"] == ["198.51.100.7/32"]
    assert loaded["dk_ips"] == ["193.163.0.0/16"]
