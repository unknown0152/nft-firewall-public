import sys
import types
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / 'src'))
import main
from main import _write_watchdog_markers


def _make_cfg(vpn_interface="wg0"):
    return types.SimpleNamespace(vpn_interface=vpn_interface)


def test_tmp_file_replaced_atomically(tmp_path, monkeypatch):
    markers_file = tmp_path / "watchdog-markers.json"
    nft_conf = tmp_path / "nftables.conf"
    nft_conf.write_text("flush ruleset\n")
    monkeypatch.setattr(main, "_MARKERS_FILE", markers_file)
    monkeypatch.setattr(main, "_NFT_CONF", nft_conf)

    _write_watchdog_markers(_make_cfg("wg0"))

    assert not markers_file.with_suffix(".tmp").exists(), ".tmp file should not remain after atomic replace"
    assert markers_file.exists(), "final JSON file should exist after write"


def test_json_content_is_correct(tmp_path, monkeypatch):
    markers_file = tmp_path / "watchdog-markers.json"
    nft_conf = tmp_path / "nftables.conf"
    nft_conf.write_text("flush ruleset\n")
    monkeypatch.setattr(main, "_MARKERS_FILE", markers_file)
    monkeypatch.setattr(main, "_NFT_CONF", nft_conf)

    _write_watchdog_markers(_make_cfg("wg0"))

    data = json.loads(markers_file.read_text())
    assert data["vpn_iface"] == "wg0"
    assert data["ip6_table"] == "killswitch"
    assert data["output_rule"] == 'comment "nft-killswitch-output"'
    assert data["persisted_ruleset"]["path"] == str(nft_conf)
    assert len(data["persisted_ruleset"]["sha256"]) == 64
    assert "updated_at" in data["persisted_ruleset"]


def test_permissions_are_644(tmp_path, monkeypatch):
    markers_file = tmp_path / "watchdog-markers.json"
    nft_conf = tmp_path / "nftables.conf"
    nft_conf.write_text("flush ruleset\n")
    monkeypatch.setattr(main, "_MARKERS_FILE", markers_file)
    monkeypatch.setattr(main, "_NFT_CONF", nft_conf)

    _write_watchdog_markers(_make_cfg("wg0"))

    mode = markers_file.stat().st_mode
    assert oct(mode & 0o777) == "0o644", f"Expected 0o644, got {oct(mode & 0o777)}"


def test_missing_persisted_ruleset_is_backward_compatible(tmp_path, monkeypatch):
    markers_file = tmp_path / "watchdog-markers.json"
    nft_conf = tmp_path / "missing.conf"
    monkeypatch.setattr(main, "_MARKERS_FILE", markers_file)
    monkeypatch.setattr(main, "_NFT_CONF", nft_conf)

    _write_watchdog_markers(_make_cfg("wg0"))

    data = json.loads(markers_file.read_text())
    assert "persisted_ruleset" not in data
