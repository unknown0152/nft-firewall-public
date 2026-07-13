"""Transactional geoblock producer-state tests."""

import sys
from contextlib import nullcontext
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from core import state
from integrations import geoblock


def test_block_country_compensates_when_country_metadata_save_fails(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(geoblock, "_STATE_FILE", tmp_path / "geo.json")
    monkeypatch.setattr(geoblock, "_fetch_country", lambda _cc: ["203.0.113.0/24"])
    monkeypatch.setattr(geoblock, "_apply_block_guard", lambda _cidr: True)
    monkeypatch.setattr(state, "firewall_transaction_lock", nullcontext)
    calls = []
    monkeypatch.setattr(
        state, "set_add_bulk", lambda name, ips: calls.append(("add", name, ips)) or len(ips)
    )
    monkeypatch.setattr(
        state, "set_del_bulk", lambda name, ips: calls.append(("del", name, ips)) or len(ips)
    )
    monkeypatch.setattr(
        geoblock, "_save_state", lambda _data: (_ for _ in ()).throw(OSError("disk full"))
    )

    with pytest.raises(OSError, match="disk full"):
        geoblock.block_country("ZZ", force=True)

    assert calls == [
        ("add", state.SET_GEO_BLOCKED, ["203.0.113.0/24"]),
        ("del", state.SET_GEO_BLOCKED, ["203.0.113.0/24"]),
    ]


def test_unblock_country_restores_live_owner_when_metadata_save_fails(
    monkeypatch, tmp_path
):
    state_file = tmp_path / "geo.json"
    state_file.write_text('{"ZZ": ["203.0.113.0/24"]}')
    monkeypatch.setattr(geoblock, "_STATE_FILE", state_file)
    monkeypatch.setattr(state, "firewall_transaction_lock", nullcontext)
    calls = []
    monkeypatch.setattr(
        state, "set_del_bulk", lambda name, ips: calls.append(("del", name, ips)) or len(ips)
    )
    monkeypatch.setattr(
        state, "set_add_bulk", lambda name, ips: calls.append(("add", name, ips)) or len(ips)
    )
    monkeypatch.setattr(
        geoblock, "_save_state", lambda _data: (_ for _ in ()).throw(OSError("disk full"))
    )

    with pytest.raises(OSError, match="disk full"):
        geoblock.unblock_country("ZZ")

    assert calls == [
        ("del", state.SET_GEO_BLOCKED, ["203.0.113.0/24"]),
        ("add", state.SET_GEO_BLOCKED, ["203.0.113.0/24"]),
    ]
