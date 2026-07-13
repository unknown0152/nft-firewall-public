"""Geoblock producer-state integration tests."""

import sys
from contextlib import nullcontext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from core import state
from integrations import geoblock


def test_block_country_uses_integrated_owner_transaction(monkeypatch):
    monkeypatch.setattr(geoblock, "_fetch_country", lambda _cc: ["203.0.113.0/24"])
    monkeypatch.setattr(geoblock, "_apply_block_guard", lambda _cidr: True)
    monkeypatch.setattr(geoblock, "_load_state", lambda: {})
    monkeypatch.setattr(state, "firewall_transaction_lock", nullcontext)
    monkeypatch.setattr(state, "set_list", lambda *_a, **_kw: [])
    calls = []
    monkeypatch.setattr(
        state,
        "geoblock_add",
        lambda cc, ips: calls.append((cc, ips)) or len(ips),
    )

    assert geoblock.block_country("ZZ", force=True) == (1, 0)
    assert calls == [("ZZ", ["203.0.113.0/24"])]


def test_unblock_country_uses_integrated_owner_transaction(monkeypatch):
    monkeypatch.setattr(
        geoblock, "_load_state", lambda: {"ZZ": ["203.0.113.0/24"]}
    )
    monkeypatch.setattr(state, "firewall_transaction_lock", nullcontext)
    calls = []
    monkeypatch.setattr(
        state,
        "geoblock_remove",
        lambda cc, ips: calls.append((cc, ips)) or len(ips),
    )

    assert geoblock.unblock_country("ZZ") == 1
    assert calls == [("ZZ", ["203.0.113.0/24"])]
