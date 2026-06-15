"""Unit tests for nft drop counter parsing."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from utils import analytics


def test_chain_drop_counter_reads_explicit_drop_prefix(monkeypatch):
    chain_output = """
table ip firewall {
    chain output {
        oifname "wg0" counter packets 23909 bytes 8781313 accept comment "nft-killswitch-output"
        counter packets 7 bytes 420 log prefix "[nft-out-drop] " flags all limit rate 5/minute
    }
}
"""

    monkeypatch.setattr(
        analytics.subprocess,
        "run",
        lambda *_args, **_kwargs: MagicMock(returncode=0, stdout=chain_output, stderr=""),
    )

    assert analytics.chain_drop_counter("output") == 7


def test_chain_drop_counter_rejects_unknown_chain():
    assert analytics.chain_drop_counter("nat") == 0


def test_total_drop_packets_sums_drop_chains(monkeypatch):
    values = {"input": 4, "output": 7, "forward": 2}

    def fake_counter(chain):
        return values[chain]

    monkeypatch.setattr(analytics, "chain_drop_counter", fake_counter)

    assert analytics.total_drop_packets() == 13
