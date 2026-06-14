"""
tests/unit/test_debug_features.py

Tests for debug-friendly output features:
1. Rules output with --no-sets
2. Geoblock status parsing
3. Set stats display logic
"""
import re
import argparse
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

import pytest
import main
from integrations import geoblock

def test_rules_no_sets_strips_elements():
    """Verify that --no-sets correctly replaces element blocks with placeholders."""
    raw_rules = """
    table ip firewall {
        set blocked_ips {
            type ipv4_addr
            flags interval
            elements = { 1.2.3.4, 5.6.7.8 }
        }
        chain input {
            type filter hook input priority filter; policy drop;
        }
    }
    """
    
    # We test the regex used in _cmd_rules
    out = re.sub(r'elements\s*=\s*\{.*?\}', 'elements = { ... }', raw_rules, flags=re.DOTALL)
    
    assert "elements = { ... }" in out
    assert "1.2.3.4" not in out
    assert "5.6.7.8" not in out
    assert "chain input" in out

def test_geoblock_get_status_structure():
    """Verify that geoblock.get_status returns the expected technical fields."""
    with patch("integrations.geoblock._load_state", return_value={"CN": ["1.1.1.0/24"], "RU": ["2.2.2.0/24"]}):
        with patch("integrations.geoblock._CACHE_DIR") as mock_cache:
            mock_cache.glob.return_value = []
            
            status = geoblock.get_status()
            
            assert "state_file" in status
            assert "cache_dir" in status
            assert status["total_cidrs"] == 2
            assert "CN" in status["blocked_countries"]
            assert "RU" in status["blocked_countries"]

@patch("core.state.set_list")
def test_set_stats_output(mock_set_list, capsys):
    """Verify that set-stats command correctly calls set_list and prints counts."""
    # Mock counts for each set
    mock_set_list.side_effect = [
        ["1.1.1.1", "2.2.2.2"], # Blocked
        ["8.8.8.8"],           # Trusted
        [],                    # Whitelist
        ["10.0.0.1"]           # Knockd
    ]
    
    args = argparse.Namespace()
    main._cmd_set_stats(args)
    
    captured = capsys.readouterr().out
    assert "Blocked IPs" in captured
    assert "2" in captured
    assert "Trusted IPs" in captured
    assert "1" in captured
    assert "Geo Whitelist" in captured
    assert "0" in captured
    assert "Knockd IPs" in captured
    assert "1" in captured
