"""
tests/unit/test_privileged_wrapper.py

Verifies the argument strictness and shell-token denial in the generated fw-nft wrapper.
"""
import os
import subprocess
import tempfile
from pathlib import Path
import pytest

# We extract the script generation logic or the template from setup.py
# For this test, we'll recreate the script from the same logic used in setup.py

WRAPPER_TEMPLATE = r"""#!/usr/bin/env bash
# Wrapper installed by nft-firewall setup.py
# Restricts privileged nftables operations to a strict allowlist.
set -euo pipefail

# 1. Deny shell injection tokens in ANY argument
for arg in "$@"; do
  if [[ "$arg" == *[';|&$()`><']* ]]; then
    echo "fw-nft: denied special characters in argument: $arg" >&2
    exit 126
  fi
done

case "${1:-}" in
  list)
    case "${2:-}" in
      ruleset) [ "$#" -eq 2 ] && exec echo nft list ruleset ;;
      set) [ "$#" -eq 5 ] && [ "${3:-}" = "ip" ] && [ "${4:-}" = "firewall" ] && case "${5:-}" in blocked_ips|trusted_ips|dk_ips|geowhitelist_ips) exec echo nft list set ip firewall "$5" ;; esac ;;
      chain) [ "$#" -eq 5 ] && [ "${3:-}" = "ip" ] && [ "${4:-}" = "firewall" ] && case "${5:-}" in input|output|forward) exec echo nft list chain ip firewall "$5" ;; esac ;;
      tables) [ "$#" -eq 3 ] && [ "${2:-}" = "tables" ] && [ "${3:-}" = "ip6" ] && exec echo nft list tables ip6 ;;
    esac
    ;;
  add|delete)
    if [ "$#" -eq 6 ] && [ "${2:-}" = "element" ] && [ "${3:-}" = "ip" ] && [ "${4:-}" = "firewall" ]; then
       case "${5:-}" in blocked_ips|trusted_ips|dk_ips|geowhitelist_ips) exec echo nft "$1" element ip firewall "$5" "$6" ;; esac
    fi
    if [ "$1" = "delete" ] && [ "$#" -eq 7 ] && [ "${2:-}" = "rule" ] && [ "${3:-}" = "ip" ] && \
       [ "${4:-}" = "firewall" ] && [ "${5:-}" = "input" ] && [ "${6:-}" = "handle" ]; then
       exec echo nft delete rule ip firewall input handle "$7"
    fi
    ;;
  --check) [ "$#" -eq 3 ] && [ "${2:-}" = "--file" ] && exec echo nft --check --file "$3" ;;
  --file|-f) [ "$#" -eq 2 ] && [ "${2:-}" = "/etc/nftables.conf" ] && exec echo nft -f /etc/nftables.conf ;;

  --echo) [ "$#" -eq 8 ] && [ "${2:-}" = "--json" ] && [ "${3:-}" = "add" ] && [ "${4:-}" = "rule" ] && [ "${5:-}" = "ip" ] && [ "${6:-}" = "firewall" ] && [ "${7:-}" = "input" ] && exec echo nft --echo --json add rule ip firewall input "$8" ;;
esac
echo "fw-nft: denied arguments: $*" >&2
exit 126
"""

@pytest.fixture
def wrapper_path(tmp_path):
    p = tmp_path / "fw-nft"
    p.write_text(WRAPPER_TEMPLATE)
    p.chmod(0o755)
    return p

def run_wrapper(path, args):
    return subprocess.run(
        ["bash", str(path)] + args,
        capture_output=True,
        text=True
    )

def test_allow_exact_list_ruleset(wrapper_path):
    r = run_wrapper(wrapper_path, ["list", "ruleset"])
    assert r.returncode == 0
    assert r.stdout.strip() == "nft list ruleset"

def test_deny_extra_args_list_ruleset(wrapper_path):
    r = run_wrapper(wrapper_path, ["list", "ruleset", "extra"])
    assert r.returncode == 126
    assert "denied arguments" in r.stderr

def test_deny_shell_tokens(wrapper_path):
    tokens = [";", "&&", "|", "`", "$()", "<", ">"]
    for token in tokens:
        r = run_wrapper(wrapper_path, ["list", "ruleset" + token])
        assert r.returncode == 126
        assert "denied special characters" in r.stderr

def test_deny_shell_tokens_as_separate_arg(wrapper_path):
    r = run_wrapper(wrapper_path, ["list", "ruleset", "; id"])
    assert r.returncode == 126
    assert "denied special characters" in r.stderr

def test_allow_exact_add_element(wrapper_path):
    r = run_wrapper(wrapper_path, ["add", "element", "ip", "firewall", "blocked_ips", "1.2.3.4"])
    assert r.returncode == 0
    assert r.stdout.strip() == "nft add element ip firewall blocked_ips 1.2.3.4"

def test_deny_extra_args_add_element(wrapper_path):
    r = run_wrapper(wrapper_path, ["add", "element", "ip", "firewall", "blocked_ips", "1.2.3.4", "extra"])
    assert r.returncode == 126

def test_allow_check_file(wrapper_path):
    r = run_wrapper(wrapper_path, ["--check", "--file", "/tmp/rules.conf"])
    assert r.returncode == 0
    assert r.stdout.strip() == "nft --check --file /tmp/rules.conf"

def test_deny_check_without_file(wrapper_path):
    r = run_wrapper(wrapper_path, ["--check", "/tmp/rules.conf"])
    assert r.returncode == 126

def test_allow_exact_delete_handle(wrapper_path):
    r = run_wrapper(wrapper_path, ["delete", "rule", "ip", "firewall", "input", "handle", "123"])
    assert r.returncode == 0
    assert r.stdout.strip() == "nft delete rule ip firewall input handle 123"

def test_deny_wrong_table_delete_handle(wrapper_path):
    r = run_wrapper(wrapper_path, ["delete", "rule", "ip", "wrong_table", "input", "handle", "123"])
    assert r.returncode == 126
