#!/usr/bin/env bash
set -euo pipefail

RULESET="${1:-}"

if [ -z "$RULESET" ]; then
  echo "Usage: $0 /path/to/ruleset.nft" >&2
  exit 2
fi

if [ ! -f "$RULESET" ]; then
  echo "FAIL: ruleset not found: $RULESET" >&2
  exit 1
fi

sudo nft --check -f "$RULESET"
echo "OK: nft ruleset syntax is valid: $RULESET"
