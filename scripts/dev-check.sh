#!/usr/bin/env bash
set -euo pipefail

echo "== Ruff check =="
if [[ -f .venv/bin/activate ]]; then
  # shellcheck source=/dev/null
  . .venv/bin/activate
fi

if command -v ruff >/dev/null 2>&1; then
  ruff check .
else
  echo "ruff not found; skipping. Install with: python3 -m pip install '.[dev]'"
fi

echo "== ShellCheck =="
if command -v shellcheck >/dev/null 2>&1; then
  find . -type f \( -name "*.sh" -o -path "./scripts/*" \) -print0 \
    | xargs -0 -r shellcheck
else
  echo "shellcheck not found; skipping."
fi

echo "== Pytest =="
if command -v pytest >/dev/null 2>&1; then
  pytest -q
else
  python3 -m pytest -q
fi

echo "OK: all dev checks passed."
