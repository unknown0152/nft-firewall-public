"""
tests/unit/test_fw_wrapper.py — Static analysis of scripts/fw wrapper allowlist.

Parses the case statement in the fw bash script and asserts:
- Security-sensitive commands (apply, docker-expose, etc.) are NOT passthrough
- Core ChatOps and operator commands ARE passthrough
- apply is explicitly redirected with an error message (not silently dropped)

No subprocess execution — purely file-based static checks.
"""
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_FW_SCRIPT = _REPO_ROOT / "scripts" / "fw"


def _parse_fw_allowlist() -> set[str]:
    """Return the set of commands that fall through to exec in scripts/fw."""
    text = _FW_SCRIPT.read_text()
    # Find the passthrough case branch — the one ending with exec "$PYTHON_BIN" ...
    # Pattern: lines between the first `case "$cmd" in` and the `apply)` arm
    m = re.search(r'case "\$cmd" in\s+(.*?)\)', text, re.DOTALL)
    if not m:
        return set()
    passthrough_line = m.group(1).strip()
    # Split the pipe-separated command names
    commands = set()
    for token in re.split(r'[|\s]+', passthrough_line):
        token = token.strip()
        if token and not token.startswith('"') and not token.startswith('$'):
            commands.add(token)
    return commands


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def fw_allowlist() -> set[str]:
    if not _FW_SCRIPT.exists():
        pytest.skip(f"fw wrapper not found at {_FW_SCRIPT}")
    return _parse_fw_allowlist()


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestFwWrapperAllowlist:

    MUST_BE_ALLOWED = {
        "block", "unblock", "allow", "disallow",
        "ip-list", "status", "health", "rules",
        "doctor", "simulate", "safe-apply", "profiles",
    }

    MUST_NOT_BE_ALLOWED = {
        "apply",            # explicitly redirected to safe-apply
        "docker-expose",    # admin-only
        "docker-unexpose",  # admin-only
    }

    def test_core_commands_in_allowlist(self, fw_allowlist):
        missing = self.MUST_BE_ALLOWED - fw_allowlist
        assert not missing, f"Commands missing from fw allowlist: {missing}"

    def test_dangerous_commands_not_in_allowlist(self, fw_allowlist):
        present = self.MUST_NOT_BE_ALLOWED & fw_allowlist
        assert not present, f"Dangerous commands in fw passthrough allowlist: {present}"

    def test_apply_is_explicitly_handled(self, fw_allowlist):
        """apply must NOT be in the passthrough arm — it must redirect."""
        assert "apply" not in fw_allowlist, (
            "'apply' must not be in the passthrough arm of scripts/fw — "
            "it should redirect with an error message"
        )

    def test_apply_produces_error_message(self):
        """The apply arm must echo a user-visible error to stderr."""
        text = _FW_SCRIPT.read_text()
        # Locate the apply) arm and confirm it echoes something
        m = re.search(r'apply\)\s*(.*?);;', text, re.DOTALL)
        assert m, "apply) arm not found in scripts/fw"
        arm_body = m.group(1)
        assert "echo" in arm_body or "printf" in arm_body, (
            "apply) arm should echo an error message directing users to safe-apply"
        )

    def test_script_is_executable_text(self):
        text = _FW_SCRIPT.read_text()
        assert text.startswith("#!/"), "scripts/fw must start with a shebang"
        assert "case" in text, "scripts/fw must contain a case statement"

    def test_allowlist_not_empty(self, fw_allowlist):
        assert len(fw_allowlist) >= 5, "fw allowlist suspiciously short"
