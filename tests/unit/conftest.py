"""Shared pytest fixtures for the NFT Firewall V12 unit test suite."""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def tmp_state_dir(tmp_path: Path) -> Path:
    """Return a temporary state directory that already exists."""
    d = tmp_path / "state"
    d.mkdir()
    return d


@pytest.fixture()
def mock_subprocess_ok(monkeypatch):
    """Patch subprocess.run globally to return rc=0, empty stdout/stderr."""
    mock = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(subprocess, "run", mock)
    return mock
