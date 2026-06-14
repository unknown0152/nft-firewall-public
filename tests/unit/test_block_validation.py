import sys
import types
import pytest

sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent.parent / 'src'))


def _make_args(ip):
    return types.SimpleNamespace(ip=ip)


def test_block_accepts_public_slash_8(monkeypatch):
    """Test that a public /8 (largest allowed) is accepted."""
    import core.state
    monkeypatch.setattr(core.state, 'block_ip', lambda ip, **_kw: True)
    from main import _cmd_block
    _cmd_block(_make_args('11.0.0.0/8'))   # should not raise


def test_block_rejects_private_never_block_range():
    """Test that default never_block private ranges are rejected."""
    from main import _cmd_block
    with pytest.raises(SystemExit):
        _cmd_block(_make_args('10.0.0.0/8'))


def test_block_rejects_slash_7():
    """Test that /7 (larger than /8) is rejected."""
    from main import _cmd_block
    with pytest.raises(SystemExit):
        _cmd_block(_make_args('10.0.0.0/7'))


def test_block_rejects_default_route():
    """Test that 0.0.0.0/0 (entire IPv4 space) is rejected."""
    from main import _cmd_block
    with pytest.raises(SystemExit):
        _cmd_block(_make_args('0.0.0.0/0'))


def test_block_rejects_invalid_string():
    """Test that invalid IP string is rejected."""
    from main import _cmd_block
    with pytest.raises(SystemExit):
        _cmd_block(_make_args('not-an-ip'))


def test_block_rejects_ipv6_network_oversized():
    """Test that oversized IPv6 network is rejected."""
    from main import _cmd_block
    with pytest.raises(SystemExit):
        _cmd_block(_make_args('2001:db8::/16'))
