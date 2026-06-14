"""Shared validation helpers for firewall inputs.

All helpers are side-effect-free.  They centralise IP/CIDR and port checks so
CLI, ChatOps, threat feeds, Docker exposure, and live set mutation enforce the
same safety rules.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

MAX_BLOCK_ADDRESSES = 2 ** 24  # /8 worth of IPv4 addresses

DEFAULT_NEVER_BLOCK: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
)


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    value: str = ""
    reason: str = ""


def _networks(items: Iterable[str]) -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for item in items:
        raw = str(item).strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            nets.append(net)
    return nets


def parse_never_block(raw: str | Sequence[str] | None) -> list[str]:
    """Parse comma/space/newline-separated never-block networks."""
    if raw is None:
        return []
    chunks = raw.replace(",", " ").split() if isinstance(raw, str) else [str(x) for x in raw]
    return [str(ipaddress.ip_network(x.strip(), strict=False)) for x in chunks if x.strip()]


def validate_port(port: int | str, label: str = "port") -> int:
    """Return *port* as an int, or raise ValueError if outside 1..65535."""
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be an integer, got {port!r}") from exc
    if not 1 <= value <= 65535:
        raise ValueError(f"{label} must be 1-65535, got {value}")
    return value


def validate_ipv4_network(value: str, *, allow_network: bool = True) -> ValidationResult:
    """Validate an IPv4 address or CIDR and return its canonical form."""
    raw = str(value).strip()
    if not raw:
        return ValidationResult(False, reason="empty IP/CIDR")
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return ValidationResult(False, reason=f"invalid IP/CIDR: {raw!r}")
    if not isinstance(net, ipaddress.IPv4Network):
        return ValidationResult(False, reason=f"IPv6 is not supported here: {raw!r}")
    if net.prefixlen == 0:
        return ValidationResult(False, reason="refusing /0 — would block or trust entire internet")
    if not allow_network and net.prefixlen != 32:
        return ValidationResult(False, reason=f"CIDR network not allowed: {raw!r}")
    return ValidationResult(True, str(net if "/" in raw or net.prefixlen != 32 else net.network_address))


def validate_block_target(
    value: str,
    *,
    never_block: Iterable[str] = (),
    max_addresses: int = MAX_BLOCK_ADDRESSES,
) -> ValidationResult:
    """Validate an IP/CIDR that would be inserted into blocked_ips."""
    result = validate_ipv4_network(value)
    if not result.ok:
        return result

    net = ipaddress.ip_network(result.value, strict=False)
    if net.num_addresses > max_addresses:
        return ValidationResult(
            False,
            reason=(
                f"refusing to block {value} - prefix covers "
                f"{net.num_addresses:,} addresses; use /8 or more specific"
            ),
        )

    protected = _networks(DEFAULT_NEVER_BLOCK) + _networks(never_block)
    for guard in protected:
        if net.subnet_of(guard) or guard.subnet_of(net) or net.overlaps(guard):
            return ValidationResult(False, reason=f"refusing to block never_block range {guard}")

    return ValidationResult(True, str(net))


def get_connection_info() -> tuple[str, str]:
    """Detect the current connecting IP and its country code using multiple APIs.
    
    Returns (ip, cc) or ("", "") on failure.
    """
    import urllib.request, json
    
    # Try multiple public APIs for redundancy
    apis = [
        "https://ipapi.co/json/",
        "https://ifconfig.co/json",
        "https://ip-api.com/json/"
    ]
    
    for url in apis:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                ip = data.get("ip") or data.get("query") or ""
                cc = data.get("country_code") or data.get("country") or ""
                if ip and cc:
                    return ip, cc.upper()
        except Exception:
            continue
    return "", ""


def validate_trusted_target(value: str) -> ValidationResult:
    """Validate an IP/CIDR that would be inserted into trusted_ips."""
    result = validate_ipv4_network(value)
    if not result.ok:
        return result
    net = ipaddress.ip_network(result.value, strict=False)
    for guard in _networks(DEFAULT_NEVER_BLOCK):
        if net.overlaps(guard):
            return ValidationResult(False, reason=f"trusted IP must be public routable, overlaps {guard}")
    return ValidationResult(True, str(net))
