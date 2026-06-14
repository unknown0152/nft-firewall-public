"""
src/integrations/threatfeed.py — Emerging Threats blocked IP feed ingestor.

Downloads the Emerging Threats compromised-IPs plaintext feed, diffs it
against the last-known state, and adds/removes entries from the nftables
blocked_ips set via core.state.block_ip / unblock_ip.

Public API
----------
    from integrations.threatfeed import sync, get_entry_count
    added, removed = sync()
    n = get_entry_count()
"""

import configparser
import ipaddress
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from utils.validation import validate_block_target

# ── Paths & constants ─────────────────────────────────────────────────────────

_STATE_FILE          = Path("/var/lib/nft-firewall/threatfeed-state.json")
_DEFAULT_URL         = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
_MAX_ENTRIES_DEFAULT = 5000


# ── Config helpers ────────────────────────────────────────────────────────────

def _find_config_path() -> "Path | None":
    """Search for firewall.ini in well-known locations.

    Returns the first path that exists, or ``None`` if none are found.
    """
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "config" / "firewall.ini",
        Path("/opt/nft-firewall/config/firewall.ini"),
        Path("/etc/nft-watchdog.conf"),
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def _load_config() -> "tuple[str, int, bool]":
    """Read the ``[threatfeed]`` section from firewall.ini.

    Returns
    -------
    tuple[str, int, bool]
        ``(url, max_entries, enabled)``.  Falls back to
        ``(_DEFAULT_URL, _MAX_ENTRIES_DEFAULT, True)`` if the section or
        individual keys are absent or the config file cannot be found.
    """
    url         = _DEFAULT_URL
    max_entries = _MAX_ENTRIES_DEFAULT
    enabled     = True

    config_path = _find_config_path()
    if config_path is None:
        return (url, max_entries, enabled)

    parser = configparser.ConfigParser()
    try:
        parser.read(str(config_path))
    except Exception:
        return (url, max_entries, enabled)

    if "threatfeed" not in parser:
        return (url, max_entries, enabled)

    section = parser["threatfeed"]
    url         = section.get("url", url)
    max_entries = int(section.get("max_entries", str(max_entries)))
    enabled     = section.getboolean("enabled", fallback=True)

    return (url, max_entries, enabled)


# ── State persistence ─────────────────────────────────────────────────────────

def _load_state() -> "set[str]":
    """Read the persisted IP set from ``_STATE_FILE``.

    Returns
    -------
    set[str]
        Set of IP strings from the last sync, or an empty set if the file
        does not exist or cannot be parsed.
    """
    if not _STATE_FILE.exists():
        return set()
    try:
        data = json.loads(_STATE_FILE.read_text())
        return set(data.get("ips", []))
    except Exception:
        return set()


def _save_state(ips: "set[str]") -> None:
    """Atomically persist *ips* to ``_STATE_FILE``.

    Writes to a ``.tmp`` sibling file, fsyncs, then replaces the target so
    that a crash mid-write never leaves a corrupt state file.

    Parameters
    ----------
    ips:
        Set of IP strings to persist.
    """
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    with tmp.open("w") as fh:
        json.dump({"ips": sorted(ips)}, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, _STATE_FILE)


# ── Feed fetching ─────────────────────────────────────────────────────────────

def _fetch_feed(url: str) -> "list[str]":
    """Download and parse the threat feed at *url*.

    Skips comment lines (starting with ``#``) and blank lines.  Validates
    each remaining line as an IPv4 address.

    Parameters
    ----------
    url:
        URL of the plaintext feed.

    Returns
    -------
    list[str]
        List of valid IPv4 address strings.  Returns ``[]`` on any network
        or parse error.
    """
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.URLError, OSError, Exception) as exc:
        print(f"[threatfeed] WARNING: feed fetch failed: {exc}")
        return []

    result = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            continue
        if isinstance(addr, ipaddress.IPv4Address):
            result.append(line)

    return result


# ── /8 guard ─────────────────────────────────────────────────────────────────

def _apply_block_guard(ip: str) -> bool:
    """Return ``True`` if *ip* is safe to insert into blocked_ips.

    This uses the shared block-target validator, including never_block defaults
    and the /8 maximum-size guard.

    Parameters
    ----------
    ip:
        IPv4 address or CIDR prefix to evaluate.

    Returns
    -------
    bool
        ``True`` if the prefix is /8 or more specific, ``False`` otherwise.
    """
    result = validate_block_target(ip)
    if result.ok:
        return True
    print(f"[threatfeed] WARNING: {result.reason}, skipping: {ip!r}")
    return False


# ── Public API ────────────────────────────────────────────────────────────────

def sync(
    url:         str = _DEFAULT_URL,
    max_entries: int = _MAX_ENTRIES_DEFAULT,
) -> "tuple[int, int]":
    """Download the threat feed and synchronise the ``blocked_ips`` nftables set.

    Diffs the freshly fetched feed against the last-known state and calls
    ``block_ip`` / ``unblock_ip`` only for the delta.  Persists the new state
    after the sync so the next call computes an accurate diff.

    Parameters
    ----------
    url:
        Feed URL.  Defaults to the Emerging Threats compromised-IPs list.
    max_entries:
        Maximum number of IPs to ingest from the feed (applied after
        fetching, before diffing).

    Returns
    -------
    tuple[int, int]
        ``(added, removed)`` counts of successfully processed entries.
    """
    from core.state import block_ip, unblock_ip  # lazy import — avoids nft at import time

    new_ips   = set(_fetch_feed(url)[:max_entries])
    old_ips   = _load_state()
    to_add    = new_ips - old_ips
    to_remove = old_ips - new_ips

    # Track only IPs we actually changed in nft. If we persist before
    # confirming, a failed block_ip silently shows up as "blocked" on the
    # next sync, the diff skips it, and the firewall drifts from the feed.
    added_ips: "set[str]" = set()
    for ip in to_add:
        if _apply_block_guard(ip) and block_ip(ip):
            added_ips.add(ip)

    removed_ips: "set[str]" = set()
    for ip in to_remove:
        if unblock_ip(ip):
            removed_ips.add(ip)

    _save_state((old_ips | added_ips) - removed_ips)
    print(f"[threatfeed] sync: +{len(added_ips)} added, -{len(removed_ips)} removed")
    return (len(added_ips), len(removed_ips))


def get_entry_count() -> int:
    """Return the number of IPs currently tracked in the threat feed state.

    Returns
    -------
    int
        Number of IPs in the last-saved state, or ``0`` on any error.
    """
    try:
        return len(_load_state())
    except Exception:
        return 0
