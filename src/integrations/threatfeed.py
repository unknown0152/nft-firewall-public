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
import fcntl
import grp
import importlib
import ipaddress
import json
import math
import os
import stat
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
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

@contextmanager
def _file_lock(lock_file: Path, *, exclusive: bool):
    """Hold a symlink-safe advisory lock at *lock_file*."""
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        lock_file,
        os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o660,
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError(f"Unsafe threat-feed lock file: {lock_file}")
        try:
            os.fchown(fd, -1, grp.getgrnam("fw-admin").gr_gid)
            os.fchmod(fd, 0o660)
        except (KeyError, PermissionError, OSError):
            pass
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextmanager
def _state_lock(*, exclusive: bool):
    """Serialize short reads and atomic replacements of persisted state."""
    lock_file = _STATE_FILE.with_name(_STATE_FILE.name + ".lock")
    with _file_lock(lock_file, exclusive=exclusive):
        yield


@contextmanager
def _reconciliation_lock():
    """Prevent overlapping feed syncs without blocking watchdog state readers."""
    lock_file = _STATE_FILE.with_name(_STATE_FILE.name + ".reconcile.lock")
    with _file_lock(lock_file, exclusive=True):
        yield


def _load_state_unlocked() -> "set[str]":
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


def _load_state() -> "set[str]":
    """Read threat-feed state while excluding concurrent replacement."""
    with _state_lock(exclusive=False):
        return _load_state_unlocked()


def _save_state_unlocked(ips: "set[str]") -> None:
    """Atomically persist *ips* to ``_STATE_FILE``.

    Writes to a ``.tmp`` sibling file, fsyncs, then replaces the target so
    that a crash mid-write never leaves a corrupt state file.

    Parameters
    ----------
    ips:
        Set of IP strings to persist.
    """
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp: "Path | None" = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=_STATE_FILE.parent,
            prefix=_STATE_FILE.name + ".",
            suffix=".tmp",
            delete=False,
        ) as fh:
            tmp = Path(fh.name)
            json.dump({"ips": sorted(ips)}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.chmod(0o640)
        try:
            os.chown(tmp, -1, grp.getgrnam("fw-admin").gr_gid)
        except (KeyError, PermissionError, OSError):
            pass
        os.replace(tmp, _STATE_FILE)
    finally:
        if tmp and tmp.exists():
            tmp.unlink(missing_ok=True)


def _save_state(ips: "set[str]") -> None:
    """Persist threat-feed state under the same lock used by reconciliation."""
    with _state_lock(exclusive=True):
        _save_state_unlocked(ips)


# ── Feed fetching ─────────────────────────────────────────────────────────────

def _fetch_feed(url: str) -> "list[str] | None":
    """Download and parse the threat feed at *url*.

    Skips comment lines (starting with ``#``) and blank lines.  Validates
    each remaining line as an IPv4 address.

    Parameters
    ----------
    url:
        URL of the plaintext feed.

    Returns
    -------
    list[str] | None
        List of valid IPv4 address strings.  Returns ``None`` when the feed
        could not be fetched; an empty list means the fetch succeeded but did
        not contain any valid entries.
    """
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.URLError, OSError, Exception) as exc:
        print(f"[threatfeed] WARNING: feed fetch failed: {exc}")
        return None

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


def _load_live_block_networks() -> "tuple[ipaddress.IPv4Network, ...]":
    """Return live blocks as networks for interval-overlap detection.

    The shared ``blocked_ips`` set can already contain a broader GeoIP or
    operator-managed prefix.  nftables then rejects a feed-owned /32 because
    interval-set elements may not overlap.  Only the kernel's live set proves
    that the address is already enforced; persistent state may be stale.
    """
    try:
        firewall_state = importlib.import_module("core.state")
        values = firewall_state.set_list(
            firewall_state.SET_BLOCKED,
            persistent_fallback=False,
        )
    except Exception:
        # Without live coverage evidence, use the normal mutation path.  Its
        # failure remains visible as a nonzero feed sync.
        return ()

    networks: list[ipaddress.IPv4Network] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            networks.append(network)
    return tuple(networks)


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

    if max_entries <= 0:
        raise ValueError("max_entries must be positive")

    with _reconciliation_lock():
        fetched = _fetch_feed(url)
        if fetched is None:
            raise RuntimeError("threat feed fetch failed; refusing to change firewall state")
        if not fetched:
            raise RuntimeError("threat feed was empty; refusing to remove existing blocks")

        fetched_ips = set(fetched)
        new_ips = set(fetched[:max_entries])
        with _state_lock(exclusive=False):
            old_ips = _load_state_unlocked()
        minimum_plausible = math.ceil(len(old_ips) * 0.75)
        if old_ips and len(fetched_ips) < minimum_plausible:
            raise RuntimeError(
                "threat feed is implausibly truncated; refusing bulk removal "
                f"({len(old_ips)} old entries, {len(fetched_ips)} fetched entries)"
            )
        to_add = new_ips - old_ips
        to_remove = old_ips - new_ips
        existing_blocks = _load_live_block_networks()

        # Track only IPs actually changed in nft so failed mutations are retried.
        added_ips: "set[str]" = set()
        covered_ips: "set[str]" = set()
        for ip in to_add:
            if not _apply_block_guard(ip):
                continue
            address = ipaddress.ip_address(ip)
            if any(address in network for network in existing_blocks):
                covered_ips.add(ip)
                continue
            if block_ip(ip):
                added_ips.add(ip)

        removed_ips: "set[str]" = set()
        for ip in to_remove:
            if unblock_ip(ip):
                removed_ips.add(ip)

        with _state_lock(exclusive=True):
            _save_state_unlocked((old_ips | added_ips) - removed_ips)
    print(
        f"[threatfeed] sync: +{len(added_ips)} added, "
        f"{len(covered_ips)} already covered, -{len(removed_ips)} removed"
    )
    failed = (
        len(to_add) - len(added_ips) - len(covered_ips)
    ) + (len(to_remove) - len(removed_ips))
    if failed:
        noun = "mutation" if failed == 1 else "mutations"
        raise RuntimeError(f"threat feed sync incomplete: {failed} {noun} failed")
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
