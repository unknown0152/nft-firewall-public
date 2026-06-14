"""
src/utils/analytics.py — Firewall analytics, GeoIP leaderboard, and packet counters.

Provides the data layer for the '!top' Wall of Shame command and the killswitch
stats section of the daily dashboard.

Public API
----------
    from utils.analytics import (
        country_flag,
        country_leaderboard,
        read_blocked_ips,
        read_persistent_ips,
        log_persistent_ip,
        total_drop_packets,
        chain_drop_counter,
        weekly_ban_counts,
        build_top_report,
    )

GeoIP
-----
IPs are resolved in batch via ip-api.com (up to 100 per HTTP call).
Results are cached in a module-level dict for CACHE_TTL seconds (24 h) so a
single ``!top`` call does not hammer the API even with a large block list.

Packet Counters
---------------
Reads the ``counter packets N`` statement that rules.py now emits on every
log/drop line in the input, output, and forward chains.  Requires the V11.0
ruleset to be applied — older rulesets without the ``counter`` keyword will
return 0.

Persistent Attackers
--------------------
When ssh_alert auto-blocks an IP via the 1-hour slow-roll window it calls
``log_persistent_ip()``, which upserts the entry in
``state/persistent_ips.json``.  ``read_persistent_ips()`` returns those
records sorted by hit count so the leaderboard is always current.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

# ── Paths ──────────────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_STATE_DIR    = _PROJECT_ROOT / "state"
_PERSISTENT_F = _STATE_DIR / "persistent_ips.json"


def _sudo_nft_args(*args: str) -> List[str]:
    wrapper = Path("/usr/local/lib/nft-firewall/fw-nft")
    if wrapper.exists():
        return ["sudo", str(wrapper), *args]
    return ["sudo", "nft", *args]

# ── Geo cache ──────────────────────────────────────────────────────────────────

_geo_cache: Dict[str, Tuple[Dict, float]] = {}   # ip → (data, expires_at)
_geo_lock   = threading.Lock()
CACHE_TTL   = 86_400   # 24 h


# ── GeoIP helpers ─────────────────────────────────────────────────────────────

def country_flag(cc: str) -> str:
    """Convert an ISO 3166-1 alpha-2 country code to its flag emoji.

    Examples: ``"CN"`` → ``"🇨🇳"``, ``"DE"`` → ``"🇩🇪"``.
    Returns ``"🏴"`` for unknown or invalid codes.
    """
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🏴"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def _geo_batch(ips: List[str]) -> Dict[str, Dict]:
    """Batch geo-resolve *ips* via ip-api.com (max 100 per request, cached).

    Returns a dict mapping each IP to its ip-api response object.
    IPs that could not be resolved are absent from the returned dict.
    """
    now      = time.time()
    results: Dict[str, Dict] = {}
    to_fetch: List[str]      = []

    with _geo_lock:
        for ip in ips:
            entry = _geo_cache.get(ip)
            if entry and entry[1] > now:
                results[ip] = entry[0]
            else:
                to_fetch.append(ip)

    if not to_fetch:
        return results

    fields = "query,country,countryCode,city,status"
    for i in range(0, len(to_fetch), 100):
        chunk   = to_fetch[i : i + 100]
        payload = json.dumps(
            [{"query": ip, "fields": fields} for ip in chunk]
        ).encode()
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data    = payload,
                headers = {"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                items = json.loads(resp.read())
            with _geo_lock:
                for item in items:
                    if item.get("status") == "success":
                        _geo_cache[item["query"]] = (item, now + CACHE_TTL)
                        results[item["query"]]    = item
        except Exception:
            pass   # network failure — skip, return partial results

    return results


# ── Block list helpers ─────────────────────────────────────────────────────────

def read_blocked_ips() -> List[str]:
    """Return all IP/CIDR entries currently in the nftables blocked_ips set."""
    try:
        r = subprocess.run(
            _sudo_nft_args("list", "set", "ip", "firewall", "blocked_ips"),
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return []
        m = re.search(r"elements\s*=\s*\{([^}]+)\}", r.stdout, re.DOTALL)
        if not m:
            return []
        raw  = m.group(1)
        ips  = [a.strip().rstrip(",") for a in raw.replace("\n", ",").split(",")]
        return [ip for ip in ips if ip]
    except Exception:
        return []


def country_leaderboard(top_n: int = 5) -> List[Tuple[int, str, str]]:
    """Return the top *top_n* attacking countries from the current block list.

    Returns a list of ``(count, display_label, country_code)`` tuples,
    sorted descending by hit count.  ``display_label`` includes the flag emoji,
    e.g. ``"🇨🇳 China"``.
    """
    ips = read_blocked_ips()
    if not ips:
        return []

    # Strip CIDR suffix for lookup, keep original for display
    lookup_ips = [ip.split("/")[0] for ip in ips]
    geo        = _geo_batch(lookup_ips)

    counts: Dict[str, int] = {}
    labels: Dict[str, str] = {}
    for ip in lookup_ips:
        info          = geo.get(ip, {})
        cc            = info.get("countryCode", "??")
        counts[cc]    = counts.get(cc, 0) + 1
        labels[cc]    = info.get("country", "Unknown")

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    return [
        (count, f"{country_flag(cc)} {labels.get(cc, cc)}", cc)
        for cc, count in ranked
    ]


def top_country_label() -> str:
    """Return a compact label for the single top attacking country, e.g. ``'🇨🇳 CN (8)'``.

    Returns ``'—'`` if the block list is empty.
    """
    leaders = country_leaderboard(1)
    if not leaders:
        return "—"
    count, label, cc = leaders[0]
    short = label.split()[-1] if " " in label else label   # flag + code
    return f"{short} ({count})"


# ── Persistent attacker log ───────────────────────────────────────────────────

def read_persistent_ips() -> List[Dict]:
    """Return all entries from ``state/persistent_ips.json``, newest first."""
    try:
        if not _PERSISTENT_F.exists():
            return []
        entries = json.loads(_PERSISTENT_F.read_text())
        return sorted(entries, key=lambda e: e.get("count", 0), reverse=True)
    except Exception:
        return []


def log_persistent_ip(ip: str, count: int, last_user: str, geo: str) -> None:
    """Upsert *ip* in ``state/persistent_ips.json``.

    Called by ``ssh_alert._auto_block()`` when the 1-hour slow-roll window fires.
    Thread-safe via file read/write (daemon is single-threaded per call here).
    """
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    entries = read_persistent_ips()

    for entry in entries:
        if entry.get("ip") == ip:
            entry.update({
                "count"    : count,
                "last_user": last_user,
                "geo"      : geo,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            })
            break
    else:
        entries.append({
            "ip"       : ip,
            "count"    : count,
            "last_user": last_user,
            "geo"      : geo,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "window"   : "1-hour",
        })

    try:
        _PERSISTENT_F.write_text(json.dumps(entries, indent=2) + "\n")
    except Exception:
        pass


# ── Packet counters ───────────────────────────────────────────────────────────

def chain_drop_counter(chain: str) -> int:
    """Return the ``counter packets N`` value from the log/drop rule in *chain*.

    Requires the V11.0 ruleset (rules.py adds ``counter`` to the log lines).
    Returns 0 if the counter is absent or the chain cannot be read.
    """
    try:
        r = subprocess.run(
            _sudo_nft_args("list", "chain", "ip", "firewall", chain),
            capture_output=True, text=True, timeout=5,
        )
        # The log/drop rule is always the last non-empty rule;
        # its counter appears as: counter packets N bytes M
        m = re.search(r"counter packets (\d+)", r.stdout)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


def total_drop_packets() -> int:
    """Return total DROP packet count across input + output + forward chains.
    
    Uses a single nft call to list the entire table for better performance.
    """
    try:
        r = subprocess.run(
            _sudo_nft_args("list", "table", "ip", "firewall"),
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return 0
        # Sum all 'counter packets N' occurrences in the entire table
        counts = re.findall(r"counter packets (\d+)", r.stdout)
        return sum(int(n) for n in counts)
    except Exception:
        return 0


# ── Weekly ban summary ────────────────────────────────────────────────────────

def weekly_ban_counts() -> Tuple[int, int]:
    """Return ``(this_week, last_week)`` auto-block counts from the ssh-alert journal.

    Counts ``[AUTO-BLOCK]`` lines emitted by the daemon so only actual blocks
    are counted (not just brute-force alerts).
    """
    def _count(since: str, until: str) -> int:
        try:
            r = subprocess.run(
                ["journalctl", "-u", "nft-ssh-alert",
                 "--since", since, "--until", until,
                 "--no-pager", "-q"],
                capture_output=True, text=True, timeout=15,
            )
            return r.stdout.count("[AUTO-BLOCK]")
        except Exception:
            return 0

    now       = datetime.now()
    week_ago  = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    two_weeks = (now - timedelta(days=14)).strftime("%Y-%m-%d")
    today     = now.strftime("%Y-%m-%d 23:59:59")
    return (
        _count(week_ago,  today),
        _count(two_weeks, week_ago),
    )


# ── !top report builder ───────────────────────────────────────────────────────

def build_top_report() -> str:
    """Build the full '!top' Wall of Shame report string for Keybase."""
    lines = [
        "🏆 *Wall of Shame*",
        "━━━━━━━━━━━━━━━━━━━━",
    ]

    # ── Country leaderboard ───────────────────────────────────────────────────
    blocked = read_blocked_ips()
    lines.append(f"\n🚩 *Top Attacking Countries*  _{len(blocked)} IP(s) in block list_")
    leaders = country_leaderboard(5)
    if leaders:
        for i, (count, label, _) in enumerate(leaders, 1):
            noun = "IP" if count == 1 else "IPs"
            lines.append(f"    {i}.  {label} — {count} {noun}")
    else:
        lines.append("    _(block list is empty)_")

    # ── Persistent attackers ──────────────────────────────────────────────────
    lines.append("\n🕐 *Most Persistent Attackers*  _(slow-roll: 10+ hits in 1h)_")
    persistent = read_persistent_ips()[:3]
    if persistent:
        for i, e in enumerate(persistent, 1):
            lines.append(
                f"    {i}.  `{e['ip']}`  {e.get('geo', '—')}"
                f"  — *{e['count']} hits*  _{e.get('timestamp', '')}_"
            )
    else:
        lines.append("    _(no slow-roll attacks recorded yet)_")

    # ── Drop counters ─────────────────────────────────────────────────────────
    total = total_drop_packets()
    lines.append("\n🛑 *Killswitch Packets Denied*")
    if total:
        lines.append(f"    Total: `{total:,}` packets")
        for chain in ("input", "output", "forward"):
            n = chain_drop_counter(chain)
            if n:
                lines.append(f"    {chain.capitalize()}: {n:,}")
    else:
        lines.append("    _(counters not yet active — re-apply ruleset)_")

    # ── Weekly snapshot ───────────────────────────────────────────────────────
    this_week, last_week = weekly_ban_counts()
    trend = "📈" if this_week > last_week else ("📉" if this_week < last_week else "➡️")
    lines.append(f"\n📊 *Weekly Auto-Blocks*  {trend}")
    lines.append(f"    This week:  *{this_week}*")
    lines.append(f"    Last week:  {last_week}")

    return "\n".join(lines)
