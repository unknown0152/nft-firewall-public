"""
src/daemons/ssh_alert.py — SSH intrusion alerter daemon.

Watches two log files in separate threads:

  1. fail2ban.log  — Ban / Unban events (exact, reliable).
  2. auth.log      — Successful logins and repeated brute-force failures
                     (throttled per source IP to one alert per 30 minutes).

Both threads use a logrotate-safe stateful tailer that persists (inode, byte
offset) between daemon restarts so no events are replayed on startup and no
events are silently skipped after a log rotation.

Geo-labels are fetched from ip-api.com on first encounter and cached for
CACHE_TTL seconds (thread-safe).

Active Defense — Auto-Block (two independent windows)
-------------------------------------------------------
Short window  — 3 hits in 5 minutes  → fast attack detected.
Long window   — 10 hits in 1 hour    → slow-roll patient attacker detected.
Either window triggers:
    python3 src/main.py block <IP>
and a 🚨 AUTO-BANNED Keybase alert naming which window fired.
Private IPs are never blocked.  Each IP is auto-blocked at most once per
daemon lifetime to avoid repeated block calls.

Alerter Persistence
-------------------
At startup, the daemon reads the live ``nft list set ip firewall blocked_ips``
and pre-populates its internal ``_auto_blocked`` set so that a daemon restart
never re-issues a block command for an IP the firewall already knows about.

Usage (systemd ExecStart)
-------------------------
    python3 src/main.py ssh-alert daemon
"""

from __future__ import annotations

import configparser
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

# ── Paths ─────────────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_LOCAL_CONF   = _PROJECT_ROOT / "config" / "firewall.ini"
_SYSTEM_CONF  = Path("/etc/nft-watchdog.conf")
_STATE_DIR    = _PROJECT_ROOT / "state"

# fw-admin sudoers only permits the fw-nft wrapper, not raw /usr/sbin/nft.
_FW_NFT_WRAPPER = Path("/usr/local/lib/nft-firewall/fw-nft")


def _sudo_nft_args(*args: str) -> List[str]:
    if _FW_NFT_WRAPPER.exists():
        return ["sudo", str(_FW_NFT_WRAPPER), *args]
    return ["sudo", "nft", *args]

# Log files to watch (standard Debian/Ubuntu paths)
FAIL2BAN_LOG  = Path("/var/log/fail2ban.log")
AUTH_LOG      = Path("/var/log/auth.log")

# State files that persist read positions across restarts
_BAN_STATE    = _STATE_DIR / "ssh-alert-ban.json"
_AUTH_STATE   = _STATE_DIR / "ssh-alert-auth.json"

# Geo cache TTL in seconds (24 h)
CACHE_TTL: int = 86_400

# Brute-force attempt throttle — one notification per IP per this many seconds
ATTEMPT_THROTTLE: int = 1_800   # 30 minutes

# Minimum failed attempts per IP to trigger a brute-force notification
ATTEMPT_THRESHOLD: int = 5

# Active Defense — short-window (fast attack)
AUTO_BLOCK_THRESHOLD: int = 3    # failures within the window to trigger a block
AUTO_BLOCK_WINDOW:    int = 300  # sliding window in seconds (5 minutes)

# Active Defense — long-window (slow-roll / patient attacker)
LONG_BLOCK_THRESHOLD: int = 10   # failures within the long window
LONG_BLOCK_WINDOW:    int = 3600 # 1 hour

# Resync interval — how often to rebuild _auto_blocked from live nftables.
# This clears IPs that were manually unblocked via !unblock so they can be
# auto-blocked again if they resume attacking.
RESYNC_INTERVAL: int = 300  # 5 minutes


# ── Module-level geo cache ────────────────────────────────────────────────────

_geo_cache:  Dict[str, Tuple[str, float]] = {}   # ip → (label, expires_at)
_geo_lock    = threading.Lock()


def _is_private_ip(ip: str) -> bool:
    """Return True if *ip* is an RFC-1918 / loopback address."""
    private_prefixes = ("10.", "127.", "169.254.")
    if any(ip.startswith(p) for p in private_prefixes):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def _geo_label(ip: str) -> str:
    """Return a human-readable geo string for *ip*, e.g. ``"Berlin, DE"``.

    Results are cached for :data:`CACHE_TTL` seconds.  Falls back to the
    raw IP string on any network or parse error.
    """
    if _is_private_ip(ip):
        return "🏠 Local Network"

    now = time.time()
    with _geo_lock:
        cached = _geo_cache.get(ip)
        if cached and cached[1] > now:
            return cached[0]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=city,country,countryCode,status"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            city    = data.get("city", "")
            country = data.get("countryCode", data.get("country", ""))
            label   = f"{city}, {country}" if city else country or ip
        else:
            label = ip
    except Exception:
        label = ip

    with _geo_lock:
        _geo_cache[ip] = (label, now + CACHE_TTL)
    return label


# ── Stateful log tailer ───────────────────────────────────────────────────────

def _load_state(state_file: Path) -> Tuple[Optional[int], int]:
    """Return ``(inode, offset)`` from *state_file*, or ``(None, 0)`` if absent."""
    try:
        with state_file.open() as f:
            d = json.load(f)
        return d.get("inode"), d.get("offset", 0)
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return None, 0


def _save_state(state_file: Path, inode: int, offset: int) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    with state_file.open("w") as f:
        json.dump({"inode": inode, "offset": offset}, f)


def _tail_stateful(log_path: Path, state_file: Path) -> Iterator[str]:
    """Logrotate-safe generator that yields new lines from *log_path*.

    On each call after a rotation (detected by inode change), reading resumes
    from byte 0 of the new file.  Progress is saved to *state_file* after every
    yielded line so a crash or restart loses at most one line.

    Blocks indefinitely; yields control to the caller between sleep cycles.
    """
    saved_inode, offset = _load_state(state_file)

    # First run — no prior state. Seek to EOF so we don't replay history.
    if saved_inode is None:
        try:
            _st_init   = log_path.stat()
            saved_inode = _st_init.st_ino   # must set BOTH so rotation check
            offset      = _st_init.st_size  # doesn't immediately reset offset
        except OSError:
            offset = 0

    while True:
        if not log_path.exists():
            time.sleep(2)
            continue

        try:
            st = log_path.stat()
        except OSError:
            time.sleep(2)
            continue

        current_inode = st.st_ino

        # Detect rotation: inode changed OR file is shorter than our offset
        if current_inode != saved_inode or st.st_size < offset:
            offset      = 0
            saved_inode = current_inode

        try:
            with log_path.open("rb") as fh:
                fh.seek(offset)
                while True:
                    raw = fh.readline()
                    if not raw:
                        break
                    offset = fh.tell()
                    _save_state(state_file, current_inode, offset)
                    try:
                        yield raw.decode("utf-8", errors="replace").rstrip("\n")
                    except GeneratorExit:
                        return
        except OSError:
            pass

        time.sleep(1)


# ── Daemon class ──────────────────────────────────────────────────────────────

class SshAlertDaemon:
    """SSH intrusion alerter — watches fail2ban.log and auth.log.

    Parameters
    ----------
    config_path:
        Path to the INI config file.  Defaults to the project-local config,
        falling back to the system-wide path.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config_path: str = config_path or (
            str(_LOCAL_CONF) if _LOCAL_CONF.exists() else str(_SYSTEM_CONF)
        )
        # per-IP attempt counters and throttle timestamps (brute-force alerting)
        self._attempt_counts:     Dict[str, int]         = {}
        self._attempt_last_sent:  Dict[str, float]       = {}
        # per-IP sliding-window timestamps — short (5 min) and long (1 hour)
        self._attempt_timestamps: Dict[str, List[float]] = {}
        self._long_timestamps:    Dict[str, List[float]] = {}
        # IPs already blocked this session — populated at startup from live nftables
        self._auto_blocked:       Set[str]               = set()
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def run_daemon(self) -> None:
        """Start the SSH alert daemon (systemd ExecStart entry point).

        Runs as fw-admin; privileged commands are executed via sudo.
        Starts two watcher threads then blocks on join.
        """
        _STATE_DIR.mkdir(parents=True, exist_ok=True)

        # Sync live blocked_ips from nftables so we don't re-block on restart
        self._sync_blocked_ips()

        print("[INFO] nft-ssh-alert started", flush=True)
        print(f"[INFO] Watching {FAIL2BAN_LOG} and {AUTH_LOG}", flush=True)

        threads = [
            threading.Thread(target=self._watch_bans,     daemon=True, name="ban-watcher"),
            threading.Thread(target=self._watch_attempts, daemon=True, name="auth-watcher"),
            threading.Thread(target=self._resync_loop,    daemon=True, name="ip-resync"),
        ]
        for t in threads:
            t.start()

        # Block until both threads die (they shouldn't unless there's an error)
        for t in threads:
            t.join()

    # ── Startup sync ─────────────────────────────────────────────────────────

    def _sync_blocked_ips(self) -> None:
        """Read the live nftables blocked_ips set into _auto_blocked.

        Prevents the daemon from re-issuing ``block <ip>`` commands after a
        restart for IPs the firewall already has in its set.
        """
        try:
            result = subprocess.run(
                _sudo_nft_args("list", "set", "ip", "firewall", "blocked_ips"),
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                print("[WARN] Could not read blocked_ips set — nft returned non-zero",
                      flush=True)
                return
            # Parse: elements = { 1.2.3.4, 5.6.7.8/32, ... }
            m = re.search(r"elements\s*=\s*\{([^}]+)\}", result.stdout, re.DOTALL)
            if m:
                raw   = m.group(1)
                addrs = [a.strip().rstrip(",") for a in raw.replace("\n", ",").split(",")]
                addrs = [a for a in addrs if a]
                with self._lock:
                    self._auto_blocked.update(addrs)
                print(f"[INFO] Synced {len(addrs)} blocked IP(s) from nftables: "
                      f"{', '.join(addrs)}", flush=True)
            else:
                print("[INFO] blocked_ips set is empty — nothing to sync", flush=True)
        except Exception as exc:
            print(f"[WARN] _sync_blocked_ips failed: {exc}", flush=True)

    def _resync_loop(self) -> None:
        """Periodically REPLACE _auto_blocked from the live nftables set.

        Unlike the startup sync (which only adds), this does a full replace so
        that IPs manually removed via ``!unblock`` are cleared from the in-memory
        guard and become eligible for auto-block again if they resume attacking.

        Runs every ``RESYNC_INTERVAL`` seconds as a daemon thread.
        """
        while True:
            time.sleep(RESYNC_INTERVAL)
            try:
                result = subprocess.run(
                    _sudo_nft_args("list", "set", "ip", "firewall", "blocked_ips"),
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    continue
                m = re.search(r"elements\s*=\s*\{([^}]+)\}", result.stdout, re.DOTALL)
                if m:
                    raw   = m.group(1)
                    addrs = {a.strip().rstrip(",")
                             for a in raw.replace("\n", ",").split(",")
                             if a.strip().rstrip(",")}
                else:
                    addrs = set()
                with self._lock:
                    removed = self._auto_blocked - addrs
                    self._auto_blocked = addrs
                if removed:
                    print(f"[INFO] Resync: cleared {len(removed)} manually-unblocked IP(s): "
                          f"{', '.join(removed)}", flush=True)
            except Exception as exc:
                print(f"[WARN] _resync_loop: {exc}", flush=True)

    # ── Ban watcher ───────────────────────────────────────────────────────────

    # fail2ban log line examples:
    #   2024-01-15 03:22:11,489 fail2ban.actions [123]: NOTICE  [sshd] Ban 1.2.3.4
    #   2024-01-15 03:22:11,489 fail2ban.actions [123]: NOTICE  [sshd] Unban 1.2.3.4
    _RE_BAN   = re.compile(r"\[(\w+)\]\s+Ban\s+([\d.:a-fA-F]+)")
    _RE_UNBAN = re.compile(r"\[(\w+)\]\s+Unban\s+([\d.:a-fA-F]+)")

    def _watch_bans(self) -> None:
        """Tail fail2ban.log and notify on every Ban / Unban event."""
        from utils.keybase import notify

        for line in _tail_stateful(FAIL2BAN_LOG, _BAN_STATE):
            try:
                m = self._RE_BAN.search(line)
                if m:
                    jail, ip = m.group(1), m.group(2)
                    geo      = _geo_label(ip)
                    notify(
                        title = "🚫 SSH Ban",
                        body  = (
                            f"━━━━━━━━━━━━━━━━━━━━\n"
                            f"    🌍  IP: `{ip}`\n"
                            f"    📍  Location: {geo}\n"
                            f"    🔒  Jail: {jail}"
                        ),
                        tags  = "no_entry",
                    )
                    print(f"[BAN] {jail} banned {ip} ({geo})", flush=True)
                    continue

                m = self._RE_UNBAN.search(line)
                if m:
                    jail, ip = m.group(1), m.group(2)
                    geo      = _geo_label(ip)
                    notify(
                        title = "🔓 SSH Unban",
                        body  = (
                            f"━━━━━━━━━━━━━━━━━━━━\n"
                            f"    🌍  IP: `{ip}`\n"
                            f"    📍  Location: {geo}\n"
                            f"    🔒  Jail: {jail}"
                        ),
                        tags  = "unlock",
                    )
                    print(f"[UNBAN] {jail} unbanned {ip} ({geo})", flush=True)
            except Exception as exc:
                print(f"[WARN] ban-watcher: {exc}", flush=True)

    # ── Auth watcher ──────────────────────────────────────────────────────────

    # auth.log line examples (OpenSSH):
    #   Jan 15 03:22:10 host sshd[1234]: Accepted publickey for alice from 1.2.3.4 port 51234 ...
    #   Jan 15 03:22:10 host sshd[1234]: Failed password for root from 1.2.3.4 port 51234 ...
    #   Jan 15 03:22:10 host sshd[1234]: Failed password for invalid user foo from 1.2.3.4 ...
    _RE_ACCEPT = re.compile(
        r"sshd\[\d+\]: Accepted \S+ for (\S+) from ([\d.:a-fA-F]+)"
    )
    _RE_FAIL   = re.compile(
        r"sshd\[\d+\]: Failed \S+ for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+)"
    )

    def _watch_attempts(self) -> None:
        """Tail auth.log and notify on successful logins and brute-force bursts."""
        from utils.keybase import notify

        for line in _tail_stateful(AUTH_LOG, _AUTH_STATE):
            try:
                # ── Successful login ─────────────────────────────────────────
                m = self._RE_ACCEPT.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    geo      = _geo_label(ip)
                    ts       = time.strftime("%Y-%m-%d %H:%M")
                    notify(
                        title = f"🔑 SSH Login — {user}",
                        body  = (
                            f"👤  User: *{user}*\n"
                            f"🌍  From: `{ip}`\n"
                            f"📍  Location: {geo}\n"
                            f"⏰  _{ts}_"
                        ),
                        tags  = "white_check_mark",
                    )
                    print(f"[LOGIN] {user} from {ip} ({geo})", flush=True)
                    # Reset all failure state on successful auth from this IP
                    with self._lock:
                        self._attempt_counts.pop(ip, None)
                        self._attempt_timestamps.pop(ip, None)
                        self._long_timestamps.pop(ip, None)
                    continue

                # ── Failed login ─────────────────────────────────────────────
                m = self._RE_FAIL.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    now      = time.time()
                    with self._lock:
                        # Brute-force alert (existing throttled logic)
                        self._attempt_counts[ip] = self._attempt_counts.get(ip, 0) + 1
                        count     = self._attempt_counts[ip]
                        last_sent = self._attempt_last_sent.get(ip, 0)

                        # Active Defense — short window (5 min) and long window (1 hour)
                        stamps = self._attempt_timestamps.get(ip, [])
                        stamps.append(now)
                        stamps = [t for t in stamps if now - t <= AUTO_BLOCK_WINDOW]
                        self._attempt_timestamps[ip] = stamps
                        window_count = len(stamps)

                        long_stamps = self._long_timestamps.get(ip, [])
                        long_stamps.append(now)
                        long_stamps = [t for t in long_stamps if now - t <= LONG_BLOCK_WINDOW]
                        self._long_timestamps[ip] = long_stamps
                        long_count = len(long_stamps)

                        already_blocked = ip in self._auto_blocked

                    if (count >= ATTEMPT_THRESHOLD
                            and now - last_sent >= ATTEMPT_THROTTLE):
                        geo = _geo_label(ip)
                        with self._lock:
                            self._attempt_last_sent[ip] = now
                            self._attempt_counts[ip]    = 0
                        notify(
                            title = "⚠️ SSH Brute-force",
                            body  = (
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"    🌍  IP: `{ip}`\n"
                                f"    📍  Location: {geo}\n"
                                f"    🔢  Attempts: {count}\n"
                                f"    👤  Latest user: *{user}*"
                            ),
                            tags  = "warning",
                        )
                        print(f"[BRUTE] {count} failures from {ip} ({geo})", flush=True)

                    # Short-window auto-block (fast attack: 3 in 5 min)
                    if (window_count >= AUTO_BLOCK_THRESHOLD
                            and not already_blocked
                            and not _is_private_ip(ip)):
                        self._auto_block(ip, window_count, user, "5-min")

                    # Long-window auto-block (slow-roll: 10 in 1 hour)
                    elif (long_count >= LONG_BLOCK_THRESHOLD
                            and not already_blocked
                            and not _is_private_ip(ip)):
                        self._auto_block(ip, long_count, user, "1-hour")

            except Exception as exc:
                print(f"[WARN] auth-watcher: {exc}", flush=True)

    # ── Active Defense ────────────────────────────────────────────────────────

    def _auto_block(self, ip: str, count: int, last_user: str,
                    window_label: str = "5-min") -> None:
        """Execute ``block <ip>`` via main.py and send a 🚨 AUTO-BANNED alert.

        Parameters
        ----------
        window_label:
            Human-readable trigger window, e.g. ``"5-min"`` or ``"1-hour"``.
            Included in the Keybase alert so the operator knows which defence
            threshold fired.
        """
        from utils.keybase import notify

        geo     = _geo_label(ip)
        fw = Path("/usr/local/bin/fw")
        if fw.exists():
            cmd = ["sudo", str(fw), "block", ip]
        else:
            main_py = str(_PROJECT_ROOT / "src" / "main.py")
            cmd = ["sudo", sys.executable, main_py, "block", ip]

        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=10,
        )
        blocked_ok = result.returncode == 0

        with self._lock:
            if blocked_ok:
                self._auto_blocked.add(ip)
                self._attempt_timestamps.pop(ip, None)
                self._long_timestamps.pop(ip, None)

        ts      = time.strftime("%Y-%m-%d %H:%M")
        status  = "Blocked ✅" if blocked_ok else "⚠️ block cmd failed"
        trigger = f"{count} attempts in {window_label}"

        notify(
            title = "🚨 AUTO-BANNED",
            body  = (
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"    🌍  IP: `{ip}`\n"
                f"    📍  Location: {geo}\n"
                f"    🔢  Trigger: {trigger}\n"
                f"    👤  Last user: *{last_user}*\n"
                f"    🔒  Status: {status}\n"
                f"    ⏰  _{ts}_"
            ),
            tags  = "rotating_light",
        )

        if blocked_ok:
            print(f"[AUTO-BLOCK] {ip} blocked — {trigger} ({geo})", flush=True)
            if window_label == "1-hour":
                try:
                    from utils.analytics import log_persistent_ip
                    log_persistent_ip(ip, count, last_user, geo)
                except Exception as exc:
                    print(f"[WARN] log_persistent_ip failed: {exc}", flush=True)
        else:
            print(f"[AUTO-BLOCK] FAILED to block {ip}: {result.stderr.strip()}", flush=True)
