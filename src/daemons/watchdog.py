"""
src/daemons/watchdog.py — NFT Watchdog Daemon.

Monitors WireGuard VPN health and auto-recovers with 4 escalating levels.
Sends Keybase chat notifications on all state changes via utils.keybase.

Recovery levels
---------------
1. Soft restart       — wg-quick down/up
2. Hard restart       — ip link delete + wg-quick up
3. DNS re-resolve     — resolve endpoint hostname fresh, update peer, restart
4. Full recreation    — systemctl stop/start wg-quick@<iface>

Usage (systemd ExecStart)
-------------------------
    python3 -m daemons.watchdog daemon

Usage (one-shot status / health)
---------------------------------
    wd = NftWatchdog()
    wd.status()                # human-readable summary to stdout
    report = wd.health()       # returns dict, no side effects
"""

from __future__ import annotations

import configparser
import hashlib
import json
import logging
import logging.handlers
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.keybase import notify

# ── Constants ─────────────────────────────────────────────────────────────────

_CONF_DEFAULTS: Dict[str, Dict[str, str]] = {
    "keybase": {
        "team": "", "target_user": "", "channel": "general", "linux_user": "",
    },
    "watchdog": {
        "check_interval"         : "30",
        "recovery_wait"          : "40",
        "recovery_retry_interval": "300",
        "hostname"               : socket.gethostname(),
        "daily_summary_hour"     : "8",
        "traffic_stall_timeout"  : "300",
    },
    "vpn": {
        "interface"        : "wg0",
        "config"           : "/etc/wireguard/wg0.conf",
        "handshake_timeout": "180",
    },
}

# ── Notification rate-limiter constants ───────────────────────────────────────

# Maximum number of Keybase notifications permitted within the rolling window.
# Prevents thread/process flooding during rapid VPN interface flaps.
_NOTIFY_MAX    = 3
_NOTIFY_WINDOW = 60.0   # seconds — rolling, self-healing; cannot permanently mute


class NftWatchdog:
    """WireGuard VPN health monitor with 4-level auto-recovery.

    Attributes
    ----------
    config_path:
        Path to the INI config file.  Defaults to ``/etc/nft-watchdog.conf``.
    """

    LOG_FILE           = Path("/var/log/nft-firewall/watchdog.log")
    MARKERS_FILE       = Path("/var/lib/nft-firewall/watchdog-markers.json")
    ENDPOINT_CACHE_FILE = Path("/var/lib/nft-firewall/wg-endpoint-cache.json")
    NFT_CONF           = Path("/etc/nftables.conf")

    def __init__(self, config_path: str = "/etc/nft-watchdog.conf") -> None:
        self.config_path:          str                          = config_path
        self._cfg:                 Optional[configparser.ConfigParser] = None
        self._markers:             Optional[Dict]               = None
        self._markers_mtime:       Optional[float]              = None
        self._last_markers_alert:  Optional[float]              = None
        # Notification rate-limiter state (rolling-window, thread-safe)
        self._notify_timestamps: List[float]    = []
        self._notify_lock:       threading.Lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def run_daemon(self) -> None:
        """Run the watchdog daemon main loop (systemd ExecStart entry point).

        Runs as fw-admin; privileged commands are executed via sudo.
        Blocks indefinitely.
        """
        self._setup_logging()
        self._log("INFO", "NFT Watchdog starting")
        self._log("INFO", f"Logs: journalctl -u nft-watchdog -f | tail -f {self.LOG_FILE}")
        # Clean up any orphaned .tmp left by a previous crash mid-atomic-write
        _orphan = self.ENDPOINT_CACHE_FILE.with_suffix(".tmp")
        if _orphan.exists():
            try:
                _orphan.unlink()
                self._log("INFO", f"Removed orphaned cache tmp file: {_orphan}")
            except OSError as exc:
                self._log("WARN", f"Could not remove orphaned {_orphan}: {exc}")
        self._load_markers(initial=True)
        self._run_loop()

    def status(self) -> None:
        """Print a human-readable one-shot status summary to stdout.

        Does not start the daemon loop and does not send notifications.
        """
        cfg   = self._load_conf()
        self._cfg = cfg
        iface = cfg.get("vpn", "interface", fallback="wg0")
        self._load_markers(initial=True)

        print(f"Watchdog config : {self.config_path}")
        print(f"VPN interface   : {iface}")

        ok, _, err = self._run(["ip", "link", "show", iface])
        print(f"Interface state : {'PRESENT' if ok else 'MISSING'} "
              f"({iface if ok else err or 'ip link show failed'})")

        vpn_ip = self._get_vpn_ip(iface)
        print(f"VPN IP          : {vpn_ip or 'NONE'}")

        age = self._get_handshake_age_seconds(iface)
        print(f"Handshake       : {f'{age}s ago' if age is not None else 'NONE (no handshake recorded)'}")

        healthy, reason = self._vpn_is_healthy(cfg)
        print(f"VPN health      : {'HEALTHY' if healthy else 'DEGRADED'} ({reason})")

        if self._markers is None:
            if self._markers_mtime is None:
                print(f"Markers file    : MISSING ({self.MARKERS_FILE}) [firewall apply required]")
            else:
                print(f"Markers file    : INVALID ({self.MARKERS_FILE})")
        else:
            print(f"Markers file    : LOADED ({self.MARKERS_FILE})")

        nft_ok, nft_what = self._check_nftables_integrity(iface)
        persisted_ok, persisted_status, persisted_what = self._check_persisted_ruleset_integrity()
        if persisted_status == "ok":
            print("Persisted conf  : OK (checksum matches)")
        elif persisted_status == "untracked":
            print("Persisted conf  : UNTRACKED (no checksum marker yet)")
        else:
            print(f"Persisted conf  : FAIL ({persisted_what})")

        if self._markers is None:
            print("Killswitch      : SKIPPED (markers not available)")
        elif nft_ok:
            print("Killswitch      : OK (markers present in ruleset)")
        else:
            print(f"Killswitch      : FAIL ({nft_what})")

    def health(self) -> Dict:
        """Return a machine-readable health report as a plain dict.

        This method has no side effects — it does not log, does not send
        notifications, and does not call ``sys.exit``.  Callers may serialise
        the result with ``json.dumps`` or inspect it programmatically.

        Returns
        -------
        dict with keys:

        - ``status``          — ``"HEALTHY"`` or ``"DEGRADED"``
        - ``reason``          — human-readable explanation
        - ``vpn_ip``          — current tunnel IP, or ``None``
        - ``handshake_age_s`` — seconds since last WireGuard handshake, or ``None``
        - ``markers``         — ``"ok"``, ``"missing"``, or ``"invalid"``
        - ``nft_integrity``   — ``True`` if killswitch markers are present in
                                the live ruleset, ``False`` otherwise
        - ``persisted_ruleset_integrity`` — ``"ok"``, ``"untracked"``,
                                ``"missing"``, or ``"mismatch"``
        """
        cfg   = self._load_conf()
        self._cfg = cfg
        iface = cfg.get("vpn", "interface", fallback="wg0")
        self._load_markers(initial=True)

        healthy, reason = self._vpn_is_healthy(cfg)
        vpn_ip          = self._get_vpn_ip(iface)
        handshake_age   = self._get_handshake_age_seconds(iface)

        if self._markers is None and self._markers_mtime is None:
            markers_status = "missing"
        elif self._markers is None:
            markers_status = "invalid"
        else:
            markers_status = "ok"

        nft_ok, _ = self._check_nftables_integrity(iface)
        persisted_ok, persisted_status, persisted_reason = (
            self._check_persisted_ruleset_integrity()
        )

        overall = (
            "HEALTHY"
            if (healthy and nft_ok and markers_status == "ok" and persisted_ok)
            else "DEGRADED"
        )

        return {
            "status"         : overall,
            "reason"         : reason,
            "vpn_ip"         : vpn_ip,
            "handshake_age_s": handshake_age,
            "markers"        : markers_status,
            "nft_integrity"  : nft_ok,
            "persisted_ruleset_integrity": persisted_status,
            "persisted_ruleset_reason"   : persisted_reason,
        }

    # ── Logging ───────────────────────────────────────────────────────────────

    def _setup_logging(self) -> None:
        fmt  = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        root = logging.getLogger()
        if root.handlers:
            return
        root.setLevel(logging.DEBUG)

        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        root.addHandler(sh)

        try:
            self.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                str(self.LOG_FILE), maxBytes=5 * 1024 * 1024, backupCount=3
            )
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except Exception as exc:
            logging.warning(f"Cannot open log file {self.LOG_FILE}: {exc}")

    def _log(self, level: str, msg: str) -> None:
        logging.log(getattr(logging, level.upper(), logging.INFO), msg)

    # ── Notifications ─────────────────────────────────────────────────────────

    def _notify_async(self, **kwargs) -> None:
        """Fire-and-forget Keybase notification with rate limiting.

        Spawns a daemon thread so a failed or slow Keybase call never blocks
        the recovery loop.  The thread is intentionally non-joined — if the
        process exits the OS reclaims it automatically.

        Rate limit: at most ``_NOTIFY_MAX`` notifications per ``_NOTIFY_WINDOW``
        seconds (rolling window).  Excess calls are dropped with a local
        ``[WARN]`` log entry.  The window is self-healing — timestamps age off
        after ``_NOTIFY_WINDOW`` seconds, making permanent muting impossible.
        """
        now = time.time()
        with self._notify_lock:
            # Prune timestamps that have aged out of the rolling window
            self._notify_timestamps = [
                ts for ts in self._notify_timestamps if now - ts < _NOTIFY_WINDOW
            ]
            if len(self._notify_timestamps) >= _NOTIFY_MAX:
                title = kwargs.get("title", "(no title)")
                self._log(
                    "WARN",
                    f"Keybase notification suppressed (rate limit: "
                    f"{_NOTIFY_MAX}/{int(_NOTIFY_WINDOW)}s): {title!r}",
                )
                return
            self._notify_timestamps.append(now)

        t = threading.Thread(target=notify, kwargs=kwargs, daemon=True)
        t.start()

    # ── Config & markers ──────────────────────────────────────────────────────

    def _load_conf(self) -> configparser.ConfigParser:
        """Load config from disk, applying built-in defaults for missing keys."""
        cfg = configparser.ConfigParser()
        for section, pairs in _CONF_DEFAULTS.items():
            cfg[section] = pairs.copy()
        path = Path(self.config_path)
        if path.exists():
            cfg.read(str(path))
        return cfg

    def _load_markers(self, initial: bool = False) -> None:
        """Read and validate the watchdog markers JSON file.

        Parameters
        ----------
        initial:
            When ``True``, suppress the Keybase notification that fires when
            the markers file is found missing or invalid.  Use ``True`` at
            daemon startup and in one-shot commands; use ``False`` inside the
            main loop.
        """
        mf = self.MARKERS_FILE
        try:
            st = mf.stat()
        except FileNotFoundError:
            self._markers       = None
            self._markers_mtime = None
            msg = f"Watchdog markers file missing: {mf} — firewall apply required"
            self._log("ERROR", msg)
            if not initial:
                now = time.time()
                if (self._last_markers_alert is None
                        or now - self._last_markers_alert >= 3600):
                    self._last_markers_alert = now
                    self._notify_async(
                        title="🚨 Watchdog Markers Missing",
                        body=(
                            f"━━━━━━━━━━━━━━━━━━━━\n"
                            f"    📋  {msg}\n"
                            f"    🛠️  Run: sudo python3 src/main.py apply <profile>"
                        ),
                        priority="urgent",
                        tags="rotating_light",
                    )
            return

        # Skip re-read if mtime unchanged
        if self._markers_mtime is not None and self._markers_mtime == st.st_mtime:
            return

        try:
            data = json.loads(mf.read_text())
            required = ("vpn_iface", "ip6_table", "output_rule")
            if not all(k in data for k in required):
                raise ValueError(f"markers JSON missing keys: {required}")
            self._markers       = data
            self._markers_mtime = st.st_mtime
        except Exception as exc:
            self._markers       = None
            self._markers_mtime = None
            msg = f"Invalid watchdog markers file {mf}: {exc}"
            self._log("ERROR", msg)
            if not initial:
                now = time.time()
                if (self._last_markers_alert is None
                        or now - self._last_markers_alert >= 3600):
                    self._last_markers_alert = now
                    self._notify_async(
                        title="🚨 Watchdog Markers Missing",
                        body=(
                            f"━━━━━━━━━━━━━━━━━━━━\n"
                            f"    📋  {msg}\n"
                            f"    🛠️  Run: sudo python3 src/main.py apply <profile>"
                        ),
                        priority="urgent",
                        tags="rotating_light",
                    )

    # ── Shell helper ──────────────────────────────────────────────────────────

    def _flush_conntrack(self) -> None:
        """Flush all conntrack entries (No-Wait Kill).

        Called immediately before every recovery attempt so that stale
        TCP/UDP sessions cannot continue to flow via the physical interface
        while the VPN is being restarted.  Requires the ``conntrack`` package; fails
        silently with a warning if the binary is absent.
        """
        ok, _, err = self._run(["conntrack", "-F"], timeout=10)
        if ok:
            self._log("INFO", "conntrack -F: flushed all connection tracking entries")
        else:
            if "No such file" in err or "not found" in err.lower():
                self._log("WARN",
                    "conntrack -F skipped: binary not found — "
                    "install 'conntrack' package for instant kill")
            else:
                self._log("WARN", f"conntrack -F failed: {err}")

    # Binaries that require root — prepend sudo so they run elevated directly
    # instead of letting them self-elevate (wg-quick does `exec sudo -- $BASH --
    # $SELF`, which produces a command that doesn't match the sudoers rule).
    _PRIVILEGED_CMDS: frozenset = frozenset(
        ["nft", "wg", "wg-quick", "ip", "conntrack", "systemctl"]
    )
    _WRAPPERS: Dict[str, str] = {
        "nft": "/usr/local/lib/nft-firewall/fw-nft",
        "wg": "/usr/local/lib/nft-firewall/fw-wg",
        "wg-quick": "/usr/local/lib/nft-firewall/fw-wg-quick",
        "ip": "/usr/local/lib/nft-firewall/fw-ip",
        "conntrack": "/usr/local/lib/nft-firewall/fw-conntrack",
        "systemctl": "/usr/local/lib/nft-firewall/fw-systemctl",
    }

    def _run(
        self, cmd: List[str], timeout: int = 15
    ) -> Tuple[bool, str, str]:
        """Run a subprocess and return ``(success, stdout, stderr)``.

        Privileged commands (nft, wg, wg-quick, ip, conntrack, systemctl) are
        automatically prefixed with ``sudo`` so they run as root without
        requiring this process to be root itself.
        """
        binary = Path(cmd[0]).name
        if binary in self._PRIVILEGED_CMDS:
            wrapper = self._WRAPPERS.get(binary)
            if wrapper and Path(wrapper).exists():
                cmd = ["sudo", wrapper] + list(cmd[1:])
            else:
                cmd = ["sudo"] + list(cmd)
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=timeout
            )
            return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
        except Exception as exc:
            return False, "", str(exc)

    # ── VPN helpers ───────────────────────────────────────────────────────────

    def _format_duration(self, seconds: float) -> str:
        """Return a human-readable duration string, e.g. ``"2m 15s"``."""
        s = int(seconds)
        return f"{s}s" if s < 60 else f"{s // 60}m {s % 60}s"

    def _get_vpn_ip(self, iface: str) -> Optional[str]:
        """Return the IPv4 address assigned to *iface*, or ``None``."""
        ok, out, _ = self._run(["ip", "addr", "show", iface])
        if ok and out:
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        return None

    def _get_handshake_age_seconds(self, iface: str) -> Optional[int]:
        """Return seconds since the last WireGuard handshake, or ``None``."""
        ok, out, _ = self._run(["wg", "show", iface, "latest-handshakes"])
        if ok and out:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        ts = int(parts[1])
                        if ts > 0:
                            return int(time.time()) - ts
                    except ValueError:
                        pass
        return None

    def _wait_for_handshake(
        self, iface: str, timeout_s: int = 40
    ) -> Tuple[bool, Optional[int]]:
        """Poll until a fresh WireGuard handshake is seen or *timeout_s* elapses.

        Returns
        -------
        tuple[bool, int | None]
            ``(True, age_seconds)`` if a handshake was seen in time,
            ``(False, None)`` otherwise.
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            age = self._get_handshake_age_seconds(iface)
            if age is not None and age < timeout_s + 30:
                return True, age
            time.sleep(5)
        return False, None

    def _get_transfer_bytes(self, iface: str) -> Optional[int]:
        """Return total bytes transferred (rx+tx across all peers), or ``None``."""
        ok, out, _ = self._run(["wg", "show", iface, "transfer"])
        if not ok or not out.strip():
            return None
        total, parsed = 0, False
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                try:
                    total  += int(parts[1]) + int(parts[2])
                    parsed  = True
                except ValueError:
                    pass
        return total if parsed else None

    def _vpn_is_healthy(
        self, cfg: configparser.ConfigParser
    ) -> Tuple[bool, str]:
        """Check interface existence, IP assignment, and handshake freshness.

        Returns
        -------
        tuple[bool, str]
            ``(True, reason)`` if all three checks pass, ``(False, reason)``
            on the first failure.
        """
        iface   = cfg.get("vpn", "interface", fallback="wg0")
        max_age = int(cfg.get("vpn", "handshake_timeout", fallback="180"))

        ok, _, _ = self._run(["ip", "link", "show", iface])
        if not ok:
            return False, f"interface {iface} does not exist"

        vpn_ip = self._get_vpn_ip(iface)
        if not vpn_ip:
            return False, f"interface {iface} has no IP address"

        age = self._get_handshake_age_seconds(iface)
        if age is None:
            return False, "no WireGuard handshake recorded yet"
        if age > max_age:
            return False, f"last handshake {age}s ago (limit {max_age}s)"

        return True, f"UP {vpn_ip} handshake {age}s ago"

    # ── Killswitch integrity ──────────────────────────────────────────────────

    def _check_nftables_integrity(self, iface: str) -> Tuple[bool, str]:
        """Verify that the killswitch markers are present in the live ruleset.
        
        Optimized to check specific chains instead of listing the entire ruleset.
        """
        if not self._markers:
            return False, "markers not loaded; cannot verify killswitch integrity"

        # 1. Check OUTPUT chain for our marker
        main_table = str(self._markers.get("main_table", "firewall")).strip()
        ok, out, _ = self._run(["nft", "list", "chain", "ip", main_table, "output"])
        
        # If the command failed, it likely means the table or chain is MISSING.
        if not ok:
             return False, f"missing: {main_table} table or output chain"
        
        # DEFINITIVE SEARCH: We look for the literal comment in the entire chain dump.
        if "nft-killswitch-output" not in out:
            return False, f"missing: OUTPUT rule marker in 'ip {main_table} output'"

        # 2. Check for IPv6 killswitch table
        ip6_table = str(self._markers.get("ip6_table", "")).strip()
        if ip6_table:
            ok, out, _ = self._run(["nft", "list", "tables", "ip6"])
            if not ok or not re.search(rf"\btable\s+ip6\s+{re.escape(ip6_table)}\b", out):
                return False, f"missing: ip6 killswitch table '{ip6_table}'"

        return True, ""

    def _check_persisted_ruleset_integrity(self) -> Tuple[bool, str, str]:
        """Verify /etc/nftables.conf against the checksum stored in markers.

        Missing checksum metadata is treated as compatible/untracked so older
        marker files do not break the watchdog. A present-but-mismatched hash is
        degraded and prevents auto-repair from loading a tampered persisted file.
        """
        if not self._markers:
            return True, "untracked", "markers not loaded"

        marker = self._markers.get("persisted_ruleset")
        if not isinstance(marker, dict):
            return True, "untracked", "no persisted ruleset checksum marker"

        expected = str(marker.get("sha256", "")).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            return True, "untracked", "invalid or missing checksum marker"

        try:
            current = hashlib.sha256(self.NFT_CONF.read_bytes()).hexdigest()
        except FileNotFoundError:
            return False, "missing", f"{self.NFT_CONF} is missing"
        except OSError as exc:
            return False, "missing", f"cannot read {self.NFT_CONF}: {exc}"

        if current != expected:
            marker_path = str(marker.get("path", self.NFT_CONF))
            return (
                False,
                "mismatch",
                f"checksum mismatch for {marker_path}",
            )
        return True, "ok", "checksum matches"

    def _validate_conf_markers(self, content: str) -> bool:
        """Return True only if *content* contains structural killswitch markers."""
        if not content or not content.strip():
            return False
        
        lowered = content.lower()
        
        # Core safety requirements — proved to be 'our' firewall.
        if "policy drop" in lowered and "nft-killswitch-output" in lowered:
            return True

        return False
    # ── Endpoint IP cache ─────────────────────────────────────────────────────

    def _cache_endpoint_ip(
        self, iface: str, hostname: str, ip: str, port: str
    ) -> None:
        """Persist the last successfully resolved endpoint IP to disk.

        Read back by ``_read_cached_endpoint_ip`` during Level 3 recovery
        when DNS is unreachable (killswitch catch-22).

        Uses an atomic write (write → fsync → os.replace) so a crash or
        power loss mid-write always leaves the cache in a valid state —
        either the previous complete JSON or the new complete JSON, never a
        partial/corrupt file.
        """
        dest = self.ENDPOINT_CACHE_FILE
        tmp  = dest.with_suffix(".tmp")
        try:
            try:
                data: Dict = json.loads(dest.read_text())
            except Exception:
                data = {}
            data[iface] = {
                "hostname": hostname,
                "ip"      : ip,
                "port"    : port,
                "ts"      : int(time.time()),
            }
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "w") as fh:
                fh.write(json.dumps(data, indent=2))
                fh.flush()
                os.fsync(fh.fileno())   # ensure bytes reach disk before rename
            os.replace(tmp, dest)       # POSIX-atomic: dest is never partially written
        except Exception as exc:
            self._log("WARN", f"Could not save endpoint cache: {exc}")
            try:
                tmp.unlink(missing_ok=True)   # don't leave a corrupt .tmp behind
            except OSError:
                pass

    def _read_cached_endpoint_ip(
        self, iface: str, hostname: str
    ) -> Optional[str]:
        """Return the last known IP for *hostname* from the endpoint cache.

        Returns ``None`` if no cache entry exists or the entry is for a
        different hostname.
        """
        try:
            data  = json.loads(self.ENDPOINT_CACHE_FILE.read_text())
            entry = data.get(iface, {})
            if entry.get("hostname") == hostname:
                ip  = entry.get("ip", "")
                age = int(time.time()) - entry.get("ts", 0)
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    self._log(
                        "INFO",
                        f"Level 3: DNS unavailable — using cached endpoint "
                        f"IP {ip} for {hostname} (cached {age}s ago)",
                    )
                    return ip
        except Exception:
            pass
        return None

    # ── Recovery levels ───────────────────────────────────────────────────────

    def _level1_soft_restart(self, iface: str) -> bool:
        """Level 1: soft restart via ``wg-quick down/up``.

        Returns
        -------
        bool
            ``True`` if ``wg-quick up`` succeeded.
        """
        self._log("INFO", "Recovery Level 1: soft restart (wg-quick down/up)")
        self._run(["wg-quick", "down", iface], timeout=30)
        time.sleep(3)
        ok, _, err = self._run(["wg-quick", "up", iface], timeout=30)
        if not ok:
            self._log("WARN", f"Level 1 wg-quick up failed: {err}")
        return ok

    def _level2_hard_restart(self, iface: str) -> bool:
        """Level 2: hard restart — delete the interface, then ``wg-quick up``.

        Returns
        -------
        bool
            ``True`` if ``wg-quick up`` succeeded.
        """
        self._log("INFO", "Recovery Level 2: hard restart (ip link delete + wg-quick up)")
        self._run(["wg-quick", "down", iface], timeout=15)
        self._run(["ip", "link", "delete", iface], timeout=10)
        time.sleep(3)
        ok, _, err = self._run(["wg-quick", "up", iface], timeout=30)
        if not ok:
            self._log("WARN", f"Level 2 wg-quick up failed: {err}")
        return ok

    def _level3_dns_reresolve(
        self, cfg: configparser.ConfigParser, iface: str
    ) -> bool:
        """Level 3: re-resolve the VPN endpoint hostname and update the peer.

        Reads the WireGuard config file to find ``PublicKey`` and ``Endpoint``,
        resolves the hostname via the system resolver (5 s hard timeout) then
        fallback DNS servers (1.1.1.1, 8.8.8.8, 9.9.9.9).

        Killswitch catch-22 fallback
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        When wg0 is down and the killswitch is active all DNS paths are
        blocked.  In that case Level 3 falls back in order:

        1. If the endpoint value is already a bare IPv4 address, use it
           directly — no DNS needed.
        2. Otherwise read the last successfully resolved IP from the on-disk
           endpoint cache (``ENDPOINT_CACHE_FILE``).

        Once an IP is obtained (by any path) the method writes a temporary
        ``wg0.conf`` with the hostname substituted by the IP so that
        ``wg-quick up`` never performs a DNS lookup.  The temporary file is
        removed immediately after ``wg-quick`` exits.

        Returns
        -------
        bool
            ``True`` if the tunnel came back up (even if the peer endpoint
            update failed — the tunnel may still work with the cached IP).
            ``False`` if no IP could be determined or ``wg-quick up`` failed.
        """
        self._log("INFO", "Recovery Level 3: DNS re-resolve endpoint + update peer + restart")
        conf_path = cfg.get("vpn", "config", fallback=f"/etc/wireguard/{iface}.conf")
        try:
            content = Path(conf_path).read_text()
        except Exception as exc:
            self._log("WARN", f"Level 3: cannot read {conf_path}: {exc}; using privileged inspection")
            ok, content, err = self._run(["wg", "config-endpoint", iface], timeout=10)
            if not ok:
                self._log("WARN", f"Level 3: privileged config inspection failed: {err}")
                return False

        m_key  = re.search(r"PublicKey\s*=\s*(\S+)", content)
        m_host = re.search(r"Endpoint\s*=\s*([^:\s]+):(\d+)", content)
        if not m_key or not m_host:
            self._log("WARN", "Level 3: cannot parse PublicKey/Endpoint from config")
            return False

        pubkey   = m_key.group(1)
        hostname = m_host.group(1)
        port     = m_host.group(2)

        # ── DNS resolution (all paths bounded) ───────────────────────────────
        new_ip: Optional[str] = None

        # System resolver — hard 5-second timeout via a daemon thread.
        # socket.getaddrinfo() ignores socket.setdefaulttimeout(); the only
        # safe way to bound it is to run it in a thread and join with timeout.
        _gai_result: List[str] = []

        def _gai() -> None:
            try:
                r = socket.getaddrinfo(hostname, None, socket.AF_INET)
                if r:
                    _gai_result.append(r[0][4][0])
            except Exception:
                pass

        _t = threading.Thread(target=_gai, daemon=True)
        _t.start()
        _t.join(timeout=5)
        if _gai_result:
            new_ip = _gai_result[0]
            self._log("INFO", f"Level 3: resolved {hostname} → {new_ip} (via system DNS)")

        # Fallback: explicit DNS servers (dig already bounded by _run timeout)
        if not new_ip:
            for dns_server in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:
                ok, out, _ = self._run(
                    ["dig", f"@{dns_server}", "+short", "+time=5", hostname]
                )
                if ok and out:
                    for line in out.splitlines():
                        line = line.strip()
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                            new_ip = line
                            self._log(
                                "INFO",
                                f"Level 3: resolved {hostname} → {new_ip} (via {dns_server})",
                            )
                            break
                if new_ip:
                    break

        # ── Killswitch catch-22 fallback ─────────────────────────────────────
        if not new_ip:
            # Case 1: the endpoint in the config is already a bare IP.
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
                new_ip = hostname
                self._log(
                    "INFO",
                    f"Level 3: endpoint is already an IP ({new_ip}) — no DNS needed",
                )
            else:
                # Case 2: hostname but DNS blocked — try the on-disk cache.
                new_ip = self._read_cached_endpoint_ip(iface, hostname)

        if not new_ip:
            self._log(
                "WARN",
                f"Level 3: DNS resolution failed for {hostname} and no cached IP available",
            )
            return False

        # The root-owned recovery helper reads the fixed WireGuard config and
        # substitutes only this validated IP. No caller-selected path crosses
        # the privilege boundary.
        self._run(["wg-quick", "down", iface], timeout=15)
        time.sleep(2)
        ok, _, err = self._run(
            ["wg-quick", "recover", iface, new_ip], timeout=30
        )

        if not ok:
            self._log("WARN", f"Level 3: wg-quick up (IP-injected) failed: {err}")
            return False

        # Update the live peer endpoint and persist the IP for future catch-22 recovery.
        ok2, _, err2 = self._run(
            ["wg", "set", iface, "peer", pubkey, "endpoint", f"{new_ip}:{port}"],
            timeout=10,
        )
        if not ok2:
            self._log("WARN", f"Level 3: wg set peer endpoint failed: {err2}")
        else:
            self._log("INFO", f"Level 3: peer endpoint updated to {new_ip}:{port}")

        self._cache_endpoint_ip(iface, hostname, new_ip, port)
        return True

    def _level4_full_recreation(self, iface: str) -> bool:
        """Level 4: full systemd service teardown and restart.

        Stops the ``wg-quick@<iface>`` service, deletes the interface, and
        starts the service again.

        Returns
        -------
        bool
            ``True`` if ``systemctl start`` succeeded.
        """
        self._log("INFO", "Recovery Level 4: full systemd service recreation")
        wg_service = f"wg-quick@{iface}.service"
        self._run(["wg-quick", "down", iface], timeout=20)
        self._run(["ip", "link", "delete", iface], timeout=10)
        self._run(["systemctl", "stop", wg_service], timeout=20)
        time.sleep(5)
        ok, _, err = self._run(["systemctl", "start", wg_service], timeout=30)
        if not ok:
            self._log("WARN", f"Level 4: systemctl start {wg_service} failed: {err}")
        return ok

    def _attempt_recovery(
        self,
        cfg: configparser.ConfigParser,
        iface: str,
        recovery_wait: int,
    ) -> Tuple[bool, int]:
        """Try each recovery level in order until the VPN comes back up.

        After each level, waits up to *recovery_wait* seconds for a WireGuard
        handshake before escalating — **but only if the interface actually came
        up**.  If the interface is absent after a level (e.g. Level 3 returned
        False without restarting) the 40-second wait is skipped entirely.

        Returns
        -------
        tuple[bool, int]
            ``(True, level_num)`` if recovery succeeded at *level_num*,
            ``(False, 0)`` if all four levels were exhausted.
        """
        levels = [
            (1, lambda: self._level1_soft_restart(iface)),
            (2, lambda: self._level2_hard_restart(iface)),
            (3, lambda: self._level3_dns_reresolve(cfg, iface)),
            (4, lambda: self._level4_full_recreation(iface)),
        ]
        for level_num, fn in levels:
            self._log("INFO", f"Trying recovery level {level_num}/4 ...")
            try:
                success = fn()
                if not success:
                    self._log("WARN", f"Level {level_num} failed — escalating immediately")
                    continue
            except Exception as exc:
                self._log("WARN", f"Level {level_num} raised exception: {exc} — escalating")
                continue

            self._log("INFO", f"Waiting up to {recovery_wait}s for WireGuard handshake ...")
            got_hs, _ = self._wait_for_handshake(iface, timeout_s=recovery_wait)
            if got_hs:
                healthy, reason = self._vpn_is_healthy(cfg)
                if healthy:
                    self._log("INFO", f"VPN restored at level {level_num}: {reason}")
                    return True, level_num
                self._log(
                    "WARN",
                    f"Level {level_num}: handshake seen but health check failed: {reason}",
                )
            else:
                self._log(
                    "WARN",
                    f"Level {level_num}: no handshake within {recovery_wait}s — escalating",
                )
        return False, 0

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Blocking daemon loop.  Re-reads config from disk on every iteration."""
        cfg = self._load_conf()
        self._cfg = cfg

        iface                   = cfg.get("vpn",      "interface",              fallback="wg0")
        check_interval          = int(cfg.get("watchdog", "check_interval",          fallback="30"))
        recovery_wait           = int(cfg.get("watchdog", "recovery_wait",           fallback="40"))
        recovery_retry_interval = int(cfg.get("watchdog", "recovery_retry_interval", fallback="300"))
        daily_hour              = int(cfg.get("watchdog", "daily_summary_hour",      fallback="8"))
        traffic_stall_timeout   = int(cfg.get("watchdog", "traffic_stall_timeout",   fallback="300"))
        host                    = cfg.get("watchdog", "hostname", fallback=socket.gethostname())

        kb_team = cfg.get("keybase", "team",        fallback="").strip()
        kb_user = cfg.get("keybase", "target_user", fallback="").strip()
        kb_ok   = (kb_team and kb_team != "your-team-name") or \
                  (kb_user and kb_user != "your-keybase-username")

        self._log("INFO", f"Monitoring {iface} every {check_interval}s | host={host}")
        self._log("INFO", f"recovery_wait={recovery_wait}s | retry_after_full_failure={recovery_retry_interval}s")
        if not kb_ok:
            self._log("WARN", f"Keybase not configured in {self.config_path} — notifications disabled")
        else:
            dest = f"team:{kb_team}" if kb_team else f"user:{kb_user}"
            self._log("INFO", f"Keybase notifications enabled — {dest}")

        # ── Startup health check ──────────────────────────────────────────────
        down_since:      Optional[float] = None
        last_nft_alert:  Optional[float] = None
        last_conf_alert: Optional[float] = None
        stall_tracker:   Optional[Dict]  = None
        last_daily_date: Optional[date]  = None

        healthy, reason = self._vpn_is_healthy(cfg)
        if healthy:
            self._log("INFO", f"Startup: VPN is UP — {reason}")
            self._notify_async(
                title="🟢 VPN Up — Watchdog Started",
                body=(
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"    🖥️  Host: {host}\n"
                    f"    📡  {reason}"
                ),
                priority="default",
                tags="white_check_mark",
            )
            was_healthy = True
        else:
            self._log("INFO", f"Startup: VPN is DOWN — {reason}")
            self._log("INFO", "Keybase notification skipped until VPN is up (killswitch blocks internet)")
            was_healthy = False
            down_since  = time.time()
            recovered, level = self._attempt_recovery(cfg, iface, recovery_wait)
            if recovered:
                fmt        = self._format_duration(time.time() - down_since)
                down_since = None
                was_healthy = True
                _, reason  = self._vpn_is_healthy(cfg)
                self._notify_async(
                    title="🟢 VPN Recovered — Watchdog Started",
                    body=(
                        f"━━━━━━━━━━━━━━━━━━━━\n"
                        f"    🖥️  Host: {host}\n"
                        f"    ⚡  Recovery level: {level}/4\n"
                        f"    ⏱️  Down for: {fmt}\n"
                        f"    📡  {reason}"
                    ),
                    priority="high",
                    tags="white_check_mark",
                )
            else:
                fmt = self._format_duration(time.time() - down_since)
                self._log("ERROR", f"Startup recovery failed — retry in {recovery_retry_interval}s")
                self._notify_async(
                    title="🔴 VPN Recovery FAILED — Watchdog Started",
                    body=(
                        f"━━━━━━━━━━━━━━━━━━━━\n"
                        f"    🖥️  Host: {host}\n"
                        f"    ⏱️  Down for: {fmt}\n"
                        f"    🔁  Retrying every {recovery_retry_interval}s\n"
                        f"    📍  {reason}"
                    ),
                    priority="urgent",
                    tags="sos",
                )

        last_recovery_at: float = time.time()

        # ── Main loop ─────────────────────────────────────────────────────────
        while True:
            try:
                # Re-read config every iteration (live reload)
                cfg = self._load_conf()
                self._cfg = cfg
                iface                   = cfg.get("vpn",      "interface",              fallback="wg0")
                check_interval          = int(cfg.get("watchdog", "check_interval",          fallback="30"))
                recovery_wait           = int(cfg.get("watchdog", "recovery_wait",           fallback="40"))
                recovery_retry_interval = int(cfg.get("watchdog", "recovery_retry_interval", fallback="300"))
                daily_hour              = int(cfg.get("watchdog", "daily_summary_hour",      fallback="8"))
                traffic_stall_timeout   = int(cfg.get("watchdog", "traffic_stall_timeout",   fallback="300"))
                host                    = cfg.get("watchdog", "hostname", fallback=socket.gethostname())

                self._load_markers(initial=False)

                # ── nftables integrity check ──────────────────────────────────
                nft_ok, nft_what = self._check_nftables_integrity(iface)
                persisted_ok, persisted_status, persisted_what = (
                    self._check_persisted_ruleset_integrity()
                )
                if not persisted_ok:
                    self._log(
                        "ERROR",
                        f"Persisted ruleset integrity FAILED: {persisted_what}",
                    )
                    if last_conf_alert is None or time.time() - last_conf_alert >= 3600:
                        self._notify_async(
                            title="🚨 Persisted Ruleset Drift",
                            body=(
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"    🖥️  Host: {host}\n"
                                f"    📋  {persisted_what}\n"
                                f"    🛠️  Manual inspection required before "
                                f"watchdog reloads /etc/nftables.conf"
                            ),
                            priority="urgent",
                            tags="rotating_light",
                        )
                        last_conf_alert = time.time()
                elif persisted_status == "ok":
                    last_conf_alert = None

                if not nft_ok:
                    self._log("ERROR", f"nftables killswitch check FAILED: {nft_what}")
                    stall_tracker = None

                    # ── Auto-repair: validate then reload /etc/nftables.conf ──
                    conf_path = "/etc/nftables.conf"
                    self._log("INFO", f"Attempting auto-repair: nft -f {conf_path}")
                    check_ok, _, check_err = self._run(
                        ["nft", "--check", "--file", conf_path], timeout=15,
                    )
                    try:
                        conf_content = Path(conf_path).read_text()
                    except OSError as exc:
                        self._log("WARN", f"Could not read {conf_path}: {exc}")
                        conf_content = ""
                    conf_valid = (
                        persisted_ok
                        and check_ok
                        and self._validate_conf_markers(conf_content)
                    )
                    if not conf_valid:
                        self._log("ERROR",
                                  f"Auto-repair aborted: {conf_path} failed validation")
                        repair_ok = False
                        repair_err = (
                            persisted_what
                            if not persisted_ok
                            else check_err or "marker validation failed"
                        )
                    else:
                        repair_ok, _, repair_err = self._run(
                            ["nft", "-f", conf_path], timeout=15,
                        )
                    if repair_ok:
                        self._log("INFO",
                                  "Killswitch rules restored from /etc/nftables.conf ✓")
                        self._notify_async(
                            title="🟢 Killswitch Rules Restored",
                            body=(
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"    🖥️  Host: {host}\n"
                                f"    🛡️  Rules were missing; auto-restored from "
                                f"/etc/nftables.conf"
                            ),
                            priority="high",
                            tags="white_check_mark",
                        )
                        last_nft_alert = None   # reset so next failure re-alerts
                    else:
                        self._log("ERROR",
                                  f"Auto-repair FAILED: {repair_err.strip()}")
                        if last_nft_alert is None or \
                                time.time() - last_nft_alert >= 3600:
                            self._notify_async(
                                title="🚨 Killswitch Rules MISSING",
                                body=(
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"    🖥️  Host: {host}\n"
                                    f"    📋  {nft_what}\n"
                                    f"    🛠️  Auto-repair failed — manual "
                                    f"intervention required"
                                ),
                                priority="urgent",
                                tags="rotating_light",
                            )
                            last_nft_alert = time.time()
                    time.sleep(check_interval)
                    continue

                # ── Passive metrics update (non-blocking, best-effort) ────────
                try:
                    from utils.metrics import metrics_update
                    metrics_update(iface=iface)
                except Exception as _me:
                    self._log("WARN", f"metrics_update failed (non-fatal): {_me}")

                # ── VPN health check ──────────────────────────────────────────
                healthy, reason = self._vpn_is_healthy(cfg)

                if healthy:
                    if not was_healthy:
                        self._log("INFO", f"VPN is back up: {reason}")
                        self._notify_async(
                            title="🟢 VPN Restored",
                            body=(
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"    🖥️  Host: {host}\n"
                                f"    📡  {reason}"
                            ),
                            priority="high",
                            tags="white_check_mark",
                        )
                        was_healthy      = True
                        last_recovery_at = time.time()
                    else:
                        self._log("INFO", f"VPN OK: {reason}")

                    # ── Traffic stall detection ───────────────────────────────
                    current_bytes = self._get_transfer_bytes(iface)
                    if current_bytes is None:
                        pass  # wg show failed; skip stall tracking this tick
                    elif stall_tracker is None:
                        stall_tracker = {"bytes": current_bytes, "since": time.time()}
                    elif current_bytes != stall_tracker["bytes"]:
                        stall_tracker = {"bytes": current_bytes, "since": time.time()}
                    else:
                        stall_age = time.time() - stall_tracker["since"]
                        if stall_age >= traffic_stall_timeout:
                            fmt_stall = self._format_duration(stall_age)
                            self._log(
                                "WARN",
                                f"Traffic stall: no bytes moved for {fmt_stall} despite healthy handshake",
                            )
                            self._notify_async(
                                title="🚨 VPN Tunnel Stalled",
                                body=(
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"    🖥️  Host: {host}\n"
                                    f"    ⏱️  No traffic for: {fmt_stall}\n"
                                    f"    ⚡  Auto-recovery starting"
                                ),
                                priority="urgent",
                                tags="rotating_light",
                            )
                            down_since       = stall_tracker["since"]
                            was_healthy      = False
                            stall_tracker    = None
                            last_recovery_at = time.time()
                            self._flush_conntrack()
                            recovered, level = self._attempt_recovery(cfg, iface, recovery_wait)
                            if recovered:
                                fmt         = self._format_duration(time.time() - down_since)
                                was_healthy = True
                                down_since  = None
                                self._notify_async(
                                    title=f"🟢 VPN Recovered (level {level}/4)",
                                    body=(
                                        f"━━━━━━━━━━━━━━━━━━━━\n"
                                        f"    🖥️  Host: {host}\n"
                                        f"    ⚡  Recovery level: {level}/4\n"
                                        f"    ⏱️  Down for: {fmt}"
                                    ),
                                    priority="high",
                                    tags="white_check_mark",
                                )
                            else:
                                fmt = self._format_duration(time.time() - down_since)
                                self._log("ERROR", "Stall recovery failed — all 4 levels exhausted")
                                self._notify_async(
                                    title="🔴 VPN Recovery FAILED",
                                    body=(
                                        f"━━━━━━━━━━━━━━━━━━━━\n"
                                        f"    🖥️  Host: {host}\n"
                                        f"    ⏱️  Down for: {fmt}\n"
                                        f"    🔁  Retrying every {recovery_retry_interval}s"
                                    ),
                                    priority="urgent",
                                    tags="sos",
                                )

                    # ── Daily health summary ──────────────────────────────────
                    if daily_hour >= 0:
                        now   = datetime.now()
                        today = now.date()
                        if now.hour == daily_hour and last_daily_date != today:
                            ks_ok, ks_msg = self._check_nftables_integrity(iface)
                            ks_status = "🟢 Active" if ks_ok else f"🔴 DEGRADED ({ks_msg})"
                            self._notify_async(
                                title="📊 Daily Health Summary",
                                body=(
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"    🖥️  Host: {host}\n"
                                    f"    🛡️  Killswitch: {ks_status}\n"
                                    f"    🟢  All systems nominal\n"
                                    f"    📡  {reason}"
                                ),
                                priority="min",
                                tags="bar_chart",
                            )
                            last_daily_date = today

                else:
                    # ── VPN is down ───────────────────────────────────────────
                    self._log("WARN", f"VPN DOWN: {reason}")
                    now_ts = time.time()

                    if was_healthy:
                        was_healthy      = False
                        last_recovery_at = now_ts
                        down_since       = now_ts
                        self._log("INFO", "Starting auto-recovery sequence ...")
                        self._notify_async(
                            title="🔴 VPN DOWN",
                            body=(
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"    🖥️  Host: {host}\n"
                                f"    📍  {reason}\n"
                                f"    ⚡  Auto-recovery starting"
                            ),
                            priority="urgent",
                            tags="rotating_light",
                        )
                        self._flush_conntrack()
                        recovered, level = self._attempt_recovery(cfg, iface, recovery_wait)
                        if recovered:
                            fmt              = self._format_duration(time.time() - down_since)
                            was_healthy      = True
                            down_since       = None
                            stall_tracker    = None
                            self._notify_async(
                                title=f"🟢 VPN Recovered (level {level}/4)",
                                body=(
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"    🖥️  Host: {host}\n"
                                    f"    ⚡  Recovery level: {level}/4\n"
                                    f"    ⏱️  Down for: {fmt}"
                                ),
                                priority="high",
                                tags="white_check_mark",
                            )
                        else:
                            fmt = self._format_duration(time.time() - down_since)
                            self._log("ERROR", f"All 4 recovery levels exhausted — retry in {recovery_retry_interval}s")
                            self._notify_async(
                                title="🔴 VPN Recovery FAILED",
                                body=(
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"    🖥️  Host: {host}\n"
                                    f"    ⏱️  Down for: {fmt}\n"
                                    f"    📍  {reason}\n"
                                    f"    🔁  Retrying every {recovery_retry_interval}s"
                                ),
                                priority="urgent",
                                tags="sos",
                            )
                    else:
                        elapsed   = now_ts - last_recovery_at
                        remaining = recovery_retry_interval - elapsed
                        if remaining <= 0:
                            self._log("INFO", f"VPN still down after {int(elapsed)}s — re-attempting recovery ...")
                            fmt_so_far = self._format_duration(now_ts - (down_since or now_ts))
                            self._notify_async(
                                title="🔴 VPN Still Down — Retrying",
                                body=(
                                    f"━━━━━━━━━━━━━━━━━━━━\n"
                                    f"    🖥️  Host: {host}\n"
                                    f"    ⏱️  Down for: {fmt_so_far}\n"
                                    f"    ⚡  Starting new recovery attempt"
                                ),
                                priority="high",
                                tags="rotating_light",
                            )
                            last_recovery_at = now_ts
                            self._flush_conntrack()
                            recovered, level = self._attempt_recovery(cfg, iface, recovery_wait)
                            _now = time.time()
                            fmt  = self._format_duration(_now - (down_since or _now))
                            if recovered:
                                was_healthy   = True
                                down_since    = None
                                stall_tracker = None
                                self._notify_async(
                                    title=f"🟢 VPN Recovered (level {level}/4)",
                                    body=(
                                        f"━━━━━━━━━━━━━━━━━━━━\n"
                                        f"    🖥️  Host: {host}\n"
                                        f"    ⚡  Recovery level: {level}/4\n"
                                        f"    ⏱️  Down for: {fmt}"
                                    ),
                                    priority="high",
                                    tags="white_check_mark",
                                )
                            else:
                                self._log("ERROR", f"Retry failed — next attempt in {recovery_retry_interval}s")
                                self._notify_async(
                                    title="🔴 VPN Recovery Retry FAILED",
                                    body=(
                                        f"━━━━━━━━━━━━━━━━━━━━\n"
                                        f"    🖥️  Host: {host}\n"
                                        f"    ⏱️  Down for: {fmt}\n"
                                        f"    🔁  Next retry in {recovery_retry_interval}s"
                                    ),
                                    priority="high",
                                    tags="sos",
                                )
                        else:
                            self._log("WARN", f"VPN still down: next retry in {int(remaining)}s")

            except Exception as exc:
                self._log("ERROR", f"Watchdog loop error: {exc}")

            time.sleep(check_interval)


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point: ``python3 -m daemons.watchdog <daemon|status|health>``."""
    import argparse
    parser = argparse.ArgumentParser(description="NFT Watchdog Daemon")
    parser.add_argument(
        "command",
        choices=["daemon", "status", "health"],
        help="daemon: run the loop | status: one-shot human summary | health: JSON health dict",
    )
    parser.add_argument(
        "--config",
        default="/etc/nft-watchdog.conf",
        help="Path to watchdog config (default: /etc/nft-watchdog.conf)",
    )
    args = parser.parse_args()

    wd = NftWatchdog(config_path=args.config)
    if args.command == "daemon":
        wd.run_daemon()
    elif args.command == "status":
        wd.status()
    elif args.command == "health":
        report = wd.health()
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["status"] == "HEALTHY" else 1)


if __name__ == "__main__":
    main()
