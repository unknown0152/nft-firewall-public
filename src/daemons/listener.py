"""
src/daemons/listener.py — Keybase ChatOps bot for nft-firewall.

Polls `keybase chat api` for unread messages and dispatches recognised
!commands by calling `sudo python3 src/main.py <cmd>`.  Only messages from
the configured ``authorized_user`` are acted upon; all others are logged and
silently dropped.

Supported chat commands
-----------------------
    !help                   — list available commands
    !status                 — watchdog health report (JSON)
    !rules                  — live nftables ruleset
    !ip-list                — blocked and trusted IP sets
    !block <ip>             — block an IP/CIDR at runtime
    !unblock <ip>           — remove from block list
    !allow <ip> [dur]       — grant 80/443 + SSH access, optional expiry (48h/30m/7d)
    !unallow <ip>           — remove from trusted set

Usage (systemd ExecStart)
-------------------------
    python3 src/main.py listener daemon
"""

from __future__ import annotations

import configparser
import hmac
import json
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

# ── Paths ─────────────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_LOCAL_CONF   = _PROJECT_ROOT / "config" / "firewall.ini"
_SYSTEM_CONF  = Path("/etc/nft-watchdog.conf")
_MAIN_PY      = _PROJECT_ROOT / "src" / "main.py"

POLL_INTERVAL: int = 5   # default seconds between Keybase API polls
MIN_POLL_INTERVAL: int = 5
MAX_POLL_INTERVAL: int = 300


# ── Pure helpers (stateless, unit-testable) ───────────────────────────────────

def parse_kb_event(line: str) -> Optional[Dict]:
    """Parse one JSON line from ``keybase chat api``.

    Returns a dict with ``sender``, ``body``, ``channel`` for remote text
    messages only.  Returns ``None`` for local echoes, non-text events, empty
    bodies, or parse errors.

    Parameters
    ----------
    line:
        Raw JSON string from the Keybase API.
    """
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None

    if obj.get("source") != "remote":
        return None
    msg = obj.get("msg")
    if not msg:
        return None
    content = msg.get("content", {})
    if content.get("type") != "text":
        return None
    body = content.get("text", {}).get("body", "").strip()
    if not body:
        return None
    return {
        "sender" : msg.get("sender", {}).get("username", ""),
        "body"   : body,
        "channel": msg.get("channel", {}),
    }


def is_authorized(sender: str, allowed: str) -> bool:
    """Return ``True`` only when *sender* matches *allowed*.

    Uses :func:`hmac.compare_digest` for constant-time comparison to prevent
    timing-based username enumeration.
    """
    if not allowed or not isinstance(allowed, str) or not isinstance(sender, str):
        return False
    return hmac.compare_digest(sender, allowed)


def strip_ansi(text: str) -> str:
    """Remove ANSI colour/formatting escape sequences from *text*."""
    return re.sub(r"\033\[[0-9;]*[A-Za-z]", "", text)


def validate_ip(ip_str: str) -> bool:
    """Return ``True`` if *ip_str* is a structurally valid IPv4 address/CIDR."""
    from utils.validation import validate_ipv4_network
    return validate_ipv4_network(ip_str.strip()).ok


def validate_duration_str(value: str) -> bool:
    """Return ``True`` if *value* is a valid nft timeout duration (48h, 30m, 7d)."""
    from utils.validation import validate_duration
    return validate_duration(value.strip()).ok


def parse_poll_interval(value: object, default: int = POLL_INTERVAL) -> int:
    """Parse and clamp the Keybase polling interval.

    The listener is operationally important, so malformed config must fall back
    to the known-compatible default instead of stopping ChatOps. Bounds prevent
    accidental log storms or hour-long blind spots.
    """
    try:
        interval = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(MIN_POLL_INTERVAL, min(MAX_POLL_INTERVAL, interval))


# ── ChatOps capabilities whitelist ────────────────────────────────────────────

class _CmdSpec(NamedTuple):
    """Declarative specification for one permitted ChatOps command."""
    cli_subcmd : str        # first arg passed to main.py (must be in _KNOWN_SAFE_SUBCMDS)
    needs_ip   : bool       # True → require exactly one validated IP/CIDR argument
    ok_fmt     : str        # .format(ip=..., host=..., dur=...) for success; "" → use CLI output
    fail_fmt   : str        # .format(ip=..., host=...) prefix for failure; "" → generic
    allows_duration : bool = False  # True → accept an optional trailing nft duration


# Hard-coded ground-truth of safe CLI subcommands.  Every entry in _CMD_WHITELIST
# must resolve to one of these.  Adding "apply", "docker-expose", etc. here
# would be a deliberate security decision, not an accident.
_KNOWN_SAFE_SUBCMDS: frozenset = frozenset({
    "block", "unblock", "allow", "disallow",
    "status", "rules", "ip-list", "access",
})

# Declarative whitelist — the ONLY commands the listener may dispatch.
# Any !verb not present is dropped with a [SECURITY] log line (default-deny).
_CMD_WHITELIST: Dict[str, _CmdSpec] = {
    "!block"  : _CmdSpec("block",    True,  "Blocked `{ip}` on {host} ✓",                 "Block failed for `{ip}`"),
    "!unblock": _CmdSpec("unblock",  True,  "Unblocked `{ip}` on {host} ✓",               "Unblock failed for `{ip}`"),
    "!allow"  : _CmdSpec("allow",    True,  "Allowed `{ip}` {dur} on {host} ✓",           "Allow failed for `{ip}`", True),
    "!unallow": _CmdSpec("disallow", True,  "Removed `{ip}` from trusted on {host} ✓",    "Unallow failed for `{ip}`"),
    "!status" : _CmdSpec("status",   False, "",                                             ""),
    "!rules"  : _CmdSpec("rules",    False, "",                                             ""),
    "!ip-list": _CmdSpec("ip-list",  False, "",                                             ""),
    "!access" : _CmdSpec("access",   False, "",                                             ""),
}

# Derived from _CMD_WHITELIST so _run_cli and the table can never diverge.
# The assert below fires at import time if anyone adds a subcmd not in _KNOWN_SAFE_SUBCMDS.
_SAFE_SUBCOMMANDS: frozenset = frozenset(s.cli_subcmd for s in _CMD_WHITELIST.values())
assert _SAFE_SUBCOMMANDS <= _KNOWN_SAFE_SUBCMDS, (
    f"_CMD_WHITELIST contains subcommands not in _KNOWN_SAFE_SUBCMDS: "
    f"{_SAFE_SUBCOMMANDS - _KNOWN_SAFE_SUBCMDS}"
)


# ── Daemon class ──────────────────────────────────────────────────────────────

class KeybaseListener:
    """Keybase ChatOps bot — polls for !commands and dispatches them to the CLI.

    Attributes
    ----------
    config_path:
        Path to the INI config file.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config_path: str = config_path or (
            str(_LOCAL_CONF) if _LOCAL_CONF.exists() else str(_SYSTEM_CONF)
        )
        self._processed: set = set()

    # ── Public API ────────────────────────────────────────────────────────────

    def run_daemon(self) -> None:
        """Start the ChatOps polling loop (systemd ExecStart entry point).

        Runs as fw-admin; privileged commands are executed via sudo.
        Blocks indefinitely.
        """
        cfg        = self._load_cfg()
        authorized = cfg["authorized_user"]
        host       = cfg["host"]

        if not authorized or authorized in ("your-keybase-username", ""):
            print("[ERROR] keybase.target_user not set in config — exiting", flush=True)
            sys.exit(1)

        start_ts = time.time()
        poll_interval = cfg["poll_interval"]
        print(f"[INFO] nft-listener started — authorized: {authorized!r} host: {host}", flush=True)
        print(f"[INFO] Polling every {poll_interval}s | dispatching via {_MAIN_PY}", flush=True)

        while True:
            sleep_for = POLL_INTERVAL
            try:
                cfg = self._load_cfg()    # live reload each tick
                sleep_for = cfg["poll_interval"]
                self._poll_once(cfg, start_ts)
            except Exception as exc:
                print(f"[ERROR] Poll error: {exc}", flush=True)
            time.sleep(sleep_for)

    # ── Config ────────────────────────────────────────────────────────────────

    def _load_cfg(self) -> Dict:
        c = configparser.ConfigParser()
        c.read(self.config_path)
        return {
            "authorized_user": c.get("keybase", "target_user", fallback="").strip(),
            "linux_user"     : c.get("keybase", "linux_user",  fallback="").strip(),
            "team"           : c.get("keybase", "team",        fallback="").strip(),
            "host"           : c.get("watchdog", "hostname",   fallback=os.uname().nodename),
            "poll_interval"  : parse_poll_interval(
                c.get("listener", "poll_interval", fallback=str(POLL_INTERVAL))
            ),
        }

    # ── Keybase subprocess helpers ────────────────────────────────────────────

    def _get_kb_user(self, cfg: Dict) -> Tuple[str, int, str]:
        """Return ``(linux_username, uid, home_dir)`` for the Keybase daemon user."""
        linux_user = cfg.get("linux_user", "").strip()
        if not linux_user:
            for pw in sorted(pwd.getpwall(), key=lambda p: p.pw_uid):
                if pw.pw_uid >= 1000 and Path(pw.pw_dir, ".config", "keybase").exists():
                    linux_user = pw.pw_name
                    break
        if not linux_user:
            for pw in sorted(pwd.getpwall(), key=lambda p: p.pw_uid):
                if pw.pw_uid >= 1000 and pw.pw_shell not in ("/usr/sbin/nologin", "/bin/false", ""):
                    linux_user = pw.pw_name
                    break
        try:
            pw = pwd.getpwnam(linux_user)
            return pw.pw_name, pw.pw_uid, pw.pw_dir
        except KeyError:
            print(f"[ERROR] Cannot find system user '{linux_user}'", flush=True)
            sys.exit(1)

    def _kb_prefix(self, cfg: Dict) -> List[str]:
        """Build the ``sudo /usr/local/bin/nft-keybase-notify`` prefix.

        Uses a root-owned wrapper script so that the sudoers rule can match an
        exact command path while the wrapper opens the Keybase user's login
        session.
        """
        self._get_kb_user(cfg)
        return ["sudo", "/usr/local/bin/nft-keybase-notify"]

    def _send_reply(self, cfg: Dict, channel: Dict, body: str) -> None:
        """Send *body* to *channel* via ``keybase chat api``."""
        payload = json.dumps({
            "method": "send",
            "params": {"options": {"channel": channel, "message": {"body": body}}},
        })
        cmd = self._kb_prefix(cfg) + ["chat", "api", "-m", payload]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                print(f"[WARN] send_reply failed: {r.stderr.strip()}", flush=True)
        except Exception as exc:
            print(f"[WARN] send_reply exception: {exc}", flush=True)

    # ── Poll ──────────────────────────────────────────────────────────────────

    def _list_all_convos(self, cfg: Dict) -> List[Dict]:
        """Fetch all active conversations. If no team, specifically prioritize DMs."""
        payload = json.dumps({"method": "list", "params": {"options": {"topic_type": "chat"}}})
        cmd = self._kb_prefix(cfg) + ["chat", "api", "-m", payload]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                print(f"[WARN] list failed (rc={r.returncode}): {r.stderr.strip()}", flush=True)
                return []
            
            res = json.loads(r.stdout).get("result", {}).get("conversations") or []
            
            # If no team is set, we need to make sure we include DMs from the target user.
            # Keybase chat api list usually returns everything, but filtering by topic_type helps.
            return res
        except Exception as exc:
            print(f"[WARN] _list_all_convos: {exc}", flush=True)
            return []

    def _read_recent_msgs(self, cfg: Dict, channel: Dict, num: int = 20) -> List[Dict]:
        payload = json.dumps({
            "method": "read",
            "params": {"options": {"channel": channel, "pagination": {"num": num}}},
        })
        cmd = self._kb_prefix(cfg) + ["chat", "api", "-m", payload]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return []
            return json.loads(r.stdout).get("result", {}).get("messages") or []
        except Exception as exc:
            print(f"[WARN] _read_recent_msgs: {exc}", flush=True)
            return []

    def _poll_once(self, cfg: Dict, start_ts: float) -> int:
        """Check all conversations for new !commands since *start_ts*.

        Returns the number of commands dispatched.
        """
        authorized = cfg.get("authorized_user", "").strip()
        if not authorized or authorized == "your-keybase-username":
            print("[SECURITY] Authorization is not configured; poll skipped", flush=True)
            return 0

        count = 0
        for convo in self._list_all_convos(cfg):
            channel   = convo.get("channel", {})
            active_at = convo.get("active_at", 0)
            if active_at and active_at < start_ts:
                continue
            for item in self._read_recent_msgs(cfg, channel):
                msg     = item.get("msg", {})
                msg_id  = msg.get("id", 0)
                sent_at = msg.get("sent_at", 0)
                if msg_id in self._processed:
                    continue
                self._processed.add(msg_id)
                if sent_at < start_ts:
                    continue
                content = msg.get("content", {})
                if content.get("type") != "text":
                    continue
                body = content.get("text", {}).get("body", "").strip()
                if not body or not body.startswith("!"):
                    continue
                
                sender = msg.get("sender", {}).get("username", "")
                
                # CRITICAL: Ignore our own messages to prevent loops (local echo)
                # Must go through the sudo wrapper — this daemon's user has no
                # Keybase session of its own, so a bare `keybase whoami` fails.
                try:
                    if getattr(self, "_own_username", None) is None:
                        self._own_username = subprocess.check_output(
                            self._kb_prefix(cfg) + ["whoami"],
                            text=True, timeout=20, stderr=subprocess.DEVNULL,
                        ).strip()
                    if sender == self._own_username:
                        continue
                except: pass

                event = {
                    "sender" : sender,
                    "body"   : body,
                    "channel": msg.get("channel", channel),
                }
                if not is_authorized(event["sender"], authorized):
                    print(f"[SECURITY] Ignored message from unauthorized user: {event['sender']!r}", flush=True)
                    continue
                print(f"[CMD] {event['sender']}: {event['body']!r}", flush=True)
                self._dispatch(cfg, event)
                count += 1
        return count

    # ── Command dispatch ──────────────────────────────────────────────────────

    def _run_cli(self, *args: str, timeout: int = 30) -> Tuple[int, str]:
        """Run ``sudo python3 src/main.py <args>`` and return ``(returncode, output)``.

        Guards:
        - ``args[0]`` must be in ``_SAFE_SUBCOMMANDS`` (derived from ``_CMD_WHITELIST``).
        - At most 2 arguments are permitted (subcommand + one optional IP/CIDR).
          Any call with 3+ args is a structural error and is blocked unconditionally.
        """
        if not args:
            print("[SECURITY] _run_cli called with no arguments — blocked", flush=True)
            return 1, "Internal error: no subcommand specified"

        subcmd = args[0]
        if subcmd not in _SAFE_SUBCOMMANDS:
            print(f"[SECURITY] Blocked non-whitelisted CLI subcommand: {subcmd!r}", flush=True)
            return 1, f"Command not permitted: {subcmd!r}"

        max_args = 3 if subcmd == "allow" else 2   # allow: subcmd + ip + optional duration
        if len(args) > max_args:
            print(f"[SECURITY] Too many arguments for {subcmd!r}: {args!r} — blocked", flush=True)
            return 1, f"Too many arguments supplied for {subcmd!r}"

        fw = "/usr/local/bin/fw"
        if Path(fw).exists():
            cmd = ["sudo", fw] + list(args)
        else:
            cmd = ["sudo", "python3", str(_MAIN_PY)] + list(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = strip_ansi((r.stdout or r.stderr or "(no output)").strip())
            return r.returncode, output
        except subprocess.TimeoutExpired:
            return 1, f"Command timed out after {timeout}s"
        except Exception as exc:
            return 1, str(exc)

    def _dispatch(self, cfg: Dict, event: Dict) -> None:
        """Route a single validated chat event to the appropriate CLI call.

        All routing is driven by ``_CMD_WHITELIST``.  Any verb not present in
        that dict is dropped with a ``[SECURITY]`` log entry and no reply
        (default-deny: do not enumerate the valid command surface to callers).
        """
        channel = event["channel"]
        body    = event["body"].strip()
        host    = cfg["host"]
        sender  = event["sender"]

        # ── Special in-process handlers (never touch main.py subprocess) ──────

        if body == "!help":
            self._send_reply(cfg, channel, (
                "*Available commands:*\n"
                "`!status` — full status dashboard\n"
                "`!top` — Wall of Shame: top attacking countries + persistent IPs\n"
                "`!rules` — live nftables ruleset\n"
                "`!ip-list` — blocked + trusted IPs\n"
                "`!block <ip>` — block an IP/CIDR\n"
                "`!unblock <ip>` — remove from block list\n"
                "`!allow <ip> [dur]` — grant 80/443 + SSH access (e.g. `!allow 1.2.3.4 48h`)\n"
                "`!access` — who currently has 80/443 access + time remaining\n"
                "`!unallow <ip>` — remove from trusted set"
            ))
            print("[CMD] help -> ok", flush=True)
            return

        if body == "!top":
            try:
                _root = Path(__file__).resolve().parent.parent.parent
                import sys as _sys
                if str(_root / "src") not in _sys.path:
                    _sys.path.insert(0, str(_root / "src"))
                from utils.analytics import build_top_report
                reply = build_top_report()
            except Exception as exc:
                reply = f"!top failed: {exc}"
            self._send_reply(cfg, channel, reply)
            print("[CMD] !top -> ok", flush=True)
            return

        # ── Whitelist lookup ───────────────────────────────────────────────────
        # Split into at most two tokens: the verb and an optional argument.
        # maxsplit=1 means any trailing tokens stay joined to `arg`, so
        # "!block 1.2.3.4 extra" yields arg="1.2.3.4 extra", which
        # validate_ip() correctly rejects as a non-network string.
        parts = body.split(None, 1)
        verb  = parts[0]
        arg   = parts[1].strip() if len(parts) == 2 else None

        spec = _CMD_WHITELIST.get(verb)
        if spec is None:
            print(f"[SECURITY] Default-deny: unknown command {verb!r} from {sender!r}",
                  flush=True)
            # Only authorized senders reach dispatch (is_authorized() gates in
            # _poll_once), so a hint here enumerates nothing to strangers.
            self._send_reply(cfg, channel, f"Unknown command `{verb}` — try `!help`")
            return

        # ── Argument validation ────────────────────────────────────────────────
        duration: Optional[str] = None
        if spec.needs_ip:
            if arg is None:
                usage = f"`{verb} <ip_or_cidr> [duration]`" if spec.allows_duration else f"`{verb} <ip_or_cidr>`"
                self._send_reply(cfg, channel, f"Usage: {usage}")
                return
            tokens = arg.split()
            ip_arg = tokens[0]
            if not validate_ip(ip_arg):
                print(f"[SECURITY] Invalid IP/CIDR {ip_arg!r} from {sender!r} — rejected",
                      flush=True)
                self._send_reply(cfg, channel, f"Invalid IP or CIDR: `{ip_arg}`")
                return
            if len(tokens) == 2 and spec.allows_duration:
                if not validate_duration_str(tokens[1]):
                    print(f"[SECURITY] Invalid duration {tokens[1]!r} from {sender!r} — rejected",
                          flush=True)
                    self._send_reply(cfg, channel,
                                     f"Invalid duration: `{tokens[1]}` (try 48h, 30m, 7d)")
                    return
                duration = tokens[1]
            elif len(tokens) > 1:
                # extra/unexpected tokens beyond ip (+ optional duration) → reject
                print(f"[SECURITY] Too many arguments for {verb!r} from {sender!r}: "
                      f"{arg!r} — rejected", flush=True)
                self._send_reply(cfg, channel, f"`{verb}` takes an IP and an optional duration.")
                return
            arg = ip_arg
        else:
            if arg is not None:
                # A no-arg command with a trailing token is anomalous.
                print(f"[SECURITY] Unexpected argument for {verb!r} from {sender!r}: "
                      f"{arg!r} — rejected", flush=True)
                self._send_reply(cfg, channel, f"`{verb}` takes no arguments.")
                return

        # ── Execute via hardened _run_cli ──────────────────────────────────────
        if not spec.needs_ip:
            cli_args = (spec.cli_subcmd,)
        elif duration is not None:
            cli_args = (spec.cli_subcmd, arg, duration)
        else:
            cli_args = (spec.cli_subcmd, arg)
        rc, out  = self._run_cli(*cli_args)

        if len(out) > 8000:
            out = out[:8000] + "\n…(truncated)"

        if rc == 0:
            dur_txt = f"for {duration}" if duration else "permanently" if spec.allows_duration else ""
            reply = (spec.ok_fmt.format(ip=arg, host=host, dur=dur_txt)
                     if spec.ok_fmt else f"```\n{out}\n```")
            print(f"[CMD] {verb} {arg or ''} -> ok".strip(), flush=True)
        else:
            reply = (f"{spec.fail_fmt.format(ip=arg, host=host)}: {out}"
                     if spec.fail_fmt else f"{verb} failed (rc={rc}):\n```\n{out}\n```")
            print(f"[CMD] {verb} {arg or ''} -> FAILED rc={rc}".strip(), flush=True)

        self._send_reply(cfg, channel, reply)
