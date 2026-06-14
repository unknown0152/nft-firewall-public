"""
src/utils/keybase.py — Shared Keybase chat notification helper.

Public API
----------
    from utils.keybase import notify

    success = notify(
        title="WireGuard down",
        body="Tunnel wg0 has not recovered after 60 s",
        tags="rotating_light,sos",
        priority="high",
    )

Config is read from (in order):
    1. <project_root>/config/firewall.ini   [keybase] section
    2. /etc/nft-watchdog.conf               [keybase] section

[keybase] section keys
----------------------
    team          — Keybase team name  (team mode, recommended)
    target_user   — Keybase username   (DM mode, fallback)
    channel       — default channel    (default: general)
    linux_user    — Linux user running the keybase daemon (auto-detected if absent)
"""

import configparser
import pwd
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

# ── Config paths ──────────────────────────────────────────────────────────────

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_LOCAL_CONF   = _PROJECT_ROOT / "config" / "firewall.ini"
_SYSTEM_CONF  = Path("/etc/nft-watchdog.conf")

_RETRY_DELAYS: Tuple[int, ...] = (0, 3, 8)


# ── Private helpers ───────────────────────────────────────────────────────────

def _load_config() -> configparser.ConfigParser:
    """Load keybase config, preferring the local project config over the system one."""
    cfg = configparser.ConfigParser()
    if _LOCAL_CONF.exists():
        cfg.read(str(_LOCAL_CONF))
    elif _SYSTEM_CONF.exists():
        cfg.read(str(_SYSTEM_CONF))
    return cfg


def _detect_target(cfg: configparser.ConfigParser) -> Optional[Tuple[str, str, str]]:
    """Return (team, target_user, channel) or None if Keybase is not configured.

    Team mode  — posts to <team>#<channel>  (recommended)
    DM mode    — posts directly to target_user  (fallback)
    """
    team    = cfg.get("keybase", "team",        fallback="").strip()
    user    = cfg.get("keybase", "target_user", fallback="").strip()
    channel = cfg.get("keybase", "channel",     fallback="general").strip()

    if team and team != "your-team-name":
        return (team, "", channel)
    if user and user != "your-keybase-username":
        return ("", user, channel)
    return None


def _detect_linux_user(cfg: configparser.ConfigParser) -> str:
    """Return the Linux username running the Keybase daemon.

    Detection order:
        1. ``linux_user`` key in config
        2. Owner of ``~/.config/keybase`` among UID≥1000 accounts
        3. First interactive UID≥1000 account
        4. Fallback: ``"nobody"``
    """
    explicit = cfg.get("keybase", "linux_user", fallback="").strip()
    if explicit:
        try:
            pwd.getpwnam(explicit)
            return explicit
        except KeyError:
            print(f"[keybase] WARNING: linux_user '{explicit}' not found — auto-detecting")

    candidates = sorted(
        (p for p in pwd.getpwall() if p.pw_uid >= 1000),
        key=lambda p: p.pw_uid,
    )

    for pw in candidates:
        if Path(pw.pw_dir, ".config", "keybase").exists():
            return pw.pw_name

    dead_shells = {"/usr/sbin/nologin", "/bin/false", ""}
    for pw in candidates:
        if pw.pw_shell not in dead_shells:
            return pw.pw_name

    return "nobody"


def _channel_for_tags(tags: str, title: str) -> str:
    """Route a notification to the appropriate Keybase channel based on tags/title."""
    tags_l  = (tags  or "").lower()
    title_l = (title or "").lower()

    if "rotating_light" in tags_l or "sos" in tags_l:
        return "vpn-down"
    if "white_check_mark" in tags_l and any(
            w in title_l for w in ("restored", "recovered", "back up")):
        return "vpn-up"
    if "ssh" in title_l or "login" in title_l:
        return "ssh"
    return "general"


# ── Public API ────────────────────────────────────────────────────────────────

def notify(title: str, body: str, tags: str = "", priority: str = "default") -> bool:
    """Send a Keybase chat message with up to 3 attempts.

    Parameters
    ----------
    title:    Short heading shown in bold at the top of the message.
    body:     Full message text.
    tags:     Comma-separated emoji shortcodes used for channel routing
              (e.g. ``"rotating_light,sos"``).
    priority: Informational string passed through for future use
              (e.g. ``"high"``, ``"default"``).  Not consumed by Keybase itself.

    Returns
    -------
    True if the message was delivered on any attempt, False if all 3 failed.
    """
    cfg     = _load_config()
    target  = _detect_target(cfg)

    if target is None:
        print("[keybase] WARNING: Keybase not configured — add [keybase] section to config")
        return False

    team, user, _default_channel = target
    channel     = _channel_for_tags(tags, title)
    full_message = f"*{title}*\n{body}"

    kb_user = _detect_linux_user(cfg)
    try:
        pw     = pwd.getpwnam(kb_user)
        kb_uid  = pw.pw_uid
        kb_home = pw.pw_dir
    except KeyError:
        print(f"[keybase] WARNING: cannot look up Linux user '{kb_user}'")
        return False

    # Use a wrapper script so sudo can match an exact command path.
    # Calling `sudo -u nuc env HOME=... keybase ...` makes sudo run /usr/bin/env,
    # which doesn't match a simple `NOPASSWD: /usr/bin/keybase` sudoers rule.
    # The wrapper sets HOME and XDG_RUNTIME_DIR then exec's keybase.
    sudo_prefix = ["sudo", "-u", kb_user, "/usr/local/bin/nft-keybase-notify"]

    if team:
        cmd  = sudo_prefix + ["chat", "send", "--channel", channel, team, full_message]
        dest = f"{team}#{channel}"
    else:
        cmd  = sudo_prefix + ["chat", "send", user, full_message]
        dest = user

    for attempt, delay in enumerate(_RETRY_DELAYS, start=1):
        if delay:
            time.sleep(delay)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                print(f"[keybase] OK → {dest}: {title!r} (attempt {attempt}/3)")
                return True
            print(f"[keybase] WARNING: attempt {attempt}/3 failed: {result.stderr.strip()}")
        except Exception as exc:
            print(f"[keybase] WARNING: attempt {attempt}/3 exception: {exc}")

    print(f"[keybase] WARNING: all 3 attempts failed for: {title!r}")
    return False
