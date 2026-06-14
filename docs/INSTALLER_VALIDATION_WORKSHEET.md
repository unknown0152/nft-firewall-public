# Internal Installer Validation Worksheet

This worksheet is for clean-VM engineering validation before any public
installation instructions are written. It is not a public install guide.

## Test Environment

- VM name:
- Snapshot name:
- Debian version:
- Kernel version:
- Date/time:
- Tester:
- Repo checkout path:
- Package baseline:
- Docker present: yes / no
- `/etc/wireguard/wg0.conf`: absent / IP endpoint / hostname endpoint
- Keybase present: yes / no
- Cosmos present: yes / no
- fail2ban present: yes / no
- Console access method:

## Preflight Checklist

- [ ] Console access confirmed.
- [ ] Snapshot taken before installer testing.
- [ ] Repo checkout is clean.
- [ ] `make check` result:
- [ ] `visudo` available:
- [ ] `nft` available:
- [ ] `wg` available:
- [ ] `systemctl` available:
- [ ] Existing `/etc/nftables.conf` noted/backed up if present:
- [ ] Existing `/etc/wireguard/wg0.conf` noted/backed up if present:

## Installer Execution Log

- Exact command run:
- Start time:
- End time:
- Exit code:
- Prompts observed:
- Values entered:
- Files/directories written:
- Users/groups created or modified:
- Sudoers changes observed:
- Unit files installed:
- Services/timers enabled or restarted:
- Did `/etc/wireguard/wg0.conf` change: yes / no / not present
- If changed, describe exactly what changed:
- Unexpected warnings/errors:

## Validation Checklist

- [ ] `fw doctor <profile>` result:
- [ ] `fw health` result:
- [ ] `fw simulate <profile>` result:
- [ ] nft syntax validation result:
- [ ] `systemctl` status summary for `nft-*` units:
- [ ] `/usr/local/bin/fw` present and executable:
- [ ] `/usr/local/lib/nft-firewall/` wrappers present and executable:
- [ ] `/etc/sudoers.d/nft-firewall` exists and validates:
- [ ] `/opt/nft-firewall` ownership/permissions checked:
- [ ] `/var/lib/nft-firewall` ownership/permissions checked:
- [ ] `/var/log/nft-firewall` ownership/permissions checked:
- [ ] `/etc/nftables.conf` present:
- [ ] `/etc/nftables.conf` syntax valid:
- [ ] Watchdog marker/state files present if expected:
- [ ] Dynamic set state file present if expected:
- Notes:

## Safe-Apply Test

Run only with console access and a fresh snapshot available.

- Profile tested:
- Rollback test command:
- Did rollback occur when `CONFIRM` was not entered: yes / no
- Host remained reachable after rollback: yes / no
- Confirmed apply command:
- Did confirmed apply persist rules: yes / no
- Host remained reachable after confirmed apply: yes / no
- `/etc/nftables.conf` updated and syntax valid: yes / no
- Observed behavior:

## Reboot Test

- Snapshot before reboot:
- Reboot command/time:
- Console access after reboot: yes / no
- `nftables.service` state:
- `nft-watchdog.service` state:
- `nft-listener.service` state:
- `nft-ssh-alert.service` state:
- Timer states:
- Firewall rules persisted: yes / no
- `fw health` after reboot:
- Degraded states observed:
- Notes:

## Uninstall Test

Use a separate snapshot for each uninstall path.

- Uninstall path tested: `setup.py uninstall` / `scripts/uninstall.sh --yes`
- Exact command:
- Exit code:
- Services/timers stopped or disabled:
- Files/directories removed:
- Files/directories intentionally preserved:
- Users/groups removed or preserved:
- `/etc/nftables.conf` final state:
- `/etc/wireguard/*.conf` preserved: yes / no / not present
- Host remained recoverable: yes / no
- Leftovers reported:
- Notes:

## Failure Capture

- Red flag encountered:
- Stage where failure occurred:
- Exact command:
- Exit code:
- Relevant logs:
  - `journalctl -u nft-watchdog -n 100 --no-pager`
  - `journalctl -u nft-listener -n 100 --no-pager`
  - `journalctl -u nft-ssh-alert -n 100 --no-pager`
  - installer output
  - `/var/log/nft-firewall/`
- Files to inspect:
  - `config/firewall.ini`
  - `/opt/nft-firewall/config/firewall.ini`
  - `/etc/nftables.conf`
  - `/etc/sudoers.d/nft-firewall`
  - `/etc/systemd/system/nft-*`
  - `/var/lib/nft-firewall/`
- Snapshot to restore:
- Testing must stop: yes / no
- Follow-up required:

## Final Outcome

- Outcome: PASS / FAIL / BLOCKED
- Supported target claim allowed from this run: yes / no
- Summary notes:
- Follow-up actions:
- Next environment to test:
