# Changelog

## Unreleased

### Security

- Hardened geowhitelist lockdown mode. `geowhitelist_ips` no longer creates a
  blanket physical-interface accept rule. It now allows only explicit TCP
  services from whitelisted sources: SSH and configured web ingress on 80/443.
- Preserved default-drop behavior for all other non-LAN physical-interface
  traffic in lockdown mode.
- Added persisted ruleset checksum verification for watchdog-managed
  auto-repair. `watchdog-markers.json` now records the SHA-256 of
  `/etc/nftables.conf` after successful apply; a mismatch degrades health and
  prevents auto-repair from loading a drifted persisted ruleset.

### Fixed

- Fixed `fw doctor` false positives for source-restricted physical-interface
  80/443 rules, including LAN-only and geowhitelist-gated rules.
- Isolated doctor unit tests from the host's live ruleset so mocked interface
  names do not conflict with the deployed physical interface.
- Made Keybase listener polling configurable with bounded parsing. This
  deployment now uses `[listener] poll_interval = 15` to reduce journal/sudo
  noise without changing command authorization or firewall behavior.

### Added

- Added best-effort JSONL audit logging for successful dynamic set mutations
  at `/var/log/nft-firewall/audit.jsonl`. This records actor, uid/euid,
  action, set name, item count, and mutated items without changing
  `/var/lib/nft-firewall/dynamic-sets.json`.
- Extended watchdog health output with persisted ruleset integrity status:
  `ok`, `untracked`, `missing`, or `mismatch`.
- Added a `fw doctor` config sanity check for explicitly configured topology,
  CIDR, boolean, port, listener, watchdog, and safety values while preserving
  the existing ConfigParser-based configuration flow.
- Added a narrow Ruff developer check for undefined-name diagnostics only, so
  maintenance can catch high-signal Python mistakes without broad style churn.

### Tests

- Added regression coverage proving geowhitelist cannot emit
  `ip saddr @geowhitelist_ips accept`.
- Added doctor invariant tests for source-restricted versus unrestricted
  physical-interface web exposure.
- Added state-management tests for ruleset simulation, apply failure cleanup,
  config persistence, backup/restore, dynamic set persistence, set mutation,
  and audit logging.
- Added watchdog checksum tests for backward-compatible untracked markers,
  matching checksums, mismatches, and missing persisted rulesets.
- Added config sanity tests for clean configs, malformed operator values, and
  `fw doctor` failure reporting.
- `scripts/dev-check.sh` now runs the local Ruff check when Ruff is installed.
- Restored missing source `systemd/` templates and `setup.sh` so the full unit
  suite runs cleanly from `/opt/nft-firewall`.
- Added `pyproject.toml` with pytest and coverage configuration.

### Operational Notes

- Applied with `safe-apply` on 2026-06-14. Backup:
  `/opt/nft-firewall/state/nftables_20260614_194815.conf`.
- Full unit suite: `198 passed`.
- Core coverage: `90.93%`, above the 80% target.
