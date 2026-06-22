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

- Changed the curl entrypoint to clone the public Git repository and run
  `setup.sh` from that checkout instead of fetching a second raw GitHub script.
  The installer now prints the checked-out commit and supports
  `NFT_FIREWALL_REF`, `NFT_FIREWALL_BRANCH`, and `NFT_FIREWALL_REPO_URL`.
- Added update-only installer mode with existing `firewall.ini` preservation,
  post-install validation, and no configuration wizard.
- Quieted update-only installer noise when `fw-admin` is already running
  services and when Keybase is not logged in.
- Fixed `fw doctor` false positives for source-restricted physical-interface
  80/443 rules, including LAN-only and geowhitelist-gated rules.
- Isolated doctor unit tests from the host's live ruleset so mocked interface
  names do not conflict with the deployed physical interface.
- Made Keybase listener polling configurable with bounded parsing to reduce
  journal/sudo noise without changing command authorization or firewall
  behavior.
- Removed Debian 13 bootstrap package assumptions that caused noisy or unsafe
  clean-host behavior: `wireguard-dkms` is no longer requested, and
  `openresolv` is no longer installed by default so `systemd-resolved` is not
  replaced.
- Optional Cosmos integration now simulates the generated nftables ruleset
  before any automatic apply. If required runtime interfaces such as `wg0` are
  missing, it reports the validation failure and skips automatic apply.

### Added

- Added guided installer modes for update-only, core firewall, Cosmos/media,
  full server, and full server with interactive Keybase login.
- Added smarter Keybase preparation during install/update: the installer starts
  the configured user's Keybase service with `run_keybase -g`, then optionally
  launches interactive `keybase login` when requested.
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
- Added public `install.sh` curl entrypoint:
  `curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash`
- Added optional curl install flow for Cosmos/Keybase integration via
  `--with-integrations`.
- Added clean-host safety tests for the public bootstrap URL, local install
  entrypoint preservation, Debian 13 package list, and simulate-before-apply
  behavior.

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
- Clean Debian 13 VM validation covered core bootstrap, interactive config
  wizard, systemd unit deployment, sudoers validation, optional Cosmos
  standalone service install, DNS preservation, no Cosmos iptables mutation,
  safe skip when `wg0` is missing, and successful ruleset apply with a dummy
  `wg0` interface.

### Operational Notes

- Public export excludes live config, runtime state, generated rulesets,
  backup artifacts, logs, and host-local history.
- Current local `make check`: passing.
- Current unit collection: `251` tests.
- Core coverage target remains 80% for `src/core`.
