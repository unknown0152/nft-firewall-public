# NFT Firewall AI Context

Last updated: 2026-06-14

This repository contains the nft-firewall source tree. On a deployed host,
operator-specific topology, runtime state, and local history should be kept in
ignored local files or host backup artifacts rather than committed to a public
repository.

## Runtime Paths

- Local deployed source tree: `/opt/nft-firewall`
- Live config: `config/firewall.ini` (local-only; use `config/firewall.ini.example` for publication)
- Dynamic set state: `/var/lib/nft-firewall/dynamic-sets.json`
- Dynamic set audit log: `/var/log/nft-firewall/audit.jsonl`
- Boot ruleset: `/etc/nftables.conf`
- Watchdog marker state: `/var/lib/nft-firewall/watchdog-markers.json`

## Architecture

- `src/core/rules.py` is a pure nftables ruleset generator. It must not apply
  firewall changes, mutate state, read config files, or notify users.
- `src/core/state.py` owns side effects: apply, save, backup, restore, live
  nftables set mutation, and best-effort audit logging for those mutations.
- `src/main.py` loads config, builds `RulesetConfig`, runs doctor checks, and
  dispatches CLI commands.
- `src/daemons/watchdog.py` checks WireGuard health, killswitch markers, and
  the persisted ruleset checksum when marker metadata is available.
- `src/daemons/listener.py` handles Keybase ChatOps through an allowlist.
- `src/daemons/ssh_alert.py` tails auth/fail2ban logs and can auto-block IPs.

## Security Invariants

- IPv6 is dropped by `table ip6 killswitch`.
- Host internet egress is only accepted through `wg0`, except loopback, LAN,
  DHCP, bridge-local traffic, and WireGuard bootstrap traffic.
- Docker must keep `iptables=false` and `ip6tables=false`.
- Docker/container internet egress is only accepted through `wg0`.
- Input policy is default drop.
- `geowhitelist_ips` is a source gate only. It must never emit a blanket
  `ip saddr @geowhitelist_ips accept` rule.
- Physical-interface TCP 80/443 is acceptable only when source restricted, for
  example to LAN or `@geowhitelist_ips`.
- The watchdog marker `comment "nft-killswitch-output"` must remain on the
  broad `oifname "wg0"` output accept rule.

## Current Refactor State

Completed in this deployment:

- Removed blanket geowhitelist accept generation.
- Geowhitelist now gates only explicit TCP services: SSH and configured 80/443.
- Doctor no longer reports LAN/source-restricted 80/443 as public exposure.
- Added regression tests for geowhitelist and doctor invariants.
- Restored source `systemd/` templates and `setup.sh` so the deployed source
  tree matches the expectations of packaging and user-model tests.
- Added `pyproject.toml` with pytest and coverage metadata.
- Keybase listener polling is configurable through `[listener] poll_interval`.
  This host is set to 15 seconds to reduce sudo/journal noise while preserving
  ChatOps behavior.
- Dynamic set mutations append JSONL audit records to
  `/var/log/nft-firewall/audit.jsonl` after successful live nft mutation and
  persistence update. The `/var/lib/nft-firewall/dynamic-sets.json` format is
  unchanged.
- Watchdog markers now include a SHA-256 stamp for `/etc/nftables.conf` after
  successful apply. The watchdog reports missing checksum metadata as
  `untracked` for backward compatibility, but treats a present mismatch as
  degraded and will not auto-repair from a mismatched persisted ruleset.
- `fw doctor` includes an incremental ConfigParser-based sanity check for
  explicitly configured topology, CIDR, boolean, port, listener, watchdog, and
  safety values. This does not replace ConfigParser or change apply behavior.
- Ruff is available as optional local developer tooling. The current lint scope
  is intentionally narrow (`F821`, `F822`, `F823`) to catch undefined-name
  defects without broad style churn.
- Current unit status: `198 passed`; current `src/core` coverage: `90.93%`.

Pending larger refactor work:

- Pydantic settings model.
- Typer or Click CLI while preserving `fw` command compatibility.
- Structured logging for daemons and CLI output.
- Systemd unit template generation and packaging.
