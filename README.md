# nft-firewall

`nft-firewall` is a low-level nftables firewall manager for Debian systems that
need a strict WireGuard killswitch, default-drop input policy, Docker isolation,
health checks, and operator tooling.

This project is intended for experienced Linux operators. It manages nftables
rules directly and can affect host connectivity. Review generated rules before
applying them, keep an out-of-band recovery path, and do not deploy it on a
production host without understanding the local network topology.

## Current Status

This repository is a public-safe source export from a real operational
deployment. The code, tests, systemd templates, and operator docs are included,
but live host configuration, runtime state, logs, backup artifacts, and private
history are intentionally excluded.

The curl bootstrap path has been tested on a clean Debian 13 systemd VM. The
tested path installs the core firewall tooling, deploys systemd units, installs
Cosmos as an optional standalone service, and validates ruleset generation. A
real WireGuard interface is still required before applying the production
killswitch policy on a real host.

## Features

- nftables ruleset generation with a default-drop input posture.
- WireGuard-oriented egress controls and killswitch health checks.
- IPv6 hard-drop killswitch support.
- Docker isolation when Docker is configured not to manage iptables itself.
- Dynamic nftables sets for block, trusted, and GeoIP-style source lists.
- Watchdog, listener, SSH alert, metrics, and report systemd templates.
- Optional Keybase notification and ChatOps integration.
- Local developer checks through Ruff, ShellCheck, and pytest.

## Public Repository Scope

This public repository intentionally excludes live host data. Do not commit:

- `config/firewall.ini`
- runtime state under `state/` or `/var/lib/nft-firewall/`
- generated `/etc/nftables.conf` copies
- audit logs or other logs
- backup bundles, runtime-state tarballs, and local archives
- `.venv/`, caches, and test artifacts

Use [config/firewall.ini.example](config/firewall.ini.example) as the starting
point for local configuration. Real interface names, LAN ranges, VPN endpoints,
SSH ports, Keybase identifiers, and service-specific values belong only in a
private deployment config.

## Quick Install

Target: Debian 13 with systemd and console or out-of-band recovery access.
Run this only after reviewing whether the default package and service changes
fit the target host.

Core firewall install:

```bash
curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash
```

Core install plus optional Cosmos/Keybase integration:

```bash
curl -fsSL https://raw.githubusercontent.com/unknown0152/nft-firewall-public/main/install.sh | sudo bash -s -- --with-integrations
```

The curl entrypoint prints normally and also writes a root-only install log under
`/var/log/nft-firewall/install-*.log` for troubleshooting.

After the core install, validate before applying firewall rules:

```bash
sudo fw doctor cosmos-vpn-secure
sudo fw simulate cosmos-vpn-secure
sudo fw safe-apply cosmos-vpn-secure
```

The optional integration path installs Cosmos as a standalone service and keeps
Cosmos config/storage under `/srv`. It skips Cosmos iptables changes so
nft-firewall remains the firewall authority.

Clean-VM validation covered the installer path without Docker, Keybase, or a
real WireGuard provider. Cosmos starts without Docker, but container management
requires Docker to be installed and reachable by Cosmos.

## Repository Structure

- `src/core/` contains ruleset generation, state persistence, and validation.
- `src/daemons/` contains watchdog, listener, knockd, and SSH alert daemons.
- `src/integrations/` contains Docker, GeoIP, and threat-feed helpers.
- `src/utils/` contains shared formatting, metrics, Keybase, and validation
  utilities.
- `systemd/` contains service and timer templates.
- `scripts/` contains local operator and maintenance helpers.
- `tests/unit/` contains the unit and invariant test suite.
- `docs/` contains operational maintenance and migration notes.

## Development Checks

The local check entrypoint is:

```bash
make check
```

It runs Ruff when available, ShellCheck when available, and the unit test suite.
Ruff is intentionally configured narrowly so it catches high-signal undefined
name errors without imposing broad style churn.

Optional local tooling can be installed into a project `.venv`:

```bash
make venv
make check
```

The `.venv` is for development checks only. Runtime services do not depend on
it.

## Operational Notes

The docs under [docs/](docs/) describe maintenance workflows such as local
change tracking, zero-downtime validation, and backup/export handling. They are
operator guidance, not a substitute for reviewing the generated nftables policy
on the target host.

Before applying generated firewall changes on a real host, use the project
doctor, health, and nftables syntax checks appropriate for that deployment.
