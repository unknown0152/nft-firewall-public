# nft-firewall

`nft-firewall` is a low-level nftables firewall manager for Debian systems that
need a strict WireGuard killswitch, default-drop input policy, Docker isolation,
health checks, and operator tooling.

This project is intended for experienced Linux operators. It manages nftables
rules directly and can affect host connectivity. Review generated rules before
applying them, keep an out-of-band recovery path, and do not deploy it on a
production host without understanding the local network topology.

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
