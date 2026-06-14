# Zero-Downtime Migration Guide

This guide assumes a deployed tree at `/opt/nft-firewall`. Adjust paths if your
deployment uses a different checkout location.

## Goals

- Preserve `/opt/nft-firewall/config/firewall.ini`.
- Preserve `/var/lib/nft-firewall/dynamic-sets.json`.
- Preserve `/var/lib/nft-firewall/watchdog-markers.json`.
- Validate the new ruleset before loading it.
- Use nftables atomic replacement through `flush ruleset` in the generated file.

## Preflight

Run from `/opt/nft-firewall`:

```bash
PYTHONPATH=src python3 -m pytest tests/unit/test_security_critical.py tests/unit/test_doctor.py -q
fw doctor cosmos-vpn-secure
fw health
PYTHONPATH=src python3 src/main.py apply cosmos-vpn-secure --dry-run > /tmp/nft-firewall-next.conf
nft -c -f /tmp/nft-firewall-next.conf
```

Confirm that the generated file contains no blanket geowhitelist accept:

```bash
rg 'geowhitelist_ips accept' /tmp/nft-firewall-next.conf || true
rg 'geowhitelist_ips tcp dport' /tmp/nft-firewall-next.conf
```

## Apply

Use a console or LAN SSH session when possible. The safe path is:

```bash
fw safe-apply cosmos-vpn-secure
```

Type `CONFIRM` only after validating that SSH, Cosmos ingress, Docker egress,
and `fw health` still behave as expected.

If unattended deployment is required, create a ruleset backup first:

```bash
fw backup
PYTHONPATH=src python3 src/main.py apply cosmos-vpn-secure
fw doctor cosmos-vpn-secure
fw health
```

## Rollback

Use the latest backup created under `/opt/nft-firewall/state`:

```bash
fw restore
fw doctor cosmos-vpn-secure
fw health
```

## Notes

- A successful apply rewrites `/etc/nftables.conf`; `nftables.service` will then
  load the same policy on boot.
- A generated apply uses `flush ruleset`, so legacy compatibility tables such
  as `table ip filter` are removed at apply time unless another service
  recreates them later.
- The WireGuard watchdog marker format is unchanged.
