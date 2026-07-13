# NFT Firewall Control-Plane Security Remediation

## Goal

Repair the confirmed privilege-boundary and reliability defects without changing the intended firewall policy, trusted access, VPN topology, Docker exposure, or Keybase command surface.

## Architecture

The firewall remains split between an unprivileged `fw-admin` control plane and small root-owned wrappers. Privileged wrappers become exact-operation adapters: fixed interface names, fixed argument counts, validated scalar inputs, and no caller-controlled configuration paths. Python state mutations use a command runner that selects raw `nft` for root and the restricted wrapper for `fw-admin`.

Safe apply becomes a transaction. It validates and snapshots the live and persistent rules, changes only the live rules during the confirmation window, persists only after confirmation, and restores live state on rejection. A missing or unreadable live ruleset is a hard backup failure.

Feed synchronization distinguishes fetch failure from a valid response, refuses destructive reconciliation after a failed or implausibly empty fetch, propagates mutation failures to the process exit status, and runs through the validated privilege boundary. Persistent JSON state uses an advisory lock around complete read-modify-write transactions.

## Components

- `setup.py` generates hardened wrappers and systemd units; installed wrappers must match generated templates.
- `src/core/state.py` owns privileged nft execution, safe backups, persistent-set transactions, and audit writes.
- `src/main.py` owns safe-apply orchestration and nonzero CLI failure behavior.
- `src/integrations/threatfeed.py` owns typed fetch results and conservative reconciliation.
- `src/daemons/listener.py` reloads the authorized Keybase user on every poll.
- systemd units receive compatible sandboxing. Units that invoke sudo cannot use `NoNewPrivileges=true`; read-only units receive stronger restrictions.

## Failure Handling

- Wrapper input outside the exact allowlist exits 126 without invoking the privileged binary.
- Backup failure aborts before changing live state.
- Unconfirmed rules are never written to `/etc/nftables.conf`.
- Feed download or parse failure exits nonzero and retains all previous blocks.
- Partial feed mutation exits nonzero and persists only confirmed changes.
- State-lock acquisition is bounded and failures are explicit rather than silently overwriting state.

## Testing

Every behavior change follows red-green TDD. Tests cover malicious WireGuard paths and hook-bearing configurations, excess wrapper arguments, persistent safe-apply rollback, backup failure, feed outage retention, non-root nft routing, nonzero partial failure, concurrent persistent-set updates, live authorization reload, and systemd hardening directives. Full `make check`, shell syntax, generated ruleset simulation, `fw doctor`, service status, timer status, live ruleset invariants, and queue-free deployment checks are required before completion.

## Deployment

The authoritative Git repository is modified on a dedicated branch. Before deployment, `/opt/nft-firewall`, installed wrappers, sudoers, systemd units, `/etc/nftables.conf`, dynamic state, and watchdog markers are backed up. Code and templates are deployed without replacing private `firewall.ini`; wrappers and units are installed from the reviewed source. Services are restarted one at a time, and the live firewall is never flushed as part of code deployment.
