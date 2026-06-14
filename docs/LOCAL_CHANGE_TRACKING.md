# Local Change Tracking

This host runs the deployed firewall from `/opt/nft-firewall`.

The local git repository in `/opt/nft-firewall` tracks the live deployed source
tree for operational change control. The first commit is the live baseline
captured on this host. Use `git status`, `git diff`, and local commits before
and after maintenance work so firewall changes are reviewable and reversible.

`/root/nft-firewall` is a divergent reference checkout only. Do not pull from
it, reset to it, or copy files from it into `/opt/nft-firewall` without an
explicit review of the diff and a live safety validation plan.

Recommended operator flow:

1. Run `fw health` and `fw doctor cosmos-vpn-secure`.
2. Check `git status --short`.
3. Make a small, reviewable change.
4. Run `make check` for the local developer validation stack.
5. Run focused live safety checks when the change can affect runtime behavior.
6. Commit the change locally with a clear message.

Do not commit generated cache files, virtual environments, or temporary test
artifacts.

## Optional Local Dev Environment

Runtime firewall services do not use the project `.venv`. The virtual
environment is only for local maintenance checks such as Ruff and pytest.

To bootstrap optional developer tooling:

```bash
make venv
make check
```

`make venv` creates `.venv/` under `/opt/nft-firewall` and installs the local
developer/test tools used by this repository there. It does not install the
firewall as a Python package and does not affect systemd services. `.venv/` is
ignored by git and should not be committed.

If `.venv/` is absent, `make check` still runs with available system tools:
Ruff is skipped when unavailable, ShellCheck is skipped when unavailable, and
pytest runs from `PATH` or via `python3 -m pytest`.

## Local vs Live Checks

`make check` is local-only. It runs developer checks against the working tree:
Ruff when available, ShellCheck when available, and the unit test suite. Use it
for script-only changes, docs changes with command examples, and Python logic
changes before committing.

Live-host checks inspect the running firewall and persisted boot ruleset:

```bash
fw health
fw doctor cosmos-vpn-secure
nft -c -f /etc/nftables.conf
systemctl list-units 'nft-*' --type=service --state=failed --no-pager --plain
```

Run the live checks after changes that can affect ruleset generation,
`/etc/nftables.conf`, watchdog/listener/ssh-alert behavior, systemd units, or
operator commands used on this host. Documentation-only and local tooling-only
changes normally need `make check`; run live checks anyway when the doc or
tooling change describes production commands.

## Off-Host Recovery

Use a git bundle to export the authoritative deployed repo history without
pulling from or merging with `/root/nft-firewall`:

```bash
make bundle
```

By default this writes a timestamped bundle to `/var/backups/nft-firewall/`.
Copy that `.bundle` file off-host with your normal backup tooling. To inspect
or restore it elsewhere:

```bash
git clone /path/to/nft-firewall-YYYYMMDDTHHMMSSZ.bundle nft-firewall
```

The bundle preserves committed source, docs, tests, local config files tracked
in git, and local commit history. It does not include ignored working-tree
artifacts such as `.venv/`, Python caches, or uncommitted changes.

Runtime state outside the repo still needs separate backup if you need full
host recovery:

- `/etc/nftables.conf`
- `/var/lib/nft-firewall/dynamic-sets.json`
- `/var/lib/nft-firewall/watchdog-markers.json`
- `/var/log/nft-firewall/audit.jsonl` if audit history must be retained

To create a read-only export of the runtime state files that exist on this
host:

```bash
make backup-state
```

By default this writes a timestamped tarball to `/var/backups/nft-firewall/`.
It includes the files listed above when present, the deployed
`/opt/nft-firewall/config/firewall.ini`, optional system config files if they
exist, and installed `nft-*` systemd unit files from `/etc/systemd/system`.

This target is export-only. It does not restore files, reload systemd, apply
nftables, or mutate live firewall state. For a rebuild, inspect the tarball and
copy files back deliberately, then run the live checks before enabling services.

### Off-Host Retention

Local files under `/var/backups/nft-firewall/` are not enough for disaster
recovery if this host is lost. After running `make bundle` and
`make backup-state`, copy both timestamped artifacts off-host:

- `nft-firewall-YYYYMMDDTHHMMSSZ.bundle`
- `nft-firewall-runtime-state-YYYYMMDDTHHMMSSZ.tar.gz`

Keep several historical generations, not only the latest pair. A practical
minimum is a few recent copies plus at least one known-good copy from before
major firewall or host maintenance.

Periodically verify off-host copies before relying on them:

```bash
git bundle verify nft-firewall-YYYYMMDDTHHMMSSZ.bundle
tar -tzf nft-firewall-runtime-state-YYYYMMDDTHHMMSSZ.tar.gz >/dev/null
```

Treat both artifact types as sensitive. They can reveal network topology,
service ports, host paths, dynamic firewall state, and operational history. If
they leave trusted storage, encrypt them with the backup system or a dedicated
tool before transfer.
