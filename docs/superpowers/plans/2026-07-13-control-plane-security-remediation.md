# NFT Firewall Control-Plane Security Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the `fw-admin` privilege escalation paths and make firewall apply, threat-feed, persistent state, and daemon behavior fail safely.

**Architecture:** Keep the current Python and nftables design, but turn every root wrapper into an exact-operation adapter. Make safe apply transactional, feed reconciliation conservative, and persistent state serialized with advisory locking.

**Tech Stack:** Python 3.13, pytest, Bash, nftables, systemd, sudo, WireGuard.

## Global Constraints

- Preserve the live `cosmos-vpn-secure` policy and current trusted IP membership.
- Never flush or replace the live ruleset during deployment.
- Never copy or commit `/opt/nft-firewall/config/firewall.ini`.
- Every behavior change requires a failing regression test before production code.
- Deployment requires a restorable host backup and fresh live health evidence.

---

### Task 1: Preserve the deployed trusted-web rule delta

**Files:**
- Modify: `src/core/rules.py`
- Test: `tests/unit/test_cosmos_secure.py`

**Interfaces:**
- Consumes: `RulesetConfig.cosmos_public_ports` and `trusted_ips`.
- Produces: source-controlled trusted-IP accepts for configured public web ports.

- [ ] Add a regression assertion that generated rules accept `@trusted_ips` only on configured public ports.
- [ ] Run the test and confirm it fails against the repository snapshot.
- [ ] Port the deployed conditional rule into `src/core/rules.py`.
- [ ] Run the focused test and full rules tests.
- [ ] Commit the preserved deployment delta.

### Task 2: Harden privileged wrappers

**Files:**
- Modify: `setup.py`
- Test: `tests/unit/test_privileged_wrapper.py`
- Test: `tests/unit/test_setup_safety.py`

**Interfaces:**
- Consumes: watchdog operations for interface `wg0` and nft dynamic-set operations.
- Produces: exact-argument root wrappers that reject caller-controlled WireGuard configuration paths and extra systemctl/ip arguments.

- [ ] Add tests that reject `wg-quick up /tmp/evil.conf`, extra units, arbitrary link deletion, malformed set elements, and nonnumeric handles.
- [ ] Run the focused tests and confirm the new cases fail.
- [ ] Generate wrappers that accept only fixed `wg0` operations, exact argument counts, validated IPv4/CIDR/duration values, and numeric handles.
- [ ] Run the focused tests and confirm they pass.
- [ ] Commit the wrapper hardening.

### Task 3: Make safe apply transactional

**Files:**
- Modify: `src/main.py`
- Modify: `src/core/state.py`
- Test: `tests/unit/test_state.py`
- Create: `tests/unit/test_safe_apply.py`

**Interfaces:**
- Consumes: generated ruleset, live ruleset backup, `CONFIRM` input.
- Produces: live-only trial application and post-confirmation persistence.

- [ ] Add tests proving backup command failure raises and unconfirmed apply never writes the new persistent configuration.
- [ ] Run the focused tests and confirm both fail for the reviewed reasons.
- [ ] Make `backup_ruleset` raise on command failure or empty output.
- [ ] Move `save_conf` and watchdog marker writes after confirmation; restore the live backup on rejection.
- [ ] Run focused and full state/apply tests.
- [ ] Commit transactional safe apply.

### Task 4: Repair threat-feed execution and failure semantics

**Files:**
- Modify: `src/core/state.py`
- Modify: `src/integrations/threatfeed.py`
- Modify: `src/main.py`
- Modify: `systemd/nft-firewall-threatfeed.service`
- Test: `tests/unit/test_state.py`
- Test: `tests/unit/test_threatfeed.py`
- Test: `tests/unit/test_setup_safety.py`

**Interfaces:**
- Consumes: HTTPS feed and restricted nft wrapper.
- Produces: conservative delta synchronization with truthful process status.

- [ ] Add tests for non-root wrapper routing, failed-fetch retention, implausibly empty-feed retention, and nonzero partial failure.
- [ ] Run the tests and confirm failures.
- [ ] Add a root/non-root nft command selector and use it for set mutations.
- [ ] Return a typed fetch failure, abort reconciliation on failure/empty response, and raise when any required mutation fails.
- [ ] Ensure the systemd unit and CLI propagate failures.
- [ ] Run focused tests and a controlled `fw-admin` dry integration against a disposable nft namespace or mocked wrapper.
- [ ] Commit threat-feed repairs.

### Task 5: Serialize persistent state and reload authorization

**Files:**
- Modify: `src/core/state.py`
- Modify: `src/daemons/listener.py`
- Test: `tests/unit/test_state.py`
- Test: `tests/unit/test_listener.py`

**Interfaces:**
- Consumes: concurrent set mutations and reloaded INI configuration.
- Produces: locked state transactions and current-user authorization on each poll.

- [ ] Add tests that reproduce lost updates and stale authorization after config change.
- [ ] Run the tests and confirm failures.
- [ ] Add `fcntl.flock` around complete state transactions with unique same-directory temporary files.
- [ ] Pass the freshly loaded authorized user into every listener poll.
- [ ] Run focused tests and commit.

### Task 6: Add compatible systemd hardening

**Files:**
- Modify: `systemd/nft-watchdog.service`
- Modify: `systemd/nft-listener.service`
- Modify: `systemd/nft-ssh-alert.service`
- Modify: `systemd/nft-webui.service`
- Modify: `systemd/nft-firewall-threatfeed.service`
- Test: `tests/unit/test_setup_safety.py`

**Interfaces:**
- Consumes: service-specific read/write paths, network families, and sudo requirements.
- Produces: sandboxed units that retain required functionality.

- [ ] Add tests for required hardening directives and allowed writable paths.
- [ ] Run tests and confirm failures.
- [ ] Add `UMask`, filesystem protections, namespace restrictions, and service-specific address-family restrictions without enabling `NoNewPrivileges` on sudo-using units.
- [ ] Run unit tests and `systemd-analyze verify`.
- [ ] Commit unit hardening.

### Task 7: Review, deploy, and verify

**Files:**
- Update: generated wrappers and installed unit files on the host.
- Preserve: `/opt/nft-firewall/config/firewall.ini`.

**Interfaces:**
- Consumes: reviewed branch and live host state.
- Produces: backed-up deployment with healthy firewall and services.

- [ ] Run `make check`, compile checks, shell checks, wrapper adversarial tests, and `systemd-analyze verify`.
- [ ] Perform a separate high-depth code review of the complete diff and fix all critical/important findings with TDD.
- [ ] Create a timestamped backup of code, wrappers, sudoers, units, nftables config, and state.
- [ ] Deploy source, regenerate wrappers/sudoers, install unit files, and restart services one at a time.
- [ ] Run `fw doctor`, `fw health`, service/timer checks, live nft invariant checks, threat-feed controlled execution, and confirm the firewall remains loaded.
- [ ] Record exact verification output and rollback path.
