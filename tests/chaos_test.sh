#!/usr/bin/env bash
# =============================================================================
# /opt/nft-firewall/tests/chaos_test.sh
# NFT Firewall v12 — Chaos Engineering Test Suite
#
# Usage:
#   sudo bash /opt/nft-firewall/tests/chaos_test.sh
#
# Drills:
#   1. Catch-22         — Kills the VPN interface; asserts watchdog auto-recovers
#   2. Command Injection — Attempts to block 0.0.0.0/0; asserts the CLI rejects it
#   3. Blackout Test    — Proves killswitch blocks all traffic when VPN is down
#   4. Rule Tampering   — Flushes nftables; asserts watchdog restores rules
#
# Safety:
#   - Requires root (exits if not)
#   - Drill 1 auto-restores VPN if watchdog does not recover within the timeout
#   - Drill 2 immediately unblocks if the dangerous CIDR was accepted (cleans up)
#   - Drill 3 auto-restores VPN on both leak-detected and watchdog-timeout paths
#   - Drill 4 manually re-applies ruleset if watchdog does not restore within timeout
# =============================================================================

set -uo pipefail   # -e intentionally omitted — we catch failures manually

# ── Globals ───────────────────────────────────────────────────────────────────

INSTALL_DIR="/opt/nft-firewall"
PYTHON="/usr/bin/python3"
MAIN_PY="${INSTALL_DIR}/src/main.py"

# How long to poll for VPN recovery (seconds). Watchdog check_interval=30s, so
# worst-case detection + level-1 restart fits comfortably inside 60 seconds.
RECOVERY_TIMEOUT=60

# Running counters
PASS_COUNT=0
FAIL_COUNT=0
declare -a FAIL_REASONS=()

# ── Colour helpers ────────────────────────────────────────────────────────────

_green()  { printf '\033[32m%s\033[0m' "$*"; }
_red()    { printf '\033[31m%s\033[0m' "$*"; }
_yellow() { printf '\033[33m%s\033[0m' "$*"; }
_bold()   { printf '\033[1m%s\033[0m'  "$*"; }
_cyan()   { printf '\033[36m%s\033[0m' "$*"; }

_header() {
    local title="$1"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $(_bold "$title")"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

_step()   { echo "  $(_cyan "→") $*"; }
_info()   { echo "  $(_yellow "!") $*"; }

_pass() {
    local label="$1"; shift
    echo "  $(_green "✓ PASS") — ${label}${*:+ ($*)}"
    (( PASS_COUNT++ )) || true
}

_fail() {
    local label="$1"; shift
    echo "  $(_red "✗ FAIL") — ${label}${*:+ ($*)}"
    (( FAIL_COUNT++ )) || true
    FAIL_REASONS+=("${label}${*:+ — $*}")
}

# ── Preflight ─────────────────────────────────────────────────────────────────

_require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "$(_red "[FATAL]") This script must be run as root:" >&2
        echo "  sudo bash $0" >&2
        exit 1
    fi
}

_detect_vpn_iface() {
    # Try firewall.ini first, fall back to 'wg0'
    local ini="${INSTALL_DIR}/config/firewall.ini"
    if [[ -f "$ini" ]]; then
        local val
        val=$(python3 -c "
import configparser, sys
c = configparser.ConfigParser()
c.read('${ini}')
print(c.get('network', 'vpn_interface', fallback='wg0'))
" 2>/dev/null)
        echo "${val:-wg0}"
    else
        echo "wg0"
    fi
}

# ── Drill 1: The Catch-22 Drill ───────────────────────────────────────────────
#
# Tears down the VPN interface then polls for up to RECOVERY_TIMEOUT seconds
# checking whether nft-watchdog brought it back up. Auto-restores if not.

drill_catch22() {
    local iface="$1"
    _header "Drill 1 — The Catch-22 Drill  (VPN auto-recovery)"

    # Verify nft-watchdog is actually running before we pull the rug
    if ! systemctl is-active --quiet nft-watchdog.service; then
        _fail "Pre-condition" "nft-watchdog.service is not running — skipping drill"
        return
    fi
    _step "nft-watchdog.service is active ✓"

    # Capture journal cursor so we only scan entries generated during this drill
    local journal_since
    journal_since=$(date --iso-8601=seconds)
    _step "Journal baseline captured at ${journal_since}"

    # Fully remove the WireGuard device so the watchdog detects a missing interface
    # on its very next poll (instead of waiting ~180s for the handshake to expire).
    # `ip link set down` only admin-disables the device but preserves kernel WireGuard
    # state, making the handshake timestamp appear fresh for up to 3 minutes.
    _step "Running: wg-quick down ${iface}"
    if ! wg-quick down "${iface}" 2>&1 | sed 's/^/        /'; then
        _fail "VPN teardown" "wg-quick down ${iface} failed — is the interface configured?"
        return
    fi
    _info "Interface ${iface} torn down. Watchdog has up to ${RECOVERY_TIMEOUT}s to recover it."

    # Poll every 5 seconds for recovery
    local elapsed=0
    local recovered=false
    local check_interval=5

    while (( elapsed < RECOVERY_TIMEOUT )); do
        sleep "${check_interval}"
        (( elapsed += check_interval )) || true

        # Check 1: Is the kernel interface operational?
        local link_state
        link_state=$(ip link show "${iface}" 2>/dev/null | grep -oP '(?<=state )\w+' || true)

        # Check 2: Does WireGuard show a recent handshake?
        local handshake_ts
        handshake_ts=$(wg show "${iface}" latest-handshakes 2>/dev/null \
            | awk '{print $2}' | head -1 || true)

        if [[ "$link_state" == "UNKNOWN" || "$link_state" == "UP" ]]; then
            _step "[t+${elapsed}s] Interface state: ${link_state} — verifying handshake ..."

            if [[ -n "$handshake_ts" && "$handshake_ts" -gt 0 ]]; then
                local age_s=$(( $(date +%s) - handshake_ts ))
                if (( age_s < 120 )); then
                    recovered=true
                    _step "[t+${elapsed}s] Fresh handshake confirmed (${age_s}s ago) ✓"
                    break
                fi
            else
                _step "[t+${elapsed}s] Interface up, awaiting handshake ..."
            fi
        else
            _step "[t+${elapsed}s] Interface state: ${link_state:-DOWN} — still waiting ..."
        fi
    done

    # Scan journal for watchdog recovery log entries (supplementary evidence)
    local journal_evidence
    journal_evidence=$(journalctl -u nft-watchdog --since "${journal_since}" \
        --no-pager --output=short-iso 2>/dev/null \
        | grep -iE "recovery level|wg-quick up|VPN Recovered|Starting auto-recovery" \
        | tail -5 || true)

    if [[ "$recovered" == true ]]; then
        _pass "Catch-22 Drill" "${iface} recovered by watchdog within ${elapsed}s"
        if [[ -n "$journal_evidence" ]]; then
            _step "Watchdog recovery log:"
            while IFS= read -r line; do
                echo "        ${line}"
            done <<< "$journal_evidence"
        fi
    else
        _fail "Catch-22 Drill" \
            "watchdog did NOT recover ${iface} within ${RECOVERY_TIMEOUT}s"

        # ── SAFETY NET: Auto-restore to prevent lockout ──────────────────────
        echo ""
        _info "$(_red "SAFETY NET TRIGGERED") — tearing down and restoring ${iface}"
        # Teardown first: if watchdog already ran wg-quick up, the interface exists
        # and a bare `wg-quick up` would fail with "already exists".
        wg-quick down "${iface}" 2>/dev/null || true
        if wg-quick up "${iface}" 2>&1 | sed 's/^/        /'; then
            _info "wg-quick up ${iface} succeeded — internet access restored"
        else
            _info "$(_red "wg-quick up also failed — run: sudo wg-quick up ${iface}")"
        fi

        if [[ -n "$journal_evidence" ]]; then
            _step "Relevant watchdog journal entries:"
            while IFS= read -r line; do
                echo "        ${line}"
            done <<< "$journal_evidence"
        fi
    fi
}

# ── Drill 2: The Command Injection Drill ─────────────────────────────────────
#
# Attempts to block the entire internet (0.0.0.0/0) via the CLI. Because
# blocked_ips uses `flags interval`, nftables WILL accept this CIDR unless
# main.py validates the input first.
#
# Expected result (PASS):  exit code != 0, CIDR was rejected
# Actual result if FAIL:   exit code 0, CIDR was accepted — immediate cleanup
#   → this reveals that 0.0.0.0/0 input validation is missing from the CLI.

drill_injection() {
    _header "Drill 2 — Command Injection Drill  (dangerous CIDR block)"

    local dangerous_cidr="0.0.0.0/0"
    local test_label="block ${dangerous_cidr} is rejected by CLI"

    _step "Attempting: python3 ${MAIN_PY} block ${dangerous_cidr}"
    _info "Expected:   non-zero exit code (input rejected)"
    _info "If accepted: internet access would be cut — immediate cleanup will run"

    # Capture both output and exit code without letting set -u abort on non-zero
    # Capture output and exit code separately.
    # Do NOT use `|| true` here — it swallows the exit code, making $? always 0.
    # set -e is intentionally off so a non-zero exit does not abort the script.
    local out exit_code
    out=$(PYTHONPATH="${INSTALL_DIR}/src" \
          "${PYTHON}" "${MAIN_PY}" block "${dangerous_cidr}" 2>&1)
    exit_code=$?

    echo "  Output: ${out}"
    echo "  Exit:   ${exit_code}"

    if [[ $exit_code -ne 0 ]]; then
        _pass "$test_label" "exit ${exit_code} — dangerous CIDR correctly rejected"
    else
        # CLI accepted the CIDR — dangerous ruleset is now active
        _fail "$test_label" \
            "exit 0 — 0.0.0.0/0 was ACCEPTED by nft (validation gap: all traffic now blocked)"

        # ── IMMEDIATE CLEANUP ────────────────────────────────────────────────
        echo ""
        _info "$(_red "CLEANUP") — removing 0.0.0.0/0 from blocked_ips immediately"
        local cleanup_out cleanup_exit
        cleanup_out=$(PYTHONPATH="${INSTALL_DIR}/src" \
                      "${PYTHON}" "${MAIN_PY}" unblock "${dangerous_cidr}" 2>&1) || true
        cleanup_exit=$?
        if [[ $cleanup_exit -eq 0 ]]; then
            _info "Cleanup succeeded — 0.0.0.0/0 removed from blocked_ips ✓"
        else
            _info "$(_red "Cleanup FAILED (exit ${cleanup_exit}): ${cleanup_out}")"
            _info "Run manually: sudo ${PYTHON} ${MAIN_PY} unblock ${dangerous_cidr}"
        fi

        # Supplementary: verify the CIDR is really gone from the live ruleset
        if ! nft list set ip firewall blocked_ips 2>/dev/null \
                | grep -q "0\.0\.0\.0/0"; then
            _info "Live ruleset confirmed: 0.0.0.0/0 is no longer in blocked_ips ✓"
        else
            _info "$(_red "WARNING: 0.0.0.0/0 still appears in blocked_ips — manual removal required")"
        fi
    fi
}

# ── Drill 3: The Blackout Test ────────────────────────────────────────────────
#
# Mathematically proves the killswitch does not leak packets when VPN drops:
#
#   Step 1 — Verify normal connectivity  (ping 8.8.8.8 MUST succeed)
#   Step 2 — Tear down the VPN           (wg-quick down)
#   Step 3 — Leak test                   (ping 8.8.8.8 MUST FAIL — 100% loss)
#            If ping succeeds → traffic bypassing killswitch → FAIL immediately
#   Step 4 — Wait for watchdog recovery  (reuse 90s polling loop)
#   Step 5 — Verify connectivity restored (ping 8.8.8.8 MUST succeed again)
#
# A killswitch implemented with a default-drop output policy will cause Step 3
# to produce "Network is unreachable" or 100% packet loss.  Any response means
# the ISP interface is passing traffic — a genuine killswitch failure.

drill_blackout() {
    local iface="$1"
    _header "Drill 3 — The Blackout Test  (killswitch leak proof)"

    local probe_host="8.8.8.8"

    # ── Step 1: Pre-condition — verify normal connectivity ────────────────────
    _step "Step 1: Verifying normal connectivity (ping ${probe_host}) ..."
    if ! ping -c 1 -W 1 "${probe_host}" &>/dev/null; then
        _fail "Pre-condition" \
            "ping ${probe_host} failed before VPN was torn down — check VPN/DNS"
        return
    fi
    _step "Connectivity OK ✓  (pre-VPN-teardown ping succeeded)"

    # ── Step 2: Tear down VPN ─────────────────────────────────────────────────
    _step "Step 2: Running: wg-quick down ${iface}"
    if ! wg-quick down "${iface}" 2>&1 | sed 's/^/        /'; then
        _fail "VPN teardown" "wg-quick down ${iface} failed — is the interface configured?"
        return
    fi
    _info "Interface ${iface} torn down."

    # ── Step 3: Leak test — traffic MUST NOT flow while VPN is down ───────────
    _step "Step 3: Leak test — ping -c 3 -W 1 ${probe_host} (MUST FAIL)"
    _info "Any reply here means traffic bypasses the killswitch!"

    local ping_out ping_exit
    ping_out=$(ping -c 3 -W 1 "${probe_host}" 2>&1)
    ping_exit=$?

    echo "  ping output:"
    while IFS= read -r line; do
        echo "        ${line}"
    done <<< "${ping_out}"

    if [[ $ping_exit -eq 0 ]]; then
        # Packets got through — killswitch is not enforcing the block
        _fail "Killswitch leak" \
            "ping succeeded while VPN was down — traffic leaked via ISP interface!"

        # ── SAFETY NET: restore VPN immediately ──────────────────────────────
        echo ""
        _info "$(_red "SAFETY NET TRIGGERED") — restoring ${iface} after leak detection"
        wg-quick down "${iface}" 2>/dev/null || true
        if wg-quick up "${iface}" 2>&1 | sed 's/^/        /'; then
            _info "wg-quick up ${iface} succeeded — internet access restored"
        else
            _info "$(_red "wg-quick up also failed — run: sudo wg-quick up ${iface}")"
        fi
        return
    fi

    # Determine whether we got "Network is unreachable" or just packet loss
    if echo "${ping_out}" | grep -qiE "unreachable|100% packet loss"; then
        _pass "Killswitch active" \
            "all 3 packets dropped while VPN was down — no leak detected"
    else
        _pass "Killswitch active" \
            "ping exit ${ping_exit} — traffic blocked while VPN was down"
    fi

    # ── Step 4: Wait for watchdog to recover the interface ────────────────────
    _step "Step 4: Waiting up to ${RECOVERY_TIMEOUT}s for watchdog to recover ${iface} ..."
    _info "Watchdog check_interval=30s — worst-case detection + restart ≈ 60s"

    local elapsed=0
    local recovered=false
    local check_interval=5

    while (( elapsed < RECOVERY_TIMEOUT )); do
        sleep "${check_interval}"
        (( elapsed += check_interval )) || true

        local link_state
        link_state=$(ip link show "${iface}" 2>/dev/null | grep -oP '(?<=state )\w+' || true)

        local handshake_ts
        handshake_ts=$(wg show "${iface}" latest-handshakes 2>/dev/null \
            | awk '{print $2}' | head -1 || true)

        if [[ "$link_state" == "UNKNOWN" || "$link_state" == "UP" ]]; then
            _step "[t+${elapsed}s] Interface state: ${link_state} — verifying handshake ..."
            if [[ -n "$handshake_ts" && "$handshake_ts" -gt 0 ]]; then
                local age_s=$(( $(date +%s) - handshake_ts ))
                if (( age_s < 120 )); then
                    recovered=true
                    _step "[t+${elapsed}s] Fresh handshake confirmed (${age_s}s ago) ✓"
                    break
                fi
            else
                _step "[t+${elapsed}s] Interface up, awaiting handshake ..."
            fi
        else
            _step "[t+${elapsed}s] Interface state: ${link_state:-DOWN} — still waiting ..."
        fi
    done

    if [[ "$recovered" == false ]]; then
        _fail "Watchdog recovery" \
            "watchdog did NOT recover ${iface} within ${RECOVERY_TIMEOUT}s"

        # ── SAFETY NET: restore VPN to prevent lockout ───────────────────────
        echo ""
        _info "$(_red "SAFETY NET TRIGGERED") — restoring ${iface} after watchdog timeout"
        wg-quick down "${iface}" 2>/dev/null || true
        if wg-quick up "${iface}" 2>&1 | sed 's/^/        /'; then
            _info "wg-quick up ${iface} succeeded — internet access restored"
        else
            _info "$(_red "wg-quick up also failed — run: sudo wg-quick up ${iface}")"
        fi
        return
    fi

    # ── Step 5: Verify connectivity is restored ───────────────────────────────
    _step "Step 5: Verifying connectivity restored after watchdog recovery ..."
    if ping -c 1 -W 3 "${probe_host}" &>/dev/null; then
        _pass "Blackout Test" \
            "killswitch held during blackout (${elapsed}s); connectivity restored by watchdog"
    else
        _fail "Post-recovery connectivity" \
            "ping ${probe_host} failed after watchdog recovered ${iface}"
    fi
}

# ── Drill 4: The Rule Tampering Drill ────────────────────────────────────────
#
# Flushes the entire nftables ruleset then waits for the watchdog to detect the
# missing firewall table and restore it via the saved conf file.
#
# Expected result (PASS):  watchdog restores the firewall table within
#                          RECOVERY_TIMEOUT seconds
# Safety net:              if watchdog times out, manually re-apply the
#                          ruleset so the machine is never left unprotected.

drill_tampering() {
    local iface="$1"
    _header "Drill 4 — Rule Tampering Drill  (nft flush ruleset → watchdog restore)"

    # Verify watchdog is running
    if ! systemctl is-active --quiet nft-watchdog.service; then
        _fail "Pre-condition" "nft-watchdog.service is not running — skipping drill"
        return
    fi
    _step "nft-watchdog.service is active ✓"

    # Pre-condition: firewall table must exist before we flush
    if ! nft list table ip firewall &>/dev/null; then
        _fail "Pre-condition" \
            "nft table 'ip firewall' not found — apply the ruleset first"
        return
    fi
    _step "Firewall table confirmed present ✓"

    # Capture journal cursor
    local journal_since
    journal_since=$(date --iso-8601=seconds)
    _step "Journal baseline captured at ${journal_since}"

    # ── Flush ────────────────────────────────────────────────────────────────
    _step "Running: nft flush ruleset"
    if ! nft flush ruleset 2>&1; then
        _fail "Ruleset flush" "nft flush ruleset failed — check nft permissions"
        return
    fi

    # Immediately confirm the table is gone
    if nft list table ip firewall &>/dev/null; then
        _fail "Post-flush check" \
            "firewall table still present after flush — unexpected kernel behaviour"
        return
    fi
    _step "Firewall table confirmed absent — watchdog has ${RECOVERY_TIMEOUT}s to restore it ✓"

    # ── Poll for restoration ──────────────────────────────────────────────────
    local elapsed=0
    local restored=false
    local check_interval=5

    while (( elapsed < RECOVERY_TIMEOUT )); do
        sleep "${check_interval}"
        (( elapsed += check_interval )) || true

        if nft list table ip firewall &>/dev/null; then
            restored=true
            _step "[t+${elapsed}s] Firewall table is back ✓"
            break
        else
            _step "[t+${elapsed}s] Table absent — still waiting ..."
        fi
    done

    # Supplementary journal evidence
    local journal_evidence
    journal_evidence=$(journalctl -u nft-watchdog --since "${journal_since}" \
        --no-pager --output=short-iso 2>/dev/null \
        | grep -iE "integrity|restore|ruleset|apply|nft" \
        | tail -5 || true)

    if [[ "$restored" == true ]]; then
        _pass "Rule Tampering Drill" \
            "firewall table restored by watchdog within ${elapsed}s"
        if [[ -n "$journal_evidence" ]]; then
            _step "Watchdog restore log:"
            while IFS= read -r line; do
                echo "        ${line}"
            done <<< "$journal_evidence"
        fi
    else
        _fail "Rule Tampering Drill" \
            "watchdog did NOT restore rules within ${RECOVERY_TIMEOUT}s"

        # ── SAFETY NET: manually re-apply the ruleset ─────────────────────────
        echo ""
        _info "$(_red "SAFETY NET TRIGGERED") — manually re-applying ruleset"

        local ini="${INSTALL_DIR}/config/firewall.ini"
        local profile
        profile=$(python3 -c "
import configparser
c = configparser.ConfigParser()
c.read('${ini}')
print(c.get('install', 'profile', fallback='cosmos-vpn-secure'))
" 2>/dev/null || echo "cosmos-vpn-secure")

        _step "Applying profile '${profile}' via main.py ..."
        if PYTHONPATH="${INSTALL_DIR}/src" \
               "${PYTHON}" "${MAIN_PY}" apply "${profile}" 2>&1 | sed 's/^/        /'; then
            _info "Manual apply succeeded — firewall rules restored ✓"
        else
            _info "$(_red "Manual apply FAILED — run: sudo ${PYTHON} ${MAIN_PY} apply ${profile}")"
        fi

        if [[ -n "$journal_evidence" ]]; then
            _step "Relevant watchdog journal entries:"
            while IFS= read -r line; do
                echo "        ${line}"
            done <<< "$journal_evidence"
        fi
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────

_summary() {
    local total=$(( PASS_COUNT + FAIL_COUNT ))
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $(_bold "Results")   ${PASS_COUNT}/$(_bold "${total}") passed"

    if (( FAIL_COUNT == 0 )); then
        echo "  $(_green "All drills passed.")"
    else
        echo "  $(_red "${FAIL_COUNT} drill(s) failed:")"
        for reason in "${FAIL_REASONS[@]}"; do
            echo "    $(_red "•") ${reason}"
        done
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Exit 1 if any drill failed so CI pipelines can detect failure
    (( FAIL_COUNT == 0 ))
}

# ── Main ──────────────────────────────────────────────────────────────────────

_require_root

VPN_IFACE=$(_detect_vpn_iface)

echo ""
echo "  $(_bold "NFT Firewall v11 — Chaos Engineering Test Suite")"
echo "  Install dir : ${INSTALL_DIR}"
echo "  VPN iface   : ${VPN_IFACE}"
echo "  Recovery TTL: ${RECOVERY_TIMEOUT}s"
echo "  Started at  : $(date '+%Y-%m-%d %H:%M:%S')"

drill_catch22 "${VPN_IFACE}"
drill_injection
drill_blackout "${VPN_IFACE}"
drill_tampering "${VPN_IFACE}"

_summary
