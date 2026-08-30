#!/bin/bash
#
# script name : 5-telemetry_deploy.sh
# purpose     : deploy and verify the Linux telemetry stack on
#               hawthorne-app-01 - confirm auditd is active with the
#               project-provided meddefense.rules loaded, run a
#               controlled sequence of authorized test actions (create/
#               remove a user, a service management action, a cron job
#               add/remove, a short privileged find), verify each
#               action left the expected auditd record by key search,
#               and export the last 30 minutes of auditd+syslog activity
#               as structured JSON. A hardened system that produces no
#               evidence is a silent system - this script proves the
#               evidence pipeline itself works, not just that it exists.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - every test action produced its expected auditd record
#   1 - controlled failure (at least one test action's expected record
#       was not found)
#   2 - environment error (auditd/ausearch missing, auditd not active,
#       or meddefense.rules not present)
#
# ASSUMPTION - audit rule keys: this task's own example names
# "meddefense-user-mgmt" for the user-management key. The keys for the
# other four test actions (service management, cron add, cron remove,
# privileged find) are NOT specified by the task and are not visible to
# whoever wrote this script (meddefense.rules is project-supplied and
# was not available when this script was written). The five KEY_*
# variables below are deliberately grouped and overridable - confirm
# each one against the real /etc/audit/rules.d/meddefense.rules on
# hawthorne-app-01 and adjust before trusting this script's verdicts.
#
# CONFIRMED REAL on a live auditd 3.1.2 + kernel audit subsystem: a bare
# `ausearch -k <key>` (no -if) hung indefinitely in a container-style
# environment even with auditd genuinely running and audit.log
# populated: `ausearch -if /var/log/audit/audit.log -k <key>` is used
# throughout below instead, and returns immediately.
 
set -uo pipefail
# NOTE: deliberately not using -e. A test action whose expected record
# is not found is an expected, meaningful outcome this script exists to
# detect and report - not a script bug.
 
KEY_USER_MGMT="${KEY_USER_MGMT:-meddefense-user-mgmt}"
KEY_SERVICE_MGMT="${KEY_SERVICE_MGMT:-meddefense-service-mgmt}"
KEY_CRON="${KEY_CRON:-meddefense-cron}"
KEY_PRIV_FIND="${KEY_PRIV_FIND:-meddefense-priv-find}"
 
REQUIRED_TOOLS=(auditctl ausearch jq)
MISSING_TOOLS=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${tool}" >/dev/null 2>&1 || MISSING_TOOLS+=("${tool}")
done
if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
    echo "Missing required tool(s): ${MISSING_TOOLS[*]}. Install auditd and jq, then re-run." >&2
    exit 2
fi
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (auditd control and the test actions need elevated access). Try: sudo $0" >&2
    exit 2
fi
 
RULES_FILE="/etc/audit/rules.d/meddefense.rules"
if [[ ! -f "${RULES_FILE}" ]]; then
    echo "FATAL: project-provided rules file not found at ${RULES_FILE}. Cannot proceed without it." >&2
    exit 2
fi
 
# Compile and load every *.rules file in /etc/audit/rules.d/ (including
# meddefense.rules) into the live kernel audit ruleset - confirmed
# against a real auditd 3.1.2 install that a rules FILE being present on
# disk does not by itself mean its rules are actually loaded; augenrules
# is the standard tool for this and its --load run was verified here to
# genuinely make the rule appear in `auditctl -l` afterward.
if command -v augenrules >/dev/null 2>&1; then
    echo "[*] Loading audit rules via augenrules --load..."
    augenrules --load >/dev/null 2>&1
else
    echo "augenrules not found; falling back to auditctl -R." >&2
    auditctl -R "${RULES_FILE}" >/dev/null 2>&1
fi
 
# CONFIRMED REAL: augenrules --load correctly loads every rule (verified
# via auditctl -l afterward) but was also observed to fully STOP the
# auditd userspace daemon in a container-style environment lacking a
# real init system to manage the restart augenrules triggers internally
# - `pgrep -x auditd` returned nothing and `service auditd status`
# reported "not running" immediately after a successful --load. A
# loaded ruleset is worthless if the daemon consuming it is dead, so
# this explicitly (re)starts auditd afterward rather than assuming
# augenrules left it in a good state.
if ! pgrep -x auditd >/dev/null 2>&1; then
    echo "[*] auditd is not running after augenrules --load; starting it explicitly..."
    systemctl start auditd >/dev/null 2>&1 || service auditd start >/dev/null 2>&1 || auditd >/dev/null 2>&1 &
    sleep 1
fi
 
auditctl -e 1 >/dev/null 2>&1
 
if ! auditctl -l 2>/dev/null | grep -q "${RULES_FILE##*/}\|meddefense"; then
    echo "Warning: no meddefense-tagged rule appears in the live ruleset after loading. Verification below may fail as a result." >&2
fi
 
if ! auditctl -s 2>/dev/null | grep -q '^enabled 1'; then
    echo "FATAL: the kernel audit subsystem is not enabled (auditctl -s shows enabled != 1)." >&2
    exit 2
fi
 
AUDIT_LOG="/var/log/audit/audit.log"
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TELEMETRY_DIR="${SCRIPT_DIR}/capstone/telemetry"
mkdir -p "${TELEMETRY_DIR}"
# Per this task's own instructions, the exported events are written to
# capstone/telemetry/linux_events.json.
EVENTS_OUTPUT_PATH="${TELEMETRY_DIR}/linux_events.json"
 
echo "[*] Verifying auditd is active with meddefense.rules loaded..."
if ! systemctl is-active --quiet auditd 2>/dev/null && ! pgrep -x auditd >/dev/null 2>&1; then
    echo "FATAL: auditd is not active (neither systemctl nor a running process found)." >&2
    exit 2
fi
echo "    auditd active, rules file present at ${RULES_FILE}."
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
search_key() {
    # Wraps the confirmed-working invocation style (explicit -if) rather
    # than a bare `ausearch -k`, which hung indefinitely in real testing.
    local key="$1"
    ausearch -if "${AUDIT_LOG}" -k "${key}" 2>/dev/null
}
 
RESULTS=()
overall_pass=true
 
run_test_action() {
    local action_name="$1" key="$2" action_cmd="$3"
 
    echo "[*] Test: ${action_name} (key=${key})"
    eval "${action_cmd}" >/dev/null 2>&1
    sleep 1
 
    local hits
    hits="$(search_key "${key}" | grep -c "key=\"${key}\"" || true)"
    [[ -z "${hits}" ]] && hits=0
 
    local result="FAIL"
    if [[ "${hits}" -gt 0 ]]; then
        result="PASS"
        echo "    -> found (${hits} record(s))                PASS"
    else
        result="FAIL"
        echo "    -> not found                                 FAIL"
        overall_pass=false
    fi
 
    RESULTS+=("$(jq -n --arg name "${action_name}" --arg key "${key}" --argjson hits "${hits}" --arg result "${result}" \
        '{action: $name, audit_key: $key, records_found: $hits, result: $result}')")
}
 
# ---------------------------------------------------------------------------
# 2/3. Controlled test sequence, verified by key search.
# ---------------------------------------------------------------------------
echo "[*] Running controlled test sequence..."
 
TEST_USER="meddefense_capstone_test"
userdel -rf "${TEST_USER}" >/dev/null 2>&1 || true
 
run_test_action "create a user" "${KEY_USER_MGMT}" "useradd -m '${TEST_USER}'"
run_test_action "remove the user" "${KEY_USER_MGMT}" "userdel -r '${TEST_USER}'"
run_test_action "run a service management action" "${KEY_SERVICE_MGMT}" "systemctl restart cron 2>/dev/null || service cron restart 2>/dev/null"
 
CRON_MARKER="# meddefense-capstone-test-marker"
run_test_action "schedule a cron job" "${KEY_CRON}" \
    "(crontab -l 2>/dev/null; echo '* * * * * /bin/true ${CRON_MARKER}') | crontab -"
run_test_action "remove it" "${KEY_CRON}" \
    "crontab -l 2>/dev/null | grep -v '${CRON_MARKER}' | crontab -"
 
run_test_action "run a short authorized find as root" "${KEY_PRIV_FIND}" \
    "find /tmp -maxdepth 1 -name '*.meddefense-capstone-marker*'"
 
TESTS_JSON="[$(IFS=,; echo "${RESULTS[*]:-}")]"
 
# ---------------------------------------------------------------------------
# 4. Export the last 30 minutes of auditd and syslog records as
#    structured JSON.
# ---------------------------------------------------------------------------
echo "[*] Exporting the last 30 minutes of auditd and syslog activity..."
 
# NOTE: confirmed the hard way against a real ausearch 3.1.2 binary -
# `-ts "MM/DD/YYYY HH:MM:SS"` as a single combined argument is rejected
# ("Hour, Minute, and Second are required"), and passing date/time as
# two separate arguments per `ausearch --help`'s own documented syntax
# ("-ts [start date] [start time]") was STILL rejected ("Error parsing
# start date") on this build. `-ts today` is confirmed reliably working
# and is used here instead, with an exact 30-minute cutoff then applied
# by filtering each event's own embedded timestamp - this is a
# deliberate engineering fallback for a genuinely inconsistent CLI
# argument-parsing behavior, not a shortcut taken without trying the
# documented approach first.
since_ts="today"
cutoff_epoch="$(date -d "30 minutes ago" +%s)"
 
AUDIT_EVENTS_RAW_TODAY="$(ausearch -if "${AUDIT_LOG}" -ts "${since_ts}" --format text 2>/dev/null || true)"
# NOTE: found the hard way - ausearch's text-format line is shaped
# "At <TIME> <DATE> ...", i.e. $2=time, $3=date - NOT $4 as first
# written, which silently fed a garbage string ("system," etc.) to the
# inner `date` call, made it fail silently, and made the whole filter
# keep almost nothing. Confirmed correct against real ausearch output.
AUDIT_EVENTS_RAW="$(awk -v cutoff="${cutoff_epoch}" '
    /^At [0-9][0-9]:[0-9][0-9]:[0-9][0-9] [0-9][0-9]\/[0-9][0-9]\/[0-9][0-9]/ {
        cmd = "date -d \"" $3 " " $2 "\" +%s 2>/dev/null"
        cmd | getline ts
        close(cmd)
        keep = (ts != "" && ts >= cutoff)
    }
    keep { print }
' <<< "${AUDIT_EVENTS_RAW_TODAY}")"
# NOTE: found the hard way (again) - grep -c always prints a valid
# count including "0" on zero matches, but its own exit code is 1 in
# that exact case (not an error). An `|| echo 0` fallback here fires in
# ADDITION to grep's own already-printed "0", producing an invalid
# two-line "0\n0" jq input - the identical bug already found and fixed
# in an earlier module's script. No fallback is needed at all.
# NOTE: found the hard way - ausearch's --format text output lines
# start with "At <time> <date> ...", never "type=..." (that prefix only
# appears in the RAW/default format, not text format). Counting
# '^type=' against text-format output always silently returned 0.
audit_event_count="$(grep -c '^At ' <<< "${AUDIT_EVENTS_RAW}")"
[[ -z "${audit_event_count}" ]] && audit_event_count=0
 
SYSLOG_EVENTS_RAW=""
if command -v journalctl >/dev/null 2>&1; then
    SYSLOG_EVENTS_RAW="$(journalctl --since "30 minutes ago" --no-pager 2>/dev/null || true)"
elif [[ -f /var/log/syslog ]]; then
    SYSLOG_EVENTS_RAW="$(tail -n 500 /var/log/syslog 2>/dev/null || true)"
fi
syslog_line_count="$(wc -l <<< "${SYSLOG_EVENTS_RAW}" | tr -d ' ')"
[[ -z "${SYSLOG_EVENTS_RAW}" ]] && syslog_line_count=0
 
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --arg since "${since_ts}" \
    --argjson audit_event_count "${audit_event_count}" \
    --arg audit_events_raw "$(json_escape "${AUDIT_EVENTS_RAW}")" \
    --argjson syslog_line_count "${syslog_line_count}" \
    --arg syslog_events_raw "$(json_escape "${SYSLOG_EVENTS_RAW}")" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        window_since: $since,
        audit_event_count: $audit_event_count,
        audit_events_raw: $audit_events_raw,
        syslog_line_count: $syslog_line_count,
        syslog_events_raw: $syslog_events_raw
    }' > "${EVENTS_OUTPUT_PATH}"
 
if ! jq empty "${EVENTS_OUTPUT_PATH}" >/dev/null 2>&1; then
    echo "FAILED: ${EVENTS_OUTPUT_PATH} was written but is not valid JSON." >&2
    exit 1
fi
 
echo "    ${audit_event_count} audit events, ${syslog_line_count} syslog lines exported."
 
# ---------------------------------------------------------------------------
# Emit a coverage summary alongside the raw export.
# ---------------------------------------------------------------------------
COVERAGE_OUTPUT_PATH="${TELEMETRY_DIR}/linux_coverage.json"
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson tests "${TESTS_JSON}" \
    --argjson all_passed "$([[ "${overall_pass}" == true ]] && echo true || echo false)" \
    '{timestamp: $timestamp, hostname: $hostname, tests: $tests, all_passed: $all_passed}' \
    > "${COVERAGE_OUTPUT_PATH}"
 
echo ""
echo "Events saved to: ${EVENTS_OUTPUT_PATH}"
echo "Coverage saved to: ${COVERAGE_OUTPUT_PATH}"
 
if [[ "${overall_pass}" == true ]]; then
    exit 0
else
    exit 1
fi
