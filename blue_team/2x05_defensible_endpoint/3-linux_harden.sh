#!/bin/bash
#
# script name : 3-linux_harden.sh
# purpose     : orchestrate the full Linux hardening pass on
#               hawthorne-app-01 as a single idempotent workflow -
#               composing the seven already-validated hardening scripts
#               from 2x00_locking_the_gates in a deterministic order,
#               capturing every sub-step's stdout and exit code as
#               structured evidence, re-running Lynis to measure the
#               real before/after delta, and mapping each step back to
#               the specific target_state.json control IDs it is
#               responsible for. This script does not reimplement any
#               hardening logic itself - it composes and measures.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - every sub-step exited 0 AND lynis_after >= the target Hardening
#       Index (LNX-LYNIS-01 in target_state.json)
#   1 - controlled failure (a sub-step failed, or the post-run Hardening
#       Index did not reach the target)
#   2 - environment error (a required sub-step script, target_state.json,
#       or baseline_linux.json is missing; lynis/jq missing)
#
# ASSUMPTION - sub-step script location: this capstone's own directory
# (blue_team/2x05_defensible_endpoint/) is a sibling of
# blue_team/2x00_locking_the_gates/, per the repository layout confirmed
# for this project. Override HARDEN_SCRIPTS_DIR below if the real layout
# differs on the deployment host.
#
# KNOWN GAP - controls_touched mapping: target_state.json (this
# capstone's Task 2 output) only defines dedicated control IDs for SSH
# (LNX-SSH-01/02), sysctl (LNX-SYSCTL-01/02), auditd (LNX-AUDITD-01) and
# AppArmor (LNX-APPARMOR-01). It has no dedicated ID for the filesystem
# permission sweep, service minimization or PAM steps - those three
# steps' controls_touched arrays are correctly empty below, not a bug.
# If Task 2's control set is later expanded to cover them, this mapping
# must be updated to match.
 
set -uo pipefail
# NOTE: deliberately not using -e. A sub-step exiting non-zero, or the
# post-run Hardening Index falling short of the target, are expected,
# meaningful outcomes this script exists to detect and report - not
# script bugs. Every command whose non-zero exit is normal control flow
# (each sub-step invocation) is handled explicitly via the wrapper
# function below, per this task's own hint.
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARDEN_SCRIPTS_DIR="${HARDEN_SCRIPTS_DIR:-${SCRIPT_DIR}/../2x00_locking_the_gates}"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
EXEC_DIR="${CAPSTONE_DIR}/exec"
BASELINE_DIR="${CAPSTONE_DIR}/baseline"
mkdir -p "${EXEC_DIR}"
 
# Per this task's own instructions, the full execution log is written to
# capstone/exec/linux_harden.log (EXEC_DIR + the filename below), and the
# JSON evidence summary to capstone/exec/linux_harden.json.
LOG_PATH="${EXEC_DIR}/linux_harden.log"
OUTPUT_PATH="${EXEC_DIR}/linux_harden.json"
TARGET_STATE_PATH="${CAPSTONE_DIR}/target_state.json"
BASELINE_LINUX_PATH="${BASELINE_DIR}/baseline_linux.json"
 
REQUIRED_TOOLS=(lynis jq)
MISSING_TOOLS=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${tool}" >/dev/null 2>&1 || MISSING_TOOLS+=("${tool}")
done
if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
    echo "Missing required tool(s): ${MISSING_TOOLS[*]}." >&2
    exit 2
fi
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (every hardening sub-step and lynis need elevated access). Try: sudo $0" >&2
    exit 2
fi
 
# A corrupted or missing target_state.json is fatal for this script, per
# this capstone's own explicit rule from Task 2.
if [[ ! -f "${TARGET_STATE_PATH}" ]] || ! jq empty "${TARGET_STATE_PATH}" >/dev/null 2>&1; then
    echo "FATAL: ${TARGET_STATE_PATH} is missing or not valid JSON. Run 2-target_state.sh first. Per this capstone's own rule, a corrupted or missing target_state.json is fatal for every downstream script." >&2
    exit 2
fi
if [[ ! -f "${BASELINE_LINUX_PATH}" ]] || ! jq empty "${BASELINE_LINUX_PATH}" >/dev/null 2>&1; then
    echo "FATAL: ${BASELINE_LINUX_PATH} is missing or not valid JSON. Run 1-baseline_snapshot.sh first." >&2
    exit 2
fi
 
lynis_before="$(jq -r '.hardening_index' "${BASELINE_LINUX_PATH}")"
lynis_target="$(jq -r '.controls[] | select(.id == "LNX-LYNIS-01") | .expected_value' "${TARGET_STATE_PATH}")"
[[ -z "${lynis_target}" || "${lynis_target}" == "null" ]] && lynis_target=80
 
echo "[*] Orchestrating Linux hardening on $(hostname)..."
echo "    Lynis before: ${lynis_before}   Target: >= ${lynis_target}"
: > "${LOG_PATH}"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
# ---------------------------------------------------------------------------
# 1. Deterministic step order, each mapped to its real 2x00 script and
#    the target_state.json control IDs it is responsible for.
# ---------------------------------------------------------------------------
declare -A STEP_SCRIPT=(
    [ssh_hardening]="4-ssh_hardening.sh"
    [sysctl_hardening]="5-sysctl_hardening.sh"
    [permission_sweep]="6-filesystem_hardening.sh"
    [service_minimization]="7-service_minimization.sh"
    [pam_configuration]="8-pam_hardening.sh"
    [apparmor_enforcement]="9-apparmor_config.sh"
    [auditd_deployment]="10-auditd_config.sh"
)
STEP_ORDER=(ssh_hardening sysctl_hardening permission_sweep service_minimization pam_configuration apparmor_enforcement auditd_deployment)
declare -A STEP_CONTROLS=(
    [ssh_hardening]="LNX-SSH-01,LNX-SSH-02"
    [sysctl_hardening]="LNX-SYSCTL-01,LNX-SYSCTL-02"
    [permission_sweep]=""
    [service_minimization]=""
    [pam_configuration]=""
    [apparmor_enforcement]="LNX-APPARMOR-01"
    [auditd_deployment]="LNX-AUDITD-01"
)
 
# ---------------------------------------------------------------------------
# Lightweight before/after state signature per step, used to determine
# the "changed" boolean without depending on any output convention of
# the underlying 2x00 scripts (which this orchestrator does not author
# and must not assume the internals of).
# ---------------------------------------------------------------------------
step_state_signature() {
    case "$1" in
        ssh_hardening)
            md5sum /etc/ssh/sshd_config 2>/dev/null | awk '{print $1}' ;;
        sysctl_hardening)
            { sysctl -n net.ipv4.ip_forward 2>/dev/null; sysctl -n kernel.randomize_va_space 2>/dev/null; } | md5sum | awk '{print $1}' ;;
        permission_sweep)
            find / -xdev -perm -0002 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | wc -l ;;
        service_minimization)
            systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | wc -l ;;
        pam_configuration)
            md5sum /etc/pam.d/common-password 2>/dev/null | awk '{print $1}' ;;
        apparmor_enforcement)
            aa-status 2>/dev/null | grep -oP '^\d+(?= profiles are in enforce mode)' || echo 0 ;;
        auditd_deployment)
            systemctl is-active auditd 2>/dev/null; auditctl -l 2>/dev/null | wc -l ;;
    esac
}
 
# ---------------------------------------------------------------------------
# Wrapper function that runs a sub-step, captures its stdout+exit code
# into the shared log, times it, and determines whether it changed
# anything - per this task's own hint.
# ---------------------------------------------------------------------------
STEP_ENTRIES=()
all_steps_ok=true
 
run_step() {
    local step_key="$1"
    local script_name="${STEP_SCRIPT[${step_key}]}"
    local script_path="${HARDEN_SCRIPTS_DIR}/${script_name}"
 
    echo "" >> "${LOG_PATH}"
    echo "===== STEP: ${step_key} (${script_name}) =====" >> "${LOG_PATH}"
 
    if [[ ! -x "${script_path}" ]]; then
        echo "SCRIPT NOT FOUND OR NOT EXECUTABLE: ${script_path}" | tee -a "${LOG_PATH}" >&2
        STEP_ENTRIES+=("$(jq -n --arg name "${step_key}" --arg path "${script_path}" \
            '{name: $name, script_path: $path, exit_code: 127, duration_seconds: 0, changed: false}')")
        all_steps_ok=false
        return
    fi
 
    local before_sig after_sig changed="false"
    before_sig="$(step_state_signature "${step_key}")"
 
    local start_ts end_ts duration exit_code
    start_ts="$(date +%s.%N)"
    "${script_path}" >> "${LOG_PATH}" 2>&1
    exit_code=$?
    end_ts="$(date +%s.%N)"
    duration="$(awk -v s="${start_ts}" -v e="${end_ts}" 'BEGIN{printf "%.2f", e - s}')"
 
    after_sig="$(step_state_signature "${step_key}")"
    [[ "${before_sig}" != "${after_sig}" ]] && changed="true"
 
    echo "exit_code=${exit_code} duration=${duration}s changed=${changed}" >> "${LOG_PATH}"
 
    if [[ "${exit_code}" -ne 0 ]]; then
        all_steps_ok=false
    fi
 
    STEP_ENTRIES+=("$(jq -n --arg name "${step_key}" --arg path "${script_path}" \
        --argjson exit_code "${exit_code}" --arg duration "${duration}" --argjson changed "${changed}" \
        '{name: $name, script_path: $path, exit_code: $exit_code, duration_seconds: ($duration | tonumber), changed: $changed}')")
 
    echo "    ${step_key}: exit=${exit_code} duration=${duration}s changed=${changed}"
}
 
echo "[*] Running hardening steps in order..."
for step in "${STEP_ORDER[@]}"; do
    run_step "${step}"
done
 
# ---------------------------------------------------------------------------
# 3. Re-run lynis and capture the new Hardening Index.
# ---------------------------------------------------------------------------
echo "[*] Re-running lynis audit system to measure the delta..."
lynis audit system --quick --no-colors >> "${LOG_PATH}" 2>&1
lynis_report="/var/log/lynis-report.dat"
lynis_after="0"
if [[ -f "${lynis_report}" ]]; then
    lynis_after="$(grep -m1 '^hardening_index=' "${lynis_report}" | cut -d= -f2 | tr -d '\r')"
fi
[[ -z "${lynis_after}" ]] && lynis_after=0
 
index_delta=$(( lynis_after - lynis_before ))
echo "    Lynis after: ${lynis_after}   Delta: ${index_delta}"
 
# ---------------------------------------------------------------------------
# controls_touched: union of every step's mapped control IDs.
# ---------------------------------------------------------------------------
CONTROLS_TOUCHED=()
for step in "${STEP_ORDER[@]}"; do
    ids="${STEP_CONTROLS[${step}]}"
    [[ -z "${ids}" ]] && continue
    IFS=',' read -ra id_arr <<< "${ids}"
    for id in "${id_arr[@]}"; do
        CONTROLS_TOUCHED+=("${id}")
    done
done
CONTROLS_TOUCHED_JSON="[$(for id in "${CONTROLS_TOUCHED[@]}"; do printf '"%s",' "$(json_escape "${id}")"; done | sed 's/,$//')]"
 
# ---------------------------------------------------------------------------
# 5. Emit linux_harden.json
# ---------------------------------------------------------------------------
STEPS_JSON="[$(IFS=,; echo "${STEP_ENTRIES[*]:-}")]"
 
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson steps "${STEPS_JSON}" \
    --argjson lynis_before "${lynis_before}" \
    --argjson lynis_after "${lynis_after}" \
    --argjson index_delta "${index_delta}" \
    --argjson controls_touched "${CONTROLS_TOUCHED_JSON}" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        steps: $steps,
        lynis_before: $lynis_before,
        lynis_after: $lynis_after,
        index_delta: $index_delta,
        controls_touched: $controls_touched
    }' > "${OUTPUT_PATH}"
 
if ! jq empty "${OUTPUT_PATH}" >/dev/null 2>&1; then
    echo "FAILED: ${OUTPUT_PATH} was written but is not valid JSON." >&2
    exit 1
fi
 
echo ""
echo "Log saved to: ${LOG_PATH}"
echo "Report saved to: ${OUTPUT_PATH}"
 
# ---------------------------------------------------------------------------
# 4. Final exit logic: 0 only if every sub-step exited 0 AND
#    lynis_after >= target.
# ---------------------------------------------------------------------------
if [[ "${all_steps_ok}" == true ]] && [[ "${lynis_after}" -ge "${lynis_target}" ]]; then
    echo "PASS: all steps succeeded and Hardening Index (${lynis_after}) meets target (${lynis_target})."
    exit 0
else
    echo "FAIL: all_steps_ok=${all_steps_ok}   lynis_after=${lynis_after} vs target=${lynis_target}" >&2
    exit 1
fi
