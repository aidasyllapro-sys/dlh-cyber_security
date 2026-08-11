#!/bin/bash
#
# script name : 12-linux_detection_proof.sh
# purpose     : read linux_attack_log.json (the ground truth produced by
#               11-linux_attack_sim.sh) and, for each of the 6 simulated
#               actions, search auditd (via ausearch, keyed on the
#               auditd_key recorded in the ground truth), auth.log and
#               syslog within a +/-30 second window around the recorded
#               timestamp. Records which source(s) captured each action,
#               the audit key (when applicable), the detail level (Full /
#               Partial / Missed) and produces a detection matrix proving
#               whether the 2x00 baseline plus the 2x02 Task 5 auditd
#               refinements provide adequate coverage. Writes the result
#               to linux_detection_matrix.json.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (ausearch requires root to read audit records). Try: sudo $0" >&2
    exit 1
fi
 
GROUND_TRUTH_PATH="linux_attack_log.json"
OUTPUT_PATH="linux_detection_matrix.json"
AUTH_LOG="/var/log/auth.log"
SYSLOG_FILE="/var/log/syslog"
WINDOW_SECONDS=30
 
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input)    GROUND_TRUTH_PATH="$2"; shift 2 ;;
        --output)   OUTPUT_PATH="$2"; shift 2 ;;
        --auth-log) AUTH_LOG="$2"; shift 2 ;;
        --syslog)   SYSLOG_FILE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done
 
if ! command -v ausearch >/dev/null 2>&1; then
    echo "ausearch not found. Is the audit package installed?" >&2
    exit 1
fi
 
if [[ ! -f "${GROUND_TRUTH_PATH}" ]]; then
    echo "Ground truth not found: ${GROUND_TRUTH_PATH}. Run 11-linux_attack_sim.sh first (or pass --input)." >&2
    exit 1
fi
 
GROUND_TRUTH_RAW="$(cat "${GROUND_TRUTH_PATH}")"
 
# ---------------------------------------------------------------------------
# Lightweight field extraction (no jq dependency) - relies on the ground
# truth being the flat, compact single-line JSON that 11-linux_attack_sim.sh
# produces. Works by anchoring on the target action_number and lazily
# matching forward to the next occurrence of the requested field, which is
# safe here because each action object contains exactly one instance of
# each field name.
# ---------------------------------------------------------------------------
get_field() {
    local action_num="$1" field="$2"
    echo "${GROUND_TRUTH_RAW}" | grep -oP "\"action_number\":${action_num},.*?\"${field}\":\"\K[^\"]*" | head -1 || true
}
 
action_count="$(echo "${GROUND_TRUTH_RAW}" | grep -oP '"action_number":\K[0-9]+' | sort -un | wc -l | tr -d ' ')"
echo "[*] Loading ground truth (${action_count} actions)..."
echo "[*] Searching telemetry..."
 
# Action 1 ("Create user") and Action 6 ("Access /etc/shadow") are expected
# to be tagged with the auditd key "identity" in the ground truth, per the
# 2x00 baseline rule watching identity files (/etc/passwd, /etc/shadow,
# /etc/group) - this script reads whatever key the ground truth actually
# provides rather than hardcoding "identity", so it stays correct if your
# meddefense.rules uses a different tag.
declare -A ACTION_LABELS=(
    [1]="Create user"
    [2]="Modify sudoers"
    [3]="Execute from /tmp"
    [4]="Reverse shell"
    [5]="Cron persistence"
    [6]="Access /etc/shadow"
)
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
epoch_to_local_ausearch_time() {
    date -d "@${1}" +"%m/%d/%Y %H:%M:%S"
}
 
epoch_from_syslog_line() {
    local line="$1" mon day time
    read -r mon day time _ <<< "${line}"
    [[ -z "${mon}" || -z "${day}" || -z "${time}" ]] && return 1
    date -d "${mon} ${day} ${time}" +%s 2>/dev/null
}
 
# search_auditd <key> <start_epoch> <end_epoch> -> prints ausearch output, or nothing
search_auditd() {
    local key="$1" start_epoch="$2" end_epoch="$3"
    local start_local end_local
    start_local="$(epoch_to_local_ausearch_time "${start_epoch}")"
    end_local="$(epoch_to_local_ausearch_time "${end_epoch}")"
    ausearch -k "${key}" -ts "${start_local}" -te "${end_local}" 2>/dev/null || true
}
 
# search_text_log <file> <start_epoch> <end_epoch> <pattern> -> prints first matching line, or nothing
search_text_log() {
    local file="$1" start_epoch="$2" end_epoch="$3" pattern="$4"
    [[ -r "${file}" ]] || return 0
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        local epoch
        epoch="$(epoch_from_syslog_line "${line}" || true)"
        [[ -z "${epoch}" ]] && continue
        if [[ "${epoch}" -ge "${start_epoch}" && "${epoch}" -le "${end_epoch}" ]]; then
            if echo "${line}" | grep -qiE "${pattern}"; then
                echo "${line}"
                return 0
            fi
        fi
    done < "${file}"
}
 
MATRIX_ROWS_JSON=()
captured_action_count=0
multi_source_count=0
 
TABLE_LINES=()
TABLE_LINES+=("$(printf '%-25s %-14s %-16s %-9s %-10s' "Action" "Source" "Key" "Detail" "Status")")
TABLE_LINES+=("$(printf '%-25s %-14s %-16s %-9s %-10s' "------" "------" "---" "------" "------")")
 
for i in $(seq 1 6); do
    description="$(get_field "${i}" "description")"
    timestamp="$(get_field "${i}" "timestamp")"
    auditd_key="$(get_field "${i}" "auditd_key")"
    label="${ACTION_LABELS[${i}]:-${description}}"
 
    if [[ -z "${timestamp}" ]]; then
        echo "Warning: could not find action ${i} in ${GROUND_TRUTH_PATH}; skipping." >&2
        continue
    fi
 
    center_epoch="$(date -d "${timestamp}" +%s)"
    start_epoch=$((center_epoch - WINDOW_SECONDS))
    end_epoch=$((center_epoch + WINDOW_SECONDS))
 
    sources_captured=0
    first_row_for_action=1
 
    # --- auditd ---
    if [[ -n "${auditd_key}" ]]; then
        auditd_output="$(search_auditd "${auditd_key}" "${start_epoch}" "${end_epoch}")"
        if [[ -n "${auditd_output}" ]]; then
            sources_captured=$((sources_captured + 1))
            display_action=""
            [[ "${first_row_for_action}" -eq 1 ]] && display_action="${label}"
            first_row_for_action=0
            TABLE_LINES+=("$(printf '%-25s %-14s %-16s %-9s %-10s' "${display_action}" "auditd" "${auditd_key}" "Full" "[CAPTURED]")")
            MATRIX_ROWS_JSON+=("$(printf '{"action_number":%s,"action":"%s","source":"auditd","key":"%s","detail":"Full","status":"CAPTURED"}' \
                "${i}" "$(json_escape "${label}")" "$(json_escape "${auditd_key}")")")
        fi
    fi
 
    # --- auth.log (only actions where it is plausibly relevant: user creation) ---
    if [[ "${i}" -eq 1 ]]; then
        auth_line="$(search_text_log "${AUTH_LOG}" "${start_epoch}" "${end_epoch}" 'useradd')"
        if [[ -n "${auth_line}" ]]; then
            sources_captured=$((sources_captured + 1))
            display_action=""
            [[ "${first_row_for_action}" -eq 1 ]] && display_action="${label}"
            first_row_for_action=0
            TABLE_LINES+=("$(printf '%-25s %-14s %-16s %-9s %-10s' "${display_action}" "auth.log" "useradd" "Full" "[CAPTURED]")")
            MATRIX_ROWS_JSON+=("$(printf '{"action_number":%s,"action":"%s","source":"auth.log","key":"useradd","detail":"Full","status":"CAPTURED"}' \
                "${i}" "$(json_escape "${label}")")")
        fi
    fi
 
    # --- syslog (only action where it is plausibly relevant: malformed cron.d entry) ---
    if [[ "${i}" -eq 5 ]]; then
        syslog_line="$(search_text_log "${SYSLOG_FILE}" "${start_epoch}" "${end_epoch}" 'cron')"
        if [[ -n "${syslog_line}" ]]; then
            sources_captured=$((sources_captured + 1))
            display_action=""
            [[ "${first_row_for_action}" -eq 1 ]] && display_action="${label}"
            first_row_for_action=0
            TABLE_LINES+=("$(printf '%-25s %-14s %-16s %-9s %-10s' "${display_action}" "syslog" "cron" "Partial" "[CAPTURED]")")
            MATRIX_ROWS_JSON+=("$(printf '{"action_number":%s,"action":"%s","source":"syslog","key":"cron","detail":"Partial","status":"CAPTURED"}' \
                "${i}" "$(json_escape "${label}")")")
        fi
    fi
 
    if [[ "${sources_captured}" -eq 0 ]]; then
        TABLE_LINES+=("$(printf '%-25s %-14s %-16s %-9s %-10s' "${label}" "-" "-" "Missed" "[MISSED]")")
        MATRIX_ROWS_JSON+=("$(printf '{"action_number":%s,"action":"%s","source":"-","key":"-","detail":"Missed","status":"MISSED"}' \
            "${i}" "$(json_escape "${label}")")")
    else
        captured_action_count=$((captured_action_count + 1))
        [[ "${sources_captured}" -gt 1 ]] && multi_source_count=$((multi_source_count + 1))
    fi
done
 
for line in "${TABLE_LINES[@]}"; do
    echo "${line}"
done
 
capture_pct=0
[[ "${action_count}" -gt 0 ]] && capture_pct=$(( (captured_action_count * 100) / action_count ))
echo "Actions: ${action_count} | Captured: ${captured_action_count}/${action_count} (${capture_pct}%) | Multi-source: ${multi_source_count}"
 
{
    printf '{'
    printf '"generated":"%s",' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '"ground_truth_source":"%s",' "$(json_escape "${GROUND_TRUTH_PATH}")"
    printf '"window_seconds":%s,' "${WINDOW_SECONDS}"
    printf '"total_actions":%s,' "${action_count}"
    printf '"captured_actions":%s,' "${captured_action_count}"
    printf '"capture_rate_pct":%s,' "${capture_pct}"
    printf '"multi_source_count":%s,' "${multi_source_count}"
    printf '"matrix":['
    for idx in "${!MATRIX_ROWS_JSON[@]}"; do
        [[ "${idx}" -gt 0 ]] && printf ','
        printf '%s' "${MATRIX_ROWS_JSON[$idx]}"
    done
    printf ']'
    printf '}'
} > "${OUTPUT_PATH}"
 
echo "Report saved to: ${OUTPUT_PATH}"
