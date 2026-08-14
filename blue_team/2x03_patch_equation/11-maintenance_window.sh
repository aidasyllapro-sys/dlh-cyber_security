#!/bin/bash
#
# script name : 11-maintenance_window.sh
# purpose     : maintenance window guard - reads a declarative
#               maintenance_windows.json (timezone + named windows, each
#               with allowed days, a start/end time, an optional
#               week-of-month restriction, or an "always" emergency
#               escape hatch), and answers a single question: is a patch
#               operation allowed to run right now? Pure decision logic -
#               this script never touches package state, only decides
#               whether another script is allowed to. Supports --check
#               (exit-code decision), --wait <seconds> (poll until a
#               window opens or timeout), and --report (JSON only).
# author      : Aïda Sylla
# date        : 2026-08-12
#
# MedDefense's declared window names (see maintenance_windows.json): the
# "standard" weekly window (Saturday 02:00-06:00), the "extended" window
# (Saturday 00:00-08:00, first week of the month only), and the "emergency"
# always-on escape hatch. This script itself never hardcodes logic around
# these three specific names - every window is evaluated generically from
# whatever entries are declared in the "windows" array of that JSON - but
# "standard", "extended", and "emergency" are the names this project's own
# config actually uses, and are referenced here for clarity.
 
set -uo pipefail
# NOTE: deliberately not using -e. Being outside every window, or only the
# emergency window applying, are expected, meaningful decisions this
# script exists to report - not script bugs.
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WINDOWS_PATH="${SCRIPT_DIR}/maintenance_windows.json"
OUTPUT_PATH="${SCRIPT_DIR}/maintenance_window.json"
SEARCH_HORIZON_DAYS=35
POLL_INTERVAL_SECONDS=30
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read maintenance_windows.json and write the report. Install it (e.g. apt install jq) and re-run." >&2
    exit 20
fi
 
if [[ ! -f "${WINDOWS_PATH}" ]]; then
    echo "maintenance_windows.json not found at ${WINDOWS_PATH}." >&2
    exit 20
fi
if ! jq empty "${WINDOWS_PATH}" >/dev/null 2>&1; then
    echo "maintenance_windows.json is not valid JSON: ${WINDOWS_PATH}" >&2
    exit 20
fi
 
# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
MODE="check"
WAIT_SECONDS=0
 
if [[ $# -eq 0 ]]; then
    MODE="check"
elif [[ "$1" == "--check" ]]; then
    MODE="check"
elif [[ "$1" == "--report" ]]; then
    MODE="report"
elif [[ "$1" == "--wait" ]]; then
    MODE="wait"
    WAIT_SECONDS="${2:-}"
    if [[ -z "${WAIT_SECONDS}" || ! "${WAIT_SECONDS}" =~ ^[0-9]+$ ]]; then
        echo "Usage: $0 --wait <seconds>" >&2
        exit 20
    fi
else
    echo "Usage: $0 [--check | --wait <seconds> | --report]" >&2
    exit 20
fi
 
TZ_NAME="$(jq -r '.timezone' "${WINDOWS_PATH}")"
window_count="$(jq '.windows | length' "${WINDOWS_PATH}")"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
# ---------------------------------------------------------------------------
# hm_to_minutes "HH:MM" -> integer minutes since midnight, for safe
# arithmetic comparison rather than relying on lexical string ordering.
# ---------------------------------------------------------------------------
hm_to_minutes() {
    local hm="$1" h m
    h="${hm%%:*}"; m="${hm##*:}"
    echo $((10#${h} * 60 + 10#${m}))
}
 
week_of_month() {
    local day_of_month="$1"
    echo $(( (day_of_month - 1) / 7 + 1 ))
}
 
# Does window $1 (JSON object) match the given day-abbrev/day-of-month/
# time-in-minutes? Non-"always" windows only.
window_matches() {
    local win="$1" day_abbrev="$2" day_of_month="$3" minutes="$4"
    local is_always start end wom start_min end_min wom_actual
 
    is_always="$(jq -r '.always // false' <<< "${win}")"
    [[ "${is_always}" == "true" ]] && return 1  # handled separately as emergency
 
    if ! jq -e --arg d "${day_abbrev}" '.days // [] | index($d) != null' <<< "${win}" >/dev/null 2>&1; then
        return 1
    fi
 
    wom="$(jq -r '.week_of_month // empty' <<< "${win}")"
    if [[ -n "${wom}" ]]; then
        wom_actual="$(week_of_month "${day_of_month}")"
        [[ "${wom}" != "${wom_actual}" ]] && return 1
    fi
 
    start="$(jq -r '.start' <<< "${win}")"
    end="$(jq -r '.end' <<< "${win}")"
    start_min="$(hm_to_minutes "${start}")"
    end_min="$(hm_to_minutes "${end}")"
 
    if [[ "${minutes}" -ge "${start_min}" && "${minutes}" -lt "${end_min}" ]]; then
        return 0
    fi
    return 1
}
 
# ---------------------------------------------------------------------------
# Evaluate "now" against every window. Sets ACTIVE_WINDOW_NAME (or empty),
# and EMERGENCY_ONLY (true/false).
# ---------------------------------------------------------------------------
evaluate_now() {
    local day_abbrev day_of_month minutes i win name is_always
    day_abbrev="$(TZ="${TZ_NAME}" date +%a)"
    day_of_month="$(TZ="${TZ_NAME}" date +%-d)"
    minutes="$(hm_to_minutes "$(TZ="${TZ_NAME}" date +%H:%M)")"
 
    ACTIVE_WINDOW_NAME=""
    EMERGENCY_ONLY="false"
    local emergency_window_present="false"
 
    for i in $(seq 0 $((window_count - 1))); do
        win="$(jq -c ".windows[${i}]" "${WINDOWS_PATH}")"
        name="$(jq -r '.name' <<< "${win}")"
        is_always="$(jq -r '.always // false' <<< "${win}")"
 
        if [[ "${is_always}" == "true" ]]; then
            emergency_window_present="true"
            EMERGENCY_WINDOW_NAME="${name}"
            continue
        fi
 
        if window_matches "${win}" "${day_abbrev}" "${day_of_month}" "${minutes}"; then
            ACTIVE_WINDOW_NAME="${name}"
            return
        fi
    done
 
    if [[ -z "${ACTIVE_WINDOW_NAME}" && "${emergency_window_present}" == "true" ]]; then
        EMERGENCY_ONLY="true"
    fi
}
 
# ---------------------------------------------------------------------------
# Find the next future occurrence of any non-"always" window, scanning
# forward day by day up to SEARCH_HORIZON_DAYS. Sets NEXT_WINDOW_NAME and
# NEXT_WINDOW_EPOCH (empty if none found within the horizon).
# ---------------------------------------------------------------------------
find_next_window() {
    local now_epoch day_offset candidate_date candidate_day_abbrev candidate_dom
    local i win is_always name start candidate_epoch wom wom_actual
    local best_epoch="" best_name=""
 
    now_epoch="$(TZ="${TZ_NAME}" date +%s)"
 
    for day_offset in $(seq 0 "${SEARCH_HORIZON_DAYS}"); do
        candidate_date="$(TZ="${TZ_NAME}" date -d "+${day_offset} days" +%Y-%m-%d)"
        candidate_day_abbrev="$(TZ="${TZ_NAME}" date -d "${candidate_date}" +%a)"
        candidate_dom="$(TZ="${TZ_NAME}" date -d "${candidate_date}" +%-d)"
 
        for i in $(seq 0 $((window_count - 1))); do
            win="$(jq -c ".windows[${i}]" "${WINDOWS_PATH}")"
            is_always="$(jq -r '.always // false' <<< "${win}")"
            [[ "${is_always}" == "true" ]] && continue
 
            if ! jq -e --arg d "${candidate_day_abbrev}" '.days // [] | index($d) != null' <<< "${win}" >/dev/null 2>&1; then
                continue
            fi
            wom="$(jq -r '.week_of_month // empty' <<< "${win}")"
            if [[ -n "${wom}" ]]; then
                wom_actual="$(week_of_month "${candidate_dom}")"
                [[ "${wom}" != "${wom_actual}" ]] && continue
            fi
 
            name="$(jq -r '.name' <<< "${win}")"
            start="$(jq -r '.start' <<< "${win}")"
            candidate_epoch="$(TZ="${TZ_NAME}" date -d "${candidate_date} ${start}" +%s)"
 
            [[ "${candidate_epoch}" -le "${now_epoch}" ]] && continue
 
            if [[ -z "${best_epoch}" || "${candidate_epoch}" -lt "${best_epoch}" ]]; then
                best_epoch="${candidate_epoch}"
                best_name="${name}"
            fi
        done
 
        # Once we have a candidate and have scanned at least a week past
        # it, we can stop early - nothing earlier will appear later.
        if [[ -n "${best_epoch}" && "${day_offset}" -ge 7 ]]; then
            break
        fi
    done
 
    NEXT_WINDOW_NAME="${best_name}"
    NEXT_WINDOW_EPOCH="${best_epoch}"
}
 
# ---------------------------------------------------------------------------
# Build the decision + write the report + print the summary.
# ---------------------------------------------------------------------------
emit_result() {
    local now_display now_epoch decision exit_code seconds_until_next next_display active_json next_name_json next_ts_json seconds_json
    now_display="$(TZ="${TZ_NAME}" date +"%Y-%m-%d %H:%M")"
    now_epoch="$(TZ="${TZ_NAME}" date +%s)"
 
    evaluate_now
 
    if [[ -n "${ACTIVE_WINDOW_NAME}" ]]; then
        decision="proceed"
        exit_code=0
    elif [[ "${EMERGENCY_ONLY}" == "true" ]]; then
        if [[ "${MEDDEFENSE_EMERGENCY:-}" == "1" ]]; then
            decision="proceed (emergency override)"
            ACTIVE_WINDOW_NAME="${EMERGENCY_WINDOW_NAME}"
            exit_code=0
        else
            decision="blocked (emergency override required: set MEDDEFENSE_EMERGENCY=1)"
            exit_code=10
        fi
    else
        decision="defer"
        exit_code=20
    fi
 
    find_next_window
    seconds_until_next=""
    next_display=""
    if [[ -n "${NEXT_WINDOW_EPOCH}" ]]; then
        seconds_until_next=$((NEXT_WINDOW_EPOCH - now_epoch))
        next_display="$(TZ="${TZ_NAME}" date -d "@${NEXT_WINDOW_EPOCH}" +"%Y-%m-%d %H:%M")"
    fi
 
    if [[ "${MODE}" != "report" ]]; then
        echo "now:            ${now_display} ${TZ_NAME} ($(TZ="${TZ_NAME}" date +%a))"
        if [[ -n "${ACTIVE_WINDOW_NAME}" ]]; then
            echo "active window:  ${ACTIVE_WINDOW_NAME}"
        else
            echo "active window:  (none)"
            if [[ -n "${NEXT_WINDOW_NAME}" ]]; then
                echo "next window:    ${NEXT_WINDOW_NAME}  at ${next_display}"
                echo "seconds until:  ${seconds_until_next}"
            fi
        fi
        echo "decision:       ${decision}"
    fi
 
    active_json="null"
    [[ -n "${ACTIVE_WINDOW_NAME}" ]] && active_json="\"$(json_escape "${ACTIVE_WINDOW_NAME}")\""
    next_name_json="null"
    [[ -n "${NEXT_WINDOW_NAME}" ]] && next_name_json="\"$(json_escape "${NEXT_WINDOW_NAME}")\""
    next_ts_json="null"
    [[ -n "${NEXT_WINDOW_EPOCH}" ]] && next_ts_json="\"$(TZ="${TZ_NAME}" date -d "@${NEXT_WINDOW_EPOCH}" -Iseconds)\""
    seconds_json="null"
    [[ -n "${seconds_until_next}" ]] && seconds_json="${seconds_until_next}"
 
    {
        printf '{'
        printf '"now":"%s",' "$(TZ="${TZ_NAME}" date -Iseconds)"
        printf '"timezone":"%s",' "$(json_escape "${TZ_NAME}")"
        printf '"active_window":%s,' "${active_json}"
        printf '"next_window":{"name":%s,"at":%s},' "${next_name_json}" "${next_ts_json}"
        printf '"seconds_until_next":%s,' "${seconds_json}"
        printf '"decision":"%s"' "$(json_escape "${decision}")"
        printf '}'
    } | jq '.' > "${OUTPUT_PATH}"
 
    if [[ "${MODE}" == "report" ]]; then
        cat "${OUTPUT_PATH}"
    else
        echo "Report saved to: $(basename "${OUTPUT_PATH}")"
    fi
 
    return "${exit_code}"
}
 
# ---------------------------------------------------------------------------
# Mode dispatch
# ---------------------------------------------------------------------------
if [[ "${MODE}" == "wait" ]]; then
    deadline=$(( $(date +%s) + WAIT_SECONDS ))
    while true; do
        evaluate_now
        if [[ -n "${ACTIVE_WINDOW_NAME}" ]] || { [[ "${EMERGENCY_ONLY}" == "true" ]] && [[ "${MEDDEFENSE_EMERGENCY:-}" == "1" ]]; }; then
            emit_result
            exit $?
        fi
        if [[ "$(date +%s)" -ge "${deadline}" ]]; then
            emit_result
            exit 20
        fi
        sleep_for=$(( POLL_INTERVAL_SECONDS < WAIT_SECONDS ? POLL_INTERVAL_SECONDS : 1 ))
        sleep "${sleep_for}"
    done
else
    emit_result
    exit $?
fi
