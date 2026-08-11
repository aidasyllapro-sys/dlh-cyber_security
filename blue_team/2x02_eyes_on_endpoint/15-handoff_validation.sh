#!/bin/bash
#
# script name : 15-handoff_validation.sh
# purpose     : run the final quality gate against telemetry_handoff/
#               before it crosses from builder to analyst use: file
#               existence, JSON validity, required field presence on
#               every event (timestamp, hostname, source_type,
#               event_category), minimum event counts per source
#               (Windows >= 1000, Linux >= 500, ground truth >= 10),
#               timestamp consistency (valid ISO 8601, no future
#               timestamps, overall range), cross-platform time range
#               overlap, and ground truth completeness against both
#               detection matrices. Reports PASS/FAIL per check with a
#               final verdict and writes handoff_validation.json.
#               Uses jq for all JSON parsing.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
# Every individual validation check below is EXPECTED to potentially fail
# as part of normal operation - that is the entire purpose of this script,
# not a bug. With -e active, every command whose non-zero exit is normal
# control flow (a check condition, a fallback default) is guarded with an
# explicit "if" or "|| default" so a failing CHECK never aborts the run
# before the remaining checks and the final report are produced.
 
HANDOFF_DIR="telemetry_handoff"
WINDOWS_EVENTS_PATH="${HANDOFF_DIR}/windows_events.json"
LINUX_EVENTS_PATH="${HANDOFF_DIR}/linux_events.json"
GROUND_TRUTH_PATH="${HANDOFF_DIR}/attack_ground_truth.json"
WINDOWS_DETECTION_PATH="windows_detection_matrix.json"
LINUX_DETECTION_PATH="linux_detection_matrix.json"
OUTPUT_PATH="handoff_validation.json"
 
MIN_WINDOWS_EVENTS=1000
MIN_LINUX_EVENTS=500
MIN_GROUND_TRUTH_ACTIONS=10
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to validate the JSON handoff package. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
echo "[*] Validating ${HANDOFF_DIR}/ ..."
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
format_number() {
    echo "$1" | rev | sed 's/\([0-9]\{3\}\)/\1,/g' | rev | sed 's/^,//'
}
 
TOTAL_CHECKS=0
PASSED_CHECKS=0
CHECK_RESULTS=()
 
check() {
    local description="$1" passed="$2" detail="${3:-}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ "${passed}" == "true" ]]; then
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        echo "[PASS] ${description}"
    else
        echo "[FAIL] ${description}"
    fi
    CHECK_RESULTS+=("$(printf '{"check":"%s","status":"%s","detail":"%s"}' \
        "$(json_escape "${description}")" "$( [[ "${passed}" == "true" ]] && echo PASS || echo FAIL )" "$(json_escape "${detail}")")")
}
 
human_size() {
    local bytes
    bytes="$(stat -c %s "$1" 2>/dev/null || echo 0)"
    awk -v b="${bytes}" 'BEGIN {
        if (b >= 1048576) { printf "%.1f MB", b/1048576 }
        else if (b >= 1024) { printf "%.1f KB", b/1024 }
        else { printf "%d B", b }
    }'
}
 
# ---------------------------------------------------------------------------
# 1. File existence
# ---------------------------------------------------------------------------
echo "=== File Existence ==="
files_ok=true
for name in windows_events.json linux_events.json attack_ground_truth.json; do
    path="${HANDOFF_DIR}/${name}"
    if [[ -f "${path}" ]]; then
        size="$(human_size "${path}")"
        check "${name} exists (${size})" "true"
    else
        check "${name} exists" "false" "file not found at ${path}"
        files_ok=false
    fi
done
 
if [[ "${files_ok}" != "true" ]]; then
    echo "VERDICT: FAIL (${PASSED_CHECKS}/${TOTAL_CHECKS} checks) - one or more required files are missing, cannot continue." >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 2. JSON validity
# ---------------------------------------------------------------------------
echo "=== JSON Validity ==="
json_ok=true
 
if jq empty "${WINDOWS_EVENTS_PATH}" >/dev/null 2>&1; then
    w_obj_count="$(jq '.events | length' "${WINDOWS_EVENTS_PATH}" 2>/dev/null || echo 0)"
    check "windows_events.json: valid JSON, ${w_obj_count} objects" "true"
else
    check "windows_events.json: valid JSON" "false" "failed to parse"
    json_ok=false
fi
 
if jq empty "${LINUX_EVENTS_PATH}" >/dev/null 2>&1; then
    l_obj_count="$(jq '.events | length' "${LINUX_EVENTS_PATH}" 2>/dev/null || echo 0)"
    check "linux_events.json: valid JSON, ${l_obj_count} objects" "true"
else
    check "linux_events.json: valid JSON" "false" "failed to parse"
    json_ok=false
fi
 
if jq empty "${GROUND_TRUTH_PATH}" >/dev/null 2>&1; then
    gt_obj_count="$(jq '.total_actions' "${GROUND_TRUTH_PATH}" 2>/dev/null || echo 0)"
    check "attack_ground_truth.json: valid JSON, ${gt_obj_count} objects" "true"
else
    check "attack_ground_truth.json: valid JSON" "false" "failed to parse"
    json_ok=false
fi
 
if [[ "${json_ok}" != "true" ]]; then
    echo "VERDICT: FAIL (${PASSED_CHECKS}/${TOTAL_CHECKS} checks) - one or more files are not valid JSON, cannot continue." >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 3. Required fields
# ---------------------------------------------------------------------------
echo "=== Required Fields ==="
w_fields_ok="$(jq '[.events[] | (has("timestamp") and has("hostname") and has("source_type") and has("event_category"))] | all' "${WINDOWS_EVENTS_PATH}")"
l_fields_ok="$(jq '[.events[] | (has("timestamp") and has("hostname") and has("source_type") and has("event_category"))] | all' "${LINUX_EVENTS_PATH}")"
if [[ "${w_fields_ok}" == "true" && "${l_fields_ok}" == "true" ]]; then
    check "All events have timestamp, hostname, source_type, event_category" "true"
else
    check "All events have timestamp, hostname, source_type, event_category" "false" "windows_ok=${w_fields_ok} linux_ok=${l_fields_ok}"
fi
 
# ---------------------------------------------------------------------------
# 4. Minimum event counts
# ---------------------------------------------------------------------------
echo "=== Minimum Event Counts ==="
if [[ "${w_obj_count}" -ge "${MIN_WINDOWS_EVENTS}" ]]; then
    check "Windows: $(format_number "${w_obj_count}") >= $(format_number "${MIN_WINDOWS_EVENTS}")" "true"
else
    check "Windows: $(format_number "${w_obj_count}") >= $(format_number "${MIN_WINDOWS_EVENTS}")" "false" "below minimum"
fi
 
if [[ "${l_obj_count}" -ge "${MIN_LINUX_EVENTS}" ]]; then
    check "Linux: $(format_number "${l_obj_count}") >= $(format_number "${MIN_LINUX_EVENTS}")" "true"
else
    check "Linux: $(format_number "${l_obj_count}") >= $(format_number "${MIN_LINUX_EVENTS}")" "false" "below minimum"
fi
 
if [[ "${gt_obj_count}" -ge "${MIN_GROUND_TRUTH_ACTIONS}" ]]; then
    check "Ground truth: $(format_number "${gt_obj_count}") >= $(format_number "${MIN_GROUND_TRUTH_ACTIONS}")" "true"
else
    check "Ground truth: $(format_number "${gt_obj_count}") >= $(format_number "${MIN_GROUND_TRUTH_ACTIONS}")" "false" "below minimum"
fi
 
# ---------------------------------------------------------------------------
# 5. Timestamp consistency
# ---------------------------------------------------------------------------
echo "=== Timestamp Consistency ==="
ISO_UTC_REGEX='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
 
w_invalid_ts="$(jq --arg re "${ISO_UTC_REGEX}" '[.events[].timestamp | select(test($re) | not)] | length' "${WINDOWS_EVENTS_PATH}")"
l_invalid_ts="$(jq --arg re "${ISO_UTC_REGEX}" '[.events[].timestamp | select(test($re) | not)] | length' "${LINUX_EVENTS_PATH}")"
if [[ "${w_invalid_ts}" -eq 0 && "${l_invalid_ts}" -eq 0 ]]; then
    check "All timestamps valid ISO 8601" "true"
else
    check "All timestamps valid ISO 8601" "false" "windows_invalid=${w_invalid_ts} linux_invalid=${l_invalid_ts}"
fi
 
now_epoch="$(date -u +%s)"
w_max_epoch="$(jq -r '[.events[].timestamp] | max' "${WINDOWS_EVENTS_PATH}" | xargs -I{} date -u -d {} +%s 2>/dev/null || echo 0)"
l_max_epoch="$(jq -r '[.events[].timestamp] | max' "${LINUX_EVENTS_PATH}" | xargs -I{} date -u -d {} +%s 2>/dev/null || echo 0)"
if [[ "${w_max_epoch}" -le "${now_epoch}" && "${l_max_epoch}" -le "${now_epoch}" ]]; then
    check "No future timestamps" "true"
else
    check "No future timestamps" "false" "one or more timestamps are later than the current time"
fi
 
w_min_ts="$(jq -r '[.events[].timestamp] | min' "${WINDOWS_EVENTS_PATH}")"
w_max_ts="$(jq -r '[.events[].timestamp] | max' "${WINDOWS_EVENTS_PATH}")"
l_min_ts="$(jq -r '[.events[].timestamp] | min' "${LINUX_EVENTS_PATH}")"
l_max_ts="$(jq -r '[.events[].timestamp] | max' "${LINUX_EVENTS_PATH}")"
overall_min_ts="$(printf '%s\n%s\n' "${w_min_ts}" "${l_min_ts}" | sort | head -1)"
overall_max_ts="$(printf '%s\n%s\n' "${w_max_ts}" "${l_max_ts}" | sort | tail -1)"
check "Range: ${overall_min_ts} to ${overall_max_ts}" "true"
 
# ---------------------------------------------------------------------------
# 6. Cross-platform alignment
# ---------------------------------------------------------------------------
echo "=== Cross-Platform Alignment ==="
w_min_epoch="$(date -u -d "${w_min_ts}" +%s 2>/dev/null || echo 0)"
w_max_epoch2="$(date -u -d "${w_max_ts}" +%s 2>/dev/null || echo 0)"
l_min_epoch="$(date -u -d "${l_min_ts}" +%s 2>/dev/null || echo 0)"
l_max_epoch2="$(date -u -d "${l_max_ts}" +%s 2>/dev/null || echo 0)"
 
overlap_start=$(( w_min_epoch > l_min_epoch ? w_min_epoch : l_min_epoch ))
overlap_end=$(( w_max_epoch2 < l_max_epoch2 ? w_max_epoch2 : l_max_epoch2 ))
overlap_seconds=$(( overlap_end - overlap_start ))
 
if [[ "${overlap_seconds}" -gt 0 ]]; then
    overlap_hours="$(awk -v s="${overlap_seconds}" 'BEGIN { printf "%.1f", s/3600 }')"
    check "Windows and Linux time ranges overlap (${overlap_hours} hours shared)" "true"
else
    check "Windows and Linux time ranges overlap" "false" "no overlap between the two platforms' time ranges"
fi
 
# ---------------------------------------------------------------------------
# 7. Ground truth completeness
#    An action "has a corresponding detection matrix entry" if its
#    action_number appears anywhere in that platform's detection matrix -
#    CAPTURED or MISSED both count as a recorded entry; this checks that
#    every simulated action was accounted for, not that it was detected
#    (detection rate is what Tasks 10/12/14 already measure).
# ---------------------------------------------------------------------------
echo "=== Ground Truth Completeness ==="
if [[ -f "${WINDOWS_DETECTION_PATH}" && -f "${LINUX_DETECTION_PATH}" ]]; then
    matched_count="$(jq -n \
        --slurpfile gt "${GROUND_TRUTH_PATH}" \
        --slurpfile wdet "${WINDOWS_DETECTION_PATH}" \
        --slurpfile ldet "${LINUX_DETECTION_PATH}" \
        '
        ($gt[0].windows // [] | map(.action_number)) as $wgt |
        ($gt[0].linux // [] | map(.action_number)) as $lgt |
        ($wdet[0].matrix // [] | map(.action_number) | unique) as $wmatrix |
        ($ldet[0].matrix // [] | map(.action_number) | unique) as $lmatrix |
        (($wgt | map(select(. as $a | $wmatrix | index($a)))) | length) as $wmatched |
        (($lgt | map(select(. as $a | $lmatrix | index($a)))) | length) as $lmatched |
        ($wmatched + $lmatched)
        ' 2>/dev/null || echo -1)"
    if [[ "${matched_count}" -eq "${gt_obj_count}" ]]; then
        check "${matched_count}/${gt_obj_count} actions have detection matrix entries" "true"
    else
        check "${matched_count}/${gt_obj_count} actions have detection matrix entries" "false" "one or more ground truth actions have no corresponding detection matrix entry"
    fi
else
    check "Ground truth completeness" "false" "windows_detection_matrix.json and/or linux_detection_matrix.json not found - run Tasks 10/12 first"
fi
 
# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
if [[ "${PASSED_CHECKS}" -eq "${TOTAL_CHECKS}" ]]; then
    verdict="PASS"
    echo "VERDICT: PASS (${PASSED_CHECKS}/${TOTAL_CHECKS} checks)"
    echo "Handoff package is ready for Module 3."
else
    verdict="FAIL"
    echo "VERDICT: FAIL (${PASSED_CHECKS}/${TOTAL_CHECKS} checks)"
    echo "Handoff package is NOT ready - review the [FAIL] items above before handing off to Module 3."
fi
 
{
    printf '{'
    printf '"generated":"%s",' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '"verdict":"%s",' "${verdict}"
    printf '"passed_checks":%s,' "${PASSED_CHECKS}"
    printf '"total_checks":%s,' "${TOTAL_CHECKS}"
    printf '"checks":['
    for idx in "${!CHECK_RESULTS[@]}"; do
        [[ "${idx}" -gt 0 ]] && printf ','
        printf '%s' "${CHECK_RESULTS[$idx]}"
    done
    printf ']'
    printf '}'
} > "${OUTPUT_PATH}"
 
echo "Report saved to: ${OUTPUT_PATH}"
 
[[ "${verdict}" == "PASS" ]]
