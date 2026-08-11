#!/bin/bash
#
# script name : 8-linux_telemetry_quality.sh
# purpose     : read linux_events_export.json (produced by 7-linux_export.sh)
#               and assess its quality using the same standard applied to
#               the Windows export: event distribution (per category and
#               per source type), time coverage (events per hour, hours
#               with/without events), gap detection (any period with no
#               events longer than 30 minutes), field completeness (core
#               fields, execve command line, SSH source IP/user, auditd
#               file path), and a weighted 0-100 quality score with a good
#               / acceptable / poor assessment. Uses jq for all JSON
#               parsing. Writes the full report to
#               linux_telemetry_quality.json.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
 
INPUT_PATH="linux_events_export.json"
OUTPUT_PATH="linux_telemetry_quality.json"
GAP_THRESHOLD_MINUTES=30
 
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input)  INPUT_PATH="$2"; shift 2 ;;
        --output) OUTPUT_PATH="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done
 
echo "[*] Analyzing linux_events_export.json..."
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to parse JSON. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
if [[ ! -f "${INPUT_PATH}" ]]; then
    echo "Input file not found: ${INPUT_PATH}. Run 7-linux_export.sh first (or pass --input)." >&2
    exit 1
fi
 
total_events="$(jq '.events | length' "${INPUT_PATH}")"
echo "Total events: ${total_events}"
 
if [[ "${total_events}" -eq 0 ]]; then
    echo "linux_events_export.json contains zero events. Nothing to assess." >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 1. Event distribution - per category and per source type
# ---------------------------------------------------------------------------
CATEGORY_DIST_FILE="$(mktemp)"
SOURCE_DIST_FILE="$(mktemp)"
trap 'rm -f "${CATEGORY_DIST_FILE}" "${SOURCE_DIST_FILE}" "${TS_FILE:-}" "${CORE_FILE:-}"' EXIT
 
jq -r '.events[].event_category' "${INPUT_PATH}" | sort | uniq -c | sort -rn | \
    awk -v total="${total_events}" '{count=$1; $1=""; cat=substr($0,2); pct=(count/total)*100; printf "%s|%d|%.2f\n", cat, count, pct}' \
    > "${CATEGORY_DIST_FILE}"
 
jq -r '.events[].source_type' "${INPUT_PATH}" | sort | uniq -c | sort -rn | \
    awk -v total="${total_events}" '{count=$1; $1=""; src=substr($0,2); pct=(count/total)*100; printf "%s|%d|%.2f\n", src, count, pct}' \
    > "${SOURCE_DIST_FILE}"
 
# ---------------------------------------------------------------------------
# 2. Time coverage - events per hour, hours with/without events
# ---------------------------------------------------------------------------
TS_FILE="$(mktemp)"
jq -r '.events[].timestamp' "${INPUT_PATH}" | sort > "${TS_FILE}"
 
first_ts="$(head -n 1 "${TS_FILE}")"
last_ts="$(tail -n 1 "${TS_FILE}")"
first_epoch="$(date -u -d "${first_ts}" +%s)"
last_epoch="$(date -u -d "${last_ts}" +%s)"
 
total_hours="$(( (last_epoch - first_epoch) / 3600 + 1 ))"
 
declare -A HOUR_COUNTS
while IFS= read -r ts; do
    [[ -z "${ts}" ]] && continue
    hour_key="${ts:0:13}"
    HOUR_COUNTS["${hour_key}"]=$(( ${HOUR_COUNTS["${hour_key}"]:-0} + 1 ))
done < "${TS_FILE}"
 
hours_with_events="${#HOUR_COUNTS[@]}"
hours_without_events=$(( total_hours - hours_with_events ))
[[ "${hours_without_events}" -lt 0 ]] && hours_without_events=0
 
echo "Hours with events: ${hours_with_events}/${total_hours}"
 
# ---------------------------------------------------------------------------
# 3. Gap detection - consecutive-event gaps longer than the threshold
# ---------------------------------------------------------------------------
gap_count=0
largest_gap_minutes=0
GAPS_JSON=""
prev_epoch=""
while IFS= read -r ts; do
    [[ -z "${ts}" ]] && continue
    epoch="$(date -u -d "${ts}" +%s)"
    if [[ -n "${prev_epoch}" ]]; then
        delta_minutes=$(( (epoch - prev_epoch) / 60 ))
        if [[ "${delta_minutes}" -gt "${GAP_THRESHOLD_MINUTES}" ]]; then
            gap_count=$((gap_count + 1))
            [[ "${delta_minutes}" -gt "${largest_gap_minutes}" ]] && largest_gap_minutes="${delta_minutes}"
        fi
    fi
    prev_epoch="${epoch}"
done < "${TS_FILE}"
 
if [[ "${gap_count}" -eq 0 ]]; then
    echo "No gaps detected"
else
    echo "Gaps detected: ${gap_count} | Largest gap: ${largest_gap_minutes} minutes"
fi
 
# ---------------------------------------------------------------------------
# 4. Field completeness
# ---------------------------------------------------------------------------
CORE_FILE="$(mktemp)"
jq -r '.events[] | [(.timestamp!=null and .timestamp!=""), (.hostname!=null and .hostname!=""), (.source_type!=null and .source_type!=""), (.event_category!=null and .event_category!="")] | all' \
    "${INPUT_PATH}" > "${CORE_FILE}"
core_complete_count="$(grep -c '^true$' "${CORE_FILE}" || true)"
required_field_completeness="$(awk -v c="${core_complete_count}" -v t="${total_events}" 'BEGIN { printf "%.2f", (c/t)*100 }')"
 
# execve command_line completeness
execve_total="$(jq -r --arg cat "execve" '.events[] | select(.event_category==$cat) | if (.enrichment.command_line // "")!="" then "1" else "0" end' "${INPUT_PATH}" | wc -l | tr -d ' ')"
execve_complete="$(jq -r --arg cat "execve" '.events[] | select(.event_category==$cat) | if (.enrichment.command_line // "")!="" then "1" else "0" end' "${INPUT_PATH}" | grep -c '^1$' || true)"
if [[ "${execve_total}" -gt 0 ]]; then
    execve_completeness="$(awk -v c="${execve_complete}" -v t="${execve_total}" 'BEGIN { printf "%.2f", (c/t)*100 }')"
    echo "execve command_line completeness: ${execve_completeness}%"
else
    execve_completeness="null"
fi
 
# SSH source_ip + user completeness
ssh_total="$(jq -r --arg cat "ssh_login" '.events[] | select(.event_category==$cat) | if ((.enrichment.source_ip // "")!="" and (.enrichment.user // "")!="") then "1" else "0" end' "${INPUT_PATH}" | wc -l | tr -d ' ')"
ssh_complete="$(jq -r --arg cat "ssh_login" '.events[] | select(.event_category==$cat) | if ((.enrichment.source_ip // "")!="" and (.enrichment.user // "")!="") then "1" else "0" end' "${INPUT_PATH}" | grep -c '^1$' || true)"
if [[ "${ssh_total}" -gt 0 ]]; then
    ssh_completeness="$(awk -v c="${ssh_complete}" -v t="${ssh_total}" 'BEGIN { printf "%.2f", (c/t)*100 }')"
    echo "SSH source_ip completeness: ${ssh_completeness}%"
else
    ssh_completeness="null"
fi
 
# auditd file_access path completeness
# NOTE: 7-linux_export.sh's file_access enrichment currently only populates
# "path" (from the PATH record's name= field) - it does not separately
# capture an "operation" or auditd "key" for file events. This check
# measures completeness of what is actually exported today (path); if
# 7-linux_export.sh is extended to also enrich operation/key, extend this
# check to match rather than silently reporting 100% on an incomplete
# schema.
file_total="$(jq -r --arg cat "file_access" '.events[] | select(.event_category==$cat) | if (.enrichment.path // "")!="" then "1" else "0" end' "${INPUT_PATH}" | wc -l | tr -d ' ')"
file_complete="$(jq -r --arg cat "file_access" '.events[] | select(.event_category==$cat) | if (.enrichment.path // "")!="" then "1" else "0" end' "${INPUT_PATH}" | grep -c '^1$' || true)"
if [[ "${file_total}" -gt 0 ]]; then
    file_completeness="$(awk -v c="${file_complete}" -v t="${file_total}" 'BEGIN { printf "%.2f", (c/t)*100 }')"
    echo "auditd file path completeness: ${file_completeness}%"
else
    file_completeness="null"
fi
 
# ---------------------------------------------------------------------------
# 5. Quality score
#    Same weighting convention as the Windows quality gate
#    (4-windows_telemetry_quality.ps1): a practical scoring convention
#    devised for this task, not an external industry-standard formula.
#      - Time coverage: 25%
#      - Gap penalty (based on largest gap): 15%
#      - Required field completeness: 20%
#      - execve command_line completeness: 15%
#      - SSH source_ip/user completeness: 15%
#      - auditd file path completeness: 10%
#    A dimension with no applicable events is excluded and the remaining
#    weights are rescaled proportionally.
# ---------------------------------------------------------------------------
time_coverage_pct="$(awk -v h="${hours_with_events}" -v t="${total_hours}" 'BEGIN { printf "%.2f", (h/t)*100 }')"
gap_capped="${largest_gap_minutes}"
[[ "${gap_capped}" -gt 100 ]] && gap_capped=100
gap_penalty_pct="$(awk -v g="${gap_capped}" 'BEGIN { v=100-g; if (v<0) v=0; printf "%.2f", v }')"
 
weighted_sum=0
total_weight=0
 
add_component() {
    local value="$1" weight="$2"
    [[ "${value}" == "null" ]] && return 0
    weighted_sum="$(awk -v s="${weighted_sum}" -v v="${value}" -v w="${weight}" 'BEGIN { printf "%.4f", s + (v*w) }')"
    total_weight=$(( total_weight + weight ))
}
 
add_component "${time_coverage_pct}" 25
add_component "${gap_penalty_pct}" 15
add_component "${required_field_completeness}" 20
add_component "${execve_completeness}" 15
add_component "${ssh_completeness}" 15
add_component "${file_completeness}" 10
 
if [[ "${total_weight}" -gt 0 ]]; then
    quality_score="$(awk -v s="${weighted_sum}" -v w="${total_weight}" 'BEGIN { printf "%.1f", s/w }')"
else
    quality_score="0.0"
fi
 
assessment="poor"
awk -v s="${quality_score}" 'BEGIN { exit !(s>=90) }' && assessment="good"
if [[ "${assessment}" == "poor" ]]; then
    awk -v s="${quality_score}" 'BEGIN { exit !(s>=75) }' && assessment="acceptable"
fi
 
echo "Quality score: ${quality_score}% (${assessment})"
 
# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
{
    printf '{'
    printf '"generated":"%s",' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '"source_file":"%s",' "${INPUT_PATH}"
    printf '"total_events":%s,' "${total_events}"
    printf '"event_distribution":{'
    printf '"by_category":['
    first=1
    while IFS='|' read -r name count pct; do
        [[ -z "${name}" ]] && continue
        [[ "${first}" -eq 0 ]] && printf ','
        printf '{"category":"%s","count":%s,"percentage":%s}' "${name}" "${count}" "${pct}"
        first=0
    done < "${CATEGORY_DIST_FILE}"
    printf '],'
    printf '"by_source_type":['
    first=1
    while IFS='|' read -r name count pct; do
        [[ -z "${name}" ]] && continue
        [[ "${first}" -eq 0 ]] && printf ','
        printf '{"source_type":"%s","count":%s,"percentage":%s}' "${name}" "${count}" "${pct}"
        first=0
    done < "${SOURCE_DIST_FILE}"
    printf ']'
    printf '},'
    printf '"time_coverage":{"total_hours":%s,"hours_with_events":%s,"hours_without_events":%s},' \
        "${total_hours}" "${hours_with_events}" "${hours_without_events}"
    printf '"gaps":{"threshold_minutes":%s,"count":%s,"largest_gap_minutes":%s},' \
        "${GAP_THRESHOLD_MINUTES}" "${gap_count}" "${largest_gap_minutes}"
    printf '"field_completeness":{"required_fields_pct":%s,"execve_command_line_pct":%s,"ssh_source_ip_pct":%s,"auditd_file_path_pct":%s},' \
        "${required_field_completeness}" "${execve_completeness}" "${ssh_completeness}" "${file_completeness}"
    printf '"quality_score":%s,' "${quality_score}"
    printf '"assessment":"%s"' "${assessment}"
    printf '}'
} > "${OUTPUT_PATH}"
 
echo "Report saved to: ${OUTPUT_PATH}"
